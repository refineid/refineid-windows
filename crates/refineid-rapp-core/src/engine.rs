//! The requester engine: the Windows side of RAPP.
//!
//! The engine drives pairing, sessions, and operations using the canonical
//! protocol boundaries from `refineid_rapp`.
//!
//! The engine is blocking and synchronous: the minidriver, PKCS#11 provider,
//! CLI, and GUI call it from their own threads.

use zeroize::Zeroizing;

use crate::ids::{OperationId, PairId, RandomIdExt, SessionId};
use crate::limits;
use crate::message::{CloseReason, ResultStatus};
use crate::offer::{OfferError, PairingOffer};
use crate::operations::{CardOperation, CardOperationResult, OperationError};
use crate::store::{
    CorePairStoreAdapter, JournalEntry, OperationJournal, PairingDisposition, PairingRecord,
    PairingStore, StoreError,
};
use crate::transport::{BinaryFrame, FrameTransport, TransportError};
use refineid_rapp::{
    CancelMessage, EndpointRole, EstablishedEndpoint, ExplicitUserIntent, LivenessMessage,
    OperationReference, OperationRequest, OperationState, PairingHandshake, PingChallenge,
    ProfileName, ProtocolErrorMessage, ReceiveOutcome, SessionCloseMessage, SessionHandshake,
    SessionState, TypedMessage, generate_pair_key_material,
};

/// Local labels sent inside `pairing.hello`. Labels, not identities.
#[derive(Clone, Debug)]
pub struct RequesterConfig {
    /// The display label shown on the proxy.
    pub display_name: String,
    /// The platform label shown on the proxy.
    pub platform: String,
}

/// What the proxy introduced itself as, for the confirmation display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIntroduction {
    /// The peer's display label.
    pub display_name: String,
    /// The peer's platform label.
    pub platform: String,
}

/// Why pairing did not produce a stored record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingError {
    /// The offer failed its structural rules.
    Offer(OfferError),
    /// Key material could not be produced.
    KeyGeneration,
    /// The handshake failed; the offer is not consumed.
    HandshakeFailed,
    /// The transport failed during pairing.
    Transport(TransportError),
    /// The peer's parameter echo did not match the local view.
    ParameterMismatch,
    /// The authenticated exchange violated the protocol; the attempt is
    /// aborted and nothing is recorded.
    ProtocolViolation,
    /// The local user denied the confirmation.
    DeniedLocally,
    /// The peer aborted or denied the confirmation.
    AbortedByPeer,
    /// The two granted sets were not equal.
    GrantsMismatch,
    /// The granted set was not a subset of offered and requested profiles.
    GrantsNotSubset,
    /// The pairing store refused the record.
    Store(StoreError),
    /// The channel failed after authentication.
    Channel,
}

impl core::fmt::Display for PairingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Offer(e) => write!(f, "pairing offer error: {e}"),
            Self::KeyGeneration => f.write_str("key generation failed"),
            Self::HandshakeFailed => f.write_str("handshake failed"),
            Self::Transport(e) => write!(f, "transport error: {e:?}"),
            Self::ParameterMismatch => f.write_str("parameter mismatch"),
            Self::ProtocolViolation => f.write_str("protocol violation"),
            Self::DeniedLocally => f.write_str("pairing denied locally"),
            Self::AbortedByPeer => f.write_str("pairing aborted by peer"),
            Self::GrantsMismatch => f.write_str("grants mismatch"),
            Self::GrantsNotSubset => f.write_str("grants not a valid subset"),
            Self::Store(e) => write!(f, "store error: {e:?}"),
            Self::Channel => f.write_str("channel error"),
        }
    }
}

impl core::error::Error for PairingError {}

/// Why a session could not be opened or continued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// No pairing record exists.
    UnknownPairing,
    /// The pairing is revoked.
    NotPaired(PairingDisposition),
    /// The session handshake failed. When `suggest_repairing` is true,
    /// three consecutive candidates failed authentication and re-pairing
    /// should be suggested without touching stored keys.
    HandshakeFailed {
        /// Whether the consecutive-failure threshold was reached.
        suggest_repairing: bool,
    },
    /// The transport failed.
    Transport(TransportError),
    /// The peer's `session.ready` parameters did not match the local view.
    ParameterMismatch,
    /// The peer closed during establishment.
    ClosedByPeer(CloseReason),
    /// A store operation failed.
    Store(StoreError),
    /// The engine encountered an internal fault.
    EngineFault,
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownPairing => f.write_str("unknown pairing"),
            Self::NotPaired(d) => write!(f, "pairing not usable ({d:?})"),
            Self::HandshakeFailed { suggest_repairing } => {
                if *suggest_repairing {
                    f.write_str("handshake failed (repairing recommended)")
                } else {
                    f.write_str("handshake failed")
                }
            }
            Self::Transport(e) => write!(f, "transport error: {e:?}"),
            Self::ParameterMismatch => f.write_str("session parameter mismatch"),
            Self::ClosedByPeer(reason) => write!(f, "session closed by peer: {reason:?}"),
            Self::Store(e) => write!(f, "store error: {e:?}"),
            Self::EngineFault => f.write_str("engine fault"),
        }
    }
}

impl core::error::Error for SessionError {}

/// Why an operation call could not be admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// The session is not healthy.
    SessionNotHealthy,
    /// The profile is not in the granted set.
    ProfileNotGranted,
    /// An operation is already active.
    OperationActive,
    /// The journal refused the durable write.
    Store(StoreError),
    /// Identifier generation failed.
    RandomUnavailable,
    /// A component exceeded an encoding limit.
    Encoding,
    /// The typed operation violated an invariant.
    Operation(OperationError),
}

impl core::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SessionNotHealthy => f.write_str("session is not healthy"),
            Self::ProfileNotGranted => f.write_str("profile is not in granted set"),
            Self::OperationActive => f.write_str("an operation is already active"),
            Self::Store(e) => write!(f, "journal error: {e:?}"),
            Self::RandomUnavailable => f.write_str("cryptographic random is unavailable"),
            Self::Encoding => f.write_str("operation encoding limit exceeded"),
            Self::Operation(e) => write!(f, "operation error: {e:?}"),
        }
    }
}

impl core::error::Error for AdmissionError {}

/// How a finished operation ended, with the session consequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationOutcome {
    /// The result was delivered, schema-validated, and acknowledged.
    Completed(CardOperationResult),
    /// The proxy user denied before commit.
    Denied,
    /// Cancellation or expiry before physical transmission.
    Cancelled,
    /// A policy or card rejection, with the profile's failure name.
    Rejected(Option<String>),
    /// The card rejected CAN, PIN 1, or PIN 2; the session closes and the
    /// pairing is durably revoked on both peers.
    CredentialRejected,
    /// Completion cannot be proven; automatic retry is permanently forbidden.
    Ambiguous,
}

/// What ended a session, reported after close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// The local side closed deliberately.
    LocalClose,
    /// The peer closed with the carried reason.
    PeerClose(CloseReason),
    /// The transport failed or ended.
    TransportLoss,
    /// A frame failed authenticated decryption.
    IntegrityFailure,
    /// The peer committed an authenticated protocol violation;
    /// the pairing was revoked immediately.
    Violation,
}

/// One live session and its established endpoint.
#[allow(
    clippy::struct_field_names,
    reason = "session_id disambiguates the RAPP session identifier"
)]
pub struct Session<Transport: FrameTransport> {
    transport: Transport,
    endpoint: EstablishedEndpoint,
    pair_id: PairId,
    session_id: SessionId,
    state: SessionState,
    granted_profiles: Vec<String>,
    end: Option<SessionEnd>,
}

impl<Transport: FrameTransport> core::fmt::Debug for Session<Transport> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("pair_id", &self.pair_id)
            .field("session_id", &self.session_id)
            .field("state", &self.state)
            .field("granted_profiles", &self.granted_profiles)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

/// The requester engine over its two durable stores.
#[derive(Debug)]
pub struct Requester<Store: PairingStore, Journal: OperationJournal> {
    config: RequesterConfig,
    store: Store,
    journal: Journal,
}

impl<Store: PairingStore, Journal: OperationJournal> Requester<Store, Journal> {
    /// Creates an engine over its stores.
    pub const fn new(config: RequesterConfig, store: Store, journal: Journal) -> Self {
        Self {
            config,
            store,
            journal,
        }
    }

    /// The pairing store, for inspection and the user's forget action.
    pub const fn store(&self) -> &Store {
        &self.store
    }

    /// Mutable access to the pairing store.
    pub const fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    /// The operation journal, for status display and reconciliation.
    pub const fn journal(&self) -> &Journal {
        &self.journal
    }

    /// Runs the requester half of a manual-code pairing exchange: executes the `CPace`
    /// PAKE exchange over the transport using the 6-digit pairing code to derive
    /// the mutual 256-bit pairing secret, then completes the pairing handshake.
    ///
    /// # Errors
    /// Returns [`PairingError`] on `CPace` PAKE failure, handshake failure,
    /// parameter mismatch, transport loss, or invalid grant.
    pub fn pair_with_code<Transport: FrameTransport>(
        &mut self,
        offer_slot: &mut Option<PairingOffer>,
        code: &str,
        requested_profiles: &[String],
        mut transport: Transport,
        confirm: impl FnOnce(&PeerIntroduction, &[String]) -> Option<Vec<String>>,
    ) -> Result<PairId, PairingError> {
        let Some(offer) = offer_slot.take() else {
            return Err(PairingError::HandshakeFailed);
        };
        let mut entropy = [0u8; 64];
        getrandom::fill(&mut entropy).map_err(|_| PairingError::KeyGeneration)?;
        let cpace = refineid_rapp::cpace::CpaceState::new(
            refineid_rapp::HandshakeRole::Initiator,
            code,
            &offer.offer_id,
            &entropy,
        )
        .map_err(|_| PairingError::HandshakeFailed)?;
        zeroize::Zeroize::zeroize(&mut entropy);

        // 1. Send Initiator's CPace frame
        let my_msg = cpace
            .write_message()
            .map_err(|_| PairingError::HandshakeFailed)?;
        transport
            .send_frame(my_msg.as_bytes())
            .map_err(PairingError::Transport)?;

        // 2. Receive Responder's CPace frame
        let peer_frame_bytes = transport.receive_frame().map_err(PairingError::Transport)?;
        let peer_frame = BinaryFrame::reconstruct(peer_frame_bytes)
            .map_err(|_| PairingError::HandshakeFailed)?;
        let derived_secret = cpace
            .read_message(&peer_frame)
            .map_err(|_| PairingError::HandshakeFailed)?;

        // 3. Proceed with standard Noise XXpsk3 pairing using derived secret
        *offer_slot = Some(offer);
        self.pair_with_secret(
            offer_slot,
            &derived_secret,
            requested_profiles,
            transport,
            confirm,
        )
    }

    /// Runs the requester half of the pairing exchange over an accepted
    /// candidate transport using an ephemeral default secret.
    ///
    /// # Errors
    /// Returns [`PairingError`] on handshake failure, parameter mismatch,
    /// transport loss, or invalid grant.
    pub fn pair<Transport: FrameTransport>(
        &mut self,
        offer_slot: &mut Option<PairingOffer>,
        requested_profiles: &[String],
        transport: Transport,
        confirm: impl FnOnce(&PeerIntroduction, &[String]) -> Option<Vec<String>>,
    ) -> Result<PairId, PairingError> {
        let secret = refineid_rapp::PairingSecret::from_random_bytes([0u8; 32]);
        self.pair_with_secret(offer_slot, &secret, requested_profiles, transport, confirm)
    }

    /// Runs the requester half of the pairing exchange over an accepted
    /// candidate transport with a verified pairing secret.
    ///
    /// # Errors
    /// Returns [`PairingError`] on handshake failure, parameter mismatch,
    /// transport loss, or invalid grant.
    #[allow(
        clippy::too_many_lines,
        reason = "pairing handshake walks 7 sequential wire messages"
    )]
    pub fn pair_with_secret<Transport: FrameTransport>(
        &mut self,
        offer_slot: &mut Option<PairingOffer>,
        pairing_secret: &refineid_rapp::PairingSecret,
        requested_profiles: &[String],
        mut transport: Transport,
        confirm: impl FnOnce(&PeerIntroduction, &[String]) -> Option<Vec<String>>,
    ) -> Result<PairId, PairingError> {
        let Some(offer) = offer_slot.take() else {
            return Err(PairingError::HandshakeFailed);
        };
        let offer_profiles = offer.profiles.clone();
        let local_keys = generate_pair_key_material().map_err(|_| PairingError::KeyGeneration)?;
        let mut handshake = match PairingHandshake::begin(
            EndpointRole::Requester,
            offer,
            transport.candidate_id(),
            local_keys,
            pairing_secret,
        ) {
            Ok(h) => h,
            Err(fail) => {
                let (err, returned_offer) = fail.into_parts();
                *offer_slot = Some(returned_offer);
                return Err(match err {
                    refineid_rapp::PairingError::Offer(e) => PairingError::Offer(e),
                    refineid_rapp::PairingError::CandidateNotUnique => {
                        PairingError::Offer(refineid_rapp::PairingOfferError::InvalidTransport)
                    }
                    _ => PairingError::HandshakeFailed,
                });
            }
        };

        // Noise XX Handshake
        // Message 1 (Requester -> Proxy)
        let m1 = handshake
            .write_message()
            .map_err(|_| PairingError::HandshakeFailed)?;
        transport
            .send_frame(m1.as_bytes())
            .map_err(PairingError::Transport)?;

        // Message 2 (Proxy -> Requester)
        let m2_bytes = transport.receive_frame().map_err(PairingError::Transport)?;
        let m2 = BinaryFrame::reconstruct(m2_bytes).map_err(|_| PairingError::HandshakeFailed)?;
        handshake
            .read_message(&m2)
            .map_err(|_| PairingError::HandshakeFailed)?;

        // Message 3 (Requester -> Proxy)
        let m3 = handshake
            .write_message()
            .map_err(|_| PairingError::HandshakeFailed)?;
        transport
            .send_frame(m3.as_bytes())
            .map_err(PairingError::Transport)?;

        if !handshake.is_complete() {
            return Err(PairingError::HandshakeFailed);
        }

        let mut confirmation = handshake
            .into_confirmation()
            .map_err(|_| PairingError::HandshakeFailed)?;
        let pair_id = confirmation.pair_id();

        // Send Requester Hello
        let hello_frame = confirmation
            .send_hello(
                self.config.display_name.clone(),
                self.config.platform.clone(),
            )
            .map_err(|_| PairingError::Channel)?;
        transport
            .send_frame(hello_frame.as_bytes())
            .map_err(PairingError::Transport)?;

        // Receive Proxy Hello
        let peer_hello_bytes = transport.receive_frame().map_err(PairingError::Transport)?;
        let peer_hello_frame =
            BinaryFrame::reconstruct(peer_hello_bytes).map_err(|_| PairingError::Channel)?;
        let now_ms = current_time_ms();
        let peer_hello = confirmation
            .receive_hello(&peer_hello_frame, now_ms)
            .map_err(|err| match err {
                refineid_rapp::PairingError::ParameterMismatch => PairingError::ParameterMismatch,
                _ => PairingError::ProtocolViolation,
            })?;
        let intro = PeerIntroduction {
            display_name: peer_hello.display_name.clone(),
            platform: peer_hello.platform.clone(),
        };

        // Confirmation callback
        let answer = confirm(&intro, requested_profiles);
        let Some(granted_names) = answer else {
            return Err(PairingError::DeniedLocally);
        };
        let mut granted_profiles = Vec::new();
        for name in &granted_names {
            let Some(p) = ProfileName::parse(name) else {
                return Err(PairingError::GrantsNotSubset);
            };
            if !requested_profiles.iter().any(|r| r == name) {
                return Err(PairingError::GrantsNotSubset);
            }
            if !offer_profiles.iter().any(|o| o == name) {
                return Err(PairingError::GrantsNotSubset);
            }
            granted_profiles.push(p);
        }
        if granted_profiles.is_empty() {
            return Err(PairingError::GrantsNotSubset);
        }

        // Send local confirmation
        let confirm_frame = confirmation
            .send_confirmation(granted_profiles)
            .map_err(|err| match err {
                refineid_rapp::PairingError::GrantMismatch => PairingError::GrantsMismatch,
                refineid_rapp::PairingError::InvalidGrantSet => PairingError::GrantsNotSubset,
                _ => PairingError::Channel,
            })?;
        transport
            .send_frame(confirm_frame.as_bytes())
            .map_err(PairingError::Transport)?;

        // Receive peer confirmation
        let peer_confirm_bytes = transport.receive_frame().map_err(PairingError::Transport)?;
        let peer_confirm_frame =
            BinaryFrame::reconstruct(peer_confirm_bytes).map_err(|_| PairingError::Channel)?;
        confirmation
            .receive_confirmation(&peer_confirm_frame, now_ms)
            .map_err(|err| match err {
                refineid_rapp::PairingError::GrantMismatch => PairingError::GrantsMismatch,
                _ => PairingError::ProtocolViolation,
            })?;

        // Into PairRecord and store
        let pair_record = confirmation
            .into_pair_record(now_ms)
            .map_err(|_| PairingError::Channel)?;
        let local_record =
            PairingRecord::from_core_pair_record(&pair_record, intro.display_name, intro.platform);
        self.store
            .insert(local_record)
            .map_err(PairingError::Store)?;

        Ok(pair_id)
    }

    /// Opens a session to a paired proxy over a connected transport.
    ///
    /// # Errors
    /// Returns [`SessionError`] on unknown pairing, revoked pairing,
    /// handshake failure, or transport loss.
    #[allow(
        clippy::too_many_lines,
        reason = "session handshake walks KK handshake and session ready exchange"
    )]
    pub fn connect<Transport: FrameTransport>(
        &mut self,
        pair_id: PairId,
        mut transport: Transport,
    ) -> Result<Session<Transport>, SessionError> {
        let record = self
            .store
            .get(pair_id)
            .map_err(|_| SessionError::UnknownPairing)?;
        if record.disposition != PairingDisposition::Paired {
            return Err(SessionError::NotPaired(record.disposition));
        }
        let granted_profiles = record.granted_profiles.clone();
        let core_record = record
            .to_core_pair_record()
            .map_err(|_| SessionError::EngineFault)?;
        let mut handshake =
            SessionHandshake::begin_requester(&core_record, ExplicitUserIntent::record())
                .map_err(|_| SessionError::EngineFault)?;

        // Message 1 (Requester -> Proxy)
        let m1 = handshake
            .write_message()
            .map_err(|_| SessionError::EngineFault)?;
        transport
            .send_frame(m1.as_bytes())
            .map_err(SessionError::Transport)?;

        // Message 2 (Proxy -> Requester)
        let m2_bytes = transport.receive_frame().map_err(SessionError::Transport)?;
        let m2 = BinaryFrame::reconstruct(m2_bytes)
            .map_err(|_| SessionError::Transport(TransportError::Failed))?;
        if handshake.read_message(&m2).is_err() {
            let mut failures = 0;
            let _ = self.store.update(pair_id, &mut |entry| {
                entry.candidate_failures += 1;
                failures = entry.candidate_failures;
            });
            return Err(SessionError::HandshakeFailed {
                suggest_repairing: failures >= limits::CANDIDATE_FAILURE_HINT_THRESHOLD,
            });
        }

        if !handshake.is_complete() {
            return Err(SessionError::EngineFault);
        }

        let mut auth = handshake
            .into_authentication()
            .map_err(|_| SessionError::EngineFault)?;
        let session_id = auth.session_id();

        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| SessionError::EngineFault)?;
        let ready_frame = auth
            .send_ready(nonce)
            .map_err(|_| SessionError::Transport(TransportError::Failed))?;
        transport
            .send_frame(ready_frame.as_bytes())
            .map_err(SessionError::Transport)?;

        let peer_ready_bytes = transport.receive_frame().map_err(SessionError::Transport)?;
        let peer_ready_frame = BinaryFrame::reconstruct(peer_ready_bytes)
            .map_err(|_| SessionError::Transport(TransportError::Failed))?;
        let now_ms = current_time_ms();
        let mut store_adapter = CorePairStoreAdapter::new(&mut self.store);
        auth.receive_ready(&mut store_adapter, &peer_ready_frame, now_ms)
            .map_err(|err| match err {
                refineid_rapp::SessionError::ParameterMismatch => SessionError::ParameterMismatch,
                refineid_rapp::SessionError::IntegrityFailure => {
                    SessionError::Transport(TransportError::Failed)
                }
                refineid_rapp::SessionError::AuthenticatedWire(_) => {
                    SessionError::ParameterMismatch
                }
                _ => SessionError::EngineFault,
            })?;

        let endpoint = auth
            .into_established()
            .map_err(|_| SessionError::EngineFault)?;
        let _ = self
            .store
            .update(pair_id, &mut |entry| entry.candidate_failures = 0);

        Ok(Session {
            transport,
            endpoint,
            pair_id,
            session_id,
            state: SessionState::Healthy,
            granted_profiles,
            end: None,
        })
    }

    /// Sends one liveness ping and verifies the echoed challenge.
    ///
    /// # Errors
    /// Returns [`SessionError`] on closed session, challenge mismatch,
    /// peer close, or transport loss.
    pub fn check_liveness<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
    ) -> Result<(), SessionError> {
        if session.state != SessionState::Healthy || session.end.is_some() {
            return Err(SessionError::EngineFault);
        }
        let mut challenge_bytes = [0u8; 32];
        getrandom::fill(&mut challenge_bytes).map_err(|_| SessionError::EngineFault)?;
        let challenge = PingChallenge::reconstruct(challenge_bytes);
        let last = session.endpoint.last_received_sequence().unwrap_or(0);
        let ping_msg = TypedMessage::LivenessPing(LivenessMessage {
            challenge,
            last_received_sequence: last,
        });
        let frame = session
            .endpoint
            .send(&ping_msg)
            .map_err(|_| SessionError::Transport(TransportError::Failed))?;
        session
            .transport
            .send_frame(frame.as_bytes())
            .map_err(SessionError::Transport)?;

        loop {
            let recv_bytes = session.transport.receive_frame().map_err(|e| {
                finish_close(session, SessionEnd::TransportLoss);
                SessionError::Transport(e)
            })?;
            let frame = BinaryFrame::reconstruct(recv_bytes).map_err(|_| {
                finish_close(session, SessionEnd::IntegrityFailure);
                SessionError::Transport(TransportError::Failed)
            })?;
            let now_ms = current_time_ms();
            let mut adapter = CorePairStoreAdapter::new(&mut self.store);
            match session.endpoint.receive(&mut adapter, &frame, now_ms) {
                Ok(ReceiveOutcome::Message(TypedMessage::LivenessPong(pong))) => {
                    if pong.challenge == challenge {
                        return Ok(());
                    }
                }
                Ok(ReceiveOutcome::Message(TypedMessage::LivenessPing(incoming_ping))) => {
                    let reply_pong = TypedMessage::LivenessPong(LivenessMessage {
                        challenge: incoming_ping.challenge,
                        last_received_sequence: session
                            .endpoint
                            .last_received_sequence()
                            .unwrap_or(0),
                    });
                    if let Ok(pong_frame) = session.endpoint.send(&reply_pong) {
                        let _ = session.transport.send_frame(pong_frame.as_bytes());
                    }
                }
                Ok(ReceiveOutcome::Message(TypedMessage::SessionClose(close_msg))) => {
                    self.apply_peer_close_reason(session.pair_id, close_msg.reason);
                    finish_close(session, SessionEnd::PeerClose(close_msg.reason));
                    return Err(SessionError::ClosedByPeer(close_msg.reason));
                }
                Ok(ReceiveOutcome::Message(_)) => {
                    self.handle_violation(session);
                    return Err(SessionError::EngineFault);
                }
                Ok(ReceiveOutcome::PairRevoked { .. }) => {
                    finish_close(session, SessionEnd::Violation);
                    return Err(SessionError::EngineFault);
                }
                Ok(ReceiveOutcome::SessionClosed(_)) | Err(_) => {
                    finish_close(session, SessionEnd::IntegrityFailure);
                    return Err(SessionError::Transport(TransportError::Failed));
                }
            }
        }
    }

    /// Closes a healthy session deliberately.
    pub fn disconnect<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        reason: CloseReason,
    ) {
        if session.end.is_some() {
            return;
        }
        let last = session.endpoint.last_received_sequence().unwrap_or(0);
        let close_msg = TypedMessage::SessionClose(SessionCloseMessage {
            reason,
            last_received_sequence: last,
        });
        if let Ok(frame) = session.endpoint.send(&close_msg) {
            let _ = session.transport.send_frame(frame.as_bytes());
        }
        finish_close(session, SessionEnd::LocalClose);
    }

    /// Runs one typed operation to its outcome.
    ///
    /// # Errors
    /// Returns [`AdmissionError`] on admission failure, profile mismatch,
    /// or session fault.
    #[allow(
        clippy::too_many_lines,
        reason = "operation execution manages prepare, commit, progress, liveness, and result state transitions"
    )]
    pub fn execute<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        operation: &CardOperation,
        expires_after_ms: u64,
    ) -> Result<OperationOutcome, AdmissionError> {
        let profile_name = operation.required_profile();
        let profile_wire = profile_name.as_str();
        if session.state != SessionState::Healthy || session.end.is_some() {
            return Err(AdmissionError::SessionNotHealthy);
        }
        if !session
            .granted_profiles
            .iter()
            .any(|name| name == profile_wire)
        {
            return Err(AdmissionError::ProfileNotGranted);
        }
        let operation_id = OperationId::random().map_err(|_| AdmissionError::RandomUnavailable)?;
        let now_ms = current_time_ms();
        let request = OperationRequest::reconstruct(
            operation_id,
            session.pair_id,
            session.session_id,
            profile_name,
            now_ms,
            expires_after_ms,
            operation.clone(),
        )
        .map_err(AdmissionError::Operation)?;
        let req_hash = request
            .request_hash()
            .map_err(|_| AdmissionError::Encoding)?;
        let consequential = request.operation.is_consequential();
        let (action_wire, _, _) = request.wire_parts();

        self.journal
            .record(JournalEntry {
                operation_id,
                pair_id: session.pair_id,
                request_hash: *req_hash.as_bytes(),
                profile: profile_wire.into(),
                action: action_wire.into(),
                state: OperationState::Requested,
                retry_prohibited: false,
                reconciled_proxy_state: None,
            })
            .map_err(AdmissionError::Store)?;

        let Ok(frame) = session
            .endpoint
            .send(&TypedMessage::OperationRequest(request))
        else {
            let outcome = self.close_with_operation(
                session,
                operation_id,
                OperationState::Requested,
                SessionEnd::TransportLoss,
            );
            return Ok(outcome);
        };
        if session.transport.send_frame(frame.as_bytes()).is_err() {
            let outcome = self.close_with_operation(
                session,
                operation_id,
                OperationState::Requested,
                SessionEnd::TransportLoss,
            );
            return Ok(outcome);
        }

        let mut state = OperationState::Requested;
        loop {
            let frame_bytes = match session.transport.receive_frame() {
                Ok(bytes) => bytes,
                Err(TransportError::TimedOut) if !matches!(state, OperationState::Committed) => {
                    let cancel_msg = TypedMessage::OperationCancel(CancelMessage {
                        reference: OperationReference {
                            operation_id,
                            request_hash: req_hash,
                        },
                        reason: Some("expired".into()),
                    });
                    if let Ok(cancel_frame) = session.endpoint.send(&cancel_msg) {
                        let _ = session.transport.send_frame(cancel_frame.as_bytes());
                    }
                    state = OperationState::Cancelled;
                    self.journal_state(operation_id, state, false);
                    return Ok(OperationOutcome::Cancelled);
                }
                Err(_) => {
                    let outcome = self.close_with_operation(
                        session,
                        operation_id,
                        state,
                        SessionEnd::TransportLoss,
                    );
                    return Ok(outcome);
                }
            };
            let Ok(frame) = BinaryFrame::reconstruct(frame_bytes) else {
                let outcome = self.close_with_operation(
                    session,
                    operation_id,
                    state,
                    SessionEnd::IntegrityFailure,
                );
                return Ok(outcome);
            };
            let now_ms = current_time_ms();
            let mut store_adapter = CorePairStoreAdapter::new(&mut self.store);
            let Ok(outcome) = session.endpoint.receive(&mut store_adapter, &frame, now_ms) else {
                let outcome = self.close_with_operation(
                    session,
                    operation_id,
                    state,
                    SessionEnd::IntegrityFailure,
                );
                return Ok(outcome);
            };
            match outcome {
                ReceiveOutcome::Message(msg) => match msg {
                    TypedMessage::LivenessPing(incoming_ping) => {
                        let reply_pong = TypedMessage::LivenessPong(LivenessMessage {
                            challenge: incoming_ping.challenge,
                            last_received_sequence: session
                                .endpoint
                                .last_received_sequence()
                                .unwrap_or(0),
                        });
                        if let Ok(pong_frame) = session.endpoint.send(&reply_pong) {
                            let _ = session.transport.send_frame(pong_frame.as_bytes());
                        }
                    }
                    TypedMessage::OperationPrepared(prepared_ref) => {
                        if prepared_ref.operation_id != operation_id {
                            let err_msg =
                                TypedMessage::Error(ProtocolErrorMessage::UnknownOperation(Some(
                                    prepared_ref.operation_id,
                                )));
                            if let Ok(err_frame) = session.endpoint.send(&err_msg) {
                                let _ = session.transport.send_frame(err_frame.as_bytes());
                            }
                            continue;
                        }
                        if prepared_ref.request_hash != req_hash
                            || !consequential
                            || state != OperationState::Requested
                        {
                            self.handle_violation(session);
                            return Ok(self.classify_after_close(operation_id, state));
                        }
                        state = OperationState::Committed;
                        self.journal_state(operation_id, state, false);
                        let commit_msg = TypedMessage::OperationCommit(prepared_ref);
                        let Ok(commit_frame) = session.endpoint.send(&commit_msg) else {
                            let outcome = self.close_with_operation(
                                session,
                                operation_id,
                                state,
                                SessionEnd::TransportLoss,
                            );
                            return Ok(outcome);
                        };
                        if session
                            .transport
                            .send_frame(commit_frame.as_bytes())
                            .is_err()
                        {
                            let outcome = self.close_with_operation(
                                session,
                                operation_id,
                                state,
                                SessionEnd::TransportLoss,
                            );
                            return Ok(outcome);
                        }
                    }
                    TypedMessage::OperationResult(result_msg) => {
                        if result_msg.operation_id != operation_id {
                            let err_msg =
                                TypedMessage::Error(ProtocolErrorMessage::UnknownOperation(Some(
                                    result_msg.operation_id,
                                )));
                            if let Ok(err_frame) = session.endpoint.send(&err_msg) {
                                let _ = session.transport.send_frame(err_frame.as_bytes());
                            }
                            continue;
                        }
                        if result_msg.request_hash != req_hash {
                            self.handle_violation(session);
                            return Ok(self.classify_after_close(operation_id, state));
                        }
                        if result_msg.status == ResultStatus::Completed
                            && state == OperationState::Requested
                            && consequential
                        {
                            self.handle_violation(session);
                            return Ok(self.classify_after_close(operation_id, state));
                        }
                        match result_msg.status {
                            ResultStatus::Completed => {
                                let Some(result) = result_msg.result else {
                                    self.handle_violation(session);
                                    return Ok(self.classify_after_close(operation_id, state));
                                };
                                state = OperationState::Completed;
                                self.journal_state(operation_id, state, false);
                                let ack_msg =
                                    TypedMessage::OperationResultAck(OperationReference {
                                        operation_id,
                                        request_hash: req_hash,
                                    });
                                if let Ok(ack_frame) = session.endpoint.send(&ack_msg) {
                                    let _ = session.transport.send_frame(ack_frame.as_bytes());
                                }
                                return Ok(OperationOutcome::Completed(result));
                            }
                            ResultStatus::Denied => {
                                state = OperationState::Denied;
                                self.journal_state(operation_id, state, false);
                                return Ok(OperationOutcome::Denied);
                            }
                            ResultStatus::Cancelled => {
                                state = OperationState::Cancelled;
                                self.journal_state(operation_id, state, false);
                                return Ok(OperationOutcome::Cancelled);
                            }
                            ResultStatus::Rejected => {
                                state = OperationState::Rejected;
                                self.journal_state(operation_id, state, false);
                                return Ok(OperationOutcome::Rejected(
                                    result_msg.error.map(|e| e.as_str().to_owned()),
                                ));
                            }
                            ResultStatus::CredentialRejected => {
                                state = OperationState::CredentialRejected;
                                self.revoke_pairing(session.pair_id, false);
                                self.journal_state(operation_id, state, true);
                                self.await_close_after_credential_rejection(session);
                                return Ok(OperationOutcome::CredentialRejected);
                            }
                            ResultStatus::Ambiguous => {
                                state = OperationState::Ambiguous;
                                self.journal_state(operation_id, state, true);
                                return Ok(OperationOutcome::Ambiguous);
                            }
                        }
                    }
                    TypedMessage::SessionClose(close_msg) => {
                        let end = SessionEnd::PeerClose(close_msg.reason);
                        self.apply_peer_close_reason(session.pair_id, close_msg.reason);
                        let outcome = self.close_with_operation(session, operation_id, state, end);
                        return Ok(outcome);
                    }
                    TypedMessage::OperationProgress(_)
                    | TypedMessage::Error(ProtocolErrorMessage::UnknownOperation(_)) => {}
                    TypedMessage::Error(ProtocolErrorMessage::Busy) => {
                        return Ok(OperationOutcome::Rejected(Some("peer_busy".to_owned())));
                    }
                    _ => {
                        self.handle_violation(session);
                        return Ok(self.classify_after_close(operation_id, state));
                    }
                },
                ReceiveOutcome::SessionClosed(_) => {
                    let outcome = self.close_with_operation(
                        session,
                        operation_id,
                        state,
                        SessionEnd::IntegrityFailure,
                    );
                    return Ok(outcome);
                }
                ReceiveOutcome::PairRevoked { .. } => {
                    let outcome = self.close_with_operation(
                        session,
                        operation_id,
                        state,
                        SessionEnd::Violation,
                    );
                    return Ok(outcome);
                }
            }
        }
    }

    /// Queries the proxy journal for an earlier operation.
    ///
    /// # Errors
    /// Returns [`SessionError`] on closed session, peer close,
    /// violation, or transport loss.
    pub fn reconcile_status<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        operation_id: OperationId,
    ) -> Result<Option<String>, SessionError> {
        if session.state != SessionState::Healthy || session.end.is_some() {
            return Err(SessionError::EngineFault);
        }
        let req_msg = TypedMessage::OperationStatusRequest(operation_id);
        let frame = session
            .endpoint
            .send(&req_msg)
            .map_err(|_| SessionError::Transport(TransportError::Failed))?;
        session
            .transport
            .send_frame(frame.as_bytes())
            .map_err(SessionError::Transport)?;

        loop {
            let recv_bytes = session.transport.receive_frame().map_err(|e| {
                finish_close(session, SessionEnd::TransportLoss);
                SessionError::Transport(e)
            })?;
            let frame = BinaryFrame::reconstruct(recv_bytes).map_err(|_| {
                finish_close(session, SessionEnd::IntegrityFailure);
                SessionError::Transport(TransportError::Failed)
            })?;
            let now_ms = current_time_ms();
            let mut adapter = CorePairStoreAdapter::new(&mut self.store);
            match session.endpoint.receive(&mut adapter, &frame, now_ms) {
                Ok(ReceiveOutcome::Message(TypedMessage::OperationStatus(report))) => {
                    if report.operation_id != operation_id {
                        continue;
                    }
                    let annotation = if report.known {
                        report.state.map(|s| format!("{s:?}"))
                    } else {
                        None
                    };
                    if let Ok(entry) = self.journal.get(operation_id) {
                        let mut updated = entry.clone();
                        updated.reconciled_proxy_state.clone_from(&annotation);
                        let _ = self.journal.record(updated);
                    }
                    return Ok(annotation);
                }
                Ok(ReceiveOutcome::Message(TypedMessage::LivenessPing(incoming_ping))) => {
                    let reply_pong = TypedMessage::LivenessPong(LivenessMessage {
                        challenge: incoming_ping.challenge,
                        last_received_sequence: session
                            .endpoint
                            .last_received_sequence()
                            .unwrap_or(0),
                    });
                    if let Ok(pong_frame) = session.endpoint.send(&reply_pong) {
                        let _ = session.transport.send_frame(pong_frame.as_bytes());
                    }
                }
                Ok(ReceiveOutcome::Message(TypedMessage::SessionClose(close_msg))) => {
                    self.apply_peer_close_reason(session.pair_id, close_msg.reason);
                    finish_close(session, SessionEnd::PeerClose(close_msg.reason));
                    return Err(SessionError::ClosedByPeer(close_msg.reason));
                }
                Ok(ReceiveOutcome::Message(_)) => {
                    self.handle_violation(session);
                    return Err(SessionError::EngineFault);
                }
                Ok(ReceiveOutcome::SessionClosed(_) | ReceiveOutcome::PairRevoked { .. }) => {
                    finish_close(session, SessionEnd::Violation);
                    return Err(SessionError::EngineFault);
                }
                Err(_) => {
                    finish_close(session, SessionEnd::IntegrityFailure);
                    return Err(SessionError::Transport(TransportError::Failed));
                }
            }
        }
    }

    /// How the session ended, once closed.
    pub const fn session_end<Transport: FrameTransport>(
        session: &Session<Transport>,
    ) -> Option<SessionEnd> {
        session.end
    }

    /// Rewrites one journal entry's state.
    fn journal_state(
        &mut self,
        operation_id: OperationId,
        state: OperationState,
        retry_prohibited: bool,
    ) {
        if let Ok(entry) = self.journal.get(operation_id) {
            let mut updated = entry.clone();
            updated.state = state;
            updated.retry_prohibited = updated.retry_prohibited || retry_prohibited;
            let _ = self.journal.record(updated);
        }
    }

    /// Durably revokes the pairing.
    fn revoke_pairing(&mut self, pair_id: PairId, peer_initiated: bool) {
        let _ = self.store.update(pair_id, &mut |entry| {
            entry.disposition = PairingDisposition::Revoked;
            entry.peer_initiated_termination = peer_initiated;
            entry.local_private = Zeroizing::new(Vec::new());
            entry.peer_public = Vec::new();
        });
    }

    /// Applies a peer close reason's pairing effect.
    fn apply_peer_close_reason(&mut self, pair_id: PairId, reason: CloseReason) {
        match reason {
            CloseReason::PairingRevoked
            | CloseReason::ProtocolViolation
            | CloseReason::CredentialRejected => {
                self.revoke_pairing(pair_id, true);
            }
            CloseReason::UserDisconnect | CloseReason::Policy | CloseReason::Shutdown => {}
        }
    }

    /// Handles an authenticated protocol violation: revokes pairing and closes session.
    fn handle_violation<Transport: FrameTransport>(&mut self, session: &mut Session<Transport>) {
        let last = session.endpoint.last_received_sequence().unwrap_or(0);
        let close_msg = TypedMessage::SessionClose(SessionCloseMessage {
            reason: CloseReason::ProtocolViolation,
            last_received_sequence: last,
        });
        if let Ok(frame) = session.endpoint.send(&close_msg) {
            let _ = session.transport.send_frame(frame.as_bytes());
        }
        self.revoke_pairing(session.pair_id, false);
        finish_close(session, SessionEnd::Violation);
    }

    /// Classifies the active operation after the session already closed.
    fn classify_after_close(
        &mut self,
        operation_id: OperationId,
        state: OperationState,
    ) -> OperationOutcome {
        match state {
            OperationState::Denied => OperationOutcome::Denied,
            OperationState::Rejected => OperationOutcome::Rejected(None),
            OperationState::CredentialRejected => OperationOutcome::CredentialRejected,
            OperationState::Completed | OperationState::Ambiguous => OperationOutcome::Ambiguous,
            OperationState::Cancelled => OperationOutcome::Cancelled,
            OperationState::Committed => {
                self.journal_state(operation_id, OperationState::Ambiguous, true);
                OperationOutcome::Ambiguous
            }
            _ => {
                self.journal_state(operation_id, OperationState::Cancelled, false);
                OperationOutcome::Cancelled
            }
        }
    }

    /// Consumes the proxy's close after a credential rejection.
    fn await_close_after_credential_rejection<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
    ) {
        let Ok(frame_bytes) = session.transport.receive_frame() else {
            finish_close(session, SessionEnd::TransportLoss);
            return;
        };
        let Ok(frame) = BinaryFrame::reconstruct(frame_bytes) else {
            finish_close(session, SessionEnd::IntegrityFailure);
            return;
        };
        let now_ms = current_time_ms();
        let mut store_adapter = CorePairStoreAdapter::new(&mut self.store);
        let end = match session.endpoint.receive(&mut store_adapter, &frame, now_ms) {
            Ok(ReceiveOutcome::Message(TypedMessage::SessionClose(msg))) => {
                self.apply_peer_close_reason(session.pair_id, msg.reason);
                SessionEnd::PeerClose(msg.reason)
            }
            Ok(ReceiveOutcome::SessionClosed(_)) => SessionEnd::IntegrityFailure,
            _ => SessionEnd::TransportLoss,
        };
        finish_close(session, end);
    }

    /// Closes the session and classifies the active operation in one step.
    fn close_with_operation<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        operation_id: OperationId,
        state: OperationState,
        end: SessionEnd,
    ) -> OperationOutcome {
        finish_close(session, end);
        self.classify_after_close(operation_id, state)
    }
}

/// Walks the session into closed and records the end.
fn finish_close<Transport: FrameTransport>(session: &mut Session<Transport>, end: SessionEnd) {
    session.endpoint.close_session();
    session.state = SessionState::Closed;
    session.end = Some(end);
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "milliseconds since Unix epoch fits safely in u64"
)]
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
