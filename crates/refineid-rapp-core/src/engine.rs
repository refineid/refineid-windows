//! The requester engine: the Windows side of RAPP.
//!
//! The engine drives pairing (Section 9), sessions (Sections 10 and 11),
//! and operations (Section 12) through the role projection of the Section
//! 14 model. Every state change consults the transcribed transition tables
//! first; an input with no modeled transition is handled by exactly one
//! unexpected-input policy class, and an engine step the model refuses is a
//! local internal fault, never an invented transition.
//!
//! The engine is blocking and synchronous: the minidriver and settings
//! application call it from their own threads, and human time on the proxy
//! is bounded by the operation's expiry budget rather than by transport
//! deadlines chosen here.

use zeroize::Zeroizing;

use crate::hashes::{grants_hash, request_hash};
use crate::ids::{
    Challenge, OperationId, PairId, PairingSecret, SessionId, derive_pair_id,
    derive_rendezvous_token, derive_session_id,
};
use crate::limits;
use crate::message::{
    Body, CloseReason, ERROR_BUSY, ERROR_UNKNOWN_OPERATION, Envelope, NegotiatedParameters,
    ResultStatus, SchemaViolation, SessionParameters,
};
use crate::noise::{
    ChannelError, HandshakeRole, SecureChannel, generate_pair_keys, pairing_prologue,
    run_pairing_handshake, run_session_handshake,
};
use crate::offer::{OfferError, PairingOffer};
use crate::operations::{CardOperation, CardOperationResult, OperationError};
use crate::states::{
    OPERATION_TRANSITIONS, OperationEvent, OperationState, SESSION_TRANSITIONS, SessionEvent,
    SessionState, requester_transition,
};
use crate::store::{
    JournalEntry, OperationJournal, PairingDisposition, PairingRecord, PairingStore, StoreError,
};
use crate::transport::{FrameTransport, TransportError};
use crate::{PAIRING_SUITE, SESSION_SUITE, WIRE_VERSION};

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
    /// aborted and nothing is recorded (Section 14.5 class 4, pre-store).
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

/// Why a session could not be opened or continued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// No pairing record exists.
    UnknownPairing,
    /// The pairing is revoked.
    NotPaired(PairingDisposition),
    /// The session handshake failed. When `suggest_repairing` is true,
    /// three consecutive candidates failed authentication and re-pairing
    /// should be suggested without touching stored keys (Section 14.6).
    HandshakeFailed {
        /// Whether the consecutive-failure threshold was reached.
        suggest_repairing: bool,
    },
    /// The transport failed.
    Transport(TransportError),
    /// The peer reported `busy`: an existing session survives, this one
    /// closed (Section 10).
    Busy,
    /// The peer's `session.ready` parameters did not match the local view.
    ParameterMismatch,
    /// The peer closed during establishment.
    ClosedByPeer(CloseReason),
    /// A store operation failed.
    Store(StoreError),
    /// The engine attempted a transition the model refuses: a local
    /// internal fault (policy class 5).
    EngineFault,
}

/// Why an operation call could not be admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// The session is not healthy (`INV-02`).
    SessionNotHealthy,
    /// The profile is not in the granted set (X-08).
    ProfileNotGranted,
    /// An operation is already active (`INV-04`).
    OperationActive,
    /// The journal refused the durable write.
    Store(StoreError),
    /// Identifier generation failed.
    RandomUnavailable,
    /// A component exceeded an encoding limit.
    Encoding,
    /// The typed operation violated a Section 13.2.1 invariant.
    Operation(OperationError),
}

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
    /// pairing is durably revoked on both peers (`INV-16`, `INV-17`,
    /// Section 13.4).
    CredentialRejected,
    /// Completion cannot be proven; automatic retry is permanently
    /// forbidden (`INV-06`).
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
    /// A frame failed authenticated decryption (policy class 2).
    IntegrityFailure,
    /// The peer committed an authenticated protocol violation
    /// (policy class 4); the pairing was revoked immediately.
    Violation,
}

/// The requester engine over its two durable stores.
#[derive(Debug)]
pub struct Requester<Store: PairingStore, Journal: OperationJournal> {
    config: RequesterConfig,
    store: Store,
    journal: Journal,
}

/// One live session and its single operation slot.
pub struct Session<Transport: FrameTransport> {
    channel: MessageChannel<Transport>,
    pair_id: PairId,
    state: SessionState,
    granted_profiles: Vec<String>,
    end: Option<SessionEnd>,
}

impl<Transport: FrameTransport> core::fmt::Debug for Session<Transport> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("pair_id", &self.pair_id)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// The envelope discipline of Section 7.3 over a secure channel.
struct MessageChannel<Transport: FrameTransport> {
    secure: SecureChannel<Transport>,
    session_id: SessionId,
    send_sequence: u64,
    receive_sequence: u64,
}

/// What reading one envelope produced.
enum Inbound {
    /// A schema-valid body in sequence.
    Message(Body),
    /// The transport failed or ended.
    Transport(TransportError),
    /// Authenticated decryption failed (policy class 2).
    Integrity,
    /// A schema, sequence, or session violation (policy class 4).
    Violation,
}

impl<Transport: FrameTransport> MessageChannel<Transport> {
    const fn new(secure: SecureChannel<Transport>, session_id: SessionId) -> Self {
        Self {
            secure,
            session_id,
            send_sequence: 0,
            receive_sequence: 0,
        }
    }

    /// The highest sequence received, for close and liveness bodies.
    const fn last_received_sequence(&self) -> u64 {
        self.receive_sequence.saturating_sub(1)
    }

    /// Sends one body under the next send sequence.
    fn send(&mut self, body: Body) -> Result<(), ChannelError> {
        let envelope = Envelope {
            version: WIRE_VERSION,
            session_id: self.session_id,
            sequence: self.send_sequence,
            body,
        };
        let plaintext = envelope
            .encode()
            .map_err(|_| ChannelError::PlaintextTooLarge)?;
        self.secure.send_plaintext(&plaintext)?;
        self.send_sequence += 1;
        Ok(())
    }

    /// Receives and disciplines one envelope.
    fn receive(&mut self) -> Inbound {
        let plaintext = match self.secure.receive_plaintext() {
            Ok(plaintext) => plaintext,
            Err(ChannelError::Transport(error)) => return Inbound::Transport(error),
            Err(ChannelError::Integrity | ChannelError::PlaintextTooLarge) => {
                return Inbound::Integrity;
            }
        };
        let envelope = match Envelope::decode(&plaintext) {
            Ok(envelope) => envelope,
            Err(SchemaViolation::UnknownCriticalField | _) => return Inbound::Violation,
        };
        // Any version difference is incompatible (Section 6).
        if envelope.version != WIRE_VERSION
            || envelope.session_id != self.session_id
            || envelope.sequence != self.receive_sequence
        {
            return Inbound::Violation;
        }
        self.receive_sequence += 1;
        Inbound::Message(envelope.body)
    }
}

/// The three ways the pairing-channel confirmation can end.
enum ConfirmationAnswer {
    Granted(Vec<String>),
    Denied,
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

    /// Runs the requester half of the pairing exchange of Section 9.3 over
    /// an accepted candidate transport.
    ///
    /// The caller created the offer, displayed its QR, and accepted one
    /// candidate connection. `confirm` is the human confirmation control:
    /// it receives the peer's introduction and the requested profiles, and
    /// returns the granted set, or `None` to deny. On success the record is
    /// stored atomically and the pairing channel is closed.
    ///
    /// # Errors
    ///
    /// A handshake failure leaves the offer live for further candidates;
    /// every failure after the handshake invalidates the attempt and stores
    /// nothing.
    #[allow(
        clippy::too_many_lines,
        reason = "the pairing exchange is one protocol sequence and reads best unsplit"
    )]
    pub fn pair<Transport: FrameTransport>(
        &mut self,
        offer: &PairingOffer,
        secret: PairingSecret,
        requested_profiles: &[String],
        transport: Transport,
        confirm: impl FnOnce(&PeerIntroduction, &[String]) -> Option<Vec<String>>,
    ) -> Result<PairId, PairingError> {
        let offer_hash = offer.offer_hash().map_err(PairingError::Offer)?;
        let transport_profile = transport.profile().to_owned();
        let candidate_id = transport.candidate_id().to_owned();
        let prologue = pairing_prologue(WIRE_VERSION, &offer_hash, &transport_profile)
            .map_err(|_| PairingError::HandshakeFailed)?;
        let local_keys = generate_pair_keys().map_err(|_| PairingError::KeyGeneration)?;
        let completed = run_pairing_handshake(
            HandshakeRole::Initiator,
            transport,
            &local_keys,
            secret,
            &prologue,
        )
        .map_err(|error| match error {
            crate::noise::HandshakeError::Transport(transport_error) => {
                PairingError::Transport(transport_error)
            }
            _ => PairingError::HandshakeFailed,
        })?;
        let peer_public = completed
            .peer_static_public
            .clone()
            .ok_or(PairingError::HandshakeFailed)?;
        let session_id = derive_session_id(&completed.handshake_hash);
        let pair_id = derive_pair_id(&completed.handshake_hash);
        let rendezvous_token = derive_rendezvous_token(&completed.handshake_hash);
        let mut channel = MessageChannel::new(completed.channel, session_id);

        // Both peers exchange pairing.hello with the negotiated-parameter
        // echo (Sections 8.4 and 9.4).
        let own_parameters = NegotiatedParameters {
            version: WIRE_VERSION,
            suite: PAIRING_SUITE.into(),
            offer_hash,
            transport_profile,
            candidate_id,
        };
        channel
            .send(Body::PairingHello {
                parameters: own_parameters.clone(),
                display_name: self.config.display_name.clone(),
                platform: self.config.platform.clone(),
                requested_profiles: Some(requested_profiles.to_vec()),
            })
            .map_err(|_| PairingError::Channel)?;
        let peer = match channel.receive() {
            Inbound::Message(Body::PairingHello {
                parameters,
                display_name,
                platform,
                requested_profiles: _,
            }) => {
                if parameters != own_parameters {
                    return Err(PairingError::ParameterMismatch);
                }
                PeerIntroduction {
                    display_name,
                    platform,
                }
            }
            Inbound::Message(Body::PairingAbort { .. }) => {
                return Err(PairingError::AbortedByPeer);
            }
            Inbound::Message(_) | Inbound::Violation => {
                return Err(PairingError::ProtocolViolation);
            }
            Inbound::Transport(error) => return Err(PairingError::Transport(error)),
            Inbound::Integrity => return Err(PairingError::Channel),
        };

        // Human confirmation, then the granted-set agreement.
        let answer = confirm(&peer, requested_profiles)
            .map_or(ConfirmationAnswer::Denied, ConfirmationAnswer::Granted);
        let mut granted = match answer {
            ConfirmationAnswer::Denied => {
                let _ = channel.send(Body::PairingAbort {
                    reason: "denied".into(),
                });
                return Err(PairingError::DeniedLocally);
            }
            ConfirmationAnswer::Granted(granted) => granted,
        };
        let permitted =
            |name: &String| offer.profiles.contains(name) && requested_profiles.contains(name);
        if granted.is_empty() || !granted.iter().all(permitted) {
            let _ = channel.send(Body::PairingAbort {
                reason: "grants".into(),
            });
            return Err(PairingError::GrantsNotSubset);
        }
        granted.sort_unstable();
        channel
            .send(Body::PairingConfirm {
                granted_profiles: granted.clone(),
            })
            .map_err(|_| PairingError::Channel)?;
        let peer_granted = match channel.receive() {
            Inbound::Message(Body::PairingConfirm { granted_profiles }) => granted_profiles,
            Inbound::Message(Body::PairingAbort { .. }) => {
                return Err(PairingError::AbortedByPeer);
            }
            Inbound::Message(_) | Inbound::Violation => {
                return Err(PairingError::ProtocolViolation);
            }
            Inbound::Transport(error) => return Err(PairingError::Transport(error)),
            Inbound::Integrity => return Err(PairingError::Channel),
        };
        let mut sorted_local = granted.clone();
        sorted_local.sort_unstable();
        let mut sorted_peer = peer_granted;
        sorted_peer.sort_unstable();
        if sorted_local != sorted_peer {
            return Err(PairingError::GrantsMismatch);
        }
        let grants = grants_hash(&granted).map_err(|_| PairingError::Channel)?;

        // Only after both confirmations: the atomic store (Section 9.3
        // step 8). The pairing channel then closes; operations use fresh
        // sessions.
        self.store
            .insert(PairingRecord {
                pair_id,
                rendezvous_token,
                local_private: Zeroizing::new(local_keys.private.to_vec()),
                local_public: local_keys.public.clone(),
                peer_public,
                granted_profiles: granted,
                grants_hash: grants,
                peer_display_name: peer.display_name,
                peer_platform: peer.platform,
                disposition: PairingDisposition::Paired,
                peer_initiated_termination: false,
                candidate_failures: 0,
                auth_cert: None,
                signature_cert: None,
                root_ca: None,
                intermediate_ca: None,
            })
            .map_err(PairingError::Store)?;
        let _ = channel.send(Body::SessionClose {
            reason: CloseReason::Shutdown,
            last_received_sequence: channel.last_received_sequence(),
        });
        Ok(pair_id)
    }

    /// Opens a session to a paired proxy over a connected transport
    /// (Section 10).
    ///
    /// # Errors
    ///
    /// Fails on the admission guards, the handshake, the parameter echo,
    /// or a peer `busy`.
    pub fn connect<Transport: FrameTransport>(
        &mut self,
        pair_id: PairId,
        transport: Transport,
    ) -> Result<Session<Transport>, SessionError> {
        let record = self
            .store
            .get(pair_id)
            .map_err(|_| SessionError::UnknownPairing)?;
        if record.disposition != PairingDisposition::Paired {
            return Err(SessionError::NotPaired(record.disposition));
        }
        let granted_profiles = record.granted_profiles.clone();
        let grants = record.grants_hash;
        let local_private = record.local_private.clone();
        let peer_public = record.peer_public.clone();
        // Model: absent --connect--> connecting --transport_connected-->
        // authenticating. The caller hands over a connected transport, so
        // both requester-side steps happen here.
        let transport_profile = transport.profile().to_owned();
        let candidate_id = transport.candidate_id().to_owned();
        let prologue =
            crate::noise::session_prologue(WIRE_VERSION, pair_id, &grants, &transport_profile)
                .map_err(|_| SessionError::EngineFault)?;
        let completed = match run_session_handshake(
            HandshakeRole::Initiator,
            transport,
            &local_private,
            &peer_public,
            &prologue,
        ) {
            Ok(completed) => completed,
            Err(crate::noise::HandshakeError::Transport(error)) => {
                return Err(SessionError::Transport(error));
            }
            Err(_) => {
                // Candidate failure: count toward the re-pairing hint
                // without touching stored keys (Section 14.6, INV-18).
                let mut failures = 0;
                self.store
                    .update(pair_id, &mut |entry| {
                        entry.candidate_failures += 1;
                        failures = entry.candidate_failures;
                    })
                    .map_err(SessionError::Store)?;
                return Err(SessionError::HandshakeFailed {
                    suggest_repairing: failures >= limits::CANDIDATE_FAILURE_HINT_THRESHOLD,
                });
            }
        };
        let session_id = derive_session_id(&completed.handshake_hash);
        let mut channel = MessageChannel::new(completed.channel, session_id);
        let nonce = Challenge::random().map_err(|_| SessionError::EngineFault)?;
        let own_parameters = SessionParameters {
            version: WIRE_VERSION,
            suite: SESSION_SUITE.into(),
            transport_profile,
            candidate_id,
            grants_hash: grants,
        };
        channel
            .send(Body::SessionReady {
                parameters: own_parameters.clone(),
                nonce: nonce.0,
            })
            .map_err(|_| SessionError::Transport(TransportError::Failed))?;
        match channel.receive() {
            Inbound::Message(Body::SessionReady { parameters, .. }) => {
                if parameters != own_parameters {
                    return Err(SessionError::ParameterMismatch);
                }
            }
            Inbound::Message(Body::Error { error, .. }) if error == ERROR_BUSY => {
                return Err(SessionError::Busy);
            }
            Inbound::Message(Body::SessionClose { reason, .. }) => {
                return Err(SessionError::ClosedByPeer(reason));
            }
            Inbound::Message(_) | Inbound::Violation => {
                return Err(SessionError::ParameterMismatch);
            }
            Inbound::Transport(error) => return Err(SessionError::Transport(error)),
            Inbound::Integrity => {
                return Err(SessionError::Transport(TransportError::Failed));
            }
        }
        // ready_verified: the session is healthy and the candidate-failure
        // count resets.
        self.store
            .update(pair_id, &mut |entry| entry.candidate_failures = 0)
            .map_err(SessionError::Store)?;
        Ok(Session {
            channel,
            pair_id,
            state: SessionState::Healthy,
            granted_profiles,
            end: None,
        })
    }

    /// Sends one liveness ping and verifies the echoed challenge
    /// (Section 11).
    ///
    /// # Errors
    ///
    /// Fails when the session is not healthy or the exchange could not be
    /// completed; the caller decides checking-state policy from the error.
    pub fn check_liveness<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
    ) -> Result<(), SessionError> {
        if session.state != SessionState::Healthy {
            return Err(SessionError::EngineFault);
        }
        let challenge = Challenge::random().map_err(|_| SessionError::EngineFault)?;
        session
            .channel
            .send(Body::LivenessPing {
                challenge,
                last_received_sequence: session.channel.last_received_sequence(),
            })
            .map_err(|_| SessionError::Transport(TransportError::Failed))?;
        loop {
            match session.channel.receive() {
                Inbound::Message(Body::LivenessPong {
                    challenge: echoed, ..
                }) => {
                    if echoed == challenge {
                        return Ok(());
                    }
                    // A pong whose challenge matches no outstanding ping is
                    // a stale-reference race: discarded, not liveness proof.
                }
                Inbound::Message(Body::LivenessPing {
                    challenge: peer_challenge,
                    ..
                }) => {
                    session
                        .channel
                        .send(Body::LivenessPong {
                            challenge: peer_challenge,
                            last_received_sequence: session.channel.last_received_sequence(),
                        })
                        .map_err(|_| SessionError::Transport(TransportError::Failed))?;
                }
                Inbound::Message(Body::SessionClose { reason, .. }) => {
                    finish_close(session, SessionEnd::PeerClose(reason));
                    return Err(SessionError::ClosedByPeer(reason));
                }
                Inbound::Message(_) | Inbound::Violation => {
                    self.handle_violation(session, None);
                    return Err(SessionError::EngineFault);
                }
                Inbound::Transport(error) => {
                    finish_close(session, SessionEnd::TransportLoss);
                    return Err(SessionError::Transport(error));
                }
                Inbound::Integrity => {
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
        if matches!(session.state, SessionState::Closed) {
            return;
        }
        let last = session.channel.last_received_sequence();
        let _ = session.channel.send(Body::SessionClose {
            reason,
            last_received_sequence: last,
        });
        finish_close(session, SessionEnd::LocalClose);
    }

    /// Runs one typed operation to its outcome (Section 12).
    ///
    /// For a profile with a consequential command the engine sends the
    /// request, waits for `operation.prepared`, journals its commit intent
    /// durably, commits, and waits for the result. For a status-class
    /// profile the proxy answers the request directly. Liveness pings from
    /// the proxy are answered while waiting.
    ///
    /// # Errors
    ///
    /// Admission failures leave the session untouched. After admission the
    /// outcome always reflects the model's classification, including the
    /// close classifications of Section 14.7.
    #[allow(
        clippy::too_many_lines,
        reason = "the operation loop is one state machine and reads best unsplit"
    )]
    pub fn execute<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        operation: &CardOperation,
        expires_after_ms: u64,
    ) -> Result<OperationOutcome, AdmissionError> {
        let profile = operation.profile();
        let action = operation.action();
        let (context, payload) = operation.wire_parts().map_err(AdmissionError::Operation)?;
        // Admission (X-08, INV-02, INV-04).
        if session.state != SessionState::Healthy {
            return Err(AdmissionError::SessionNotHealthy);
        }
        if !session.granted_profiles.iter().any(|name| name == profile) {
            return Err(AdmissionError::ProfileNotGranted);
        }
        let operation_id = OperationId::random().map_err(|_| AdmissionError::RandomUnavailable)?;
        let hash = request_hash(
            session.channel.session_id,
            operation_id,
            profile,
            action,
            &context,
            &payload,
        )
        .map_err(|_| AdmissionError::Encoding)?;
        let consequential = operation.is_consequential();
        let mut state =
            advance_operation(OperationState::Idle, OperationEvent::OperationRequestSent)
                .ok_or(AdmissionError::SessionNotHealthy)?;
        self.journal
            .record(JournalEntry {
                operation_id,
                pair_id: session.pair_id,
                request_hash: hash,
                profile: profile.into(),
                action: action.into(),
                state,
                retry_prohibited: false,
                reconciled_proxy_state: None,
            })
            .map_err(AdmissionError::Store)?;
        if session
            .channel
            .send(Body::OperationRequest {
                operation_id,
                profile: profile.into(),
                action: action.into(),
                request_hash: hash,
                expires_after_ms,
                context,
                payload,
            })
            .is_err()
        {
            let outcome =
                self.close_with_operation(session, operation_id, state, SessionEnd::TransportLoss);
            return Ok(outcome);
        }

        loop {
            match session.channel.receive() {
                Inbound::Message(Body::LivenessPing { challenge, .. }) => {
                    let last = session.channel.last_received_sequence();
                    if session
                        .channel
                        .send(Body::LivenessPong {
                            challenge,
                            last_received_sequence: last,
                        })
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
                Inbound::Message(Body::OperationPrepared {
                    operation_id: echoed_id,
                    request_hash: echoed_hash,
                }) => {
                    if echoed_id != operation_id {
                        // Stale-reference race (policy class 3).
                        let _ = session.channel.send(Body::Error {
                            error: ERROR_UNKNOWN_OPERATION.into(),
                            operation_id: Some(echoed_id),
                        });
                        continue;
                    }
                    if echoed_hash != hash || !consequential {
                        self.handle_violation(session, Some((operation_id, state)));
                        return Ok(self.classify_after_close(operation_id, state));
                    }
                    let Some(next) = advance_operation(state, OperationEvent::PreparedReceived)
                    else {
                        self.handle_violation(session, Some((operation_id, state)));
                        return Ok(self.classify_after_close(operation_id, state));
                    };
                    state = next;
                    self.journal_state(operation_id, state, false);
                    // The durable commit intent precedes operation.commit.
                    let Some(committed) = advance_operation(state, OperationEvent::CommitSent)
                    else {
                        self.handle_violation(session, Some((operation_id, state)));
                        return Ok(self.classify_after_close(operation_id, state));
                    };
                    self.journal_state(operation_id, committed, false);
                    state = committed;
                    if session
                        .channel
                        .send(Body::OperationCommit {
                            operation_id,
                            request_hash: hash,
                        })
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
                Inbound::Message(Body::OperationResult {
                    operation_id: echoed_id,
                    request_hash: echoed_hash,
                    status,
                    error,
                    body,
                }) => {
                    if echoed_id != operation_id {
                        let _ = session.channel.send(Body::Error {
                            error: ERROR_UNKNOWN_OPERATION.into(),
                            operation_id: Some(echoed_id),
                        });
                        continue;
                    }
                    if echoed_hash != hash {
                        self.handle_violation(session, Some((operation_id, state)));
                        return Ok(self.classify_after_close(operation_id, state));
                    }
                    let event = match status {
                        ResultStatus::Completed => OperationEvent::ResultCompletedReceived,
                        ResultStatus::Denied => OperationEvent::ResultDeniedReceived,
                        ResultStatus::Cancelled => OperationEvent::ResultCancelledReceived,
                        ResultStatus::Rejected => OperationEvent::ResultRejectedReceived,
                        ResultStatus::CredentialRejected => {
                            OperationEvent::ResultCredentialRejectedReceived
                        }
                        ResultStatus::Ambiguous => OperationEvent::ResultAmbiguousReceived,
                    };
                    // The completed-in-requested row is guarded by the
                    // profile having no consequential command.
                    if status == ResultStatus::Completed
                        && state == OperationState::Requested
                        && consequential
                    {
                        self.handle_violation(session, Some((operation_id, state)));
                        return Ok(self.classify_after_close(operation_id, state));
                    }
                    let Some(next) = advance_operation(state, event) else {
                        self.handle_violation(session, Some((operation_id, state)));
                        return Ok(self.classify_after_close(operation_id, state));
                    };
                    // Section 13.2.1: a completed body must answer exactly
                    // this operation's schema, and every other status
                    // carries an empty body. A mismatch in a successfully
                    // decrypted message is an authenticated violation.
                    if next == OperationState::Completed {
                        let Ok(result) = CardOperationResult::from_body(operation, body) else {
                            self.handle_violation(session, Some((operation_id, state)));
                            return Ok(self.classify_after_close(operation_id, state));
                        };
                        state = next;
                        self.journal_state(operation_id, state, false);
                        let _ = session.channel.send(Body::OperationResultAck {
                            operation_id,
                            request_hash: hash,
                        });
                        return Ok(OperationOutcome::Completed(result));
                    }
                    if !body.is_empty() {
                        self.handle_violation(session, Some((operation_id, state)));
                        return Ok(self.classify_after_close(operation_id, state));
                    }
                    state = next;
                    let retry_prohibited = state == OperationState::Ambiguous;
                    self.journal_state(operation_id, state, retry_prohibited);
                    return Ok(match state {
                        OperationState::Denied => OperationOutcome::Denied,
                        OperationState::Cancelled => OperationOutcome::Cancelled,
                        OperationState::Rejected => OperationOutcome::Rejected(error),
                        OperationState::CredentialRejected => {
                            // INV-16 and Section 13.4: the authenticated
                            // credential_rejected result durably revokes the
                            // pairing on this peer before the terminal
                            // outcome is reported; the proxy then closes.
                            self.revoke_pairing(session.pair_id, false);
                            self.await_close_after_credential_rejection(session);
                            OperationOutcome::CredentialRejected
                        }
                        _ => OperationOutcome::Ambiguous,
                    });
                }
                Inbound::Message(Body::SessionClose { reason, .. }) => {
                    let end = SessionEnd::PeerClose(reason);
                    self.apply_peer_close_reason(session.pair_id, reason);
                    let outcome = self.close_with_operation(session, operation_id, state, end);
                    return Ok(outcome);
                }
                Inbound::Message(Body::Error { error, .. }) if error == ERROR_UNKNOWN_OPERATION => {
                    // The peer answered something of ours as stale: a race,
                    // no state change (policy class 3).
                }
                Inbound::Message(_) | Inbound::Violation => {
                    self.handle_violation(session, Some((operation_id, state)));
                    return Ok(self.classify_after_close(operation_id, state));
                }
                Inbound::Transport(TransportError::TimedOut)
                    if !matches!(state, OperationState::Committed) =>
                {
                    // Local expiry before commit cancels safely
                    // (Section 12.4).
                    let Some(next) =
                        advance_operation(state, OperationEvent::CancelSentOrRequestExpired)
                    else {
                        let outcome = self.close_with_operation(
                            session,
                            operation_id,
                            state,
                            SessionEnd::TransportLoss,
                        );
                        return Ok(outcome);
                    };
                    let _ = session.channel.send(Body::OperationCancel {
                        operation_id,
                        request_hash: hash,
                        reason: Some("expired".into()),
                    });
                    state = next;
                    self.journal_state(operation_id, state, false);
                    return Ok(OperationOutcome::Cancelled);
                }
                Inbound::Transport(_) => {
                    let outcome = self.close_with_operation(
                        session,
                        operation_id,
                        state,
                        SessionEnd::TransportLoss,
                    );
                    return Ok(outcome);
                }
                Inbound::Integrity => {
                    let outcome = self.close_with_operation(
                        session,
                        operation_id,
                        state,
                        SessionEnd::IntegrityFailure,
                    );
                    return Ok(outcome);
                }
            }
        }
    }

    /// Queries the proxy journal for an earlier operation (Section 12.6).
    ///
    /// The authenticated answer is stored as a journal annotation; it
    /// transitions nothing.
    ///
    /// # Errors
    ///
    /// Fails when the session is unusable or the answer violates the
    /// protocol.
    pub fn reconcile_status<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        operation_id: OperationId,
    ) -> Result<Option<String>, SessionError> {
        if session.state != SessionState::Healthy {
            return Err(SessionError::EngineFault);
        }
        session
            .channel
            .send(Body::OperationStatusRequest { operation_id })
            .map_err(|_| SessionError::Transport(TransportError::Failed))?;
        loop {
            match session.channel.receive() {
                Inbound::Message(Body::OperationStatus {
                    operation_id: echoed,
                    known,
                    state,
                    ..
                }) => {
                    if echoed != operation_id {
                        continue;
                    }
                    let annotation = known.then_some(state).flatten();
                    if let Ok(entry) = self.journal.get(operation_id) {
                        let mut updated = entry.clone();
                        updated.reconciled_proxy_state.clone_from(&annotation);
                        let _ = self.journal.record(updated);
                    }
                    return Ok(annotation);
                }
                Inbound::Message(Body::LivenessPing { challenge, .. }) => {
                    let last = session.channel.last_received_sequence();
                    session
                        .channel
                        .send(Body::LivenessPong {
                            challenge,
                            last_received_sequence: last,
                        })
                        .map_err(|_| SessionError::Transport(TransportError::Failed))?;
                }
                Inbound::Message(Body::SessionClose { reason, .. }) => {
                    self.apply_peer_close_reason(session.pair_id, reason);
                    finish_close(session, SessionEnd::PeerClose(reason));
                    return Err(SessionError::ClosedByPeer(reason));
                }
                Inbound::Message(_) | Inbound::Violation => {
                    self.handle_violation(session, None);
                    return Err(SessionError::EngineFault);
                }
                Inbound::Transport(error) => {
                    finish_close(session, SessionEnd::TransportLoss);
                    return Err(SessionError::Transport(error));
                }
                Inbound::Integrity => {
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

    /// Durably revokes the pairing: destroys both stored keys and leaves
    /// the record as the tombstone (Section 14.6).
    fn revoke_pairing(&mut self, pair_id: PairId, peer_initiated: bool) {
        let _ = self.store.update(pair_id, &mut |entry| {
            entry.disposition = PairingDisposition::Revoked;
            entry.peer_initiated_termination = peer_initiated;
            entry.local_private = Zeroizing::new(Vec::new());
            entry.peer_public = Vec::new();
        });
    }

    /// Applies a peer close reason's pairing effect (Sections 13.4
    /// and 14.6).
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

    /// Handles an authenticated protocol violation (policy class 4): the
    /// first violation immediately revokes the pairing, with one
    /// best-effort close notice (Section 14.6).
    fn handle_violation<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        operation: Option<(OperationId, OperationState)>,
    ) {
        let last = session.channel.last_received_sequence();
        let _ = session.channel.send(Body::SessionClose {
            reason: CloseReason::ProtocolViolation,
            last_received_sequence: last,
        });
        self.revoke_pairing(session.pair_id, false);
        let _ = operation;
        finish_close(session, SessionEnd::Violation);
    }

    /// Classifies the active operation after the session already closed.
    fn classify_after_close(
        &mut self,
        operation_id: OperationId,
        state: OperationState,
    ) -> OperationOutcome {
        if state.is_terminal() {
            return match state {
                OperationState::Denied => OperationOutcome::Denied,
                OperationState::Rejected => OperationOutcome::Rejected(None),
                OperationState::CredentialRejected => OperationOutcome::CredentialRejected,
                OperationState::Ambiguous => OperationOutcome::Ambiguous,
                _ => OperationOutcome::Cancelled,
            };
        }
        // Section 14.7: closure before commit produces cancelled; closure
        // with a committed operation produces ambiguous on the requester.
        let event = if state == OperationState::Committed {
            OperationEvent::SessionClosedPostCommit
        } else {
            OperationEvent::SessionClosedPreCommit
        };
        let classified = advance_operation(state, event).unwrap_or(OperationState::Ambiguous);
        let retry_prohibited = classified == OperationState::Ambiguous;
        self.journal_state(operation_id, classified, retry_prohibited);
        if classified == OperationState::Ambiguous {
            OperationOutcome::Ambiguous
        } else {
            OperationOutcome::Cancelled
        }
    }

    /// Consumes the proxy's close after a credential rejection.
    fn await_close_after_credential_rejection<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
    ) {
        let end = match session.channel.receive() {
            Inbound::Message(Body::SessionClose { reason, .. }) => {
                self.apply_peer_close_reason(session.pair_id, reason);
                SessionEnd::PeerClose(reason)
            }
            Inbound::Integrity => SessionEnd::IntegrityFailure,
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

/// Walks the session machine into `closed` and records the end.
fn finish_close<Transport: FrameTransport>(session: &mut Session<Transport>, end: SessionEnd) {
    let event = match end {
        SessionEnd::LocalClose => SessionEvent::UserDisconnect,
        SessionEnd::PeerClose(_) => SessionEvent::PeerCloseReceived,
        SessionEnd::TransportLoss => SessionEvent::TransportFailed,
        SessionEnd::IntegrityFailure => SessionEvent::SessionIntegrityFailed,
        SessionEnd::Violation => SessionEvent::AuthenticatedProtocolViolation,
    };
    if let Some(closing) = advance_session(session.state, event) {
        session.state = closing;
    }
    if let Some(closed) = advance_session(session.state, SessionEvent::CloseCompleteOrDeadline) {
        session.state = closed;
    }
    session.end = Some(end);
}

/// Advances one operation state through the requester projection.
fn advance_operation(from: OperationState, event: OperationEvent) -> Option<OperationState> {
    requester_transition(OPERATION_TRANSITIONS, from, event).map(|transition| transition.to)
}

/// Advances one session state through the requester projection.
fn advance_session(from: SessionState, event: SessionEvent) -> Option<SessionState> {
    requester_transition(SESSION_TRANSITIONS, from, event).map(|transition| transition.to)
}
