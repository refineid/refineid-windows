//! The requester engine: the workstation side of RAPP v26.10.29.
//!
//! The engine drives pairing, sessions, and operations through the
//! canonical protocol boundaries of `refineid_rapp`: a typed code is tried
//! across the Custodians in pairing mode by `PairingCandidates` (section
//! 4.2), the Custodian's `session.ready` is verified by
//! `SessionAuthentication`, liveness (section 8.3) runs in
//! `EstablishedSessionRuntime`, and the operations of section 8 in
//! `RequesterOperationEngine`. Nothing of an operation outlives its
//! session, so nothing of one is stored.
//!
//! The engine is blocking and synchronous: the PKCS#11 module, the key
//! storage provider's agent, the CLI, and the GUI call it from their own
//! threads. A session transport receives with [`SESSION_RECEIVE_TICK`] as
//! its deadline, so a session that hears nothing still sends its ping after
//! 5 seconds of silence and ends after 30, and an engine that follows a
//! raised [`Withdrawal`] closes each open session with `service_withdrawn`
//! within one tick (section 4.5 item 8). Each session records on its
//! pairing that it is established, so no idle-expiry check expires a
//! pairing in session (section 4.6 item 5).

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// Noise handshake completion window after `CPace` success (section 3.3).
const POST_PAKE_HANDSHAKE: Duration = Duration::from_millis(refineid_rapp::POST_PAKE_HANDSHAKE_MS);

/// Hello, confirmation, and storage window after Noise completion (section 3.3).
const POST_PAKE_CONFIRMATION: Duration =
    Duration::from_millis(refineid_rapp::POST_PAKE_CONFIRMATION_MS);

/// Uniform bytes one `CPace` scalar is drawn from (section 6.1.1).
const CPACE_SCALAR_ENTROPY_BYTES: usize = 64;

/// How long a Custodian's `CPace` step 2 may take to arrive after step 1:
/// the attempt deadline (section 3.3 item 3; section 4.2, "Trying Each
/// Custodian in Pairing Mode" item 4).
const CPACE_STEP_TWO_WAIT: Duration = Duration::from_millis(refineid_rapp::CPACE_ATTEMPT_WINDOW_MS);

/// Receive ticks within the quit bound of section 4.5 item 8: a withdrawal
/// is noticed within the first, and the rest of the bound is left for the
/// `service_withdrawn` close to be written.
const RECEIVE_TICKS_PER_QUIT_BOUND: u64 = 4;

/// The receive deadline of a session transport: how long one receive waits
/// before the session's liveness and the requester's withdrawal are looked
/// at again.
///
/// Well below the 5-second ping interval of section 8.3, so a ping goes out
/// on time, and a fraction of the quit bound of section 4.5 item 8.
pub const SESSION_RECEIVE_TICK: Duration =
    Duration::from_millis(refineid_rapp::QUIT_WITHDRAWAL_BOUND_MS / RECEIVE_TICKS_PER_QUIT_BOUND);

/// The wait of a Custodian that refused `CPace` step 1 and then served its
/// offer: it counts as busy with no wait (section 4.2, "Busy Refusal" item
/// 2).
const OFFER_AFTER_REFUSAL_WAIT_MS: u64 = 0;

/// How often a requester waiting out a Custodian's busy answer looks at
/// whether the user stopped the search.
const BUSY_WAIT_TICK: Duration = SESSION_RECEIVE_TICK;

/// How long a session handshake or the Custodian's first message may stay
/// silent: the silence that ends an established session (section 8.3).
const SESSION_SILENCE_LIMIT: Duration =
    Duration::from_millis(refineid_rapp::SESSION_SILENCE_LIMIT_MS);

/// How often an established session records its time on its pairing
/// again: one day, the least often an endpoint checks for idle expiry
/// (RAPP v26.10.29 section 4.6 item 5).
const SESSION_RECORD_INTERVAL_MS: u64 =
    refineid_rapp::PAIRING_IDLE_EXPIRY_MS / refineid_rapp::PAIRING_IDLE_EXPIRY_DAYS;

use crate::ids::{Challenge, OperationId, PairId, RandomIdExt, SessionId};
use crate::message::{CardPresence, CardStatusMessage, CloseReason, ResultError, ResultStatus};
use crate::offer::{BootstrapAnswer, OfferError, PairingBusy, PairingOffer};
use crate::operations::{CardOperation, CardOperationError, CardOperationResult};
use crate::presence::{CardSighting, SIGHTING_REFRESH_MS};
use crate::store::{
    PairingRecord, PairingState, PairingStore, StoreError, expire_revocation_notices,
    forget_pairing, revoke_pairing,
};
use crate::transport::{BinaryFrame, FrameTransport, TransportError};
use refineid_rapp::{
    ActivePairing, AuthenticatedViolation, EndpointRole, EstablishedSessionRuntime,
    ExplicitUserIntent, NextCandidate, NextEndpoint, OperationRequest, OperationViolation,
    PairRecord, PairingCandidates, PairingHandshake, PairingSecret, PairingStorage, PingChallenge,
    ProfileName, ProgressEvent, ReadyOutcome, RequesterDispatch, RequesterEngineError,
    RequesterOperationEngine, RuntimePoll, RuntimeReceive, SessionAuthentication, SessionHandshake,
    SweepError, TransportProfile, TypedMessage, generate_pair_key_material,
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

/// Why one pairing connection did not produce a stored record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingError {
    /// The offer failed its structural rules.
    Offer(OfferError),
    /// Key material could not be produced.
    KeyGeneration,
    /// The handshake failed.
    HandshakeFailed,
    /// The custodian's confirmation tag did not verify: it does not show
    /// the code typed here.
    CodeMismatch,
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
    /// The connection's transport profile is not a registered one.
    UnregisteredTransport,
    /// A post-PAKE phase passed its section 3.3 deadline.
    DeadlineExpired,
    /// The peer never confirmed that it stored the pairing (section 4.3
    /// item 4); the record stored here is gone with its keys.
    StorageUnconfirmed,
}

impl core::fmt::Display for PairingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Offer(e) => write!(f, "pairing offer error: {e}"),
            Self::KeyGeneration => f.write_str("key generation failed"),
            Self::HandshakeFailed => f.write_str("handshake failed"),
            Self::UnregisteredTransport => f.write_str("unregistered transport profile"),
            Self::DeadlineExpired => f.write_str("pairing deadline expired"),
            Self::StorageUnconfirmed => f.write_str("the phone did not confirm the pairing"),
            Self::CodeMismatch => f.write_str("the phone does not show the code"),
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

/// Why a typed code paired with no Custodian (RAPP v26.10.29 section 4.2,
/// "Trying Each Custodian in Pairing Mode").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingSearchError {
    /// The input is not a six-character pairing code (section 3.1); no
    /// Custodian was tried.
    InvalidCode,
    /// The user stopped the search.
    Stopped,
    /// No Custodian in pairing mode was tried before the search ended.
    NoneInPairingMode,
    /// Every Custodian tried refused the code (item 6); the report names
    /// none of them.
    NotAccepted,
    /// A Custodian proved it holds the code, and the ceremony with it then
    /// failed (section 3.3 item 7).
    Ceremony(PairingError),
}

impl core::fmt::Display for PairingSearchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidCode => f.write_str("not a pairing code"),
            Self::Stopped => f.write_str("pairing stopped"),
            Self::NoneInPairingMode => f.write_str("no phone in pairing mode was found"),
            Self::NotAccepted => f.write_str("the code was not accepted"),
            Self::Ceremony(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for PairingSearchError {}

/// Where a requester finds the Custodians a typed code is tried with.
///
/// A source names the endpoints it finds in pairing mode and opens a
/// pairing connection to one (RAPP v26.10.29 section 4.2, "Trying Each
/// Custodian in Pairing Mode").
pub trait PairingCandidateSource {
    /// How the source names an endpoint it found.
    type Endpoint: Clone + PartialEq;
    /// The connection a pairing runs over.
    type Transport: FrameTransport;

    /// Whether the user stopped the search.
    fn stopped(&self) -> bool {
        false
    }

    /// One discovery round: the endpoints found in pairing mode now, or
    /// `None` once the search is over.
    fn discover(&mut self) -> Option<Vec<Self::Endpoint>>;

    /// Opens a pairing connection to `endpoint`, past its `"pairing"`
    /// routing preamble, and reads its bootstrap answer (section 4.2,
    /// Bootstrap Read Flow): the offer with the open connection, or the
    /// Custodian's `pairing-busy` once the connection is closed; `None`
    /// when no connection opens or it answers nothing this requester can
    /// use.
    fn open(&mut self, endpoint: &Self::Endpoint) -> Option<PairingConnection<Self::Transport>>;

    /// Reads the bootstrap answer again on `transport` after the Custodian
    /// refused its `CPace` step 1 with [`TransportError::Refused`] (section
    /// 4.2, "Busy Refusal" item 2); `None` on a transport with no such
    /// refusal or when the read fails.
    fn bootstrap_again(&mut self, transport: &mut Self::Transport) -> Option<BootstrapAnswer> {
        let _ = transport;
        None
    }
}

/// A Custodian's bootstrap answer on a pairing connection (section 4.2,
/// Bootstrap Read Flow item 3).
#[derive(Debug)]
pub enum PairingConnection<Transport> {
    /// The Custodian can admit an attempt: the open connection and the
    /// offer it served.
    Offer(Transport, PairingOffer),
    /// The Custodian cannot admit an attempt now; the connection is closed.
    Busy(PairingBusy),
}

/// A pairing connection the caller already opened, as the one Custodian a
/// code is tried with.
#[derive(Debug)]
pub struct OpenedConnection<Transport>(Option<Transport>);

impl<Transport> OpenedConnection<Transport> {
    /// The connection `transport`, past its `"pairing"` routing preamble.
    pub const fn new(transport: Transport) -> Self {
        Self(Some(transport))
    }
}

impl<Transport: FrameTransport> PairingCandidateSource for OpenedConnection<Transport> {
    type Endpoint = ();
    type Transport = Transport;

    fn discover(&mut self) -> Option<Vec<()>> {
        self.0.is_some().then(|| vec![()])
    }

    fn open(&mut self, _endpoint: &()) -> Option<PairingConnection<Transport>> {
        read_bootstrap_answer(self.0.take()?).ok()
    }
}

/// Reads the first frame of the pairing connection `transport`: the
/// Custodian's bootstrap answer.
///
/// The answer is read for the connection's transport profile (section
/// 4.2, Bootstrap Read Flow items 2 and 3), and the connection is closed
/// after a `pairing-busy`. Development builds report a connection that
/// answers nothing usable.
///
/// # Errors
/// [`PairingError::Transport`] when no frame arrives,
/// [`PairingError::UnregisteredTransport`] for a connection of no
/// registered profile, and [`PairingError::Offer`] when the frame is
/// neither a `pairing-busy` nor an offer this connection can bind.
pub fn read_bootstrap_answer<Transport: FrameTransport>(
    mut transport: Transport,
) -> Result<PairingConnection<Transport>, PairingError> {
    crate::offer::read_bootstrap(&mut transport)
        .map(|answer| match answer {
            BootstrapAnswer::Offer(offer) => PairingConnection::Offer(transport, offer),
            BootstrapAnswer::Busy(busy) => PairingConnection::Busy(busy),
        })
        .map_err(|error| match error {
            crate::offer::BootstrapError::Transport(error) => PairingError::Transport(error),
            crate::offer::BootstrapError::UnregisteredTransport => {
                PairingError::UnregisteredTransport
            }
            crate::offer::BootstrapError::Offer(error) => PairingError::Offer(error),
        })
        .inspect_err(|error| refineid_dev_errors::report!(Rapp, "pairing offer not read", error))
}

/// Why a Custodian did not prove it holds the code.
enum CodeRefusal {
    /// The Custodian answered `pairing-busy` in place of `CPace` step 2,
    /// asking for this wait in milliseconds (section 4.2, "Busy Refusal"
    /// item 2).
    Busy(u64),
    /// The Custodian refused the `CPace` step 1 write; its bootstrap answer
    /// tells whether it was busy (section 4.2, "Busy Refusal" item 2).
    StepOneRefused,
    /// The Custodian refused the code (section 4.2, "Trying Each Custodian
    /// in Pairing Mode" item 4).
    Refused(PairingError),
}

impl From<PairingError> for CodeRefusal {
    fn from(error: PairingError) -> Self {
        Self::Refused(error)
    }
}

/// A Custodian's proof that it holds the code: its `CPace` step 2 verified,
/// with the step 3 that answers it and the key both sides derived.
struct CodeConfirmed {
    candidate_id: String,
    step_three: BinaryFrame,
    pairing_secret: PairingSecret,
}

/// Why a session could not be opened or continued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// No pairing record exists.
    UnknownPairing,
    /// The pairing is revoked; its keys are gone.
    NotPaired,
    /// The user forgot the pairing: it serves nothing, and its next session
    /// carries only the `pairing_revoked` close (section 4.6 item 2).
    Forgotten,
    /// The pairing owes no revocation notice: it was not forgotten here.
    NotForgotten,
    /// The peer never confirmed that it stored the pairing; the record
    /// opens no session (section 4.3 item 4).
    StorageUnconfirmed,
    /// The session handshake or the Custodian's first message failed
    /// authentication. Nothing stored changes (section 10.1 item 1).
    HandshakeFailed,
    /// The transport failed.
    Transport(TransportError),
    /// The Custodian's first message violated the protocol; the sealed
    /// `protocol_violation` close was delivered and the pairing stays
    /// (section 10.1 item 2).
    Violation(AuthenticatedViolation),
    /// The Custodian closed the session in place of `session.ready`. A
    /// `pairing_revoked` close has revoked the pairing here (section 4.6
    /// item 4).
    ClosedByPeer(CloseReason),
    /// The session is over.
    Ended(SessionEnd),
    /// The requester withdrew (section 4.5 item 8): it dials no session,
    /// and a session whose `session.ready` it verified as it withdrew got
    /// the `service_withdrawn` close.
    Withdrawn,
    /// A store operation failed.
    Store(StoreError),
    /// The engine encountered an internal fault.
    EngineFault,
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownPairing => f.write_str("unknown pairing"),
            Self::NotPaired => f.write_str("the pairing is revoked"),
            Self::Forgotten => f.write_str("the pairing was forgotten on this computer"),
            Self::NotForgotten => f.write_str("the pairing owes no revocation notice"),
            Self::StorageUnconfirmed => f.write_str("the phone did not confirm the pairing"),
            Self::HandshakeFailed => f.write_str("handshake failed"),
            Self::Transport(e) => write!(f, "transport error: {e:?}"),
            Self::Violation(violation) => write!(f, "protocol violation: {violation:?}"),
            Self::ClosedByPeer(reason) => write!(f, "session closed by peer: {reason:?}"),
            Self::Ended(end) => write!(f, "session ended: {end:?}"),
            Self::Withdrawn => f.write_str("this computer withdrew from remote use"),
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
    /// An operation of the session is already live (section 8.1 item 1).
    OperationActive,
    /// Identifier generation failed.
    RandomUnavailable,
    /// The typed operation violated an invariant.
    Operation(CardOperationError),
}

impl core::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SessionNotHealthy => f.write_str("session is not healthy"),
            Self::ProfileNotGranted => f.write_str("profile is not in granted set"),
            Self::OperationActive => f.write_str("an operation is already active"),
            Self::RandomUnavailable => f.write_str("cryptographic random is unavailable"),
            Self::Operation(e) => write!(f, "operation error: {e:?}"),
        }
    }
}

impl core::error::Error for AdmissionError {}

/// How an operation ended (RAPP v26.10.29 section 8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationOutcome {
    /// `operation.result` `completed`, with its typed response.
    Completed(CardOperationResult),
    /// `operation.result` `rejected`; `user_cancelled` is the holder
    /// declining on the phone.
    Rejected(ResultError),
    /// `operation.result` `cancelled`: the deadline passed before the card
    /// was commanded.
    Cancelled(ResultError),
    /// An `error` refused the request before admission (`busy`,
    /// `duplicate_operation`).
    Refused(ResultError),
    /// The session ended before a result; the operation is over with it
    /// (section 8.1 item 3). A new operation needs a new request.
    Lost,
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
    /// The peer's authenticated traffic violated the protocol; the sealed
    /// `protocol_violation` close was delivered and the pairing stays.
    Violation,
    /// Nothing arrived from the peer for the silence limit of section 8.3.
    Silence,
}

/// One live session: its transport, its liveness, and its operations.
#[allow(
    clippy::struct_field_names,
    reason = "session_id disambiguates the RAPP session identifier"
)]
pub struct Session<Transport: FrameTransport> {
    transport: Transport,
    runtime: EstablishedSessionRuntime,
    operations: RequesterOperationEngine,
    pair_id: PairId,
    session_id: SessionId,
    granted_profiles: Vec<ProfileName>,
    end: Option<SessionEnd>,
    card: Option<CardStatusMessage>,
    /// When, on the continuous clock, this session last recorded the card
    /// it hears present; `None` until it records the present status.
    sighted_at_ms: Option<u64>,
    /// When, on the continuous clock, this session last recorded on its
    /// pairing that it is established (section 4.6 item 5); `None` until
    /// the store accepted a record.
    recorded_at_ms: Option<u64>,
    /// Whether the store accepted the record of the session's end.
    end_recorded: bool,
    /// The session's place among the open sessions of the withdrawal its
    /// engine follows, held until the session ends.
    open: Option<OpenSession>,
}

impl<Transport: FrameTransport> Session<Transport> {
    /// What the custodian last said about its card on this session
    /// (`card.status`, section 8.4): `None` until it has said anything.
    #[must_use]
    pub const fn card_status(&self) -> Option<CardStatusMessage> {
        self.card
    }

    /// The pairing this session belongs to.
    #[must_use]
    pub const fn pair_id(&self) -> PairId {
        self.pair_id
    }

    /// How the session ended, once it has.
    #[must_use]
    pub const fn end(&self) -> Option<SessionEnd> {
        self.end
    }

    /// Closes the session locally and records how it ended. The live
    /// operation, if any, is over with it. Development builds report every
    /// end but a deliberate local close.
    fn finish(&mut self, end: SessionEnd) {
        if end != SessionEnd::LocalClose {
            refineid_dev_errors::report!(Rapp, "phone session closed", end);
        }
        self.runtime.close_session();
        self.operations.session_closed();
        self.end = Some(end);
        self.open = None;
    }

    /// Sends one sealed frame; a transport that fails ends the session.
    fn deliver(&mut self, frame: &BinaryFrame) -> bool {
        if self.transport.send_frame(frame.as_bytes()).is_ok() {
            return true;
        }
        self.finish(SessionEnd::TransportLoss);
        false
    }
}

impl<Transport: FrameTransport> core::fmt::Debug for Session<Transport> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("pair_id", &self.pair_id)
            .field("session_id", &self.session_id)
            .field("granted_profiles", &self.granted_profiles)
            .field("end", &self.end)
            .field("card", &self.card)
            .finish_non_exhaustive()
    }
}

/// One step of a session, as an operation or an idle caller sees it.
enum Event {
    /// Nothing for the caller: a liveness exchange, a card status, a
    /// message for no live operation, or a receive that timed out.
    Idle,
    /// The live operation's state changed.
    Progress(OperationId, ProgressEvent),
    /// The live operation ended.
    Finished(OperationId, OperationOutcome),
    /// The session is over.
    Ended,
}

/// A requester's withdrawal (RAPP v26.10.29 section 4.5 item 8), shared
/// between the engines that follow it and whatever withdraws.
///
/// The user turning remote use off, a local card doing so, or the user
/// quitting raises it, and once raised it stays raised. Suspension, sleep,
/// network loss and the operating system ending the process are not
/// withdrawal and raise nothing.
#[derive(Clone, Debug, Default)]
pub struct Withdrawal(Arc<WithdrawalShared>);

/// What the clones of one [`Withdrawal`] share.
#[derive(Debug, Default)]
struct WithdrawalShared {
    state: Mutex<WithdrawalState>,
    /// Signalled whenever an open session ends.
    session_ended: Condvar,
}

/// Whether the requester withdrew, and how many sessions of the engines
/// following it are open.
#[derive(Debug, Default)]
struct WithdrawalState {
    raised: bool,
    open_sessions: usize,
}

impl Withdrawal {
    /// A withdrawal not yet raised.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Withdraws: each open session of the engines following this closes
    /// with `service_withdrawn` at its next receive, at most one
    /// [`SESSION_RECEIVE_TICK`] away while the session is driven, and none
    /// dials after it.
    pub fn raise(&self) {
        drop(self.raised_state());
    }

    /// Withdraws, as [`Self::raise`], and waits at most `bound` for every
    /// open session to end with its close written: a requester that quits
    /// passes `QUIT_WITHDRAWAL_BOUND_MS` and exits once it returns. Returns
    /// whether every session ended within the bound.
    #[must_use]
    pub fn raise_and_wait(&self, bound: Duration) -> bool {
        let (state, waited) = self
            .0
            .session_ended
            .wait_timeout_while(self.raised_state(), bound, |state| state.open_sessions > 0)
            .unwrap_or_else(PoisonError::into_inner);
        drop(state);
        !waited.timed_out()
    }

    /// Whether the requester withdrew.
    #[must_use]
    pub fn is_raised(&self) -> bool {
        self.state().raised
    }

    /// Counts a session as open until the returned place is dropped.
    fn session_opened(&self) -> OpenSession {
        self.state().open_sessions += 1;
        OpenSession(self.clone())
    }

    /// The state, raised, still locked.
    fn raised_state(&self) -> MutexGuard<'_, WithdrawalState> {
        let mut state = self.state();
        state.raised = true;
        state
    }

    fn state(&self) -> MutexGuard<'_, WithdrawalState> {
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One open session counted by its engine's [`Withdrawal`]; dropping it
/// ends the session's count and wakes a requester waiting to quit.
#[derive(Debug)]
struct OpenSession(Withdrawal);

impl Drop for OpenSession {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.open_sessions = state.open_sessions.saturating_sub(1);
        drop(state);
        self.0.0.session_ended.notify_all();
    }
}

/// The requester engine over its durable pairing store.
#[derive(Debug)]
pub struct Requester<Store: PairingStore> {
    config: RequesterConfig,
    store: Store,
    /// The withdrawal this engine follows, if any.
    withdrawal: Option<Withdrawal>,
}

impl<Store: PairingStore> Requester<Store> {
    /// Creates an engine over its store.
    pub const fn new(config: RequesterConfig, store: Store) -> Self {
        Self {
            config,
            store,
            withdrawal: None,
        }
    }

    /// Makes the engine follow `withdrawal` (section 4.5 item 8): once it
    /// is raised, an open session gets the `service_withdrawn` close at its
    /// next receive, an operation waiting on it ends as
    /// [`OperationOutcome::Lost`], and neither a session nor a revocation
    /// notice is dialled. The pairing stays.
    #[must_use]
    pub fn following(mut self, withdrawal: Withdrawal) -> Self {
        self.withdrawal = Some(withdrawal);
        self
    }

    /// Whether the withdrawal this engine follows is raised.
    #[must_use]
    pub fn withdrawn(&self) -> bool {
        self.withdrawal.as_ref().is_some_and(Withdrawal::is_raised)
    }

    /// The pairing store, for inspection.
    pub const fn store(&self) -> &Store {
        &self.store
    }

    /// Mutable access to the pairing store.
    pub const fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    /// Pairs with the Custodian showing `code`, trying in turn each
    /// Custodian `source` finds in pairing mode (RAPP v26.10.29 sections 3,
    /// 4.2 and 6), and returns the pairing with the endpoint it was made
    /// on.
    ///
    /// One pairing connection is open at a time, each endpoint is opened
    /// once, and at most [`refineid_rapp::PAIRING_CANDIDATES_MAX`] are
    /// opened. A Custodian that answers `pairing-busy`, at bootstrap, in
    /// place of `CPace` step 2, or by refusing step 1 on BLE, is not a try:
    /// its endpoint is opened again after every other endpoint waiting and
    /// no sooner than the wait it asked for, which the search sits out
    /// quietly. The offer a connection serves is admitted before `CPace`
    /// step 1, so a Custodian found on two endpoints receives one guess. On an
    /// admitted offer the requester binds the entry for the connection's
    /// transport profile, sends `Y_A`, and verifies the Custodian's
    /// `Y_B || T_B`. A connection that serves no usable offer, closes,
    /// sends no step 2 within the attempt deadline, or whose `T_B` does not
    /// verify moves the search on. A verified `T_B` ends it: the requester
    /// answers with `T_A` and hands the `CPace` key to `Noise_XXpsk3` under
    /// the 10 s post-PAKE deadlines of section 3.3; the pairing hello,
    /// confirmation, and storage confirmation follow inside that channel,
    /// and the record is stored before its confirmation is sent (section
    /// 4.3 item 4). `confirm` sees the Custodian's introduction and returns
    /// the profiles to grant, or `None` to refuse. Development builds
    /// report each refusal and a search that ends without a pairing.
    ///
    /// # Errors
    /// [`PairingSearchError::InvalidCode`] for input that is not a pairing
    /// code, [`PairingSearchError::Stopped`] once `source` is stopped,
    /// [`PairingSearchError::NoneInPairingMode`] when the search ends with
    /// no Custodian tried, [`PairingSearchError::NotAccepted`] when every
    /// Custodian tried refused the code or one still answered busy at the
    /// connection limit, and
    /// [`PairingSearchError::Ceremony`] when the Custodian holding the code
    /// fails the handshake, a deadline, the grants, or the storage.
    pub fn pair_with_code<Source: PairingCandidateSource>(
        &mut self,
        code: &str,
        source: &mut Source,
        confirm: impl FnOnce(&PeerIntroduction, &[ProfileName]) -> Option<Vec<ProfileName>>,
    ) -> Result<(PairId, Source::Endpoint), PairingSearchError> {
        self.search_with_code(code, source, confirm)
            .inspect_err(|error| {
                if *error != PairingSearchError::Stopped {
                    refineid_dev_errors::report!(Rapp, "pairing failed", error);
                }
            })
    }

    /// [`Self::pair_with_code`], its outcome unreported.
    fn search_with_code<Source: PairingCandidateSource>(
        &mut self,
        code: &str,
        source: &mut Source,
        confirm: impl FnOnce(&PeerIntroduction, &[ProfileName]) -> Option<Vec<ProfileName>>,
    ) -> Result<(PairId, Source::Endpoint), PairingSearchError> {
        let code = crate::offer::normalize_pairing_code(code)
            .map(Zeroizing::new)
            .ok_or(PairingSearchError::InvalidCode)?;
        let mut candidates = PairingCandidates::<Source::Endpoint>::new();
        loop {
            if source.stopped() {
                return Err(PairingSearchError::Stopped);
            }
            let endpoint = match candidates.next_endpoint(current_time_ms()) {
                Ok(NextEndpoint::Open(endpoint)) => endpoint.clone(),
                Ok(NextEndpoint::NotBefore(due_ms)) => {
                    Self::sit_out_busy(source, due_ms);
                    continue;
                }
                Ok(NextEndpoint::Exhausted) | Err(_) => {
                    let found = source
                        .discover()
                        .ok_or(PairingSearchError::NoneInPairingMode)?;
                    for endpoint in found {
                        candidates.found(endpoint);
                    }
                    continue;
                }
            };
            let next = match source.open(&endpoint) {
                Some(PairingConnection::Busy(busy)) => {
                    candidates.busy(busy.retry_after_ms(), current_time_ms())
                }
                Some(PairingConnection::Offer(mut transport, offer))
                    if candidates.begin_try(&offer).is_ok() =>
                {
                    match Self::offer_code(&code, &offer, &mut transport) {
                        Ok(confirmed) => {
                            let _ = candidates.accepted();
                            return self
                                .finish_pairing(offer, &confirmed, transport, confirm)
                                .map(|pair_id| (pair_id, endpoint))
                                .map_err(PairingSearchError::Ceremony);
                        }
                        Err(CodeRefusal::Busy(retry_after_ms)) => {
                            candidates.busy(retry_after_ms, current_time_ms())
                        }
                        Err(CodeRefusal::StepOneRefused) => {
                            match source.bootstrap_again(&mut transport) {
                                Some(BootstrapAnswer::Busy(busy)) => {
                                    candidates.busy(busy.retry_after_ms(), current_time_ms())
                                }
                                Some(BootstrapAnswer::Offer(_)) => {
                                    candidates.busy(OFFER_AFTER_REFUSAL_WAIT_MS, current_time_ms())
                                }
                                None => candidates.closed(),
                            }
                        }
                        Err(CodeRefusal::Refused(error)) => {
                            refineid_dev_errors::report!(Rapp, "pairing code refused", error);
                            candidates.closed()
                        }
                    }
                }
                Some(PairingConnection::Offer(..)) | None => candidates.closed(),
            };
            if next == Ok(NextCandidate::NotAccepted) {
                return Err(PairingSearchError::NotAccepted);
            }
        }
    }

    /// Waits until the monotonic time `due_ms` a busy Custodian asked for,
    /// or until the user stops the search; nothing is shown meanwhile
    /// (section 4.2, "Trying Each Custodian in Pairing Mode" item 1).
    fn sit_out_busy<Source: PairingCandidateSource>(source: &Source, due_ms: u64) {
        loop {
            let left_ms = due_ms.saturating_sub(current_time_ms());
            if left_ms == 0 || source.stopped() {
                return;
            }
            std::thread::sleep(Duration::from_millis(left_ms).min(BUSY_WAIT_TICK));
        }
    }

    /// Runs `CPace` with `code` on `offer` up to the Custodian's proof that
    /// it holds the code: binds the offer's entry for the connection's
    /// transport profile, sends `Y_A`, and verifies the Custodian's
    /// `Y_B || T_B`, which must arrive within the attempt deadline. A
    /// `pairing-busy` in place of step 2, or a refused step 1 write, is the
    /// Custodian's busy refusal (section 4.2, "Busy Refusal" item 2).
    fn offer_code<Transport: FrameTransport>(
        code: &str,
        offer: &PairingOffer,
        transport: &mut Transport,
    ) -> Result<CodeConfirmed, CodeRefusal> {
        let profile = TransportProfile::parse(transport.profile())
            .ok_or(PairingError::UnregisteredTransport)?;
        let candidate_id = offer
            .entry(profile)
            .map(|entry| entry.candidate_id.clone())
            .ok_or(PairingError::UnregisteredTransport)?;
        let offer_hash = offer
            .offer_hash()
            .map_err(|_| PairingError::HandshakeFailed)?;
        let context =
            refineid_rapp::standard_pairing_context_v2(&offer_hash, profile.name(), &candidate_id)
                .map_err(|_| PairingError::HandshakeFailed)?;
        let mut entropy = Zeroizing::new([0u8; CPACE_SCALAR_ENTROPY_BYTES]);
        getrandom::fill(entropy.as_mut()).map_err(|_| PairingError::KeyGeneration)?;
        let (initiator, step_one) =
            refineid_rapp::CpaceKc2Initiator::new(code, &context, &offer.offer_id, &entropy)
                .map_err(|_| PairingError::HandshakeFailed)?;
        drop(entropy);

        let step_one_frame = refineid_rapp::encode_kc2_step1_frame(&step_one)
            .map_err(|_| PairingError::HandshakeFailed)?;
        transport
            .send_frame(step_one_frame.as_bytes())
            .map_err(|error| match error {
                TransportError::Refused => CodeRefusal::StepOneRefused,
                error => CodeRefusal::Refused(PairingError::Transport(error)),
            })?;
        let waited = transport
            .set_receive_deadline(CPACE_STEP_TWO_WAIT)
            .map_err(PairingError::Transport)?;
        let step_two = transport.receive_frame();
        transport
            .set_receive_deadline(waited)
            .map_err(PairingError::Transport)?;
        let step_two = step_two.map_err(PairingError::Transport)?;
        if let Ok(busy) = PairingBusy::from_cbor(&step_two) {
            return Err(CodeRefusal::Busy(busy.retry_after_ms()));
        }
        let step_two =
            BinaryFrame::reconstruct(step_two).map_err(|_| PairingError::HandshakeFailed)?;
        let (step_three, pairing_secret) =
            initiator
                .process_step2_frame(&step_two)
                .map_err(|error| match error {
                    refineid_rapp::CpaceError::ConfirmationTagMismatch => {
                        PairingError::CodeMismatch
                    }
                    _ => PairingError::HandshakeFailed,
                })?;
        Ok(CodeConfirmed {
            candidate_id,
            step_three,
            pairing_secret,
        })
    }

    /// Answers the Custodian that proved it holds the code with `T_A`, then
    /// runs the pairing to its stored record.
    fn finish_pairing<Transport: FrameTransport>(
        &mut self,
        offer: PairingOffer,
        confirmed: &CodeConfirmed,
        mut transport: Transport,
        confirm: impl FnOnce(&PeerIntroduction, &[ProfileName]) -> Option<Vec<ProfileName>>,
    ) -> Result<PairId, PairingError> {
        transport
            .send_frame(confirmed.step_three.as_bytes())
            .map_err(PairingError::Transport)?;
        self.complete_pairing(
            offer,
            &confirmed.candidate_id,
            &confirmed.pairing_secret,
            transport,
            confirm,
        )
    }

    /// Runs `Noise_XXpsk3` under the `CPace` key, then the pairing hello and
    /// confirmation, and stores the resulting record.
    #[allow(
        clippy::too_many_lines,
        reason = "pairing handshake walks 7 sequential wire messages"
    )]
    fn complete_pairing<Transport: FrameTransport>(
        &mut self,
        offer: PairingOffer,
        candidate_id: &str,
        pairing_secret: &PairingSecret,
        mut transport: Transport,
        confirm: impl FnOnce(&PeerIntroduction, &[ProfileName]) -> Option<Vec<ProfileName>>,
    ) -> Result<PairId, PairingError> {
        // The handshake refuses an offer naming an unregistered profile, so
        // every name parses once it has begun.
        let offered: Vec<ProfileName> = offer
            .profiles
            .iter()
            .filter_map(|name| ProfileName::parse(name))
            .collect();
        let handshake_deadline = Instant::now() + POST_PAKE_HANDSHAKE;
        let local_keys = generate_pair_key_material().map_err(|_| PairingError::KeyGeneration)?;
        let mut handshake = match PairingHandshake::begin(
            EndpointRole::Requester,
            offer,
            candidate_id,
            local_keys,
            pairing_secret,
        ) {
            Ok(h) => h,
            Err(fail) => {
                let (err, _offer) = fail.into_parts();
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
        if Instant::now() > handshake_deadline {
            return Err(PairingError::DeadlineExpired);
        }
        let confirmation_deadline = Instant::now() + POST_PAKE_CONFIRMATION;

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

        // The user grants the profiles from those offered; the confirmation
        // refuses an empty, repeated, or unoffered grant.
        let Some(granted_profiles) = confirm(&intro, &offered) else {
            return Err(PairingError::DeniedLocally);
        };
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

        if Instant::now() > confirmation_deadline {
            return Err(PairingError::DeadlineExpired);
        }

        // The record is stored unconfirmed, then confirmed to the peer over
        // the still-open channel; it opens nothing until the peer's
        // confirmation is recorded (section 4.3 item 4).
        let (pair_record, storage) = confirmation
            .into_storage(crate::clock::unix_time_ms())
            .map_err(|_| PairingError::Channel)?;
        self.store
            .insert(PairingRecord::new(pair_record, intro))
            .map_err(PairingError::Store)?;
        let confirmed = Self::confirm_storage(&mut transport, storage, confirmation_deadline)
            .and_then(|active| {
                let mut active = Some(active);
                let mut confirmed = Err(PairingError::StorageUnconfirmed);
                self.store
                    .update(pair_id, &mut |entry| {
                        if let Some(active) = active.take() {
                            confirmed = entry
                                .confirm_storage(active)
                                .map_err(|_| PairingError::ProtocolViolation);
                        }
                    })
                    .map_err(PairingError::Store)?;
                confirmed
            });
        if let Err(error) = confirmed {
            // A pairing the peer never confirmed does not survive here: its
            // keys go at once and nobody is told (section 4.6 item 3).
            let _ = self.store.remove(pair_id);
            return Err(error);
        }
        Ok(pair_id)
    }

    /// Sends the local storage confirmation and receives the peer's; the
    /// pairing is then active (section 4.3 item 4).
    fn confirm_storage<Transport: FrameTransport>(
        transport: &mut Transport,
        mut storage: PairingStorage,
        confirmation_deadline: Instant,
    ) -> Result<ActivePairing, PairingError> {
        // A transport that fails anywhere in this exchange left the peer's
        // confirmation unreceived; the outcome is the same whichever side
        // went first.
        let stored_frame = storage.send_stored().map_err(|_| PairingError::Channel)?;
        transport
            .send_frame(stored_frame.as_bytes())
            .map_err(|_| PairingError::StorageUnconfirmed)?;
        let peer_stored_bytes = transport
            .receive_frame()
            .map_err(|_| PairingError::StorageUnconfirmed)?;
        if Instant::now() > confirmation_deadline {
            return Err(PairingError::StorageUnconfirmed);
        }
        let peer_stored_frame =
            BinaryFrame::reconstruct(peer_stored_bytes).map_err(|_| PairingError::Channel)?;
        storage
            .receive_stored(&peer_stored_frame, current_time_ms())
            .map_err(|error| match error {
                refineid_rapp::PairingError::PairIdMismatch => PairingError::ProtocolViolation,
                _ => PairingError::Channel,
            })?;
        storage
            .into_active()
            .map_err(|_| PairingError::StorageUnconfirmed)
    }

    /// Opens a session to a paired custodian over a connected transport,
    /// already past its `"session"` routing preamble: the `Noise_KK`
    /// handshake, then the Custodian's `session.ready` (RAPP v26.10.29
    /// sections 6.3 and 7.1 item 5).
    ///
    /// A Custodian that closes in place of `session.ready` ends the attempt;
    /// a `pairing_revoked` close revokes the pairing here (section 4.6 item
    /// 4). A first message that violates the protocol gets the sealed
    /// `protocol_violation` close and the pairing stays (section 10.1).
    /// After the engine withdrew, the transport is dropped untouched; a
    /// session whose `session.ready` is verified as the engine withdraws
    /// gets the `service_withdrawn` close (section 4.5 item 8).
    ///
    /// # Errors
    /// [`SessionError`] on an unknown, revoked, forgotten, or unconfirmed
    /// pairing, a failed handshake, a transport failure, a violation, the
    /// Custodian's close, or the engine's withdrawal.
    pub fn connect<Transport: FrameTransport>(
        &mut self,
        pair_id: PairId,
        transport: Transport,
    ) -> Result<Session<Transport>, SessionError> {
        self.open_session(pair_id, transport).inspect_err(|error| {
            if *error != SessionError::Withdrawn {
                refineid_dev_errors::report!(Rapp, "phone session not opened", error);
            }
        })
    }

    /// [`Self::connect`], unreported.
    fn open_session<Transport: FrameTransport>(
        &mut self,
        pair_id: PairId,
        mut transport: Transport,
    ) -> Result<Session<Transport>, SessionError> {
        if self.withdrawn() {
            return Err(SessionError::Withdrawn);
        }
        let record = self
            .store
            .get(pair_id)
            .map_err(|_| SessionError::UnknownPairing)?;
        let keys = record
            .serving_record()
            .ok_or_else(|| match record.state() {
                PairingState::Unconfirmed => SessionError::StorageUnconfirmed,
                PairingState::Forgotten => SessionError::Forgotten,
                PairingState::Revoked { .. } | PairingState::Serving => SessionError::NotPaired,
            })?;
        let granted_profiles = keys.serving_profiles().to_vec();
        let mut authentication = Self::authenticate(keys, &mut transport)?;
        let session_id = authentication.session_id();
        let ready = receive_handshake_frame(&mut transport)?;
        match authentication.receive_ready(&ready, current_time_ms()) {
            Ok(ReadyOutcome::Verified) => {}
            Ok(ReadyOutcome::PeerClosed(reason)) => {
                self.apply_peer_close(pair_id, reason);
                return Err(SessionError::ClosedByPeer(reason));
            }
            Ok(ReadyOutcome::ViolationClosed { violation, notice }) => {
                if let Some(notice) = notice {
                    let _ = transport.send_frame(notice.as_bytes());
                }
                return Err(SessionError::Violation(violation));
            }
            Err(refineid_rapp::SessionError::IntegrityFailure) => {
                return Err(SessionError::HandshakeFailed);
            }
            Err(_) => return Err(SessionError::EngineFault),
        }
        let endpoint = authentication
            .into_established()
            .map_err(|_| SessionError::EngineFault)?;
        let mut session = Session {
            transport,
            runtime: EstablishedSessionRuntime::new(endpoint, current_time_ms()),
            operations: RequesterOperationEngine::new(),
            pair_id,
            session_id,
            granted_profiles,
            end: None,
            card: None,
            sighted_at_ms: None,
            recorded_at_ms: None,
            end_recorded: false,
            open: self.withdrawal.as_ref().map(Withdrawal::session_opened),
        };
        self.record_session(&mut session);
        if self.withdrawn() {
            self.disconnect(&mut session, CloseReason::ServiceWithdrawn);
            return Err(SessionError::Withdrawn);
        }
        Ok(session)
    }

    /// Delivers the `pairing_revoked` close of a pairing forgotten while no
    /// session was open, over a connected transport already past its
    /// `"session"` routing preamble: the `Noise_KK` handshake, then the close
    /// as the session's first and only message. The keys are destroyed once
    /// it is sent (RAPP v26.10.29 section 4.6 items 2 and 3); no card session
    /// starts. A notice past its 30 days is not sent: the keys go untold.
    /// After the engine withdrew, nothing is sent and the notice stays owed
    /// (section 4.5 item 8).
    ///
    /// # Errors
    /// [`SessionError::NotForgotten`] when the pairing owes no notice,
    /// [`SessionError::Withdrawn`] after the engine withdrew, and the
    /// handshake and transport errors of [`Self::connect`].
    pub fn deliver_revocation_notice<Transport: FrameTransport>(
        &mut self,
        pair_id: PairId,
        transport: Transport,
    ) -> Result<(), SessionError> {
        self.revocation_notice(pair_id, transport)
            .inspect_err(|error| {
                if *error != SessionError::Withdrawn {
                    refineid_dev_errors::report!(Rapp, "revocation notice not delivered", error);
                }
            })
    }

    /// [`Self::deliver_revocation_notice`], unreported.
    fn revocation_notice<Transport: FrameTransport>(
        &mut self,
        pair_id: PairId,
        mut transport: Transport,
    ) -> Result<(), SessionError> {
        if self.withdrawn() {
            return Err(SessionError::Withdrawn);
        }
        expire_revocation_notices(&mut self.store, crate::clock::unix_time_ms());
        let record = self
            .store
            .get(pair_id)
            .map_err(|_| SessionError::UnknownPairing)?;
        let keys = record
            .pair_record()
            .filter(|_| record.owes_revocation_notice())
            .ok_or(SessionError::NotForgotten)?;
        let mut authentication = Self::authenticate(keys, &mut transport)?;
        let notice = authentication
            .send_revocation_notice()
            .map_err(|_| SessionError::EngineFault)?;
        transport
            .send_frame(notice.as_bytes())
            .map_err(SessionError::Transport)?;
        revoke_pairing(&mut self.store, pair_id, false).map_err(SessionError::Store)
    }

    /// The user forgets a pairing that has no open session here (RAPP
    /// v26.10.29 section 4.6): it serves nothing from now on and keeps its
    /// keys only for the `pairing_revoked` close of its next session. One
    /// the peer never confirmed, and a revoked one, are removed.
    ///
    /// # Errors
    /// [`SessionError::UnknownPairing`] when no record exists, and
    /// [`SessionError::Store`] when the change is refused.
    pub fn forget_pairing(&mut self, pair_id: PairId) -> Result<(), SessionError> {
        forget_pairing(&mut self.store, pair_id, crate::clock::unix_time_ms()).map_err(|error| {
            match error {
                StoreError::Unknown => SessionError::UnknownPairing,
                other => SessionError::Store(other),
            }
        })
    }

    /// The user forgets the pairing of an open session (RAPP v26.10.29
    /// section 4.6 item 1): the `pairing_revoked` close goes out at once and
    /// the keys are destroyed. A close that cannot be sent leaves the
    /// pairing forgotten, for the next session to carry the close.
    ///
    /// # Errors
    /// [`SessionError::Store`] when the change is refused.
    pub fn forget_pairing_in_session<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
    ) -> Result<(), SessionError> {
        let delivered = session.end.is_none()
            && session
                .runtime
                .close_with_reason(CloseReason::PairingRevoked)
                .is_ok_and(|notice| session.transport.send_frame(notice.as_bytes()).is_ok());
        if session.end.is_none() {
            session.finish(SessionEnd::LocalClose);
        }
        if delivered {
            revoke_pairing(&mut self.store, session.pair_id, false).map_err(SessionError::Store)
        } else {
            self.forget_pairing(session.pair_id)
        }
    }

    /// Keeps an idle session alive for one receive: answers the peer's
    /// ping, sends ours after 5 seconds of silence, notes `card.status`, and
    /// ends the session after 30 seconds of silence or on the peer's close
    /// (RAPP v26.10.29 sections 8.3 and 8.4), or with the `service_withdrawn`
    /// close once the engine withdrew (section 4.5 item 8).
    ///
    /// # Errors
    /// [`SessionError::Ended`] once the session is over.
    pub fn keep_alive<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
    ) -> Result<(), SessionError> {
        self.next_event(session);
        session
            .end
            .map_or(Ok(()), |end| Err(SessionError::Ended(end)))
    }

    /// Closes a healthy session deliberately.
    pub fn disconnect<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        reason: CloseReason,
    ) {
        if session.end.is_none() {
            if let Ok(notice) = session.runtime.close_with_reason(reason) {
                let _ = session.transport.send_frame(notice.as_bytes());
            }
            session.finish(SessionEnd::LocalClose);
        }
        self.record_session(session);
    }

    /// Closes an open session with `service_withdrawn` once the engine
    /// withdrew (section 4.5 item 8); the pairing stays.
    fn close_if_withdrawn<Transport: FrameTransport>(&mut self, session: &mut Session<Transport>) {
        if self.withdrawn() {
            self.disconnect(session, CloseReason::ServiceWithdrawn);
        }
    }

    /// Runs one typed operation to its outcome.
    ///
    /// # Errors
    /// Returns [`AdmissionError`] on admission failure or profile mismatch.
    pub fn execute<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        operation: &CardOperation,
        expires_after_ms: u64,
    ) -> Result<OperationOutcome, AdmissionError> {
        self.execute_observed(session, operation, expires_after_ms, &mut |_| {})
    }

    /// Runs one typed operation to its outcome, reporting each
    /// `operation.progress` event of it to `observe`: queued behind another
    /// session's operation, the PIN prompt on the phone's screen, the
    /// wait for the card and its end (RAPP v26.10.29 section 8.2). The
    /// operation lives inside the session: it ends with its result, or with
    /// the session (section 8.1).
    ///
    /// # Errors
    /// Returns [`AdmissionError`] on admission failure or profile mismatch.
    pub fn execute_observed<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        operation: &CardOperation,
        expires_after_ms: u64,
        observe: &mut dyn FnMut(ProgressEvent),
    ) -> Result<OperationOutcome, AdmissionError> {
        let outcome = self.run_operation(session, operation, expires_after_ms, observe);
        self.record_session(session);
        match &outcome {
            Ok(OperationOutcome::Completed(_)) => {}
            Ok(ended) => {
                refineid_dev_errors::report!(Rapp, "operation ended without a result", ended);
            }
            Err(error) => refineid_dev_errors::report!(Rapp, "operation not admitted", error),
        }
        outcome
    }

    /// [`Self::execute_observed`], unreported.
    fn run_operation<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        operation: &CardOperation,
        expires_after_ms: u64,
        observe: &mut dyn FnMut(ProgressEvent),
    ) -> Result<OperationOutcome, AdmissionError> {
        self.close_if_withdrawn(session);
        if session.end.is_some() {
            return Err(AdmissionError::SessionNotHealthy);
        }
        let profile: ProfileName = operation.required_profile();
        if !session.granted_profiles.contains(&profile) {
            return Err(AdmissionError::ProfileNotGranted);
        }
        let operation_id = OperationId::random().map_err(|_| AdmissionError::RandomUnavailable)?;
        let request = OperationRequest::reconstruct(
            operation_id,
            profile,
            current_time_ms(),
            expires_after_ms,
            operation.clone(),
        )
        .map_err(AdmissionError::Operation)?;
        let message = session
            .operations
            .begin(request)
            .map_err(|error| match error {
                RequesterEngineError::LiveOperation => AdmissionError::OperationActive,
                RequesterEngineError::InvalidLocalRequest(error) => {
                    AdmissionError::Operation(error)
                }
                _ => AdmissionError::SessionNotHealthy,
            })?;
        let Ok(frame) = session.runtime.endpoint_mut().send(&message) else {
            session.finish(SessionEnd::TransportLoss);
            return Ok(OperationOutcome::Lost);
        };
        if !session.deliver(&frame) {
            return Ok(OperationOutcome::Lost);
        }
        loop {
            match self.next_event(session) {
                Event::Progress(id, event) if id == operation_id => observe(event),
                Event::Finished(id, outcome) if id == operation_id => return Ok(outcome),
                Event::Ended => return Ok(OperationOutcome::Lost),
                Event::Idle | Event::Progress(..) | Event::Finished(..) => {}
            }
        }
    }

    /// Runs the `Noise_KK` handshake of a stored record as the initiator and
    /// enters the authentication of the Custodian's first message.
    fn authenticate<Transport: FrameTransport>(
        keys: &PairRecord,
        transport: &mut Transport,
    ) -> Result<SessionAuthentication, SessionError> {
        let profile =
            TransportProfile::parse(transport.profile()).ok_or(SessionError::EngineFault)?;
        let mut handshake =
            SessionHandshake::begin_requester(keys, profile, ExplicitUserIntent::record())
                .map_err(|_| SessionError::EngineFault)?;
        let first = handshake
            .write_message()
            .map_err(|_| SessionError::EngineFault)?;
        transport
            .send_frame(first.as_bytes())
            .map_err(SessionError::Transport)?;
        let second = receive_handshake_frame(transport)?;
        handshake
            .read_message(&second)
            .map_err(|_| SessionError::HandshakeFailed)?;
        if !handshake.is_complete() {
            return Err(SessionError::EngineFault);
        }
        handshake
            .into_authentication()
            .map_err(|_| SessionError::EngineFault)
    }

    /// Applies a peer close reason's pairing effect: a `pairing_revoked`
    /// close revokes the pairing here (section 4.6 item 4), and a
    /// `service_withdrawn` close withdraws the custodian's presence (section
    /// 4.5 item 6). No other close changes the pairing.
    fn apply_peer_close(&mut self, pair_id: PairId, reason: CloseReason) {
        match reason {
            CloseReason::PairingRevoked => {
                let _ = revoke_pairing(&mut self.store, pair_id, true);
            }
            CloseReason::ServiceWithdrawn => crate::stream::mark_withdrawn(pair_id),
            CloseReason::Normal
            | CloseReason::Complete
            | CloseReason::UserDisconnect
            | CloseReason::Policy
            | CloseReason::ProtocolViolation
            | CloseReason::Shutdown
            | CloseReason::CardUnavailable => {}
        }
    }

    /// Advances the session by one receive and records the card it hears
    /// present.
    fn next_event<Transport: FrameTransport>(&mut self, session: &mut Session<Transport>) -> Event {
        let event = self.receive_event(session);
        self.record_sighting(session);
        self.record_session(session);
        event
    }

    /// Records on the session's pairing that a session to it is established
    /// (section 4.6 item 5): when the session is established, again every
    /// [`SESSION_RECORD_INTERVAL_MS`] while it lasts, and when it ends, so
    /// no idle-expiry check, in this process or another, expires a pairing
    /// in session. A refused record changes nothing and is tried again on
    /// the next event; development builds report it. A pairing removed
    /// meanwhile has nothing to record.
    fn record_session<Transport: FrameTransport>(&mut self, session: &mut Session<Transport>) {
        if session.end_recorded {
            return;
        }
        let now = current_time_ms();
        let ended = session.end.is_some();
        if !ended
            && session
                .recorded_at_ms
                .is_some_and(|at| now.saturating_sub(at) < SESSION_RECORD_INTERVAL_MS)
        {
            return;
        }
        match self
            .store
            .sweep(session.pair_id, crate::clock::unix_time_ms(), true)
        {
            Ok(_) | Err(SweepError::Store(StoreError::Unknown)) => {
                session.recorded_at_ms = Some(now);
                session.end_recorded = ended;
            }
            Err(error) => refineid_dev_errors::report!(Rapp, "session time not recorded", error),
        }
    }

    /// Records the card the session hears present in the pairing store, at
    /// once when the custodian reports it and again every
    /// [`SIGHTING_REFRESH_MS`] while it stays present, so every local
    /// consumer's offer follows the custodian's word (section 8.4 item 3).
    /// An ended session or a report of absence records nothing: the last
    /// sighting ages out over the grace. A refused write is tried again on
    /// the next event.
    fn record_sighting<Transport: FrameTransport>(&mut self, session: &mut Session<Transport>) {
        let Some(CardStatusMessage {
            card: CardPresence::Present(fingerprint),
            ..
        }) = session.card
        else {
            return;
        };
        if session.end.is_some() {
            return;
        }
        let now = current_time_ms();
        if session
            .sighted_at_ms
            .is_some_and(|at| now.saturating_sub(at) < SIGHTING_REFRESH_MS)
        {
            return;
        }
        let sighting = CardSighting::new(fingerprint, crate::clock::unix_time_ms());
        if self
            .store
            .record_card_sighting(session.pair_id, sighting)
            .is_ok()
        {
            session.sighted_at_ms = Some(now);
        }
    }

    /// Advances the session by one receive: the engine's withdrawal first,
    /// then liveness, then whatever arrived.
    fn receive_event<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
    ) -> Event {
        self.close_if_withdrawn(session);
        if session.end.is_some() {
            return Event::Ended;
        }
        let Ok(challenge) = Challenge::random() else {
            session.finish(SessionEnd::LocalClose);
            return Event::Ended;
        };
        match session.runtime.poll(
            current_time_ms(),
            PingChallenge::reconstruct(*challenge.as_bytes()),
        ) {
            Ok(RuntimePoll::NoAction) => {}
            Ok(RuntimePoll::Send(ping)) => {
                if !session.deliver(&ping) {
                    return Event::Ended;
                }
            }
            Ok(RuntimePoll::SessionClosed(_)) => {
                session.finish(SessionEnd::Silence);
                return Event::Ended;
            }
            Ok(RuntimePoll::AlreadyClosed) | Err(_) => {
                session.finish(SessionEnd::TransportLoss);
                return Event::Ended;
            }
        }
        let bytes = match session.transport.receive_frame() {
            Ok(bytes) => bytes,
            Err(TransportError::TimedOut) => return Event::Idle,
            Err(_) => {
                session.finish(SessionEnd::TransportLoss);
                return Event::Ended;
            }
        };
        let Ok(frame) = BinaryFrame::reconstruct(bytes) else {
            session.finish(SessionEnd::IntegrityFailure);
            return Event::Ended;
        };
        let message = match session.runtime.receive(&frame, current_time_ms()) {
            Ok(RuntimeReceive::Message(message)) => message,
            Ok(RuntimeReceive::Send(pong)) => {
                return if session.deliver(&pong) {
                    Event::Idle
                } else {
                    Event::Ended
                };
            }
            Ok(RuntimeReceive::LivenessConfirmed | RuntimeReceive::IgnoredStalePong) => {
                return Event::Idle;
            }
            Ok(RuntimeReceive::PeerClosed(reason)) => {
                self.apply_peer_close(session.pair_id, reason);
                session.finish(SessionEnd::PeerClose(reason));
                return Event::Ended;
            }
            Ok(RuntimeReceive::ViolationClosed { notice, .. }) => {
                return close_for_violation(session, notice);
            }
            Ok(RuntimeReceive::SessionClosed(_)) | Err(_) => {
                session.finish(SessionEnd::IntegrityFailure);
                return Event::Ended;
            }
        };
        dispatch(session, message)
    }
}

/// Hands one authenticated message to the session's operations.
fn dispatch<Transport: FrameTransport>(
    session: &mut Session<Transport>,
    message: TypedMessage,
) -> Event {
    match session.operations.receive(message) {
        Ok(RequesterDispatch::CardStatus(status)) => {
            session.card = Some(status);
            session.sighted_at_ms = None;
            Event::Idle
        }
        Ok(RequesterDispatch::Progress {
            operation_id,
            event,
        }) => Event::Progress(operation_id, event),
        Ok(RequesterDispatch::Completed {
            operation_id,
            result,
        }) => Event::Finished(operation_id, OperationOutcome::Completed(result)),
        Ok(RequesterDispatch::Ended {
            operation_id,
            status,
            error,
        }) => Event::Finished(
            operation_id,
            match status {
                ResultStatus::Cancelled => OperationOutcome::Cancelled(error),
                ResultStatus::Completed | ResultStatus::Rejected => {
                    OperationOutcome::Rejected(error)
                }
            },
        ),
        Ok(RequesterDispatch::Refused {
            operation_id,
            error,
        }) => Event::Finished(operation_id, OperationOutcome::Refused(error)),
        Err(RequesterEngineError::AuthenticatedProtocolViolation(violation)) => {
            let closed = session
                .runtime
                .close_for_operation_violation(OperationViolation::Requester(violation));
            let notice = if let RuntimeReceive::ViolationClosed { notice, .. } = closed {
                notice
            } else {
                None
            };
            close_for_violation(session, notice)
        }
        Ok(
            RequesterDispatch::PeerError(_)
            | RequesterDispatch::Ignored(_)
            | RequesterDispatch::NotOperation(_),
        )
        | Err(_) => Event::Idle,
    }
}

/// Delivers the sealed `protocol_violation` close, when there is one, and
/// ends the session; the pairing stays (section 10.1 item 2).
fn close_for_violation<Transport: FrameTransport>(
    session: &mut Session<Transport>,
    notice: Option<BinaryFrame>,
) -> Event {
    if let Some(notice) = notice {
        let _ = session.transport.send_frame(notice.as_bytes());
    }
    session.finish(SessionEnd::Violation);
    Event::Ended
}

/// Receives one handshake frame, waiting through the transport's receive
/// ticks for at most the session silence limit.
fn receive_handshake_frame<Transport: FrameTransport>(
    transport: &mut Transport,
) -> Result<BinaryFrame, SessionError> {
    let started = Instant::now();
    loop {
        match transport.receive_frame() {
            Ok(bytes) => {
                return BinaryFrame::reconstruct(bytes)
                    .map_err(|_| SessionError::Transport(TransportError::OversizedFrame));
            }
            Err(TransportError::TimedOut) if started.elapsed() < SESSION_SILENCE_LIMIT => {}
            Err(error) => return Err(SessionError::Transport(error)),
        }
    }
}

/// The continuous clock every protocol deadline is measured on (section
/// 8.1 item 2).
fn current_time_ms() -> u64 {
    crate::clock::continuous_ms()
}
