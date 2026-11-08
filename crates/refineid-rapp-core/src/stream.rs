//! The `fi.refineid.stream` transport (RAPP transport and discovery
//! hierarchy, sections 3.2 and 4).
//!
//! The custodian (the phone) listens on an ephemeral TCP port and advertises
//! `_refineid-stream._tcp.local.` under a fresh random instance name, with a
//! TXT record naming its mode: `mode=pairing` during a pairing ceremony,
//! `mode=session` while it serves stored pairings, and `mode=withdrawn`
//! briefly when it stops serving (RAPP v26.11.2 section 4.5). The requester
//! browses by those attributes, dials, and opens every connection with one
//! plaintext routing preamble. A session preamble
//! carries a fresh nonce and a tag keyed by the pairing's static agreement,
//! so no value on the wire names a pairing twice. TXT records are handed to
//! `refineid_rapp` unparsed. An anomaly closes the connection without
//! touching stored state (specification section 10.1, class 1).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::backlog::{BacklogRoute, BacklogSightings};
use crate::engine::{
    PairingCandidateSource, PairingConnection, Requester, SESSION_RECEIVE_TICK,
    TRANSPORT_LABEL_NETWORK, read_bootstrap_answer,
};
use crate::ids::PairId;
use crate::store::{PairingRecord, PairingStore, expire_revocation_notices, revoke_pairing};
use crate::transport::{FrameTransport, TcpFrameTransport, TransportError};
use crate::view;
use refineid_rapp::{
    DiscoveryKey, DiscoveryRecord, InstanceName, PairRecord, RoutingKey, SessionRouting,
    TransportProfile, WithdrawalKey, WithdrawnRecord, discovery_epoch, withdrawal_counter,
};
pub use refineid_rapp::{MAX_ROUTING_PREAMBLE_FRAME, RoutingPreamble, STREAM_PROFILE};

/// The DNS-SD service type of the stream tier.
pub const STREAM_SERVICE_TYPE: &str = "_refineid-stream._tcp.local";

/// The registered candidate identifier of the stream profile (RAPP v26.11.2
/// section 2.2).
pub const STREAM_CANDIDATE_ID: &str = refineid_rapp::STREAM_CANDIDATE_ID;

/// TXT key naming the discovery mode.
const MODE_KEY: &str = "mode";
/// TXT key naming the record format version.
const VERSION_KEY: &str = "v";
/// The one TXT format version this requester understands.
const SUPPORTED_TXT_VERSION: &str = "1";

/// The custodian discovery modes of hierarchy section 4.3 a requester
/// browses for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryMode {
    /// An explicit pairing ceremony is open on the custodian.
    Pairing,
    /// The custodian serves sessions for stored pairings.
    Session,
}

impl DiscoveryMode {
    /// The TXT `mode` value.
    #[must_use]
    pub const fn txt_value(self) -> &'static str {
        match self {
            Self::Pairing => "pairing",
            Self::Session => "session",
        }
    }
}

/// One advertised custodian: its instance, endpoints, and TXT entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamService {
    /// The advertised instance portion of the name (random; carries no
    /// identity).
    pub instance: String,
    /// `ip:port` endpoints that answered for this instance.
    pub endpoints: Vec<String>,
    /// The TXT `key=value` entries exactly as published, in order.
    pub txt: Vec<(String, String)>,
}

impl StreamService {
    fn entries(&self) -> Vec<(&str, &str)> {
        self.txt
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }

    /// Whether the record names format version 1 and `mode`; keys compare
    /// case-insensitively (RFC 6763 section 6.4).
    #[must_use]
    pub fn advertises(&self, mode: DiscoveryMode) -> bool {
        match mode {
            DiscoveryMode::Session => self.discovery_record().is_some(),
            DiscoveryMode::Pairing => {
                let value = |key: &str| {
                    let mut found = self
                        .txt
                        .iter()
                        .filter(|(name, _)| name.eq_ignore_ascii_case(key));
                    let first = found.next().map(|(_, value)| value.as_str());
                    if found.next().is_some() { None } else { first }
                };
                value(VERSION_KEY) == Some(SUPPORTED_TXT_VERSION)
                    && value(MODE_KEY) == Some(DiscoveryMode::Pairing.txt_value())
            }
        }
    }

    /// The well-formed `mode=session` record this service publishes.
    #[must_use]
    pub fn discovery_record(&self) -> Option<DiscoveryRecord> {
        DiscoveryRecord::parse(&self.entries()).ok()
    }

    /// The well-formed `mode=withdrawn` record this service publishes.
    #[must_use]
    pub fn withdrawn_record(&self) -> Option<WithdrawnRecord> {
        WithdrawnRecord::parse(&self.entries()).ok()
    }

    /// Whether this session record names `pairing` in the discovery epoch of
    /// `unix_seconds` or an adjacent one (hierarchy section 4.3).
    #[must_use]
    pub fn names_pairing(&self, pairing: &PairRecord, unix_seconds: u64) -> bool {
        let (Some(record), Ok(key)) = (self.discovery_record(), DiscoveryKey::derive(pairing))
        else {
            return false;
        };
        key.matches_record(&record, discovery_epoch(unix_seconds))
    }

    /// Whether this service announces that the custodian of `pairing`
    /// stopped serving (specification section 4.5).
    #[must_use]
    pub fn withdraws(&self, pairing: &PairRecord, unix_seconds: u64) -> bool {
        let (Some(record), Ok(instance), Ok(key)) = (
            self.withdrawn_record(),
            InstanceName::new(&self.instance),
            WithdrawalKey::derive(pairing),
        ) else {
            return false;
        };
        key.matches(&record, &instance, withdrawal_counter(unix_seconds))
    }
}

/// What a browse found for one stored pairing.
#[derive(Debug, Default)]
pub struct SessionCandidates {
    /// Session-mode services to try, those whose hints name the pairing
    /// first, then those publishing no hints.
    pub services: Vec<StreamService>,
    /// Whether a withdrawn record named the pairing.
    pub withdrawn: bool,
}

/// Sorts browsed services for one stored pairing. A service whose hints name
/// only other pairings is left out.
#[must_use]
pub fn session_candidates(
    services: Vec<StreamService>,
    pairing: &PairRecord,
    unix_seconds: u64,
) -> SessionCandidates {
    let withdrawn = services
        .iter()
        .any(|service| service.withdraws(pairing, unix_seconds));
    let (named, rest): (Vec<_>, Vec<_>) = services
        .into_iter()
        .filter(|service| service.advertises(DiscoveryMode::Session))
        .partition(|service| service.names_pairing(pairing, unix_seconds));
    let unhinted = rest.into_iter().filter(|service| {
        service
            .discovery_record()
            .is_some_and(|record| record.hints().is_empty())
    });
    SessionCandidates {
        services: named.into_iter().chain(unhinted).collect(),
        withdrawn,
    }
}

/// One accepted, preamble-classified stream connection.
#[derive(Debug)]
pub enum StreamAccept {
    /// The dialing requester asked for the active pairing offer.
    Pairing(TcpFrameTransport),
    /// The dialing requester asked for a fresh session with a stored pairing.
    Session {
        /// The routing value from the preamble. The caller matches it
        /// against non-revoked pairings and closes on no match.
        routing: SessionRouting,
        /// The connection, positioned after the preamble.
        transport: TcpFrameTransport,
    },
}

/// A custodian-side stream listener that classifies each connection by its
/// preamble. The requester never listens; mock custodians and tests do.
#[derive(Debug)]
pub struct StreamListener {
    listener: TcpListener,
    candidate_id: String,
    receive_deadline: Duration,
}

impl StreamListener {
    /// Binds the listener.
    ///
    /// # Errors
    ///
    /// Fails when the address cannot be bound.
    pub fn bind(
        address: &str,
        candidate_id: &str,
        receive_deadline: Duration,
    ) -> Result<Self, StreamError> {
        let listener = TcpListener::bind(address).map_err(|_| StreamError::Bind)?;
        Ok(Self {
            listener,
            candidate_id: candidate_id.to_owned(),
            receive_deadline,
        })
    }

    /// The bound local port, for assembling advertised endpoints.
    ///
    /// # Errors
    ///
    /// Fails when the socket cannot report its address.
    pub fn local_port(&self) -> Result<u16, StreamError> {
        self.listener
            .local_addr()
            .map(|address| address.port())
            .map_err(|_| StreamError::Bind)
    }

    /// Accepts one connection, reads exactly one bounded preamble frame,
    /// and classifies it. A connection whose preamble is invalid is closed
    /// and reported; stored state never changes here.
    ///
    /// # Errors
    ///
    /// Fails on accept failure or an invalid preamble.
    pub fn accept(&self) -> Result<StreamAccept, StreamError> {
        let (socket, _peer) = self.listener.accept().map_err(|_| StreamError::Accept)?;
        self.classify(socket)
    }

    /// Attempts to accept an incoming connection within `timeout`.
    ///
    /// Returns `Ok(None)` if no connection arrives within `timeout`.
    ///
    /// # Errors
    ///
    /// Fails on accept failure or an invalid preamble.
    pub fn accept_timeout(&self, timeout: Duration) -> Result<Option<StreamAccept>, StreamError> {
        self.listener
            .set_nonblocking(true)
            .map_err(|_| StreamError::Accept)?;
        let start = Instant::now();
        loop {
            match self.listener.accept() {
                Ok((socket, _peer)) => {
                    let _ = self.listener.set_nonblocking(false);
                    let _ = socket.set_nonblocking(false);
                    return self.classify(socket).map(Some);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() >= timeout {
                        let _ = self.listener.set_nonblocking(false);
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => {
                    let _ = self.listener.set_nonblocking(false);
                    return Err(StreamError::Accept);
                }
            }
        }
    }

    fn classify(&self, socket: TcpStream) -> Result<StreamAccept, StreamError> {
        let mut transport =
            TcpFrameTransport::new(socket, &self.candidate_id, self.receive_deadline)
                .map_err(|_| StreamError::Accept)?;
        let preamble = transport.receive_frame().map_err(StreamError::Preamble)?;
        match RoutingPreamble::decode(TransportProfile::Stream, &preamble)? {
            RoutingPreamble::Pairing => Ok(StreamAccept::Pairing(transport)),
            RoutingPreamble::Session(routing) => Ok(StreamAccept::Session { routing, transport }),
        }
    }
}

/// What a dial sends first: the pairing preamble, or a fresh session routing
/// value for one stored pairing.
#[derive(Clone, Copy, Debug)]
pub enum DialPurpose<'a> {
    /// Ask for the custodian's active pairing offer.
    Pairing,
    /// Open a session with this stored pairing.
    Session(&'a RoutingKey),
}

/// One routing preamble encoded for the transport profile of the connection
/// it opens (section 2.2.1): the first frame the requester sends.
///
/// The only constructor is [`DialPurpose::preamble`], so a value is proof
/// that its bytes are a preamble of the named profile within
/// [`MAX_ROUTING_PREAMBLE_FRAME`]. The bytes are transit: they go to the
/// connection's `send_frame` once, and nothing reads them back.
pub struct PreambleFrame {
    profile: TransportProfile,
    bytes: Vec<u8>,
}

impl PreambleFrame {
    /// The transport profile the preamble was encoded for.
    #[must_use]
    pub const fn profile(&self) -> TransportProfile {
        self.profile
    }

    /// The encoded preamble, for the connection's first `send_frame`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for PreambleFrame {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreambleFrame")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl DialPurpose<'_> {
    /// The routing preamble for this purpose on `profile` (section 2.2.1).
    /// A session preamble carries a fresh nonce on every call.
    ///
    /// # Errors
    ///
    /// Fails when no random nonce can be drawn or the preamble does not encode.
    pub fn preamble(self, profile: TransportProfile) -> Result<PreambleFrame, StreamError> {
        let preamble = match self {
            Self::Pairing => RoutingPreamble::Pairing,
            Self::Session(key) => RoutingPreamble::Session(
                key.route(profile, |bytes| {
                    getrandom::fill(bytes).map_err(|_| refineid_rapp::RandomUnavailable)
                })
                .map_err(|_| StreamError::Random)?,
            ),
        };
        let bytes = preamble.encode(profile)?;
        if bytes.len() > MAX_ROUTING_PREAMBLE_FRAME {
            return Err(StreamError::Oversized);
        }
        Ok(PreambleFrame { profile, bytes })
    }
}

/// Dials an advertised custodian and sends the routing preamble, as the
/// requester does for pairing and for every session. A session preamble is
/// built afresh for every connection attempt.
///
/// # Errors
///
/// Fails when no endpoint accepts the connection or the preamble cannot be
/// built or sent.
pub fn dial(
    endpoints: &[String],
    candidate_id: &str,
    receive_deadline: Duration,
    purpose: DialPurpose<'_>,
) -> Result<TcpFrameTransport, StreamError> {
    for endpoint in endpoints {
        let Ok(mut addresses) = endpoint.as_str().to_socket_addrs() else {
            continue;
        };
        let Some(address) = addresses.next() else {
            continue;
        };
        let Ok(socket) = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) else {
            continue;
        };
        let preamble = purpose.preamble(TransportProfile::Stream)?;
        let mut transport = TcpFrameTransport::new(socket, candidate_id, receive_deadline)
            .map_err(|_| StreamError::Accept)?;
        transport
            .send_frame(preamble.as_bytes())
            .map_err(StreamError::Preamble)?;
        return Ok(transport);
    }
    Err(StreamError::Unreachable)
}

/// Why a requester dials its custodian (RAPP v26.11.2 section 8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialCause {
    /// A local consumer asks for the card with no session open.
    ConsumerRequest,
    /// The requester keeps its session to the custodian: it dials when the
    /// custodian appears and within the redial window.
    Holding,
}

/// Dials the custodian serving the stored `pairing` with a session preamble,
/// as the requester's view of it admits (RAPP v26.11.2 section 8.3).
///
/// Endpoints in `preferred`, configured endpoints, are tried first and
/// always. Then a `browse_window` browse looks at the session-mode
/// services that may be the custodian's, those whose hints name this
/// pairing ahead of those publishing none (hierarchy section 4.3): a
/// service in sight that was not at the previous look is an appearance,
/// and a withdrawn record that verifies for the pairing withdraws it
/// (section 4.5 item 6). A withdrawn custodian is not dialed until it
/// appears again; otherwise the view admits the dial when the custodian
/// appeared, for a local consumer's request, or within the redial window.
/// A dial that reaches no service counts as failed in the view.
///
/// The connection receives with [`SESSION_RECEIVE_TICK`] as its deadline,
/// the liveness tick of the requester engine.
///
/// # Errors
/// [`StreamError::Withdrawn`] when the custodian is withdrawn and has not
/// appeared since; [`StreamError::NotDue`] when the view admits no dial
/// now; [`StreamError::Unreachable`] when no endpoint accepts the
/// connection; [`StreamError::Malformed`] when the pairing's keys are
/// unusable.
pub fn dial_session(
    pairing: &PairRecord,
    preferred: &[String],
    browse_window: Duration,
    cause: DialCause,
) -> Result<TcpFrameTransport, StreamError> {
    dialled_session(pairing, preferred, browse_window, cause).inspect_err(|error| {
        if !matches!(error, StreamError::NotDue) {
            refineid_dev_errors::report!(
                Rapp,
                "phone not dialled",
                error,
                pairing.peer_display_name().as_str(),
                TRANSPORT_LABEL_NETWORK
            );
        }
    })
}

/// [`dial_session`], unreported.
fn dialled_session(
    pairing: &PairRecord,
    preferred: &[String],
    browse_window: Duration,
    cause: DialCause,
) -> Result<TcpFrameTransport, StreamError> {
    let key = RoutingKey::derive(pairing).map_err(|_| StreamError::Malformed)?;
    let attempt = |endpoints: &[String]| {
        if endpoints.is_empty() {
            return None;
        }
        dial(
            endpoints,
            STREAM_CANDIDATE_ID,
            SESSION_RECEIVE_TICK,
            DialPurpose::Session(&key),
        )
        .ok()
    };
    if let Some(transport) = attempt(preferred) {
        return Ok(transport);
    }
    let pair_id = pairing.pair_id();
    let unix_seconds = crate::clock::unix_time_seconds();
    let found = session_candidates(browse_stream_services(browse_window), pairing, unix_seconds);
    let appeared = view::look(
        pair_id,
        found
            .services
            .iter()
            .map(|service| service.instance.clone()),
    );
    if found.withdrawn && !appeared {
        view::withdrawn_record_matched(pair_id);
    }
    if view::is_withdrawn(pair_id) {
        return Err(StreamError::Withdrawn);
    }
    let now_ms = crate::clock::continuous_ms();
    if !view::dial_admitted(pair_id, now_ms, cause == DialCause::ConsumerRequest) {
        return Err(StreamError::NotDue);
    }
    for service in &found.services {
        if let Some(transport) = attempt(&service.endpoints) {
            return Ok(transport);
        }
    }
    view::dial_failed(pair_id, crate::clock::continuous_ms());
    Err(StreamError::Unreachable)
}

/// Delivers the `pairing_revoked` close of every forgotten pairing whose
/// custodian appears in one `browse_window` browse: the requester's
/// revocation backlog (RAPP v26.11.2 section 4.6 item 6).
///
/// Pairings whose notice expired go untold first. For each pairing that
/// still owes its notice, only a `mode=session` record carrying its
/// discovery hint counts as an appearance; then at most one connection
/// opens, to the instance whose hint matched, carrying the close as its
/// first message. The keys and the record go only on the custodian's echo;
/// anything else keeps the pairing in the backlog for its next appearance.
/// A custodian that does not appear is never dialed: no dial runs on a
/// timer. The backlog runs whether remote use is on, off or suspended,
/// alongside the active pairing, and offers no identity and starts no
/// operation.
///
/// `sightings` is the process's appearance memory, kept across rounds: a
/// phone that stays listed is an appearance only once, and only a completed
/// round that misses it marks it absent. Sightings of pairings that owe no
/// notice anymore are dropped.
pub fn deliver_backlog_notices<Store: PairingStore>(
    requester: &mut Requester<Store>,
    browse_window: Duration,
    sightings: &mut BacklogSightings,
) {
    expire_revocation_notices(requester.store_mut(), crate::clock::unix_time_ms());
    for pair_id in requester.store().pair_ids() {
        if notice_resolved(requester, pair_id) {
            sightings.remove_pairing(pair_id);
        }
    }
    let owed: Vec<PairId> = requester
        .store()
        .pair_ids()
        .into_iter()
        .filter(|pair_id| {
            requester
                .store()
                .get(*pair_id)
                .is_ok_and(PairingRecord::owes_revocation_notice)
        })
        .collect();
    if owed.is_empty() {
        return;
    }
    let services = browse_stream_services(browse_window);
    let unix_seconds = crate::clock::unix_time_seconds();
    let now_continuous_ms = crate::clock::continuous_ms();
    let now_wall_ms = crate::clock::unix_time_ms();
    for pair_id in owed {
        deliver_backlog_notice(
            requester,
            pair_id,
            BacklogRound {
                services: &services,
                unix_seconds,
                now_continuous_ms,
                now_wall_ms,
                sightings,
            },
        );
    }
}

/// Tries one forgotten pairing's notice against the browsed `services`:
/// when one names the pairing and thereby appears for it, at most one
/// connection opens to the instance whose hint matched, carrying the
/// `pairing_revoked` close as its first message. Returns whether the
/// custodian appeared. Without an appearance nothing is dialed.
/// One round of the revocation backlog over the stream transport: the
/// custodians one browse found, when the round ran on each clock, and the
/// process's appearance memory, kept across rounds.
struct BacklogRound<'a> {
    /// The custodians the round's browse found.
    services: &'a [StreamService],
    /// The discovery epoch the hints are matched in, in seconds.
    unix_seconds: u64,
    /// When the round ran, in continuous-clock milliseconds.
    now_continuous_ms: u64,
    /// When the round ran, in wall-clock milliseconds since the Unix epoch.
    now_wall_ms: u64,
    /// The process's appearance memory.
    sightings: &'a mut BacklogSightings,
}

/// Tries one forgotten pairing's notice against the browsed `services`:
/// when one names the pairing and thereby appears for it, at most one
/// connection opens to the instance whose hint matched, carrying the
/// `pairing_revoked` close as its first message. Returns whether the
/// custodian appeared. Without an appearance nothing is dialed.
fn deliver_backlog_notice<Store: PairingStore>(
    requester: &mut Requester<Store>,
    pair_id: PairId,
    round: BacklogRound<'_>,
) -> bool {
    deliver_backlog_notice_with(requester, pair_id, round, &mut |endpoints, key| {
        dial(
            endpoints,
            STREAM_CANDIDATE_ID,
            SESSION_RECEIVE_TICK,
            DialPurpose::Session(key),
        )
        .ok()
    })
}

/// [`deliver_backlog_notice`], with the connection opened by `connect`.
fn deliver_backlog_notice_with<Store, Transport, Connect>(
    requester: &mut Requester<Store>,
    pair_id: PairId,
    mut round: BacklogRound<'_>,
    connect: &mut Connect,
) -> bool
where
    Store: PairingStore,
    Transport: FrameTransport,
    Connect: FnMut(&[String], &RoutingKey) -> Option<Transport>,
{
    let Some((key, endpoints)) = backlog_dial_plan(requester, pair_id, &mut round) else {
        return false;
    };
    if let Some(transport) = connect(&endpoints, &key) {
        // The engine reports a notice it could not deliver.
        let _ = requester.deliver_revocation_notice(pair_id, round.now_wall_ms, transport);
        revoke_if_notice_expired(requester, pair_id, round.now_wall_ms, round.sightings);
    }
    if notice_resolved(requester, pair_id) {
        round.sightings.remove_pairing(pair_id);
    }
    true
}

/// Whether `pair_id` owes no revocation notice anymore: gone, revoked, or
/// serving again. Its sightings are dropped with it.
fn notice_resolved<Store: PairingStore>(requester: &Requester<Store>, pair_id: PairId) -> bool {
    !requester
        .store()
        .get(pair_id)
        .is_ok_and(PairingRecord::owes_revocation_notice)
}

/// The backlog's dial for one forgotten pairing in this browse: the routing
/// key and the endpoints of the instance whose appearance this is.
///
/// Re-reads the record: a pairing gone or no longer forgotten is not
/// dialed, and one past its notice expiry is revoked untold instead.
/// Otherwise the hint-matched instances are the phone's sightings on the
/// stream route: the first appearance dials, at most one connection for
/// it, and a phone that stays in sight dials nothing until it has been
/// absent and reappears.
fn backlog_dial_plan<Store: PairingStore>(
    requester: &mut Requester<Store>,
    pair_id: PairId,
    round: &mut BacklogRound<'_>,
) -> Option<(RoutingKey, Vec<String>)> {
    if revoke_if_notice_expired(requester, pair_id, round.now_wall_ms, round.sightings) {
        return None;
    }
    // The key and the hint-matched endpoints are copied out first, so the
    // delivery below can hold the store mutably.
    let (key, named): (RoutingKey, Vec<(String, Vec<String>)>) = {
        let Ok(record) = requester.store().get(pair_id) else {
            return None;
        };
        if !record.owes_revocation_notice() {
            return None;
        }
        let keys = record.pair_record()?;
        let found = session_candidates(round.services.to_vec(), keys, round.unix_seconds);
        let named = found
            .services
            .iter()
            .filter(|service| service.names_pairing(keys, round.unix_seconds))
            .map(|service| (service.instance.clone(), service.endpoints.clone()))
            .collect();
        let Ok(key) = RoutingKey::derive(keys) else {
            return None;
        };
        (key, named)
    };
    // The round completed: every remembered sighting of this pairing that
    // it did not list is now observed absent. Every listed sighting is in
    // sight again; only an appearance dials, at most one connection for it.
    let dialable: Vec<&(String, Vec<String>)> = named
        .iter()
        .filter(|(_, endpoints)| !endpoints.is_empty())
        .collect();
    let listed: Vec<&str> = dialable
        .iter()
        .map(|(instance, _)| instance.as_str())
        .collect();
    round.sightings.round_completed(
        pair_id,
        BacklogRoute::Stream,
        &listed,
        round.now_continuous_ms,
    );
    let mut dial: Option<Vec<String>> = None;
    for (instance, endpoints) in dialable {
        if round.sightings.appearance(
            pair_id,
            BacklogRoute::Stream,
            instance,
            round.now_continuous_ms,
        ) && dial.is_none()
        {
            dial = Some(endpoints.clone());
        }
    }
    Some((key, dial?))
}

/// Revokes `pair_id` untold when its `pairing_revoked` close is owed no
/// longer at `now_wall_ms` (RAPP v26.11.2 section 4.6 item 3), and reports
/// whether it did. Anything still owed, and anything no longer stored, is
/// left alone.
fn revoke_if_notice_expired<Store: PairingStore>(
    requester: &mut Requester<Store>,
    pair_id: PairId,
    now_wall_ms: u64,
    sightings: &mut BacklogSightings,
) -> bool {
    let expired = requester.store().get(pair_id).is_ok_and(|record| {
        record
            .pair_record()
            .is_some_and(|keys| keys.revocation_notice_expired(now_wall_ms))
    });
    if expired {
        let _ = revoke_pairing(requester.store_mut(), pair_id, false, now_wall_ms);
        sightings.remove_pairing(pair_id);
    }
    expired
}

/// How long one TCP connect may take before the next endpoint is tried.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn parse_dns_name(buf: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_offset = 0;
    let mut jumps = 0;

    while offset < buf.len() {
        let len = *buf.get(offset)? as usize;
        if len == 0 {
            if !jumped {
                next_offset = offset + 1;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if jumps > 10 {
                return None;
            }
            let b2 = *buf.get(offset + 1)? as usize;
            let ptr = ((len & 0x3F) << 8) | b2;
            if !jumped {
                next_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            jumps += 1;
            continue;
        }
        offset += 1;
        let end = offset.checked_add(len)?;
        if end > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(buf.get(offset..end)?).ok()?;
        labels.push(label.to_ascii_lowercase());
        offset = end;
    }
    Some((labels.join("."), next_offset))
}

/// DNS resource-record types the browser reads (RFC 1035, RFC 2782).
const RR_TYPE_A: u16 = 1;
const RR_TYPE_PTR: u16 = 12;
const RR_TYPE_TXT: u16 = 16;
const RR_TYPE_SRV: u16 = 33;
/// DNS message header length in bytes.
const DNS_HEADER_BYTES: usize = 12;
/// Fixed bytes after a resource record's name: type, class, TTL, length.
const RR_FIXED_BYTES: usize = 10;
/// SRV rdata bytes before the target name: priority, weight, port.
const SRV_FIXED_BYTES: usize = 6;
/// Largest mDNS response the browser reads.
const MDNS_RESPONSE_BYTES: usize = 4096;
/// The mDNS IPv4 group address (RFC 6762 section 3).
const MDNS_GROUP_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// The mDNS port (RFC 6762 section 3).
const MDNS_PORT: u16 = 5353;
/// Where every browse question is sent.
const MDNS_GROUP: std::net::SocketAddrV4 =
    std::net::SocketAddrV4::new(MDNS_GROUP_ADDRESS, MDNS_PORT);
/// Poll interval while waiting for answers on each socket.
const MDNS_POLL: Duration = Duration::from_millis(125);
/// Interval at which the browse question is asked again within one window
/// (RFC 6762 section 5.2); a custodian does not answer every question.
const MDNS_REQUERY: Duration = Duration::from_secs(1);
/// The DNS class of a browse question (IN) and the unicast-response bit a
/// legacy question sets on it (RFC 6762 section 5.4).
const DNS_CLASS_IN: u16 = 0x0001;
const DNS_UNICAST_RESPONSE: u16 = 0x8000;

/// Records gathered from mDNS answers before they are joined per instance.
#[derive(Debug, Default)]
struct MdnsRecords {
    instances: Vec<String>,
    services: BTreeMap<String, (u16, String, Option<Ipv4Addr>)>,
    texts: BTreeMap<String, Vec<(String, String)>>,
    addresses: BTreeMap<String, Ipv4Addr>,
}

impl MdnsRecords {
    fn into_services(self) -> Vec<StreamService> {
        let mut found = Vec::new();
        for instance in self.instances {
            let Some((port, host, responder)) = self.services.get(&instance) else {
                continue;
            };
            let mut endpoints = Vec::new();
            if let Some(ip) = self.addresses.get(host) {
                endpoints.push(format!("{ip}:{port}"));
            }
            if let Some(ip) = responder
                && !endpoints.contains(&format!("{ip}:{port}"))
            {
                endpoints.push(format!("{ip}:{port}"));
            }
            if endpoints.is_empty() {
                continue;
            }
            let label = instance
                .strip_suffix(&format!(".{STREAM_SERVICE_TYPE}"))
                .unwrap_or(&instance)
                .to_owned();
            found.push(StreamService {
                instance: label,
                endpoints,
                txt: self.texts.get(&instance).cloned().unwrap_or_default(),
            });
        }
        found
    }
}

/// Parses one mDNS response into `records`; malformed input is ignored.
fn parse_mdns_response(data: &[u8], responder: Option<Ipv4Addr>, records: &mut MdnsRecords) {
    if data.len() < DNS_HEADER_BYTES {
        return;
    }
    let count = |index: usize| usize::from(u16::from_be_bytes([data[index], data[index + 1]]));
    let questions = count(4);
    let resources = count(6) + count(8) + count(10);
    let mut offset = DNS_HEADER_BYTES;
    for _ in 0..questions {
        let Some((_, next)) = parse_dns_name(data, offset) else {
            return;
        };
        offset = next + 4;
    }
    for _ in 0..resources {
        let Some((name, after_name)) = parse_dns_name(data, offset) else {
            return;
        };
        if after_name + RR_FIXED_BYTES > data.len() {
            return;
        }
        let rtype = u16::from_be_bytes([data[after_name], data[after_name + 1]]);
        let length = usize::from(u16::from_be_bytes([
            data[after_name + 8],
            data[after_name + 9],
        ]));
        let start = after_name + RR_FIXED_BYTES;
        let end = start + length;
        if end > data.len() {
            return;
        }
        let rdata = &data[start..end];
        match rtype {
            RR_TYPE_PTR if name == STREAM_SERVICE_TYPE => {
                if let Some((instance, _)) = parse_dns_name(data, start)
                    && !records.instances.contains(&instance)
                {
                    records.instances.push(instance);
                }
            }
            RR_TYPE_SRV if rdata.len() >= SRV_FIXED_BYTES => {
                let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                if let Some((host, _)) = parse_dns_name(data, start + SRV_FIXED_BYTES) {
                    records.services.insert(name, (port, host, responder));
                }
            }
            RR_TYPE_TXT => {
                records.texts.insert(name, parse_txt(rdata));
            }
            RR_TYPE_A if rdata.len() == 4 => {
                records
                    .addresses
                    .insert(name, Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
            }
            _ => {}
        }
        offset = end;
    }
}

/// Splits TXT rdata into its length-prefixed `key=value` strings (RFC 6763
/// section 6), unchanged and in order; a bare `key` keeps an empty value.
/// Interpreting them is left to `refineid_rapp`.
fn parse_txt(rdata: &[u8]) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < rdata.len() {
        let length = usize::from(rdata[offset]);
        let end = offset + 1 + length;
        let Some(entry) = rdata.get(offset + 1..end) else {
            break;
        };
        if let Ok(text) = core::str::from_utf8(entry)
            && !text.is_empty()
        {
            let (key, value) = text.split_once('=').unwrap_or((text, ""));
            entries.push((key.to_owned(), value.to_owned()));
        }
        offset = end;
    }
    entries
}

/// The IPv4 addresses of the interfaces a browse asks on: every interface
/// but loopback that has one, each once.
///
/// The platform's default multicast interface is not enough: on a Windows
/// host with Hyper-V, WSL or Docker Desktop the default is the virtual
/// switch, and a question sent only there never reaches the phone on
/// Wi-Fi. When no interface can be listed, the unspecified address keeps
/// the browse on the default interface.
fn browse_interfaces() -> Vec<Ipv4Addr> {
    let listed = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|interface| (interface.is_loopback(), interface.ip()));
    browse_interfaces_among(listed)
}

/// [`browse_interfaces`] over `(is_loopback, address)` pairs.
fn browse_interfaces_among(interfaces: impl Iterator<Item = (bool, IpAddr)>) -> Vec<Ipv4Addr> {
    let addresses: BTreeSet<Ipv4Addr> = interfaces
        .filter_map(|(is_loopback, address)| match address {
            IpAddr::V4(v4) if !is_loopback => Some(v4),
            IpAddr::V4(_) | IpAddr::V6(_) => None,
        })
        .collect();
    if addresses.is_empty() {
        return vec![Ipv4Addr::UNSPECIFIED];
    }
    addresses.into_iter().collect()
}

/// The sockets one browse asks on, and the interfaces it asks through.
///
/// A responder answers an ordinary question by multicast (RFC 6762 section
/// 6), which only a socket bound to the mDNS port and joined to the group
/// hears; that port is shared with the system responder. A legacy question
/// from an ephemeral port (section 6.7) asks for a unicast answer, which
/// some responders give, and which still arrives where the mDNS port cannot
/// be shared. Both questions go out through every interface in turn, and
/// the group socket is joined on each, so a phone on any of them is heard.
struct BrowseSockets {
    group: Option<std::net::UdpSocket>,
    legacy: std::net::UdpSocket,
    interfaces: Vec<Ipv4Addr>,
}

impl BrowseSockets {
    fn open() -> Option<Self> {
        let interfaces = browse_interfaces();
        let legacy = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        legacy.set_read_timeout(Some(MDNS_POLL)).ok()?;
        Some(Self {
            group: Self::group_socket(&interfaces),
            legacy,
            interfaces,
        })
    }

    /// Binds the shared mDNS port and joins the group on every interface
    /// that accepts it; `None` where the platform refuses the port or every
    /// join.
    fn group_socket(interfaces: &[Ipv4Addr]) -> Option<std::net::UdpSocket> {
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
        socket.set_reuse_address(true).ok()?;
        let port = std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
        socket.bind(&SockAddr::from(port)).ok()?;
        let joined = interfaces
            .iter()
            .filter(|interface| {
                socket
                    .join_multicast_v4(&MDNS_GROUP_ADDRESS, interface)
                    .is_ok()
            })
            .count();
        if joined == 0 {
            return None;
        }
        socket.set_read_timeout(Some(MDNS_POLL)).ok()?;
        Some(socket.into())
    }

    /// Asks the browse question on every socket through every interface;
    /// false when none went out.
    fn ask(&self) -> bool {
        let mut sent = false;
        for interface in &self.interfaces {
            if let Some(group) = &self.group {
                sent |= Self::send_through(group, *interface, &browse_query(false));
            }
            sent |= Self::send_through(&self.legacy, *interface, &browse_query(true));
        }
        sent
    }

    /// Sends `question` to the group through `interface`; false when the
    /// interface refuses multicast or the send fails.
    fn send_through(socket: &std::net::UdpSocket, interface: Ipv4Addr, question: &[u8]) -> bool {
        socket2::SockRef::from(socket)
            .set_multicast_if_v4(&interface)
            .is_ok()
            && socket.send_to(question, MDNS_GROUP).is_ok()
    }

    /// Reads one datagram from whichever socket has one within its poll.
    fn receive(&self, buffer: &mut [u8]) -> Option<(usize, std::net::SocketAddr)> {
        if let Some(group) = &self.group
            && let Ok(received) = group.recv_from(buffer)
        {
            return Some(received);
        }
        self.legacy.recv_from(buffer).ok()
    }
}

/// Browses `_refineid-stream._tcp.local.` for `timeout` and returns every
/// advertised custodian, with the TXT entries it published.
///
/// The question goes out as an ordinary multicast question and as a legacy
/// one asking for a unicast answer, so both kinds of answer are heard, and
/// it is repeated once a second within the window, because a
/// custodian does not answer every single question.
#[must_use]
pub fn browse_stream_services(timeout: Duration) -> Vec<StreamService> {
    let Some(sockets) = BrowseSockets::open() else {
        return Vec::new();
    };
    if !sockets.ask() {
        return Vec::new();
    }

    let start = Instant::now();
    let mut next_query = MDNS_REQUERY;
    let mut records = MdnsRecords::default();
    let mut buffer = [0u8; MDNS_RESPONSE_BYTES];
    while start.elapsed() < timeout {
        if start.elapsed() >= next_query {
            // A failed repeat is not fatal: the first question went out.
            sockets.ask();
            next_query += MDNS_REQUERY;
        }
        let Some((read, peer)) = sockets.receive(&mut buffer) else {
            continue;
        };
        let responder = match peer {
            std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
            std::net::SocketAddr::V6(_) => None,
        };
        parse_mdns_response(&buffer[..read], responder, &mut records);
    }
    records.into_services()
}

/// One PTR question for the stream service type, class IN, with the
/// unicast-response bit when `unicast_response` is set.
fn browse_query(unicast_response: bool) -> Vec<u8> {
    let mut query = vec![0u8; DNS_HEADER_BYTES];
    query[5] = 1;
    for label in STREAM_SERVICE_TYPE.split('.') {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the service-type labels are fixed and under 64 bytes"
        )]
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&RR_TYPE_PTR.to_be_bytes());
    let class = if unicast_response {
        DNS_CLASS_IN | DNS_UNICAST_RESPONSE
    } else {
        DNS_CLASS_IN
    };
    query.extend_from_slice(&class.to_be_bytes());
    query
}

/// Browses for custodians advertising `mode`, each with at least one
/// endpoint.
#[must_use]
pub fn browse(mode: DiscoveryMode, timeout: Duration) -> Vec<StreamService> {
    browse_stream_services(timeout)
        .into_iter()
        .filter(|service| service.advertises(mode))
        .collect()
}

/// The custodians in pairing mode on the local network.
///
/// They are browsed round by round until the search time is spent or
/// `stopped` holds, and are the endpoints a typed code is tried with (RAPP
/// v26.11.2 section 4.2, "Trying Each Custodian in Pairing Mode"). Each is
/// known by its service instance and dialed at the addresses it last
/// answered from.
pub struct PairingServices<Stopped: Fn() -> bool> {
    found: Vec<StreamService>,
    search_until: Instant,
    browse_window: Duration,
    receive_deadline: Duration,
    stopped: Stopped,
}

impl<Stopped: Fn() -> bool> PairingServices<Stopped> {
    /// Searches for `search`, browsing `browse_window` a round, and opens
    /// pairing connections whose receives wait `receive_deadline`.
    pub fn new(
        search: Duration,
        browse_window: Duration,
        receive_deadline: Duration,
        stopped: Stopped,
    ) -> Self {
        Self {
            found: Vec::new(),
            search_until: Instant::now() + search,
            browse_window,
            receive_deadline,
            stopped,
        }
    }
}

impl<Stopped: Fn() -> bool> core::fmt::Debug for PairingServices<Stopped> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PairingServices")
            .field("found", &self.found.len())
            .finish_non_exhaustive()
    }
}

impl<Stopped: Fn() -> bool> PairingCandidateSource for PairingServices<Stopped> {
    type Endpoint = String;
    type Transport = TcpFrameTransport;

    fn stopped(&self) -> bool {
        (self.stopped)()
    }

    fn discover(&mut self) -> Option<Vec<String>> {
        if Instant::now() >= self.search_until {
            return None;
        }
        let services = browse(DiscoveryMode::Pairing, self.browse_window);
        let instances = services
            .iter()
            .map(|service| service.instance.clone())
            .collect();
        for service in services {
            self.found
                .retain(|known| known.instance != service.instance);
            self.found.push(service);
        }
        Some(instances)
    }

    fn open(&mut self, instance: &String) -> Option<PairingConnection<TcpFrameTransport>> {
        let service = self
            .found
            .iter()
            .find(|service| &service.instance == instance)?;
        dial_pairing(&service.endpoints, self.receive_deadline, &self.stopped)
    }
}

/// One custodian at addresses the user named, the one endpoint a typed
/// code is tried with.
///
/// Every pairing connection to it, a reopening after a busy answer
/// included, is dialed afresh; the first may be one the caller already
/// opened.
#[derive(Debug)]
pub struct PairingAddress {
    endpoints: Vec<String>,
    receive_deadline: Duration,
    opened: Option<TcpFrameTransport>,
    found: bool,
}

impl PairingAddress {
    /// The custodian at `endpoints`, whose first pairing connection
    /// `opened` is already past its `"pairing"` routing preamble; each
    /// later one waits `receive_deadline` per receive.
    #[must_use]
    pub const fn new(
        opened: TcpFrameTransport,
        endpoints: Vec<String>,
        receive_deadline: Duration,
    ) -> Self {
        Self {
            endpoints,
            receive_deadline,
            opened: Some(opened),
            found: false,
        }
    }
}

impl PairingCandidateSource for PairingAddress {
    type Endpoint = ();
    type Transport = TcpFrameTransport;

    fn discover(&mut self) -> Option<Vec<()>> {
        (!core::mem::replace(&mut self.found, true)).then(|| vec![()])
    }

    fn open(&mut self, _endpoint: &()) -> Option<PairingConnection<TcpFrameTransport>> {
        match self.opened.take() {
            Some(transport) => read_bootstrap_answer(transport).ok(),
            None => dial_pairing(&self.endpoints, self.receive_deadline, &|| false),
        }
    }
}

/// How long a found custodian is dialed before it counts as unreachable.
///
/// A phone whose Wi-Fi sleeps between short waking windows, about every
/// thirty seconds on an Android saving power, accepts a connection only in
/// those windows; one five-second attempt misses most of them, and the
/// search does not try a custodian again once its attempt failed. Dialing
/// through a whole cycle reaches such a phone.
const PAIRING_DIAL_WINDOW: Duration = Duration::from_secs(35);

/// The pause between two attempts that found the custodian unreachable.
const PAIRING_DIAL_PAUSE: Duration = Duration::from_millis(500);

/// Dials a pairing connection to `endpoints` and reads its bootstrap
/// answer (section 4.2, Bootstrap Read Flow item 2); `None` when no
/// connection opens within [`PAIRING_DIAL_WINDOW`], the search is
/// `stopped` meanwhile, or the connection answers nothing usable.
fn dial_pairing(
    endpoints: &[String],
    receive_deadline: Duration,
    stopped: &dyn Fn() -> bool,
) -> Option<PairingConnection<TcpFrameTransport>> {
    let started = Instant::now();
    let error = loop {
        match dial(
            endpoints,
            STREAM_CANDIDATE_ID,
            receive_deadline,
            DialPurpose::Pairing,
        ) {
            Ok(transport) => return read_bootstrap_answer(transport).ok(),
            Err(StreamError::Unreachable)
                if started.elapsed() < PAIRING_DIAL_WINDOW && !stopped() =>
            {
                std::thread::sleep(PAIRING_DIAL_PAUSE);
            }
            Err(error) => break error,
        }
    };
    refineid_dev_errors::report!(Rapp, "pairing connection not opened", error);
    None
}

/// Rejected stream-profile bytes, parameters, or connection steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// The preamble or a pairing key was not as specified.
    Malformed,
    /// Preamble frame exceeded [`MAX_ROUTING_PREAMBLE_FRAME`].
    Oversized,
    /// Purpose string is not registered; the connection closes unanswered.
    UnknownPurpose,
    /// The listener address could not be bound or reported.
    Bind,
    /// A connection could not be accepted or wrapped.
    Accept,
    /// The preamble frame could not be moved.
    Preamble(TransportError),
    /// No advertised endpoint accepted the connection.
    Unreachable,
    /// The custodian announced it stopped serving this pairing, or closed
    /// with `card_unavailable`, and has not announced itself since.
    Withdrawn,
    /// The requester's view admits no dial now: no appearance, no consumer
    /// asking, and no redial window running (section 8.3).
    NotDue,
    /// The platform random source failed.
    Random,
}

impl From<refineid_rapp::PreambleError> for StreamError {
    fn from(err: refineid_rapp::PreambleError) -> Self {
        match err {
            refineid_rapp::PreambleError::Oversized => Self::Oversized,
            refineid_rapp::PreambleError::UnknownPurpose => Self::UnknownPurpose,
            refineid_rapp::PreambleError::Malformed => Self::Malformed,
        }
    }
}

impl core::fmt::Display for StreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed stream profile data"),
            Self::Oversized => write!(f, "oversized routing preamble frame"),
            Self::UnknownPurpose => write!(f, "unknown routing preamble purpose"),
            Self::Bind => write!(f, "failed to bind stream listener"),
            Self::Accept => write!(f, "failed to accept stream connection"),
            Self::Preamble(e) => write!(f, "failed to move preamble frame: {e}"),
            Self::Unreachable => write!(f, "stream endpoint unreachable"),
            Self::Withdrawn => write!(f, "the phone stopped serving this pairing"),
            Self::NotDue => write!(f, "no dial is due"),
            Self::Random => write!(f, "random source unavailable"),
        }
    }
}

impl core::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Preamble(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use super::{
        DialPurpose, DiscoveryMode, MdnsRecords, StreamAccept, StreamError, StreamListener,
        StreamService, browse_interfaces_among, dial, parse_mdns_response,
    };
    use crate::backlog::BacklogSightings;
    use crate::ids::{GrantsHash, PairId};
    use crate::store::PairingStore;
    use crate::transport::FrameTransport;
    use refineid_rapp::noise::x25519_public_key;
    use refineid_rapp::{
        DISCOVERY_HINT_EPOCH_SECONDS, DiscoveryKey, EndpointRole, InstanceName, PairRecord,
        ProfileName, RoutingKey, RoutingPreamble, SessionRouting, TransportProfile, WithdrawalKey,
        route_session, withdrawal_counter,
    };

    const DEADLINE: Duration = Duration::from_secs(2);
    const CANDIDATE: &str = "stream-test";
    const STREAM_CANDIDATE: &str = super::STREAM_CANDIDATE_ID;

    /// Synthetic keys of `rapp-routing-v26.11.2.json` (`pair_keys`).
    const PAIR_ID: [u8; 16] = [0x33; 16];
    const CUSTODIAN_PRIVATE: [u8; 32] = [0x11; 32];
    const REQUESTER_PRIVATE: [u8; 32] = [0x22; 32];
    /// `routing_tag[rapp-stream]` of the same corpus.
    const STREAM_NONCE: [u8; 16] = [0x44; 16];
    const STREAM_TAG_HEX: &str = "a09a6add3714bee03f06d252451d620c";
    /// `discovery_hint[epoch-1990560]` of the same corpus.
    const HINT_EPOCH: u64 = 1_990_560;
    const HINT_AT_EPOCH_HEX: &str = "731f265bc8f6bce5";

    fn pair_record(role: EndpointRole, local: [u8; 32], remote: [u8; 32]) -> PairRecord {
        PairRecord::new(
            PairId::from_array(PAIR_ID),
            role,
            local,
            x25519_public_key(&local),
            x25519_public_key(&remote),
            GrantsHash::from_array([0x55; 32]),
            vec![ProfileName::parse(crate::profiles::PROFILE_AUTHENTICATION).unwrap()],
            refineid_rapp::DisplayName::parse("Phone".to_owned()).unwrap(),
            0,
        )
        .unwrap()
    }

    fn requester() -> PairRecord {
        pair_record(
            EndpointRole::Requester,
            REQUESTER_PRIVATE,
            CUSTODIAN_PRIVATE,
        )
    }

    fn custodian() -> PairRecord {
        pair_record(EndpointRole::Proxy, CUSTODIAN_PRIVATE, REQUESTER_PRIVATE)
    }

    fn stranger() -> PairRecord {
        pair_record(EndpointRole::Requester, [0x66; 32], CUSTODIAN_PRIVATE)
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    fn service(instance: &str, txt: &[(&str, &str)]) -> StreamService {
        StreamService {
            instance: instance.to_owned(),
            endpoints: vec![format!("{instance}:1")],
            txt: txt
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    fn session(instance: &str, hints: Option<&str>) -> StreamService {
        let mut txt = vec![("v", "1"), ("mode", "session")];
        if let Some(hints) = hints {
            txt.push(("hints", hints));
        }
        service(instance, &txt)
    }

    #[test]
    fn the_requester_derives_the_corpus_routing_tag() {
        let key = RoutingKey::derive(&requester()).unwrap();
        assert_eq!(
            hex(&key.tag(TransportProfile::Stream, &STREAM_NONCE)),
            STREAM_TAG_HEX
        );
    }

    #[test]
    fn a_hint_names_its_pairing_in_adjacent_epochs() {
        let now = HINT_EPOCH * DISCOVERY_HINT_EPOCH_SECONDS;
        let named = session("a", Some(HINT_AT_EPOCH_HEX));
        assert!(named.names_pairing(&requester(), now));
        assert!(named.names_pairing(&requester(), now + DISCOVERY_HINT_EPOCH_SECONDS));
        assert!(!named.names_pairing(&requester(), now + 2 * DISCOVERY_HINT_EPOCH_SECONDS));
        assert!(!named.names_pairing(&stranger(), now));
    }

    #[test]
    fn hint_values_must_be_lowercase_but_keys_may_be_any_case() {
        let now = HINT_EPOCH * DISCOVERY_HINT_EPOCH_SECONDS;
        let upper_value = session("a", Some(&HINT_AT_EPOCH_HEX.to_uppercase()));
        assert!(!upper_value.names_pairing(&requester(), now));
        let upper_keys = service(
            "a",
            &[
                ("V", "1"),
                ("Mode", "session"),
                ("HINTS", HINT_AT_EPOCH_HEX),
            ],
        );
        assert!(upper_keys.names_pairing(&requester(), now));
    }

    #[test]
    fn session_candidates_put_named_services_first_and_drop_foreign_ones() {
        let now = HINT_EPOCH * DISCOVERY_HINT_EPOCH_SECONDS;
        let foreign = hex(&DiscoveryKey::derive(&stranger()).unwrap().hint(HINT_EPOCH));
        let services = vec![
            session("silent", None),
            session("foreign", Some(&foreign)),
            service("pairing", &[("v", "1"), ("mode", "pairing")]),
            session("named", Some(HINT_AT_EPOCH_HEX)),
        ];
        let found = super::session_candidates(services, &requester(), now);
        let ordered: Vec<String> = found
            .services
            .into_iter()
            .map(|service| service.instance)
            .collect();
        assert_eq!(ordered, ["named", "silent"]);
        assert!(!found.withdrawn);
    }

    fn withdrawn(instance: &str, pairing: &PairRecord, now: u64) -> StreamService {
        let hint = WithdrawalKey::derive(pairing).unwrap().hint(
            &InstanceName::new(instance).unwrap(),
            withdrawal_counter(now),
        );
        let mut entries = vec![hex(&hint)];
        entries.extend((0_u8..7).map(|filler| hex(&[filler; 8])));
        let list = entries.join(",");
        service(
            instance,
            &[("v", "1"), ("mode", "withdrawn"), ("withdrawn", &list)],
        )
    }

    #[test]
    fn a_withdrawn_record_names_only_its_own_pairing() {
        let now = 1_791_504_899;
        let record = withdrawn("refineid-7f2a1c84", &custodian(), now);
        assert!(record.withdraws(&requester(), now));
        assert!(!record.withdraws(&stranger(), now));
        assert!(!record.withdraws(&requester(), now + 180));
        let renamed = StreamService {
            instance: "refineid-0b9e44d1".to_owned(),
            ..record.clone()
        };
        assert!(!renamed.withdraws(&requester(), now));
        let found = super::session_candidates(vec![record], &requester(), now);
        assert!(found.withdrawn);
        assert!(found.services.is_empty());
    }

    /// A forgotten pairing of its own for the backlog tests. Each test keeps
    /// its own appearance memory, so tests share nothing. Its keys are the
    /// corpus keys, so the corpus discovery hint names it.
    fn backlog_pair_record(tag: u8) -> PairRecord {
        PairRecord::new(
            PairId::from_array([tag; 16]),
            EndpointRole::Requester,
            REQUESTER_PRIVATE,
            x25519_public_key(&REQUESTER_PRIVATE),
            x25519_public_key(&CUSTODIAN_PRIVATE),
            GrantsHash::from_array([0x55; 32]),
            vec![ProfileName::parse(crate::profiles::PROFILE_AUTHENTICATION).unwrap()],
            refineid_rapp::DisplayName::parse("Phone".to_owned()).unwrap(),
            0,
        )
        .unwrap()
    }

    /// The custodian side's record of the backlog fixture: the same pair
    /// with the roles mirrored, as the phone that hears the close holds it.
    fn backlog_proxy_record(tag: u8) -> PairRecord {
        PairRecord::new(
            PairId::from_array([tag; 16]),
            EndpointRole::Proxy,
            CUSTODIAN_PRIVATE,
            x25519_public_key(&CUSTODIAN_PRIVATE),
            x25519_public_key(&REQUESTER_PRIVATE),
            GrantsHash::from_array([0x55; 32]),
            vec![ProfileName::parse(crate::profiles::PROFILE_AUTHENTICATION).unwrap()],
            refineid_rapp::DisplayName::parse("Phone".to_owned()).unwrap(),
            0,
        )
        .unwrap()
    }

    /// A requester holding `keys` forgotten: the revocation backlog of one.
    /// A session is recorded for the pairing now, so the notice is owed and
    /// not expired.
    fn backlog_requester(
        keys: PairRecord,
    ) -> crate::engine::Requester<crate::store::MemoryPairingStore> {
        let pair_id = keys.pair_id();
        let mut store = crate::store::MemoryPairingStore::new();
        store
            .insert(crate::store::PairingRecord::new(keys, "iOS".to_owned()))
            .unwrap();
        store
            .sweep(pair_id, crate::clock::unix_time_ms(), true)
            .unwrap();
        let mut requester = crate::engine::Requester::new(
            crate::engine::RequesterConfig {
                display_name: refineid_rapp::DisplayName::parse(
                    "Windows - EXAMPLE-HOST".to_owned(),
                )
                .unwrap(),
                platform: "Windows".to_owned(),
            },
            store,
        );
        requester.forget_pairing(pair_id).unwrap();
        requester
    }

    /// The pairing's own hint at a fixed epoch, as its custodian would
    /// announce it.
    fn backlog_hint(tag: u8) -> String {
        use refineid_rapp::DiscoveryKey;
        hex(&DiscoveryKey::derive(&backlog_pair_record(tag))
            .unwrap()
            .hint(HINT_EPOCH))
    }

    /// The hint epoch the backlog fixtures announce in, in seconds.
    fn backlog_epoch_seconds() -> u64 {
        HINT_EPOCH * DISCOVERY_HINT_EPOCH_SECONDS
    }

    /// One backlog round of the tests: the `services` a browse found at
    /// `now_ms` on the continuous clock, matched in the hint epoch, with
    /// the test's appearance memory.
    fn round<'a>(
        services: &'a [StreamService],
        now_ms: u64,
        wall_ms: u64,
        sightings: &'a mut BacklogSightings,
    ) -> super::BacklogRound<'a> {
        super::BacklogRound {
            services,
            unix_seconds: backlog_epoch_seconds(),
            now_continuous_ms: now_ms,
            now_wall_ms: wall_ms,
            sightings,
        }
    }

    /// A moment on the continuous clock; sightings of these tests start
    /// here.
    const SIGHTED_MS: u64 = 10_000_000;
    /// The loss hold: thirty seconds of absence ends a sighting.
    const LOSS_HOLD_MS: u64 = 30_000;
    /// One day in milliseconds.
    const DAY_MS: u64 = 86_400_000;
    /// Days after the latest session the expired-notice test counts: past
    /// the pairing's thirty-day idle expiry.
    const PAST_EXPIRY_DAYS: u64 = 31;
    /// The `session.ready` nonce the scripted custodian sends.
    const READY_NONCE: [u8; 32] = [0x41; 32];

    /// The scripted custodian side of a revocation delivery over `transport`:
    /// the handshake as responder, then the requester's close received and
    /// echoed. Returns the close's reason.
    fn echo_revocation_close(
        mut transport: super::super::transport::MemoryTransport,
        proxy_keys: &PairRecord,
    ) -> refineid_rapp::CloseReason {
        use refineid_rapp::{BinaryFrame, SessionHandshake, TransportProfile};
        let mut handshake =
            SessionHandshake::begin_proxy(proxy_keys, TransportProfile::Stream).unwrap();
        let first = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
        handshake.read_message(&first).unwrap();
        let second = handshake.write_message().unwrap();
        transport.send_frame(second.as_bytes()).unwrap();
        let mut authentication = handshake.into_authentication().unwrap();
        let ready = authentication
            .send_ready(
                READY_NONCE,
                &refineid_rapp::DisplayName::parse("Phone".to_owned()).unwrap(),
            )
            .unwrap();
        transport.send_frame(ready.as_bytes()).unwrap();
        let mut endpoint = authentication.into_established().unwrap();
        loop {
            let bytes = transport.receive_frame().unwrap();
            let frame = BinaryFrame::reconstruct(bytes).unwrap();
            if let refineid_rapp::ReceiveOutcome::PeerClosed { reason, echo } = endpoint
                .receive(&frame, crate::clock::unix_time_ms())
                .unwrap()
            {
                transport.send_frame(echo.unwrap().as_bytes()).unwrap();
                return reason;
            }
        }
    }

    #[test]
    fn a_backlog_notice_dials_only_on_appearance() {
        use crate::store::PairingRecord;

        let keys = backlog_pair_record(0x39);
        let pair_id = keys.pair_id();
        let mut requester = backlog_requester(keys);
        let mut sightings = BacklogSightings::new();
        let hint = backlog_hint(0x39);
        let wall_ms = crate::clock::unix_time_ms();
        let services = [session("backlog-instance", Some(hint.as_str()))];
        let dials = core::cell::Cell::new(0);
        let mut refused = |_endpoints: &[String], _key: &RoutingKey| {
            dials.set(dials.get() + 1);
            None::<super::super::transport::MemoryTransport>
        };
        // Nothing in sight dials nothing; the notice stays owed.
        assert!(!super::deliver_backlog_notice_with(
            &mut requester,
            pair_id,
            round(&[], SIGHTED_MS, wall_ms, &mut sightings),
            &mut refused,
        ));
        assert_eq!(dials.get(), 0);
        assert!(
            requester
                .store()
                .get(pair_id)
                .is_ok_and(PairingRecord::owes_revocation_notice)
        );
        // The custodian appears: a session record carrying the pairing's
        // hint under a fresh instance. The connection fails to open here;
        // the appearance alone is what is tried.
        assert!(super::deliver_backlog_notice_with(
            &mut requester,
            pair_id,
            round(&services, SIGHTED_MS, wall_ms, &mut sightings),
            &mut refused,
        ));
        assert_eq!(dials.get(), 1);
        assert!(
            requester
                .store()
                .get(pair_id)
                .is_ok_and(PairingRecord::owes_revocation_notice)
        );
        // Still listed across a round a minute later is no new appearance:
        // elapsed time alone is never absence, so nothing dials again.
        assert!(!super::deliver_backlog_notice_with(
            &mut requester,
            pair_id,
            round(&services, SIGHTED_MS + 60_000, wall_ms, &mut sightings),
            &mut refused,
        ));
        assert_eq!(dials.get(), 1);
        assert!(
            requester
                .store()
                .get(pair_id)
                .is_ok_and(PairingRecord::owes_revocation_notice)
        );
    }

    #[test]
    fn a_backlog_notice_dials_again_only_after_observed_absence_for_the_loss_hold() {
        use crate::store::PairingRecord;

        let keys = backlog_pair_record(0x3A);
        let pair_id = keys.pair_id();
        let mut requester = backlog_requester(keys);
        let mut sightings = BacklogSightings::new();
        let hint = backlog_hint(0x3A);
        let wall_ms = crate::clock::unix_time_ms();
        let services = [session("backlog-instance", Some(hint.as_str()))];
        let dials = core::cell::Cell::new(0);
        let mut refused = |_endpoints: &[String], _key: &RoutingKey| {
            dials.set(dials.get() + 1);
            None::<super::super::transport::MemoryTransport>
        };
        assert!(super::deliver_backlog_notice_with(
            &mut requester,
            pair_id,
            round(&services, SIGHTED_MS, wall_ms, &mut sightings),
            &mut refused,
        ));
        assert_eq!(dials.get(), 1);
        // Still listed is no new appearance: nothing dials again.
        assert!(!super::deliver_backlog_notice_with(
            &mut requester,
            pair_id,
            round(&services, SIGHTED_MS + 1, wall_ms, &mut sightings),
            &mut refused,
        ));
        assert_eq!(dials.get(), 1);
        // One completed round misses the phone: its absence starts here.
        assert!(!super::deliver_backlog_notice_with(
            &mut requester,
            pair_id,
            round(&[], SIGHTED_MS + 2, wall_ms, &mut sightings),
            &mut refused,
        ));
        assert_eq!(dials.get(), 1);
        // Back 10 seconds after the missed round, within the hold: no new
        // appearance.
        assert!(!super::deliver_backlog_notice_with(
            &mut requester,
            pair_id,
            round(&services, SIGHTED_MS + 2 + 10_000, wall_ms, &mut sightings),
            &mut refused,
        ));
        assert_eq!(dials.get(), 1);
        // Missed again, and back 31 seconds after that absence: an
        // appearance, dialed again.
        assert!(!super::deliver_backlog_notice_with(
            &mut requester,
            pair_id,
            round(&[], SIGHTED_MS + 3 + 10_000, wall_ms, &mut sightings),
            &mut refused,
        ));
        assert_eq!(dials.get(), 1);
        assert!(super::deliver_backlog_notice_with(
            &mut requester,
            pair_id,
            round(
                &services,
                SIGHTED_MS + 3 + 10_000 + LOSS_HOLD_MS + 1_000,
                wall_ms,
                &mut sightings
            ),
            &mut refused,
        ));
        assert_eq!(dials.get(), 2);
        assert!(
            requester
                .store()
                .get(pair_id)
                .is_ok_and(PairingRecord::owes_revocation_notice)
        );
    }

    #[test]
    fn an_expired_backlog_notice_is_revoked_untold_without_a_dial() {
        use crate::store::PairingState;

        // The pairing's latest session is past its idle expiry: thirty days
        // after that session, counted from the session and not the forget.
        let pair_id = backlog_pair_record(0x3B).pair_id();
        let wall_ms = crate::clock::unix_time_ms();
        let session_ms = wall_ms - PAST_EXPIRY_DAYS * DAY_MS;
        let mut store = crate::store::MemoryPairingStore::new();
        store
            .insert(crate::store::PairingRecord::new(
                backlog_pair_record(0x3B),
                "iOS".to_owned(),
            ))
            .unwrap();
        store.sweep(pair_id, session_ms, true).unwrap();
        let mut requester = crate::engine::Requester::new(
            crate::engine::RequesterConfig {
                display_name: refineid_rapp::DisplayName::parse(
                    "Windows - EXAMPLE-HOST".to_owned(),
                )
                .unwrap(),
                platform: "Windows".to_owned(),
            },
            store,
        );
        requester.forget_pairing(pair_id).unwrap();
        let hint = backlog_hint(0x3B);
        let services = [session("backlog-instance", Some(hint.as_str()))];
        let dials = core::cell::Cell::new(0);
        let mut refused = |_endpoints: &[String], _key: &RoutingKey| {
            dials.set(dials.get() + 1);
            None::<super::super::transport::MemoryTransport>
        };
        // The appearance dials nothing; the pairing goes untold.
        let mut sightings = BacklogSightings::new();
        assert!(!super::deliver_backlog_notice_with(
            &mut requester,
            pair_id,
            round(&services, SIGHTED_MS, wall_ms, &mut sightings),
            &mut refused,
        ));
        assert_eq!(dials.get(), 0);
        let record = requester.store().get(pair_id).unwrap();
        assert_eq!(record.state(), PairingState::Revoked { by_peer: false });
        assert!(record.pair_record().is_none());
        assert!(!record.owes_revocation_notice());
    }

    #[test]
    fn a_backlog_dial_carries_the_close_and_destroys_the_pairing_on_the_echo() {
        use crate::store::PairingState;
        use crate::transport::MemoryTransport;

        let keys = backlog_pair_record(0x3C);
        let pair_id = keys.pair_id();
        let mut requester = backlog_requester(keys);
        let hint = backlog_hint(0x3C);
        let wall_ms = crate::clock::unix_time_ms();
        let services = [session("backlog-instance", Some(hint.as_str()))];
        let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
        let proxy_keys = backlog_proxy_record(0x3C);
        let proxy = std::thread::spawn(move || echo_revocation_close(proxy_transport, &proxy_keys));
        let mut transport = Some(requester_transport);
        let mut dials = 0;
        let mut connect = |_endpoints: &[String], _key: &RoutingKey| {
            dials += 1;
            transport.take()
        };
        let mut sightings = BacklogSightings::new();
        assert!(super::deliver_backlog_notice_with(
            &mut requester,
            pair_id,
            round(&services, SIGHTED_MS, wall_ms, &mut sightings),
            &mut connect,
        ));
        assert_eq!(dials, 1);
        assert_eq!(
            proxy.join().unwrap(),
            refineid_rapp::CloseReason::PairingRevoked
        );
        let record = requester.store().get(pair_id).unwrap();
        assert_eq!(record.state(), PairingState::Revoked { by_peer: false });
        assert!(record.pair_record().is_none());
    }

    #[test]
    fn a_withdrawn_pairing_still_dials_its_configured_endpoint() {
        let pairing = pair_record(EndpointRole::Requester, [0x88; 32], CUSTODIAN_PRIVATE);
        crate::view::withdrawn_record_matched(pairing.pair_id());
        let listener = StreamListener::bind("127.0.0.1:0", STREAM_CANDIDATE, DEADLINE).unwrap();
        let endpoint = format!("127.0.0.1:{}", listener.local_port().unwrap());
        let accepter = std::thread::spawn(move || listener.accept().map(|_| ()));
        let dialed = super::dial_session(
            &pairing,
            &[endpoint],
            Duration::ZERO,
            super::DialCause::Holding,
        );
        assert!(dialed.is_ok());
        accepter.join().unwrap().unwrap();
        assert!(crate::view::is_withdrawn(pairing.pair_id()));
        crate::view::pairing_left(pairing.pair_id());
    }

    #[test]
    fn bare_txt_keys_reach_the_record_parser() {
        assert_eq!(
            super::parse_txt(b"\x03v=1\x0cmode=session\x05debug"),
            [
                ("v".to_owned(), "1".to_owned()),
                ("mode".to_owned(), "session".to_owned()),
                ("debug".to_owned(), String::new()),
            ]
        );
        let flagged = service("a", &[("v", "1"), ("mode", "session"), ("debug", "")]);
        assert!(flagged.discovery_record().is_none());
    }

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn record(owner: &[&str], rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut out = name(owner);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&120u32.to_be_bytes());
        out.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    /// A response like a custodian's: PTR, SRV, TXT, and A records.
    fn response(instance: &str, txt: &[&str]) -> Vec<u8> {
        let service = ["_refineid-stream", "_tcp", "local"];
        let full = [instance, "_refineid-stream", "_tcp", "local"];
        let host = ["refineid-b3d90e15", "local"];
        let mut srv = vec![0, 0, 0, 0];
        srv.extend_from_slice(&47110u16.to_be_bytes());
        srv.extend_from_slice(&name(&host));
        let mut txt_rdata = Vec::new();
        for entry in txt {
            txt_rdata.push(u8::try_from(entry.len()).unwrap());
            txt_rdata.extend_from_slice(entry.as_bytes());
        }
        let mut packet = vec![0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0];
        packet.extend(record(&service, super::RR_TYPE_PTR, &name(&full)));
        packet.extend(record(&full, super::RR_TYPE_SRV, &srv));
        packet.extend(record(&full, super::RR_TYPE_TXT, &txt_rdata));
        packet.extend(record(&host, super::RR_TYPE_A, &[192, 0, 2, 10]));
        packet
    }

    #[test]
    fn a_browse_asks_through_every_ipv4_interface_but_loopback() {
        let listed = [
            (true, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            (false, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 215))),
            (false, IpAddr::V4(Ipv4Addr::new(172, 20, 144, 1))),
            (false, IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            (false, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 215))),
        ];
        assert_eq!(
            browse_interfaces_among(listed.into_iter()),
            vec![Ipv4Addr::new(10, 0, 0, 215), Ipv4Addr::new(172, 20, 144, 1)]
        );
    }

    #[test]
    fn a_browse_without_a_listed_interface_keeps_the_default_one() {
        assert_eq!(
            browse_interfaces_among(std::iter::empty()),
            vec![Ipv4Addr::UNSPECIFIED]
        );
        assert_eq!(
            browse_interfaces_among([(true, IpAddr::V4(Ipv4Addr::LOCALHOST))].into_iter()),
            vec![Ipv4Addr::UNSPECIFIED]
        );
    }

    #[test]
    fn browse_joins_records_and_reads_the_mode() {
        let mut records = MdnsRecords::default();
        parse_mdns_response(
            &response("refineid-7f2a1c84", &["v=1", "mode=pairing"]),
            None,
            &mut records,
        );
        parse_mdns_response(
            &response("refineid-0b9e44d1", &["v=1", "mode=session"]),
            None,
            &mut records,
        );
        let services = records.into_services();
        assert_eq!(services.len(), 2);
        let pairing: Vec<_> = services
            .iter()
            .filter(|service| service.advertises(DiscoveryMode::Pairing))
            .collect();
        assert_eq!(pairing.len(), 1);
        assert_eq!(pairing[0].instance, "refineid-7f2a1c84");
        assert_eq!(pairing[0].endpoints, ["192.0.2.10:47110"]);
        assert!(services[1].advertises(DiscoveryMode::Session));
    }

    #[test]
    fn a_record_without_version_one_is_not_a_custodian() {
        let mut records = MdnsRecords::default();
        parse_mdns_response(
            &response("refineid-7f2a1c84", &["v=2", "mode=pairing"]),
            None,
            &mut records,
        );
        let services = records.into_services();
        assert!(!services[0].advertises(DiscoveryMode::Pairing));
    }

    #[test]
    fn truncated_responses_are_ignored() {
        let mut records = MdnsRecords::default();
        let packet = response("refineid-7f2a1c84", &["v=1", "mode=pairing"]);
        for cut in 0..packet.len() {
            parse_mdns_response(&packet[..cut], None, &mut records);
        }
    }

    #[test]
    fn preambles_round_trip_and_reject_oversized_frames() {
        let profile = TransportProfile::Stream;
        let pairing = RoutingPreamble::Pairing.encode(profile).unwrap();
        assert_eq!(
            RoutingPreamble::decode(profile, &pairing).unwrap(),
            RoutingPreamble::Pairing
        );
        let oversized = vec![0u8; super::MAX_ROUTING_PREAMBLE_FRAME + 1];
        assert_eq!(
            RoutingPreamble::decode(profile, &oversized),
            Err(refineid_rapp::PreambleError::Oversized)
        );
    }

    #[test]
    fn custodian_listener_routes_requester_dials_by_tag() {
        let listener = StreamListener::bind("127.0.0.1:0", CANDIDATE, DEADLINE).unwrap();
        let port = listener.local_port().unwrap();
        let endpoints = vec![format!("127.0.0.1:{port}")];

        let dial_endpoints = endpoints.clone();
        let dialer = std::thread::spawn(move || {
            dial(&dial_endpoints, CANDIDATE, DEADLINE, DialPurpose::Pairing).unwrap()
        });
        let accepted = listener.accept().unwrap();
        assert!(matches!(accepted, StreamAccept::Pairing(_)));
        drop(dialer.join().unwrap());

        let mut seen: Vec<SessionRouting> = Vec::new();
        for _ in 0..2 {
            let dial_endpoints = endpoints.clone();
            let dialer = std::thread::spawn(move || {
                let key = RoutingKey::derive(&requester()).unwrap();
                let mut transport = dial(
                    &dial_endpoints,
                    CANDIDATE,
                    DEADLINE,
                    DialPurpose::Session(&key),
                )
                .unwrap();
                transport.send_frame(&[0x01, 0x02]).unwrap();
            });
            let StreamAccept::Session {
                routing,
                mut transport,
            } = listener.accept().unwrap()
            else {
                panic!("expected a session accept");
            };
            let keys = [
                RoutingKey::derive(&stranger()).unwrap(),
                RoutingKey::derive(&custodian()).unwrap(),
            ];
            assert_eq!(
                route_session(&keys, TransportProfile::Stream, &routing),
                Some(1)
            );
            assert_eq!(transport.receive_frame().unwrap(), vec![0x01, 0x02]);
            dialer.join().unwrap();
            seen.push(routing);
        }
        assert_ne!(seen[0].nonce(), seen[1].nonce());
    }

    #[test]
    fn garbage_preambles_close_without_classification() {
        let listener = StreamListener::bind("127.0.0.1:0", CANDIDATE, DEADLINE).unwrap();
        let port = listener.local_port().unwrap();
        let dialer = std::thread::spawn(move || {
            let socket = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
            let mut transport =
                crate::transport::TcpFrameTransport::new(socket, CANDIDATE, DEADLINE).unwrap();
            transport.send_frame(&[0xFF, 0x00, 0x11]).unwrap();
        });
        assert!(matches!(listener.accept(), Err(StreamError::Malformed)));
        dialer.join().unwrap();
    }

    #[test]
    fn an_unreachable_custodian_is_reported() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(matches!(
            dial(
                &[format!("127.0.0.1:{port}")],
                CANDIDATE,
                DEADLINE,
                DialPurpose::Pairing
            ),
            Err(StreamError::Unreachable)
        ));
    }
}
