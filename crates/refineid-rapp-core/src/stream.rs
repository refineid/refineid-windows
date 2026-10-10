//! The `fi.refineid.stream.v1` transport tier (RAPP transport and discovery
//! hierarchy, sections 3.3 and 4).
//!
//! The custodian (the phone) listens on an ephemeral TCP port and advertises
//! `_refineid-stream._tcp.local.` under a fresh random instance name, with a
//! TXT record naming its mode: `mode=pairing` during a pairing ceremony,
//! `mode=session` while it serves stored pairings, and `mode=withdrawn`
//! briefly when it stops serving. The requester browses by those attributes,
//! dials, and opens every connection with one plaintext routing preamble. A
//! session preamble carries a fresh nonce and a tag keyed by the pairing's
//! static agreement, so no value on the wire names a pairing twice. TXT
//! records are handed to `refineid_rapp` unparsed. An anomaly closes the
//! connection without touching stored state (specification section 10.1,
//! class 1).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::ids::PairId;
use crate::transport::{FrameTransport, TcpFrameTransport, TransportError};
use refineid_rapp::{
    DiscoveryKey, DiscoveryRecord, InstanceName, PairRecord, RoutingKey, SessionRouting,
    TransportProfile, WithdrawalKey, WithdrawnRecord, discovery_epoch, withdrawal_counter,
};
pub use refineid_rapp::{MAX_ROUTING_PREAMBLE_FRAME, RoutingPreamble, STREAM_PROFILE};

/// The DNS-SD service type of the stream tier.
pub const STREAM_SERVICE_TYPE: &str = "_refineid-stream._tcp.local";

/// The registered candidate identifier of the stream profile (RAPP v26.10.10
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

/// Pairings whose custodian announced it stopped serving. A requester does
/// not dial them again until a session record names them (specification
/// section 4.5).
static WITHDRAWN: Mutex<BTreeSet<[u8; 16]>> = Mutex::new(BTreeSet::new());

/// Records that the custodian of `pair_id` stopped serving, as announced by a
/// withdrawn record or a `service_withdrawn` session close.
pub fn mark_withdrawn(pair_id: PairId) {
    WITHDRAWN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(*pair_id.as_bytes());
}

/// Whether the custodian of `pair_id` announced it stopped serving and has
/// not been seen serving since.
#[must_use]
pub fn is_withdrawn(pair_id: PairId) -> bool {
    WITHDRAWN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(pair_id.as_bytes())
}

fn clear_withdrawn(pair_id: PairId) {
    WITHDRAWN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(pair_id.as_bytes());
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
        let start = std::time::Instant::now();
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

impl DialPurpose<'_> {
    fn preamble(self) -> Result<Vec<u8>, StreamError> {
        let profile = TransportProfile::Stream;
        let preamble = match self {
            Self::Pairing => RoutingPreamble::Pairing,
            Self::Session(key) => RoutingPreamble::Session(
                key.route(profile, |bytes| {
                    getrandom::fill(bytes).map_err(|_| refineid_rapp::RandomUnavailable)
                })
                .map_err(|_| StreamError::Random)?,
            ),
        };
        Ok(preamble.encode(profile)?)
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
        let preamble = purpose.preamble()?;
        let mut transport = TcpFrameTransport::new(socket, candidate_id, receive_deadline)
            .map_err(|_| StreamError::Accept)?;
        transport
            .send_frame(&preamble)
            .map_err(StreamError::Preamble)?;
        return Ok(transport);
    }
    Err(StreamError::Unreachable)
}

/// Dials the custodian serving the stored `pairing` with a session preamble.
///
/// Endpoints in `preferred` are tried first, then the session-mode services a
/// `browse_window` browse finds, those whose hints name this pairing ahead of
/// those publishing none (hierarchy section 4.3), then `fallback`.
///
/// A pairing whose custodian announced it stopped serving is not dialed
/// again until a session record names it; the browse that sees such an
/// announcement ends the attempt.
///
/// # Errors
/// [`StreamError::Withdrawn`] when the custodian announced it stopped
/// serving; [`StreamError::Unreachable`] when no endpoint accepts the
/// connection; [`StreamError::Malformed`] when the pairing's keys are
/// unusable.
pub fn dial_session(
    pairing: &PairRecord,
    preferred: &[String],
    fallback: &[String],
    browse_window: Duration,
    receive_deadline: Duration,
) -> Result<TcpFrameTransport, StreamError> {
    let key = RoutingKey::derive(pairing).map_err(|_| StreamError::Malformed)?;
    let attempt = |endpoints: &[String]| {
        if endpoints.is_empty() {
            return None;
        }
        dial(
            endpoints,
            STREAM_CANDIDATE_ID,
            receive_deadline,
            DialPurpose::Session(&key),
        )
        .ok()
    };
    let withdrawn = is_withdrawn(pairing.pair_id());
    if !withdrawn && let Some(transport) = attempt(preferred) {
        return Ok(transport);
    }
    let unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let found = session_candidates(browse_stream_services(browse_window), pairing, unix_seconds);
    let named = found
        .services
        .iter()
        .any(|service| service.names_pairing(pairing, unix_seconds));
    if named {
        clear_withdrawn(pairing.pair_id());
    } else if found.withdrawn {
        mark_withdrawn(pairing.pair_id());
        return Err(StreamError::Withdrawn);
    } else if withdrawn {
        return Err(StreamError::Withdrawn);
    }
    for service in found.services {
        if let Some(transport) = attempt(&service.endpoints) {
            return Ok(transport);
        }
    }
    attempt(fallback).ok_or(StreamError::Unreachable)
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
/// The mDNS IPv4 group and port (RFC 6762 section 3).
const MDNS_GROUP: std::net::SocketAddrV4 =
    std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(224, 0, 0, 251), 5353);
/// Poll interval while waiting for answers.
const MDNS_POLL: Duration = Duration::from_millis(250);

/// Records gathered from mDNS answers before they are joined per instance.
#[derive(Debug, Default)]
struct MdnsRecords {
    instances: Vec<String>,
    services: BTreeMap<String, (u16, String, Option<std::net::Ipv4Addr>)>,
    texts: BTreeMap<String, Vec<(String, String)>>,
    addresses: BTreeMap<String, std::net::Ipv4Addr>,
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
fn parse_mdns_response(
    data: &[u8],
    responder: Option<std::net::Ipv4Addr>,
    records: &mut MdnsRecords,
) {
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
                records.addresses.insert(
                    name,
                    std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]),
                );
            }
            _ => {}
        }
        offset = end;
    }
}

/// Splits TXT rdata into its length-prefixed `key=value` strings (RFC 6763
/// section 6), unchanged and in order; interpreting them is left to
/// `refineid_rapp`.
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
            && let Some((key, value)) = text.split_once('=')
        {
            entries.push((key.to_owned(), value.to_owned()));
        }
        offset = end;
    }
    entries
}

/// Browses `_refineid-stream._tcp.local.` for `timeout` and returns every
/// advertised custodian, with the TXT entries it published.
///
/// The query asks for unicast answers from an ephemeral port (RFC 6762
/// section 5.4), so it works beside a system mDNS responder.
#[must_use]
pub fn browse_stream_services(timeout: Duration) -> Vec<StreamService> {
    use std::net::UdpSocket;
    use std::time::Instant;

    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return Vec::new();
    };
    let _ = socket.set_read_timeout(Some(MDNS_POLL));
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
    // Class IN with the unicast-response bit.
    query.extend_from_slice(&0x8001u16.to_be_bytes());
    if socket.send_to(&query, MDNS_GROUP).is_err() {
        return Vec::new();
    }

    let start = Instant::now();
    let mut records = MdnsRecords::default();
    let mut buffer = [0u8; MDNS_RESPONSE_BYTES];
    while start.elapsed() < timeout {
        let Ok((read, peer)) = socket.recv_from(&mut buffer) else {
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

/// Browses for custodians advertising `mode`, each with at least one
/// endpoint.
#[must_use]
pub fn browse(mode: DiscoveryMode, timeout: Duration) -> Vec<StreamService> {
    browse_stream_services(timeout)
        .into_iter()
        .filter(|service| service.advertises(mode))
        .collect()
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
    /// The custodian announced it stopped serving this pairing.
    Withdrawn,
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
    use std::time::Duration;

    use super::{
        DialPurpose, DiscoveryMode, MdnsRecords, StreamAccept, StreamError, StreamListener,
        StreamService, dial, parse_mdns_response,
    };
    use crate::ids::{GrantsHash, PairId};
    use crate::transport::FrameTransport;
    use refineid_rapp::noise::x25519_public_key;
    use refineid_rapp::{
        DISCOVERY_HINT_EPOCH_SECONDS, DiscoveryKey, EndpointRole, InstanceName, PairRecord,
        ProfileName, RoutingKey, RoutingPreamble, SessionRouting, TransportProfile, WithdrawalKey,
        route_session, withdrawal_counter,
    };

    const DEADLINE: Duration = Duration::from_secs(2);
    const CANDIDATE: &str = "stream-test";

    /// Synthetic keys of `rapp-routing-v26.10.10.json` (`pair_keys`).
    const PAIR_ID: [u8; 16] = [0x33; 16];
    const CUSTODIAN_PRIVATE: [u8; 32] = [0x11; 32];
    const REQUESTER_PRIVATE: [u8; 32] = [0x22; 32];
    /// `routing_tag[RAPP-stream-v1]` of the same corpus.
    const STREAM_NONCE: [u8; 16] = [0x44; 16];
    const STREAM_TAG_HEX: &str = "f073a90d6f9fc979301b3db7eda0551f";
    /// `discovery_hint[epoch-1990560]` of the same corpus.
    const HINT_EPOCH: u64 = 1_990_560;
    const HINT_AT_EPOCH_HEX: &str = "054526c9fdd3b180";

    fn pair_record(role: EndpointRole, local: [u8; 32], remote: [u8; 32]) -> PairRecord {
        PairRecord::new(
            PairId::from_array(PAIR_ID),
            role,
            local,
            x25519_public_key(&local),
            x25519_public_key(&remote),
            GrantsHash::from_array([0x55; 32]),
            vec![ProfileName::parse(crate::profiles::PROFILE_AUTHENTICATION).unwrap()],
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

    #[test]
    fn a_withdrawn_pairing_is_remembered_until_cleared() {
        let pair = PairId::from_array([0x77; 16]);
        assert!(!super::is_withdrawn(pair));
        super::mark_withdrawn(pair);
        assert!(super::is_withdrawn(pair));
        super::clear_withdrawn(pair);
        assert!(!super::is_withdrawn(pair));
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
