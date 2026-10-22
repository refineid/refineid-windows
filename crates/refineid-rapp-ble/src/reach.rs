//! Reaching a stored pairing's phone over Bluetooth (RAPP v26.10.22
//! section 2.2.1).
//!
//! An advertisement cannot say whose phone it is, so a session preamble is
//! routed to each advertiser of a scan, strongest first, until one accepts
//! the session. An advertiser that refuses the session is not dialled
//! again in this search (core STPA R-53); one whose link fails to open is,
//! on the next scan, since a GATT connection can fail and then succeed.
//!
//! A pairing its user forgot is reached the same way, to deliver its
//! `pairing_revoked` close as the first message of the session (section
//! 4.6 item 2).

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use refineid_rapp::RoutingKey;
use refineid_rapp_core::engine::{Requester, SESSION_RECEIVE_TICK, Session, SessionError};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::CloseReason;
use refineid_rapp_core::store::PairingStore;
use refineid_rapp_core::stream::DialPurpose;

use crate::gatt::{BleLink, BleLinkError};
use crate::link::AdvertiserAddress;
use crate::scan::{ScanError, ScannedAdvertiser, scan};

/// One scan for advertisers before each round of dials.
const SCAN_WINDOW: Duration = Duration::from_secs(4);

/// What one step of the search did, for a caller that reports progress.
#[derive(Debug)]
pub enum Attempt<'a> {
    /// A session preamble is about to be routed to this advertiser.
    Routing(&'a ScannedAdvertiser),
    /// The link to the advertiser did not open; it is dialled again later.
    LinkFailed(BleLinkError),
    /// The advertiser refused the session; it is not dialled again.
    Refused(SessionError),
}

/// Why no session was opened.
#[derive(Clone, Copy, Debug)]
pub enum ReachError {
    /// The scan could not run.
    Scan(ScanError),
    /// No advertiser accepted the session before the window closed.
    NotReached,
    /// The pairing can open no session: it is unknown, revoked, forgotten,
    /// unconfirmed, or its phone revoked it on this attempt.
    Pairing(SessionError),
}

impl core::fmt::Display for ReachError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Scan(error) => write!(formatter, "{error}"),
            Self::NotReached => write!(
                formatter,
                "the paired phone was not reached; over Bluetooth it is found only while \
                 RefineID is open on it"
            ),
            Self::Pairing(error) => write!(formatter, "{error}"),
        }
    }
}

impl core::error::Error for ReachError {}

/// Searches for the phone of `pair_id` for at most `window` and opens a
/// session with it. The link receives with the requester engine's liveness
/// tick as its deadline.
///
/// # Errors
/// [`ReachError`] when the scan fails, no advertiser accepts in time, or
/// the pairing can open no session.
pub fn reach_session<Store: PairingStore>(
    requester: &mut Requester<Store>,
    pair_id: PairId,
    key: &RoutingKey,
    window: Duration,
    progress: impl FnMut(Attempt<'_>),
) -> Result<Session<BleLink>, ReachError> {
    reach(key, window, progress, |link| {
        requester.connect(pair_id, link)
    })
}

/// Searches for the phone of the forgotten `pair_id` for at most `window`
/// and delivers the pairing's `pairing_revoked` close as the first message
/// of a session with it; the keys are destroyed once it is sent.
///
/// # Errors
/// [`ReachError`] when the scan fails, no advertiser accepts in time, or
/// the pairing owes no notice.
pub fn reach_revocation_notice<Store: PairingStore>(
    requester: &mut Requester<Store>,
    pair_id: PairId,
    key: &RoutingKey,
    window: Duration,
    progress: impl FnMut(Attempt<'_>),
) -> Result<(), ReachError> {
    reach(key, window, progress, |link| {
        requester.deliver_revocation_notice(pair_id, link)
    })
}

/// Routes `key`'s preamble to each advertiser, strongest first, and hands
/// every link that opens to `open` until one succeeds.
fn reach<T>(
    key: &RoutingKey,
    window: Duration,
    mut progress: impl FnMut(Attempt<'_>),
    mut open: impl FnMut(BleLink) -> Result<T, SessionError>,
) -> Result<T, ReachError> {
    let deadline = Instant::now() + window;
    let mut refused: BTreeSet<AdvertiserAddress> = BTreeSet::new();
    while Instant::now() < deadline {
        let advertisers = scan(SCAN_WINDOW).map_err(ReachError::Scan)?;
        for advertiser in &advertisers {
            if refused.contains(&advertiser.address) {
                continue;
            }
            progress(Attempt::Routing(advertiser));
            let link = match BleLink::open(
                advertiser.address,
                DialPurpose::Session(key),
                SESSION_RECEIVE_TICK,
            ) {
                Ok(link) => link,
                Err(error) => {
                    progress(Attempt::LinkFailed(error));
                    continue;
                }
            };
            match open(link) {
                Ok(opened) => return Ok(opened),
                Err(error) if ends_the_search(error) => return Err(ReachError::Pairing(error)),
                Err(error) => {
                    progress(Attempt::Refused(error));
                    refused.insert(advertiser.address);
                }
            }
        }
    }
    Err(ReachError::NotReached)
}

/// Whether an attempt's failure leaves the pairing unable to open any
/// session, so no other advertiser is tried.
const fn ends_the_search(error: SessionError) -> bool {
    matches!(
        error,
        SessionError::UnknownPairing
            | SessionError::NotPaired
            | SessionError::Forgotten
            | SessionError::NotForgotten
            | SessionError::StorageUnconfirmed
            | SessionError::ClosedByPeer(CloseReason::PairingRevoked)
    )
}
