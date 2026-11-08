//! Reaching a stored pairing's phone over Bluetooth (RAPP v26.11.2
//! section 2.2.1).
//!
//! An advertisement cannot say whose phone it is, so a session preamble is
//! routed to each advertiser of a scan, strongest first, until one accepts
//! the session. An advertiser that refuses the session is not dialled
//! again in this search (core STPA R-53); one whose link fails to open is,
//! on the next scan, since a GATT connection can fail and then succeed.
//!
//! A pairing its user forgot is reached by appearance alone, to deliver
//! its `pairing_revoked` close as the first message of the session
//! (section 4.6 items 2 and 6): the revocation backlog over Bluetooth. An
//! appearance is an advertiser first seen, or seen again after absence for
//! the loss hold; a phone that stays in sight is never dialed again.
//!
//! Every scan is a look for the requester's view of the phone (section
//! 4.7): an advertiser newly in sight is an appearance. A session is
//! dialed only as the view admits (section 8.3): when the phone appeared,
//! for a local consumer's request, or within the redial window, and never
//! while the phone is withdrawn; meanwhile the scan only watches. A
//! forgotten pairing dials on an appearance and never on a timer.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use refineid_rapp::RoutingKey;
use refineid_rapp_core::backlog::{BacklogRoute, BacklogSightings};
use refineid_rapp_core::clock::{continuous_ms, unix_time_ms};
use refineid_rapp_core::engine::{Requester, SESSION_RECEIVE_TICK, Session, SessionError};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::CloseReason;
use refineid_rapp_core::store::{PairingStore, expire_revocation_notices};
use refineid_rapp_core::stream::{DialCause, DialPurpose};
use refineid_rapp_core::view;

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
    /// No session can open: the pairing is unknown, revoked, forgotten or
    /// unconfirmed, its phone revoked it on this attempt, or the requester
    /// withdrew (RAPP v26.11.2 section 4.5 item 8).
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
/// session with it when `cause` admits a dial (section 8.3). The link
/// receives with the requester engine's liveness tick as its deadline.
///
/// # Errors
/// [`ReachError`] when the scan fails, no advertiser accepts in time, or
/// the pairing can open no session.
pub fn reach_session<Store: PairingStore>(
    requester: &mut Requester<Store>,
    pair_id: PairId,
    key: &RoutingKey,
    window: Duration,
    cause: DialCause,
    progress: impl FnMut(Attempt<'_>),
) -> Result<Session<BleLink>, ReachError> {
    reach(pair_id, key, window, cause, progress, |link| {
        requester.connect(pair_id, link)
    })
}

/// Delivers a forgotten pairing's `pairing_revoked` close over Bluetooth.
///
/// Scans for the phone of the forgotten `pair_id` for at most `window` and
/// delivers the close as the first message of a session with it: the
/// revocation backlog over Bluetooth (RAPP v26.11.2 section 4.6 item 6).
/// The record is re-read before the window opens and before every round of
/// dials: a pairing gone or no longer forgotten is not dialed, and one past
/// its notice expiry is revoked untold instead. Only an appearance dials: an
/// advertiser first seen, or seen again after absence for the loss hold.
/// Then at most one connection opens, carrying the close as its first
/// message. The keys and the record go only on the phone's echo; anything
/// else keeps the pairing in the backlog for its next appearance. A phone
/// that stays in sight is never dialed again until it has been absent and
/// reappears: no dial runs on a timer.
///
/// # Errors
/// [`ReachError`] when the scan fails, no advertiser accepts in time, or
/// the pairing owes no notice.
pub fn reach_revocation_notice<Store: PairingStore>(
    requester: &mut Requester<Store>,
    pair_id: PairId,
    key: &RoutingKey,
    window: Duration,
    sightings: &mut BacklogSightings,
    progress: impl FnMut(Attempt<'_>),
) -> Result<(), ReachError> {
    if !notice_still_owed(requester, pair_id, sightings) {
        return Err(ReachError::Pairing(SessionError::NotForgotten));
    }
    reach_backlog(
        requester,
        pair_id,
        key,
        window,
        sightings,
        progress,
        |requester, link| requester.deliver_revocation_notice(pair_id, unix_time_ms(), link),
    )
}

/// Whether the backlog still owes `pair_id` its `pairing_revoked` close: a
/// pairing gone or no longer forgotten is skipped, and one past its notice
/// expiry is revoked untold here (RAPP v26.11.2 section 4.6 item 3). A
/// pairing owed nothing anymore keeps no sightings either.
fn notice_still_owed<Store: PairingStore>(
    requester: &mut Requester<Store>,
    pair_id: PairId,
    sightings: &mut BacklogSightings,
) -> bool {
    let now_ms = unix_time_ms();
    let owed = requester.store().get(pair_id).is_ok_and(|record| {
        record.owes_revocation_notice()
            && record
                .pair_record()
                .is_some_and(|keys| !keys.revocation_notice_expired(now_ms))
    });
    if owed {
        return true;
    }
    let expired = requester.store().get(pair_id).is_ok_and(|record| {
        record
            .pair_record()
            .is_some_and(|keys| keys.revocation_notice_expired(now_ms))
    });
    if expired {
        let _ = expire_revocation_notices(requester.store_mut(), now_ms);
    }
    sightings.remove_pairing(pair_id);
    false
}

/// Routes `key`'s preamble to each newly appeared advertiser, strongest
/// first. Only an appearance dials: an advertiser first seen, or seen again
/// after a completed scan missed it for the loss hold. A link that fails to
/// open is tried again on later scans of this window only. Hands every link
/// that opens to `open` until one succeeds; a delivery that went out,
/// echoed or not, ends the search, and so does a failure that leaves no
/// session able to open.
fn reach_backlog<T, Store: PairingStore>(
    requester: &mut Requester<Store>,
    pair_id: PairId,
    key: &RoutingKey,
    window: Duration,
    sightings: &mut BacklogSightings,
    mut progress: impl FnMut(Attempt<'_>),
    mut open: impl FnMut(&mut Requester<Store>, BleLink) -> Result<T, SessionError>,
) -> Result<T, ReachError> {
    let deadline = Instant::now() + window;
    let mut refused: BTreeSet<AdvertiserAddress> = BTreeSet::new();
    let mut link_failed: BTreeSet<AdvertiserAddress> = BTreeSet::new();
    while Instant::now() < deadline {
        // The record may have resolved on the other route, or expired,
        // while this window runs.
        if !notice_still_owed(requester, pair_id, sightings) {
            return Err(ReachError::Pairing(SessionError::NotForgotten));
        }
        let advertisers = scan(SCAN_WINDOW).map_err(ReachError::Scan)?;
        // The scan completed: every remembered sighting it missed is now
        // observed absent. Seeing what is in sight announces nothing
        // without an appearance, so nothing dials then.
        let now_ms = continuous_ms();
        let listed: Vec<String> = advertisers
            .iter()
            .map(|advertiser| advertiser.address.to_string())
            .collect();
        let listed: Vec<&str> = listed.iter().map(String::as_str).collect();
        sightings.round_completed(pair_id, BacklogRoute::Ble, &listed, now_ms);
        let mut fresh: Vec<&ScannedAdvertiser> = Vec::new();
        for advertiser in &advertisers {
            if refused.contains(&advertiser.address) {
                continue;
            }
            let appeared = sightings.appearance(
                pair_id,
                BacklogRoute::Ble,
                &advertiser.address.to_string(),
                now_ms,
            );
            if appeared || link_failed.contains(&advertiser.address) {
                fresh.push(advertiser);
            }
        }
        if fresh.is_empty() {
            continue;
        }
        for advertiser in fresh {
            progress(Attempt::Routing(advertiser));
            let link = match BleLink::open(
                advertiser.address,
                DialPurpose::Session(key),
                SESSION_RECEIVE_TICK,
            ) {
                Ok(link) => link,
                Err(error) => {
                    progress(Attempt::LinkFailed(error));
                    link_failed.insert(advertiser.address);
                    continue;
                }
            };
            match open(requester, link) {
                Ok(opened) => {
                    sightings.remove_pairing(pair_id);
                    return Ok(opened);
                }
                // The notice went out: echoed or not, the backlog keeps the
                // pairing for its next appearance.
                Err(SessionError::Unacknowledged) => {
                    return Err(ReachError::Pairing(SessionError::Unacknowledged));
                }
                Err(error) if ends_the_search(error) => return Err(ReachError::Pairing(error)),
                Err(error) => {
                    progress(Attempt::Refused(error));
                    refused.insert(advertiser.address);
                    link_failed.remove(&advertiser.address);
                }
            }
        }
        // The appearance's advertisers all refused or stayed shut: later
        // scans dial only when the phone appears anew.
    }
    Err(ReachError::NotReached)
}

/// Routes `key`'s preamble to each advertiser, strongest first, and hands
/// every link that opens to `open` until one succeeds; a session dial only
/// when the view of `pair_id` admits it for `cause`.
fn reach<T>(
    pair_id: PairId,
    key: &RoutingKey,
    window: Duration,
    cause: DialCause,
    mut progress: impl FnMut(Attempt<'_>),
    mut open: impl FnMut(BleLink) -> Result<T, SessionError>,
) -> Result<T, ReachError> {
    let deadline = Instant::now() + window;
    let mut refused: BTreeSet<AdvertiserAddress> = BTreeSet::new();
    while Instant::now() < deadline {
        let advertisers = scan(SCAN_WINDOW).map_err(ReachError::Scan)?;
        view::look(
            pair_id,
            advertisers
                .iter()
                .map(|advertiser| advertiser.address.to_string()),
        );
        if !view::dial_admitted(
            pair_id,
            continuous_ms(),
            cause == DialCause::ConsumerRequest,
        ) {
            continue;
        }
        let mut dialed = false;
        for advertiser in &advertisers {
            if refused.contains(&advertiser.address) {
                continue;
            }
            progress(Attempt::Routing(advertiser));
            dialed = true;
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
        if dialed {
            view::dial_failed(pair_id, continuous_ms());
        }
    }
    Err(ReachError::NotReached)
}

/// Whether an attempt's failure leaves no session able to open, so no
/// other advertiser is tried.
const fn ends_the_search(error: SessionError) -> bool {
    matches!(
        error,
        SessionError::UnknownPairing
            | SessionError::NotPaired
            | SessionError::Forgotten
            | SessionError::NotForgotten
            | SessionError::StorageUnconfirmed
            | SessionError::Withdrawn
            | SessionError::ClosedByPeer(CloseReason::PairingRevoked)
    )
}
