//! Reaching a stored pairing's phone over Bluetooth (RAPP v26.10.18
//! sections 2.2.1 and 4.4).
//!
//! An advertisement cannot say whose phone it is, so a session preamble is
//! routed to each admitted advertiser of a scan, strongest first, until one
//! accepts the session. An advertiser that refuses the session is not dialled
//! again in this search (core STPA R-53); one whose link fails to open is,
//! on the next scan, since a GATT connection can fail and then succeed.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use refineid_rapp::RoutingKey;
use refineid_rapp_core::engine::{Requester, Session, SessionError};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::store::{OperationJournal, PairingStore};
use refineid_rapp_core::stream::DialPurpose;

use crate::gatt::{BleLink, BleLinkError};
use crate::link::{AdvertiserAddress, ProximityGate};
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
        }
    }
}

impl core::error::Error for ReachError {}

/// Searches for the phone of `pair_id` for at most `window` and opens a
/// session with it. Each link waits at most `receive_deadline` for a frame.
///
/// # Errors
/// [`ReachError`] when the scan fails or no advertiser accepts in time.
pub fn reach_session<Store: PairingStore, Journal: OperationJournal>(
    requester: &mut Requester<Store, Journal>,
    pair_id: PairId,
    key: &RoutingKey,
    gate: ProximityGate,
    window: Duration,
    receive_deadline: Duration,
    mut progress: impl FnMut(Attempt<'_>),
) -> Result<Session<BleLink>, ReachError> {
    let deadline = Instant::now() + window;
    let mut refused: BTreeSet<AdvertiserAddress> = BTreeSet::new();
    while Instant::now() < deadline {
        let advertisers = scan(SCAN_WINDOW, gate).map_err(ReachError::Scan)?;
        for advertiser in &advertisers {
            if !advertiser.admitted || refused.contains(&advertiser.address) {
                continue;
            }
            progress(Attempt::Routing(advertiser));
            let link = match BleLink::open(
                advertiser.address,
                DialPurpose::Session(key),
                receive_deadline,
            ) {
                Ok(link) => link,
                Err(error) => {
                    progress(Attempt::LinkFailed(error));
                    continue;
                }
            };
            match requester.connect(pair_id, link) {
                Ok(session) => return Ok(session),
                Err(error) => {
                    progress(Attempt::Refused(error));
                    refused.insert(advertiser.address);
                }
            }
        }
    }
    Err(ReachError::NotReached)
}
