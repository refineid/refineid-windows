//! The revocation backlog's appearance memory (RAPP v26.11.2 section 4.6
//! item 6).
//!
//! A forgotten pairing's phone is dialed only when it appears for the
//! pairing, over either discovery route, and at most once per appearance: a
//! phone that stays in sight is never dialed again until it has been absent
//! and reappears. Absence is observed, never inferred from elapsed time:
//! only a completed browse or scan round that does not list the sighting
//! marks it absent, and time between rounds without such a round is never
//! absence. A sighting listed again is an appearance only once it has been
//! absent for the loss hold below. The memory is per forgotten pairing and
//! route, and lives for as long as the process runs; a restart treats the
//! first sighting as an appearance. A pairing's entries go when the pairing
//! is destroyed, on its echo or its expiry.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use refineid_rapp::PAIR_ID_SIZE;

use crate::ids::PairId;

/// Which discovery route saw the phone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BacklogRoute {
    /// A `mode=session` mDNS record carrying the pairing's discovery hint.
    Stream,
    /// A RAPP BLE advertisement.
    Ble,
}

/// How long a forgotten pairing's phone must be absent before seeing it
/// again is a new appearance: thirty seconds of observed absence.
const BACKLOG_LOSS_HOLD_MS: u64 = 30_000;

/// One sighting of a forgotten pairing's phone: when its observed absence
/// began, if a completed round has missed it since it was last listed.
#[derive(Clone, Copy, Debug)]
struct Sighting {
    /// When a completed round last missed the sighting, in continuous-clock
    /// milliseconds; `None` while the sighting is listed.
    absent_since_ms: Option<u64>,
}

/// The sightings of one [`BacklogSightings`], by pairing, route, and
/// sighting.
type Sightings = BTreeMap<([u8; PAIR_ID_SIZE], BacklogRoute, String), Sighting>;

/// The appearance memory of the revocation backlog.
///
/// An owned value the caller keeps for as long as the process runs and
/// passes to every backlog round. Tests keep their own, so they share
/// nothing with each other or with the wall and continuous clocks of other
/// tests.
#[derive(Debug, Default)]
pub struct BacklogSightings {
    sightings: Sightings,
}

impl BacklogSightings {
    /// An empty appearance memory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Notes that a browse or scan round completed at `now_ms` on the
    /// continuous clock, listing `listed` for `pair_id` on `route`: the
    /// instance names of the `mode=session` records carrying the pairing's
    /// hint, or the addresses of the RAPP BLE advertisers seen.
    ///
    /// Every remembered sighting of the pairing on the route that the round
    /// did not list is now observed absent: its absence starts here, or
    /// keeps its earlier start when an earlier round already missed it. A
    /// round that lists nothing still completes, and marks every remembered
    /// sighting absent. Time between rounds without a completed round that
    /// missed the sighting is never absence.
    pub fn round_completed(
        &mut self,
        pair_id: PairId,
        route: BacklogRoute,
        listed: &[&str],
        now_ms: u64,
    ) {
        for ((seen_pair, seen_route, seen_sighting), sighting) in &mut self.sightings {
            if *seen_pair == *pair_id.as_bytes()
                && *seen_route == route
                && !listed.contains(&seen_sighting.as_str())
                && sighting.absent_since_ms.is_none()
            {
                sighting.absent_since_ms = Some(now_ms);
            }
        }
    }

    /// Notes that `pair_id`'s phone is listed on `route` under `sighting` at
    /// `now_ms` on the continuous clock: the instance name of a
    /// `mode=session` record carrying the pairing's hint, or the address of
    /// a RAPP BLE advertiser.
    ///
    /// Returns whether this is an appearance: a sighting never seen on the
    /// route, or one observed absent for the loss hold. A listed sighting
    /// is in sight again either way, so its absence ends here; a phone that
    /// stays listed across rounds is an appearance only once.
    #[must_use]
    pub fn appearance(
        &mut self,
        pair_id: PairId,
        route: BacklogRoute,
        sighting: &str,
        now_ms: u64,
    ) -> bool {
        let key = (*pair_id.as_bytes(), route, sighting.to_owned());
        let appeared = self.sightings.get(&key).is_none_or(|seen| {
            seen.absent_since_ms
                .is_some_and(|since| now_ms.saturating_sub(since) >= BACKLOG_LOSS_HOLD_MS)
        });
        self.sightings.insert(
            key,
            Sighting {
                absent_since_ms: None,
            },
        );
        appeared
    }

    /// Drops every sighting of `pair_id`, on every route: its revocation
    /// notice resolved on its echo, or the pairing went untold at its idle
    /// expiry, so no round watches for it anymore.
    pub fn remove_pairing(&mut self, pair_id: PairId) {
        self.sightings
            .retain(|(seen_pair, _, _), _| *seen_pair != *pair_id.as_bytes());
    }
}

/// The sightings of this process, kept for as long as it runs: production
/// rounds pass this memory in, so a phone that stays in sight across rounds
/// spaced further apart than the loss hold still dials only once.
static SHARED: Mutex<BacklogSightings> = Mutex::new(BacklogSightings {
    sightings: BTreeMap::new(),
});

/// Locks the sightings of this process.
pub fn shared() -> MutexGuard<'static, BacklogSightings> {
    SHARED.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use super::{BacklogRoute, BacklogSightings};
    use crate::ids::PairId;

    /// A moment on the continuous clock.
    const NOW_MS: u64 = 1_000_000;
    /// The loss hold: thirty seconds of observed absence ends a sighting.
    const LOSS_HOLD_MS: u64 = 30_000;
    /// A synthetic instance name.
    const INSTANCE: &str = "refineid-instance";
    /// Another synthetic instance name.
    const FRESH_INSTANCE: &str = "refineid-fresh";

    /// A pairing of its own for each test; each test also keeps its own
    /// memory, so tests share nothing.
    fn pairing(tag: u8) -> PairId {
        PairId::from_array([tag; 16])
    }

    #[test]
    fn a_first_sighting_is_an_appearance_and_a_staying_phone_is_none() {
        let mut sightings = BacklogSightings::new();
        let pair = pairing(b'a');
        assert!(sightings.appearance(pair, BacklogRoute::Stream, INSTANCE, NOW_MS));
        sightings.round_completed(pair, BacklogRoute::Stream, &[INSTANCE], NOW_MS);
        assert!(!sightings.appearance(pair, BacklogRoute::Stream, INSTANCE, NOW_MS));
        // Still listed across rounds spaced past the loss hold: elapsed
        // time alone is never absence, so nothing dials again.
        sightings.round_completed(pair, BacklogRoute::Stream, &[INSTANCE], NOW_MS + 60_000);
        assert!(!sightings.appearance(pair, BacklogRoute::Stream, INSTANCE, NOW_MS + 60_000));
        sightings.round_completed(pair, BacklogRoute::Stream, &[INSTANCE], NOW_MS + 120_000);
        assert!(!sightings.appearance(pair, BacklogRoute::Stream, INSTANCE, NOW_MS + 120_000));
    }

    #[test]
    fn a_phone_absent_one_round_and_back_after_the_hold_is_an_appearance() {
        let mut sightings = BacklogSightings::new();
        let pair = pairing(b'b');
        assert!(sightings.appearance(pair, BacklogRoute::Stream, INSTANCE, NOW_MS));
        // One completed round misses the phone: its absence starts here.
        sightings.round_completed(pair, BacklogRoute::Stream, &[], NOW_MS + 1);
        // Back 31 seconds later, past the hold: a new appearance.
        assert!(sightings.appearance(
            pair,
            BacklogRoute::Stream,
            INSTANCE,
            NOW_MS + 1 + LOSS_HOLD_MS + 1_000
        ));
        // The appearance is spent: still in sight dials nothing.
        sightings.round_completed(
            pair,
            BacklogRoute::Stream,
            &[INSTANCE],
            NOW_MS + 1 + LOSS_HOLD_MS + 1_000,
        );
        assert!(!sightings.appearance(
            pair,
            BacklogRoute::Stream,
            INSTANCE,
            NOW_MS + 1 + LOSS_HOLD_MS + 1_000
        ));
    }

    #[test]
    fn a_phone_back_before_the_hold_ends_is_no_appearance() {
        let mut sightings = BacklogSightings::new();
        let pair = pairing(b'c');
        assert!(sightings.appearance(pair, BacklogRoute::Ble, INSTANCE, NOW_MS));
        // One completed scan misses the phone: its absence starts here.
        sightings.round_completed(pair, BacklogRoute::Ble, &[], NOW_MS + 1);
        // Back 10 seconds after the missed round, within the hold: no new
        // appearance, and the sighting continues.
        assert!(!sightings.appearance(pair, BacklogRoute::Ble, INSTANCE, NOW_MS + 1 + 10_000));
        sightings.round_completed(pair, BacklogRoute::Ble, &[INSTANCE], NOW_MS + 1 + 10_000);
        assert!(!sightings.appearance(pair, BacklogRoute::Ble, INSTANCE, NOW_MS + 1 + 11_000));
        // Missed again, and back past the hold from that absence: an
        // appearance.
        sightings.round_completed(pair, BacklogRoute::Ble, &[], NOW_MS + 1 + 12_000);
        assert!(sightings.appearance(
            pair,
            BacklogRoute::Ble,
            INSTANCE,
            NOW_MS + 1 + 12_000 + LOSS_HOLD_MS
        ));
    }

    #[test]
    fn other_pairings_sightings_survive_any_elapsed_time() {
        let mut sightings = BacklogSightings::new();
        let pair = pairing(b'd');
        let other = pairing(b'e');
        assert!(sightings.appearance(pair, BacklogRoute::Stream, INSTANCE, NOW_MS));
        // Rounds for another pairing, far later, never purge this one: no
        // time-based purge drops entries.
        sightings.round_completed(other, BacklogRoute::Stream, &[INSTANCE], NOW_MS + 3_600_000);
        assert!(sightings.appearance(other, BacklogRoute::Stream, INSTANCE, NOW_MS + 3_600_000));
        sightings.round_completed(pair, BacklogRoute::Stream, &[INSTANCE], NOW_MS + 3_600_000);
        assert!(!sightings.appearance(pair, BacklogRoute::Stream, INSTANCE, NOW_MS + 3_600_000));
    }

    #[test]
    fn removing_a_pairing_drops_its_sightings_on_every_route() {
        let mut sightings = BacklogSightings::new();
        let pair = pairing(b'f');
        let other = pairing(b'g');
        assert!(sightings.appearance(pair, BacklogRoute::Stream, INSTANCE, NOW_MS));
        assert!(sightings.appearance(pair, BacklogRoute::Ble, INSTANCE, NOW_MS));
        assert!(sightings.appearance(other, BacklogRoute::Stream, INSTANCE, NOW_MS));
        sightings.remove_pairing(pair);
        // The destroyed pairing's next sighting is a first sighting again;
        // the other's sighting continues.
        assert!(sightings.appearance(pair, BacklogRoute::Stream, INSTANCE, NOW_MS));
        assert!(sightings.appearance(pair, BacklogRoute::Ble, INSTANCE, NOW_MS));
        assert!(!sightings.appearance(other, BacklogRoute::Stream, INSTANCE, NOW_MS));
    }

    #[test]
    fn sightings_are_per_pairing_route_and_sighting() {
        let mut sightings = BacklogSightings::new();
        let pair = pairing(b'h');
        let other = pairing(b'i');
        assert!(sightings.appearance(pair, BacklogRoute::Stream, INSTANCE, NOW_MS));
        assert!(sightings.appearance(pair, BacklogRoute::Stream, FRESH_INSTANCE, NOW_MS));
        assert!(sightings.appearance(pair, BacklogRoute::Ble, INSTANCE, NOW_MS));
        assert!(sightings.appearance(other, BacklogRoute::Stream, INSTANCE, NOW_MS));
        assert!(!sightings.appearance(pair, BacklogRoute::Stream, INSTANCE, NOW_MS));
        assert!(!sightings.appearance(pair, BacklogRoute::Stream, FRESH_INSTANCE, NOW_MS));
        assert!(!sightings.appearance(pair, BacklogRoute::Ble, INSTANCE, NOW_MS));
        assert!(!sightings.appearance(other, BacklogRoute::Stream, INSTANCE, NOW_MS));
        // A round that misses one sighting leaves the others in sight, and
        // a listing within the hold ends its absence without an appearance.
        sightings.round_completed(pair, BacklogRoute::Stream, &[FRESH_INSTANCE], NOW_MS + 1);
        assert!(!sightings.appearance(pair, BacklogRoute::Stream, FRESH_INSTANCE, NOW_MS + 1));
        assert!(!sightings.appearance(pair, BacklogRoute::Stream, INSTANCE, NOW_MS + 1 + 10_000));
        // Missed again, and back after the hold from that absence: an
        // appearance.
        sightings.round_completed(
            pair,
            BacklogRoute::Stream,
            &[FRESH_INSTANCE],
            NOW_MS + 1 + 10_001,
        );
        assert!(sightings.appearance(
            pair,
            BacklogRoute::Stream,
            INSTANCE,
            NOW_MS + 1 + 10_001 + LOSS_HOLD_MS
        ));
    }
}
