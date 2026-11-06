//! The requester's view of its custodian, one per stored pairing in this
//! process (RAPP v26.11.2 section 4.7, the `requester_view_of_custodian`
//! machine of `rapp-state-machine-v26.11.2.yaml`).
//!
//! The view decides when this computer may dial its phone (section 8.3):
//! when the phone appears, when a local consumer asks for the card, and
//! within the redial window after a loss. How a session ended moves it
//! (section 4.5 item 6, "How a session ends"): a `service_withdrawn` or
//! `card_unavailable` close makes it withdrawn, where nothing is dialed
//! until the phone announces itself again; a protocol violation leaves it
//! idle, where only an appearance or a consumer dials; a loss opens the
//! redial window; a `pairing_revoked` close ends it. A dial that ends
//! before `session.ready` opens the window too, counted from the first
//! failed dial since the phone last appeared.
//!
//! An appearance is a sight that was not in sight at the previous look: a
//! `mode=session` record under an instance name not seen before, or back
//! after vanishing, or a BLE advertiser address newly in sight. Seeing
//! what was already in sight announces nothing. None of this is shown to
//! the user (section 4.7).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use refineid_rapp::{PAIR_ID_SIZE, REDIAL_WINDOW_MS, RequesterSessionEnd};

use crate::ids::PairId;

/// Where the requester's view of one custodian stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewState {
    /// No session and no redial window: only an appearance or a consumer
    /// dials.
    Idle,
    /// A dial is set up or due; `window_opened_ms`, on the continuous
    /// clock, is when the redial window opened, `None` while the first dial
    /// since an appearance or a consumer's request has not failed.
    Connecting {
        /// When the redial window opened, if it has.
        window_opened_ms: Option<u64>,
    },
    /// A session is healthy.
    Connected,
    /// A verified withdrawal or a `card_unavailable` close: no dial and no
    /// offer until the custodian announces itself again.
    Withdrawn,
}

/// One custodian's view: its state and what was in sight at the last look.
#[derive(Debug)]
struct CustodianView {
    state: ViewState,
    in_sight: BTreeSet<String>,
}

impl CustodianView {
    const fn new() -> Self {
        Self {
            state: ViewState::Idle,
            in_sight: BTreeSet::new(),
        }
    }
}

/// The views of this process, by pairing.
static VIEWS: Mutex<BTreeMap<[u8; PAIR_ID_SIZE], CustodianView>> = Mutex::new(BTreeMap::new());

fn views() -> MutexGuard<'static, BTreeMap<[u8; PAIR_ID_SIZE], CustodianView>> {
    VIEWS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Applies `change` to the view of `pair_id`, made idle on first use.
fn with_view<T>(pair_id: PairId, change: impl FnOnce(&mut CustodianView) -> T) -> T {
    change(
        views()
            .entry(*pair_id.as_bytes())
            .or_insert_with(CustodianView::new),
    )
}

/// The view of `pair_id` now.
#[must_use]
pub fn state(pair_id: PairId) -> ViewState {
    views()
        .get(pair_id.as_bytes())
        .map_or(ViewState::Idle, |view| view.state)
}

/// Whether the custodian of `pair_id` withdrew, or closed with
/// `card_unavailable`, and has not announced itself since.
#[must_use]
pub fn is_withdrawn(pair_id: PairId) -> bool {
    state(pair_id) == ViewState::Withdrawn
}

/// One look at what discovery shows of the custodian of `pair_id`.
///
/// The sightings are the instance names of the `mode=session` records that may be its, or the BLE
/// advertisers in sight. Returns whether the custodian appeared: something
/// is in sight that was not at the previous look. An appearance moves an
/// idle or withdrawn view to connecting (`record_appeared`,
/// `advertisement_appeared`); a connected view ignores discovery.
pub fn look(pair_id: PairId, sightings: impl IntoIterator<Item = String>) -> bool {
    let sightings: BTreeSet<String> = sightings.into_iter().collect();
    with_view(pair_id, |view| {
        let appeared = sightings.iter().any(|seen| !view.in_sight.contains(seen));
        view.in_sight = sightings;
        if appeared && view.state != ViewState::Connected {
            view.state = ViewState::Connecting {
                window_opened_ms: None,
            };
        }
        appeared
    })
}

/// A withdrawn record verified for `pair_id` on its associated instance
/// (`withdrawn_record_matched`): the view is withdrawn unless a session is
/// open, which outranks discovery (section 4.5 item 6).
pub fn withdrawn_record_matched(pair_id: PairId) {
    with_view(pair_id, |view| {
        if view.state != ViewState::Connected {
            view.state = ViewState::Withdrawn;
        }
    });
}

/// Whether a dial to the custodian of `pair_id` is admitted at `now_ms` on
/// the continuous clock (section 8.3).
///
/// Never while withdrawn; from idle only
/// for a local consumer that asks for the card (`consumer_asked`); while
/// connecting, for the first dial and then within the redial window. A
/// window that has passed leaves the view idle (`redial_window_ended`). An
/// admitted consumer's dial moves the view to connecting.
#[must_use]
pub fn dial_admitted(pair_id: PairId, now_ms: u64, consumer_asked: bool) -> bool {
    with_view(pair_id, |view| match view.state {
        ViewState::Withdrawn => false,
        ViewState::Connected
        | ViewState::Connecting {
            window_opened_ms: None,
        } => true,
        ViewState::Connecting {
            window_opened_ms: Some(opened_ms),
        } => {
            if now_ms.saturating_sub(opened_ms) < REDIAL_WINDOW_MS {
                true
            } else {
                view.state = ViewState::Idle;
                if consumer_asked {
                    view.state = ViewState::Connecting {
                        window_opened_ms: None,
                    };
                }
                consumer_asked
            }
        }
        ViewState::Idle => {
            if consumer_asked {
                view.state = ViewState::Connecting {
                    window_opened_ms: None,
                };
            }
            consumer_asked
        }
    })
}

/// A dial to the custodian of `pair_id` ended before `session.ready` at
/// `now_ms` (`dial_failed`): the redial window opens with the first such
/// dial and runs on; once it has passed the view is idle.
pub fn dial_failed(pair_id: PairId, now_ms: u64) {
    with_view(pair_id, |view| {
        if let ViewState::Connecting { window_opened_ms } = &mut view.state {
            let opened_ms = *window_opened_ms.get_or_insert(now_ms);
            if now_ms.saturating_sub(opened_ms) >= REDIAL_WINDOW_MS {
                view.state = ViewState::Idle;
            }
        }
    });
}

/// The custodian of `pair_id` sent a `session.ready` this requester
/// verified (`dial_succeeded`).
pub fn session_opened(pair_id: PairId) {
    with_view(pair_id, |view| view.state = ViewState::Connected);
}

/// This requester closed its session to the custodian of `pair_id` for its
/// own reasons: no redial follows.
pub fn session_closed_here(pair_id: PairId) {
    with_view(pair_id, |view| view.state = ViewState::Idle);
}

/// A session to the custodian of `pair_id`, or a dial in place of its
/// `session.ready`, ended as `end` says at `now_ms` (section 4.5 item 6).
///
/// A revocation ends the view, a withdrawal or `card_unavailable` makes it
/// withdrawn, a violation leaves it idle, and a loss opens the redial
/// window at once.
pub fn session_ended(pair_id: PairId, end: RequesterSessionEnd, now_ms: u64) {
    if end == RequesterSessionEnd::Revoked {
        views().remove(pair_id.as_bytes());
        return;
    }
    with_view(pair_id, |view| {
        view.state = match end {
            RequesterSessionEnd::Withdrawn => ViewState::Withdrawn,
            RequesterSessionEnd::Violation | RequesterSessionEnd::Revoked => ViewState::Idle,
            RequesterSessionEnd::Loss => ViewState::Connecting {
                window_opened_ms: Some(now_ms),
            },
        };
    });
}

/// The pairing `pair_id` stopped being active here (`pairing_left`).
pub fn pairing_left(pair_id: PairId) {
    views().remove(pair_id.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::{
        ViewState, dial_admitted, dial_failed, is_withdrawn, look, pairing_left, session_ended,
        session_opened, state, withdrawn_record_matched,
    };
    use crate::ids::PairId;
    use refineid_rapp::{PAIR_ID_SIZE, REDIAL_WINDOW_MS, RequesterSessionEnd};

    /// A moment on the continuous clock.
    const NOW_MS: u64 = 1_000_000;
    /// A synthetic instance name.
    const INSTANCE: &str = "refineid-instance";
    /// Another synthetic instance name.
    const FRESH_INSTANCE: &str = "refineid-fresh";

    /// A pairing of its own for each test, as the views are process-wide.
    fn pairing(tag: u8) -> PairId {
        PairId::from_array([tag; PAIR_ID_SIZE])
    }

    #[test]
    fn a_loss_redials_within_the_window_and_not_after() {
        let pair = pairing(b'l');
        session_opened(pair);
        session_ended(pair, RequesterSessionEnd::Loss, NOW_MS);
        assert!(dial_admitted(pair, NOW_MS + REDIAL_WINDOW_MS - 1, false));
        assert!(!dial_admitted(pair, NOW_MS + REDIAL_WINDOW_MS, false));
        assert_eq!(state(pair), ViewState::Idle);
        assert!(dial_admitted(pair, NOW_MS + REDIAL_WINDOW_MS, true));
        pairing_left(pair);
    }

    #[test]
    fn a_withdrawal_dials_nothing_until_the_custodian_appears_anew() {
        let pair = pairing(b'w');
        assert!(look(pair, [INSTANCE.to_owned()]));
        session_opened(pair);
        session_ended(pair, RequesterSessionEnd::Withdrawn, NOW_MS);
        assert!(is_withdrawn(pair));
        assert!(!dial_admitted(pair, NOW_MS, true));
        assert!(!look(pair, [INSTANCE.to_owned()]));
        assert!(is_withdrawn(pair));
        assert!(look(pair, [FRESH_INSTANCE.to_owned()]));
        assert!(dial_admitted(pair, NOW_MS, false));
        pairing_left(pair);
    }

    #[test]
    fn a_violation_waits_for_an_appearance_or_a_consumer() {
        let pair = pairing(b'v');
        session_opened(pair);
        session_ended(pair, RequesterSessionEnd::Violation, NOW_MS);
        assert_eq!(state(pair), ViewState::Idle);
        assert!(!dial_admitted(pair, NOW_MS, false));
        assert!(dial_admitted(pair, NOW_MS, true));
        pairing_left(pair);
    }

    #[test]
    fn failed_dials_open_the_window_from_the_first() {
        let pair = pairing(b'f');
        assert!(look(pair, [INSTANCE.to_owned()]));
        dial_failed(pair, NOW_MS);
        assert!(dial_admitted(pair, NOW_MS + REDIAL_WINDOW_MS - 1, false));
        dial_failed(pair, NOW_MS + REDIAL_WINDOW_MS);
        assert_eq!(state(pair), ViewState::Idle);
        pairing_left(pair);
    }

    #[test]
    fn a_withdrawn_record_does_not_outrank_an_open_session() {
        let pair = pairing(b'r');
        session_opened(pair);
        withdrawn_record_matched(pair);
        assert_eq!(state(pair), ViewState::Connected);
        session_ended(pair, RequesterSessionEnd::Revoked, NOW_MS);
        assert_eq!(state(pair), ViewState::Idle);
        withdrawn_record_matched(pair);
        assert!(is_withdrawn(pair));
        pairing_left(pair);
    }
}
