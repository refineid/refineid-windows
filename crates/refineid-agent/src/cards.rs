//! The agent's card watch (Windows STPA W-R-22): a FINEID card's propagated
//! entries stand in `CurrentUser\My` only while the card is in a reader of
//! this computer. At the agent's start and whenever a card arrives or leaves,
//! it removes every FINEID entry whose card is not in a reader. It touches no
//! card that the Card Module does not serve, and reads the ones it serves
//! silently through the Smart Card Key Storage Provider.

use std::ffi::CString;
use std::thread::sleep;
use std::time::{Duration, Instant};

use pcsc::{Context, Error as PcscError, PNP_NOTIFICATION, ReaderState, Scope, State};
use refineid_windows_credential_store::card_certificates::{
    AnswerToReset, CardRead, CardReaders, Pass, PersonalCardEntries, ReaderName, ReaderReading,
    ReadersReading, remove_entries_of_absent_cards,
};
use refineid_windows_credential_store::card_reading::read_card;

/// How long the watcher waits before judging again after a pass that
/// left the decision to a later one, unless a card arrives or leaves
/// first.
const RETRY_PAUSE: Duration = Duration::from_secs(10);
/// How long it waits before asking again for a smart card service that
/// is not running. Windows runs the service only while a reader is
/// attached.
const SERVICE_PAUSE: Duration = Duration::from_secs(5);
/// The least time between two readings of the readers while it waits,
/// so a reader that reports a change and then the same state again
/// cannot keep it busy.
const READING_INTERVAL: Duration = Duration::from_millis(500);

/// Removes the entries of absent cards now, and again after every
/// change of the readers.
pub fn watch() {
    let mut readers = PcscReaders;
    loop {
        let judged = pass(&mut readers);
        #[cfg(debug_assertions)]
        crate::test_card_cas::present();
        match judged {
            Some(Pass::Judged { readers: seen, .. }) => wait_for_change(&seen),
            Some(Pass::Deferred {
                readers: Some(seen),
            }) => wait_for_change_or(&seen, RETRY_PAUSE),
            Some(Pass::Deferred { readers: None }) | None => sleep(RETRY_PAUSE),
        }
    }
}

/// One pass over the user's Personal store; `None` when the store did
/// not open or failed.
fn pass(readers: &mut PcscReaders) -> Option<Pass> {
    let mut entries = match PersonalCardEntries::open() {
        Ok(entries) => entries,
        Err(error) => {
            refineid_dev_errors::report!(Agent, "personal store not opened", error);
            return None;
        }
    };
    match remove_entries_of_absent_cards(readers, &mut entries) {
        Ok(pass) => Some(pass),
        Err(error) => {
            refineid_dev_errors::report!(Agent, "card certificates not removed", error);
            None
        }
    }
}

/// Waits until the readers differ from `seen`.
fn wait_for_change(seen: &ReadersReading) {
    wait_until(seen, None);
}

/// Waits until the readers differ from `seen`, or `pause` passed.
fn wait_for_change_or(seen: &ReadersReading, pause: Duration) {
    wait_until(seen, Some(Instant::now() + pause));
}

/// Waits until the readers differ from `seen`, or `deadline` passed.
/// Every return follows a reading of the readers that differs from
/// `seen`, or the deadline, so a change between the pass's reading and
/// this wait is never missed: the card events count it.
fn wait_until(seen: &ReadersReading, deadline: Option<Instant>) {
    loop {
        let remaining = match deadline {
            Some(deadline) => match deadline.checked_duration_since(Instant::now()) {
                Some(remaining) if !remaining.is_zero() => Some(remaining),
                _ => return,
            },
            None => None,
        };
        let Ok(context) = Context::establish(Scope::User) else {
            if *seen != ReadersReading::default() {
                return;
            }
            sleep(remaining.map_or(SERVICE_PAUSE, |rest| rest.min(SERVICE_PAUSE)));
            continue;
        };
        let Some((reading, mut states)) = read_states(&context) else {
            return;
        };
        if reading != *seen {
            return;
        }
        let mut pnp = ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE);
        let _baseline = context.get_status_change(Duration::ZERO, core::slice::from_mut(&mut pnp));
        pnp.sync_current_state();
        states.push(pnp);
        for state in &mut states {
            state.sync_current_state();
        }
        // A change, a timeout and a stopped service all end the wait
        // alike: the next reading says what happened.
        let _changed = context.get_status_change(remaining, &mut states);
        sleep(READING_INTERVAL);
    }
}

/// The readers of this computer, read through PC/SC, and their cards,
/// read through the Smart Card Key Storage Provider.
struct PcscReaders;

impl CardReaders for PcscReaders {
    fn reading(&mut self) -> Option<ReadersReading> {
        match Context::establish(Scope::User) {
            Ok(context) => read_states(&context).map(|(reading, _)| reading),
            Err(PcscError::NoService | PcscError::ServiceStopped) => {
                Some(ReadersReading::default())
            }
            Err(_) => None,
        }
    }

    fn certificates(&mut self, reader: &ReaderName, card: &AnswerToReset) -> CardRead {
        read_card(reader, card)
    }
}

/// Every reader's state now, touching no card, with the states it was
/// read from; `None` when a reader's state is not known.
fn read_states(context: &Context) -> Option<(ReadersReading, Vec<ReaderState>)> {
    let names: Vec<CString> = match context.list_readers_owned() {
        Ok(names) => names,
        Err(PcscError::NoReadersAvailable | PcscError::NoService | PcscError::ServiceStopped) => {
            Vec::new()
        }
        Err(_) => return None,
    };
    let mut states: Vec<ReaderState> = names
        .into_iter()
        .map(|name| ReaderState::new(name, State::UNAWARE))
        .collect();
    // A zero wait that timed out leaves a state Windows did not report as
    // the caller passed it, without `CHANGED`.
    let mut answered = true;
    if !states.is_empty() {
        match context.get_status_change(Duration::ZERO, &mut states) {
            Ok(()) => {}
            Err(PcscError::Timeout) => answered = false,
            Err(_) => return None,
        }
    }
    let mut readers = Vec::with_capacity(states.len());
    for state in &states {
        let event = state.event_state();
        let reported = answered || event.contains(State::CHANGED);
        if !reported || event.contains(State::UNAVAILABLE) {
            return None;
        }
        let present = event.contains(State::PRESENT) && !event.contains(State::EMPTY);
        readers.push(ReaderReading {
            name: ReaderName::new(state.name().to_string_lossy().into_owned()),
            card_events: state.event_count(),
            card: present.then(|| AnswerToReset::new(state.atr().to_vec())),
        });
    }
    Some((ReadersReading::new(readers), states))
}
