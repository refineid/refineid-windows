// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! The sign-in sweep (Windows STPA W-R-21, W-R-22): what a computer keeps of
//! a holder is held to its bounds even when no other `RefineID` process runs.
//! At every sign-in it loads the protected pairing set and checks idle expiry
//! when no agent holds a session. Then it stays, watching the smart card
//! readers: at its start and whenever a card arrives or leaves, it removes
//! from `CurrentUser\My` every FINEID entry whose card is not in a reader. It
//! shows nothing, opens no pipe, listens on no network or Bluetooth, and
//! ends with the user's session.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    sweep::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the RefineID sign-in sweep runs on Windows only");
}

#[cfg(windows)]
mod sweep {
    use std::ffi::CString;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    use pcsc::{Context, Error as PcscError, PNP_NOTIFICATION, ReaderState, Scope, State};
    use refineid_agent_pipe::PipeError;
    use refineid_agent_pipe::server::AgentLock;
    use refineid_rapp_core::clock::unix_time_ms;
    use refineid_rapp_core::store::sweep_pairings;
    use refineid_windows_credential_store::ProtectedPairingStore;
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

    /// Runs the sweep, and then watches the readers until the session ends.
    pub fn run() {
        sweep_pairing_set();
        watch_cards();
    }

    /// Loading the set applies W-R-21. An agent running now checks idle
    /// expiry itself, knowing which session it holds.
    fn sweep_pairing_set() {
        let lock = AgentLock::acquire();
        let mut store = match ProtectedPairingStore::load() {
            Ok(store) => store,
            Err(error) => {
                refineid_dev_errors::report!(Agent, "pairing store not loaded", error);
                return;
            }
        };
        match lock {
            Ok(_held_for_the_check) => {
                let _expired = sweep_pairings(&mut store, unix_time_ms(), |_| false);
            }
            Err(PipeError::AgentRunning) => {}
            Err(error) => refineid_dev_errors::report!(Agent, "agent lock not read", error),
        }
    }

    /// Removes the entries of absent cards now, and again after every
    /// change of the readers.
    fn watch_cards() {
        let mut readers = PcscReaders;
        loop {
            match pass(&mut readers) {
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
            let _baseline =
                context.get_status_change(Duration::ZERO, core::slice::from_mut(&mut pnp));
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
            Err(
                PcscError::NoReadersAvailable | PcscError::NoService | PcscError::ServiceStopped,
            ) => Vec::new(),
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
}
