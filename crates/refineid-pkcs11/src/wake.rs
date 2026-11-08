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

//! The paired phone asked for its card within a reading's wait.
//!
//! A reading that finds no certificate offered may ask the phone for its
//! card (RAPP v26.11.2 section 8.3: a request with no session open dials).
//! The dial runs on a thread of its own, one at a time: it opens a session,
//! has it confirm the card the phone reports and reads the card's
//! authentication certificate. The reading waits for it at most its own
//! wait, and a reading that arrives meanwhile waits for the same dial. A
//! dial that outlasts the wait goes on, and the certificate it reads serves
//! the readings after it. The certificate is held here, in memory only
//! (refineid-core `doc/security/certificate-custody.md`).

use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// What the dials have left: the certificate the last one read, and the
/// dial under way.
struct State<K, C> {
    /// The pairing a session confirmed the card of, and the card's
    /// certificate.
    learned: Option<(K, C)>,
    /// A dial is under way.
    dialing: bool,
    /// The thread of the latest dial, until it is joined.
    worker: Option<JoinHandle<()>>,
}

/// The dials for the card of the pairing `K`, whose certificate is `C`.
pub struct Wake<K, C> {
    state: Mutex<State<K, C>>,
    ended: Condvar,
}

impl<K, C> Wake<K, C>
where
    K: Copy + PartialEq + Send + 'static,
    C: Clone + Send + 'static,
{
    /// No dial yet, and no certificate.
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(State {
                learned: None,
                dialing: false,
                worker: None,
            }),
            ended: Condvar::new(),
        }
    }

    /// The certificate a session confirmed for `pairing`, if one did.
    pub fn learned(&self, pairing: K) -> Option<C> {
        self.state.lock().ok().and_then(|state| {
            state
                .learned
                .as_ref()
                .filter(|(learned, _)| *learned == pairing)
                .map(|(_, certificate)| certificate.clone())
        })
    }

    /// Drops the certificate held here: its offer no longer stands.
    pub fn forget(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.learned = None;
        }
    }

    /// Asks for the card of `pairing`: starts `dial` on a thread of its own
    /// unless a dial is under way, and waits at most `wait` for the dial
    /// under way to end. A zero `wait` starts nothing.
    ///
    /// `dial` answers with the certificate a session confirmed, or none.
    pub fn ask(
        self: &Arc<Self>,
        pairing: K,
        wait: Duration,
        dial: impl FnOnce() -> Option<C> + Send + 'static,
    ) {
        if wait.is_zero() {
            return;
        }
        let asked = Instant::now();
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if !state.dialing {
            // A dial that is not under way has given its answer: its thread
            // is ending, if it has not ended.
            if let Some(ended) = state.worker.take() {
                let _ = ended.join();
            }
            let wake = Arc::clone(self);
            let spawned = thread::Builder::new()
                .name("refineid-phone-wake".to_owned())
                .spawn(move || {
                    let learned = dial();
                    wake.dial_ended(pairing, learned);
                });
            match spawned {
                Ok(worker) => {
                    state.dialing = true;
                    state.worker = Some(worker);
                }
                Err(error) => {
                    refineid_dev_errors::report!(Pkcs11, "phone not dialled", error);
                    return;
                }
            }
        }
        while state.dialing {
            let left = wait.saturating_sub(asked.elapsed());
            if left.is_zero() {
                return;
            }
            let Ok((next, _)) = self.ended.wait_timeout(state, left) else {
                return;
            };
            state = next;
        }
    }

    /// Waits for the dial under way, if any, to end: no code of the module
    /// runs on its thread after.
    pub fn finish(&self) {
        let worker = self
            .state
            .lock()
            .ok()
            .and_then(|mut state| state.worker.take());
        if let Some(worker) = worker {
            let _ = worker.join();
        }
    }

    /// The dial for `pairing` ended with `learned`.
    fn dial_ended(&self, pairing: K, learned: Option<C>) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(certificate) = learned {
                state.learned = Some((pairing, certificate));
            }
            state.dialing = false;
        }
        self.ended.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::Wake;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    /// The pairing of the tests' phone.
    const PAIRING: u8 = 1;
    /// Another pairing.
    const OTHER_PAIRING: u8 = 2;
    /// The certificate the tests' phone's card holds.
    const CERTIFICATE: &str = "synthetic authentication certificate";
    /// The wait the tests' readings are granted.
    const WAIT: Duration = Duration::from_millis(300);
    /// How long into a dial an answering phone's session confirms the card.
    const ANSWERS_AFTER: Duration = Duration::from_millis(50);
    /// How long a phone out of reach holds a dial: past the wait.
    const OUT_OF_REACH: Duration = Duration::from_millis(600);
    /// What the scheduler may add to a reading beyond its wait.
    const SCHEDULING_SLACK: Duration = Duration::from_millis(500);

    type TestWake = Wake<u8, String>;

    /// A fake phone whose session confirms the card after `after`, or
    /// confirms none, counting its dials in `dials`.
    fn phone(
        dials: &Arc<AtomicUsize>,
        after: Duration,
        answers: bool,
    ) -> impl FnOnce() -> Option<String> + Send + 'static {
        let dials = Arc::clone(dials);
        move || {
            dials.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(after);
            answers.then(|| CERTIFICATE.to_owned())
        }
    }

    #[test]
    fn an_answering_phone_is_read_within_the_wait() {
        let wake = Arc::new(TestWake::new());
        let dials = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        wake.ask(PAIRING, WAIT, phone(&dials, ANSWERS_AFTER, true));
        assert!(started.elapsed() < WAIT, "{:?}", started.elapsed());
        assert_eq!(wake.learned(PAIRING).as_deref(), Some(CERTIFICATE));
        assert_eq!(wake.learned(OTHER_PAIRING), None);
        assert_eq!(dials.load(Ordering::SeqCst), 1);
        wake.finish();
    }

    #[test]
    fn a_phone_out_of_reach_holds_a_reading_to_its_wait_and_its_dial_goes_on() {
        let wake = Arc::new(TestWake::new());
        let dials = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        wake.ask(PAIRING, WAIT, phone(&dials, OUT_OF_REACH, true));
        let took = started.elapsed();
        assert!(took >= WAIT, "{took:?}");
        assert!(took < WAIT + SCHEDULING_SLACK, "{took:?}");
        assert_eq!(wake.learned(PAIRING), None);
        // The dial outlasts the reading and raises what it reads for the
        // readings after it.
        wake.finish();
        assert_eq!(wake.learned(PAIRING).as_deref(), Some(CERTIFICATE));
    }

    #[test]
    fn a_reading_during_a_dial_waits_for_it_and_dials_nothing() {
        let wake = Arc::new(TestWake::new());
        let dials = Arc::new(AtomicUsize::new(0));
        let first = {
            let wake = Arc::clone(&wake);
            let dial = phone(&dials, OUT_OF_REACH, false);
            std::thread::spawn(move || wake.ask(PAIRING, OUT_OF_REACH + WAIT, dial))
        };
        while dials.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }
        let started = Instant::now();
        wake.ask(PAIRING, WAIT, phone(&dials, ANSWERS_AFTER, true));
        assert!(started.elapsed() < WAIT + SCHEDULING_SLACK);
        first.join().expect("the first reading");
        assert_eq!(dials.load(Ordering::SeqCst), 1);
        assert_eq!(wake.learned(PAIRING), None);
        wake.finish();
    }

    #[test]
    fn a_reading_with_no_wait_dials_nothing() {
        let wake = Arc::new(TestWake::new());
        let dials = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        wake.ask(PAIRING, Duration::ZERO, phone(&dials, ANSWERS_AFTER, true));
        assert!(started.elapsed() < SCHEDULING_SLACK);
        wake.finish();
        assert_eq!(dials.load(Ordering::SeqCst), 0);
        assert_eq!(wake.learned(PAIRING), None);
    }

    #[test]
    fn a_dial_that_reads_nothing_keeps_no_certificate_and_a_forgotten_one_goes() {
        let wake = Arc::new(TestWake::new());
        let dials = Arc::new(AtomicUsize::new(0));
        wake.ask(PAIRING, WAIT, phone(&dials, ANSWERS_AFTER, false));
        assert_eq!(wake.learned(PAIRING), None);
        wake.ask(PAIRING, WAIT, phone(&dials, ANSWERS_AFTER, true));
        assert_eq!(wake.learned(PAIRING).as_deref(), Some(CERTIFICATE));
        wake.forget();
        assert_eq!(wake.learned(PAIRING), None);
        assert_eq!(dials.load(Ordering::SeqCst), 2);
        wake.finish();
    }
}
