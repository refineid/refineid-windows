//! The gate every change to the browsers' offer passes through (Windows
//! STPA W-R-8, W-R-16).
//!
//! The session thread installs and removes the phone's certificate while
//! the agent serves; the agent's quit closes the gate and removes the offer
//! for good. Both hold the gate while they act, so the quit's removal runs
//! after any install already under way, and an install that comes after it
//! finds the gate closed and changes nothing.

use std::sync::{Mutex, PoisonError};

/// Serializes the changes to the offer and ends them at the quit.
#[derive(Debug)]
pub struct OfferGate {
    /// Whether the quit closed the gate; it never opens again.
    closed: Mutex<bool>,
}

impl OfferGate {
    /// An open gate.
    pub const fn new() -> Self {
        Self {
            closed: Mutex::new(false),
        }
    }

    /// Runs `change` on the offer while holding the gate, unless the quit
    /// closed it; returns its result, or `None` when it did not run.
    pub fn change<T>(&self, change: impl FnOnce() -> T) -> Option<T> {
        let closed = self.closed.lock().unwrap_or_else(PoisonError::into_inner);
        if *closed {
            return None;
        }
        let changed = change();
        drop(closed);
        Some(changed)
    }

    /// Closes the gate for good and runs `remove` while holding it.
    pub fn close(&self, remove: impl FnOnce()) {
        let mut closed = self.closed.lock().unwrap_or_else(PoisonError::into_inner);
        *closed = true;
        remove();
        drop(closed);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::channel;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use super::OfferGate;

    /// How long the test lets the quit try for the gate while an install
    /// holds it.
    const CLOSE_ATTEMPT_WAIT: Duration = Duration::from_millis(100);

    #[test]
    fn a_change_after_the_close_does_nothing() {
        let gate = OfferGate::new();
        gate.close(|| {});
        assert_eq!(gate.change(|| "installed"), None);
    }

    #[test]
    fn a_change_before_the_close_runs() {
        let gate = OfferGate::new();
        assert_eq!(gate.change(|| "installed"), Some("installed"));
    }

    #[test]
    fn the_close_removes_after_an_install_under_way() {
        let gate = Arc::new(OfferGate::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let (entered, install_entered) = channel();
        let (release, install_released) = channel::<()>();

        let installing = {
            let gate = Arc::clone(&gate);
            let events = Arc::clone(&events);
            thread::spawn(move || {
                gate.change(|| {
                    entered.send(()).expect("the test waits for the install");
                    install_released
                        .recv()
                        .expect("the test releases the install");
                    events.lock().expect("events").push("install");
                })
            })
        };
        install_entered.recv().expect("the install holds the gate");

        let closing = {
            let gate = Arc::clone(&gate);
            let events = Arc::clone(&events);
            thread::spawn(move || gate.close(|| events.lock().expect("events").push("remove")))
        };
        thread::sleep(CLOSE_ATTEMPT_WAIT);
        assert!(!closing.is_finished());
        assert!(events.lock().expect("events").is_empty());

        release.send(()).expect("the install waits for its release");
        assert_eq!(installing.join().expect("install"), Some(()));
        closing.join().expect("close");
        assert_eq!(*events.lock().expect("events"), ["install", "remove"]);
        assert_eq!(gate.change(|| "installed"), None);
    }
}
