//! The `RefineID` agent: one per Windows user, started at every sign-in by
//! the machine's `Run` value the installer writes and removes, and running
//! until the user signs out. No Windows service runs.
//!
//! It holds the paired phone's RAPP session over Bluetooth and serves the
//! key storage provider's signature requests on the agent pipe (Windows
//! STPA section 5, W-R-1, W-R-3, W-R-6, W-R-8, W-R-15), and it watches the
//! smart card readers so a FINEID card's certificates stand in the user's
//! Personal store only while that card is in a reader (W-R-22).
//!
//! The pipe thread accepts one provider at a time, reads its request, and
//! hands it to the session thread, which owns the requester, the pairing
//! store and the Bluetooth link. The session thread keeps the session
//! alive with liveness checks, opens it again when it is lost, reads the
//! card's authentication certificate from the phone at every session and
//! keeps it in memory, puts it in the user's store while the phone is
//! present, and runs each request as one `browser_authenticate`. It checks
//! every pairing for idle expiry (RAPP v26.11.2 section 4.6 item 5) each
//! time it reads the pairing store and once a day while it holds a session.
//! The card thread watches the readers.
//!
//! Started from a console, Ctrl+C, Ctrl+Break or closing that console quits
//! the agent: it withdraws (RAPP v26.11.2 section 4.5 item 8), closing its
//! open session with `service_withdrawn` within `QUIT_WITHDRAWAL_BOUND_MS`,
//! withdraws the offer to browsers, keeps the pairing, and exits. Started
//! at sign-in it has no console and shows nothing.
//!
//! A development build reports the agent's failures to the Windows Event
//! Log through `refineid-dev-errors`; a release build writes nothing.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod cards;
#[cfg(windows)]
mod console;
#[cfg(any(windows, test))]
mod offer_gate;
#[cfg(windows)]
mod session;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    session::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the RefineID agent runs on Windows only");
}
