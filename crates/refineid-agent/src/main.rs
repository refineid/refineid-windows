//! The `RefineID` agent: one per Windows user, holding the paired phone's
//! RAPP session over Bluetooth and serving the key storage provider's
//! signature requests on the agent pipe (Windows STPA section 5, W-R-1,
//! W-R-3, W-R-6, W-R-8, W-R-15).
//!
//! The pipe thread accepts one provider at a time, reads its request, and
//! hands it to the session thread, which owns the requester, the pairing
//! store and the Bluetooth link. The session thread keeps the session
//! alive with liveness checks, opens it again when it is lost, puts the
//! pairing's authentication certificate in the user's store while the
//! pairing is usable, and runs each request as one `browser_authenticate`.
//!
//! Ctrl+C, Ctrl+Break or closing its console window quits the agent: it
//! withdraws (RAPP v26.10.22 section 4.5 item 8), closing its open session
//! with `service_withdrawn` within `QUIT_WITHDRAWAL_BOUND_MS`, withdraws
//! the offer to browsers, keeps the pairing, and exits.
//!
//! A development build reports the agent's failures to the Windows Event
//! Log through `refineid-dev-errors`; a release build writes nothing.

#[cfg(windows)]
mod console;
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
