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

//! The errors of a development build, made visible.
//!
//! A debug build (`debug_assertions`) writes every failure a `RefineID`
//! process reports with [`report!`] to the Windows Event Log: the
//! Application log, source `RefineID`, at the error level. Every process
//! that runs `RefineID` code reports there, the app, the agent, the card
//! module inside `lsass.exe`, the browsers and `certutil.exe`, the PKCS#11
//! module, the document signer and the RAPP crates, and the app's Errors
//! window shows the entries as they arrive. The development install
//! registers the source; see `scripts/install-dev.ps1`.
//!
//! An entry carries three strings: the event and its cause
//! (`phone session closed: TransportLoss`), the file name of the reporting
//! program, and how many times the failure came. Its event identifier names
//! the reporting component ([`Component`]); identifier 1 is the app's own.
//! A failure that repeats itself is counted and written again at most once
//! per [`REPEAT_WINDOW`], so a loop that fails the same way on every pass
//! does not flood the log.
//!
//! A cause is a name and nothing else: the case of an error value with
//! every payload that is not itself a case dropped, a fixed text, or a
//! Windows status by its name. A report never carries a PIN, CAN or PUK,
//! their length or digits, a name, certificate content, a serial number,
//! a device name or a pairing identifier.
//!
//! A release build compiles none of this: [`report!`] expands to nothing,
//! so no sink, Event Log import or message text reaches the binary. A
//! `cargo test` binary records nothing, so a test's deliberate failures
//! never reach a developer's own log.

#![cfg_attr(
    all(windows, debug_assertions),
    allow(unsafe_code, reason = "the Windows Event Log boundary")
)]

#[cfg(debug_assertions)]
mod cause;
#[cfg(all(windows, debug_assertions))]
mod event_log;
#[cfg(debug_assertions)]
mod record;
#[cfg(debug_assertions)]
mod status;

#[cfg(debug_assertions)]
pub use cause::Cause;
#[cfg(debug_assertions)]
pub use record::{Component, REPEAT_WINDOW, record};
#[cfg(debug_assertions)]
pub use status::StatusCode;

/// Reports a failure in a development build; expands to nothing in a
/// release build.
///
/// The first argument names the [`Component`], the second is the event, a
/// `&'static str` such as a string literal, and the third is its cause, one
/// of:
///
/// - a string literal, a fixed description;
/// - `status code`, a Windows status (`SCARD_`, `NTE_`, an `HRESULT` or a
///   Win32 error) in a `u32` or `i32` variable, written by its name;
/// - `name expression`, a `&'static str` naming the cause;
/// - a variable holding an error value, written as the case it is
///   ([`Cause::case`]).
///
/// ```ignore
/// refineid_dev_errors::report!(Rapp, "phone session not opened", error);
/// refineid_dev_errors::report!(Reader, "card transmit failed", status rc);
/// ```
///
/// In a release build a variable cause is only borrowed, so it stays used,
/// and nothing else of the call remains.
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! report {
    ($component:ident, $event:expr, $cause:literal) => {
        $crate::record(
            $crate::Component::$component,
            $event,
            &$crate::Cause::text($cause),
        )
    };
    ($component:ident, $event:expr, status $code:ident) => {
        $crate::record(
            $crate::Component::$component,
            $event,
            &$crate::Cause::status($code),
        )
    };
    ($component:ident, $event:expr, name $name:expr) => {
        $crate::record(
            $crate::Component::$component,
            $event,
            &$crate::Cause::text($name),
        )
    };
    ($component:ident, $event:expr, $cause:ident) => {
        $crate::record(
            $crate::Component::$component,
            $event,
            &$crate::Cause::case(&$cause),
        )
    };
}

/// Reports a failure in a development build; expands to nothing in a
/// release build.
#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! report {
    ($component:ident, $event:expr, $cause:literal) => {{}};
    ($component:ident, $event:expr, status $code:ident) => {{
        let _ = &$code;
    }};
    ($component:ident, $event:expr, name $name:expr) => {{}};
    ($component:ident, $event:expr, $cause:ident) => {{
        let _ = &$cause;
    }};
}
