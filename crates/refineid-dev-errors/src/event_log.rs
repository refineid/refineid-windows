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

//! The Windows Event Log: the Application log, source `RefineID`.
//!
//! The development install registers the source with a message file that
//! renders every event identifier as its first string, so Event Viewer
//! shows the message as written. Writing needs no registration: an
//! unregistered source still writes, and Event Viewer then prefaces the
//! strings with a note that the description is missing.

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};

use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, RegisterEventSourceW, ReportEventW,
};

use crate::record::Entry;

/// The event source every `RefineID` process writes as.
const SOURCE: &str = "RefineID";

/// The category of every entry: none.
const NO_CATEGORY: u16 = 0;

/// The size of the raw data every entry carries: none.
const NO_RAW_DATA: u32 = 0;

/// The registered source handle, opened on first use and kept for the
/// life of the process.
static SOURCE_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// `text` as a NUL-terminated UTF-16 string.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// The source handle, opening it on first use; null when Windows refuses.
fn source() -> *mut c_void {
    let cached = SOURCE_HANDLE.load(Ordering::Acquire);
    if !cached.is_null() {
        return cached;
    }
    let name = wide(SOURCE);
    // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the
    // call; a null server name selects the local computer.
    let opened = unsafe { RegisterEventSourceW(core::ptr::null(), name.as_ptr()) };
    if opened.is_null() {
        return opened;
    }
    match SOURCE_HANDLE.compare_exchange(
        core::ptr::null_mut(),
        opened,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => opened,
        Err(winner) => {
            // SAFETY: `opened` came from RegisterEventSourceW above and no
            // other code has seen it.
            unsafe { DeregisterEventSource(opened) };
            winner
        }
    }
}

/// Writes `entry` as an error event from `program`: the message, the
/// program and the number of occurrences, in that order.
pub fn write(entry: &Entry, program: &str) {
    let handle = source();
    if handle.is_null() {
        return;
    }
    let message = wide(&entry.message);
    let program = wide(program);
    let occurrences = wide(&entry.occurrences.to_string());
    let strings = [message.as_ptr(), program.as_ptr(), occurrences.as_ptr()];
    let Ok(string_count) = u16::try_from(strings.len()) else {
        return;
    };
    // SAFETY: `handle` is an open event source; `strings` holds
    // `string_count` pointers to NUL-terminated UTF-16 strings that outlive
    // the call; there is no user SID and no raw data.
    unsafe {
        ReportEventW(
            handle,
            EVENTLOG_ERROR_TYPE,
            NO_CATEGORY,
            entry.component.event_id(),
            core::ptr::null_mut(),
            string_count,
            NO_RAW_DATA,
            strings.as_ptr(),
            core::ptr::null(),
        );
    }
}
