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

//! One reported failure, from the call to the entries written.

use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::cause::Cause;

/// How long a failure that repeats itself is only counted.
///
/// The first report is written at once, and a repeat is written with its
/// count once this long has passed since the last write, or as soon as
/// another failure comes.
pub const REPEAT_WINDOW: Duration = Duration::from_secs(60);

/// The longest entry message kept, in characters.
const MAXIMUM_MESSAGE_CHARACTERS: usize = 240;

/// The directory a `cargo test` binary runs from, under the target
/// directory.
const TEST_BINARY_DIRECTORY: &str = "deps";

/// The part of `RefineID` that reports a failure. Its entries carry the
/// event identifier [`Component::event_id`] names; identifier 1 is the
/// `RefineID` app's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    /// The per-user agent holding the phone's Bluetooth session.
    Agent,
    /// The named pipe between the key storage provider and the agent.
    AgentPipe,
    /// The Bluetooth link to the phone.
    Bluetooth,
    /// The smart card minidriver (Card Module).
    CardModule,
    /// The card-management service behind the app's PIN page.
    CardService,
    /// Document signing and its timestamp authorities.
    DocumentSigning,
    /// The CNG key storage provider for the paired phone.
    KeyStorageProvider,
    /// The PKCS#11 module.
    Pkcs11,
    /// The RAPP requester engine and its stream transport.
    Rapp,
    /// The app's bridge to the RAPP requester.
    RappBridge,
    /// The PC/SC reader adapter.
    Reader,
}

/// Event identifiers, one per component (identifier 1 is the app's).
mod event_id {
    pub(super) const AGENT: u32 = 2;
    pub(super) const AGENT_PIPE: u32 = 3;
    pub(super) const BLUETOOTH: u32 = 4;
    pub(super) const CARD_MODULE: u32 = 5;
    pub(super) const CARD_SERVICE: u32 = 6;
    pub(super) const DOCUMENT_SIGNING: u32 = 7;
    pub(super) const KEY_STORAGE_PROVIDER: u32 = 8;
    pub(super) const PKCS11: u32 = 9;
    pub(super) const RAPP: u32 = 10;
    pub(super) const RAPP_BRIDGE: u32 = 11;
    pub(super) const READER: u32 = 12;
}

impl Component {
    /// The event identifier the component's entries carry.
    #[must_use]
    pub const fn event_id(self) -> u32 {
        match self {
            Self::Agent => event_id::AGENT,
            Self::AgentPipe => event_id::AGENT_PIPE,
            Self::Bluetooth => event_id::BLUETOOTH,
            Self::CardModule => event_id::CARD_MODULE,
            Self::CardService => event_id::CARD_SERVICE,
            Self::DocumentSigning => event_id::DOCUMENT_SIGNING,
            Self::KeyStorageProvider => event_id::KEY_STORAGE_PROVIDER,
            Self::Pkcs11 => event_id::PKCS11,
            Self::Rapp => event_id::RAPP,
            Self::RappBridge => event_id::RAPP_BRIDGE,
            Self::Reader => event_id::READER,
        }
    }
}

/// One entry to write: who reported what, and how many times.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The component that reported.
    pub component: Component,
    /// The event and its cause.
    pub message: String,
    /// How many times the failure came since its last entry.
    pub occurrences: u32,
}

/// The failure this process reported last, and its repeats not yet
/// written.
#[derive(Debug)]
struct Run {
    component: Component,
    message: String,
    written_at: Instant,
    unwritten: u32,
}

/// The last failure of this process, shared by its threads.
static LAST: Mutex<Option<Run>> = Mutex::new(None);

/// Records one failure: `event: cause`, from `component`.
///
/// Never fails and never panics its caller: a report that could break
/// the path it watches would be taken out of it. A `cargo test` binary
/// records nothing.
pub fn record(component: Component, event: &'static str, cause: &Cause) {
    if is_test_binary() {
        return;
    }
    let message = message(event, cause);
    let mut last = LAST.lock().unwrap_or_else(PoisonError::into_inner);
    for entry in observe(&mut last, component, message, Instant::now()) {
        write(&entry);
    }
}

/// `event: cause` on one line, at most [`MAXIMUM_MESSAGE_CHARACTERS`]
/// long.
fn message(event: &str, cause: &Cause) -> String {
    format!("{event}: {}", cause.as_str())
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAXIMUM_MESSAGE_CHARACTERS)
        .collect()
}

/// The entries one report writes at `now`, given the run before it: the
/// earlier failure's unwritten repeats when another failure comes, then
/// the new failure; or a repeat with its count once [`REPEAT_WINDOW`]
/// passed since the run was last written; or nothing.
fn observe(
    last: &mut Option<Run>,
    component: Component,
    message: String,
    now: Instant,
) -> Vec<Entry> {
    if let Some(run) = last.as_mut()
        && run.component == component
        && run.message == message
    {
        run.unwritten = run.unwritten.saturating_add(1);
        if now.saturating_duration_since(run.written_at) < REPEAT_WINDOW {
            return Vec::new();
        }
        let entry = Entry {
            component,
            message,
            occurrences: run.unwritten,
        };
        run.unwritten = 0;
        run.written_at = now;
        return vec![entry];
    }
    let mut entries = Vec::new();
    if let Some(run) = last.take()
        && run.unwritten > 0
    {
        entries.push(Entry {
            component: run.component,
            message: run.message,
            occurrences: run.unwritten,
        });
    }
    entries.push(Entry {
        component,
        message: message.clone(),
        occurrences: 1,
    });
    *last = Some(Run {
        component,
        message,
        written_at: now,
        unwritten: 0,
    });
    entries
}

/// Whether this process is a `cargo test` binary, which runs from the
/// target directory's `deps`.
fn is_test_binary() -> bool {
    static TEST_BINARY: OnceLock<bool> = OnceLock::new();
    *TEST_BINARY.get_or_init(|| {
        std::env::current_exe().is_ok_and(|path| {
            path.parent()
                .and_then(std::path::Path::file_name)
                .is_some_and(|directory| directory == TEST_BINARY_DIRECTORY)
        })
    })
}

/// The file name of this program, as the entries carry it.
#[cfg(windows)]
fn program() -> &'static str {
    static PROGRAM: OnceLock<String> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .unwrap_or_default()
    })
}

/// Writes `entry` to the Windows Event Log.
#[cfg(windows)]
fn write(entry: &Entry) {
    crate::event_log::write(entry, program());
}

/// Off Windows there is no Event Log; nothing is written.
#[cfg(not(windows))]
const fn write(_entry: &Entry) {}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{Component, Entry, REPEAT_WINDOW, observe};

    const FIRST: &str = "phone session closed: TransportLoss";
    const SECOND: &str = "Bluetooth scan failed: RadioUnavailable";
    const MOMENT: Duration = Duration::from_secs(1);

    fn entry(message: &str, occurrences: u32) -> Entry {
        Entry {
            component: Component::Rapp,
            message: message.to_owned(),
            occurrences,
        }
    }

    #[test]
    fn a_new_failure_is_written_at_once() {
        let mut last = None;
        let written = observe(&mut last, Component::Rapp, FIRST.to_owned(), Instant::now());
        assert_eq!(written, vec![entry(FIRST, 1)]);
    }

    #[test]
    fn a_repeat_inside_the_window_is_only_counted() {
        let start = Instant::now();
        let mut last = None;
        observe(&mut last, Component::Rapp, FIRST.to_owned(), start);
        let written = observe(&mut last, Component::Rapp, FIRST.to_owned(), start + MOMENT);
        assert!(written.is_empty());
    }

    #[test]
    fn a_repeat_after_the_window_is_written_with_its_count() {
        let start = Instant::now();
        let mut last = None;
        observe(&mut last, Component::Rapp, FIRST.to_owned(), start);
        observe(&mut last, Component::Rapp, FIRST.to_owned(), start + MOMENT);
        let written = observe(
            &mut last,
            Component::Rapp,
            FIRST.to_owned(),
            start + REPEAT_WINDOW + MOMENT,
        );
        assert_eq!(written, vec![entry(FIRST, 2)]);
    }

    #[test]
    fn another_failure_first_writes_the_counted_repeats() {
        let start = Instant::now();
        let mut last = None;
        observe(&mut last, Component::Rapp, FIRST.to_owned(), start);
        observe(&mut last, Component::Rapp, FIRST.to_owned(), start + MOMENT);
        observe(&mut last, Component::Rapp, FIRST.to_owned(), start + MOMENT);
        let written = observe(
            &mut last,
            Component::Rapp,
            SECOND.to_owned(),
            start + MOMENT,
        );
        assert_eq!(written, vec![entry(FIRST, 2), entry(SECOND, 1)]);
    }

    #[test]
    fn the_same_text_from_another_component_is_another_failure() {
        let start = Instant::now();
        let mut last = None;
        observe(&mut last, Component::Rapp, FIRST.to_owned(), start);
        let written = observe(&mut last, Component::Agent, FIRST.to_owned(), start);
        assert_eq!(
            written,
            vec![Entry {
                component: Component::Agent,
                message: FIRST.to_owned(),
                occurrences: 1,
            }]
        );
    }

    #[test]
    fn a_message_is_one_bounded_line() {
        let long = "x".repeat(super::MAXIMUM_MESSAGE_CHARACTERS);
        let cause = crate::Cause::text("line\nbreak");
        assert_eq!(super::message("event", &cause), "event: line break");
        let leaked: &'static str = Box::leak(long.into_boxed_str());
        let bounded = super::message("event", &crate::Cause::text(leaked));
        assert_eq!(bounded.chars().count(), super::MAXIMUM_MESSAGE_CHARACTERS);
    }

    #[test]
    fn every_component_has_its_own_identifier() {
        let all = [
            Component::Agent,
            Component::AgentPipe,
            Component::Bluetooth,
            Component::CardModule,
            Component::CardService,
            Component::DocumentSigning,
            Component::KeyStorageProvider,
            Component::Pkcs11,
            Component::Rapp,
            Component::RappBridge,
            Component::Reader,
        ];
        let mut identifiers: Vec<u32> = all.iter().map(|component| component.event_id()).collect();
        identifiers.sort_unstable();
        identifiers.dedup();
        assert_eq!(identifiers.len(), all.len());
    }
}
