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

//! Narrow C ABI for the `RefineID` Windows remote-card UI.
//!
//! Raw pointers end in this crate. The typed pairing code and the display
//! name are copied into owned Rust strings before use. The
//! requester never holds a CAN, PIN, or PUK, so none can cross this boundary;
//! the phone-side proxy owns every credential. Public identity fields (the
//! cardholder name and personal identifier) do cross in the JSON reply
//! because the UI displays them, but they never enter a log.
//!
//! The requester is long-lived, so this ABI is handle-based: a caller begins
//! a pairing with the code the phone shows, polls its state, confirms it,
//! then reads the paired card. Each handle owns one background pairing
//! thread that finds the phone by its DNS-SD `mode=pairing` record and dials
//! it (RAPP v26.10.18 section 2.2), and, after pairing, the live `Requester`
//! whose device-only credential store persists the pairing so the minidriver
//! can later load and use it behind this same ABI. After a card read the
//! handle also holds the offering session of section 8.4 on a watch thread:
//! the phone's certificate is offered to browsers only while that session
//! reports a card, and withdrawn the moment it closes, the card leaves, or
//! the phone announces it forgot this computer. This computer only ever
//! dials out; it listens on no port.

#![expect(
    unsafe_code,
    reason = "this crate is the deliberately narrow C ABI boundary used by the C# UI process"
)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::c_char;
use std::collections::HashMap;
use std::ffi::CString;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::thread::JoinHandle;

use refineid_rapp::ProgressEvent;
use refineid_rapp_core::engine::{
    OperationOutcome, PairingError, PeerIntroduction, Requester, RequesterConfig, SessionEnd,
};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::CloseReason;
use refineid_rapp_core::offer::normalize_pairing_code;
use refineid_rapp_core::operations::{CardOperation, CardOperationResult};
use refineid_rapp_core::store::{MemoryJournal, PairingDisposition, PairingRecord, PairingStore};
use refineid_rapp_core::stream::{
    DialPurpose, DiscoveryMode, STREAM_CANDIDATE_ID, StreamError, browse, dial, dial_session,
};
use refineid_windows_credential_store::{ProtectedPairingStore, delete_pairing_set};
#[cfg(windows)]
use refineid_windows_credential_store::{install_browser_certificate, remove_browser_certificates};
use serde::Serialize;

/// Frame receive deadline on a dialed stream connection.
const RECEIVE_DEADLINE_MS: u64 = 60_000;

/// How long one DNS-SD browse listens for custodian records.
const BROWSE_WINDOW_MS: u64 = 3_000;

/// Browse rounds a pairing makes before reporting that no phone is in
/// pairing mode; together they span the 60 s offer lifetime.
const MAX_PAIRING_BROWSE_ROUNDS: u32 = 20;

/// Browse rounds a card read makes before reporting that the paired phone
/// is not on the network.
const MAX_SESSION_BROWSE_ROUNDS: u32 = 3;

/// Operation expiry sent on the wire; the holder approves within this.
const OPERATION_EXPIRY_MS: u64 = 120_000;

/// Longest typed pairing code accepted, in bytes, before normalization.
const MAX_CODE_BYTES: usize = 64;

/// Longest requester display name accepted, in bytes.
const MAX_NAME_BYTES: usize = 256;

/// Longest granted-profile JSON array accepted, in bytes.
const MAX_GRANTED_BYTES: usize = 4_096;

/// Frame receive deadline on the offering session: a liveness answer or a
/// card status arrives well within it.
const WATCH_RECEIVE_DEADLINE_MS: u64 = 15_000;

/// Pause between liveness pings on the offering session.
const LIVENESS_INTERVAL_MS: u64 = 10_000;

/// Pause before the watch dials the phone again after losing it.
const WATCH_RETRY_MS: u64 = 15_000;

/// How long the forget action browses for the phone to tell it, once.
const FORGET_BROWSE_WINDOW_MS: u64 = 1_500;

/// Shown while the phone's consent view is on screen.
const CONSENT_SHOWN_STATUS: &str = "Approve the request on your phone.";

/// Shown while the offering session reports no card on the phone.
const CARD_ABSENT_STATUS: &str = "The phone has no card.";

/// Shown while the phone cannot be reached and nothing is offered.
const PHONE_UNREACHABLE_STATUS: &str = "The phone is not reachable.";

/// Shown once the phone announced it forgot this computer.
const REVOKED_STATUS: &str = "The phone forgot this computer. Pair again.";

/// Shown when the store holds no confirmed pairing for the watch to serve.
const NO_PAIRING_STATUS: &str = "No phone is paired with this device.";

/// The requester engine specialised to the device-only credential-store
/// pairing store and the in-memory operation journal.
type StreamRequester = Requester<ProtectedPairingStore, MemoryJournal>;

#[derive(Debug)]
struct ApiFailure {
    code: &'static str,
    message: String,
}

impl ApiFailure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Serialize)]
struct ApiError<'a> {
    code: &'a str,
    message: &'a str,
}

#[derive(Serialize)]
struct ApiEnvelope<'a, T> {
    ok: bool,
    data: Option<&'a T>,
    error: Option<ApiError<'a>>,
}

#[derive(Serialize)]
struct BeginPairingDto {
    handle: u64,
}

#[derive(Serialize)]
struct PairingStateDto {
    state: &'static str,
    peer: Option<PeerDto>,
    pair_id_hex: Option<String>,
    message: Option<String>,
    /// What the offering session last heard about the phone's card; absent
    /// until a session reports it.
    card_present: Option<bool>,
}

#[derive(Serialize)]
struct PeerDto {
    display_name: String,
    platform: String,
    profiles: Vec<String>,
}

#[derive(Serialize)]
struct AckDto {
    ok: bool,
}

#[derive(Serialize)]
struct CardReadDto {
    identity: IdentityDto,
}

#[derive(Serialize)]
struct IdentityDto {
    display_name: String,
    person_id: String,
}

/// The phase of one pairing handle, shared between the background thread and
/// the calling threads that poll and confirm it.
enum Phase {
    Offer,
    AwaitingConfirmation {
        display_name: String,
        platform: String,
        profiles: Vec<String>,
    },
    Paired {
        pair_id_hex: String,
    },
    Denied,
    Cancelled,
    Failed(String),
}

/// The live requester, parked here once pairing succeeds so a later read can
/// drive the card on the caller's thread.
struct Paired {
    requester: StreamRequester,
    pair_id: PairId,
    pairing: refineid_rapp::PairRecord,
}

/// State a pairing handle shares across threads.
struct Shared {
    phase: Phase,
    decision_tx: Option<Sender<Option<Vec<String>>>>,
    end_requested: bool,
    paired: Option<Paired>,
    /// The phone's card as the offering session last reported it.
    card_present: Option<bool>,
    /// A line for the user about the phone, or nothing.
    status: Option<String>,
    /// Whether the offering watch thread runs for this handle.
    watching: bool,
    /// Whether an operation runs on this handle; the watch leaves the
    /// phone alone while one does.
    operation_in_flight: bool,
}

/// One pairing handle: its shared state and the background pairing thread.
struct Handle {
    shared: Mutex<Shared>,
    thread: Option<JoinHandle<()>>,
}

static REGISTRY: LazyLock<Mutex<HashMap<u64, Handle>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Free a UTF-8 JSON string returned by this library.
///
/// `json` must be either null or a pointer returned by one of the
/// `refineid_rapp_*` functions in this library.
///
/// # Safety
///
/// A non-null `json` must be an unmodified pointer returned by this library,
/// and the caller must pass it to this function exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_rapp_string_free(json: *mut c_char) {
    if json.is_null() {
        return;
    }
    // SAFETY: The C ABI contract above requires a pointer produced by
    // CString::into_raw in reply_json. Reconstructing it exactly once returns
    // the allocation to Rust.
    drop(unsafe { CString::from_raw(json) });
}

/// Forget every stored pairing, clearing the device-only credential.
///
/// This is the holder's local forget action: it destroys the stored pair
/// keys so no session can be opened against them again. It does not notify the
/// peer, matching the specification's `forget_pairing` rather than
/// `local_revoke`. Clearing an empty store succeeds, so the action is
/// idempotent.
#[unsafe(no_mangle)]
pub extern "C" fn refineid_rapp_forget_pairings() -> *mut c_char {
    reply_json(|| {
        forget_browser_certificates();
        tell_phones_they_are_forgotten();
        delete_pairing_set()
            .map_err(|error| ApiFailure::new("forget_failed", format!("{error}")))?;
        Ok(AckDto { ok: true })
    })
}

/// Tells each paired phone that this computer is forgetting it, over one
/// short-lived session, before the pairings are deleted (RAPP v26.10.18
/// section 4.6 item 1). A phone that is not on the network learns nothing
/// and is forgotten regardless.
fn tell_phones_they_are_forgotten() {
    let Ok(store) = ProtectedPairingStore::load() else {
        return;
    };
    let usable = forgettable_pairs(store.records());
    let mut requester = Requester::new(
        RequesterConfig {
            display_name: String::new(),
            platform: "Windows".to_owned(),
        },
        store,
        MemoryJournal::new(),
    );
    for (pair_id, pairing) in usable {
        let transport = dial_session(
            &pairing,
            &[],
            &[],
            std::time::Duration::from_millis(FORGET_BROWSE_WINDOW_MS),
            receive_deadline(),
        )
        .ok();
        requester.forget_pairing(pair_id, transport);
    }
}

/// The pairings a forget action tells about: every one the phone confirmed
/// and that still holds keys, not only the one a read would use.
fn forgettable_pairs(records: &[PairingRecord]) -> Vec<(PairId, refineid_rapp::PairRecord)> {
    records
        .iter()
        .filter(|record| {
            record.disposition == PairingDisposition::Paired && record.storage_confirmed
        })
        .filter_map(|record| {
            record
                .to_core_pair_record()
                .ok()
                .map(|pairing| (record.pair_id, pairing))
        })
        .collect()
}

/// Open the pairing this device already holds, without a new ceremony.
///
/// Returns `{ handle }` parked in the paired state, so
/// [`refineid_rapp_read_card`] drives the card through the stored pairing,
/// or `no_pairing` when the store holds no usable one. The handle is
/// released with [`refineid_rapp_end_pairing`] like any other.
///
/// # Safety
///
/// `name` must address `name_length` readable UTF-8 bytes for the duration
/// of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_rapp_open_pairing(
    name: *const u8,
    name_length: usize,
) -> *mut c_char {
    reply_json(|| {
        // SAFETY: The input is pointer- and bound-checked before the slice
        // is formed, then copied into owned Rust before use.
        let name = unsafe { copy_utf8(name, name_length, MAX_NAME_BYTES, "name") }?;
        open_pairing(name)
    })
}

/// Begin a pairing with the code the phone shows.
///
/// Returns `{ handle }` immediately, or `invalid_code` when the input is not
/// a six-character pairing code (RAPP v26.10.10 section 3.1). The background
/// thread finds the phone in pairing mode, dials it, reads its offer, and
/// runs the pairing handshake; the caller drives confirmation through
/// [`refineid_rapp_poll_pairing`] and [`refineid_rapp_confirm_pairing`].
///
/// # Safety
///
/// Each pointer must address the accompanying number of readable bytes for
/// the duration of the call, and both inputs must be UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_rapp_begin_pairing(
    code: *const u8,
    code_length: usize,
    name: *const u8,
    name_length: usize,
) -> *mut c_char {
    reply_json(|| {
        // SAFETY: Each input is pointer- and bound-checked before the slice
        // is formed, then copied into owned Rust before use.
        let code = unsafe { copy_utf8(code, code_length, MAX_CODE_BYTES, "code") }?;
        // SAFETY: As above.
        let name = unsafe { copy_utf8(name, name_length, MAX_NAME_BYTES, "name") }?;
        if normalize_pairing_code(&code).is_none() {
            return Err(ApiFailure::new(
                "invalid_code",
                "Type the six characters the phone shows.",
            ));
        }
        begin_pairing(code, name)
    })
}

/// Poll the state of a pairing handle.
#[allow(
    clippy::significant_drop_tightening,
    reason = "the guard yields a borrow that must outlive it in this lock chain"
)]
#[unsafe(no_mangle)]
pub extern "C" fn refineid_rapp_poll_pairing(handle: u64) -> *mut c_char {
    reply_json(|| {
        let registry = lock_registry()?;
        let entry = registry
            .get(&handle)
            .ok_or_else(|| ApiFailure::new("unknown_handle", "No such pairing handle."))?;
        let shared = lock_shared(&entry.shared)?;
        Ok(handle_state(&shared))
    })
}

/// Confirm a pairing awaiting the caller's decision.
///
/// `granted` is a JSON array of profile names, or empty to grant exactly the
/// profiles the peer requested.
///
/// # Safety
///
/// `granted` must address `granted_length` readable UTF-8 bytes, or be null
/// with a zero length to grant every requested profile.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_rapp_confirm_pairing(
    handle: u64,
    granted: *const u8,
    granted_length: usize,
) -> *mut c_char {
    reply_json(|| {
        let profiles = if granted_length == 0 {
            Vec::new()
        } else {
            // SAFETY: pointer- and bound-checked before the slice is formed.
            let text = unsafe { copy_utf8(granted, granted_length, MAX_GRANTED_BYTES, "granted") }?;
            serde_json::from_str::<Vec<String>>(&text).map_err(|_| {
                ApiFailure::new(
                    "invalid_granted",
                    "The granted profiles must be a JSON array of strings.",
                )
            })?
        };
        deliver_decision(handle, Some(profiles))?;
        Ok(AckDto { ok: true })
    })
}

/// Deny or cancel a pairing awaiting the caller's decision.
#[unsafe(no_mangle)]
pub extern "C" fn refineid_rapp_cancel_pairing(handle: u64) -> *mut c_char {
    reply_json(|| {
        deliver_decision(handle, None)?;
        Ok(AckDto { ok: true })
    })
}

/// Read the paired card: card status, identity, and the authentication
/// certificate length. Blocks until the phone dials a session for this
/// pairing, then runs the safe reads and closes the session.
///
/// The returned identity fields are shown to the user; no card data is
/// logged. Signing is not yet exposed: `browser_authenticate` and
/// `sign_document` need a digest input and a per-operation approval on the
/// phone and will be added here next.
#[unsafe(no_mangle)]
pub extern "C" fn refineid_rapp_read_card(handle: u64) -> *mut c_char {
    reply_json(|| {
        // Take the paired card out under a brief lock so the blocking read
        // does not hold the global registry while it waits for a session.
        let mut paired = take_paired(handle)?;
        let result = read_paired_card(handle, &mut paired);
        restore_paired(handle, paired);
        if result.is_ok() {
            start_offering_watch(handle);
        }
        result
    })
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "the guard yields a borrow that must outlive it in this lock chain"
)]
fn take_paired(handle: u64) -> Result<Paired, ApiFailure> {
    let registry = lock_registry()?;
    let entry = registry
        .get(&handle)
        .ok_or_else(|| ApiFailure::new("unknown_handle", "No such pairing handle."))?;
    let mut shared = lock_shared(&entry.shared)?;
    shared.paired.take().ok_or_else(|| {
        ApiFailure::new(
            "not_paired",
            "This handle has no paired card, or a read is already in progress.",
        )
    })
}

fn restore_paired(handle: u64, paired: Paired) {
    if let Ok(registry) = REGISTRY.lock()
        && let Some(entry) = registry.get(&handle)
        && let Ok(mut shared) = entry.shared.lock()
    {
        shared.paired = Some(paired);
    }
}

/// End a pairing: stop its background thread and release the handle.
#[unsafe(no_mangle)]
pub extern "C" fn refineid_rapp_end_pairing(handle: u64) -> *mut c_char {
    reply_json(|| {
        let removed = {
            let mut registry = lock_registry()?;
            registry.remove(&handle)
        };
        let Some(mut entry) = removed else {
            return Ok(AckDto { ok: true });
        };
        // Release a thread waiting for a decision. A thread blocked on the
        // network finishes on its receive deadline, sees the handle gone,
        // and drops the requester it owns; it is not joined here.
        let watching = entry.shared.lock().is_ok_and(|mut shared| {
            shared.end_requested = true;
            if let Some(decision_tx) = shared.decision_tx.take() {
                let _ = decision_tx.send(None);
            }
            shared.watching
        });
        if watching {
            // The offering session ends with its handle; so does the offer.
            forget_browser_certificates();
        }
        drop(entry.thread.take());
        Ok(AckDto { ok: true })
    })
}

fn begin_pairing(code: String, name: String) -> Result<BeginPairingDto, ApiFailure> {
    let pairing_store = ProtectedPairingStore::load()
        .map_err(|error| ApiFailure::new("pairing_store_unavailable", format!("{error}")))?;
    let requester = Requester::new(
        RequesterConfig {
            display_name: name,
            platform: "Windows".to_owned(),
        },
        pairing_store,
        MemoryJournal::new(),
    );

    let handle_id = register_handle(Shared {
        phase: Phase::Offer,
        decision_tx: None,
        end_requested: false,
        paired: None,
        card_present: None,
        status: None,
        watching: false,
        operation_in_flight: false,
    })?;
    // The thread reaches the shared state through the registry by handle id,
    // owning the pieces it moves and locking only briefly each time.
    let thread = std::thread::spawn(move || {
        pairing_thread(handle_id, requester, &code);
    });
    if let Ok(mut registry) = lock_registry()
        && let Some(entry) = registry.get_mut(&handle_id)
    {
        entry.thread = Some(thread);
    }
    Ok(BeginPairingDto { handle: handle_id })
}

fn open_pairing(name: String) -> Result<BeginPairingDto, ApiFailure> {
    let pairing_store = ProtectedPairingStore::load()
        .map_err(|error| ApiFailure::new("pairing_store_unavailable", format!("{error}")))?;
    let record = pairing_store
        .usable_pairing()
        .ok_or_else(|| ApiFailure::new("no_pairing", "No phone is paired with this device."))?;
    let pair_id = record.pair_id;
    let pairing = record.to_core_pair_record().map_err(|_| {
        ApiFailure::new(
            "pairing_unusable",
            "The stored pairing is unusable; pair the phone again.",
        )
    })?;
    let requester = Requester::new(
        RequesterConfig {
            display_name: name,
            platform: "Windows".to_owned(),
        },
        pairing_store,
        MemoryJournal::new(),
    );
    let handle_id = register_handle(Shared {
        phase: Phase::Paired {
            pair_id_hex: hex::encode(pair_id.as_bytes()),
        },
        decision_tx: None,
        end_requested: false,
        paired: Some(Paired {
            requester,
            pair_id,
            pairing,
        }),
        card_present: None,
        status: None,
        watching: false,
        operation_in_flight: false,
    })?;
    Ok(BeginPairingDto { handle: handle_id })
}

/// Parks shared state in the registry under a fresh handle id.
fn register_handle(shared: Shared) -> Result<u64, ApiFailure> {
    let handle_id = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    lock_registry()?.insert(
        handle_id,
        Handle {
            shared: Mutex::new(shared),
            thread: None,
        },
    );
    Ok(handle_id)
}

/// Finds a phone in pairing mode, dials it with the pairing preamble, and
/// pairs with the typed code. A phone that cannot be reached is skipped;
/// a mistyped code or a refused pairing ends the attempt.
fn pairing_thread(handle_id: u64, mut requester: StreamRequester, code: &str) {
    for _ in 0..MAX_PAIRING_BROWSE_ROUNDS {
        if ended(handle_id) {
            return;
        }
        for service in browse(DiscoveryMode::Pairing, browse_window()) {
            if ended(handle_id) {
                return;
            }
            let Ok(transport) = dial(
                &service.endpoints,
                STREAM_CANDIDATE_ID,
                receive_deadline(),
                DialPurpose::Pairing,
            ) else {
                continue;
            };
            let (decision_tx, decision_rx) = channel::<Option<Vec<String>>>();
            if !publish_decision_sender(handle_id, decision_tx) {
                return;
            }
            let confirm = |peer: &PeerIntroduction, offered: &[String]| -> Option<Vec<String>> {
                set_awaiting(handle_id, peer, offered);
                match decision_rx.recv() {
                    Ok(Some(granted)) => Some(if granted.is_empty() {
                        offered.to_vec()
                    } else {
                        granted
                    }),
                    Ok(None) | Err(_) => None,
                }
            };
            match requester.pair_with_code(code, transport, confirm) {
                Ok(pair_id) => {
                    finish_pairing(handle_id, requester, pair_id);
                    return;
                }
                Err(error) => {
                    if fail_attempt(handle_id, error) {
                        return;
                    }
                }
            }
        }
    }
    set_phase(
        handle_id,
        Phase::Failed("No phone in pairing mode was found on this network.".to_owned()),
    );
}

fn finish_pairing(handle_id: u64, mut requester: StreamRequester, pair_id: PairId) {
    // This device holds one phone. A pairing made afresh replaces whatever
    // was stored before, dead or alive, together with the certificate the
    // old phone left for browsers; the first read places the new one.
    let stale: Vec<PairId> = requester
        .store()
        .pair_ids()
        .into_iter()
        .filter(|stored| *stored != pair_id)
        .collect();
    if !stale.is_empty() {
        forget_browser_certificates();
        for stored in stale {
            let _ = requester.store_mut().remove(stored);
        }
    }
    let Ok(record) = requester.store().get(pair_id) else {
        set_phase(
            handle_id,
            Phase::Failed("The stored pairing could not be read.".to_owned()),
        );
        return;
    };
    let Ok(pairing) = record.to_core_pair_record() else {
        set_phase(
            handle_id,
            Phase::Failed("The stored pairing could not be read.".to_owned()),
        );
        return;
    };
    let pair_id_hex = hex::encode(pair_id.as_bytes());
    // If the handle is gone, the closure is never run and the moved
    // requester is dropped here instead.
    let _stored = registry_entry_apply(handle_id, move |shared| {
        shared.decision_tx = None;
        shared.phase = Phase::Paired { pair_id_hex };
        shared.paired = Some(Paired {
            requester,
            pair_id,
            pairing,
        });
    });
}

fn read_paired_card(handle_id: u64, paired: &mut Paired) -> Result<CardReadDto, ApiFailure> {
    let mut outcome = Err(StreamError::Unreachable);
    for _ in 0..MAX_SESSION_BROWSE_ROUNDS {
        outcome = dial_session(
            &paired.pairing,
            &[],
            &[],
            browse_window(),
            receive_deadline(),
        );
        if matches!(
            outcome,
            Ok(_) | Err(StreamError::Withdrawn | StreamError::Revoked)
        ) {
            break;
        }
    }
    let session_transport = outcome.map_err(|error| match error {
        StreamError::Withdrawn => {
            ApiFailure::new("withdrawn", "The paired phone turned remote access off.")
        }
        StreamError::Revoked => {
            paired.requester.apply_verified_revocation(paired.pair_id);
            forget_browser_certificates();
            ApiFailure::new("revoked", REVOKED_STATUS)
        }
        _ => ApiFailure::new(
            "no_session",
            "The paired phone was not found on this network.",
        ),
    })?;

    let mut session = paired
        .requester
        .connect(paired.pair_id, session_transport)
        .map_err(|error| ApiFailure::new("session_failed", format!("{error:?}")))?;

    // The requester screen shows only the holder identity, so the read is one
    // operation and the phone reads the card once. The answer carries the
    // authentication certificate, which browsers need through the key
    // storage provider: on the pairing record for signing, and, once the
    // offering session reports the card, in the user's certificate store so
    // Edge and Chrome offer it.
    let (identity, certificate) = match run_operation(
        handle_id,
        paired,
        &mut session,
        &CardOperation::ReadIdentity,
    )? {
        CardOperationResult::Identity(mut identity) => {
            let certificate = identity.certificates.drain(..).next();
            (
                IdentityDto {
                    display_name: identity.holder_name,
                    person_id: identity.card_id,
                },
                certificate,
            )
        }
        _ => return Err(unexpected_result("read_identity")),
    };

    paired
        .requester
        .disconnect(&mut session, CloseReason::UserDisconnect);

    let certificate = certificate.ok_or_else(|| {
        ApiFailure::new(
            "no_certificate",
            "The phone sent no certificate with the identity.",
        )
    })?;
    remember_certificate(paired, &certificate);

    Ok(CardReadDto { identity })
}

/// Starts the offering watch for a handle that has none yet.
fn start_offering_watch(handle_id: u64) {
    let started = registry_entry_apply(handle_id, |shared| {
        let fresh = !shared.watching;
        shared.watching = true;
        fresh
    });
    if started == Some(true) {
        std::thread::spawn(move || offering_watch(handle_id));
    }
}

/// The offering session of section 8.4: holds a session to the paired phone
/// for as long as the handle lives, offers the phone's certificate to
/// browsers while that session reports a card, and withdraws it the moment
/// the session ends, the card leaves, or the phone announces it forgot this
/// computer.
fn offering_watch(handle_id: u64) {
    let _mark = WatchMark(handle_id);
    let mut offered = false;
    while !ended(handle_id) {
        let Ok(store) = ProtectedPairingStore::load() else {
            withdraw_offer(handle_id, &mut offered, PHONE_UNREACHABLE_STATUS);
            pause(WATCH_RETRY_MS);
            continue;
        };
        let Some((pair_id, pairing, certificate)) = store.usable_pairing().and_then(|record| {
            record
                .to_core_pair_record()
                .ok()
                .map(|pairing| (record.pair_id, pairing, record.auth_cert.clone()))
        }) else {
            withdraw_offer(handle_id, &mut offered, NO_PAIRING_STATUS);
            return;
        };
        let mut requester = Requester::new(
            RequesterConfig {
                display_name: String::new(),
                platform: "Windows".to_owned(),
            },
            store,
            MemoryJournal::new(),
        );
        let transport = match dial_session(
            &pairing,
            &[],
            &[],
            browse_window(),
            std::time::Duration::from_millis(WATCH_RECEIVE_DEADLINE_MS),
        ) {
            Ok(transport) => transport,
            Err(StreamError::Revoked) => {
                requester.apply_verified_revocation(pair_id);
                withdraw_offer(handle_id, &mut offered, REVOKED_STATUS);
                set_phase(handle_id, Phase::Failed(REVOKED_STATUS.to_owned()));
                return;
            }
            Err(_) => {
                withdraw_offer(handle_id, &mut offered, PHONE_UNREACHABLE_STATUS);
                pause(WATCH_RETRY_MS);
                continue;
            }
        };
        let Ok(mut session) = requester.connect(pair_id, transport) else {
            withdraw_offer(handle_id, &mut offered, PHONE_UNREACHABLE_STATUS);
            pause(WATCH_RETRY_MS);
            continue;
        };
        while !ended(handle_id) {
            // An operation in flight has the phone's attention; a ping it
            // answers late must not read as the phone leaving.
            if operation_in_flight(handle_id) {
                pause(LIVENESS_INTERVAL_MS);
                continue;
            }
            if requester.check_liveness(&mut session).is_err() {
                break;
            }
            let present = session.card_present();
            registry_entry_apply(handle_id, |shared| shared.card_present = present);
            match present {
                Some(true) => {
                    if !offered
                        && let Some(certificate) = &certificate
                        && offer_to_browsers(certificate, pair_id).is_ok()
                    {
                        offered = true;
                    }
                    clear_watch_status(handle_id);
                }
                Some(false) => withdraw_offer(handle_id, &mut offered, CARD_ABSENT_STATUS),
                None => {}
            }
            pause(LIVENESS_INTERVAL_MS);
        }
        let revoked = matches!(
            StreamRequester::session_end(&session),
            Some(SessionEnd::PeerClose(CloseReason::PairingRevoked))
        );
        if revoked {
            withdraw_offer(handle_id, &mut offered, REVOKED_STATUS);
            set_phase(handle_id, Phase::Failed(REVOKED_STATUS.to_owned()));
            return;
        }
        withdraw_offer(handle_id, &mut offered, PHONE_UNREACHABLE_STATUS);
        if !ended(handle_id) {
            pause(WATCH_RETRY_MS);
        }
    }
    withdraw_offer(handle_id, &mut offered, PHONE_UNREACHABLE_STATUS);
}

/// Marks the handle as watched for the thread's lifetime; dropping it on
/// any exit lets the next read start a watch again.
struct WatchMark(u64);

impl Drop for WatchMark {
    fn drop(&mut self) {
        registry_entry_apply(self.0, |shared| shared.watching = false);
    }
}

/// Whether `status` is a line the offering watch wrote, as opposed to one an
/// operation wrote about its own progress.
fn is_watch_status(status: &str) -> bool {
    matches!(
        status,
        PHONE_UNREACHABLE_STATUS | CARD_ABSENT_STATUS | NO_PAIRING_STATUS
    )
}

/// Removes the watch's own line and leaves an operation's line in place.
fn clear_watch_status(handle_id: u64) {
    registry_entry_apply(handle_id, |shared| {
        if shared.status.as_deref().is_some_and(is_watch_status) {
            shared.status = None;
        }
    });
}

fn operation_in_flight(handle_id: u64) -> bool {
    registry_entry_apply(handle_id, |shared| shared.operation_in_flight).unwrap_or(false)
}

/// Withdraws the offer, if one stands, and tells the user why.
fn withdraw_offer(handle_id: u64, offered: &mut bool, status: &str) {
    if *offered {
        forget_browser_certificates();
        *offered = false;
    }
    registry_entry_apply(handle_id, |shared| {
        shared.status = Some(status.to_owned());
    });
}

fn pause(milliseconds: u64) {
    std::thread::sleep(std::time::Duration::from_millis(milliseconds));
}

/// Keeps the authentication certificate on the pairing record, where the
/// key storage provider reads it when a browser asks for a signature.
fn remember_certificate(paired: &mut Paired, certificate: &[u8]) {
    // A refused write only means the next read stores it again.
    let _ = paired
        .requester
        .store_mut()
        .update(paired.pair_id, &mut |record| {
            record.auth_cert = Some(certificate.to_vec());
        });
}

/// Places the certificate in the user's certificate store, bound to the
/// `RefineID` key storage provider, so Edge and Chrome offer it.
#[cfg(windows)]
fn offer_to_browsers(certificate: &[u8], pair_id: PairId) -> Result<(), ApiFailure> {
    install_browser_certificate(certificate, pair_id)
        .map_err(|error| ApiFailure::new("certificate_store_failed", format!("{error}")))
}

#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the Windows arm fails; this one keeps the caller's signature"
)]
const fn offer_to_browsers(_certificate: &[u8], _pair_id: PairId) -> Result<(), ApiFailure> {
    Ok(())
}

/// Removes the certificates the app placed for browsers.
#[cfg(windows)]
fn forget_browser_certificates() {
    // Forgetting the pairing is the action that matters; a certificate
    // left behind opens nothing without it.
    let _ = remove_browser_certificates();
}

#[cfg(not(windows))]
const fn forget_browser_certificates() {}

fn run_operation(
    handle_id: u64,
    paired: &mut Paired,
    session: &mut refineid_rapp_core::engine::Session<
        refineid_rapp_core::transport::TcpFrameTransport,
    >,
    operation: &CardOperation,
) -> Result<CardOperationResult, ApiFailure> {
    registry_entry_apply(handle_id, |shared| shared.operation_in_flight = true);
    let outcome =
        paired
            .requester
            .execute_observed(session, operation, OPERATION_EXPIRY_MS, &mut |event| {
                if event == ProgressEvent::ConsentShown {
                    registry_entry_apply(handle_id, |shared| {
                        shared.status = Some(CONSENT_SHOWN_STATUS.to_owned());
                    });
                }
            });
    registry_entry_apply(handle_id, |shared| {
        shared.operation_in_flight = false;
        shared.status = None;
    });
    let outcome =
        outcome.map_err(|error| ApiFailure::new("operation_not_admitted", format!("{error:?}")))?;
    match outcome {
        OperationOutcome::Completed(result) => Ok(result),
        OperationOutcome::Denied => Err(ApiFailure::new(
            "denied",
            "The holder denied the request on the phone.",
        )),
        OperationOutcome::Cancelled => Err(ApiFailure::new(
            "cancelled",
            "The request was cancelled or expired.",
        )),
        OperationOutcome::Rejected(reason) => Err(ApiFailure::new(
            "rejected",
            reason.unwrap_or_else(|| "The request was rejected.".to_owned()),
        )),
        OperationOutcome::CredentialRejected => Err(ApiFailure::new(
            "credential_rejected",
            "A credential was rejected; the pairing is revoked on both devices.",
        )),
        OperationOutcome::Ambiguous => Err(ApiFailure::new(
            "ambiguous",
            "The card result is unproven and will not be retried.",
        )),
    }
}

fn unexpected_result(action: &str) -> ApiFailure {
    ApiFailure::new(
        "unexpected_result",
        format!("The card returned an unexpected result for {action}."),
    )
}

/// The handle's state as the caller sees it: the phase, and, once a card
/// has been read, what the offering session says about the phone.
fn handle_state(shared: &Shared) -> PairingStateDto {
    let mut dto = state_dto(&shared.phase);
    dto.card_present = shared.card_present;
    if dto.message.is_none() {
        dto.message.clone_from(&shared.status);
    }
    dto
}

fn state_dto(phase: &Phase) -> PairingStateDto {
    match phase {
        Phase::Offer => PairingStateDto {
            state: "offer",
            peer: None,
            pair_id_hex: None,
            message: None,
            card_present: None,
        },
        Phase::AwaitingConfirmation {
            display_name,
            platform,
            profiles,
        } => PairingStateDto {
            state: "awaiting_confirmation",
            peer: Some(PeerDto {
                display_name: display_name.clone(),
                platform: platform.clone(),
                profiles: profiles.clone(),
            }),
            pair_id_hex: None,
            message: None,
            card_present: None,
        },
        Phase::Paired { pair_id_hex } => PairingStateDto {
            state: "paired",
            peer: None,
            pair_id_hex: Some(pair_id_hex.clone()),
            message: None,
            card_present: None,
        },
        Phase::Denied => PairingStateDto {
            state: "denied",
            peer: None,
            pair_id_hex: None,
            message: None,
            card_present: None,
        },
        Phase::Cancelled => PairingStateDto {
            state: "cancelled",
            peer: None,
            pair_id_hex: None,
            message: None,
            card_present: None,
        },
        Phase::Failed(message) => PairingStateDto {
            state: "failed",
            peer: None,
            pair_id_hex: None,
            message: Some(message.clone()),
            card_present: None,
        },
    }
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "the guard yields a borrow that must outlive it in this lock chain"
)]
fn deliver_decision(handle: u64, decision: Option<Vec<String>>) -> Result<(), ApiFailure> {
    let registry = lock_registry()?;
    let entry = registry
        .get(&handle)
        .ok_or_else(|| ApiFailure::new("unknown_handle", "No such pairing handle."))?;
    let mut shared = lock_shared(&entry.shared)?;
    let is_deny = decision.is_none();
    let Some(decision_tx) = shared.decision_tx.take() else {
        return Err(ApiFailure::new(
            "not_awaiting",
            "This pairing is not awaiting a decision.",
        ));
    };
    decision_tx.send(decision).map_err(|_| {
        ApiFailure::new(
            "decision_undeliverable",
            "The pairing thread is no longer waiting.",
        )
    })?;
    if is_deny {
        shared.phase = Phase::Denied;
    }
    Ok(())
}

fn set_awaiting(handle_id: u64, peer: &PeerIntroduction, offered: &[String]) {
    registry_entry_apply(handle_id, |shared| {
        shared.phase = Phase::AwaitingConfirmation {
            display_name: peer.display_name.clone(),
            platform: peer.platform.clone(),
            profiles: offered.to_vec(),
        };
    });
}

fn set_phase(handle_id: u64, phase: Phase) {
    registry_entry_apply(handle_id, |shared| {
        shared.phase = phase;
    });
}

fn publish_decision_sender(handle_id: u64, decision_tx: Sender<Option<Vec<String>>>) -> bool {
    registry_entry_apply(handle_id, move |shared| {
        shared.decision_tx = Some(decision_tx);
    })
    .is_some()
}

/// Records a failed pairing attempt. Returns whether the attempt ends the
/// pairing: a refusal, a mistyped code, or an ended handle; a phone that
/// could not complete the exchange leaves the next one to be tried.
fn fail_attempt(handle_id: u64, error: PairingError) -> bool {
    let (ends, phase) = match error {
        PairingError::DeniedLocally | PairingError::AbortedByPeer => (true, Phase::Denied),
        PairingError::CodeMismatch => (
            true,
            Phase::Failed("The code does not match the one the phone shows.".to_owned()),
        ),
        _ => (false, Phase::Offer),
    };
    registry_entry_apply(handle_id, |shared| {
        shared.decision_tx = None;
        shared.phase = if shared.end_requested {
            Phase::Cancelled
        } else {
            phase
        };
    });
    ends || ended(handle_id)
}

/// Applies `update` to a handle's shared state, returning `Some(())` when the
/// handle still exists.
#[allow(
    clippy::significant_drop_tightening,
    reason = "the guard yields a borrow that must outlive it in this lock chain"
)]
fn registry_entry_apply<R, F: FnOnce(&mut Shared) -> R>(handle_id: u64, update: F) -> Option<R> {
    let registry = REGISTRY.lock().ok()?;
    let entry = registry.get(&handle_id)?;
    let mut shared = entry.shared.lock().ok()?;
    Some(update(&mut shared))
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "the guard yields a borrow that must outlive it in this lock chain"
)]
fn ended(handle_id: u64) -> bool {
    let Ok(registry) = REGISTRY.lock() else {
        return true;
    };
    let Some(entry) = registry.get(&handle_id) else {
        return true;
    };
    let Ok(shared) = entry.shared.lock() else {
        return true;
    };
    shared.end_requested
}

const fn receive_deadline() -> std::time::Duration {
    std::time::Duration::from_millis(RECEIVE_DEADLINE_MS)
}

const fn browse_window() -> std::time::Duration {
    std::time::Duration::from_millis(BROWSE_WINDOW_MS)
}

fn lock_registry() -> Result<MutexGuard<'static, HashMap<u64, Handle>>, ApiFailure> {
    REGISTRY
        .lock()
        .map_err(|_| ApiFailure::new("state_poisoned", "The requester registry is unusable."))
}

fn lock_shared(shared: &Mutex<Shared>) -> Result<MutexGuard<'_, Shared>, ApiFailure> {
    shared
        .lock()
        .map_err(|_| ApiFailure::new("state_poisoned", "The pairing state is unusable."))
}

unsafe fn copy_utf8(
    input: *const u8,
    length: usize,
    maximum: usize,
    label: &'static str,
) -> Result<String, ApiFailure> {
    // SAFETY: copy_bytes validates the pointer and bound before reading.
    let bytes = unsafe { copy_bytes(input, length, maximum, label) }?;
    String::from_utf8(bytes)
        .map_err(|_| ApiFailure::new("invalid_utf8", format!("{label} was not valid UTF-8")))
}

unsafe fn copy_bytes(
    input: *const u8,
    length: usize,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<u8>, ApiFailure> {
    if length == 0 {
        return Err(ApiFailure::new(
            "empty_input",
            format!("{label} must not be empty"),
        ));
    }
    if length > maximum {
        return Err(ApiFailure::new(
            "input_too_long",
            format!("{label} exceeds the accepted length"),
        ));
    }
    if input.is_null() {
        return Err(ApiFailure::new(
            "null_input",
            format!("{label} pointer was null"),
        ));
    }
    // SAFETY: The caller's C ABI obligation is that input points to at least
    // length readable bytes. The checks above reject null and cap length
    // before the slice is formed; to_vec immediately detaches it.
    Ok(unsafe { core::slice::from_raw_parts(input, length) }.to_vec())
}

fn reply_json<T, F>(operation: F) -> *mut c_char
where
    T: Serialize,
    F: FnOnce() -> Result<T, ApiFailure>,
{
    let result = catch_unwind(AssertUnwindSafe(operation));
    let json = match result {
        Ok(Ok(data)) => serialize_envelope(&ApiEnvelope {
            ok: true,
            data: Some(&data),
            error: None,
        }),
        Ok(Err(error)) => serialize_envelope::<T>(&ApiEnvelope {
            ok: false,
            data: None,
            error: Some(ApiError {
                code: error.code,
                message: &error.message,
            }),
        }),
        Err(_) => serialize_envelope::<T>(&ApiEnvelope {
            ok: false,
            data: None,
            error: Some(ApiError {
                code: "internal_panic",
                message: "The native requester stopped unexpectedly.",
            }),
        }),
    };
    CString::new(json).map_or(core::ptr::null_mut(), CString::into_raw)
}

fn serialize_envelope<T: Serialize>(envelope: &ApiEnvelope<'_, T>) -> String {
    serde_json::to_string(envelope).unwrap_or_else(|_| {
        "{\"ok\":false,\"data\":null,\"error\":{\"code\":\"serialization_failed\",\"message\":\"The native response could not be encoded.\"}}".to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CARD_ABSENT_STATUS, CONSENT_SHOWN_STATUS, NO_PAIRING_STATUS, PHONE_UNREACHABLE_STATUS,
        Phase, REVOKED_STATUS, is_watch_status, state_dto,
    };

    #[test]
    fn the_watch_clears_only_its_own_lines() {
        assert!(is_watch_status(PHONE_UNREACHABLE_STATUS));
        assert!(is_watch_status(CARD_ABSENT_STATUS));
        assert!(is_watch_status(NO_PAIRING_STATUS));
        assert!(!is_watch_status(CONSENT_SHOWN_STATUS));
        assert!(!is_watch_status(REVOKED_STATUS));
    }

    #[test]
    fn state_labels_are_closed() {
        assert_eq!(state_dto(&Phase::Offer).state, "offer");
        assert_eq!(state_dto(&Phase::Denied).state, "denied");
        assert_eq!(state_dto(&Phase::Cancelled).state, "cancelled");
        assert_eq!(
            state_dto(&Phase::Paired {
                pair_id_hex: "00".to_owned()
            })
            .state,
            "paired"
        );
    }

    #[test]
    fn awaiting_state_carries_the_peer() {
        let dto = state_dto(&Phase::AwaitingConfirmation {
            display_name: "iPhone".to_owned(),
            platform: "iOS".to_owned(),
            profiles: vec!["fi.refineid.card-status.v1".to_owned()],
        });
        assert_eq!(dto.state, "awaiting_confirmation");
        let peer = dto.peer.expect("peer present");
        assert_eq!(peer.display_name, "iPhone");
        assert_eq!(peer.profiles.len(), 1);
    }
}
