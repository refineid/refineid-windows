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
//! it (RAPP v26.10.9 section 2.2), and, after pairing, the live `Requester`
//! whose device-only credential store persists the pairing so the minidriver
//! can later load and use it behind this same ABI. This computer only ever
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

use refineid_rapp_core::engine::{
    OperationOutcome, PairingError, PeerIntroduction, Requester, RequesterConfig,
};
use refineid_rapp_core::ids::{PairId, RendezvousToken};
use refineid_rapp_core::message::CloseReason;
use refineid_rapp_core::offer::normalize_pairing_code;
use refineid_rapp_core::operations::{CardOperation, CardOperationResult};
use refineid_rapp_core::store::{MemoryJournal, PairingStore};
use refineid_rapp_core::stream::{
    DiscoveryMode, STREAM_CANDIDATE_ID, StreamRendezvous, browse, dial, session_candidates,
};
use refineid_windows_credential_store::{CredentialPairingStore, delete_pairing_set};
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

/// The requester engine specialised to the device-only credential-store
/// pairing store and the in-memory operation journal.
type StreamRequester = Requester<CredentialPairingStore, MemoryJournal>;

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
    rendezvous: RendezvousToken,
}

/// State a pairing handle shares across threads.
struct Shared {
    phase: Phase,
    decision_tx: Option<Sender<Option<Vec<String>>>>,
    end_requested: bool,
    paired: Option<Paired>,
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
        delete_pairing_set()
            .map_err(|error| ApiFailure::new("forget_failed", format!("{error}")))?;
        Ok(AckDto { ok: true })
    })
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
/// a six-character pairing code (RAPP v26.10.9 section 3.1). The background
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
        Ok(state_dto(&shared.phase))
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
        let result = read_paired_card(&mut paired);
        restore_paired(handle, paired);
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
        if let Ok(mut shared) = entry.shared.lock() {
            shared.end_requested = true;
            if let Some(decision_tx) = shared.decision_tx.take() {
                let _ = decision_tx.send(None);
            }
        }
        drop(entry.thread.take());
        Ok(AckDto { ok: true })
    })
}

fn begin_pairing(code: String, name: String) -> Result<BeginPairingDto, ApiFailure> {
    let pairing_store = CredentialPairingStore::load()
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
    let pairing_store = CredentialPairingStore::load()
        .map_err(|error| ApiFailure::new("pairing_store_unavailable", format!("{error}")))?;
    let (pair_id, rendezvous) = pairing_store
        .usable_pairing()
        .map(|record| (record.pair_id, record.rendezvous_token))
        .ok_or_else(|| ApiFailure::new("no_pairing", "No phone is paired with this device."))?;
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
            rendezvous,
        }),
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
                &StreamRendezvous::Pairing,
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

fn finish_pairing(handle_id: u64, requester: StreamRequester, pair_id: PairId) {
    let Ok(record) = requester.store().get(pair_id) else {
        set_phase(
            handle_id,
            Phase::Failed("The stored pairing could not be read.".to_owned()),
        );
        return;
    };
    let rendezvous = record.rendezvous_token;
    let pair_id_hex = hex::encode(pair_id.as_bytes());
    // If the handle is gone, the closure is never run and the moved
    // requester is dropped here instead.
    let _stored = registry_entry_apply(handle_id, move |shared| {
        shared.decision_tx = None;
        shared.phase = Phase::Paired { pair_id_hex };
        shared.paired = Some(Paired {
            requester,
            pair_id,
            rendezvous,
        });
    });
}

fn read_paired_card(paired: &mut Paired) -> Result<CardReadDto, ApiFailure> {
    let session_transport = (0..MAX_SESSION_BROWSE_ROUNDS)
        .find_map(|_| {
            session_candidates(
                browse(DiscoveryMode::Session, browse_window()),
                &paired.rendezvous,
                unix_seconds(),
            )
            .iter()
            .find_map(|service| {
                dial(
                    &service.endpoints,
                    STREAM_CANDIDATE_ID,
                    receive_deadline(),
                    &StreamRendezvous::Session(paired.rendezvous),
                )
                .ok()
            })
        })
        .ok_or_else(|| {
            ApiFailure::new(
                "no_session",
                "The paired phone was not found on this network.",
            )
        })?;

    let mut session = paired
        .requester
        .connect(paired.pair_id, session_transport)
        .map_err(|error| ApiFailure::new("session_failed", format!("{error:?}")))?;

    // The requester screen shows only the holder identity, so the read is one
    // operation and the phone reads the card once. Card status and the
    // certificate bytes are separate operations added when a screen needs them.
    let identity = match run_operation(paired, &mut session, &CardOperation::ReadIdentity)? {
        CardOperationResult::Identity(identity) => IdentityDto {
            display_name: identity.holder_name,
            person_id: identity.card_id,
        },
        _ => return Err(unexpected_result("read_identity")),
    };

    paired
        .requester
        .disconnect(&mut session, CloseReason::UserDisconnect);

    Ok(CardReadDto { identity })
}

fn run_operation(
    paired: &mut Paired,
    session: &mut refineid_rapp_core::engine::Session<
        refineid_rapp_core::transport::TcpFrameTransport,
    >,
    operation: &CardOperation,
) -> Result<CardOperationResult, ApiFailure> {
    let outcome = paired
        .requester
        .execute(session, operation, OPERATION_EXPIRY_MS)
        .map_err(|error| ApiFailure::new("operation_not_admitted", format!("{error:?}")))?;
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

fn state_dto(phase: &Phase) -> PairingStateDto {
    match phase {
        Phase::Offer => PairingStateDto {
            state: "offer",
            peer: None,
            pair_id_hex: None,
            message: None,
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
        },
        Phase::Paired { pair_id_hex } => PairingStateDto {
            state: "paired",
            peer: None,
            pair_id_hex: Some(pair_id_hex.clone()),
            message: None,
        },
        Phase::Denied => PairingStateDto {
            state: "denied",
            peer: None,
            pair_id_hex: None,
            message: None,
        },
        Phase::Cancelled => PairingStateDto {
            state: "cancelled",
            peer: None,
            pair_id_hex: None,
            message: None,
        },
        Phase::Failed(message) => PairingStateDto {
            state: "failed",
            peer: None,
            pair_id_hex: None,
            message: Some(message.clone()),
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
fn registry_entry_apply<F: FnOnce(&mut Shared)>(handle_id: u64, update: F) -> Option<()> {
    let registry = REGISTRY.lock().ok()?;
    let entry = registry.get(&handle_id)?;
    let mut shared = entry.shared.lock().ok()?;
    update(&mut shared);
    Some(())
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

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
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
    use super::{Phase, state_dto};

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
