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

//! `CardTransport` impl over Windows winscard.dll's `SCardTransmit`.
//!
//! The Card Module API hands the minidriver an already-open
//! `SCARDHANDLE` (and `SCARDCONTEXT`) in `CARD_DATA`. We wrap that
//! into the shared `refineid-apdu` `CardTransport` port so the
//! card-edge logic (cert read, PIN verify, PSO chain) runs unchanged
//! across adapters.
#![expect(
    clippy::redundant_pub_crate,
    reason = "This private transport module still uses pub(crate) for crate-internal ABI plumbing and consistency with sibling modules"
)]

use core::time::Duration;

use refineid_apdu::{
    CardTransport, CommandApdu, CredentialCommand, ResponseApdu, TransportErrorExt,
    TransportErrorKind, TransportOutcome,
};
#[cfg(test)]
use refineid_atr::{Atr, AtrError};
use refineid_auth::Pin2;
use refineid_pace::{OpenedByCan, PaceSession, SmError, SmTransport};
use refineid_rapp_core::engine::{
    OperationOutcome, Requester, RequesterConfig, Session, SessionEnd, SessionError,
};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::{CloseReason, ResultError};
use refineid_rapp_core::operations::{CardOperation, CardOperationResult};
use refineid_rapp_core::store::{PairingRecord, PairingStore};
use refineid_rapp_core::stream::{DialCause, StreamError};
use refineid_rapp_core::transport::TcpFrameTransport;
use refineid_sign::{QualifiedSignSession, QualifiedUnlockError, SignScheme, SigningKey};
use refineid_windows_credential_store::ProtectedPairingStore;

use crate::apdu_bridge::t0_case3_from_short_case4;

use crate::ffi::{
    DWORD, SCARD_E_COMM_DATA_LOST, SCARD_E_NO_KEY_CONTAINER, SCARD_F_INTERNAL_ERROR,
    SCARD_W_CANCELLED_BY_USER, SCARD_W_REMOVED_CARD, SCARD_W_WRONG_CHV, SCARDHANDLE,
};

/// Sentinel `SCARDHANDLE` representing an absent or invalidated card handle.
const INVALID_HANDLE: SCARDHANDLE = 0;

/// PC/SC `SCARD_S_SUCCESS`: the winscard call returned no error.
const SCARD_S_SUCCESS: u32 = 0;

/// PC/SC `SCARD_LEAVE_CARD` disposition for `SCardEndTransaction`:
/// release the transaction without resetting or powering down the
/// card.
const SCARD_LEAVE_CARD: u32 = 0;

/// PC/SC `SCARD_ATTR_CURRENT_PROTOCOL_TYPE`: attribute class 8
/// (`SCARD_CLASS_PROTOCOL`) tag `0x0201`, encoded as
/// `(class << 16) | tag`. Read via [`SCardGetAttrib`] to learn the
/// active protocol of the handle the Base CSP opened for us.
pub(crate) const SCARD_ATTR_CURRENT_PROTOCOL_TYPE: u32 = 0x0008_0201;

/// ISO 7816-4 SW1 = `0x61`: "command processed, SW2 more bytes are
/// available" -- issue GET RESPONSE for SW2 bytes (T=0 chaining).
const SW1_BYTES_AVAILABLE: u8 = 0x61;

/// ISO 7816-4 SW1 = `0x6C`: "wrong Le" -- reissue the command with
/// `Le` set to SW2, the exact length the card will return (T=0).
const SW1_WRONG_LE: u8 = 0x6C;

/// ISO 7816-4 INS = `0xC0`: GET RESPONSE.
const INS_GET_RESPONSE: u8 = 0xC0;

/// ISO 7816-4 P1/P2 for the GET RESPONSE we issue: both zero.
const P_ZERO: u8 = 0x00;

/// Mask selecting the CLA high nibble; we preserve it from the
/// original command so the GET RESPONSE matches its logical channel.
const CLA_HIGH_NIBBLE_MASK: u8 = 0xF0;

/// Shortest meaningful APDU response: SW1 + SW2 with an empty body.
const MIN_RESPONSE_LEN: usize = 2;

/// Receive-buffer length: the largest extended-APDU response body
/// (`u16::MAX + 1` = 65536 bytes) plus the two trailing status
/// bytes. The card never returns more in a single exchange.
const RECV_BUFFER_LEN: usize = (u16::MAX as usize) + 1 + MIN_RESPONSE_LEN;

/// Maximum aggregate response body for one logical APDU.
const CHAIN_BODY_MAX_BYTES: usize = RECV_BUFFER_LEN - MIN_RESPONSE_LEN;

/// A one-byte-per-hop hostile chain cannot exceed this many
/// continuations before also exceeding the aggregate byte ceiling.
const MAX_CHAIN_ITERATIONS: usize = CHAIN_BODY_MAX_BYTES;

// winscard.dll, linked directly: cleaner than routing these few
// symbols through a generated binding crate.
#[link(name = "winscard")]
unsafe extern "system" {
    fn SCardBeginTransaction(h_card: SCARDHANDLE) -> u32;

    fn SCardEndTransaction(h_card: SCARDHANDLE, disposition: u32) -> u32;

    fn SCardTransmit(
        h_card: SCARDHANDLE,
        send_pci: *const u8,
        send_buffer: *const u8,
        send_length: u32,
        recv_pci: *mut u8,
        recv_buffer: *mut u8,
        recv_length: *mut u32,
    ) -> u32;

    /// Read a card/handle attribute (e.g.
    /// [`SCARD_ATTR_CURRENT_PROTOCOL_TYPE`]). Consumed by the
    /// Card Module entry points in `lib.rs`.
    pub(crate) fn SCardGetAttrib(
        h_card: SCARDHANDLE,
        attr_id: u32,
        attr: *mut u8,
        attr_len: *mut u32,
    ) -> u32;
}

/// PC/SC IO request header (`SCARD_IO_REQUEST`). We only need the
/// two header fields; `SCardTransmit` reads the protocol PCI through
/// a pointer to one of the winscard.dll globals below.
#[repr(C)]
struct ScardIoRequest {
    protocol: u32,
    pci_length: u32,
}

// Protocol PCI globals exported by winscard.dll (PC/SC
// `SCARD_PCI_T0` / `SCARD_PCI_T1`). Declared as link-time symbols.
#[link(name = "winscard")]
unsafe extern "system" {
    static g_rgSCardT0Pci: ScardIoRequest;
    static g_rgSCardT1Pci: ScardIoRequest;
}

/// Active card transmission protocol, as reported by PC/SC. The wire
/// values are the `SCARD_PROTOCOL_*` bit flags; we only ever see one
/// of the two character protocols on a live handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScardProtocol {
    /// T=0 (byte-oriented). PC/SC `SCARD_PROTOCOL_T0` = 1.
    T0,
    /// T=1 (block-oriented). PC/SC `SCARD_PROTOCOL_T1` = 2.
    T1,
}

impl ScardProtocol {
    /// PC/SC `SCARD_PROTOCOL_T0`.
    const PCSC_T0: u32 = 1;
    /// PC/SC `SCARD_PROTOCOL_T1`.
    const PCSC_T1: u32 = 2;

    /// Decode the PC/SC protocol word the Base CSP recorded for the
    /// handle. Returns `None` for any value other than the two
    /// character protocols (e.g. `SCARD_PROTOCOL_RAW`), which we do
    /// not drive.
    pub(crate) const fn from_pcsc(value: u32) -> Option<Self> {
        match value {
            Self::PCSC_T0 => Some(Self::T0),
            Self::PCSC_T1 => Some(Self::T1),
            _ => None,
        }
    }

    /// Pointer to the winscard.dll PCI global for this protocol,
    /// as the `*const u8` `SCardTransmit` expects for its send-PCI
    /// argument. Forming the address of an extern static is safe;
    /// only dereferencing would be unsafe, and we never do -- the
    /// pointer is handed straight to winscard.
    fn pci_ptr(self) -> *const u8 {
        match self {
            Self::T0 => (&raw const g_rgSCardT0Pci).cast::<u8>(),
            Self::T1 => (&raw const g_rgSCardT1Pci).cast::<u8>(),
        }
    }
}

/// RAII guard bracketing an APDU sequence in a PC/SC transaction so no
/// other card user interleaves between SELECT / READ / VERIFY / MSE / PSO /
/// GET RESPONSE steps. Ends the transaction on drop.
pub(crate) struct ScardTransaction {
    h_card: SCARDHANDLE,
}

impl ScardTransaction {
    pub(crate) fn begin(h_card: SCARDHANDLE) -> Result<Self, TransportError> {
        // SAFETY: `h_card` is the open handle the Base CSP gave us.
        let rc = unsafe { SCardBeginTransaction(h_card) };
        if rc != SCARD_S_SUCCESS {
            refineid_dev_errors::report!(CardModule, "card transaction not begun", status rc);
            return Err(TransportError::TransactionFailed(rc));
        }
        Ok(Self { h_card })
    }
}

impl Drop for ScardTransaction {
    fn drop(&mut self) {
        // SAFETY: pairs with the successful SCardBeginTransaction.
        unsafe {
            let _ = SCardEndTransaction(self.h_card, SCARD_LEAVE_CARD);
        }
    }
}

/// `CardTransport` over an open winscard.dll handle. Owned exclusively by
/// the Card Module context (not `Clone`) so no handle alias can send
/// out-of-band APDUs while a sealed `QualifiedSignSession` is active.
pub(crate) struct WinScardTransport {
    /// Open card handle from `CARD_DATA`.
    pub(crate) h_card: SCARDHANDLE,
    /// Raw ATR bytes from `CARD_DATA`, parsed on demand in [`Self::atr`].
    pub(crate) atr: Vec<u8>,
    /// Active transmission protocol of `h_card`.
    pub(crate) protocol: ScardProtocol,
}

/// Synthetic ATR reported for remote cards served via RAPP.
///
/// Matches FINEID-S4-1-v4.0 registration where bytes 12..17 are masked
/// and carry ASCII "RAPP\0".
pub(crate) const REMOTE_SYNTHETIC_ATR: [u8; 20] = [
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0x52, 0x41, 0x50, 0x50,
    0x00, 0x82, 0x90, 0x00,
];

/// Development test CCID card ATR (e.g. for development on Windows VMs with USB CCID readers).
pub(crate) const DEV_TEST_CARD_ATR: [u8; 23] = [
    0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59,
    0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
];

/// Returns true if the ATR identifies a RAPP remote card.
pub(crate) fn is_remote_card(atr: &[u8]) -> bool {
    atr == REMOTE_SYNTHETIC_ATR
        || (atr.len() >= 17 && &atr[12..16] == b"RAPP")
        || atr == DEV_TEST_CARD_ATR
}

/// How long one DNS-SD browse listens for the phone's session record.
const BROWSE_ROUND: Duration = Duration::from_secs(3);

/// Browse rounds before a dial that stays unanswered gives up; a single
/// query goes unanswered often enough that one round is not a verdict.
const BROWSE_ROUNDS: u32 = 3;

/// Operation expiry sent on the wire; the holder approves within this.
const OPERATION_LIFETIME_MS: u64 = 300_000;

/// Why a remote operation gave no result.
#[derive(Debug)]
pub(crate) enum RemoteFailure {
    /// The holder declined on the phone (`user_cancelled`).
    UserCancelled,
    /// The pairing serves nothing: the user forgot it here, or the phone
    /// closed with `pairing_revoked` (RAPP v26.11.2 section 4.6).
    Unpaired,
    /// No dial reached the phone: it reads as no card in the reader
    /// (RAPP v26.11.2 section 4.7), exactly as if no phone were there.
    NoCard,
    /// The session ended before the operation's result arrived.
    Lost,
    /// The phone's card did not answer this operation (`card_error`): a
    /// failed operation, never the card's absence, which only `card.status`
    /// reports (RAPP v26.11.2 section 8.4 item 1).
    CardError,
    /// Any other refusal or fault, named for debug logs.
    Failed(String),
}

impl RemoteFailure {
    /// The Card Module status this failure reports. `retry_floor` and every
    /// other refusal have no Windows status of their own and report an
    /// internal error.
    pub(crate) const fn status(&self) -> DWORD {
        match self {
            Self::UserCancelled => SCARD_W_CANCELLED_BY_USER,
            Self::Unpaired => SCARD_E_NO_KEY_CONTAINER,
            Self::NoCard => SCARD_W_REMOVED_CARD,
            Self::Lost | Self::CardError => SCARD_E_COMM_DATA_LOST,
            Self::Failed(_) => SCARD_F_INTERNAL_ERROR,
        }
    }
}

impl core::fmt::Display for RemoteFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UserCancelled => formatter.write_str("the holder declined on the phone"),
            Self::Unpaired => formatter.write_str("the pairing serves nothing; pair again"),
            Self::NoCard => formatter.write_str("no card present"),
            Self::Lost => formatter.write_str("the session ended before the result"),
            Self::CardError => formatter.write_str("the phone's card did not answer"),
            Self::Failed(reason) => formatter.write_str(reason),
        }
    }
}

/// Remote card transport backed by the RAPP requester engine over a stream session.
pub(crate) struct RemoteCardTransport {
    pub(crate) atr: Vec<u8>,
    pub(crate) pair_id: PairId,
}

impl RemoteCardTransport {
    pub(crate) const fn new(atr: Vec<u8>, pair_id: PairId) -> Self {
        Self { atr, pair_id }
    }

    /// Establishes a session transport to the paired custodian for this
    /// operation, a local consumer's request (RAPP v26.11.2 section 8.3): an
    /// explicit `REFINEID_RAPP_ENDPOINT` for test harnesses first, then the
    /// phone found by its session-mode discovery record. A withdrawn phone
    /// is not dialed (section 4.5 item 6). This computer only dials; it never
    /// listens.
    fn connect_session_transport(
        &self,
        store: &ProtectedPairingStore,
    ) -> Result<TcpFrameTransport, RemoteFailure> {
        let preferred: Vec<String> = std::env::var("REFINEID_RAPP_ENDPOINT")
            .ok()
            .map(|endpoint| endpoint.trim().to_owned())
            .filter(|endpoint| !endpoint.is_empty())
            .into_iter()
            .collect();
        let pairing = store
            .get(self.pair_id)
            .ok()
            .and_then(PairingRecord::serving_record)
            .ok_or(RemoteFailure::Unpaired)?;
        let mut outcome = Err(StreamError::Unreachable);
        for _ in 0..BROWSE_ROUNDS {
            outcome = refineid_rapp_core::stream::dial_session(
                pairing,
                &preferred,
                BROWSE_ROUND,
                DialCause::ConsumerRequest,
            );
            if matches!(
                outcome,
                Ok(_) | Err(StreamError::Withdrawn | StreamError::NotDue)
            ) {
                break;
            }
        }
        outcome.map_err(|_| RemoteFailure::NoCard)
    }

    /// Executes a typed card operation via RAPP.
    pub(crate) fn execute_operation(
        &self,
        operation: &CardOperation,
    ) -> Result<CardOperationResult, RemoteFailure> {
        let store = ProtectedPairingStore::load().map_err(|error| {
            RemoteFailure::Failed(format!("the pairing store cannot be loaded: {error}"))
        })?;
        let transport = self.connect_session_transport(&store)?;
        let mut requester = Requester::new(RequesterConfig::this_computer(), store);

        // The phone's `pairing_revoked` close revokes the pairing in the
        // protected store the requester runs over (RAPP v26.11.2 section
        // 4.6 item 4), and the user is told to pair again.
        let mut session = match requester.connect(self.pair_id, transport) {
            Ok(session) => session,
            Err(SessionError::ClosedByPeer(CloseReason::PairingRevoked)) => {
                return Err(RemoteFailure::Unpaired);
            }
            Err(error) => {
                return Err(RemoteFailure::Failed(format!(
                    "session connect failed: {error}"
                )));
            }
        };

        let outcome = requester.execute(&mut session, operation, OPERATION_LIFETIME_MS);
        if session.end() == Some(SessionEnd::PeerClose(CloseReason::PairingRevoked)) {
            return Err(RemoteFailure::Unpaired);
        }
        // The result goes back now; the close and its echo follow on a
        // thread of their own. A session the phone already closed is not
        // closed again (section 4.6 item 4), and a `pairing_revoked` close
        // that crosses this one still revokes the stored pairing.
        close_in_background(Closing { requester, session });
        match outcome {
            Ok(OperationOutcome::Completed(result)) => Ok(result),
            Ok(
                OperationOutcome::Rejected(ResultError::UserCancelled)
                | OperationOutcome::Cancelled(ResultError::UserCancelled),
            ) => Err(RemoteFailure::UserCancelled),
            Ok(
                OperationOutcome::Rejected(ResultError::CardError)
                | OperationOutcome::Cancelled(ResultError::CardError),
            ) => Err(RemoteFailure::CardError),
            Ok(OperationOutcome::Lost) => Err(RemoteFailure::Lost),
            Ok(other) => Err(RemoteFailure::Failed(format!(
                "operation failed with outcome: {other:?}"
            ))),
            Err(error) => Err(RemoteFailure::Failed(format!(
                "operation execute failed: {error}"
            ))),
        }
    }
}

/// One remote session to close once its operation's result is handed back.
struct Closing {
    requester: Requester<ProtectedPairingStore>,
    session: Session<TcpFrameTransport>,
}

impl Closing {
    /// Closes the session, waiting at most the engine's echo bound.
    fn close(mut self) {
        self.requester
            .disconnect(&mut self.session, CloseReason::UserDisconnect);
    }
}

/// A closing session crosses to the thread that closes it.
const _: () = {
    const fn sendable<T: Send>() {}
    sendable::<Closing>();
};

/// Closes `closing` on a thread of its own, so the caller does not wait for
/// the phone's echo of the close. The thread holds a reference to this DLL
/// until it ends, so a host that unloads the Card Module meanwhile does not
/// unload the code it runs; where no thread can start, the session is closed
/// here.
fn close_in_background(closing: Closing) {
    use windows_sys::Win32::Foundation::{CloseHandle, HMODULE};
    use windows_sys::Win32::System::LibraryLoader::{
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GetModuleHandleExW,
    };
    use windows_sys::Win32::System::Threading::CreateThread;

    let mut module: HMODULE = core::ptr::null_mut();
    // SAFETY: the address of a function in this module identifies it; the
    // lookup adds a reference the closing thread releases.
    let pinned = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            (close_in_background as *const ()).cast(),
            &raw mut module,
        )
    };
    if pinned == 0 || module.is_null() {
        closing.close();
        return;
    }
    let parameter = Box::into_raw(Box::new(BackgroundClose { closing, module }));
    // SAFETY: `close_thread` takes ownership of `parameter`, a leaked box of
    // the type it reclaims; the thread starts at once with the default stack.
    let thread = unsafe {
        CreateThread(
            core::ptr::null(),
            DEFAULT_STACK_SIZE,
            Some(close_thread),
            parameter.cast(),
            START_AT_ONCE,
            core::ptr::null_mut(),
        )
    };
    if thread.is_null() {
        // SAFETY: no thread took `parameter`; it is reclaimed once, here.
        let work = unsafe { Box::from_raw(parameter) };
        let BackgroundClose { closing, module } = *work;
        closing.close();
        release_module(module);
        return;
    }
    // SAFETY: the handle was just returned and is closed once; the thread
    // runs on without it.
    unsafe { CloseHandle(thread) };
}

/// What the closing thread receives: the session and the reference to this
/// DLL it releases as it exits.
struct BackgroundClose {
    closing: Closing,
    module: windows_sys::Win32::Foundation::HMODULE,
}

/// The closing thread: closes the session, then releases its reference to
/// this DLL and exits, so no code of this DLL runs after the release.
unsafe extern "system" fn close_thread(parameter: *mut core::ffi::c_void) -> u32 {
    use windows_sys::Win32::System::LibraryLoader::FreeLibraryAndExitThread;

    // SAFETY: `close_in_background` passed a leaked `BackgroundClose` box
    // that only this thread reclaims.
    let work = unsafe { Box::from_raw(parameter.cast::<BackgroundClose>()) };
    let BackgroundClose { closing, module } = *work;
    let closed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| closing.close()));
    if closed.is_err() {
        refineid_dev_errors::report!(Rapp, "session close failed", "the close panicked");
    }
    // SAFETY: `module` is the reference `close_in_background` took for this
    // thread; the call releases it and ends the thread without returning.
    unsafe { FreeLibraryAndExitThread(module, CLOSE_THREAD_EXIT) }
}

/// `CreateThread`'s stack size for the executable's default.
const DEFAULT_STACK_SIZE: usize = 0;
/// `CreateThread`'s creation flags for a thread that runs at once.
const START_AT_ONCE: u32 = 0;
/// The closing thread's exit code; nothing reads it.
const CLOSE_THREAD_EXIT: u32 = 0;

/// Releases a reference to this DLL taken for a thread that never started.
fn release_module(module: windows_sys::Win32::Foundation::HMODULE) {
    use windows_sys::Win32::Foundation::FreeLibrary;

    // SAFETY: `module` is a reference this DLL took and releases once.
    unsafe { FreeLibrary(module) };
}

/// The Card Module transport for one acquired context.
///
/// Contact cards use `Plain`. A contactless card that was primed by the
/// settings app uses `Protected` for the entire context so certificate reads,
/// PIN verification, and signatures all share one PACE secure-messaging SSC.
/// A paired remote phone uses `Remote` to execute typed operations via RAPP.
pub(crate) enum CardSessionTransport {
    /// Direct ISO 7816 transmission for a contact card.
    Plain(WinScardTransport),
    /// PACE secure messaging over a contactless PC/SC handle.
    Protected {
        /// Active `refineid-pace` secure-messaging channel.
        transport: SmTransport<WinScardTransport, OpenedByCan>,
        /// Active PC/SC handle associated with `transport`.
        h_card: SCARDHANDLE,
        /// Raw ATR bytes captured from `CARD_DATA`.
        atr: Vec<u8>,
        /// Active PC/SC transmission protocol.
        protocol: ScardProtocol,
    },
    /// RAPP remote card bridge over typed operations.
    Remote(Box<RemoteCardTransport>),
}

impl CardSessionTransport {
    /// Adopt a direct contact transport.
    pub(crate) const fn plain(transport: WinScardTransport) -> Self {
        Self::Plain(transport)
    }

    /// Adopt a transport and its freshly established PACE session.
    pub(crate) fn protected(
        transport: WinScardTransport,
        session: PaceSession<OpenedByCan>,
    ) -> Self {
        let h_card = transport.h_card;
        let atr = transport.atr.clone();
        let protocol = transport.protocol;
        Self::Protected {
            transport: SmTransport::new(transport, session),
            h_card,
            atr,
            protocol,
        }
    }

    /// Adopt a remote RAPP transport.
    pub(crate) fn remote(transport: RemoteCardTransport) -> Self {
        Self::Remote(Box::new(transport))
    }

    /// Whether every application command is currently PACE-protected.
    pub(crate) const fn is_protected(&self) -> bool {
        matches!(self, Self::Protected { .. })
    }

    /// Whether this context represents a RAPP remote card.
    pub(crate) const fn is_remote(&self) -> bool {
        matches!(self, Self::Remote(_))
    }

    /// Reference to the remote card transport if remote.
    pub(crate) fn remote_ref(&self) -> Option<&RemoteCardTransport> {
        match self {
            Self::Remote(transport) => Some(transport.as_ref()),
            _ => None,
        }
    }

    /// Update the active handle of a plain contact transport after Windows
    /// reconnected the card.
    pub(crate) const fn set_plain_h_card(&mut self, live_h_card: SCARDHANDLE) {
        if let Self::Plain(transport) = self {
            transport.h_card = live_h_card;
        }
    }

    /// Clear the cached PC/SC handle after observing an invalid/disconnected
    /// handle so a later reuse of the same numeric handle value must go
    /// through full handle refresh (including PACE re-establishment).
    pub(crate) const fn invalidate_h_card(&mut self) {
        match self {
            Self::Plain(transport) => transport.h_card = INVALID_HANDLE,
            Self::Protected { h_card, .. } => *h_card = INVALID_HANDLE,
            Self::Remote(_) => {}
        }
    }

    /// Refresh a protected contactless session after Windows changed the card
    /// handle: runs `open_pace` on a fresh raw transport for `live_h_card` and
    /// installs the replacement `SmTransport` only if PACE succeeds.
    pub(crate) fn refresh_protected<E>(
        &mut self,
        live_h_card: SCARDHANDLE,
        open_pace: impl FnOnce(&mut WinScardTransport) -> Result<PaceSession<OpenedByCan>, E>,
    ) -> Result<(), E> {
        let Self::Protected { atr, protocol, .. } = self else {
            return Ok(());
        };
        let mut raw = WinScardTransport {
            h_card: live_h_card,
            atr: atr.clone(),
            protocol: *protocol,
        };
        let session = open_pace(&mut raw)?;
        *self = Self::protected(raw, session);
        Ok(())
    }

    /// Active PC/SC handle.
    pub(crate) const fn h_card(&self) -> SCARDHANDLE {
        match self {
            Self::Plain(transport) => transport.h_card,
            Self::Protected { h_card, .. } => *h_card,
            Self::Remote(_) => 0,
        }
    }

    /// Raw ATR bytes captured from `CARD_DATA`.
    pub(crate) fn atr_bytes(&self) -> &[u8] {
        match self {
            Self::Plain(transport) => &transport.atr,
            Self::Protected { atr, .. } => atr,
            Self::Remote(transport) => &transport.atr,
        }
    }

    /// Parsed ATR from `CARD_DATA`.
    #[cfg(test)]
    pub(crate) fn atr(&self) -> Result<Atr, AtrError> {
        Atr::new(self.atr_bytes())
    }
}

/// Read-only metadata snapshot retained beside a sealed
/// [`QualifiedSignSession`] so handle-refresh and transport-kind queries
/// never need access to the sealed inner transport.
#[derive(Debug, Clone, Copy)]
pub(crate) struct QualifiedSessionMeta {
    pub(crate) h_card: SCARDHANDLE,
}

/// Why [`CardSessionSlot::open_qualified`] did not seal a qualified session.
pub(crate) enum QualifiedOpenFailure {
    /// Card-level or PIN 2 unlock failure returned by `refineid-sign`.
    Unlock(QualifiedUnlockError<CardSessionTransportError>),
    /// Slot was in an unusable transient state (fail-closed).
    SessionUnavailable,
}

/// Per-context transport slot: either idle (`CardSessionTransport`) or
/// sealed inside a single-use [`QualifiedSignSession`] after PIN 2
/// verification.
pub(crate) enum CardSessionSlot {
    /// No pending qualified-signing session.
    Idle(CardSessionTransport),
    /// Sealed after a card-accepted Signature PIN 2 VERIFY (in `DF.ESIGN` on
    /// organizational cards) until consumed by one qualified signature or
    /// explicitly disarmed.
    ///
    /// Note on PC/SC transaction lifetime: the Windows Card Module ABI splits
    /// PIN verification (`CardAuthenticateEx`) and signing (`CardSignData`)
    /// into separate FFI calls owned by the Base CSP/KSP. Leaving an unmatched
    /// `SCardBeginTransaction` across FFI return would deadlock the Base CSP
    /// or leak an exclusive reader lock if the caller cancels after PIN entry,
    /// while caching PIN 2 in memory is forbidden by policy. Instead, each FFI
    /// entry point holds a transaction across its own multi-APDU sequence, and
    /// any intervening card reset, handle change, or DF change fails closed on
    /// the card while `sign_qualified_once` consumes this session unconditionally.
    QualifiedVerified {
        session: QualifiedSignSession<CardSessionTransport>,
        meta: QualifiedSessionMeta,
    },
    /// Transient placeholder while a fallible ownership transition owns the
    /// transport; never left behind on any normal return path.
    Transitioning,
}

impl CardSessionSlot {
    /// Wrap a freshly constructed [`CardSessionTransport`] with no pending
    /// PIN 2 verification.
    pub(crate) const fn idle(transport: CardSessionTransport) -> Self {
        Self::Idle(transport)
    }

    /// Whether a local Signature PIN 2 session is currently armed for one
    /// qualified signature.
    pub(crate) const fn is_qualified_verified(&self) -> bool {
        matches!(self, Self::QualifiedVerified { .. })
    }

    /// Whether this context represents a RAPP remote card.
    pub(crate) const fn is_remote(&self) -> bool {
        match self {
            Self::Idle(transport) => transport.is_remote(),
            Self::QualifiedVerified { .. } | Self::Transitioning => false,
        }
    }

    /// Active PC/SC handle associated with this session.
    pub(crate) const fn h_card(&self) -> SCARDHANDLE {
        match self {
            Self::Idle(transport) => transport.h_card(),
            Self::QualifiedVerified { meta, .. } => meta.h_card,
            Self::Transitioning => 0,
        }
    }

    /// Reference to the remote card transport if idle and remote.
    pub(crate) fn remote_ref(&self) -> Option<&RemoteCardTransport> {
        match self {
            Self::Idle(transport) => transport.remote_ref(),
            Self::QualifiedVerified { .. } | Self::Transitioning => None,
        }
    }

    /// Discard any pending Rust-side [`QualifiedSignSession`] capability and
    /// return mutable access to the underlying [`CardSessionTransport`].
    pub(crate) fn disarm_qualified(&mut self) -> Result<&mut CardSessionTransport, DWORD> {
        if matches!(self, Self::QualifiedVerified { .. }) {
            let prev = core::mem::replace(self, Self::Transitioning);
            if let Self::QualifiedVerified { session, .. } = prev {
                *self = Self::Idle(session.into_transport());
            }
        }
        match self {
            Self::Idle(transport) => Ok(transport),
            Self::QualifiedVerified { .. } | Self::Transitioning => Err(SCARD_F_INTERNAL_ERROR),
        }
    }

    /// Disarm any pending [`QualifiedSignSession`] and clear the cached PC/SC
    /// handle after observing a disconnect or invalid handle.
    pub(crate) fn invalidate_handle(&mut self) {
        if let Ok(tx) = self.disarm_qualified() {
            tx.invalidate_h_card();
        }
    }

    /// Verify Signature PIN 2 and seal the transport into a single-use
    /// [`QualifiedSignSession`]. On any error, the transport is returned to
    /// [`Self::Idle`].
    pub(crate) fn open_qualified(
        &mut self,
        scheme: SignScheme,
        pin2: Pin2,
    ) -> Result<(), QualifiedOpenFailure> {
        let _ = self.disarm_qualified();
        let prev = core::mem::replace(self, Self::Transitioning);
        let Self::Idle(transport) = prev else {
            return Err(QualifiedOpenFailure::SessionUnavailable);
        };
        let meta = QualifiedSessionMeta {
            h_card: transport.h_card(),
        };
        match QualifiedSignSession::open(transport, scheme, pin2) {
            Ok(session) => {
                *self = Self::QualifiedVerified { session, meta };
                Ok(())
            }
            Err((transport, error)) => {
                *self = Self::Idle(transport);
                Err(QualifiedOpenFailure::Unlock(error))
            }
        }
    }

    /// Consume the armed [`QualifiedSignSession`] for at most one qualified
    /// signature and return the transport to [`Self::Idle`].
    pub(crate) fn sign_qualified_once<R>(
        &mut self,
        sign: impl FnOnce(SigningKey<'_, CardSessionTransport>) -> R,
    ) -> Result<R, DWORD> {
        if !matches!(self, Self::QualifiedVerified { .. }) {
            return Err(SCARD_W_WRONG_CHV);
        }
        let prev = core::mem::replace(self, Self::Transitioning);
        let Self::QualifiedVerified { session, .. } = prev else {
            return Err(SCARD_F_INTERNAL_ERROR);
        };
        let (transport, result) = session.sign_once(sign);
        *self = Self::Idle(transport);
        Ok(result)
    }
}

/// Failure from either the direct PC/SC path, its PACE SM wrapper, or remote card.
#[derive(Debug)]
pub(crate) enum CardSessionTransportError {
    /// Direct PC/SC failure.
    Plain(TransportError),
    /// Secure-messaging or underlying PC/SC failure.
    Protected(SmError<TransportError>),
    /// Remote card does not support raw APDUs.
    RemoteNotApdu,
}

impl core::fmt::Display for CardSessionTransportError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Plain(error) => write!(formatter, "{error}"),
            Self::Protected(error) => write!(formatter, "{error}"),
            Self::RemoteNotApdu => {
                write!(
                    formatter,
                    "RAPP remote card does not support raw APDU transmission"
                )
            }
        }
    }
}

impl core::error::Error for CardSessionTransportError {}

impl TransportErrorExt for CardSessionTransportError {
    fn kind(&self) -> TransportErrorKind {
        match self {
            Self::Plain(error) => error.kind(),
            Self::Protected(error) => error.kind(),
            Self::RemoteNotApdu => TransportErrorKind::Backend,
        }
    }
}

/// winscard.dll transport faults, classified into the shared
/// [`TransportErrorKind`] vocabulary via [`TransportErrorExt`].
#[derive(Debug)]
pub(crate) enum TransportError {
    /// `SCardTransmit` returned a non-success PC/SC code.
    ApduFailed(u32),
    /// `SCardBeginTransaction` returned a non-success PC/SC code.
    TransactionFailed(u32),
    /// An APDU was longer than `u32`, which `SCardTransmit` cannot
    /// express. Unreachable in practice (APDUs are kilobytes), but
    /// the conversion is fallible so we surface it instead of
    /// truncating.
    ApduTooLong(usize),
    /// A `61xx` chain returned no data while asking for another hop.
    ChainStalled,
    /// A `61xx` chain exceeded the extended response body ceiling.
    ChainTooLong,
    /// A `61xx` chain exceeded its defensive continuation ceiling.
    ChainIterationLimit,
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ApduFailed(rc) => write!(f, "SCardTransmit failed: {rc:#010X}"),
            Self::TransactionFailed(rc) => {
                write!(f, "SCardBeginTransaction failed: {rc:#010X}")
            }
            Self::ApduTooLong(len) => write!(f, "APDU too long for SCardTransmit: {len} bytes"),
            Self::ChainStalled => write!(f, "61xx GET RESPONSE chain made no progress"),
            Self::ChainTooLong => write!(f, "61xx GET RESPONSE chain exceeded 64 KiB"),
            Self::ChainIterationLimit => {
                write!(f, "61xx GET RESPONSE chain exceeded iteration limit")
            }
        }
    }
}

impl core::error::Error for TransportError {}

impl TransportErrorExt for TransportError {
    fn kind(&self) -> TransportErrorKind {
        // Every winscard fault is opaque at this layer; the PC/SC
        // return code in `Display` carries the detail.
        TransportErrorKind::Backend
    }
}

impl WinScardTransport {
    /// One raw `SCardTransmit`. Returns the response body (status
    /// bytes split off) plus SW1/SW2, or `None` if the card returned
    /// fewer than two bytes (a protocol desync the caller maps to
    /// [`TransportOutcome::ProtocolDesync`]).
    fn raw_transmit_wire(&self, wire: &[u8]) -> Result<Option<(Vec<u8>, u8, u8)>, TransportError> {
        let send_length = u32::try_from(wire.len())
            .map_err(|_ignored| TransportError::ApduTooLong(wire.len()))?;

        let mut buf = vec![0_u8; RECV_BUFFER_LEN];
        let mut buf_len = u32::try_from(buf.len()).unwrap_or(u32::MAX);

        // SAFETY: `h_card` is the open handle; `pci_ptr` points at a
        // winscard PCI global; the send/recv buffers are valid for
        // the lengths we pass; `buf_len` is updated in place.
        let rc = unsafe {
            SCardTransmit(
                self.h_card,
                self.protocol.pci_ptr(),
                wire.as_ptr(),
                send_length,
                core::ptr::null_mut(),
                buf.as_mut_ptr(),
                &raw mut buf_len,
            )
        };
        if rc != SCARD_S_SUCCESS {
            refineid_dev_errors::report!(CardModule, "card transmit failed", status rc);
            return Err(TransportError::ApduFailed(rc));
        }

        let received = usize::try_from(buf_len).unwrap_or(buf.len()).min(buf.len());
        buf.truncate(received);
        if buf.len() < MIN_RESPONSE_LEN {
            return Ok(None);
        }
        let Some(sw2) = buf.pop() else {
            return Ok(None);
        };
        let Some(sw1) = buf.pop() else {
            return Ok(None);
        };
        Ok(Some((buf, sw1, sw2)))
    }

    /// Parsed ATR from `CARD_DATA`.
    #[cfg(test)]
    pub(crate) fn atr(&self) -> Result<Atr, AtrError> {
        Atr::new(&self.atr)
    }

    /// Settle a T=0 `61xx` `GET RESPONSE` chain onto `(body, sw1, sw2)`.
    fn settle_t0_response_chain(
        &self,
        initial_cla: u8,
        mut body: Vec<u8>,
        mut sw1: u8,
        mut sw2: u8,
    ) -> Result<TransportOutcome, TransportError> {
        let mut chain_iterations = 0_usize;
        while self.protocol == ScardProtocol::T0 && sw1 == SW1_BYTES_AVAILABLE {
            chain_iterations = chain_iterations.saturating_add(1);
            if chain_iterations > MAX_CHAIN_ITERATIONS {
                return Err(TransportError::ChainIterationLimit);
            }
            let get_response = [initial_cla, INS_GET_RESPONSE, P_ZERO, P_ZERO, sw2];
            let Some((next_body, next_sw1, next_sw2)) = self.raw_transmit_wire(&get_response)?
            else {
                return Ok(TransportOutcome::ProtocolDesync);
            };
            if next_sw1 == SW1_BYTES_AVAILABLE && next_body.is_empty() {
                return Err(TransportError::ChainStalled);
            }
            let Some(next_len) = body.len().checked_add(next_body.len()) else {
                return Err(TransportError::ChainTooLong);
            };
            if next_len > CHAIN_BODY_MAX_BYTES {
                return Err(TransportError::ChainTooLong);
            }
            body.extend_from_slice(&next_body);
            sw1 = next_sw1;
            sw2 = next_sw2;
        }

        Ok(TransportOutcome::Response(ResponseApdu { body, sw1, sw2 }))
    }
}

impl CardTransport for WinScardTransport {
    type Error = TransportError;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let _transaction = ScardTransaction::begin(self.h_card)?;

        let bytes = command.as_bytes();
        let initial_cla = bytes
            .first()
            .map_or(P_ZERO, |first| first & CLA_HIGH_NIBBLE_MASK);

        let t0_stripped = if self.protocol == ScardProtocol::T0 {
            t0_case3_from_short_case4(bytes)
        } else {
            None
        };
        let wire = t0_stripped.as_deref().unwrap_or(bytes);

        let Some((mut body, mut sw1, mut sw2)) = self.raw_transmit_wire(wire)? else {
            return Ok(TransportOutcome::ProtocolDesync);
        };

        // Only builder-proven read-only case-2 commands permit one
        // corrected retry.
        if self.protocol == ScardProtocol::T0
            && sw1 == SW1_WRONG_LE
            && let Some(retry_apdu) = command.corrected_wrong_le(sw2)
        {
            let Some((retry_body, retry_sw1, retry_sw2)) =
                self.raw_transmit_wire(retry_apdu.as_bytes())?
            else {
                return Ok(TransportOutcome::ProtocolDesync);
            };
            body = retry_body;
            sw1 = retry_sw1;
            sw2 = retry_sw2;
        }

        self.settle_t0_response_chain(initial_cla, body, sw1, sw2)
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        let _transaction = ScardTransaction::begin(self.h_card)?;

        // Send the exposed credential wire bytes exactly once: no 6Cxx retry,
        // no retention, and any T=0 scratch copy is zeroized before return.
        let (initial_cla, raw_outcome) = command.expose_wire(|wire| {
            let cla = wire
                .first()
                .map_or(P_ZERO, |first| first & CLA_HIGH_NIBBLE_MASK);
            let outcome = if self.protocol == ScardProtocol::T0
                && let Some(stripped) = t0_case3_from_short_case4(wire)
            {
                let stripped = zeroize::Zeroizing::new(stripped);
                self.raw_transmit_wire(stripped.as_slice())
            } else {
                self.raw_transmit_wire(wire)
            };
            (cla, outcome)
        });

        let Some((body, sw1, sw2)) = raw_outcome? else {
            return Ok(TransportOutcome::ProtocolDesync);
        };

        self.settle_t0_response_chain(initial_cla, body, sw1, sw2)
    }
}

impl CardTransport for CardSessionTransport {
    type Error = CardSessionTransportError;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        match self {
            Self::Plain(transport) => CardTransport::transmit(transport, command)
                .map_err(CardSessionTransportError::Plain),
            Self::Protected { transport, .. } => CardTransport::transmit(transport, command)
                .map_err(CardSessionTransportError::Protected),
            Self::Remote(_) => Err(CardSessionTransportError::RemoteNotApdu),
        }
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        match self {
            Self::Plain(transport) => transport
                .transmit_credential(command)
                .map_err(CardSessionTransportError::Plain),
            Self::Protected { transport, .. } => transport
                .transmit_credential(command)
                .map_err(CardSessionTransportError::Protected),
            Self::Remote(_) => Err(CardSessionTransportError::RemoteNotApdu),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CardSessionTransport, REMOTE_SYNTHETIC_ATR, RemoteFailure, ScardProtocol, WinScardTransport,
    };
    use crate::ffi::{SCARD_E_NO_KEY_CONTAINER, SCARD_W_REMOVED_CARD};

    #[test]
    fn synthetic_card_atr_survives_both_transport_layers() {
        let transport = WinScardTransport {
            h_card: Default::default(),
            atr: REMOTE_SYNTHETIC_ATR.to_vec(),
            protocol: ScardProtocol::T0,
        };
        assert_eq!(
            transport
                .atr()
                .expect("synthetic ATR parses")
                .to_wire_bytes(),
            REMOTE_SYNTHETIC_ATR
        );
        let session = CardSessionTransport::plain(transport);
        assert_eq!(
            session.atr().expect("session ATR parses").to_wire_bytes(),
            REMOTE_SYNTHETIC_ATR
        );
    }

    #[test]
    fn an_absent_phone_reads_as_no_card_in_the_reader() {
        assert_eq!(RemoteFailure::NoCard.status(), SCARD_W_REMOVED_CARD);
        assert_eq!(RemoteFailure::NoCard.to_string(), "no card present");
    }

    #[test]
    fn a_pairing_that_serves_nothing_still_asks_to_pair_again() {
        assert_eq!(RemoteFailure::Unpaired.status(), SCARD_E_NO_KEY_CONTAINER);
        assert_eq!(
            RemoteFailure::Unpaired.to_string(),
            "the pairing serves nothing; pair again"
        );
    }
}
