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
//! into the shared `refineid-lib-core` `CardTransport` port so the
//! card-edge logic (cert read, PIN verify, PSO chain) runs unchanged
//! across adapters.
#![expect(
    clippy::redundant_pub_crate,
    reason = "This private transport module still uses pub(crate) for crate-internal ABI plumbing and consistency with sibling modules"
)]

use core::time::Duration;

use refineid_lib_core::atr::{Atr, AtrError};
use refineid_lib_core::pace::PaceSession;
use refineid_lib_core::secure_messaging::{SmError, SmTransport};
use refineid_lib_core::transport::{
    CardTransport, CommandApdu, ResponseApdu, TransportErrorExt, TransportErrorKind,
    TransportOutcome,
};
use refineid_rapp_core::engine::{OperationOutcome, Requester, RequesterConfig};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::CloseReason;
use refineid_rapp_core::operations::{CardOperation, CardOperationResult};
use refineid_rapp_core::store::{MemoryJournal, MemoryPairingStore, PairingRecord, PairingStore};
use refineid_rapp_core::stream::{StreamAccept, StreamListener, StreamRendezvous, dial};
use refineid_rapp_core::transport::TcpFrameTransport;

use crate::ffi::SCARDHANDLE;

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

/// RAII guard bracketing an APDU chain in a PC/SC transaction so no
/// other card user interleaves between our SELECT / READ / GET
/// RESPONSE steps. Ends the transaction on drop.
struct ScardTransaction {
    h_card: SCARDHANDLE,
}

impl ScardTransaction {
    fn begin(h_card: SCARDHANDLE) -> Result<Self, TransportError> {
        // SAFETY: `h_card` is the open handle the Base CSP gave us.
        let rc = unsafe { SCardBeginTransaction(h_card) };
        if rc != SCARD_S_SUCCESS {
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

/// `CardTransport` over an open winscard.dll handle. Cloneable so the
/// Card Module entry points can hand copies to the use-case layer; the
/// handle itself is owned by the Base CSP.
#[derive(Clone)]
pub(crate) struct WinScardTransport {
    /// Open card handle from `CARD_DATA`.
    pub(crate) h_card: SCARDHANDLE,
    /// Raw ATR bytes from `CARD_DATA`, parsed on demand in [`atr`].
    ///
    /// [`atr`]: CardTransport::atr
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

/// Virtual smart card ATR produced by Windows TPM Virtual Smart Card.
pub(crate) const VIRTUAL_SMART_CARD_ATR: [u8; 17] = [
    0x3B, 0x8D, 0x01, 0x80, 0xFB, 0xA0, 0x00, 0x00, 0x03, 0x97, 0x42, 0x54, 0x46, 0x59, 0x04, 0x01,
    0xCF,
];

/// Development test CCID card ATR (e.g. for development on Windows VMs with USB CCID readers).
pub(crate) const DEV_TEST_CARD_ATR: [u8; 23] = [
    0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59,
    0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
];

/// Returns true if the ATR identifies a RAPP remote card or virtual card.
pub(crate) fn is_remote_card(atr: &[u8]) -> bool {
    atr == REMOTE_SYNTHETIC_ATR
        || (atr.len() >= 17 && &atr[12..16] == b"RAPP")
        || atr == VIRTUAL_SMART_CARD_ATR
        || atr == DEV_TEST_CARD_ATR
}

/// Remote card transport backed by the RAPP requester engine over a stream session.
pub(crate) struct RemoteCardTransport {
    pub(crate) atr: Vec<u8>,
    pub(crate) pair_id: PairId,
    pub(crate) pairing_record: PairingRecord,
}

impl RemoteCardTransport {
    pub(crate) fn new(atr: Vec<u8>, pair_id: PairId, pairing_record: PairingRecord) -> Self {
        Self {
            atr,
            pair_id,
            pairing_record,
        }
    }

    /// Establishes a session transport to the paired proxy.
    fn connect_session_transport(&self) -> Result<TcpFrameTransport, String> {
        let dial_timeout = Duration::from_secs(5);
        let candidate_id = "stream-1";
        let service_name = refineid_rapp_core::stream::stream_rendezvous_name(
            self.pairing_record.rendezvous_token.as_bytes(),
        );

        // 1. Discover phone proxy endpoint via mDNS matching our pairing rendezvous token.
        let mut endpoints = refineid_rapp_core::stream::discover_stream_endpoints(
            Some(&service_name),
            Duration::from_secs(2),
        );

        // 2. Allow explicit override via REFINEID_RAPP_ENDPOINT for test harnesses
        if let Ok(env_endpoint) = std::env::var("REFINEID_RAPP_ENDPOINT")
            && !env_endpoint.trim().is_empty()
        {
            endpoints.insert(0, env_endpoint.trim().to_owned());
        }

        // 3. Add local mock proxy endpoint as fallback.
        let local_dial_endpoint = "127.0.0.1:47110";
        endpoints.push(local_dial_endpoint.to_owned());

        // 4. Dial discovered endpoints with our session rendezvous token.
        if let Ok(transport) = dial(
            &endpoints,
            candidate_id,
            dial_timeout,
            &StreamRendezvous::Session(self.pairing_record.rendezvous_token),
        ) {
            return Ok(transport);
        }

        // 4. Fallback listener check for reverse-dial mock test harnesses (short timeout).
        let listen_timeout = Duration::from_secs(2);
        let listen_endpoint = "127.0.0.1:47110";
        if let Ok(listener) = StreamListener::bind(listen_endpoint, candidate_id, listen_timeout)
            && let Ok(Some(StreamAccept::Session {
                rendezvous_token,
                transport,
            })) = listener.accept_timeout(listen_timeout)
            && rendezvous_token == self.pairing_record.rendezvous_token
        {
            return Ok(transport);
        }

        Err("unable to reach paired proxy via mDNS dial or local fallback".into())
    }

    /// Executes a typed card operation via RAPP.
    pub(crate) fn execute_operation(
        &self,
        operation: &CardOperation,
    ) -> Result<CardOperationResult, String> {
        let transport = self.connect_session_transport()?;
        let mut store = MemoryPairingStore::new();
        let _ = store.insert(self.pairing_record.clone());
        let mut requester = Requester::new(
            RequesterConfig {
                display_name: "RefineID Windows Remote Arm".into(),
                platform: "Windows".into(),
            },
            store,
            MemoryJournal::new(),
        );

        let mut session = requester
            .connect(self.pair_id, transport)
            .map_err(|e| format!("session connect failed: {e:?}"))?;

        let outcome = requester
            .execute(&mut session, operation, 30_000)
            .map_err(|e| format!("operation execute failed: {e:?}"))?;

        requester.disconnect(&mut session, CloseReason::UserDisconnect);

        match outcome {
            OperationOutcome::Completed(result) => Ok(result),
            OperationOutcome::Denied => {
                Err("operation was denied by the user on the remote device".into())
            }
            other => Err(format!("operation failed with outcome: {other:?}")),
        }
    }
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
    Protected(SmTransport<WinScardTransport>),
    /// RAPP remote card bridge over typed operations.
    Remote(Box<RemoteCardTransport>),
}

impl CardSessionTransport {
    /// Adopt a direct contact transport.
    pub(crate) const fn plain(transport: WinScardTransport) -> Self {
        Self::Plain(transport)
    }

    /// Adopt a transport and its freshly established PACE session.
    pub(crate) fn protected(transport: WinScardTransport, session: PaceSession) -> Self {
        Self::Protected(SmTransport::new(transport, session))
    }

    /// Adopt a remote RAPP transport.
    pub(crate) fn remote(transport: RemoteCardTransport) -> Self {
        Self::Remote(Box::new(transport))
    }

    /// Whether every application command is currently PACE-protected.
    pub(crate) const fn is_protected(&self) -> bool {
        matches!(self, Self::Protected(_))
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

    /// Mutable reference to the remote card transport if remote.
    pub(crate) fn remote_mut(&mut self) -> Option<&mut RemoteCardTransport> {
        match self {
            Self::Remote(transport) => Some(transport.as_mut()),
            _ => None,
        }
    }

    /// The raw Windows transport beneath the optional SM channel.
    pub(crate) const fn raw(&self) -> &WinScardTransport {
        match self {
            Self::Plain(transport) => transport,
            Self::Protected(transport) => transport.inner(),
            Self::Remote(_) => panic!("raw transport requested for remote card"),
        }
    }

    /// The raw Windows transport beneath the optional SM channel.
    ///
    /// A protected caller may use this only to establish the replacement PACE
    /// session immediately after Windows changed the card handle.
    pub(crate) const fn raw_mut(&mut self) -> &mut WinScardTransport {
        match self {
            Self::Plain(transport) => transport,
            Self::Protected(transport) => transport.inner_mut(),
            Self::Remote(_) => panic!("raw_mut transport requested for remote card"),
        }
    }

    /// Replace the PACE session after Windows reset a protected card.
    pub(crate) fn replace_pace_session(&mut self, session: PaceSession) {
        if let Self::Protected(transport) = self {
            transport.replace_session(session);
        }
    }

    /// Active PC/SC handle.
    pub(crate) const fn h_card(&self) -> SCARDHANDLE {
        match self {
            Self::Plain(transport) => transport.h_card,
            Self::Protected(transport) => transport.inner().h_card,
            Self::Remote(_) => 0,
        }
    }

    /// Active PC/SC protocol, for bounded diagnostics only.
    pub(crate) const fn protocol(&self) -> ScardProtocol {
        match self {
            Self::Plain(transport) => transport.protocol,
            Self::Protected(transport) => transport.inner().protocol,
            Self::Remote(_) => ScardProtocol::T1,
        }
    }

    /// Raw ATR bytes captured from `CARD_DATA`.
    pub(crate) fn atr_bytes(&self) -> &[u8] {
        match self {
            Self::Plain(transport) => &transport.atr,
            Self::Protected(transport) => &transport.inner().atr,
            Self::Remote(transport) => &transport.atr,
        }
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
    fn raw_transmit(
        &self,
        apdu: &CommandApdu,
    ) -> Result<Option<(Vec<u8>, u8, u8)>, TransportError> {
        let wire = apdu.as_bytes();
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
}

impl CardTransport for WinScardTransport {
    type Error = TransportError;

    fn transmit_outcome(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, TransportError> {
        // The Base CSP hands us an already-open handle; we cannot
        // choose its share mode, but we must bracket each APDU chain
        // in a PC/SC transaction so no other user interleaves.
        let _transaction = ScardTransaction::begin(self.h_card)?;

        let bytes = apdu.as_bytes();
        let Some((mut body, mut sw1, mut sw2)) = self.raw_transmit(apdu)? else {
            return Ok(TransportOutcome::ProtocolDesync);
        };

        // Only builder-proven read-only case-2 commands permit one
        // corrected retry. Raw and credential-bearing commands
        // treat 6Cxx as terminal.
        if self.protocol == ScardProtocol::T0
            && sw1 == SW1_WRONG_LE
            && let Some(retry_apdu) = apdu.corrected_wrong_le(sw2)
        {
            let Some((retry_body, retry_sw1, retry_sw2)) = self.raw_transmit(&retry_apdu)? else {
                return Ok(TransportOutcome::ProtocolDesync);
            };
            body = retry_body;
            sw1 = retry_sw1;
            sw2 = retry_sw2;
        }

        // T=0 GET RESPONSE chain: `61 XX` -> issue GET RESPONSE for
        // XX bytes. FINEID cert reads issue READ BINARY at multiple
        // offsets, each of which may return `61 XX`; concatenate the
        // chained bodies.
        let mut chain_iterations = 0_usize;
        while self.protocol == ScardProtocol::T0 && sw1 == SW1_BYTES_AVAILABLE {
            chain_iterations = chain_iterations.saturating_add(1);
            if chain_iterations > MAX_CHAIN_ITERATIONS {
                return Err(TransportError::ChainIterationLimit);
            }
            // Preserve the original CLA high nibble (FINEID uses 0x00).
            let cla = bytes
                .first()
                .map_or(P_ZERO, |first| first & CLA_HIGH_NIBBLE_MASK);
            let le = sw2;
            let get_response = CommandApdu::new(vec![cla, INS_GET_RESPONSE, P_ZERO, P_ZERO, le]);
            let Some((next_body, next_sw1, next_sw2)) = self.raw_transmit(&get_response)? else {
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

    fn atr(&self) -> Result<Atr, AtrError> {
        Atr::new(&self.atr)
    }
}

impl CardTransport for CardSessionTransport {
    type Error = CardSessionTransportError;

    fn transmit_outcome(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        match self {
            Self::Plain(transport) => transport
                .transmit_outcome(apdu)
                .map_err(CardSessionTransportError::Plain),
            Self::Protected(transport) => transport
                .transmit_outcome(apdu)
                .map_err(CardSessionTransportError::Protected),
            Self::Remote(_) => Err(CardSessionTransportError::RemoteNotApdu),
        }
    }

    fn atr(&self) -> Result<Atr, AtrError> {
        Atr::new(self.atr_bytes())
    }
}
