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

//! Windows smart-card minidriver (Card Module) for FINEID.
//!
//! Sibling adapter to the PKCS#11 cdylib: hooks the FINEID card into
//! the Microsoft Base CSP/KSP so Edge, Chrome, Schannel, .NET, VPN,
//! RDP, and Wi-Fi EAP-TLS reach it through the OS smart-card stack.
//! Card-edge work delegates to `refineid-lib-core` (one protocol
//! implementation shared with the other adapters).
//!
//! Windows-only. The implementation lives behind `#[cfg(windows)]`;
//! on every other target this crate is intentionally empty so the
//! cross-platform workspace build stays green. Type-check it with
//! `cargo check --target x86_64-pc-windows-msvc`. Hardware claims
//! additionally require a Windows reader and a real card before
//! reaching `main`.
//!
//! Public build, installation, and acceptance rules live in the
//! repository root documentation.

// The crate is unsafe FFI by construction (the Card Module ABI is a
// C function table the Base CSP/KSP calls). Workspace lints deny
// `unsafe_code` everywhere else; this crate, like the PKCS#11
// cdylib, is one of the few places that legitimately needs it. Every
// `unsafe` block is still explicit (`unsafe_op_in_unsafe_fn` denied
// below). On non-windows the crate is empty and the allow is inert.
// Some Card Module ABI slots are deliberately represented even when
// the current read-only card profile rejects the corresponding
// operation. `expect` (not `allow`) keeps each exception visible and
// makes a vanished exception noisy.
#![cfg_attr(
    windows,
    expect(
        clippy::missing_const_for_fn,
        reason = "The unsupported Card Module stubs intentionally mirror the runtime function-pointer ABI surface; if clippy stops seeing them as trivial constant returns, this expectation should go noisy"
    )
)]
#![cfg_attr(
    windows,
    expect(
        clippy::option_if_let_else,
        reason = "This ABI adapter prefers explicit early-return control flow over stylistic map_or rewrites; if the pattern disappears the expectation should go noisy"
    )
)]
#![cfg_attr(
    any(windows, test),
    expect(
        unsafe_code,
        reason = "the Card Module ABI is a C function table the Base CSP/KSP calls -- extern \"system\" FFI over caller-provided pointers is the entire point"
    )
)]
#![deny(unsafe_op_in_unsafe_fn)]
// The Card Module ABI mirrors `cardmod.h`: struct fields, entry-point
// parameters, and callbacks keep the exact Windows SDK spelling
// (`pCardData`, `dwFlags`, `bContainerIndex`, ...) so the code stays
// line-comparable with Microsoft's headers and documentation.
// `allow` (not `expect`) because the lint fires on hundreds of
// SDK-named items by design, not as leftover debt.
#![cfg_attr(
    any(windows, test),
    allow(
        non_snake_case,
        non_camel_case_types,
        non_upper_case_globals,
        reason = "Card Module ABI names stay line-comparable with the Windows SDK"
    )
)]

#[cfg(windows)]
mod card_driver;
#[cfg(windows)]
mod card_registrations;
#[cfg(windows)]
mod card_roots;
#[cfg(windows)]
mod cardmod;
#[cfg(any(windows, test))]
mod ffi;
#[cfg(windows)]
mod ksp;
#[cfg(windows)]
mod ksp_register;
#[cfg(windows)]
mod ksp_verify;
// Pure byte codecs: compiled on the host too so `cargo test` covers them.
#[cfg(any(windows, test))]
mod apdu_bridge;
#[cfg(any(windows, test))]
mod ksp_codec;
#[cfg(any(windows, test))]
mod pin_scheme;
#[cfg(all(windows, debug_assertions))]
mod reported;
#[cfg(windows)]
mod transport;

/// The Card Module entry point `name` as the function table installs it: a
/// development build installs the wrapper in [`reported`] that reports a
/// failing return.
#[cfg(all(windows, debug_assertions))]
macro_rules! entry {
    ($name:ident) => {
        reported::$name
    };
}

/// The Card Module entry point `name` as the function table installs it.
#[cfg(all(windows, not(debug_assertions)))]
macro_rules! entry {
    ($name:ident) => {
        $name
    };
}

#[cfg(windows)]
use core::mem::size_of;
#[cfg(windows)]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(windows)]
use std::sync::Mutex;

#[cfg(windows)]
use cardmod::{
    CardCapabilityModel, CardModel, ContainerDescriptor, Ctx, KeyAlgorithm, PIN_ID_AUTH,
    PIN_ID_PUK, PIN_ID_QUALIFIED_SIG, create_pin_set,
};
#[cfg(any(windows, test))]
#[allow(
    clippy::wildcard_imports,
    reason = "The Card Module implementation mirrors the complete crate-private Windows ABI table"
)]
use ffi::*;
#[cfg(windows)]
use refineid_agent_pipe::identity::{calling_program, computer_name, interface_language};
#[cfg(windows)]
use refineid_agent_pipe::{RemoteKey, in_process_operation};
#[cfg(windows)]
use refineid_digest::{Sha256, Sha384};
#[cfg(windows)]
use refineid_lib_core::auth::{
    AuthError, ChangePinOutcome, PIN_MAX_LENGTH, PIN_MIN_LENGTH, PUK_MAX_LENGTH, PUK_MIN_LENGTH,
    PinOps, PinReferenceScheme, PinSlot, PinStatus, PukStatus, UnblockOutcome, VerifyOutcome,
};
#[cfg(windows)]
use refineid_lib_core::crypto::container::{Ciphertext, RsaPkcs1};
#[cfg(windows)]
use refineid_lib_core::pin::PinBytes;
#[cfg(windows)]
use refineid_lib_core::pin_cache::PinSafetyCache;
#[cfg(windows)]
use refineid_lib_core::pin_retry_risk::{
    RetryFloorRefusal, check_puk_retry_floor, check_retry_floor, reports_no_tries_left,
};
#[cfg(windows)]
use refineid_lib_core::pkcs15::{CertSlot, Pkcs15Ops};
#[cfg(windows)]
use refineid_lib_core::sign::{KeyRef, SignOps, commands::ExternalHashValue};
#[cfg(windows)]
use refineid_lib_core::x509::{EcCurve, OwnedCert, PublicKeyAlgorithm, extract_rsa_public_key};
#[cfg(windows)]
use refineid_pace::{Can, OpenedByCan, PaceError, PaceSession, read_card_access, run_pace};
#[cfg(windows)]
use refineid_pkcs15::{TokenSerial, render_token_serial};
#[cfg(windows)]
use refineid_rapp_core::operations::{CardOperationResult, KeyProfile, SignatureAlgorithm};
#[cfg(windows)]
use refineid_windows_credential_store::card_certificates::CardId;
#[cfg(windows)]
use refineid_windows_credential_store::{ProtectedPairingStore, read_can};
#[cfg(windows)]
use transport::{
    CardSessionTransport, RemoteCardTransport, SCARD_ATTR_CURRENT_PROTOCOL_TYPE, ScardProtocol,
    WinScardTransport, is_remote_card,
};

#[cfg(windows)]
fn live_token_serial(tx: &mut CardSessionTransport) -> Result<TokenSerial, DWORD> {
    tx.read_token_info()
        .map_err(|_error| SCARD_F_INTERNAL_ERROR)?
        .serial_number_hex
        .map(render_token_serial)
        .filter(|serial| !serial.as_str().is_empty())
        .ok_or(SCARD_F_INTERNAL_ERROR)
}

#[cfg(windows)]
fn report_prepare_failure(failure: pin_scheme::PinPrepareFailure) -> DWORD {
    if failure == pin_scheme::PinPrepareFailure::PinLengths {
        refineid_dev_errors::report!(
            CardModule,
            "PIN lengths not read",
            "the card session failed"
        );
    }
    SCARD_F_INTERNAL_ERROR
}

/// Resolve the card's credential numbering, probe `slot`'s counter
/// without spending a try, and apply the retry floor.
#[cfg(windows)]
fn live_verify_floor(
    tx: &mut CardSessionTransport,
    slot: PinSlot,
) -> Result<(PinReferenceScheme, PinStatus), DWORD> {
    let (scheme, status) =
        pin_scheme::prepare_pin_verify(tx, slot).map_err(report_prepare_failure)?;
    retry_floor_answer(slot, status)?;
    Ok((scheme, status))
}

/// Apply the retry floor to `slot` before any command that can spend one
/// of its attempts. A refusal below the floor answers
/// `SCARD_W_CHV_BLOCKED`, which routes the user to the PUK; a counter the
/// card did not report answers `SCARD_F_INTERNAL_ERROR`, since no PIN was
/// presented. At zero tries left or a blocked PIN the command goes out and
/// the card's answer reports it blocked.
#[cfg(windows)]
fn retry_floor_answer(slot: PinSlot, status: PinStatus) -> Result<(), DWORD> {
    check_retry_floor(slot.into(), status).map_err(|refusal| match refusal {
        RetryFloorRefusal::TriesBelowFloor { .. } => {
            refineid_dev_errors::report!(
                CardModule,
                "PIN not tried",
                "the retry counter is below its floor"
            );
            SCARD_W_CHV_BLOCKED
        }
        RetryFloorRefusal::CounterUnreadable { .. } => {
            refineid_dev_errors::report!(
                CardModule,
                "PIN not tried",
                "the retry counter is unreadable"
            );
            SCARD_F_INTERNAL_ERROR
        }
    })
}

/// Apply the PUK retry floor to a counter read under the card's resolved
/// numbering before anything that presents the PUK. A PUK at two or
/// one tries left answers `SCARD_W_CHV_BLOCKED`; a counter the card did
/// not report answers `SCARD_F_INTERNAL_ERROR`. At zero tries left or a
/// blocked PUK the floor admits the command: the card answers for
/// itself and spends nothing, and [`map_unblock_outcome`] reports its
/// answer. The target PIN's counter does not gate the unblock.
#[cfg(windows)]
fn puk_floor_answer(status: PukStatus) -> Result<(), DWORD> {
    check_puk_retry_floor(status).map_err(|refusal| match refusal {
        RetryFloorRefusal::TriesBelowFloor { .. } => {
            refineid_dev_errors::report!(
                CardModule,
                "PUK not tried",
                "the retry counter is below its floor"
            );
            SCARD_W_CHV_BLOCKED
        }
        RetryFloorRefusal::CounterUnreadable { .. } => {
            refineid_dev_errors::report!(
                CardModule,
                "PUK not tried",
                "the retry counter is unreadable"
            );
            SCARD_F_INTERNAL_ERROR
        }
    })
}

/// The answer for a PIN change or reset the card service refused: an
/// entry of a length the card does not accept is an invalid parameter,
/// as a malformed entry is; a transport failure is internal.
#[cfg(windows)]
fn manage_error_answer<TE>(error: &AuthError<TE>) -> DWORD {
    match error {
        AuthError::PinPolicy(_reason) => SCARD_E_INVALID_PARAMETER,
        AuthError::Transport(_error) => SCARD_F_INTERNAL_ERROR,
    }
}

/// Hold a card-confirmed PIN 1 after `VERIFY` succeeded.
///
/// A successful PIN 1 `VERIFY` restores the card's retry counter to the try
/// limit (FINEID S1 v4.2 section 3.5), so caching is allowed after that
/// card-confirmed success even if the operation started at 4/5 or 3/5.
/// Prior to verification success nothing is cached, and every subsequent
/// checkout re-verifies the live serial and retry counter.
#[cfg(windows)]
fn hold_verified_pin1(serial: TokenSerial, pin: PinBytes) {
    let _ = with_pin_safety(|cache| cache.store_pin1(serial, pin));
}

#[cfg(windows)]
const MAX_ATR_LEN: usize = 33;
#[cfg(windows)]
#[expect(
    clippy::too_many_lines,
    reason = "CardAcquireContext is the ABI entry point that validates CARD_DATA, probes the handle, reads the auth cert, and installs the vendor context in one place"
)]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn CardAcquireContext(
    pCardData: *mut CARD_DATA,
    _dwFlags: DWORD,
) -> DWORD {
    if pCardData.is_null() {
        refineid_dev_errors::report!(CardModule, "CardAcquireContext failed", "no card data");
        return SCARD_E_INVALID_PARAMETER;
    }
    let cd = unsafe { &mut *pCardData };

    if cd.dwVersion < CARD_DATA_VERSION_FOUR {
        refineid_dev_errors::report!(
            CardModule,
            "CardAcquireContext failed",
            "card data version unsupported"
        );
        return SCARD_E_UNSUPPORTED_FEATURE;
    }

    cd.dwVersion = cd.dwVersion.min(CARD_DATA_VERSION_SIX);

    if cd.pbAtr.is_null() || cd.cbAtr == 0 || cd.hScard == 0 {
        refineid_dev_errors::report!(
            CardModule,
            "CardAcquireContext failed",
            "no ATR or card handle"
        );
        return SCARD_E_INVALID_PARAMETER;
    }
    let atr_len = usize::try_from(cd.cbAtr).unwrap_or(usize::MAX);
    if atr_len > MAX_ATR_LEN {
        refineid_dev_errors::report!(CardModule, "CardAcquireContext failed", "ATR too long");
        return SCARD_E_INVALID_PARAMETER;
    }
    let atr = unsafe { core::slice::from_raw_parts(cd.pbAtr, atr_len) }.to_vec();

    let mut proto_buf = [0_u8; 4];
    let mut proto_len = 4_u32;
    let proto_rc = unsafe {
        transport::SCardGetAttrib(
            cd.hScard,
            SCARD_ATTR_CURRENT_PROTOCOL_TYPE,
            proto_buf.as_mut_ptr(),
            &raw mut proto_len,
        )
    };
    let protocol = if proto_rc == SCARD_S_SUCCESS && proto_len == 4 {
        let raw = u32::from_le_bytes(proto_buf);
        ScardProtocol::from_pcsc(raw).unwrap_or(ScardProtocol::T1)
    } else {
        ScardProtocol::T1
    };

    let (transport, auth_cert_der, signature_cert_der) = if is_remote_card(&atr) {
        let store = match ProtectedPairingStore::load() {
            Ok(s) => s,
            Err(e) => {
                refineid_dev_errors::report!(CardModule, "CardAcquireContext failed", e);
                return SCARD_F_INTERNAL_ERROR;
            }
        };
        let Some(pairing) = store.usable_pairing() else {
            refineid_dev_errors::report!(
                CardModule,
                "CardAcquireContext failed",
                "no usable pairing"
            );
            return SCARD_E_UNKNOWN_CARD;
        };
        let pair_id = pairing.pair_id();
        // The card is offered on the certificate whose card a session heard
        // present within the grace, and on nothing else (RAPP v26.11.2
        // section 8.4 items 2 and 3). No store keeps it: the process that
        // holds the phone's session offers it in the personal store, and it
        // is read from there.
        let Some(auth) = refineid_windows_credential_store::offered_phone_certificate(
            &store,
            pair_id,
            refineid_rapp_core::clock::unix_time_ms(),
        ) else {
            refineid_dev_errors::report!(
                CardModule,
                "CardAcquireContext failed",
                "no session heard the phone's card within the grace"
            );
            return SCARD_E_UNKNOWN_CARD;
        };
        // The authentication certificate is the only one offered
        // (refineid-core `doc/security/certificate-custody.md`); it answers
        // for both containers of the remote card.
        let (auth_der, sig_der) = (auth.as_der().to_vec(), auth.as_der().to_vec());

        let remote_tx = RemoteCardTransport::new(atr, pair_id);
        (CardSessionTransport::remote(remote_tx), auth_der, sig_der)
    } else {
        let mut raw_transport = WinScardTransport {
            h_card: cd.hScard,
            atr,
            protocol,
        };

        let (mut transport, auth_cert_der) = match raw_transport
            .read_certificate(CertSlot::Authentication)
        {
            Ok(cert) => (
                CardSessionTransport::plain(raw_transport),
                cert.as_bytes().to_vec(),
            ),
            Err(_plain_error) => {
                let can = match read_can(&raw_transport.atr) {
                    Ok(Some(can)) => can,
                    Ok(None) => {
                        refineid_dev_errors::report!(
                            CardModule,
                            "CardAcquireContext failed",
                            "the certificate is sealed and no card access number is saved"
                        );
                        return SCARD_F_INTERNAL_ERROR;
                    }
                    Err(error) => {
                        refineid_dev_errors::report!(
                            CardModule,
                            "card access number not read",
                            error
                        );
                        return SCARD_F_INTERNAL_ERROR;
                    }
                };
                let pace_session = match open_minidriver_pace(&mut raw_transport, &can) {
                    Ok(session) => session,
                    Err(error) => {
                        refineid_dev_errors::report!(CardModule, "contactless PACE failed", error);
                        return SCARD_F_INTERNAL_ERROR;
                    }
                };
                let mut protected = CardSessionTransport::protected(raw_transport, pace_session);
                let cert = match protected.read_certificate(CertSlot::Authentication) {
                    Ok(cert) => cert.as_bytes().to_vec(),
                    Err(error) => {
                        refineid_dev_errors::report!(
                            CardModule,
                            "authentication certificate not read",
                            error
                        );
                        return SCARD_F_INTERNAL_ERROR;
                    }
                };
                (protected, cert)
            }
        };
        let signature_cert_der = match transport.read_certificate(CertSlot::Signature) {
            Ok(cert) => cert.as_bytes().to_vec(),
            Err(error) => {
                refineid_dev_errors::report!(CardModule, "signature certificate not read", error);
                return SCARD_F_INTERNAL_ERROR;
            }
        };
        (transport, auth_cert_der, signature_cert_der)
    };

    let Some(card) = CardModel::build_card_model(cd, auth_cert_der, signature_cert_der) else {
        refineid_dev_errors::report!(
            CardModule,
            "CardAcquireContext failed",
            "the card model was not built"
        );
        return SCARD_F_INTERNAL_ERROR;
    };

    let ctx = Box::new(Ctx {
        transport: Mutex::new(transport),
        card,
        pin1_authenticated: false,
        pin2_authenticated: false,
        pin2_scheme: PinReferenceScheme::Citizen,
    });
    cd.pvVendorSpecific = Box::into_raw(ctx).cast();

    cd.pfnCardDeleteContext = Some(entry!(CardDeleteContext));
    cd.pfnCardQueryCapabilities = Some(entry!(CardQueryCapabilities));
    cd.pfnCardDeleteContainer = Some(unsupported_delete_container);
    cd.pfnCardCreateContainer = Some(unsupported_create_container);
    cd.pfnCardGetContainerInfo = Some(entry!(CardGetContainerInfo));
    cd.pfnCardAuthenticatePin = Some(entry!(CardAuthenticatePin));
    cd.pfnCardGetChallenge = Some(unsupported_get_challenge);
    cd.pfnCardAuthenticateChallenge = Some(unsupported_authenticate_challenge);
    cd.pfnCardUnblockPin = Some(entry!(CardUnblockPin));
    cd.pfnCardChangeAuthenticator = Some(entry!(CardChangeAuthenticator));
    cd.pfnCardDeauthenticate = Some(entry!(CardDeauthenticate));
    cd.pfnCardCreateDirectory = Some(unsupported_create_directory);
    cd.pfnCardDeleteDirectory = Some(unsupported_delete_directory);
    cd.pvUnused3 = core::ptr::null_mut();
    cd.pvUnused4 = core::ptr::null_mut();
    cd.pfnCardCreateFile = Some(unsupported_create_file);
    cd.pfnCardReadFile = Some(entry!(CardReadFile));
    cd.pfnCardWriteFile = Some(unsupported_write_file);
    cd.pfnCardDeleteFile = Some(unsupported_delete_file);
    cd.pfnCardEnumFiles = Some(entry!(CardEnumFiles));
    cd.pfnCardGetFileInfo = Some(entry!(CardGetFileInfo));
    cd.pfnCardQueryFreeSpace = Some(entry!(CardQueryFreeSpace));
    cd.pfnCardQueryKeySizes = Some(entry!(CardQueryKeySizes));
    cd.pfnCardSignData = Some(entry!(CardSignData));
    cd.pfnCardRSADecrypt = Some(entry!(CardRSADecrypt));
    cd.pfnCardConstructDHAgreement = None;

    if cd.dwVersion >= CARD_DATA_VERSION_FIVE {
        cd.pfnCardDeriveKey = None;
        cd.pfnCardDestroyDHAgreement = None;
        cd.pfnCspGetDHAgreement = None;
    }
    if cd.dwVersion >= CARD_DATA_VERSION_SIX {
        cd.pfnCardGetChallengeEx = Some(unsupported_get_challenge_ex);
        cd.pfnCardAuthenticateEx = Some(entry!(CardAuthenticateEx));
        cd.pfnCardChangeAuthenticatorEx = Some(entry!(CardChangeAuthenticatorEx));
        cd.pfnCardDeauthenticateEx = Some(entry!(CardDeauthenticateEx));
        cd.pfnCardGetContainerProperty = Some(entry!(CardGetContainerProperty));
        cd.pfnCardSetContainerProperty = Some(unsupported_set_container_property);
        cd.pfnCardGetProperty = Some(entry!(CardGetProperty));
        cd.pfnCardSetProperty = Some(unsupported_set_property);
    }

    SCARD_S_SUCCESS
}

#[cfg(windows)]
unsafe extern "system" fn CardDeleteContext(pCardData: *mut CARD_DATA) -> DWORD {
    if pCardData.is_null() {
        return SCARD_E_INVALID_PARAMETER;
    }
    let cd = unsafe { &mut *pCardData };
    if !cd.pvVendorSpecific.is_null() {
        unsafe {
            drop(Box::from_raw(cd.pvVendorSpecific.cast::<Ctx>()));
        }
        cd.pvVendorSpecific = core::ptr::null_mut();
    }
    SCARD_S_SUCCESS
}

#[cfg(windows)]
unsafe extern "system" fn CardQueryCapabilities(
    _pCardData: *mut CARD_DATA,
    pCaps: *mut CARD_CAPABILITIES,
) -> DWORD {
    if pCaps.is_null() {
        return SCARD_E_INVALID_PARAMETER;
    }
    let caps = unsafe { &mut *pCaps };
    caps.dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
    caps.fCertificateCompression = 1;
    caps.fKeyGen = 0;
    SCARD_S_SUCCESS
}

#[cfg(windows)]
const RSA1_MAGIC: u32 = 0x3141_5352;
#[cfg(windows)]
const PUBLICKEYBLOB: u8 = 0x06;
#[cfg(windows)]
const CUR_BLOB_VERSION: u8 = 0x02;
#[cfg(windows)]
const CALG_RSA_KEYX: u32 = 0x0000_A400;
#[cfg(windows)]
const CALG_RSA_SIGN: u32 = 0x0000_2400;
#[cfg(windows)]
const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345;
#[cfg(windows)]
const BCRYPT_ECDSA_PUBLIC_P384_MAGIC: u32 = 0x3353_4345;

#[cfg(windows)]
fn try_dword_len(len: usize) -> Option<DWORD> {
    DWORD::try_from(len).ok()
}

#[cfg(windows)]
static CARDCF_VALUE: AtomicU64 = AtomicU64::new(0);

#[cfg(windows)]
fn cardcf_initial_value() -> u64 {
    1
}

#[cfg(windows)]
unsafe fn cspalloc(cd: &CARD_DATA, len: usize) -> PVOID {
    match cd.pfnCspAlloc {
        Some(alloc) => unsafe { alloc(len) },
        None => core::ptr::null_mut(),
    }
}

#[cfg(windows)]
unsafe fn alloc_copy(cd: &CARD_DATA, data: &[u8]) -> Option<PBYTE> {
    let p = unsafe { cspalloc(cd, data.len()) };
    if p.is_null() {
        return None;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), p.cast::<u8>(), data.len());
    }
    Some(p.cast::<u8>())
}

#[cfg(windows)]
fn read_cstr(p: LPSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0_usize;
    unsafe {
        while *p.add(len) != 0 && len < 512 {
            len += 1;
        }
        let bytes = core::slice::from_raw_parts(p.cast::<u8>(), len);
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// The root directory of the minidriver's file system, as the
/// caller names it: no directory.
#[cfg(any(windows, test))]
const ROOT_DIRECTORY: Option<&str> = None;
/// The one directory under the root (Microsoft card minidriver
/// specification, "Card File System").
#[cfg(any(windows, test))]
const MSCP_DIRECTORY: &str = "mscp";
/// Root file: the cache freshness record.
#[cfg(any(windows, test))]
const CARDCF_FILE: &str = "cardcf";
/// Root file: the card identifier.
#[cfg(any(windows, test))]
const CARDID_FILE: &str = "cardid";
/// Root file: the application directory list.
#[cfg(any(windows, test))]
const CARDAPPS_FILE: &str = "cardapps";
/// `mscp` file: the container map.
#[cfg(any(windows, test))]
const CMAPFILE_FILE: &str = "cmapfile";
/// `mscp` file: the trusted roots bundle, which this card module never has.
/// Windows propagates a card's `msroots` certificates into the user's Root
/// store, trusted for every purpose; the DVV roots reach Windows through the
/// Microsoft Trusted Root Program and the issuing CA through the
/// authentication certificate's Authority Information Access.
#[cfg(any(windows, test))]
const MSROOTS_FILE: &str = "msroots";

/// One file of the minidriver's file system, resolved once from the
/// directory and file name a caller passed. A value names a file this
/// minidriver serves; the name comparisons live in [`Self::resolve`]
/// and nowhere else.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum CardFile {
    /// `cardcf`, the cache freshness record.
    CardCf,
    /// `cardid`, the card identifier.
    CardId,
    /// `cardapps`, the application directory list.
    CardApps,
    /// `mscp/cmapfile`, the container map.
    CmapFile,
    /// A certificate file under `mscp`, named by its container.
    Container(String),
}

/// Why a directory and file name resolve to no [`CardFile`].
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoSuchFile {
    /// The directory is not one this file system has.
    Directory,
    /// The directory exists; the file is not in it.
    File,
}

#[cfg(any(windows, test))]
impl CardFile {
    /// The file `directory` and `file` name. The root holds the three
    /// card files; `mscp` holds the container map and one certificate
    /// file per container, and answers `cardcf` too, as some callers ask
    /// for it there. It has no `msroots`, the one Base CSP file a
    /// read-only card may lack (minidriver specification v7.07,
    /// "Read-Only Cards"). Whether a container file exists is the card
    /// model's to say, so a `Container` is any other `mscp` name.
    fn resolve(directory: Option<&str>, file: &str) -> Result<Self, NoSuchFile> {
        match directory {
            ROOT_DIRECTORY => match file {
                CARDCF_FILE => Ok(Self::CardCf),
                CARDID_FILE => Ok(Self::CardId),
                CARDAPPS_FILE => Ok(Self::CardApps),
                _ => Err(NoSuchFile::File),
            },
            Some(MSCP_DIRECTORY) => match file {
                CMAPFILE_FILE => Ok(Self::CmapFile),
                MSROOTS_FILE => Err(NoSuchFile::File),
                CARDCF_FILE => Ok(Self::CardCf),
                other => Ok(Self::Container(other.to_owned())),
            },
            Some(_) => Err(NoSuchFile::Directory),
        }
    }
}

/// The directory a caller passed: `None` for the root.
#[cfg(windows)]
fn read_directory(p: LPSTR) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(read_cstr(p))
    }
}

/// The bytes of `file` on this card, or `None` for a container file
/// the card does not have.
#[cfg(windows)]
fn card_file_bytes(card: &CardCapabilityModel, file: &CardFile) -> Option<Vec<u8>> {
    match file {
        CardFile::CardCf => Some(synth_cardcf()),
        CardFile::CardId => Some(synth_cardid(card.auth_cert_der().unwrap_or(&[]))),
        CardFile::CardApps => Some(synth_cardapps()),
        CardFile::CmapFile => Some(synth_cmapfile(card)),
        CardFile::Container(name) => container_file_bytes(card, name),
    }
}

/// The status a failed lookup answers.
#[cfg(windows)]
const fn no_such_file_status(reason: NoSuchFile) -> DWORD {
    match reason {
        NoSuchFile::Directory => SCARD_E_DIR_NOT_FOUND,
        NoSuchFile::File => SCARD_E_FILE_NOT_FOUND,
    }
}

#[cfg(windows)]
unsafe fn checked_card_data_and_ctx<'a>(
    pCardData: *mut CARD_DATA,
) -> Result<(&'a CARD_DATA, &'a Ctx), DWORD> {
    if pCardData.is_null() {
        return Err(SCARD_E_INVALID_PARAMETER);
    }
    let cd = unsafe { &*pCardData };
    if cd.pvVendorSpecific.is_null() {
        return Err(SCARD_E_INVALID_HANDLE);
    }
    let ctx = unsafe { &*(cd.pvVendorSpecific.cast::<Ctx>()) };
    Ok((cd, ctx))
}

#[cfg(windows)]
unsafe fn checked_card_data_and_ctx_mut<'a>(
    pCardData: *mut CARD_DATA,
) -> Result<(&'a CARD_DATA, &'a mut Ctx), DWORD> {
    if pCardData.is_null() {
        return Err(SCARD_E_INVALID_PARAMETER);
    }
    let cd = unsafe { &*pCardData };
    if cd.pvVendorSpecific.is_null() {
        return Err(SCARD_E_INVALID_HANDLE);
    }
    let ctx = unsafe { &mut *(cd.pvVendorSpecific.cast::<Ctx>()) };
    Ok((cd, ctx))
}

#[cfg(windows)]
fn lock_transport(
    transport: &Mutex<CardSessionTransport>,
) -> std::sync::MutexGuard<'_, CardSessionTransport> {
    match transport.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(windows)]
const INVALID_SCARD_HANDLE: SCARDHANDLE = 0;

/// Select the Master File, read `EF.CardAccess`, and establish a PACE session
/// using the stored Card Access Number.
#[cfg(windows)]
fn open_minidriver_pace(
    raw: &mut WinScardTransport,
    can: &Can,
) -> Result<PaceSession<OpenedByCan>, PaceError<transport::TransportError>> {
    let _master_file_selection = raw.select_mf();
    let card_access = read_card_access(raw)?;
    run_pace(raw, &card_access, can)
}

/// The Base CSP may reconnect and hand a different `SCARDHANDLE`
/// between entry points. Refresh the transport handle from the live
/// `CARD_DATA` and drop in-process PIN state on change -- a new
/// handle means the card's security state was reset, so any prior
/// PIN verification no longer holds card-side (legacy parity).
#[cfg(windows)]
fn sync_transport_handle(
    tx: &mut CardSessionTransport,
    pin1_authenticated: &mut bool,
    pin2_authenticated: &mut bool,
    live_h_card: SCARDHANDLE,
) -> Result<bool, DWORD> {
    if tx.is_remote() {
        return Ok(false);
    }
    if live_h_card == INVALID_SCARD_HANDLE {
        return Err(SCARD_E_INVALID_HANDLE);
    }
    if tx.h_card() == live_h_card {
        return Ok(false);
    }

    *pin1_authenticated = false;
    *pin2_authenticated = false;

    if tx.is_protected() {
        let can = match read_can(tx.atr_bytes()) {
            Ok(Some(can)) => can,
            Ok(None) => {
                refineid_dev_errors::report!(
                    CardModule,
                    "card handle refresh failed",
                    "no card access number is saved"
                );
                return Err(SCARD_F_INTERNAL_ERROR);
            }
            Err(error) => {
                refineid_dev_errors::report!(CardModule, "card access number not read", error);
                return Err(SCARD_F_INTERNAL_ERROR);
            }
        };
        tx.refresh_protected(live_h_card, |raw| open_minidriver_pace(raw, &can))
            .map_err(|error| {
                refineid_dev_errors::report!(CardModule, "contactless PACE failed", error);
                SCARD_F_INTERNAL_ERROR
            })?;
    } else {
        tx.set_plain_h_card(live_h_card);
    }
    Ok(true)
}

/// Access the process-wide PIN safety cache. Holds positive PIN caches
/// and process-lifetime rejection memory across Card Module contexts.
#[cfg(windows)]
#[expect(
    clippy::significant_drop_tightening,
    reason = "closure f requires mutable access to the PinSafetyCache while holding the lock"
)]
fn with_pin_safety<R>(f: impl FnOnce(&mut PinSafetyCache) -> R) -> Result<R, DWORD> {
    static PIN_SAFETY: Mutex<Option<PinSafetyCache>> = Mutex::new(None);
    let mut guard = PIN_SAFETY.lock().map_err(|_| SCARD_F_INTERNAL_ERROR)?;
    if guard.is_none() {
        let cache = PinSafetyCache::new().map_err(|_| SCARD_F_INTERNAL_ERROR)?;
        *guard = Some(cache);
    }
    let cache = guard.as_mut().ok_or(SCARD_F_INTERNAL_ERROR)?;
    Ok(f(cache))
}

/// Re-verify the cached PIN on the card right before a private-key
/// operation. The Base CSP can reset the card between the PIN entry
/// and the sign call (each reconnect drops the card's security
/// state), which surfaces as `NTE_INTERNAL_ERROR` from the KSP and
/// `ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED` in Edge. Returns
/// `Some(error)` when verification is required but fails.
#[cfg(windows)]
fn reverify_cached_pin(
    pin1_authenticated: &mut bool,
    pin2_authenticated: &mut bool,
    tx: &mut CardSessionTransport,
    pin_id: DWORD,
) -> Option<DWORD> {
    if tx.is_remote() {
        return None;
    }
    if pin_id == PIN_ID_QUALIFIED_SIG {
        return if *pin2_authenticated {
            None
        } else {
            Some(SCARD_W_WRONG_CHV)
        };
    }
    // A failed read is a transport failure: the held PIN 1 stays, and the
    // retry counter read before its next use decides (RAPP v26.11.2
    // section 11 item 2).
    let serial = match live_token_serial(tx) {
        Ok(serial) => serial,
        Err(error) => {
            reset_card_state(pin1_authenticated, pin2_authenticated);
            return Some(error);
        }
    };
    let (scheme, status) = match pin_scheme::prepare_pin_verify(tx, PinSlot::Pin1) {
        Ok(prepared) => prepared,
        Err(failure) => {
            reset_card_state(pin1_authenticated, pin2_authenticated);
            return Some(report_prepare_failure(failure));
        }
    };
    if let Err(error) = retry_floor_answer(PinSlot::Pin1, status) {
        clear_pin_state(pin1_authenticated, pin2_authenticated);
        return Some(error);
    }
    let slot = PinSlot::Pin1;
    let checkout = with_pin_safety(|cache| cache.checkout_pin1(&serial, status))
        .ok()
        .flatten();
    // A held value is never handed out for a blocked PIN 1; the lock is
    // reported as the reason, from this reading, with nothing presented.
    let Some(checkout) = checkout else {
        return Some(if reports_no_tries_left(status) {
            SCARD_W_CHV_BLOCKED
        } else {
            SCARD_W_WRONG_CHV
        });
    };
    let pin = checkout.pin().clone();
    let is_rejected =
        with_pin_safety(|cache| cache.is_rejected(&serial, slot, &pin)).unwrap_or(false);
    if is_rejected {
        clear_pin_state(pin1_authenticated, pin2_authenticated);
        refineid_dev_errors::report!(
            CardModule,
            "held PIN 1 not used",
            "the card rejected it before"
        );
        return Some(SCARD_W_WRONG_CHV);
    }
    let outcome = tx.verify_pin_with_scheme(scheme, PinSlot::Pin1, pin.clone());
    match outcome {
        Ok(VerifyOutcome::Ok) => {
            let _ = with_pin_safety(|cache| checkout.restore_after_success(cache));
            *pin1_authenticated = true;
            None
        }
        Ok(VerifyOutcome::WrongPin { .. }) => {
            let _ = with_pin_safety(|cache| cache.record_rejected(&serial, slot, &pin));
            clear_pin_state(pin1_authenticated, pin2_authenticated);
            refineid_dev_errors::report!(
                CardModule,
                "held PIN 1 not verified",
                "the card rejected it"
            );
            Some(SCARD_W_WRONG_CHV)
        }
        Ok(VerifyOutcome::Locked) => {
            clear_pin_state(pin1_authenticated, pin2_authenticated);
            refineid_dev_errors::report!(
                CardModule,
                "held PIN 1 not verified",
                "the PIN is blocked"
            );
            Some(SCARD_W_CHV_BLOCKED)
        }
        Ok(other) => {
            clear_pin_state(pin1_authenticated, pin2_authenticated);
            refineid_dev_errors::report!(CardModule, "held PIN 1 not verified", other);
            Some(SCARD_W_WRONG_CHV)
        }
        Err(err) => {
            let _ = with_pin_safety(|cache| checkout.restore_after_unanswered(cache));
            reset_card_state(pin1_authenticated, pin2_authenticated);
            refineid_dev_errors::report!(CardModule, "held PIN 1 not verified", err);
            Some(SCARD_F_INTERNAL_ERROR)
        }
    }
}

#[cfg(any(windows, test))]
pub(crate) unsafe fn read_wstr(p: LPCWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0_usize;
    while unsafe { *p.add(len) } != 0 && len < 256 {
        len += 1;
    }
    let slice = unsafe { core::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsedSigningPadding {
    Pkcs1 { hash_name: Option<String> },
    Pss { hash_name: String, salt_len: usize },
}

#[cfg(any(windows, test))]
pub(crate) unsafe fn parse_signing_padding(
    p_info: *const CARD_SIGNING_INFO,
) -> Result<ParsedSigningPadding, DWORD> {
    if p_info.is_null() {
        return Err(SCARD_E_INVALID_PARAMETER);
    }
    let dw_version = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*p_info).dwVersion)) };
    if !(CARD_SIGNING_INFO_BASIC_VERSION..=CARD_SIGNING_INFO_CURRENT_VERSION).contains(&dw_version)
    {
        return Err(SCARD_E_INVALID_PARAMETER);
    }
    let basic = unsafe { &*p_info.cast::<CARD_SIGNING_INFO_BASIC>() };
    if dw_version >= CARD_SIGNING_INFO_CURRENT_VERSION
        && (basic.dwSigningFlags & CARD_PADDING_INFO_PRESENT) != 0
    {
        let v2 = unsafe { &*p_info };
        match v2.dwPaddingType {
            CARD_PADDING_PKCS1 => {
                let hash_name = if v2.pPaddingInfo.is_null() {
                    None
                } else {
                    let pad = unsafe { &*v2.pPaddingInfo.cast::<BCRYPT_PKCS1_PADDING_INFO>() };
                    if pad.pszAlgId.is_null() {
                        None
                    } else {
                        Some(unsafe { read_wstr(pad.pszAlgId) }.to_uppercase())
                    }
                };
                Ok(ParsedSigningPadding::Pkcs1 { hash_name })
            }
            CARD_PADDING_PSS => {
                if v2.pPaddingInfo.is_null() {
                    return Err(SCARD_E_INVALID_PARAMETER);
                }
                let pad = unsafe { &*v2.pPaddingInfo.cast::<BCRYPT_PSS_PADDING_INFO>() };
                let hash_name = if pad.pszAlgId.is_null() {
                    String::from("SHA256")
                } else {
                    unsafe { read_wstr(pad.pszAlgId) }.to_uppercase()
                };
                let salt_len = pad.cbSalt as usize;
                Ok(ParsedSigningPadding::Pss {
                    hash_name,
                    salt_len,
                })
            }
            _ => Err(SCARD_E_UNSUPPORTED_FEATURE),
        }
    } else {
        // v1 callers or v2 without CARD_PADDING_INFO_PRESENT default to PKCS#1 v1.5 per cardmod.h.
        // v2.pPaddingInfo and v2.dwPaddingType are unpopulated and MUST NOT be read.
        Ok(ParsedSigningPadding::Pkcs1 { hash_name: None })
    }
}

#[cfg(any(windows, test))]
pub(crate) unsafe fn parse_rsa_decrypt_padding(p_info: PVOID) -> Result<(), DWORD> {
    if p_info.is_null() {
        return Err(SCARD_E_INVALID_PARAMETER);
    }
    let dw_version = unsafe { core::ptr::read_unaligned(p_info.cast::<DWORD>()) };
    if !(CARD_RSA_DECRYPT_INFO_BASIC_VERSION..=CARD_RSA_DECRYPT_INFO_CURRENT_VERSION)
        .contains(&dw_version)
    {
        return Err(SCARD_E_INVALID_PARAMETER);
    }
    if dw_version >= CARD_RSA_DECRYPT_INFO_CURRENT_VERSION {
        let v2 = unsafe { &*p_info.cast::<CARD_RSA_DECRYPT_INFO>() };
        if v2.dwPaddingType == CARD_PADDING_NONE {
            return Err(SCARD_E_UNSUPPORTED_FEATURE);
        }
        if v2.dwPaddingType != CARD_PADDING_PKCS1 {
            return Err(SCARD_E_UNSUPPORTED_FEATURE);
        }
    }
    // v1 callers always imply PKCS#1 v1.5 per cardmod.h.
    Ok(())
}

#[cfg(windows)]
unsafe fn pin_id_from_user_id(pwszUserId: LPWSTR) -> DWORD {
    if pwszUserId.is_null() {
        return PIN_ID_AUTH;
    }
    let text = unsafe { read_wstr(pwszUserId.cast_const()) };
    if text.eq_ignore_ascii_case("PIN2") || text.eq_ignore_ascii_case("SIGN") || text == "3" {
        PIN_ID_QUALIFIED_SIG
    } else if text.eq_ignore_ascii_case("PUK") || text.eq_ignore_ascii_case("ADMIN") || text == "2"
    {
        PIN_ID_PUK
    } else {
        PIN_ID_AUTH
    }
}

#[cfg(windows)]
fn external_hash_from_alg_and_bytes(_alg: DWORD, bytes: &[u8]) -> Option<ExternalHashValue> {
    match bytes.len() {
        20 => Some(ExternalHashValue::Sha1(bytes.try_into().ok()?)),
        32 => Some(ExternalHashValue::Sha256(bytes.try_into().ok()?)),
        48 => Some(ExternalHashValue::Sha384(bytes.try_into().ok()?)),
        64 => Some(ExternalHashValue::Sha512(bytes.try_into().ok()?)),
        // Some callers omit aiHashAlg or pass an unexpected value;
        // allow a length-based fallback so TLS-sign callers that
        // hand a plain digest still proceed.
        _ => None,
    }
}

#[cfg(windows)]
unsafe fn write_dword_out(pbData: PBYTE, cbData: DWORD, pdwDataLen: PDWORD, v: DWORD) -> DWORD {
    if !pdwDataLen.is_null() {
        unsafe {
            *pdwDataLen = 4;
        }
    }
    if pbData.is_null() || cbData < 4 {
        return SCARD_E_INSUFFICIENT_BUFFER;
    }
    let bytes = v.to_le_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), pbData, 4);
    }
    SCARD_S_SUCCESS
}

#[cfg(windows)]
unsafe fn write_bytes_out(pbData: PBYTE, cbData: DWORD, pdwDataLen: PDWORD, bytes: &[u8]) -> DWORD {
    let Some(byte_len) = try_dword_len(bytes.len()) else {
        return SCARD_F_INTERNAL_ERROR;
    };
    if !pdwDataLen.is_null() {
        unsafe {
            *pdwDataLen = byte_len;
        }
    }
    if pbData.is_null() || cbData < byte_len {
        return SCARD_E_INSUFFICIENT_BUFFER;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), pbData, bytes.len());
    }
    SCARD_S_SUCCESS
}

#[cfg(windows)]
unsafe fn write_struct_out<T>(
    pbData: PBYTE,
    cbData: DWORD,
    pdwDataLen: PDWORD,
    value: &T,
) -> DWORD {
    let size = size_of::<T>();
    let Some(struct_size) = try_dword_len(size) else {
        return SCARD_F_INTERNAL_ERROR;
    };
    if !pdwDataLen.is_null() {
        unsafe {
            *pdwDataLen = struct_size;
        }
    }
    if pbData.is_null() || cbData < struct_size {
        return SCARD_E_INSUFFICIENT_BUFFER;
    }
    let bytes =
        unsafe { core::slice::from_raw_parts(core::ptr::from_ref(value).cast::<u8>(), size) };
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), pbData, size);
    }
    SCARD_S_SUCCESS
}

#[cfg(windows)]
fn normalize_name(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(windows)]
unsafe fn wstr_eq(p: LPCWSTR, s: &str) -> bool {
    let got = unsafe { read_wstr(p) };
    got == s
}

#[cfg(windows)]
unsafe fn wstr_matches_any(p: LPCWSTR, aliases: &[&str]) -> bool {
    let got = normalize_name(&unsafe { read_wstr(p) });
    aliases.iter().any(|alias| got == normalize_name(alias))
}

#[cfg(windows)]
fn encode_multisz(values: &[&str]) -> Vec<u8> {
    let mut utf16 = Vec::<u16>::new();
    for value in values {
        utf16.extend(value.encode_utf16());
        utf16.push(0);
    }
    utf16.push(0);
    let mut bytes = Vec::with_capacity(utf16.len() * 2);
    for ch in utf16 {
        bytes.extend_from_slice(&ch.to_le_bytes());
    }
    bytes
}

#[cfg(windows)]
fn pin_purpose(pin_id: DWORD) -> DWORD {
    match pin_id {
        PIN_ID_QUALIFIED_SIG => NonRepudiationPin,
        PIN_ID_PUK => UnblockOnlyPin,
        _ => PrimaryCardPin,
    }
}

#[cfg(windows)]
fn pin_change_permission(pin_id: DWORD) -> DWORD {
    match pin_id {
        PIN_ID_AUTH => create_pin_set(PIN_ID_AUTH),
        PIN_ID_QUALIFIED_SIG => create_pin_set(PIN_ID_QUALIFIED_SIG),
        _ => PIN_SET_NONE,
    }
}

#[cfg(windows)]
fn pin_unblock_permission(pin_id: DWORD) -> DWORD {
    match pin_id {
        PIN_ID_AUTH | PIN_ID_QUALIFIED_SIG => create_pin_set(PIN_ID_PUK),
        _ => PIN_SET_NONE,
    }
}

/// `dwPinCachePolicyInfo` carries a value only for `PIN_CACHE_TIMED`, which
/// no PIN here uses.
#[cfg(windows)]
const NO_PIN_CACHE_POLICY_INFO: DWORD = 0;

/// The Base CSP's PIN caching for each PIN (RAPP v26.11.2 section 11 item
/// 2): PIN 1 in its process memory, as this module holds it; PIN 2 asked for
/// every signature.
#[cfg(windows)]
fn pin_cache_policy(pin_id: DWORD) -> DWORD {
    match pin_id {
        PIN_ID_AUTH => PIN_CACHE_NORMAL,
        PIN_ID_QUALIFIED_SIG => PIN_CACHE_ALWAYS_PROMPT,
        _ => PIN_CACHE_NONE,
    }
}

#[cfg(windows)]
fn authenticated_pin_set(ctx: &Ctx) -> DWORD {
    let mut pin_set = PIN_SET_NONE;
    let has_pin1 = ctx.pin1_authenticated
        || with_pin_safety(|cache| cache.has_positive_pin1()).unwrap_or(false);
    if has_pin1 {
        pin_set |= create_pin_set(PIN_ID_AUTH);
    }
    let has_pin2 = ctx.pin2_authenticated;
    if has_pin2 {
        pin_set |= create_pin_set(PIN_ID_QUALIFIED_SIG);
    }
    pin_set
}

/// The lengths an entry for `pin_id` may have before it reaches the card
/// service: what the PIN and PUK commands carry. The card service narrows
/// a PIN change or reset to the card's own lengths, and the card decides
/// any narrower range at VERIFY.
#[cfg(windows)]
fn pin_len_bounds(pin_id: DWORD) -> Option<(usize, usize)> {
    match pin_id {
        PIN_ID_AUTH | PIN_ID_QUALIFIED_SIG => Some((PIN_MIN_LENGTH, PIN_MAX_LENGTH)),
        PIN_ID_PUK => Some((PUK_MIN_LENGTH, PUK_MAX_LENGTH)),
        _ => None,
    }
}

#[cfg(windows)]
unsafe fn checked_pin_bytes(ptr: PBYTE, len: DWORD, pin_id: DWORD) -> Result<PinBytes, DWORD> {
    if ptr.is_null() || len == 0 {
        return Err(SCARD_E_INVALID_PARAMETER);
    }
    let (min_len, max_len) = pin_len_bounds(pin_id).ok_or(SCARD_E_INVALID_PARAMETER)?;
    let len_usize = usize::try_from(len).unwrap_or(usize::MAX);
    if len_usize < min_len || len_usize > max_len {
        return Err(SCARD_E_INVALID_PARAMETER);
    }
    PinBytes::new(unsafe { core::slice::from_raw_parts(ptr, len_usize) }.to_vec())
        .map_err(|_| SCARD_E_INVALID_PARAMETER)
}

#[cfg(windows)]
fn pin_slot_for_id(pin_id: DWORD) -> Option<PinSlot> {
    match pin_id {
        PIN_ID_AUTH => Some(PinSlot::Pin1),
        PIN_ID_QUALIFIED_SIG => Some(PinSlot::Pin2),
        _ => None,
    }
}

/// Remaining PIN tries reported to `CardAuthenticatePin` when the card
/// reports the PIN blocked.
#[cfg(windows)]
const NO_ATTEMPTS_REMAINING: DWORD = 0;

/// Session-PIN length reported by `CardAuthenticateEx`, which supports
/// plaintext PIN verification only.
#[cfg(windows)]
const NO_SESSION_PIN_LEN: DWORD = 0;

/// Which Card Module authentication entry point is verifying a PIN,
/// selecting its ABI-specific locked-attempts output and debug reporting.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerifyCaller {
    AuthenticatePin,
    AuthenticateEx,
}

#[cfg(windows)]
fn clear_cached_pin(ctx: &mut Ctx) {
    clear_pin_state(&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);
}

/// Destroys the held PIN 1 and forgets the card's verified state: the card
/// rejected a PIN, reported a retry counter that forbids reuse, or a new PIN
/// is being entered.
#[cfg(windows)]
fn clear_pin_state(pin1_authenticated: &mut bool, pin2_authenticated: &mut bool) {
    let _ = with_pin_safety(|cache| {
        cache.clear_positive();
    });
    reset_card_state(pin1_authenticated, pin2_authenticated);
}

/// Forgets the card's verified state after a transport failure or a failed
/// command: the held PIN 1 stays, and the retry counter read before its next
/// use decides (RAPP v26.11.2 section 11 item 2).
#[cfg(windows)]
const fn reset_card_state(pin1_authenticated: &mut bool, pin2_authenticated: &mut bool) {
    *pin1_authenticated = false;
    *pin2_authenticated = false;
}

/// PIN 2 is entered for every signature and never held (RAPP v26.11.2
/// section 11 item 2): the card spends it on one signature, and the next
/// one asks again.
#[cfg(windows)]
const fn spend_pin2(ctx: &mut Ctx) {
    ctx.pin2_authenticated = false;
}

#[cfg(windows)]
unsafe fn write_attempts_remaining(pcAttemptsRemaining: PDWORD, attempts: Option<DWORD>) {
    if let Some(attempts) = attempts
        && !pcAttemptsRemaining.is_null()
    {
        unsafe {
            *pcAttemptsRemaining = attempts;
        }
    }
}

#[cfg(windows)]
fn map_verify_outcome<E: core::fmt::Debug>(
    ctx: &mut Ctx,
    slot: PinSlot,
    scheme: PinReferenceScheme,
    caller: VerifyCaller,
    outcome: Result<VerifyOutcome, E>,
) -> (DWORD, Option<DWORD>) {
    match outcome {
        Ok(VerifyOutcome::Ok) => {
            if slot == PinSlot::Pin1 {
                ctx.pin1_authenticated = true;
            } else {
                ctx.pin2_authenticated = true;
                ctx.pin2_scheme = scheme;
            }
            (SCARD_S_SUCCESS, None)
        }
        Ok(VerifyOutcome::WrongPin { retries_left }) => {
            if caller == VerifyCaller::AuthenticateEx {
                refineid_dev_errors::report!(
                    CardModule,
                    "CardAuthenticateEx failed",
                    "the card rejected the PIN"
                );
            }
            clear_cached_pin(ctx);
            (SCARD_W_WRONG_CHV, Some(DWORD::from(retries_left.get())))
        }
        Ok(VerifyOutcome::Locked) => {
            if caller == VerifyCaller::AuthenticateEx {
                refineid_dev_errors::report!(
                    CardModule,
                    "CardAuthenticateEx failed",
                    "the PIN is blocked"
                );
            }
            clear_cached_pin(ctx);
            let attempts = match caller {
                VerifyCaller::AuthenticatePin => Some(NO_ATTEMPTS_REMAINING),
                VerifyCaller::AuthenticateEx => None,
            };
            (SCARD_W_CHV_BLOCKED, attempts)
        }
        Ok(VerifyOutcome::Other(sw)) => {
            if caller == VerifyCaller::AuthenticateEx {
                let status = refineid_lib_core::apdu::status_word::StatusWord::from_u16(sw);
                refineid_dev_errors::report!(CardModule, "CardAuthenticateEx failed", status);
            }
            clear_cached_pin(ctx);
            (SCARD_W_WRONG_CHV, None)
        }
        Err(error) => {
            if caller == VerifyCaller::AuthenticateEx {
                refineid_dev_errors::report!(CardModule, "CardAuthenticateEx failed", error);
            }
            clear_cached_pin(ctx);
            (SCARD_F_INTERNAL_ERROR, None)
        }
    }
}

#[cfg(windows)]
fn verify_card_pin(
    ctx: &mut Ctx,
    live_h_card: SCARDHANDLE,
    slot: PinSlot,
    pin: PinBytes,
    caller: VerifyCaller,
) -> (DWORD, Option<DWORD>) {
    let mut tx = lock_transport(&ctx.transport);
    if let Err(error) = sync_transport_handle(
        &mut tx,
        &mut ctx.pin1_authenticated,
        &mut ctx.pin2_authenticated,
        live_h_card,
    ) {
        return (error, None);
    }
    // Any new explicit PIN operation invalidates previous positive state.
    clear_pin_state(&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);
    let serial = match live_token_serial(&mut tx) {
        Ok(serial) => serial,
        Err(error) => return (error, None),
    };
    let (scheme, status) = match live_verify_floor(&mut tx, slot) {
        Ok(admitted) => admitted,
        Err(error) => return (error, None),
    };
    let is_rejected = with_pin_safety(|cache| cache.bars_presenting(&serial, slot, &pin, status))
        .unwrap_or(false);
    if is_rejected {
        return (SCARD_W_WRONG_CHV, None);
    }
    let outcome = tx.verify_pin_with_scheme(scheme, slot, pin.clone());
    drop(tx);
    let is_ok = matches!(outcome, Ok(VerifyOutcome::Ok));
    if matches!(outcome, Ok(VerifyOutcome::WrongPin { .. })) {
        let _ = with_pin_safety(|cache| cache.record_rejected(&serial, slot, &pin));
    }
    let result = map_verify_outcome(ctx, slot, scheme, caller, outcome);
    if is_ok && slot == PinSlot::Pin1 {
        hold_verified_pin1(serial, pin);
    }
    result
}

#[cfg(windows)]
fn map_change_pin_outcome(ctx: &mut Ctx, outcome: ChangePinOutcome) -> (DWORD, Option<DWORD>) {
    match outcome {
        ChangePinOutcome::Ok => {
            clear_cached_pin(ctx);
            (SCARD_S_SUCCESS, None)
        }
        ChangePinOutcome::WrongCurrentPin { retries_left } => {
            clear_cached_pin(ctx);
            (SCARD_W_WRONG_CHV, Some(DWORD::from(retries_left.get())))
        }
        ChangePinOutcome::Locked => {
            clear_cached_pin(ctx);
            (SCARD_W_CHV_BLOCKED, None)
        }
        ChangePinOutcome::LengthError => (SCARD_E_INVALID_PARAMETER, None),
        ChangePinOutcome::Other(_sw) => {
            clear_cached_pin(ctx);
            (SCARD_F_INTERNAL_ERROR, None)
        }
    }
}

#[cfg(windows)]
fn change_card_pin(
    ctx: &mut Ctx,
    live_h_card: SCARDHANDLE,
    slot: PinSlot,
    current_pin: &PinBytes,
    new_pin: PinBytes,
) -> (DWORD, Option<DWORD>) {
    let mut tx = lock_transport(&ctx.transport);
    if let Err(error) = sync_transport_handle(
        &mut tx,
        &mut ctx.pin1_authenticated,
        &mut ctx.pin2_authenticated,
        live_h_card,
    ) {
        return (error, None);
    }
    let serial = match live_token_serial(&mut tx) {
        Ok(serial) => serial,
        Err(error) => return (error, None),
    };
    let (lengths, status) = match pin_scheme::prepare_pin_change(&mut *tx, slot) {
        Ok(prepared) => prepared,
        Err(failure) => return (report_prepare_failure(failure), None),
    };
    if let Err(error) = retry_floor_answer(slot, status) {
        return (error, None);
    }
    let is_rejected = with_pin_safety(|cache| {
        cache.bars_presenting(&serial, slot, current_pin, status)
            || cache.bars_presenting(&serial, slot, &new_pin, status)
    })
    .unwrap_or(false);
    if is_rejected {
        return (SCARD_W_WRONG_CHV, None);
    }
    let outcome = tx.change_pin(&lengths, slot, current_pin.clone(), new_pin);
    drop(tx);
    match outcome {
        Ok(o) => {
            if matches!(o, ChangePinOutcome::WrongCurrentPin { .. }) {
                let _ = with_pin_safety(|cache| {
                    cache.record_rejected(&serial, slot, current_pin);
                });
            }
            map_change_pin_outcome(ctx, o)
        }
        Err(error) => (manage_error_answer(&error), None),
    }
}

#[cfg(windows)]
fn map_unblock_outcome(ctx: &mut Ctx, outcome: UnblockOutcome) -> DWORD {
    match outcome {
        UnblockOutcome::Ok => {
            clear_cached_pin(ctx);
            SCARD_S_SUCCESS
        }
        UnblockOutcome::WrongPuk { .. } => {
            clear_cached_pin(ctx);
            SCARD_W_WRONG_CHV
        }
        UnblockOutcome::PukLocked | UnblockOutcome::Invalidated => {
            clear_cached_pin(ctx);
            SCARD_W_CHV_BLOCKED
        }
        UnblockOutcome::LengthError => SCARD_E_INVALID_PARAMETER,
        UnblockOutcome::Other(_sw) => SCARD_F_INTERNAL_ERROR,
    }
}

#[cfg(windows)]
fn unblock_card_pin(
    ctx: &mut Ctx,
    live_h_card: SCARDHANDLE,
    target_slot: PinSlot,
    puk: PinBytes,
    new_pin: PinBytes,
) -> DWORD {
    let mut tx = lock_transport(&ctx.transport);
    if let Err(error) = sync_transport_handle(
        &mut tx,
        &mut ctx.pin1_authenticated,
        &mut ctx.pin2_authenticated,
        live_h_card,
    ) {
        return error;
    }
    if let Err(error) = live_token_serial(&mut tx) {
        return error;
    }
    let (lengths, status) = match pin_scheme::prepare_pin_unblock(&mut *tx) {
        Ok(prepared) => prepared,
        Err(failure) => return report_prepare_failure(failure),
    };
    if let Err(error) = puk_floor_answer(status) {
        return error;
    }
    let outcome = tx.reset_retry_counter(&lengths, target_slot, puk, new_pin);
    drop(tx);
    match outcome {
        Ok(o) => map_unblock_outcome(ctx, o),
        Err(error) => manage_error_answer(&error),
    }
}

#[cfg(windows)]
fn synth_cardcf() -> Vec<u8> {
    let mut v = CARDCF_VALUE.load(Ordering::Relaxed);
    if v == 0 {
        v = cardcf_initial_value();
        CARDCF_VALUE.store(v, Ordering::Relaxed);
    }
    let b0 = (v & 0xFF) as u8;
    let b1 = ((v >> 8) & 0xFF) as u8;
    let b2 = ((v >> 16) & 0xFF) as u8;
    let b3 = ((v >> 24) & 0xFF) as u8;
    let b4 = ((v >> 32) & 0xFF) as u8;
    vec![1_u8, b0, b1, b2, b3, b4]
}

#[cfg(windows)]
fn synth_cardid(auth_cert: &[u8]) -> Vec<u8> {
    CardId::of_authentication_certificate(auth_cert)
        .as_bytes()
        .to_vec()
}

#[cfg(windows)]
fn synth_cardapps() -> Vec<u8> {
    b"mscp\0\0\0\0".to_vec()
}

#[cfg(windows)]
fn synth_cmapfile(card: &CardCapabilityModel) -> Vec<u8> {
    let record_size = size_of::<CONTAINER_MAP_RECORD>();
    let record_count = card
        .cmapfile_records
        .iter()
        .rposition(|record| record.bFlags & CONTAINER_MAP_VALID_CONTAINER != 0)
        .map_or(0, |index| index + 1);
    let mut out = Vec::with_capacity(record_count * record_size);
    for rec in card.cmapfile_records.iter().take(record_count) {
        let bytes = unsafe {
            core::slice::from_raw_parts(core::ptr::from_ref(rec).cast::<u8>(), record_size)
        };
        out.extend_from_slice(bytes);
    }
    out
}

#[cfg(windows)]
fn container_file_bytes(card: &CardCapabilityModel, file: &str) -> Option<Vec<u8>> {
    for container in &card.containers {
        if !container.is_visible() {
            continue;
        }
        if container.reported_sig_bits > 0 && file == container.sig_file {
            return Some(container.cert_der.clone());
        }
        if let Some(keyex_file) = container.keyex_file.as_deref()
            && file == keyex_file
        {
            return Some(container.cert_der.clone());
        }
    }
    None
}

#[cfg(windows)]
fn aggregated_key_sizes<I>(containers: I) -> Option<CARD_KEY_SIZES>
where
    I: IntoIterator<Item = u16>,
{
    let mut it = containers.into_iter();
    let first = it.next()?;
    let mut min_bits = first;
    let mut max_bits = first;
    for bits in it {
        min_bits = min_bits.min(bits);
        max_bits = max_bits.max(bits);
    }
    Some(CARD_KEY_SIZES {
        dwVersion: CARD_KEY_SIZES_CURRENT_VERSION,
        dwMinimumBitlen: DWORD::from(min_bits),
        dwDefaultBitlen: DWORD::from(max_bits),
        dwMaximumBitlen: DWORD::from(max_bits),
        dwIncrementalBitlen: 0,
    })
}

#[cfg(windows)]
fn build_legacy_rsa_pubkey_blob(cert_der: &[u8], alg: u32) -> Option<Vec<u8>> {
    let cert = OwnedCert::from_der(cert_der).ok()?;
    let spki = cert.view().spki.as_der();
    let pk = extract_rsa_public_key(spki)?;
    let mut exp = 0_u32;
    for &b in pk.exponent.as_bytes() {
        exp = (exp << 8) | u32::from(b);
    }
    let mut modulus_le = pk.modulus.as_bytes().to_vec();
    modulus_le.reverse();
    let bit_length = u32::try_from(pk.modulus.as_bytes().len() * 8).ok()?;

    let mut out = Vec::with_capacity(8 + 12 + modulus_le.len());
    out.push(PUBLICKEYBLOB);
    out.push(CUR_BLOB_VERSION);
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&alg.to_le_bytes());
    out.extend_from_slice(&RSA1_MAGIC.to_le_bytes());
    out.extend_from_slice(&bit_length.to_le_bytes());
    out.extend_from_slice(&exp.to_le_bytes());
    out.extend_from_slice(&modulus_le);
    Some(out)
}

#[cfg(windows)]
fn build_cng_ecdsa_pubkey_blob(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert = OwnedCert::from_der(cert_der).ok()?;
    let spki = cert.view().spki;
    let q = spki.ec_public_key_point()?;
    let field_bytes = match spki.algorithm() {
        PublicKeyAlgorithm::Ec(EcCurve::Secp256r1 | EcCurve::BrainpoolP256r1) => 32,
        PublicKeyAlgorithm::Ec(EcCurve::Secp384r1 | EcCurve::BrainpoolP384r1) => 48,
        _ => return None,
    };
    let point = q.as_bytes();
    if point.len() != 1 + (2 * field_bytes) || point.first() != Some(&0x04) {
        return None;
    }
    let magic = if field_bytes == 32 {
        BCRYPT_ECDSA_PUBLIC_P256_MAGIC
    } else {
        BCRYPT_ECDSA_PUBLIC_P384_MAGIC
    };
    let x = &point[1..=field_bytes];
    let y = &point[1 + field_bytes..];
    let mut out = Vec::with_capacity(8 + x.len() + y.len());
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&u32::try_from(field_bytes).ok()?.to_le_bytes());
    out.extend_from_slice(x);
    out.extend_from_slice(y);
    Some(out)
}

#[cfg(windows)]
unsafe fn build_container_info_struct(
    cd: &CARD_DATA,
    container: &ContainerDescriptor,
) -> Option<CONTAINER_INFO> {
    match container.key_alg {
        KeyAlgorithm::Rsa { .. } => {
            let sig_blob = if container.allow_sign {
                build_legacy_rsa_pubkey_blob(&container.cert_der, CALG_RSA_SIGN)?
            } else {
                Vec::new()
            };
            let keyex_blob = if container.keyex_bits() > 0 {
                build_legacy_rsa_pubkey_blob(&container.cert_der, CALG_RSA_KEYX)?
            } else {
                Vec::new()
            };
            let sig_ptr = if sig_blob.is_empty() {
                core::ptr::null_mut()
            } else {
                unsafe { alloc_copy(cd, &sig_blob)? }
            };
            let keyex_ptr = if keyex_blob.is_empty() {
                core::ptr::null_mut()
            } else {
                unsafe { alloc_copy(cd, &keyex_blob)? }
            };
            Some(CONTAINER_INFO {
                dwVersion: CONTAINER_INFO_CURRENT_VERSION,
                dwReserved: 0,
                cbSigPublicKey: try_dword_len(sig_blob.len())?,
                pbSigPublicKey: sig_ptr,
                cbKeyExPublicKey: try_dword_len(keyex_blob.len())?,
                pbKeyExPublicKey: keyex_ptr,
            })
        }
        KeyAlgorithm::Ec(_) => {
            let sig_blob = build_cng_ecdsa_pubkey_blob(&container.cert_der)?;
            let sig_ptr = unsafe { alloc_copy(cd, &sig_blob)? };
            Some(CONTAINER_INFO {
                dwVersion: CONTAINER_INFO_CURRENT_VERSION,
                dwReserved: 0,
                cbSigPublicKey: try_dword_len(sig_blob.len())?,
                pbSigPublicKey: sig_ptr,
                cbKeyExPublicKey: 0,
                pbKeyExPublicKey: core::ptr::null_mut(),
            })
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn CardReadFile(
    pCardData: *mut CARD_DATA,
    pszDirectoryName: LPSTR,
    pszFileName: LPSTR,
    _dwFlags: DWORD,
    ppbData: *mut PBYTE,
    pcbData: PDWORD,
) -> DWORD {
    if pszFileName.is_null() || ppbData.is_null() || pcbData.is_null() {
        return SCARD_E_INVALID_PARAMETER;
    }
    let (cd, ctx) = match unsafe { checked_card_data_and_ctx(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };

    let file = match CardFile::resolve(
        read_directory(pszDirectoryName).as_deref(),
        &read_cstr(pszFileName),
    ) {
        Ok(file) => file,
        Err(reason) => return no_such_file_status(reason),
    };
    let Some(data) = card_file_bytes(&ctx.card, &file) else {
        return SCARD_E_FILE_NOT_FOUND;
    };

    let Some(p) = (unsafe { alloc_copy(cd, &data) }) else {
        return SCARD_E_NO_MEMORY;
    };
    unsafe {
        *ppbData = p;
        *pcbData = match try_dword_len(data.len()) {
            Some(len) => len,
            None => return SCARD_F_INTERNAL_ERROR,
        };
    }
    SCARD_S_SUCCESS
}

#[cfg(windows)]
unsafe extern "system" fn CardEnumFiles(
    pCardData: *mut CARD_DATA,
    pszDirectoryName: LPSTR,
    pmszFileNames: *mut LPSTR,
    pdwLen: PDWORD,
    _dwFlags: DWORD,
) -> DWORD {
    if pmszFileNames.is_null() || pdwLen.is_null() {
        return SCARD_E_INVALID_PARAMETER;
    }
    let (cd, ctx) = match unsafe { checked_card_data_and_ctx(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };

    let names = match read_directory(pszDirectoryName).as_deref() {
        ROOT_DIRECTORY => {
            let mut v = Vec::new();
            for name in [CARDCF_FILE, CARDID_FILE, CARDAPPS_FILE] {
                v.extend_from_slice(name.as_bytes());
                v.push(0);
            }
            v.push(0);
            v
        }
        Some(MSCP_DIRECTORY) => {
            let mut v = Vec::new();
            v.extend_from_slice(CMAPFILE_FILE.as_bytes());
            v.push(0);
            for container in &ctx.card.containers {
                if !container.is_visible() {
                    continue;
                }
                if let Some(keyex_file) = container.keyex_file.as_deref() {
                    v.extend_from_slice(keyex_file.as_bytes());
                    v.push(0);
                }
                if container.reported_sig_bits > 0 {
                    v.extend_from_slice(container.sig_file.as_bytes());
                    v.push(0);
                }
            }
            v.push(0);
            v
        }
        Some(_) => return SCARD_E_DIR_NOT_FOUND,
    };

    let Some(p) = (unsafe { alloc_copy(cd, &names) }) else {
        return SCARD_E_NO_MEMORY;
    };
    unsafe {
        *pmszFileNames = p.cast::<u8>();
        *pdwLen = match try_dword_len(names.len()) {
            Some(len) => len,
            None => return SCARD_F_INTERNAL_ERROR,
        };
    }
    SCARD_S_SUCCESS
}

#[cfg(windows)]
unsafe extern "system" fn CardGetFileInfo(
    pCardData: *mut CARD_DATA,
    pszDirectoryName: LPSTR,
    pszFileName: LPSTR,
    pInfo: *mut CARD_FILE_INFO,
) -> DWORD {
    if pInfo.is_null() {
        return SCARD_E_INVALID_PARAMETER;
    }
    let (_cd, ctx) = match unsafe { checked_card_data_and_ctx(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    let file = match CardFile::resolve(
        read_directory(pszDirectoryName).as_deref(),
        &read_cstr(pszFileName),
    ) {
        Ok(file) => file,
        Err(reason) => return no_such_file_status(reason),
    };
    // The size is the size of what CardReadFile would return, from the
    // same bytes, so the two can never disagree.
    let Some(size) = card_file_bytes(&ctx.card, &file).map(|bytes| bytes.len()) else {
        return SCARD_E_FILE_NOT_FOUND;
    };

    let info = unsafe { &mut *pInfo };
    info.dwVersion = CARD_FILE_INFO_CURRENT_VERSION;
    info.cbFileSize = match try_dword_len(size) {
        Some(len) => len,
        None => return SCARD_F_INTERNAL_ERROR,
    };
    info.AccessCondition = 0;
    SCARD_S_SUCCESS
}

#[cfg(windows)]
unsafe extern "system" fn CardQueryFreeSpace(
    pCardData: *mut CARD_DATA,
    _dwFlags: DWORD,
    pInfo: *mut CARD_FREE_SPACE_INFO,
) -> DWORD {
    if pInfo.is_null() {
        return SCARD_E_INVALID_PARAMETER;
    }
    let (_cd, ctx) = match unsafe { checked_card_data_and_ctx(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    let info = unsafe { &mut *pInfo };
    info.dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
    info.dwBytesAvailable = 0;
    info.dwKeyContainersAvailable = match try_dword_len(
        ctx.card
            .containers
            .iter()
            .filter(|container| !container.is_visible())
            .count(),
    ) {
        Some(len) => len,
        None => return SCARD_F_INTERNAL_ERROR,
    };
    info.dwMaxKeyContainers = match try_dword_len(ctx.card.containers.len()) {
        Some(len) => len,
        None => return SCARD_F_INTERNAL_ERROR,
    };
    SCARD_S_SUCCESS
}

#[cfg(windows)]
unsafe extern "system" fn CardQueryKeySizes(
    pCardData: *mut CARD_DATA,
    dwKeySpec: DWORD,
    _dwFlags: DWORD,
    pInfo: *mut CARD_KEY_SIZES,
) -> DWORD {
    if pInfo.is_null() {
        return SCARD_E_INVALID_PARAMETER;
    }
    let (_cd, ctx) = match unsafe { checked_card_data_and_ctx(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    let sizes = match dwKeySpec {
        AT_KEYEXCHANGE => aggregated_key_sizes(
            ctx.card
                .containers
                .iter()
                .filter(|container| {
                    container.is_visible()
                        && container.allow_decrypt
                        && matches!(container.key_alg, KeyAlgorithm::Rsa { .. })
                })
                .map(|container| container.key_alg.bits()),
        ),
        AT_SIGNATURE => aggregated_key_sizes(
            ctx.card
                .containers
                .iter()
                .filter(|container| {
                    container.is_visible()
                        && container.allow_sign
                        && matches!(container.key_alg, KeyAlgorithm::Rsa { .. })
                })
                .map(|container| container.key_alg.bits()),
        ),
        AT_ECDSA_P256 => aggregated_key_sizes(
            ctx.card
                .containers
                .iter()
                .filter(|container| {
                    container.is_visible()
                        && container.allow_sign
                        && matches!(
                            container.key_alg,
                            KeyAlgorithm::Ec(curve) if curve.bits() == 256
                        )
                })
                .map(|container| container.key_alg.bits()),
        ),
        AT_ECDSA_P384 => aggregated_key_sizes(
            ctx.card
                .containers
                .iter()
                .filter(|container| {
                    container.is_visible()
                        && container.allow_sign
                        && matches!(
                            container.key_alg,
                            KeyAlgorithm::Ec(curve) if curve.bits() == 384
                        )
                })
                .map(|container| container.key_alg.bits()),
        ),
        _ => None,
    };
    sizes.map_or(SCARD_E_UNSUPPORTED_FEATURE, |s| {
        unsafe {
            *pInfo = s;
        }
        SCARD_S_SUCCESS
    })
}

#[cfg(windows)]
unsafe extern "system" fn CardGetContainerInfo(
    pCardData: *mut CARD_DATA,
    bContainerIndex: BYTE,
    _flags: DWORD,
    pInfo: *mut CONTAINER_INFO,
) -> DWORD {
    if pInfo.is_null() {
        return SCARD_E_INVALID_PARAMETER;
    }
    let (cd, ctx) = match unsafe { checked_card_data_and_ctx(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    let Some(container) = ctx.card.visible_container(bContainerIndex) else {
        return SCARD_E_NO_KEY_CONTAINER;
    };
    let Some(info) = (unsafe { build_container_info_struct(cd, container) }) else {
        refineid_dev_errors::report!(
            CardModule,
            "CardGetContainerInfo failed",
            "the public key blob was not built"
        );
        return SCARD_F_INTERNAL_ERROR;
    };
    unsafe {
        *pInfo = info;
    }
    SCARD_S_SUCCESS
}

#[cfg(windows)]
unsafe extern "system" fn CardAuthenticatePin(
    pCardData: *mut CARD_DATA,
    pwszUserId: LPWSTR,
    pbPin: PBYTE,
    cbPin: DWORD,
    pcAttemptsRemaining: PDWORD,
) -> DWORD {
    let (cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    if ctx.transport.lock().is_ok_and(|tx| tx.is_remote()) {
        let pin_id = unsafe { pin_id_from_user_id(pwszUserId) };
        if pin_id == PIN_ID_QUALIFIED_SIG {
            ctx.pin2_authenticated = true;
        } else {
            ctx.pin1_authenticated = true;
        }
        return SCARD_S_SUCCESS;
    }
    if pbPin.is_null() || cbPin == 0 {
        return SCARD_E_INVALID_PARAMETER;
    }
    let pin_id = unsafe { pin_id_from_user_id(pwszUserId) };
    if pin_id == PIN_ID_PUK {
        return SCARD_E_UNSUPPORTED_FEATURE;
    }
    let pin = match unsafe { checked_pin_bytes(pbPin, cbPin, pin_id) } {
        Ok(pin) => pin,
        Err(rc) => return rc,
    };
    let slot = if pin_id == PIN_ID_QUALIFIED_SIG {
        PinSlot::Pin2
    } else {
        PinSlot::Pin1
    };
    let (status, attempts) =
        verify_card_pin(ctx, cd.hScard, slot, pin, VerifyCaller::AuthenticatePin);
    unsafe {
        write_attempts_remaining(pcAttemptsRemaining, attempts);
    }
    status
}

#[cfg(windows)]
#[expect(
    clippy::too_many_lines,
    reason = "CardSignData is one ABI dispatch transaction whose validation, PIN state, padding selection, card call, and allocator return must remain reviewable in execution order"
)]
unsafe extern "system" fn CardSignData(
    pCardData: *mut CARD_DATA,
    pInfo: *mut CARD_SIGNING_INFO,
) -> DWORD {
    if pInfo.is_null() {
        return SCARD_E_INVALID_PARAMETER;
    }
    let padding = match unsafe { parse_signing_padding(pInfo) } {
        Ok(p) => p,
        Err(rc) => return rc,
    };
    let (cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    let basic = unsafe { &mut *pInfo.cast::<CARD_SIGNING_INFO_BASIC>() };
    let Some(container) = ctx.card.visible_container(basic.bContainerIndex).cloned() else {
        return SCARD_E_NO_KEY_CONTAINER;
    };

    let remote_arm = {
        let (pin1, pin2) = (&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);
        let mut tx = lock_transport(&ctx.transport);
        if let Err(rc) = sync_transport_handle(&mut tx, pin1, pin2, cd.hScard) {
            return rc;
        }
        if tx.is_remote() {
            tx.remote_ref().map(|r| (r.pair_id, r.atr.clone()))
        } else {
            None
        }
    };

    let authenticated = if remote_arm.is_some() {
        true
    } else if container.pin_id == PIN_ID_QUALIFIED_SIG {
        ctx.pin2_authenticated
    } else {
        ctx.pin1_authenticated
            || with_pin_safety(|cache| cache.has_positive_pin1()).unwrap_or(false)
    };
    if !authenticated {
        refineid_dev_errors::report!(
            CardModule,
            "CardSignData failed",
            "the key's PIN is not verified"
        );
        return SCARD_W_WRONG_CHV;
    }

    if basic.dwSigningFlags & CARD_BUFFER_SIZE_ONLY != 0 {
        basic.pbSignedData = core::ptr::null_mut();
        basic.cbSignedData = match try_dword_len(container.key_alg.signature_len()) {
            Some(len) => len,
            None => return SCARD_F_INTERNAL_ERROR,
        };
        return SCARD_S_SUCCESS;
    }
    if basic.pbData.is_null() || basic.cbData == 0 {
        return SCARD_E_INVALID_PARAMETER;
    }
    let in_bytes = unsafe { core::slice::from_raw_parts(basic.pbData, basic.cbData as usize) };

    if let Some((pair_id, atr)) = remote_arm {
        let (key_profile, algorithm) = match (&container.key_alg, &padding) {
            (KeyAlgorithm::Rsa { bits }, ParsedSigningPadding::Pss { .. }) => {
                let kp = if *bits <= 2048 {
                    KeyProfile::Rsa2048
                } else {
                    KeyProfile::Rsa3072
                };
                (kp, SignatureAlgorithm::RsaPssSha256)
            }
            (KeyAlgorithm::Rsa { bits }, ParsedSigningPadding::Pkcs1 { hash_name }) => {
                let kp = if *bits <= 2048 {
                    KeyProfile::Rsa2048
                } else {
                    KeyProfile::Rsa3072
                };
                let algo = if let Some(name) = hash_name {
                    match name.as_str() {
                        "SHA384" => SignatureAlgorithm::RsaPkcs1Sha384,
                        "SHA512" => SignatureAlgorithm::RsaPkcs1Sha512,
                        _ => SignatureAlgorithm::RsaPkcs1Sha256,
                    }
                } else {
                    match in_bytes.len() {
                        48 => SignatureAlgorithm::RsaPkcs1Sha384,
                        64 => SignatureAlgorithm::RsaPkcs1Sha512,
                        _ => SignatureAlgorithm::RsaPkcs1Sha256,
                    }
                };
                (kp, algo)
            }
            (KeyAlgorithm::Ec(curve), _) => {
                let kp = if curve.bits() == 256 {
                    KeyProfile::EcdsaP256
                } else {
                    KeyProfile::EcdsaP384
                };
                let algo = match in_bytes.len() {
                    28 => SignatureAlgorithm::EcdsaSha224,
                    32 => SignatureAlgorithm::EcdsaSha256,
                    48 => SignatureAlgorithm::EcdsaSha384,
                    64 => SignatureAlgorithm::EcdsaSha512,
                    _ => {
                        if curve.bits() == 256 {
                            SignatureAlgorithm::EcdsaSha256
                        } else {
                            SignatureAlgorithm::EcdsaSha384
                        }
                    }
                };
                (kp, algo)
            }
        };

        let key = if container.pin_id == PIN_ID_QUALIFIED_SIG {
            RemoteKey::QualifiedSignature
        } else {
            RemoteKey::Authentication
        };
        let Some(program) = calling_program() else {
            refineid_dev_errors::report!(
                CardModule,
                "remote signature refused",
                "the calling program has no image name"
            );
            return SCARD_E_UNSUPPORTED_FEATURE;
        };
        let operation = in_process_operation(
            key,
            &program,
            &computer_name(),
            interface_language(),
            key_profile,
            algorithm,
            in_bytes.to_vec(),
        );

        let remote_tx = RemoteCardTransport::new(atr, pair_id);
        let result = match remote_tx.execute_operation(&operation) {
            Ok(r) => r,
            Err(err) => {
                refineid_dev_errors::report!(CardModule, "remote signature failed", err);
                return err.status();
            }
        };

        let CardOperationResult::Signature(mut sig_bytes) = result else {
            refineid_dev_errors::report!(
                CardModule,
                "remote signature failed",
                "another result came"
            );
            return SCARD_F_INTERNAL_ERROR;
        };

        if matches!(container.key_alg, KeyAlgorithm::Rsa { .. }) {
            sig_bytes.reverse();
        } else if let KeyAlgorithm::Ec(curve) = &container.key_alg {
            let field_bytes = curve.bits() / 8;
            let Some(p1363) = cardmod::remote_ecdsa_to_p1363(&sig_bytes, field_bytes) else {
                refineid_dev_errors::report!(
                    CardModule,
                    "remote signature failed",
                    "the ECDSA signature length is wrong"
                );
                return SCARD_F_INTERNAL_ERROR;
            };
            sig_bytes = p1363;
        }

        let Some(needed) = try_dword_len(sig_bytes.len()) else {
            return SCARD_F_INTERNAL_ERROR;
        };
        let Some(p) = (unsafe { alloc_copy(cd, &sig_bytes) }) else {
            return SCARD_E_NO_MEMORY;
        };
        basic.pbSignedData = p;
        basic.cbSignedData = needed;
        return SCARD_S_SUCCESS;
    }

    let key_ref = if container.pin_id == PIN_ID_QUALIFIED_SIG {
        KeyRef::Sign(ctx.pin2_scheme)
    } else {
        KeyRef::Auth
    };

    // RSA-PSS path: TLS 1.3 CertificateVerify (Firefox osclientcerts,
    // CNG KSP callers) requires RSASSA-PSS. FINEID S1 v4.2 Table 6
    // defines a native RSA-PSS algorithm reference, so send the digest
    // through PSO:HASH and let the card perform PSS internally.
    if let ParsedSigningPadding::Pss {
        ref hash_name,
        salt_len,
    } = padding
    {
        if !container.allow_pss || !matches!(container.key_alg, KeyAlgorithm::Rsa { .. }) {
            return SCARD_E_UNSUPPORTED_FEATURE;
        }
        let (digest_len, hash) = match hash_name.as_str() {
            "SHA1" => (
                20,
                ExternalHashValue::Sha1(match in_bytes.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return SCARD_E_INVALID_PARAMETER,
                }),
            ),
            "SHA256" => (
                32,
                ExternalHashValue::Sha256(match in_bytes.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return SCARD_E_INVALID_PARAMETER,
                }),
            ),
            "SHA384" => (
                48,
                ExternalHashValue::Sha384(match in_bytes.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return SCARD_E_INVALID_PARAMETER,
                }),
            ),
            "SHA512" => (
                64,
                ExternalHashValue::Sha512(match in_bytes.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return SCARD_E_INVALID_PARAMETER,
                }),
            ),
            _ => return SCARD_E_INVALID_PARAMETER,
        };
        if salt_len != digest_len {
            return SCARD_E_INVALID_PARAMETER;
        }
        let mut tx = lock_transport(&ctx.transport);
        if let Err(rc) = sync_transport_handle(
            &mut tx,
            &mut ctx.pin1_authenticated,
            &mut ctx.pin2_authenticated,
            cd.hScard,
        ) {
            return rc;
        }
        // The card may have been reset since PIN verification (the
        // Base CSP reconnects between calls); re-verify with the
        // cached PIN inside the same transaction so the security
        // state is guaranteed at PSO time (legacy parity).
        if let Some(rc) = reverify_cached_pin(
            &mut ctx.pin1_authenticated,
            &mut ctx.pin2_authenticated,
            &mut tx,
            container.pin_id,
        ) {
            return rc;
        }
        let sig = tx.sign_pre_hashed_rsa_pss(key_ref, hash);
        drop(tx);
        let sig = match sig {
            Ok(sig) => sig,
            Err(err) => {
                refineid_dev_errors::report!(CardModule, "RSA-PSS signature failed", err);
                reset_card_state(&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);
                return SCARD_F_INTERNAL_ERROR;
            }
        };
        // CryptoAPI expects RSA signature integers in little-endian order.
        let mut sig_bytes = sig.as_bytes().to_vec();
        sig_bytes.reverse();
        let Some(sig_len) = try_dword_len(sig_bytes.len()) else {
            return SCARD_F_INTERNAL_ERROR;
        };
        let Some(p) = (unsafe { alloc_copy(cd, &sig_bytes) }) else {
            return SCARD_E_NO_MEMORY;
        };
        basic.pbSignedData = p;
        basic.cbSignedData = sig_len;
        if container.pin_id == PIN_ID_QUALIFIED_SIG {
            spend_pin2(ctx);
        }
        return SCARD_S_SUCCESS;
    }

    let hash = if let ParsedSigningPadding::Pkcs1 {
        hash_name: Some(name),
    } = &padding
    {
        match name.as_str() {
            "SHA1" => {
                if in_bytes.len() != 20 {
                    return SCARD_E_INVALID_PARAMETER;
                }
                match in_bytes.try_into() {
                    Ok(b) => ExternalHashValue::Sha1(b),
                    Err(_) => return SCARD_E_INVALID_PARAMETER,
                }
            }
            "SHA256" => {
                if in_bytes.len() != 32 {
                    return SCARD_E_INVALID_PARAMETER;
                }
                match in_bytes.try_into() {
                    Ok(b) => ExternalHashValue::Sha256(b),
                    Err(_) => return SCARD_E_INVALID_PARAMETER,
                }
            }
            "SHA384" => {
                if in_bytes.len() != 48 {
                    return SCARD_E_INVALID_PARAMETER;
                }
                match in_bytes.try_into() {
                    Ok(b) => ExternalHashValue::Sha384(b),
                    Err(_) => return SCARD_E_INVALID_PARAMETER,
                }
            }
            "SHA512" => {
                if in_bytes.len() != 64 {
                    return SCARD_E_INVALID_PARAMETER;
                }
                match in_bytes.try_into() {
                    Ok(b) => ExternalHashValue::Sha512(b),
                    Err(_) => return SCARD_E_INVALID_PARAMETER,
                }
            }
            _ => return SCARD_E_INVALID_PARAMETER,
        }
    } else {
        let Some(h) = external_hash_from_alg_and_bytes(basic.aiHashAlg, in_bytes) else {
            return SCARD_E_INVALID_PARAMETER;
        };
        h
    };

    let mut tx = lock_transport(&ctx.transport);
    if let Err(rc) = sync_transport_handle(
        &mut tx,
        &mut ctx.pin1_authenticated,
        &mut ctx.pin2_authenticated,
        cd.hScard,
    ) {
        return rc;
    }
    if let Some(rc) = reverify_cached_pin(
        &mut ctx.pin1_authenticated,
        &mut ctx.pin2_authenticated,
        &mut tx,
        container.pin_id,
    ) {
        return rc;
    }
    let sig = match container.key_alg {
        KeyAlgorithm::Rsa { .. } => tx
            .sign_pre_hashed_rsa_pkcs1(key_ref, hash)
            .map(|s| s.as_bytes().to_vec()),
        KeyAlgorithm::Ec(curve) if curve.bits() == 256 => {
            let ExternalHashValue::Sha256(bytes) = hash else {
                return SCARD_E_INVALID_PARAMETER;
            };
            tx.sign_pre_hashed_sha256_ecdsa_p256(key_ref, Sha256::from_bytes(bytes))
                .map(|s| s.as_bytes().to_vec())
        }
        KeyAlgorithm::Ec(curve) if curve.bits() == 384 => match hash {
            ExternalHashValue::Sha256(bytes) => tx
                .sign_pre_hashed_sha256_ecdsa_p384(key_ref, Sha256::from_bytes(bytes))
                .map(|s| s.as_bytes().to_vec()),
            ExternalHashValue::Sha384(bytes) => tx
                .sign_pre_hashed_sha384_ecdsa_p384(key_ref, Sha384::from_bytes(bytes))
                .map(|s| s.as_bytes().to_vec()),
            _ => return SCARD_E_INVALID_PARAMETER,
        },
        KeyAlgorithm::Ec(_) => return SCARD_E_UNSUPPORTED_FEATURE,
    };
    drop(tx);

    let Ok(mut sig_bytes) = sig else {
        reset_card_state(&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);
        return SCARD_F_INTERNAL_ERROR;
    };
    if matches!(container.key_alg, KeyAlgorithm::Rsa { .. }) {
        sig_bytes.reverse();
    }
    let Some(needed) = try_dword_len(sig_bytes.len()) else {
        return SCARD_F_INTERNAL_ERROR;
    };
    let Some(p) = (unsafe { alloc_copy(cd, &sig_bytes) }) else {
        return SCARD_E_NO_MEMORY;
    };
    basic.pbSignedData = p;
    basic.cbSignedData = needed;
    if container.pin_id == PIN_ID_QUALIFIED_SIG {
        spend_pin2(ctx);
    }
    SCARD_S_SUCCESS
}

#[cfg(windows)]
unsafe extern "system" fn CardDeauthenticate(
    pCardData: *mut CARD_DATA,
    _pwszUserId: LPWSTR,
    _dwFlags: DWORD,
) -> DWORD {
    let (_cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    ctx.pin1_authenticated = false;
    ctx.pin2_authenticated = false;
    SCARD_S_SUCCESS
}

#[cfg(windows)]
unsafe extern "system" fn CardDeauthenticateEx(
    pCardData: *mut CARD_DATA,
    PinId: DWORD,
    _dwFlags: DWORD,
) -> DWORD {
    let (_cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    match PinId {
        PIN_SET_ALL_ROLES | PIN_ID_AUTH | PIN_ID_QUALIFIED_SIG | PIN_ID_PUK | ROLE_EVERYONE => {
            ctx.pin1_authenticated = false;
            ctx.pin2_authenticated = false;
            SCARD_S_SUCCESS
        }
        _ => SCARD_E_INVALID_PARAMETER,
    }
}

#[cfg(windows)]
unsafe extern "system" fn CardRSADecrypt(pCardData: *mut CARD_DATA, pInfo: PVOID) -> DWORD {
    if pInfo.is_null() {
        return SCARD_E_INVALID_PARAMETER;
    }
    if let Err(rc) = unsafe { parse_rsa_decrypt_padding(pInfo) } {
        return rc;
    }
    let (cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    if ctx.transport.lock().is_ok_and(|tx| tx.is_remote()) {
        return SCARD_E_UNSUPPORTED_FEATURE;
    }
    let basic = unsafe { &mut *pInfo.cast::<CARD_RSA_DECRYPT_INFO_BASIC>() };
    let Some(container) = ctx.card.visible_container(basic.bContainerIndex).cloned() else {
        return SCARD_E_NO_KEY_CONTAINER;
    };
    if !container.allow_decrypt {
        return SCARD_E_UNSUPPORTED_FEATURE;
    }
    if basic.pbData.is_null() || basic.cbData == 0 {
        return SCARD_E_INVALID_PARAMETER;
    }

    let ciphertext =
        unsafe { core::slice::from_raw_parts(basic.pbData, basic.cbData as usize) }.to_vec();
    let mut tx = lock_transport(&ctx.transport);
    if let Err(rc) = sync_transport_handle(
        &mut tx,
        &mut ctx.pin1_authenticated,
        &mut ctx.pin2_authenticated,
        cd.hScard,
    ) {
        return rc;
    }
    if let Some(rc) = reverify_cached_pin(
        &mut ctx.pin1_authenticated,
        &mut ctx.pin2_authenticated,
        &mut tx,
        PIN_ID_AUTH,
    ) {
        return rc;
    }
    let plain = tx.decrypt_rsa_pkcs1_auth(Ciphertext::<RsaPkcs1>::new(ciphertext));
    drop(tx);
    let Ok(plaintext) = plain else {
        reset_card_state(&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);
        return SCARD_F_INTERNAL_ERROR;
    };
    let plaintext_bytes = plaintext.as_bytes();
    if plaintext_bytes.len() > basic.cbData as usize {
        return SCARD_E_INSUFFICIENT_BUFFER;
    }

    let pad_len = (basic.cbData as usize).saturating_sub(plaintext_bytes.len());
    unsafe {
        for i in 0..pad_len {
            *basic.pbData.add(i) = 0;
        }
        core::ptr::copy_nonoverlapping(
            plaintext_bytes.as_ptr(),
            basic.pbData.add(pad_len),
            plaintext_bytes.len(),
        );
    }
    SCARD_S_SUCCESS
}

#[cfg(windows)]
#[expect(
    clippy::too_many_lines,
    reason = "CardGetProperty is a direct, fail-closed dispatch table for the externally specified Windows Card Module property surface"
)]
unsafe extern "system" fn CardGetProperty(
    pCardData: *mut CARD_DATA,
    wszProperty: LPCWSTR,
    pbData: PBYTE,
    cbData: DWORD,
    pdwDataLen: PDWORD,
    dwFlags: DWORD,
) -> DWORD {
    if wszProperty.is_null() {
        return SCARD_E_INVALID_PARAMETER;
    }
    let (_cd, ctx) = match unsafe { checked_card_data_and_ctx(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };

    if unsafe {
        wstr_matches_any(
            wszProperty,
            &["Free Space", "CP_CARD_FREE_SPACE", "CardFreeSpace"],
        )
    } {
        let info = CARD_FREE_SPACE_INFO {
            dwVersion: CARD_FREE_SPACE_INFO_CURRENT_VERSION,
            dwBytesAvailable: 0,
            dwKeyContainersAvailable: match try_dword_len(
                ctx.card
                    .containers
                    .iter()
                    .filter(|container| !container.is_visible())
                    .count(),
            ) {
                Some(len) => len,
                None => return SCARD_F_INTERNAL_ERROR,
            },
            dwMaxKeyContainers: match try_dword_len(ctx.card.containers.len()) {
                Some(len) => len,
                None => return SCARD_F_INTERNAL_ERROR,
            },
        };
        return unsafe { write_struct_out(pbData, cbData, pdwDataLen, &info) };
    }

    if unsafe {
        wstr_matches_any(
            wszProperty,
            &["Capabilities", "CP_CARD_CAPABILITIES", "CardCapabilities"],
        )
    } {
        let caps = CARD_CAPABILITIES {
            dwVersion: CARD_CAPABILITIES_CURRENT_VERSION,
            fCertificateCompression: 1,
            fKeyGen: 0,
        };
        return unsafe { write_struct_out(pbData, cbData, pdwDataLen, &caps) };
    }

    if unsafe {
        wstr_matches_any(
            wszProperty,
            &["Read Only Mode", "CP_CARD_READ_ONLY", "CardReadOnly"],
        )
    } {
        return unsafe { write_dword_out(pbData, cbData, pdwDataLen, 1) };
    }

    if unsafe { wstr_matches_any(wszProperty, &["Key Sizes", "CP_CARD_KEYSIZES", "KeySizes"]) } {
        let bits = ctx
            .card
            .containers
            .iter()
            .filter(|container| container.is_visible())
            .map(|container| container.key_alg.bits());
        let Some(ks) = aggregated_key_sizes(bits) else {
            return SCARD_F_INTERNAL_ERROR;
        };
        return unsafe { write_struct_out(pbData, cbData, pdwDataLen, &ks) };
    }

    if unsafe {
        wstr_matches_any(
            wszProperty,
            &[
                "Supports Windows x.509 Enrollment",
                "CP_SUPPORTS_WIN_X509_ENROLLMENT",
                "SupportsWindowsx509Enrollment",
            ],
        )
    } {
        return unsafe { write_dword_out(pbData, cbData, pdwDataLen, 0) };
    }

    if unsafe {
        wstr_matches_any(
            wszProperty,
            &[
                "CP_KEY_IMPORT_SUPPORT",
                "Key Import Support",
                "KeyImportSupport",
            ],
        )
    } {
        return unsafe { write_dword_out(pbData, cbData, pdwDataLen, 0) };
    }

    if unsafe {
        wstr_matches_any(
            wszProperty,
            &["CP_CHAINING_MODES", "Chaining Modes", "ChainingModes"],
        )
    } {
        if dwFlags != CARD_CIPHER_OPERATION {
            return SCARD_E_INVALID_PARAMETER;
        }
        let modes = encode_multisz(&[]);
        return unsafe { write_bytes_out(pbData, cbData, pdwDataLen, &modes) };
    }

    if unsafe { wstr_matches_any(wszProperty, &["PIN Information", "CP_CARD_PIN_INFO"]) } {
        if dwFlags != PIN_ID_AUTH && dwFlags != PIN_ID_QUALIFIED_SIG && dwFlags != PIN_ID_PUK {
            return SCARD_E_INVALID_PARAMETER;
        }
        let is_remote = ctx.transport.lock().is_ok_and(|tx| tx.is_remote());
        let info = PIN_INFO {
            dwVersion: PIN_INFO_CURRENT_VERSION,
            PinType: if is_remote {
                EmptyPinType
            } else {
                AlphaNumericPinType
            },
            PinPurpose: pin_purpose(dwFlags),
            dwChangePermission: if is_remote {
                0
            } else {
                pin_change_permission(dwFlags)
            },
            dwUnblockPermission: if is_remote {
                0
            } else {
                pin_unblock_permission(dwFlags)
            },
            PinCachePolicy: PIN_CACHE_POLICY {
                dwVersion: PIN_CACHE_POLICY_CURRENT_VERSION,
                PinCachePolicyType: pin_cache_policy(dwFlags),
                dwPinCachePolicyInfo: NO_PIN_CACHE_POLICY_INFO,
            },
            dwFlags: if is_remote || dwFlags == PIN_ID_AUTH {
                CARD_PIN_INFO_NO_PROMPT_ON_SIGN
            } else {
                0
            },
        };
        return unsafe { write_struct_out(pbData, cbData, pdwDataLen, &info) };
    }

    if unsafe {
        wstr_matches_any(
            wszProperty,
            &[
                "CP_CARD_PIN_STRENGTH_VERIFY",
                "PIN Strength Verify",
                "CP_CARD_PIN_STRENGTH_CHANGE",
                "PIN Strength Change",
                "CP_CARD_PIN_STRENGTH_UNBLOCK",
                "PIN Strength Unblock",
            ],
        )
    } {
        if dwFlags != PIN_ID_AUTH && dwFlags != PIN_ID_QUALIFIED_SIG && dwFlags != PIN_ID_PUK {
            return SCARD_E_INVALID_PARAMETER;
        }
        return unsafe { write_dword_out(pbData, cbData, pdwDataLen, CARD_PIN_STRENGTH_PLAINTEXT) };
    }

    if unsafe {
        wstr_matches_any(
            wszProperty,
            &["Cache Mode", "CP_CARD_CACHE_MODE", "CardCacheMode"],
        )
    } {
        // A read-only card, whose certificates name its holder: the Base CSP
        // and KSP keep its files per process and clear them when the card
        // leaves, not in the global cache keyed by the card.
        return unsafe {
            write_dword_out(pbData, cbData, pdwDataLen, CARD_CACHE_MODE_SESSION_ONLY)
        };
    }

    if unsafe {
        wstr_matches_any(
            wszProperty,
            &[
                "Authenticated State",
                "CP_CARD_AUTHENTICATED_STATE",
                "CardAuthenticatedState",
            ],
        )
    } {
        return unsafe { write_dword_out(pbData, cbData, pdwDataLen, authenticated_pin_set(ctx)) };
    }

    if unsafe {
        wstr_matches_any(
            wszProperty,
            &["PIN List", "CP_CARD_LIST_PINS", "CardListPins"],
        )
    } {
        return unsafe { write_dword_out(pbData, cbData, pdwDataLen, ctx.card.pin_set()) };
    }

    if unsafe {
        wstr_matches_any(
            wszProperty,
            &[
                "Card Identifier",
                "CP_CARD_GUID",
                "CardGUID",
                "Card Serial Number",
                "CP_CARD_SERIAL_NO",
                "CardSerialNo",
            ],
        )
    } {
        let serial = synth_cardid(ctx.card.auth_cert_der().unwrap_or(&[]));
        return unsafe { write_bytes_out(pbData, cbData, pdwDataLen, &serial) };
    }

    if unsafe {
        wstr_matches_any(
            wszProperty,
            &[
                "Enumerate Algorithms",
                "CP_ENUM_ALGORITHMS",
                "EnumAlgorithms",
            ],
        )
    } {
        let algs = match dwFlags {
            CARD_ASYMMETRIC_OPERATION => encode_multisz(&ctx.card.algorithms()),
            CARD_CIPHER_OPERATION => encode_multisz(&[]),
            _ => return SCARD_E_INVALID_PARAMETER,
        };
        return unsafe { write_bytes_out(pbData, cbData, pdwDataLen, &algs) };
    }

    if unsafe { wstr_matches_any(wszProperty, &["Padding Schemes", "PaddingSchemes"]) } {
        return match dwFlags {
            CARD_ASYMMETRIC_OPERATION => {
                let mut schemes = 0;
                if ctx.card.containers.iter().any(|container| {
                    container.is_visible()
                        && container.allow_sign
                        && matches!(container.key_alg, KeyAlgorithm::Rsa { .. })
                }) {
                    schemes |= CARD_PADDING_PKCS1;
                }
                if ctx
                    .card
                    .containers
                    .iter()
                    .any(|container| container.is_visible() && container.allow_pss)
                {
                    schemes |= CARD_PADDING_PSS;
                }
                unsafe { write_dword_out(pbData, cbData, pdwDataLen, schemes) }
            }
            CARD_CIPHER_OPERATION => unsafe { write_dword_out(pbData, cbData, pdwDataLen, 0) },
            _ => SCARD_E_INVALID_PARAMETER,
        };
    }

    SCARD_E_INVALID_PARAMETER
}

#[cfg(windows)]
unsafe extern "system" fn CardGetContainerProperty(
    pCardData: *mut CARD_DATA,
    bContainerIndex: BYTE,
    wszProperty: LPCWSTR,
    pbData: PBYTE,
    cbData: DWORD,
    pdwDataLen: PDWORD,
    dwFlags: DWORD,
) -> DWORD {
    if wszProperty.is_null() {
        return SCARD_E_INVALID_PARAMETER;
    }
    if dwFlags != 0 {
        return SCARD_E_INVALID_PARAMETER;
    }

    let (cd, ctx) = match unsafe { checked_card_data_and_ctx(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    let Some(container) = ctx.card.visible_container(bContainerIndex) else {
        return SCARD_E_NO_KEY_CONTAINER;
    };

    if unsafe { wstr_eq(wszProperty, "PIN Identifier") } {
        return unsafe { write_dword_out(pbData, cbData, pdwDataLen, container.pin_id) };
    }
    if unsafe { wstr_eq(wszProperty, "Container Info") } {
        let Some(info) = (unsafe { build_container_info_struct(cd, container) }) else {
            return SCARD_F_INTERNAL_ERROR;
        };
        return unsafe { write_struct_out(pbData, cbData, pdwDataLen, &info) };
    }
    if unsafe { wstr_matches_any(wszProperty, &["Key Sizes", "CP_CARD_KEYSIZES", "KeySizes"]) } {
        let ks = CARD_KEY_SIZES {
            dwVersion: CARD_KEY_SIZES_CURRENT_VERSION,
            dwMinimumBitlen: DWORD::from(container.key_alg.bits()),
            dwDefaultBitlen: DWORD::from(container.key_alg.bits()),
            dwMaximumBitlen: DWORD::from(container.key_alg.bits()),
            dwIncrementalBitlen: 0,
        };
        return unsafe { write_struct_out(pbData, cbData, pdwDataLen, &ks) };
    }

    SCARD_E_INVALID_PARAMETER
}

#[cfg(windows)]
unsafe extern "system" fn CardUnblockPin(
    pCardData: *mut CARD_DATA,
    pwszUserId: LPWSTR,
    pbAuthData: PBYTE,
    cbAuth: DWORD,
    pbNewPinData: PBYTE,
    cbNewPin: DWORD,
    _cRetries: DWORD,
    _dwFlags: DWORD,
) -> DWORD {
    let target_pin_id = unsafe { pin_id_from_user_id(pwszUserId) };
    let Some(target_slot) = pin_slot_for_id(target_pin_id) else {
        return SCARD_E_INVALID_PARAMETER;
    };
    let (cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    if ctx.transport.lock().is_ok_and(|tx| tx.is_remote()) {
        return SCARD_E_UNSUPPORTED_FEATURE;
    }
    clear_pin_state(&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);
    let puk = match unsafe { checked_pin_bytes(pbAuthData, cbAuth, PIN_ID_PUK) } {
        Ok(puk) => puk,
        Err(rc) => return rc,
    };
    let new_pin = match unsafe { checked_pin_bytes(pbNewPinData, cbNewPin, target_pin_id) } {
        Ok(pin) => pin,
        Err(rc) => return rc,
    };
    unblock_card_pin(ctx, cd.hScard, target_slot, puk, new_pin)
}

#[cfg(windows)]
unsafe extern "system" fn CardChangeAuthenticator(
    pCardData: *mut CARD_DATA,
    pwszUserId: LPWSTR,
    pbCurrentAuth: PBYTE,
    cbCurrentAuth: DWORD,
    pbNewAuth: PBYTE,
    cbNewAuth: DWORD,
    _cRetries: DWORD,
    _dwFlags: DWORD,
    pcAttemptsRemaining: PDWORD,
) -> DWORD {
    let pin_id = unsafe { pin_id_from_user_id(pwszUserId) };
    let Some(slot) = pin_slot_for_id(pin_id) else {
        return SCARD_E_INVALID_PARAMETER;
    };
    let (cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    if ctx.transport.lock().is_ok_and(|tx| tx.is_remote()) {
        return SCARD_E_UNSUPPORTED_FEATURE;
    }
    clear_pin_state(&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);
    let current_pin = match unsafe { checked_pin_bytes(pbCurrentAuth, cbCurrentAuth, pin_id) } {
        Ok(pin) => pin,
        Err(rc) => return rc,
    };
    let new_pin = match unsafe { checked_pin_bytes(pbNewAuth, cbNewAuth, pin_id) } {
        Ok(pin) => pin,
        Err(rc) => return rc,
    };
    let (status, attempts) = change_card_pin(ctx, cd.hScard, slot, &current_pin, new_pin);
    unsafe {
        write_attempts_remaining(pcAttemptsRemaining, attempts);
    }
    status
}

#[cfg(windows)]
unsafe extern "system" fn CardAuthenticateEx(
    pCardData: *mut CARD_DATA,
    PinId: DWORD,
    _dwFlags: DWORD,
    pbPinData: PBYTE,
    cbPinData: DWORD,
    ppbSessionPin: *mut PBYTE,
    pcbSessionPin: PDWORD,
    pcAttemptsRemaining: PDWORD,
) -> DWORD {
    // The Base CSP probes session-PIN support. Session PINs are not
    // supported: initialise the out parameters (the caller reads them
    // after return -- leaving them uninitialised fails the KSP's
    // internal consistency check with NTE_INTERNAL_ERROR) and handle
    // the request as a plain PIN verification.
    if !ppbSessionPin.is_null() {
        unsafe {
            *ppbSessionPin = core::ptr::null_mut();
        }
    }
    if !pcbSessionPin.is_null() {
        unsafe {
            *pcbSessionPin = NO_SESSION_PIN_LEN;
        }
    }
    if PinId == PIN_ID_PUK {
        return SCARD_E_UNSUPPORTED_FEATURE;
    }
    let Some(slot) = pin_slot_for_id(PinId) else {
        return SCARD_E_INVALID_PARAMETER;
    };
    let (cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    if ctx.transport.lock().is_ok_and(|tx| tx.is_remote()) {
        if PinId == PIN_ID_QUALIFIED_SIG {
            ctx.pin2_authenticated = true;
        } else {
            ctx.pin1_authenticated = true;
        }
        return SCARD_S_SUCCESS;
    }
    let pin = match unsafe { checked_pin_bytes(pbPinData, cbPinData, PinId) } {
        Ok(pin) => pin,
        Err(rc) => return rc,
    };
    let (status, attempts) =
        verify_card_pin(ctx, cd.hScard, slot, pin, VerifyCaller::AuthenticateEx);
    unsafe {
        write_attempts_remaining(pcAttemptsRemaining, attempts);
    }
    status
}

#[cfg(windows)]
unsafe extern "system" fn CardChangeAuthenticatorEx(
    pCardData: *mut CARD_DATA,
    _dwFlags: DWORD,
    dwAuthenticatingPinId: DWORD,
    pbAuthenticatingPinData: PBYTE,
    cbAuthenticatingPinData: DWORD,
    dwTargetPinId: DWORD,
    pbTargetData: PBYTE,
    cbTargetData: DWORD,
    _cRetries: DWORD,
    pcAttemptsRemaining: PDWORD,
) -> DWORD {
    let (cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    if ctx.transport.lock().is_ok_and(|tx| tx.is_remote()) {
        return SCARD_E_UNSUPPORTED_FEATURE;
    }
    clear_pin_state(&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);

    if dwAuthenticatingPinId == PIN_ID_PUK {
        let Some(target_slot) = pin_slot_for_id(dwTargetPinId) else {
            return SCARD_E_INVALID_PARAMETER;
        };
        let puk = match unsafe {
            checked_pin_bytes(pbAuthenticatingPinData, cbAuthenticatingPinData, PIN_ID_PUK)
        } {
            Ok(p) => p,
            Err(rc) => return rc,
        };
        let new_pin = match unsafe { checked_pin_bytes(pbTargetData, cbTargetData, dwTargetPinId) }
        {
            Ok(p) => p,
            Err(rc) => return rc,
        };
        return unblock_card_pin(ctx, cd.hScard, target_slot, puk, new_pin);
    }

    if dwAuthenticatingPinId != dwTargetPinId {
        return SCARD_E_INVALID_PARAMETER;
    }
    let Some(target_slot) = pin_slot_for_id(dwTargetPinId) else {
        return SCARD_E_INVALID_PARAMETER;
    };
    let current_pin = match unsafe {
        checked_pin_bytes(
            pbAuthenticatingPinData,
            cbAuthenticatingPinData,
            dwTargetPinId,
        )
    } {
        Ok(p) => p,
        Err(rc) => return rc,
    };
    let new_pin = match unsafe { checked_pin_bytes(pbTargetData, cbTargetData, dwTargetPinId) } {
        Ok(p) => p,
        Err(rc) => return rc,
    };
    let (status, attempts) = change_card_pin(ctx, cd.hScard, target_slot, &current_pin, new_pin);
    unsafe {
        write_attempts_remaining(pcAttemptsRemaining, attempts);
    }
    status
}

/// Defines Card Module `extern "system"` entry points that answer
/// [`SCARD_E_UNSUPPORTED_FEATURE`] for operations this read-only card
/// profile does not support.
#[cfg(windows)]
macro_rules! unsupported_card_entries {
    ($($name:ident($($argument:ident: $type:ty),* $(,)?);)*) => {
        $(
            unsafe extern "system" fn $name($($argument: $type),*) -> DWORD {
                SCARD_E_UNSUPPORTED_FEATURE
            }
        )*
    };
}

#[cfg(windows)]
unsupported_card_entries! {
    unsupported_delete_container(
        _pCardData: *mut CARD_DATA,
        _bContainerIndex: BYTE,
        _dwReserved: DWORD,
    );
    unsupported_create_container(
        _pCardData: *mut CARD_DATA,
        _bContainerIndex: BYTE,
        _dwFlags: DWORD,
        _dwKeySpec: DWORD,
        _dwKeySize: DWORD,
        _pbKeyData: PBYTE,
    );
    unsupported_get_challenge(
        _pCardData: *mut CARD_DATA,
        _ppbChallengeData: *mut PBYTE,
        _pcbChallengeData: PDWORD,
    );
    unsupported_authenticate_challenge(
        _pCardData: *mut CARD_DATA,
        _pbResponseData: PBYTE,
        _cbResponseData: DWORD,
        _pcAttemptsRemaining: PDWORD,
    );
    unsupported_create_directory(
        _pCardData: *mut CARD_DATA,
        _pszDirectoryName: LPSTR,
        _AccessCondition: DWORD,
    );
    unsupported_delete_directory(
        _pCardData: *mut CARD_DATA,
        _pszDirectoryName: LPSTR,
    );
    unsupported_create_file(
        _pCardData: *mut CARD_DATA,
        _pszDirectoryName: LPSTR,
        _pszFileName: LPSTR,
        _cbInitialCreationSize: DWORD,
        _AccessCondition: DWORD,
    );
    unsupported_write_file(
        _pCardData: *mut CARD_DATA,
        _pszDirectoryName: LPSTR,
        _pszFileName: LPSTR,
        _dwFlags: DWORD,
        _pbData: PBYTE,
        _cbData: DWORD,
    );
    unsupported_delete_file(
        _pCardData: *mut CARD_DATA,
        _pszDirectoryName: LPSTR,
        _pszFileName: LPSTR,
        _dwFlags: DWORD,
    );
    unsupported_get_challenge_ex(
        _pCardData: *mut CARD_DATA,
        _PinId: DWORD,
        _ppbChallengeData: *mut PBYTE,
        _pcbChallengeData: PDWORD,
        _dwFlags: DWORD,
    );
    unsupported_set_container_property(
        _pCardData: *mut CARD_DATA,
        _bContainerIndex: BYTE,
        _wszProperty: LPCWSTR,
        _pbData: PBYTE,
        _cbData: DWORD,
        _dwFlags: DWORD,
    );
    unsupported_set_property(
        _pCardData: *mut CARD_DATA,
        _wszProperty: LPCWSTR,
        _pbData: PBYTE,
        _cbData: DWORD,
        _dwFlags: DWORD,
    );
}

#[cfg(test)]
mod tests {
    use super::{CardFile, NoSuchFile};

    #[test]
    fn the_root_holds_the_three_card_files() {
        assert_eq!(CardFile::resolve(None, "cardcf"), Ok(CardFile::CardCf));
        assert_eq!(CardFile::resolve(None, "cardid"), Ok(CardFile::CardId));
        assert_eq!(CardFile::resolve(None, "cardapps"), Ok(CardFile::CardApps));
    }

    #[test]
    fn the_root_has_no_other_file() {
        assert_eq!(CardFile::resolve(None, "cmapfile"), Err(NoSuchFile::File));
        assert_eq!(CardFile::resolve(None, "cardc"), Err(NoSuchFile::File));
        assert_eq!(CardFile::resolve(None, "cardcfx"), Err(NoSuchFile::File));
        assert_eq!(CardFile::resolve(None, ""), Err(NoSuchFile::File));
    }

    #[test]
    fn mscp_holds_the_map_and_container_files() {
        assert_eq!(
            CardFile::resolve(Some("mscp"), "cmapfile"),
            Ok(CardFile::CmapFile)
        );
        assert_eq!(
            CardFile::resolve(Some("mscp"), "cardcf"),
            Ok(CardFile::CardCf)
        );
        assert_eq!(
            CardFile::resolve(Some("mscp"), "kxc00"),
            Ok(CardFile::Container("kxc00".to_owned()))
        );
    }

    /// No card CA reaches the user's Root store through this module:
    /// `msroots` is a file the card does not have, and Windows propagates
    /// nothing.
    #[test]
    fn mscp_has_no_roots_bundle() {
        assert_eq!(
            CardFile::resolve(Some("mscp"), "msroots"),
            Err(NoSuchFile::File)
        );
    }

    #[test]
    fn any_other_directory_is_no_directory() {
        assert_eq!(
            CardFile::resolve(Some("msc"), "cmapfile"),
            Err(NoSuchFile::Directory)
        );
        assert_eq!(
            CardFile::resolve(Some("mscpx"), "cmapfile"),
            Err(NoSuchFile::Directory)
        );
        assert_eq!(
            CardFile::resolve(Some(""), "cardcf"),
            Err(NoSuchFile::Directory)
        );
    }

    mod padding_and_version_tests {
        use crate::ffi::{
            BCRYPT_PKCS1_PADDING_INFO, BCRYPT_PSS_PADDING_INFO, CARD_PADDING_INFO_PRESENT,
            CARD_PADDING_NONE, CARD_PADDING_OAEP, CARD_PADDING_PKCS1, CARD_PADDING_PSS,
            CARD_RSA_DECRYPT_INFO, CARD_RSA_DECRYPT_INFO_BASIC,
            CARD_RSA_DECRYPT_INFO_BASIC_VERSION, CARD_RSA_DECRYPT_INFO_CURRENT_VERSION,
            CARD_SIGNING_INFO, CARD_SIGNING_INFO_BASIC, CARD_SIGNING_INFO_BASIC_VERSION,
            CARD_SIGNING_INFO_CURRENT_VERSION, SCARD_E_INVALID_PARAMETER,
            SCARD_E_UNSUPPORTED_FEATURE,
        };
        use crate::{ParsedSigningPadding, parse_rsa_decrypt_padding, parse_signing_padding};

        #[test]
        fn struct_layout_and_offsets() {
            assert!(size_of::<CARD_SIGNING_INFO_BASIC>() < size_of::<CARD_SIGNING_INFO>());
            assert_eq!(
                core::mem::offset_of!(CARD_SIGNING_INFO_BASIC, dwVersion),
                core::mem::offset_of!(CARD_SIGNING_INFO, dwVersion)
            );
            assert_eq!(
                core::mem::offset_of!(CARD_SIGNING_INFO_BASIC, bContainerIndex),
                core::mem::offset_of!(CARD_SIGNING_INFO, bContainerIndex)
            );
            assert_eq!(
                core::mem::offset_of!(CARD_SIGNING_INFO_BASIC, dwKeySpec),
                core::mem::offset_of!(CARD_SIGNING_INFO, dwKeySpec)
            );
            assert_eq!(
                core::mem::offset_of!(CARD_SIGNING_INFO_BASIC, dwSigningFlags),
                core::mem::offset_of!(CARD_SIGNING_INFO, dwSigningFlags)
            );
            assert_eq!(
                core::mem::offset_of!(CARD_SIGNING_INFO_BASIC, aiHashAlg),
                core::mem::offset_of!(CARD_SIGNING_INFO, aiHashAlg)
            );
            assert_eq!(
                core::mem::offset_of!(CARD_SIGNING_INFO_BASIC, pbData),
                core::mem::offset_of!(CARD_SIGNING_INFO, pbData)
            );
            assert_eq!(
                core::mem::offset_of!(CARD_SIGNING_INFO_BASIC, cbData),
                core::mem::offset_of!(CARD_SIGNING_INFO, cbData)
            );
            assert_eq!(
                core::mem::offset_of!(CARD_SIGNING_INFO_BASIC, pbSignedData),
                core::mem::offset_of!(CARD_SIGNING_INFO, pbSignedData)
            );
            assert_eq!(
                core::mem::offset_of!(CARD_SIGNING_INFO_BASIC, cbSignedData),
                core::mem::offset_of!(CARD_SIGNING_INFO, cbSignedData)
            );

            assert!(size_of::<CARD_RSA_DECRYPT_INFO_BASIC>() < size_of::<CARD_RSA_DECRYPT_INFO>());
            assert_eq!(
                core::mem::offset_of!(CARD_RSA_DECRYPT_INFO_BASIC, dwVersion),
                core::mem::offset_of!(CARD_RSA_DECRYPT_INFO, dwVersion)
            );
            assert_eq!(
                core::mem::offset_of!(CARD_RSA_DECRYPT_INFO_BASIC, bContainerIndex),
                core::mem::offset_of!(CARD_RSA_DECRYPT_INFO, bContainerIndex)
            );
            assert_eq!(
                core::mem::offset_of!(CARD_RSA_DECRYPT_INFO_BASIC, dwKeySpec),
                core::mem::offset_of!(CARD_RSA_DECRYPT_INFO, dwKeySpec)
            );
            assert_eq!(
                core::mem::offset_of!(CARD_RSA_DECRYPT_INFO_BASIC, pbData),
                core::mem::offset_of!(CARD_RSA_DECRYPT_INFO, pbData)
            );
            assert_eq!(
                core::mem::offset_of!(CARD_RSA_DECRYPT_INFO_BASIC, cbData),
                core::mem::offset_of!(CARD_RSA_DECRYPT_INFO, cbData)
            );
        }

        #[test]
        fn card_signing_info_v1_allocation_is_parsed_as_pkcs1_without_reading_v2_tail() {
            let mut basic = CARD_SIGNING_INFO_BASIC {
                dwVersion: CARD_SIGNING_INFO_BASIC_VERSION,
                bContainerIndex: 0,
                dwKeySpec: 1,
                dwSigningFlags: 0,
                aiHashAlg: 0x8004,
                pbData: core::ptr::null_mut(),
                cbData: 0,
                pbSignedData: core::ptr::null_mut(),
                cbSignedData: 0,
            };
            let p_info = (&raw mut basic).cast::<CARD_SIGNING_INFO>();
            let parsed = unsafe { parse_signing_padding(p_info) };
            assert_eq!(parsed, Ok(ParsedSigningPadding::Pkcs1 { hash_name: None }));
        }

        #[test]
        fn card_signing_info_v2_without_padding_flag_ignores_v2_tail() {
            let v2 = CARD_SIGNING_INFO {
                dwVersion: CARD_SIGNING_INFO_CURRENT_VERSION,
                bContainerIndex: 0,
                dwKeySpec: 1,
                dwSigningFlags: 0, // CARD_PADDING_INFO_PRESENT not set
                aiHashAlg: 0x8004,
                pbData: core::ptr::null_mut(),
                cbData: 0,
                pbSignedData: core::ptr::null_mut(),
                cbSignedData: 0,
                pPaddingInfo: 0xDEAD_BEEF as *mut _,
                dwPaddingType: 0xBAAD_F00D,
            };
            let parsed = unsafe { parse_signing_padding(&raw const v2) };
            assert_eq!(parsed, Ok(ParsedSigningPadding::Pkcs1 { hash_name: None }));
        }

        #[test]
        fn card_signing_info_v2_with_pkcs1_padding_reads_hash_name() {
            let alg_name: Vec<u16> = "SHA256\0".encode_utf16().collect();
            let pad_info = BCRYPT_PKCS1_PADDING_INFO {
                pszAlgId: alg_name.as_ptr(),
            };
            let v2 = CARD_SIGNING_INFO {
                dwVersion: CARD_SIGNING_INFO_CURRENT_VERSION,
                bContainerIndex: 0,
                dwKeySpec: 1,
                dwSigningFlags: CARD_PADDING_INFO_PRESENT,
                aiHashAlg: 0,
                pbData: core::ptr::null_mut(),
                cbData: 0,
                pbSignedData: core::ptr::null_mut(),
                cbSignedData: 0,
                pPaddingInfo: (&raw const pad_info).cast_mut().cast(),
                dwPaddingType: CARD_PADDING_PKCS1,
            };
            let parsed = unsafe { parse_signing_padding(&raw const v2) };
            assert_eq!(
                parsed,
                Ok(ParsedSigningPadding::Pkcs1 {
                    hash_name: Some("SHA256".to_string()),
                })
            );

            // Null pPaddingInfo with PKCS1 is allowed (defaults to None hash_name)
            let v2_null_pad = CARD_SIGNING_INFO {
                dwVersion: CARD_SIGNING_INFO_CURRENT_VERSION,
                bContainerIndex: 0,
                dwKeySpec: 1,
                dwSigningFlags: CARD_PADDING_INFO_PRESENT,
                aiHashAlg: 0,
                pbData: core::ptr::null_mut(),
                cbData: 0,
                pbSignedData: core::ptr::null_mut(),
                cbSignedData: 0,
                pPaddingInfo: core::ptr::null_mut(),
                dwPaddingType: CARD_PADDING_PKCS1,
            };
            assert_eq!(
                unsafe { parse_signing_padding(&raw const v2_null_pad) },
                Ok(ParsedSigningPadding::Pkcs1 { hash_name: None })
            );

            // Null pszAlgId in pad_info also yields None
            let pad_info_null_alg = BCRYPT_PKCS1_PADDING_INFO {
                pszAlgId: core::ptr::null(),
            };
            let v2_null_alg = CARD_SIGNING_INFO {
                dwVersion: CARD_SIGNING_INFO_CURRENT_VERSION,
                bContainerIndex: 0,
                dwKeySpec: 1,
                dwSigningFlags: CARD_PADDING_INFO_PRESENT,
                aiHashAlg: 0,
                pbData: core::ptr::null_mut(),
                cbData: 0,
                pbSignedData: core::ptr::null_mut(),
                cbSignedData: 0,
                pPaddingInfo: (&raw const pad_info_null_alg).cast_mut().cast(),
                dwPaddingType: CARD_PADDING_PKCS1,
            };
            assert_eq!(
                unsafe { parse_signing_padding(&raw const v2_null_alg) },
                Ok(ParsedSigningPadding::Pkcs1 { hash_name: None })
            );
        }

        #[test]
        fn card_signing_info_v2_with_pss_padding_reads_hash_and_salt() {
            let alg_name: Vec<u16> = "SHA384\0".encode_utf16().collect();
            let pad_info = BCRYPT_PSS_PADDING_INFO {
                pszAlgId: alg_name.as_ptr(),
                cbSalt: 48,
            };
            let v2 = CARD_SIGNING_INFO {
                dwVersion: CARD_SIGNING_INFO_CURRENT_VERSION,
                bContainerIndex: 0,
                dwKeySpec: 1,
                dwSigningFlags: CARD_PADDING_INFO_PRESENT,
                aiHashAlg: 0,
                pbData: core::ptr::null_mut(),
                cbData: 0,
                pbSignedData: core::ptr::null_mut(),
                cbSignedData: 0,
                pPaddingInfo: (&raw const pad_info).cast_mut().cast(),
                dwPaddingType: CARD_PADDING_PSS,
            };
            assert_eq!(
                unsafe { parse_signing_padding(&raw const v2) },
                Ok(ParsedSigningPadding::Pss {
                    hash_name: "SHA384".to_string(),
                    salt_len: 48,
                })
            );

            // Null pszAlgId defaults to SHA256
            let pad_info_default_alg = BCRYPT_PSS_PADDING_INFO {
                pszAlgId: core::ptr::null(),
                cbSalt: 32,
            };
            let v2_default_alg = CARD_SIGNING_INFO {
                dwVersion: CARD_SIGNING_INFO_CURRENT_VERSION,
                bContainerIndex: 0,
                dwKeySpec: 1,
                dwSigningFlags: CARD_PADDING_INFO_PRESENT,
                aiHashAlg: 0,
                pbData: core::ptr::null_mut(),
                cbData: 0,
                pbSignedData: core::ptr::null_mut(),
                cbSignedData: 0,
                pPaddingInfo: (&raw const pad_info_default_alg).cast_mut().cast(),
                dwPaddingType: CARD_PADDING_PSS,
            };
            assert_eq!(
                unsafe { parse_signing_padding(&raw const v2_default_alg) },
                Ok(ParsedSigningPadding::Pss {
                    hash_name: "SHA256".to_string(),
                    salt_len: 32,
                })
            );

            // PSS requires pPaddingInfo
            let v2_no_pad = CARD_SIGNING_INFO {
                dwVersion: CARD_SIGNING_INFO_CURRENT_VERSION,
                bContainerIndex: 0,
                dwKeySpec: 1,
                dwSigningFlags: CARD_PADDING_INFO_PRESENT,
                aiHashAlg: 0,
                pbData: core::ptr::null_mut(),
                cbData: 0,
                pbSignedData: core::ptr::null_mut(),
                cbSignedData: 0,
                pPaddingInfo: core::ptr::null_mut(),
                dwPaddingType: CARD_PADDING_PSS,
            };
            assert_eq!(
                unsafe { parse_signing_padding(&raw const v2_no_pad) },
                Err(SCARD_E_INVALID_PARAMETER)
            );
        }

        #[test]
        fn card_signing_info_v2_rejects_unsupported_padding() {
            for pad_type in [CARD_PADDING_NONE, CARD_PADDING_OAEP, 0x9999] {
                let v2 = CARD_SIGNING_INFO {
                    dwVersion: CARD_SIGNING_INFO_CURRENT_VERSION,
                    bContainerIndex: 0,
                    dwKeySpec: 1,
                    dwSigningFlags: CARD_PADDING_INFO_PRESENT,
                    aiHashAlg: 0,
                    pbData: core::ptr::null_mut(),
                    cbData: 0,
                    pbSignedData: core::ptr::null_mut(),
                    cbSignedData: 0,
                    pPaddingInfo: core::ptr::null_mut(),
                    dwPaddingType: pad_type,
                };
                assert_eq!(
                    unsafe { parse_signing_padding(&raw const v2) },
                    Err(SCARD_E_UNSUPPORTED_FEATURE)
                );
            }
        }

        #[test]
        fn card_signing_info_invalid_version_or_null() {
            assert_eq!(
                unsafe { parse_signing_padding(core::ptr::null()) },
                Err(SCARD_E_INVALID_PARAMETER)
            );

            for bad_version in [0, 3, 100] {
                let v = CARD_SIGNING_INFO {
                    dwVersion: bad_version,
                    bContainerIndex: 0,
                    dwKeySpec: 1,
                    dwSigningFlags: 0,
                    aiHashAlg: 0,
                    pbData: core::ptr::null_mut(),
                    cbData: 0,
                    pbSignedData: core::ptr::null_mut(),
                    cbSignedData: 0,
                    pPaddingInfo: core::ptr::null_mut(),
                    dwPaddingType: 0,
                };
                assert_eq!(
                    unsafe { parse_signing_padding(&raw const v) },
                    Err(SCARD_E_INVALID_PARAMETER)
                );
            }
        }

        #[test]
        fn card_rsa_decrypt_v1_allocation_is_parsed_without_reading_v2_tail() {
            let mut basic = CARD_RSA_DECRYPT_INFO_BASIC {
                dwVersion: CARD_RSA_DECRYPT_INFO_BASIC_VERSION,
                bContainerIndex: 0,
                dwKeySpec: 1,
                pbData: core::ptr::null_mut(),
                cbData: 0,
            };
            let p_info = (&raw mut basic).cast::<core::ffi::c_void>();
            assert_eq!(unsafe { parse_rsa_decrypt_padding(p_info) }, Ok(()));
        }

        #[test]
        fn card_rsa_decrypt_v2_checks() {
            let v2_pkcs1 = CARD_RSA_DECRYPT_INFO {
                dwVersion: CARD_RSA_DECRYPT_INFO_CURRENT_VERSION,
                bContainerIndex: 0,
                dwKeySpec: 1,
                pbData: core::ptr::null_mut(),
                cbData: 0,
                pPaddingInfo: core::ptr::null_mut(),
                dwPaddingType: CARD_PADDING_PKCS1,
            };
            assert_eq!(
                unsafe { parse_rsa_decrypt_padding((&raw const v2_pkcs1).cast_mut().cast()) },
                Ok(())
            );

            let v2_none = CARD_RSA_DECRYPT_INFO {
                dwVersion: CARD_RSA_DECRYPT_INFO_CURRENT_VERSION,
                bContainerIndex: 0,
                dwKeySpec: 1,
                pbData: core::ptr::null_mut(),
                cbData: 0,
                pPaddingInfo: core::ptr::null_mut(),
                dwPaddingType: CARD_PADDING_NONE,
            };
            assert_eq!(
                unsafe { parse_rsa_decrypt_padding((&raw const v2_none).cast_mut().cast()) },
                Err(SCARD_E_UNSUPPORTED_FEATURE)
            );

            let v2_oaep = CARD_RSA_DECRYPT_INFO {
                dwVersion: CARD_RSA_DECRYPT_INFO_CURRENT_VERSION,
                bContainerIndex: 0,
                dwKeySpec: 1,
                pbData: core::ptr::null_mut(),
                cbData: 0,
                pPaddingInfo: core::ptr::null_mut(),
                dwPaddingType: CARD_PADDING_OAEP,
            };
            assert_eq!(
                unsafe { parse_rsa_decrypt_padding((&raw const v2_oaep).cast_mut().cast()) },
                Err(SCARD_E_UNSUPPORTED_FEATURE)
            );

            assert_eq!(
                unsafe { parse_rsa_decrypt_padding(core::ptr::null_mut()) },
                Err(SCARD_E_INVALID_PARAMETER)
            );

            for bad_version in [0, 3, 100] {
                let v = CARD_RSA_DECRYPT_INFO {
                    dwVersion: bad_version,
                    bContainerIndex: 0,
                    dwKeySpec: 1,
                    pbData: core::ptr::null_mut(),
                    cbData: 0,
                    pPaddingInfo: core::ptr::null_mut(),
                    dwPaddingType: CARD_PADDING_PKCS1,
                };
                assert_eq!(
                    unsafe { parse_rsa_decrypt_padding((&raw const v).cast_mut().cast()) },
                    Err(SCARD_E_INVALID_PARAMETER)
                );
            }
        }
    }

    #[cfg(windows)]
    mod windows_pin_helpers {
        use std::sync::Mutex;

        use refineid_lib_core::apdu::status_word::{PinRetries, StatusWord};
        use refineid_lib_core::auth::{
            ChangePinOutcome, PIN_MAX_LENGTH, PIN_MIN_LENGTH, PUK_MAX_LENGTH, PUK_MIN_LENGTH,
            PinReferenceScheme, PinSlot, UnblockOutcome, VerifyOutcome,
        };

        use crate::cardmod::{
            CardCapabilityModel, Ctx, PIN_ID_AUTH, PIN_ID_PUK, PIN_ID_QUALIFIED_SIG,
        };
        use crate::ffi::{
            DWORD, ROLE_EVERYONE, SCARD_E_INVALID_HANDLE, SCARD_E_INVALID_PARAMETER,
            SCARD_F_INTERNAL_ERROR, SCARD_S_SUCCESS, SCARD_W_CHV_BLOCKED, SCARD_W_WRONG_CHV,
        };
        use crate::transport::{CardSessionTransport, ScardProtocol, WinScardTransport};
        use crate::{
            INVALID_SCARD_HANDLE, NO_ATTEMPTS_REMAINING, VerifyCaller, map_change_pin_outcome,
            map_unblock_outcome, map_verify_outcome, pin_len_bounds, pin_slot_for_id,
            sync_transport_handle, write_attempts_remaining,
        };

        const INITIAL_H_CARD: usize = 1;
        const RECONNECTED_H_CARD: usize = 2;
        const TWO_RETRIES: u8 = 2;
        const UNTOUCHED_ATTEMPTS_SENTINEL: DWORD = DWORD::MAX;

        fn test_ctx(pin1_authenticated: bool, pin2_authenticated: bool) -> Ctx {
            let transport = WinScardTransport {
                h_card: Default::default(),
                atr: Vec::new(),
                protocol: ScardProtocol::T1,
            };
            Ctx {
                transport: Mutex::new(CardSessionTransport::plain(transport)),
                card: CardCapabilityModel {
                    containers: Vec::new(),
                    cmapfile_records: Vec::new(),
                },
                pin1_authenticated,
                pin2_authenticated,
                pin2_scheme: PinReferenceScheme::Citizen,
            }
        }

        #[test]
        fn pin_slot_and_bounds_cover_card_pin_roles() {
            assert_eq!(pin_slot_for_id(PIN_ID_AUTH), Some(PinSlot::Pin1));
            assert_eq!(pin_slot_for_id(PIN_ID_QUALIFIED_SIG), Some(PinSlot::Pin2));
            assert_eq!(pin_slot_for_id(PIN_ID_PUK), None);
            assert_eq!(pin_slot_for_id(ROLE_EVERYONE), None);

            assert_eq!(
                pin_len_bounds(PIN_ID_AUTH),
                Some((PIN_MIN_LENGTH, PIN_MAX_LENGTH))
            );
            assert_eq!(
                pin_len_bounds(PIN_ID_QUALIFIED_SIG),
                Some((PIN_MIN_LENGTH, PIN_MAX_LENGTH))
            );
            assert_eq!(
                pin_len_bounds(PIN_ID_PUK),
                Some((PUK_MIN_LENGTH, PUK_MAX_LENGTH))
            );
            assert_eq!(pin_len_bounds(ROLE_EVERYONE), None);
        }

        #[test]
        fn verify_outcome_locked_reports_zero_attempts_only_for_authenticate_pin() {
            let mut v4_ctx = test_ctx(true, true);
            assert_eq!(
                map_verify_outcome(
                    &mut v4_ctx,
                    PinSlot::Pin1,
                    PinReferenceScheme::Citizen,
                    VerifyCaller::AuthenticatePin,
                    Ok::<_, &str>(VerifyOutcome::Locked),
                ),
                (SCARD_W_CHV_BLOCKED, Some(NO_ATTEMPTS_REMAINING))
            );
            assert!(!v4_ctx.pin1_authenticated);
            assert!(!v4_ctx.pin2_authenticated);

            let mut v6_ctx = test_ctx(true, true);
            assert_eq!(
                map_verify_outcome(
                    &mut v6_ctx,
                    PinSlot::Pin1,
                    PinReferenceScheme::Citizen,
                    VerifyCaller::AuthenticateEx,
                    Ok::<_, &str>(VerifyOutcome::Locked),
                ),
                (SCARD_W_CHV_BLOCKED, None)
            );
            assert!(!v6_ctx.pin1_authenticated);
            assert!(!v6_ctx.pin2_authenticated);
        }

        #[test]
        fn verify_outcome_ok_sets_slot_authentication_and_pin2_scheme() {
            let mut pin1_ctx = test_ctx(false, false);
            assert_eq!(
                map_verify_outcome(
                    &mut pin1_ctx,
                    PinSlot::Pin1,
                    PinReferenceScheme::Citizen,
                    VerifyCaller::AuthenticatePin,
                    Ok::<_, &str>(VerifyOutcome::Ok),
                ),
                (SCARD_S_SUCCESS, None)
            );
            assert!(pin1_ctx.pin1_authenticated);
            assert!(!pin1_ctx.pin2_authenticated);

            let mut pin2_ctx = test_ctx(false, false);
            assert_eq!(
                map_verify_outcome(
                    &mut pin2_ctx,
                    PinSlot::Pin2,
                    PinReferenceScheme::Organizational,
                    VerifyCaller::AuthenticateEx,
                    Ok::<_, &str>(VerifyOutcome::Ok),
                ),
                (SCARD_S_SUCCESS, None)
            );
            assert!(!pin2_ctx.pin1_authenticated);
            assert!(pin2_ctx.pin2_authenticated);
            assert_eq!(pin2_ctx.pin2_scheme, PinReferenceScheme::Organizational);
        }

        #[test]
        fn verify_outcome_failures_clear_state_and_surface_retries() {
            let retries = PinRetries::from_nibble(TWO_RETRIES).expect("valid retry count");
            let unmodeled_sw = StatusWord::FileNotFound.as_u16();

            for caller in [VerifyCaller::AuthenticatePin, VerifyCaller::AuthenticateEx] {
                let mut wrong_ctx = test_ctx(true, true);
                assert_eq!(
                    map_verify_outcome(
                        &mut wrong_ctx,
                        PinSlot::Pin1,
                        PinReferenceScheme::Citizen,
                        caller,
                        Ok::<_, &str>(VerifyOutcome::WrongPin {
                            retries_left: retries,
                        }),
                    ),
                    (SCARD_W_WRONG_CHV, Some(DWORD::from(TWO_RETRIES)))
                );
                assert!(!wrong_ctx.pin1_authenticated);
                assert!(!wrong_ctx.pin2_authenticated);

                let mut other_ctx = test_ctx(true, true);
                assert_eq!(
                    map_verify_outcome(
                        &mut other_ctx,
                        PinSlot::Pin2,
                        PinReferenceScheme::Citizen,
                        caller,
                        Ok::<_, &str>(VerifyOutcome::Other(unmodeled_sw)),
                    ),
                    (SCARD_W_WRONG_CHV, None)
                );
                assert!(!other_ctx.pin1_authenticated);
                assert!(!other_ctx.pin2_authenticated);

                let mut err_ctx = test_ctx(true, true);
                assert_eq!(
                    map_verify_outcome(
                        &mut err_ctx,
                        PinSlot::Pin1,
                        PinReferenceScheme::Citizen,
                        caller,
                        Err("transport lost"),
                    ),
                    (SCARD_F_INTERNAL_ERROR, None)
                );
                assert!(!err_ctx.pin1_authenticated);
                assert!(!err_ctx.pin2_authenticated);
            }
        }

        #[test]
        fn change_pin_outcome_maps_status_attempts_and_context_state() {
            let retries = PinRetries::from_nibble(TWO_RETRIES).expect("valid retry count");
            let unmodeled_sw = StatusWord::FileNotFound.as_u16();

            let mut ok_ctx = test_ctx(true, true);
            assert_eq!(
                map_change_pin_outcome(&mut ok_ctx, ChangePinOutcome::Ok),
                (SCARD_S_SUCCESS, None)
            );
            assert!(!ok_ctx.pin1_authenticated);
            assert!(!ok_ctx.pin2_authenticated);

            let mut wrong_ctx = test_ctx(true, true);
            assert_eq!(
                map_change_pin_outcome(
                    &mut wrong_ctx,
                    ChangePinOutcome::WrongCurrentPin {
                        retries_left: retries,
                    },
                ),
                (SCARD_W_WRONG_CHV, Some(DWORD::from(TWO_RETRIES)))
            );
            assert!(!wrong_ctx.pin1_authenticated);

            let mut locked_ctx = test_ctx(true, true);
            assert_eq!(
                map_change_pin_outcome(&mut locked_ctx, ChangePinOutcome::Locked),
                (SCARD_W_CHV_BLOCKED, None)
            );
            assert!(!locked_ctx.pin1_authenticated);

            let mut len_ctx = test_ctx(true, false);
            assert_eq!(
                map_change_pin_outcome(&mut len_ctx, ChangePinOutcome::LengthError),
                (SCARD_E_INVALID_PARAMETER, None)
            );
            assert!(len_ctx.pin1_authenticated);

            let mut other_ctx = test_ctx(true, true);
            assert_eq!(
                map_change_pin_outcome(&mut other_ctx, ChangePinOutcome::Other(unmodeled_sw)),
                (SCARD_F_INTERNAL_ERROR, None)
            );
            assert!(!other_ctx.pin1_authenticated);
        }

        #[test]
        fn unblock_outcome_maps_status_and_context_state() {
            let retries = PinRetries::from_nibble(TWO_RETRIES).expect("valid retry count");
            let unmodeled_sw = StatusWord::FileNotFound.as_u16();

            let mut ok_ctx = test_ctx(true, true);
            assert_eq!(
                map_unblock_outcome(&mut ok_ctx, UnblockOutcome::Ok),
                SCARD_S_SUCCESS
            );
            assert!(!ok_ctx.pin1_authenticated);
            assert!(!ok_ctx.pin2_authenticated);

            let mut wrong_ctx = test_ctx(true, true);
            assert_eq!(
                map_unblock_outcome(
                    &mut wrong_ctx,
                    UnblockOutcome::WrongPuk {
                        retries_left: retries,
                    },
                ),
                SCARD_W_WRONG_CHV
            );
            assert!(!wrong_ctx.pin1_authenticated);

            for blocked in [UnblockOutcome::PukLocked, UnblockOutcome::Invalidated] {
                let mut blocked_ctx = test_ctx(true, true);
                assert_eq!(
                    map_unblock_outcome(&mut blocked_ctx, blocked),
                    SCARD_W_CHV_BLOCKED
                );
                assert!(!blocked_ctx.pin1_authenticated);
            }

            let mut len_ctx = test_ctx(true, false);
            assert_eq!(
                map_unblock_outcome(&mut len_ctx, UnblockOutcome::LengthError),
                SCARD_E_INVALID_PARAMETER
            );
            assert!(len_ctx.pin1_authenticated);

            let mut other_ctx = test_ctx(true, false);
            assert_eq!(
                map_unblock_outcome(&mut other_ctx, UnblockOutcome::Other(unmodeled_sw)),
                SCARD_F_INTERNAL_ERROR
            );
            assert!(other_ctx.pin1_authenticated);
        }

        #[test]
        fn write_attempts_remaining_guards_null_and_none() {
            unsafe {
                write_attempts_remaining(core::ptr::null_mut(), Some(DWORD::from(TWO_RETRIES)));
            }

            let mut attempts = UNTOUCHED_ATTEMPTS_SENTINEL;
            unsafe {
                write_attempts_remaining(&raw mut attempts, None);
            }
            assert_eq!(attempts, UNTOUCHED_ATTEMPTS_SENTINEL);

            unsafe {
                write_attempts_remaining(&raw mut attempts, Some(DWORD::from(TWO_RETRIES)));
            }
            assert_eq!(attempts, DWORD::from(TWO_RETRIES));
        }

        #[test]
        fn sync_transport_handle_refreshes_handle_and_clears_pin_state() {
            let mut ctx = test_ctx(true, true);
            let tx = ctx.transport.get_mut().expect("unpoisoned");
            tx.set_plain_h_card(INITIAL_H_CARD);
            assert_eq!(
                sync_transport_handle(
                    tx,
                    &mut ctx.pin1_authenticated,
                    &mut ctx.pin2_authenticated,
                    INVALID_SCARD_HANDLE,
                ),
                Err(SCARD_E_INVALID_HANDLE)
            );
            assert_eq!(tx.h_card(), INITIAL_H_CARD);
            assert!(ctx.pin1_authenticated);
            assert!(ctx.pin2_authenticated);

            let tx = ctx.transport.get_mut().expect("unpoisoned");
            assert_eq!(
                sync_transport_handle(
                    tx,
                    &mut ctx.pin1_authenticated,
                    &mut ctx.pin2_authenticated,
                    INITIAL_H_CARD,
                ),
                Ok(false)
            );
            assert!(ctx.pin1_authenticated);
            assert!(ctx.pin2_authenticated);

            let tx = ctx.transport.get_mut().expect("unpoisoned");
            assert_eq!(
                sync_transport_handle(
                    tx,
                    &mut ctx.pin1_authenticated,
                    &mut ctx.pin2_authenticated,
                    RECONNECTED_H_CARD,
                ),
                Ok(true)
            );
            assert_eq!(tx.h_card(), RECONNECTED_H_CARD);
            assert!(!ctx.pin1_authenticated);
            assert!(!ctx.pin2_authenticated);
        }
    }
}
