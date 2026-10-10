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
    windows,
    expect(
        dead_code,
        reason = "incremental Card Module port -- entry-point users of the data model + scaffolding land in later commits; the unfulfilled expectation will flag this for removal at completion"
    )
)]
#![cfg_attr(
    windows,
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
    windows,
    allow(
        non_snake_case,
        non_camel_case_types,
        non_upper_case_globals,
        reason = "Card Module ABI names stay line-comparable with the Windows SDK"
    )
)]

#[cfg(windows)]
mod cardmod;
#[cfg(windows)]
mod ffi;
#[cfg(windows)]
mod msroots;
#[cfg(windows)]
mod transport;

#[cfg(windows)]
use core::mem::size_of;
#[cfg(windows)]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(windows)]
use std::sync::Mutex;

#[cfg(windows)]
use cardmod::{CardCapabilityModel, CardModel, ContainerDescriptor, Ctx, KeyAlgorithm, Log};
#[cfg(windows)]
#[allow(
    clippy::wildcard_imports,
    reason = "The Card Module implementation mirrors the complete crate-private Windows ABI table"
)]
use ffi::*;
#[cfg(windows)]
use refineid_lib_core::auth::{ChangePinOutcome, PinOps, PinSlot, UnblockOutcome, VerifyOutcome};
#[cfg(windows)]
use refineid_lib_core::crypto::container::{Ciphertext, RsaPkcs1};
#[cfg(windows)]
use refineid_lib_core::crypto::digest::{Sha256, Sha384};
#[cfg(windows)]
use refineid_lib_core::crypto::rsa::HashAlg as PssHashAlg;
#[cfg(windows)]
use refineid_lib_core::identity::{TokenSerial, render_token_serial};
#[cfg(windows)]
use refineid_lib_core::pace::run_pace_with_can;
#[cfg(windows)]
use refineid_lib_core::pin::PinBytes;
#[cfg(windows)]
use refineid_lib_core::pin_cache::{PIN2_CACHE_LIFETIME, PinSafetyCache};
#[cfg(windows)]
use refineid_lib_core::pin_retry_risk::pin1_status_permits_consumer_authentication;
#[cfg(windows)]
use refineid_lib_core::pkcs15::{CertSlot, Pkcs15Ops};
#[cfg(windows)]
use refineid_lib_core::sign::{KeyRef, SignOps, commands::ExternalHashValue};
#[cfg(windows)]
use refineid_lib_core::x509::{EcCurve, OwnedCert, PublicKeyAlgorithm, extract_rsa_public_key};
#[cfg(windows)]
use refineid_rapp_core::operations::{
    CardOperation, CardOperationResult, CertificateKind, KeyProfile, SignatureAlgorithm,
};
#[cfg(windows)]
use refineid_windows_credential_store::{CredentialPairingStore, read_can};
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
fn live_pin1_authentication_is_permitted(tx: &mut CardSessionTransport) -> Result<bool, DWORD> {
    tx.select_pkcs15_application()
        .map_err(|_error| SCARD_F_INTERNAL_ERROR)?;
    let pin1 = tx
        .pin_status(PinSlot::Pin1)
        .map_err(|_error| SCARD_F_INTERNAL_ERROR)?;
    Ok(pin1_status_permits_consumer_authentication(pin1))
}

#[cfg(windows)]
const MAX_ATR_LEN: usize = 33;
#[cfg(windows)]
const PIN_ID_AUTH: DWORD = ROLE_USER;
#[cfg(windows)]
const PIN_ID_PUK: DWORD = ROLE_ADMIN;
#[cfg(windows)]
const PIN_ID_QUALIFIED_SIG: DWORD = 3;
#[cfg(windows)]
const CALG_SHA1: DWORD = 0x0000_8004;
#[cfg(windows)]
const CALG_SHA_224: DWORD = 0x0000_800C;
#[cfg(windows)]
const CALG_SHA_256: DWORD = 0x0000_800C;
#[cfg(windows)]
const CALG_SHA_384: DWORD = 0x0000_800D;
#[cfg(windows)]
const CALG_SHA_512: DWORD = 0x0000_800E;
#[cfg(windows)]
const ENABLE_CNG_KSP_SURFACE: bool = false;

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
    Log::dbg("CardAcquireContext: entry");
    if pCardData.is_null() {
        Log::dbg("CardAcquireContext: null CARD_DATA");
        return SCARD_E_INVALID_PARAMETER;
    }
    let cd = unsafe { &mut *pCardData };

    if cd.dwVersion < CARD_DATA_VERSION_FOUR {
        Log::dbg("CardAcquireContext: unsupported CARD_DATA version");
        return SCARD_E_UNSUPPORTED_FEATURE;
    }

    let max_supported_version = if ENABLE_CNG_KSP_SURFACE {
        CARD_DATA_CURRENT_VERSION
    } else {
        CARD_DATA_VERSION_SIX
    };
    cd.dwVersion = cd.dwVersion.min(max_supported_version);

    if cd.pbAtr.is_null() || cd.cbAtr == 0 || cd.hScard == 0 {
        Log::dbg("CardAcquireContext: invalid ATR or card handle");
        return SCARD_E_INVALID_PARAMETER;
    }
    let atr_len = usize::try_from(cd.cbAtr).unwrap_or(usize::MAX);
    if atr_len > MAX_ATR_LEN {
        Log::dbg("CardAcquireContext: ATR too long");
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
        Log::dbg("CardAcquireContext: remote card detected via ATR");
        let store = match CredentialPairingStore::load() {
            Ok(s) => s,
            Err(e) => {
                Log::dbg(&format!(
                    "CardAcquireContext: failed to load CredentialPairingStore: {e:?}"
                ));
                return SCARD_F_INTERNAL_ERROR;
            }
        };
        let Some(pairing) = store.usable_pairing() else {
            Log::dbg("CardAcquireContext: no usable pairing found for remote card");
            return SCARD_E_UNKNOWN_CARD;
        };
        let (auth_der, sig_der) = if let Some(auth_der) = pairing.auth_cert.clone() {
            let sig_der = pairing
                .signature_cert
                .clone()
                .unwrap_or_else(|| auth_der.clone());
            (auth_der, sig_der)
        } else {
            let remote_tx = RemoteCardTransport::new(atr.clone(), pairing.pair_id, pairing.clone());
            let cert_res = match remote_tx.execute_operation(&CardOperation::ReadCertificate {
                kind: CertificateKind::Authentication,
            }) {
                Ok(r) => r,
                Err(e) => {
                    Log::dbg(&format!(
                        "CardAcquireContext: remote read_certificate failed: {e}"
                    ));
                    return SCARD_F_INTERNAL_ERROR;
                }
            };
            let CardOperationResult::Certificate(der) = cert_res else {
                return SCARD_F_INTERNAL_ERROR;
            };
            (der.clone(), der)
        };

        // Cache root/intermediate CA certificates from pairing record if present
        if let (Some(root), inter) = (&pairing.root_ca, &pairing.intermediate_ca) {
            let roots = refineid_lib_core::trust_roots::RootCertificates::new(
                Some(root.clone()),
                inter.clone(),
            );
            let bundle = roots.to_pkcs7_bundle();
            msroots::set_root_certificates(bundle);
            let _ = refineid_lib_core::trust_roots::set_root_certificates(roots);
        }

        let remote_tx = RemoteCardTransport::new(atr, pairing.pair_id, pairing.clone());
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
                cert.into_bytes(),
            ),
            Err(_plain_error) => {
                let can = match read_can(&raw_transport.atr) {
                    Ok(Some(can)) => can,
                    Ok(None) => {
                        Log::dbg(
                            "CardAcquireContext: authentication cert is sealed and NFC is not primed",
                        );
                        return SCARD_F_INTERNAL_ERROR;
                    }
                    Err(_error) => {
                        Log::dbg("CardAcquireContext: Windows NFC credential lookup failed");
                        return SCARD_F_INTERNAL_ERROR;
                    }
                };
                let _master_file_selection = raw_transport.select_mf();
                let pace_session = match run_pace_with_can(&mut raw_transport, can) {
                    Ok(session) => session,
                    Err(_error) => {
                        Log::dbg("CardAcquireContext: contactless PACE failed");
                        return SCARD_F_INTERNAL_ERROR;
                    }
                };
                let mut protected = CardSessionTransport::protected(raw_transport, pace_session);
                let cert = match protected.read_certificate(CertSlot::Authentication) {
                    Ok(cert) => cert.into_bytes(),
                    Err(_error) => {
                        Log::dbg("CardAcquireContext: protected authentication cert read failed");
                        return SCARD_F_INTERNAL_ERROR;
                    }
                };
                (protected, cert)
            }
        };
        let signature_cert_der = match transport.read_certificate(CertSlot::Signature) {
            Ok(cert) => cert.into_bytes(),
            Err(_err) => {
                Log::dbg("CardAcquireContext: failed to read qualified-signature cert");
                return SCARD_F_INTERNAL_ERROR;
            }
        };
        if let Some(roots) =
            refineid_lib_core::trust_roots::fetch_and_cache_from_card(&mut transport)
        {
            let bundle = roots.to_pkcs7_bundle();
            msroots::set_root_certificates(bundle);
        }
        (transport, auth_cert_der, signature_cert_der)
    };

    let Some(card) = CardModel::build_card_model(cd, auth_cert_der, signature_cert_der) else {
        Log::dbg("CardAcquireContext: failed to build card model");
        return SCARD_F_INTERNAL_ERROR;
    };

    let ctx = Box::new(Ctx {
        transport: Mutex::new(transport),
        card,
        pin1_authenticated: false,
        pin2_authenticated: false,
    });
    cd.pvVendorSpecific = Box::into_raw(ctx).cast();

    cd.pfnCardDeleteContext = Some(CardDeleteContext);
    cd.pfnCardQueryCapabilities = Some(CardQueryCapabilities);
    cd.pfnCardDeleteContainer = Some(unsupported_delete_container);
    cd.pfnCardCreateContainer = Some(unsupported_create_container);
    cd.pfnCardGetContainerInfo = Some(CardGetContainerInfo);
    cd.pfnCardAuthenticatePin = Some(CardAuthenticatePin);
    cd.pfnCardGetChallenge = Some(unsupported_get_challenge);
    cd.pfnCardAuthenticateChallenge = Some(unsupported_authenticate_challenge);
    cd.pfnCardUnblockPin = Some(CardUnblockPin);
    cd.pfnCardChangeAuthenticator = Some(CardChangeAuthenticator);
    cd.pfnCardDeauthenticate = Some(CardDeauthenticate);
    cd.pfnCardCreateDirectory = Some(unsupported_create_directory);
    cd.pfnCardDeleteDirectory = Some(unsupported_delete_directory);
    cd.pvUnused3 = core::ptr::null_mut();
    cd.pvUnused4 = core::ptr::null_mut();
    cd.pfnCardCreateFile = Some(unsupported_create_file);
    cd.pfnCardReadFile = Some(CardReadFile);
    cd.pfnCardWriteFile = Some(unsupported_write_file);
    cd.pfnCardDeleteFile = Some(unsupported_delete_file);
    cd.pfnCardEnumFiles = Some(CardEnumFiles);
    cd.pfnCardGetFileInfo = Some(CardGetFileInfo);
    cd.pfnCardQueryFreeSpace = Some(CardQueryFreeSpace);
    cd.pfnCardQueryKeySizes = Some(CardQueryKeySizes);
    cd.pfnCardSignData = Some(CardSignData);
    cd.pfnCardRSADecrypt = Some(CardRSADecrypt);
    cd.pfnCardConstructDHAgreement = None;

    if cd.dwVersion >= CARD_DATA_VERSION_FIVE {
        cd.pfnCardDeriveKey = None;
        cd.pfnCardDestroyDHAgreement = None;
        cd.pfnCspGetDHAgreement = None;
    }
    if cd.dwVersion >= CARD_DATA_VERSION_SIX {
        cd.pfnCardGetChallengeEx = Some(unsupported_get_challenge_ex);
        cd.pfnCardAuthenticateEx = Some(CardAuthenticateEx);
        cd.pfnCardChangeAuthenticatorEx = Some(CardChangeAuthenticatorEx);
        cd.pfnCardDeauthenticateEx = Some(CardDeauthenticateEx);
        cd.pfnCardGetContainerProperty = Some(CardGetContainerProperty);
        cd.pfnCardSetContainerProperty = Some(unsupported_set_container_property);
        cd.pfnCardGetProperty = Some(CardGetProperty);
        cd.pfnCardSetProperty = Some(unsupported_set_property);
    }
    if ENABLE_CNG_KSP_SURFACE && cd.dwVersion >= CARD_DATA_VERSION_SEVEN {
        cd.pfnCspUnpadData = None;
        cd.pfnMDImportSessionKey = Some(unsupported_md_import_session_key);
        cd.pfnMDEncryptData = Some(unsupported_md_encrypt_data);
        cd.pfnCardImportSessionKey = Some(unsupported_card_import_session_key);
        cd.pfnCardGetSharedKeyHandle = Some(unsupported_get_shared_key_handle);
        cd.pfnCardGetAlgorithmProperty = Some(unsupported_get_algorithm_property);
        cd.pfnCardGetKeyProperty = Some(unsupported_get_key_property);
        cd.pfnCardSetKeyProperty = Some(unsupported_set_key_property);
        cd.pfnCardDestroyKey = Some(unsupported_destroy_key);
        cd.pfnCardProcessEncryptedData = Some(unsupported_process_encrypted_data);
        cd.pfnCardCreateContainerEx = Some(unsupported_create_container_ex);
    }

    Log::dbg("CardAcquireContext: success");
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

/// Advance the synthetic cardcf freshness counter so the Base CSP /
/// KSP data cache (including any cached PIN state keyed on cardcf)
/// is treated as stale and discarded.
#[cfg(windows)]
fn bump_cardcf() {
    let mut current = CARDCF_VALUE.load(Ordering::Relaxed);
    if current == 0 {
        current = cardcf_initial_value();
    }
    let next = (current.wrapping_add(1)) & 0x0000_00FF_FFFF_FFFF;
    CARDCF_VALUE.store(next.max(1), Ordering::Relaxed);
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

#[cfg(windows)]
fn cstr_eq(p: LPSTR, s: &str) -> bool {
    if p.is_null() {
        return false;
    }
    let len = s.len();
    let bytes = unsafe { core::slice::from_raw_parts(p.cast::<u8>(), len + 1) };
    bytes[len] == 0 && &bytes[..len] == s.as_bytes()
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
    live_h_card: usize,
    site: &str,
) -> Result<bool, DWORD> {
    if tx.is_remote() {
        return Ok(false);
    }
    if tx.h_card() == live_h_card {
        return Ok(false);
    }

    Log::dbg(&format!(
        "{site}: transport hScard refresh {:#x} -> {:#x}",
        tx.h_card(),
        live_h_card
    ));
    tx.raw_mut().h_card = live_h_card;
    *pin1_authenticated = false;
    *pin2_authenticated = false;

    if tx.is_protected() {
        let can = match read_can(tx.atr_bytes()) {
            Ok(Some(can)) => can,
            Ok(None) => {
                Log::dbg(&format!("{site}: NFC credential is no longer configured"));
                return Err(SCARD_F_INTERNAL_ERROR);
            }
            Err(_error) => {
                Log::dbg(&format!("{site}: NFC credential lookup failed"));
                return Err(SCARD_F_INTERNAL_ERROR);
            }
        };
        let raw = tx.raw_mut();
        let _master_file_selection = raw.select_mf();
        let session = run_pace_with_can(raw, can).map_err(|_error| {
            Log::dbg(&format!("{site}: PACE re-establishment failed"));
            SCARD_F_INTERNAL_ERROR
        })?;
        tx.replace_pace_session(session);
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
    let serial = match live_token_serial(tx) {
        Ok(serial) => serial,
        Err(error) => {
            clear_pin_state(pin1_authenticated, pin2_authenticated);
            return Some(error);
        }
    };
    if !matches!(live_pin1_authentication_is_permitted(tx), Ok(true)) {
        clear_pin_state(pin1_authenticated, pin2_authenticated);
        Log::dbg("reverify_cached_pin: PIN1 retry floor is below three or unreadable");
        return Some(SCARD_W_WRONG_CHV);
    }
    let slot = PinSlot::Pin1;
    let checkout = with_pin_safety(|cache| cache.checkout_pin1(&serial))
        .ok()
        .flatten();
    let Some(checkout) = checkout else {
        Log::dbg("reverify_cached_pin: no card-bound PIN1 available");
        return Some(SCARD_W_WRONG_CHV);
    };
    let pin = checkout.pin().clone();
    let is_rejected =
        with_pin_safety(|cache| cache.is_rejected(&serial, slot, &pin)).unwrap_or(false);
    if is_rejected {
        clear_pin_state(pin1_authenticated, pin2_authenticated);
        Log::dbg("reverify_cached_pin: PIN was previously rejected by the card");
        return Some(SCARD_W_WRONG_CHV);
    }
    let outcome = tx.verify_pin1(pin.clone());
    match outcome {
        Ok(VerifyOutcome::Ok) => {
            let _ = with_pin_safety(|cache| checkout.restore_after_success(cache));
            *pin1_authenticated = true;
            Log::dbg("reverify_cached_pin: verified cached PIN1 on card -> OK");
            None
        }
        Ok(VerifyOutcome::WrongPin { .. }) => {
            let _ = with_pin_safety(|cache| cache.record_rejected(&serial, slot, &pin));
            clear_pin_state(pin1_authenticated, pin2_authenticated);
            Log::dbg("reverify_cached_pin: card rejected PIN; remembered for process lifetime");
            Some(SCARD_W_WRONG_CHV)
        }
        Ok(other) => {
            clear_pin_state(pin1_authenticated, pin2_authenticated);
            Log::dbg(&format!("reverify_cached_pin: verify failed ({other:?})"));
            Some(SCARD_W_WRONG_CHV)
        }
        Err(err) => {
            clear_pin_state(pin1_authenticated, pin2_authenticated);
            Log::dbg(&format!("reverify_cached_pin: transport error ({err:?})"));
            Some(SCARD_F_INTERNAL_ERROR)
        }
    }
}

#[cfg(windows)]
unsafe fn read_wstr(p: LPCWSTR) -> String {
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
fn create_pin_set(pin_id: DWORD) -> DWORD {
    1_u32 << pin_id
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

#[cfg(windows)]
fn pin_cache_policy(pin_id: DWORD) -> DWORD {
    match pin_id {
        PIN_ID_AUTH => PIN_CACHE_NORMAL,
        PIN_ID_QUALIFIED_SIG => PIN_CACHE_TIMED,
        _ => PIN_CACHE_NONE,
    }
}

#[cfg(windows)]
fn pin_cache_policy_info(pin_id: DWORD) -> DWORD {
    /// Microsoft defines `dwPinCachePolicyInfo` in seconds for
    /// `PIN_CACHE_TIMED`.
    const PIN2_CACHE_TIMEOUT_SECONDS: DWORD = cache_timeout_seconds(PIN2_CACHE_LIFETIME);
    match pin_id {
        PIN_ID_QUALIFIED_SIG => PIN2_CACHE_TIMEOUT_SECONDS,
        _ => 0,
    }
}

/// Converts a shared policy lifetime to the whole seconds Windows wants.
///
/// The assertion runs at compile time, so a future lifetime too large for
/// the field fails the build instead of silently wrapping into a much
/// shorter cache window than the policy intends.
#[cfg(windows)]
const fn cache_timeout_seconds(lifetime: core::time::Duration) -> DWORD {
    let seconds = lifetime.as_secs();
    assert!(
        seconds <= DWORD::MAX as u64,
        "a PIN cache lifetime must fit the Windows dwPinCachePolicyInfo field"
    );
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the assertion above rejects any value that would truncate"
    )]
    let seconds = seconds as DWORD;
    seconds
}

#[cfg(windows)]
fn authenticated_pin_set(ctx: &Ctx) -> DWORD {
    let mut pin_set = PIN_SET_NONE;
    let has_pin1 = ctx.pin1_authenticated
        || with_pin_safety(PinSafetyCache::has_positive_pin1).unwrap_or(false);
    if has_pin1 {
        pin_set |= create_pin_set(PIN_ID_AUTH);
    }
    let has_pin2 = ctx.pin2_authenticated
        || with_pin_safety(PinSafetyCache::has_positive_pin2).unwrap_or(false);
    if has_pin2 {
        pin_set |= create_pin_set(PIN_ID_QUALIFIED_SIG);
    }
    pin_set
}

#[cfg(windows)]
fn pin_len_bounds(pin_id: DWORD) -> Option<(usize, usize)> {
    match pin_id {
        PIN_ID_AUTH => Some((4, 12)),
        PIN_ID_QUALIFIED_SIG => Some((6, 12)),
        PIN_ID_PUK => Some((7, 8)),
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

#[cfg(windows)]
fn clear_cached_pin(ctx: &mut Ctx, _pin_id: DWORD) {
    clear_pin_state(&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);
}

#[cfg(windows)]
fn clear_pin_state(pin1_authenticated: &mut bool, pin2_authenticated: &mut bool) {
    let _ = with_pin_safety(|cache| {
        cache.clear_positive();
    });
    *pin1_authenticated = false;
    *pin2_authenticated = false;
}

#[cfg(windows)]
fn map_change_pin_outcome(
    ctx: &mut Ctx,
    pin_id: DWORD,
    outcome: ChangePinOutcome,
    pcAttemptsRemaining: PDWORD,
) -> DWORD {
    match outcome {
        ChangePinOutcome::Ok => {
            clear_cached_pin(ctx, pin_id);
            SCARD_S_SUCCESS
        }
        ChangePinOutcome::WrongCurrentPin { retries_left } => {
            clear_cached_pin(ctx, pin_id);
            if !pcAttemptsRemaining.is_null() {
                unsafe {
                    *pcAttemptsRemaining = DWORD::from(retries_left.get());
                }
            }
            SCARD_W_WRONG_CHV
        }
        ChangePinOutcome::Locked => {
            clear_cached_pin(ctx, pin_id);
            SCARD_W_CHV_BLOCKED
        }
        ChangePinOutcome::LengthError => SCARD_E_INVALID_PARAMETER,
        ChangePinOutcome::Other(_sw) => {
            clear_cached_pin(ctx, pin_id);
            SCARD_F_INTERNAL_ERROR
        }
    }
}

#[cfg(windows)]
fn map_unblock_outcome(ctx: &mut Ctx, pin_id: DWORD, outcome: UnblockOutcome) -> DWORD {
    match outcome {
        UnblockOutcome::Ok => {
            clear_cached_pin(ctx, pin_id);
            SCARD_S_SUCCESS
        }
        UnblockOutcome::WrongPuk { .. } => {
            clear_cached_pin(ctx, pin_id);
            SCARD_W_WRONG_CHV
        }
        UnblockOutcome::PukLocked | UnblockOutcome::Invalidated => {
            clear_cached_pin(ctx, pin_id);
            SCARD_W_CHV_BLOCKED
        }
        UnblockOutcome::LengthError => SCARD_E_INVALID_PARAMETER,
        UnblockOutcome::Other(_sw) => SCARD_F_INTERNAL_ERROR,
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
    let mut seeded = Vec::with_capacity(64 + auth_cert.len());
    seeded.extend_from_slice(b"refineid-card-id-v8-two-container-freshness");
    seeded.extend_from_slice(auth_cert);
    let h = Sha256::of(seeded);
    h.as_bytes()[..16].to_vec()
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
        PublicKeyAlgorithm::Ec(EcCurve::Secp256r1 | EcCurve::BrainpoolP256r1)
        | PublicKeyAlgorithm::EcExplicit { bits: 256 } => 32,
        PublicKeyAlgorithm::Ec(EcCurve::Secp384r1 | EcCurve::BrainpoolP384r1)
        | PublicKeyAlgorithm::EcExplicit { bits: 384 } => 48,
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

    let file = read_cstr(pszFileName);
    Log::dbg(&format!(
        "CardReadFile dir={} file={file}",
        if pszDirectoryName.is_null() {
            String::from("<root>")
        } else {
            read_cstr(pszDirectoryName)
        }
    ));
    let data = if pszDirectoryName.is_null() {
        if cstr_eq(pszFileName, "cardcf") {
            synth_cardcf()
        } else if cstr_eq(pszFileName, "cardid") {
            synth_cardid(ctx.card.auth_cert_der().unwrap_or(&[]))
        } else if cstr_eq(pszFileName, "cardapps") {
            synth_cardapps()
        } else {
            return SCARD_E_FILE_NOT_FOUND;
        }
    } else if cstr_eq(pszDirectoryName, "mscp") {
        if cstr_eq(pszFileName, "cmapfile") {
            synth_cmapfile(&ctx.card)
        } else if cstr_eq(pszFileName, "msroots") {
            msroots::active_msroots_pkcs7_der().to_vec()
        } else if let Some(bytes) = container_file_bytes(&ctx.card, &file) {
            bytes
        } else if cstr_eq(pszFileName, "cardcf") {
            synth_cardcf()
        } else {
            return SCARD_E_FILE_NOT_FOUND;
        }
    } else {
        return SCARD_E_DIR_NOT_FOUND;
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

    let names = if pszDirectoryName.is_null() {
        let mut v = Vec::new();
        v.extend_from_slice(b"cardcf\0");
        v.extend_from_slice(b"cardid\0");
        v.extend_from_slice(b"cardapps\0");
        v.push(0);
        v
    } else if cstr_eq(pszDirectoryName, "mscp") {
        let mut v = Vec::new();
        v.extend_from_slice(b"cmapfile\0");
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
        v.extend_from_slice(b"msroots\0");
        v.push(0);
        v
    } else {
        return SCARD_E_DIR_NOT_FOUND;
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
    let file = read_cstr(pszFileName);

    let size = if pszDirectoryName.is_null() {
        if cstr_eq(pszFileName, "cardcf") {
            6
        } else if cstr_eq(pszFileName, "cardid") {
            16
        } else if cstr_eq(pszFileName, "cardapps") {
            8
        } else {
            return SCARD_E_FILE_NOT_FOUND;
        }
    } else if cstr_eq(pszDirectoryName, "mscp") {
        if cstr_eq(pszFileName, "cmapfile") {
            synth_cmapfile(&ctx.card).len()
        } else if cstr_eq(pszFileName, "msroots") {
            msroots::active_msroots_pkcs7_der().len()
        } else if let Some(bytes) = container_file_bytes(&ctx.card, &file) {
            bytes.len()
        } else {
            return SCARD_E_FILE_NOT_FOUND;
        }
    } else {
        return SCARD_E_DIR_NOT_FOUND;
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
    Log::dbg(&format!("CardGetContainerInfo idx={bContainerIndex}"));
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
        Log::dbg("CardGetContainerInfo -> INTERNAL (blob build failed)");
        return SCARD_F_INTERNAL_ERROR;
    };
    Log::dbg(&format!(
        "CardGetContainerInfo -> OK cbSig={} cbKeyEx={}",
        info.cbSigPublicKey, info.cbKeyExPublicKey
    ));
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
    Log::dbg("CardAuthenticatePin: entry");
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

    let mut tx = lock_transport(&ctx.transport);
    if let Err(error) = sync_transport_handle(
        &mut tx,
        &mut ctx.pin1_authenticated,
        &mut ctx.pin2_authenticated,
        cd.hScard,
        "CardAuthenticatePin",
    ) {
        return error;
    }
    // Any new explicit PIN operation invalidates previous positive state.
    clear_pin_state(&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);
    let serial = match live_token_serial(&mut tx) {
        Ok(serial) => serial,
        Err(error) => return error,
    };
    let pin1_cache_allowed =
        slot != PinSlot::Pin1 || matches!(live_pin1_authentication_is_permitted(&mut tx), Ok(true));
    let is_rejected =
        with_pin_safety(|cache| cache.is_rejected(&serial, slot, &pin)).unwrap_or(false);
    if is_rejected {
        return SCARD_W_WRONG_CHV;
    }
    let outcome = if slot == PinSlot::Pin1 {
        tx.verify_pin1(pin.clone())
    } else {
        tx.verify_pin(slot, pin.clone())
    };
    drop(tx);
    match outcome {
        Ok(VerifyOutcome::Ok) => {
            if slot == PinSlot::Pin1 {
                ctx.pin1_authenticated = true;
                if pin1_cache_allowed {
                    let _ = with_pin_safety(|cache| cache.store_pin1(serial, pin));
                }
            } else {
                ctx.pin2_authenticated = true;
                let _ = with_pin_safety(|cache| cache.store_pin2(serial, pin));
            }
            SCARD_S_SUCCESS
        }
        Ok(VerifyOutcome::WrongPin { retries_left }) => {
            let _ = with_pin_safety(|cache| cache.record_rejected(&serial, slot, &pin));
            clear_cached_pin(ctx, pin_id);
            if !pcAttemptsRemaining.is_null() {
                unsafe {
                    *pcAttemptsRemaining = DWORD::from(retries_left.get());
                }
            }
            SCARD_W_WRONG_CHV
        }
        Ok(VerifyOutcome::Locked) => {
            clear_cached_pin(ctx, pin_id);
            if !pcAttemptsRemaining.is_null() {
                unsafe {
                    *pcAttemptsRemaining = 0;
                }
            }
            SCARD_W_CHV_BLOCKED
        }
        Ok(VerifyOutcome::Other(_sw)) => {
            clear_cached_pin(ctx, pin_id);
            SCARD_W_WRONG_CHV
        }
        Err(_err) => {
            clear_cached_pin(ctx, pin_id);
            SCARD_F_INTERNAL_ERROR
        }
    }
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
    let (cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    let info = unsafe { &mut *pInfo };
    let Some(container) = ctx.card.visible_container(info.bContainerIndex).cloned() else {
        return SCARD_E_NO_KEY_CONTAINER;
    };

    {
        let (pin1, pin2) = (&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);
        let mut tx = lock_transport(&ctx.transport);
        let _ = sync_transport_handle(&mut tx, pin1, pin2, cd.hScard, "CardSignData");
    }

    Log::dbg(&format!(
        "CardSignData idx={} dwKeySpec={} cbData={} dwPaddingType={} aiHashAlg={:#x} pin1={} pin2={}",
        info.bContainerIndex,
        info.dwKeySpec,
        info.cbData,
        info.dwPaddingType,
        info.aiHashAlg,
        ctx.pin1_authenticated,
        ctx.pin2_authenticated,
    ));

    let authenticated = if ctx.transport.lock().is_ok_and(|tx| tx.is_remote()) {
        true
    } else if container.pin_id == PIN_ID_QUALIFIED_SIG {
        ctx.pin2_authenticated
    } else {
        ctx.pin1_authenticated
            || with_pin_safety(PinSafetyCache::has_positive_pin1).unwrap_or(false)
    };
    if !authenticated {
        Log::dbg("CardSignData -> WRONG_CHV (not authenticated)");
        return SCARD_W_WRONG_CHV;
    }

    if info.dwSigningFlags & CARD_BUFFER_SIZE_ONLY != 0 {
        info.pbSignedData = core::ptr::null_mut();
        info.cbSignedData = match try_dword_len(container.key_alg.signature_len()) {
            Some(len) => len,
            None => return SCARD_F_INTERNAL_ERROR,
        };
        return SCARD_S_SUCCESS;
    }
    if info.pbData.is_null() || info.cbData == 0 {
        return SCARD_E_INVALID_PARAMETER;
    }
    let in_bytes = unsafe { core::slice::from_raw_parts(info.pbData, info.cbData as usize) };

    let remote_arm = {
        let tx = lock_transport(&ctx.transport);
        if tx.is_remote() {
            tx.remote_ref()
                .map(|r| (r.pair_id, r.pairing_record.clone(), r.atr.clone()))
        } else {
            None
        }
    };

    if let Some((pair_id, pairing_record, atr)) = remote_arm {
        let (key_profile, algorithm) = match (&container.key_alg, info.dwPaddingType) {
            (KeyAlgorithm::Rsa { bits }, CARD_PADDING_PSS) => {
                let kp = if *bits <= 2048 {
                    KeyProfile::Rsa2048
                } else {
                    KeyProfile::Rsa3072
                };
                (kp, SignatureAlgorithm::RsaPssSha256)
            }
            (KeyAlgorithm::Rsa { bits }, _) => {
                let kp = if *bits <= 2048 {
                    KeyProfile::Rsa2048
                } else {
                    KeyProfile::Rsa3072
                };
                let algo = match in_bytes.len() {
                    48 => SignatureAlgorithm::RsaPkcs1Sha384,
                    64 => SignatureAlgorithm::RsaPkcs1Sha512,
                    _ => SignatureAlgorithm::RsaPkcs1Sha256,
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

        let digest = in_bytes.to_vec();
        let operation = if container.pin_id == PIN_ID_QUALIFIED_SIG {
            CardOperation::SignDocument {
                document_name: "Document".to_owned(),
                key_profile,
                algorithm,
                digest,
            }
        } else {
            let origin = std::env::var("REFINEID_RP_ORIGIN")
                .ok()
                .or_else(|| std::env::var("REFINEID_ORIGIN").ok())
                .filter(|s| !s.trim().is_empty() && s.len() <= 512)
                .unwrap_or_else(|| "https://card.refineid.fi".to_owned());
            CardOperation::BrowserAuthenticate {
                origin,
                key_profile,
                algorithm,
                digest,
            }
        };

        let remote_tx = RemoteCardTransport::new(atr, pair_id, pairing_record);
        let result = match remote_tx.execute_operation(&operation) {
            Ok(r) => r,
            Err(err) => {
                Log::dbg(&format!("CardSignData: remote operation failed: {err}"));
                return SCARD_F_INTERNAL_ERROR;
            }
        };

        let CardOperationResult::Signature(mut sig_bytes) = result else {
            Log::dbg("CardSignData: remote operation did not return signature");
            return SCARD_F_INTERNAL_ERROR;
        };

        if matches!(container.key_alg, KeyAlgorithm::Rsa { .. }) {
            sig_bytes.reverse();
        } else if let KeyAlgorithm::Ec(curve) = &container.key_alg {
            let field_bytes = curve.bits() / 8;
            let Some(p1363) = cardmod::remote_ecdsa_to_p1363(&sig_bytes, field_bytes) else {
                Log::dbg(&format!(
                    "CardSignData: unexpected remote ECDSA signature length: {} (expected {})",
                    sig_bytes.len(),
                    field_bytes * 2
                ));
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
        info.pbSignedData = p;
        info.cbSignedData = needed;
        return SCARD_S_SUCCESS;
    }

    let key_ref = if container.pin_id == PIN_ID_QUALIFIED_SIG {
        KeyRef::Sign
    } else {
        KeyRef::Auth
    };

    // RSA-PSS path: TLS 1.3 CertificateVerify (Firefox osclientcerts,
    // CNG KSP callers) requires RSASSA-PSS. FINEID S1 v4.2 Table 6
    // defines a native RSA-PSS algorithm reference, so send the digest
    // through PSO:HASH and let the card perform PSS internally.
    if info.dwPaddingType == CARD_PADDING_PSS {
        if !container.allow_pss || !matches!(container.key_alg, KeyAlgorithm::Rsa { .. }) {
            return SCARD_E_UNSUPPORTED_FEATURE;
        }
        if info.pPaddingInfo.is_null() {
            return SCARD_E_INVALID_PARAMETER;
        }
        let pad = unsafe { &*info.pPaddingInfo.cast::<BCRYPT_PSS_PADDING_INFO>() };
        let hash_name = if pad.pszAlgId.is_null() {
            String::from("SHA256")
        } else {
            unsafe { read_wstr(pad.pszAlgId) }.to_uppercase()
        };
        let Ok(hash_alg) = PssHashAlg::try_from(hash_name.as_str()) else {
            return SCARD_E_INVALID_PARAMETER;
        };
        let digest_len = match hash_alg {
            PssHashAlg::Sha1 => 20,
            PssHashAlg::Sha256 => 32,
            PssHashAlg::Sha384 => 48,
            PssHashAlg::Sha512 => 64,
        };
        if pad.cbSalt as usize != digest_len {
            return SCARD_E_INVALID_PARAMETER;
        }
        let hash = match hash_alg {
            PssHashAlg::Sha1 => ExternalHashValue::Sha1(match in_bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => return SCARD_E_INVALID_PARAMETER,
            }),
            PssHashAlg::Sha256 => ExternalHashValue::Sha256(match in_bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => return SCARD_E_INVALID_PARAMETER,
            }),
            PssHashAlg::Sha384 => ExternalHashValue::Sha384(match in_bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => return SCARD_E_INVALID_PARAMETER,
            }),
            PssHashAlg::Sha512 => ExternalHashValue::Sha512(match in_bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => return SCARD_E_INVALID_PARAMETER,
            }),
        };
        let mut tx = lock_transport(&ctx.transport);
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
        Log::dbg(&format!(
            "CardSignData PSS native: protocol={:?} digest_len={}",
            tx.protocol(),
            in_bytes.len()
        ));
        let sig = tx.sign_pre_hashed_rsa_pss(key_ref, hash);
        drop(tx);
        let sig = match sig {
            Ok(sig) => sig,
            Err(err) => {
                Log::dbg(&format!("CardSignData PSS -> INTERNAL ({err:?})"));
                clear_cached_pin(ctx, container.pin_id);
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
        info.pbSignedData = p;
        info.cbSignedData = sig_len;
        if container.pin_id == PIN_ID_QUALIFIED_SIG {
            clear_cached_pin(ctx, container.pin_id);
        }
        return SCARD_S_SUCCESS;
    }

    let Some(hash) = external_hash_from_alg_and_bytes(info.aiHashAlg, in_bytes) else {
        return SCARD_E_INVALID_PARAMETER;
    };

    let mut tx = lock_transport(&ctx.transport);
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
        clear_cached_pin(ctx, container.pin_id);
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
    info.pbSignedData = p;
    info.cbSignedData = needed;
    if container.pin_id == PIN_ID_QUALIFIED_SIG {
        clear_cached_pin(ctx, container.pin_id);
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
    let (_cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
        Ok(values) => values,
        Err(rc) => return rc,
    };
    if ctx.transport.lock().is_ok_and(|tx| tx.is_remote()) {
        return SCARD_E_UNSUPPORTED_FEATURE;
    }
    let info = unsafe { &mut *pInfo.cast::<CARD_RSA_DECRYPT_INFO>() };
    let Some(container) = ctx.card.visible_container(info.bContainerIndex).cloned() else {
        return SCARD_E_NO_KEY_CONTAINER;
    };
    if !container.allow_decrypt {
        return SCARD_E_UNSUPPORTED_FEATURE;
    }
    if info.pbData.is_null() || info.cbData == 0 {
        return SCARD_E_INVALID_PARAMETER;
    }
    if info.dwPaddingType != CARD_PADDING_NONE && info.dwPaddingType != CARD_PADDING_PKCS1 {
        return SCARD_E_UNSUPPORTED_FEATURE;
    }

    let ciphertext =
        unsafe { core::slice::from_raw_parts(info.pbData, info.cbData as usize) }.to_vec();
    let mut tx = lock_transport(&ctx.transport);
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
        clear_cached_pin(ctx, PIN_ID_AUTH);
        return SCARD_F_INTERNAL_ERROR;
    };
    let plaintext_bytes = plaintext.as_bytes();
    if plaintext_bytes.len() > info.cbData as usize {
        return SCARD_E_INSUFFICIENT_BUFFER;
    }

    let pad_len = (info.cbData as usize).saturating_sub(plaintext_bytes.len());
    unsafe {
        for i in 0..pad_len {
            *info.pbData.add(i) = 0;
        }
        core::ptr::copy_nonoverlapping(
            plaintext_bytes.as_ptr(),
            info.pbData.add(pad_len),
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
    Log::dbg(&format!(
        "CardGetProperty '{}' cbData={cbData} dwFlags={dwFlags}",
        unsafe { read_wstr(wszProperty) }
    ));
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
                dwPinCachePolicyInfo: pin_cache_policy_info(dwFlags),
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
        return unsafe {
            write_dword_out(pbData, cbData, pdwDataLen, CARD_CACHE_MODE_GLOBAL_CACHE)
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
    let (_cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
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

    let mut tx = lock_transport(&ctx.transport);
    if let Err(error) = live_token_serial(&mut tx) {
        return error;
    }
    let outcome = match target_slot {
        PinSlot::Pin1 => tx.unblock_pin1(puk, new_pin),
        PinSlot::Pin2 => tx.reset_retry_counter(PinSlot::Pin2, puk, new_pin),
    };
    drop(tx);
    match outcome {
        Ok(o) => map_unblock_outcome(ctx, target_pin_id, o),
        Err(_e) => SCARD_F_INTERNAL_ERROR,
    }
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
    let (_cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
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
    let mut tx = lock_transport(&ctx.transport);
    let serial = match live_token_serial(&mut tx) {
        Ok(serial) => serial,
        Err(error) => return error,
    };
    let is_rejected = with_pin_safety(|cache| {
        cache.is_rejected(&serial, slot, &current_pin) || cache.is_rejected(&serial, slot, &new_pin)
    })
    .unwrap_or(false);
    if is_rejected {
        return SCARD_W_WRONG_CHV;
    }

    let outcome = match slot {
        PinSlot::Pin1 => tx.change_pin1(current_pin.clone(), new_pin),
        PinSlot::Pin2 => tx.change_pin(PinSlot::Pin2, current_pin.clone(), new_pin),
    };
    drop(tx);
    match outcome {
        Ok(o) => {
            if matches!(o, ChangePinOutcome::WrongCurrentPin { .. }) {
                let _ = with_pin_safety(|cache| {
                    cache.record_rejected(&serial, slot, &current_pin);
                });
            }
            map_change_pin_outcome(ctx, pin_id, o, pcAttemptsRemaining)
        }
        Err(_e) => SCARD_F_INTERNAL_ERROR,
    }
}

#[cfg(windows)]
#[expect(clippy::too_many_lines, reason = "Minidriver API implementation")]
unsafe extern "system" fn CardAuthenticateEx(
    pCardData: *mut CARD_DATA,
    PinId: DWORD,
    dwFlags: DWORD,
    pbPinData: PBYTE,
    cbPinData: DWORD,
    ppbSessionPin: *mut PBYTE,
    pcbSessionPin: PDWORD,
    pcAttemptsRemaining: PDWORD,
) -> DWORD {
    Log::dbg(&format!(
        "CardAuthenticateEx PinId={PinId} dwFlags={dwFlags:#x} cbPinData={cbPinData}"
    ));
    // The Base CSP probes session-PIN support. We do not implement
    // session PINs: initialise the out parameters (the caller reads
    // them after return -- leaving them dangling makes the KSP fail
    // its internal consistency check, NTE_INTERNAL_ERROR) and treat
    // the request as a plain PIN verification (legacy parity).
    if !ppbSessionPin.is_null() {
        unsafe {
            *ppbSessionPin = core::ptr::null_mut();
        }
    }
    if !pcbSessionPin.is_null() {
        unsafe {
            *pcbSessionPin = 0;
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

    let mut tx = lock_transport(&ctx.transport);
    if let Err(error) = sync_transport_handle(
        &mut tx,
        &mut ctx.pin1_authenticated,
        &mut ctx.pin2_authenticated,
        cd.hScard,
        "CardAuthenticateEx",
    ) {
        return error;
    }
    clear_pin_state(&mut ctx.pin1_authenticated, &mut ctx.pin2_authenticated);
    let serial = match live_token_serial(&mut tx) {
        Ok(serial) => serial,
        Err(error) => return error,
    };
    let pin1_cache_allowed =
        slot != PinSlot::Pin1 || matches!(live_pin1_authentication_is_permitted(&mut tx), Ok(true));
    let is_rejected =
        with_pin_safety(|cache| cache.is_rejected(&serial, slot, &pin)).unwrap_or(false);
    if is_rejected {
        return SCARD_W_WRONG_CHV;
    }
    let outcome = if slot == PinSlot::Pin1 {
        tx.verify_pin1(pin.clone())
    } else {
        tx.verify_pin(slot, pin.clone())
    };
    drop(tx);
    match outcome {
        Ok(VerifyOutcome::Ok) => {
            Log::dbg("CardAuthenticateEx -> OK");
            if slot == PinSlot::Pin1 {
                ctx.pin1_authenticated = true;
                if pin1_cache_allowed {
                    let _ = with_pin_safety(|cache| cache.store_pin1(serial, pin));
                }
            } else {
                ctx.pin2_authenticated = true;
                let _ = with_pin_safety(|cache| cache.store_pin2(serial, pin));
            }
            SCARD_S_SUCCESS
        }
        Ok(VerifyOutcome::WrongPin { retries_left }) => {
            Log::dbg(&format!(
                "CardAuthenticateEx -> WRONG_CHV (retries={retries_left})"
            ));
            let _ = with_pin_safety(|cache| cache.record_rejected(&serial, slot, &pin));
            clear_cached_pin(ctx, PinId);
            if !pcAttemptsRemaining.is_null() {
                unsafe {
                    *pcAttemptsRemaining = DWORD::from(retries_left.get());
                }
            }
            SCARD_W_WRONG_CHV
        }
        Ok(VerifyOutcome::Locked) => {
            Log::dbg("CardAuthenticateEx -> CHV_BLOCKED");
            clear_cached_pin(ctx, PinId);
            SCARD_W_CHV_BLOCKED
        }
        Ok(VerifyOutcome::Other(sw)) => {
            Log::dbg(&format!("CardAuthenticateEx -> WRONG_CHV (sw={sw:#06x})"));
            clear_cached_pin(ctx, PinId);
            SCARD_W_WRONG_CHV
        }
        Err(e) => {
            Log::dbg(&format!("CardAuthenticateEx -> INTERNAL ({e:?})"));
            clear_cached_pin(ctx, PinId);
            SCARD_F_INTERNAL_ERROR
        }
    }
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
    let (_cd, ctx) = match unsafe { checked_card_data_and_ctx_mut(pCardData) } {
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
        let mut tx = lock_transport(&ctx.transport);
        if let Err(error) = live_token_serial(&mut tx) {
            return error;
        }
        let outcome = match target_slot {
            PinSlot::Pin1 => tx.unblock_pin1(puk, new_pin),
            PinSlot::Pin2 => tx.reset_retry_counter(PinSlot::Pin2, puk, new_pin),
        };
        drop(tx);
        return match outcome {
            Ok(o) => map_unblock_outcome(ctx, dwTargetPinId, o),
            Err(_) => SCARD_F_INTERNAL_ERROR,
        };
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
    let mut tx = lock_transport(&ctx.transport);
    let serial = match live_token_serial(&mut tx) {
        Ok(serial) => serial,
        Err(error) => return error,
    };
    let is_rejected = with_pin_safety(|cache| {
        cache.is_rejected(&serial, target_slot, &current_pin)
            || cache.is_rejected(&serial, target_slot, &new_pin)
    })
    .unwrap_or(false);
    if is_rejected {
        return SCARD_W_WRONG_CHV;
    }
    let outcome = match target_slot {
        PinSlot::Pin1 => tx.change_pin1(current_pin.clone(), new_pin),
        PinSlot::Pin2 => tx.change_pin(PinSlot::Pin2, current_pin.clone(), new_pin),
    };
    drop(tx);
    match outcome {
        Ok(o) => {
            if matches!(o, ChangePinOutcome::WrongCurrentPin { .. }) {
                let _ = with_pin_safety(|cache| {
                    cache.record_rejected(&serial, target_slot, &current_pin);
                });
            }
            map_change_pin_outcome(ctx, dwTargetPinId, o, pcAttemptsRemaining)
        }
        Err(_) => SCARD_F_INTERNAL_ERROR,
    }
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_delete_container(
    _p: *mut CARD_DATA,
    _container: BYTE,
    _flags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_create_container(
    _p: *mut CARD_DATA,
    _container: BYTE,
    _flags: DWORD,
    _keySpec: DWORD,
    _keySize: DWORD,
    _keyData: PBYTE,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_get_container_info(
    _p: *mut CARD_DATA,
    _container: BYTE,
    _flags: DWORD,
    _info: *mut CONTAINER_INFO,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_authenticate_pin(
    _p: *mut CARD_DATA,
    _pwszUserId: LPWSTR,
    _pbPin: PBYTE,
    _cbPin: DWORD,
    _pcAttemptsRemaining: PDWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_get_challenge(
    _p: *mut CARD_DATA,
    _pbChallenge: *mut PBYTE,
    _pcbChallenge: PDWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_authenticate_challenge(
    _p: *mut CARD_DATA,
    _pbResponse: PBYTE,
    _cbResponse: DWORD,
    _pcAttemptsRemaining: PDWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_deauthenticate(
    _p: *mut CARD_DATA,
    _pwszUserId: LPWSTR,
    _dwFlags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_create_directory(
    _p: *mut CARD_DATA,
    _pszDirectoryName: LPSTR,
    _AccessCondition: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_delete_directory(
    _p: *mut CARD_DATA,
    _pszDirectoryName: LPSTR,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_create_file(
    _p: *mut CARD_DATA,
    _pszDirectoryName: LPSTR,
    _pszFileName: LPSTR,
    _cbInitialCreationSize: DWORD,
    _AccessCondition: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_read_file(
    _p: *mut CARD_DATA,
    _pszDirectoryName: LPSTR,
    _pszFileName: LPSTR,
    _dwFlags: DWORD,
    _ppbData: *mut PBYTE,
    _pcbData: PDWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_write_file(
    _p: *mut CARD_DATA,
    _pszDirectoryName: LPSTR,
    _pszFileName: LPSTR,
    _dwFlags: DWORD,
    _pbData: PBYTE,
    _cbData: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_delete_file(
    _p: *mut CARD_DATA,
    _pszDirectoryName: LPSTR,
    _pszFileName: LPSTR,
    _dwFlags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_enum_files(
    _p: *mut CARD_DATA,
    _pszDirectoryName: LPSTR,
    _ppmszFileNames: *mut LPSTR,
    _pdwcbFileName: PDWORD,
    _dwFlags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_get_file_info(
    _p: *mut CARD_DATA,
    _pszDirectoryName: LPSTR,
    _pszFileName: LPSTR,
    _pCardFileInfo: *mut CARD_FILE_INFO,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_query_free_space(
    _p: *mut CARD_DATA,
    _dwFlags: DWORD,
    _pCardFreeSpaceInfo: *mut CARD_FREE_SPACE_INFO,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_query_key_sizes(
    _p: *mut CARD_DATA,
    _dwKeySpec: DWORD,
    _dwFlags: DWORD,
    _pCardKeySizes: *mut CARD_KEY_SIZES,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_sign_data(
    _p: *mut CARD_DATA,
    _pInfo: *mut CARD_SIGNING_INFO,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_rsa_decrypt(_p: *mut CARD_DATA, _pInfo: PVOID) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_construct_dh_agreement(
    _p: *mut CARD_DATA,
    _info: PVOID,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_derive_key(_p: *mut CARD_DATA, _info: PVOID) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_destroy_dh_agreement(
    _p: *mut CARD_DATA,
    _b: BYTE,
    _flags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_csp_get_dh_agreement(
    _p: *mut CARD_DATA,
    _hSecretAgreement: PVOID,
    _pbSecretAgreementIndex: *mut BYTE,
    _dwFlags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_get_challenge_ex(
    _p: *mut CARD_DATA,
    _PinId: DWORD,
    _ppbChallengeData: *mut PBYTE,
    _pcbChallengeData: PDWORD,
    _dwFlags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_deauthenticate_ex(
    _p: *mut CARD_DATA,
    _PinId: DWORD,
    _dwFlags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_get_container_property(
    _p: *mut CARD_DATA,
    _bContainerIndex: BYTE,
    _wszProperty: LPCWSTR,
    _pbData: PBYTE,
    _cbData: DWORD,
    _pdwDataLen: PDWORD,
    _dwFlags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_set_container_property(
    _p: *mut CARD_DATA,
    _bContainerIndex: BYTE,
    _wszProperty: LPCWSTR,
    _pbData: PBYTE,
    _cbData: DWORD,
    _dwFlags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_get_property(
    _p: *mut CARD_DATA,
    _wszProperty: LPCWSTR,
    _pbData: PBYTE,
    _cbData: DWORD,
    _pdwDataLen: PDWORD,
    _dwFlags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_set_property(
    _p: *mut CARD_DATA,
    _wszProperty: LPCWSTR,
    _pbData: PBYTE,
    _cbData: DWORD,
    _dwFlags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_md_import_session_key(
    _p: *mut CARD_DATA,
    _pInfo: PVOID,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_md_encrypt_data(_p: *mut CARD_DATA, _pInfo: PVOID) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_card_import_session_key(
    _p: *mut CARD_DATA,
    _pInfo: PVOID,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_get_shared_key_handle(
    _p: *mut CARD_DATA,
    _pInfo: PVOID,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_get_algorithm_property(
    _p: *mut CARD_DATA,
    _pwszAlgId: LPCWSTR,
    _pwszProperty: LPCWSTR,
    _pbData: PBYTE,
    _cbData: DWORD,
    _pdwDataLen: PDWORD,
    _dwFlags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_get_key_property(
    _p: *mut CARD_DATA,
    _hKey: CARD_KEY_HANDLE,
    _pwszProperty: LPCWSTR,
    _pbData: PBYTE,
    _cbData: DWORD,
    _pdwDataLen: PDWORD,
    _dwFlags: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_set_key_property(_p: *mut CARD_DATA, _info: PVOID) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_destroy_key(_p: *mut CARD_DATA, _info: PVOID) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_process_encrypted_data(
    _p: *mut CARD_DATA,
    _info: PVOID,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}

#[cfg(windows)]
unsafe extern "system" fn unsupported_create_container_ex(
    _p: *mut CARD_DATA,
    _container: BYTE,
    _flags: DWORD,
    _keySpec: DWORD,
    _keySize: DWORD,
    _keyData: PBYTE,
    _pinId: DWORD,
) -> DWORD {
    SCARD_E_UNSUPPORTED_FEATURE
}
