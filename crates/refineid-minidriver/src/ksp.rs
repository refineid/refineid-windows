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

//! The CNG key storage provider for a paired phone.
//!
//! Browsers and Schannel reach a certificate's private key through CNG:
//! `CryptAcquireCertificatePrivateKey` reads the certificate's key provider
//! info, `ncrypt.dll` loads the named provider DLL through
//! `GetKeyStorageInterface`, and the signature request lands in [`SignHash`]
//! below. This provider never sees a key: it looks up the pairing the key
//! name refers to and asks the phone for a `BrowserAuthenticate` signature
//! over RAPP, the same operation the Card Module's remote arm uses.
//!
//! The provider is read-only. It opens keys that the `RefineID` app placed in
//! the user's certificate store (`rapp:<pair id>`), reports their public
//! half from the cached certificate, and signs. Everything else in the
//! function table returns `NTE_NOT_SUPPORTED`.
//!
//! Buffers handed to the caller (`EnumKeys`, `EnumAlgorithms`) come from the
//! process heap so that either this module's `FreeBuffer` or a plain
//! `HeapFree` releases them.
#![expect(
    clippy::redundant_pub_crate,
    reason = "the exported entry point keeps the pub(crate) spelling of the sibling Card Module entry points"
)]

use core::ffi::c_void;
use core::mem::size_of;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use refineid_lib_core::x509::{EcCurve, OwnedCert, PublicKeyAlgorithm, extract_rsa_public_key};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::operations::{
    CardOperation, CardOperationResult, KeyProfile, SignatureAlgorithm,
};
use refineid_rapp_core::store::{PairingDisposition, PairingRecord};
use refineid_windows_credential_store::{
    CredentialPairingStore, KEY_STORAGE_PROVIDER, browser_key_name, browser_key_pair_id,
};
use windows_sys::Win32::Foundation::{
    HANDLE, NTE_BAD_FLAGS, NTE_BAD_KEYSET, NTE_BUFFER_TOO_SMALL, NTE_FAIL, NTE_INVALID_HANDLE,
    NTE_INVALID_PARAMETER, NTE_NO_MEMORY, NTE_NO_MORE_ITEMS, NTE_NOT_SUPPORTED, NTE_USER_CANCELLED,
    S_OK,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_INTERFACE_VERSION, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_PSS_PADDING_INFO, BCryptBufferDesc,
    NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_IMPL_HARDWARE_FLAG, NCRYPT_IMPL_REMOVABLE_FLAG,
    NCRYPT_KEY_HANDLE, NCRYPT_KEY_STORAGE_FUNCTION_TABLE, NCRYPT_MACHINE_KEY_FLAG,
    NCRYPT_MAX_KEY_NAME_LENGTH, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PAD_PSS_FLAG, NCRYPT_PROV_HANDLE,
    NCRYPT_SECRET_HANDLE, NCRYPT_SIGNATURE_INTERFACE, NCRYPT_SIGNATURE_OPERATION,
    NCryptAlgorithmName, NCryptKeyName,
};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HEAP_ZERO_MEMORY, HeapAlloc, HeapFree};
use windows_sys::core::{HRESULT, PCWSTR};

use crate::cardmod::{Log, remote_ecdsa_to_p1363};
use crate::ksp_codec::{
    Digest, KeyKind, ecc_public_blob, requester_label, rsa_public_blob, rsa_signature_to_width,
};
use crate::transport::{REMOTE_SYNTHETIC_ATR, RemoteCardTransport};

/// `NCRYPT_VERSION_PROPERTY` value: 1.0.
const PROVIDER_VERSION: u32 = 0x0001_0000;
/// `NCRYPT_IMPL_TYPE_PROPERTY` value: the key lives on a removable device.
const IMPL_TYPE: u32 = NCRYPT_IMPL_HARDWARE_FLAG | NCRYPT_IMPL_REMOVABLE_FLAG;
/// Longest wide string this module reads from a caller.
const MAX_WIDE_UNITS: usize = NCRYPT_MAX_KEY_NAME_LENGTH as usize;
/// The CNG algorithm identifiers this provider signs with.
const ALGORITHMS: [&str; 3] = ["ECDSA_P256", "ECDSA_P384", "RSA"];

/// One key the caller has opened: the pairing to dial and the public half
/// to describe it with.
#[derive(Clone)]
struct OpenKey {
    name: String,
    pair_id: PairId,
    record: PairingRecord,
    certificate: Vec<u8>,
    kind: KeyKind,
}

/// What an `NCRYPT_HANDLE` handed out by this provider stands for.
enum Handle {
    Provider,
    Key(Box<OpenKey>),
}

static HANDLES: Mutex<BTreeMap<usize, Handle>> = Mutex::new(BTreeMap::new());
static NEXT_HANDLE: AtomicUsize = AtomicUsize::new(1);

fn handles() -> MutexGuard<'static, BTreeMap<usize, Handle>> {
    HANDLES.lock().unwrap_or_else(PoisonError::into_inner)
}

fn register(handle: Handle) -> usize {
    let id = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    handles().insert(id, handle);
    id
}

fn is_provider(handle: NCRYPT_PROV_HANDLE) -> bool {
    matches!(handles().get(&handle), Some(Handle::Provider))
}

/// A copy of the opened key, so no lock is held while the phone is dialed.
fn opened_key(handle: NCRYPT_KEY_HANDLE) -> Option<OpenKey> {
    match handles().get(&handle) {
        Some(Handle::Key(key)) => Some((**key).clone()),
        _ => None,
    }
}

/// The key kind a certificate's public key implies, if this provider can
/// sign with it.
fn key_kind(certificate: &[u8]) -> Option<KeyKind> {
    let cert = OwnedCert::from_der(certificate).ok()?;
    match cert.view().spki.algorithm() {
        PublicKeyAlgorithm::Rsa { modulus_bits } => Some(KeyKind::Rsa { bits: modulus_bits }),
        PublicKeyAlgorithm::Ec(EcCurve::Secp256r1) => Some(KeyKind::EcP256),
        PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => Some(KeyKind::EcP384),
        _ => None,
    }
}

fn key_from_record(record: &PairingRecord) -> Option<OpenKey> {
    if record.disposition != PairingDisposition::Paired {
        return None;
    }
    let certificate = record.auth_cert.clone()?;
    let kind = key_kind(&certificate)?;
    Some(OpenKey {
        name: browser_key_name(record.pair_id),
        pair_id: record.pair_id,
        record: record.clone(),
        certificate,
        kind,
    })
}

/// Every stored pairing this provider can sign for, in store order.
fn usable_keys() -> Vec<OpenKey> {
    match CredentialPairingStore::load() {
        Ok(store) => store.records().iter().filter_map(key_from_record).collect(),
        Err(error) => {
            Log::dbg(&format!("KSP: pairing store unavailable: {error}"));
            Vec::new()
        }
    }
}

/// The CNG public key blob for the opened key.
fn public_blob(key: &OpenKey) -> Option<Vec<u8>> {
    let cert = OwnedCert::from_der(&key.certificate).ok()?;
    let view = cert.view();
    match key.kind {
        KeyKind::EcP256 | KeyKind::EcP384 => {
            ecc_public_blob(view.spki.ec_public_key_point()?.as_bytes())
        }
        KeyKind::Rsa { .. } => {
            let rsa = extract_rsa_public_key(view.spki.as_der())?;
            rsa_public_blob(rsa.modulus.as_bytes(), rsa.exponent.as_bytes())
        }
    }
}

/// What the phone shows as the asking party. A relying-party origin set by
/// a test harness wins; otherwise the calling program is named, since CNG
/// never tells a provider which site a browser is signing for.
fn browser_origin() -> String {
    std::env::var("REFINEID_RP_ORIGIN")
        .ok()
        .or_else(|| std::env::var("REFINEID_ORIGIN").ok())
        .map(|origin| origin.trim().to_owned())
        .filter(|origin| !origin.is_empty() && origin.len() <= 256)
        .unwrap_or_else(|| {
            let executable = std::env::current_exe()
                .ok()
                .and_then(|path| {
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                })
                .unwrap_or_default();
            requester_label(&executable)
        })
}

fn wide_units(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

fn wide_bytes(text: &str) -> Vec<u8> {
    wide_units(text)
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn dword(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// Reads a NUL-terminated wide string the caller owns, bounded by
/// `MAX_WIDE_UNITS`.
///
/// # Safety
///
/// `ptr` is null or points at a readable NUL-terminated UTF-16 string.
unsafe fn read_wide(ptr: PCWSTR) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut units = Vec::new();
    for offset in 0..MAX_WIDE_UNITS {
        // SAFETY: the caller guarantees a NUL-terminated string, and the
        // loop stops at the terminator or the bound.
        let unit = unsafe { *ptr.add(offset) };
        if unit == 0 {
            return String::from_utf16(&units).ok();
        }
        units.push(unit);
    }
    None
}

/// Hands `data` to the caller through the CNG size-query-then-fill
/// convention.
///
/// # Safety
///
/// `pbOutput` is null or points at `cbOutput` writable bytes, and
/// `pcbResult` is null or points at a writable `u32`.
unsafe fn write_output(
    pbOutput: *mut u8,
    cbOutput: u32,
    pcbResult: *mut u32,
    data: &[u8],
) -> HRESULT {
    if pcbResult.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let Ok(needed) = u32::try_from(data.len()) else {
        return NTE_FAIL;
    };
    // SAFETY: checked non-null above; the caller owns the u32.
    unsafe { *pcbResult = needed };
    if pbOutput.is_null() {
        return S_OK;
    }
    if cbOutput < needed {
        return NTE_BUFFER_TOO_SMALL;
    }
    // SAFETY: the caller's buffer holds at least `needed` bytes.
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), pbOutput, data.len()) };
    S_OK
}

/// Zeroed process-heap memory the caller releases through `FreeBuffer`.
fn heap_alloc(size: usize) -> *mut c_void {
    // SAFETY: plain Win32 heap allocation; a null return is handled by
    // every caller.
    unsafe { HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size) }
}

// --- the function table -------------------------------------------------

unsafe extern "system" fn OpenProvider(
    phProvider: *mut NCRYPT_PROV_HANDLE,
    _pszProviderName: PCWSTR,
    _dwFlags: u32,
) -> HRESULT {
    if phProvider.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    // SAFETY: checked non-null; the caller owns the handle slot.
    unsafe { *phProvider = register(Handle::Provider) };
    S_OK
}

unsafe extern "system" fn OpenKey(
    hProvider: NCRYPT_PROV_HANDLE,
    phKey: *mut NCRYPT_KEY_HANDLE,
    pszKeyName: PCWSTR,
    _dwLegacyKeySpec: u32,
    dwFlags: u32,
) -> HRESULT {
    if !is_provider(hProvider) {
        return NTE_INVALID_HANDLE;
    }
    if phKey.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    if dwFlags & NCRYPT_MACHINE_KEY_FLAG != 0 {
        // Pairings belong to the Windows user, never to the machine.
        return NTE_BAD_KEYSET;
    }
    // SAFETY: `pszKeyName` is the caller's NUL-terminated key name.
    let Some(name) = (unsafe { read_wide(pszKeyName) }) else {
        return NTE_INVALID_PARAMETER;
    };
    let Some(pair_id) = browser_key_pair_id(&name) else {
        return NTE_BAD_KEYSET;
    };
    let Some(key) = usable_keys().into_iter().find(|key| key.pair_id == pair_id) else {
        Log::dbg("KSP: OpenKey: no usable pairing with a cached certificate");
        return NTE_BAD_KEYSET;
    };
    Log::dbg(&format!("KSP: OpenKey: {}", key.kind.algorithm_name()));
    // SAFETY: checked non-null; the caller owns the handle slot.
    unsafe { *phKey = register(Handle::Key(Box::new(key))) };
    S_OK
}

unsafe extern "system" fn GetProviderProperty(
    hProvider: NCRYPT_PROV_HANDLE,
    pszProperty: PCWSTR,
    pbOutput: *mut u8,
    cbOutput: u32,
    pcbResult: *mut u32,
    _dwFlags: u32,
) -> HRESULT {
    if !is_provider(hProvider) {
        return NTE_INVALID_HANDLE;
    }
    // SAFETY: `pszProperty` is the caller's NUL-terminated property name.
    let Some(property) = (unsafe { read_wide(pszProperty) }) else {
        return NTE_INVALID_PARAMETER;
    };
    // Property names are the `NCRYPT_*_PROPERTY` strings of ncrypt.h.
    let value = match property.as_str() {
        "Impl Type" => dword(IMPL_TYPE),
        "Name" => wide_bytes(KEY_STORAGE_PROVIDER),
        "Version" => dword(PROVIDER_VERSION),
        "Max Name Length" => dword(NCRYPT_MAX_KEY_NAME_LENGTH),
        _ => return NTE_NOT_SUPPORTED,
    };
    // SAFETY: the output triple is the caller's.
    unsafe { write_output(pbOutput, cbOutput, pcbResult, &value) }
}

unsafe extern "system" fn GetKeyProperty(
    hProvider: NCRYPT_PROV_HANDLE,
    hKey: NCRYPT_KEY_HANDLE,
    pszProperty: PCWSTR,
    pbOutput: *mut u8,
    cbOutput: u32,
    pcbResult: *mut u32,
    _dwFlags: u32,
) -> HRESULT {
    let Some(key) = opened_key(hKey) else {
        return NTE_INVALID_HANDLE;
    };
    // SAFETY: `pszProperty` is the caller's NUL-terminated property name.
    let Some(property) = (unsafe { read_wide(pszProperty) }) else {
        return NTE_INVALID_PARAMETER;
    };
    let Ok(bits) = u32::try_from(key.kind.bits()) else {
        return NTE_FAIL;
    };
    // Property names are the `NCRYPT_*_PROPERTY` strings of ncrypt.h.
    let value = match property.as_str() {
        "Algorithm Group" => wide_bytes(key.kind.algorithm_group()),
        "Algorithm Name" => wide_bytes(key.kind.algorithm_name()),
        "Length" => dword(bits),
        // NCRYPT_SUPPORTED_LENGTHS: min, max, increment, default.
        "Lengths" => [bits, bits, 0, bits]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect(),
        "Key Usage" => dword(NCRYPT_ALLOW_SIGNING_FLAG),
        "Export Policy" | "Key Type" => dword(0),
        "Name" | "Unique Name" => wide_bytes(&key.name),
        "Provider Handle" => hProvider.to_ne_bytes().to_vec(),
        "SmartCardKeyCertificate" => key.certificate,
        "Impl Type" => dword(IMPL_TYPE),
        "Version" => dword(PROVIDER_VERSION),
        _ => return NTE_NOT_SUPPORTED,
    };
    // SAFETY: the output triple is the caller's.
    unsafe { write_output(pbOutput, cbOutput, pcbResult, &value) }
}

unsafe extern "system" fn SetProviderProperty(
    hProvider: NCRYPT_PROV_HANDLE,
    _pszProperty: PCWSTR,
    _pbInput: *const u8,
    _cbInput: u32,
    _dwFlags: u32,
) -> HRESULT {
    // Window handles, use contexts and PIN hints have no meaning here: the
    // phone carries its own consent prompt. Accepting them keeps callers
    // that set them before signing on their happy path.
    if is_provider(hProvider) {
        S_OK
    } else {
        NTE_INVALID_HANDLE
    }
}

unsafe extern "system" fn SetKeyProperty(
    _hProvider: NCRYPT_PROV_HANDLE,
    hKey: NCRYPT_KEY_HANDLE,
    _pszProperty: PCWSTR,
    _pbInput: *const u8,
    _cbInput: u32,
    _dwFlags: u32,
) -> HRESULT {
    if opened_key(hKey).is_some() {
        S_OK
    } else {
        NTE_INVALID_HANDLE
    }
}

unsafe extern "system" fn FreeProvider(hProvider: NCRYPT_PROV_HANDLE) -> HRESULT {
    let mut handles = handles();
    match handles.get(&hProvider) {
        Some(Handle::Provider) => {
            handles.remove(&hProvider);
            S_OK
        }
        _ => NTE_INVALID_HANDLE,
    }
}

unsafe extern "system" fn FreeKey(
    _hProvider: NCRYPT_PROV_HANDLE,
    hKey: NCRYPT_KEY_HANDLE,
) -> HRESULT {
    let mut handles = handles();
    match handles.get(&hKey) {
        Some(Handle::Key(_)) => {
            handles.remove(&hKey);
            S_OK
        }
        _ => NTE_INVALID_HANDLE,
    }
}

unsafe extern "system" fn FreeBuffer(pvInput: *mut c_void) -> HRESULT {
    if pvInput.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    // SAFETY: every buffer this provider hands out comes from the process
    // heap (`heap_alloc`).
    unsafe { HeapFree(GetProcessHeap(), 0, pvInput) };
    S_OK
}

unsafe extern "system" fn IsAlgSupported(
    hProvider: NCRYPT_PROV_HANDLE,
    pszAlgId: PCWSTR,
    _dwFlags: u32,
) -> HRESULT {
    if !is_provider(hProvider) {
        return NTE_INVALID_HANDLE;
    }
    // SAFETY: `pszAlgId` is the caller's NUL-terminated algorithm name.
    match unsafe { read_wide(pszAlgId) } {
        Some(name) if ALGORITHMS.contains(&name.as_str()) => S_OK,
        Some(_) => NTE_NOT_SUPPORTED,
        None => NTE_INVALID_PARAMETER,
    }
}

unsafe extern "system" fn EnumAlgorithms(
    hProvider: NCRYPT_PROV_HANDLE,
    dwAlgOperations: u32,
    pdwAlgCount: *mut u32,
    ppAlgList: *mut *mut NCryptAlgorithmName,
    _dwFlags: u32,
) -> HRESULT {
    if !is_provider(hProvider) {
        return NTE_INVALID_HANDLE;
    }
    if pdwAlgCount.is_null() || ppAlgList.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    // The caller asks for a set of `NCRYPT_*_OPERATION` classes, zero
    // meaning all; this provider only signs.
    if dwAlgOperations != 0 && dwAlgOperations & NCRYPT_SIGNATURE_OPERATION == 0 {
        // SAFETY: checked non-null; both slots are the caller's.
        unsafe {
            *pdwAlgCount = 0;
            *ppAlgList = core::ptr::null_mut();
        }
        return S_OK;
    }
    let Ok(count) = u32::try_from(ALGORITHMS.len()) else {
        return NTE_FAIL;
    };
    // One allocation: the entry array, then the names it points into.
    let names: Vec<Vec<u16>> = ALGORITHMS.iter().map(|name| wide_units(name)).collect();
    let header = size_of::<NCryptAlgorithmName>() * ALGORITHMS.len();
    let total = header + names.iter().map(|name| name.len() * 2).sum::<usize>();
    let buffer = heap_alloc(total);
    if buffer.is_null() {
        return NTE_NO_MEMORY;
    }
    // SAFETY: `buffer` holds `total` zeroed bytes; entries are written at
    // their natural alignment (the heap block is 8-byte aligned) and the
    // wide strings after the entry array at 2-byte alignment.
    unsafe {
        let mut next = buffer.byte_add(header).cast::<u16>();
        for (index, name) in names.iter().enumerate() {
            core::ptr::copy_nonoverlapping(name.as_ptr(), next, name.len());
            buffer
                .cast::<NCryptAlgorithmName>()
                .add(index)
                .write(NCryptAlgorithmName {
                    pszName: next,
                    dwClass: NCRYPT_SIGNATURE_INTERFACE,
                    dwAlgOperations: NCRYPT_SIGNATURE_OPERATION,
                    dwFlags: 0,
                });
            next = next.add(name.len());
        }
        *pdwAlgCount = count;
        *ppAlgList = buffer.cast();
    }
    S_OK
}

unsafe extern "system" fn EnumKeys(
    hProvider: NCRYPT_PROV_HANDLE,
    _pszScope: PCWSTR,
    ppKeyName: *mut *mut NCryptKeyName,
    ppEnumState: *mut *mut c_void,
    dwFlags: u32,
) -> HRESULT {
    if !is_provider(hProvider) {
        return NTE_INVALID_HANDLE;
    }
    if ppKeyName.is_null() || ppEnumState.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    if dwFlags & NCRYPT_MACHINE_KEY_FLAG != 0 {
        return NTE_NO_MORE_ITEMS;
    }
    // The enumeration state is one heap `u32`: the index of the next key.
    // SAFETY: checked non-null; the state slot is the caller's.
    let mut state = unsafe { *ppEnumState }.cast::<u32>();
    if state.is_null() {
        state = heap_alloc(size_of::<u32>()).cast::<u32>();
        if state.is_null() {
            return NTE_NO_MEMORY;
        }
        // SAFETY: freshly allocated, zeroed, and handed to the caller.
        unsafe { *ppEnumState = state.cast() };
    }
    // SAFETY: `state` is this module's own heap `u32`.
    let index = unsafe { *state } as usize;
    let keys = usable_keys();
    let Some(key) = keys.get(index) else {
        return NTE_NO_MORE_ITEMS;
    };
    let Ok(next_index) = u32::try_from(index + 1) else {
        return NTE_FAIL;
    };
    let name = wide_units(&key.name);
    let algorithm = wide_units(key.kind.algorithm_name());
    let header = size_of::<NCryptKeyName>();
    let buffer = heap_alloc(header + (name.len() + algorithm.len()) * 2);
    if buffer.is_null() {
        return NTE_NO_MEMORY;
    }
    // SAFETY: the block holds the entry and both strings; the entry sits at
    // the 8-byte-aligned block start and the strings follow at 2-byte
    // alignment.
    unsafe {
        let name_ptr = buffer.byte_add(header).cast::<u16>();
        core::ptr::copy_nonoverlapping(name.as_ptr(), name_ptr, name.len());
        let algorithm_ptr = name_ptr.add(name.len());
        core::ptr::copy_nonoverlapping(algorithm.as_ptr(), algorithm_ptr, algorithm.len());
        buffer.cast::<NCryptKeyName>().write(NCryptKeyName {
            pszName: name_ptr,
            pszAlgid: algorithm_ptr,
            dwLegacyKeySpec: 0,
            dwFlags: 0,
        });
        *ppKeyName = buffer.cast();
        *state = next_index;
    }
    S_OK
}

unsafe extern "system" fn ExportKey(
    _hProvider: NCRYPT_PROV_HANDLE,
    hKey: NCRYPT_KEY_HANDLE,
    hExportKey: NCRYPT_KEY_HANDLE,
    pszBlobType: PCWSTR,
    _pParameterList: *const BCryptBufferDesc,
    pbOutput: *mut u8,
    cbOutput: u32,
    pcbResult: *mut u32,
    _dwFlags: u32,
) -> HRESULT {
    let Some(key) = opened_key(hKey) else {
        return NTE_INVALID_HANDLE;
    };
    if hExportKey != 0 {
        return NTE_NOT_SUPPORTED;
    }
    // SAFETY: `pszBlobType` is the caller's NUL-terminated blob type.
    let Some(blob_type) = (unsafe { read_wide(pszBlobType) }) else {
        return NTE_INVALID_PARAMETER;
    };
    let wants_public = matches!(
        (blob_type.as_str(), key.kind),
        ("PUBLICBLOB", _)
            | ("ECCPUBLICBLOB", KeyKind::EcP256 | KeyKind::EcP384)
            | ("RSAPUBLICBLOB", KeyKind::Rsa { .. })
    );
    if !wants_public {
        return NTE_NOT_SUPPORTED;
    }
    let Some(blob) = public_blob(&key) else {
        return NTE_FAIL;
    };
    // SAFETY: the output triple is the caller's.
    unsafe { write_output(pbOutput, cbOutput, pcbResult, &blob) }
}

/// The RSA signature scheme a caller's padding flags and info ask for.
///
/// # Safety
///
/// `pPaddingInfo` is null or points at the padding struct `dwFlags` names.
unsafe fn rsa_algorithm(
    pPaddingInfo: *const c_void,
    dwFlags: u32,
    digest: Digest,
) -> Result<SignatureAlgorithm, HRESULT> {
    if dwFlags & NCRYPT_PAD_PKCS1_FLAG != 0 {
        let info = pPaddingInfo.cast::<BCRYPT_PKCS1_PADDING_INFO>();
        if info.is_null() {
            return Err(NTE_INVALID_PARAMETER);
        }
        // SAFETY: the PKCS#1 flag promises a BCRYPT_PKCS1_PADDING_INFO.
        let alg_id = unsafe { (*info).pszAlgId };
        // A null algorithm means PKCS#1 over a bare hash without
        // DigestInfo (TLS 1.0/1.1 MD5+SHA1); the phone does not offer it.
        // SAFETY: `alg_id` is the caller's NUL-terminated algorithm name.
        let Some(named) =
            (unsafe { read_wide(alg_id) }).and_then(|n| Digest::from_cng_algorithm(&n))
        else {
            return Err(NTE_NOT_SUPPORTED);
        };
        if named != digest {
            return Err(NTE_INVALID_PARAMETER);
        }
        return match named {
            Digest::Sha256 => Ok(SignatureAlgorithm::RsaPkcs1Sha256),
            Digest::Sha384 => Ok(SignatureAlgorithm::RsaPkcs1Sha384),
            Digest::Sha512 => Ok(SignatureAlgorithm::RsaPkcs1Sha512),
            Digest::Sha224 => Err(NTE_NOT_SUPPORTED),
        };
    }
    if dwFlags & NCRYPT_PAD_PSS_FLAG != 0 {
        let info = pPaddingInfo.cast::<BCRYPT_PSS_PADDING_INFO>();
        if info.is_null() {
            return Err(NTE_INVALID_PARAMETER);
        }
        // SAFETY: the PSS flag promises a BCRYPT_PSS_PADDING_INFO.
        let alg_id = unsafe { (*info).pszAlgId };
        // SAFETY: `alg_id` is the caller's NUL-terminated algorithm name.
        let named = unsafe { read_wide(alg_id) }.and_then(|n| Digest::from_cng_algorithm(&n));
        return if named == Some(Digest::Sha256) && digest == Digest::Sha256 {
            Ok(SignatureAlgorithm::RsaPssSha256)
        } else {
            Err(NTE_NOT_SUPPORTED)
        };
    }
    // Raw RSA (no padding) is never offered.
    Err(NTE_BAD_FLAGS)
}

unsafe extern "system" fn SignHash(
    _hProvider: NCRYPT_PROV_HANDLE,
    hKey: NCRYPT_KEY_HANDLE,
    pPaddingInfo: *const c_void,
    pbHashValue: *const u8,
    cbHashValue: u32,
    pbSignature: *mut u8,
    cbSignature: u32,
    pcbResult: *mut u32,
    dwFlags: u32,
) -> HRESULT {
    let Some(key) = opened_key(hKey) else {
        return NTE_INVALID_HANDLE;
    };
    if pcbResult.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let Ok(needed) = u32::try_from(key.kind.signature_bytes()) else {
        return NTE_FAIL;
    };
    // SAFETY: checked non-null; the caller owns the u32.
    unsafe { *pcbResult = needed };
    if pbSignature.is_null() {
        // Size query.
        return S_OK;
    }
    if cbSignature < needed {
        return NTE_BUFFER_TOO_SMALL;
    }
    if pbHashValue.is_null() || cbHashValue == 0 {
        return NTE_INVALID_PARAMETER;
    }
    // SAFETY: the caller's hash buffer holds `cbHashValue` bytes.
    let hash = unsafe { core::slice::from_raw_parts(pbHashValue, cbHashValue as usize) };
    let Some(digest) = Digest::from_length(hash.len()) else {
        return NTE_INVALID_PARAMETER;
    };
    let algorithm = match key.kind {
        KeyKind::EcP256 | KeyKind::EcP384 => match digest {
            Digest::Sha224 => SignatureAlgorithm::EcdsaSha224,
            Digest::Sha256 => SignatureAlgorithm::EcdsaSha256,
            Digest::Sha384 => SignatureAlgorithm::EcdsaSha384,
            Digest::Sha512 => SignatureAlgorithm::EcdsaSha512,
        },
        // SAFETY: the padding pointer belongs to the flags the caller set.
        KeyKind::Rsa { .. } => match unsafe { rsa_algorithm(pPaddingInfo, dwFlags, digest) } {
            Ok(algorithm) => algorithm,
            Err(code) => return code,
        },
    };
    let key_profile = match key.kind {
        KeyKind::EcP256 => KeyProfile::EcdsaP256,
        KeyKind::EcP384 => KeyProfile::EcdsaP384,
        KeyKind::Rsa { bits } if bits <= 2048 => KeyProfile::Rsa2048,
        KeyKind::Rsa { .. } => KeyProfile::Rsa3072,
    };
    let operation = CardOperation::BrowserAuthenticate {
        origin: browser_origin(),
        key_profile,
        algorithm,
        digest: hash.to_vec(),
    };
    Log::dbg(&format!("KSP: SignHash: {}", key.kind.algorithm_name()));
    let transport =
        RemoteCardTransport::new(REMOTE_SYNTHETIC_ATR.to_vec(), key.pair_id, key.record);
    let result = match transport.execute_operation(&operation) {
        Ok(result) => result,
        Err(error) => {
            Log::dbg(&format!("KSP: SignHash: remote operation failed: {error}"));
            return if error.contains("denied") {
                NTE_USER_CANCELLED
            } else {
                NTE_FAIL
            };
        }
    };
    let CardOperationResult::Signature(signature) = result else {
        Log::dbg("KSP: SignHash: remote operation returned no signature");
        return NTE_FAIL;
    };
    let encoded = match key.kind {
        KeyKind::EcP256 | KeyKind::EcP384 => {
            remote_ecdsa_to_p1363(&signature, key.kind.element_bytes())
        }
        KeyKind::Rsa { .. } => rsa_signature_to_width(&signature, key.kind.element_bytes()),
    };
    let Some(encoded) = encoded else {
        Log::dbg("KSP: SignHash: remote signature has an unexpected length");
        return NTE_FAIL;
    };
    // SAFETY: the output triple is the caller's.
    unsafe { write_output(pbSignature, cbSignature, pcbResult, &encoded) }
}

// --- entries this read-only provider does not offer ----------------------

unsafe extern "system" fn CreatePersistedKey(
    _hProvider: NCRYPT_PROV_HANDLE,
    _phKey: *mut NCRYPT_KEY_HANDLE,
    _pszAlgId: PCWSTR,
    _pszKeyName: PCWSTR,
    _dwLegacyKeySpec: u32,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn FinalizeKey(
    _hProvider: NCRYPT_PROV_HANDLE,
    _hKey: NCRYPT_KEY_HANDLE,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn DeleteKey(
    _hProvider: NCRYPT_PROV_HANDLE,
    _hKey: NCRYPT_KEY_HANDLE,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn Encrypt(
    _hProvider: NCRYPT_PROV_HANDLE,
    _hKey: NCRYPT_KEY_HANDLE,
    _pbInput: *const u8,
    _cbInput: u32,
    _pPaddingInfo: *const c_void,
    _pbOutput: *mut u8,
    _cbOutput: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn Decrypt(
    _hProvider: NCRYPT_PROV_HANDLE,
    _hKey: NCRYPT_KEY_HANDLE,
    _pbInput: *const u8,
    _cbInput: u32,
    _pPaddingInfo: *const c_void,
    _pbOutput: *mut u8,
    _cbOutput: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn ImportKey(
    _hProvider: NCRYPT_PROV_HANDLE,
    _hImportKey: NCRYPT_KEY_HANDLE,
    _pszBlobType: PCWSTR,
    _pParameterList: *const BCryptBufferDesc,
    _phKey: *mut NCRYPT_KEY_HANDLE,
    _pbData: *const u8,
    _cbData: u32,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn VerifySignature(
    _hProvider: NCRYPT_PROV_HANDLE,
    _hKey: NCRYPT_KEY_HANDLE,
    _pPaddingInfo: *const c_void,
    _pbHashValue: *const u8,
    _cbHashValue: u32,
    _pbSignature: *const u8,
    _cbSignature: u32,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn PromptUser(
    _hProvider: NCRYPT_PROV_HANDLE,
    _hKey: NCRYPT_KEY_HANDLE,
    _pszOperation: PCWSTR,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn NotifyChangeKey(
    _hProvider: NCRYPT_PROV_HANDLE,
    _phEvent: *mut HANDLE,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn SecretAgreement(
    _hProvider: NCRYPT_PROV_HANDLE,
    _hPrivKey: NCRYPT_KEY_HANDLE,
    _hPubKey: NCRYPT_KEY_HANDLE,
    _phAgreedSecret: *mut NCRYPT_SECRET_HANDLE,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn DeriveKey(
    _hProvider: NCRYPT_PROV_HANDLE,
    _hSharedSecret: NCRYPT_SECRET_HANDLE,
    _pwszKDF: PCWSTR,
    _pParameterList: *const BCryptBufferDesc,
    _pbDerivedKey: *mut u8,
    _cbDerivedKey: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn FreeSecret(
    _hProvider: NCRYPT_PROV_HANDLE,
    _hSharedSecret: NCRYPT_SECRET_HANDLE,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn KeyDerivation(
    _hProvider: NCRYPT_PROV_HANDLE,
    _hKey: NCRYPT_KEY_HANDLE,
    _pParameterList: *const BCryptBufferDesc,
    _pbDerivedKey: *mut u8,
    _cbDerivedKey: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn CreateClaim(
    _hProv: NCRYPT_PROV_HANDLE,
    _hSubjectKey: NCRYPT_KEY_HANDLE,
    _hAuthorityKey: NCRYPT_KEY_HANDLE,
    _dwClaimType: u32,
    _pParameterList: *const BCryptBufferDesc,
    _pbClaimBlob: *mut u8,
    _cbClaimBlob: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

unsafe extern "system" fn VerifyClaim(
    _hProv: NCRYPT_PROV_HANDLE,
    _hSubjectKey: NCRYPT_KEY_HANDLE,
    _hAuthorityKey: NCRYPT_KEY_HANDLE,
    _dwClaimType: u32,
    _pParameterList: *const BCryptBufferDesc,
    _pbClaimBlob: *const u8,
    _cbClaimBlob: u32,
    _pOutput: *mut BCryptBufferDesc,
    _dwFlags: u32,
) -> HRESULT {
    NTE_NOT_SUPPORTED
}

static FUNCTION_TABLE: NCRYPT_KEY_STORAGE_FUNCTION_TABLE = NCRYPT_KEY_STORAGE_FUNCTION_TABLE {
    Version: BCRYPT_INTERFACE_VERSION {
        MajorVersion: 1,
        MinorVersion: 0,
    },
    OpenProvider: Some(OpenProvider),
    OpenKey: Some(OpenKey),
    CreatePersistedKey: Some(CreatePersistedKey),
    GetProviderProperty: Some(GetProviderProperty),
    GetKeyProperty: Some(GetKeyProperty),
    SetProviderProperty: Some(SetProviderProperty),
    SetKeyProperty: Some(SetKeyProperty),
    FinalizeKey: Some(FinalizeKey),
    DeleteKey: Some(DeleteKey),
    FreeProvider: Some(FreeProvider),
    FreeKey: Some(FreeKey),
    FreeBuffer: Some(FreeBuffer),
    Encrypt: Some(Encrypt),
    Decrypt: Some(Decrypt),
    IsAlgSupported: Some(IsAlgSupported),
    EnumAlgorithms: Some(EnumAlgorithms),
    EnumKeys: Some(EnumKeys),
    ImportKey: Some(ImportKey),
    ExportKey: Some(ExportKey),
    SignHash: Some(SignHash),
    VerifySignature: Some(VerifySignature),
    PromptUser: Some(PromptUser),
    NotifyChangeKey: Some(NotifyChangeKey),
    SecretAgreement: Some(SecretAgreement),
    DeriveKey: Some(DeriveKey),
    FreeSecret: Some(FreeSecret),
    KeyDerivation: Some(KeyDerivation),
    CreateClaim: Some(CreateClaim),
    VerifyClaim: Some(VerifyClaim),
};

/// The entry point `ncrypt.dll` resolves in a registered key storage
/// provider's image.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn GetKeyStorageInterface(
    _pszProviderName: PCWSTR,
    ppFunctionTable: *mut *mut NCRYPT_KEY_STORAGE_FUNCTION_TABLE,
    _dwFlags: u32,
) -> HRESULT {
    if ppFunctionTable.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    // SAFETY: checked non-null; the table is immutable static data that
    // ncrypt.dll only reads.
    unsafe { *ppFunctionTable = (&raw const FUNCTION_TABLE).cast_mut() };
    S_OK
}
