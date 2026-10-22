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

//! FFI types for the Microsoft Card Module API.
//!
//! Header reference: `cardmod.h` from the Windows Driver Kit.
//! Specification: Microsoft Smart Card Minidriver Specification v7+.
//!
//! These types must match the Windows ABI exactly. The struct field
//! order, sizes, and calling convention (`extern "system"`) are
//! load-bearing -- getting any wrong crashes the smart-card resource
//! manager process.

// ABI mirror of `cardmod.h`: the Windows header is the authority for
// these names and shapes. The C names are verbatim (`non_snake_case` /
// `non_camel_case_types`) and the full ABI surface is declared whether
// or not it is wired yet (`dead_code`). Items are `pub(crate)` (the
// cdylib's real exports are the `extern "system"` entry points, not
// these), which keeps them off the crate's public docs.
#![expect(
    nonstandard_style,
    reason = "Windows Card Module FFI mirrors cardmod.h verbatim; if this module stops carrying the ABI spellings, the expectation should go noisy so the exemption can be revisited"
)]
#![expect(
    clippy::redundant_pub_crate,
    reason = "The FFI surface is intentionally crate-internal but spelled uniformly as pub(crate) across the ABI mirror; clippy's private-module simplification is noise here"
)]
#![expect(
    clippy::upper_case_acronyms,
    reason = "Windows ABI typedef names intentionally preserve the WDK spellings (DWORD, LPWSTR, SCARDHANDLE, ...) so the FFI mirror stays grep-compatible with cardmod.h"
)]

use std::os::raw::c_void;

// ---------- basic types ----------------------------------------------------

pub(crate) type DWORD = u32;
pub(crate) type BYTE = u8;
pub(crate) type WORD = u16;
pub(crate) type BOOL = i32;
pub(crate) type LPWSTR = *mut u16;
pub(crate) type LPCWSTR = *const u16;
pub(crate) type LPSTR = *mut u8;
pub(crate) type LPCSTR = *const u8;
pub(crate) type PBYTE = *mut BYTE;
pub(crate) type LPVOID = *mut c_void;
pub(crate) type PVOID = *mut c_void;
pub(crate) type PDWORD = *mut DWORD;
pub(crate) type HANDLE = *mut c_void;
pub(crate) type CARD_KEY_HANDLE = usize; // ULONG_PTR
pub(crate) type SCARDCONTEXT = usize; // ULONG_PTR
pub(crate) type SCARDHANDLE = usize; // ULONG_PTR

// ---------- SCard / NTSTATUS error codes -----------------------------------

pub(crate) const SCARD_S_SUCCESS: DWORD = 0;
pub(crate) const SCARD_F_INTERNAL_ERROR: DWORD = 0x8010_0001;
pub(crate) const SCARD_E_CANCELLED: DWORD = 0x8010_0002;
pub(crate) const SCARD_E_INVALID_HANDLE: DWORD = 0x8010_0003;
pub(crate) const SCARD_E_INVALID_PARAMETER: DWORD = 0x8010_0004;
pub(crate) const SCARD_E_NO_MEMORY: DWORD = 0x8010_0006;
pub(crate) const SCARD_E_INSUFFICIENT_BUFFER: DWORD = 0x8010_0008;
pub(crate) const SCARD_E_UNKNOWN_CARD: DWORD = 0x8010_000D;
pub(crate) const SCARD_E_INVALID_VALUE: DWORD = 0x8010_0011;
pub(crate) const SCARD_W_UNRESPONSIVE_CARD: DWORD = 0x8010_0066;
pub(crate) const SCARD_W_UNPOWERED_CARD: DWORD = 0x8010_0067;
pub(crate) const SCARD_W_RESET_CARD: DWORD = 0x8010_0068;
pub(crate) const SCARD_W_REMOVED_CARD: DWORD = 0x8010_0069;
pub(crate) const SCARD_W_WRONG_CHV: DWORD = 0x8010_006B;
pub(crate) const SCARD_W_CHV_BLOCKED: DWORD = 0x8010_006C;
pub(crate) const SCARD_E_DIR_NOT_FOUND: DWORD = 0x8010_0023;
pub(crate) const SCARD_E_FILE_NOT_FOUND: DWORD = 0x8010_0024;
pub(crate) const SCARD_E_NO_FILE: DWORD = 0x8010_0024;
pub(crate) const SCARD_E_NO_DIR: DWORD = 0x8010_0023;
pub(crate) const SCARD_E_NO_KEY_CONTAINER: DWORD = 0x8010_0030;
pub(crate) const SCARD_E_UNSUPPORTED_FEATURE: DWORD = 0x8010_001F;
pub(crate) const SCARD_E_NO_ACCESS: DWORD = 0x8010_0027;
pub(crate) const SCARD_E_WRITE_TOO_MANY: DWORD = 0x8010_0028;
pub(crate) const SCARD_E_NO_MORE_AVAILABLE: DWORD = 0x8010_0022;
// Microsoft Learn, "Authentication Return Values", Smart Card Return
// Values (Scarderr.h).
/// "The action was canceled by the user."
pub(crate) const SCARD_W_CANCELLED_BY_USER: DWORD = 0x8010_006E;
/// "A communications error with the smart card has been detected."
pub(crate) const SCARD_E_COMM_DATA_LOST: DWORD = 0x8010_002F;
/// "The specified reader is not currently available for use."
pub(crate) const SCARD_E_READER_UNAVAILABLE: DWORD = 0x8010_0017;
pub(crate) const NTE_NO_KEY: DWORD = 0x8009_000D;
pub(crate) const NTE_BAD_KEYSET: DWORD = 0x8009_0016;

// ---------- CARD_DATA version constants ------------------------------------

pub(crate) const CARD_DATA_CURRENT_VERSION: DWORD = 7;
pub(crate) const CARD_DATA_VERSION_FOUR: DWORD = 4;
pub(crate) const CARD_DATA_VERSION_FIVE: DWORD = 5;
pub(crate) const CARD_DATA_VERSION_SIX: DWORD = 6;
pub(crate) const CARD_DATA_VERSION_SEVEN: DWORD = 7;

// ---------- card capabilities flags ----------------------------------------

#[repr(C)]
#[derive(Default)]
pub(crate) struct CARD_CAPABILITIES {
    pub(crate) dwVersion: DWORD,
    pub(crate) fCertificateCompression: BOOL,
    pub(crate) fKeyGen: BOOL,
}
pub(crate) const CARD_CAPABILITIES_CURRENT_VERSION: DWORD = 1;

#[repr(C)]
pub(crate) struct CONTAINER_INFO {
    pub(crate) dwVersion: DWORD,
    pub(crate) dwReserved: DWORD,
    pub(crate) cbSigPublicKey: DWORD,
    pub(crate) pbSigPublicKey: PBYTE,
    pub(crate) cbKeyExPublicKey: DWORD,
    pub(crate) pbKeyExPublicKey: PBYTE,
}
pub(crate) const CONTAINER_INFO_CURRENT_VERSION: DWORD = 1;

#[repr(C)]
pub(crate) struct CARD_FREE_SPACE_INFO {
    pub(crate) dwVersion: DWORD,
    pub(crate) dwBytesAvailable: DWORD,
    pub(crate) dwKeyContainersAvailable: DWORD,
    pub(crate) dwMaxKeyContainers: DWORD,
}
pub(crate) const CARD_FREE_SPACE_INFO_CURRENT_VERSION: DWORD = 1;

#[repr(C)]
pub(crate) struct CARD_KEY_SIZES {
    pub(crate) dwVersion: DWORD,
    pub(crate) dwMinimumBitlen: DWORD,
    pub(crate) dwDefaultBitlen: DWORD,
    pub(crate) dwMaximumBitlen: DWORD,
    pub(crate) dwIncrementalBitlen: DWORD,
}
pub(crate) const CARD_KEY_SIZES_CURRENT_VERSION: DWORD = 1;

#[repr(C)]
pub(crate) struct CARD_FILE_INFO {
    pub(crate) dwVersion: DWORD,
    pub(crate) cbFileSize: DWORD,
    pub(crate) AccessCondition: DWORD,
}
pub(crate) const CARD_FILE_INFO_CURRENT_VERSION: DWORD = 1;

#[repr(C)]
pub(crate) struct PIN_INFO {
    pub(crate) dwVersion: DWORD,
    pub(crate) PinType: DWORD,
    pub(crate) PinPurpose: DWORD,
    pub(crate) dwChangePermission: DWORD,
    pub(crate) dwUnblockPermission: DWORD,
    pub(crate) PinCachePolicy: PIN_CACHE_POLICY,
    pub(crate) dwFlags: DWORD,
}
pub(crate) const PIN_INFO_CURRENT_VERSION: DWORD = 6;
pub(crate) const PIN_INFO_REQUIRE_SECURE_ENTRY: DWORD = 1;
pub(crate) const CARD_PIN_INFO_NO_PROMPT_ON_SIGN: DWORD = 0x0000_0002;

#[repr(C)]
pub(crate) struct PIN_CACHE_POLICY {
    pub(crate) dwVersion: DWORD,
    pub(crate) PinCachePolicyType: DWORD,
    pub(crate) dwPinCachePolicyInfo: DWORD,
}

pub(crate) const CARD_AUTHENTICATE_GENERATE_SESSION_PIN: DWORD = 0x1000_0000;
pub(crate) const CARD_PIN_SILENT_CONTEXT: DWORD = 0x0000_0040;
pub(crate) const CARD_PIN_STRENGTH_PLAINTEXT: DWORD = 0x0000_0001;
pub(crate) const CARD_PIN_STRENGTH_SESSION_PIN: DWORD = 0x0000_0002;
pub(crate) const PIN_CACHE_POLICY_CURRENT_VERSION: DWORD = 6;

// PIN id constants used by Base CSP
pub(crate) const ROLE_USER: DWORD = 1;
pub(crate) const ROLE_ADMIN: DWORD = 2;
pub(crate) const PIN_SET_NONE: DWORD = 0x00;
pub(crate) const PIN_SET_ALL_ROLES: DWORD = 0xFF;
pub(crate) const ROLE_EVERYONE: DWORD = 0;

// CardRSADecrypt info structure -- Base CSP populates this and hands
// it to the minidriver. Layout per cardmod.h CARD_RSA_DECRYPT_INFO.
#[repr(C)]
pub(crate) struct CARD_RSA_DECRYPT_INFO {
    pub(crate) dwVersion: DWORD,
    pub(crate) bContainerIndex: BYTE,
    pub(crate) dwKeySpec: DWORD,
    pub(crate) pbData: PBYTE, // in/out: ciphertext, replaced with plaintext
    pub(crate) cbData: DWORD, // length of pbData buffer
    pub(crate) pPaddingInfo: PVOID, // not used for v1
    pub(crate) dwPaddingType: DWORD,
}
pub(crate) const CARD_RSA_DECRYPT_INFO_BASIC_VERSION: DWORD = 1;
pub(crate) const CARD_RSA_DECRYPT_INFO_CURRENT_VERSION: DWORD = 2;

// CardSignData info structure
#[repr(C)]
pub(crate) struct CARD_SIGNING_INFO {
    pub(crate) dwVersion: DWORD,
    pub(crate) bContainerIndex: BYTE,
    pub(crate) dwKeySpec: DWORD,
    pub(crate) dwSigningFlags: DWORD,
    pub(crate) aiHashAlg: DWORD, // ALG_ID
    pub(crate) pbData: PBYTE,
    pub(crate) cbData: DWORD,
    pub(crate) pbSignedData: PBYTE,
    pub(crate) cbSignedData: DWORD,
    pub(crate) pPaddingInfo: PVOID,
    pub(crate) dwPaddingType: DWORD,
}
pub(crate) const CARD_SIGNING_INFO_BASIC_VERSION: DWORD = 1;
pub(crate) const CARD_SIGNING_INFO_CURRENT_VERSION: DWORD = 2;

// dwKeySpec values
pub(crate) const AT_KEYEXCHANGE: DWORD = 1;
pub(crate) const AT_SIGNATURE: DWORD = 2;
pub(crate) const AT_ECDHE_P256: DWORD = 0xAE06;
pub(crate) const AT_ECDHE_P384: DWORD = 0xAE07;
pub(crate) const AT_ECDHE_P521: DWORD = 0xAE08;
pub(crate) const AT_ECDSA_P256: DWORD = 0xAE09;
pub(crate) const AT_ECDSA_P384: DWORD = 0xAE0A;
pub(crate) const AT_ECDSA_P521: DWORD = 0xAE0B;

// padding-type values
pub(crate) const CARD_PADDING_NONE: DWORD = 0x0000_0001;
pub(crate) const CARD_PADDING_PKCS1: DWORD = 0x0000_0002;
pub(crate) const CARD_PADDING_PSS: DWORD = 0x0000_0004;
pub(crate) const CARD_PADDING_OAEP: DWORD = 0x0000_0008;
pub(crate) const CARD_BUFFER_SIZE_ONLY: DWORD = 0x2000_0000;
pub(crate) const CARD_PADDING_INFO_PRESENT: DWORD = 0x4000_0000;
pub(crate) const CARD_CIPHER_OPERATION: DWORD = 0x0000_0001;
pub(crate) const CARD_ASYMMETRIC_OPERATION: DWORD = 0x0000_0002;

#[repr(C)]
pub(crate) struct BCRYPT_PKCS1_PADDING_INFO {
    pub(crate) pszAlgId: LPCWSTR,
}

// BCRYPT_PSS_PADDING_INFO -- points to via CARD_SIGNING_INFO.pPaddingInfo
// when dwPaddingType == CARD_PADDING_PSS. pszAlgId is a UTF-16
// algorithm-name string ("SHA256", "SHA384", "SHA512", etc).
#[repr(C)]
pub(crate) struct BCRYPT_PSS_PADDING_INFO {
    pub(crate) pszAlgId: LPCWSTR,
    pub(crate) cbSalt: DWORD,
}

// CARD_BUFFER for ReadFile signature
// (Windows uses PBYTE + PDWORD, no separate type)

// Container index: 0 = default container = AT_SIGNATURE / AT_KEYEXCHANGE
pub(crate) const CARD_DEFAULT_CONTAINER: BYTE = 0;

// ---------- function pointer typedefs --------------------------------------

pub(crate) type PFN_CSP_ALLOC = Option<unsafe extern "system" fn(size: usize) -> PVOID>;
pub(crate) type PFN_CSP_REALLOC = Option<unsafe extern "system" fn(p: PVOID, size: usize) -> PVOID>;
pub(crate) type PFN_CSP_FREE = Option<unsafe extern "system" fn(p: PVOID)>;
pub(crate) type PFN_CSP_CACHE_ADD_FILE = Option<
    unsafe extern "system" fn(
        ctx: PVOID,
        name: LPWSTR,
        flags: DWORD,
        data: PBYTE,
        len: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CSP_CACHE_LOOKUP_FILE = Option<
    unsafe extern "system" fn(
        ctx: PVOID,
        name: LPWSTR,
        flags: DWORD,
        data: *mut PBYTE,
        len: PDWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CSP_CACHE_DELETE_FILE =
    Option<unsafe extern "system" fn(ctx: PVOID, name: LPWSTR, flags: DWORD) -> DWORD>;
pub(crate) type PFN_CSP_PAD_DATA = Option<
    unsafe extern "system" fn(
        info: PVOID,
        data: PBYTE,
        dataLen: DWORD,
        out: PBYTE,
        outLen: PDWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CSP_UNPAD_DATA = Option<
    unsafe extern "system" fn(
        info: PVOID,
        data: PBYTE,
        dataLen: DWORD,
        out: PBYTE,
        outLen: PDWORD,
    ) -> DWORD,
>;

pub(crate) type PFN_CARD_DELETE_CONTEXT =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA) -> DWORD>;
pub(crate) type PFN_CARD_QUERY_CAPABILITIES =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, caps: *mut CARD_CAPABILITIES) -> DWORD>;
pub(crate) type PFN_CARD_DELETE_CONTAINER =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, container: BYTE, flags: DWORD) -> DWORD>;
pub(crate) type PFN_CARD_CREATE_CONTAINER = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        container: BYTE,
        flags: DWORD,
        keySpec: DWORD,
        keySize: DWORD,
        keyData: PBYTE,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_GET_CONTAINER_INFO = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        container: BYTE,
        flags: DWORD,
        info: *mut CONTAINER_INFO,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_AUTHENTICATE_PIN = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pwszUserId: LPWSTR,
        pbPin: PBYTE,
        cbPin: DWORD,
        pcAttemptsRemaining: PDWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_GET_CHALLENGE = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pbChallenge: *mut PBYTE,
        pcbChallenge: PDWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_AUTHENTICATE_CHALLENGE = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pbResponse: PBYTE,
        cbResponse: DWORD,
        pcAttemptsRemaining: PDWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_UNBLOCK_PIN = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pwszUserId: LPWSTR,
        pbAuthData: PBYTE,
        cbAuth: DWORD,
        pbNewPinData: PBYTE,
        cbNewPin: DWORD,
        cRetries: DWORD,
        dwFlags: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_CHANGE_AUTHENTICATOR = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pwszUserId: LPWSTR,
        pbCurrentAuth: PBYTE,
        cbCurrentAuth: DWORD,
        pbNewAuth: PBYTE,
        cbNewAuth: DWORD,
        cRetries: DWORD,
        dwFlags: DWORD,
        pcAttemptsRemaining: PDWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_DEAUTHENTICATE = Option<
    unsafe extern "system" fn(p: *mut CARD_DATA, pwszUserId: LPWSTR, dwFlags: DWORD) -> DWORD,
>;
pub(crate) type PFN_CARD_CREATE_DIRECTORY = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pszDirectoryName: LPSTR,
        AccessCondition: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_DELETE_DIRECTORY =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, pszDirectoryName: LPSTR) -> DWORD>;
pub(crate) type PFN_CARD_CREATE_FILE = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pszDirectoryName: LPSTR,
        pszFileName: LPSTR,
        cbInitialCreationSize: DWORD,
        AccessCondition: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_READ_FILE = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pszDirectoryName: LPSTR,
        pszFileName: LPSTR,
        dwFlags: DWORD,
        ppbData: *mut PBYTE,
        pcbData: PDWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_WRITE_FILE = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pszDirectoryName: LPSTR,
        pszFileName: LPSTR,
        dwFlags: DWORD,
        pbData: PBYTE,
        cbData: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_DELETE_FILE = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pszDirectoryName: LPSTR,
        pszFileName: LPSTR,
        dwFlags: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_ENUM_FILES = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pszDirectoryName: LPSTR,
        pmszFileNames: *mut LPSTR,
        pdwLen: PDWORD,
        dwFlags: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_GET_FILE_INFO = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pszDirectoryName: LPSTR,
        pszFileName: LPSTR,
        info: *mut CARD_FILE_INFO,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_QUERY_FREE_SPACE = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        dwFlags: DWORD,
        info: *mut CARD_FREE_SPACE_INFO,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_QUERY_KEY_SIZES = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        dwKeySpec: DWORD,
        dwFlags: DWORD,
        info: *mut CARD_KEY_SIZES,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_SIGN_DATA =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, info: *mut CARD_SIGNING_INFO) -> DWORD>;
pub(crate) type PFN_CARD_RSA_DECRYPT =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, info: PVOID) -> DWORD>;
pub(crate) type PFN_CARD_CONSTRUCT_DH_AGREEMENT =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, info: PVOID) -> DWORD>;
pub(crate) type PFN_CARD_DERIVE_KEY =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, info: PVOID) -> DWORD>;
pub(crate) type PFN_CARD_DESTROY_DH_AGREEMENT =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, b: BYTE, flags: DWORD) -> DWORD>;
pub(crate) type PFN_CSP_GET_DH_AGREEMENT = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        hSecretAgreement: PVOID,
        pbSecretAgreementIndex: *mut BYTE,
        dwFlags: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_GET_CHALLENGE_EX = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        PinId: DWORD,
        ppbChallengeData: *mut PBYTE,
        pcbChallengeData: PDWORD,
        dwFlags: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_AUTHENTICATE_EX = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        PinId: DWORD,
        dwFlags: DWORD,
        pbPinData: PBYTE,
        cbPinData: DWORD,
        ppbSessionPin: *mut PBYTE,
        pcbSessionPin: PDWORD,
        pcAttemptsRemaining: PDWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_CHANGE_AUTHENTICATOR_EX = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        dwFlags: DWORD,
        dwAuthenticatingPinId: DWORD,
        pbAuthenticatingPinData: PBYTE,
        cbAuthenticatingPinData: DWORD,
        dwTargetPinId: DWORD,
        pbTargetData: PBYTE,
        cbTargetData: DWORD,
        cRetries: DWORD,
        pcAttemptsRemaining: PDWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_DEAUTHENTICATE_EX =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, PinId: DWORD, dwFlags: DWORD) -> DWORD>;
pub(crate) type PFN_CARD_GET_CONTAINER_PROPERTY = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        bContainerIndex: BYTE,
        wszProperty: LPCWSTR,
        pbData: PBYTE,
        cbData: DWORD,
        pdwDataLen: PDWORD,
        dwFlags: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_SET_CONTAINER_PROPERTY = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        bContainerIndex: BYTE,
        wszProperty: LPCWSTR,
        pbData: PBYTE,
        cbData: DWORD,
        dwFlags: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_GET_PROPERTY = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        wszProperty: LPCWSTR,
        pbData: PBYTE,
        cbData: DWORD,
        pdwDataLen: PDWORD,
        dwFlags: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_SET_PROPERTY = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        wszProperty: LPCWSTR,
        pbData: PBYTE,
        cbData: DWORD,
        dwFlags: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_MD_IMPORT_SESSION_KEY =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, info: PVOID) -> DWORD>;
pub(crate) type PFN_MD_ENCRYPT_DATA =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, info: PVOID) -> DWORD>;
pub(crate) type PFN_CARD_IMPORT_SESSION_KEY =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, info: PVOID) -> DWORD>;
pub(crate) type PFN_CARD_GET_SHARED_KEY_HANDLE =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, info: PVOID) -> DWORD>;
pub(crate) type PFN_CARD_GET_ALGORITHM_PROPERTY = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        pwszAlgId: LPCWSTR,
        pwszProperty: LPCWSTR,
        pbData: PBYTE,
        cbData: DWORD,
        pdwDataLen: PDWORD,
        dwFlags: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_GET_KEY_PROPERTY = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        hKey: CARD_KEY_HANDLE,
        pwszProperty: LPCWSTR,
        pbData: PBYTE,
        cbData: DWORD,
        pdwDataLen: PDWORD,
        dwFlags: DWORD,
    ) -> DWORD,
>;
pub(crate) type PFN_CARD_SET_KEY_PROPERTY =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, info: PVOID) -> DWORD>;
pub(crate) type PFN_CARD_DESTROY_KEY =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, info: PVOID) -> DWORD>;
pub(crate) type PFN_CARD_PROCESS_ENCRYPTED_DATA =
    Option<unsafe extern "system" fn(p: *mut CARD_DATA, info: PVOID) -> DWORD>;
pub(crate) type PFN_CARD_CREATE_CONTAINER_EX = Option<
    unsafe extern "system" fn(
        p: *mut CARD_DATA,
        container: BYTE,
        flags: DWORD,
        keySpec: DWORD,
        keySize: DWORD,
        keyData: PBYTE,
        pinId: DWORD,
    ) -> DWORD,
>;

// ---------- CARD_DATA ------------------------------------------------------

#[repr(C)]
pub(crate) struct CARD_DATA {
    // input fields
    pub(crate) dwVersion: DWORD,
    pub(crate) pbAtr: PBYTE,
    pub(crate) cbAtr: DWORD,
    pub(crate) pwszCardName: LPWSTR,
    pub(crate) pfnCspAlloc: PFN_CSP_ALLOC,
    pub(crate) pfnCspReAlloc: PFN_CSP_REALLOC,
    pub(crate) pfnCspFree: PFN_CSP_FREE,
    pub(crate) pfnCspCacheAddFile: PFN_CSP_CACHE_ADD_FILE,
    pub(crate) pfnCspCacheLookupFile: PFN_CSP_CACHE_LOOKUP_FILE,
    pub(crate) pfnCspCacheDeleteFile: PFN_CSP_CACHE_DELETE_FILE,
    pub(crate) pvCacheContext: PVOID,
    pub(crate) pfnCspPadData: PFN_CSP_PAD_DATA,
    pub(crate) hSCardCtx: SCARDCONTEXT,
    pub(crate) hScard: SCARDHANDLE,

    // output field -- minidriver allocates per-context state and stores
    // the pointer here. Note: directly follows hScard with NO padding
    // fields per cardmod.h; getting this wrong shifts every function
    // pointer below.
    pub(crate) pvVendorSpecific: PVOID,

    // function pointer table v4
    pub(crate) pfnCardDeleteContext: PFN_CARD_DELETE_CONTEXT,
    pub(crate) pfnCardQueryCapabilities: PFN_CARD_QUERY_CAPABILITIES,
    pub(crate) pfnCardDeleteContainer: PFN_CARD_DELETE_CONTAINER,
    pub(crate) pfnCardCreateContainer: PFN_CARD_CREATE_CONTAINER,
    pub(crate) pfnCardGetContainerInfo: PFN_CARD_GET_CONTAINER_INFO,
    pub(crate) pfnCardAuthenticatePin: PFN_CARD_AUTHENTICATE_PIN,
    pub(crate) pfnCardGetChallenge: PFN_CARD_GET_CHALLENGE,
    pub(crate) pfnCardAuthenticateChallenge: PFN_CARD_AUTHENTICATE_CHALLENGE,
    pub(crate) pfnCardUnblockPin: PFN_CARD_UNBLOCK_PIN,
    pub(crate) pfnCardChangeAuthenticator: PFN_CARD_CHANGE_AUTHENTICATOR,
    pub(crate) pfnCardDeauthenticate: PFN_CARD_DEAUTHENTICATE,
    pub(crate) pfnCardCreateDirectory: PFN_CARD_CREATE_DIRECTORY,
    pub(crate) pfnCardDeleteDirectory: PFN_CARD_DELETE_DIRECTORY,
    pub(crate) pvUnused3: PVOID,
    pub(crate) pvUnused4: PVOID,
    pub(crate) pfnCardCreateFile: PFN_CARD_CREATE_FILE,
    pub(crate) pfnCardReadFile: PFN_CARD_READ_FILE,
    pub(crate) pfnCardWriteFile: PFN_CARD_WRITE_FILE,
    pub(crate) pfnCardDeleteFile: PFN_CARD_DELETE_FILE,
    pub(crate) pfnCardEnumFiles: PFN_CARD_ENUM_FILES,
    pub(crate) pfnCardGetFileInfo: PFN_CARD_GET_FILE_INFO,
    pub(crate) pfnCardQueryFreeSpace: PFN_CARD_QUERY_FREE_SPACE,
    pub(crate) pfnCardQueryKeySizes: PFN_CARD_QUERY_KEY_SIZES,
    pub(crate) pfnCardSignData: PFN_CARD_SIGN_DATA,
    pub(crate) pfnCardRSADecrypt: PFN_CARD_RSA_DECRYPT,
    pub(crate) pfnCardConstructDHAgreement: PFN_CARD_CONSTRUCT_DH_AGREEMENT,

    // v5 additions
    pub(crate) pfnCardDeriveKey: PFN_CARD_DERIVE_KEY,
    pub(crate) pfnCardDestroyDHAgreement: PFN_CARD_DESTROY_DH_AGREEMENT,
    pub(crate) pfnCspGetDHAgreement: PFN_CSP_GET_DH_AGREEMENT,

    // v6 additions
    pub(crate) pfnCardGetChallengeEx: PFN_CARD_GET_CHALLENGE_EX,
    pub(crate) pfnCardAuthenticateEx: PFN_CARD_AUTHENTICATE_EX,
    pub(crate) pfnCardChangeAuthenticatorEx: PFN_CARD_CHANGE_AUTHENTICATOR_EX,
    pub(crate) pfnCardDeauthenticateEx: PFN_CARD_DEAUTHENTICATE_EX,
    pub(crate) pfnCardGetContainerProperty: PFN_CARD_GET_CONTAINER_PROPERTY,
    pub(crate) pfnCardSetContainerProperty: PFN_CARD_SET_CONTAINER_PROPERTY,
    pub(crate) pfnCardGetProperty: PFN_CARD_GET_PROPERTY,
    pub(crate) pfnCardSetProperty: PFN_CARD_SET_PROPERTY,

    // v7 additions
    pub(crate) pfnCspUnpadData: PFN_CSP_UNPAD_DATA,
    pub(crate) pfnMDImportSessionKey: PFN_MD_IMPORT_SESSION_KEY,
    pub(crate) pfnMDEncryptData: PFN_MD_ENCRYPT_DATA,
    pub(crate) pfnCardImportSessionKey: PFN_CARD_IMPORT_SESSION_KEY,
    pub(crate) pfnCardGetSharedKeyHandle: PFN_CARD_GET_SHARED_KEY_HANDLE,
    pub(crate) pfnCardGetAlgorithmProperty: PFN_CARD_GET_ALGORITHM_PROPERTY,
    pub(crate) pfnCardGetKeyProperty: PFN_CARD_GET_KEY_PROPERTY,
    pub(crate) pfnCardSetKeyProperty: PFN_CARD_SET_KEY_PROPERTY,
    pub(crate) pfnCardDestroyKey: PFN_CARD_DESTROY_KEY,
    pub(crate) pfnCardProcessEncryptedData: PFN_CARD_PROCESS_ENCRYPTED_DATA,
    pub(crate) pfnCardCreateContainerEx: PFN_CARD_CREATE_CONTAINER_EX,
}

// CardGetProperty well-known property NAMES (the wide-string keys
// the Base CSP passes) are deferred to the cardmod port: they have
// no consumer until CardGetProperty/CardSetProperty land, and they
// belong as a closed `CardProperty` enum (one wire string per
// variant) rather than a loose set of `&str` consts. Added there.

pub(crate) const CARD_CACHE_MODE_GLOBAL_CACHE: DWORD = 1;
pub(crate) const CARD_CACHE_MODE_SESSION_ONLY: DWORD = 2;
pub(crate) const CARD_CACHE_MODE_NO_CACHE: DWORD = 3;

pub(crate) const PIN_CACHE_NORMAL: DWORD = 0;
pub(crate) const PIN_CACHE_TIMED: DWORD = 1;
pub(crate) const PIN_CACHE_NONE: DWORD = 2;
pub(crate) const PIN_CACHE_ALWAYS_PROMPT: DWORD = 3;

pub(crate) const AlphaNumericPinType: DWORD = 0;
pub(crate) const ExternalPinType: DWORD = 1;
pub(crate) const ChallengeResponsePinType: DWORD = 2;
pub(crate) const EmptyPinType: DWORD = 3;

pub(crate) const AuthenticationPin: DWORD = 0;
pub(crate) const DigitalSignaturePin: DWORD = 1;
pub(crate) const EncryptionPin: DWORD = 2;
pub(crate) const NonRepudiationPin: DWORD = 3;
pub(crate) const AdministratorPin: DWORD = 4;
pub(crate) const PrimaryCardPin: DWORD = 5;
pub(crate) const UnblockOnlyPin: DWORD = 6;

// CMAP and other constants
pub(crate) const MAX_CONTAINER_NAME_LEN: usize = 39;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CONTAINER_MAP_RECORD {
    pub(crate) wszGuid: [u16; MAX_CONTAINER_NAME_LEN + 1],
    pub(crate) bFlags: BYTE,
    pub(crate) bReserved: BYTE,
    pub(crate) wSigKeySizeBits: WORD,
    pub(crate) wKeyExchangeKeySizeBits: WORD,
}
pub(crate) const CONTAINER_MAP_VALID_CONTAINER: BYTE = 1;
pub(crate) const CONTAINER_MAP_DEFAULT_CONTAINER: BYTE = 2;
