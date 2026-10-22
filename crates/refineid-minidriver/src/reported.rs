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

//! The Card Module entry points a development build installs: each calls
//! the entry point of the same name and reports a failing return to the
//! Windows Event Log through `refineid-dev-errors`.
//!
//! An entry point's answers are not failures: the statuses the Smart Card
//! Minidriver Specification has it return to a caller that probes, such as
//! a file that does not exist, a container index past the last one, an
//! unknown property, or a buffer the size query leaves empty. Release
//! builds install the entry points themselves and compile none of this.

use crate::ffi::{
    BYTE, CARD_CAPABILITIES, CARD_DATA, CARD_FILE_INFO, CARD_FREE_SPACE_INFO, CARD_KEY_SIZES,
    CARD_SIGNING_INFO, CONTAINER_INFO, DWORD, LPCWSTR, LPSTR, LPWSTR, PBYTE, PDWORD, PVOID,
    SCARD_E_DIR_NOT_FOUND, SCARD_E_FILE_NOT_FOUND, SCARD_E_INSUFFICIENT_BUFFER,
    SCARD_E_INVALID_PARAMETER, SCARD_E_NO_KEY_CONTAINER, SCARD_E_UNSUPPORTED_FEATURE,
    SCARD_S_SUCCESS,
};

/// Defines, for each entry point, a wrapper of the same name and signature
/// that reports every status but success and the listed answers.
macro_rules! reported {
    ($($name:ident($($argument:ident: $type:ty),*) answers [$($answer:ident),*];)*) => {
        $(
            #[doc = concat!("[`", stringify!($name), "`](super::", stringify!($name), "), reporting its failures.")]
            pub unsafe extern "system" fn $name($($argument: $type),*) -> DWORD {
                // SAFETY: the caller's contract for this entry point passes
                // on unchanged.
                let status = unsafe { super::$name($($argument),*) };
                if status != SCARD_S_SUCCESS $(&& status != $answer)* {
                    refineid_dev_errors::report!(
                        CardModule,
                        concat!(stringify!($name), " failed"),
                        status status
                    );
                }
                status
            }
        )*
    };
}

reported! {
    CardDeleteContext(pCardData: *mut CARD_DATA) answers [];
    CardQueryCapabilities(pCardData: *mut CARD_DATA, pCaps: *mut CARD_CAPABILITIES) answers [];
    CardGetContainerInfo(
        pCardData: *mut CARD_DATA,
        bContainerIndex: BYTE,
        flags: DWORD,
        pInfo: *mut CONTAINER_INFO
    ) answers [SCARD_E_NO_KEY_CONTAINER];
    CardAuthenticatePin(
        pCardData: *mut CARD_DATA,
        pwszUserId: LPWSTR,
        pbPin: PBYTE,
        cbPin: DWORD,
        pcAttemptsRemaining: PDWORD
    ) answers [];
    CardUnblockPin(
        pCardData: *mut CARD_DATA,
        pwszUserId: LPWSTR,
        pbAuthData: PBYTE,
        cbAuth: DWORD,
        pbNewPinData: PBYTE,
        cbNewPin: DWORD,
        cRetries: DWORD,
        dwFlags: DWORD
    ) answers [];
    CardChangeAuthenticator(
        pCardData: *mut CARD_DATA,
        pwszUserId: LPWSTR,
        pbCurrentAuth: PBYTE,
        cbCurrentAuth: DWORD,
        pbNewAuth: PBYTE,
        cbNewAuth: DWORD,
        cRetries: DWORD,
        dwFlags: DWORD,
        pcAttemptsRemaining: PDWORD
    ) answers [];
    CardDeauthenticate(pCardData: *mut CARD_DATA, pwszUserId: LPWSTR, dwFlags: DWORD) answers [];
    CardReadFile(
        pCardData: *mut CARD_DATA,
        pszDirectoryName: LPSTR,
        pszFileName: LPSTR,
        dwFlags: DWORD,
        ppbData: *mut PBYTE,
        pcbData: PDWORD
    ) answers [SCARD_E_FILE_NOT_FOUND, SCARD_E_DIR_NOT_FOUND];
    CardEnumFiles(
        pCardData: *mut CARD_DATA,
        pszDirectoryName: LPSTR,
        pmszFileNames: *mut LPSTR,
        pdwLen: PDWORD,
        dwFlags: DWORD
    ) answers [SCARD_E_DIR_NOT_FOUND];
    CardGetFileInfo(
        pCardData: *mut CARD_DATA,
        pszDirectoryName: LPSTR,
        pszFileName: LPSTR,
        pInfo: *mut CARD_FILE_INFO
    ) answers [SCARD_E_FILE_NOT_FOUND, SCARD_E_DIR_NOT_FOUND];
    CardQueryFreeSpace(
        pCardData: *mut CARD_DATA,
        dwFlags: DWORD,
        pInfo: *mut CARD_FREE_SPACE_INFO
    ) answers [];
    CardQueryKeySizes(
        pCardData: *mut CARD_DATA,
        dwKeySpec: DWORD,
        dwFlags: DWORD,
        pInfo: *mut CARD_KEY_SIZES
    ) answers [SCARD_E_UNSUPPORTED_FEATURE];
    CardSignData(
        pCardData: *mut CARD_DATA,
        pInfo: *mut CARD_SIGNING_INFO
    ) answers [SCARD_E_INSUFFICIENT_BUFFER];
    CardRSADecrypt(pCardData: *mut CARD_DATA, pInfo: PVOID) answers [];
    CardAuthenticateEx(
        pCardData: *mut CARD_DATA,
        PinId: DWORD,
        dwFlags: DWORD,
        pbPinData: PBYTE,
        cbPinData: DWORD,
        ppbSessionPin: *mut PBYTE,
        pcbSessionPin: PDWORD,
        pcAttemptsRemaining: PDWORD
    ) answers [];
    CardChangeAuthenticatorEx(
        pCardData: *mut CARD_DATA,
        dwFlags: DWORD,
        dwAuthenticatingPinId: DWORD,
        pbAuthenticatingPinData: PBYTE,
        cbAuthenticatingPinData: DWORD,
        dwTargetPinId: DWORD,
        pbTargetData: PBYTE,
        cbTargetData: DWORD,
        cRetries: DWORD,
        pcAttemptsRemaining: PDWORD
    ) answers [];
    CardDeauthenticateEx(pCardData: *mut CARD_DATA, PinId: DWORD, dwFlags: DWORD) answers [];
    CardGetContainerProperty(
        pCardData: *mut CARD_DATA,
        bContainerIndex: BYTE,
        wszProperty: LPCWSTR,
        pbData: PBYTE,
        cbData: DWORD,
        pdwDataLen: PDWORD,
        dwFlags: DWORD
    ) answers [SCARD_E_NO_KEY_CONTAINER, SCARD_E_INSUFFICIENT_BUFFER, SCARD_E_INVALID_PARAMETER];
    CardGetProperty(
        pCardData: *mut CARD_DATA,
        wszProperty: LPCWSTR,
        pbData: PBYTE,
        cbData: DWORD,
        pdwDataLen: PDWORD,
        dwFlags: DWORD
    ) answers [SCARD_E_INSUFFICIENT_BUFFER, SCARD_E_INVALID_PARAMETER];
}
