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

//! Narrow Windows Credential Manager boundary for contactless card access.
//!
//! Only the six-digit CAN is stored. PIN1, PIN2, recovery codes, certificate
//! private material, and PACE session keys never enter this store. A credential
//! is keyed by the complete PC/SC contactless ATR, matching the Apple port's
//! pre-PACE lookup model: an ATR identifies a card family, while the protected
//! card serial becomes available only after the CAN has established PACE.

#![cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "CredReadW, CredWriteW, CredDeleteW, CredFree, CryptProtectData, CryptUnprotectData, LocalFree, and the certificate store calls are the small Windows FFI boundary"
    )
)]

use core::fmt;

#[cfg(windows)]
use refineid_lib_core::can::CAN_DIGITS;
use refineid_lib_core::can::Can;

#[cfg(windows)]
use zeroize::Zeroize as _;

mod certstore;
mod pairing;

pub use certstore::{
    BROWSER_KEY_PREFIX, KEY_STORAGE_PROVIDER, browser_key_name, browser_key_pair_id,
};
#[cfg(windows)]
pub use certstore::{install_browser_certificate, remove_browser_certificates};
pub use pairing::{ProtectedPairingStore, delete_pairing_set};

/// Maximum PC/SC ATR size accepted by the shared credential namespace.
///
/// The Card Module ABI currently caps ATRs at 33 bytes. A slightly larger
/// bound leaves the store reusable by PC/SC adapters without accepting an
/// unbounded target name.
#[cfg(any(windows, test))]
const MAX_ATR_BYTES: usize = 64;

/// Prefix reserved for `RefineID` generic credentials.
#[cfg(any(windows, test))]
const TARGET_PREFIX: &str = "RefineID_NFC_ATR_";

/// A Windows Credential Manager failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStoreError {
    /// An empty ATR cannot identify a contactless card family.
    EmptyAtr,
    /// The ATR exceeded the bounded credential-key input.
    AtrTooLong {
        /// Actual ATR length.
        got: usize,
    },
    /// Windows rejected a Credential Manager operation.
    Windows {
        /// `GetLastError` value returned by the failing API.
        code: u32,
    },
    /// A stored blob was not a valid six-digit CAN.
    InvalidStoredCan,
    /// A stored pairing-set blob was malformed.
    InvalidStoredPairing,
    /// A pairing record could not be encoded for storage.
    PairingNotEncodable,
    /// Windows rejected a certificate store operation.
    CertificateStore {
        /// `GetLastError` value returned by the failing API.
        code: u32,
    },
    /// DPAPI refused to protect or unprotect the pairing set.
    Protection {
        /// `GetLastError` value returned by the failing API.
        code: u32,
    },
    /// The user's local application data directory is not known.
    ProfileUnavailable,
    /// An unprotected copy of this user's pairing set exists and could not
    /// be deleted.
    UnprotectedCopyRemains,
    /// The protected pairing set file, or the card sightings beside it,
    /// could not be written, read, or removed.
    File {
        /// What the file system reported.
        kind: std::io::ErrorKind,
    },
    /// This build is not running on Windows.
    UnsupportedPlatform,
}

impl CredentialStoreError {
    /// The file-system failure behind a pairing set operation.
    fn file(error: &std::io::Error) -> Self {
        Self::File { kind: error.kind() }
    }
}

impl fmt::Display for CredentialStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAtr => formatter.write_str("contactless ATR cannot be empty"),
            Self::AtrTooLong { got } => {
                write!(formatter, "contactless ATR is too long: {got} bytes")
            }
            Self::Windows { code } => {
                write!(
                    formatter,
                    "Windows Credential Manager failed with code {code}"
                )
            }
            Self::InvalidStoredCan => {
                formatter.write_str("stored contactless credential is malformed")
            }
            Self::InvalidStoredPairing => formatter.write_str("stored pairing set is malformed"),
            Self::PairingNotEncodable => {
                formatter.write_str("a pairing record could not be encoded for storage")
            }
            Self::CertificateStore { code } => {
                write!(
                    formatter,
                    "Windows certificate store failed with code {code}"
                )
            }
            Self::Protection { code } => {
                write!(formatter, "DPAPI failed with code {code}")
            }
            Self::ProfileUnavailable => {
                formatter.write_str("the user's local application data directory is unknown")
            }
            Self::UnprotectedCopyRemains => {
                formatter.write_str("an unprotected copy of the pairing set could not be deleted")
            }
            Self::File { kind } => write!(formatter, "pairing set file: {kind}"),
            Self::UnsupportedPlatform => {
                formatter.write_str("Windows Credential Manager is unavailable")
            }
        }
    }
}

impl core::error::Error for CredentialStoreError {}

#[cfg(windows)]
struct CredentialGuard(*mut windows_sys::Win32::Security::Credentials::CREDENTIALW);

#[cfg(windows)]
impl Drop for CredentialGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::Security::Credentials::CredFree;

        // SAFETY: CredReadW returned this allocation. When it has the only
        // valid CAN shape, its writable six-byte blob is cleared before the
        // enclosing Windows allocation is freed exactly once.
        unsafe {
            let credential = &mut *self.0;
            if usize::try_from(credential.CredentialBlobSize) == Ok(CAN_DIGITS)
                && !credential.CredentialBlob.is_null()
            {
                core::slice::from_raw_parts_mut(credential.CredentialBlob, CAN_DIGITS).zeroize();
            }
            CredFree(self.0.cast());
        }
    }
}

/// Save a validated CAN for the PC/SC contactless ATR.
///
/// The generic credential is scoped to the current Windows user's credential
/// set and persists across that user's logon sessions. It is written only
/// after the caller has proved the CAN against the card with PACE.
///
/// # Errors
/// Invalid ATR input or a Windows Credential Manager failure.
#[cfg(windows)]
pub fn save_can(atr: &[u8], can: &Can) -> Result<(), CredentialStoreError> {
    use core::ptr;

    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW,
    };

    let mut target = target_name_wide(atr)?;
    let mut blob = can.as_bytes().to_vec();
    let blob_size =
        u32::try_from(blob.len()).map_err(|_error| CredentialStoreError::InvalidStoredCan)?;
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: blob_size,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        Comment: ptr::null_mut(),
        TargetAlias: ptr::null_mut(),
        UserName: ptr::null_mut(),
        ..CREDENTIALW::default()
    };

    // SAFETY: `credential` and every pointer it contains remain valid for the
    // duration of the call. `CredentialBlobSize` is the exact six-byte blob.
    let written = unsafe { CredWriteW(&raw const credential, 0) };
    // SAFETY: `GetLastError` must be captured before any other Windows call.
    let error_code = if written == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    blob.zeroize();
    target.zeroize();
    if written == 0 {
        return Err(CredentialStoreError::Windows { code: error_code });
    }
    Ok(())
}

/// Read the CAN stored for the PC/SC contactless ATR.
///
/// `Ok(None)` means the card family has not been primed for this Windows user.
///
/// # Errors
/// Invalid ATR input, a malformed stored blob, or a Windows Credential Manager
/// failure other than "not found".
#[cfg(windows)]
pub fn read_can(atr: &[u8]) -> Result<Option<Can>, CredentialStoreError> {
    use core::ptr;

    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
    use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CREDENTIALW, CredReadW};

    let mut target = target_name_wide(atr)?;
    let mut raw_credential = ptr::null_mut::<CREDENTIALW>();
    // SAFETY: `target` is NUL-terminated and `raw_credential` is a valid out
    // pointer. A successful allocation is released by `CredentialGuard`.
    let read = unsafe {
        CredReadW(
            target.as_ptr(),
            CRED_TYPE_GENERIC,
            0,
            &raw mut raw_credential,
        )
    };
    // SAFETY: `GetLastError` must be captured before any other Windows call.
    let error_code = if read == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    target.zeroize();
    if read == 0 {
        return if error_code == ERROR_NOT_FOUND {
            Ok(None)
        } else {
            Err(CredentialStoreError::Windows { code: error_code })
        };
    }
    if raw_credential.is_null() {
        return Err(CredentialStoreError::InvalidStoredCan);
    }

    let guard = CredentialGuard(raw_credential);
    // SAFETY: the guard owns a non-null CREDENTIALW returned by CredReadW.
    let credential = unsafe { &*guard.0 };
    let blob_len = usize::try_from(credential.CredentialBlobSize)
        .map_err(|_error| CredentialStoreError::InvalidStoredCan)?;
    if blob_len != CAN_DIGITS || credential.CredentialBlob.is_null() {
        return Err(CredentialStoreError::InvalidStoredCan);
    }
    // SAFETY: Windows reports `CredentialBlobSize` readable bytes. The exact
    // six-byte bound was checked before constructing the slice.
    let blob = unsafe { core::slice::from_raw_parts(credential.CredentialBlob, blob_len) };
    let mut digits = [0_u8; CAN_DIGITS];
    digits.copy_from_slice(blob);
    let parsed = core::str::from_utf8(&digits)
        .ok()
        .and_then(|value| Can::new(value).ok())
        .ok_or(CredentialStoreError::InvalidStoredCan);
    digits.zeroize();
    parsed.map(Some)
}

/// Delete the CAN stored for the PC/SC contactless ATR.
///
/// Deleting an absent item succeeds, making revocation idempotent.
///
/// # Errors
/// Invalid ATR input or a Windows Credential Manager failure other than
/// "not found".
#[cfg(windows)]
pub fn delete_can(atr: &[u8]) -> Result<(), CredentialStoreError> {
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
    use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CredDeleteW};

    let mut target = target_name_wide(atr)?;
    // SAFETY: `target` is a valid NUL-terminated UTF-16 string for the call.
    let deleted = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
    // SAFETY: `GetLastError` must be captured before any other Windows call.
    let error_code = if deleted == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    target.zeroize();
    if deleted != 0 {
        return Ok(());
    }
    if error_code == ERROR_NOT_FOUND {
        Ok(())
    } else {
        Err(CredentialStoreError::Windows { code: error_code })
    }
}

#[cfg(not(windows))]
/// Non-Windows builds expose the same API for workspace type checking.
///
/// # Errors
/// Always fails: the Windows Credential Manager is unavailable off Windows.
pub const fn save_can(_atr: &[u8], _can: &Can) -> Result<(), CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

#[cfg(not(windows))]
/// Non-Windows builds expose the same API for workspace type checking.
///
/// # Errors
/// Always fails: the Windows Credential Manager is unavailable off Windows.
pub const fn read_can(_atr: &[u8]) -> Result<Option<Can>, CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

#[cfg(not(windows))]
/// Non-Windows builds expose the same API for workspace type checking.
///
/// # Errors
/// Always fails: the Windows Credential Manager is unavailable off Windows.
pub const fn delete_can(_atr: &[u8]) -> Result<(), CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

#[cfg(windows)]
fn target_name_wide(atr: &[u8]) -> Result<Vec<u16>, CredentialStoreError> {
    let target = target_name(atr)?;
    Ok(target.encode_utf16().chain(core::iter::once(0)).collect())
}

#[cfg(any(windows, test))]
fn target_name(atr: &[u8]) -> Result<String, CredentialStoreError> {
    if atr.is_empty() {
        return Err(CredentialStoreError::EmptyAtr);
    }
    if atr.len() > MAX_ATR_BYTES {
        return Err(CredentialStoreError::AtrTooLong { got: atr.len() });
    }
    let mut target = String::with_capacity(TARGET_PREFIX.len() + atr.len().saturating_mul(2));
    target.push_str(TARGET_PREFIX);
    for byte in atr {
        use core::fmt::Write as _;

        write!(&mut target, "{byte:02X}")
            .map_err(|_error| CredentialStoreError::AtrTooLong { got: atr.len() })?;
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::{CredentialStoreError, MAX_ATR_BYTES, TARGET_PREFIX, target_name};

    #[test]
    fn target_name_is_bounded_uppercase_hex() {
        assert_eq!(
            target_name(&[0x3B, 0x80, 0x01]).expect("valid ATR"),
            format!("{TARGET_PREFIX}3B8001")
        );
    }

    #[test]
    fn target_name_rejects_empty_atr() {
        assert_eq!(target_name(&[]), Err(CredentialStoreError::EmptyAtr));
    }

    #[test]
    fn target_name_rejects_oversize_atr() {
        let atr = vec![0_u8; MAX_ATR_BYTES + 1];
        assert_eq!(
            target_name(&atr),
            Err(CredentialStoreError::AtrTooLong {
                got: MAX_ATR_BYTES + 1
            })
        );
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "writes and immediately removes one synthetic Windows credential"]
    fn windows_credential_manager_round_trip() {
        use refineid_lib_core::can::Can;

        use super::{delete_can, read_can, save_can};

        const SYNTHETIC_ATR: [u8; MAX_ATR_BYTES] = [0xA5; MAX_ATR_BYTES];

        struct Cleanup;

        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ignored = delete_can(&SYNTHETIC_ATR);
            }
        }

        delete_can(&SYNTHETIC_ATR).expect("synthetic credential cleanup before test");
        let _cleanup = Cleanup;
        let can = Can::new("135790").expect("synthetic CAN");
        save_can(&SYNTHETIC_ATR, &can).expect("save synthetic credential");
        assert_eq!(
            read_can(&SYNTHETIC_ATR).expect("read synthetic credential"),
            Some(can)
        );
        delete_can(&SYNTHETIC_ATR).expect("delete synthetic credential");
        assert_eq!(
            read_can(&SYNTHETIC_ATR).expect("confirm synthetic credential deletion"),
            None
        );
    }
}
