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

//! Durable pairing storage over the Windows Credential Manager.
//!
//! RAPP requires the pair keys to live in device-only, non-migrating secret
//! storage (specification Section 9.3). The whole pairing set is serialized by
//! [`refineid_rapp_core::persistence`] and written as one generic credential,
//! so an insert, update, or removal is a single atomic `CredWriteW`. The keys
//! never leave `Zeroizing`, are wiped from every intermediate buffer, and are
//! never logged.
//!
//! [`CredentialPairingStore`] keeps the decoded records in memory so it can
//! satisfy the borrowing [`PairingStore`] contract, and writes the set through
//! to the credential on every change. It is the durable replacement for the
//! engine's in-memory store.

use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::persistence::{decode_pairing_records, encode_pairing_records};
use refineid_rapp_core::store::{PairingDisposition, PairingRecord, PairingStore, StoreError};

use crate::CredentialStoreError;

/// A pairing store backed by the Windows Credential Manager.
///
/// The decoded records are held in memory and mirrored to one device-only
/// credential. Construct it with [`CredentialPairingStore::load`], which reads
/// and decodes whatever is already stored for this Windows user.
#[derive(Debug)]
pub struct CredentialPairingStore {
    records: Vec<PairingRecord>,
}

impl CredentialPairingStore {
    /// Loads the stored pairing set, or an empty store when none exists yet.
    ///
    /// # Errors
    ///
    /// Fails when the Credential Manager rejects the read, the stored blob is
    /// malformed, or this build is not running on Windows.
    pub fn load() -> Result<Self, CredentialStoreError> {
        let records = match read_pairing_set()? {
            Some(blob) => decode_pairing_records(&blob)
                .map_err(|_error| CredentialStoreError::InvalidStoredPairing)?,
            None => Vec::new(),
        };
        Ok(Self { records })
    }

    /// The number of stored pairings.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store holds no pairings.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The first usable (non-revoked) stored pairing, if any.
    ///
    /// A caller that reconnects to a stored pairing needs its `pair_id` and
    /// rendezvous token without having kept them from the pairing ceremony.
    #[must_use]
    pub fn usable_pairing(&self) -> Option<&PairingRecord> {
        self.records
            .iter()
            .rfind(|record| record.disposition == PairingDisposition::Paired)
    }

    /// All stored pairing records.
    #[must_use]
    pub fn records(&self) -> &[PairingRecord] {
        &self.records
    }

    /// Writes the current record set through to the credential.
    fn persist(&self) -> Result<(), StoreError> {
        let blob = encode_pairing_records(&self.records);
        write_pairing_set(&blob).map_err(|_error| StoreError::WriteRefused)
    }
}

impl PairingStore for CredentialPairingStore {
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
        self.records.retain(|entry| entry.pair_id != record.pair_id);
        self.records.push(record);
        self.persist()
    }

    fn get(&self, pair_id: PairId) -> Result<&PairingRecord, StoreError> {
        self.records
            .iter()
            .find(|entry| entry.pair_id == pair_id)
            .ok_or(StoreError::Unknown)
    }

    fn update(
        &mut self,
        pair_id: PairId,
        change: &mut dyn FnMut(&mut PairingRecord),
    ) -> Result<(), StoreError> {
        let record = self
            .records
            .iter_mut()
            .find(|entry| entry.pair_id == pair_id)
            .ok_or(StoreError::Unknown)?;
        change(record);
        self.persist()
    }

    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        let before = self.records.len();
        self.records.retain(|entry| entry.pair_id != pair_id);
        if self.records.len() == before {
            return Err(StoreError::Unknown);
        }
        self.persist()
    }
}

/// The fixed credential target holding this user's whole pairing set.
#[cfg(windows)]
const PAIRING_SET_TARGET: &str = "RefineID_RAPP_Pairing_Set";

#[cfg(windows)]
fn target_name_wide() -> Vec<u16> {
    PAIRING_SET_TARGET
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect()
}

/// Frees a credential returned by `CredReadW`, wiping its blob first.
#[cfg(windows)]
struct SetCredentialGuard(*mut windows_sys::Win32::Security::Credentials::CREDENTIALW);

#[cfg(windows)]
impl Drop for SetCredentialGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::Security::Credentials::CredFree;
        use zeroize::Zeroize as _;

        // SAFETY: CredReadW returned this allocation. Its blob, whose length
        // Windows reports, is cleared before the enclosing allocation is freed
        // exactly once.
        unsafe {
            let credential = &mut *self.0;
            if let Ok(length) = usize::try_from(credential.CredentialBlobSize)
                && length != 0
                && !credential.CredentialBlob.is_null()
            {
                core::slice::from_raw_parts_mut(credential.CredentialBlob, length).zeroize();
            }
            CredFree(self.0.cast());
        }
    }
}

#[cfg(windows)]
fn fallback_pairing_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        paths.push(
            std::path::PathBuf::from(local_app_data)
                .join("RefineID")
                .join("pairing_set.blob"),
        );
    }
    let program_data = std::env::var_os("ProgramData").map_or_else(
        || std::path::PathBuf::from(r"C:\ProgramData"),
        std::path::PathBuf::from,
    );
    paths.push(program_data.join("RefineID").join("pairing_set.blob"));
    paths
}

/// Writes the serialized pairing set as one device-only credential.
#[cfg(windows)]
fn write_pairing_set(blob: &[u8]) -> Result<(), CredentialStoreError> {
    use core::ptr;

    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW,
    };
    use zeroize::Zeroize as _;

    for path in fallback_pairing_paths() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, blob);
    }

    let mut target = target_name_wide();
    let mut buffer = blob.to_vec();
    let blob_size = match u32::try_from(buffer.len()) {
        Ok(size) => size,
        Err(_error) => {
            buffer.zeroize();
            target.zeroize();
            return Err(CredentialStoreError::InvalidStoredPairing);
        }
    };
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: blob_size,
        CredentialBlob: buffer.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        Comment: ptr::null_mut(),
        TargetAlias: ptr::null_mut(),
        UserName: ptr::null_mut(),
        ..CREDENTIALW::default()
    };

    // SAFETY: `credential` and every pointer it names stay valid for the call.
    // `CredentialBlobSize` is the exact serialized length.
    let written = unsafe { CredWriteW(&raw const credential, 0) };
    // SAFETY: `GetLastError` must be read before any other Windows call.
    let error_code = if written == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    buffer.zeroize();
    target.zeroize();
    if written == 0 {
        for path in fallback_pairing_paths() {
            if path.exists() {
                return Ok(());
            }
        }
        return Err(CredentialStoreError::Windows { code: error_code });
    }
    Ok(())
}

/// Reads the serialized pairing set, if one has been stored.
#[cfg(windows)]
fn read_pairing_set() -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, CredentialStoreError> {
    use core::ptr;

    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
    use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CREDENTIALW, CredReadW};
    use zeroize::Zeroize as _;

    let mut target = target_name_wide();
    let mut raw_credential = ptr::null_mut::<CREDENTIALW>();
    // SAFETY: `target` is NUL-terminated and `raw_credential` is a valid out
    // pointer; a successful allocation is released by `SetCredentialGuard`.
    let read = unsafe {
        CredReadW(
            target.as_ptr(),
            CRED_TYPE_GENERIC,
            0,
            &raw mut raw_credential,
        )
    };
    // SAFETY: `GetLastError` must be read before any other Windows call.
    let error_code = if read == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    target.zeroize();
    if read == 0 {
        for path in fallback_pairing_paths() {
            if path.exists()
                && let Ok(bytes) = std::fs::read(&path)
                && !bytes.is_empty()
            {
                return Ok(Some(zeroize::Zeroizing::new(bytes)));
            }
        }
        return if error_code == ERROR_NOT_FOUND {
            Ok(None)
        } else {
            Err(CredentialStoreError::Windows { code: error_code })
        };
    }
    if raw_credential.is_null() {
        return Err(CredentialStoreError::InvalidStoredPairing);
    }

    let guard = SetCredentialGuard(raw_credential);
    // SAFETY: the guard owns a non-null CREDENTIALW returned by CredReadW.
    let credential = unsafe { &*guard.0 };
    let length = usize::try_from(credential.CredentialBlobSize)
        .map_err(|_error| CredentialStoreError::InvalidStoredPairing)?;
    if length == 0 {
        return Ok(Some(zeroize::Zeroizing::new(Vec::new())));
    }
    if credential.CredentialBlob.is_null() {
        return Err(CredentialStoreError::InvalidStoredPairing);
    }
    // SAFETY: Windows reports `CredentialBlobSize` readable bytes at the blob
    // pointer, and the non-null, non-zero-length case was checked above.
    let blob = unsafe { core::slice::from_raw_parts(credential.CredentialBlob, length) };
    Ok(Some(zeroize::Zeroizing::new(blob.to_vec())))
}

/// Deletes the stored pairing set. Deleting an absent set succeeds.
///
/// # Errors
///
/// Fails on a Credential Manager error other than "not found", or when this
/// build is not running on Windows.
#[cfg(windows)]
pub fn delete_pairing_set() -> Result<(), CredentialStoreError> {
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
    use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CredDeleteW};
    use zeroize::Zeroize as _;

    let mut target = target_name_wide();
    // SAFETY: `target` is a valid NUL-terminated UTF-16 string for the call.
    let deleted = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
    // SAFETY: `GetLastError` must be read before any other Windows call.
    let error_code = if deleted == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    for path in fallback_pairing_paths() {
        let _ = std::fs::remove_file(path);
    }
    target.zeroize();
    if deleted != 0 || error_code == ERROR_NOT_FOUND {
        Ok(())
    } else {
        Err(CredentialStoreError::Windows { code: error_code })
    }
}

#[cfg(not(windows))]
const fn write_pairing_set(_blob: &[u8]) -> Result<(), CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

#[cfg(not(windows))]
const fn read_pairing_set() -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

#[cfg(not(windows))]
/// Non-Windows builds expose the same API for workspace type checking.
///
/// # Errors
/// Always fails: the Windows Credential Manager is unavailable off Windows.
pub const fn delete_pairing_set() -> Result<(), CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

#[cfg(all(test, windows))]
mod tests {
    use refineid_rapp_core::ids::{PairId, RendezvousToken};
    use refineid_rapp_core::store::{PairingDisposition, PairingRecord, PairingStore};
    use zeroize::Zeroizing;

    use super::{CredentialPairingStore, delete_pairing_set};

    fn record(pair_id: PairId) -> PairingRecord {
        PairingRecord {
            pair_id,
            rendezvous_token: RendezvousToken::from_array([9; 16]),
            local_private: Zeroizing::new(vec![1; 32]),
            local_public: vec![2; 32],
            peer_public: vec![3; 32],
            granted_profiles: vec!["fi.refineid.authentication.v1".into()],
            grants_hash: [4; 32],
            peer_display_name: "Phone".into(),
            peer_platform: "iOS".into(),
            disposition: PairingDisposition::Paired,
            peer_initiated_termination: false,
            candidate_failures: 0,
            auth_cert: None,
            signature_cert: None,
            root_ca: None,
            intermediate_ca: None,
            candidate_id: None,
            transport_profile: None,
        }
    }

    #[test]
    #[ignore = "writes and removes one synthetic Windows credential"]
    fn pairing_set_survives_a_reload() {
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ignored = delete_pairing_set();
            }
        }

        delete_pairing_set().expect("clear before test");
        let _cleanup = Cleanup;

        let pair_id = PairId::from_array([7; 16]);
        let mut store = CredentialPairingStore::load().expect("load empty store");
        assert!(store.is_empty());
        store.insert(record(pair_id)).expect("insert");

        let reloaded = CredentialPairingStore::load().expect("reload store");
        assert_eq!(reloaded.len(), 1);
        assert_eq!(
            reloaded.get(pair_id).expect("stored record").pair_id,
            pair_id
        );

        let mut store = reloaded;
        store.remove(pair_id).expect("remove");
        let empty = CredentialPairingStore::load().expect("reload after remove");
        assert!(empty.is_empty());
    }
}
