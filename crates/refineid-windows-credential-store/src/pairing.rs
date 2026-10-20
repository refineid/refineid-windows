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

//! Durable pairing storage, protected to the Windows user by DPAPI.
//!
//! RAPP requires the pair keys to live in device-only, non-migrating secret
//! storage (RAPP v26.10.18 section 4.3 item 4). The whole pairing set is
//! serialized by [`refineid_rapp_core::persistence`], protected with
//! `CryptProtectData` to the current user under a purpose entropy, and
//! written as one file in the user's local application data, through a
//! temporary file and a rename, so an insert, update, or removal replaces
//! the set at once. Only this Windows user, on this computer, can unprotect
//! it. A Credential Manager credential cannot hold the set: a record carries
//! its cached certificates, and a generic credential holds at most
//! `CRED_MAX_CREDENTIAL_BLOB_SIZE` (2560) bytes.
//!
//! The keys never leave `Zeroizing`, are wiped from every intermediate
//! buffer, and are never logged. The store deletes, unread, every
//! unprotected copy of the set it finds: plaintext files in the user's and
//! the machine's application data, and the generic credential.
//!
//! [`ProtectedPairingStore`] keeps the decoded records in memory so it can
//! satisfy the borrowing [`PairingStore`] contract, and writes the set through
//! on every change. It is the durable replacement for the engine's in-memory
//! store.

use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::persistence::{decode_pairing_records, encode_pairing_records};
use refineid_rapp_core::store::{
    PairingDisposition, PairingRecord, PairingStore, StoreError, revoke_unconfirmed,
};
use zeroize::Zeroizing;

use crate::CredentialStoreError;

/// A pairing store protected to the Windows user by DPAPI.
///
/// The decoded records are held in memory and mirrored to one protected
/// file. Construct it with [`ProtectedPairingStore::load`], which reads and
/// decodes whatever is already stored for this Windows user.
#[derive(Debug)]
pub struct ProtectedPairingStore {
    records: Vec<PairingRecord>,
}

impl ProtectedPairingStore {
    /// Loads the stored pairing set, or an empty store when none exists yet,
    /// after deleting every unprotected copy of a set.
    ///
    /// A record whose peer never confirmed its storage was written inside a
    /// pairing this computer did not complete; it is revoked here, at the
    /// first load after that pairing (RAPP v26.10.18 section 4.3 item 4).
    ///
    /// # Errors
    ///
    /// Fails when the protected set cannot be read or unprotected, the
    /// stored blob is malformed, or this build is not running on Windows.
    pub fn load() -> Result<Self, CredentialStoreError> {
        remove_unprotected_copies();
        let records = match read_pairing_set()? {
            Some(blob) => decode_pairing_records(&blob)
                .map_err(|_error| CredentialStoreError::InvalidStoredPairing)?,
            None => Vec::new(),
        };
        let mut store = Self { records };
        if !revoke_unconfirmed(&mut store).is_empty() {
            store
                .persist()
                .map_err(|_error| CredentialStoreError::InvalidStoredPairing)?;
        }
        Ok(store)
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

    /// The first usable stored pairing, if any: one neither revoked nor
    /// awaiting the peer's storage confirmation.
    ///
    /// A caller that reconnects to a stored pairing needs its `pair_id` and
    /// keys without having kept them from the pairing ceremony.
    #[must_use]
    pub fn usable_pairing(&self) -> Option<&PairingRecord> {
        self.records.iter().rfind(|record| {
            record.disposition == PairingDisposition::Paired && record.storage_confirmed
        })
    }

    /// All stored pairing records.
    #[must_use]
    pub fn records(&self) -> &[PairingRecord] {
        &self.records
    }

    /// Records that the phone announced it forgot `pair_id` (RAPP v26.10.18
    /// section 4.6 item 5): the keys are destroyed and the record stays as
    /// the tombstone the user is told about.
    ///
    /// # Errors
    ///
    /// Fails when no such pairing is stored or the set cannot be written.
    pub fn forget_after_revocation(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        self.update(pair_id, &mut |record| {
            record.disposition = PairingDisposition::Revoked;
            record.peer_initiated_termination = true;
            record.local_private = Zeroizing::new(Vec::new());
            record.peer_public = Vec::new();
        })
    }

    /// Replaces the records held here with the stored set as it is now, so
    /// a write applies to what is stored and not to the copy this value was
    /// loaded with: another store instance may have revoked a pairing or
    /// deleted the set in the meantime.
    ///
    /// A set that cannot be read leaves the records as they are; a set that
    /// is gone leaves them empty.
    fn refresh_from_storage(&mut self) {
        match stored_records_now() {
            Refresh::Replace(records) => self.records = records,
            Refresh::Clear => self.records.clear(),
            Refresh::Keep => {}
        }
    }

    /// Writes the current record set through to the protected file.
    fn persist(&self) -> Result<(), StoreError> {
        let blob = encode_pairing_records(&self.records);
        write_pairing_set(&blob).map_err(|_error| StoreError::WriteRefused)
    }
}

impl PairingStore for ProtectedPairingStore {
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
        self.refresh_from_storage();
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
        self.refresh_from_storage();
        let record = self
            .records
            .iter_mut()
            .find(|entry| entry.pair_id == pair_id)
            .ok_or(StoreError::Unknown)?;
        change(record);
        self.persist()
    }

    fn pair_ids(&self) -> Vec<PairId> {
        self.records
            .iter()
            .rev()
            .map(|entry| entry.pair_id)
            .collect()
    }

    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        self.refresh_from_storage();
        let before = self.records.len();
        self.records.retain(|entry| entry.pair_id != pair_id);
        if self.records.len() == before {
            return Err(StoreError::Unknown);
        }
        self.persist()
    }
}

/// What the stored set says the records are right now.
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "only the Windows store can report a set to replace or clear"
    )
)]
enum Refresh {
    /// The stored set holds these records.
    Replace(Vec<PairingRecord>),
    /// The stored set is gone.
    Clear,
    /// The set could not be read, or there is none on this platform.
    Keep,
}

#[cfg(windows)]
fn stored_records_now() -> Refresh {
    match read_pairing_set() {
        Ok(Some(blob)) => decode_pairing_records(&blob).map_or(Refresh::Keep, Refresh::Replace),
        Ok(None) => Refresh::Clear,
        Err(_) => Refresh::Keep,
    }
}

/// Off Windows there is no set to read; the records stand.
#[cfg(not(windows))]
const fn stored_records_now() -> Refresh {
    Refresh::Keep
}

/// The directory under the user's local application data that holds the set.
#[cfg(windows)]
const PROFILE_DIRECTORY: &str = "RefineID";
/// The protected pairing set.
#[cfg(windows)]
const PAIRING_SET_FILE: &str = "pairing-set.dpapi";
/// The protected set being written, renamed over [`PAIRING_SET_FILE`] once
/// it is complete on disk.
#[cfg(windows)]
const PAIRING_SET_PARTIAL_FILE: &str = "pairing-set.dpapi.partial";
/// The purpose the set is protected for: a DPAPI blob protected for anything
/// else does not unprotect as a pairing set.
#[cfg(windows)]
const PAIRING_SET_ENTROPY: &[u8] = b"fi.refineid.windows.rapp-pairing-set.v1";
/// The name of an unprotected plaintext copy of the set.
#[cfg(windows)]
const UNPROTECTED_COPY_FILE: &str = "pairing_set.blob";
/// The generic credential that held an unprotected copy of the set.
#[cfg(windows)]
const UNPROTECTED_CREDENTIAL_TARGET: &str = "RefineID_RAPP_Pairing_Set";

/// The user's local application data directory for `RefineID`.
#[cfg(windows)]
fn profile_directory() -> Result<std::path::PathBuf, CredentialStoreError> {
    std::env::var_os("LOCALAPPDATA")
        .map(|local| std::path::PathBuf::from(local).join(PROFILE_DIRECTORY))
        .ok_or(CredentialStoreError::ProfileUnavailable)
}

/// Deletes every unprotected copy of a pairing set, without reading it.
///
/// Deletion is all that is wanted of them; one that cannot be deleted (a
/// machine-wide copy another account created) is left for that account's
/// own load, and nothing here ever reads it.
#[cfg(windows)]
fn remove_unprotected_copies() {
    use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CredDeleteW};

    if let Ok(directory) = profile_directory() {
        let _ = std::fs::remove_file(directory.join(UNPROTECTED_COPY_FILE));
    }
    if let Some(program_data) = std::env::var_os("ProgramData") {
        let _ = std::fs::remove_file(
            std::path::PathBuf::from(program_data)
                .join(PROFILE_DIRECTORY)
                .join(UNPROTECTED_COPY_FILE),
        );
    }
    let target = wide(UNPROTECTED_CREDENTIAL_TARGET);
    // SAFETY: `target` is a NUL-terminated UTF-16 string that outlives the
    // call; a missing credential is the expected outcome and is ignored.
    let _ = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
}

#[cfg(not(windows))]
const fn remove_unprotected_copies() {}

#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// A DPAPI output buffer, wiped and released with `LocalFree`.
#[cfg(windows)]
struct DpapiOutput(windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB);

#[cfg(windows)]
impl DpapiOutput {
    const fn empty() -> Self {
        Self(
            windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: core::ptr::null_mut(),
            },
        )
    }

    fn bytes(&self) -> Result<&[u8], CredentialStoreError> {
        let length = usize::try_from(self.0.cbData)
            .map_err(|_error| CredentialStoreError::InvalidStoredPairing)?;
        if length == 0 {
            return Ok(&[]);
        }
        if self.0.pbData.is_null() {
            return Err(CredentialStoreError::InvalidStoredPairing);
        }
        // SAFETY: DPAPI reports `cbData` readable bytes at the non-null
        // `pbData` it allocated, which this value owns until drop.
        Ok(unsafe { core::slice::from_raw_parts(self.0.pbData, length) })
    }
}

#[cfg(windows)]
impl Drop for DpapiOutput {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;
        use zeroize::Zeroize as _;

        if self.0.pbData.is_null() {
            return;
        }
        // SAFETY: DPAPI allocated `cbData` bytes at `pbData` with
        // `LocalAlloc`; they are wiped, then released exactly once.
        unsafe {
            if let Ok(length) = usize::try_from(self.0.cbData) {
                core::slice::from_raw_parts_mut(self.0.pbData, length).zeroize();
            }
            LocalFree(self.0.pbData.cast());
        }
    }
}

/// The `CRYPT_INTEGER_BLOB` view of `bytes` DPAPI reads as input.
#[cfg(windows)]
fn input_blob(
    bytes: &[u8],
) -> Result<windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB, CredentialStoreError> {
    Ok(
        windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len())
                .map_err(|_error| CredentialStoreError::InvalidStoredPairing)?,
            pbData: bytes.as_ptr().cast_mut(),
        },
    )
}

/// Protects `plain` to the current user under the pairing-set entropy.
#[cfg(windows)]
fn protect(plain: &[u8]) -> Result<Vec<u8>, CredentialStoreError> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData};

    let input = input_blob(plain)?;
    let entropy = input_blob(PAIRING_SET_ENTROPY)?;
    let mut output = DpapiOutput::empty();
    // SAFETY: `input` and `entropy` describe live buffers that DPAPI only
    // reads; `output` receives an allocation it then owns.
    let protected = unsafe {
        CryptProtectData(
            &raw const input,
            core::ptr::null(),
            &raw const entropy,
            core::ptr::null(),
            core::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output.0,
        )
    };
    if protected == 0 {
        // SAFETY: read immediately after the failing call.
        let code = unsafe { GetLastError() };
        return Err(CredentialStoreError::Protection { code });
    }
    Ok(output.bytes()?.to_vec())
}

/// Unprotects a blob [`protect`] wrote for the current user.
#[cfg(windows)]
fn unprotect(protected: &[u8]) -> Result<Zeroizing<Vec<u8>>, CredentialStoreError> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let input = input_blob(protected)?;
    let entropy = input_blob(PAIRING_SET_ENTROPY)?;
    let mut output = DpapiOutput::empty();
    // SAFETY: as in `protect`; DPAPI writes no description through the
    // null description pointer.
    let unprotected = unsafe {
        CryptUnprotectData(
            &raw const input,
            core::ptr::null_mut(),
            &raw const entropy,
            core::ptr::null(),
            core::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output.0,
        )
    };
    if unprotected == 0 {
        // SAFETY: read immediately after the failing call.
        let code = unsafe { GetLastError() };
        return Err(CredentialStoreError::Protection { code });
    }
    Ok(Zeroizing::new(output.bytes()?.to_vec()))
}

/// Protects the serialized pairing set and replaces the stored file with it.
#[cfg(windows)]
fn write_pairing_set(blob: &[u8]) -> Result<(), CredentialStoreError> {
    use std::io::Write as _;

    let protected = protect(blob)?;
    let directory = profile_directory()?;
    std::fs::create_dir_all(&directory).map_err(|error| CredentialStoreError::file(&error))?;
    let partial = directory.join(PAIRING_SET_PARTIAL_FILE);
    let written = std::fs::File::create(&partial).and_then(|mut file| {
        file.write_all(&protected)?;
        file.sync_all()
    });
    if let Err(error) = written {
        let _ = std::fs::remove_file(&partial);
        return Err(CredentialStoreError::file(&error));
    }
    std::fs::rename(&partial, directory.join(PAIRING_SET_FILE)).map_err(|error| {
        let _ = std::fs::remove_file(&partial);
        CredentialStoreError::file(&error)
    })
}

/// Reads and unprotects the serialized pairing set, if one has been stored.
#[cfg(windows)]
fn read_pairing_set() -> Result<Option<Zeroizing<Vec<u8>>>, CredentialStoreError> {
    let path = profile_directory()?.join(PAIRING_SET_FILE);
    let protected = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(CredentialStoreError::file(&error)),
    };
    unprotect(&protected)
        .map(Some)
        .map_err(|_error| CredentialStoreError::InvalidStoredPairing)
}

/// Deletes the stored pairing set and every unprotected copy. Deleting an
/// absent set succeeds.
///
/// # Errors
///
/// Fails when the protected file exists and cannot be removed, or when this
/// build is not running on Windows.
#[cfg(windows)]
pub fn delete_pairing_set() -> Result<(), CredentialStoreError> {
    remove_unprotected_copies();
    match std::fs::remove_file(profile_directory()?.join(PAIRING_SET_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CredentialStoreError::file(&error)),
    }
}

#[cfg(not(windows))]
const fn write_pairing_set(_blob: &[u8]) -> Result<(), CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

#[cfg(not(windows))]
const fn read_pairing_set() -> Result<Option<Zeroizing<Vec<u8>>>, CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

#[cfg(not(windows))]
/// Non-Windows builds expose the same API for workspace type checking.
///
/// # Errors
/// Always fails: DPAPI is unavailable off Windows.
pub const fn delete_pairing_set() -> Result<(), CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

#[cfg(all(test, windows))]
mod tests {
    use refineid_rapp_core::ids::PairId;
    use refineid_rapp_core::store::{PairingDisposition, PairingRecord, PairingStore};
    use zeroize::Zeroizing;

    use super::{
        PAIRING_SET_FILE, ProtectedPairingStore, delete_pairing_set, profile_directory, protect,
        unprotect,
    };

    const KEY_BYTES: usize = 32;
    const GRANTS_HASH_BYTES: usize = 32;
    const PAIR_ID_BYTES: usize = 16;
    /// The length of a DER certificate as large as the cards carry, so the
    /// set exceeds what one generic credential could hold.
    const LARGE_CERTIFICATE_BYTES: usize = 1_900;

    fn record(pair_id: PairId) -> PairingRecord {
        PairingRecord {
            pair_id,
            local_private: Zeroizing::new(vec![1; KEY_BYTES]),
            local_public: vec![2; KEY_BYTES],
            peer_public: vec![3; KEY_BYTES],
            granted_profiles: vec!["fi.refineid.authentication.v1".into()],
            grants_hash: [4; GRANTS_HASH_BYTES],
            peer_display_name: "Phone".into(),
            peer_platform: "iOS".into(),
            storage_confirmed: true,
            disposition: PairingDisposition::Paired,
            peer_initiated_termination: false,
            candidate_failures: 0,
            auth_cert: Some(vec![5; LARGE_CERTIFICATE_BYTES]),
            signature_cert: Some(vec![6; LARGE_CERTIFICATE_BYTES]),
            root_ca: None,
            intermediate_ca: None,
        }
    }

    #[test]
    fn a_protected_blob_unprotects_to_itself_and_not_in_plain_sight() {
        let plain = b"synthetic pairing set";
        let protected = protect(plain).expect("protect");
        assert!(
            !protected
                .windows(plain.len())
                .any(|window| window == plain.as_slice())
        );
        assert_eq!(unprotect(&protected).expect("unprotect").as_slice(), plain);
    }

    #[test]
    fn a_blob_protected_for_another_purpose_does_not_unprotect() {
        assert!(unprotect(b"not a DPAPI blob").is_err());
    }

    #[test]
    #[ignore = "writes and removes this user's pairing set file"]
    fn a_set_larger_than_a_credential_survives_a_reload_protected() {
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ignored = delete_pairing_set();
            }
        }

        delete_pairing_set().expect("clear before test");
        let _cleanup = Cleanup;

        let pair_id = PairId::from_array([7; PAIR_ID_BYTES]);
        let mut store = ProtectedPairingStore::load().expect("load empty store");
        assert!(store.is_empty());
        store.insert(record(pair_id)).expect("insert");

        let on_disk = std::fs::read(profile_directory().expect("profile").join(PAIRING_SET_FILE))
            .expect("file written");
        assert!(
            !on_disk
                .windows(KEY_BYTES)
                .any(|window| window.iter().all(|&byte| byte == 1))
        );

        let reloaded = ProtectedPairingStore::load().expect("reload store");
        assert_eq!(reloaded.len(), 1);
        assert_eq!(
            reloaded.get(pair_id).expect("stored record").pair_id,
            pair_id
        );

        let mut store = reloaded;
        store.remove(pair_id).expect("remove");
        let empty = ProtectedPairingStore::load().expect("reload after remove");
        assert!(empty.is_empty());
    }
}
