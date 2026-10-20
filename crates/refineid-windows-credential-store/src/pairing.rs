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
//! temporary file of its own and a rename, so an insert, update, or removal
//! replaces the set at once. Only this Windows user, on this computer, can
//! unprotect it. A Credential Manager credential cannot hold the set: a
//! record carries its cached certificates, and a generic credential holds at
//! most `CRED_MAX_CREDENTIAL_BLOB_SIZE` (2560) bytes.
//!
//! The keys stay in `Zeroizing` buffers, are wiped from every intermediate
//! buffer, and are never logged. The store deletes, unread, every
//! unprotected copy of the set it finds: plaintext files in the user's and
//! the machine's application data, and the generic credential.
//!
//! [`ProtectedPairingStore`] keeps the decoded records in memory so it can
//! satisfy the borrowing [`PairingStore`] contract, and writes the set through
//! on every change, after re-reading it: a change is never written over a set
//! that could not be read.

use std::path::{Path, PathBuf};

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
    directory: PathBuf,
}

impl ProtectedPairingStore {
    /// Loads this user's stored pairing set, or an empty store when none
    /// exists yet, after deleting every unprotected copy of a set.
    ///
    /// A record whose peer never confirmed its storage was written inside a
    /// pairing this computer did not complete; it is revoked here, at the
    /// first load after that pairing (RAPP v26.10.18 section 4.3 item 4).
    ///
    /// # Errors
    ///
    /// Fails when an unprotected copy in this user's profile cannot be
    /// deleted, the protected set cannot be read or unprotected, the stored
    /// blob is malformed, or this build is not running on Windows.
    pub fn load() -> Result<Self, CredentialStoreError> {
        Self::load_from(profile_directory()?)
    }

    /// Loads the pairing set kept in `directory`.
    fn load_from(directory: PathBuf) -> Result<Self, CredentialStoreError> {
        remove_unprotected_copies(&directory)?;
        let records = match read_pairing_set(&directory)? {
            Some(blob) => decode_pairing_records(&blob)
                .map_err(|_error| CredentialStoreError::InvalidStoredPairing)?,
            None => Vec::new(),
        };
        let mut store = Self { records, directory };
        // Each revocation is written as it is made; one that could not be
        // written stands in memory and is written here.
        if !revoke_unconfirmed(&mut store).is_empty() {
            store.persist()?;
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

    /// The most recently stored usable pairing, if any: one neither revoked
    /// nor awaiting the peer's storage confirmation.
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
    /// Fails when no such pairing is stored, the stored set cannot be read,
    /// or the set cannot be written.
    pub fn forget_after_revocation(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        self.update(pair_id, &mut |record| {
            record.disposition = PairingDisposition::Revoked;
            record.peer_initiated_termination = true;
            record.local_private = Zeroizing::new(Vec::new());
            record.peer_public = Vec::new();
        })
    }

    /// Replaces the records held here with the stored set as it is now, so
    /// a change applies to what is stored and not to the copy this value was
    /// loaded with: another store instance may have revoked a pairing or
    /// deleted the set in the meantime. A set that is gone leaves the
    /// records empty.
    ///
    /// A set that cannot be read stops the change: written over, it would
    /// be lost.
    fn refresh_from_storage(&mut self) -> Result<(), StoreError> {
        match read_pairing_set(&self.directory) {
            Ok(Some(blob)) => {
                self.records =
                    decode_pairing_records(&blob).map_err(|_error| StoreError::Unreadable)?;
                Ok(())
            }
            Ok(None) => {
                self.records.clear();
                Ok(())
            }
            Err(_error) => Err(StoreError::Unreadable),
        }
    }

    /// Writes the current record set through to the protected file.
    fn persist(&self) -> Result<(), CredentialStoreError> {
        let blob = encode_pairing_records(&self.records);
        write_pairing_set(&self.directory, &blob)
    }

    /// Re-reads the stored set, applies `change`, and writes it.
    fn change(
        &mut self,
        change: impl FnOnce(&mut Vec<PairingRecord>) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        self.refresh_from_storage()?;
        change(&mut self.records)?;
        self.persist().map_err(|_error| StoreError::WriteRefused)
    }
}

impl PairingStore for ProtectedPairingStore {
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
        self.change(|records| {
            records.retain(|entry| entry.pair_id != record.pair_id);
            records.push(record);
            Ok(())
        })
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
        self.change(|records| {
            let record = records
                .iter_mut()
                .find(|entry| entry.pair_id == pair_id)
                .ok_or(StoreError::Unknown)?;
            change(record);
            Ok(())
        })
    }

    fn pair_ids(&self) -> Vec<PairId> {
        self.records
            .iter()
            .rev()
            .map(|entry| entry.pair_id)
            .collect()
    }

    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        self.change(|records| {
            let before = records.len();
            records.retain(|entry| entry.pair_id != pair_id);
            if records.len() == before {
                return Err(StoreError::Unknown);
            }
            Ok(())
        })
    }
}

/// The directory under the user's local application data that holds the set.
const PROFILE_DIRECTORY: &str = "RefineID";
/// The protected pairing set.
#[cfg(windows)]
const PAIRING_SET_FILE: &str = "pairing-set.dpapi";
/// The suffix of the temporary file a write fills before the rename.
#[cfg(windows)]
const PARTIAL_SUFFIX: &str = "partial";
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
fn profile_directory() -> Result<PathBuf, CredentialStoreError> {
    std::env::var_os("LOCALAPPDATA")
        .map(|local| PathBuf::from(local).join(PROFILE_DIRECTORY))
        .ok_or(CredentialStoreError::ProfileUnavailable)
}

/// Deletes every unprotected copy of a pairing set, without reading it.
///
/// A copy in `directory` or the generic credential, both this user's, must
/// go: one that cannot be deleted fails the load. A machine-wide copy in
/// `%ProgramData%` that cannot be deleted belongs to another account, which
/// deletes it at its own load; this user has no right to.
#[cfg(windows)]
fn remove_unprotected_copies(directory: &Path) -> Result<(), CredentialStoreError> {
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
    use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CredDeleteW};

    match std::fs::remove_file(directory.join(UNPROTECTED_COPY_FILE)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_error) => return Err(CredentialStoreError::UnprotectedCopyRemains),
    }
    if let Some(program_data) = std::env::var_os("ProgramData") {
        let _another_accounts_copy_is_not_ours_to_delete = std::fs::remove_file(
            PathBuf::from(program_data)
                .join(PROFILE_DIRECTORY)
                .join(UNPROTECTED_COPY_FILE),
        );
    }
    let target = wide(UNPROTECTED_CREDENTIAL_TARGET);
    // SAFETY: `target` is a NUL-terminated UTF-16 string that outlives the
    // call.
    let deleted = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
    // SAFETY: read immediately after the failing call.
    if deleted == 0 && unsafe { GetLastError() } != ERROR_NOT_FOUND {
        return Err(CredentialStoreError::UnprotectedCopyRemains);
    }
    Ok(())
}

#[cfg(not(windows))]
const fn remove_unprotected_copies(_directory: &Path) -> Result<(), CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

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

/// The `CRYPT_INTEGER_BLOB` view of `bytes` DPAPI reads as input: a null
/// pointer for an empty buffer, as Windows expects.
///
/// The structure's pointer is mutable by declaration only; `CryptProtectData`
/// and `CryptUnprotectData` read their input and entropy and never write
/// them, so the cast from a shared slice writes through nothing.
#[cfg(windows)]
fn input_blob(
    bytes: &[u8],
) -> Result<windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB, CredentialStoreError> {
    Ok(
        windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len())
                .map_err(|_error| CredentialStoreError::InvalidStoredPairing)?,
            pbData: if bytes.is_empty() {
                core::ptr::null_mut()
            } else {
                bytes.as_ptr().cast_mut()
            },
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

/// A temporary file name no other write uses: two stores writing at once
/// each fill their own file, and the later rename wins whole.
#[cfg(windows)]
fn partial_file_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    static WRITES: AtomicU64 = AtomicU64::new(0);
    let write = WRITES.fetch_add(1, Ordering::Relaxed);
    format!(
        "{PAIRING_SET_FILE}.{}.{write}.{PARTIAL_SUFFIX}",
        std::process::id()
    )
}

/// Protects the serialized pairing set and replaces the stored file with it.
#[cfg(windows)]
fn write_pairing_set(directory: &Path, blob: &[u8]) -> Result<(), CredentialStoreError> {
    use std::io::Write as _;

    let protected = protect(blob)?;
    std::fs::create_dir_all(directory).map_err(|error| CredentialStoreError::file(&error))?;
    let partial = directory.join(partial_file_name());
    let written = std::fs::File::create_new(&partial).and_then(|mut file| {
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

#[cfg(not(windows))]
const fn write_pairing_set(_directory: &Path, _blob: &[u8]) -> Result<(), CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

/// Reads and unprotects the serialized pairing set, if one has been stored.
#[cfg(windows)]
fn read_pairing_set(directory: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, CredentialStoreError> {
    let protected = match std::fs::read(directory.join(PAIRING_SET_FILE)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(CredentialStoreError::file(&error)),
    };
    unprotect(&protected).map(Some)
}

#[cfg(not(windows))]
const fn read_pairing_set(
    _directory: &Path,
) -> Result<Option<Zeroizing<Vec<u8>>>, CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

/// Deletes this user's stored pairing set and every unprotected copy.
/// Deleting an absent set succeeds.
///
/// # Errors
///
/// Fails when the protected file or an unprotected copy of this user's
/// exists and cannot be removed, or when this build is not running on
/// Windows.
pub fn delete_pairing_set() -> Result<(), CredentialStoreError> {
    delete_pairing_set_in(&profile_directory()?)
}

#[cfg(windows)]
fn delete_pairing_set_in(directory: &Path) -> Result<(), CredentialStoreError> {
    remove_unprotected_copies(directory)?;
    match std::fs::remove_file(directory.join(PAIRING_SET_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CredentialStoreError::file(&error)),
    }
}

#[cfg(not(windows))]
const fn delete_pairing_set_in(_directory: &Path) -> Result<(), CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

#[cfg(all(test, windows))]
mod tests {
    use refineid_rapp_core::ids::PairId;
    use refineid_rapp_core::store::{PairingDisposition, PairingRecord, PairingStore, StoreError};
    use zeroize::Zeroizing;

    use super::{
        PAIRING_SET_FILE, ProtectedPairingStore, UNPROTECTED_COPY_FILE, delete_pairing_set_in,
        input_blob, protect, unprotect,
    };

    const KEY_BYTES: usize = 32;
    const GRANTS_HASH_BYTES: usize = 32;
    const PAIR_ID_BYTES: usize = 16;
    /// The length of a DER certificate as large as the cards carry, so the
    /// set exceeds what one generic credential could hold.
    const LARGE_CERTIFICATE_BYTES: usize = 1_900;
    const PRIVATE_KEY_FILL: u8 = 1;

    /// A directory of its own for one test, removed when the test ends.
    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "refineid-pairing-store-test-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn record(pair_id: PairId) -> PairingRecord {
        PairingRecord {
            pair_id,
            local_private: Zeroizing::new(vec![PRIVATE_KEY_FILL; KEY_BYTES]),
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
                .as_slice()
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
    fn an_empty_input_is_passed_as_a_null_pointer() {
        let blob = input_blob(&[]).expect("blob");
        assert_eq!(blob.cbData, 0);
        assert!(blob.pbData.is_null());
    }

    #[test]
    fn a_set_larger_than_a_credential_survives_a_reload_protected() {
        let directory = TestDirectory::new("reload");
        let pair_id = PairId::from_array([7; PAIR_ID_BYTES]);
        let mut store = ProtectedPairingStore::load_from(directory.0.clone()).expect("load");
        assert!(store.is_empty());
        store.insert(record(pair_id)).expect("insert");

        let on_disk = std::fs::read(directory.0.join(PAIRING_SET_FILE)).expect("file written");
        assert!(
            !on_disk
                .as_slice()
                .windows(KEY_BYTES)
                .any(|window| window.iter().all(|&byte| byte == PRIVATE_KEY_FILL))
        );

        let mut reloaded = ProtectedPairingStore::load_from(directory.0.clone()).expect("reload");
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded.get(pair_id).expect("stored").pair_id, pair_id);
        reloaded.remove(pair_id).expect("remove");
        assert!(
            ProtectedPairingStore::load_from(directory.0.clone())
                .expect("reload after remove")
                .is_empty()
        );
        delete_pairing_set_in(&directory.0).expect("delete");
        assert!(!directory.0.join(PAIRING_SET_FILE).exists());
    }

    #[test]
    fn a_change_is_never_written_over_a_set_that_cannot_be_read() {
        let directory = TestDirectory::new("unreadable");
        let first = PairId::from_array([7; PAIR_ID_BYTES]);
        let second = PairId::from_array([8; PAIR_ID_BYTES]);
        let mut store = ProtectedPairingStore::load_from(directory.0.clone()).expect("load");
        store.insert(record(first)).expect("insert");
        let stored = directory.0.join(PAIRING_SET_FILE);
        let before = std::fs::read(&stored).expect("stored");
        std::fs::write(&stored, b"not a DPAPI blob").expect("corrupt");

        assert_eq!(store.insert(record(second)), Err(StoreError::Unreadable));
        assert_eq!(
            std::fs::read(&stored).expect("still there"),
            b"not a DPAPI blob"
        );
        std::fs::write(&stored, before).expect("restore");
    }

    #[test]
    fn an_unprotected_copy_in_the_profile_is_deleted_unread() {
        let directory = TestDirectory::new("copy");
        let copy = directory.0.join(UNPROTECTED_COPY_FILE);
        std::fs::write(&copy, b"plaintext set").expect("copy");
        let store = ProtectedPairingStore::load_from(directory.0.clone()).expect("load");
        assert!(store.is_empty());
        assert!(!copy.exists());
    }
}
