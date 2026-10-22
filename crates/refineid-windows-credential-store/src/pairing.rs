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
//! storage (RAPP v26.10.22 section 4.3 item 4). The whole pairing set is
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
//!
//! Beside the set, in a directory of plain files, one per pairing, the
//! store keeps the last card a session heard present (RAPP v26.10.22
//! section 8.4): a pair identifier, the fingerprint of a public certificate
//! and a time, nothing secret. Every requester process of this user offers
//! the phone's identity by it, and a session refreshes it every few
//! seconds, so it is not written through the protected set. Each pairing's
//! file is replaced whole, so no write reads another's or touches it.

use std::path::{Path, PathBuf};

use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::persistence::{decode_pairing_records, encode_pairing_records};
use refineid_rapp_core::presence::{CardSighting, decode_sighting, encode_sighting};
use refineid_rapp_core::store::{
    PairingRecord, PairingStore, StoreError, expire_revocation_notices, remove_unconfirmed,
    revoke_pairing,
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
    sightings: Vec<(PairId, CardSighting)>,
    directory: PathBuf,
}

impl ProtectedPairingStore {
    /// Loads this user's stored pairing set, or an empty store when none
    /// exists yet, after deleting every unprotected copy of a set.
    ///
    /// A record whose peer never confirmed its storage was written inside a
    /// pairing this computer did not complete; it is removed with its keys
    /// here, at the first load after that pairing (RAPP v26.10.22 section
    /// 4.3 item 4). A forgotten pairing whose `pairing_revoked` close was
    /// not delivered within 30 days loses its keys untold (section 4.6
    /// item 3).
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
        let sightings = read_sightings(&directory);
        let mut store = Self {
            records,
            sightings,
            directory,
        };
        // Each change is written as it is made; one that could not be
        // written stands in memory and is written here.
        let removed = remove_unconfirmed(&mut store);
        let expired =
            expire_revocation_notices(&mut store, refineid_rapp_core::clock::unix_time_ms());
        if !removed.is_empty() || !expired.is_empty() {
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

    /// The most recently stored usable pairing, if any: one that serves
    /// (neither revoked, nor forgotten, nor awaiting the peer's storage
    /// confirmation).
    ///
    /// A caller that reconnects to a stored pairing needs its `pair_id` and
    /// keys without having kept them from the pairing ceremony.
    #[must_use]
    pub fn usable_pairing(&self) -> Option<&PairingRecord> {
        self.records.iter().rfind(|record| record.serves())
    }

    /// The pairings forgotten here whose `pairing_revoked` close is still
    /// owed to the phone (RAPP v26.10.22 section 4.6 item 2).
    pub fn forgotten_pairings(&self) -> impl Iterator<Item = &PairingRecord> {
        self.records
            .iter()
            .filter(|record| record.owes_revocation_notice())
    }

    /// All stored pairing records.
    #[must_use]
    pub fn records(&self) -> &[PairingRecord] {
        &self.records
    }

    /// Records that the phone revoked `pair_id` with its `pairing_revoked`
    /// close (RAPP v26.10.22 section 4.6 item 4): the keys are destroyed and
    /// the record stays so the user is told.
    ///
    /// # Errors
    ///
    /// Fails when no such pairing is stored, the stored set cannot be read,
    /// or the set cannot be written.
    pub fn revoke_by_peer(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        revoke_pairing(self, pair_id, true)
    }

    /// Replaces the records held here with the stored set as it is now, so
    /// a change applies to what is stored and not to the copy this value was
    /// loaded with: another store instance, in this process or another, may
    /// have forgotten or revoked a pairing or deleted the set in the
    /// meantime. A set that is gone leaves the records empty.
    ///
    /// # Errors
    ///
    /// [`StoreError::Unreadable`] when the set cannot be read; the records
    /// held here stay as they were, and a change written over a set that
    /// could not be read would lose it.
    pub fn refresh(&mut self) -> Result<(), StoreError> {
        self.sightings = read_sightings(&self.directory);
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
        let blob = encode_pairing_records(self.records.iter())
            .map_err(|_error| CredentialStoreError::PairingNotEncodable)?;
        write_pairing_set(&self.directory, &blob)
    }

    /// Re-reads the stored set, applies `change`, and writes it.
    fn change(
        &mut self,
        change: impl FnOnce(&mut Vec<PairingRecord>) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        self.refresh()?;
        change(&mut self.records)?;
        self.persist().map_err(|_error| StoreError::WriteRefused)
    }
}

impl PairingStore for ProtectedPairingStore {
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
        self.change(|records| {
            let pair_id = record.pair_id();
            records.retain(|entry| entry.pair_id() != pair_id);
            records.push(record);
            Ok(())
        })
    }

    fn get(&self, pair_id: PairId) -> Result<&PairingRecord, StoreError> {
        self.records
            .iter()
            .find(|entry| entry.pair_id() == pair_id)
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
                .find(|entry| entry.pair_id() == pair_id)
                .ok_or(StoreError::Unknown)?;
            change(record);
            Ok(())
        })
    }

    fn pair_ids(&self) -> Vec<PairId> {
        self.records
            .iter()
            .rev()
            .map(PairingRecord::pair_id)
            .collect()
    }

    /// Removes the record, then its card sighting; a sighting that cannot
    /// be removed offers nothing without its record.
    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        self.change(|records| {
            let before = records.len();
            records.retain(|entry| entry.pair_id() != pair_id);
            if records.len() == before {
                return Err(StoreError::Unknown);
            }
            Ok(())
        })?;
        remove_sighting(&self.directory, pair_id);
        self.sightings.retain(|(sighted, _)| *sighted != pair_id);
        Ok(())
    }

    fn card_sighting(&self, pair_id: PairId) -> Option<CardSighting> {
        self.sightings
            .iter()
            .find(|(sighted, _)| *sighted == pair_id)
            .map(|(_, sighting)| *sighting)
    }

    /// Replaces the pairing's own sighting file whole; no other pairing's
    /// file is read or written.
    fn record_card_sighting(
        &mut self,
        pair_id: PairId,
        sighting: CardSighting,
    ) -> Result<(), StoreError> {
        write_sighting(&self.directory, pair_id, sighting)
            .map_err(|_error| StoreError::WriteRefused)?;
        self.sightings.retain(|(sighted, _)| *sighted != pair_id);
        self.sightings.push((pair_id, sighting));
        Ok(())
    }
}

/// The directory under the user's local application data that holds the set.
const PROFILE_DIRECTORY: &str = "RefineID";
/// The protected pairing set.
#[cfg(windows)]
const PAIRING_SET_FILE: &str = "pairing-set.dpapi";
/// The directory of the last card a session heard present for each
/// pairing, one unprotected file per pairing: nothing in it is secret.
const CARD_SIGHTINGS_DIRECTORY: &str = "card-sightings";
/// The extension of one pairing's sighting file.
const SIGHTING_EXTENSION: &str = "sighting";
/// The suffix of the temporary file a write fills before the rename.
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

/// A temporary file name for `file` no other write uses: two stores writing
/// at once each fill their own file, and the later rename wins whole.
fn partial_file_name(file: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    static WRITES: AtomicU64 = AtomicU64::new(0);
    let write = WRITES.fetch_add(1, Ordering::Relaxed);
    format!("{file}.{}.{write}.{PARTIAL_SUFFIX}", std::process::id())
}

/// Replaces the file `file` in `directory` with `bytes` whole, through a
/// temporary file of its own and a rename.
fn replace_file(directory: &Path, file: &str, bytes: &[u8]) -> Result<(), CredentialStoreError> {
    use std::io::Write as _;

    std::fs::create_dir_all(directory).map_err(|error| CredentialStoreError::file(&error))?;
    let partial = directory.join(partial_file_name(file));
    let written = std::fs::File::create_new(&partial).and_then(|mut opened| {
        opened.write_all(bytes)?;
        opened.sync_all()
    });
    if let Err(error) = written {
        let _ = std::fs::remove_file(&partial);
        return Err(CredentialStoreError::file(&error));
    }
    std::fs::rename(&partial, directory.join(file)).map_err(|error| {
        let _ = std::fs::remove_file(&partial);
        CredentialStoreError::file(&error)
    })
}

/// The name of `pair_id`'s sighting file: the pair identifier in
/// hexadecimal.
fn sighting_file_name(pair_id: PairId) -> String {
    use core::fmt::Write as _;

    let mut name = String::new();
    for byte in pair_id.as_bytes() {
        // Writing into a String cannot fail.
        let _ = write!(name, "{byte:02x}");
    }
    name.push('.');
    name.push_str(SIGHTING_EXTENSION);
    name
}

/// The card sightings recorded in `directory`, one per pairing file. A
/// file that is unreadable or not a sighting holds none, and is left as it
/// is: the offer it bounded lapses until a session hears the card again.
fn read_sightings(directory: &Path) -> Vec<(PairId, CardSighting)> {
    let Ok(files) = std::fs::read_dir(directory.join(CARD_SIGHTINGS_DIRECTORY)) else {
        return Vec::new();
    };
    files
        .filter_map(Result::ok)
        .map(|file| file.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == SIGHTING_EXTENSION)
        })
        .filter_map(|path| std::fs::read(path).ok())
        .filter_map(|bytes| decode_sighting(&bytes).ok())
        .collect()
}

/// Replaces `pair_id`'s sighting file in `directory` with `sighting`.
fn write_sighting(
    directory: &Path,
    pair_id: PairId,
    sighting: CardSighting,
) -> Result<(), CredentialStoreError> {
    replace_file(
        &directory.join(CARD_SIGHTINGS_DIRECTORY),
        &sighting_file_name(pair_id),
        &encode_sighting(pair_id, sighting),
    )
}

/// Removes `pair_id`'s sighting file from `directory`; one that cannot be
/// removed offers nothing without its pairing.
fn remove_sighting(directory: &Path, pair_id: PairId) {
    let _ = std::fs::remove_file(
        directory
            .join(CARD_SIGHTINGS_DIRECTORY)
            .join(sighting_file_name(pair_id)),
    );
}

/// Protects the serialized pairing set and replaces the stored file with it.
#[cfg(windows)]
fn write_pairing_set(directory: &Path, blob: &[u8]) -> Result<(), CredentialStoreError> {
    replace_file(directory, PAIRING_SET_FILE, &protect(blob)?)
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
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(CredentialStoreError::file(&error)),
    }
    match std::fs::remove_dir_all(directory.join(CARD_SIGHTINGS_DIRECTORY)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CredentialStoreError::file(&error)),
    }
}

#[cfg(not(windows))]
const fn delete_pairing_set_in(_directory: &Path) -> Result<(), CredentialStoreError> {
    Err(CredentialStoreError::UnsupportedPlatform)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test scaffolding is constructed to be infallible"
)]
mod sighting_tests {
    use refineid_rapp::CertificateFingerprint;
    use refineid_rapp_core::ids::PairId;
    use refineid_rapp_core::presence::CardSighting;

    use super::{
        CARD_SIGHTINGS_DIRECTORY, read_sightings, remove_sighting, sighting_file_name,
        write_sighting,
    };

    /// A synthetic pair identifier.
    const PAIR: PairId = PairId::from_array(*b"synthetic pair 1");
    /// Another synthetic pair identifier.
    const OTHER_PAIR: PairId = PairId::from_array(*b"synthetic pair 2");
    /// A synthetic card fingerprint.
    const CARD: CertificateFingerprint =
        CertificateFingerprint::from_array(*b"the fingerprint of a known card.");
    /// The wall-clock time the card is heard present.
    const HEARD_AT_MS: u64 = 1_700_000_000_000;
    /// A later time the card is heard present again.
    const HEARD_AGAIN_AT_MS: u64 = 1_700_000_010_000;

    /// A directory of this test's own, removed when it ends.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("refineid-sightings-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sorted(mut sightings: Vec<(PairId, CardSighting)>) -> Vec<(PairId, CardSighting)> {
        sightings.sort_by_key(|(pair_id, _)| *pair_id);
        sightings
    }

    #[test]
    fn each_pairing_keeps_its_own_sighting() {
        let scratch = Scratch::new("per-pairing");
        assert!(read_sightings(&scratch.0).is_empty());
        let first = CardSighting::new(CARD, HEARD_AT_MS);
        let again = CardSighting::new(CARD, HEARD_AGAIN_AT_MS);
        write_sighting(&scratch.0, PAIR, first).unwrap();
        write_sighting(&scratch.0, OTHER_PAIR, first).unwrap();
        write_sighting(&scratch.0, PAIR, again).unwrap();
        assert_eq!(
            sorted(read_sightings(&scratch.0)),
            vec![(PAIR, again), (OTHER_PAIR, first)]
        );
        remove_sighting(&scratch.0, PAIR);
        assert_eq!(read_sightings(&scratch.0), vec![(OTHER_PAIR, first)]);
    }

    #[test]
    fn a_sighting_file_that_does_not_decode_is_left_and_holds_none() {
        let scratch = Scratch::new("foreign");
        let directory = scratch.0.join(CARD_SIGHTINGS_DIRECTORY);
        std::fs::create_dir_all(&directory).unwrap();
        let foreign = directory.join(sighting_file_name(PAIR));
        std::fs::write(&foreign, b"not a sighting").unwrap();
        write_sighting(&scratch.0, OTHER_PAIR, CardSighting::new(CARD, HEARD_AT_MS)).unwrap();
        assert_eq!(
            read_sightings(&scratch.0),
            vec![(OTHER_PAIR, CardSighting::new(CARD, HEARD_AT_MS))]
        );
        assert_eq!(std::fs::read(&foreign).unwrap(), b"not a sighting");
    }
}

#[cfg(all(test, windows))]
mod tests {
    use refineid_lib_core::x509::OwnedCert;
    use refineid_rapp::noise::x25519_public_key;
    use refineid_rapp::{
        EndpointRole, PairRecord, ProfileName, X25519_KEY_SIZE, compute_grants_hash,
    };
    use refineid_rapp_core::engine::PeerIntroduction;
    use refineid_rapp_core::ids::PairId;
    use refineid_rapp_core::store::{PairingRecord, PairingStore, StoreError};

    use super::{
        PAIRING_SET_FILE, ProtectedPairingStore, UNPROTECTED_COPY_FILE, delete_pairing_set_in,
        input_blob, protect, unprotect,
    };

    /// A synthetic requester static private key.
    const REQUESTER_PRIVATE: [u8; X25519_KEY_SIZE] = *b"synthetic requester private key.";
    /// A synthetic custodian static private key.
    const CUSTODIAN_PRIVATE: [u8; X25519_KEY_SIZE] = *b"synthetic custodian private key.";
    /// The pairing creation time the fixtures record.
    const CREATED_AT_MS: u64 = 1_700_000_000_000;
    /// Two public FINEID intermediate CA certificates, as large as the
    /// cards' own, so the set exceeds what one generic credential holds
    /// (`CRED_MAX_CREDENTIAL_BLOB_SIZE`).
    const LARGE_CERTIFICATE: &[u8] =
        include_bytes!("../../refineid-pkcs11/ca-certs/fineid-intermediate-02-citizen-g4r.der");
    const OTHER_LARGE_CERTIFICATE: &[u8] = include_bytes!(
        "../../refineid-pkcs11/ca-certs/fineid-intermediate-03-organisation-g4r.der"
    );
    const FIRST_PAIR: PairId = PairId::from_array(*b"synthetic pair 1");
    const SECOND_PAIR: PairId = PairId::from_array(*b"synthetic pair 2");

    /// A synthetic payload that is not a DPAPI blob.
    const NOT_PROTECTED: &[u8] = b"not a DPAPI blob";

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
        let profiles = vec![ProfileName::Authentication];
        let keys = PairRecord::new(
            pair_id,
            EndpointRole::Requester,
            REQUESTER_PRIVATE,
            x25519_public_key(&REQUESTER_PRIVATE),
            x25519_public_key(&CUSTODIAN_PRIVATE),
            compute_grants_hash(&profiles).expect("grants hash"),
            profiles,
            CREATED_AT_MS,
        )
        .expect("record");
        let mut record = PairingRecord::new(
            keys,
            PeerIntroduction {
                display_name: "Phone".into(),
                platform: "iOS".into(),
            },
        );
        record.remember_authentication_certificate(
            OwnedCert::from_der(LARGE_CERTIFICATE).expect("certificate"),
        );
        record.remember_signature_certificate(
            OwnedCert::from_der(OTHER_LARGE_CERTIFICATE).expect("certificate"),
        );
        record
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
        assert!(unprotect(NOT_PROTECTED).is_err());
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
        let pair_id = FIRST_PAIR;
        let mut store = ProtectedPairingStore::load_from(directory.0.clone()).expect("load");
        assert!(store.is_empty());
        store.insert(record(pair_id)).expect("insert");

        let on_disk = std::fs::read(directory.0.join(PAIRING_SET_FILE)).expect("file written");
        assert!(
            !on_disk
                .as_slice()
                .windows(REQUESTER_PRIVATE.len())
                .any(|window| window == REQUESTER_PRIVATE)
        );

        let mut reloaded = ProtectedPairingStore::load_from(directory.0.clone()).expect("reload");
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded.get(pair_id).expect("stored").pair_id(), pair_id);
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
        let first = FIRST_PAIR;
        let second = SECOND_PAIR;
        let mut store = ProtectedPairingStore::load_from(directory.0.clone()).expect("load");
        store.insert(record(first)).expect("insert");
        let stored = directory.0.join(PAIRING_SET_FILE);
        let before = std::fs::read(&stored).expect("stored");
        std::fs::write(&stored, NOT_PROTECTED).expect("corrupt");

        assert_eq!(store.insert(record(second)), Err(StoreError::Unreadable));
        assert_eq!(std::fs::read(&stored).expect("still there"), NOT_PROTECTED);
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
