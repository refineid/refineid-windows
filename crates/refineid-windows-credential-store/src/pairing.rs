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
//! storage (RAPP v26.11.2 section 4.3 item 4). The whole pairing set is
//! serialized by [`refineid_rapp_core::persistence`], protected with
//! `CryptProtectData` to the current user under a purpose entropy, and
//! written as one file in the user's local application data, through a
//! temporary file of its own and a rename, so an insert, update, or removal
//! replaces the set at once. Only this Windows user, on this computer, can
//! unprotect it. The set is one file rather than a Credential Manager
//! credential, which holds at most `CRED_MAX_CREDENTIAL_BLOB_SIZE` (2560)
//! bytes.
//!
//! DPAPI separates Windows users and does not separate people who share one
//! Windows user, so the set holds no certificate of a holder: the card's
//! authentication certificate is read from the phone at every session and
//! kept in the memory of the process that holds it. A record the phone
//! revoked keeps the phone's name for
//! [`REVOCATION_NOTICE_DAYS`](refineid_rapp_core::store::REVOCATION_NOTICE_DAYS).
//! Every load and every change judges the set by the store's clock, and
//! writes what is left when the judgement changed it. A reader beside the
//! owner does this too, since it may be the only program running; a write
//! it cannot make is tried again by the next one.
//!
//! One stamp of the set's file (its length and times, which every write's
//! rename changes) decides what a look at the store costs. Housekeeping,
//! what lies beside the set, is done when the file differs from the one
//! this process last kept house at: at its first load, after every change,
//! and once after another process changed the set, never at every load or
//! [`ProtectedPairingStore::follow`] of an unchanged set, since a process
//! loads the store for each operation. It deletes the unprotected copies
//! and what earlier builds left, removes each entry this user's personal
//! certificate store holds for a pairing whose phone no session heard
//! within the grace, and each card sighting file that bounds no offer.
//! Between housekeepings a look holds no such sighting in memory either. A
//! store value reads and decrypts the set again only when its file changed
//! since it last read it, and the personal store is listed before the set
//! is read, so one decryption serves the read and its judgement.
//!
//! The keys stay in `Zeroizing` buffers, are wiped from every intermediate
//! buffer, and are never logged. The store deletes, unread, every
//! unprotected copy of the set it finds: plaintext files in the user's and
//! the machine's application data, and the generic credential.
//!
//! [`ProtectedPairingStore`] keeps the decoded records in memory so it can
//! satisfy the borrowing [`PairingStore`] contract, and writes the set through
//! on every change, after re-reading it: a change is never written over a set
//! that could not be read. An idle-expiry check (RAPP v26.11.2 section 4.6
//! item 5) writes the set first and changes the record held here only once
//! the write succeeded.
//!
//! Stored pairings are not migrated: a record the codec refuses, written
//! for an earlier protocol version or holding an engine record of an
//! earlier format, is left out at load, and the set is written back
//! without it, so it is refused once.
//!
//! Beside the set, in a directory of plain files, one per pairing, the
//! store keeps the last card a session heard present (RAPP v26.11.2
//! section 8.4): a pair identifier, the fingerprint of a public certificate
//! and a time, nothing secret. Every requester process of this user offers
//! the phone's identity by it, and a session refreshes it every few
//! seconds, so it is not written through the protected set. Each pairing's
//! file is replaced whole, so no write reads another's or touches it. A
//! fingerprint still says which card was here, so a sighting is kept only
//! while its pairing serves and it bounds an offer: no longer than the grace
//! of section 8.4 item 3, or until the next `RefineID` process of this user
//! runs when that is later.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::persistence::{
    PairingCodecError, PairingSet, decode_pairing_records, encode_pairing_records,
};
use refineid_rapp_core::presence::{CardSighting, decode_sighting, encode_sighting};
use refineid_rapp_core::store::{
    PairingRecord, PairingStore, RecordStoreError, StoreError, SweepOutcome,
    drop_outlived_revocations, expire_revocation_notices, remove_unconfirmed, revoke_pairing,
};
use zeroize::Zeroizing;

use crate::CredentialStoreError;
use crate::certstore::{
    BrowserEntry, browser_entries, remove_browser_entries, stale_browser_entries,
};

/// The wall clock the store judges its bounds by: milliseconds since the
/// Unix epoch.
type Clock = fn() -> u64;

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
    clock: Clock,
    /// Whether this store judges this user's personal certificate store. A
    /// test's store, in a directory of its own, leaves it alone.
    judges_browser_entries: bool,
    /// Whether a pairing stored by an earlier build was removed and no
    /// pairing has been stored since.
    earlier_pairing_removed: bool,
    /// The protected set's file as it was just before this value last read
    /// it for [`Self::follow`], or `None` while that is not known.
    followed: Option<SetStamp>,
}

/// What the protected set's file looked like at one look: its length and
/// its modification and creation times, `None` for no file. A write
/// replaces the file through a rename, which changes them.
type SetStamp = Option<(
    u64,
    Option<std::time::SystemTime>,
    Option<std::time::SystemTime>,
)>;

impl ProtectedPairingStore {
    /// Loads this user's stored pairing set, or an empty store when none
    /// exists yet, after deleting every unprotected copy of a set.
    ///
    /// A record whose peer never confirmed its storage was written inside a
    /// pairing this computer did not complete; it is removed with its keys
    /// here, at the first load after that pairing (RAPP v26.11.2 section
    /// 4.3 item 4). A forgotten pairing whose `pairing_revoked` close was
    /// not delivered within 30 days loses its keys untold (section 4.6
    /// item 3). A record the codec refuses is left out, and the set is
    /// written back without it. A set this build cannot decode, and that no
    /// later build wrote, is deleted with its card sightings. Either way the
    /// user is told to pair again ([`Self::earlier_pairing_removed`]).
    /// The revocation notice's bound is applied to what is left, and the
    /// personal certificate store and the card sightings beside it are
    /// judged. What earlier
    /// builds left in the directory and this build never reads is removed.
    ///
    /// # Errors
    ///
    /// Fails when an unprotected copy in this user's profile cannot be
    /// deleted, the protected set cannot be read or unprotected, the stored
    /// set is of a later build's format or cannot be deleted, or this build
    /// is not running on Windows.
    pub fn load() -> Result<Self, CredentialStoreError> {
        Self::load_with(
            profile_directory()?,
            refineid_rapp_core::clock::unix_time_ms,
            true,
        )
    }

    /// Loads the pairing set kept in `directory`, judged by `clock`.
    fn load_with(
        directory: PathBuf,
        clock: Clock,
        judges_browser_entries: bool,
    ) -> Result<Self, CredentialStoreError> {
        let followed = set_stamp(&directory);
        let housekeeping = housekeeping_due(&directory, followed);
        if housekeeping {
            remove_unprotected_copies(&directory)?;
            remove_earlier_build_files(&directory);
        }
        // Listed before the set is read: the program that offers a
        // certificate writes its record before it installs the entry, so an
        // entry listed here has its record in the set read next.
        let entries = (housekeeping && judges_browser_entries).then(browser_entries);
        let mut set_removed = false;
        let set = match read_pairing_set(&directory)? {
            Some(blob) => match decode_pairing_records(&blob) {
                Ok(set) => set,
                Err(error) if written_by_a_later_build(error) => {
                    return Err(CredentialStoreError::InvalidStoredPairing);
                }
                Err(error) => {
                    refineid_dev_errors::report!(Rapp, "stored pairing set removed", error);
                    delete_pairing_set_in(&directory)?;
                    leave_earlier_pairing_notice(&directory);
                    set_removed = true;
                    PairingSet::default()
                }
            },
            None => PairingSet::default(),
        };
        if set.refused > 0 {
            leave_earlier_pairing_notice(&directory);
        }
        let sightings = read_sightings(&directory);
        let earlier_pairing_removed = directory.join(EARLIER_PAIRING_NOTICE).exists();
        let mut store = Self {
            records: set.records,
            sightings,
            directory,
            clock,
            judges_browser_entries,
            earlier_pairing_removed,
            followed: Some(followed),
        };
        // Each change is written as it is made; one that could not be
        // written stands in memory and is written here, as is the set
        // without its refused records.
        let removed = remove_unconfirmed(&mut store);
        let now_ms = clock();
        let expired = expire_revocation_notices(&mut store, now_ms);
        let bounded = drop_outlived_revocations(&mut store.records, now_ms);
        let rewritten = !removed.is_empty() || !expired.is_empty() || set.refused > 0;
        if rewritten {
            store.persist()?;
        } else if bounded {
            store.persist_bound();
        }
        if housekeeping {
            store.judge_beside(entries);
        } else if rewritten || bounded || set_removed {
            store.judge_what_lies_beside();
        } else {
            store.hold_bounding_sightings();
        }
        Ok(store)
    }

    /// Whether a pairing an earlier build stored, in a format this build
    /// does not read, was removed and no pairing has been stored since: the
    /// user is told to pair again.
    #[must_use]
    pub const fn earlier_pairing_removed(&self) -> bool {
        self.earlier_pairing_removed
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
    /// owed to the phone (RAPP v26.11.2 section 4.6 item 2).
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
    /// close (RAPP v26.11.2 section 4.6 item 4): the keys are destroyed and
    /// the record stays so the user is told.
    ///
    /// # Errors
    ///
    /// Fails when no such pairing is stored, the stored set cannot be read,
    /// or the set cannot be written.
    pub fn revoke_by_peer(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        revoke_pairing(self, pair_id, true, (self.clock)())
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
        if self.reread()? {
            self.persist_bound();
            self.judge_what_lies_beside();
        }
        Ok(())
    }

    /// Brings the card sightings and records held here up to what is
    /// stored, at the cost of reading the sightings and the set file's
    /// metadata while the set is unchanged: the protected set is read and
    /// unprotected again only when its file changed since this value last
    /// read it, as [`Self::refresh`] does. A reader that asks at every call
    /// of a host, as the PKCS#11 module does, stays cheap.
    ///
    /// # Errors
    ///
    /// As [`Self::refresh`].
    pub fn follow(&mut self) -> Result<(), StoreError> {
        let stamp = set_stamp(&self.directory);
        if self.followed == Some(stamp) {
            self.sightings = read_sightings(&self.directory);
            self.hold_bounding_sightings();
            return Ok(());
        }
        let housekeeping = housekeeping_due(&self.directory, stamp);
        let entries = (housekeeping && self.judges_browser_entries).then(browser_entries);
        let bounded = self.reread()?;
        if bounded {
            self.persist_bound();
        }
        if housekeeping || bounded {
            self.judge_beside(entries);
        } else {
            self.hold_bounding_sightings();
        }
        Ok(())
    }

    /// Replaces the records held here with the stored set as it is now,
    /// without a revoked record whose notice passed at this moment. Returns
    /// whether that bound removed anything.
    fn reread(&mut self) -> Result<bool, StoreError> {
        self.sightings = read_sightings(&self.directory);
        let stamp = set_stamp(&self.directory);
        match read_pairing_set(&self.directory) {
            Ok(Some(blob)) => {
                self.records = decode_pairing_records(&blob)
                    .map_err(|_error| StoreError::Unreadable)?
                    .records;
            }
            Ok(None) => self.records.clear(),
            Err(_error) => return Err(StoreError::Unreadable),
        }
        self.followed = Some(stamp);
        Ok(drop_outlived_revocations(&mut self.records, (self.clock)()))
    }

    /// Writes the set after the notice's bound changed it. A refused write
    /// is tried again by the next judgement; a program that only reads may
    /// have no right to write.
    fn persist_bound(&mut self) {
        if let Err(error) = self.persist() {
            refineid_dev_errors::report!(Rapp, "outlived notice not written", error);
        }
    }

    /// Brings what lies beside the set in line with the records: the card
    /// sightings, what a stopped write left, and the entries of this user's
    /// personal certificate store.
    ///
    /// The personal store is listed first and the set read again after: the
    /// program that offers a certificate writes its record before it installs
    /// the entry, so an entry listed here has its record in what is read next.
    fn judge_what_lies_beside(&mut self) {
        self.judge_beside(None);
    }

    /// [`Self::judge_what_lies_beside`], with the personal store's entries
    /// `listed` before the records held here were read, or listed here and
    /// the set read again after when `None`.
    fn judge_beside(&mut self, listed: Option<Vec<BrowserEntry>>) {
        self.judge_beside_unrecorded(listed);
        housekeeping_done(&self.directory);
    }

    /// [`Self::judge_beside`], without recording that this process kept
    /// house.
    fn judge_beside_unrecorded(&mut self, listed: Option<Vec<BrowserEntry>>) {
        let now_ms = (self.clock)();
        let records = &self.records;
        keep_sightings(&self.directory, now_ms, &|pair_id, sighting| {
            bounds_an_offer(records, now_ms, pair_id, sighting)
        });
        self.sightings = read_sightings(&self.directory);
        remove_stopped_writes(&self.directory, now_ms);
        if !self.judges_browser_entries {
            return;
        }
        let entries = if let Some(entries) = listed {
            entries
        } else {
            let entries = browser_entries();
            if entries.is_empty() || self.reread().is_err() {
                return;
            }
            entries
        };
        if entries.is_empty() {
            return;
        }
        let records: Vec<&PairingRecord> = self.records.iter().collect();
        let sightings = &self.sightings;
        let sighting = |pair_id: PairId| {
            sightings
                .iter()
                .find(|(sighted, _)| *sighted == pair_id)
                .map(|(_, sighting)| *sighting)
        };
        let stale = stale_browser_entries(&entries, &records, &sighting, now_ms);
        if !stale.is_empty() {
            remove_browser_entries(&stale);
        }
    }

    /// Holds only the card sightings that bound an offer, as a judgement
    /// would leave them, without touching their files.
    fn hold_bounding_sightings(&mut self) {
        let now_ms = (self.clock)();
        let records = &self.records;
        self.sightings
            .retain(|(pair_id, sighting)| bounds_an_offer(records, now_ms, *pair_id, *sighting));
    }

    /// Writes the current record set through to the protected file.
    fn persist(&mut self) -> Result<(), CredentialStoreError> {
        let blob = encode_pairing_records(self.records.iter())
            .map_err(|_error| CredentialStoreError::PairingNotEncodable)?;
        write_pairing_set(&self.directory, &blob)?;
        self.followed = Some(set_stamp(&self.directory));
        Ok(())
    }

    /// Re-reads the stored set, applies `change`, and writes it.
    fn change(
        &mut self,
        change: impl FnOnce(&mut Vec<PairingRecord>) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        self.refresh()?;
        change(&mut self.records)?;
        drop_outlived_revocations(&mut self.records, (self.clock)());
        self.persist().map_err(|_error| StoreError::WriteRefused)?;
        self.judge_what_lies_beside();
        Ok(())
    }
}

impl PairingStore for ProtectedPairingStore {
    /// Stores the record; a pairing stored answers the notice that an
    /// earlier build's pairing was removed.
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
        self.change(|records| {
            let pair_id = record.pair_id();
            records.retain(|entry| entry.pair_id() != pair_id);
            records.push(record);
            Ok(())
        })?;
        remove_earlier_pairing_notice(&self.directory);
        self.earlier_pairing_removed = false;
        Ok(())
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

    /// Removes the record; the judgement after the change takes its card
    /// sighting and its entry in the personal certificate store.
    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        self.change(|records| {
            let before = records.len();
            records.retain(|entry| entry.pair_id() != pair_id);
            if records.len() == before {
                return Err(StoreError::Unknown);
            }
            Ok(())
        })?;
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

    /// Removes the pairing's own sighting file; one that cannot be removed
    /// is read back by the next refresh, and the identity it names ages out
    /// over the grace.
    fn drop_card_sighting(&mut self, pair_id: PairId) {
        remove_sighting(&self.directory, pair_id);
        self.sightings.retain(|(sighted, _)| *sighted != pair_id);
    }

    /// Re-reads the stored set and checks the pairing as it is stored now;
    /// a change is written as the whole set, with the checked record in its
    /// place, before the record held here changes. A pairing that expired
    /// has nobody to tell, so nothing of it is written.
    fn sweep(
        &mut self,
        pair_id: PairId,
        now_ms: u64,
        session_established: bool,
    ) -> Result<SweepOutcome, RecordStoreError<StoreError>> {
        self.refresh().map_err(RecordStoreError::Store)?;
        let index = self
            .records
            .iter()
            .position(|entry| entry.pair_id() == pair_id)
            .ok_or(RecordStoreError::Store(StoreError::Unknown))?;
        let (before, from) = self.records.split_at_mut(index);
        let Some((record, after)) = from.split_first_mut() else {
            return Err(RecordStoreError::Store(StoreError::Unknown));
        };
        let directory = &self.directory;
        let outcome = record.sweep(now_ms, session_established, |checked| {
            let mut set: Vec<&PairingRecord> = before.iter().collect();
            if !checked.revoked_record_outlived(now_ms) {
                set.push(checked);
            }
            set.extend(after.iter());
            let blob = encode_pairing_records(set.iter().copied())
                .map_err(|_error| StoreError::WriteRefused)?;
            write_pairing_set(directory, &blob).map_err(|_error| StoreError::WriteRefused)
        })?;
        // A write left the set as held here, so following it reads nothing.
        self.followed = Some(set_stamp(&self.directory));
        if outcome == SweepOutcome::Expired {
            drop_outlived_revocations(&mut self.records, now_ms);
            self.judge_what_lies_beside();
        }
        Ok(outcome)
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
/// How old a temporary file is before it counts as left by a stopped write:
/// far longer than any write, so no write in progress is taken.
const STOPPED_WRITE_AGE_MS: u64 = 60_000;
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

/// The notice that a pairing an earlier build stored was removed, until a
/// pairing is stored again. It is empty: its presence is the notice.
const EARLIER_PAIRING_NOTICE: &str = "earlier-pairing-removed";
/// What earlier builds, and development deployments of them, left in the
/// directory that this build neither reads nor writes: a log file of
/// builds that logged, the lock file of an unreleased build, and agent
/// copies the pipe client refuses, as only the installed agent under
/// Program Files serves.
const EARLIER_BUILD_FILES: &[&str] = &["agent.log", "pairing-set.lock", "bin"];

/// Each profile directory this process kept house in, with the stamp its
/// set's file had when it last did.
static HOUSEKEPT: Mutex<Vec<(PathBuf, SetStamp)>> = Mutex::new(Vec::new());

/// Whether a look at `directory`, whose set's file has `stamp`, keeps
/// house: this process never kept house there, or the set changed since.
fn housekeeping_due(directory: &Path, stamp: SetStamp) -> bool {
    !HOUSEKEPT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .any(|(kept, at)| kept == directory && *at == stamp)
}

/// Records that this process kept house in `directory` at its set's file
/// as it is now.
fn housekeeping_done(directory: &Path) {
    let stamp = set_stamp(directory);
    let mut kept = HOUSEKEPT.lock().unwrap_or_else(PoisonError::into_inner);
    match kept.iter_mut().find(|(kept, _)| kept == directory) {
        Some((_, at)) => *at = stamp,
        None => kept.push((directory.to_path_buf(), stamp)),
    }
}

/// Forgets that this process kept house in `directory`, as a new process
/// would.
#[cfg(all(test, windows))]
fn forget_housekeeping(directory: &Path) {
    HOUSEKEPT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|(kept, _)| kept != directory);
}

/// Whether `sighting` of `pair_id` bounds an offer at `now_ms`: it has not
/// lapsed and its pairing among `records` serves.
fn bounds_an_offer(
    records: &[PairingRecord],
    now_ms: u64,
    pair_id: PairId,
    sighting: CardSighting,
) -> bool {
    !sighting.lapsed_at(now_ms)
        && records
            .iter()
            .any(|record| record.pair_id() == pair_id && record.serves())
}

/// Whether `error` refuses a set a later build wrote: one of a revision
/// above this build's. A downgrade keeps it, for the later build to read.
const fn written_by_a_later_build(error: PairingCodecError) -> bool {
    matches!(error, PairingCodecError::UnsupportedVersion { .. })
}

/// Removes [`EARLIER_BUILD_FILES`] from `directory`. One that cannot be
/// removed now is tried again at the next load.
fn remove_earlier_build_files(directory: &Path) {
    for name in EARLIER_BUILD_FILES {
        let path = directory.join(name);
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match removed {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                let kind = error.kind();
                refineid_dev_errors::report!(Rapp, "earlier build's file not removed", kind);
            }
        }
    }
}

/// Leaves the notice that an earlier build's pairing was removed. A notice
/// that cannot be written leaves the user with the plain no-pairing status.
fn leave_earlier_pairing_notice(directory: &Path) {
    if let Err(error) = replace_file(directory, EARLIER_PAIRING_NOTICE, &[]) {
        refineid_dev_errors::report!(Rapp, "pairing notice not written", error);
    }
}

/// Removes the notice once a pairing is stored.
fn remove_earlier_pairing_notice(directory: &Path) {
    match std::fs::remove_file(directory.join(EARLIER_PAIRING_NOTICE)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            let kind = error.kind();
            refineid_dev_errors::report!(Rapp, "pairing notice not removed", kind);
        }
    }
}

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

/// Removes from `directory` every sighting file `keep` refuses and every file
/// that is not a sighting; a file that cannot be removed is judged again next
/// time. A temporary file of a write in progress stays.
fn keep_sightings(directory: &Path, now_ms: u64, keep: &dyn Fn(PairId, CardSighting) -> bool) {
    let sightings = directory.join(CARD_SIGHTINGS_DIRECTORY);
    remove_stopped_writes(&sightings, now_ms);
    let Ok(files) = std::fs::read_dir(&sightings) else {
        return;
    };
    for path in files.filter_map(Result::ok).map(|file| file.path()) {
        if is_partial(&path) {
            continue;
        }
        let kept = std::fs::read(&path)
            .ok()
            .and_then(|bytes| decode_sighting(&bytes).ok())
            .is_some_and(|(pair_id, sighting)| keep(pair_id, sighting));
        if !kept {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Whether `path` names a temporary file a write fills before the rename.
fn is_partial(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension == PARTIAL_SUFFIX)
}

/// Removes from `directory` the temporary files of writes that stopped: a
/// crash between filling one and the rename leaves what it was about to store.
fn remove_stopped_writes(directory: &Path, now_ms: u64) {
    let Ok(files) = std::fs::read_dir(directory) else {
        return;
    };
    for file in files.filter_map(Result::ok) {
        let path = file.path();
        if !is_partial(&path) {
            continue;
        }
        let written_ms = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|since| u64::try_from(since.as_millis()).ok());
        if written_ms.is_none_or(|at_ms| now_ms.saturating_sub(at_ms) >= STOPPED_WRITE_AGE_MS) {
            let _ = std::fs::remove_file(path);
        }
    }
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

/// The protected set's file in `directory` as it looks now.
#[cfg(windows)]
fn set_stamp(directory: &Path) -> SetStamp {
    std::fs::metadata(directory.join(PAIRING_SET_FILE))
        .ok()
        .map(|metadata| {
            (
                metadata.len(),
                metadata.modified().ok(),
                metadata.created().ok(),
            )
        })
}

#[cfg(not(windows))]
const fn set_stamp(_directory: &Path) -> SetStamp {
    None
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

/// Synthetic records for this crate's tests, on every platform.
#[cfg(test)]
pub mod test_records {
    use refineid_lib_core::x509::{OwnedCert, UnvalidatedCertificate};
    use refineid_rapp::noise::x25519_public_key;
    use refineid_rapp::{
        DisplayName, EndpointRole, PairRecord, ProfileName, X25519_KEY_SIZE, compute_grants_hash,
    };
    use refineid_rapp_core::ids::PairId;
    use refineid_rapp_core::store::PairingRecord;
    #[cfg(windows)]
    use refineid_rapp_core::store::{REVOCATION_NOTICE_DAYS, REVOCATION_NOTICE_MS};

    /// A synthetic requester static private key.
    pub const REQUESTER_PRIVATE: [u8; X25519_KEY_SIZE] = *b"synthetic requester private key.";
    /// A synthetic custodian static private key.
    const CUSTODIAN_PRIVATE: [u8; X25519_KEY_SIZE] = *b"synthetic custodian private key.";
    /// A synthetic certificate standing in for a holder's.
    pub const CERTIFICATE: &[u8] = include_bytes!("../../refineid-rapp-cli/src/mock_cert.der");
    /// The pairing creation time the fixtures record.
    pub const CREATED_AT_MS: u64 = 1_700_000_000_000;
    /// One day in milliseconds.
    #[cfg(windows)]
    const DAY_MS: u64 = REVOCATION_NOTICE_MS / REVOCATION_NOTICE_DAYS;
    /// Six days after creation: short of the revocation notice's bound.
    #[cfg(windows)]
    pub const DAY_6_MS: u64 = CREATED_AT_MS + REVOCATION_NOTICE_MS - DAY_MS;
    /// Eight days after creation: past it.
    #[cfg(windows)]
    pub const DAY_8_MS: u64 = CREATED_AT_MS + REVOCATION_NOTICE_MS + DAY_MS;
    /// The fixtures' pairing.
    pub const PAIR: PairId = PairId::from_array(*b"synthetic pair 1");

    /// The fixtures' pairing `pair_id`, created at `created_at_ms`.
    pub fn bare_record(pair_id: PairId, created_at_ms: u64) -> PairingRecord {
        let profiles = vec![ProfileName::Authentication];
        let keys = PairRecord::new(
            pair_id,
            EndpointRole::Requester,
            REQUESTER_PRIVATE,
            x25519_public_key(&REQUESTER_PRIVATE),
            x25519_public_key(&CUSTODIAN_PRIVATE),
            compute_grants_hash(&profiles).expect("grants hash"),
            profiles,
            DisplayName::parse("Phone".to_owned()).expect("a display name"),
            created_at_ms,
        )
        .expect("record");
        PairingRecord::new(keys, "iOS".to_owned())
    }

    /// The fixtures' certificate, parsed.
    pub fn certificate() -> OwnedCert {
        OwnedCert::from_der(UnvalidatedCertificate::new(CERTIFICATE.to_vec())).expect("certificate")
    }

    /// [`PAIR`], created at [`CREATED_AT_MS`].
    pub fn paired_record() -> PairingRecord {
        bare_record(PAIR, CREATED_AT_MS)
    }
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
        CARD_SIGHTINGS_DIRECTORY, PARTIAL_SUFFIX, STOPPED_WRITE_AGE_MS, keep_sightings,
        read_sightings, remove_sighting, remove_stopped_writes, sighting_file_name, write_sighting,
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
    fn a_judgement_keeps_only_what_it_approves_and_takes_foreign_files() {
        let scratch = Scratch::new("judgement");
        let first = CardSighting::new(CARD, HEARD_AT_MS);
        write_sighting(&scratch.0, PAIR, first).unwrap();
        write_sighting(&scratch.0, OTHER_PAIR, first).unwrap();
        let directory = scratch.0.join(CARD_SIGHTINGS_DIRECTORY);
        let foreign = directory.join("foreign.sighting");
        std::fs::write(&foreign, b"not a sighting").unwrap();
        keep_sightings(&scratch.0, HEARD_AT_MS, &|pair_id, _| pair_id == OTHER_PAIR);
        assert_eq!(read_sightings(&scratch.0), vec![(OTHER_PAIR, first)]);
        assert!(!foreign.exists());
        keep_sightings(&scratch.0, HEARD_AT_MS, &|_, _| false);
        assert!(read_sightings(&scratch.0).is_empty());
    }

    #[test]
    fn a_temporary_file_stays_while_young_and_leaves_when_its_write_stopped() {
        let scratch = Scratch::new("stopped");
        std::fs::create_dir_all(&scratch.0).unwrap();
        let partial = scratch.0.join(format!("set.1.1.{PARTIAL_SUFFIX}"));
        std::fs::write(&partial, b"a stopped write").unwrap();
        let written_ms = std::fs::metadata(&partial)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let written_ms = u64::try_from(written_ms).unwrap();
        remove_stopped_writes(&scratch.0, written_ms);
        assert!(partial.exists());
        remove_stopped_writes(&scratch.0, written_ms + STOPPED_WRITE_AGE_MS);
        assert!(!partial.exists());
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
    use refineid_rapp::{CertificateFingerprint, PAIRING_IDLE_EXPIRY_MS};
    use refineid_rapp_core::ids::PairId;
    use refineid_rapp_core::presence::CardSighting;
    use refineid_rapp_core::store::{
        PairingRecord, PairingState, PairingStore, RecordStoreError, StoreError, SweepOutcome,
        forget_pairing, revoke_pairing,
    };

    use super::test_records::{
        CREATED_AT_MS, DAY_6_MS, DAY_8_MS, PAIR, REQUESTER_PRIVATE, bare_record, certificate,
        paired_record,
    };
    use super::{
        CARD_SIGHTINGS_DIRECTORY, EARLIER_BUILD_FILES, EARLIER_PAIRING_NOTICE, PAIRING_SET_FILE,
        ProtectedPairingStore, UNPROTECTED_COPY_FILE, delete_pairing_set_in, forget_housekeeping,
        input_blob, protect, sighting_file_name, unprotect,
    };

    /// The store in `directory` with today's clock, as a process that just
    /// started loads it, leaving this user's personal certificate store
    /// alone.
    fn load_from(
        directory: std::path::PathBuf,
    ) -> Result<ProtectedPairingStore, crate::CredentialStoreError> {
        forget_housekeeping(&directory);
        ProtectedPairingStore::load_with(directory, refineid_rapp_core::clock::unix_time_ms, false)
    }

    /// The store in `directory`, its clock reading `clock`, as a process
    /// that just started loads it.
    fn load_at(directory: &std::path::Path, clock: super::Clock) -> ProtectedPairingStore {
        forget_housekeeping(directory);
        reload_at(directory, clock)
    }

    /// The store in `directory`, its clock reading `clock`, loaded again by
    /// a process that loaded it before.
    fn reload_at(directory: &std::path::Path, clock: super::Clock) -> ProtectedPairingStore {
        ProtectedPairingStore::load_with(directory.to_path_buf(), clock, false).expect("load")
    }

    const fn at_creation() -> u64 {
        CREATED_AT_MS
    }

    const fn at_day_6() -> u64 {
        DAY_6_MS
    }

    const fn at_day_8() -> u64 {
        DAY_8_MS
    }

    /// Whether the set stored in `directory`, unprotected, holds the
    /// certificate's bytes anywhere.
    fn stored_set_holds_the_certificate(directory: &std::path::Path) -> bool {
        let protected = std::fs::read(directory.join(PAIRING_SET_FILE)).expect("stored");
        let plain = unprotect(&protected).expect("unprotected");
        plain
            .as_slice()
            .windows(super::test_records::CERTIFICATE.len())
            .any(|window| window == super::test_records::CERTIFICATE)
    }

    /// A sighting of the fixtures' certificate heard at `heard_at_ms`.
    fn sighting(heard_at_ms: u64) -> CardSighting {
        CardSighting::new(
            CertificateFingerprint::of_certificate(certificate().as_der()),
            heard_at_ms,
        )
    }
    /// The moment the fixtures' pairing has had no session for the idle
    /// limit, counted from its creation.
    const IDLE_EXPIRED_AT_MS: u64 = CREATED_AT_MS + PAIRING_IDLE_EXPIRY_MS;
    /// Several stored pairings.
    const STORED_PAIRS: [PairId; 4] = [
        FIRST_PAIR,
        SECOND_PAIR,
        PairId::from_array(*b"synthetic pair 3"),
        PairId::from_array(*b"synthetic pair 4"),
    ];
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
        record_created_at(pair_id, CREATED_AT_MS)
    }

    /// The fixtures' pairing as created at `created_at_ms`.
    fn record_created_at(pair_id: PairId, created_at_ms: u64) -> PairingRecord {
        bare_record(pair_id, created_at_ms)
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

    /// A synthetic stored set in no format any build writes.
    const NO_KNOWN_FORMAT: &[u8] = b"synthetic set in no known format";
    /// A synthetic stored set of a revision far above this build's: the
    /// set's format tag followed by the revision byte `~`.
    const LATER_REVISION: &[u8] = b"RAPP-pair-set~";

    /// Stores `plain`, protected, as the set in `directory`.
    fn store_protected(directory: &std::path::Path, plain: &[u8]) {
        std::fs::write(
            directory.join(PAIRING_SET_FILE),
            protect(plain).expect("protect"),
        )
        .expect("stored");
    }

    #[test]
    fn a_set_this_build_cannot_decode_is_removed_and_the_user_told_to_pair_again() {
        let directory = TestDirectory::new("undecodable");
        store_protected(&directory.0, NO_KNOWN_FORMAT);
        let store = load_from(directory.0.clone()).expect("load");
        assert!(store.is_empty());
        assert!(store.earlier_pairing_removed());
        assert!(!directory.0.join(PAIRING_SET_FILE).exists());
        assert!(directory.0.join(EARLIER_PAIRING_NOTICE).exists());
        let reloaded = load_from(directory.0.clone()).expect("reload");
        assert!(reloaded.earlier_pairing_removed());
    }

    #[test]
    fn a_set_a_later_build_wrote_is_kept() {
        let directory = TestDirectory::new("later");
        store_protected(&directory.0, LATER_REVISION);
        assert!(load_from(directory.0.clone()).is_err());
        assert!(directory.0.join(PAIRING_SET_FILE).exists());
        assert!(!directory.0.join(EARLIER_PAIRING_NOTICE).exists());
    }

    #[test]
    fn storing_a_pairing_answers_the_notice() {
        let directory = TestDirectory::new("notice");
        store_protected(&directory.0, NO_KNOWN_FORMAT);
        let mut store = load_from(directory.0.clone()).expect("load");
        store
            .insert(record_created_at(
                FIRST_PAIR,
                refineid_rapp_core::clock::unix_time_ms(),
            ))
            .expect("insert");
        assert!(!store.earlier_pairing_removed());
        assert!(!directory.0.join(EARLIER_PAIRING_NOTICE).exists());
        assert!(
            !load_from(directory.0.clone())
                .expect("reload")
                .earlier_pairing_removed()
        );
    }

    #[test]
    fn what_earlier_builds_left_goes_and_what_this_build_uses_stays() {
        let directory = TestDirectory::new("earlier-files");
        for name in EARLIER_BUILD_FILES {
            std::fs::write(directory.0.join(name), b"synthetic").expect("written");
        }
        let agent_copies = directory.0.join("bin");
        let _ = std::fs::remove_file(&agent_copies);
        std::fs::create_dir_all(agent_copies.join("old")).expect("bin");
        std::fs::write(agent_copies.join("old").join("agent.exe"), b"synthetic").expect("copy");
        let kept = directory.0.join("trusted-lists");
        std::fs::create_dir_all(&kept).expect("kept");
        load_from(directory.0.clone()).expect("load");
        for name in EARLIER_BUILD_FILES {
            assert!(!directory.0.join(name).exists(), "{name} is removed");
        }
        assert!(kept.exists());
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
    fn a_set_survives_a_reload_protected() {
        let directory = TestDirectory::new("reload");
        let pair_id = FIRST_PAIR;
        let mut store = load_from(directory.0.clone()).expect("load");
        assert!(store.is_empty());
        for stored in STORED_PAIRS {
            store
                .insert(record_created_at(
                    stored,
                    refineid_rapp_core::clock::unix_time_ms(),
                ))
                .expect("insert");
        }

        let on_disk = std::fs::read(directory.0.join(PAIRING_SET_FILE)).expect("file written");
        assert!(
            !on_disk
                .as_slice()
                .windows(REQUESTER_PRIVATE.len())
                .any(|window| window == REQUESTER_PRIVATE)
        );

        let mut reloaded = load_from(directory.0.clone()).expect("reload");
        assert_eq!(reloaded.len(), STORED_PAIRS.len());
        assert_eq!(reloaded.get(pair_id).expect("stored").pair_id(), pair_id);
        for stored in STORED_PAIRS {
            reloaded.remove(stored).expect("remove");
        }
        assert!(
            load_from(directory.0.clone())
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
        let mut store = load_from(directory.0.clone()).expect("load");
        store.insert(record(first)).expect("insert");
        let stored = directory.0.join(PAIRING_SET_FILE);
        let before = std::fs::read(&stored).expect("stored");
        std::fs::write(&stored, NOT_PROTECTED).expect("corrupt");

        assert_eq!(store.insert(record(second)), Err(StoreError::Unreadable));
        assert_eq!(std::fs::read(&stored).expect("still there"), NOT_PROTECTED);
        std::fs::write(&stored, before).expect("restore");
    }

    #[test]
    fn an_expiry_is_stored_with_the_whole_record() {
        // The pairing expires now, so the reload finds it inside the notice
        // window of section 4.6 item 3.
        let expired_at_ms = refineid_rapp_core::clock::unix_time_ms();
        let directory = TestDirectory::new("expiry");
        let mut store = load_from(directory.0.clone()).expect("load");
        store
            .insert(record_created_at(
                FIRST_PAIR,
                expired_at_ms - PAIRING_IDLE_EXPIRY_MS,
            ))
            .expect("insert");
        assert_eq!(
            store.sweep(FIRST_PAIR, expired_at_ms, false),
            Ok(SweepOutcome::Expired)
        );
        assert!(store.get(FIRST_PAIR).is_err());
        let reloaded = load_from(directory.0.clone()).expect("reload");
        assert!(reloaded.get(FIRST_PAIR).is_err());
    }

    #[test]
    fn the_stored_bytes_hold_no_certificate() {
        let directory = TestDirectory::new("no-certificate");
        let mut store = load_at(&directory.0, at_creation);
        store.insert(paired_record()).expect("insert");
        store
            .record_card_sighting(PAIR, sighting(CREATED_AT_MS))
            .expect("sighting");
        assert!(!stored_set_holds_the_certificate(&directory.0));
        assert!(
            load_at(&directory.0, at_day_6)
                .get(PAIR)
                .expect("stored")
                .serves()
        );
    }

    #[test]
    fn a_record_this_computer_revoked_leaves_the_store_and_one_the_phone_revoked_stands_a_while() {
        let directory = TestDirectory::new("revoked-records");
        let mut store = load_at(&directory.0, at_creation);
        store.insert(paired_record()).expect("insert");
        revoke_pairing(&mut store, PAIR, false, CREATED_AT_MS).expect("revoke");
        assert!(store.get(PAIR).is_err());

        store.insert(paired_record()).expect("insert");
        store.revoke_by_peer(PAIR).expect("revoke");
        let reloaded = load_at(&directory.0, at_day_6);
        assert_eq!(
            reloaded.get(PAIR).expect("told").state(),
            PairingState::Revoked { by_peer: true }
        );
        assert!(load_at(&directory.0, at_day_8).get(PAIR).is_err());
    }

    #[test]
    fn a_sighting_leaves_with_its_record_and_when_it_lapsed() {
        let directory = TestDirectory::new("sightings");
        let file = directory
            .0
            .join(CARD_SIGHTINGS_DIRECTORY)
            .join(sighting_file_name(PAIR));

        let mut store = load_at(&directory.0, at_creation);
        store.insert(paired_record()).expect("insert");
        store
            .record_card_sighting(PAIR, sighting(CREATED_AT_MS))
            .expect("sighted");
        assert!(file.exists());
        let reloaded = load_at(&directory.0, at_day_6);
        assert!(reloaded.card_sighting(PAIR).is_none());
        assert!(!file.exists(), "a lapsed sighting is not kept");

        let mut store = load_at(&directory.0, at_creation);
        store
            .record_card_sighting(PAIR, sighting(CREATED_AT_MS))
            .expect("sighted");
        store.revoke_by_peer(PAIR).expect("revoke");
        assert!(!file.exists(), "a revoked pairing keeps no sighting");

        store.insert(paired_record()).expect("insert");
        store
            .record_card_sighting(PAIR, sighting(CREATED_AT_MS))
            .expect("sighted");
        forget_pairing(&mut store, PAIR, CREATED_AT_MS).expect("forget");
        assert!(!file.exists(), "a forgotten pairing keeps no sighting");
    }

    #[test]
    fn a_follower_sees_what_another_store_wrote_and_reads_an_unchanged_set_once() {
        let directory = TestDirectory::new("follow");
        let mut follower = load_at(&directory.0, at_creation);
        let mut writer = load_at(&directory.0, at_creation);
        writer.insert(paired_record()).expect("insert");
        follower.follow().expect("followed");
        assert!(follower.get(PAIR).is_ok(), "a pairing stored elsewhere");
        writer
            .record_card_sighting(PAIR, sighting(CREATED_AT_MS))
            .expect("sighted");
        follower.follow().expect("followed");
        assert!(follower.card_sighting(PAIR).is_some(), "a sighting");
        // An unchanged set is not read again: one that no longer
        // unprotects goes unnoticed until its file changes.
        let stamp = follower.followed;
        follower.follow().expect("an unchanged set");
        assert_eq!(follower.followed, stamp);
        forget_pairing(&mut writer, PAIR, CREATED_AT_MS).expect("forget");
        follower.follow().expect("followed");
        assert!(
            follower.usable_pairing().is_none(),
            "a pairing forgotten elsewhere"
        );
    }

    #[test]
    fn a_session_record_keeps_every_other_record_in_its_place() {
        let directory = TestDirectory::new("session-record");
        let mut store = load_from(directory.0.clone()).expect("load");
        store.insert(record(FIRST_PAIR)).expect("insert");
        store.insert(record(SECOND_PAIR)).expect("insert");
        assert_eq!(
            store.sweep(FIRST_PAIR, IDLE_EXPIRED_AT_MS, true),
            Ok(SweepOutcome::Recorded)
        );
        let reloaded = load_from(directory.0.clone()).expect("reload");
        assert_eq!(reloaded.pair_ids(), vec![SECOND_PAIR, FIRST_PAIR]);
        let last_session = |pair_id| {
            reloaded
                .get(pair_id)
                .expect("stored")
                .pair_record()
                .expect("keys")
                .last_session_at_ms()
        };
        assert_eq!(last_session(FIRST_PAIR), Some(IDLE_EXPIRED_AT_MS));
        assert_eq!(last_session(SECOND_PAIR), None);
    }

    #[test]
    fn a_sweep_over_a_set_that_cannot_be_read_changes_nothing_and_is_repeated() {
        let directory = TestDirectory::new("sweep-unreadable");
        let mut store = load_from(directory.0.clone()).expect("load");
        store.insert(record(FIRST_PAIR)).expect("insert");
        let stored = directory.0.join(PAIRING_SET_FILE);
        let before = std::fs::read(&stored).expect("stored");
        std::fs::write(&stored, NOT_PROTECTED).expect("corrupt");

        assert_eq!(
            store.sweep(FIRST_PAIR, IDLE_EXPIRED_AT_MS, false),
            Err(RecordStoreError::Store(StoreError::Unreadable))
        );
        assert!(store.get(FIRST_PAIR).expect("held").serves());
        assert_eq!(std::fs::read(&stored).expect("still there"), NOT_PROTECTED);

        std::fs::write(&stored, before).expect("restore");
        assert_eq!(
            store.sweep(FIRST_PAIR, IDLE_EXPIRED_AT_MS, false),
            Ok(SweepOutcome::Expired)
        );
    }

    #[test]
    fn a_process_keeps_house_at_its_first_load_alone() {
        let directory = TestDirectory::new("housekeeping");
        let copy = directory.0.join(UNPROTECTED_COPY_FILE);
        let mut store = load_at(&directory.0, at_creation);
        store.insert(paired_record()).expect("insert");
        std::fs::write(&copy, b"plaintext set").expect("copy");
        let reloaded = reload_at(&directory.0, at_creation);
        assert_eq!(reloaded.len(), 1);
        assert!(copy.exists(), "a later load keeps no house");
        load_at(&directory.0, at_creation);
        assert!(!copy.exists(), "the next process keeps house");
    }

    #[test]
    fn a_lapsed_sighting_is_not_held_between_housekeepings() {
        let directory = TestDirectory::new("held-sightings");
        let file = directory
            .0
            .join(CARD_SIGHTINGS_DIRECTORY)
            .join(sighting_file_name(PAIR));
        let mut store = load_at(&directory.0, at_creation);
        store.insert(paired_record()).expect("insert");
        store
            .record_card_sighting(PAIR, sighting(CREATED_AT_MS))
            .expect("sighted");
        assert!(
            reload_at(&directory.0, at_creation)
                .card_sighting(PAIR)
                .is_some()
        );
        assert!(
            reload_at(&directory.0, at_day_6)
                .card_sighting(PAIR)
                .is_none()
        );
        assert!(file.exists(), "a later load removes no file");
        assert!(
            load_at(&directory.0, at_day_6)
                .card_sighting(PAIR)
                .is_none()
        );
        assert!(!file.exists(), "the next process removes it");
    }

    #[test]
    fn an_unprotected_copy_in_the_profile_is_deleted_unread() {
        let directory = TestDirectory::new("copy");
        let copy = directory.0.join(UNPROTECTED_COPY_FILE);
        std::fs::write(&copy, b"plaintext set").expect("copy");
        let store = load_from(directory.0.clone()).expect("load");
        assert!(store.is_empty());
        assert!(!copy.exists());
    }
}
