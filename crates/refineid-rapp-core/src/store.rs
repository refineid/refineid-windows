//! Durable pairing records.
//!
//! A pairing record is the atomic result of pairing (RAPP v26.11.2 section
//! 4.3): the engine's own [`PairRecord`], which holds the pair keys,
//! `pair_id`, the granted profiles, `grants_hash`, whether the peer
//! confirmed its storage, and when the user forgot the pairing, together
//! with the labels the peer introduced itself with. A record is stored before
//! the peer
//! confirms its own storage (section 4.3 item 4) and serves nothing until
//! that confirmation is recorded; one found unconfirmed at load was written
//! in a confirmation window this endpoint did not complete, and is removed
//! with its keys.
//!
//! A record its user forgot while no session was open keeps its keys for
//! the `pairing_revoked` close alone, for one bounded attempt: it serves
//! nothing, the attempt sends that close as the first message of a session,
//! and the keys are destroyed once its echo arrives or 10 seconds after the
//! forget (section 4.6 items 2 and 6). A pairing the phone revoked keeps no
//! keys and no certificate; it stays, with the phone's name, only so the user
//! is told (section 4.7), until the user forgets it or
//! [`REVOCATION_NOTICE_DAYS`] pass. A pairing this computer revoked or
//! that expired has nobody to tell, and a durable store keeps nothing of it.
//!
//! A record holds no certificate. The card's authentication certificate
//! names the holder, so it is read from the phone at every session and kept
//! in the memory of the process that holds the session, and that process
//! offers it to local consumers only while the phone is present: a session
//! heard its card within the grace ([`offer_stands`]).
//!
//! The peer's display name lives in the engine's record while the keys are
//! held, and is refreshed at the start of every session (section 4.3 item
//! 4); a revoked record keeps the last one.
//!
//! A pairing that has had no established session for 30 days expires
//! (section 4.6 item 5): the engine's record keeps the latest time a
//! session to it was established, and [`PairingStore::sweep`] checks it,
//! storing the change before it is made. An expired pairing loses its keys
//! at once and nothing is sent (section 4.6 item 6).
//!
//! The store also keeps, per pairing, the last [`CardSighting`]: the card a
//! session on this computer last heard present, which bounds the identity
//! every local consumer is offered (section 8.4 item 3,
//! [`offer_stands`]).
//!
//! The store is a trait so the Windows build can put pair keys behind the
//! platform credential store, while tests use the in-memory form shipped
//! here. A record is neither `Clone` nor printable with its keys: the keys
//! live in the engine's record, which is neither.

use refineid_lib_core::x509::OwnedCert;
use refineid_rapp::{
    ActivePairing, DisplayName, PAIRING_IDLE_EXPIRY_DAYS, PAIRING_IDLE_EXPIRY_MS, PairRecord,
    PairRecordCodecError, PairingError, ProfileName, decode_pair_record,
};
/// What an idle-expiry check did, and why a change to a stored record
/// changed nothing, as [`PairingStore::sweep`] answers.
pub use refineid_rapp::{RecordStoreError, SweepOutcome};

use crate::ids::PairId;
use crate::presence::CardSighting;

/// Days a record the phone revoked keeps the phone's name, so the user is
/// told that the phone forgot this computer (RAPP v26.11.2 section 4.7).
pub const REVOCATION_NOTICE_DAYS: u64 = 7;
const _: () = assert!(REVOCATION_NOTICE_DAYS < PAIRING_IDLE_EXPIRY_DAYS);
/// [`REVOCATION_NOTICE_DAYS`] in milliseconds.
pub const REVOCATION_NOTICE_MS: u64 =
    REVOCATION_NOTICE_DAYS * (PAIRING_IDLE_EXPIRY_MS / PAIRING_IDLE_EXPIRY_DAYS);

/// The revocation time of the stand-in keys a record holds while its own are
/// moved out for a change; it never reaches storage.
const STAND_IN_REVOKED_AT_MS: u64 = 0;

/// The keys of a stored pairing.
enum Keys {
    /// The engine's record: keys, grants, storage confirmation, forget time.
    Held(PairRecord),
    /// The keys are destroyed.
    Revoked {
        /// The pairing that was revoked.
        pair_id: PairId,
        /// Whether the peer revoked it with its `pairing_revoked` close.
        by_peer: bool,
        /// When it was revoked, milliseconds since the Unix epoch.
        at_ms: u64,
        /// The name the peer last sent for itself.
        peer_display_name: DisplayName,
    },
}

/// Where a stored pairing stands (RAPP v26.11.2 sections 4.3 and 4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingState {
    /// Stored, and the peer has not confirmed its own storage: serves
    /// nothing.
    Unconfirmed,
    /// Serves sessions and operations.
    Serving,
    /// Forgotten here while no session was open: serves nothing, and keeps
    /// its keys only for the `pairing_revoked` close of its next session.
    /// The engine's record holds when.
    Forgotten,
    /// Revoked: the keys are destroyed.
    Revoked {
        /// Whether the peer revoked it with its `pairing_revoked` close.
        by_peer: bool,
    },
}

/// One stored peer relationship.
pub struct PairingRecord {
    keys: Keys,
    /// The platform the peer described itself with in `pairing.hello`.
    peer_platform: String,
}

impl core::fmt::Debug for PairingRecord {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PairingRecord")
            .field("pair_id", &self.pair_id())
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl PairingRecord {
    /// The record of a pairing the engine just stored, with the platform
    /// its peer described itself with. The peer's display name is the
    /// engine record's.
    #[must_use]
    pub const fn new(record: PairRecord, peer_platform: String) -> Self {
        Self {
            keys: Keys::Held(record),
            peer_platform,
        }
    }

    /// A revoked record as storage holds it.
    pub(crate) const fn revoked(
        pair_id: PairId,
        by_peer: bool,
        at_ms: u64,
        peer_display_name: DisplayName,
        peer_platform: String,
    ) -> Self {
        Self {
            keys: Keys::Revoked {
                pair_id,
                by_peer,
                at_ms,
                peer_display_name,
            },
            peer_platform,
        }
    }

    /// The pair identifier.
    #[must_use]
    pub const fn pair_id(&self) -> PairId {
        match &self.keys {
            Keys::Held(record) => record.pair_id(),
            Keys::Revoked { pair_id, .. } => *pair_id,
        }
    }

    /// The name the peer last sent for itself (section 4.3 item 4).
    #[must_use]
    pub const fn peer_display_name(&self) -> &DisplayName {
        match &self.keys {
            Keys::Held(record) => record.peer_display_name(),
            Keys::Revoked {
                peer_display_name, ..
            } => peer_display_name,
        }
    }

    /// The platform the peer described itself with when it paired.
    #[must_use]
    pub fn peer_platform(&self) -> &str {
        &self.peer_platform
    }

    /// Keeps `name`, the display name the peer sent at the start of a
    /// session, as the record's (section 4.3 item 4). Returns whether it
    /// differs from the stored one; a record whose keys are destroyed keeps
    /// its last name.
    pub(crate) fn rename_peer(&mut self, name: &DisplayName) -> bool {
        match &mut self.keys {
            Keys::Held(record) => record
                .record_peer_display_name(name, |_| Ok::<(), core::convert::Infallible>(()))
                .unwrap_or(false),
            Keys::Revoked { .. } => false,
        }
    }

    /// Where the pairing stands.
    #[must_use]
    pub const fn state(&self) -> PairingState {
        match &self.keys {
            Keys::Revoked { by_peer, .. } => PairingState::Revoked { by_peer: *by_peer },
            Keys::Held(record) => match record.forgotten_at_ms() {
                Some(_) => PairingState::Forgotten,
                None if record.is_storage_confirmed() => PairingState::Serving,
                None => PairingState::Unconfirmed,
            },
        }
    }

    /// Whether the pairing serves sessions and operations: it holds its
    /// keys, the peer confirmed its storage, and its user has not forgotten
    /// it.
    #[must_use]
    pub const fn serves(&self) -> bool {
        matches!(self.state(), PairingState::Serving)
    }

    /// Whether the pairing was forgotten here and still owes the peer its
    /// `pairing_revoked` close (section 4.6 item 2). Only a pairing the peer
    /// confirmed is told.
    #[must_use]
    pub const fn owes_revocation_notice(&self) -> bool {
        match &self.keys {
            Keys::Held(record) => {
                record.is_storage_confirmed() && record.forgotten_at_ms().is_some()
            }
            Keys::Revoked { .. } => false,
        }
    }

    /// The engine's record of a pairing that serves.
    #[must_use]
    pub const fn serving_record(&self) -> Option<&PairRecord> {
        match &self.keys {
            Keys::Held(record)
                if record.is_storage_confirmed() && record.forgotten_at_ms().is_none() =>
            {
                Some(record)
            }
            Keys::Held(_) | Keys::Revoked { .. } => None,
        }
    }

    /// The engine's record, while the keys are held.
    #[must_use]
    pub const fn pair_record(&self) -> Option<&PairRecord> {
        match &self.keys {
            Keys::Held(record) => Some(record),
            Keys::Revoked { .. } => None,
        }
    }

    /// The profiles the pairing granted; none once revoked.
    #[must_use]
    pub fn granted_profiles(&self) -> &[ProfileName] {
        self.pair_record().map_or(&[], PairRecord::profiles)
    }

    /// Whether nothing of this revoked record is left to keep at `now_ms`:
    /// nobody is to be told of a pairing this computer revoked or that
    /// expired, and the notice that the phone forgot this computer stands for
    /// [`REVOCATION_NOTICE_MS`], or until the clock reads before it.
    #[must_use]
    pub const fn revoked_record_outlived(&self, now_ms: u64) -> bool {
        match self.keys {
            Keys::Held(_) => false,
            Keys::Revoked { by_peer: false, .. } => true,
            Keys::Revoked {
                by_peer: true,
                at_ms,
                ..
            } => now_ms < at_ms || now_ms - at_ms >= REVOCATION_NOTICE_MS,
        }
    }

    /// When the pairing was revoked, while its keys are destroyed.
    #[must_use]
    pub const fn revoked_at_ms(&self) -> Option<u64> {
        match self.keys {
            Keys::Held(_) => None,
            Keys::Revoked { at_ms, .. } => Some(at_ms),
        }
    }

    /// Records the peer's storage confirmation: the engine's record becomes
    /// confirmed (section 4.3 item 4). A record of another pairing, or one
    /// whose keys are gone, stays unconfirmed or loses its keys.
    pub(crate) fn confirm_storage(&mut self, active: ActivePairing) -> Result<(), PairingError> {
        let placeholder = self.revoked_keys(false, STAND_IN_REVOKED_AT_MS);
        match core::mem::replace(&mut self.keys, placeholder) {
            Keys::Held(record) => {
                self.keys = Keys::Held(active.confirm(record)?);
                Ok(())
            }
            revoked @ Keys::Revoked { .. } => {
                self.keys = revoked;
                Err(PairingError::StorageUnconfirmed)
            }
        }
    }

    /// The user forgets the pairing at `at_ms` while no session is open:
    /// it serves nothing and keeps its keys for the close (section 4.6 item
    /// 2). A pairing already forgotten keeps its first time.
    fn forget(&mut self, at_ms: u64) {
        let placeholder = self.revoked_keys(false, STAND_IN_REVOKED_AT_MS);
        self.keys = match core::mem::replace(&mut self.keys, placeholder) {
            Keys::Held(record) if record.forgotten_at_ms().is_none() => {
                Keys::Held(record.forgotten(at_ms))
            }
            keys => keys,
        };
    }

    /// Destroys the keys at `at_ms`; the peer's name and platform stay so
    /// the user is told (section 4.6 items 3 and 4).
    fn revoke(&mut self, by_peer: bool, at_ms: u64) {
        self.keys = self.revoked_keys(by_peer, at_ms);
    }

    /// The keys of this pairing once destroyed, keeping the peer's name.
    fn revoked_keys(&self, by_peer: bool, at_ms: u64) -> Keys {
        Keys::Revoked {
            pair_id: self.pair_id(),
            by_peer,
            at_ms,
            peer_display_name: self.peer_display_name().clone(),
        }
    }

    /// One idle-expiry check of the pairing at `now_ms`, milliseconds since
    /// the Unix epoch (section 4.6 item 5); `session_established` says
    /// whether a session to it is established now. The engine's record
    /// decides ([`PairRecord::sweep`]): with a session it records the time
    /// and the pairing stays; without one the pairing expires once it has
    /// had no session for 30 days, and a requester then destroys its keys at
    /// once, with nothing sent (section 4.6 item 6).
    ///
    /// The change is stored before it is made: `store` receives the record
    /// as the check leaves it, revoked when it expired, and this record
    /// changes only once `store` accepted it. A check that changes nothing,
    /// and a record whose keys are destroyed, call nothing.
    ///
    /// # Errors
    /// [`RecordStoreError::Store`] with `store`'s error, and
    /// [`RecordStoreError::Encoding`] when the checked record does not
    /// encode; the record is unchanged in both.
    pub fn sweep<E>(
        &mut self,
        now_ms: u64,
        session_established: bool,
        store: impl FnOnce(&Self) -> Result<(), E>,
    ) -> Result<SweepOutcome, RecordStoreError<E>> {
        let expired_keys = self.revoked_keys(false, now_ms);
        let Keys::Held(keys) = &mut self.keys else {
            return Ok(SweepOutcome::Kept);
        };
        let peer_platform = &self.peer_platform;
        let outcome = keys
            .sweep(now_ms, session_established, |encoded| {
                let checked = decode_pair_record(encoded).map_err(CheckedWrite::Encoding)?;
                let stored = if checked.forgotten_at_ms().is_some() {
                    Self {
                        keys: expired_keys,
                        peer_platform: peer_platform.clone(),
                    }
                } else {
                    Self {
                        keys: Keys::Held(checked),
                        peer_platform: peer_platform.clone(),
                    }
                };
                store(&stored).map_err(CheckedWrite::Store)
            })
            .map_err(|error| match error {
                RecordStoreError::Encoding(error)
                | RecordStoreError::Store(CheckedWrite::Encoding(error)) => {
                    RecordStoreError::Encoding(error)
                }
                RecordStoreError::Store(CheckedWrite::Store(error)) => {
                    RecordStoreError::Store(error)
                }
            })?;
        if outcome == SweepOutcome::Expired {
            self.revoke(false, now_ms);
        }
        Ok(outcome)
    }
}

/// Why the record a sweep left was not handed to the store, or what the
/// store answered.
enum CheckedWrite<E> {
    /// The engine's encoding of the checked record did not decode back.
    Encoding(PairRecordCodecError),
    /// The store refused the checked record.
    Store(E),
}

/// Why a store operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// No record exists for the identifier.
    Unknown,
    /// The backing store refused the write.
    WriteRefused,
    /// The backing store could not be read, so no change was made: a write
    /// made without the stored records would overwrite them.
    Unreadable,
}

/// Durable storage for pairing records.
pub trait PairingStore {
    /// Stores a new record atomically, in place of one with its identifier.
    ///
    /// # Errors
    ///
    /// Fails when the backing store refuses the write.
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError>;

    /// Reads one record.
    ///
    /// # Errors
    ///
    /// Fails when no record exists.
    fn get(&self, pair_id: PairId) -> Result<&PairingRecord, StoreError>;

    /// Applies a change to one record.
    ///
    /// # Errors
    ///
    /// Fails when no record exists or the write is refused.
    fn update(
        &mut self,
        pair_id: PairId,
        change: &mut dyn FnMut(&mut PairingRecord),
    ) -> Result<(), StoreError>;

    /// Removes one record entirely, with its card sighting.
    ///
    /// # Errors
    ///
    /// Fails when no record exists.
    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError>;

    /// Every stored pairing, newest first.
    fn pair_ids(&self) -> Vec<PairId>;

    /// The card a session on this computer last heard present for
    /// `pair_id` (section 8.4 item 1).
    fn card_sighting(&self, pair_id: PairId) -> Option<CardSighting>;

    /// Records that a session heard `sighting`'s card present for
    /// `pair_id`, in place of the pairing's earlier sighting.
    ///
    /// # Errors
    ///
    /// Fails when the write is refused.
    fn record_card_sighting(
        &mut self,
        pair_id: PairId,
        sighting: CardSighting,
    ) -> Result<(), StoreError>;

    /// Drops the card sighting of `pair_id`: the custodian withdrew or
    /// closed with `card_unavailable`, so its identity is offered to no
    /// local consumer from now on, without the grace (section 4.5 item 6).
    fn drop_card_sighting(&mut self, pair_id: PairId);

    /// The idle-expiry check of RAPP v26.11.2 section 4.6 item 5 on one
    /// pairing at `now_ms` ([`PairingRecord::sweep`]), its change written
    /// through before it is made.
    ///
    /// # Errors
    ///
    /// [`RecordStoreError::Store`] with [`StoreError::Unknown`] when no record
    /// exists, or with the backing store's refusal, and
    /// [`RecordStoreError::Encoding`] when the checked record does not encode.
    /// The record is unchanged in every case, so the next check repeats
    /// the whole step.
    fn sweep(
        &mut self,
        pair_id: PairId,
        now_ms: u64,
        session_established: bool,
    ) -> Result<SweepOutcome, RecordStoreError<StoreError>>;
}

/// Whether a pairing's identity is offered on `certificate` at `now_ms`.
///
/// It is (RAPP v26.11.2 section 8.4 item 3) while the pairing
/// serves, and the last card a session on this computer heard present is
/// that certificate's card and was heard within the grace. False withdraws
/// the offer: the pairing is forgotten or revoked, a session heard another
/// card, or no session has heard the card for the grace.
pub fn offer_stands<S: PairingStore + ?Sized>(
    store: &S,
    pair_id: PairId,
    certificate: &OwnedCert,
    now_ms: u64,
) -> bool {
    store.get(pair_id).is_ok_and(PairingRecord::serves)
        && store
            .card_sighting(pair_id)
            .is_some_and(|sighting| sighting.stands_for(certificate, now_ms))
}

/// What the revocation notice leaves of `records` at `now_ms`: a revoked
/// record with nothing left to tell leaves the set. Returns whether anything
/// changed.
pub fn drop_outlived_revocations(records: &mut Vec<PairingRecord>, now_ms: u64) -> bool {
    let before = records.len();
    records.retain(|record| !record.revoked_record_outlived(now_ms));
    records.len() != before
}

/// Revokes a pairing at `now_ms`: its keys are destroyed and the record stays
/// so the user is told, as one the peer revoked when `by_peer` (section 4.6
/// items 3 and 4).
///
/// # Errors
///
/// Fails when no record exists or the write is refused.
pub fn revoke_pairing<S: PairingStore + ?Sized>(
    store: &mut S,
    pair_id: PairId,
    by_peer: bool,
    now_ms: u64,
) -> Result<(), StoreError> {
    store.update(pair_id, &mut |record| record.revoke(by_peer, now_ms))
}

/// The user's forget action on a pairing with no open session (section
/// 4.6 item 6).
///
/// A confirmed pairing keeps its keys for the `pairing_revoked` close of
/// one bounded attempt and serves nothing from `now_ms` on. A pairing the peer never confirmed is
/// removed with its keys and nobody is told. A revoked record is cleared,
/// and one already forgotten stays as it is.
///
/// # Errors
///
/// Fails when no record exists or the write is refused.
pub fn forget_pairing<S: PairingStore + ?Sized>(
    store: &mut S,
    pair_id: PairId,
    now_ms: u64,
) -> Result<(), StoreError> {
    match store.get(pair_id)?.state() {
        PairingState::Unconfirmed | PairingState::Revoked { .. } => store.remove(pair_id),
        PairingState::Forgotten => Ok(()),
        PairingState::Serving => store.update(pair_id, &mut |record| record.forget(now_ms)),
    }
}

/// Removes every stored pairing whose peer never confirmed its storage,
/// keys included.
///
/// Such a record was written inside a confirmation window this endpoint
/// did not complete (RAPP v26.11.2 section 4.3 item 4); its keys are
/// destroyed and nobody is told (section 4.6 item 3). Returns the removed
/// pair identifiers.
pub fn remove_unconfirmed<S: PairingStore + ?Sized>(store: &mut S) -> Vec<PairId> {
    let unconfirmed: Vec<PairId> = store
        .pair_ids()
        .into_iter()
        .filter(|pair_id| {
            store
                .get(*pair_id)
                .is_ok_and(|record| record.state() == PairingState::Unconfirmed)
        })
        .collect();
    for pair_id in &unconfirmed {
        let _ = store.remove(*pair_id);
    }
    unconfirmed
}

/// Revokes, untold, every forgotten pairing whose bounded attempt has
/// passed at `now_ms`.
///
/// Its `pairing_revoked` close was not acknowledged within 10 seconds of
/// the forget, or the clock was set back past it (RAPP v26.11.2 section
/// 4.6 item 6). Returns the revoked pair identifiers.
pub fn expire_revocation_notices<S: PairingStore + ?Sized>(
    store: &mut S,
    now_ms: u64,
) -> Vec<PairId> {
    let expired: Vec<PairId> = store
        .pair_ids()
        .into_iter()
        .filter(|pair_id| {
            store.get(*pair_id).is_ok_and(|record| {
                record
                    .pair_record()
                    .is_some_and(|keys| keys.revocation_notice_expired(now_ms))
            })
        })
        .collect();
    for pair_id in &expired {
        let _ = revoke_pairing(store, *pair_id, false, now_ms);
    }
    expired
}

/// The idle-expiry check of RAPP v26.11.2 section 4.6 item 5 on every
/// stored pairing.
///
/// `now_ms` is milliseconds since the Unix epoch. `in_session` says whether
/// a session to a pairing is established now; such a pairing has the time
/// recorded and stays.
///
/// Returns the pairings that expired: each is forgotten, serves nothing
/// and offers no identity from now on, and nothing is sent or shown. A
/// pairing whose change the store refused is unchanged and is checked
/// again on the next sweep; development builds report the refusal. A
/// pairing removed meanwhile has nothing to check.
pub fn sweep_pairings<S: PairingStore + ?Sized>(
    store: &mut S,
    now_ms: u64,
    in_session: impl Fn(PairId) -> bool,
) -> Vec<PairId> {
    let mut expired = Vec::new();
    for pair_id in store.pair_ids() {
        match store.sweep(pair_id, now_ms, in_session(pair_id)) {
            Ok(SweepOutcome::Expired) => expired.push(pair_id),
            Ok(SweepOutcome::Recorded | SweepOutcome::Kept)
            | Err(RecordStoreError::Store(StoreError::Unknown)) => {}
            Err(error) => {
                refineid_dev_errors::report!(Rapp, "pairing idle check not stored", error);
            }
        }
    }
    expired
}

/// An in-memory pairing store for tests and composition.
#[derive(Debug, Default)]
pub struct MemoryPairingStore {
    records: Vec<PairingRecord>,
    sightings: Vec<(PairId, CardSighting)>,
}

impl MemoryPairingStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl PairingStore for MemoryPairingStore {
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
        let pair_id = record.pair_id();
        self.records.retain(|entry| entry.pair_id() != pair_id);
        self.records.push(record);
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
        let record = self
            .records
            .iter_mut()
            .find(|entry| entry.pair_id() == pair_id)
            .ok_or(StoreError::Unknown)?;
        change(record);
        Ok(())
    }

    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        let before = self.records.len();
        self.records.retain(|entry| entry.pair_id() != pair_id);
        if self.records.len() == before {
            return Err(StoreError::Unknown);
        }
        self.sightings.retain(|(sighted, _)| *sighted != pair_id);
        Ok(())
    }

    fn pair_ids(&self) -> Vec<PairId> {
        self.records
            .iter()
            .rev()
            .map(PairingRecord::pair_id)
            .collect()
    }

    fn card_sighting(&self, pair_id: PairId) -> Option<CardSighting> {
        self.sightings
            .iter()
            .find(|(sighted, _)| *sighted == pair_id)
            .map(|(_, sighting)| *sighting)
    }

    fn record_card_sighting(
        &mut self,
        pair_id: PairId,
        sighting: CardSighting,
    ) -> Result<(), StoreError> {
        self.sightings.retain(|(sighted, _)| *sighted != pair_id);
        self.sightings.push((pair_id, sighting));
        Ok(())
    }

    fn drop_card_sighting(&mut self, pair_id: PairId) {
        self.sightings.retain(|(sighted, _)| *sighted != pair_id);
    }

    fn sweep(
        &mut self,
        pair_id: PairId,
        now_ms: u64,
        session_established: bool,
    ) -> Result<SweepOutcome, RecordStoreError<StoreError>> {
        self.records
            .iter_mut()
            .find(|entry| entry.pair_id() == pair_id)
            .ok_or(RecordStoreError::Store(StoreError::Unknown))?
            .sweep(now_ms, session_established, |_| Ok(()))
    }
}

/// Records built from synthetic keys for this crate's tests.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
pub(crate) mod fixtures {
    use refineid_lib_core::x509::{OwnedCert, UnvalidatedCertificate};
    use refineid_rapp::noise::x25519_public_key;
    use refineid_rapp::{
        DisplayName, EncodedPairRecord, EndpointRole, PairRecord, ProfileName, WireValue,
        X25519_KEY_SIZE, decode_deterministic_cbor, encode_deterministic_cbor,
    };

    use super::PairingRecord;
    use crate::ids::PairId;

    /// A synthetic requester static private key.
    const REQUESTER_PRIVATE: [u8; X25519_KEY_SIZE] = *b"synthetic requester private key.";
    /// A synthetic custodian static private key.
    const CUSTODIAN_PRIVATE: [u8; X25519_KEY_SIZE] = *b"synthetic custodian private key.";
    /// The certificate of the CLI's mock custodian, a self-issued test
    /// certificate checked in as `refineid-rapp-cli/src/mock_cert.der`.
    pub const MOCK_CERTIFICATE_DER: &[u8] =
        include_bytes!("../../refineid-rapp-cli/src/mock_cert.der");
    /// The pairing creation time the fixtures record.
    pub const CREATED_AT_MS: u64 = 1_700_000_000_000;

    /// A synthetic pair identifier.
    pub const FIRST_PAIR: PairId = PairId::from_array(*b"synthetic pair 1");
    /// Another synthetic pair identifier.
    pub const SECOND_PAIR: PairId = PairId::from_array(*b"synthetic pair 2");

    /// The name the fixtures' phone gives itself.
    pub const PHONE_NAME: &str = "Phone";
    /// The platform the fixtures' phone describes itself with.
    pub const PHONE_PLATFORM: &str = "iOS";

    /// The fixtures' phone's display name.
    pub fn phone_name() -> DisplayName {
        DisplayName::parse(PHONE_NAME.to_owned()).unwrap()
    }

    /// The fixtures' phone's platform.
    pub fn phone() -> String {
        PHONE_PLATFORM.to_owned()
    }

    /// The engine's record of a confirmed requester pairing granting
    /// `profiles`.
    pub fn pair_record(pair_id: PairId, profiles: Vec<ProfileName>) -> PairRecord {
        let grants_hash = refineid_rapp::compute_grants_hash(&profiles).unwrap();
        PairRecord::new(
            pair_id,
            EndpointRole::Requester,
            REQUESTER_PRIVATE,
            x25519_public_key(&REQUESTER_PRIVATE),
            x25519_public_key(&CUSTODIAN_PRIVATE),
            grants_hash,
            profiles,
            phone_name(),
            CREATED_AT_MS,
        )
        .unwrap()
    }

    /// A confirmed pairing granting card status.
    pub fn record(pair_id: PairId) -> PairingRecord {
        PairingRecord::new(pair_record(pair_id, vec![ProfileName::CardStatus]), phone())
    }

    /// A pairing granting card status whose peer has not confirmed its
    /// storage, as storage holds one: the engine builds an unconfirmed
    /// record only inside a pairing or from its own encoding.
    pub fn unconfirmed_record(pair_id: PairId) -> PairingRecord {
        let encoded =
            refineid_rapp::encode_pair_record(&pair_record(pair_id, vec![ProfileName::CardStatus]))
                .unwrap();
        let WireValue::Map(mut fields) = decode_deterministic_cbor(encoded.as_bytes()).unwrap()
        else {
            panic!("an encoded pair record is a map");
        };
        fields.insert(STORAGE_CONFIRMED_FIELD.to_owned(), WireValue::Bool(false));
        let unconfirmed = encode_deterministic_cbor(&WireValue::Map(fields)).unwrap();
        PairingRecord::new(
            refineid_rapp::decode_pair_record(&EncodedPairRecord::from_stored(unconfirmed))
                .unwrap(),
            phone(),
        )
    }

    /// The field of the engine's record encoding that holds the storage
    /// confirmation.
    const STORAGE_CONFIRMED_FIELD: &str = "storage_confirmed";

    /// The mock custodian's certificate.
    pub fn certificate() -> OwnedCert {
        OwnedCert::from_der(UnvalidatedCertificate::new(MOCK_CERTIFICATE_DER.to_vec())).unwrap()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use super::fixtures::{
        CREATED_AT_MS, FIRST_PAIR, SECOND_PAIR, certificate, phone, phone_name, record,
        unconfirmed_record,
    };
    use super::{
        MemoryPairingStore, PairingRecord, PairingState, PairingStore, REVOCATION_NOTICE_DAYS,
        REVOCATION_NOTICE_MS, StoreError, drop_outlived_revocations, expire_revocation_notices,
        forget_pairing, offer_stands, remove_unconfirmed, revoke_pairing, sweep_pairings,
    };
    use crate::ids::PairId;
    use crate::presence::CardSighting;
    use refineid_rapp::{
        CertificateFingerprint, IDENTITY_OFFER_GRACE_MS, PAIRING_IDLE_EXPIRY_MS,
        REVOCATION_ATTEMPT_BOUND_MS, RecordStoreError, SweepOutcome,
    };

    /// The wall-clock time the user forgets a pairing in these tests.
    const FORGOTTEN_AT_MS: u64 = 1_800_000_000_000;
    /// The last moment before a notice window closes.
    const JUST_BEFORE_MS: u64 = 1;

    #[test]
    fn an_unconfirmed_record_is_removed_at_load_and_serves_nothing() {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        store.insert(unconfirmed_record(SECOND_PAIR)).unwrap();
        let pending = store.get(SECOND_PAIR).unwrap();
        assert_eq!(pending.state(), PairingState::Unconfirmed);
        assert!(!pending.serves());
        assert!(!pending.owes_revocation_notice());
        assert_eq!(remove_unconfirmed(&mut store), vec![SECOND_PAIR]);
        assert!(matches!(store.get(SECOND_PAIR), Err(StoreError::Unknown)));
        assert!(store.get(FIRST_PAIR).unwrap().serves());
        assert!(remove_unconfirmed(&mut store).is_empty());
    }

    #[test]
    fn forgetting_an_unconfirmed_record_removes_it_untold() {
        let mut store = MemoryPairingStore::new();
        store.insert(unconfirmed_record(FIRST_PAIR)).unwrap();
        forget_pairing(&mut store, FIRST_PAIR, FORGOTTEN_AT_MS).unwrap();
        assert!(store.pair_ids().is_empty());
    }

    #[test]
    fn a_forgotten_pairing_keeps_its_keys_and_serves_nothing() {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        forget_pairing(&mut store, FIRST_PAIR, FORGOTTEN_AT_MS).unwrap();
        let forgotten = store.get(FIRST_PAIR).unwrap();
        assert_eq!(forgotten.state(), PairingState::Forgotten);
        assert!(!forgotten.serves());
        assert!(forgotten.owes_revocation_notice());
        let keys = forgotten.pair_record().unwrap();
        assert_eq!(keys.forgotten_at_ms(), Some(FORGOTTEN_AT_MS));
        assert!(keys.serving_profiles().is_empty());
    }

    #[test]
    fn forgetting_a_revoked_record_removes_it() {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        store.insert(record(SECOND_PAIR)).unwrap();
        revoke_pairing(&mut store, SECOND_PAIR, true, CREATED_AT_MS).unwrap();
        forget_pairing(&mut store, SECOND_PAIR, FORGOTTEN_AT_MS).unwrap();
        assert_eq!(store.pair_ids(), vec![FIRST_PAIR]);
    }

    #[test]
    fn a_revocation_destroys_the_keys_and_keeps_the_record() {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        revoke_pairing(&mut store, FIRST_PAIR, true, CREATED_AT_MS).unwrap();
        let revoked = store.get(FIRST_PAIR).unwrap();
        assert_eq!(revoked.state(), PairingState::Revoked { by_peer: true });
        assert!(revoked.pair_record().is_none());
        assert!(revoked.granted_profiles().is_empty());
        assert!(!revoked.serves());
        assert!(!revoked.owes_revocation_notice());
    }

    #[test]
    fn an_undelivered_notice_expires_after_the_bounded_attempt() {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        forget_pairing(&mut store, FIRST_PAIR, FORGOTTEN_AT_MS).unwrap();
        let window_end = FORGOTTEN_AT_MS + REVOCATION_ATTEMPT_BOUND_MS;
        assert!(expire_revocation_notices(&mut store, window_end - JUST_BEFORE_MS).is_empty());
        assert_eq!(
            expire_revocation_notices(&mut store, window_end),
            vec![FIRST_PAIR]
        );
        assert_eq!(
            store.get(FIRST_PAIR).unwrap().state(),
            PairingState::Revoked { by_peer: false }
        );
    }

    #[test]
    fn records_are_replaced_updated_and_removed() {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        store.insert(record(FIRST_PAIR)).unwrap();
        assert_eq!(store.pair_ids(), vec![FIRST_PAIR]);
        store.remove(FIRST_PAIR).unwrap();
        assert!(matches!(store.get(FIRST_PAIR), Err(StoreError::Unknown)));
    }

    /// The wall-clock time a session hears the card present in these tests.
    const HEARD_AT_MS: u64 = 1_800_000_000_000;

    /// A store holding a confirmed pairing whose card a session open at
    /// [`HEARD_AT_MS`] heard.
    fn offering_store() -> MemoryPairingStore {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        store.sweep(FIRST_PAIR, HEARD_AT_MS, true).unwrap();
        let heard = offering_store_heard_at(HEARD_AT_MS);
        store
            .record_card_sighting(FIRST_PAIR, heard.card_sighting(FIRST_PAIR).unwrap())
            .unwrap();
        store
    }

    /// A store holding a confirmed pairing whose card a session heard at
    /// `heard_at_ms`.
    fn offering_store_heard_at(heard_at_ms: u64) -> MemoryPairingStore {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        store
            .record_card_sighting(
                FIRST_PAIR,
                CardSighting::new(
                    CertificateFingerprint::of_certificate(certificate().as_der()),
                    heard_at_ms,
                ),
            )
            .unwrap();
        store
    }

    #[test]
    fn a_confirmed_certificate_is_offered_through_the_grace() {
        let store = offering_store();
        assert!(offer_stands(
            &store,
            FIRST_PAIR,
            &certificate(),
            HEARD_AT_MS
        ));
        assert!(!offer_stands(
            &store,
            FIRST_PAIR,
            &certificate(),
            HEARD_AT_MS + IDENTITY_OFFER_GRACE_MS
        ));
        assert!(!offer_stands(
            &store,
            SECOND_PAIR,
            &certificate(),
            HEARD_AT_MS
        ));
    }

    #[test]
    fn a_removed_pairing_takes_its_sighting_with_it() {
        let mut store = offering_store();
        store.remove(FIRST_PAIR).unwrap();
        assert_eq!(store.card_sighting(FIRST_PAIR), None);
    }

    #[test]
    fn a_forgotten_pairing_offers_nothing_at_once() {
        let mut store = offering_store();
        forget_pairing(&mut store, FIRST_PAIR, HEARD_AT_MS).unwrap();
        assert!(!offer_stands(
            &store,
            FIRST_PAIR,
            &certificate(),
            HEARD_AT_MS
        ));
    }

    #[test]
    fn another_card_heard_withdraws_the_offer_at_once() {
        let mut store = offering_store();
        store
            .record_card_sighting(
                FIRST_PAIR,
                CardSighting::new(
                    CertificateFingerprint::from_array(*b"the fingerprint of another card."),
                    HEARD_AT_MS,
                ),
            )
            .unwrap();
        assert!(!offer_stands(
            &store,
            FIRST_PAIR,
            &certificate(),
            HEARD_AT_MS
        ));
    }

    /// The moment the fixtures' pairing has had no session for the idle
    /// limit, counted from its creation.
    const IDLE_EXPIRED_AT_MS: u64 = CREATED_AT_MS + PAIRING_IDLE_EXPIRY_MS;

    /// A store that refuses every idle-expiry write while `refusing`, as a
    /// backing store that cannot write does; everything else is the
    /// in-memory store's.
    struct RefusingStore {
        inner: MemoryPairingStore,
        refusing: bool,
    }

    impl PairingStore for RefusingStore {
        fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
            self.inner.insert(record)
        }

        fn get(&self, pair_id: PairId) -> Result<&PairingRecord, StoreError> {
            self.inner.get(pair_id)
        }

        fn update(
            &mut self,
            pair_id: PairId,
            change: &mut dyn FnMut(&mut PairingRecord),
        ) -> Result<(), StoreError> {
            self.inner.update(pair_id, change)
        }

        fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError> {
            self.inner.remove(pair_id)
        }

        fn pair_ids(&self) -> Vec<PairId> {
            self.inner.pair_ids()
        }

        fn card_sighting(&self, pair_id: PairId) -> Option<CardSighting> {
            self.inner.card_sighting(pair_id)
        }

        fn record_card_sighting(
            &mut self,
            pair_id: PairId,
            sighting: CardSighting,
        ) -> Result<(), StoreError> {
            self.inner.record_card_sighting(pair_id, sighting)
        }

        fn drop_card_sighting(&mut self, pair_id: PairId) {
            self.inner.drop_card_sighting(pair_id);
        }

        fn sweep(
            &mut self,
            pair_id: PairId,
            now_ms: u64,
            session_established: bool,
        ) -> Result<SweepOutcome, RecordStoreError<StoreError>> {
            let refusing = self.refusing;
            self.inner
                .records
                .iter_mut()
                .find(|entry| entry.pair_id() == pair_id)
                .ok_or(RecordStoreError::Store(StoreError::Unknown))?
                .sweep(now_ms, session_established, |_| {
                    if refusing {
                        Err(StoreError::WriteRefused)
                    } else {
                        Ok(())
                    }
                })
        }
    }

    #[test]
    fn a_pairing_idle_for_the_limit_expires_and_its_identity_is_withdrawn() {
        let mut store = offering_store_heard_at(IDLE_EXPIRED_AT_MS);
        assert!(
            sweep_pairings(&mut store, IDLE_EXPIRED_AT_MS - JUST_BEFORE_MS, |_| false).is_empty()
        );
        assert!(store.get(FIRST_PAIR).unwrap().serves());
        assert_eq!(
            sweep_pairings(&mut store, IDLE_EXPIRED_AT_MS, |_| false),
            vec![FIRST_PAIR]
        );
        let expired = store.get(FIRST_PAIR).unwrap();
        assert_eq!(expired.state(), PairingState::Revoked { by_peer: false });
        assert!(!expired.serves());
        assert!(
            !expired.owes_revocation_notice(),
            "an expired pairing sends nothing"
        );
        assert!(!offer_stands(
            &store,
            FIRST_PAIR,
            &certificate(),
            IDLE_EXPIRED_AT_MS
        ));
    }

    #[test]
    fn a_pairing_in_session_never_expires() {
        let long_past_the_limit_ms = IDLE_EXPIRED_AT_MS + PAIRING_IDLE_EXPIRY_MS;
        let mut store = offering_store_heard_at(long_past_the_limit_ms);
        assert!(
            sweep_pairings(&mut store, long_past_the_limit_ms, |pair_id| {
                pair_id == FIRST_PAIR
            })
            .is_empty()
        );
        let kept = store.get(FIRST_PAIR).unwrap();
        assert!(kept.serves());
        assert_eq!(
            kept.pair_record().unwrap().last_session_at_ms(),
            Some(long_past_the_limit_ms)
        );
        assert!(offer_stands(
            &store,
            FIRST_PAIR,
            &certificate(),
            long_past_the_limit_ms
        ));
        assert!(
            sweep_pairings(
                &mut store,
                long_past_the_limit_ms + PAIRING_IDLE_EXPIRY_MS - JUST_BEFORE_MS,
                |_| false
            )
            .is_empty()
        );
    }

    #[test]
    fn only_the_idle_pairing_expires() {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        store.insert(record(SECOND_PAIR)).unwrap();
        assert_eq!(
            sweep_pairings(&mut store, IDLE_EXPIRED_AT_MS, |pair_id| {
                pair_id == SECOND_PAIR
            }),
            vec![FIRST_PAIR]
        );
        assert_eq!(
            store.get(FIRST_PAIR).unwrap().state(),
            PairingState::Revoked { by_peer: false }
        );
        assert!(store.get(SECOND_PAIR).unwrap().serves());
    }

    #[test]
    fn an_expiry_the_store_refused_is_repeated_on_the_next_sweep() {
        let mut store = RefusingStore {
            inner: offering_store_heard_at(IDLE_EXPIRED_AT_MS),
            refusing: true,
        };
        assert!(sweep_pairings(&mut store, IDLE_EXPIRED_AT_MS, |_| false).is_empty());
        assert!(store.get(FIRST_PAIR).unwrap().serves());
        store.refusing = false;
        assert_eq!(
            sweep_pairings(&mut store, IDLE_EXPIRED_AT_MS, |_| false),
            vec![FIRST_PAIR]
        );
        assert!(!offer_stands(
            &store,
            FIRST_PAIR,
            &certificate(),
            IDLE_EXPIRED_AT_MS
        ));
    }

    #[test]
    fn a_session_record_the_store_refused_is_repeated_on_the_next_sweep() {
        let mut store = RefusingStore {
            inner: MemoryPairingStore::new(),
            refusing: true,
        };
        store.insert(record(FIRST_PAIR)).unwrap();
        assert_eq!(
            store.sweep(FIRST_PAIR, HEARD_AT_MS, true),
            Err(RecordStoreError::Store(StoreError::WriteRefused))
        );
        let last_session = |store: &RefusingStore| {
            store
                .get(FIRST_PAIR)
                .unwrap()
                .pair_record()
                .unwrap()
                .last_session_at_ms()
        };
        assert_eq!(last_session(&store), None);
        store.refusing = false;
        assert_eq!(
            store.sweep(FIRST_PAIR, HEARD_AT_MS, true),
            Ok(SweepOutcome::Recorded)
        );
        assert_eq!(last_session(&store), Some(HEARD_AT_MS));
    }

    #[test]
    fn the_store_receives_the_whole_record_as_the_check_leaves_it() {
        let mut checked = record(FIRST_PAIR);
        let mut stored = None;
        assert_eq!(
            checked.sweep(IDLE_EXPIRED_AT_MS, false, |swept| {
                stored = Some((
                    swept.state(),
                    swept.peer_display_name().clone(),
                    swept.peer_platform().to_owned(),
                ));
                Err(StoreError::WriteRefused)
            }),
            Err(RecordStoreError::Store(StoreError::WriteRefused))
        );
        assert_eq!(
            stored,
            Some((
                PairingState::Revoked { by_peer: false },
                phone_name(),
                phone(),
            )),
            "the store saw the expired record revoked, its keys gone, the phone's name kept"
        );
        assert_eq!(
            checked.state(),
            PairingState::Serving,
            "a refused store leaves the record as it was"
        );
    }

    #[test]
    fn a_check_that_changes_nothing_stores_nothing() {
        let mut fresh = record(FIRST_PAIR);
        assert_eq!(
            fresh.sweep(CREATED_AT_MS, false, |_| -> Result<(), StoreError> {
                panic!("nothing changed, so nothing is stored")
            }),
            Ok(SweepOutcome::Kept)
        );
        let mut store = MemoryPairingStore::new();
        store.insert(record(SECOND_PAIR)).unwrap();
        revoke_pairing(&mut store, SECOND_PAIR, true, CREATED_AT_MS).unwrap();
        assert!(sweep_pairings(&mut store, IDLE_EXPIRED_AT_MS, |_| false).is_empty());
        assert_eq!(
            store.get(SECOND_PAIR).unwrap().state(),
            PairingState::Revoked { by_peer: true }
        );
    }

    #[test]
    fn a_pairing_unknown_to_the_store_has_nothing_to_check() {
        let mut store = MemoryPairingStore::new();
        assert_eq!(
            store.sweep(FIRST_PAIR, IDLE_EXPIRED_AT_MS, false),
            Err(RecordStoreError::Store(StoreError::Unknown))
        );
    }

    /// One day in milliseconds.
    const DAY_MS: u64 = REVOCATION_NOTICE_MS / REVOCATION_NOTICE_DAYS;
    /// Six days after the fixtures' pairing was created: short of the notice
    /// bound.
    const DAY_6_MS: u64 = CREATED_AT_MS + REVOCATION_NOTICE_MS - DAY_MS;
    /// Eight days after the fixtures' pairing was created: past it.
    const DAY_8_MS: u64 = CREATED_AT_MS + REVOCATION_NOTICE_MS + DAY_MS;

    #[test]
    fn the_notice_bound_is_seven_days() {
        const NAMED_DAYS: u64 = 7;
        assert_eq!(REVOCATION_NOTICE_DAYS, NAMED_DAYS);
    }

    #[test]
    fn an_offer_stands_on_the_sighted_certificate_only_within_the_grace() {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        assert!(
            !offer_stands(&store, FIRST_PAIR, &certificate(), DAY_6_MS),
            "a pairing whose phone no session heard offers nothing"
        );
        store
            .record_card_sighting(
                FIRST_PAIR,
                CardSighting::new(
                    CertificateFingerprint::of_certificate(certificate().as_der()),
                    DAY_6_MS,
                ),
            )
            .unwrap();
        assert!(offer_stands(&store, FIRST_PAIR, &certificate(), DAY_6_MS));
        assert!(!offer_stands(
            &store,
            FIRST_PAIR,
            &certificate(),
            DAY_6_MS + IDENTITY_OFFER_GRACE_MS
        ));
    }

    #[test]
    fn a_forgotten_or_expired_pairing_offers_nothing_on_its_sighting() {
        for leave in [
            |store: &mut MemoryPairingStore| {
                forget_pairing(store, FIRST_PAIR, IDLE_EXPIRED_AT_MS).unwrap();
            },
            |store: &mut MemoryPairingStore| {
                store.sweep(FIRST_PAIR, IDLE_EXPIRED_AT_MS, false).unwrap();
            },
        ] {
            let mut store = offering_store_heard_at(IDLE_EXPIRED_AT_MS);
            assert!(offer_stands(
                &store,
                FIRST_PAIR,
                &certificate(),
                IDLE_EXPIRED_AT_MS
            ));
            leave(&mut store);
            assert!(!offer_stands(
                &store,
                FIRST_PAIR,
                &certificate(),
                IDLE_EXPIRED_AT_MS
            ));
        }
    }

    #[test]
    fn the_notice_erases_a_revoked_record_with_nothing_left_to_tell() {
        let mut records = vec![
            PairingRecord::revoked(FIRST_PAIR, false, CREATED_AT_MS, phone_name(), phone()),
            record(SECOND_PAIR),
        ];
        assert!(drop_outlived_revocations(&mut records, CREATED_AT_MS));
        let pair_ids: Vec<PairId> = records.iter().map(PairingRecord::pair_id).collect();
        assert_eq!(pair_ids, vec![SECOND_PAIR]);
        assert!(!drop_outlived_revocations(&mut records, CREATED_AT_MS));
    }

    #[test]
    fn the_notice_that_the_phone_forgot_stands_for_six_days_and_goes_by_eight() {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        revoke_pairing(&mut store, FIRST_PAIR, true, CREATED_AT_MS).unwrap();
        let entry = store.get(FIRST_PAIR).unwrap();
        assert!(!entry.revoked_record_outlived(DAY_6_MS));
        assert!(entry.revoked_record_outlived(DAY_8_MS));
        assert!(entry.revoked_record_outlived(CREATED_AT_MS - DAY_MS));
    }

    #[test]
    fn a_record_prints_no_keys() {
        let text = format!("{:?}", record(FIRST_PAIR));
        assert!(!text.contains("synthetic requester"));
        assert!(text.contains("pair_id"));
    }
}
