//! Durable pairing records and the operation journal.
//!
//! A pairing record is the atomic result of pairing: pair keys, `pair_id`,
//! granted profiles, `grants_hash`, labels, and the
//! fail-stop marker. The journal records each operation from the moment its
//! request is written (RAPP v26.10.10 section 8): an unanswered consequential
//! request is in flight and ends ambiguous, and terminal states are
//! permanent.
//!
//! Both stores are traits so the Windows build can put pair keys behind the
//! platform credential store and the journal on disk, while tests use the
//! in-memory forms shipped here. Neither store ever contains a credential
//! value, a card identifier, or message plaintext.

use zeroize::Zeroizing;

use crate::ids::{OperationId, PairId};
pub use refineid_rapp::OperationState;

/// The fail-stop disposition of a stored pairing (Section 14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingDisposition {
    /// The pairing is usable.
    Paired,
    /// The pairing was terminated — by local action, authenticated peer
    /// notice, an authenticated protocol violation, or credential rejection.
    /// Keys are destroyed; the record is the tombstone.
    Revoked,
}

/// One stored peer relationship.
#[derive(Clone)]
pub struct PairingRecord {
    /// The derived pair identifier.
    pub pair_id: PairId,
    /// The local pair-specific private key; emptied on revocation.
    pub local_private: Zeroizing<Vec<u8>>,
    /// The local pair-specific public key.
    pub local_public: Vec<u8>,
    /// The peer's pair-specific public key; emptied on revocation.
    pub peer_public: Vec<u8>,
    /// The granted credential profiles.
    pub granted_profiles: Vec<String>,
    /// The grants hash bound into every session prologue.
    pub grants_hash: [u8; 32],
    /// The peer's display label. A label, not an identity.
    pub peer_display_name: String,
    /// The peer's platform label.
    pub peer_platform: String,
    /// The fail-stop disposition.
    pub disposition: PairingDisposition,
    /// Whether the peer initiated the revocation.
    pub peer_initiated_termination: bool,
    /// Consecutive failed session-candidate authentications, for the
    /// re-pairing hint of Section 14.6.
    pub candidate_failures: u32,
    /// Cached DER bytes of the authentication certificate, if populated.
    pub auth_cert: Option<Vec<u8>>,
    /// Cached DER bytes of the signature certificate, if populated.
    pub signature_cert: Option<Vec<u8>>,
    /// Cached DER bytes of the root CA certificate, if populated.
    pub root_ca: Option<Vec<u8>>,
    /// Cached DER bytes of the intermediate CA certificate, if populated.
    pub intermediate_ca: Option<Vec<u8>>,
}

impl core::fmt::Debug for PairingRecord {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PairingRecord")
            .field("pair_id", &self.pair_id)
            .field("disposition", &self.disposition)
            .finish_non_exhaustive()
    }
}

/// Default display name when peer display name is unspecified.
pub const DEFAULT_PEER_DISPLAY_NAME: &str = "Peer";
/// Default platform when peer platform is unspecified.
pub const DEFAULT_PEER_PLATFORM: &str = "Unknown";

impl PairingRecord {
    /// Convert to canonical core [`refineid_rapp::PairRecord`].
    ///
    /// # Errors
    /// Returns [`refineid_rapp::PairRecordError`] if keys or profiles are invalid.
    pub fn to_core_pair_record(
        &self,
    ) -> Result<refineid_rapp::PairRecord, refineid_rapp::PairRecordError> {
        let local_private: [u8; 32] = self
            .local_private
            .as_slice()
            .try_into()
            .map_err(|_| refineid_rapp::PairRecordError::InvalidStaticKey)?;
        let local_public: [u8; 32] = self
            .local_public
            .as_slice()
            .try_into()
            .map_err(|_| refineid_rapp::PairRecordError::InvalidStaticKey)?;
        let peer_public: [u8; 32] = self
            .peer_public
            .as_slice()
            .try_into()
            .map_err(|_| refineid_rapp::PairRecordError::InvalidStaticKey)?;
        let mut profiles: Vec<refineid_rapp::ProfileName> = Vec::new();
        for p in &self.granted_profiles {
            let parsed = refineid_rapp::ProfileName::parse(p)
                .ok_or(refineid_rapp::PairRecordError::NoNegotiatedProfiles)?;
            profiles.push(parsed);
        }
        if profiles.is_empty() {
            return Err(refineid_rapp::PairRecordError::NoNegotiatedProfiles);
        }
        let grants_hash = refineid_rapp::GrantsHash::from_array(self.grants_hash);
        refineid_rapp::PairRecord::new(
            self.pair_id,
            refineid_rapp::EndpointRole::Requester,
            local_private,
            local_public,
            peer_public,
            grants_hash,
            profiles,
            0,
        )
    }

    /// Construct from canonical core [`refineid_rapp::PairRecord`].
    #[must_use]
    pub fn from_core_pair_record(
        core: &refineid_rapp::PairRecord,
        peer_display_name: String,
        peer_platform: String,
    ) -> Self {
        Self {
            pair_id: core.pair_id(),
            local_private: Zeroizing::new(core.local_static_private().to_vec()),
            local_public: core.local_static_public().to_vec(),
            peer_public: core.remote_static_public().to_vec(),
            granted_profiles: core
                .profiles()
                .iter()
                .map(|p| p.as_str().to_owned())
                .collect(),
            grants_hash: *core.grants_hash().as_bytes(),
            peer_display_name,
            peer_platform,
            disposition: PairingDisposition::Paired,
            peer_initiated_termination: false,
            candidate_failures: 0,
            auth_cert: None,
            signature_cert: None,
            root_ca: None,
            intermediate_ca: None,
        }
    }
}

/// Adapter bridging [`PairingStore`] to canonical core [`refineid_rapp::PairStore`].
#[derive(Debug)]
pub struct CorePairStoreAdapter<'a, S: PairingStore> {
    /// Backing pairing store.
    pub inner: &'a mut S,
}

impl<'a, S: PairingStore> CorePairStoreAdapter<'a, S> {
    /// Creates a new adapter over the given pairing store.
    pub const fn new(inner: &'a mut S) -> Self {
        Self { inner }
    }
}

impl<S: PairingStore> refineid_rapp::PairStore for CorePairStoreAdapter<'_, S> {
    type Error = StoreError;

    fn load(&mut self, pair_id: PairId) -> Result<Option<refineid_rapp::PairRecord>, Self::Error> {
        match self.inner.get(pair_id) {
            Ok(rec) => {
                if rec.disposition == PairingDisposition::Paired {
                    rec.to_core_pair_record()
                        .map(Some)
                        .map_err(|_| StoreError::Unknown)
                } else {
                    Ok(None)
                }
            }
            Err(StoreError::Unknown) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn insert(
        &mut self,
        record: refineid_rapp::PairRecord,
    ) -> Result<(), refineid_rapp::PairStoreError<Self::Error>> {
        let (display_name, platform) = self.inner.get(record.pair_id()).map_or_else(
            |_| {
                (
                    DEFAULT_PEER_DISPLAY_NAME.to_owned(),
                    DEFAULT_PEER_PLATFORM.to_owned(),
                )
            },
            |r| (r.peer_display_name.clone(), r.peer_platform.clone()),
        );
        let pairing_record = PairingRecord::from_core_pair_record(&record, display_name, platform);
        self.inner
            .insert(pairing_record)
            .map_err(refineid_rapp::PairStoreError::Backend)
    }

    fn revoke(
        &mut self,
        tombstone: refineid_rapp::PairTombstone,
    ) -> Result<(), refineid_rapp::PairStoreError<Self::Error>> {
        self.inner
            .update(tombstone.pair_id, &mut |r| {
                r.disposition = PairingDisposition::Revoked;
                r.local_private = Zeroizing::new(Vec::new());
                r.peer_public = Vec::new();
            })
            .map_err(refineid_rapp::PairStoreError::Backend)
    }

    fn is_revoked(&mut self, pair_id: PairId) -> Result<bool, Self::Error> {
        match self.inner.get(pair_id) {
            Ok(rec) => Ok(rec.disposition == PairingDisposition::Revoked),
            Err(StoreError::Unknown) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// Why a store operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// No record exists for the identifier.
    Unknown,
    /// The backing store refused the write.
    WriteRefused,
}

/// Durable storage for pairing records.
pub trait PairingStore {
    /// Stores a new record atomically.
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

    /// Removes one record entirely (the user's forget action).
    ///
    /// # Errors
    ///
    /// Fails when no record exists.
    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError>;

    /// Every stored pairing, newest first.
    fn pair_ids(&self) -> Vec<PairId>;
}

/// An in-memory pairing store for tests and composition.
#[derive(Debug, Default)]
pub struct MemoryPairingStore {
    records: Vec<PairingRecord>,
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
        self.records.retain(|entry| entry.pair_id != record.pair_id);
        self.records.push(record);
        Ok(())
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
        Ok(())
    }

    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        let before = self.records.len();
        self.records.retain(|entry| entry.pair_id != pair_id);
        if self.records.len() == before {
            return Err(StoreError::Unknown);
        }
        Ok(())
    }

    fn pair_ids(&self) -> Vec<PairId> {
        self.records
            .iter()
            .rev()
            .map(|entry| entry.pair_id)
            .collect()
    }
}

/// One journaled operation on the requester.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    /// The operation identifier.
    pub operation_id: OperationId,
    /// The pairing the operation ran under.
    pub pair_id: PairId,
    /// The request hash of the journaled request.
    pub request_hash: [u8; 32],
    /// The credential profile name.
    pub profile: String,
    /// The profile action name.
    pub action: String,
    /// The current requester-projection state.
    pub state: OperationState,
    /// Whether automatic retry is permanently forbidden (`INV-06`).
    pub retry_prohibited: bool,
    /// The custodian's state from a section 8.3 status answer,
    /// stored as an annotation that transitions nothing.
    pub reconciled_proxy_state: Option<String>,
}

/// The requester's durable operation journal.
pub trait OperationJournal {
    /// Creates or replaces the entry for one operation.
    ///
    /// The write must be durable before the call returns: the request is
    /// journaled before `operation.request` is sent.
    ///
    /// # Errors
    ///
    /// Fails when the backing store refuses the write.
    fn record(&mut self, entry: JournalEntry) -> Result<(), StoreError>;

    /// Reads the entry for one operation.
    ///
    /// # Errors
    ///
    /// Fails when no entry exists.
    fn get(&self, operation_id: OperationId) -> Result<&JournalEntry, StoreError>;

    /// The non-terminal entries needing section 8.3 reconciliation.
    fn open_entries(&self) -> Vec<&JournalEntry>;
}

/// An in-memory journal for tests and composition.
#[derive(Debug, Default)]
pub struct MemoryJournal {
    entries: Vec<JournalEntry>,
}

impl MemoryJournal {
    /// Creates an empty journal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl OperationJournal for MemoryJournal {
    fn record(&mut self, entry: JournalEntry) -> Result<(), StoreError> {
        self.entries
            .retain(|existing| existing.operation_id != entry.operation_id);
        self.entries.push(entry);
        Ok(())
    }

    fn get(&self, operation_id: OperationId) -> Result<&JournalEntry, StoreError> {
        self.entries
            .iter()
            .find(|entry| entry.operation_id == operation_id)
            .ok_or(StoreError::Unknown)
    }

    fn open_entries(&self) -> Vec<&JournalEntry> {
        self.entries
            .iter()
            .filter(|entry| !entry.state.is_terminal())
            .collect()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use super::{
        JournalEntry, MemoryJournal, MemoryPairingStore, OperationJournal, OperationState,
        PairingDisposition, PairingRecord, PairingStore, StoreError,
    };
    use crate::ids::{OperationId, PairId};
    use zeroize::Zeroizing;

    fn record(pair_id: PairId) -> PairingRecord {
        PairingRecord {
            pair_id,
            local_private: Zeroizing::new(vec![1; 32]),
            local_public: vec![2; 32],
            peer_public: vec![3; 32],
            granted_profiles: vec!["fi.refineid.card-status.v1".into()],
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
        }
    }

    #[test]
    fn pairing_records_round_trip_and_update() {
        let mut store = MemoryPairingStore::new();
        let pair_id = PairId::from_array([7; 16]);
        store.insert(record(pair_id)).unwrap();
        store
            .update(pair_id, &mut |entry| entry.candidate_failures += 1)
            .unwrap();
        assert_eq!(store.get(pair_id).unwrap().candidate_failures, 1);
        store.remove(pair_id).unwrap();
        assert!(matches!(store.get(pair_id), Err(StoreError::Unknown)));
    }

    #[test]
    fn journal_reports_open_entries_only() {
        let mut journal = MemoryJournal::new();
        let open = JournalEntry {
            operation_id: OperationId::from_array([1; 16]),
            pair_id: PairId::from_array([7; 16]),
            request_hash: [0; 32],
            profile: "fi.refineid.authentication.v1".into(),
            action: "sign".into(),
            state: OperationState::Committed,
            retry_prohibited: false,
            reconciled_proxy_state: None,
        };
        let done = JournalEntry {
            operation_id: OperationId::from_array([2; 16]),
            state: OperationState::Completed,
            ..open.clone()
        };
        journal.record(open.clone()).unwrap();
        journal.record(done).unwrap();
        let open_entries = journal.open_entries();
        assert_eq!(open_entries.len(), 1);
        assert_eq!(open_entries[0].operation_id, open.operation_id);
    }

    #[test]
    fn pairing_record_debug_redacts_keys() {
        let text = format!("{:?}", record(PairId::from_array([7; 16])));
        assert!(!text.contains('1'));
        assert!(text.contains("pair_id"));
    }
}
