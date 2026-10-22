//! Durable pairing records.
//!
//! A pairing record is the atomic result of pairing (RAPP v26.10.22 section
//! 4.3): the engine's own [`PairRecord`], which holds the pair keys,
//! `pair_id`, the granted profiles, `grants_hash`, whether the peer
//! confirmed its storage, and when the user forgot the pairing, together
//! with the labels the peer introduced itself with and the certificates
//! the phone's card answered with. A record is stored before the peer
//! confirms its own storage (section 4.3 item 4) and serves nothing until
//! that confirmation is recorded; one found unconfirmed at load was written
//! in a confirmation window this endpoint did not complete, and is removed
//! with its keys.
//!
//! A record its user forgot while no session was open keeps its keys for
//! the `pairing_revoked` close alone: it serves nothing, the next session
//! sends that close as its first message, and the keys are destroyed once
//! it is sent or 30 days after the forget (section 4.6 items 2 and 3). A
//! revoked record keeps no keys and no certificates; it stays only so the
//! user is told, until the user forgets it too.
//!
//! The store also keeps, per pairing, the last [`CardSighting`]: the card a
//! session on this computer last heard present, which bounds the identity
//! every local consumer is offered (section 8.4 item 3,
//! [`offered_certificate`]).
//!
//! The store is a trait so the Windows build can put pair keys behind the
//! platform credential store, while tests use the in-memory form shipped
//! here. A record is neither `Clone` nor printable with its keys: the keys
//! live in the engine's record, which is neither.

use refineid_lib_core::x509::OwnedCert;
use refineid_rapp::{ActivePairing, PairRecord, PairingError, ProfileName};

use crate::engine::PeerIntroduction;
use crate::ids::PairId;
use crate::presence::CardSighting;

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
    },
}

/// Where a stored pairing stands (RAPP v26.10.22 sections 4.3 and 4.6).
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
    peer: PeerIntroduction,
    certificates: Certificates,
}

/// The certificates a pairing's card answered with, and the chain a
/// development custodian is installed with.
struct Certificates {
    authentication: Option<OwnedCert>,
    signature: Option<OwnedCert>,
    root: Option<OwnedCert>,
    intermediate: Option<OwnedCert>,
}

impl Certificates {
    /// No certificate known yet.
    const NONE: Self = Self {
        authentication: None,
        signature: None,
        root: None,
        intermediate: None,
    };
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
    /// The record of a pairing the engine just stored, with the labels its
    /// peer introduced itself with and no certificates yet.
    #[must_use]
    pub const fn new(record: PairRecord, peer: PeerIntroduction) -> Self {
        Self {
            keys: Keys::Held(record),
            peer,
            certificates: Certificates::NONE,
        }
    }

    /// A revoked record as storage holds it.
    pub(crate) const fn revoked(pair_id: PairId, by_peer: bool, peer: PeerIntroduction) -> Self {
        Self {
            keys: Keys::Revoked { pair_id, by_peer },
            peer,
            certificates: Certificates::NONE,
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

    /// The labels the peer introduced itself with.
    #[must_use]
    pub const fn peer(&self) -> &PeerIntroduction {
        &self.peer
    }

    /// The card's authentication certificate as the phone last answered it.
    #[must_use]
    pub const fn authentication_certificate(&self) -> Option<&OwnedCert> {
        self.certificates.authentication.as_ref()
    }

    /// The card's signature certificate as the phone last answered it.
    #[must_use]
    pub const fn signature_certificate(&self) -> Option<&OwnedCert> {
        self.certificates.signature.as_ref()
    }

    /// The root certificate a development custodian's chain is installed
    /// with.
    #[must_use]
    pub const fn root_certificate(&self) -> Option<&OwnedCert> {
        self.certificates.root.as_ref()
    }

    /// The intermediate certificate a development custodian's chain is
    /// installed with.
    #[must_use]
    pub const fn intermediate_certificate(&self) -> Option<&OwnedCert> {
        self.certificates.intermediate.as_ref()
    }

    /// Keeps the card's authentication certificate.
    pub fn remember_authentication_certificate(&mut self, certificate: OwnedCert) {
        self.certificates.authentication = Some(certificate);
    }

    /// Keeps the card's signature certificate.
    pub fn remember_signature_certificate(&mut self, certificate: OwnedCert) {
        self.certificates.signature = Some(certificate);
    }

    /// Keeps a development custodian's root certificate.
    pub fn remember_root_certificate(&mut self, certificate: OwnedCert) {
        self.certificates.root = Some(certificate);
    }

    /// Keeps a development custodian's intermediate certificate.
    pub fn remember_intermediate_certificate(&mut self, certificate: OwnedCert) {
        self.certificates.intermediate = Some(certificate);
    }

    /// Records the peer's storage confirmation: the engine's record becomes
    /// confirmed (section 4.3 item 4). A record of another pairing, or one
    /// whose keys are gone, stays unconfirmed or loses its keys.
    pub(crate) fn confirm_storage(&mut self, active: ActivePairing) -> Result<(), PairingError> {
        let placeholder = Keys::Revoked {
            pair_id: self.pair_id(),
            by_peer: false,
        };
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
        let pair_id = self.pair_id();
        let placeholder = Keys::Revoked {
            pair_id,
            by_peer: false,
        };
        self.keys = match core::mem::replace(&mut self.keys, placeholder) {
            Keys::Held(record) if record.forgotten_at_ms().is_none() => {
                Keys::Held(record.forgotten(at_ms))
            }
            keys => keys,
        };
    }

    /// Destroys the keys and the certificates; the labels stay so the user
    /// is told (section 4.6 items 3 and 4).
    fn revoke(&mut self, by_peer: bool) {
        self.keys = Keys::Revoked {
            pair_id: self.pair_id(),
            by_peer,
        };
        self.certificates = Certificates::NONE;
    }
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
}

/// The certificate a pairing's identity is offered to local consumers on at
/// `now_ms` (RAPP v26.10.22 section 8.4 item 3).
///
/// It is the cached authentication certificate of a pairing that serves,
/// while the last card a session on this computer heard present is that
/// certificate's card and was heard within the grace. `None` withdraws the
/// offer: the pairing is forgotten or revoked, a session heard another
/// card, or no session has heard the card for the grace.
pub fn offered_certificate<S: PairingStore + ?Sized>(
    store: &S,
    pair_id: PairId,
    now_ms: u64,
) -> Option<&OwnedCert> {
    let certificate = store
        .get(pair_id)
        .ok()
        .filter(|record| record.serves())?
        .authentication_certificate()?;
    store
        .card_sighting(pair_id)
        .filter(|sighting| sighting.stands_for(certificate, now_ms))
        .map(|_| certificate)
}

/// Revokes a pairing: its keys are destroyed and the record stays so the
/// user is told, as one the peer revoked when `by_peer` (section 4.6 items
/// 3 and 4).
///
/// # Errors
///
/// Fails when no record exists or the write is refused.
pub fn revoke_pairing<S: PairingStore + ?Sized>(
    store: &mut S,
    pair_id: PairId,
    by_peer: bool,
) -> Result<(), StoreError> {
    store.update(pair_id, &mut |record| record.revoke(by_peer))
}

/// The user's forget action on a pairing with no open session (section
/// 4.6).
///
/// A confirmed pairing keeps its keys for the `pairing_revoked` close and
/// serves nothing from `now_ms` on. A pairing the peer never confirmed is
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
/// did not complete (RAPP v26.10.22 section 4.3 item 4); its keys are
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

/// Revokes, untold, every forgotten pairing whose notice window has passed
/// at `now_ms`.
///
/// Its `pairing_revoked` close was not delivered within 30 days of the
/// forget (RAPP v26.10.22 section 4.6 item 3). Returns the revoked pair
/// identifiers.
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
        let _ = revoke_pairing(store, *pair_id, false);
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
}

/// Records built from synthetic keys for this crate's tests.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
pub(crate) mod fixtures {
    use refineid_lib_core::x509::OwnedCert;
    use refineid_rapp::noise::x25519_public_key;
    use refineid_rapp::{
        EndpointRole, PairRecord, ProfileName, WireValue, X25519_KEY_SIZE,
        decode_deterministic_cbor, encode_deterministic_cbor,
    };

    use super::PairingRecord;
    use crate::engine::PeerIntroduction;
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
    const CREATED_AT_MS: u64 = 1_700_000_000_000;

    /// A synthetic pair identifier.
    pub const FIRST_PAIR: PairId = PairId::from_array(*b"synthetic pair 1");
    /// Another synthetic pair identifier.
    pub const SECOND_PAIR: PairId = PairId::from_array(*b"synthetic pair 2");

    /// The labels the fixtures' phone introduces itself with.
    pub fn phone() -> PeerIntroduction {
        PeerIntroduction {
            display_name: "Phone".to_owned(),
            platform: "iOS".to_owned(),
        }
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
        let WireValue::Map(mut fields) = decode_deterministic_cbor(&encoded).unwrap() else {
            panic!("an encoded pair record is a map");
        };
        fields.insert(STORAGE_CONFIRMED_FIELD.to_owned(), WireValue::Bool(false));
        let unconfirmed = encode_deterministic_cbor(&WireValue::Map(fields)).unwrap();
        PairingRecord::new(
            refineid_rapp::decode_pair_record(&unconfirmed).unwrap(),
            phone(),
        )
    }

    /// The field of the engine's record encoding that holds the storage
    /// confirmation.
    const STORAGE_CONFIRMED_FIELD: &str = "storage_confirmed";

    /// The mock custodian's certificate.
    pub fn certificate() -> OwnedCert {
        OwnedCert::from_der(MOCK_CERTIFICATE_DER).unwrap()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use super::fixtures::{FIRST_PAIR, SECOND_PAIR, certificate, record, unconfirmed_record};
    use super::{
        MemoryPairingStore, PairingState, PairingStore, StoreError, expire_revocation_notices,
        forget_pairing, offered_certificate, remove_unconfirmed, revoke_pairing,
    };
    use crate::presence::CardSighting;
    use refineid_rapp::{CertificateFingerprint, IDENTITY_OFFER_GRACE_MS, REVOCATION_NOTICE_MS};

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
        revoke_pairing(&mut store, SECOND_PAIR, true).unwrap();
        forget_pairing(&mut store, SECOND_PAIR, FORGOTTEN_AT_MS).unwrap();
        assert_eq!(store.pair_ids(), vec![FIRST_PAIR]);
    }

    #[test]
    fn a_revocation_destroys_the_keys_and_certificates_and_keeps_the_record() {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        store
            .update(FIRST_PAIR, &mut |entry| {
                entry.remember_authentication_certificate(certificate());
            })
            .unwrap();
        revoke_pairing(&mut store, FIRST_PAIR, true).unwrap();
        let revoked = store.get(FIRST_PAIR).unwrap();
        assert_eq!(revoked.state(), PairingState::Revoked { by_peer: true });
        assert!(revoked.pair_record().is_none());
        assert!(revoked.authentication_certificate().is_none());
        assert!(revoked.granted_profiles().is_empty());
        assert!(!revoked.serves());
        assert!(!revoked.owes_revocation_notice());
    }

    #[test]
    fn an_undelivered_notice_expires_after_its_window() {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        forget_pairing(&mut store, FIRST_PAIR, FORGOTTEN_AT_MS).unwrap();
        let window_end = FORGOTTEN_AT_MS + REVOCATION_NOTICE_MS;
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
        store
            .update(FIRST_PAIR, &mut |entry| {
                entry.remember_authentication_certificate(certificate());
            })
            .unwrap();
        assert!(
            store
                .get(FIRST_PAIR)
                .unwrap()
                .authentication_certificate()
                .is_some()
        );
        store.insert(record(FIRST_PAIR)).unwrap();
        assert_eq!(store.pair_ids(), vec![FIRST_PAIR]);
        store.remove(FIRST_PAIR).unwrap();
        assert!(matches!(store.get(FIRST_PAIR), Err(StoreError::Unknown)));
    }

    /// The wall-clock time a session hears the card present in these tests.
    const HEARD_AT_MS: u64 = 1_800_000_000_000;

    /// A store holding a confirmed pairing whose certificate is cached and
    /// whose card a session heard at [`HEARD_AT_MS`].
    fn offering_store() -> MemoryPairingStore {
        let mut store = MemoryPairingStore::new();
        store.insert(record(FIRST_PAIR)).unwrap();
        store
            .update(FIRST_PAIR, &mut |entry| {
                entry.remember_authentication_certificate(certificate());
            })
            .unwrap();
        store
            .record_card_sighting(
                FIRST_PAIR,
                CardSighting::new(
                    CertificateFingerprint::of_certificate(certificate().as_der()),
                    HEARD_AT_MS,
                ),
            )
            .unwrap();
        store
    }

    #[test]
    fn a_confirmed_certificate_is_offered_through_the_grace() {
        let store = offering_store();
        assert!(offered_certificate(&store, FIRST_PAIR, HEARD_AT_MS).is_some());
        assert!(
            offered_certificate(&store, FIRST_PAIR, HEARD_AT_MS + IDENTITY_OFFER_GRACE_MS)
                .is_none()
        );
        assert!(offered_certificate(&store, SECOND_PAIR, HEARD_AT_MS).is_none());
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
        assert!(offered_certificate(&store, FIRST_PAIR, HEARD_AT_MS).is_none());
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
        assert!(offered_certificate(&store, FIRST_PAIR, HEARD_AT_MS).is_none());
    }

    #[test]
    fn a_record_prints_no_keys() {
        let text = format!("{:?}", record(FIRST_PAIR));
        assert!(!text.contains("synthetic requester"));
        assert!(text.contains("pair_id"));
    }
}
