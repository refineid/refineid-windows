//! Durable pairing records.
//!
//! A pairing record is the atomic result of pairing (RAPP v26.10.29 section
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
//! A pairing that has had no established session for 30 days expires
//! (section 4.6 item 5): the engine's record keeps the latest time a
//! session to it was established, and [`PairingStore::sweep`] checks it,
//! storing the change before it is made. An expired pairing is forgotten
//! as if its user had forgotten it, silently.
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
use refineid_rapp::{
    ActivePairing, PairRecord, PairRecordCodecError, PairingError, ProfileName, decode_pair_record,
};
/// What an idle-expiry check did, and why it changed nothing, as
/// [`PairingStore::sweep`] answers.
pub use refineid_rapp::{SweepError, SweepOutcome};

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

/// Where a stored pairing stands (RAPP v26.10.29 sections 4.3 and 4.6).
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
#[derive(Clone)]
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

    /// One idle-expiry check of the pairing at `now_ms`, milliseconds since
    /// the Unix epoch (section 4.6 item 5); `session_established` says
    /// whether a session to it is established now. The engine's record
    /// decides ([`PairRecord::sweep`]): with a session it records the time
    /// and the pairing stays; without one the pairing expires once it has
    /// had no session for 30 days, and is then forgotten as at a forget
    /// (section 4.6 item 2), with nothing sent.
    ///
    /// The change is stored before it is made: `store` receives the record
    /// as the check leaves it, and this record changes only once `store`
    /// accepted it. A check that changes nothing, and a record whose keys
    /// are destroyed, call nothing.
    ///
    /// # Errors
    /// [`SweepError::Store`] with `store`'s error, and
    /// [`SweepError::Encoding`] when the checked record does not encode;
    /// the record is unchanged in both.
    pub fn sweep<E>(
        &mut self,
        now_ms: u64,
        session_established: bool,
        store: impl FnOnce(&Self) -> Result<(), E>,
    ) -> Result<SweepOutcome, SweepError<E>> {
        let Keys::Held(keys) = &mut self.keys else {
            return Ok(SweepOutcome::Kept);
        };
        let (peer, certificates) = (&self.peer, &self.certificates);
        keys.sweep(now_ms, session_established, |encoded| {
            let checked = decode_pair_record(encoded).map_err(CheckedWrite::Encoding)?;
            store(&Self {
                keys: Keys::Held(checked),
                peer: peer.clone(),
                certificates: certificates.clone(),
            })
            .map_err(CheckedWrite::Store)
        })
        .map_err(|error| match error {
            SweepError::Encoding(error) | SweepError::Store(CheckedWrite::Encoding(error)) => {
                SweepError::Encoding(error)
            }
            SweepError::Store(CheckedWrite::Store(error)) => SweepError::Store(error),
        })
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

    /// The idle-expiry check of RAPP v26.10.29 section 4.6 item 5 on one
    /// pairing at `now_ms` ([`PairingRecord::sweep`]), its change written
    /// through before it is made.
    ///
    /// # Errors
    ///
    /// [`SweepError::Store`] with [`StoreError::Unknown`] when no record
    /// exists, or with the backing store's refusal, and
    /// [`SweepError::Encoding`] when the checked record does not encode.
    /// The record is unchanged in every case, so the next check repeats
    /// the whole step.
    fn sweep(
        &mut self,
        pair_id: PairId,
        now_ms: u64,
        session_established: bool,
    ) -> Result<SweepOutcome, SweepError<StoreError>>;
}

/// The certificate a pairing's identity is offered to local consumers on at
/// `now_ms` (RAPP v26.10.29 section 8.4 item 3).
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
/// did not complete (RAPP v26.10.29 section 4.3 item 4); its keys are
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
/// forget (RAPP v26.10.29 section 4.6 item 3). Returns the revoked pair
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

/// The idle-expiry check of RAPP v26.10.29 section 4.6 item 5 on every
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
            | Err(SweepError::Store(StoreError::Unknown)) => {}
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

    fn sweep(
        &mut self,
        pair_id: PairId,
        now_ms: u64,
        session_established: bool,
    ) -> Result<SweepOutcome, SweepError<StoreError>> {
        self.records
            .iter_mut()
            .find(|entry| entry.pair_id() == pair_id)
            .ok_or(SweepError::Store(StoreError::Unknown))?
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
        EncodedPairRecord, EndpointRole, PairRecord, ProfileName, WireValue, X25519_KEY_SIZE,
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
    pub const CREATED_AT_MS: u64 = 1_700_000_000_000;

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
        CREATED_AT_MS, FIRST_PAIR, SECOND_PAIR, certificate, phone, record, unconfirmed_record,
    };
    use super::{
        MemoryPairingStore, PairingRecord, PairingState, PairingStore, StoreError,
        expire_revocation_notices, forget_pairing, offered_certificate, remove_unconfirmed,
        revoke_pairing, sweep_pairings,
    };
    use crate::ids::PairId;
    use crate::presence::CardSighting;
    use refineid_rapp::{
        CertificateFingerprint, IDENTITY_OFFER_GRACE_MS, PAIRING_IDLE_EXPIRY_MS,
        REVOCATION_NOTICE_MS, SweepError, SweepOutcome,
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
        offering_store_heard_at(HEARD_AT_MS)
    }

    /// A store holding a confirmed pairing whose certificate is cached and
    /// whose card a session heard at `heard_at_ms`.
    fn offering_store_heard_at(heard_at_ms: u64) -> MemoryPairingStore {
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
                    heard_at_ms,
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

        fn sweep(
            &mut self,
            pair_id: PairId,
            now_ms: u64,
            session_established: bool,
        ) -> Result<SweepOutcome, SweepError<StoreError>> {
            let refusing = self.refusing;
            self.inner
                .records
                .iter_mut()
                .find(|entry| entry.pair_id() == pair_id)
                .ok_or(SweepError::Store(StoreError::Unknown))?
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
        assert!(offered_certificate(&store, FIRST_PAIR, IDLE_EXPIRED_AT_MS).is_some());
        assert_eq!(
            sweep_pairings(&mut store, IDLE_EXPIRED_AT_MS, |_| false),
            vec![FIRST_PAIR]
        );
        let expired = store.get(FIRST_PAIR).unwrap();
        assert_eq!(expired.state(), PairingState::Forgotten);
        assert!(!expired.serves());
        assert!(expired.owes_revocation_notice());
        assert!(offered_certificate(&store, FIRST_PAIR, IDLE_EXPIRED_AT_MS).is_none());
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
        assert!(offered_certificate(&store, FIRST_PAIR, long_past_the_limit_ms).is_some());
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
            PairingState::Forgotten
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
        assert!(offered_certificate(&store, FIRST_PAIR, IDLE_EXPIRED_AT_MS).is_some());
        store.refusing = false;
        assert_eq!(
            sweep_pairings(&mut store, IDLE_EXPIRED_AT_MS, |_| false),
            vec![FIRST_PAIR]
        );
        assert!(offered_certificate(&store, FIRST_PAIR, IDLE_EXPIRED_AT_MS).is_none());
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
            Err(SweepError::Store(StoreError::WriteRefused))
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
        checked.remember_authentication_certificate(certificate());
        let mut stored = None;
        assert_eq!(
            checked.sweep(IDLE_EXPIRED_AT_MS, false, |swept| {
                stored = Some((
                    swept.state(),
                    swept.peer().clone(),
                    swept.authentication_certificate().is_some(),
                ));
                Err(StoreError::WriteRefused)
            }),
            Err(SweepError::Store(StoreError::WriteRefused))
        );
        assert_eq!(
            stored,
            Some((PairingState::Forgotten, phone(), true)),
            "the store saw the expired record, labels and certificate included"
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
        revoke_pairing(&mut store, SECOND_PAIR, true).unwrap();
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
            Err(SweepError::Store(StoreError::Unknown))
        );
    }

    #[test]
    fn a_record_prints_no_keys() {
        let text = format!("{:?}", record(FIRST_PAIR));
        assert!(!text.contains("synthetic requester"));
        assert!(text.contains("pair_id"));
    }
}
