//! Device-local serialization of a pairing record.
//!
//! A durable [`PairingStore`](crate::store::PairingStore) — on Windows, the
//! platform credential store — needs the record's bytes. This module is the
//! only serialization boundary for [`PairingRecord`], and the storage
//! border it is read back through: a versioned, length-framed encoding with
//! no external serde surface. The keys travel inside the engine's own
//! encoding of its record ([`refineid_rapp::encode_pair_record`]), which
//! [`refineid_rapp::decode_pair_record`] checks back into a record whose
//! every predicate holds; the cached certificates come back only as
//! certificates that parse.
//!
//! The encoded blob carries the private key, so [`encode_pairing_record`]
//! returns it inside [`Zeroizing`]; callers hand it straight to device-only
//! secret storage and never log it. [`decode_pairing_record`] bounds-checks
//! every field and rejects trailing bytes, so a truncated or tampered blob
//! fails closed rather than yielding a half-built record. Neither direction
//! ever prints a key.
//!
//! Stored records are not migrated. A record written for an earlier RAPP
//! protocol version, or one whose engine record is in a format the engine
//! does not read, is refused: [`decode_pairing_records`] leaves it out of
//! the set and counts it, so the store that writes the set back drops it
//! for good and its peer pairs again.

use refineid_lib_core::x509::OwnedCert;
use refineid_rapp::{EndpointRole, PAIR_ID_SIZE, PairRecordCodecError};
use zeroize::Zeroizing;

use crate::engine::PeerIntroduction;
use crate::ids::PairId;
use crate::store::{PairingRecord, PairingState};

/// Format tag identifying a `RefineID` pairing-record blob.
const PAIRING_BLOB_MAGIC: &[u8] = b"RAPP-pair-record";

/// The pairing-record encoding revision.
const PAIRING_BLOB_VERSION: u8 = 8;

/// The highest revision written for an earlier RAPP protocol version. Those
/// pairings cannot open RAPP v26.10.22 sessions, so they are not loaded.
const LAST_EARLIER_PROTOCOL_BLOB_VERSION: u8 = 7;

/// The lowest revision ever written.
const FIRST_BLOB_VERSION: u8 = 1;

/// Format tag identifying a whole stored pairing set.
const PAIRING_SET_MAGIC: &[u8] = b"RAPP-pair-set";

/// The pairing-set encoding revision.
const PAIRING_SET_VERSION: u8 = 1;

/// Keys tag: the engine's record, keys held, follows.
const KEYS_HELD: u8 = 0;
/// Keys tag: the keys are destroyed; the pair identifier and who revoked
/// follow.
const KEYS_REVOKED: u8 = 1;

/// Boolean false on the wire.
const BOOLEAN_FALSE: u8 = 0;
/// Boolean true on the wire.
const BOOLEAN_TRUE: u8 = 1;

/// Bytes of one encoded length.
const LENGTH_BYTES: usize = size_of::<u32>();

/// Why a stored pairing blob could not be encoded or decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingCodecError {
    /// The blob did not begin with the pairing-record format tag.
    BadMagic,
    /// The record was written for an earlier RAPP protocol version, whose
    /// pairings cannot open sessions with this one.
    EarlierProtocol {
        /// The revision found in the blob.
        found: u8,
    },
    /// The blob used an encoding revision this build does not understand.
    UnsupportedVersion {
        /// The revision found in the blob.
        found: u8,
    },
    /// The blob ended before a field was fully read.
    Truncated,
    /// Bytes remained after the last field was read.
    TrailingBytes,
    /// A keys tag was neither held nor revoked.
    InvalidKeys,
    /// A boolean or presence field was neither zero nor one.
    InvalidBoolean,
    /// A text field was not valid UTF-8.
    InvalidText,
    /// A field is longer than a length prefix can state.
    Oversized,
    /// The engine refused its record's encoding.
    PairRecord(PairRecordCodecError),
    /// The engine's record belongs to a custodian, not to this requester.
    NotRequester,
    /// A cached certificate does not parse as an X.509 certificate.
    InvalidCertificate,
}

impl core::fmt::Display for PairingCodecError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => formatter.write_str("blob is not a pairing record"),
            Self::UnsupportedVersion { found } => {
                write!(formatter, "unsupported pairing-record revision {found}")
            }
            Self::EarlierProtocol { found } => {
                write!(
                    formatter,
                    "pairing-record revision {found} belongs to an earlier protocol version"
                )
            }
            Self::Truncated => formatter.write_str("pairing record ended mid-field"),
            Self::TrailingBytes => formatter.write_str("pairing record had trailing bytes"),
            Self::InvalidKeys => formatter.write_str("pairing record had an unknown keys tag"),
            Self::InvalidBoolean => formatter.write_str("pairing record had a malformed flag"),
            Self::InvalidText => formatter.write_str("pairing record held invalid text"),
            Self::Oversized => formatter.write_str("pairing record field too long"),
            Self::PairRecord(error) => write!(formatter, "pairing keys refused: {error}"),
            Self::NotRequester => formatter.write_str("pairing record is not a requester's"),
            Self::InvalidCertificate => {
                formatter.write_str("pairing record held an invalid certificate")
            }
        }
    }
}

impl core::error::Error for PairingCodecError {}

/// Serializes a pairing record for device-only secret storage.
///
/// The returned blob contains the pair-specific private key and is therefore
/// wrapped in [`Zeroizing`]: hand it directly to device-only storage
/// and never log it.
///
/// # Errors
///
/// Fails when the engine cannot encode its record or a field is longer than
/// a length prefix states.
pub fn encode_pairing_record(
    record: &PairingRecord,
) -> Result<Zeroizing<Vec<u8>>, PairingCodecError> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(PAIRING_BLOB_MAGIC);
    out.push(PAIRING_BLOB_VERSION);
    match (record.pair_record(), record.state()) {
        (Some(keys), _) => {
            out.push(KEYS_HELD);
            let encoded = Zeroizing::new(
                refineid_rapp::encode_pair_record(keys).map_err(PairingCodecError::PairRecord)?,
            );
            put_bytes(&mut out, &encoded)?;
        }
        (None, state) => {
            out.push(KEYS_REVOKED);
            out.extend_from_slice(record.pair_id().as_bytes());
            out.push(boolean_tag(matches!(
                state,
                PairingState::Revoked { by_peer: true }
            )));
        }
    }
    put_bytes(&mut out, record.peer().display_name.as_bytes())?;
    put_bytes(&mut out, record.peer().platform.as_bytes())?;
    put_optional_certificate(&mut out, record.authentication_certificate())?;
    put_optional_certificate(&mut out, record.signature_certificate())?;
    put_optional_certificate(&mut out, record.root_certificate())?;
    put_optional_certificate(&mut out, record.intermediate_certificate())?;
    Ok(out)
}

/// Reconstructs a pairing record from a device-only blob.
///
/// # Errors
///
/// Fails when the blob is not a pairing record, uses an unknown revision, ends
/// mid-field, carries trailing bytes, or holds a malformed field: keys the
/// engine refuses, a custodian's record, or a certificate that does not
/// parse.
pub fn decode_pairing_record(blob: &[u8]) -> Result<PairingRecord, PairingCodecError> {
    let mut reader = Reader::new(blob);
    if reader.take(PAIRING_BLOB_MAGIC.len())? != PAIRING_BLOB_MAGIC {
        return Err(PairingCodecError::BadMagic);
    }
    let version = reader.take_u8()?;
    if version != PAIRING_BLOB_VERSION {
        if (FIRST_BLOB_VERSION..=LAST_EARLIER_PROTOCOL_BLOB_VERSION).contains(&version) {
            return Err(PairingCodecError::EarlierProtocol { found: version });
        }
        return Err(PairingCodecError::UnsupportedVersion { found: version });
    }
    let keys = match reader.take_u8()? {
        KEYS_HELD => {
            let keys = refineid_rapp::decode_pair_record(reader.take_length_prefixed()?)
                .map_err(PairingCodecError::PairRecord)?;
            if keys.role() != EndpointRole::Requester {
                return Err(PairingCodecError::NotRequester);
            }
            Ok(keys)
        }
        KEYS_REVOKED => {
            let pair_id = PairId::from_array(reader.take_array::<PAIR_ID_SIZE>()?);
            let by_peer = boolean_from_tag(reader.take_u8()?)?;
            Err((pair_id, by_peer))
        }
        _ => return Err(PairingCodecError::InvalidKeys),
    };
    let peer = PeerIntroduction {
        display_name: reader.take_text()?,
        platform: reader.take_text()?,
    };
    let mut record = match keys {
        Ok(keys) => PairingRecord::new(keys, peer),
        Err((pair_id, by_peer)) => PairingRecord::revoked(pair_id, by_peer, peer),
    };
    if let Some(certificate) = reader.take_optional_certificate()? {
        record.remember_authentication_certificate(certificate);
    }
    if let Some(certificate) = reader.take_optional_certificate()? {
        record.remember_signature_certificate(certificate);
    }
    if let Some(certificate) = reader.take_optional_certificate()? {
        record.remember_root_certificate(certificate);
    }
    if let Some(certificate) = reader.take_optional_certificate()? {
        record.remember_intermediate_certificate(certificate);
    }
    reader.finish()?;
    Ok(record)
}

/// Serializes a whole pairing set as one device-only blob.
///
/// The durable store persists every record together so one atomic credential
/// write covers an insert, update, or removal. Like [`encode_pairing_record`],
/// the result carries private keys and is wrapped in [`Zeroizing`].
///
/// # Errors
///
/// Fails when a record cannot be encoded.
pub fn encode_pairing_records<'record>(
    records: impl ExactSizeIterator<Item = &'record PairingRecord>,
) -> Result<Zeroizing<Vec<u8>>, PairingCodecError> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(PAIRING_SET_MAGIC);
    out.push(PAIRING_SET_VERSION);
    put_length(&mut out, records.len())?;
    for record in records {
        put_bytes(&mut out, &encode_pairing_record(record)?)?;
    }
    Ok(out)
}

/// A stored pairing set as this build reads it.
#[derive(Debug, Default)]
pub struct PairingSet {
    /// The records this build reads, in stored order.
    pub records: Vec<PairingRecord>,
    /// How many stored records were refused and left out of
    /// [`Self::records`]: written for an earlier RAPP protocol version, or
    /// holding an engine record in a format the engine does not read.
    pub refused: usize,
}

/// Whether `error` refuses one stored record under the no-migration rule,
/// so the record is left out of its set and its peer pairs again.
const fn is_refused_record(error: PairingCodecError) -> bool {
    matches!(
        error,
        PairingCodecError::EarlierProtocol { .. }
            | PairingCodecError::PairRecord(PairRecordCodecError::UnsupportedVersion)
    )
}

/// Reconstructs a whole pairing set from a device-only blob.
///
/// An empty slice decodes to an empty set, so a store whose credential does not
/// yet exist starts clean. A refused record is left out and counted in
/// [`PairingSet::refused`]; development builds report each one.
///
/// # Errors
///
/// Fails when the blob is not a pairing set, uses an unknown revision, ends
/// mid-field, carries trailing bytes, or holds a malformed record.
pub fn decode_pairing_records(blob: &[u8]) -> Result<PairingSet, PairingCodecError> {
    if blob.is_empty() {
        return Ok(PairingSet::default());
    }
    let mut reader = Reader::new(blob);
    if reader.take(PAIRING_SET_MAGIC.len())? != PAIRING_SET_MAGIC {
        return Err(PairingCodecError::BadMagic);
    }
    let version = reader.take_u8()?;
    if version != PAIRING_SET_VERSION {
        return Err(PairingCodecError::UnsupportedVersion { found: version });
    }
    let count = reader.take_length()?;
    let mut set = PairingSet::default();
    for _ in 0..count {
        match decode_pairing_record(reader.take_length_prefixed()?) {
            Ok(record) => set.records.push(record),
            Err(error) if is_refused_record(error) => {
                refineid_dev_errors::report!(Rapp, "stored pairing refused", error);
                set.refused += 1;
            }
            Err(error) => return Err(error),
        }
    }
    reader.finish()?;
    Ok(set)
}

/// Maps a boolean to its wire tag.
const fn boolean_tag(value: bool) -> u8 {
    if value { BOOLEAN_TRUE } else { BOOLEAN_FALSE }
}

/// Maps a wire tag to a boolean.
const fn boolean_from_tag(tag: u8) -> Result<bool, PairingCodecError> {
    match tag {
        BOOLEAN_FALSE => Ok(false),
        BOOLEAN_TRUE => Ok(true),
        _ => Err(PairingCodecError::InvalidBoolean),
    }
}

/// Appends a count as a big-endian `u32`.
fn put_length(out: &mut Vec<u8>, length: usize) -> Result<(), PairingCodecError> {
    let bounded = u32::try_from(length).map_err(|_| PairingCodecError::Oversized)?;
    out.extend_from_slice(&bounded.to_be_bytes());
    Ok(())
}

/// Appends a length-prefixed byte string.
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PairingCodecError> {
    put_length(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// Appends an optional certificate as its length-prefixed DER.
fn put_optional_certificate(
    out: &mut Vec<u8>,
    certificate: Option<&OwnedCert>,
) -> Result<(), PairingCodecError> {
    if let Some(certificate) = certificate {
        out.push(BOOLEAN_TRUE);
        put_bytes(out, certificate.as_der())
    } else {
        out.push(BOOLEAN_FALSE);
        Ok(())
    }
}

/// A bounds-checked forward cursor over a blob.
struct Reader<'blob> {
    remaining: &'blob [u8],
}

impl<'blob> Reader<'blob> {
    const fn new(blob: &'blob [u8]) -> Self {
        Self { remaining: blob }
    }

    /// Takes exactly `count` bytes or reports truncation.
    const fn take(&mut self, count: usize) -> Result<&'blob [u8], PairingCodecError> {
        if self.remaining.len() < count {
            return Err(PairingCodecError::Truncated);
        }
        let (head, tail) = self.remaining.split_at(count);
        self.remaining = tail;
        Ok(head)
    }

    /// Takes one byte.
    fn take_u8(&mut self) -> Result<u8, PairingCodecError> {
        self.take(size_of::<u8>())?
            .first()
            .copied()
            .ok_or(PairingCodecError::Truncated)
    }

    /// Takes a fixed-size array.
    fn take_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], PairingCodecError> {
        let slice = self.take(LENGTH)?;
        let mut array = [0_u8; LENGTH];
        array.copy_from_slice(slice);
        Ok(array)
    }

    /// Takes a big-endian `u32` length as a `usize`.
    fn take_length(&mut self) -> Result<usize, PairingCodecError> {
        let length = u32::from_be_bytes(self.take_array::<LENGTH_BYTES>()?);
        usize::try_from(length).map_err(|_| PairingCodecError::Oversized)
    }

    /// Takes a length-prefixed byte string.
    fn take_length_prefixed(&mut self) -> Result<&'blob [u8], PairingCodecError> {
        let length = self.take_length()?;
        self.take(length)
    }

    /// Takes a length-prefixed UTF-8 string.
    fn take_text(&mut self) -> Result<String, PairingCodecError> {
        let bytes = self.take_length_prefixed()?;
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_error| PairingCodecError::InvalidText)
    }

    /// Takes an optional certificate, parsed at this border.
    fn take_optional_certificate(&mut self) -> Result<Option<OwnedCert>, PairingCodecError> {
        if !boolean_from_tag(self.take_u8()?)? {
            return Ok(None);
        }
        OwnedCert::from_der(self.take_length_prefixed()?)
            .map(Some)
            .map_err(|_error| PairingCodecError::InvalidCertificate)
    }

    /// Confirms the blob was consumed exactly.
    const fn finish(&self) -> Result<(), PairingCodecError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(PairingCodecError::TrailingBytes)
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use super::{
        LAST_EARLIER_PROTOCOL_BLOB_VERSION, PAIRING_BLOB_MAGIC, PAIRING_SET_MAGIC,
        PAIRING_SET_VERSION, PairingCodecError, Reader, decode_pairing_record,
        decode_pairing_records, encode_pairing_record, encode_pairing_records, put_bytes,
        put_length,
    };
    use refineid_lib_core::x509::OwnedCert;
    use refineid_rapp::{
        PAIR_RECORD_FORMAT_VERSION, PairRecordCodecError, WireValue, decode_deterministic_cbor,
        encode_deterministic_cbor,
    };

    use crate::store::fixtures::{
        FIRST_PAIR, SECOND_PAIR, certificate, record, unconfirmed_record,
    };
    use crate::store::{
        MemoryPairingStore, PairingRecord, PairingState, PairingStore, forget_pairing,
        revoke_pairing,
    };

    /// The wall-clock time the user forgets a pairing in these tests.
    const FORGOTTEN_AT_MS: u64 = 1_800_000_000_000;
    /// A revision newer than any this build writes.
    const FUTURE_BLOB_VERSION: u8 = u8::MAX;
    /// The engine's record format before the current one.
    const EARLIER_KEYS_FORMAT: u64 = PAIR_RECORD_FORMAT_VERSION - 1;
    /// The field of the engine's record encoding that holds its format.
    const KEYS_FORMAT_FIELD: &str = "format_version";
    /// The field the engine's current record format added: the latest time
    /// a session to the pairing was established.
    const LAST_SESSION_FIELD: &str = "last_session_at_ms";

    /// The full record, certificates included.
    fn sample() -> PairingRecord {
        let mut sample = record(FIRST_PAIR);
        sample.remember_authentication_certificate(certificate());
        sample.remember_signature_certificate(certificate());
        sample.remember_root_certificate(certificate());
        sample.remember_intermediate_certificate(certificate());
        sample
    }

    fn round_trip(record: &PairingRecord) -> PairingRecord {
        decode_pairing_record(&encode_pairing_record(record).unwrap()).unwrap()
    }

    fn assert_same(left: &PairingRecord, right: &PairingRecord) {
        assert_eq!(left.pair_id(), right.pair_id());
        assert_eq!(left.state(), right.state());
        assert_eq!(left.granted_profiles(), right.granted_profiles());
        assert_eq!(left.peer(), right.peer());
        assert_eq!(
            left.pair_record()
                .map(refineid_rapp::PairRecord::local_static_private),
            right
                .pair_record()
                .map(refineid_rapp::PairRecord::local_static_private)
        );
        assert_eq!(
            left.pair_record()
                .map(refineid_rapp::PairRecord::grants_hash),
            right
                .pair_record()
                .map(refineid_rapp::PairRecord::grants_hash)
        );
        assert_eq!(
            left.authentication_certificate().map(OwnedCert::as_der),
            right.authentication_certificate().map(OwnedCert::as_der)
        );
        assert_eq!(
            left.signature_certificate().map(OwnedCert::as_der),
            right.signature_certificate().map(OwnedCert::as_der)
        );
        assert_eq!(
            left.root_certificate().map(OwnedCert::as_der),
            right.root_certificate().map(OwnedCert::as_der)
        );
        assert_eq!(
            left.intermediate_certificate().map(OwnedCert::as_der),
            right.intermediate_certificate().map(OwnedCert::as_der)
        );
    }

    /// A store holding `record` in the state `prepare` leaves it in.
    fn stored(
        record: PairingRecord,
        prepare: impl FnOnce(&mut MemoryPairingStore),
    ) -> PairingRecord {
        let pair_id = record.pair_id();
        let mut store = MemoryPairingStore::new();
        store.insert(record).unwrap();
        prepare(&mut store);
        round_trip(store.get(pair_id).unwrap())
    }

    #[test]
    fn round_trips_every_field() {
        let record = sample();
        assert_same(&record, &round_trip(&record));
    }

    #[test]
    fn round_trips_an_unconfirmed_record() {
        let record = unconfirmed_record(FIRST_PAIR);
        let decoded = round_trip(&record);
        assert_eq!(decoded.state(), PairingState::Unconfirmed);
        assert_same(&record, &decoded);
    }

    #[test]
    fn round_trips_a_forgotten_record() {
        let decoded = stored(sample(), |store| {
            forget_pairing(store, FIRST_PAIR, FORGOTTEN_AT_MS).unwrap();
        });
        assert_eq!(decoded.state(), PairingState::Forgotten);
        assert_eq!(
            decoded
                .pair_record()
                .and_then(refineid_rapp::PairRecord::forgotten_at_ms),
            Some(FORGOTTEN_AT_MS)
        );
    }

    #[test]
    fn round_trips_a_revoked_record() {
        let decoded = stored(sample(), |store| {
            revoke_pairing(store, FIRST_PAIR, true).unwrap();
        });
        assert_eq!(decoded.state(), PairingState::Revoked { by_peer: true });
        assert_eq!(decoded.pair_id(), FIRST_PAIR);
        assert!(decoded.pair_record().is_none());
        assert!(decoded.authentication_certificate().is_none());
    }

    #[test]
    fn round_trips_a_multi_record_set() {
        let records = [sample(), record(SECOND_PAIR)];
        let decoded = decode_pairing_records(&encode_pairing_records(records.iter()).unwrap())
            .unwrap()
            .records;
        assert_eq!(decoded.len(), records.len());
        for (original, decoded) in records.iter().zip(&decoded) {
            assert_same(original, decoded);
        }
    }

    #[test]
    fn an_empty_blob_is_an_empty_set() {
        assert!(decode_pairing_records(&[]).unwrap().records.is_empty());
    }

    #[test]
    fn round_trips_an_empty_set() {
        let none: Vec<PairingRecord> = Vec::new();
        assert!(
            decode_pairing_records(&encode_pairing_records(none.iter()).unwrap())
                .unwrap()
                .records
                .is_empty()
        );
    }

    #[test]
    fn rejects_a_foreign_blob() {
        assert!(matches!(
            decode_pairing_record(b"not a pairing record at all"),
            Err(PairingCodecError::BadMagic)
        ));
    }

    #[test]
    fn rejects_a_truncated_blob() {
        let blob = encode_pairing_record(&sample()).unwrap();
        let cut = blob.split_last().map_or(&[][..], |(_, rest)| rest);
        assert!(matches!(
            decode_pairing_record(cut),
            Err(PairingCodecError::Truncated)
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut blob = encode_pairing_record(&sample()).unwrap().to_vec();
        blob.extend_from_slice(b"!");
        assert!(matches!(
            decode_pairing_record(&blob),
            Err(PairingCodecError::TrailingBytes)
        ));
    }

    /// `record`'s blob written under another revision.
    fn with_version(record: &PairingRecord, version: u8) -> Vec<u8> {
        let blob = encode_pairing_record(record).unwrap();
        let after_version = blob
            .get(PAIRING_BLOB_MAGIC.len() + size_of::<u8>()..)
            .unwrap();
        let mut rewritten = PAIRING_BLOB_MAGIC.to_vec();
        rewritten.push(version);
        rewritten.extend_from_slice(after_version);
        rewritten
    }

    #[test]
    fn rejects_an_unknown_revision() {
        assert!(matches!(
            decode_pairing_record(&with_version(&sample(), FUTURE_BLOB_VERSION)),
            Err(PairingCodecError::UnsupportedVersion { found })
                if found == FUTURE_BLOB_VERSION
        ));
    }

    #[test]
    fn refuses_a_record_of_an_earlier_protocol_version() {
        assert!(matches!(
            decode_pairing_record(&with_version(&sample(), LAST_EARLIER_PROTOCOL_BLOB_VERSION)),
            Err(PairingCodecError::EarlierProtocol { .. })
        ));
    }

    /// A stored set of the record blobs `records`.
    fn set_of(records: &[Vec<u8>]) -> Vec<u8> {
        let mut set = PAIRING_SET_MAGIC.to_vec();
        set.push(PAIRING_SET_VERSION);
        put_length(&mut set, records.len()).unwrap();
        for record in records {
            put_bytes(&mut set, record).unwrap();
        }
        set
    }

    /// `record`'s blob with the engine's record inside it in the engine's
    /// earlier format, as a build before the current format stored it.
    fn with_earlier_keys_format(record: &PairingRecord) -> Vec<u8> {
        let keys = refineid_rapp::encode_pair_record(record.pair_record().unwrap()).unwrap();
        let WireValue::Map(mut fields) = decode_deterministic_cbor(&keys).unwrap() else {
            panic!("an encoded pair record is a map");
        };
        fields.insert(
            KEYS_FORMAT_FIELD.to_owned(),
            WireValue::Unsigned(EARLIER_KEYS_FORMAT),
        );
        fields.remove(LAST_SESSION_FIELD);
        let earlier = encode_deterministic_cbor(&WireValue::Map(fields)).unwrap();

        let blob = encode_pairing_record(record).unwrap();
        let mut reader = Reader::new(&blob);
        reader.take(PAIRING_BLOB_MAGIC.len()).unwrap();
        let revision = reader.take_u8().unwrap();
        let keys_tag = reader.take_u8().unwrap();
        reader.take_length_prefixed().unwrap();
        let mut rewritten = PAIRING_BLOB_MAGIC.to_vec();
        rewritten.push(revision);
        rewritten.push(keys_tag);
        put_bytes(&mut rewritten, &earlier).unwrap();
        rewritten.extend_from_slice(reader.remaining);
        rewritten
    }

    #[test]
    fn a_set_leaves_out_records_of_an_earlier_protocol_version() {
        let current = record(SECOND_PAIR);
        let earlier = with_version(&sample(), LAST_EARLIER_PROTOCOL_BLOB_VERSION);
        let decoded = decode_pairing_records(&set_of(&[
            earlier,
            encode_pairing_record(&current).unwrap().to_vec(),
        ]))
        .unwrap();
        assert_eq!(decoded.refused, 1);
        let [only] = decoded.records.as_slice() else {
            panic!("expected only the current record");
        };
        assert_same(&current, only);
    }

    #[test]
    fn a_record_whose_keys_are_in_an_earlier_format_is_refused() {
        assert!(matches!(
            decode_pairing_record(&with_earlier_keys_format(&record(FIRST_PAIR))),
            Err(PairingCodecError::PairRecord(
                PairRecordCodecError::UnsupportedVersion
            ))
        ));
    }

    #[test]
    fn a_set_leaves_out_and_counts_records_whose_keys_are_in_an_earlier_format() {
        let current = record(SECOND_PAIR);
        let decoded = decode_pairing_records(&set_of(&[
            with_earlier_keys_format(&record(FIRST_PAIR)),
            encode_pairing_record(&current).unwrap().to_vec(),
        ]))
        .unwrap();
        assert_eq!(decoded.refused, 1);
        let [only] = decoded.records.as_slice() else {
            panic!("expected only the current record");
        };
        assert_same(&current, only);
    }

    #[test]
    fn a_set_of_current_records_refuses_none() {
        let records = [sample(), record(SECOND_PAIR)];
        let decoded =
            decode_pairing_records(&encode_pairing_records(records.iter()).unwrap()).unwrap();
        assert_eq!(decoded.refused, 0);
    }

    #[test]
    fn a_malformed_record_fails_the_whole_set() {
        let mut truncated = encode_pairing_record(&record(FIRST_PAIR)).unwrap().to_vec();
        truncated.pop();
        assert!(matches!(
            decode_pairing_records(&set_of(&[truncated])),
            Err(PairingCodecError::Truncated)
        ));
    }
}
