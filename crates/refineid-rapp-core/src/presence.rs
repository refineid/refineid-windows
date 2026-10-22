//! What sessions on this computer heard of a pairing's card, and the identity
//! offer it bounds (RAPP v26.10.22 section 8.4).
//!
//! A requester offers a pairing's identity to local consumers on a
//! certificate whose fingerprint the custodian confirmed on a session, and
//! keeps offering it between sessions; the offer goes once no session has
//! heard the card present for [`IDENTITY_OFFER_GRACE_MS`], and at once when a
//! session hears another card (section 8.4 items 2 and 3). Every requester
//! process of one user offers by the same evidence: the last
//! [`CardSighting`] of each pairing, which the session that heard it records
//! in the pairing store.

use refineid_lib_core::x509::OwnedCert;
use refineid_rapp::{
    CERTIFICATE_FINGERPRINT_SIZE, CertificateFingerprint, IDENTITY_OFFER_GRACE_MS, PAIR_ID_SIZE,
};

use crate::ids::PairId;

/// How often a session that hears the card present records it again while
/// it stays present: well inside the grace, so the offer stands for as long
/// as such a session is open.
pub const SIGHTING_REFRESH_MS: u64 = 10_000;

/// The last moment a session on this computer heard the custodian report a
/// card present (`card.status`, section 8.4 item 1).
///
/// It names the card and the time on the wall clock, which every process
/// and every boot of this computer shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardSighting {
    fingerprint: CertificateFingerprint,
    at_ms: u64,
}

impl CardSighting {
    /// The card of `fingerprint`, heard present at `at_ms` on the wall clock.
    #[must_use]
    pub const fn new(fingerprint: CertificateFingerprint, at_ms: u64) -> Self {
        Self { fingerprint, at_ms }
    }

    /// The fingerprint of the card heard present.
    #[must_use]
    pub const fn fingerprint(&self) -> CertificateFingerprint {
        self.fingerprint
    }

    /// Whether the offer of `certificate` stands at `now_ms`: this sighting
    /// names the certificate's card and is younger than the grace (section
    /// 8.4 item 3). A sighting dated after `now_ms`, by a wall clock set back
    /// since, does not stand.
    #[must_use]
    pub fn stands_for(&self, certificate: &OwnedCert, now_ms: u64) -> bool {
        CertificateFingerprint::of_certificate(certificate.as_der()) == self.fingerprint
            && now_ms
                .checked_sub(self.at_ms)
                .is_some_and(|age| age < IDENTITY_OFFER_GRACE_MS)
    }
}

/// The leading bytes of an encoded sighting set; a set that does not start
/// with them is not one.
const SIGHTINGS_MAGIC: &[u8] = b"fi.refineid.windows.card-sightings";

/// Bytes of a sighting's wall-clock time, big-endian.
const TIME_BYTES: usize = size_of::<u64>();

/// Bytes of one encoded entry: the pair identifier, the card's fingerprint
/// and the time it was heard present.
const ENTRY_BYTES: usize = PAIR_ID_SIZE + CERTIFICATE_FINGERPRINT_SIZE + TIME_BYTES;

/// A sighting set that does not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SightingsCodecError;

impl core::fmt::Display for SightingsCodecError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("the card sighting set does not decode")
    }
}

impl core::error::Error for SightingsCodecError {}

/// Encodes the last sighting of each pairing. Nothing in it is secret: a
/// pair identifier, the fingerprint of a public certificate and a time.
#[must_use]
pub fn encode_sightings(sightings: &[(PairId, CardSighting)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGHTINGS_MAGIC.len() + sightings.len() * ENTRY_BYTES);
    out.extend_from_slice(SIGHTINGS_MAGIC);
    for (pair_id, sighting) in sightings {
        out.extend_from_slice(pair_id.as_bytes());
        out.extend_from_slice(sighting.fingerprint.as_bytes());
        out.extend_from_slice(&sighting.at_ms.to_be_bytes());
    }
    out
}

/// Decodes a sighting set written by [`encode_sightings`].
///
/// # Errors
///
/// [`SightingsCodecError`] when the bytes are not such a set.
pub fn decode_sightings(bytes: &[u8]) -> Result<Vec<(PairId, CardSighting)>, SightingsCodecError> {
    let entries = bytes
        .strip_prefix(SIGHTINGS_MAGIC)
        .ok_or(SightingsCodecError)?;
    let (whole, rest) = entries.as_chunks::<ENTRY_BYTES>();
    if !rest.is_empty() {
        return Err(SightingsCodecError);
    }
    whole
        .iter()
        .map(|entry| {
            let (pair_id, after) = entry.split_at(PAIR_ID_SIZE);
            let (fingerprint, time) = after.split_at(CERTIFICATE_FINGERPRINT_SIZE);
            let at_ms = u64::from_be_bytes(time.try_into().map_err(|_| SightingsCodecError)?);
            Ok((
                PairId::reconstruct(pair_id).map_err(|_| SightingsCodecError)?,
                CardSighting::new(
                    CertificateFingerprint::reconstruct(fingerprint)
                        .map_err(|_| SightingsCodecError)?,
                    at_ms,
                ),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use refineid_rapp::{CertificateFingerprint, IDENTITY_OFFER_GRACE_MS};

    use super::{CardSighting, SIGHTINGS_MAGIC, decode_sightings, encode_sightings};
    use crate::store::fixtures::{FIRST_PAIR, SECOND_PAIR, certificate};

    /// The wall-clock time the card is heard present in these tests.
    const HEARD_AT_MS: u64 = 1_700_000_000_000;
    /// A fingerprint no certificate here has.
    const OTHER_CARD: CertificateFingerprint =
        CertificateFingerprint::from_array(*b"the fingerprint of another card.");

    fn heard() -> CardSighting {
        CardSighting::new(
            CertificateFingerprint::of_certificate(certificate().as_der()),
            HEARD_AT_MS,
        )
    }

    #[test]
    fn the_offer_stands_through_the_grace_and_not_after() {
        let sighting = heard();
        assert!(sighting.stands_for(&certificate(), HEARD_AT_MS));
        assert!(sighting.stands_for(&certificate(), HEARD_AT_MS + IDENTITY_OFFER_GRACE_MS - 1));
        assert!(!sighting.stands_for(&certificate(), HEARD_AT_MS + IDENTITY_OFFER_GRACE_MS));
    }

    #[test]
    fn another_card_heard_withdraws_the_offer_at_once() {
        let sighting = CardSighting::new(OTHER_CARD, HEARD_AT_MS);
        assert!(!sighting.stands_for(&certificate(), HEARD_AT_MS));
    }

    #[test]
    fn a_sighting_from_after_now_does_not_stand() {
        assert!(!heard().stands_for(&certificate(), HEARD_AT_MS - 1));
    }

    #[test]
    fn a_sighting_set_round_trips() {
        let set = vec![
            (FIRST_PAIR, heard()),
            (SECOND_PAIR, CardSighting::new(OTHER_CARD, HEARD_AT_MS)),
        ];
        assert_eq!(decode_sightings(&encode_sightings(&set)), Ok(set));
        assert_eq!(decode_sightings(&encode_sightings(&[])), Ok(Vec::new()));
    }

    #[test]
    fn a_foreign_or_cut_set_does_not_decode() {
        assert!(decode_sightings(b"not a sighting set").is_err());
        let encoded = encode_sightings(&[(FIRST_PAIR, heard())]);
        let cut = encoded.get(..encoded.len() - 1).unwrap_or_default();
        assert!(decode_sightings(cut).is_err());
        assert!(decode_sightings(SIGHTINGS_MAGIC).is_ok_and(|set| set.is_empty()));
    }
}
