//! What sessions on this computer heard of a pairing's card, and the identity
//! offer it bounds (RAPP v26.10.29 section 8.4).
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
    /// names the certificate's card and was heard within the grace (section
    /// 8.4 item 3).
    ///
    /// A sighting dated after `now_ms`, by a wall clock set back since,
    /// stands until the grace after its date has passed while it lies less
    /// than the grace ahead; one further ahead does not stand, so a step
    /// back of the clock stretches the offer by less than one grace.
    #[must_use]
    pub fn stands_for(&self, certificate: &OwnedCert, now_ms: u64) -> bool {
        let age = now_ms.saturating_sub(self.at_ms);
        let ahead = self.at_ms.saturating_sub(now_ms);
        CertificateFingerprint::of_certificate(certificate.as_der()) == self.fingerprint
            && age < IDENTITY_OFFER_GRACE_MS
            && ahead < IDENTITY_OFFER_GRACE_MS
    }

    /// The wall-clock moment the offer this sighting bounds lapses unless a
    /// session hears the card again (section 8.4 item 3).
    #[must_use]
    pub const fn offer_lapses_at_ms(&self) -> u64 {
        self.at_ms.saturating_add(IDENTITY_OFFER_GRACE_MS)
    }
}

/// The leading bytes of an encoded sighting; bytes that do not start with
/// them are not one.
const SIGHTING_MAGIC: &[u8] = b"fi.refineid.windows.card-sighting";

/// Bytes of a sighting's wall-clock time, big-endian.
const TIME_BYTES: usize = size_of::<u64>();

/// Bytes of one encoded sighting after the magic: the pair identifier, the
/// card's fingerprint and the time it was heard present.
const SIGHTING_BYTES: usize = PAIR_ID_SIZE + CERTIFICATE_FINGERPRINT_SIZE + TIME_BYTES;

/// A sighting that does not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SightingCodecError;

impl core::fmt::Display for SightingCodecError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("the card sighting does not decode")
    }
}

impl core::error::Error for SightingCodecError {}

/// Encodes one pairing's last sighting. Nothing in it is secret: a pair
/// identifier, the fingerprint of a public certificate and a time.
#[must_use]
pub fn encode_sighting(pair_id: PairId, sighting: CardSighting) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGHTING_MAGIC.len() + SIGHTING_BYTES);
    out.extend_from_slice(SIGHTING_MAGIC);
    out.extend_from_slice(pair_id.as_bytes());
    out.extend_from_slice(sighting.fingerprint.as_bytes());
    out.extend_from_slice(&sighting.at_ms.to_be_bytes());
    out
}

/// Decodes a sighting written by [`encode_sighting`].
///
/// # Errors
///
/// [`SightingCodecError`] when the bytes are not one.
pub fn decode_sighting(bytes: &[u8]) -> Result<(PairId, CardSighting), SightingCodecError> {
    let entry: &[u8; SIGHTING_BYTES] = bytes
        .strip_prefix(SIGHTING_MAGIC)
        .and_then(|entry| entry.try_into().ok())
        .ok_or(SightingCodecError)?;
    let (pair_id, after) = entry.split_at(PAIR_ID_SIZE);
    let (fingerprint, time) = after.split_at(CERTIFICATE_FINGERPRINT_SIZE);
    let at_ms = u64::from_be_bytes(time.try_into().map_err(|_| SightingCodecError)?);
    Ok((
        PairId::reconstruct(pair_id).map_err(|_| SightingCodecError)?,
        CardSighting::new(
            CertificateFingerprint::reconstruct(fingerprint).map_err(|_| SightingCodecError)?,
            at_ms,
        ),
    ))
}

#[cfg(test)]
mod tests {
    use refineid_rapp::{CertificateFingerprint, IDENTITY_OFFER_GRACE_MS};

    use super::{CardSighting, decode_sighting, encode_sighting};
    use crate::store::fixtures::{FIRST_PAIR, certificate};

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
        assert_eq!(
            sighting.offer_lapses_at_ms(),
            HEARD_AT_MS + IDENTITY_OFFER_GRACE_MS
        );
    }

    #[test]
    fn another_card_heard_withdraws_the_offer_at_once() {
        let sighting = CardSighting::new(OTHER_CARD, HEARD_AT_MS);
        assert!(!sighting.stands_for(&certificate(), HEARD_AT_MS));
    }

    #[test]
    fn a_clock_set_back_within_the_grace_keeps_the_offer() {
        assert!(heard().stands_for(&certificate(), HEARD_AT_MS - 1));
        assert!(heard().stands_for(&certificate(), HEARD_AT_MS - IDENTITY_OFFER_GRACE_MS + 1));
    }

    #[test]
    fn a_clock_set_back_beyond_the_grace_does_not_stretch_the_offer() {
        assert!(!heard().stands_for(&certificate(), HEARD_AT_MS - IDENTITY_OFFER_GRACE_MS));
    }

    #[test]
    fn a_sighting_round_trips() {
        assert_eq!(
            decode_sighting(&encode_sighting(FIRST_PAIR, heard())),
            Ok((FIRST_PAIR, heard()))
        );
    }

    #[test]
    fn a_foreign_or_cut_sighting_does_not_decode() {
        assert!(decode_sighting(b"not a sighting").is_err());
        let encoded = encode_sighting(FIRST_PAIR, heard());
        let cut = encoded.get(..encoded.len() - 1).unwrap_or_default();
        assert!(decode_sighting(cut).is_err());
    }
}
