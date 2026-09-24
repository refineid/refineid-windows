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

//! Minimal X.509 CRL (Certificate Revocation List) parser,
//! scoped to revocation checking.
//!
//! Given the DER bytes of an RFC 5280 `CertificateList`, exposes
//! the issuer DN, `thisUpdate`, optional `nextUpdate`, and a
//! `Crl::find_serial` lookup that lazily walks the revoked-cert
//! list. The parser does **not** verify the CRL's signature --
//! that ties to the issuer trust store and lives a layer up.
//!
//! Per-entry extensions: the `reasonCode` extension (OID
//! `2.5.29.21`) is parsed and surfaced as
//! [`RevokedEntry::reason`]. Other per-entry extensions (invalidity
//! date, certificate issuer for indirect CRLs) and CRL-level
//! extensions are not interpreted yet -- they land when a use
//! case needs them.
//!
//! Decoded with the `der` / `x509-cert` `RustCrypto` stack and reuses
//! the time parser from [`crate::x509`]. The module ships in full;
//! the higher-level revocation flow that wires it in is queued.

use crate::identity::CertSerial;
use crate::x509::{DateTime, X509Error};
use spki::der::asn1::{AnyRef, ObjectIdentifier};
use spki::der::{Decode as _, Reader as _, SliceReader, Tag, TagNumber, Tagged as _};
use x509_cert::crl::RevokedCert;
use x509_cert::ext::Extension;

/// `id-ce-cRLReasons` (RFC 5280 sec.5.3.1) -- the per-entry
/// `reasonCode` extension OID.
const OID_CRL_REASONS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.21");

/// `CRLReason` ENUMERATED (RFC 5280 sec.5.3.1).
///
/// Shared by the CRL per-entry `reasonCode` extension and OCSP
/// `RevokedInfo` (RFC 6960 sec.4.2.1 reuses the same ENUMERATED). A
/// closed set: an unassigned code (the reserved `7`, or anything out
/// of range) is treated as "no recognised reason" at the parse
/// boundary -- the cert is still revoked, the reason is simply
/// absent. `Display` renders `<name> (<0xNN>)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlReason {
    /// `0` -- no specific reason given.
    Unspecified,
    /// `1` -- the private key is suspected compromised.
    KeyCompromise,
    /// `2` -- the issuing CA's key is suspected compromised.
    CaCompromise,
    /// `3` -- the subject's affiliation changed.
    AffiliationChanged,
    /// `4` -- replaced by a newer cert (DVV uses this on FINEID
    /// card swaps).
    Superseded,
    /// `5` -- the cert is no longer needed.
    CessationOfOperation,
    /// `6` -- temporarily suspended (certificateHold).
    CertificateHold,
    /// `8` -- remove from a delta-CRL.
    RemoveFromCrl,
    /// `9` -- a privilege in the cert was withdrawn.
    PrivilegeWithdrawn,
    /// `10` -- the attribute-authority key is compromised.
    AaCompromise,
}

impl CrlReason {
    /// Map a `CRLReason` ENUMERATED byte to its variant. `None` for
    /// the reserved `7` or any out-of-range code (treated as "no
    /// recognised reason" -- see the type docs).
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Unspecified,
            1 => Self::KeyCompromise,
            2 => Self::CaCompromise,
            3 => Self::AffiliationChanged,
            4 => Self::Superseded,
            5 => Self::CessationOfOperation,
            6 => Self::CertificateHold,
            8 => Self::RemoveFromCrl,
            9 => Self::PrivilegeWithdrawn,
            10 => Self::AaCompromise,
            _ => return None,
        })
    }

    /// The on-wire ENUMERATED code for this reason.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            Self::RemoveFromCrl => 8,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
        }
    }
}

impl core::fmt::Display for CrlReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match *self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "keyCompromise",
            Self::CaCompromise => "cACompromise",
            Self::AffiliationChanged => "affiliationChanged",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessationOfOperation",
            Self::CertificateHold => "certificateHold",
            Self::RemoveFromCrl => "removeFromCRL",
            Self::PrivilegeWithdrawn => "privilegeWithdrawn",
            Self::AaCompromise => "aACompromise",
        };
        write!(f, "{name} ({:#04x})", self.code())
    }
}

/// X.509 v2 CRL, parsed enough to check whether a given cert
/// serial is on the revocation list.
#[non_exhaustive]
#[derive(Debug, Clone)]
#[expect(
    clippy::partial_pub_fields,
    reason = "the parsed-once typed values (raw_der, tbs_der, signature_alg_oid, ...) are intentionally pub for read; revoked_seq_value is intentionally private because it requires the typed `revoked_certificates()` iterator accessor below to be walked.  Making all-public would expose the iterator-only field to direct walking that bypasses BER-typed parsing; making all-private would force ceremony on every typed-value reader."
)]
pub struct Crl<'a> {
    /// Full CRL DER bytes (outer `SEQUENCE` and downward).
    pub raw_der: &'a [u8],
    /// `tbsCertList` SEQUENCE bytes including outer tag + length
    /// -- exactly the bytes covered by the CRL signature.
    pub tbs_der: &'a [u8],
    /// `issuer` Distinguished Name (the whole `Name` SEQUENCE,
    /// outer tag/length included). Typed [`crate::x509::Name`] so a
    /// CRL's issuer pairs against a cert's issuer with the same
    /// byte-exact `==` the rest of chain building uses.
    pub issuer: crate::x509::Name<'a>,
    /// `thisUpdate` -- timestamp at which the CRL is current
    /// per RFC 5280 §5.1.2.4.
    pub this_update: DateTime,
    /// `nextUpdate` -- timestamp at which the issuer commits to
    /// publishing the next CRL per RFC 5280 §5.1.2.5. `None` for
    /// CRLs without the optional field.
    pub next_update: Option<DateTime>,
    /// Value bytes of the `revokedCertificates` SEQUENCE -- a
    /// sequence of `RevokedCertificate` SEQUENCEs. `None` if
    /// the CRL declares no revoked entries (the field is OPTIONAL).
    revoked_seq_value: Option<&'a [u8]>,
    /// Signature algorithm OID body (the value of the `06 LL`
    /// TLV inside the outer `signatureAlgorithm`).
    pub signature_alg_oid: &'a [u8],
    /// Outer signature BIT STRING value with the unused-bits
    /// leading byte stripped.
    pub signature_bits: &'a [u8],
}

impl Crl<'_> {
    /// Verify the CRL signature against the issuer's SPKI.
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    /// As for `x509::verify_tbs_signature`.
    #[inline]
    pub fn verify_signature<B: AsRef<[u8]>>(
        &self,
        issuer_spki_der: B,
    ) -> Result<(), crate::x509::VerifyError> {
        let issuer_spki_der = issuer_spki_der.as_ref();
        crate::x509::verify_tbs_signature(crate::x509::TbsSignature {
            tbs_der: self.tbs_der,
            signature_alg_oid: self.signature_alg_oid,
            signature_bits: self.signature_bits,
            issuer_spki_der,
        })
    }
}

/// A [`Crl`] whose issuer signature has been verified against a
/// signer SPKI.
///
/// Trust by construction (see `doc/typing-discipline.md`): the only
/// production constructor is [`VerifiedCrl::verify`], so holding this
/// type is proof the CRL signature checked against a signer.
/// [`crate::revocation::check_against_crl`] takes a `VerifiedCrl`, so
/// a CRL's revocation list cannot be consulted without a checked
/// signature -- the same gate as [`crate::ocsp::VerifiedOcspResponse`].
#[derive(Debug, Clone)]
pub struct VerifiedCrl<'a> {
    /// The verified CRL.
    crl: Crl<'a>,
}

impl<'a> VerifiedCrl<'a> {
    /// Verify `crl`'s issuer signature against `signer_spki` and, on
    /// success, wrap it. The only production door to a verified CRL.
    ///
    /// # Errors
    /// [`crate::x509::VerifyError`] when the signature does not verify
    /// against `signer_spki`.
    #[inline]
    pub fn verify(
        crl: &Crl<'a>,
        signer_spki: &crate::x509::SpkiDer<'_>,
    ) -> Result<Self, crate::x509::VerifyError> {
        crl.verify_signature(signer_spki.as_der())?;
        Ok(Self { crl: crl.clone() })
    }

    /// Borrow the verified CRL. `pub(crate)`: reachable only on a
    /// verified CRL, and only within the crate's revocation logic --
    /// so any revocation-list read is downstream of a checked
    /// signature.
    #[inline]
    #[must_use]
    pub(crate) const fn as_crl(&self) -> &Crl<'a> {
        &self.crl
    }

    /// Test-only: wrap a CRL *without* verifying its signature, to
    /// exercise revocation-status logic in isolation. `#[cfg(test)]`-
    /// gated, so the production "only door is `verify`" guarantee is
    /// unaffected.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn from_unverified_for_test(crl: Crl<'a>) -> Self {
        Self { crl }
    }
}

/// One entry in `revokedCertificates`.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RevokedEntry {
    /// The revoked cert's serial number.
    pub serial: CertSerial,
    /// `revocationDate` per RFC 5280 §5.3.1.
    pub revocation_date: DateTime,
    /// `CRLReason` from the `reasonCode` per-entry extension (OID
    /// 2.5.29.21) when present and recognised. `None` when the
    /// issuer didn't include the extension (or used an unassigned
    /// code).
    pub reason: Option<CrlReason>,
}

/// Owning wrapper around a parsed X.509 CRL.
///
/// Same pattern as [`crate::x509::OwnedCert`]: holds the CRL's
/// DER bytes plus a re-parseable view. Public entry point under
/// typing-discipline rule D; free `parse_crl` is `pub(crate)`
/// because it returns a borrowed view tied to the input.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct OwnedCrl {
    /// DER-encoded `CertificateList` SEQUENCE bytes (RFC 5280
    /// §5.1). Stored verbatim so re-parsing and signature
    /// re-verification both work; the parser view inside
    /// `OwnedCrl` borrows back into this buffer.
    der: Vec<u8>,
}

impl OwnedCrl {
    /// Parse `der` as an X.509 v2 CRL, allocating an owned copy
    /// of the bytes so the resulting wrapper is independent of
    /// the input borrow.
    ///
    /// # Errors
    /// [`X509Error`] from the CRL parser.
    #[inline]
    pub fn from_der<B: AsRef<[u8]>>(der: B) -> Result<Self, X509Error> {
        let bytes = der.as_ref().to_vec();
        Crl::parse(&bytes)?;
        Ok(Self { der: bytes })
    }

    /// Re-parse the owned DER and hand back the borrowed view.
    ///
    /// # Performance
    /// Parses the DER on **every call** (O(n) in the DER length). For
    /// repeated field access bind the view once (`let crl = owned.view();`)
    /// and reuse it, rather than calling `view()` per field.
    ///
    /// # Panics
    /// Never -- [`from_der`] validated at construction.
    ///
    /// [`from_der`]: Self::from_der
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "Invariant: `from_der` parsed the same bytes and returned `Ok` before constructing `Self`; the bytes are owned and immutable, so re-parse cannot fail."
    )]
    #[inline]
    pub fn view(&self) -> Crl<'_> {
        Crl::parse(&self.der).expect("OwnedCrl: from_der validated DER at construction")
    }

    /// Raw DER bytes the wrapper owns.
    #[inline]
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// Verify the CRL signature against the issuer's SPKI. See
    /// [`Crl::verify_signature`].
    ///
    /// # Errors
    /// As for [`Crl::verify_signature`].
    #[inline]
    pub fn verify_signature<B: AsRef<[u8]>>(
        &self,
        issuer_spki_der: B,
    ) -> Result<(), crate::x509::VerifyError> {
        self.view().verify_signature(issuer_spki_der)
    }
}

impl<'a> Crl<'a> {
    /// Parse a `CertificateList` DER blob.
    ///
    /// # Errors
    /// Any der decode failure, or a top-level shape that doesn't look
    /// like `CertificateList ::= SEQUENCE { TBSCertList,
    /// AlgorithmIdentifier, BIT STRING }`.
    #[inline]
    pub(crate) fn parse(der: &'a [u8]) -> Result<Self, X509Error> {
        // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm,
        //                                signatureValue BIT STRING }
        let outer = AnyRef::from_der(der)
            .map_err(|_ignored| X509Error::UnexpectedStructure("CRL not a TLV"))?;
        if outer.tag() != Tag::Sequence {
            return Err(X509Error::UnexpectedStructure("CRL not SEQUENCE"));
        }
        let mut reader = SliceReader::new(outer.value())
            .map_err(|_ignored| X509Error::UnexpectedStructure("CRL body"))?;

        // tbsCertList -- the exact bytes the signature covers.
        let tbs_der = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList"))?;

        // signatureAlgorithm AlgorithmIdentifier -- carry the OID body
        // (the value of its `06 LL` TLV), borrowed from the input.
        let sig_alg = AnyRef::from_der(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("CRL signatureAlgorithm"))?,
        )
        .map_err(|_ignored| X509Error::UnexpectedStructure("CRL signatureAlgorithm"))?;
        let mut alg_reader = SliceReader::new(sig_alg.value())
            .map_err(|_ignored| X509Error::UnexpectedStructure("CRL signatureAlgorithm body"))?;
        let alg_oid =
            AnyRef::from_der(alg_reader.tlv_bytes().map_err(|_ignored| {
                X509Error::UnexpectedStructure("CRL signatureAlgorithm OID")
            })?)
            .map_err(|_ignored| X509Error::UnexpectedStructure("CRL signatureAlgorithm OID"))?;
        if alg_oid.tag() != Tag::ObjectIdentifier {
            return Err(X509Error::UnexpectedStructure("CRL signatureAlgorithm OID"));
        }
        let signature_alg_oid = alg_oid.value();

        // signatureValue BIT STRING -- strip the leading unused-bits byte.
        let sig_bits = AnyRef::from_der(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("CRL signature"))?,
        )
        .map_err(|_ignored| X509Error::UnexpectedStructure("CRL signature"))?;
        if sig_bits.tag() != Tag::BitString {
            return Err(X509Error::UnexpectedStructure(
                "CRL signature not BIT STRING",
            ));
        }
        let signature_bits = sig_bits
            .value()
            .get(1..)
            .ok_or(X509Error::UnexpectedStructure(
                "CRL signature BIT STRING empty",
            ))?;

        parse_tbs_cert_list(tbs_der, der, signature_alg_oid, signature_bits)
    }
}

/// Decode a `TBSCertList` SEQUENCE into a borrowing [`Crl`].
///
/// RFC 5280 §5.1.2 -- `TBSCertList` is the part of a CRL covered
/// by the issuer's signature. `tbs_der` is the un-tagged
/// SEQUENCE bytes; `raw` is the full CRL DER (for signature
/// verification reference); `signature_alg_oid` and
/// `signature_bits` are the outer wrapper's fields, already
/// validated by the caller to match the TBS's `signature` field.
///
/// The function does not verify the signature; it only parses
/// the TBS payload. Signature verification lives on
/// [`OwnedCrl::verify_signature`] in this module.
fn parse_tbs_cert_list<'a>(
    tbs_der: &'a [u8],
    raw: &'a [u8],
    signature_alg_oid: &'a [u8],
    signature_bits: &'a [u8],
) -> Result<Crl<'a>, X509Error> {
    // TBSCertList ::= SEQUENCE {
    //     version                 INTEGER OPTIONAL,
    //     signature               AlgorithmIdentifier,
    //     issuer                  Name,
    //     thisUpdate              Time,
    //     nextUpdate              Time OPTIONAL,
    //     revokedCertificates     SEQUENCE OF ... OPTIONAL,
    //     crlExtensions           [0] EXPLICIT Extensions OPTIONAL
    // }
    // crlExtensions [0] EXPLICIT, matched as a value rather than as
    // a pattern so the tag number stays one expression.
    const CRL_EXTENSIONS_TAG: Tag = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(0),
    };

    let tbs = AnyRef::from_der(tbs_der)
        .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList not a TLV"))?;
    if tbs.tag() != Tag::Sequence {
        return Err(X509Error::UnexpectedStructure("tbsCertList not SEQUENCE"));
    }
    let mut reader = SliceReader::new(tbs.value())
        .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList body"))?;

    // version INTEGER OPTIONAL, then signature AlgorithmIdentifier.
    // Read the first field: if it is the version INTEGER, the
    // signature is the next field; otherwise this field WAS the
    // signature (version absent) and is already consumed.
    let first = AnyRef::from_der(
        reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList version/signature"))?,
    )
    .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList version/signature"))?;
    if first.tag() == Tag::Integer {
        reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList signature"))?;
    }

    // issuer Name -- exact bytes (byte-exact for OCSP issuer match).
    let issuer_dn_der = reader
        .tlv_bytes()
        .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList issuer"))?;

    // thisUpdate Time -- decoded by x509-cert (UTCTime /
    // GeneralizedTime choice + RFC 5280 YY normalisation).
    let this_update = x509_cert::time::Time::from_der(
        reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList thisUpdate"))?,
    )
    .map_err(|_ignored| X509Error::InvalidTime)?
    .to_date_time();

    // Optional nextUpdate (Time) / revokedCertificates (SEQUENCE) /
    // crlExtensions ([0] EXPLICIT).
    let mut next_update: Option<DateTime> = None;
    let mut revoked_seq_value: Option<&[u8]> = None;
    while !reader.is_finished() {
        let field_tlv = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList trailing field"))?;
        let any = AnyRef::from_der(field_tlv)
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList trailing field"))?;
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "der's Tag enum is large and open-ended; only the three TBSCertList trailing-field tags are valid here, and any other tag is a structural error"
        )]
        match any.tag() {
            Tag::UtcTime | Tag::GeneralizedTime => {
                next_update = Some(
                    x509_cert::time::Time::from_der(field_tlv)
                        .map_err(|_ignored| X509Error::InvalidTime)?
                        .to_date_time(),
                );
            }
            Tag::Sequence => {
                revoked_seq_value = Some(any.value());
            }
            // crlExtensions [0] EXPLICIT -- not interpreted.
            tag if tag == CRL_EXTENSIONS_TAG => {}
            _ => return Err(X509Error::UnexpectedStructure("unexpected CRL field")),
        }
    }

    Ok(Crl {
        raw_der: raw,
        tbs_der,
        issuer: crate::x509::Name::from_validated(issuer_dn_der),
        this_update,
        next_update,
        revoked_seq_value,
        signature_alg_oid,
        signature_bits,
    })
}

impl<'a> Crl<'a> {
    /// Lazily iterate the revoked-certificate entries. A malformed
    /// entry ends iteration (treated as end-of-list) so one corrupt
    /// entry can't poison the rest of the lookup.
    #[inline]
    #[must_use]
    pub(crate) fn entries(&self) -> RevokedIter<'a> {
        RevokedIter {
            reader: self
                .revoked_seq_value
                .and_then(|body| SliceReader::new(body).ok()),
        }
    }

    /// Walk the CRL's revoked entries looking for `serial`. Returns
    /// the matching entry or `None` when the serial isn't listed.
    #[inline]
    #[must_use]
    pub(crate) fn find_serial(&self, serial: &CertSerial) -> Option<RevokedEntry> {
        self.entries().find(|entry| &entry.serial == serial)
    }
}

/// Iterator yielded by `Crl::entries`.
#[non_exhaustive]
#[derive(Debug)]
pub struct RevokedIter<'a> {
    /// Reader over the `revokedCertificates SEQUENCE OF` body; each
    /// `next()` decodes one `RevokedCert`. `None` when the CRL lists
    /// no revoked certs.
    reader: Option<SliceReader<'a>>,
}

impl Iterator for RevokedIter<'_> {
    type Item = RevokedEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let reader = self.reader.as_mut()?;
        if reader.is_finished() {
            return None;
        }
        // Peel one RevokedCert TLV and decode it with the typed
        // x509-cert structure -- trust the type for field validation.
        let revoked =
            RevokedCert::<x509_cert::certificate::Rfc5280>::from_der(reader.tlv_bytes().ok()?)
                .ok()?;
        let serial = CertSerial::from_bytes(revoked.serial_number.as_bytes().to_vec());
        let revocation_date = revoked.revocation_date.to_date_time();
        let reason = revoked
            .crl_entry_extensions
            .as_deref()
            .and_then(RevokedIter::find_reason_code);
        Some(RevokedEntry {
            serial,
            revocation_date,
            reason,
        })
    }
}

impl RevokedIter<'_> {
    /// Find the `reasonCode` extension (OID 2.5.29.21) among an
    /// entry's `crlEntryExtensions` and decode its ENUMERATED value
    /// into a [`CrlReason`]. `None` if absent, unrecognised, or
    /// malformed.
    fn find_reason_code(extensions: &[Extension]) -> Option<CrlReason> {
        let reason_ext = extensions
            .iter()
            .find(|ext| ext.extn_id == OID_CRL_REASONS)?;
        // extnValue OCTET STRING wraps the `CRLReason` ENUMERATED.
        let inner = AnyRef::from_der(reason_ext.extn_value.as_bytes()).ok()?;
        if inner.tag() != Tag::Enumerated {
            return None;
        }
        let value = inner.value();
        if value.len() == 1 {
            value.first().copied().and_then(CrlReason::from_code)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{Crl, CrlReason, RevokedEntry, X509Error};
    use crate::identity::CertSerial;
    use core::str::FromStr as _;
    use spki::AlgorithmIdentifierOwned;
    use spki::der::Encode as _;
    use spki::der::asn1::{Any, BitString, ObjectIdentifier, OctetString, UtcTime};
    use spki::der::{DateTime, Tag};
    use x509_cert::certificate::Version;
    use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Time;

    /// One revoked-cert row for [`build_crl`], in our domain types.
    struct RevokedFixture {
        /// The revoked cert's serial number.
        serial: CertSerial,
        /// When it was revoked.
        revoked_at: DateTime,
        /// Optional `CRLReason`.
        reason: Option<CrlReason>,
    }

    /// A distinct cert serial for fixtures. The value is arbitrary
    /// -- only its uniqueness matters, since the CRL logic keys on
    /// serial *equality*, not on any particular serial.
    fn fixture_serial(n: u8) -> CertSerial {
        CertSerial::from_bytes(vec![n])
    }

    /// Wrap a [`DateTime`] as a `UTCTime`-encoded `Time` for the
    /// x509-cert CRL encoder.
    fn as_utc(dt: DateTime) -> Time {
        Time::UtcTime(UtcTime::from_date_time(dt).expect("fixture date in the UTCTime window"))
    }

    /// A `UTCTime` at the given civil-time components.
    fn at(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Time {
        as_utc(DateTime::new(year, month, day, hour, minute, second).expect("valid fixture date"))
    }

    /// Build a CRL DER blob from typed fixtures via x509-cert's
    /// `CertificateList` encoder -- no hand-assembled ASN.1 bytes.
    fn build_crl(entries: &[RevokedFixture], with_next_update: bool) -> Vec<u8> {
        let sig_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: None,
        };
        let revoked: Vec<RevokedCert> = entries
            .iter()
            .map(|e| RevokedCert {
                serial_number: SerialNumber::new(e.serial.as_bytes())
                    .expect("fixture serial encodes"),
                revocation_date: as_utc(e.revoked_at),
                crl_entry_extensions: e.reason.map(|r| {
                    let enumerated = Any::new(Tag::Enumerated, vec![r.code()])
                        .expect("reason code fits an ENUMERATED");
                    vec![Extension {
                        extn_id: super::OID_CRL_REASONS,
                        critical: false,
                        extn_value: OctetString::new(
                            enumerated.to_der().expect("ENUMERATED encodes to DER"),
                        )
                        .expect("reason DER fits an OCTET STRING"),
                    }]
                }),
            })
            .collect();
        let tbs = TbsCertList {
            version: Version::V2,
            signature: sig_alg.clone(),
            issuer: Name::from_str("CN=Issuer").expect("issuer name parses"),
            this_update: at(2026, 5, 20, 12, 0, 0),
            next_update: with_next_update.then(|| at(2026, 6, 20, 12, 0, 0)),
            revoked_certificates: (!revoked.is_empty()).then_some(revoked),
            crl_extensions: None,
        };
        CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::new(0, b"sig").expect("signature bits encode"),
        }
        .to_der()
        .expect("fixture CRL encodes to DER")
    }

    #[test]
    fn parses_crl_with_next_update_and_revoked_list() {
        let serial_a = fixture_serial(1);
        let serial_b = fixture_serial(2);
        let der = build_crl(
            &[
                RevokedFixture {
                    serial: serial_a.clone(),
                    revoked_at: DateTime::new(2026, 1, 1, 0, 0, 0).expect("valid"),
                    reason: None,
                },
                RevokedFixture {
                    serial: serial_b.clone(),
                    revoked_at: DateTime::new(2026, 3, 15, 10, 30, 0).expect("valid"),
                    reason: None,
                },
            ],
            true,
        );
        let crl = Crl::parse(&der).expect("parses");
        assert_eq!(
            crl.this_update,
            DateTime::new(2026, 5, 20, 12, 0, 0).expect("valid")
        );
        assert_eq!(
            crl.next_update,
            Some(DateTime::new(2026, 6, 20, 12, 0, 0).expect("valid"))
        );
        let entries: Vec<RevokedEntry> = crl.entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].serial, serial_a);
        assert_eq!(entries[1].serial, serial_b);
        assert_eq!(entries[1].revocation_date.month(), 3);
    }

    #[test]
    fn find_serial_returns_entry_when_present() {
        let serial = fixture_serial(3);
        let der = build_crl(
            &[RevokedFixture {
                serial: serial.clone(),
                revoked_at: DateTime::new(2026, 2, 1, 8, 0, 0).expect("valid"),
                reason: None,
            }],
            true,
        );
        let crl = Crl::parse(&der).expect("parses");
        let entry = crl.find_serial(&serial).expect("found");
        assert_eq!(entry.revocation_date.year(), 2026);
        assert_eq!(entry.revocation_date.month(), 2);
        assert_eq!(entry.revocation_date.day(), 1);
        assert!(entry.reason.is_none());
        let absent = fixture_serial(9);
        assert!(crl.find_serial(&absent).is_none());
    }

    #[test]
    fn handles_crl_without_next_update() {
        let serial = fixture_serial(4);
        let der = build_crl(
            &[RevokedFixture {
                serial: serial.clone(),
                revoked_at: DateTime::new(2026, 1, 1, 0, 0, 0).expect("valid"),
                reason: None,
            }],
            false,
        );
        let crl = Crl::parse(&der).expect("parses");
        assert!(crl.next_update.is_none());
        assert!(crl.find_serial(&serial).is_some());
    }

    #[test]
    fn handles_empty_revocation_list() {
        let der = build_crl(&[], true);
        let crl = Crl::parse(&der).expect("parses");
        assert_eq!(crl.entries().count(), 0);
        // The list is empty, so a lookup for any serial must miss.
        let any_serial = fixture_serial(9);
        assert!(crl.find_serial(&any_serial).is_none());
    }

    #[test]
    fn rejects_non_sequence_outer() {
        // A bare INTEGER TLV: a valid DER element that is not the
        // CertificateList SEQUENCE the parser requires.
        let bad = Any::new(Tag::Integer, vec![5])
            .expect("INTEGER fixture builds")
            .to_der()
            .expect("INTEGER fixture encodes to DER");
        let err = Crl::parse(&bad).expect_err("non-SEQUENCE outer is rejected");
        assert!(matches!(err, X509Error::UnexpectedStructure(_)));
    }

    /// reasonCode = superseded (RFC 5280 sec.5.3.1) -- DVV uses this
    /// on FINEID card swaps.
    #[test]
    fn find_serial_surfaces_superseded_reason() {
        let serial = fixture_serial(5);
        let der = build_crl(
            &[RevokedFixture {
                serial: serial.clone(),
                revoked_at: DateTime::new(2026, 5, 21, 5, 42, 53).expect("valid"),
                reason: Some(CrlReason::Superseded),
            }],
            true,
        );
        let crl = Crl::parse(&der).expect("parses");
        let entry = crl.find_serial(&serial).expect("found");
        assert_eq!(entry.reason, Some(CrlReason::Superseded));
    }

    #[test]
    fn crl_reason_renders_name_and_code() {
        assert_eq!(CrlReason::Superseded.to_string(), "superseded (0x04)");
        assert_eq!(CrlReason::from_code(7), None);
    }
}
