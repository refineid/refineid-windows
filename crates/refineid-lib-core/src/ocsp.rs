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

//! OCSP request/response codec for revocation checking (RFC 6960).
//!
//! This module owns ASN.1-level codec only:
//!
//! - [`build_request`] produces the DER bytes of an `OCSPRequest`
//!   ready to POST to the responder URL (`Content-Type:
//!   application/ocsp-request`). Needs the issuer's SHA-1 `Name`
//!   hash and `SPKI` hash and the cert's serial -- the hashes are
//!   the caller's responsibility (they live one layer up where
//!   `sha1` is wired in) so this module stays additive-dep-free.
//! - `parse_response` decodes an `OCSPResponse` body into a
//!   structured [`OcspResponse`] with the produced-at timestamp,
//!   producing responder ID hint, and the list of per-cert
//!   statuses.
//!
//! The request side also owns the nonce: [`OcspNonce`] draws the
//! RFC 8954 randomness and [`build_request_with_nonce`] encodes the
//! extension. Out of scope: responder signature verification (trust
//! lives a layer up) and the HTTP transport (lib-core stays HTTP-free
//! per the crate's charter).

use crate::ber::tlv;
use crate::identity::CertSerial;
use crate::oid::known;
use crate::x509::{DateTime, X509Error};
use spki::der::asn1::{AnyRef, ObjectIdentifier};
use spki::der::{Decode as _, Reader as _, SliceReader, Tag, Tagged as _};

/// `id-sha1` OID (`1.3.14.3.2.26`), the default and
/// MUST-support `CertID.hashAlgorithm` per RFC 6960 §4.3.
/// SHA-1 here is a binding identifier over the issuer Name and
/// key, not a security primitive -- a collision would not let
/// an attacker forge responses (the responder also signs over
/// `tbsResponseData`).
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

/// What [`OcspHelpers::parse_response_data`] takes out of a
/// `ResponseData`: when the responder spoke, what it said about each
/// certificate, and the nonce it echoed back if it echoed one.
type ResponseDataParts = (DateTime, Vec<SingleResponse>, Option<Vec<u8>>);

/// `id-pkix-ocsp-nonce` (RFC 8954 sec.2.1).
const OID_OCSP_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");

/// DER tags this module writes, and dispatches on when reading.
/// Reading a tag is a byte comparison rather than a `der::Tag`
/// match: the byte is what is on the wire, and it does not move when
/// the `der` crate reorganises its tag types.
const TAG_INTEGER: u8 = 0x02;
/// `OCTET STRING`.
const TAG_OCTET_STRING: u8 = 0x04;
/// `NULL`, always zero-length.
const TAG_NULL: u8 = 0x05;
/// `OBJECT IDENTIFIER`.
const TAG_OID: u8 = 0x06;
/// `GeneralizedTime`.
const TAG_GENERALIZED_TIME: u8 = 0x18;
/// `SEQUENCE`, constructed.
const TAG_SEQUENCE: u8 = 0x30;
/// `[0]` primitive -- `certStatus` `good`, an IMPLICIT NULL.
const TAG_CONTEXT_0_PRIMITIVE: u8 = 0x80;
/// `[0]` constructed -- `responseBytes`, `nextUpdate`, and
/// `revocationReason` inside `RevokedInfo`.
const TAG_CONTEXT_0: u8 = 0xA0;
/// `[1]` constructed -- `certStatus` `revoked`, `responderID` byName,
/// and `responseExtensions`. Which one is meant is decided by where
/// it appears, not by the tag.
const TAG_CONTEXT_1: u8 = 0xA1;
/// `[2]` constructed -- `requestExtensions`, EXPLICIT so the inner
/// `Extensions` SEQUENCE is written whole inside it.
const TAG_CONTEXT_2: u8 = 0xA2;

// The `BasicOCSPResponse` `responseType` (`id-pkix-ocsp-basic`,
// RFC 6960 §4.2.1) is `known::BASIC_OCSP_RESPONSE`; the parser asserts
// it inside the outer `ResponseBytes` wrapper.

// ----- Request side -----

/// The `CertID.issuerNameHash` (RFC 6960 sec.4.1.1).
///
/// SHA-1 of the issuer's DER-encoded `Name`. A distinct type from
/// [`IssuerKeyHash`] so the two same-shaped digests cannot be transposed in
/// a [`build_request`] call: swapping them yields a valid-looking request
/// that silently mis-identifies the cert, and the type makes that a compile
/// error instead.
#[derive(Clone, Copy, Debug)]
pub struct IssuerNameHash([u8; 20]);

/// The `CertID.issuerKeyHash` (RFC 6960 sec.4.1.1).
///
/// SHA-1 of the issuer's `subjectPublicKey` BIT STRING value. The
/// role-distinct sibling of [`IssuerNameHash`]; see that type for why they
/// are not interchangeable.
#[derive(Clone, Copy, Debug)]
pub struct IssuerKeyHash([u8; 20]);

impl IssuerNameHash {
    /// Tag an already-computed SHA-1 digest as the issuer-name hash.
    #[must_use]
    pub const fn new(digest: [u8; 20]) -> Self {
        Self(digest)
    }

    /// The raw SHA-1 digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 20] {
        self.0
    }
}

impl IssuerKeyHash {
    /// Tag an already-computed SHA-1 digest as the issuer-key hash.
    #[must_use]
    pub const fn new(digest: [u8; 20]) -> Self {
        Self(digest)
    }

    /// The raw SHA-1 digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 20] {
        self.0
    }

    /// Compute the issuer-key hash from a typed
    /// [`SubjectPublicKeyInfo`](crate::x509::SpkiDer): SHA-1 over the
    /// `subjectPublicKey` BIT STRING value (RFC 6960 sec.4.1.1). The
    /// raw key material is reached only here and never escapes as a
    /// bare `&[u8]`. Total -- a constructed `SpkiDer` already
    /// validated its envelope, so there is no failure mode.
    #[must_use]
    pub fn from_subject_public_key(spki: &crate::x509::SpkiDer<'_>) -> Self {
        use sha1::Digest as _;
        let mut digest = [0_u8; 20];
        digest.copy_from_slice(&sha1::Sha1::digest(spki.subject_public_key_bits()));
        Self::new(digest)
    }
}

/// A 128-bit OCSP request nonce (RFC 8954).
///
/// Fresh randomness the responder echoes back, so an old signed response
/// can't be replayed. Constructible only from a successful RNG draw via
/// [`OcspNonce::random`], so an all-zero or otherwise unfilled buffer can
/// never reach [`build_request_with_nonce`].
#[derive(Clone, Copy, Debug)]
pub struct OcspNonce([u8; 16]);

impl OcspNonce {
    /// Draw 16 bytes (128 bits -- RFC 8954's minimum) of OS randomness.
    ///
    /// A failed OS RNG means no cryptographic operation on this host can be
    /// trusted, so the caller must propagate the error and abort -- never
    /// drop the nonce and send a replayable request.
    ///
    /// # Errors
    /// Returns [`crate::rng::Failure`] if the OS RNG is unavailable, exactly
    /// like the other RNG draws in this crate ([`crate::aa`],
    /// [`crate::pace`], [`crate::ca`]).
    pub fn random() -> Result<Self, crate::rng::Failure> {
        Ok(Self(crate::rng::array::<16>()?))
    }

    /// The 16 nonce bytes, for matching against the responder's echoed
    /// value (RFC 8954 sec.2.1).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The DER bytes of an `OCSPRequest`, ready to POST.
///
/// A domain wrapper over the serialized request (`Content-Type:
/// application/ocsp-request`) so [`build_request`] returns "an OCSP
/// request", not an anonymous `Vec<u8>` a caller could pass anywhere.
#[derive(Clone, Debug)]
pub struct OcspRequest(Vec<u8>);

impl OcspRequest {
    /// The request's DER bytes, for the HTTP POST body.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}

/// Build the DER bytes of an `OCSPRequest` for one cert lookup,
/// using SHA-1 as the `CertID.hashAlgorithm`.
///
/// `issuer_name_sha1` is the SHA-1 hash of the **issuer's
/// DER-encoded `Name`** (the value bytes that an X.509 Name
/// SEQUENCE wraps -- equivalent to OpenSSL
/// `X509_NAME_hash_old`). `issuer_key_sha1` is the SHA-1 hash
/// of the issuer's **`subjectPublicKeyInfo.subjectPublicKey`
/// BIT STRING value** (the key bits with the leading "unused
/// bits" byte stripped, per RFC 6960 sec.4.1.1). `serial` is
/// the target cert's serial INTEGER value bytes.
///
/// Layered above this module: a thin helper that takes a
/// parsed issuer [`crate::x509::Certificate`] and a target
/// [`crate::x509::Certificate`], computes both SHA-1 hashes,
/// and calls in here. That helper lives outside lib-core to
/// keep this crate dep-light.
///
/// Infallible: the body is a fixed nesting of SEQUENCEs over a
/// fixed-size hash and a serial the parser already validated, and
/// the writer imposes no length ceiling. It returned a `Result`
/// while a typed encoder was doing the work, and the error was
/// unreachable then too.
#[inline]
#[must_use]
pub fn build_request(
    issuer_name_sha1: IssuerNameHash,
    issuer_key_sha1: IssuerKeyHash,
    serial: &CertSerial,
) -> OcspRequest {
    OcspRequest(OcspHelpers::encode_request(
        &issuer_name_sha1,
        &issuer_key_sha1,
        serial,
        None,
    ))
}

/// `build_request` plus an OCSP nonce extension (RFC 8954).
///
/// The nonce should be 16-32 bytes of fresh randomness drawn via
/// [`OcspNonce::random`] (the `crate::rng` fail-closed seam); the
/// responder echoes it back, defeating replay of an old signed
/// response.
///
/// Infallible, as [`build_request`].
#[inline]
#[must_use]
pub fn build_request_with_nonce(
    issuer_name_sha1: IssuerNameHash,
    issuer_key_sha1: IssuerKeyHash,
    serial: &CertSerial,
    nonce: &OcspNonce,
) -> OcspRequest {
    OcspRequest(OcspHelpers::encode_request(
        &issuer_name_sha1,
        &issuer_key_sha1,
        serial,
        Some(nonce),
    ))
}

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct OcspHelpers;

impl OcspHelpers {
    /// Encode an `OCSPRequest` for one cert lookup: SHA-1 as the
    /// `CertID.hashAlgorithm`, the optional signature omitted (RFC
    /// 6960 sec.4.1.1 -- responders accept unsigned requests).
    ///
    /// Written out rather than delegated to a typed encoder. The
    /// structure is four nested SEQUENCEs and one extension, and the
    /// serial goes out as the exact INTEGER body the certificate
    /// carried: an encoder that renormalised it would build a
    /// `CertID` the responder answers `unknown` to, which is a hard
    /// failure to diagnose from the far end.
    fn encode_request(
        issuer_name_sha1: &IssuerNameHash,
        issuer_key_sha1: &IssuerKeyHash,
        serial: &CertSerial,
        nonce: Option<&OcspNonce>,
    ) -> Vec<u8> {
        // CertID ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
        //   issuerNameHash OCTET STRING, issuerKeyHash OCTET STRING,
        //   serialNumber CertificateSerialNumber }
        let mut algorithm = tlv(TAG_OID, OID_SHA1.as_bytes());
        // Explicit NULL parameters: a responder in the field is
        // likelier to match a CertID carrying them than one that
        // leaves the field absent.
        algorithm.extend_from_slice(&tlv(TAG_NULL, []));
        let mut cert_id = tlv(TAG_SEQUENCE, algorithm);
        cert_id.extend_from_slice(&tlv(TAG_OCTET_STRING, issuer_name_sha1.as_bytes()));
        cert_id.extend_from_slice(&tlv(TAG_OCTET_STRING, issuer_key_sha1.as_bytes()));
        cert_id.extend_from_slice(&tlv(TAG_INTEGER, serial.as_bytes()));

        // Request ::= SEQUENCE { reqCert CertID, ... } and
        // requestList ::= SEQUENCE OF Request -- one of each here.
        let request = tlv(TAG_SEQUENCE, tlv(TAG_SEQUENCE, cert_id));
        let mut tbs_request = tlv(TAG_SEQUENCE, request);

        if let Some(nonce) = nonce {
            // RFC 8954: extnValue is an OCTET STRING whose content is
            // itself the DER OCTET STRING holding the nonce.
            let mut extension = tlv(TAG_OID, OID_OCSP_NONCE.as_bytes());
            extension.extend_from_slice(&tlv(
                TAG_OCTET_STRING,
                tlv(TAG_OCTET_STRING, nonce.as_bytes()),
            ));
            let extensions = tlv(TAG_SEQUENCE, tlv(TAG_SEQUENCE, extension));
            // requestExtensions [2] EXPLICIT.
            tbs_request.extend_from_slice(&tlv(TAG_CONTEXT_2, extensions));
        }

        // OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest, ... }
        tlv(TAG_SEQUENCE, tlv(TAG_SEQUENCE, tbs_request))
    }

    /// Decode `ResponseData` (RFC 6960 sec.4.2.1) into the three
    /// things this crate takes from it.
    ///
    /// ```text
    /// ResponseData ::= SEQUENCE {
    ///   version [0] EXPLICIT Version DEFAULT v1,
    ///   responderID ResponderID,
    ///   producedAt GeneralizedTime,
    ///   responses SEQUENCE OF SingleResponse,
    ///   responseExtensions [1] EXPLICIT Extensions OPTIONAL }
    /// ```
    ///
    /// `[1]` cannot be read from the tag alone -- `responderID`
    /// byName is `[1]` too -- so the two are told apart by position,
    /// which is exactly what the ordering of a SEQUENCE guarantees: a
    /// `[1]` before `producedAt` is the responder's name, one after
    /// the responses is the extensions. Fields this crate does not
    /// read are skipped rather than refused, so a responder adding
    /// one it is entitled to add does not make its answer unreadable.
    fn parse_response_data(der: &[u8]) -> Result<ResponseDataParts, X509Error> {
        let mut reader = Self::sequence_reader(der, "OCSP tbsResponseData")?;
        let mut produced_at: Option<DateTime> = None;
        let mut responses: Vec<SingleResponse> = Vec::new();
        let mut nonce: Option<Vec<u8>> = None;

        while !reader.is_finished() {
            let field = reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP ResponseData field"))?;
            match field.first() {
                Some(&TAG_GENERALIZED_TIME) => produced_at = Some(Self::generalized_time(field)?),
                Some(&TAG_SEQUENCE) => {
                    let mut list = Self::sequence_reader(field, "OCSP responses")?;
                    while !list.is_finished() {
                        let entry = list.tlv_bytes().map_err(|_ignored| {
                            X509Error::UnexpectedStructure("OCSP SingleResponse")
                        })?;
                        responses.push(Self::parse_single_response(entry)?);
                    }
                }
                // responseExtensions, but only once producedAt has
                // been seen; before that, a [1] is the responder name.
                Some(&TAG_CONTEXT_1) if produced_at.is_some() => {
                    nonce = Self::nonce_from_extensions(Self::value_of(field, "OCSP extensions")?)?;
                }
                _ => {}
            }
        }

        Ok((
            produced_at.ok_or(X509Error::UnexpectedStructure("OCSP producedAt missing"))?,
            responses,
            nonce,
        ))
    }

    /// Decode one `SingleResponse` (RFC 6960 sec.4.2.1).
    fn parse_single_response(der: &[u8]) -> Result<SingleResponse, X509Error> {
        let mut reader = Self::sequence_reader(der, "OCSP SingleResponse")?;
        let cert_id = Self::parse_cert_id(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP certID"))?,
        )?;
        let status = Self::parse_cert_status(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP certStatus"))?,
        )?;
        let this_update = Self::generalized_time(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP thisUpdate"))?,
        )?;

        // nextUpdate [0] EXPLICIT, then singleExtensions [1] EXPLICIT.
        let mut next_update = None;
        while !reader.is_finished() {
            let field = reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP SingleResponse tail"))?;
            if field.first() == Some(&TAG_CONTEXT_0) {
                next_update = Some(Self::generalized_time(Self::value_of(
                    field,
                    "OCSP nextUpdate",
                )?)?);
            }
        }

        Ok(SingleResponse {
            cert_id,
            status,
            this_update,
            next_update,
        })
    }

    /// Decode a `CertID` (RFC 6960 sec.4.1.1).
    fn parse_cert_id(der: &[u8]) -> Result<CertId, X509Error> {
        let mut reader = Self::sequence_reader(der, "OCSP CertID")?;
        // hashAlgorithm AlgorithmIdentifier -- the OID only; the
        // parameters are not consulted.
        let algorithm = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("CertID hashAlgorithm"))?;
        let mut algorithm_reader = Self::sequence_reader(algorithm, "CertID hashAlgorithm")?;
        let oid_tlv = algorithm_reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("CertID hashAlgorithm OID"))?;
        if oid_tlv.first() != Some(&TAG_OID) {
            return Err(X509Error::UnexpectedStructure("CertID hashAlgorithm OID"));
        }
        let hash_algorithm_oid = Self::value_of(oid_tlv, "CertID hashAlgorithm OID")?.to_vec();
        let issuer_name_hash = Self::octet_string(&mut reader, "CertID issuerNameHash")?;
        let issuer_key_hash = Self::octet_string(&mut reader, "CertID issuerKeyHash")?;
        let serial_tlv = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("CertID serialNumber"))?;
        if serial_tlv.first() != Some(&TAG_INTEGER) {
            return Err(X509Error::UnexpectedStructure("CertID serialNumber"));
        }
        let serial =
            CertSerial::from_bytes(Self::value_of(serial_tlv, "CertID serialNumber")?.to_vec());

        Ok(CertId {
            hash_algorithm_oid,
            issuer_name_hash,
            issuer_key_hash,
            serial,
        })
    }

    /// Decode the `certStatus` CHOICE (RFC 6960 sec.4.2.1).
    ///
    /// ```text
    /// CertStatus ::= CHOICE {
    ///   good    [0] IMPLICIT NULL,
    ///   revoked [1] IMPLICIT RevokedInfo,
    ///   unknown [2] IMPLICIT UnknownInfo }
    /// RevokedInfo ::= SEQUENCE {
    ///   revocationTime GeneralizedTime,
    ///   revocationReason [0] EXPLICIT CRLReason OPTIONAL }
    /// ```
    ///
    /// An alternative this crate does not know reads as `Unknown`
    /// rather than as an error, which is the safe direction: the
    /// reading of a status nobody here understands is that the
    /// responder vouched for nothing.
    fn parse_cert_status(der: &[u8]) -> Result<CertStatus, X509Error> {
        match der.first() {
            Some(&TAG_CONTEXT_0_PRIMITIVE) => Ok(CertStatus::Good),
            Some(&TAG_CONTEXT_1) => {
                let mut reader = SliceReader::new(Self::value_of(der, "OCSP RevokedInfo")?)
                    .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP RevokedInfo body"))?;
                let revoked_at = Self::generalized_time(
                    reader
                        .tlv_bytes()
                        .map_err(|_ignored| X509Error::UnexpectedStructure("revocationTime"))?,
                )?;
                let mut reason = None;
                while !reader.is_finished() {
                    let field = reader.tlv_bytes().map_err(|_ignored| {
                        X509Error::UnexpectedStructure("OCSP RevokedInfo tail")
                    })?;
                    if field.first() == Some(&TAG_CONTEXT_0) {
                        let enumerated = Self::value_of(field, "revocationReason")?;
                        reason = Self::value_of(enumerated, "CRLReason")?
                            .first()
                            .and_then(|code| crate::crl::CrlReason::from_code(*code));
                    }
                }
                Ok(CertStatus::Revoked { revoked_at, reason })
            }
            _ => Ok(CertStatus::Unknown),
        }
    }

    /// The nonce out of an `Extensions` SEQUENCE, if it carries one.
    ///
    /// RFC 8954: `extnValue` is an OCTET STRING whose content is
    /// itself the DER OCTET STRING holding the nonce, so the value
    /// sits two layers in.
    fn nonce_from_extensions(extensions: &[u8]) -> Result<Option<Vec<u8>>, X509Error> {
        let mut reader = Self::sequence_reader(extensions, "OCSP Extensions")?;
        while !reader.is_finished() {
            let extension = reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP Extension"))?;
            let mut fields = Self::sequence_reader(extension, "OCSP Extension body")?;
            let oid_tlv = fields
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP Extension OID"))?;
            if Self::value_of(oid_tlv, "OCSP Extension OID")? != OID_OCSP_NONCE.as_bytes() {
                continue;
            }
            // Step past the optional critical BOOLEAN to extnValue.
            while !fields.is_finished() {
                let field = fields
                    .tlv_bytes()
                    .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP extnValue"))?;
                if field.first() == Some(&TAG_OCTET_STRING) {
                    let inner = Self::value_of(field, "OCSP extnValue")?;
                    // A responder that omits RFC 8954's inner wrapper
                    // is read as having sent the bytes bare, rather
                    // than as having sent nothing.
                    return Ok(Some(if inner.first() == Some(&TAG_OCTET_STRING) {
                        Self::value_of(inner, "OCSP nonce")?.to_vec()
                    } else {
                        inner.to_vec()
                    }));
                }
            }
        }
        Ok(None)
    }

    /// A reader over the body of a TLV that must be a SEQUENCE.
    fn sequence_reader<'d>(
        der: &'d [u8],
        what: &'static str,
    ) -> Result<SliceReader<'d>, X509Error> {
        if der.first() != Some(&TAG_SEQUENCE) {
            return Err(X509Error::UnexpectedStructure(what));
        }
        SliceReader::new(Self::value_of(der, what)?)
            .map_err(|_ignored| X509Error::UnexpectedStructure(what))
    }

    /// The value bytes of one TLV.
    fn value_of<'d>(der: &'d [u8], what: &'static str) -> Result<&'d [u8], X509Error> {
        Ok(AnyRef::from_der(der)
            .map_err(|_ignored| X509Error::UnexpectedStructure(what))?
            .value())
    }

    /// The next TLV, which must be an OCTET STRING, as its contents.
    fn octet_string(
        reader: &mut SliceReader<'_>,
        what: &'static str,
    ) -> Result<Vec<u8>, X509Error> {
        let tlv_bytes = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure(what))?;
        if tlv_bytes.first() != Some(&TAG_OCTET_STRING) {
            return Err(X509Error::UnexpectedStructure(what));
        }
        Ok(Self::value_of(tlv_bytes, what)?.to_vec())
    }

    /// A `GeneralizedTime` TLV as a [`DateTime`].
    fn generalized_time(der: &[u8]) -> Result<DateTime, X509Error> {
        Ok(spki::der::asn1::GeneralizedTime::from_der(der)
            .map_err(|_ignored| X509Error::InvalidTime)?
            .to_date_time())
    }
}

// ----- Response side -----

/// Top-level `OCSPResponseStatus` (RFC 6960 sec.4.2.1).
///
/// The ENUMERATED values 0..6 are defined; 4 is reserved.
/// Anything else surfaces as [`OcspResponseStatus::Other`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspResponseStatus {
    /// Wire value 0: response generation succeeded (the only
    /// status that carries a `BasicOcspResponse` payload).
    Successful,
    /// Wire value 1: request couldn't be parsed.
    MalformedRequest,
    /// Wire value 2: internal responder error.
    InternalError,
    /// Wire value 3: try again later.
    TryLater,
    /// Wire value 5: request must be signed.
    SigRequired,
    /// Wire value 6: request unauthorized.
    Unauthorized,
    /// Any other ENUMERATED byte the responder returned (4 is
    /// reserved per RFC 6960; unknown values too). Tier 0 `u8`
    /// -- the spec ENUMERATED is open to extension.
    Other(u8),
}

impl OcspResponseStatus {
    /// Decode the raw ENUMERATED byte into the typed enum.
    /// Trust boundary for the OCSP `responseStatus` field.
    #[inline]
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Successful,
            1 => Self::MalformedRequest,
            2 => Self::InternalError,
            3 => Self::TryLater,
            5 => Self::SigRequired,
            6 => Self::Unauthorized,
            other => Self::Other(other),
        }
    }
}

/// Parsed `OCSPResponse`.
///
/// The optional `basic` field carries the [`BasicOcspResponse`]
/// when `responseStatus = successful` and the embedded
/// `responseBytes` use `id-pkix-ocsp-basic` (the only response
/// type RFC 6960 defines).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct OcspResponse<'a> {
    /// Top-level `responseStatus` decoded from the ENUMERATED.
    pub status: OcspResponseStatus,
    /// Embedded `BasicOcspResponse` when `status == Successful`
    /// and the wrapped `responseBytes` use the
    /// `id-pkix-ocsp-basic` type; `None` otherwise.
    pub basic: Option<BasicOcspResponse<'a>>,
}

/// Parsed `BasicOCSPResponse.tbsResponseData` plus the outer
/// signature material.
#[non_exhaustive]
#[derive(Debug, Clone)]
#[expect(
    clippy::partial_pub_fields,
    reason = "the parsed-once typed values (produced_at, tbs_response_data_der, signature_alg_oid, ...) are intentionally pub for read; responses is intentionally private behind the single_responses() accessor so callers read the typed per-entry SingleResponse values, not the raw Vec."
)]
pub struct BasicOcspResponse<'a> {
    /// `producedAt` from `tbsResponseData` per RFC 6960 §4.2.1
    /// -- the time the responder signed this reply.
    pub produced_at: DateTime,
    /// The decoded `tbsResponseData.responses`. Read via
    /// [`BasicOcspResponse::single_responses`].
    responses: Vec<SingleResponse>,
    /// `tbsResponseData` bytes (tag+length+value) -- exactly the
    /// bytes covered by the response signature.
    pub tbs_response_data_der: &'a [u8],
    /// `signatureAlgorithm.algorithm` OID body (the value of the
    /// `06 LL` TLV).
    pub signature_alg_oid: &'a [u8],
    /// Outer `signature` BIT STRING value with the unused-bits
    /// leading byte stripped.
    pub signature_bits: &'a [u8],
    /// DER bytes of each optional cert in the `[0] EXPLICIT
    /// certs SEQUENCE OF Certificate` field. Empty when the
    /// responder didn't embed any chain certs (it expects the
    /// caller to know the responder by some out-of-band means).
    pub embedded_cert_ders: Vec<&'a [u8]>,
    /// The OCSP nonce (RFC 8954) echoed in `responseExtensions`,
    /// when present -- match it against the request nonce.
    pub nonce: Option<Vec<u8>>,
}

impl BasicOcspResponse<'_> {
    /// Verify the response signature against the issuer's SPKI.
    ///
    /// # Errors
    /// As for `x509::verify_tbs_signature`.
    #[inline]
    pub fn verify_signature<B: AsRef<[u8]>>(
        &self,
        signer_spki_der: B,
    ) -> Result<(), crate::x509::VerifyError> {
        let signer_spki_der = signer_spki_der.as_ref();
        crate::x509::verify_tbs_signature(crate::x509::TbsSignature {
            tbs_der: self.tbs_response_data_der,
            signature_alg_oid: self.signature_alg_oid,
            signature_bits: self.signature_bits,
            issuer_spki_der: signer_spki_der,
        })
    }

    /// The per-cert `SingleResponse` entries of `tbsResponseData`.
    #[inline]
    #[must_use]
    pub(crate) fn single_responses(&self) -> &[SingleResponse] {
        &self.responses
    }

    /// Test-only convenience: find the `SingleResponse` whose
    /// `CertID` matches `serial`. Production reads status only via
    /// [`VerifiedOcspResponse::single_responses`] (trust by
    /// construction), so this exists just to keep the parser KATs
    /// terse; `#[cfg(test)]`-gated to stay off the production
    /// surface.
    #[cfg(test)]
    #[inline]
    #[must_use]
    pub(crate) fn find_serial(&self, serial: &CertSerial) -> Option<&SingleResponse> {
        self.single_responses()
            .iter()
            .find(|r| &r.cert_id.serial == serial)
    }
}

/// A [`BasicOcspResponse`] whose responder signature has been
/// verified against a signer SPKI.
///
/// Trust by construction (see `doc/typing-discipline.md`): the only
/// production constructor is [`VerifiedOcspResponse::verify`], so
/// holding this type is proof the response signature checked against
/// a signer. Per-cert revocation status
/// ([`crate::revocation::check_against_ocsp_response`] via
/// `find_serial`) is reachable *only* through a
/// verified response -- you cannot read a status off an unverified
/// OCSP reply, by type.
#[derive(Debug, Clone)]
pub struct VerifiedOcspResponse<'a> {
    /// The verified inner response.
    basic: BasicOcspResponse<'a>,
}

impl<'a> VerifiedOcspResponse<'a> {
    /// Verify `basic`'s responder signature against `signer_spki`
    /// and, on success, wrap it as a [`VerifiedOcspResponse`]. The
    /// only production door to a verified response.
    ///
    /// # Errors
    /// [`crate::x509::VerifyError`] when the signature does not
    /// verify against `signer_spki`.
    #[inline]
    pub fn verify(
        basic: &BasicOcspResponse<'a>,
        signer_spki: &crate::x509::SpkiDer<'_>,
    ) -> Result<Self, crate::x509::VerifyError> {
        basic.verify_signature(signer_spki.as_der())?;
        Ok(Self {
            basic: basic.clone(),
        })
    }

    /// The per-cert `SingleResponse` entries of this *verified*
    /// response. Reachable only on a verified response, so any status
    /// read is proof of a checked signature.
    #[inline]
    #[must_use]
    pub fn single_responses(&self) -> &[SingleResponse] {
        self.basic.single_responses()
    }

    /// Test-only: wrap a basic response *without* verifying its
    /// signature, to exercise status-translation logic in isolation.
    /// `#[cfg(test)]`-gated, so the production "only door is
    /// `verify`" guarantee is unaffected.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn from_unverified_basic_for_test(basic: BasicOcspResponse<'a>) -> Self {
        Self { basic }
    }
}

/// One entry in a `BasicOCSPResponse.responses`.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SingleResponse {
    /// `CertID` identifying which certificate this entry is about.
    pub cert_id: CertId,
    /// `certStatus` CHOICE -- Good / Revoked{at, reason} /
    /// Unknown per RFC 6960 §4.2.1.
    pub status: CertStatus,
    /// `thisUpdate` -- timestamp at which the responder asserts
    /// this status was current.
    pub this_update: DateTime,
    /// `nextUpdate` when the responder commits to a refresh
    /// horizon; `None` for responders that don't.
    pub next_update: Option<DateTime>,
}

/// `CertID` -- which certificate a [`SingleResponse`] is about.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertId {
    /// `hashAlgorithm.algorithm` OID body.
    pub hash_algorithm_oid: Vec<u8>,
    /// `issuerNameHash`.
    pub issuer_name_hash: Vec<u8>,
    /// `issuerKeyHash`.
    pub issuer_key_hash: Vec<u8>,
    /// `serialNumber` of the certificate this entry is about.
    pub serial: CertSerial,
}

impl CertId {
    /// Whether this entry answers the exact request this module builds.
    #[must_use]
    pub fn matches_request(
        &self,
        issuer_name_hash: IssuerNameHash,
        issuer_key_hash: IssuerKeyHash,
        serial: &CertSerial,
    ) -> bool {
        self.hash_algorithm_oid == OID_SHA1.as_bytes()
            && self.issuer_name_hash == issuer_name_hash.as_bytes()
            && self.issuer_key_hash == issuer_key_hash.as_bytes()
            && &self.serial == serial
    }
}

/// `CertStatus` CHOICE.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    /// Cert is not revoked (`good` per RFC 6960 §4.2.1).
    Good,
    /// Cert is revoked; carries the revocation timestamp and
    /// optional reason code.
    Revoked {
        /// `revocationTime` per RFC 6960 §4.2.2.2.
        revoked_at: DateTime,
        /// `CRLReason` (RFC 5280 sec.5.3.1) when the responder
        /// includes it. `None` means no reason was supplied.
        reason: Option<crate::crl::CrlReason>,
    },
    /// Responder has no information about this cert (out of its
    /// authority, or unknown serial).
    Unknown,
}

/// Owning wrapper around a parsed OCSP response.
///
/// Same pattern as [`crate::x509::OwnedCert`] /
/// [`crate::crl::OwnedCrl`]: holds the OCSP response DER plus a
/// re-parseable view. Public entry point under typing-discipline
/// rule D; free `parse_response` is `pub(crate)` because it
/// returns a borrowed view tied to the input.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct OwnedOcspResponse {
    /// DER bytes of the outer `OCSPResponse` SEQUENCE (RFC 6960
    /// §4.2.1). Validated at construction via [`parse_response`];
    /// the [`Self::view`] re-parse cannot fail because the
    /// buffer is owned and immutable.
    der: Vec<u8>,
}

impl OwnedOcspResponse {
    /// Parse `der` as an OCSP response, allocating an owned copy
    /// so the wrapper is independent of the input borrow.
    ///
    /// # Errors
    /// [`X509Error`] from the OCSP parser.
    #[inline]
    pub fn from_der<B: AsRef<[u8]>>(der: B) -> Result<Self, X509Error> {
        let bytes = der.as_ref().to_vec();
        // Validate the DER at construction; the parsed view borrows
        // `bytes` and is dropped immediately. `drop()` makes the
        // discard explicit (the parsed value owns a `Vec` of
        // borrowed cert DER slices, so the `let _` shape elides a
        // destructor).
        drop(OcspResponse::parse(&bytes)?);
        Ok(Self { der: bytes })
    }

    /// Re-parse the owned DER and hand back the borrowed view.
    ///
    /// # Performance
    /// Parses the DER on **every call** (O(n) in the DER length). For
    /// repeated field access bind the view once (`let resp = owned.view();`)
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
    pub fn view(&self) -> OcspResponse<'_> {
        OcspResponse::parse(&self.der)
            .expect("OwnedOcspResponse: from_der validated DER at construction")
    }

    /// Raw DER bytes.
    #[inline]
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}

impl<'a> OcspResponse<'a> {
    /// Parse an `OCSPResponse` DER blob.
    ///
    /// # Errors
    /// Any der decode failure, or a top-level shape that doesn't match
    /// `OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED,
    /// responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }`.
    #[inline]
    pub(crate) fn parse(der: &'a [u8]) -> Result<Self, X509Error> {
        let outer = AnyRef::from_der(der)
            .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP not a TLV"))?;
        if outer.tag() != Tag::Sequence {
            return Err(X509Error::UnexpectedStructure("OCSP not SEQUENCE"));
        }
        let mut reader = SliceReader::new(outer.value())
            .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP body"))?;

        // responseStatus ENUMERATED.
        let status_any = AnyRef::from_der(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("missing responseStatus"))?,
        )
        .map_err(|_ignored| X509Error::UnexpectedStructure("missing responseStatus"))?;
        if status_any.tag() != Tag::Enumerated {
            return Err(X509Error::UnexpectedStructure("malformed responseStatus"));
        }
        let &[status_byte] = status_any.value() else {
            return Err(X509Error::UnexpectedStructure("malformed responseStatus"));
        };
        let status = OcspResponseStatus::from_byte(status_byte);

        // responseBytes [0] EXPLICIT { responseType OID, response OCTET STRING }.
        let mut basic: Option<BasicOcspResponse<'_>> = None;
        if status == OcspResponseStatus::Successful && !reader.is_finished() {
            let rb_explicit_der = reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP responseBytes"))?;
            let rb_explicit = AnyRef::from_der(rb_explicit_der)
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP responseBytes"))?;
            if rb_explicit_der.first() == Some(&TAG_CONTEXT_0) {
                let rb_seq = AnyRef::from_der(rb_explicit.value()).map_err(|_ignored| {
                    X509Error::UnexpectedStructure("OCSP responseBytes not SEQUENCE")
                })?;
                let mut rb_reader = SliceReader::new(rb_seq.value()).map_err(|_ignored| {
                    X509Error::UnexpectedStructure("OCSP responseBytes body")
                })?;
                let rtype =
                    AnyRef::from_der(rb_reader.tlv_bytes().map_err(|_ignored| {
                        X509Error::UnexpectedStructure("missing responseType")
                    })?)
                    .map_err(|_ignored| X509Error::UnexpectedStructure("missing responseType"))?;
                // RFC 6960 defines only the basic-OCSP response type; any
                // other leaves `basic = None` and the caller falls back on
                // the top-level status.
                if rtype.tag() == Tag::ObjectIdentifier
                    && rtype.value() == known::BASIC_OCSP_RESPONSE.as_bytes()
                {
                    let resp_octet =
                        AnyRef::from_der(rb_reader.tlv_bytes().map_err(|_ignored| {
                            X509Error::UnexpectedStructure("missing response octet")
                        })?)
                        .map_err(|_ignored| {
                            X509Error::UnexpectedStructure("missing response octet")
                        })?;
                    if resp_octet.tag() != Tag::OctetString {
                        return Err(X509Error::UnexpectedStructure(
                            "response field not OCTET STRING",
                        ));
                    }
                    basic = Some(BasicOcspResponse::parse(resp_octet.value())?);
                }
            }
        }

        Ok(OcspResponse { status, basic })
    }
}

impl<'a> BasicOcspResponse<'a> {
    /// Decode the `BasicOCSPResponse` SEQUENCE (RFC 6960 §4.2.1).
    ///
    /// The outer fields are walked with der's `SliceReader` so the
    /// signature-covered `tbsResponseData` (and the embedded cert
    /// DERs) stay byte-exact zero-copy views; the structured
    /// `tbsResponseData` contents are decoded with x509-ocsp's typed
    /// `ResponseData`.
    fn parse(der: &'a [u8]) -> Result<Self, X509Error> {
        // BasicOCSPResponse ::= SEQUENCE {
        //   tbsResponseData ResponseData, signatureAlgorithm,
        //   signature BIT STRING, certs [0] EXPLICIT ... OPTIONAL }
        let outer = AnyRef::from_der(der)
            .map_err(|_ignored| X509Error::UnexpectedStructure("BasicOCSPResponse not a TLV"))?;
        if outer.tag() != Tag::Sequence {
            return Err(X509Error::UnexpectedStructure(
                "BasicOCSPResponse not SEQUENCE",
            ));
        }
        let mut reader = SliceReader::new(outer.value())
            .map_err(|_ignored| X509Error::UnexpectedStructure("BasicOCSPResponse body"))?;

        // tbsResponseData -- exact bytes (the signature covers these).
        let tbs_response_data_der = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsResponseData"))?;

        // signatureAlgorithm AlgorithmIdentifier -- OID body.
        let sig_alg = AnyRef::from_der(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP signatureAlgorithm"))?,
        )
        .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP signatureAlgorithm"))?;
        let mut alg_reader = SliceReader::new(sig_alg.value())
            .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP signatureAlgorithm body"))?;
        let alg_oid =
            AnyRef::from_der(alg_reader.tlv_bytes().map_err(|_ignored| {
                X509Error::UnexpectedStructure("OCSP signatureAlgorithm OID")
            })?)
            .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP signatureAlgorithm OID"))?;
        if alg_oid.tag() != Tag::ObjectIdentifier {
            return Err(X509Error::UnexpectedStructure(
                "OCSP signatureAlgorithm OID",
            ));
        }
        let signature_alg_oid = alg_oid.value();

        // signature BIT STRING -- strip the leading unused-bits byte.
        let sig_bits = AnyRef::from_der(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP signature"))?,
        )
        .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP signature"))?;
        if sig_bits.tag() != Tag::BitString {
            return Err(X509Error::UnexpectedStructure(
                "OCSP signature not BIT STRING",
            ));
        }
        let signature_bits = sig_bits
            .value()
            .get(1..)
            .ok_or(X509Error::UnexpectedStructure(
                "OCSP signature BIT STRING empty",
            ))?;

        // Optional [0] EXPLICIT certs SEQUENCE OF Certificate.
        let mut embedded_cert_ders: Vec<&[u8]> = Vec::new();
        if !reader.is_finished() {
            let certs_explicit_der = reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP certs field"))?;
            let certs_explicit = AnyRef::from_der(certs_explicit_der)
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP certs field"))?;
            if certs_explicit_der.first() == Some(&TAG_CONTEXT_0) {
                let certs_seq = AnyRef::from_der(certs_explicit.value()).map_err(|_ignored| {
                    X509Error::UnexpectedStructure("OCSP certs not SEQUENCE")
                })?;
                let mut certs_reader = SliceReader::new(certs_seq.value())
                    .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP certs body"))?;
                while !certs_reader.is_finished() {
                    let cert_der = certs_reader
                        .tlv_bytes()
                        .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP embedded cert"))?;
                    embedded_cert_ders.push(cert_der);
                }
            }
        }

        let (produced_at, responses, nonce) =
            OcspHelpers::parse_response_data(tbs_response_data_der)?;

        Ok(BasicOcspResponse {
            produced_at,
            responses,
            tbs_response_data_der,
            signature_alg_oid,
            signature_bits,
            embedded_cert_ders,
            nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CertStatus, IssuerKeyHash, IssuerNameHash, OID_OCSP_NONCE, OID_SHA1, ObjectIdentifier,
        OcspHelpers, OcspNonce, OcspResponseStatus, TAG_CONTEXT_0, TAG_CONTEXT_0_PRIMITIVE,
        TAG_CONTEXT_1, TAG_CONTEXT_2, TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_NULL,
        TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, build_request, build_request_with_nonce,
    };

    /// `BIT STRING` -- only the fixtures write one.
    const TAG_BIT_STRING: u8 = 0x03;
    /// `ENUMERATED` -- `responseStatus` and `CRLReason`, likewise.
    const TAG_ENUMERATED: u8 = 0x0A;
    /// `[2]` primitive -- `certStatus` `unknown`. The parser reaches
    /// `Unknown` through its fallback arm rather than by naming this,
    /// so only a fixture writes it.
    const TAG_CONTEXT_2_PRIMITIVE: u8 = 0x82;
    use crate::ber::tlv;
    use crate::identity::CertSerial;
    use spki::der::{DateTime, Reader as _};

    /// Arbitrary distinct issuer hashes -- the values are irrelevant
    /// here; only name-vs-key distinctness matters.
    const FILL_NAME_HASH: [u8; 20] = [0xAA; 20];
    const FILL_KEY_HASH: [u8; 20] = [0xBB; 20];
    /// Serial the round-trip tests follow through the encoding.
    const ROUNDTRIP_SERIAL: [u8; 3] = [0x12, 0x34, 0x56];
    /// `id-pkix-ocsp-basic`, the only responseType this crate reads.
    const OID_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";

    /// A distinct cert serial for fixtures. The value is arbitrary
    /// -- only uniqueness matters; OCSP matching keys on serial
    /// equality.
    fn fixture_serial(n: u8) -> CertSerial {
        CertSerial::from_bytes(vec![n])
    }

    /// A `GeneralizedTime` TLV for a civil time, `YYYYMMDDHHMMSSZ`.
    fn gtime(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Vec<u8> {
        let text = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
        tlv(TAG_GENERALIZED_TIME, text.as_bytes())
    }

    /// A `CertID` about `serial`.
    fn cert_id_der(serial: &CertSerial) -> Vec<u8> {
        let mut algorithm = tlv(TAG_OID, OID_SHA1.as_bytes());
        algorithm.extend_from_slice(&tlv(TAG_NULL, []));
        let mut body = tlv(TAG_SEQUENCE, algorithm);
        body.extend_from_slice(&tlv(TAG_OCTET_STRING, FILL_NAME_HASH));
        body.extend_from_slice(&tlv(TAG_OCTET_STRING, FILL_KEY_HASH));
        body.extend_from_slice(&tlv(TAG_INTEGER, serial.as_bytes()));
        tlv(TAG_SEQUENCE, body)
    }

    /// One `SingleResponse`; `status` is the `certStatus` alternative.
    fn single_response_der(serial: &CertSerial, status: &[u8]) -> Vec<u8> {
        let mut body = cert_id_der(serial);
        body.extend_from_slice(status);
        body.extend_from_slice(&gtime(2026, 5, 20, 12, 0, 0));
        tlv(TAG_SEQUENCE, body)
    }

    /// A successful `OCSPResponse` around one `ResponseData` body.
    ///
    /// The signature is never checked here -- `parse` reads bytes and
    /// `verify` is a separate door -- so it is three filler octets.
    fn wrap_response(response_data: Vec<u8>) -> Vec<u8> {
        let mut basic = tlv(TAG_SEQUENCE, response_data);
        basic.extend_from_slice(&tlv(TAG_SEQUENCE, tlv(TAG_OID, OID_SHA1.as_bytes())));
        basic.extend_from_slice(&tlv(TAG_BIT_STRING, [0x00, b's', b'i', b'g']));
        let basic = tlv(TAG_SEQUENCE, basic);

        let mut response_bytes = tlv(TAG_OID, ObjectIdentifier::new_unwrap(OID_BASIC).as_bytes());
        response_bytes.extend_from_slice(&tlv(TAG_OCTET_STRING, basic));
        let mut outer = tlv(TAG_ENUMERATED, [0x00]);
        outer.extend_from_slice(&tlv(TAG_CONTEXT_0, tlv(TAG_SEQUENCE, response_bytes)));
        tlv(TAG_SEQUENCE, outer)
    }

    /// `ResponseData` carrying `singles`, plus optional extensions.
    fn response_data(singles: &[u8], extensions: Option<Vec<u8>>) -> Vec<u8> {
        // responderID byName [1], empty Name -- never read.
        let mut body = tlv(TAG_CONTEXT_1, tlv(TAG_SEQUENCE, []));
        body.extend_from_slice(&gtime(2026, 5, 20, 12, 0, 0));
        body.extend_from_slice(&tlv(TAG_SEQUENCE, singles));
        if let Some(extensions) = extensions {
            body.extend_from_slice(&tlv(TAG_CONTEXT_1, extensions));
        }
        body
    }

    /// A successful response carrying exactly one `SingleResponse`,
    /// built by hand so the parser is checked against an encoder that
    /// is not the one under test.
    fn build_response(single: &[u8]) -> Vec<u8> {
        wrap_response(response_data(single, None))
    }

    /// A bare `OCSPResponse` SEQUENCE { responseStatus }.
    fn status_only_response(status_byte: u8) -> Vec<u8> {
        tlv(TAG_SEQUENCE, tlv(TAG_ENUMERATED, [status_byte]))
    }

    /// The `CertID` bytes out of a built request.
    ///
    /// `OCSPRequest > tbsRequest > requestList > Request > CertID`,
    /// every layer a SEQUENCE taking the first element.
    fn cert_id_of(request_der: &[u8]) -> Vec<u8> {
        let mut current = request_der.to_vec();
        for _ in 0_u8..4 {
            let mut reader =
                OcspHelpers::sequence_reader(&current, "test").expect("each layer is a SEQUENCE");
            current = reader.tlv_bytes().expect("a first element").to_vec();
        }
        current
    }

    #[test]
    fn a_built_request_parses_back_to_what_went_in() {
        // Deconstruct what the encoder constructed. The two are
        // separate code, so their agreement is evidence about both.
        let serial = CertSerial::from_bytes(ROUNDTRIP_SERIAL.to_vec());
        let request = build_request(
            IssuerNameHash::new(FILL_NAME_HASH),
            IssuerKeyHash::new(FILL_KEY_HASH),
            &serial,
        );
        let parsed = OcspHelpers::parse_cert_id(&cert_id_of(request.as_der()))
            .expect("the encoder's CertID parses");
        assert_eq!(parsed.hash_algorithm_oid, OID_SHA1.as_bytes());
        assert_eq!(parsed.issuer_name_hash, FILL_NAME_HASH);
        assert_eq!(parsed.issuer_key_hash, FILL_KEY_HASH);
        assert_eq!(parsed.serial.as_bytes(), ROUNDTRIP_SERIAL);
    }

    #[test]
    fn a_parsed_cert_id_re_encodes_to_the_same_bytes() {
        // ...and reconstruct it. Byte equality after the round trip
        // catches what field-by-field equality cannot: a field read
        // into the right place from the wrong offset.
        let serial = CertSerial::from_bytes(ROUNDTRIP_SERIAL.to_vec());
        let original = cert_id_der(&serial);
        let parsed = OcspHelpers::parse_cert_id(&original).expect("parses");
        let mut algorithm = tlv(TAG_OID, &parsed.hash_algorithm_oid);
        algorithm.extend_from_slice(&tlv(TAG_NULL, []));
        let mut body = tlv(TAG_SEQUENCE, algorithm);
        body.extend_from_slice(&tlv(TAG_OCTET_STRING, &parsed.issuer_name_hash));
        body.extend_from_slice(&tlv(TAG_OCTET_STRING, &parsed.issuer_key_hash));
        body.extend_from_slice(&tlv(TAG_INTEGER, parsed.serial.as_bytes()));
        assert_eq!(
            tlv(TAG_SEQUENCE, body),
            original,
            "CertID did not survive a decode-then-encode round trip"
        );
    }

    #[test]
    fn a_requested_nonce_comes_back_out_of_the_request() {
        let nonce = OcspNonce::random().expect("the test host has randomness");
        let request = build_request_with_nonce(
            IssuerNameHash::new(FILL_NAME_HASH),
            IssuerKeyHash::new(FILL_KEY_HASH),
            &CertSerial::from_bytes(ROUNDTRIP_SERIAL.to_vec()),
            &nonce,
        );
        let mut outer = OcspHelpers::sequence_reader(request.as_der(), "OCSPRequest")
            .expect("OCSPRequest is a SEQUENCE");
        let tbs = outer.tlv_bytes().expect("tbsRequest");
        let mut fields =
            OcspHelpers::sequence_reader(tbs, "tbsRequest").expect("tbsRequest is a SEQUENCE");
        let mut found = None;
        while !fields.is_finished() {
            let field = fields.tlv_bytes().expect("a field");
            if field.first() == Some(&TAG_CONTEXT_2) {
                let extensions =
                    OcspHelpers::value_of(field, "extensions").expect("[2] has a value");
                found = OcspHelpers::nonce_from_extensions(extensions).expect("parses");
            }
        }
        assert_eq!(
            found.as_deref(),
            Some(nonce.as_bytes()),
            "the nonce did not survive encode then decode"
        );
    }

    #[test]
    fn a_request_without_a_nonce_names_no_nonce_extension() {
        let request = build_request(
            IssuerNameHash::new(FILL_NAME_HASH),
            IssuerKeyHash::new(FILL_KEY_HASH),
            &CertSerial::from_bytes(ROUNDTRIP_SERIAL.to_vec()),
        );
        let needle = OID_OCSP_NONCE.as_bytes();
        assert!(
            !request.as_der().windows(needle.len()).any(|w| w == needle),
            "a request built without a nonce named the nonce extension"
        );
    }

    #[test]
    fn parse_response_decodes_good_status() {
        let serial = fixture_serial(1);
        let der = build_response(&single_response_der(
            &serial,
            &tlv(TAG_CONTEXT_0_PRIMITIVE, []),
        ));
        let resp = super::OcspResponse::parse(&der).expect("parses");
        assert_eq!(resp.status, OcspResponseStatus::Successful);
        let basic = resp.basic.expect("basic present");
        assert_eq!(
            basic.produced_at,
            DateTime::new(2026, 5, 20, 12, 0, 0).expect("valid")
        );
        let single = basic.find_serial(&serial).expect("serial found");
        assert!(matches!(single.status, CertStatus::Good));
        let absent = fixture_serial(9);
        assert!(basic.find_serial(&absent).is_none());
    }

    #[test]
    fn parse_response_decodes_revoked_status_with_reason() {
        // RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime,
        //   revocationReason [0] EXPLICIT CRLReason OPTIONAL }
        let mut revoked_info = gtime(2026, 5, 1, 8, 0, 0);
        revoked_info.extend_from_slice(&tlv(TAG_CONTEXT_0, tlv(TAG_ENUMERATED, [0x01])));
        let serial = fixture_serial(2);
        let der = build_response(&single_response_der(
            &serial,
            &tlv(TAG_CONTEXT_1, revoked_info),
        ));
        let resp = super::OcspResponse::parse(&der).expect("parses");
        let basic = resp.basic.expect("basic present");
        let sr = basic.find_serial(&serial).expect("serial found");
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "CertStatus is #[non_exhaustive]; the test asserts the Revoked-with-reason path and panics on every non-Revoked variant (Good, Unknown) or future addition with a Debug rendering for diagnosis."
        )]
        match sr.status {
            CertStatus::Revoked { revoked_at, reason } => {
                assert_eq!(revoked_at.year(), 2026);
                assert_eq!(reason, Some(crate::crl::CrlReason::KeyCompromise));
            }
            _ => panic!("expected Revoked, got {:?}", sr.status),
        }
    }

    #[test]
    fn parse_response_decodes_unknown_status() {
        let serial = fixture_serial(3);
        let der = build_response(&single_response_der(
            &serial,
            &tlv(TAG_CONTEXT_2_PRIMITIVE, []),
        ));
        let resp = super::OcspResponse::parse(&der).expect("parses");
        let basic = resp.basic.expect("basic present");
        let sr = basic.find_serial(&serial).expect("serial found");
        assert!(matches!(sr.status, CertStatus::Unknown));
    }

    #[test]
    fn parse_response_handles_try_later() {
        let der = status_only_response(3);
        let resp = super::OcspResponse::parse(&der).expect("parses");
        assert_eq!(resp.status, OcspResponseStatus::TryLater);
        assert!(resp.basic.is_none());
    }

    #[test]
    fn a_next_update_is_read_when_the_responder_gives_one() {
        let serial = fixture_serial(4);
        let mut body = cert_id_der(&serial);
        body.extend_from_slice(&tlv(TAG_CONTEXT_0_PRIMITIVE, []));
        body.extend_from_slice(&gtime(2026, 5, 20, 12, 0, 0));
        body.extend_from_slice(&tlv(TAG_CONTEXT_0, gtime(2026, 6, 20, 12, 0, 0)));
        let der = build_response(&tlv(TAG_SEQUENCE, body));
        let resp = super::OcspResponse::parse(&der).expect("parses");
        let basic = resp.basic.expect("basic present");
        let sr = basic.find_serial(&serial).expect("serial found");
        assert_eq!(
            sr.next_update,
            Some(DateTime::new(2026, 6, 20, 12, 0, 0).expect("valid"))
        );
    }

    #[test]
    fn a_responder_nonce_is_read_back_from_the_response() {
        let serial = fixture_serial(5);
        let single = single_response_der(&serial, &tlv(TAG_CONTEXT_0_PRIMITIVE, []));
        let mut extension = tlv(TAG_OID, OID_OCSP_NONCE.as_bytes());
        extension.extend_from_slice(&tlv(
            TAG_OCTET_STRING,
            tlv(TAG_OCTET_STRING, [0xDE, 0xAD, 0xBE, 0xEF]),
        ));
        let extensions = tlv(TAG_SEQUENCE, tlv(TAG_SEQUENCE, extension));
        let der = wrap_response(response_data(&single, Some(extensions)));
        let resp = super::OcspResponse::parse(&der).expect("parses");
        let basic = resp.basic.expect("basic present");
        assert_eq!(basic.nonce.as_deref(), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    }

    #[test]
    fn a_responder_id_before_produced_at_is_not_read_as_extensions() {
        // Both are [1]; only position separates them. A parser that
        // matched on the tag alone would read the responder's name as
        // an extension list and lose the nonce.
        let serial = fixture_serial(6);
        let single = single_response_der(&serial, &tlv(TAG_CONTEXT_0_PRIMITIVE, []));
        let mut extension = tlv(TAG_OID, OID_OCSP_NONCE.as_bytes());
        extension.extend_from_slice(&tlv(TAG_OCTET_STRING, tlv(TAG_OCTET_STRING, [0x01, 0x02])));
        let extensions = tlv(TAG_SEQUENCE, tlv(TAG_SEQUENCE, extension));
        let der = wrap_response(response_data(&single, Some(extensions)));
        let basic = super::OcspResponse::parse(&der)
            .expect("parses")
            .basic
            .expect("basic present");
        assert_eq!(basic.nonce.as_deref(), Some(&[0x01, 0x02][..]));
    }
}
