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

//! Slot / token / object model over PC/SC.
//!
//! A FINEID token exposes one profile object ([`ObjectKind::Profile`],
//! handle [`OBJ_PROFILE`]) declaring that its certificates are readable
//! without a login, the authentication certificate
//! ([`ObjectKind::Certificate`], handle [`OBJ_CERTIFICATE`]), its
//! public key ([`ObjectKind::PublicKey`], handle [`OBJ_PUBLIC_KEY`],
//! for consumers such as p11tool / libp11 that enumerate public
//! keys), its auth private key ([`ObjectKind::PrivateKey`], handle
//! [`OBJ_PRIVATE_KEY`]), the CA certificates read from the card (the
//! issuing CA in EF.4336 and the DVV root in EF.4334) and from the
//! per-user cache of earlier card reads ([`ObjectKind::Ca`], handles
//! starting at [`OBJ_CA_BASE`]), and for each CA certificate an NSS
//! trust record ([`ObjectKind::Trust`], the handle range after the CA
//! certificates) that marks it a trust anchor for client
//! authentication and email only, for exactly as long as the CA
//! certificate object itself exists. The profile object is what lets
//! NSS search the certificates and trust records as soon as the card
//! is present rather than after a login. The module ships no
//! certificate of its own: every CA certificate it presents was read
//! from a card. All authentication objects carry the same
//! [`crate::ck::CKA_ID`] so NSS pairs them.
//!
//! The card is opened only for the moment it takes to read the
//! certificate or run a signature, then dropped -- this module never
//! holds a PC/SC handle across PKCS#11 calls, so the desktop CLI
//! shares the reader.

use std::io::Write as _;
use std::sync::{Arc, Mutex};

#[cfg(feature = "pin-change")]
use refineid_lib_core::auth::{AuthError, ChangePinOutcome};
use refineid_lib_core::auth::{PinOps as _, PinSlot, PinStatus, VerifyOutcome};
use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend as _, ReaderId};
use refineid_lib_core::crypto::container::{EcdsaP384, RsaPkcs1Sha256, Signature};
use refineid_lib_core::crypto::digest::{Md5, Sha1, Sha224, Sha256, Sha384, Sha512};
use refineid_lib_core::identity::{TokenSerial, derive_printed_serial, render_token_serial};
use refineid_lib_core::pin::PinBytes;
use refineid_lib_core::pin_cache::PinSafetyCache;
use refineid_lib_core::pin_retry_risk::{
    RetryFloorRefusal, check_retry_floor, pin1_status_permits_reusable_cache,
};
use refineid_lib_core::pkcs15::{CertSlot, Pkcs15Ops as _};
use refineid_lib_core::x509::{
    EcCurve, OwnedCert, PublicKeyAlgorithm, UnvalidatedCertificate, extract_rsa_public_key,
};
use refineid_lib_pcsc::{PcscBackend, PcscCard};

#[cfg(feature = "pin-change")]
use crate::ck::CKR_PIN_LEN_RANGE;
use crate::ck::{
    CK_CERTIFICATE_CATEGORY_AUTHORITY, CK_CERTIFICATE_CATEGORY_TOKEN_USER, CK_FALSE, CK_TRUE,
    CKA_ALWAYS_AUTHENTICATE, CKA_ALWAYS_SENSITIVE, CKA_CERTIFICATE_CATEGORY, CKA_CERTIFICATE_TYPE,
    CKA_CLASS, CKA_DERIVE, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_ID,
    CKA_ISSUER, CKA_KEY_TYPE, CKA_LABEL, CKA_LOCAL, CKA_MODIFIABLE, CKA_MODULUS, CKA_MODULUS_BITS,
    CKA_NEVER_EXTRACTABLE, CKA_NSS_CERT_MD5_HASH, CKA_NSS_CERT_SHA1_HASH,
    CKA_NSS_TRUST_CLIENT_AUTH, CKA_NSS_TRUST_CODE_SIGNING, CKA_NSS_TRUST_EMAIL_PROTECTION,
    CKA_NSS_TRUST_SERVER_AUTH, CKA_NSS_TRUST_STEP_UP_APPROVED, CKA_PRIVATE, CKA_PROFILE_ID,
    CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_SERIAL_NUMBER, CKA_SIGN, CKA_SIGN_RECOVER, CKA_SUBJECT,
    CKA_TOKEN, CKA_TRUSTED, CKA_UNWRAP, CKA_VALUE, CKA_VERIFY, CKA_WRAP, CKC_X_509, CKK_EC,
    CKK_RSA, CKO_CERTIFICATE, CKO_NSS_TRUST, CKO_PRIVATE_KEY, CKO_PROFILE, CKO_PUBLIC_KEY,
    CKP_PUBLIC_CERTIFICATES_TOKEN, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_OK,
    CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE,
    CKR_USER_NOT_LOGGED_IN, CKT_NSS_MUST_VERIFY_TRUST, CKT_NSS_TRUSTED_DELEGATOR, CkAttributeType,
    CkBbool, CkObjectHandle, CkRv, CkTrust, CkUlong,
};
use crate::sign::{Mechanism, sign_with_card};

/// Object handle for the authentication certificate. Fixed for the
/// process; the session's slot disambiguates which card it belongs
/// to. Non-zero (0 is [`crate::ck::CK_INVALID_HANDLE`]).
pub const OBJ_CERTIFICATE: CkObjectHandle = 1;
/// Object handle for the authentication private key. Fixed for the
/// process; shares [`CKA_ID`] with the certificate so NSS pairs them.
pub const OBJ_PRIVATE_KEY: CkObjectHandle = 2;
/// Object handle for the authentication public key, derived from the
/// certificate SPKI. Shares [`CKA_ID`] with the other two objects.
pub const OBJ_PUBLIC_KEY: CkObjectHandle = 3;
/// Object handle for the token's one profile object
/// ([`ObjectKind::Profile`]). Fixed for the process; the object is a
/// constant of the module, not of the card.
pub const OBJ_PROFILE: CkObjectHandle = 4;
/// Base object handle for on-card and persisted CA certificates.
/// Subsequent CA certificates receive sequential handles: `OBJ_CA_BASE + index`.
/// The range is [`MAX_CA_OBJECTS`] wide; the NSS trust record of the CA
/// certificate at `index` follows it at
/// `OBJ_CA_BASE + MAX_CA_OBJECTS + index`, so a trust record's handle
/// names its certificate by the same index.
pub const OBJ_CA_BASE: CkObjectHandle = 5;
/// The CA certificate slots this module reads from the card, in the
/// order they are read: the issuing CA (EF.4336), then the root
/// (EF.4334). Both live directly under the MF and are readable without
/// a PIN (FINEID S4-1 v4.2 section 8.1.16).
const ON_CARD_CA_SLOTS: &[CertSlot] = &[CertSlot::IssuingCaEcc, CertSlot::RootCa];
/// The most CA certificate objects one token carries: the persisted
/// cache's bound plus the slots read from the card.
/// [`TokenObjects::push_ca_cert`] admits no more, which keeps every
/// [`ObjectKind::Ca`] handle inside its range and every
/// [`ObjectKind::Trust`] handle inside the range that follows.
const MAX_CA_OBJECTS: usize = MAX_CA_CERTS + ON_CARD_CA_SLOTS.len();
/// One past the last handle offset, from [`OBJ_CA_BASE`], of a trust
/// record: the CA certificate range and the trust range together.
const CA_AND_TRUST_HANDLE_OFFSETS: usize = MAX_CA_OBJECTS * 2;

/// Fixed human-readable token / object label used when the card's
/// certificate carries no usable common name. NSS shows it in the
/// certificate-selection UI.
const DEFAULT_LABEL: &str = "FINEID";

/// ASN.1 DER tag for `INTEGER` (X.690 s8.3; universal 2). Used to
/// rebuild the [`CKA_SERIAL_NUMBER`] TLV from the parsed value bytes.
const DER_TAG_INTEGER: u8 = 0x02;
/// ASN.1 DER tag for `OCTET STRING` (X.690 s8.7; universal 4). Wraps
/// the SEC1 point for [`CKA_EC_POINT`].
const DER_TAG_OCTET_STRING: u8 = 0x04;
/// X.690 s8.1.3.5 long-form length marker: a length octet with bit 8
/// set introduces long-form length. Values below it are short-form
/// (the length is the octet itself).
const DER_SHORT_FORM_LIMIT: usize = 0x80;
/// X.690 s8.1.3.5 long-form prefix for a length encoded in one
/// subsequent octet (`0x80 | 1`).
const DER_LONG_FORM_ONE_OCTET: u8 = 0x81;
/// X.690 s8.1.3.5 long-form prefix for a length encoded in two
/// subsequent octets (`0x80 | 2`).
const DER_LONG_FORM_TWO_OCTETS: u8 = 0x82;

/// ASN.1 `DigestInfo` prefix for SHA-256 (RFC 8017 s9.2 note 1):
/// `SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL },
/// OCTET STRING (32) }` minus the hash bytes. `CKM_RSA_PKCS`
/// callers pass `DigestInfo || hash` -- the same input shape the
/// sign path takes to the card.
const DIGEST_INFO_SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// DER encoding of the ANSI X9.62 named-curve OID for secp384r1 /
/// NIST P-384 (`1.3.132.0.34`): `OBJECT IDENTIFIER` TLV. This is the
/// value NSS expects for [`CKA_EC_PARAMS`] on the ECC FINEID card
/// (RFC 5480 s2.1.1; SEC2 v2 s2.6.1).
const EC_PARAMS_SECP384R1: [u8; 7] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

/// Which of the token's objects an attribute query refers to.
///
/// HARD LIMIT: the token claims exactly one profile,
/// [`CKP_PUBLIC_CERTIFICATES_TOKEN`], through [`Self::Profile`]. Never
/// add a second `CKO_PROFILE` object, and never one answering
/// `CKA_PROFILE_ID` = `CKP_AUTHENTICATION_TOKEN`: that profile invites
/// a client to log in proactively, and a PIN prompt must appear only
/// when a TLS handshake actually needs the key, never at browser
/// startup. The public-certificates profile asserts nothing about the
/// key or the login; it only says the certificates are readable
/// without one, which they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// The X.509 authentication certificate ([`CKO_CERTIFICATE`]).
    Certificate,
    /// The authentication public key ([`CKO_PUBLIC_KEY`]), from the
    /// certificate SPKI.
    PublicKey,
    /// The authentication private key ([`CKO_PRIVATE_KEY`]).
    PrivateKey,
    /// The profile object ([`CKO_PROFILE`]) claiming
    /// [`CKP_PUBLIC_CERTIFICATES_TOKEN`]: the token's certificates
    /// are readable without a login. Built from specification
    /// constants alone, so it exists on every token the module raises,
    /// local or phone-served, whatever the card carries.
    Profile,
    /// Dynamic CA certificate object at index `usize`.
    Ca(usize),
    /// The NSS trust record ([`CKO_NSS_TRUST`]) of the CA certificate
    /// at index `usize`; exists exactly when that [`Self::Ca`] does.
    Trust(usize),
}

/// A handle offset for a CA certificate or trust index; an index no
/// handle can carry saturates to a handle that names nothing.
fn handle_offset(index: usize) -> CkObjectHandle {
    CkObjectHandle::try_from(index).unwrap_or(CkObjectHandle::MAX)
}

impl ObjectKind {
    /// Resolve an object handle to its kind, or `None` when the
    /// handle names no valid object range this token exposes.
    #[must_use]
    pub(crate) fn from_handle(handle: CkObjectHandle) -> Option<Self> {
        match handle {
            OBJ_CERTIFICATE => Some(Self::Certificate),
            OBJ_PRIVATE_KEY => Some(Self::PrivateKey),
            OBJ_PUBLIC_KEY => Some(Self::PublicKey),
            OBJ_PROFILE => Some(Self::Profile),
            h if h >= OBJ_CA_BASE => {
                let offset = usize::try_from(h - OBJ_CA_BASE).ok()?;
                match offset {
                    o if o < MAX_CA_OBJECTS => Some(Self::Ca(o)),
                    o if o < CA_AND_TRUST_HANDLE_OFFSETS => Some(Self::Trust(o - MAX_CA_OBJECTS)),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// The object handle for this kind.
    #[must_use]
    pub(crate) fn handle(self) -> CkObjectHandle {
        match self {
            Self::Certificate => OBJ_CERTIFICATE,
            Self::PrivateKey => OBJ_PRIVATE_KEY,
            Self::PublicKey => OBJ_PUBLIC_KEY,
            Self::Profile => OBJ_PROFILE,
            Self::Ca(idx) => OBJ_CA_BASE.saturating_add(handle_offset(idx)),
            Self::Trust(idx) => {
                OBJ_CA_BASE.saturating_add(handle_offset(idx.saturating_add(MAX_CA_OBJECTS)))
            }
        }
    }
}

/// Result of an attribute lookup: either a borrowed slice from certificate
/// or token metadata, an inlined scalar byte buffer, or a marker that the
/// attribute exists but is sensitive (the private key's [`CKA_VALUE`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrValue<'a> {
    /// Borrowed slice from certificate / key DER or token metadata.
    Borrowed(&'a [u8]),
    /// Inlined scalar bytes (for [`CkUlong`], [`CkBbool`]) with zero heap allocations.
    Inline([u8; 8], usize),
    /// The attribute exists but its value is sensitive and withheld.
    Sensitive,
}

impl AttrValue<'_> {
    /// Borrow the underlying attribute bytes if available.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Borrowed(slice) => Some(slice),
            Self::Inline(buf, len) => Some(&buf[..*len]),
            Self::Sensitive => None,
        }
    }
}

/// A CA certificate object on the token, read from a card, with the
/// values its NSS trust record answers.
#[derive(Debug, Clone)]
pub struct CaObject {
    cert: OwnedCert,
    id: Sha1,
    label: String,
    serial_der: Vec<u8>,
    /// SHA-1 of the certificate DER ([`CKA_NSS_CERT_SHA1_HASH`]).
    der_sha1: Sha1,
    /// MD5 of the certificate DER ([`CKA_NSS_CERT_MD5_HASH`]), a lookup
    /// key NSS carries on every trust record; no decision rests on it.
    der_md5: Md5,
}

impl CaObject {
    pub(crate) fn new(cert: OwnedCert) -> Self {
        let view = cert.view();
        let label = view
            .subject
            .common_name()
            .map_or_else(|| "CA Certificate".to_owned(), |cn| cn.as_str().to_owned());
        let id = Sha1::of(view.spki.as_der());
        let serial_der = der_integer(view.serial_der);
        let der_sha1 = Sha1::of(cert.as_der());
        let der_md5 = Md5::of(cert.as_der());
        Self {
            cert,
            id,
            label,
            serial_der,
            der_sha1,
            der_md5,
        }
    }

    #[must_use]
    pub(crate) fn id_bytes(&self) -> &[u8] {
        self.id.as_bytes()
    }

    #[must_use]
    pub(crate) fn label_bytes(&self) -> &[u8] {
        self.label.as_bytes()
    }

    #[must_use]
    pub(crate) fn serial_der(&self) -> &[u8] {
        &self.serial_der
    }

    #[must_use]
    pub(crate) fn der_sha1_bytes(&self) -> &[u8] {
        self.der_sha1.as_bytes()
    }

    #[must_use]
    pub(crate) fn der_md5_bytes(&self) -> &[u8] {
        self.der_md5.as_bytes()
    }
}

/// Strongly typed key material parsed from the card profile certificate SPKI.
#[derive(Debug, Clone)]
pub enum TokenKeyMaterial {
    Rsa {
        modulus: Vec<u8>,
        modulus_bits: CkUlong,
        public_exponent: Vec<u8>,
    },
    Ec {
        params: &'static [u8],
        point: Vec<u8>,
    },
}

impl TokenKeyMaterial {
    fn extract(spki: &refineid_lib_core::x509::SpkiDer<'_>) -> Result<Self, CkRv> {
        match spki.algorithm() {
            PublicKeyAlgorithm::Rsa { modulus_bits } => {
                let public = extract_rsa_public_key(spki.as_der()).ok_or(CKR_DEVICE_ERROR)?;
                let bits = CkUlong::try_from(modulus_bits).map_err(|_| CKR_DEVICE_ERROR)?;
                Ok(Self::Rsa {
                    modulus: public.modulus.as_bytes().to_vec(),
                    modulus_bits: bits,
                    public_exponent: public.exponent.as_bytes().to_vec(),
                })
            }
            PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => {
                let point = spki.ec_public_key_point().ok_or(CKR_DEVICE_ERROR)?;
                Ok(Self::Ec {
                    params: &EC_PARAMS_SECP384R1,
                    point: der_octet_string(point.as_bytes()),
                })
            }
            PublicKeyAlgorithm::Ec(_)
            | PublicKeyAlgorithm::EcExplicit { .. }
            | PublicKeyAlgorithm::Other => Err(CKR_DEVICE_ERROR),
        }
    }

    #[must_use]
    pub(crate) const fn key_type(&self) -> CkUlong {
        match self {
            Self::Rsa { .. } => CKK_RSA,
            Self::Ec { .. } => CKK_EC,
        }
    }

    #[must_use]
    pub(crate) const fn mechanism(&self) -> Mechanism {
        match self {
            Self::Rsa { .. } => Mechanism::RsaPkcs,
            Self::Ec { .. } => Mechanism::Ecdsa,
        }
    }
}

/// An NSS trust level this token asserts for one purpose; the two of
/// NSS's levels this module ever answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NssTrustLevel {
    /// [`CKT_NSS_TRUSTED_DELEGATOR`]: an anchor; certificates the CA
    /// issued are trusted for the purpose.
    TrustedDelegator,
    /// [`CKT_NSS_MUST_VERIFY_TRUST`]: nothing asserted; a chain must
    /// reach some other anchor. Not a distrust (that would be
    /// [`crate::ck::CKT_NSS_NOT_TRUSTED`]).
    MustVerifyTrust,
}

impl NssTrustLevel {
    /// The `CK_TRUST` value NSS reads.
    const fn ck_trust(self) -> CkTrust {
        match self {
            Self::TrustedDelegator => CKT_NSS_TRUSTED_DELEGATOR,
            Self::MustVerifyTrust => CKT_NSS_MUST_VERIFY_TRUST,
        }
    }
}

/// What a token asserts about a CA certificate, per NSS purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NssTrustRecord {
    /// [`CKA_NSS_TRUST_SERVER_AUTH`].
    server_auth: NssTrustLevel,
    /// [`CKA_NSS_TRUST_CLIENT_AUTH`].
    client_auth: NssTrustLevel,
    /// [`CKA_NSS_TRUST_CODE_SIGNING`].
    code_signing: NssTrustLevel,
    /// [`CKA_NSS_TRUST_EMAIL_PROTECTION`].
    email_protection: NssTrustLevel,
}

/// The trust every CA certificate on this token carries: an anchor for
/// the holder's own uses of the card, TLS client authentication and
/// email, and no assertion for the purposes the card has nothing to
/// do with, TLS server authentication and code signing. The DVV roots
/// are in no Mozilla-derived root store, and this token does not add
/// them to one: a web site chaining to the DVV root stays unverified.
///
/// In NSS's own flags (`lib/pki/certificate.c`,
/// `nssTrust_ToCERTCertTrust`) the record reads as trusted client CA
/// for TLS and trusted CA for email, which `certutil -L` prints as the
/// trust string `T,C,`.
const CARD_CA_TRUST: NssTrustRecord = NssTrustRecord {
    server_auth: NssTrustLevel::MustVerifyTrust,
    client_auth: NssTrustLevel::TrustedDelegator,
    code_signing: NssTrustLevel::MustVerifyTrust,
    email_protection: NssTrustLevel::TrustedDelegator,
};

/// The token objects, parsed from the card's authentication
/// certificate and cached per slot while the same card stays present.
#[derive(Debug, Clone)]
pub struct TokenObjects {
    /// The parsed leaf authentication certificate.
    auth_cert: OwnedCert,
    /// [`CKA_ID`]: SHA-1 of the SPKI DER, shared by cert and key.
    auth_cert_id: Sha1,
    /// Human-readable label for [`CKA_LABEL`] (common name, else [`DEFAULT_LABEL`]).
    auth_cert_label: String,
    /// Pre-encoded serial number DER INTEGER for the authentication certificate.
    auth_cert_serial_der: Vec<u8>,
    /// Chip serial from PKCS#15 EF.TokenInfo: the plastic-printed
    /// card identifier when [`derive_printed_serial`] recognises
    /// the chip generation (the form a citizen can check against
    /// the card body), else the full rendered serial via
    /// [`render_token_serial`]; empty when the card reports none.
    /// Reported in `CK_TOKEN_INFO.serialNumber`.
    token_serial: String,
    /// Key-type specific material extracted and validated from the SPKI.
    key_material: TokenKeyMaterial,
    /// The CA certificate objects, each read from a card: distinct by
    /// DER, in discovery order, at most [`MAX_CA_OBJECTS`].
    ca_objects: Vec<CaObject>,
}

/// Encode a [`CkUlong`] attribute value into an inline zero-allocation buffer.
#[expect(
    clippy::host_endian_bytes,
    reason = "PKCS#11 CK_ULONG attribute values live in caller memory as a native-endian machine word; NSS reads them back as CK_ULONG, so the on-wire bytes must match the host byte order, not a fixed endianness"
)]
fn ulong_attr(value: CkUlong) -> AttrValue<'static> {
    let bytes = value.to_ne_bytes();
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(&bytes);
    AttrValue::Inline(buf, bytes.len())
}

/// Encode a [`CkBbool`] attribute value into an inline zero-allocation buffer.
fn bool_attr(value: CkBbool) -> AttrValue<'static> {
    let mut buf = [0u8; 8];
    buf[0] = value;
    AttrValue::Inline(buf, 1)
}

/// Number of bits per byte used for length shifts.
const BITS_PER_BYTE: u32 = 8;
/// Mask to extract a single low byte from an integer.
const BYTE_MASK: usize = 0xFF;

/// Append a DER length for `len` to `out` (X.690 s8.1.3). Handles the
/// short form and one/two-octet long forms; every value this module
/// encodes is far below 65536 bytes.
fn push_der_len(out: &mut Vec<u8>, len: usize) {
    if len < DER_SHORT_FORM_LIMIT {
        if let Ok(short) = u8::try_from(len) {
            out.push(short);
        }
    } else if let Ok(one) = u8::try_from(len) {
        out.push(DER_LONG_FORM_ONE_OCTET);
        out.push(one);
    } else {
        let high =
            u8::try_from((len.checked_shr(BITS_PER_BYTE).unwrap_or(0)) & BYTE_MASK).unwrap_or(0);
        let low = u8::try_from(len & BYTE_MASK).unwrap_or(0);
        out.push(DER_LONG_FORM_TWO_OCTETS);
        out.push(high);
        out.push(low);
    }
}

/// Rebuild a DER `INTEGER` TLV from the certificate's serial value
/// bytes (`Certificate::serial_der` yields the INTEGER contents only,
/// no tag/length). NSS matches [`CKA_SERIAL_NUMBER`] against the full
/// TLV.
fn der_integer(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len().saturating_add(2));
    out.push(DER_TAG_INTEGER);
    push_der_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// Wrap a SEC1 EC point in a DER `OCTET STRING` TLV for [`CKA_EC_POINT`]
/// per PKCS#11 v2.40 s2.3.4.
fn der_octet_string(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len().saturating_add(2));
    out.push(DER_TAG_OCTET_STRING);
    push_der_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// Reject empty byte slices by mapping them to `None`.
fn non_empty(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.is_empty() { None } else { Some(bytes) }
}

/// Attribute lookup for the profile object ([`ObjectKind::Profile`]):
/// a public, unmodifiable token object of class [`CKO_PROFILE`] whose
/// [`CKA_PROFILE_ID`] is [`CKP_PUBLIC_CERTIFICATES_TOKEN`] (PKCS#11
/// v3.0 base specification s4.14). It reads nothing from the card, so
/// every token answers it the same way.
///
/// NSS searches the profile objects of a token as soon as it is
/// present, before any login, with a template of [`CKA_TOKEN`] true and
/// [`CKA_CLASS`] `CKO_PROFILE`, and reads each one's `CKA_PROFILE_ID`
/// (`lib/pk11wrap/pk11slot.c`, `PK11_InitToken` and
/// `pk11_ReadProfileList`); finding this profile makes the token
/// friendly (`PK11_IsFriendly`), so its certificate and trust objects
/// are searched without waiting for a login (`lib/dev/devutil.c`,
/// `search_for_objects`).
fn profile_attribute(attr: CkAttributeType) -> Option<AttrValue<'static>> {
    match attr {
        CKA_CLASS => Some(ulong_attr(CKO_PROFILE)),
        CKA_PROFILE_ID => Some(ulong_attr(CKP_PUBLIC_CERTIFICATES_TOKEN)),
        CKA_TOKEN => Some(bool_attr(CK_TRUE)),
        CKA_PRIVATE | CKA_MODIFIABLE => Some(bool_attr(CK_FALSE)),
        _ => None,
    }
}

impl TokenObjects {
    /// Build token objects from the card's leaf authentication certificate
    /// DER bytes, with no CA certificate yet: the caller pushes the ones
    /// read from the card and the cache with [`Self::push_ca_cert`].
    ///
    /// # Errors
    /// [`CKR_DEVICE_ERROR`] if the DER does not parse or the key
    /// algorithm is neither RSA nor secp384r1 EC (the only two FINEID
    /// auth profiles).
    pub(crate) fn from_cert_der(cert_der: Vec<u8>) -> Result<Self, CkRv> {
        let auth_cert = OwnedCert::from_der(UnvalidatedCertificate::new(cert_der))
            .map_err(|_parse_err| CKR_DEVICE_ERROR)?;
        let view = auth_cert.view();
        let key_material = TokenKeyMaterial::extract(&view.spki)?;
        let auth_cert_id = Sha1::of(view.spki.as_der());
        let auth_cert_label = view
            .subject
            .common_name()
            .map_or_else(|| DEFAULT_LABEL.to_owned(), |cn| cn.as_str().to_owned());
        let auth_cert_serial_der = der_integer(view.serial_der);
        let ca_objects = Vec::new();
        Ok(Self {
            auth_cert,
            auth_cert_id,
            auth_cert_label,
            auth_cert_serial_der,
            token_serial: String::new(),
            key_material,
            ca_objects,
        })
    }

    /// The sign mechanism for this card profile.
    #[must_use]
    pub(crate) const fn mechanism(&self) -> Mechanism {
        self.key_material.mechanism()
    }

    /// The rendered chip serial from EF.TokenInfo; empty when the
    /// card did not report one.
    #[must_use]
    pub(crate) fn token_serial(&self) -> &str {
        &self.token_serial
    }

    #[cfg_attr(
        not(windows),
        expect(
            dead_code,
            reason = "set_token_serial is used by remote_token_objects on Windows"
        )
    )]
    pub(crate) fn set_token_serial(&mut self, serial: String) {
        self.token_serial = serial;
    }

    /// Look up one attribute of one object.
    ///
    /// Returns `None` when the attribute type does not apply to the
    /// object (the caller maps that to
    /// [`crate::ck::CKR_ATTRIBUTE_TYPE_INVALID`]); returns
    /// [`AttrValue::Sensitive`] for the private key's [`CKA_VALUE`].
    #[must_use]
    pub(crate) fn attribute(
        &self,
        kind: ObjectKind,
        attr: CkAttributeType,
    ) -> Option<AttrValue<'_>> {
        match kind {
            ObjectKind::Certificate => self.certificate_attribute(attr),
            ObjectKind::PublicKey => self.public_key_attribute(attr),
            ObjectKind::PrivateKey => self.private_key_attribute(attr),
            ObjectKind::Profile => profile_attribute(attr),
            ObjectKind::Ca(_) => {
                let ca = self.ca_object_for_kind(kind)?;
                Self::ca_object_attribute(ca, attr)
            }
            ObjectKind::Trust(_) => {
                let ca = self.ca_object_for_kind(kind)?;
                Self::trust_attribute(ca, attr)
            }
        }
    }

    /// Attribute lookup for the NSS trust record of the CA certificate
    /// `ca`.
    ///
    /// NSS finds the record by [`CKA_CLASS`], [`CKA_ISSUER`] and
    /// [`CKA_SERIAL_NUMBER`] (`lib/dev/devtoken.c`,
    /// `nssToken_FindTrustForCertificate`), the same issuer and serial
    /// the certificate object answers, then reads the label, the two
    /// certificate digests, the subject and the four purpose levels
    /// (`lib/dev/devutil.c`, `create_trust`). The MD5 digest is a
    /// lookup key NSS carries on every record it reads or writes; no
    /// decision rests on it.
    fn trust_attribute(ca: &CaObject, attr: CkAttributeType) -> Option<AttrValue<'_>> {
        let view = ca.cert.view();
        match attr {
            CKA_CLASS => Some(ulong_attr(CKO_NSS_TRUST)),
            CKA_TOKEN => Some(bool_attr(CK_TRUE)),
            CKA_PRIVATE | CKA_MODIFIABLE | CKA_NSS_TRUST_STEP_UP_APPROVED => {
                Some(bool_attr(CK_FALSE))
            }
            CKA_LABEL => Some(AttrValue::Borrowed(ca.label_bytes())),
            CKA_ISSUER => non_empty(view.issuer.as_der()).map(AttrValue::Borrowed),
            CKA_SUBJECT => non_empty(view.subject.as_der()).map(AttrValue::Borrowed),
            CKA_SERIAL_NUMBER => non_empty(ca.serial_der()).map(AttrValue::Borrowed),
            CKA_NSS_CERT_SHA1_HASH => Some(AttrValue::Borrowed(ca.der_sha1_bytes())),
            CKA_NSS_CERT_MD5_HASH => Some(AttrValue::Borrowed(ca.der_md5_bytes())),
            CKA_NSS_TRUST_SERVER_AUTH => Some(ulong_attr(CARD_CA_TRUST.server_auth.ck_trust())),
            CKA_NSS_TRUST_CLIENT_AUTH => Some(ulong_attr(CARD_CA_TRUST.client_auth.ck_trust())),
            CKA_NSS_TRUST_CODE_SIGNING => Some(ulong_attr(CARD_CA_TRUST.code_signing.ck_trust())),
            CKA_NSS_TRUST_EMAIL_PROTECTION => {
                Some(ulong_attr(CARD_CA_TRUST.email_protection.ck_trust()))
            }
            _ => None,
        }
    }

    /// Attribute lookup for a CA certificate object read from a card.
    fn ca_object_attribute(ca: &CaObject, attr: CkAttributeType) -> Option<AttrValue<'_>> {
        let view = ca.cert.view();
        match attr {
            CKA_CLASS => Some(ulong_attr(CKO_CERTIFICATE)),
            CKA_CERTIFICATE_TYPE => Some(ulong_attr(CKC_X_509)),
            CKA_CERTIFICATE_CATEGORY => Some(ulong_attr(CK_CERTIFICATE_CATEGORY_AUTHORITY)),
            CKA_TOKEN => Some(bool_attr(CK_TRUE)),
            // The PKCS#11 trust bit stays false: the certificate's trust,
            // per purpose, is the companion trust record's to state
            // (PKCS#11 v2.40 s4.4: CKA_TRUSTED; NSS lib/pk11wrap/pk11cert.c
            // imports token certificates without requiring CKA_TRUSTED).
            CKA_PRIVATE | CKA_TRUSTED => Some(bool_attr(CK_FALSE)),
            CKA_LABEL => Some(AttrValue::Borrowed(ca.label_bytes())),
            CKA_ID => Some(AttrValue::Borrowed(ca.id_bytes())),
            CKA_VALUE => Some(AttrValue::Borrowed(ca.cert.as_der())),
            CKA_ISSUER => non_empty(view.issuer.as_der()).map(AttrValue::Borrowed),
            CKA_SUBJECT => non_empty(view.subject.as_der()).map(AttrValue::Borrowed),
            CKA_SERIAL_NUMBER => non_empty(ca.serial_der()).map(AttrValue::Borrowed),
            _ => None,
        }
    }

    /// Attribute lookup for the certificate object.
    ///
    /// [`CKA_TRUSTED`] and [`CKA_LOCAL`] are answered `CK_FALSE`
    /// rather than left absent: both are honest (an end-entity
    /// credential is not a trust anchor; the certificate was
    /// personalised by DVV, not generated through this module) and a
    /// concrete answer keeps `pkcs11-tool --list-objects` free of
    /// attribute-read failure noise.
    fn certificate_attribute(&self, attr: CkAttributeType) -> Option<AttrValue<'_>> {
        let view = self.auth_cert.view();
        match attr {
            CKA_CLASS => Some(ulong_attr(CKO_CERTIFICATE)),
            CKA_CERTIFICATE_TYPE => Some(ulong_attr(CKC_X_509)),
            CKA_CERTIFICATE_CATEGORY => Some(ulong_attr(CK_CERTIFICATE_CATEGORY_TOKEN_USER)),
            CKA_KEY_TYPE => Some(ulong_attr(self.key_material.key_type())),
            CKA_TOKEN => Some(bool_attr(CK_TRUE)),
            CKA_PRIVATE | CKA_TRUSTED | CKA_LOCAL => Some(bool_attr(CK_FALSE)),
            CKA_LABEL => Some(AttrValue::Borrowed(self.auth_cert_label.as_bytes())),
            CKA_ID => Some(AttrValue::Borrowed(self.auth_cert_id.as_bytes())),
            CKA_VALUE => Some(AttrValue::Borrowed(self.auth_cert.as_der())),
            CKA_ISSUER => non_empty(view.issuer.as_der()).map(AttrValue::Borrowed),
            CKA_SUBJECT => non_empty(view.subject.as_der()).map(AttrValue::Borrowed),
            CKA_SERIAL_NUMBER => non_empty(&self.auth_cert_serial_der).map(AttrValue::Borrowed),
            _ => None,
        }
    }

    /// Attribute lookup for the public key object, served from the
    /// certificate SPKI. [`CKA_VERIFY`] is `CK_TRUE` (the key's
    /// purpose per the certificate); the other usage flags are
    /// `CK_FALSE` because this token performs none of those
    /// operations.
    fn public_key_attribute(&self, attr: CkAttributeType) -> Option<AttrValue<'_>> {
        match attr {
            CKA_CLASS => Some(ulong_attr(CKO_PUBLIC_KEY)),
            CKA_KEY_TYPE => Some(ulong_attr(self.key_material.key_type())),
            CKA_TOKEN | CKA_VERIFY => Some(bool_attr(CK_TRUE)),
            CKA_PRIVATE | CKA_ENCRYPT | CKA_WRAP | CKA_DERIVE => Some(bool_attr(CK_FALSE)),
            CKA_LABEL => Some(AttrValue::Borrowed(self.auth_cert_label.as_bytes())),
            CKA_ID => Some(AttrValue::Borrowed(self.auth_cert_id.as_bytes())),
            CKA_SUBJECT => {
                non_empty(self.auth_cert.view().subject.as_der()).map(AttrValue::Borrowed)
            }
            CKA_MODULUS => match &self.key_material {
                TokenKeyMaterial::Rsa { modulus, .. } => Some(AttrValue::Borrowed(modulus)),
                TokenKeyMaterial::Ec { .. } => None,
            },
            CKA_MODULUS_BITS => match &self.key_material {
                TokenKeyMaterial::Rsa { modulus_bits, .. } => Some(ulong_attr(*modulus_bits)),
                TokenKeyMaterial::Ec { .. } => None,
            },
            CKA_PUBLIC_EXPONENT => match &self.key_material {
                TokenKeyMaterial::Rsa {
                    public_exponent, ..
                } => Some(AttrValue::Borrowed(public_exponent)),
                TokenKeyMaterial::Ec { .. } => None,
            },
            CKA_EC_PARAMS => match &self.key_material {
                TokenKeyMaterial::Ec { params, .. } => Some(AttrValue::Borrowed(params)),
                TokenKeyMaterial::Rsa { .. } => None,
            },
            CKA_EC_POINT => match &self.key_material {
                TokenKeyMaterial::Ec { point, .. } => Some(AttrValue::Borrowed(point)),
                TokenKeyMaterial::Rsa { .. } => None,
            },
            _ => None,
        }
    }

    /// Attribute lookup for the private key object.
    ///
    /// The extractability triple ([`CKA_EXTRACTABLE`] false,
    /// [`CKA_NEVER_EXTRACTABLE`] / [`CKA_ALWAYS_SENSITIVE`] true)
    /// states the FINEID guarantee that the private key never leaves
    /// the card -- it is what a security review greps for, and an
    /// absent attribute never matches a find template asking for
    /// `CKA_EXTRACTABLE = FALSE`.
    fn private_key_attribute(&self, attr: CkAttributeType) -> Option<AttrValue<'_>> {
        match attr {
            CKA_CLASS => Some(ulong_attr(CKO_PRIVATE_KEY)),
            CKA_KEY_TYPE => Some(ulong_attr(self.key_material.key_type())),
            CKA_TOKEN
            | CKA_PRIVATE
            | CKA_SIGN
            | CKA_SENSITIVE
            | CKA_NEVER_EXTRACTABLE
            | CKA_ALWAYS_SENSITIVE => Some(bool_attr(CK_TRUE)),
            CKA_ALWAYS_AUTHENTICATE
            | CKA_EXTRACTABLE
            | CKA_SIGN_RECOVER
            | CKA_UNWRAP
            | CKA_DERIVE => Some(bool_attr(CK_FALSE)),
            CKA_LABEL => Some(AttrValue::Borrowed(self.auth_cert_label.as_bytes())),
            CKA_ID => Some(AttrValue::Borrowed(self.auth_cert_id.as_bytes())),
            CKA_SUBJECT => {
                non_empty(self.auth_cert.view().subject.as_der()).map(AttrValue::Borrowed)
            }
            CKA_VALUE => Some(AttrValue::Sensitive),
            CKA_MODULUS => match &self.key_material {
                TokenKeyMaterial::Rsa { modulus, .. } => Some(AttrValue::Borrowed(modulus)),
                TokenKeyMaterial::Ec { .. } => None,
            },
            CKA_MODULUS_BITS => match &self.key_material {
                TokenKeyMaterial::Rsa { modulus_bits, .. } => Some(ulong_attr(*modulus_bits)),
                TokenKeyMaterial::Ec { .. } => None,
            },
            CKA_PUBLIC_EXPONENT => match &self.key_material {
                TokenKeyMaterial::Rsa {
                    public_exponent, ..
                } => Some(AttrValue::Borrowed(public_exponent)),
                TokenKeyMaterial::Ec { .. } => None,
            },
            CKA_EC_PARAMS => match &self.key_material {
                TokenKeyMaterial::Ec { params, .. } => Some(AttrValue::Borrowed(params)),
                TokenKeyMaterial::Rsa { .. } => None,
            },
            CKA_EC_POINT => match &self.key_material {
                TokenKeyMaterial::Ec { point, .. } => Some(AttrValue::Borrowed(point)),
                TokenKeyMaterial::Rsa { .. } => None,
            },
            _ => None,
        }
    }

    /// Append a CA certificate read from a card, with its trust record,
    /// unless the token already holds the same DER or holds
    /// [`MAX_CA_OBJECTS`] certificates: the handle ranges of the
    /// certificates and their trust records are that wide, and a
    /// certificate beyond them would have no handle.
    pub(crate) fn push_ca_cert(&mut self, cert: OwnedCert) {
        if self.ca_objects.len() >= MAX_CA_OBJECTS
            || self
                .ca_objects
                .iter()
                .any(|obj| obj.cert.as_der() == cert.as_der())
        {
            return;
        }
        self.ca_objects.push(CaObject::new(cert));
    }

    /// Software signature verification against the cached
    /// certificate public key -- pure host-side computation, no
    /// card IO, no PIN. Serves `C_Verify` so `pkcs11-tool
    /// --verify` and libp11-style consumers work without the
    /// caller re-extracting the public key.
    ///
    /// Input shapes mirror the sign path exactly:
    /// `CKM_RSA_PKCS` takes `DigestInfo || SHA-256 hash`;
    /// `CKM_ECDSA` takes a raw digest (SHA-1/224/256/384/512
    /// lengths accepted) with raw `r || s` signatures.
    pub(crate) fn verify_signature(
        &self,
        mechanism: Mechanism,
        data: &[u8],
        signature: &[u8],
    ) -> CkRv {
        if signature.len() != mechanism.signature_len() {
            return CKR_SIGNATURE_LEN_RANGE;
        }
        match mechanism {
            Mechanism::RsaPkcs => self.verify_rsa_pkcs(data, signature),
            Mechanism::Ecdsa => self.verify_ecdsa(data, signature),
        }
    }

    /// `CKM_RSA_PKCS` software verify: strict `DigestInfo`
    /// (SHA-256) input, PKCS#1 v1.5 padding check in lib-core.
    fn verify_rsa_pkcs(&self, data: &[u8], signature: &[u8]) -> CkRv {
        let Some(hash) = data.strip_prefix(&DIGEST_INFO_SHA256_PREFIX) else {
            return CKR_DATA_INVALID;
        };
        let Ok(digest) = <[u8; 32]>::try_from(hash) else {
            return CKR_DATA_INVALID;
        };
        let Some(key) = extract_rsa_public_key(self.auth_cert.view().spki.as_der()) else {
            return CKR_DEVICE_ERROR;
        };
        let sig = Signature::<RsaPkcs1Sha256>::new(signature.to_vec());
        match key.verify_pkcs1v15_sha256_digest(&digest, &sig) {
            Ok(()) => CKR_OK,
            Err(_mismatch) => CKR_SIGNATURE_INVALID,
        }
    }

    /// `CKM_ECDSA` software verify: the digest length selects the
    /// hash family (PKCS#11 attaches no hash to `CKM_ECDSA`; the
    /// caller already hashed), the signature is card-native raw
    /// `r || s`.
    fn verify_ecdsa(&self, data: &[u8], signature: &[u8]) -> CkRv {
        let Some(point) = self.auth_cert.view().spki.ec_public_key_point() else {
            return CKR_DEVICE_ERROR;
        };
        let sig = Signature::<EcdsaP384>::new(signature.to_vec());
        let outcome = if let Ok(digest) = <[u8; 20]>::try_from(data) {
            point.verify_p384_sha1_raw(sig, Sha1::from_bytes(digest))
        } else if let Ok(digest) = <[u8; 28]>::try_from(data) {
            point.verify_p384_sha224_raw(sig, Sha224::from_bytes(digest))
        } else if let Ok(digest) = <[u8; 32]>::try_from(data) {
            point.verify_p384_sha256_raw(sig, Sha256::from_bytes(digest))
        } else if let Ok(digest) = <[u8; 48]>::try_from(data) {
            point.verify_p384_sha384_raw(sig, Sha384::from_bytes(digest))
        } else if let Ok(digest) = <[u8; 64]>::try_from(data) {
            point.verify_p384_sha512_raw(sig, Sha512::from_bytes(digest))
        } else {
            return CKR_DATA_LEN_RANGE;
        };
        match outcome {
            Ok(()) => CKR_OK,
            Err(_mismatch) => CKR_SIGNATURE_INVALID,
        }
    }

    /// Look up the CA certificate object matching `kind` by dynamic
    /// index: the certificate object itself, or the one a trust
    /// record belongs to.
    #[must_use]
    pub(crate) fn ca_object_for_kind(&self, kind: ObjectKind) -> Option<&CaObject> {
        match kind {
            ObjectKind::Ca(idx) | ObjectKind::Trust(idx) => self.ca_objects.get(idx),
            ObjectKind::Certificate
            | ObjectKind::PrivateKey
            | ObjectKind::PublicKey
            | ObjectKind::Profile => None,
        }
    }

    /// Check whether the object corresponding to `kind` exists on this token.
    #[must_use]
    pub(crate) fn object_exists(&self, kind: ObjectKind) -> bool {
        match kind {
            ObjectKind::Certificate
            | ObjectKind::PublicKey
            | ObjectKind::PrivateKey
            | ObjectKind::Profile => true,
            ObjectKind::Ca(idx) | ObjectKind::Trust(idx) => idx < self.ca_objects.len(),
        }
    }

    /// Return all object kinds currently present on this token: the
    /// three authentication objects, the profile object, then each CA
    /// certificate, then each CA certificate's trust record.
    #[must_use]
    pub(crate) fn all_object_kinds(&self) -> Vec<ObjectKind> {
        let mut kinds = vec![
            ObjectKind::Certificate,
            ObjectKind::PublicKey,
            ObjectKind::PrivateKey,
            ObjectKind::Profile,
        ];
        for idx in 0..self.ca_objects.len() {
            kinds.push(ObjectKind::Ca(idx));
        }
        for idx in 0..self.ca_objects.len() {
            kinds.push(ObjectKind::Trust(idx));
        }
        kinds
    }

    /// Test whether an object matches every `(type, value)` pair in a
    /// `C_FindObjects` template. A template entry matches only when
    /// the attribute is present, concrete, and byte-equal; a
    /// sensitive or absent attribute never matches.
    #[must_use]
    pub(crate) fn matches(
        &self,
        kind: ObjectKind,
        template: &[(CkAttributeType, Vec<u8>)],
    ) -> bool {
        if !self.object_exists(kind) {
            return false;
        }
        template.iter().all(|(attr, wanted)| {
            self.attribute(kind, *attr)
                .is_some_and(|val| val.as_bytes() == Some(wanted.as_slice()))
        })
    }
}

/// Resolve the filesystem directory used for caching on-card CA certificates.
///
/// The cache only ever holds certificates read from a card (`EF.4336`,
/// `EF.4334`); the module ships none. It lets a later session, and the
/// phone-served token, present the CA certificates without a card read.
///
/// Cache-directory integrity relies on the OS user profile's access control
/// lists (ACLs) to prevent unauthorized modification of cached CA certificates
/// by other users. Local attackers possessing access to the user profile are
/// out of scope.
fn persistent_ca_dir() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("REFINEID_CA_CACHE_DIR")
        && !dir.is_empty()
    {
        return Some(std::path::PathBuf::from(dir));
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA")
            && !local_app_data.is_empty()
        {
            return Some(
                std::path::PathBuf::from(local_app_data)
                    .join("refineid")
                    .join("ca-certificates"),
            );
        }
        if let Ok(app_data) = std::env::var("APPDATA")
            && !app_data.is_empty()
        {
            return Some(
                std::path::PathBuf::from(app_data)
                    .join("refineid")
                    .join("ca-certificates"),
            );
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME")
            && !home.is_empty()
        {
            return Some(
                std::path::PathBuf::from(home).join("Library/Caches/fi.refineid/ca-certificates"),
            );
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(xdg_cache) = std::env::var("XDG_CACHE_HOME")
            && !xdg_cache.is_empty()
        {
            return Some(
                std::path::PathBuf::from(xdg_cache)
                    .join("refineid")
                    .join("ca-certificates"),
            );
        }
        if let Ok(home) = std::env::var("HOME")
            && !home.is_empty()
        {
            return Some(std::path::PathBuf::from(home).join(".cache/refineid/ca-certificates"));
        }
    }
    None
}

const MAX_CA_CERTS: usize = 16;
const MAX_CA_CERT_BYTES: u64 = 65536;

/// Check if an X.509 certificate's validity window is currently valid (fail closed).
fn is_cert_valid(cert: &OwnedCert) -> bool {
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return false;
    };
    let view = cert.view();
    view.not_before.unix_duration() <= now && now <= view.not_after.unix_duration()
}

/// Check if an X.509 certificate asserts certificate authority status (either via `BasicConstraints` CA:TRUE or self-signed).
fn is_ca_cert(cert: &OwnedCert) -> bool {
    let view = cert.view();
    if let Some(exts) = view.extensions
        && refineid_lib_core::x509::extract_basic_constraints(exts).ca
    {
        return true;
    }
    view.subject.as_der() == view.issuer.as_der()
}

/// Check if a certificate meets the persistence policy: unexpired and asserts CA status.
fn meets_ca_persistence_policy(cert: &OwnedCert) -> bool {
    is_cert_valid(cert) && is_ca_cert(cert)
}

/// Load persisted CA certificates from a directory, purging any expired, oversized, or non-CA ones.
fn load_persisted_ca_certs_from(dir: &std::path::Path) -> Vec<OwnedCert> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("der"))
        })
        .collect();
    paths.sort();

    let mut certs = Vec::new();
    for path in paths {
        if certs.len() >= MAX_CA_CERTS {
            break;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() || metadata.len() > MAX_CA_CERT_BYTES {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.len() > usize::try_from(MAX_CA_CERT_BYTES).unwrap_or(usize::MAX) {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let Ok(cert) = OwnedCert::from_der(UnvalidatedCertificate::new(bytes)) else {
            let _ = std::fs::remove_file(&path);
            continue;
        };
        if !meets_ca_persistence_policy(&cert) {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        certs.push(cert);
    }
    certs
}

/// Load persisted CA certificates from disk.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling state module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn load_persisted_ca_certs() -> Vec<OwnedCert> {
    persistent_ca_dir().map_or_else(Vec::new, |dir| load_persisted_ca_certs_from(&dir))
}

/// Persist a policy-conformant CA certificate to a specific directory.
fn persist_ca_cert_to(dir: &std::path::Path, cert: &OwnedCert) {
    if !meets_ca_persistence_policy(cert) {
        return;
    }
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let der = cert.as_der();
    let fingerprint = Sha256::of(der);
    let hex_name = hex::encode(fingerprint.as_bytes());
    let final_path = dir.join(format!("{hex_name}.der"));
    if final_path.exists() {
        return;
    }
    let temp_name = format!(".{hex_name}.tmp.{}", std::process::id());
    let temp_path = dir.join(temp_name);
    let write_res = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .and_then(|mut f| {
            f.write_all(der)?;
            f.flush()
        });
    if write_res.is_ok() {
        if std::fs::rename(&temp_path, &final_path).is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
    } else {
        let _ = std::fs::remove_file(&temp_path);
    }
}

/// Persist a policy-conformant CA certificate to disk.
fn persist_ca_cert(cert: &OwnedCert) {
    if let Some(dir) = persistent_ca_dir() {
        persist_ca_cert_to(&dir, cert);
    }
}

/// Attempt to read and parse an optional CA certificate from a card slot.
///
/// Returns `Some(OwnedCert)` when the slot is populated on the card profile
/// and contains a valid DER X.509 certificate; returns `None` when the slot
/// is absent on older card generations or unreadable.
fn read_optional_ca_cert(card: &mut PcscCard, slot: CertSlot) -> Option<OwnedCert> {
    let raw = match card.read_certificate(slot) {
        Ok(raw) => raw,
        Err(_read_err) => return None,
    };
    OwnedCert::from_der(UnvalidatedCertificate::new(raw.into_bytes())).ok()
}

/// Build the token objects for `reader_name`: open the card once,
/// read EF.TokenInfo (chip serial, card label), the authentication
/// certificate via the PKCS#15 chain and the CA certificates in
/// [`ON_CARD_CA_SLOTS`], drop the card, and parse.
///
/// A missing or unreadable EF.TokenInfo is tolerated (empty
/// serial / label); the certificate read is mandatory. A CA slot that
/// is absent or unreadable is skipped; one that parses as an unexpired
/// CA certificate is presented, with its trust record, and written to
/// the per-user cache.
///
/// # Errors
/// [`CKR_DEVICE_ERROR`] if the reader cannot be opened or the
/// certificate cannot be read or parsed.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling state module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn build_token_objects(reader_name: &str) -> Result<TokenObjects, CkRv> {
    let backend = PcscBackend;
    let reader = ReaderId::new(reader_name.to_owned());
    let mut card = backend
        .open_session(&reader, ReaderAccessCap::Read)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    let token_info = card.read_token_info().ok();
    let serial = token_info
        .as_ref()
        .and_then(|info| info.serial_number_hex.clone())
        .map(render_token_serial)
        .map(|full| {
            derive_printed_serial(&full).map_or_else(
                || full.as_str().to_owned(),
                |printed| printed.as_str().to_owned(),
            )
        });
    let cert = card
        .read_certificate(CertSlot::Authentication)
        .or_else(|_| card.read_certificate(CertSlot::AuthenticationAlt))
        .map_err(|_read_err| CKR_DEVICE_ERROR)?;

    let mut cas = load_persisted_ca_certs();
    let on_card_cas: Vec<OwnedCert> = ON_CARD_CA_SLOTS
        .iter()
        .filter_map(|slot| read_optional_ca_cert(&mut card, *slot))
        .filter(meets_ca_persistence_policy)
        .collect();
    for ca in &on_card_cas {
        persist_ca_cert(ca);
    }
    for ca in on_card_cas {
        if !cas.iter().any(|c| c.as_der() == ca.as_der()) {
            cas.push(ca);
        }
    }
    drop(card);

    let mut objects = TokenObjects::from_cert_der(cert.into_bytes())?;
    if let Some(serial) = serial {
        objects.token_serial = serial;
    }
    for ca in cas {
        objects.push_ca_cert(ca);
    }
    Ok(objects)
}

/// Build token objects for a remote RAPP token from its authentication certificate DER.
///
/// Loads the persisted CA certificates so remote tokens carry the same
/// trust anchors as local card tokens.
#[cfg_attr(
    not(windows),
    expect(
        dead_code,
        reason = "remote token objects helper is only invoked by windows remote RAPP pairing dispatch"
    )
)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling state module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn remote_token_objects(
    cert_der: Vec<u8>,
    serial: String,
) -> Result<TokenObjects, CkRv> {
    let mut objects = TokenObjects::from_cert_der(cert_der)?;
    objects.set_token_serial(serial);
    for ca in load_persisted_ca_certs() {
        objects.push_ca_cert(ca);
    }
    Ok(objects)
}

/// Probe the live PIN1 retry state without consuming a retry.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn card_pin1_status(reader_name: &str) -> Result<PinStatus, CkRv> {
    if reader_name.starts_with("rapp:") {
        return Ok(PinStatus::Verified);
    }
    let backend = PcscBackend;
    let reader = ReaderId::new(reader_name.to_owned());
    let mut card = backend
        .open_session(&reader, ReaderAccessCap::Read)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    card.select_pkcs15_application()
        .map_err(|_select_err| CKR_DEVICE_ERROR)?;
    card.pin_status(PinSlot::Pin1)
        .map_err(|_status_err| CKR_DEVICE_ERROR)
}

/// Run a signature on the card at `reader_name`.
///
/// Mirrors the proven FINEID chain: open the card, select the
/// PKCS#15 application, VERIFY PIN1 in that application context (the
/// card refuses VERIFY from MF context with `SW=6985`), then run the
/// pre-hashed PSO chain via [`sign_with_card`]. The card is dropped
/// before returning.
///
/// # Errors
/// [`CKR_PIN_INCORRECT`] / [`CKR_PIN_LOCKED`] on PIN failure,
/// [`CKR_DEVICE_ERROR`] on any card / transport failure, or the
/// mechanism-specific data errors from [`sign_with_card`].
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn card_sign(
    reader_name: &str,
    pin_cache: &Arc<Mutex<PinSafetyCache>>,
    mechanism: Mechanism,
    input: &[u8],
) -> Result<Vec<u8>, CkRv> {
    if let Some(hex_id) = reader_name.strip_prefix("rapp:") {
        return remote_card_sign(hex_id, mechanism, input);
    }
    let backend = PcscBackend;
    let reader = ReaderId::new(reader_name.to_owned());
    // PinSequence: the whole SELECT -> probe -> VERIFY -> PSO span
    // runs inside one held PC/SC transaction, so no concurrent
    // card consumer can interleave and disturb the security state
    // between our APDUs. The PIN is already in the cache -- no
    // prompt or non-card wait happens while the card is open.
    let mut card = backend
        .open_session(&reader, ReaderAccessCap::PinSequence)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    card.select_pkcs15_application()
        .map_err(|_select_err| CKR_DEVICE_ERROR)?;
    // A failed read is a transport failure: the held PIN 1 stays, and the
    // retry counter read before its next use decides (RAPP v26.11.2
    // section 11 item 2).
    let serial = live_token_serial(&mut card)?;
    let pin1_status = card
        .pin_status(PinSlot::Pin1)
        .map_err(|_status_err| CKR_DEVICE_ERROR)?;
    if let Err(error) = pin1_verify_guard(pin1_status) {
        clear_positive(pin_cache);
        return Err(error);
    }
    let checkout = pin_cache
        .lock()
        .map_err(|_poisoned| CKR_DEVICE_ERROR)?
        .checkout_pin1(&serial, pin1_status)
        .ok_or(CKR_USER_NOT_LOGGED_IN)?;

    // The held PIN 1 is presented to the card for every operation; the
    // card's verified state is never taken as lasting (credential custody).
    let outcome = card.verify_pin(PinSlot::Pin1, checkout.pin().clone());
    match outcome {
        Ok(VerifyOutcome::Ok) => {
            let mut cache = pin_cache.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?;
            checkout.restore_after_success(&mut cache);
            drop(cache);
            sign_with_card(&mut card, mechanism, input)
        }
        Ok(VerifyOutcome::WrongPin { .. }) => {
            pin_cache
                .lock()
                .map_err(|_poisoned| CKR_DEVICE_ERROR)?
                .record_rejected(&serial, PinSlot::Pin1, checkout.pin());
            Err(CKR_PIN_INCORRECT)
        }
        Ok(VerifyOutcome::Locked) => Err(CKR_PIN_LOCKED),
        Ok(VerifyOutcome::Other(_)) => Err(CKR_DEVICE_ERROR),
        Err(_transport) => {
            // The answer was lost: the PIN stays held for a retry counter
            // that shows the card did not refuse it.
            let mut cache = pin_cache.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?;
            checkout.restore_after_unanswered(&mut cache);
            Err(CKR_DEVICE_ERROR)
        }
    }
}

#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "helper for parsing DER lengths on Windows/tests")
)]
fn parse_der_len(der: &[u8], idx: &mut usize) -> Option<usize> {
    if *idx >= der.len() {
        return None;
    }
    let first = der[*idx];
    *idx += 1;
    if first & 0x80 == 0 {
        return Some(first as usize);
    }
    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 || *idx + num_bytes > der.len() {
        return None;
    }
    let mut len = 0usize;
    for _ in 0..num_bytes {
        len = (len << 8) | (der[*idx] as usize);
        *idx += 1;
    }
    Some(len)
}

/// Normalizes a remote ECDSA signature to IEEE P1363 (`r || s`).
///
/// RAPP v26.11.2 section 9.2 sends the fixed-width raw form, which may itself
/// begin with the DER sequence tag, so the raw length is checked before any
/// DER decoding; other lengths are accepted only as DER.
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "P1363 ECDSA conversion used on Windows/tests")
)]
#[must_use]
pub fn remote_ecdsa_to_p1363(signature: &[u8], field_bytes: usize) -> Option<Vec<u8>> {
    if signature.len() == field_bytes * 2 {
        Some(signature.to_vec())
    } else {
        ecdsa_der_to_p1363(signature, field_bytes)
    }
}

#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "P1363 ECDSA conversion used on Windows/tests")
)]
pub fn ecdsa_der_to_p1363(der: &[u8], field_bytes: usize) -> Option<Vec<u8>> {
    if field_bytes == 0 || der.is_empty() || der[0] != 0x30 {
        return None;
    }
    let mut idx = 1;
    let seq_len = parse_der_len(der, &mut idx)?;
    if idx + seq_len != der.len() {
        return None;
    }
    if idx >= der.len() || der[idx] != 0x02 {
        return None;
    }
    idx += 1;
    let r_len = parse_der_len(der, &mut idx)?;
    if idx + r_len > der.len() {
        return None;
    }
    let r_raw = &der[idx..idx + r_len];
    idx += r_len;

    if idx >= der.len() || der[idx] != 0x02 {
        return None;
    }
    idx += 1;
    let s_len = parse_der_len(der, &mut idx)?;
    if idx + s_len != der.len() {
        return None;
    }
    let s_raw = &der[idx..idx + s_len];

    let mut r_slice = r_raw;
    while r_slice.len() > 1 && r_slice[0] == 0 {
        r_slice = &r_slice[1..];
    }
    if r_slice.is_empty() || (r_slice.len() == 1 && r_slice[0] == 0) || r_slice.len() > field_bytes
    {
        return None;
    }

    let mut s_slice = s_raw;
    while s_slice.len() > 1 && s_slice[0] == 0 {
        s_slice = &s_slice[1..];
    }
    if s_slice.is_empty() || (s_slice.len() == 1 && s_slice[0] == 0) || s_slice.len() > field_bytes
    {
        return None;
    }

    let mut out = vec![0u8; field_bytes * 2];
    let r_pad = field_bytes - r_slice.len();
    out[r_pad..field_bytes].copy_from_slice(r_slice);

    let s_pad = field_bytes - s_slice.len();
    out[field_bytes + s_pad..field_bytes * 2].copy_from_slice(s_slice);

    Some(out)
}

/// The lifetime a remote operation is sent with (RAPP v26.11.2 section
/// 8.1 item 2).
#[cfg(windows)]
const REMOTE_OPERATION_LIFETIME_MS: u64 = 30_000;

/// How long one DNS-SD browse listens for the paired phone's session record.
#[cfg(windows)]
const REMOTE_BROWSE_WINDOW: core::time::Duration = core::time::Duration::from_secs(2);

#[cfg(windows)]
pub struct RemoteCardTransport {
    pub(crate) pair_id: refineid_rapp_core::ids::PairId,
}

#[cfg(windows)]
impl RemoteCardTransport {
    pub(crate) const fn new(pair_id: refineid_rapp_core::ids::PairId) -> Self {
        Self { pair_id }
    }

    /// Establishes a session transport to the paired custodian found by its
    /// session-mode discovery record, for this operation, a local consumer's
    /// request (RAPP v26.11.2 section 8.3). This computer only dials; it never
    /// listens.
    fn connect_session_transport(
        &self,
        store: &refineid_windows_credential_store::ProtectedPairingStore,
    ) -> Result<refineid_rapp_core::transport::TcpFrameTransport, String> {
        use refineid_rapp_core::store::PairingStore as _;

        let pairing = store
            .get(self.pair_id)
            .ok()
            .and_then(refineid_rapp_core::store::PairingRecord::serving_record)
            .ok_or_else(|| "the pairing serves nothing; pair again".to_owned())?;
        refineid_rapp_core::stream::dial_session(
            pairing,
            &[],
            REMOTE_BROWSE_WINDOW,
            refineid_rapp_core::stream::DialCause::ConsumerRequest,
        )
        // The stream reports the failed dial.
        .map_err(|_| "unable to reach the paired phone".to_owned())
    }

    pub(crate) fn execute_operation(
        &self,
        operation: &refineid_rapp_core::operations::CardOperation,
    ) -> Result<refineid_rapp_core::operations::CardOperationResult, String> {
        use refineid_rapp_core::engine::{
            OperationOutcome, Requester, RequesterConfig, SessionEnd, SessionError,
        };
        use refineid_rapp_core::message::{CloseReason, ResultError};

        let store =
            refineid_windows_credential_store::ProtectedPairingStore::load().map_err(|error| {
                refineid_dev_errors::report!(Pkcs11, "pairing store not loaded", error);
                format!("the pairing store cannot be loaded: {error}")
            })?;
        let transport = self.connect_session_transport(&store)?;
        let mut requester = Requester::new(RequesterConfig::this_computer(), store);

        // The phone's `pairing_revoked` close revokes the pairing in the
        // protected store the requester runs over (RAPP v26.11.2 section
        // 4.6 item 4), and the user is told to pair again.
        let mut session = match requester.connect(self.pair_id, transport) {
            Ok(session) => session,
            Err(SessionError::ClosedByPeer(CloseReason::PairingRevoked)) => {
                return Err("the phone forgot this computer; pair again".to_owned());
            }
            Err(error) => return Err(format!("session connect failed: {error}")),
        };

        let outcome = requester.execute(&mut session, operation, REMOTE_OPERATION_LIFETIME_MS);
        // A session the phone already closed is not closed again (section
        // 4.6 item 4).
        requester.disconnect(&mut session, CloseReason::UserDisconnect);
        if session.end() == Some(SessionEnd::PeerClose(CloseReason::PairingRevoked)) {
            return Err("the phone forgot this computer; pair again".to_owned());
        }

        match outcome.map_err(|e| format!("operation execute failed: {e}"))? {
            OperationOutcome::Completed(result) => Ok(result),
            OperationOutcome::Rejected(ResultError::UserCancelled) => {
                Err("operation was denied by the user on the remote device".into())
            }
            other => Err(format!("operation failed with outcome: {other:?}")),
        }
    }
}

fn remote_card_sign(hex_id: &str, mechanism: Mechanism, input: &[u8]) -> Result<Vec<u8>, CkRv> {
    #[cfg(windows)]
    {
        use refineid_agent_pipe::identity::{ProcessIdentity, computer_name};
        use refineid_agent_pipe::{RemoteKey, in_process_operation};
        use refineid_rapp_core::operations::{CardOperationResult, KeyProfile, SignatureAlgorithm};
        use refineid_windows_credential_store::ProtectedPairingStore;
        let store = ProtectedPairingStore::load().map_err(|_| CKR_DEVICE_ERROR)?;
        let pair = store
            .records()
            .iter()
            .find(|p| p.serves() && hex::encode(p.pair_id().as_bytes()) == hex_id)
            .ok_or(CKR_DEVICE_ERROR)?;

        let (key_profile, algorithm, digest) = match mechanism {
            Mechanism::Ecdsa => {
                let kp = pair
                    .authentication_certificate()
                    .and_then(|cert| {
                        let view = cert.view();
                        match view.spki.algorithm() {
                            PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => {
                                Some(KeyProfile::EcdsaP384)
                            }
                            PublicKeyAlgorithm::Ec(_) => Some(KeyProfile::EcdsaP256),
                            _ => None,
                        }
                    })
                    .unwrap_or(KeyProfile::EcdsaP384);

                let algo = match input.len() {
                    28 => SignatureAlgorithm::EcdsaSha224,
                    32 => SignatureAlgorithm::EcdsaSha256,
                    48 => SignatureAlgorithm::EcdsaSha384,
                    64 => SignatureAlgorithm::EcdsaSha512,
                    _ => return Err(CKR_DATA_LEN_RANGE),
                };
                (kp, algo, input.to_vec())
            }
            Mechanism::RsaPkcs => {
                let kp = pair
                    .authentication_certificate()
                    .and_then(|cert| {
                        let view = cert.view();
                        match view.spki.algorithm() {
                            PublicKeyAlgorithm::Rsa { modulus_bits } => {
                                if modulus_bits <= 2048 {
                                    Some(KeyProfile::Rsa2048)
                                } else {
                                    Some(KeyProfile::Rsa3072)
                                }
                            }
                            _ => None,
                        }
                    })
                    .unwrap_or(KeyProfile::Rsa3072);

                let algo = match input.len() {
                    32 => SignatureAlgorithm::RsaPkcs1Sha256,
                    48 => SignatureAlgorithm::RsaPkcs1Sha384,
                    64 => SignatureAlgorithm::RsaPkcs1Sha512,
                    _ => return Err(CKR_DATA_LEN_RANGE),
                };
                (kp, algo, input.to_vec())
            }
        };

        let image = ProcessIdentity::current()
            .map_err(|error| {
                refineid_dev_errors::report!(Pkcs11, "remote signature refused", error);
                CKR_DEVICE_ERROR
            })?
            .image;
        let op = in_process_operation(
            RemoteKey::Authentication,
            &image,
            &computer_name(),
            key_profile,
            algorithm,
            digest,
        )
        .map_err(|refusal| {
            refineid_dev_errors::report!(Pkcs11, "remote signature refused", refusal);
            CKR_DEVICE_ERROR
        })?;

        let remote_tx = RemoteCardTransport::new(pair.pair_id());
        // The engine reports why the operation failed.
        let result = remote_tx
            .execute_operation(&op)
            .map_err(|_| CKR_DEVICE_ERROR)?;

        match result {
            CardOperationResult::Signature(signature_bytes) => match mechanism {
                Mechanism::Ecdsa => {
                    remote_ecdsa_to_p1363(&signature_bytes, 48).ok_or(CKR_DEVICE_ERROR)
                }
                Mechanism::RsaPkcs => Ok(signature_bytes),
            },
            _ => Err(CKR_DEVICE_ERROR),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (hex_id, mechanism, input);
        Err(CKR_DEVICE_ERROR)
    }
}

/// Verify and cache a `C_Login` PIN only after the live card accepts it.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn card_login(
    reader_name: &str,
    pin_cache: &Arc<Mutex<PinSafetyCache>>,
    pin1: PinBytes,
) -> Result<(), CkRv> {
    if reader_name.starts_with("rapp:") {
        return Ok(());
    }
    let backend = PcscBackend;
    let reader = ReaderId::new(reader_name.to_owned());
    // PinSequence: SELECT -> probe -> VERIFY is one held
    // transaction; the PIN arrived with the call, so nothing
    // non-card happens while the card is open.
    let mut card = backend
        .open_session(&reader, ReaderAccessCap::PinSequence)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    card.select_pkcs15_application()
        .map_err(|_select_err| CKR_DEVICE_ERROR)?;
    let serial = live_token_serial(&mut card)?;
    let pin1_status = card
        .pin_status(PinSlot::Pin1)
        .map_err(|_status_err| CKR_DEVICE_ERROR)?;
    if let Err(error) = pin1_verify_guard(pin1_status) {
        clear_positive(pin_cache);
        return Err(error);
    }
    let mut cache = pin_cache.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?;
    if cache.is_rejected(&serial, PinSlot::Pin1, &pin1) {
        return Err(CKR_PIN_INCORRECT);
    }
    match card
        .verify_pin(PinSlot::Pin1, pin1.clone())
        .map_err(|_verify_err| CKR_DEVICE_ERROR)?
    {
        VerifyOutcome::Ok => {
            let stored = if pin1_status_permits_reusable_cache(pin1_status) {
                cache.store_pin1(serial, pin1)
            } else {
                cache.stage_pin1_once(serial, pin1)
            };
            stored.map_err(|_rejected| CKR_PIN_INCORRECT)
        }
        VerifyOutcome::WrongPin { .. } => {
            cache.record_rejected(&serial, PinSlot::Pin1, &pin1);
            drop(cache);
            Err(CKR_PIN_INCORRECT)
        }
        VerifyOutcome::Locked => Err(CKR_PIN_LOCKED),
        VerifyOutcome::Other(_sw) => Err(CKR_DEVICE_ERROR),
    }
}

/// Apply the retry floor to PIN 1 before any command that can spend a
/// PIN 1 attempt. A refusal below the floor or at a blocked PIN answers
/// `CKR_PIN_LOCKED`; a counter the card did not report answers
/// `CKR_DEVICE_ERROR`.
fn pin1_verify_guard(status: PinStatus) -> Result<(), CkRv> {
    check_retry_floor(PinSlot::Pin1.into(), status).map_err(|refusal| match refusal {
        RetryFloorRefusal::TriesBelowFloor { .. } | RetryFloorRefusal::Blocked { .. } => {
            refineid_dev_errors::report!(
                Pkcs11,
                "PIN 1 not tried",
                "the retry counter is below its floor"
            );
            CKR_PIN_LOCKED
        }
        RetryFloorRefusal::CounterUnreadable { .. } => {
            refineid_dev_errors::report!(
                Pkcs11,
                "PIN 1 not tried",
                "the retry counter is unreadable"
            );
            CKR_DEVICE_ERROR
        }
    })
}

fn live_token_serial(card: &mut PcscCard) -> Result<TokenSerial, CkRv> {
    card.read_token_info()
        .map_err(|_read_err| CKR_DEVICE_ERROR)?
        .serial_number_hex
        .map(render_token_serial)
        .filter(|serial| !serial.as_str().is_empty())
        .ok_or(CKR_DEVICE_ERROR)
}

fn clear_positive(pin_cache: &Arc<Mutex<PinSafetyCache>>) {
    if let Ok(mut cache) = pin_cache.lock() {
        cache.clear_positive();
    }
}

/// Change PIN1 on the card at `reader_name`.
///
/// Only compiled into the `pin-change` build; the default
/// (login-only) beta stubs `C_SetPIN`, so this has no caller there.
///
/// Mirrors [`card_sign`]'s proven chain: open the card, select the
/// PKCS#15 application (reference-data commands are refused from MF
/// context the same way VERIFY is), then run `CHANGE REFERENCE
/// DATA` with the current + new PIN pair in one command -- no prior
/// VERIFY is needed. The card is dropped before returning. On `Ok`
/// the card has reset the retry counter and cleared its PIN
/// presentation, so the caller must refresh any cached PIN1.
///
/// Typed inputs cross the boundary owned: [`ReaderId`] names the
/// reader and both PINs are consumed (their buffers zeroize on
/// drop), matching [`refineid_lib_core::auth::PinOps::change_pin`]. The
/// card's PIN 1 lengths are read first, and an entry of another length
/// is refused before the command.
///
/// # Errors
/// [`CKR_PIN_INCORRECT`] when the current PIN is wrong,
/// [`CKR_PIN_LOCKED`] when the slot is blocked,
/// [`CKR_PIN_LEN_RANGE`] on a length rejection (local policy or
/// card-side), [`CKR_DEVICE_ERROR`] on any card / transport failure.
#[cfg(feature = "pin-change")]
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is called from sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn card_change_pin1(
    reader: &ReaderId,
    current_pin1: PinBytes,
    new_pin1: PinBytes,
) -> Result<(), CkRv> {
    let backend = PcscBackend;
    // PinSequence: SELECT -> probe -> CHANGE REFERENCE DATA is one
    // held transaction; both PINs arrived with the call.
    let mut card = backend
        .open_session(reader, ReaderAccessCap::PinSequence)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    card.select_pkcs15_application()
        .map_err(|_select_err| CKR_DEVICE_ERROR)?;
    // The empty-body VERIFY probe consumes no retry. Apply the same
    // retry floor as login and signing before CHANGE REFERENCE DATA.
    let status = card
        .pin_status(PinSlot::Pin1)
        .map_err(|_probe_err| CKR_DEVICE_ERROR)?;
    pin1_verify_guard(status)?;
    let lengths = card
        .read_card_pin_lengths()
        .map_err(|_read_err| CKR_DEVICE_ERROR)?;
    let outcome = card
        .change_pin(&lengths, PinSlot::Pin1, current_pin1, new_pin1)
        .map_err(|change_err| match change_err {
            AuthError::PinPolicy(_reason) => CKR_PIN_LEN_RANGE,
            AuthError::Transport(_transport_err) => CKR_DEVICE_ERROR,
        })?;
    match outcome {
        ChangePinOutcome::Ok => Ok(()),
        ChangePinOutcome::WrongCurrentPin { .. } => Err(CKR_PIN_INCORRECT),
        ChangePinOutcome::Locked => Err(CKR_PIN_LOCKED),
        ChangePinOutcome::LengthError => Err(CKR_PIN_LEN_RANGE),
        ChangePinOutcome::Other(_sw) => Err(CKR_DEVICE_ERROR),
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "unit tests assert on fixed offsets of compile-time-known byte fixtures; production code stays panic-free."
)]
mod tests {
    #[test]
    fn raw_remote_signature_starting_with_the_der_tag_stays_raw() {
        let mut raw = vec![0x30u8];
        raw.extend(vec![0x5au8; 95]);
        assert_eq!(super::remote_ecdsa_to_p1363(&raw, 48), Some(raw));
    }

    use refineid_lib_core::apdu::status_word::PinRetries;
    use refineid_lib_core::auth::PinStatus;

    use super::{
        DER_LONG_FORM_ONE_OCTET, DER_TAG_INTEGER, DER_TAG_OCTET_STRING, OBJ_CERTIFICATE,
        OBJ_PRIVATE_KEY, OBJ_PROFILE, OBJ_PUBLIC_KEY, ObjectKind, OwnedCert,
        UnvalidatedCertificate, der_integer, der_octet_string, pin1_verify_guard,
    };
    use crate::ck::{CKR_DEVICE_ERROR, CKR_PIN_LOCKED};

    /// The synthetic self-signed P-384 CA of the RAPP mock pairing
    /// fixtures, standing in for a CA certificate read from a card.
    const MOCK_CA_DER: &[u8] = include_bytes!("../../refineid-rapp-cli/src/mock_ca.der");
    /// The synthetic P-384 leaf that CA issued, standing in for the
    /// card's authentication certificate.
    const MOCK_LEAF_DER: &[u8] = include_bytes!("../../refineid-rapp-cli/src/mock_cert.der");

    fn parse(der: &[u8]) -> OwnedCert {
        OwnedCert::from_der(UnvalidatedCertificate::new(der.to_vec())).expect("fixture parses")
    }

    fn token_objects() -> super::TokenObjects {
        super::TokenObjects::from_cert_der(MOCK_LEAF_DER.to_vec())
            .expect("token objects from the mock leaf")
    }

    /// Native-endian `CK_ULONG` bytes, the form a find template carries.
    fn ulong(value: crate::ck::CkUlong) -> Vec<u8> {
        value.to_ne_bytes().to_vec()
    }

    #[test]
    fn pin1_verify_guard_serves_five_four_three_and_refuses_the_rest() {
        const SERVED: [u8; 3] = [5, 4, 3];
        const REFUSED: [u8; 3] = [2, 1, 0];
        const UNMODELED_SW: u16 = 0x6F00;
        let retries = |count| {
            PinRetries::from_nibble(count).expect("test retry count fits the status-word nibble")
        };

        for count in SERVED {
            assert_eq!(
                pin1_verify_guard(PinStatus::Remaining(retries(count))),
                Ok(())
            );
        }
        for count in REFUSED {
            assert_eq!(
                pin1_verify_guard(PinStatus::Remaining(retries(count))),
                Err(CKR_PIN_LOCKED)
            );
        }
        assert_eq!(pin1_verify_guard(PinStatus::Verified), Ok(()));
        assert_eq!(pin1_verify_guard(PinStatus::Locked), Err(CKR_PIN_LOCKED));
        assert_eq!(pin1_verify_guard(PinStatus::NoInfo), Err(CKR_DEVICE_ERROR));
        assert_eq!(
            pin1_verify_guard(PinStatus::Other(UNMODELED_SW)),
            Err(CKR_DEVICE_ERROR)
        );
    }

    #[test]
    fn object_kind_handle_round_trip() {
        assert_eq!(
            ObjectKind::from_handle(OBJ_CERTIFICATE),
            Some(ObjectKind::Certificate)
        );
        assert_eq!(
            ObjectKind::from_handle(OBJ_PRIVATE_KEY),
            Some(ObjectKind::PrivateKey)
        );
        assert_eq!(
            ObjectKind::from_handle(OBJ_PUBLIC_KEY),
            Some(ObjectKind::PublicKey)
        );
        assert_eq!(
            ObjectKind::from_handle(OBJ_PROFILE),
            Some(ObjectKind::Profile)
        );
        assert_eq!(ObjectKind::from_handle(0), None);
        assert_eq!(ObjectKind::Certificate.handle(), OBJ_CERTIFICATE);
        assert_eq!(ObjectKind::PrivateKey.handle(), OBJ_PRIVATE_KEY);
        assert_eq!(ObjectKind::PublicKey.handle(), OBJ_PUBLIC_KEY);
        assert_eq!(ObjectKind::Profile.handle(), OBJ_PROFILE);
    }

    /// Trust handles follow the certificate handles by index; both
    /// ranges are [`super::MAX_CA_OBJECTS`] wide and end.
    #[test]
    fn trust_handle_round_trip_and_bounds() {
        let last = super::MAX_CA_OBJECTS - 1;
        assert_eq!(
            ObjectKind::Trust(0).handle(),
            super::OBJ_CA_BASE + super::handle_offset(super::MAX_CA_OBJECTS)
        );
        for kind in [
            ObjectKind::Ca(0),
            ObjectKind::Ca(last),
            ObjectKind::Trust(0),
            ObjectKind::Trust(1),
            ObjectKind::Trust(last),
        ] {
            assert_eq!(ObjectKind::from_handle(kind.handle()), Some(kind));
        }
        assert_eq!(
            ObjectKind::from_handle(ObjectKind::Trust(super::MAX_CA_OBJECTS).handle()),
            None
        );
        assert_eq!(
            ObjectKind::from_handle(
                super::OBJ_CA_BASE + super::handle_offset(super::CA_AND_TRUST_HANDLE_OFFSETS)
            ),
            None
        );
    }

    /// The token admits no more CA certificates than its handle range
    /// carries, so the last admitted certificate and its trust record
    /// are both reachable by handle and nothing beyond them exists.
    #[test]
    fn the_token_admits_no_more_ca_certificates_than_its_handle_range() {
        let mut objects = token_objects();
        // Distinct DER per variant: the last byte of the signature value
        // differs, which parsing does not check.
        for variant in 0..=super::MAX_CA_OBJECTS {
            let mut der = MOCK_CA_DER.to_vec();
            *der.last_mut().expect("non-empty DER") =
                u8::try_from(variant).expect("variant count fits a byte");
            objects.push_ca_cert(parse(&der));
        }
        let last = super::MAX_CA_OBJECTS - 1;
        assert_eq!(
            objects.all_object_kinds().len(),
            4 + super::CA_AND_TRUST_HANDLE_OFFSETS
        );
        for kind in [ObjectKind::Ca(last), ObjectKind::Trust(last)] {
            assert!(objects.object_exists(kind));
            assert_eq!(ObjectKind::from_handle(kind.handle()), Some(kind));
        }
        assert!(!objects.object_exists(ObjectKind::Ca(super::MAX_CA_OBJECTS)));
        assert!(!objects.object_exists(ObjectKind::Trust(super::MAX_CA_OBJECTS)));
    }

    /// The token presents, before and after CA certificates arrive, one
    /// profile object: a public, unmodifiable token object claiming the
    /// public-certificates profile and no other.
    #[test]
    fn the_profile_object_claims_public_certificates_only() {
        use crate::ck::{
            CK_FALSE, CK_TRUE, CKA_CLASS, CKA_LABEL, CKA_MODIFIABLE, CKA_PRIVATE, CKA_PROFILE_ID,
            CKA_TOKEN, CKO_PROFILE, CKP_AUTHENTICATION_TOKEN, CKP_PUBLIC_CERTIFICATES_TOKEN,
        };

        let mut objects = token_objects();
        let profile_class = [(CKA_CLASS, ulong(CKO_PROFILE))];
        let profiles = |objects: &super::TokenObjects| {
            objects
                .all_object_kinds()
                .into_iter()
                .filter(|kind| objects.matches(*kind, &profile_class))
                .collect::<Vec<_>>()
        };
        assert_eq!(profiles(&objects), vec![ObjectKind::Profile]);
        objects.push_ca_cert(parse(MOCK_CA_DER));
        assert_eq!(profiles(&objects), vec![ObjectKind::Profile]);

        let read = |attr| {
            objects
                .attribute(ObjectKind::Profile, attr)
                .and_then(|value| value.as_bytes().map(<[u8]>::to_vec))
        };
        assert_eq!(read(CKA_CLASS), Some(ulong(CKO_PROFILE)));
        assert_eq!(
            read(CKA_PROFILE_ID),
            Some(ulong(CKP_PUBLIC_CERTIFICATES_TOKEN))
        );
        assert_eq!(read(CKA_TOKEN), Some(vec![CK_TRUE]));
        assert_eq!(read(CKA_PRIVATE), Some(vec![CK_FALSE]));
        assert_eq!(read(CKA_MODIFIABLE), Some(vec![CK_FALSE]));
        assert_eq!(read(CKA_LABEL), None);

        // NSS's own search template, then the one profile this token
        // must never claim.
        let nss_template = [(CKA_TOKEN, vec![CK_TRUE]), (CKA_CLASS, ulong(CKO_PROFILE))];
        assert!(objects.matches(ObjectKind::Profile, &nss_template));
        let authentication_token = [(CKA_PROFILE_ID, ulong(CKP_AUTHENTICATION_TOKEN))];
        assert!(
            objects
                .all_object_kinds()
                .into_iter()
                .all(|kind| !objects.matches(kind, &authentication_token))
        );
    }

    /// Each CA certificate has exactly one trust record, found by the
    /// NSS trust class together with the certificate's issuer and
    /// serial number, the template of
    /// `nssToken_FindTrustForCertificate`. The record exists exactly
    /// while its certificate object does, answers the certificate's
    /// label and subject, and matches no other certificate's template.
    #[test]
    fn each_ca_certificate_has_one_trust_record_found_by_issuer_and_serial() {
        use crate::ck::{CKA_CLASS, CKA_ISSUER, CKA_LABEL, CKA_SERIAL_NUMBER, CKA_SUBJECT};

        let mut objects = token_objects();
        assert!(!objects.object_exists(ObjectKind::Trust(0)));
        // Two certificates with distinct serials under the same issuer.
        objects.push_ca_cert(parse(MOCK_CA_DER));
        objects.push_ca_cert(parse(MOCK_LEAF_DER));
        assert_eq!(
            objects.all_object_kinds(),
            vec![
                ObjectKind::Certificate,
                ObjectKind::PublicKey,
                ObjectKind::PrivateKey,
                ObjectKind::Profile,
                ObjectKind::Ca(0),
                ObjectKind::Ca(1),
                ObjectKind::Trust(0),
                ObjectKind::Trust(1),
            ]
        );
        assert!(!objects.object_exists(ObjectKind::Trust(2)));
        let bytes = |kind, attr| {
            objects
                .attribute(kind, attr)
                .and_then(|value| value.as_bytes().map(<[u8]>::to_vec))
                .expect("attribute present")
        };
        for (ca, trust) in [
            (ObjectKind::Ca(0), ObjectKind::Trust(0)),
            (ObjectKind::Ca(1), ObjectKind::Trust(1)),
        ] {
            let template = vec![
                (CKA_CLASS, bytes(trust, CKA_CLASS)),
                (CKA_ISSUER, bytes(ca, CKA_ISSUER)),
                (CKA_SERIAL_NUMBER, bytes(ca, CKA_SERIAL_NUMBER)),
            ];
            let found: Vec<ObjectKind> = objects
                .all_object_kinds()
                .into_iter()
                .filter(|kind| objects.matches(*kind, &template))
                .collect();
            assert_eq!(found, vec![trust]);
            assert_eq!(bytes(trust, CKA_LABEL), bytes(ca, CKA_LABEL));
            assert_eq!(bytes(trust, CKA_SUBJECT), bytes(ca, CKA_SUBJECT));
        }
    }

    /// A trust record is a public, unmodifiable token object of the
    /// NSS trust class carrying the digests of its certificate's DER
    /// and the card's trust: an anchor for client authentication and
    /// email, nothing asserted for server authentication and code
    /// signing, no step-up. It carries no certificate value or key id
    /// of its own, and the certificate object it belongs to claims no
    /// PKCS#11 trust bit.
    #[test]
    fn a_trust_record_marks_the_ca_for_client_auth_and_email_only() {
        use refineid_lib_core::crypto::digest::{Md5, Sha1};

        use crate::ck::{
            CK_FALSE, CK_TRUE, CKA_CLASS, CKA_ID, CKA_MODIFIABLE, CKA_NSS_CERT_MD5_HASH,
            CKA_NSS_CERT_SHA1_HASH, CKA_NSS_TRUST_CLIENT_AUTH, CKA_NSS_TRUST_CODE_SIGNING,
            CKA_NSS_TRUST_EMAIL_PROTECTION, CKA_NSS_TRUST_SERVER_AUTH,
            CKA_NSS_TRUST_STEP_UP_APPROVED, CKA_PRIVATE, CKA_TOKEN, CKA_TRUSTED, CKA_VALUE,
            CKO_NSS_TRUST, CKT_NSS_MUST_VERIFY_TRUST, CKT_NSS_TRUSTED_DELEGATOR,
        };

        let mut objects = token_objects();
        objects.push_ca_cert(parse(MOCK_CA_DER));
        let trust = ObjectKind::Trust(0);
        let attr = |attr| objects.attribute(trust, attr);
        assert_eq!(attr(CKA_CLASS), Some(super::ulong_attr(CKO_NSS_TRUST)));
        assert_eq!(attr(CKA_TOKEN), Some(super::bool_attr(CK_TRUE)));
        assert_eq!(attr(CKA_PRIVATE), Some(super::bool_attr(CK_FALSE)));
        assert_eq!(attr(CKA_MODIFIABLE), Some(super::bool_attr(CK_FALSE)));
        assert_eq!(
            attr(CKA_NSS_TRUST_STEP_UP_APPROVED),
            Some(super::bool_attr(CK_FALSE))
        );
        assert_eq!(
            attr(CKA_NSS_CERT_SHA1_HASH),
            Some(super::AttrValue::Borrowed(Sha1::of(MOCK_CA_DER).as_bytes()))
        );
        assert_eq!(
            attr(CKA_NSS_CERT_MD5_HASH),
            Some(super::AttrValue::Borrowed(Md5::of(MOCK_CA_DER).as_bytes()))
        );
        assert_eq!(
            attr(CKA_NSS_TRUST_CLIENT_AUTH),
            Some(super::ulong_attr(CKT_NSS_TRUSTED_DELEGATOR))
        );
        assert_eq!(
            attr(CKA_NSS_TRUST_EMAIL_PROTECTION),
            Some(super::ulong_attr(CKT_NSS_TRUSTED_DELEGATOR))
        );
        assert_eq!(
            attr(CKA_NSS_TRUST_SERVER_AUTH),
            Some(super::ulong_attr(CKT_NSS_MUST_VERIFY_TRUST))
        );
        assert_eq!(
            attr(CKA_NSS_TRUST_CODE_SIGNING),
            Some(super::ulong_attr(CKT_NSS_MUST_VERIFY_TRUST))
        );
        assert_eq!(attr(CKA_VALUE), None);
        assert_eq!(attr(CKA_ID), None);
        assert_eq!(
            objects.attribute(ObjectKind::Ca(0), CKA_TRUSTED),
            Some(super::bool_attr(CK_FALSE))
        );
    }

    #[test]
    fn empty_der_span_is_an_absent_attribute() {
        const EMPTY_SPAN: &[u8] = &[];
        const NON_EMPTY_SPAN: &[u8] = b"non-empty";
        assert_eq!(super::non_empty(EMPTY_SPAN), None);
        assert_eq!(super::non_empty(NON_EMPTY_SPAN), Some(NON_EMPTY_SPAN));
    }

    #[test]
    fn der_integer_short_form() {
        const TEST_SERIAL_BYTES: [u8; 3] = [1, 2, 3];
        let tlv = der_integer(&TEST_SERIAL_BYTES);
        let mut expected = Vec::with_capacity(TEST_SERIAL_BYTES.len().saturating_add(2));
        expected.push(DER_TAG_INTEGER);
        expected.push(u8::try_from(TEST_SERIAL_BYTES.len()).expect("test serial len fits in u8"));
        expected.extend_from_slice(&TEST_SERIAL_BYTES);
        assert_eq!(tlv, expected);
    }

    #[test]
    fn der_octet_string_short_form() {
        const TEST_OCTETS: &[u8] = b"sample-point-bytes";
        let tlv = der_octet_string(TEST_OCTETS);
        let mut expected = Vec::with_capacity(TEST_OCTETS.len().saturating_add(2));
        expected.push(DER_TAG_OCTET_STRING);
        expected.push(u8::try_from(TEST_OCTETS.len()).expect("test octet len fits in u8"));
        expected.extend_from_slice(TEST_OCTETS);
        assert_eq!(tlv, expected);
    }

    #[test]
    fn der_length_long_form_one_octet() {
        const TEST_PAYLOAD_LEN: usize = 200;
        const ZERO_BYTE: u8 = 0;
        const TAG_OVERHEAD_BYTES: usize = 1;
        const LENGTH_FLAG_BYTES: usize = 1;
        const LENGTH_VALUE_BYTES: usize = 1;
        const TOTAL_HEADER_BYTES: usize =
            TAG_OVERHEAD_BYTES + LENGTH_FLAG_BYTES + LENGTH_VALUE_BYTES;

        let body = vec![ZERO_BYTE; TEST_PAYLOAD_LEN];
        let tlv = der_octet_string(&body);
        assert_eq!(tlv[0], DER_TAG_OCTET_STRING);
        assert_eq!(tlv[1], DER_LONG_FORM_ONE_OCTET);
        assert_eq!(
            tlv[2],
            u8::try_from(TEST_PAYLOAD_LEN).expect("200 fits in u8")
        );
        assert_eq!(tlv.len(), TEST_PAYLOAD_LEN + TOTAL_HEADER_BYTES);
    }

    #[test]
    fn persistent_ca_roundtrip_and_pruning() {
        let unique_name = format!("refineid-test-ca-cache-pkcs11-{}", std::process::id());
        let temp_dir = std::env::temp_dir().join(unique_name);
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::create_dir_all(&temp_dir);

        let cert1 = parse(MOCK_CA_DER);
        assert!(super::meets_ca_persistence_policy(&cert1));
        super::persist_ca_cert_to(&temp_dir, &cert1);

        // Plant an unparseable / corrupted file to verify purging
        let corrupt_path = temp_dir.join("corrupt.der");
        let _ = std::fs::write(&corrupt_path, b"not-a-valid-der-certificate");

        // Plant an oversized file (> 64 KB) to verify purging
        let oversized_path = temp_dir.join("oversized.der");
        let oversized_len = usize::try_from(super::MAX_CA_CERT_BYTES).unwrap_or(usize::MAX) + 1;
        let _ = std::fs::write(&oversized_path, vec![0u8; oversized_len]);

        let loaded = super::load_persisted_ca_certs_from(&temp_dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].as_der(), cert1.as_der());

        // Corrupt and oversized files should have been purged
        assert!(!corrupt_path.exists());
        assert!(!oversized_path.exists());

        // A pushed CA certificate brings its trust record with it.
        let mut objects = token_objects();
        assert!(!objects.object_exists(ObjectKind::Ca(0)));

        objects.push_ca_cert(cert1);
        assert!(objects.object_exists(ObjectKind::Ca(0)));
        assert!(!objects.object_exists(ObjectKind::Ca(1)));
        assert_eq!(
            objects.all_object_kinds(),
            vec![
                ObjectKind::Certificate,
                ObjectKind::PublicKey,
                ObjectKind::PrivateKey,
                ObjectKind::Profile,
                ObjectKind::Ca(0),
                ObjectKind::Trust(0),
            ]
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn leaf_cert_rejected_by_ca_policy() {
        const LEAF_DER: &[u8] = MOCK_LEAF_DER;
        let leaf = parse(LEAF_DER);
        assert!(!super::is_ca_cert(&leaf));
        assert!(!super::meets_ca_persistence_policy(&leaf));

        let unique_name = format!("refineid-test-leaf-rejection-{}", std::process::id());
        let temp_dir = std::env::temp_dir().join(unique_name);
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::create_dir_all(&temp_dir);

        // Directly plant the leaf certificate DER in cache dir
        let leaf_path = temp_dir.join("leaf.der");
        std::fs::write(&leaf_path, LEAF_DER).expect("write leaf");

        let loaded = super::load_persisted_ca_certs_from(&temp_dir);
        assert!(loaded.is_empty());
        assert!(
            !leaf_path.exists(),
            "leaf certificate must be purged from cache"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn expired_ca_cert_purged_from_cache() {
        let mut expired_der = MOCK_CA_DER.to_vec();
        // Replace 360904092249Z (2036) with 200101000000Z (2020)
        let pos = expired_der
            .windows(13)
            .position(|w| w == b"360904092249Z")
            .expect("notAfter found in mock CA");
        expired_der[pos..pos + 13].copy_from_slice(b"200101000000Z");

        let expired_cert = OwnedCert::from_der(UnvalidatedCertificate::new(expired_der.clone()))
            .expect("valid DER structure");
        assert!(super::is_ca_cert(&expired_cert));
        assert!(!super::is_cert_valid(&expired_cert));
        assert!(!super::meets_ca_persistence_policy(&expired_cert));

        let unique_name = format!("refineid-test-expired-purge-{}", std::process::id());
        let temp_dir = std::env::temp_dir().join(unique_name);
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::create_dir_all(&temp_dir);

        let expired_path = temp_dir.join("expired.der");
        std::fs::write(&expired_path, &expired_der).expect("write expired CA");

        let loaded = super::load_persisted_ca_certs_from(&temp_dir);
        assert!(loaded.is_empty());
        assert!(
            !expired_path.exists(),
            "expired CA must be purged from cache"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
