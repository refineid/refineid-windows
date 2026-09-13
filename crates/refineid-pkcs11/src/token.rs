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
//! A FINEID token exposes exactly three objects for Firefox / NSS
//! client-cert TLS: the authentication certificate
//! ([`ObjectKind::Certificate`], handle [`OBJ_CERTIFICATE`]), its
//! public key ([`ObjectKind::PublicKey`], handle [`OBJ_PUBLIC_KEY`],
//! for consumers such as p11tool / libp11 that enumerate public
//! keys), and its auth private key ([`ObjectKind::PrivateKey`],
//! handle [`OBJ_PRIVATE_KEY`]). All carry the same
//! [`crate::ck::CKA_ID`] so NSS pairs them.
//!
//! The card is opened only for the moment it takes to read the
//! certificate or run a signature, then dropped -- this module never
//! holds a PC/SC handle across PKCS#11 calls, so the desktop CLI
//! shares the reader.

use std::sync::{Arc, Mutex};

#[cfg(feature = "pin-change")]
use refineid_lib_core::auth::ChangePinOutcome;
use refineid_lib_core::auth::{PinOps as _, PinSlot, PinStatus, VerifyOutcome};
use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend as _, ReaderId};
use refineid_lib_core::crypto::container::{EcdsaP384, RsaPkcs1Sha256, Signature};
use refineid_lib_core::crypto::digest::{Sha1, Sha224, Sha256, Sha384, Sha512};
use refineid_lib_core::identity::{TokenSerial, derive_printed_serial, render_token_serial};
use refineid_lib_core::pin::PinBytes;
use refineid_lib_core::pin_cache::PinSafetyCache;
use refineid_lib_core::pin_retry_risk::{PinRetryRisk, pin1_status_permits_reusable_cache};
use refineid_lib_core::pkcs15::{CertSlot, Pkcs15Ops as _};
use refineid_lib_core::x509::{EcCurve, OwnedCert, PublicKeyAlgorithm, extract_rsa_public_key};
use refineid_lib_pcsc::{PcscBackend, PcscCard};

#[cfg(feature = "pin-change")]
use crate::ck::CKR_PIN_LEN_RANGE;
use crate::ck::{
    CK_CERTIFICATE_CATEGORY_AUTHORITY, CK_CERTIFICATE_CATEGORY_TOKEN_USER, CK_FALSE, CK_TRUE,
    CKA_ALWAYS_AUTHENTICATE, CKA_ALWAYS_SENSITIVE, CKA_CERTIFICATE_CATEGORY, CKA_CERTIFICATE_TYPE,
    CKA_CLASS, CKA_DERIVE, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_ID,
    CKA_ISSUER, CKA_KEY_TYPE, CKA_LABEL, CKA_LOCAL, CKA_MODULUS, CKA_MODULUS_BITS,
    CKA_NEVER_EXTRACTABLE, CKA_PRIVATE, CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_SERIAL_NUMBER,
    CKA_SIGN, CKA_SIGN_RECOVER, CKA_SUBJECT, CKA_TOKEN, CKA_TRUSTED, CKA_UNWRAP, CKA_VALUE,
    CKA_VERIFY, CKA_WRAP, CKC_X_509, CKK_EC, CKK_RSA, CKO_CERTIFICATE, CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_OK,
    CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE,
    CKR_USER_NOT_LOGGED_IN, CkAttributeType, CkBbool, CkObjectHandle, CkRv, CkUlong,
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
/// Object handles for the embedded DVV intermediate and root CA certificates.
pub const OBJ_CA_CITIZEN_G4E: CkObjectHandle = 4;
pub const OBJ_CA_CITIZEN_G4R: CkObjectHandle = 5;
pub const OBJ_CA_CITIZEN_G3: CkObjectHandle = 6;
pub const OBJ_CA_ORG_G4R: CkObjectHandle = 7;
pub const OBJ_CA_ROOT_ECC: CkObjectHandle = 8;
pub const OBJ_CA_ROOT_RSA: CkObjectHandle = 9;

/// SHA-256 fingerprint constants for authentic DVV intermediate and root CA certificates.
/// Citing DVV (Digital and Population Data Services Agency) published certificate profiles
/// and test fixtures in `crates/refineid-pkcs11/ca-certs/*.der`:
/// - DVV Citizen Certificates - G4E (`fineid-intermediate-01-citizen-g4e.der`)
/// - DVV Citizen Certificates - G4R (`fineid-intermediate-02-citizen-g4r.der`)
/// - VRK Gov. CA for Citizen Certificates - G3 (`fineid-intermediate-00-citizen-g3.der`)
/// - DVV Organisational Certificates - G4R (`fineid-intermediate-03-organisation-g4r.der`)
/// - DVV Gov. Root CA - G3 ECC (`dvv-gov-root-ca-g3-ecc.der`)
/// - DVV Gov. Root CA - G3 RSA (`dvv-gov-root-ca-g3-rsa.der`)
const PINNED_DVV_CA_CITIZEN_G4E: [u8; 32] = [
    0xaa, 0xd1, 0xbe, 0xac, 0x46, 0x96, 0x10, 0x2a, 0x88, 0xbf, 0x9d, 0x51, 0x8d, 0x64, 0xf8, 0xb0,
    0x14, 0xf7, 0x8f, 0x9b, 0x15, 0x25, 0x79, 0xc9, 0x59, 0x99, 0x83, 0x13, 0x19, 0x79, 0x24, 0xd7,
];
const PINNED_DVV_CA_CITIZEN_G4R: [u8; 32] = [
    0x21, 0x76, 0xc0, 0x5e, 0x69, 0xee, 0x24, 0x94, 0x6a, 0x14, 0x0d, 0x13, 0xf9, 0xef, 0xa2, 0x22,
    0xb3, 0xf1, 0xe7, 0x68, 0xe1, 0xe2, 0xa6, 0x7b, 0x31, 0x39, 0x69, 0xcc, 0x03, 0xb8, 0x20, 0x64,
];
const PINNED_DVV_CA_CITIZEN_G3: [u8; 32] = [
    0x39, 0xa8, 0x35, 0xb1, 0x4b, 0x6b, 0x63, 0x13, 0xf7, 0x78, 0x37, 0x1c, 0x79, 0xcb, 0x43, 0x4d,
    0xd5, 0x18, 0xc8, 0xfd, 0x32, 0x5b, 0x74, 0x9d, 0x9b, 0xe6, 0x69, 0xdf, 0xf2, 0x03, 0x84, 0xe8,
];
const PINNED_DVV_CA_ORG_G4R: [u8; 32] = [
    0xdf, 0xc3, 0xe9, 0x65, 0x17, 0x6f, 0x88, 0x3a, 0x9c, 0xf0, 0xf6, 0x8c, 0xea, 0xee, 0xab, 0x66,
    0x3e, 0xdf, 0xd8, 0xe7, 0x9d, 0xe3, 0x29, 0x43, 0x73, 0xc2, 0x8a, 0x85, 0x69, 0x84, 0x00, 0x6f,
];
const PINNED_DVV_CA_ROOT_ECC: [u8; 32] = [
    0x55, 0x46, 0xa5, 0x25, 0x04, 0xfb, 0xa7, 0x4f, 0x61, 0xff, 0xd4, 0x89, 0x00, 0x67, 0x52, 0x9a,
    0xde, 0x3b, 0x9c, 0x9d, 0x07, 0xe5, 0x02, 0x59, 0x28, 0x31, 0xcc, 0xda, 0x9b, 0x36, 0x9f, 0xd3,
];
const PINNED_DVV_CA_ROOT_RSA: [u8; 32] = [
    0xd3, 0xed, 0x3f, 0xc4, 0x0a, 0xd2, 0x6b, 0x52, 0xe0, 0x01, 0xe1, 0xe1, 0x8f, 0x4b, 0x94, 0x49,
    0x52, 0x9d, 0xeb, 0x75, 0xa8, 0x1d, 0x5e, 0xb6, 0x80, 0xd7, 0xb6, 0x2d, 0xb2, 0x3b, 0xa9, 0x6d,
];

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

/// Which of the token's three objects an attribute query refers to.
///
/// HARD LIMIT: never add a `CKO_PROFILE` object (or any object
/// answering `CKA_PROFILE_ID` = `CKP_AUTHENTICATION_TOKEN`). NSS
/// reads that profile as permission to log in proactively and
/// prompts for PIN1 at Firefox startup, before the user asked for
/// anything -- a blocker-severity regression when it was tried
/// (eager PIN1 from `CKP_AUTHENTICATION_TOKEN`). PIN prompts must
/// appear only when a TLS handshake actually needs the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// The X.509 authentication certificate ([`CKO_CERTIFICATE`]).
    Certificate,
    /// The authentication public key ([`CKO_PUBLIC_KEY`]), from the
    /// certificate SPKI.
    PublicKey,
    /// The authentication private key ([`CKO_PRIVATE_KEY`]).
    PrivateKey,
    /// Pinned DVV CA: DVV Citizen Certificates - G4E
    CaCitizenG4e,
    /// Pinned DVV CA: DVV Citizen Certificates - G4R
    CaCitizenG4r,
    /// Pinned DVV CA: VRK Gov. CA for Citizen Certificates - G3
    CaCitizenG3,
    /// Pinned DVV CA: DVV Organisational Certificates - G4R
    CaOrgG4r,
    /// Pinned DVV CA: DVV Gov. Root CA - G3 ECC
    CaRootEcc,
    /// Pinned DVV CA: DVV Gov. Root CA - G3 RSA
    CaRootRsa,
}

impl ObjectKind {
    /// SHA-256 fingerprint for authentic pinned DVV CA certificates.
    #[must_use]
    pub(crate) const fn pinned_ca_fingerprint(self) -> Option<&'static [u8; 32]> {
        match self {
            Self::CaCitizenG4e => Some(&PINNED_DVV_CA_CITIZEN_G4E),
            Self::CaCitizenG4r => Some(&PINNED_DVV_CA_CITIZEN_G4R),
            Self::CaCitizenG3 => Some(&PINNED_DVV_CA_CITIZEN_G3),
            Self::CaOrgG4r => Some(&PINNED_DVV_CA_ORG_G4R),
            Self::CaRootEcc => Some(&PINNED_DVV_CA_ROOT_ECC),
            Self::CaRootRsa => Some(&PINNED_DVV_CA_ROOT_RSA),
            Self::Certificate | Self::PrivateKey | Self::PublicKey => None,
        }
    }

    /// Resolve a fixed object handle to its kind, or `None` when the
    /// handle names no object this token exposes.
    #[must_use]
    pub(crate) const fn from_handle(handle: CkObjectHandle) -> Option<Self> {
        match handle {
            OBJ_CERTIFICATE => Some(Self::Certificate),
            OBJ_PRIVATE_KEY => Some(Self::PrivateKey),
            OBJ_PUBLIC_KEY => Some(Self::PublicKey),
            OBJ_CA_CITIZEN_G4E => Some(Self::CaCitizenG4e),
            OBJ_CA_CITIZEN_G4R => Some(Self::CaCitizenG4r),
            OBJ_CA_CITIZEN_G3 => Some(Self::CaCitizenG3),
            OBJ_CA_ORG_G4R => Some(Self::CaOrgG4r),
            OBJ_CA_ROOT_ECC => Some(Self::CaRootEcc),
            OBJ_CA_ROOT_RSA => Some(Self::CaRootRsa),
            _ => None,
        }
    }

    /// The fixed object handle for this kind.
    #[must_use]
    pub(crate) const fn handle(self) -> CkObjectHandle {
        match self {
            Self::Certificate => OBJ_CERTIFICATE,
            Self::PrivateKey => OBJ_PRIVATE_KEY,
            Self::PublicKey => OBJ_PUBLIC_KEY,
            Self::CaCitizenG4e => OBJ_CA_CITIZEN_G4E,
            Self::CaCitizenG4r => OBJ_CA_CITIZEN_G4R,
            Self::CaCitizenG3 => OBJ_CA_CITIZEN_G3,
            Self::CaOrgG4r => OBJ_CA_ORG_G4R,
            Self::CaRootEcc => OBJ_CA_ROOT_ECC,
            Self::CaRootRsa => OBJ_CA_ROOT_RSA,
        }
    }

    /// All object kinds exposed by the token.
    pub(crate) const ALL: [Self; 9] = [
        Self::Certificate,
        Self::PublicKey,
        Self::PrivateKey,
        Self::CaCitizenG4e,
        Self::CaCitizenG4r,
        Self::CaCitizenG3,
        Self::CaOrgG4r,
        Self::CaRootEcc,
        Self::CaRootRsa,
    ];
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

/// A parsed and verified CA certificate object on the token.
#[derive(Debug, Clone)]
pub struct CaObject {
    cert: OwnedCert,
    id: Sha1,
    label: String,
    serial_der: Vec<u8>,
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
        Self {
            cert,
            id,
            label,
            serial_der,
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
    /// Intermediate and root CA certificate objects.
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

impl TokenObjects {
    /// Build token objects from the card's leaf authentication certificate
    /// DER bytes. Loads and verifies all embedded intermediate and root CA
    /// trust anchors.
    ///
    /// # Errors
    /// [`CKR_DEVICE_ERROR`] if the DER does not parse or the key
    /// algorithm is neither RSA nor secp384r1 EC (the only two FINEID
    /// auth profiles).
    pub(crate) fn from_cert_der(cert_der: Vec<u8>) -> Result<Self, CkRv> {
        let auth_cert = OwnedCert::from_der(cert_der).map_err(|_parse_err| CKR_DEVICE_ERROR)?;
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
        allow(dead_code, reason = "set_token_serial is used on Windows or in tests")
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
            ObjectKind::CaCitizenG4e
            | ObjectKind::CaCitizenG4r
            | ObjectKind::CaCitizenG3
            | ObjectKind::CaOrgG4r
            | ObjectKind::CaRootEcc
            | ObjectKind::CaRootRsa => {
                let ca = self.ca_object_for_kind(kind)?;
                Self::ca_object_attribute(ca, attr)
            }
        }
    }

    /// Attribute lookup for an authentic on-card CA certificate object.
    fn ca_object_attribute(ca: &CaObject, attr: CkAttributeType) -> Option<AttrValue<'_>> {
        let view = ca.cert.view();
        match attr {
            CKA_CLASS => Some(ulong_attr(CKO_CERTIFICATE)),
            CKA_CERTIFICATE_TYPE => Some(ulong_attr(CKC_X_509)),
            CKA_CERTIFICATE_CATEGORY => Some(ulong_attr(CK_CERTIFICATE_CATEGORY_AUTHORITY)),
            CKA_TOKEN | CKA_TRUSTED => Some(bool_attr(CK_TRUE)),
            CKA_PRIVATE => Some(bool_attr(CK_FALSE)),
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

    /// Append an on-card CA certificate to the token cache.
    pub(crate) fn push_ca_cert(&mut self, cert: OwnedCert) {
        if self
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

    /// Resolve a CA object matching the specific [`ObjectKind`]'s pinned fingerprint.
    #[must_use]
    pub(crate) fn ca_object_for_kind(&self, kind: ObjectKind) -> Option<&CaObject> {
        let wanted_fp = kind.pinned_ca_fingerprint()?;
        self.ca_objects.iter().find(|obj| {
            let fp = Sha256::of(obj.cert.as_der());
            fp.as_bytes() == wanted_fp
        })
    }

    /// Check whether the object corresponding to `kind` exists on this token.
    #[must_use]
    pub(crate) fn object_exists(&self, kind: ObjectKind) -> bool {
        match kind {
            ObjectKind::Certificate | ObjectKind::PublicKey | ObjectKind::PrivateKey => true,
            ObjectKind::CaCitizenG4e
            | ObjectKind::CaCitizenG4r
            | ObjectKind::CaCitizenG3
            | ObjectKind::CaOrgG4r
            | ObjectKind::CaRootEcc
            | ObjectKind::CaRootRsa => self.ca_object_for_kind(kind).is_some(),
        }
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
    view.not_before.unix_duration() <= now && now < view.not_after.unix_duration()
}

/// Check if a certificate is an authentic CA (matches a pinned DVV CA root or intermediate).
fn is_authentic_ca(cert: &OwnedCert) -> bool {
    let der = cert.as_der();
    let fp = Sha256::of(der);
    let fp_bytes = fp.as_bytes();
    [
        PINNED_DVV_CA_CITIZEN_G4E,
        PINNED_DVV_CA_CITIZEN_G4R,
        PINNED_DVV_CA_CITIZEN_G3,
        PINNED_DVV_CA_ORG_G4R,
        PINNED_DVV_CA_ROOT_ECC,
        PINNED_DVV_CA_ROOT_RSA,
    ]
    .iter()
    .any(|pinned| pinned == fp_bytes)
}

/// Load persisted CA certificates from a directory, purging any expired, oversized, or unauthentic ones.
fn load_persisted_ca_certs_from(dir: &std::path::Path) -> Vec<OwnedCert> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("der"))
        .collect();
    paths.sort();

    let mut certs = Vec::new();
    for path in paths.into_iter().take(MAX_CA_CERTS) {
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        if metadata.len() > MAX_CA_CERT_BYTES {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(cert) = OwnedCert::from_der(bytes) else {
            let _ = std::fs::remove_file(&path);
            continue;
        };
        if !is_cert_valid(&cert) || !is_authentic_ca(&cert) {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        certs.push(cert);
    }
    certs
}

/// Load persisted CA certificates from disk.
fn load_persisted_ca_certs() -> Vec<OwnedCert> {
    persistent_ca_dir().map_or_else(Vec::new, |dir| load_persisted_ca_certs_from(&dir))
}

/// Persist an authentic, unexpired CA certificate to a specific directory.
fn persist_ca_cert_to(dir: &std::path::Path, cert: &OwnedCert) {
    if !is_cert_valid(cert) || !is_authentic_ca(cert) {
        return;
    }
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let der = cert.as_der();
    let fingerprint = Sha256::of(der);
    let hex_name = hex::encode(fingerprint.as_bytes());
    let final_path = dir.join(format!("{hex_name}.der"));
    let temp_path = dir.join(format!(".{hex_name}.tmp.{}", std::process::id()));
    if std::fs::write(&temp_path, der).is_ok() {
        let _ = std::fs::rename(temp_path, final_path);
    }
}

/// Persist an authentic, unexpired CA certificate to disk.
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
    OwnedCert::from_der(raw.into_bytes()).ok()
}

/// Build the token objects for `reader_name`: open the card once,
/// read EF.TokenInfo (chip serial, card label) and the
/// authentication certificate via the PKCS#15 chain, drop the
/// card, and parse.
///
/// A missing or unreadable EF.TokenInfo is tolerated (empty
/// serial / label); the certificate read is mandatory.
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
    if cas.is_empty() {
        let on_card_cas: Vec<OwnedCert> = [CertSlot::IssuingCaEcc, CertSlot::RootCa]
            .into_iter()
            .filter_map(|slot| read_optional_ca_cert(&mut card, slot))
            .collect();
        for ca in &on_card_cas {
            persist_ca_cert(ca);
        }
        cas = on_card_cas;
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
    let serial = match live_token_serial(&mut card) {
        Ok(serial) => serial,
        Err(error) => {
            clear_positive(pin_cache);
            return Err(error);
        }
    };
    let pin1_status = match card.pin_status(PinSlot::Pin1) {
        Ok(status) => status,
        Err(_status_err) => {
            clear_positive(pin_cache);
            return Err(CKR_DEVICE_ERROR);
        }
    };
    if let Err(error) = pin1_verify_guard(pin1_status) {
        clear_positive(pin_cache);
        return Err(error);
    }
    let checkout = pin_cache
        .lock()
        .map_err(|_poisoned| CKR_DEVICE_ERROR)?
        .checkout_pin1(&serial)
        .ok_or(CKR_USER_NOT_LOGGED_IN)?;

    let is_verified = pin1_status == PinStatus::Verified;
    let outcome = if is_verified {
        // Citing FINEID S1 v4.2 §3.5: card is already in verified state and session holds authenticated PIN1
        match sign_with_card(&mut card, mechanism, input) {
            Ok(signature) => {
                let mut cache = pin_cache.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?;
                checkout.restore_after_success(&mut cache);
                return Ok(signature);
            }
            Err(CKR_DEVICE_ERROR) => {
                // Security not satisfied or session reset: fall back to VERIFY PIN1
                card.verify_pin(PinSlot::Pin1, checkout.pin().clone())
                    .map_err(|_verify_err| CKR_DEVICE_ERROR)
            }
            Err(e) => return Err(e),
        }
    } else {
        card.verify_pin(PinSlot::Pin1, checkout.pin().clone())
            .map_err(|_verify_err| CKR_DEVICE_ERROR)
    };

    match outcome {
        Ok(VerifyOutcome::Ok) => {
            let signature = sign_with_card(&mut card, mechanism, input)?;
            let mut cache = pin_cache.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?;
            checkout.restore_after_success(&mut cache);
            Ok(signature)
        }
        Ok(VerifyOutcome::WrongPin { .. }) => {
            pin_cache
                .lock()
                .map_err(|_poisoned| CKR_DEVICE_ERROR)?
                .record_rejected(&serial, PinSlot::Pin1, checkout.pin());
            Err(CKR_PIN_INCORRECT)
        }
        Ok(VerifyOutcome::Locked) => Err(CKR_PIN_LOCKED),
        Ok(VerifyOutcome::Other(_)) | Err(_) => Err(CKR_DEVICE_ERROR),
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

#[cfg(windows)]
pub struct RemoteCardTransport {
    pub(crate) pair_id: refineid_rapp_core::ids::PairId,
    pub(crate) pairing_record: refineid_rapp_core::store::PairingRecord,
}

#[cfg(windows)]
impl RemoteCardTransport {
    pub(crate) fn new(
        pair_id: refineid_rapp_core::ids::PairId,
        pairing_record: refineid_rapp_core::store::PairingRecord,
    ) -> Self {
        Self {
            pair_id,
            pairing_record,
        }
    }

    fn connect_session_transport(
        &self,
    ) -> Result<refineid_rapp_core::transport::TcpFrameTransport, String> {
        use core::time::Duration;
        use refineid_rapp_core::stream::{
            StreamAccept, StreamListener, StreamRendezvous, dial, discover_stream_endpoints,
            stream_rendezvous_name,
        };

        let dial_timeout = Duration::from_secs(5);
        let candidate_id = "stream-1";
        let service_name = stream_rendezvous_name(&self.pairing_record.rendezvous_token.0);

        crate::diag::diag!("connect_session_transport: discovering proxy for {service_name}...");
        // 1. Discover phone proxy endpoint via mDNS matching our pairing rendezvous token.
        let mut endpoints = discover_stream_endpoints(Some(&service_name), Duration::from_secs(2));
        crate::diag::diag!("connect_session_transport: discovered endpoints: {endpoints:?}");

        // 2. Add local mock proxy endpoint as fallback.
        let local_dial_endpoint = "127.0.0.1:47110";
        endpoints.push(local_dial_endpoint.to_owned());

        // 3. Dial discovered endpoints with our session rendezvous token.
        crate::diag::diag!("connect_session_transport: dialing endpoints {endpoints:?}...");
        match dial(
            &endpoints,
            candidate_id,
            dial_timeout,
            &StreamRendezvous::Session(self.pairing_record.rendezvous_token),
        ) {
            Ok(transport) => {
                crate::diag::diag!("connect_session_transport: dial succeeded!");
                return Ok(transport);
            }
            Err(err) => {
                crate::diag::diag!("connect_session_transport: dial failed: {err:?}");
            }
        }

        // 4. Fallback listener check for reverse-dial mock test harnesses (short timeout).
        let listen_timeout = Duration::from_millis(150);
        let listen_endpoint = "0.0.0.0:47110";
        if let Ok(listener) = StreamListener::bind(listen_endpoint, candidate_id, listen_timeout)
            && let Ok(Some(StreamAccept::Session {
                rendezvous_token,
                transport,
            })) = listener.accept_timeout(listen_timeout)
            && rendezvous_token == self.pairing_record.rendezvous_token
        {
            crate::diag::diag!("connect_session_transport: reverse dial accepted!");
            return Ok(transport);
        }

        Err("unable to reach paired proxy via mDNS dial or local fallback".into())
    }

    pub(crate) fn execute_operation(
        &self,
        operation: &refineid_rapp_core::operations::CardOperation,
    ) -> Result<refineid_rapp_core::operations::CardOperationResult, String> {
        use refineid_rapp_core::engine::{OperationOutcome, Requester, RequesterConfig};
        use refineid_rapp_core::message::CloseReason;
        use refineid_rapp_core::store::{MemoryJournal, MemoryPairingStore, PairingStore};

        let transport = self.connect_session_transport()?;
        let mut store = MemoryPairingStore::new();
        let _ = store.insert(self.pairing_record.clone());
        let mut requester = Requester::new(
            RequesterConfig {
                display_name: "RefineID PKCS#11".into(),
                platform: "Windows".into(),
            },
            store,
            MemoryJournal::new(),
        );

        let mut session = requester
            .connect(self.pair_id, transport)
            .map_err(|e| format!("session connect failed: {e:?}"))?;

        let outcome = requester
            .execute(&mut session, operation, 30_000)
            .map_err(|e| format!("operation execute failed: {e:?}"))?;

        requester.disconnect(&mut session, CloseReason::UserDisconnect);

        match outcome {
            OperationOutcome::Completed(result) => Ok(result),
            OperationOutcome::Denied => {
                Err("operation was denied by the user on the remote device".into())
            }
            other => Err(format!("operation failed with outcome: {other:?}")),
        }
    }
}

fn remote_card_sign(hex_id: &str, mechanism: Mechanism, input: &[u8]) -> Result<Vec<u8>, CkRv> {
    #[cfg(windows)]
    {
        use refineid_rapp_core::operations::{
            CardOperation, CardOperationResult, KeyProfile, SignatureAlgorithm,
        };
        use refineid_windows_credential_store::CredentialPairingStore;
        let store = CredentialPairingStore::load().map_err(|_| CKR_DEVICE_ERROR)?;
        let pair = store
            .records()
            .iter()
            .find(|p| hex::encode(p.pair_id.0) == hex_id)
            .cloned()
            .ok_or(CKR_DEVICE_ERROR)?;

        let (key_profile, algorithm, digest) = match mechanism {
            Mechanism::Ecdsa => {
                let kp = pair
                    .auth_cert
                    .as_ref()
                    .and_then(|der| {
                        let cert = OwnedCert::from_der(der.clone()).ok()?;
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
                    .auth_cert
                    .as_ref()
                    .and_then(|der| {
                        let cert = OwnedCert::from_der(der.clone()).ok()?;
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

        let op = CardOperation::BrowserAuthenticate {
            origin: "https://card.refineid.fi".into(),
            key_profile,
            algorithm,
            digest,
        };

        let remote_tx = RemoteCardTransport::new(pair.pair_id, pair);
        let result = remote_tx.execute_operation(&op).map_err(|err| {
            crate::diag::diag!("remote_card_sign execute_operation failed: {err}");
            CKR_DEVICE_ERROR
        })?;

        match result {
            CardOperationResult::Signature(signature_bytes) => match mechanism {
                Mechanism::Ecdsa => {
                    if signature_bytes.first() == Some(&0x30) {
                        ecdsa_der_to_p1363(&signature_bytes, 48).ok_or(CKR_DEVICE_ERROR)
                    } else if signature_bytes.len() == 96 {
                        Ok(signature_bytes)
                    } else {
                        Err(CKR_DEVICE_ERROR)
                    }
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
    let serial = match live_token_serial(&mut card) {
        Ok(serial) => serial,
        Err(error) => {
            clear_positive(pin_cache);
            return Err(error);
        }
    };
    let pin1_status = match card.pin_status(PinSlot::Pin1) {
        Ok(status) => status,
        Err(_status_err) => {
            clear_positive(pin_cache);
            return Err(CKR_DEVICE_ERROR);
        }
    };
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

/// Refuse every PIN-bearing APDU once fewer than three attempts remain.
/// Firefox does not surface retry warnings, so the module may consume
/// attempts down to two remaining and no further: a near-last attempt is
/// never `RefineID`'s to spend, and only another middleware locks the card.
/// Mirrors the `CryptoTokenKit` adapter's retry floor of three.
const fn pin1_verify_guard(status: PinStatus) -> Result<(), CkRv> {
    match status {
        PinStatus::Remaining(retries) => match PinRetryRisk::from_retries(retries) {
            Some(risk) if risk.permits_pkcs11() => Ok(()),
            Some(_) => Err(CKR_PIN_LOCKED),
            None => Err(CKR_DEVICE_ERROR),
        },
        PinStatus::Locked => Err(CKR_PIN_LOCKED),
        PinStatus::Verified => Ok(()),
        PinStatus::NoInfo | PinStatus::Other(_) => Err(CKR_DEVICE_ERROR),
    }
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
/// drop), matching [`refineid_lib_core::auth::PinOps::change_pin`].
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
    // consumer floor as login and signing before CHANGE REFERENCE DATA.
    let status = card
        .pin_status(PinSlot::Pin1)
        .map_err(|_probe_err| CKR_DEVICE_ERROR)?;
    pin1_verify_guard(status)?;
    let outcome = card
        .change_pin(PinSlot::Pin1, current_pin1, new_pin1)
        .map_err(|_change_err| CKR_DEVICE_ERROR)?;
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
    use refineid_lib_core::apdu::status_word::PinRetries;
    use refineid_lib_core::auth::PinStatus;

    use super::{
        DER_LONG_FORM_ONE_OCTET, DER_TAG_INTEGER, DER_TAG_OCTET_STRING, OBJ_CERTIFICATE,
        OBJ_PRIVATE_KEY, OBJ_PUBLIC_KEY, ObjectKind, OwnedCert, Sha256, der_integer,
        der_octet_string, pin1_verify_guard,
    };
    use crate::ck::{CKR_DEVICE_ERROR, CKR_PIN_LOCKED};

    #[test]
    fn pin1_verify_guard_blocks_only_one_and_two_attempts() {
        let retries = |count| {
            PinRetries::from_nibble(count).expect("test retry count fits the status-word nibble")
        };

        assert_eq!(pin1_verify_guard(PinStatus::Remaining(retries(5))), Ok(()));
        assert_eq!(pin1_verify_guard(PinStatus::Remaining(retries(4))), Ok(()));
        assert_eq!(pin1_verify_guard(PinStatus::Remaining(retries(3))), Ok(()));
        assert_eq!(
            pin1_verify_guard(PinStatus::Remaining(retries(2))),
            Err(CKR_PIN_LOCKED)
        );
        assert_eq!(
            pin1_verify_guard(PinStatus::Remaining(retries(1))),
            Err(CKR_PIN_LOCKED)
        );
        // Zero attempts passes the floor; the card itself then reports locked.
        assert_eq!(pin1_verify_guard(PinStatus::Remaining(retries(0))), Ok(()));
        assert_eq!(pin1_verify_guard(PinStatus::Locked), Err(CKR_PIN_LOCKED));
        assert_eq!(pin1_verify_guard(PinStatus::NoInfo), Err(CKR_DEVICE_ERROR));
        assert_eq!(
            pin1_verify_guard(PinStatus::Other(1)),
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
        assert_eq!(ObjectKind::from_handle(0), None);
        assert_eq!(ObjectKind::Certificate.handle(), OBJ_CERTIFICATE);
        assert_eq!(ObjectKind::PrivateKey.handle(), OBJ_PRIVATE_KEY);
        assert_eq!(ObjectKind::PublicKey.handle(), OBJ_PUBLIC_KEY);
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
        const TEST_CA_1_DER: &[u8] =
            include_bytes!("../ca-certs/fineid-intermediate-01-citizen-g4e.der");

        let unique_name = format!("refineid-test-ca-cache-pkcs11-{}", std::process::id());
        let temp_dir = std::env::temp_dir().join(unique_name);
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::create_dir_all(&temp_dir);

        let cert1 = OwnedCert::from_der(TEST_CA_1_DER).expect("valid cert1");
        super::persist_ca_cert_to(&temp_dir, &cert1);

        // Plant an unparseable / corrupted file to verify purging
        let corrupt_path = temp_dir.join("corrupt.der");
        let _ = std::fs::write(&corrupt_path, b"not-a-valid-der-certificate");

        // Plant an oversized file (> 64 KB) to verify purging
        let oversized_path = temp_dir.join("oversized.der");
        let _ = std::fs::write(&oversized_path, vec![0u8; 70000]);

        let loaded = super::load_persisted_ca_certs_from(&temp_dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].as_der(), cert1.as_der());

        // Corrupt and oversized files should have been purged
        assert!(!corrupt_path.exists());
        assert!(!oversized_path.exists());

        // Test object_exists and ca_object_for_kind
        let mut objects = super::TokenObjects::from_cert_der(TEST_CA_1_DER.to_vec())
            .expect("token objects from cert der");
        assert!(!objects.object_exists(ObjectKind::CaCitizenG4e));
        assert!(!objects.object_exists(ObjectKind::CaRootEcc));

        objects.push_ca_cert(cert1);
        assert!(objects.object_exists(ObjectKind::CaCitizenG4e));
        assert!(!objects.object_exists(ObjectKind::CaRootEcc));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn all_six_pinned_dvv_fingerprints_match_published_fixtures() {
        let fixtures: [(&[u8], [u8; 32]); 6] = [
            (
                include_bytes!("../ca-certs/fineid-intermediate-01-citizen-g4e.der"),
                super::PINNED_DVV_CA_CITIZEN_G4E,
            ),
            (
                include_bytes!("../ca-certs/fineid-intermediate-02-citizen-g4r.der"),
                super::PINNED_DVV_CA_CITIZEN_G4R,
            ),
            (
                include_bytes!("../ca-certs/fineid-intermediate-00-citizen-g3.der"),
                super::PINNED_DVV_CA_CITIZEN_G3,
            ),
            (
                include_bytes!("../ca-certs/fineid-intermediate-03-organisation-g4r.der"),
                super::PINNED_DVV_CA_ORG_G4R,
            ),
            (
                include_bytes!("../ca-certs/dvv-gov-root-ca-g3-ecc.der"),
                super::PINNED_DVV_CA_ROOT_ECC,
            ),
            (
                include_bytes!("../ca-certs/dvv-gov-root-ca-g3-rsa.der"),
                super::PINNED_DVV_CA_ROOT_RSA,
            ),
        ];

        for (der, expected_fp) in fixtures {
            let fp = Sha256::of(der);
            assert_eq!(fp.as_bytes(), &expected_fp);
        }
    }
}
