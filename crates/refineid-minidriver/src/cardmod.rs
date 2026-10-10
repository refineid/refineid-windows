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

//! Card Module (cardmod) implementation -- the body of the Windows
//! minidriver.
//!
//! Windows-only; declared `#[cfg(windows)]` from `lib.rs`. The
//! `CardXxx` entry points and the function-table wiring land in
//! later commits; this module starts with the data model (the
//! per-context state and the card-capability description the entry
//! points operate on).
#![expect(
    clippy::redundant_pub_crate,
    reason = "This private helper module still uses pub(crate) consistently for crate-internal minidriver state and capability types"
)]

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;

use crate::ffi::{
    AT_ECDSA_P256, AT_ECDSA_P384, AT_SIGNATURE, BYTE, CARD_DATA, CARD_DEFAULT_CONTAINER,
    CONTAINER_MAP_DEFAULT_CONTAINER, CONTAINER_MAP_RECORD, CONTAINER_MAP_VALID_CONTAINER, DWORD,
    MAX_CONTAINER_NAME_LEN, PBYTE, PVOID, ROLE_ADMIN, ROLE_USER, SCARD_E_NO_MEMORY,
    SCARD_E_UNSUPPORTED_FEATURE, SCARD_S_SUCCESS,
};
use crate::transport::CardSessionTransport;
use refineid_lib_core::sign::{KEY_REF_AUTH, KEY_REF_SIGN};
use refineid_lib_core::x509::{
    EcCurve, OwnedCert, PublicKeyAlgorithm, parse_subject_public_key_info,
};

/// Per-`CardAcquireContext` state, stored behind `CARD_DATA`'s
/// `pvVendorSpecific` for the life of the Card Module context.
pub(crate) struct Ctx {
    pub(crate) transport: Mutex<CardSessionTransport>,
    pub(crate) card: CardCapabilityModel,
    /// Whether PIN1 has been verified in this Card Module context.
    pub(crate) pin1_authenticated: bool,
    /// Whether PIN2 has been verified for the current operation.
    pub(crate) pin2_authenticated: bool,
}

/// PIN role IDs as the Base CSP addresses them. `ROLE_USER` /
/// `ROLE_ADMIN` are the ABI's user/admin roles; the qualified-
/// signature PIN gets the next free id (3).
const PIN_ID_AUTH: DWORD = ROLE_USER;
const PIN_ID_PUK: DWORD = ROLE_ADMIN;
const PIN_ID_QUALIFIED_SIG: DWORD = 3;

// Windows' Base Smart Card CSP/msclmd signing path parses characters
// 30..36 of the container name as a PIV certificate file tag before
// it calls into CardSignData. Keep 5fc10a (PIV digital-signature cert)
// at that offset so TLS client-auth key opens progress to PIN1/signing.
const AUTH_CONTAINER_GUID: &str = "{00000000-0000-0000-0000-000005fc10a0}";
const QUAL_SIG_CONTAINER_GUID: &str = "{7A6D5E7C-FE1D-4F1A-B8C2-FA1B1B7C3A02}";
const MAX_VIRTUAL_CONTAINERS: usize = 32;

/// Bounded buffer limits enforced at the ABI boundary so an
/// adversarial / malformed `CARD_DATA` can't drive an unbounded
/// read or allocation.
const MAX_ATR_LEN: usize = 33;
const MAX_PIN1_LEN: usize = 12;
const MAX_PIN2_LEN: usize = 12;
const MAX_SIGN_INPUT_LEN: usize = 4096;
const MAX_DECRYPT_INPUT_LEN: usize = 4096;

/// A Windows key-container GUID: the
/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` string the Base CSP uses as
/// a container name. A *format*-validated value (38 chars -- braces, 32
/// hex digits, 4 dashes), not a strict 128-bit UUID: a FINEID container
/// GUID embeds a PIV cert tag at a fixed offset (see
/// `AUTH_CONTAINER_GUID`), which is still a well-formed GUID string. The
/// raw text crosses into this type only at [`Guid::parse`]; thereafter
/// the value is known well-formed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Guid(String);

/// [`Guid::parse`] rejected a malformed container-GUID string.
#[derive(Debug)]
struct GuidFormatError;

impl Guid {
    /// Parse the canonical brace / hex / dash form.
    ///
    /// # Errors
    /// [`GuidFormatError`] when `s` is not 38 characters of the
    /// `{8-4-4-4-12}` hex shape.
    fn parse(s: &str) -> Result<Self, GuidFormatError> {
        /// Total length of `{8-4-4-4-12}` incl. braces and dashes.
        const GUID_STR_LEN: usize = 38;
        /// Byte offsets of the four `-` separators.
        const DASH_AT: [usize; 4] = [9, 14, 19, 24];
        if s.len() != GUID_STR_LEN {
            return Err(GuidFormatError);
        }
        for (offset, byte) in s.bytes().enumerate() {
            let ok = if offset == 0 {
                byte == b'{'
            } else if offset == GUID_STR_LEN - 1 {
                byte == b'}'
            } else if DASH_AT.contains(&offset) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            };
            if !ok {
                return Err(GuidFormatError);
            }
        }
        Ok(Self(s.to_owned()))
    }

    /// The canonical container-GUID string.
    fn as_str(&self) -> &str {
        &self.0
    }
}

fn qualified_signature_container(
    cert_der: Vec<u8>,
    key_alg: KeyAlgorithm,
) -> Option<ContainerDescriptor> {
    Some(ContainerDescriptor {
        index: 1,
        guid: Guid::parse(QUAL_SIG_CONTAINER_GUID).ok()?,
        pin_id: PIN_ID_QUALIFIED_SIG,
        cert_der,
        key_alg,
        key_ref: KEY_REF_SIGN,
        allow_sign: true,
        allow_decrypt: false,
        allow_pss: matches!(key_alg, KeyAlgorithm::Rsa { .. }),
        cmap_flags: CONTAINER_MAP_VALID_CONTAINER,
        reported_sig_bits: key_alg.bits(),
        reported_keyex_bits: 0,
        sig_file: "ksc01".to_owned(),
        keyex_file: None,
    })
}

/// The key algorithm a container's certificate carries. Drives the
/// reported key sizes, the `AT_*` key-spec the Base CSP expects, and
/// the signature-length advertised back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyAlgorithm {
    Rsa { bits: u16 },
    Ec(EcCurve),
}

impl KeyAlgorithm {
    /// Reported key size in bits. For EC this is the field-prime bit
    /// length from [`EcCurve::bits`] (256 / 384; 0 for an
    /// unrecognised curve, which a FINEID container never carries).
    pub(crate) fn bits(self) -> u16 {
        match self {
            Self::Rsa { bits } => bits,
            // EcCurve::bits() is 0/256/384; all fit u16.
            Self::Ec(curve) => u16::try_from(curve.bits()).unwrap_or(0),
        }
    }

    /// Raw signature length in bytes: modulus bytes for RSA, `r || s`
    /// (twice the field bytes) for ECDSA.
    pub(crate) fn signature_len(self) -> usize {
        match self {
            Self::Rsa { bits } => usize::from(bits) / 8,
            Self::Ec(curve) => (curve.bits() / 8) * 2,
        }
    }

    /// The Base CSP `AT_*` key-spec for this algorithm. EC maps by
    /// field size (256 -> P-256, else P-384, matching FINEID's
    /// newer-scheme P-384 qualified key).
    pub(crate) fn key_spec(self) -> DWORD {
        match self {
            Self::Rsa { .. } => AT_SIGNATURE,
            Self::Ec(curve) => {
                if curve.bits() == 256 {
                    AT_ECDSA_P256
                } else {
                    AT_ECDSA_P384
                }
            }
        }
    }
}

/// One certificate slot exposed to the Base CSP as a key container.
#[derive(Clone, Debug)]
pub(crate) struct ContainerDescriptor {
    pub(crate) index: BYTE,
    pub(crate) guid: Guid,
    pub(crate) pin_id: DWORD,
    pub(crate) cert_der: Vec<u8>,
    pub(crate) key_alg: KeyAlgorithm,
    pub(crate) key_ref: u8,
    pub(crate) allow_sign: bool,
    pub(crate) allow_decrypt: bool,
    pub(crate) allow_pss: bool,
    pub(crate) cmap_flags: BYTE,
    pub(crate) reported_sig_bits: u16,
    pub(crate) reported_keyex_bits: u16,
    pub(crate) sig_file: String,
    pub(crate) keyex_file: Option<String>,
}

impl ContainerDescriptor {
    pub(crate) fn is_visible(&self) -> bool {
        self.cmap_flags & CONTAINER_MAP_VALID_CONTAINER != 0
    }

    pub(crate) fn keyex_bits(&self) -> u16 {
        if self.is_visible() {
            self.reported_keyex_bits
        } else {
            0
        }
    }
}

/// The full card model built once at `CardAcquireContext`: the
/// containers the card exposes plus the `cmapfile` records the Base
/// CSP reads to enumerate them.
#[derive(Clone, Debug)]
pub(crate) struct CardCapabilityModel {
    pub(crate) containers: Vec<ContainerDescriptor>,
    pub(crate) cmapfile_records: Vec<CONTAINER_MAP_RECORD>,
}

impl CardCapabilityModel {
    pub(crate) fn auth_cert_der(&self) -> Option<&[u8]> {
        self.containers
            .first()
            .map(|container| container.cert_der.as_slice())
    }

    pub(crate) fn container(&self, index: BYTE) -> Option<&ContainerDescriptor> {
        self.containers
            .iter()
            .find(|container| container.index == index)
    }

    pub(crate) fn visible_container(&self, index: BYTE) -> Option<&ContainerDescriptor> {
        self.container(index)
            .filter(|container| container.is_visible())
    }

    pub(crate) fn container_mut(&mut self, index: BYTE) -> Option<&mut ContainerDescriptor> {
        self.containers
            .iter_mut()
            .find(|container| container.index == index)
    }

    /// The signing algorithms the card advertises (`"RSA"` / `"ECDSA"`),
    /// derived from the visible, sign-capable containers.
    pub(crate) fn algorithms(&self) -> Vec<&'static str> {
        let mut algorithms = Vec::new();
        let has_rsa = self.containers.iter().any(|container| {
            container.is_visible()
                && container.allow_sign
                && matches!(container.key_alg, KeyAlgorithm::Rsa { .. })
        });
        let has_ecdsa = self.containers.iter().any(|container| {
            container.is_visible()
                && container.allow_sign
                && matches!(container.key_alg, KeyAlgorithm::Ec(_))
        });
        if has_rsa {
            algorithms.push("RSA");
        }
        if has_ecdsa {
            algorithms.push("ECDSA");
        }
        algorithms
    }

    /// The Base CSP `PIN_SET` bitmask: always PIN1 + PUK, plus the
    /// qualified-signature PIN when a visible container uses it.
    pub(crate) fn pin_set(&self) -> DWORD {
        let mut pins = create_pin_set(PIN_ID_AUTH) | create_pin_set(PIN_ID_PUK);
        if self
            .containers
            .iter()
            .any(|container| container.pin_id == PIN_ID_QUALIFIED_SIG && container.is_visible())
        {
            pins |= create_pin_set(PIN_ID_QUALIFIED_SIG);
        }
        pins
    }

    /// Rewrite the cmapfile record for `index` from its container's
    /// current flags / key sizes / GUID (a no-op for an out-of-range
    /// or absent slot).
    fn sync_container_to_record(&mut self, index: BYTE) {
        let Some(container) = self.container(index).cloned() else {
            return;
        };
        let Some(record) = self.cmapfile_records.get_mut(usize::from(index)) else {
            return;
        };
        *record = CONTAINER_MAP_RECORD::empty();
        record.bFlags = container.cmap_flags;
        record.wSigKeySizeBits = container.reported_sig_bits;
        record.wKeyExchangeKeySizeBits = container.reported_keyex_bits;
        if container.is_visible() {
            record.write_guid(&container.guid);
        }
    }

    /// Pull the cmapfile records back into the containers -- the Base
    /// CSP may have rewritten the records (e.g. on container delete),
    /// and the containers track flags / key sizes / GUID from them.
    fn apply_records_to_containers(&mut self) {
        for container in &mut self.containers {
            let Some(record) = self.cmapfile_records.get(usize::from(container.index)) else {
                continue;
            };
            if record.bFlags & CONTAINER_MAP_VALID_CONTAINER == 0 {
                continue;
            }
            container.cmap_flags = record.bFlags;
            container.reported_sig_bits = record.wSigKeySizeBits;
            container.reported_keyex_bits = record.wKeyExchangeKeySizeBits;
            if let Some(guid) = record.read_guid() {
                container.guid = guid;
            }
        }
        let indices: Vec<BYTE> = self
            .containers
            .iter()
            .map(|container| container.index)
            .collect();
        for index in indices {
            self.sync_container_to_record(index);
        }
    }
}

/// The single-bit `PIN_SET` mask for a PIN id (the Base CSP's
/// `PIN_SET` is a bitfield indexed by PIN id).
fn create_pin_set(pin_id: DWORD) -> DWORD {
    1_u32 << pin_id
}

/// Card-model construction helpers, grouped on a unit struct so the
/// borrowed-parameter entries are associated fns, not top-level free
/// fns (typing-discipline Rule A). `build_card_model` joins this in a
/// later commit.
pub(crate) struct CardModel;

impl CardModel {
    /// Classify a container certificate's key into the minidriver's
    /// [`KeyAlgorithm`], reading the `SubjectPublicKeyInfo` via
    /// lib-core. Takes a parsed [`OwnedCert`] (typed origin) so the
    /// caller parses once and no raw `&[u8]` crosses the boundary.
    /// `None` for a curve the minidriver doesn't surface (explicit-
    /// params EC, unknown OID) -- a FINEID auth / qualified-signature
    /// cert never carries one.
    fn detect_key_algorithm(cert: &OwnedCert) -> Option<KeyAlgorithm> {
        match parse_subject_public_key_info(cert.view().spki.as_der())? {
            PublicKeyAlgorithm::Rsa { modulus_bits } => Some(KeyAlgorithm::Rsa {
                bits: u16::try_from(modulus_bits).ok()?,
            }),
            PublicKeyAlgorithm::Ec(curve) => Some(KeyAlgorithm::Ec(curve)),
            _ => None,
        }
    }

    /// Deserialize a `cmapfile` blob (the Base CSP cache form) into its
    /// fixed-size `CONTAINER_MAP_RECORD`s. `None` if the length isn't a
    /// whole number of records. `bytes` is the raw cache blob -- the
    /// parse boundary.
    fn parse_cmapfile_records(bytes: &[u8]) -> Option<Vec<CONTAINER_MAP_RECORD>> {
        let record_size = size_of::<CONTAINER_MAP_RECORD>();
        if bytes.len() < record_size || !bytes.len().is_multiple_of(record_size) {
            return None;
        }
        let mut records = Vec::with_capacity(bytes.len() / record_size);
        for chunk in bytes.chunks_exact(record_size) {
            // CONTAINER_MAP_RECORD is #[repr(C)] POD; copy the record's
            // bytes in. chunk is exactly record_size by chunks_exact.
            let mut record = CONTAINER_MAP_RECORD::empty();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    chunk.as_ptr(),
                    core::ptr::from_mut(&mut record).cast::<u8>(),
                    record_size,
                );
            }
            records.push(record);
        }
        Some(records)
    }

    /// The default `cmapfile` record table (`MAX_VIRTUAL_CONTAINERS`
    /// slots) with each container's flags / key sizes / GUID written
    /// into its index slot.
    fn default_cmapfile_records(containers: &[ContainerDescriptor]) -> Vec<CONTAINER_MAP_RECORD> {
        let mut records: Vec<CONTAINER_MAP_RECORD> =
            core::iter::repeat_with(CONTAINER_MAP_RECORD::empty)
                .take(MAX_VIRTUAL_CONTAINERS)
                .collect();
        for container in containers {
            let Some(record) = records.get_mut(usize::from(container.index)) else {
                continue;
            };
            record.bFlags = container.cmap_flags;
            record.wSigKeySizeBits = container.reported_sig_bits;
            record.wKeyExchangeKeySizeBits = container.reported_keyex_bits;
            if container.is_visible() {
                record.write_guid(&container.guid);
            }
        }
        records
    }

    /// Build the full card model at `CardAcquireContext`: the auth and
    /// qualified-signature containers, the default `cmapfile` records,
    /// and -- when the Base
    /// CSP cache holds a persisted virtual cmapfile -- the cached
    /// records applied over the containers. `cd` supplies the CSP cache
    /// callbacks; `auth_cert_der` and `signature_cert_der` are the two
    /// on-card end-entity certificates. `None` if either certificate
    /// cannot be parsed or classified.
    pub(crate) fn build_card_model(
        cd: &CARD_DATA,
        auth_cert_der: Vec<u8>,
        signature_cert_der: Vec<u8>,
    ) -> Option<CardCapabilityModel> {
        let auth_cert = OwnedCert::from_der(&auth_cert_der).ok()?;
        let auth_key_alg = Self::detect_key_algorithm(&auth_cert)?;
        let signature_cert = OwnedCert::from_der(&signature_cert_der).ok()?;
        let signature_key_alg = Self::detect_key_algorithm(&signature_cert)?;
        let auth_container = ContainerDescriptor {
            index: CARD_DEFAULT_CONTAINER,
            guid: Guid::parse(AUTH_CONTAINER_GUID).ok()?,
            pin_id: PIN_ID_AUTH,
            cert_der: auth_cert_der,
            key_alg: auth_key_alg,
            key_ref: KEY_REF_AUTH,
            allow_sign: true,
            allow_decrypt: false,
            // TLS 1.3 client-cert signatures require RSASSA-PSS
            // (RFC 8446 §4.2.3); Firefox's osclientcerts and
            // Schannel both request PSS on the auth key. The card
            // itself only pads PKCS#1 v1.5, so `CardSignData` does
            // host-side EMSA-PSS + the raw private-key op. EC keys
            // never use PSS.
            allow_pss: matches!(auth_key_alg, KeyAlgorithm::Rsa { .. }),
            cmap_flags: CONTAINER_MAP_VALID_CONTAINER | CONTAINER_MAP_DEFAULT_CONTAINER,
            reported_sig_bits: auth_key_alg.bits(),
            reported_keyex_bits: 0,
            sig_file: "ksc00".to_owned(),
            keyex_file: None,
        };
        let signature_container =
            qualified_signature_container(signature_cert_der, signature_key_alg)?;
        let containers = vec![auth_container, signature_container];
        let mut card = CardCapabilityModel {
            cmapfile_records: Self::default_cmapfile_records(&containers),
            containers,
        };
        // The Base CSP may have persisted a virtual cmapfile from a
        // prior context; prefer it over the freshly derived default so
        // container GUIDs stay stable across contexts. A parse failure
        // drops the stale blob and falls back to the default.
        if let Some(bytes) = unsafe { cache_lookup_bytes(cd, VIRTUAL_CMAPFILE_CACHE_TAG) } {
            if let Some(mut cached) = Self::parse_cmapfile_records(&bytes) {
                cached.resize(MAX_VIRTUAL_CONTAINERS, CONTAINER_MAP_RECORD::empty());
                card.cmapfile_records = cached;
                Log::dbg("build_card_model: loaded virtual cmapfile from Base CSP cache");
            } else {
                Log::dbg("build_card_model: virtual cmapfile cache parse failed, using defaults");
                let _rc: DWORD = unsafe { cache_delete_tag(cd, VIRTUAL_CMAPFILE_CACHE_TAG) };
            }
        }
        card.apply_records_to_containers();
        Some(card)
    }
}

/// Normalizes a remote ECDSA signature to IEEE P1363 (`r || s`).
///
/// RAPP v26.10.9 section 9.2 sends the fixed-width raw form, which may itself
/// begin with the DER sequence tag, so the raw length is checked before any
/// DER decoding; other lengths are accepted only as DER.
pub(crate) fn remote_ecdsa_to_p1363(signature: &[u8], field_bytes: usize) -> Option<Vec<u8>> {
    if signature.len() == field_bytes * 2 {
        Some(signature.to_vec())
    } else {
        ecdsa_der_to_p1363(signature, field_bytes)
    }
}

/// Converts an ECDSA signature from ASN.1 DER (`SEQUENCE { r INTEGER, s INTEGER }`)
/// to IEEE P1363 raw concatenation format (`r || s`, where each component is fixed-width
/// big-endian and padded with leading zeros or stripped of sign padding to `field_bytes`).
///
/// Returns `None` if the input is malformed, integer values are zero, or an integer
/// magnitude exceeds `field_bytes`.
pub(crate) fn ecdsa_der_to_p1363(der: &[u8], field_bytes: usize) -> Option<Vec<u8>> {
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
    let r_start = field_bytes - r_slice.len();
    out[r_start..field_bytes].copy_from_slice(r_slice);
    let s_start = (field_bytes * 2) - s_slice.len();
    out[s_start..field_bytes * 2].copy_from_slice(s_slice);

    Some(out)
}

fn parse_der_len(der: &[u8], idx: &mut usize) -> Option<usize> {
    if *idx >= der.len() {
        return None;
    }
    let first = der[*idx];
    *idx += 1;
    if first < 0x80 {
        Some(first as usize)
    } else if first == 0x81 {
        if *idx >= der.len() {
            return None;
        }
        let len = der[*idx] as usize;
        *idx += 1;
        Some(len)
    } else if first == 0x82 {
        if *idx + 1 >= der.len() {
            return None;
        }
        let len = ((der[*idx] as usize) << 8) | (der[*idx + 1] as usize);
        *idx += 2;
        Some(len)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::remote_ecdsa_to_p1363;
    use super::{
        CONTAINER_MAP_DEFAULT_CONTAINER, CONTAINER_MAP_RECORD, CONTAINER_MAP_VALID_CONTAINER,
        CardCapabilityModel, KEY_REF_SIGN, KeyAlgorithm, PIN_ID_QUALIFIED_SIG, ecdsa_der_to_p1363,
        qualified_signature_container,
    };

    #[test]
    fn qualified_signature_container_routes_to_pin2_and_key_ref_02() {
        let cert = vec![1, 2, 3];
        let container =
            qualified_signature_container(cert.clone(), KeyAlgorithm::Rsa { bits: 3072 })
                .expect("valid descriptor");

        assert_eq!(container.index, 1);
        assert_eq!(container.pin_id, PIN_ID_QUALIFIED_SIG);
        assert_eq!(container.key_ref, KEY_REF_SIGN);
        assert_eq!(container.cert_der, cert);
        assert_eq!(container.sig_file, "ksc01");
        assert!(container.allow_sign);
        assert!(container.allow_pss);
        assert!(!container.allow_decrypt);
        assert_eq!(container.cmap_flags & CONTAINER_MAP_DEFAULT_CONTAINER, 0);
        assert_eq!(container.reported_sig_bits, 3072);
        assert_eq!(container.reported_keyex_bits, 0);
    }

    #[test]
    fn p384_qualified_container_routes_to_pin2_without_rsa_pss() {
        let cert = vec![1, 2, 3];
        let container = qualified_signature_container(
            cert,
            KeyAlgorithm::Ec(refineid_lib_core::x509::EcCurve::Secp384r1),
        )
        .expect("valid descriptor");

        assert_eq!(container.pin_id, PIN_ID_QUALIFIED_SIG);
        assert_eq!(container.key_ref, KEY_REF_SIGN);
        assert!(container.allow_sign);
        assert!(!container.allow_decrypt);
        assert!(!container.allow_pss);
        assert_eq!(container.reported_sig_bits, 384);
        assert_eq!(container.reported_keyex_bits, 0);
        assert_eq!(container.key_alg.signature_len(), 96);
    }

    #[test]
    fn stale_empty_cache_record_does_not_hide_physical_container() {
        let container =
            qualified_signature_container(vec![1, 2, 3], KeyAlgorithm::Rsa { bits: 3072 })
                .expect("valid descriptor");
        let mut records = vec![CONTAINER_MAP_RECORD::empty(); 2];
        let mut model = CardCapabilityModel {
            containers: vec![container],
            cmapfile_records: records.clone(),
        };

        model.apply_records_to_containers();

        assert!(model.containers[0].is_visible());
        assert_ne!(
            model.cmapfile_records[1].bFlags & CONTAINER_MAP_VALID_CONTAINER,
            0
        );
        records[1] = model.cmapfile_records[1];
        assert_eq!(records[1].wSigKeySizeBits, 3072);
    }

    #[test]
    fn raw_signature_starting_with_the_der_tag_stays_raw() {
        let mut raw = vec![0x30u8];
        raw.extend(vec![0x5au8; 95]);
        assert_eq!(remote_ecdsa_to_p1363(&raw, 48), Some(raw));
    }

    #[test]
    fn non_raw_length_is_read_as_der() {
        let r_raw = vec![0x33u8; 47];
        let s_raw = vec![0x44u8; 48];
        let mut der = vec![0x30u8, 99, 0x02, 47];
        der.extend_from_slice(&r_raw);
        der.extend_from_slice(&[0x02, 48]);
        der.extend_from_slice(&s_raw);
        let p1363 = remote_ecdsa_to_p1363(&der, 48).expect("valid DER");
        assert_eq!(p1363.len(), 96);
        assert_eq!(&p1363[48..], &s_raw);
        assert_eq!(remote_ecdsa_to_p1363(&[0x01, 0x02], 48), None);
    }

    #[test]
    fn ecdsa_der_to_p1363_converts_der_to_raw() {
        // r = 48 bytes with MSB set (0x80..), requiring 0x00 DER prefix -> 49 bytes in DER
        let mut r_raw = vec![0x80u8];
        r_raw.extend(vec![0x11u8; 47]);
        // s = 48 bytes with MSB unset (0x70..), no prefix -> 48 bytes in DER
        let mut s_raw = vec![0x70u8];
        s_raw.extend(vec![0x22u8; 47]);

        let mut der = vec![0x30u8, 101]; // outer len = 2 + 49 + 2 + 48 = 101
        der.push(0x02);
        der.push(49);
        der.push(0x00);
        der.extend_from_slice(&r_raw);
        der.push(0x02);
        der.push(48);
        der.extend_from_slice(&s_raw);

        let p1363 = ecdsa_der_to_p1363(&der, 48).expect("valid conversion");
        assert_eq!(p1363.len(), 96);
        assert_eq!(&p1363[..48], &r_raw);
        assert_eq!(&p1363[48..], &s_raw);
    }

    #[test]
    fn ecdsa_der_to_p1363_pads_short_integers() {
        // r = 47 bytes (high byte was 0)
        let r_raw = vec![0x33u8; 47];
        let s_raw = vec![0x44u8; 48];

        let mut der = vec![0x30u8, 99]; // 2 + 47 + 2 + 48 = 99
        der.push(0x02);
        der.push(47);
        der.extend_from_slice(&r_raw);
        der.push(0x02);
        der.push(48);
        der.extend_from_slice(&s_raw);

        let p1363 = ecdsa_der_to_p1363(&der, 48).expect("valid conversion");
        assert_eq!(p1363.len(), 96);
        assert_eq!(p1363[0], 0x00);
        assert_eq!(&p1363[1..48], &r_raw);
        assert_eq!(&p1363[48..], &s_raw);
    }

    #[test]
    fn ecdsa_der_to_p1363_rejects_malformed_input() {
        // Empty
        assert!(ecdsa_der_to_p1363(&[], 48).is_none());
        // Wrong tag
        assert!(
            ecdsa_der_to_p1363(&[0x02, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], 48).is_none()
        );
        // Truncated
        assert!(ecdsa_der_to_p1363(&[0x30, 0x10, 0x02, 0x01, 0x01], 48).is_none());
        // Field bytes 0
        assert!(ecdsa_der_to_p1363(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], 0).is_none());
        // Zero value
        assert!(
            ecdsa_der_to_p1363(&[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01], 48).is_none()
        );
        // Oversized integer (> field_bytes)
        let mut r_too_big = vec![0x01u8];
        r_too_big.extend(vec![0x11u8; 48]);
        let mut der = vec![0x30u8, 102];
        der.push(0x02);
        der.push(49);
        der.extend_from_slice(&r_too_big);
        der.push(0x02);
        der.push(48);
        der.extend(vec![0x22u8; 48]);
        assert!(ecdsa_der_to_p1363(&der, 48).is_none());
    }
}

impl CONTAINER_MAP_RECORD {
    /// A zeroed record -- the starting point before a visible
    /// container's fields are written in.
    fn empty() -> Self {
        Self {
            wszGuid: [0_u16; MAX_CONTAINER_NAME_LEN + 1],
            bFlags: 0,
            bReserved: 0,
            wSigKeySizeBits: 0,
            wKeyExchangeKeySizeBits: 0,
        }
    }

    /// The container GUID stored in `wszGuid` (NUL-terminated UTF-16),
    /// parsed into a typed [`Guid`]. `None` when the slot is empty or
    /// carries a malformed value.
    fn read_guid(&self) -> Option<Guid> {
        let len = self
            .wszGuid
            .iter()
            .position(|ch| *ch == 0)
            .unwrap_or(self.wszGuid.len());
        let text = String::from_utf16_lossy(self.wszGuid.get(..len).unwrap_or(&[]));
        Guid::parse(&text).ok()
    }

    /// Write `guid` into `wszGuid` as NUL-terminated UTF-16, truncated
    /// to the field width.
    fn write_guid(&mut self, guid: &Guid) {
        self.wszGuid = [0_u16; MAX_CONTAINER_NAME_LEN + 1];
        for (slot, ch) in self
            .wszGuid
            .iter_mut()
            .zip(guid.as_str().encode_utf16().take(MAX_CONTAINER_NAME_LEN))
        {
            *slot = ch;
        }
    }
}

// ----- Base CSP file cache (CspCacheLookupFile / AddFile / DeleteFile) -----
//
// The Base CSP hands the Card Module a small key/value cache through
// callback pointers in `CARD_DATA`, keyed by a wide-string tag and
// scoped to `pvCacheContext`. The minidriver uses it to persist the
// virtual cmapfile (the container map) across calls instead of
// re-deriving it every context. Every callback is optional -- a CSP
// may pass null pointers, in which case the operation degrades to a
// cache miss / unsupported-feature.
//
// Buffer ownership crosses the boundary in both directions: AddFile
// data must be allocated from the CSP's own allocator (`pfnCspAlloc`),
// and a successful LookupFile hands back a CSP-owned buffer the Card
// Module must copy out of and release with `pfnCspFree`.

/// Cache tag for the persisted virtual cmapfile blob.
const VIRTUAL_CMAPFILE_CACHE_TAG: &str = "refineid.virtual.cmapfile";

/// Encode a cache tag as a NUL-terminated UTF-16 string for the
/// wide-string CSP cache callbacks.
fn cache_tag_wide(tag: &str) -> Vec<u16> {
    tag.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Allocate `len` bytes from the CSP's allocator, or null if the
/// allocator callback is absent.
unsafe fn cspalloc(cd: &CARD_DATA, len: usize) -> PVOID {
    match cd.pfnCspAlloc {
        Some(alloc) => unsafe { alloc(len) },
        None => core::ptr::null_mut(),
    }
}

/// Release a CSP-allocated buffer through the CSP's free callback
/// (no-op if the callback is absent).
unsafe fn cspfree(cd: &CARD_DATA, p: PVOID) {
    if let Some(free) = cd.pfnCspFree {
        unsafe { free(p) };
    }
}

/// Look up `tag` in the Base CSP file cache. On a hit, copies the
/// bytes out of the CSP-owned buffer and frees it; returns `None` on
/// a miss or when the lookup callback is absent.
unsafe fn cache_lookup_bytes(cd: &CARD_DATA, tag: &str) -> Option<Vec<u8>> {
    let Some(lookup) = cd.pfnCspCacheLookupFile else {
        Log::dbg("cache_lookup_bytes: pfnCspCacheLookupFile=None (no cache callback)");
        return None;
    };
    let wide = cache_tag_wide(tag);
    let mut ptr: PBYTE = core::ptr::null_mut();
    let mut len: DWORD = 0;
    let rc = unsafe {
        lookup(
            cd.pvCacheContext,
            wide.as_ptr().cast_mut(),
            0,
            &raw mut ptr,
            &raw mut len,
        )
    };
    if rc != SCARD_S_SUCCESS || ptr.is_null() {
        Log::dbg("cache_lookup_bytes -> MISS");
        return None;
    }
    let len = usize::try_from(len).unwrap_or(0);
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec();
    unsafe { cspfree(cd, ptr.cast::<c_void>()) };
    Log::dbg("cache_lookup_bytes -> HIT");
    Some(bytes)
}

/// Store `bytes` under `tag` in the Base CSP file cache via a
/// CSP-allocated copy. Returns the callback's status word, or an
/// unsupported / no-memory status when the callback or allocation
/// is unavailable.
unsafe fn cache_store_bytes(cd: &CARD_DATA, tag: &str, bytes: &[u8]) -> DWORD {
    let Some(add) = cd.pfnCspCacheAddFile else {
        Log::dbg("cache_store_bytes: pfnCspCacheAddFile=None");
        return SCARD_E_UNSUPPORTED_FEATURE;
    };
    let wide = cache_tag_wide(tag);
    let ptr = unsafe { cspalloc(cd, bytes.len()) };
    if ptr.is_null() {
        Log::dbg("cache_store_bytes: cspalloc -> null");
        return SCARD_E_NO_MEMORY;
    }
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len()) };
    let len = DWORD::try_from(bytes.len()).unwrap_or(DWORD::MAX);
    let rc = unsafe {
        add(
            cd.pvCacheContext,
            wide.as_ptr().cast_mut(),
            0,
            ptr.cast::<BYTE>(),
            len,
        )
    };
    unsafe { cspfree(cd, ptr) };
    rc
}

/// Delete `tag` from the Base CSP file cache. Returns the callback's
/// status word, or unsupported-feature when the callback is absent.
unsafe fn cache_delete_tag(cd: &CARD_DATA, tag: &str) -> DWORD {
    let Some(delete) = cd.pfnCspCacheDeleteFile else {
        Log::dbg("cache_delete_tag: pfnCspCacheDeleteFile=None");
        return SCARD_E_UNSUPPORTED_FEATURE;
    };
    let wide = cache_tag_wide(tag);
    unsafe { delete(cd.pvCacheContext, wide.as_ptr().cast_mut(), 0) }
}

// ----- Diagnostic logging (Windows Event Log) -----
//
// The minidriver runs inside SCardSvr -- no console, no stdout, no
// flat-file fallback. Production diagnostics go to the Windows Event
// Log (Application channel, source "RefineID-Minidriver"), visible in
// Event Viewer. The `advapi32` Event Log API is hand-rolled here, the
// same way `transport.rs` hand-rolls the `winscard` API, so the crate
// adds no `windows-sys` dependency.
//
// Source registration happens at MSIX install time; if the source
// isn't registered, ReportEventW still works (Event Viewer just shows
// a generic "description for Event ID X cannot be found" preamble).

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegisterEventSourceW(server_name: *const u16, source_name: *const u16) -> *mut c_void;
    fn ReportEventW(
        event_log: *mut c_void,
        event_type: u16,
        category: u16,
        event_id: u32,
        user_sid: *mut c_void,
        num_strings: u16,
        data_size: u32,
        strings: *const *const u16,
        raw_data: *const c_void,
    ) -> i32;
}

/// `EVENTLOG_*` severities (ISO 7816-unrelated -- Win32 Event Log
/// `wType` values, winnt.h).
const EVENTLOG_ERROR_TYPE: u16 = 0x0001;
const EVENTLOG_WARNING_TYPE: u16 = 0x0002;
const EVENTLOG_INFORMATION_TYPE: u16 = 0x0004;

/// `"RefineID-Minidriver\0"` as a NUL-terminated UTF-16 source name
/// for `RegisterEventSourceW`.
const EVENT_SOURCE_NAME: &[u16] = &[
    'R' as u16, 'e' as u16, 'F' as u16, 'i' as u16, 'n' as u16, 'e' as u16, 'I' as u16, 'D' as u16,
    '-' as u16, 'M' as u16, 'i' as u16, 'n' as u16, 'i' as u16, 'd' as u16, 'r' as u16, 'i' as u16,
    'v' as u16, 'e' as u16, 'r' as u16, 0,
];

/// Cached event-source handle. `AtomicPtr` so no pointer<->integer
/// casts are needed; first writer wins (a leaked duplicate handle is
/// cheap and harmless).
static EVENT_SOURCE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// Event Log severity for [`Log::report`].
#[derive(Clone, Copy)]
#[repr(u16)]
enum LogLevel {
    Info,
    Warn,
    Error,
}

/// Diagnostic-logging helpers grouped on a unit struct, so the
/// borrowed-parameter entries are associated fns rather than
/// top-level free fns (typing-discipline Rule A).
pub(crate) struct Log;

impl Log {
    /// The cached event-source handle, registering it on first use.
    fn source() -> *mut c_void {
        let cached = EVENT_SOURCE.load(Ordering::Acquire);
        if !cached.is_null() {
            return cached;
        }
        let handle = unsafe { RegisterEventSourceW(core::ptr::null(), EVENT_SOURCE_NAME.as_ptr()) };
        if !handle.is_null() {
            let _ignored = EVENT_SOURCE.compare_exchange(
                core::ptr::null_mut(),
                handle,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
        handle
    }

    /// Write one Event Log record. No-op if the source handle can't be
    /// acquired. Hard rule: never pass PIN / PUK / key / session-key
    /// material as `msg` (alpha logging policy: PINs and personal
    /// certificate material are never event-log data).
    fn report(level: LogLevel, event_id: u32, msg: &str) {
        let handle = Self::source();
        if handle.is_null() {
            return;
        }
        let wide: Vec<u16> = msg.encode_utf16().chain(core::iter::once(0)).collect();
        let strings: [*const u16; 1] = [wide.as_ptr()];
        let event_type = match level {
            LogLevel::Info => EVENTLOG_INFORMATION_TYPE,
            LogLevel::Warn => EVENTLOG_WARNING_TYPE,
            LogLevel::Error => EVENTLOG_ERROR_TYPE,
        };
        unsafe {
            ReportEventW(
                handle,
                event_type,
                0,
                event_id,
                core::ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                core::ptr::null(),
            );
        }
    }

    /// Alpha-stage trace: every callback entry / branch / return code
    /// is reported at Info against the `RefineID-Minidriver` source
    /// (golden rule #2 -- Event Log is the only diagnostic channel
    /// inside `SCardSvr`). Unconditional during alpha; level gating
    /// returns with the manifested ETW provider post-alpha.
    pub(crate) fn dbg(msg: &str) {
        Self::report(LogLevel::Info, 1, msg);
    }
}
