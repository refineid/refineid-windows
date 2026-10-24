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

//! Byte-level encodings the key storage provider hands to CNG, kept free of
//! Windows so the host test suite covers them.
//!
//! CNG public key blobs follow `bcrypt.h`: an `BCRYPT_ECCKEY_BLOB` header
//! (magic, coordinate length) before `X || Y`, and an `BCRYPT_RSAKEY_BLOB`
//! header (magic, bit length, exponent length, modulus length, two zero
//! prime lengths) before `e || n`. All header fields are little-endian
//! 32-bit values.
#![expect(
    clippy::redundant_pub_crate,
    reason = "This private codec module uses pub(crate) for consistency with its sibling modules"
)]

/// `BCRYPT_ECDSA_PUBLIC_P256_MAGIC` (`"ECS1"`).
const ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345;
/// `BCRYPT_ECDSA_PUBLIC_P384_MAGIC` (`"ECS3"`).
const ECDSA_PUBLIC_P384_MAGIC: u32 = 0x3353_4345;
/// `BCRYPT_RSAPUBLIC_MAGIC` (`"RSA1"`).
const RSAPUBLIC_MAGIC: u32 = 0x3141_5352;

/// Bits in one byte, the step between a modulus length and its byte width.
const BITS_PER_BYTE: usize = 8;
/// Modulus length of an RSA key the `rsa_2048` signing profile covers.
const RSA_2048_MODULUS_BITS: usize = 2048;
/// Modulus length of an RSA key the `rsa_3072` signing profile covers.
const RSA_3072_MODULUS_BITS: usize = 3072;

/// The RSA modulus lengths a signing profile exists for; a certificate with
/// any other modulus is not a key this provider offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RsaKeySize {
    /// A 2048-bit modulus, the `rsa_2048` profile.
    Bits2048,
    /// A 3072-bit modulus, the `rsa_3072` profile.
    Bits3072,
}

impl RsaKeySize {
    /// The profile a modulus of exactly `bits` bits belongs to, if any.
    pub(crate) const fn from_bits(bits: usize) -> Option<Self> {
        match bits {
            RSA_2048_MODULUS_BITS => Some(Self::Bits2048),
            RSA_3072_MODULUS_BITS => Some(Self::Bits3072),
            _ => None,
        }
    }

    /// Modulus length in bits.
    pub(crate) const fn bits(self) -> usize {
        match self {
            Self::Bits2048 => RSA_2048_MODULUS_BITS,
            Self::Bits3072 => RSA_3072_MODULUS_BITS,
        }
    }
}

/// The public key kinds a paired card can present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyKind {
    /// ECDSA on NIST P-256.
    EcP256,
    /// ECDSA on NIST P-384.
    EcP384,
    /// RSA with one of the profiled modulus lengths.
    Rsa(RsaKeySize),
}

impl KeyKind {
    /// Field element length in bytes for an EC key, modulus length for RSA.
    pub(crate) const fn element_bytes(self) -> usize {
        match self {
            Self::EcP256 => 32,
            Self::EcP384 => 48,
            Self::Rsa(size) => size.bits().div_ceil(BITS_PER_BYTE),
        }
    }

    /// Length of one signature as CNG receives it: `r || s` for ECDSA, the
    /// big-endian modulus-sized integer for RSA.
    pub(crate) const fn signature_bytes(self) -> usize {
        match self {
            Self::EcP256 | Self::EcP384 => self.element_bytes() * 2,
            Self::Rsa(_) => self.element_bytes(),
        }
    }

    /// Key length in bits, as `NCRYPT_LENGTH_PROPERTY` reports it.
    pub(crate) const fn bits(self) -> usize {
        match self {
            Self::EcP256 => 256,
            Self::EcP384 => 384,
            Self::Rsa(size) => size.bits(),
        }
    }

    /// `NCRYPT_ALGORITHM_GROUP_PROPERTY` value.
    pub(crate) const fn algorithm_group(self) -> &'static str {
        match self {
            Self::EcP256 | Self::EcP384 => "ECDSA",
            Self::Rsa(_) => "RSA",
        }
    }

    /// `NCRYPT_ALGORITHM_PROPERTY` value.
    pub(crate) const fn algorithm_name(self) -> &'static str {
        match self {
            Self::EcP256 => "ECDSA_P256",
            Self::EcP384 => "ECDSA_P384",
            Self::Rsa(_) => "RSA",
        }
    }
}

/// The digest a caller hands in, told apart by its length the way the Card
/// Module does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Digest {
    /// 28 bytes.
    Sha224,
    /// 32 bytes.
    Sha256,
    /// 48 bytes.
    Sha384,
    /// 64 bytes.
    Sha512,
}

impl Digest {
    /// The digest a hash of `length` bytes must be, if any.
    pub(crate) const fn from_length(length: usize) -> Option<Self> {
        match length {
            28 => Some(Self::Sha224),
            32 => Some(Self::Sha256),
            48 => Some(Self::Sha384),
            64 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The digest a CNG hash algorithm identifier names, if supported.
    pub(crate) fn from_cng_algorithm(name: &str) -> Option<Self> {
        match name {
            "SHA256" => Some(Self::Sha256),
            "SHA384" => Some(Self::Sha384),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Digest length in bytes.
    pub(crate) const fn length(self) -> usize {
        match self {
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// `BCRYPT_ECCPUBLIC_BLOB` for an uncompressed SEC 1 point
/// (`0x04 || X || Y`), or `None` when the point is not a P-256 or P-384 one.
pub(crate) fn ecc_public_blob(point: &[u8]) -> Option<Vec<u8>> {
    let (magic, element) = match point.len() {
        65 => (ECDSA_PUBLIC_P256_MAGIC, 32usize),
        97 => (ECDSA_PUBLIC_P384_MAGIC, 48usize),
        _ => return None,
    };
    if point.first() != Some(&0x04) {
        return None;
    }
    let mut blob = Vec::with_capacity(8 + element * 2);
    blob.extend_from_slice(&magic.to_le_bytes());
    blob.extend_from_slice(&u32::try_from(element).ok()?.to_le_bytes());
    blob.extend_from_slice(&point[1..]);
    Some(blob)
}

/// `BCRYPT_RSAPUBLIC_BLOB` for a modulus and public exponent given as
/// big-endian integers without sign padding.
pub(crate) fn rsa_public_blob(modulus: &[u8], exponent: &[u8]) -> Option<Vec<u8>> {
    if modulus.is_empty() || exponent.is_empty() {
        return None;
    }
    let bits = u32::try_from(modulus.len() * 8).ok()?;
    let mut blob = Vec::with_capacity(24 + exponent.len() + modulus.len());
    blob.extend_from_slice(&RSAPUBLIC_MAGIC.to_le_bytes());
    blob.extend_from_slice(&bits.to_le_bytes());
    blob.extend_from_slice(&u32::try_from(exponent.len()).ok()?.to_le_bytes());
    blob.extend_from_slice(&u32::try_from(modulus.len()).ok()?.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(exponent);
    blob.extend_from_slice(modulus);
    Some(blob)
}

/// Pads an RSA signature on the left to the modulus length, or rejects one
/// that is longer than the modulus.
pub(crate) fn rsa_signature_to_width(signature: &[u8], width: usize) -> Option<Vec<u8>> {
    if signature.len() > width {
        return None;
    }
    let mut padded = vec![0u8; width - signature.len()];
    padded.extend_from_slice(signature);
    Some(padded)
}

#[cfg(test)]
mod tests {
    use super::{
        BITS_PER_BYTE, Digest, KeyKind, RSA_2048_MODULUS_BITS, RSA_3072_MODULUS_BITS, RsaKeySize,
        ecc_public_blob, rsa_public_blob, rsa_signature_to_width,
    };

    #[test]
    fn an_ecc_blob_carries_the_magic_and_the_coordinates() {
        let mut point = vec![0x04];
        point.extend((1u8..=96).collect::<Vec<u8>>());
        let blob = ecc_public_blob(&point).expect("P-384 point");
        assert_eq!(&blob[..4], b"ECS3");
        assert_eq!(&blob[4..8], &48u32.to_le_bytes());
        assert_eq!(&blob[8..], &point[1..]);
        assert_eq!(blob.len(), 104);
    }

    #[test]
    fn a_p256_point_gets_its_own_magic() {
        let mut point = vec![0x04];
        point.extend(core::iter::repeat_n(7u8, 64));
        let blob = ecc_public_blob(&point).expect("P-256 point");
        assert_eq!(&blob[..4], b"ECS1");
        assert_eq!(&blob[4..8], &32u32.to_le_bytes());
    }

    #[test]
    fn compressed_or_odd_points_are_rejected() {
        assert!(ecc_public_blob(&[0x02; 65]).is_none());
        assert!(ecc_public_blob(&[0x04; 66]).is_none());
        assert!(ecc_public_blob(&[]).is_none());
    }

    #[test]
    fn an_rsa_blob_carries_the_header_then_e_then_n() {
        let modulus = [0xC1u8; 384];
        let exponent = [0x01u8, 0x00, 0x01];
        let blob = rsa_public_blob(&modulus, &exponent).expect("rsa blob");
        assert_eq!(&blob[..4], b"RSA1");
        assert_eq!(&blob[4..8], &3072u32.to_le_bytes());
        assert_eq!(&blob[8..12], &3u32.to_le_bytes());
        assert_eq!(&blob[12..16], &384u32.to_le_bytes());
        assert_eq!(&blob[16..24], &[0u8; 8]);
        assert_eq!(&blob[24..27], &exponent);
        assert_eq!(&blob[27..], &modulus);
        assert!(rsa_public_blob(&[], &exponent).is_none());
    }

    #[test]
    fn signature_widths_follow_the_key_kind() {
        assert_eq!(KeyKind::EcP256.signature_bytes(), 64);
        assert_eq!(KeyKind::EcP384.signature_bytes(), 96);
        assert_eq!(
            KeyKind::Rsa(RsaKeySize::Bits3072).signature_bytes(),
            RSA_3072_MODULUS_BITS / BITS_PER_BYTE
        );
        assert_eq!(
            KeyKind::Rsa(RsaKeySize::Bits2048).bits(),
            RSA_2048_MODULUS_BITS
        );
        assert_eq!(KeyKind::EcP384.algorithm_name(), "ECDSA_P384");
        assert_eq!(KeyKind::Rsa(RsaKeySize::Bits2048).algorithm_group(), "RSA");
    }

    #[test]
    fn only_the_profiled_rsa_moduli_are_keys() {
        assert_eq!(
            RsaKeySize::from_bits(RSA_2048_MODULUS_BITS),
            Some(RsaKeySize::Bits2048)
        );
        assert_eq!(
            RsaKeySize::from_bits(RSA_3072_MODULUS_BITS),
            Some(RsaKeySize::Bits3072)
        );
        let unprofiled = [
            RSA_2048_MODULUS_BITS / 2,
            RSA_2048_MODULUS_BITS - 1,
            RSA_3072_MODULUS_BITS + 1,
            RSA_2048_MODULUS_BITS * 2,
        ];
        for bits in unprofiled {
            assert_eq!(RsaKeySize::from_bits(bits), None);
        }
        for size in [RsaKeySize::Bits2048, RsaKeySize::Bits3072] {
            assert_eq!(
                KeyKind::Rsa(size).element_bytes(),
                size.bits() / BITS_PER_BYTE
            );
        }
    }

    #[test]
    fn short_rsa_signatures_are_left_padded_and_long_ones_rejected() {
        assert_eq!(rsa_signature_to_width(&[1, 2], 4), Some(vec![0, 0, 1, 2]));
        assert_eq!(rsa_signature_to_width(&[1, 2, 3], 3), Some(vec![1, 2, 3]));
        assert!(rsa_signature_to_width(&[1, 2, 3, 4], 3).is_none());
    }

    #[test]
    fn digests_are_told_apart_by_length_and_cng_name() {
        assert_eq!(Digest::from_length(48), Some(Digest::Sha384));
        assert_eq!(Digest::from_length(20), None);
        assert_eq!(Digest::from_cng_algorithm("SHA256"), Some(Digest::Sha256));
        assert_eq!(Digest::from_cng_algorithm("SHA1"), None);
        assert_eq!(Digest::Sha512.length(), 64);
    }
}
