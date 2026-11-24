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

//! Pure local-card signing request validation and dispatch onto
//! `refineid-sign`.
//!
//! Kept free of `winscard` FFI so host `cargo test` validates algorithm
//! selection, SHA-1 rejection, and citizen vs. organizational signing chains
//! (including authentication-key inline-digest signing and sealed
//! `QualifiedSignSession` dispatch).

use refineid_apdu::CardTransport;
use refineid_sign::commands::{SHA1_LEN, SHA256_LEN, SHA384_LEN, SHA512_LEN};
use refineid_sign::{SignError, Signature, SigningKey};

use crate::ParsedSigningPadding;
use crate::ffi::{
    ALG_ID_NONE, CALG_SHA_256, CALG_SHA_384, CALG_SHA_512, DWORD, SCARD_E_INVALID_PARAMETER,
    SCARD_E_UNSUPPORTED_FEATURE,
};

/// Resolve a legacy `wincrypt.h` `CARD_SIGNING_INFO.aiHashAlg` identifier into
/// the corresponding CNG hash name, rejecting `CALG_SHA1` and any other
/// unsupported non-zero `ALG_ID` so callers cannot silently reinterpret one
/// hash algorithm as another.
const fn hash_name_from_alg_id(ai_hash_alg: DWORD) -> Result<Option<&'static str>, DWORD> {
    match ai_hash_alg {
        ALG_ID_NONE => Ok(None),
        CALG_SHA_256 => Ok(Some("SHA256")),
        CALG_SHA_384 => Ok(Some("SHA384")),
        CALG_SHA_512 => Ok(Some("SHA512")),
        // Rejects CALG_SHA1 and all other unsupported non-zero ALG_ID values.
        _ => Err(SCARD_E_UNSUPPORTED_FEATURE),
    }
}

/// Reconcile an optional padding hash name with an optional `aiHashAlg`-derived
/// hash name. When both are supplied they must match; length inference is only
/// permitted when neither is supplied.
fn resolve_explicit_hash_name<'a>(
    padding_hash: Option<&'a str>,
    alg_hash: Option<&'static str>,
) -> Result<Option<&'a str>, DWORD> {
    match (padding_hash, alg_hash) {
        (Some(pad), Some(alg)) if pad == alg => Ok(Some(pad)),
        (Some(_), Some(_)) => Err(SCARD_E_INVALID_PARAMETER),
        (Some(pad), None) => Ok(Some(pad)),
        (None, Some(alg)) => Ok(Some(alg)),
        (None, None) => Ok(None),
    }
}

/// Key profile relevant to local card-side signing dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKeyProfile {
    /// RSA-3072 key (`allow_pss` mirrors the container capability).
    Rsa { allow_pss: bool },
    /// NIST P-256 ECDSA key.
    EcP256,
    /// NIST P-384 ECDSA key.
    EcP384,
    /// Any other elliptic curve not served by local FINEID card signing.
    UnsupportedEc,
}

/// Validated card-side signing request ready to run on a [`SigningKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalSignRequest {
    RsaPssSha256([u8; SHA256_LEN]),
    RsaPssSha384([u8; SHA384_LEN]),
    RsaPssSha512([u8; SHA512_LEN]),
    RsaPkcs1Sha256([u8; SHA256_LEN]),
    RsaPkcs1Sha384([u8; SHA384_LEN]),
    RsaPkcs1Sha512([u8; SHA512_LEN]),
    EcdsaP256Sha256([u8; SHA256_LEN]),
    EcdsaP384Sha256([u8; SHA256_LEN]),
    EcdsaP384Sha384([u8; SHA384_LEN]),
}

impl LocalSignRequest {
    /// Validate `profile`, `padding`, `ai_hash_alg`, and `digest` before
    /// touching the card or spending a qualified PIN 2 session.
    ///
    /// SHA-1 and unsupported non-zero `ai_hash_alg` identifiers are explicitly
    /// rejected with [`SCARD_E_UNSUPPORTED_FEATURE`]; length inference is only
    /// used when both the padding hash name and `ai_hash_alg` are omitted.
    pub fn parse(
        profile: SigningKeyProfile,
        padding: &ParsedSigningPadding,
        ai_hash_alg: DWORD,
        digest: &[u8],
    ) -> Result<Self, DWORD> {
        let alg_hash = hash_name_from_alg_id(ai_hash_alg)?;
        match (profile, padding) {
            (
                SigningKeyProfile::Rsa { allow_pss },
                ParsedSigningPadding::Pss {
                    hash_name,
                    salt_len,
                },
            ) => {
                if let Some(expected) = alg_hash
                    && expected != hash_name
                {
                    return Err(SCARD_E_INVALID_PARAMETER);
                }
                Self::parse_rsa_pss(allow_pss, hash_name, *salt_len, digest)
            }
            (SigningKeyProfile::Rsa { .. }, ParsedSigningPadding::Pkcs1 { hash_name }) => {
                let resolved = resolve_explicit_hash_name(hash_name.as_deref(), alg_hash)?;
                Self::parse_rsa_pkcs1(resolved, digest)
            }
            (SigningKeyProfile::EcP256, ParsedSigningPadding::Pkcs1 { hash_name }) => {
                let resolved = resolve_explicit_hash_name(hash_name.as_deref(), alg_hash)?;
                Self::parse_ecdsa_p256(resolved, digest)
            }
            (SigningKeyProfile::EcP384, ParsedSigningPadding::Pkcs1 { hash_name }) => {
                let resolved = resolve_explicit_hash_name(hash_name.as_deref(), alg_hash)?;
                Self::parse_ecdsa_p384(resolved, digest)
            }
            (_, ParsedSigningPadding::Pss { .. }) | (SigningKeyProfile::UnsupportedEc, _) => {
                Err(SCARD_E_UNSUPPORTED_FEATURE)
            }
        }
    }

    fn parse_rsa_pss(
        allow_pss: bool,
        hash_name: &str,
        salt_len: usize,
        digest: &[u8],
    ) -> Result<Self, DWORD> {
        if !allow_pss {
            return Err(SCARD_E_UNSUPPORTED_FEATURE);
        }
        match hash_name {
            "SHA1" => Err(SCARD_E_UNSUPPORTED_FEATURE),
            "SHA256" => {
                if salt_len != SHA256_LEN {
                    return Err(SCARD_E_INVALID_PARAMETER);
                }
                digest
                    .try_into()
                    .map(Self::RsaPssSha256)
                    .map_err(|_| SCARD_E_INVALID_PARAMETER)
            }
            "SHA384" => {
                if salt_len != SHA384_LEN {
                    return Err(SCARD_E_INVALID_PARAMETER);
                }
                digest
                    .try_into()
                    .map(Self::RsaPssSha384)
                    .map_err(|_| SCARD_E_INVALID_PARAMETER)
            }
            "SHA512" => {
                if salt_len != SHA512_LEN {
                    return Err(SCARD_E_INVALID_PARAMETER);
                }
                digest
                    .try_into()
                    .map(Self::RsaPssSha512)
                    .map_err(|_| SCARD_E_INVALID_PARAMETER)
            }
            _ => Err(SCARD_E_INVALID_PARAMETER),
        }
    }

    fn parse_rsa_pkcs1(hash_name: Option<&str>, digest: &[u8]) -> Result<Self, DWORD> {
        if let Some(name) = hash_name {
            return match name {
                "SHA1" => Err(SCARD_E_UNSUPPORTED_FEATURE),
                "SHA256" => digest
                    .try_into()
                    .map(Self::RsaPkcs1Sha256)
                    .map_err(|_| SCARD_E_INVALID_PARAMETER),
                "SHA384" => digest
                    .try_into()
                    .map(Self::RsaPkcs1Sha384)
                    .map_err(|_| SCARD_E_INVALID_PARAMETER),
                "SHA512" => digest
                    .try_into()
                    .map(Self::RsaPkcs1Sha512)
                    .map_err(|_| SCARD_E_INVALID_PARAMETER),
                _ => Err(SCARD_E_INVALID_PARAMETER),
            };
        }
        match digest.len() {
            SHA1_LEN => Err(SCARD_E_UNSUPPORTED_FEATURE),
            SHA256_LEN => digest
                .try_into()
                .map(Self::RsaPkcs1Sha256)
                .map_err(|_| SCARD_E_INVALID_PARAMETER),
            SHA384_LEN => digest
                .try_into()
                .map(Self::RsaPkcs1Sha384)
                .map_err(|_| SCARD_E_INVALID_PARAMETER),
            SHA512_LEN => digest
                .try_into()
                .map(Self::RsaPkcs1Sha512)
                .map_err(|_| SCARD_E_INVALID_PARAMETER),
            _ => Err(SCARD_E_INVALID_PARAMETER),
        }
    }

    fn parse_ecdsa_p256(hash_name: Option<&str>, digest: &[u8]) -> Result<Self, DWORD> {
        if let Some(name) = hash_name {
            if name == "SHA1" {
                return Err(SCARD_E_UNSUPPORTED_FEATURE);
            }
            if name != "SHA256" {
                return Err(SCARD_E_INVALID_PARAMETER);
            }
        } else if digest.len() == SHA1_LEN {
            return Err(SCARD_E_UNSUPPORTED_FEATURE);
        }
        digest
            .try_into()
            .map(Self::EcdsaP256Sha256)
            .map_err(|_| SCARD_E_INVALID_PARAMETER)
    }

    fn parse_ecdsa_p384(hash_name: Option<&str>, digest: &[u8]) -> Result<Self, DWORD> {
        if let Some(name) = hash_name {
            return match name {
                "SHA1" => Err(SCARD_E_UNSUPPORTED_FEATURE),
                "SHA256" => digest
                    .try_into()
                    .map(Self::EcdsaP384Sha256)
                    .map_err(|_| SCARD_E_INVALID_PARAMETER),
                "SHA384" => digest
                    .try_into()
                    .map(Self::EcdsaP384Sha384)
                    .map_err(|_| SCARD_E_INVALID_PARAMETER),
                _ => Err(SCARD_E_INVALID_PARAMETER),
            };
        }
        match digest.len() {
            SHA1_LEN => Err(SCARD_E_UNSUPPORTED_FEATURE),
            SHA256_LEN => digest
                .try_into()
                .map(Self::EcdsaP384Sha256)
                .map_err(|_| SCARD_E_INVALID_PARAMETER),
            SHA384_LEN => digest
                .try_into()
                .map(Self::EcdsaP384Sha384)
                .map_err(|_| SCARD_E_INVALID_PARAMETER),
            _ => Err(SCARD_E_INVALID_PARAMETER),
        }
    }

    /// Whether the card returns a big-endian RSA integer that must be
    /// reversed to little-endian for the Windows Card Module ABI.
    #[must_use]
    pub const fn is_rsa(self) -> bool {
        matches!(
            self,
            Self::RsaPssSha256(_)
                | Self::RsaPssSha384(_)
                | Self::RsaPssSha512(_)
                | Self::RsaPkcs1Sha256(_)
                | Self::RsaPkcs1Sha384(_)
                | Self::RsaPkcs1Sha512(_)
        )
    }
}

/// Drive `request` against a prepared [`SigningKey`], returning raw card
/// signature bytes.
pub fn execute_local_sign<T: CardTransport>(
    key: SigningKey<'_, T>,
    request: LocalSignRequest,
) -> Result<Vec<u8>, SignError<T::Error>> {
    match request {
        LocalSignRequest::RsaPssSha256(digest) => key
            .sign_prehashed_sha256_rsa_pss(digest)
            .map(Signature::into_bytes),
        LocalSignRequest::RsaPssSha384(digest) => key
            .sign_prehashed_sha384_rsa_pss(digest)
            .map(Signature::into_bytes),
        LocalSignRequest::RsaPssSha512(digest) => key
            .sign_prehashed_sha512_rsa_pss(digest)
            .map(Signature::into_bytes),
        LocalSignRequest::RsaPkcs1Sha256(digest) => key
            .sign_prehashed_sha256_rsa(digest)
            .map(Signature::into_bytes),
        LocalSignRequest::RsaPkcs1Sha384(digest) => key
            .sign_prehashed_sha384_rsa(digest)
            .map(Signature::into_bytes),
        LocalSignRequest::RsaPkcs1Sha512(digest) => key
            .sign_prehashed_sha512_rsa(digest)
            .map(Signature::into_bytes),
        LocalSignRequest::EcdsaP256Sha256(digest) => key
            .sign_prehashed_sha256_ecdsa_p256(digest)
            .map(Signature::into_bytes),
        LocalSignRequest::EcdsaP384Sha256(digest) => key
            .sign_prehashed_sha256_ecdsa(digest)
            .map(Signature::into_bytes),
        LocalSignRequest::EcdsaP384Sha384(digest) => key
            .sign_prehashed_sha384_ecdsa(digest)
            .map(Signature::into_bytes),
    }
}

#[cfg(test)]
mod tests {
    use refineid_apdu::iso7816::{
        SelectByAidNoFci, SelectFile, SelectFileResponseMode, SelectFileTarget,
    };
    use refineid_apdu::{
        Aid, ApduClass, CardTransport, CommandApdu, CredentialCommand, FileId, PinRetries,
        ResponseApdu, StatusWord, TransportOutcome,
    };
    use refineid_auth::verify::{VERIFY_INS, VERIFY_P1};
    use refineid_auth::{Pin2, PinReferenceScheme, PinSlot, UnvalidatedSecret};
    use refineid_pkcs15::ESIGN_AID;
    use refineid_sign::commands::{
        ExternalHashValue, MseSet, PsoComputeDigitalSignature, PsoHashExternal, SHA1_LEN,
        SHA256_LEN, SHA384_LEN, SignatureAlgRef, expected_length_le,
    };
    use refineid_sign::{
        ECDSA_P256_SIG_BYTES, KEY_REF_AUTH, KeyRef, ORG_QUALIFIED_KEY_REF, QualifiedSignSession,
        RSA_3072_SIG_BYTES, SignOps as _, SignScheme,
    };

    use super::{LocalSignRequest, SigningKeyProfile, execute_local_sign};
    use crate::ParsedSigningPadding;
    use crate::ffi::{
        ALG_ID_NONE, CALG_SHA_256, CALG_SHA_384, CALG_SHA1, DWORD, SCARD_E_INVALID_PARAMETER,
        SCARD_E_UNSUPPORTED_FEATURE,
    };

    const DIGEST_FILL: u8 = 0x5A;
    const SIG_FILL: u8 = 0xC3;
    const PRISTINE_TRIES: u8 = 5;
    const BAD_PSS_SALT_LEN: usize = 16;
    const CALG_MD5_UNSUPPORTED: DWORD = 0x0000_8003;
    const SYNTHETIC_PIN2: &[u8] = b"135790";

    #[derive(Debug)]
    struct ScriptedTransport {
        steps: Vec<(bool, Vec<u8>, ResponseApdu)>,
        cursor: usize,
    }

    impl ScriptedTransport {
        fn plain(steps: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
            Self {
                steps: steps
                    .into_iter()
                    .map(|(wire, response)| (false, wire, response))
                    .collect(),
                cursor: 0,
            }
        }

        fn mixed(steps: Vec<(bool, Vec<u8>, ResponseApdu)>) -> Self {
            Self { steps, cursor: 0 }
        }

        fn drained(&self) -> bool {
            self.cursor == self.steps.len()
        }

        fn step(&mut self, is_credential: bool, wire: &[u8]) -> Result<TransportOutcome, String> {
            let (expected_cred, expected_wire, response) = self
                .steps
                .get(self.cursor)
                .ok_or_else(|| format!("unexpected extra APDU at step {}", self.cursor))?;
            if *expected_cred != is_credential || expected_wire != wire {
                return Err(format!("APDU mismatch at step {}", self.cursor));
            }
            self.cursor += 1;
            Ok(TransportOutcome::Response(response.clone()))
        }
    }

    impl CardTransport for ScriptedTransport {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            self.step(false, command.as_bytes())
        }

        fn transmit_credential(
            &mut self,
            command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            let wire = command.expose_wire(<[u8]>::to_vec);
            self.step(true, &wire)
        }
    }

    fn ok(body: Vec<u8>) -> ResponseApdu {
        let [sw1, sw2] = StatusWord::Success.as_u16().to_be_bytes();
        ResponseApdu { body, sw1, sw2 }
    }

    fn probe_pristine() -> ResponseApdu {
        let [sw1, sw2] = StatusWord::PinIncorrect {
            retries: PinRetries::from_nibble(PRISTINE_TRIES).expect("valid count"),
        }
        .as_u16()
        .to_be_bytes();
        ResponseApdu {
            body: Vec::new(),
            sw1,
            sw2,
        }
    }

    #[test]
    fn parse_rejects_sha1_and_bad_salt_lengths() {
        let sha1 = [DIGEST_FILL; SHA1_LEN];
        let sha256 = [DIGEST_FILL; SHA256_LEN];
        let sha384 = [DIGEST_FILL; SHA384_LEN];

        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::Rsa { allow_pss: true },
                &ParsedSigningPadding::Pss {
                    hash_name: String::from("SHA1"),
                    salt_len: SHA1_LEN,
                },
                ALG_ID_NONE,
                &sha1,
            ),
            Err(SCARD_E_UNSUPPORTED_FEATURE)
        );
        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::Rsa { allow_pss: true },
                &ParsedSigningPadding::Pkcs1 {
                    hash_name: Some(String::from("SHA1")),
                },
                ALG_ID_NONE,
                &sha1,
            ),
            Err(SCARD_E_UNSUPPORTED_FEATURE)
        );
        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::Rsa { allow_pss: true },
                &ParsedSigningPadding::Pkcs1 { hash_name: None },
                ALG_ID_NONE,
                &sha1,
            ),
            Err(SCARD_E_UNSUPPORTED_FEATURE)
        );
        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::Rsa { allow_pss: true },
                &ParsedSigningPadding::Pss {
                    hash_name: String::from("SHA256"),
                    salt_len: BAD_PSS_SALT_LEN,
                },
                ALG_ID_NONE,
                &sha256,
            ),
            Err(SCARD_E_INVALID_PARAMETER)
        );
        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::EcP256,
                &ParsedSigningPadding::Pkcs1 { hash_name: None },
                ALG_ID_NONE,
                &sha384,
            ),
            Err(SCARD_E_INVALID_PARAMETER)
        );
        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::EcP256,
                &ParsedSigningPadding::Pkcs1 {
                    hash_name: Some(String::from("SHA256")),
                },
                ALG_ID_NONE,
                &sha1,
            ),
            Err(SCARD_E_INVALID_PARAMETER),
            "explicit SHA256 with a 20-byte digest is an invalid parameter, not SHA-1 inference"
        );
        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::EcP384,
                &ParsedSigningPadding::Pkcs1 { hash_name: None },
                ALG_ID_NONE,
                &sha256,
            ),
            Ok(LocalSignRequest::EcdsaP384Sha256(sha256))
        );
        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::UnsupportedEc,
                &ParsedSigningPadding::Pkcs1 { hash_name: None },
                ALG_ID_NONE,
                &sha256,
            ),
            Err(SCARD_E_UNSUPPORTED_FEATURE)
        );
    }

    #[test]
    fn parse_validates_legacy_ai_hash_alg_identifiers() {
        let sha256 = [DIGEST_FILL; SHA256_LEN];
        let sha384 = [DIGEST_FILL; SHA384_LEN];

        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::Rsa { allow_pss: true },
                &ParsedSigningPadding::Pkcs1 { hash_name: None },
                CALG_SHA1,
                &sha256,
            ),
            Err(SCARD_E_UNSUPPORTED_FEATURE),
            "explicit CALG_SHA1 must not silently sign a SHA-256-sized buffer as SHA-256"
        );
        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::Rsa { allow_pss: true },
                &ParsedSigningPadding::Pkcs1 { hash_name: None },
                CALG_MD5_UNSUPPORTED,
                &sha256,
            ),
            Err(SCARD_E_UNSUPPORTED_FEATURE)
        );
        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::Rsa { allow_pss: true },
                &ParsedSigningPadding::Pkcs1 { hash_name: None },
                CALG_SHA_256,
                &sha384,
            ),
            Err(SCARD_E_INVALID_PARAMETER),
            "explicit CALG_SHA_256 must reject a mismatched digest length"
        );
        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::Rsa { allow_pss: true },
                &ParsedSigningPadding::Pkcs1 { hash_name: None },
                CALG_SHA_384,
                &sha384,
            ),
            Ok(LocalSignRequest::RsaPkcs1Sha384(sha384))
        );
        assert_eq!(
            LocalSignRequest::parse(
                SigningKeyProfile::Rsa { allow_pss: true },
                &ParsedSigningPadding::Pkcs1 {
                    hash_name: Some(String::from("SHA384")),
                },
                CALG_SHA_256,
                &sha384,
            ),
            Err(SCARD_E_INVALID_PARAMETER),
            "conflicting padding hash name and aiHashAlg must be rejected"
        );
    }

    #[test]
    fn organizational_auth_key_signs_inline_without_pso_hash() {
        let digest = [DIGEST_FILL; SHA256_LEN];
        let sig_bytes = vec![SIG_FILL; RSA_3072_SIG_BYTES];
        let request = LocalSignRequest::parse(
            SigningKeyProfile::Rsa { allow_pss: true },
            &ParsedSigningPadding::Pss {
                hash_name: String::from("SHA256"),
                salt_len: SHA256_LEN,
            },
            ALG_ID_NONE,
            &digest,
        )
        .expect("RSA-PSS SHA-256 request parses");
        assert!(request.is_rsa());

        let mse = MseSet {
            alg_ref: SignatureAlgRef::SHA256_RSA_PSS,
            key_ref: KEY_REF_AUTH,
        }
        .into_apdu()
        .expect("MSE encodes")
        .as_bytes()
        .to_vec();
        let inline_cds = PsoComputeDigitalSignature
            .into_apdu_with_digest(
                ExternalHashValue::Sha256(digest),
                expected_length_le(RSA_3072_SIG_BYTES),
            )
            .expect("inline PSO:CDS encodes")
            .as_bytes()
            .to_vec();

        let mut transport = ScriptedTransport::plain(vec![
            (mse, ok(Vec::new())),
            (inline_cds, ok(sig_bytes.clone())),
        ]);
        let signed = execute_local_sign(
            transport.authentication_key(SignScheme::Organizational),
            request,
        )
        .expect("organizational auth signing succeeds inline");
        assert_eq!(signed, sig_bytes);
        assert!(transport.drained());
    }

    #[test]
    fn citizen_auth_key_uses_pso_hash_then_empty_pso_cds() {
        let digest = [DIGEST_FILL; SHA256_LEN];
        let sig_bytes = vec![SIG_FILL; ECDSA_P256_SIG_BYTES];
        let request = LocalSignRequest::parse(
            SigningKeyProfile::EcP256,
            &ParsedSigningPadding::Pkcs1 { hash_name: None },
            ALG_ID_NONE,
            &digest,
        )
        .expect("P-256 SHA-256 request parses");
        assert!(!request.is_rsa());

        let mse = MseSet {
            alg_ref: SignatureAlgRef::SHA256_ECDSA,
            key_ref: KEY_REF_AUTH,
        }
        .into_apdu()
        .expect("MSE encodes")
        .as_bytes()
        .to_vec();
        let pso_hash = PsoHashExternal {
            hash: ExternalHashValue::Sha256(digest),
        }
        .into_apdu()
        .expect("PSO:HASH encodes")
        .as_bytes()
        .to_vec();
        let pso_cds = PsoComputeDigitalSignature
            .into_apdu(expected_length_le(ECDSA_P256_SIG_BYTES))
            .as_bytes()
            .to_vec();

        let mut transport = ScriptedTransport::plain(vec![
            (mse, ok(Vec::new())),
            (pso_hash, ok(Vec::new())),
            (pso_cds, ok(sig_bytes.clone())),
        ]);
        let signed = execute_local_sign(transport.authentication_key(SignScheme::Citizen), request)
            .expect("citizen P-256 auth signing succeeds");
        assert_eq!(signed, sig_bytes);
        assert!(transport.drained());
    }

    #[test]
    fn organizational_qualified_session_enters_esign_and_signs_inline() {
        let digest = [DIGEST_FILL; SHA256_LEN];
        let sig_bytes = vec![SIG_FILL; ECDSA_P256_SIG_BYTES];
        let request = LocalSignRequest::parse(
            SigningKeyProfile::EcP256,
            &ParsedSigningPadding::Pkcs1 { hash_name: None },
            ALG_ID_NONE,
            &digest,
        )
        .expect("P-256 request parses");

        let select_mf = SelectFile {
            class: ApduClass::Plain,
            target: SelectFileTarget::AnyByFileId(Some(FileId::MF)),
            response_mode: SelectFileResponseMode::None,
        }
        .into_apdu()
        .as_bytes()
        .to_vec();
        let select_esign = SelectByAidNoFci {
            aid: Aid::from_slice(ESIGN_AID).expect("valid ESIGN AID"),
        }
        .into_apdu()
        .as_bytes()
        .to_vec();
        let probe_pin2 = vec![
            ApduClass::Plain.as_byte(),
            VERIFY_INS,
            VERIFY_P1,
            PinReferenceScheme::Organizational.reference(PinSlot::Pin2),
        ];
        let mut verify_pin2 = probe_pin2.clone();
        verify_pin2.push(u8::try_from(SYNTHETIC_PIN2.len()).expect("fits u8"));
        verify_pin2.extend_from_slice(SYNTHETIC_PIN2);
        let mse = MseSet {
            alg_ref: SignatureAlgRef::SHA256_ECDSA,
            key_ref: KeyRef::Sign
                .reference(SignScheme::Organizational)
                .expect("org qualified key ref"),
        }
        .into_apdu()
        .expect("MSE encodes")
        .as_bytes()
        .to_vec();
        assert_eq!(mse.last().copied(), Some(ORG_QUALIFIED_KEY_REF));
        let inline_cds = PsoComputeDigitalSignature
            .into_apdu_with_digest(
                ExternalHashValue::Sha256(digest),
                expected_length_le(ECDSA_P256_SIG_BYTES),
            )
            .expect("inline PSO:CDS encodes")
            .as_bytes()
            .to_vec();

        let transport = ScriptedTransport::mixed(vec![
            (false, select_mf, ok(Vec::new())),
            (false, select_esign, ok(Vec::new())),
            (false, probe_pin2, probe_pristine()),
            (true, verify_pin2, ok(Vec::new())),
            (false, mse, ok(Vec::new())),
            (false, inline_cds, ok(sig_bytes.clone())),
        ]);
        let pin2 = Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(SYNTHETIC_PIN2.to_vec()))
            .expect("valid synthetic PIN 2");
        let session = QualifiedSignSession::open(transport, SignScheme::Organizational, pin2)
            .expect("organizational qualified session opens");
        let (transport, signed) = session.sign_once(|key| execute_local_sign(key, request));
        assert_eq!(signed.expect("qualified signing succeeds"), sig_bytes);
        assert!(transport.drained());
    }
}
