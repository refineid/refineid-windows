//! The messages on the agent's pipe: one signature request from the key
//! storage provider, one answer from the agent (Windows STPA W-R-1, W-R-6).
//!
//! A request names the pairing, the key profile, the signature algorithm
//! and the digest; it names neither the site nor the calling program, which
//! the agent learns from the pipe itself (W-R-10). Every message starts with
//! [`WIRE_VERSION`] and a kind byte, and decodes only through [`SignRequest::decode`]
//! and [`SignAnswer::decode`], which refuse anything not exactly as written
//! here.

use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::operations::{KeyProfile, SignatureAlgorithm, SignatureAlgorithmExt};

/// The version byte every message starts with.
pub const WIRE_VERSION: u8 = 1;
/// The longest message either side sends or accepts.
pub const MAX_MESSAGE: usize = 1024;

/// The size of a pairing identifier on the wire.
const PAIR_ID_LEN: usize = refineid_rapp::PAIR_ID_SIZE;
/// The longest signature an answer carries: RSA 3072, the largest key
/// profile.
const MAX_SIGNATURE: usize = 384;

const KIND_SIGN: u8 = 1;

const ANSWER_SIGNATURE: u8 = 1;
const ANSWER_DENIED: u8 = 2;
const ANSWER_CANCELLED: u8 = 3;
const ANSWER_REJECTED: u8 = 4;
const ANSWER_LOST: u8 = 5;
const ANSWER_NO_PHONE: u8 = 6;
const ANSWER_BUSY: u8 = 7;
const ANSWER_FAILED: u8 = 8;

const PROFILE_ECDSA_P256: u8 = 1;
const PROFILE_ECDSA_P384: u8 = 2;
const PROFILE_RSA_2048: u8 = 3;
const PROFILE_RSA_3072: u8 = 4;

const ALGORITHM_ECDSA_SHA224: u8 = 1;
const ALGORITHM_ECDSA_SHA256: u8 = 2;
const ALGORITHM_ECDSA_SHA384: u8 = 3;
const ALGORITHM_ECDSA_SHA512: u8 = 4;
const ALGORITHM_RSA_PKCS1_SHA256: u8 = 5;
const ALGORITHM_RSA_PKCS1_SHA384: u8 = 6;
const ALGORITHM_RSA_PKCS1_SHA512: u8 = 7;
const ALGORITHM_RSA_PSS_SHA256: u8 = 8;

/// Why a message was refused at the border.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The message is longer than [`MAX_MESSAGE`].
    Oversized,
    /// The version byte is not [`WIRE_VERSION`].
    Version,
    /// The kind byte names no message.
    Kind,
    /// The message ends early or carries bytes after its end.
    Length,
    /// The key profile byte names no profile.
    Profile,
    /// The algorithm byte names no algorithm.
    Algorithm,
    /// The digest is not the length the algorithm signs.
    Digest,
    /// The signature is empty or longer than any key signs.
    Signature,
    /// The algorithm is not one the key profile signs with.
    Mismatch,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let what = match self {
            Self::Oversized => "the message is too long",
            Self::Version => "the message has another version",
            Self::Kind => "the message kind is unknown",
            Self::Length => "the message length is wrong",
            Self::Profile => "the key profile is unknown",
            Self::Algorithm => "the signature algorithm is unknown",
            Self::Digest => "the digest length does not match the algorithm",
            Self::Signature => "the signature length is out of range",
            Self::Mismatch => "the algorithm does not suit the key profile",
        };
        formatter.write_str(what)
    }
}

impl core::error::Error for WireError {}

/// One signature the key storage provider asks the agent for.
///
/// A value is proof that the algorithm suits the key profile and the digest
/// is exactly as long as the algorithm signs: the fields are private and both
/// constructors check it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pair_id: PairId,
    key_profile: KeyProfile,
    algorithm: SignatureAlgorithm,
    digest: Vec<u8>,
}

impl SignRequest {
    /// A request to sign `digest` with the key of `pair_id`.
    ///
    /// # Errors
    /// [`WireError::Digest`] when the digest is not as long as `algorithm`
    /// signs.
    pub fn new(
        pair_id: PairId,
        key_profile: KeyProfile,
        algorithm: SignatureAlgorithm,
        digest: &[u8],
    ) -> Result<Self, WireError> {
        if !suits(key_profile, algorithm) {
            return Err(WireError::Mismatch);
        }
        if digest.len() != algorithm.digest_length() {
            return Err(WireError::Digest);
        }
        Ok(Self {
            pair_id,
            key_profile,
            algorithm,
            digest: digest.to_vec(),
        })
    }

    /// The pairing whose key signs.
    #[must_use]
    pub const fn pair_id(&self) -> PairId {
        self.pair_id
    }

    /// The key profile the certificate implies.
    #[must_use]
    pub const fn key_profile(&self) -> KeyProfile {
        self.key_profile
    }

    /// The signature algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// The digest to sign.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// The request as it crosses the pipe.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(5 + PAIR_ID_LEN + self.digest.len());
        bytes.push(WIRE_VERSION);
        bytes.push(KIND_SIGN);
        bytes.extend_from_slice(self.pair_id.as_bytes());
        bytes.push(profile_code(self.key_profile));
        bytes.push(algorithm_code(self.algorithm));
        // The digest is at most 64 bytes, as `new` and `decode` ensure.
        bytes.push(u8::try_from(self.digest.len()).unwrap_or(u8::MAX));
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    /// Decodes a request from the pipe.
    ///
    /// # Errors
    /// [`WireError`] naming the first thing that is not as specified.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes)?;
        if reader.byte()? != KIND_SIGN {
            return Err(WireError::Kind);
        }
        let pair_id: [u8; PAIR_ID_LEN] = reader
            .take(PAIR_ID_LEN)?
            .try_into()
            .map_err(|_| WireError::Length)?;
        let key_profile = profile_from(reader.byte()?)?;
        let algorithm = algorithm_from(reader.byte()?)?;
        let digest_len = usize::from(reader.byte()?);
        let digest = reader.take(digest_len)?;
        reader.end()?;
        Self::new(PairId::from_array(pair_id), key_profile, algorithm, digest)
    }
}

/// The agent's answer to one [`SignRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignAnswer {
    /// The phone signed; the bytes are the card's signature as the phone
    /// returned it, which the provider verifies before use (W-R-5).
    Signature(Vec<u8>),
    /// The holder declined on the phone.
    Denied,
    /// The operation expired before the card was commanded.
    Cancelled,
    /// The phone refused the request.
    Rejected,
    /// The session to the phone ended before its answer; the operation
    /// ended with it (RAPP v26.10.21 section 8.1 item 3).
    Lost,
    /// The paired phone could not be reached in time.
    NoPhone,
    /// Another signature is in progress.
    Busy,
    /// The agent could not serve the request.
    Failed,
}

impl SignAnswer {
    /// The answer as it crosses the pipe. A signature that is empty or
    /// longer than any key signs is sent as [`SignAnswer::Failed`], since
    /// the receiver would refuse it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        if let Self::Signature(signature) = self
            && (signature.is_empty() || signature.len() > MAX_SIGNATURE)
        {
            return Self::Failed.encode();
        }
        let kind = match self {
            Self::Signature(_) => ANSWER_SIGNATURE,
            Self::Denied => ANSWER_DENIED,
            Self::Cancelled => ANSWER_CANCELLED,
            Self::Rejected => ANSWER_REJECTED,
            Self::Lost => ANSWER_LOST,
            Self::NoPhone => ANSWER_NO_PHONE,
            Self::Busy => ANSWER_BUSY,
            Self::Failed => ANSWER_FAILED,
        };
        let mut bytes = vec![WIRE_VERSION, kind];
        if let Self::Signature(signature) = self {
            // At most `MAX_SIGNATURE` bytes, as checked above.
            let length = u16::try_from(signature.len()).unwrap_or(u16::MAX);
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(signature);
        }
        bytes
    }

    /// Decodes an answer from the pipe.
    ///
    /// # Errors
    /// [`WireError`] naming the first thing that is not as specified.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes)?;
        let answer = match reader.byte()? {
            ANSWER_SIGNATURE => {
                let length_bytes: [u8; 2] =
                    reader.take(2)?.try_into().map_err(|_| WireError::Length)?;
                let length = usize::from(u16::from_le_bytes(length_bytes));
                if length == 0 || length > MAX_SIGNATURE {
                    return Err(WireError::Signature);
                }
                Self::Signature(reader.take(length)?.to_vec())
            }
            ANSWER_DENIED => Self::Denied,
            ANSWER_CANCELLED => Self::Cancelled,
            ANSWER_REJECTED => Self::Rejected,
            ANSWER_LOST => Self::Lost,
            ANSWER_NO_PHONE => Self::NoPhone,
            ANSWER_BUSY => Self::Busy,
            ANSWER_FAILED => Self::Failed,
            _ => return Err(WireError::Kind),
        };
        reader.end()?;
        Ok(answer)
    }
}

/// Reads a message front to back, refusing anything short or long.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_MESSAGE {
            return Err(WireError::Oversized);
        }
        let mut reader = Self { rest: bytes };
        if reader.byte()? != WIRE_VERSION {
            return Err(WireError::Version);
        }
        Ok(reader)
    }

    fn byte(&mut self) -> Result<u8, WireError> {
        let (&first, rest) = self.rest.split_first().ok_or(WireError::Length)?;
        self.rest = rest;
        Ok(first)
    }

    const fn take(&mut self, count: usize) -> Result<&'a [u8], WireError> {
        if self.rest.len() < count {
            return Err(WireError::Length);
        }
        let (taken, rest) = self.rest.split_at(count);
        self.rest = rest;
        Ok(taken)
    }

    const fn end(&self) -> Result<(), WireError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(WireError::Length)
        }
    }
}

/// Whether `algorithm` is one the key of `profile` signs with.
const fn suits(profile: KeyProfile, algorithm: SignatureAlgorithm) -> bool {
    let ecdsa = matches!(
        algorithm,
        SignatureAlgorithm::EcdsaSha224
            | SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384
            | SignatureAlgorithm::EcdsaSha512
    );
    match profile {
        KeyProfile::EcdsaP256 | KeyProfile::EcdsaP384 => ecdsa,
        KeyProfile::Rsa2048 | KeyProfile::Rsa3072 => !ecdsa,
    }
}

const fn profile_code(profile: KeyProfile) -> u8 {
    match profile {
        KeyProfile::EcdsaP256 => PROFILE_ECDSA_P256,
        KeyProfile::EcdsaP384 => PROFILE_ECDSA_P384,
        KeyProfile::Rsa2048 => PROFILE_RSA_2048,
        KeyProfile::Rsa3072 => PROFILE_RSA_3072,
    }
}

const fn profile_from(code: u8) -> Result<KeyProfile, WireError> {
    match code {
        PROFILE_ECDSA_P256 => Ok(KeyProfile::EcdsaP256),
        PROFILE_ECDSA_P384 => Ok(KeyProfile::EcdsaP384),
        PROFILE_RSA_2048 => Ok(KeyProfile::Rsa2048),
        PROFILE_RSA_3072 => Ok(KeyProfile::Rsa3072),
        _ => Err(WireError::Profile),
    }
}

const fn algorithm_code(algorithm: SignatureAlgorithm) -> u8 {
    match algorithm {
        SignatureAlgorithm::EcdsaSha224 => ALGORITHM_ECDSA_SHA224,
        SignatureAlgorithm::EcdsaSha256 => ALGORITHM_ECDSA_SHA256,
        SignatureAlgorithm::EcdsaSha384 => ALGORITHM_ECDSA_SHA384,
        SignatureAlgorithm::EcdsaSha512 => ALGORITHM_ECDSA_SHA512,
        SignatureAlgorithm::RsaPkcs1Sha256 => ALGORITHM_RSA_PKCS1_SHA256,
        SignatureAlgorithm::RsaPkcs1Sha384 => ALGORITHM_RSA_PKCS1_SHA384,
        SignatureAlgorithm::RsaPkcs1Sha512 => ALGORITHM_RSA_PKCS1_SHA512,
        SignatureAlgorithm::RsaPssSha256 => ALGORITHM_RSA_PSS_SHA256,
    }
}

const fn algorithm_from(code: u8) -> Result<SignatureAlgorithm, WireError> {
    match code {
        ALGORITHM_ECDSA_SHA224 => Ok(SignatureAlgorithm::EcdsaSha224),
        ALGORITHM_ECDSA_SHA256 => Ok(SignatureAlgorithm::EcdsaSha256),
        ALGORITHM_ECDSA_SHA384 => Ok(SignatureAlgorithm::EcdsaSha384),
        ALGORITHM_ECDSA_SHA512 => Ok(SignatureAlgorithm::EcdsaSha512),
        ALGORITHM_RSA_PKCS1_SHA256 => Ok(SignatureAlgorithm::RsaPkcs1Sha256),
        ALGORITHM_RSA_PKCS1_SHA384 => Ok(SignatureAlgorithm::RsaPkcs1Sha384),
        ALGORITHM_RSA_PKCS1_SHA512 => Ok(SignatureAlgorithm::RsaPkcs1Sha512),
        ALGORITHM_RSA_PSS_SHA256 => Ok(SignatureAlgorithm::RsaPssSha256),
        _ => Err(WireError::Algorithm),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> PairId {
        PairId::from_array([7; PAIR_ID_LEN])
    }

    fn request() -> SignRequest {
        SignRequest::new(
            pair(),
            KeyProfile::EcdsaP384,
            SignatureAlgorithm::EcdsaSha384,
            &[0x5A; 48],
        )
        .expect("a 48-byte digest is what ECDSA SHA-384 signs")
    }

    #[test]
    fn a_request_round_trips() {
        assert_eq!(SignRequest::decode(&request().encode()), Ok(request()));
    }

    #[test]
    fn a_digest_of_the_wrong_length_is_refused() {
        assert_eq!(
            SignRequest::new(
                pair(),
                KeyProfile::EcdsaP384,
                SignatureAlgorithm::EcdsaSha384,
                &[0; 32]
            ),
            Err(WireError::Digest)
        );
        let mut bytes = request().encode();
        let length_at = 2 + PAIR_ID_LEN + 2;
        bytes[length_at] = 32;
        bytes.truncate(length_at + 1 + 32);
        assert_eq!(SignRequest::decode(&bytes), Err(WireError::Digest));
    }

    #[test]
    fn a_request_with_trailing_or_missing_bytes_is_refused() {
        let mut long = request().encode();
        long.push(0);
        assert_eq!(SignRequest::decode(&long), Err(WireError::Length));
        let mut short = request().encode();
        short.pop();
        assert_eq!(SignRequest::decode(&short), Err(WireError::Length));
    }

    #[test]
    fn another_version_or_kind_is_refused() {
        let mut bytes = request().encode();
        bytes[0] = WIRE_VERSION + 1;
        assert_eq!(SignRequest::decode(&bytes), Err(WireError::Version));
        let mut bytes = request().encode();
        bytes[1] = 0;
        assert_eq!(SignRequest::decode(&bytes), Err(WireError::Kind));
    }

    #[test]
    fn unknown_profile_and_algorithm_codes_are_refused() {
        let mut bytes = request().encode();
        bytes[2 + PAIR_ID_LEN] = 0;
        assert_eq!(SignRequest::decode(&bytes), Err(WireError::Profile));
        let mut bytes = request().encode();
        bytes[2 + PAIR_ID_LEN + 1] = 0;
        assert_eq!(SignRequest::decode(&bytes), Err(WireError::Algorithm));
    }

    #[test]
    fn every_algorithm_and_profile_code_round_trips() {
        for algorithm in [
            SignatureAlgorithm::EcdsaSha224,
            SignatureAlgorithm::EcdsaSha256,
            SignatureAlgorithm::EcdsaSha384,
            SignatureAlgorithm::EcdsaSha512,
            SignatureAlgorithm::RsaPkcs1Sha256,
            SignatureAlgorithm::RsaPkcs1Sha384,
            SignatureAlgorithm::RsaPkcs1Sha512,
            SignatureAlgorithm::RsaPssSha256,
        ] {
            assert_eq!(algorithm_from(algorithm_code(algorithm)), Ok(algorithm));
        }
        for profile in [
            KeyProfile::EcdsaP256,
            KeyProfile::EcdsaP384,
            KeyProfile::Rsa2048,
            KeyProfile::Rsa3072,
        ] {
            assert_eq!(profile_from(profile_code(profile)), Ok(profile));
        }
    }

    #[test]
    fn every_answer_round_trips() {
        for answer in [
            SignAnswer::Signature(vec![1; 96]),
            SignAnswer::Denied,
            SignAnswer::Cancelled,
            SignAnswer::Rejected,
            SignAnswer::Lost,
            SignAnswer::NoPhone,
            SignAnswer::Busy,
            SignAnswer::Failed,
        ] {
            assert_eq!(SignAnswer::decode(&answer.encode()), Ok(answer));
        }
    }

    #[test]
    fn an_empty_or_oversized_signature_is_sent_as_a_failure() {
        assert_eq!(
            SignAnswer::decode(&SignAnswer::Signature(Vec::new()).encode()),
            Ok(SignAnswer::Failed)
        );
        assert_eq!(
            SignAnswer::decode(&SignAnswer::Signature(vec![1; MAX_SIGNATURE + 1]).encode()),
            Ok(SignAnswer::Failed)
        );
        let mut oversized = vec![WIRE_VERSION, ANSWER_SIGNATURE];
        let length = u16::try_from(MAX_SIGNATURE + 1).expect("fits");
        oversized.extend_from_slice(&length.to_le_bytes());
        oversized.extend(vec![1; MAX_SIGNATURE + 1]);
        assert_eq!(SignAnswer::decode(&oversized), Err(WireError::Signature));
    }

    #[test]
    fn an_algorithm_the_profile_does_not_sign_with_is_refused() {
        assert_eq!(
            SignRequest::new(
                pair(),
                KeyProfile::EcdsaP256,
                SignatureAlgorithm::RsaPkcs1Sha256,
                &[0; 32]
            ),
            Err(WireError::Mismatch)
        );
        assert_eq!(
            SignRequest::new(
                pair(),
                KeyProfile::Rsa2048,
                SignatureAlgorithm::EcdsaSha256,
                &[0; 32]
            ),
            Err(WireError::Mismatch)
        );
    }

    #[test]
    fn an_oversized_message_is_refused_before_it_is_read() {
        assert_eq!(
            SignAnswer::decode(&[WIRE_VERSION; MAX_MESSAGE + 1]),
            Err(WireError::Oversized)
        );
    }
}
