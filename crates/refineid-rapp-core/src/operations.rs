//! Typed card operations re-exported from `refineid_rapp`.

pub use refineid_rapp::{
    CardInspection, CardKeyProfile, CardKeyProfile as KeyProfile, CardOperation,
    CardOperationError, CardOperationError as OperationError, CardOperationResult, CertificateKind,
    CredentialKind, OperationRequest, SignatureAlgorithm,
};

/// Extension trait providing digest length metadata for signature algorithms.
pub trait SignatureAlgorithmExt {
    /// Returns the length in bytes of the hash digest expected by this algorithm.
    fn digest_length(self) -> usize;
}

impl SignatureAlgorithmExt for SignatureAlgorithm {
    fn digest_length(self) -> usize {
        match self {
            Self::EcdsaSha224 => 28,
            Self::EcdsaSha256 | Self::RsaPkcs1Sha256 | Self::RsaPssSha256 => 32,
            Self::EcdsaSha384 | Self::RsaPkcs1Sha384 => 48,
            Self::EcdsaSha512 | Self::RsaPkcs1Sha512 => 64,
        }
    }
}

/// Extension trait providing action name metadata for card operations.
pub trait CardOperationExt {
    /// Returns the wire action name for this card operation.
    fn action(&self) -> &'static str;
}

impl CardOperationExt for CardOperation {
    fn action(&self) -> &'static str {
        match self {
            Self::InspectCard => "inspect_card",
            Self::ReadIdentity => "read_identity",
            Self::ReadCertificate { .. } => "read_certificate",
            Self::BrowserAuthenticate { .. } => "browser_authenticate",
            Self::SignDocument { .. } => "sign_document",
        }
    }
}
