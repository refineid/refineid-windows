//! Protocol identifiers re-exported and extended from `refineid_rapp`.

use getrandom::fill;

pub use refineid_rapp::{
    GrantsHash, OfferId, OperationId, PairId, PairingSecret, RendezvousToken, RequestHash,
    SessionId, derive_pair_id, derive_rendezvous_token, derive_session_id,
};

/// The random-generator failure surfaced by identifier creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomUnavailable;

fn secure_random<const N: usize>() -> Result<[u8; N], RandomUnavailable> {
    let mut buf = [0u8; N];
    fill(&mut buf).map_err(|_| RandomUnavailable)?;
    Ok(buf)
}

/// A random 32-byte liveness challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge(pub [u8; 32]);

impl Challenge {
    /// Creates a fresh random challenge.
    ///
    /// # Errors
    /// Fails only when the operating system's generator is unavailable.
    pub fn random() -> Result<Self, RandomUnavailable> {
        Ok(Self(secure_random()?))
    }

    /// Public bytes of the challenge.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Extension trait for generating random identifiers.
pub trait RandomIdExt: Sized {
    /// Generates a new identifier using a cryptographically secure random source.
    ///
    /// # Errors
    /// Returns [`RandomUnavailable`] when the platform entropy source fails.
    fn random() -> Result<Self, RandomUnavailable>;
}

impl RandomIdExt for OfferId {
    fn random() -> Result<Self, RandomUnavailable> {
        Ok(Self::from_array(secure_random()?))
    }
}

impl RandomIdExt for OperationId {
    fn random() -> Result<Self, RandomUnavailable> {
        Ok(Self::from_array(secure_random()?))
    }
}

impl RandomIdExt for PairingSecret {
    fn random() -> Result<Self, RandomUnavailable> {
        Ok(Self::from_random_bytes(secure_random()?))
    }
}
