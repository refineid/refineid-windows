//! The credential-profile registry (RAPP v26.10.22 section 9).
//!
//! The names come from `refineid_rapp`; this module names them for callers
//! that hold a profile as text, such as a stored grant.

pub use refineid_rapp::ProfileName;

/// Card status, identity, and certificates: reads only.
pub const PROFILE_CARD_STATUS: &str = ProfileName::CardStatus.as_str();
/// Browser or application authentication: PIN 1 verify and key operation.
pub const PROFILE_AUTHENTICATION: &str = ProfileName::Authentication.as_str();
/// Sign a document digest: PIN 2 verify and key operation.
pub const PROFILE_DOCUMENT_SIGNING: &str = ProfileName::DocumentSigning.as_str();
