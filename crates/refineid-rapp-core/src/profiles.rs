//! The credential-profile registry (RAPP v26.10.10 section 9).
//!
//! The names reserve design space; the card-specific payload schemas need a
//! separate reviewed profile specification, so this module carries only
//! what the core protocol requires of a profile: its name and whether its
//! actions culminate in a consequential credential command.

pub use refineid_rapp::ProfileName;

/// Inspect supported card and retry state. No consequential command.
pub const PROFILE_CARD_STATUS: &str = "fi.refineid.card-status.v1";
/// Browser or application authentication: PIN 1 verify and key operation.
pub const PROFILE_AUTHENTICATION: &str = "fi.refineid.authentication.v1";
/// Sign a document digest: PIN 2 verify and key operation.
pub const PROFILE_DOCUMENT_SIGNING: &str = "fi.refineid.document-signing.v1";
