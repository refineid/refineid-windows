//! Replay of the corpus `rejected_envelope` section against this crate's
//! envelope reader.
//!
//! The corpus rejection classes come from the independent reference
//! implementation's error vocabulary; each vector is mapped to exactly one
//! of this crate's `message::SchemaViolation` variants by the explicit table
//! below, and equality with that variant is asserted.

use refineid_rapp_core::WIRE_VERSION;
use refineid_rapp_core::message::{Envelope, SchemaViolation};
use serde::Deserialize;

mod corpus_util;
use corpus_util::{CORPUS_JSON, decode_hex};

/// Vectors in the `rejected_envelope` section.
const REJECTED_ENVELOPE_COUNT: usize = 12;

/// The one vector whose envelope is schema-valid and rejected only by the
/// version admission rule.
const UNSUPPORTED_VERSION_VECTOR: &str = "unsupported-version";
/// The corpus rejection class of that vector.
const UNSUPPORTED_VERSION_ERROR: &str = "UnsupportedVersion";

/// The corpus section this file replays.
#[derive(Deserialize)]
struct Corpus {
    rejected_envelope: Vec<RejectedEnvelope>,
}

/// One rejected-envelope vector.
#[derive(Deserialize)]
struct RejectedEnvelope {
    name: String,
    canonical_cbor_hex: String,
    supported_critical: Vec<String>,
    error: String,
}

#[test]
fn malformed_or_unsupported_envelopes_are_rejected_by_class() {
    let corpus: Corpus =
        serde_json::from_str(CORPUS_JSON).expect("the vendored RAPP corpus must be valid JSON");
    assert_eq!(corpus.rejected_envelope.len(), REJECTED_ENVELOPE_COUNT);
    for vector in &corpus.rejected_envelope {
        // This crate understands no critical extension at all, which matches
        // the corpus declaration of an empty supported set for every vector.
        assert!(
            vector.supported_critical.is_empty(),
            "{} declares supported critical extensions this crate cannot model",
            vector.name
        );
        let bytes = decode_hex(&vector.canonical_cbor_hex);
        if vector.name == UNSUPPORTED_VERSION_VECTOR {
            // The admission decision lives in the engine's message
            // channel, which is not public. A well-formed envelope
            // with a non-current version decodes and fails the
            // comparison, exactly as the engine applies it; a
            // malformed version shape (like the historical
            // two-element array) fails `Envelope::decode` itself.
            assert_eq!(vector.error, UNSUPPORTED_VERSION_ERROR, "{}", vector.name);
            match Envelope::decode(&bytes) {
                Err(_) => {}
                Ok(envelope) => assert_ne!(
                    envelope.version, WIRE_VERSION,
                    "{} must fail the version admission comparison",
                    vector.name
                ),
            }
            continue;
        }
        let expected = expected_schema_violation(&vector.name, &vector.error);
        assert_eq!(
            Envelope::decode(&bytes),
            Err(expected),
            "{} rejection class",
            vector.name
        );
    }
}

/// Maps one corpus envelope rejection, named in the reference
/// implementation's vocabulary, to this crate's `SchemaViolation` variant.
///
/// Two families collapse deliberately. First, this crate's envelope reader
/// matches each known key together with its schema shape, so a known key
/// carrying the wrong shape falls into the unknown-field arm. Second, RAPP
/// 0.1 understands no critical extension, so a missing and an unsupported
/// critical extension are the same local violation.
fn expected_schema_violation(name: &str, error: &str) -> SchemaViolation {
    match (name, error) {
        ("missing-version", "MissingField { field: \"version\" }") => SchemaViolation::MissingField,
        ("unknown-envelope-field", "UnknownField") => SchemaViolation::UnknownField,
        ("wrong-version-type", "WrongType { field: \"version\" }") => {
            SchemaViolation::WrongFieldType
        }
        ("unknown-message-type", "UnknownMessageType") => SchemaViolation::UnknownMessageType,
        (
            "wrong-session-id-length",
            "WrongLength { field: \"session_id\", expected: 16, got: 15 }",
        ) => SchemaViolation::WrongFieldType,
        ("wrong-sequence-type", "WrongType { field: \"sequence\" }")
        | ("wrong-body-type", "WrongType { field: \"body\" }")
        | ("wrong-critical-type", "WrongType { field: \"critical\" }")
        | ("wrong-extensions-type", "WrongType { field: \"extensions\" }") => {
            SchemaViolation::UnknownField
        }
        ("critical-extension-missing", "CriticalExtensionMissing")
        | ("unsupported-critical-extension", "UnsupportedCriticalExtension") => {
            SchemaViolation::UnknownCriticalField
        }
        (name, error) => panic!("unmapped rejected-envelope vector {name} ({error})"),
    }
}
