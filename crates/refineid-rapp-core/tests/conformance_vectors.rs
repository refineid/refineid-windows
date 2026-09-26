//! Replay of the versioned, implementation-independent RAPP conformance
//! corpus against this crate's deterministic CBOR, identifier derivation,
//! and defined hashes.
//!
//! The corpus is shared with an independent implementation of the same
//! protocol document; its vector names and rejection classes come from that
//! implementation's vocabulary, so every rejection class is mapped to this
//! crate's error variant with an explicit table.
//!
//! The `stream_rendezvous` section is replayed by `stream_vectors.rs`; its
//! vector count still gates the corpus metadata here.

use std::collections::HashSet;

use refineid_rapp_core::cbor::{DecodeError, Value};
use refineid_rapp_core::hashes::{grants_hash, request_hash};
use refineid_rapp_core::ids::{
    OPERATION_ID_LENGTH, OperationId, PAIR_ID_LENGTH, RENDEZVOUS_TOKEN_LENGTH, SESSION_ID_LENGTH,
    SessionId, derive_pair_id, derive_rendezvous_token, derive_session_id,
};
use serde::Deserialize;

mod corpus_util;
use corpus_util::{CORPUS_JSON, decode_hex, fixed};

/// The corpus self-description this replay is written against.
const CORPUS_FORMAT: &str = "fi.refineid.rapp.conformance-v1";
/// The protocol document revision the corpus is derived from.
const PROTOCOL_DOCUMENT_VERSION: &str = "26.9.13";

/// Vectors in the `deterministic_cbor` section.
const DETERMINISTIC_CBOR_COUNT: usize = 15;
/// Vectors in the `rejected_cbor` section.
const REJECTED_CBOR_COUNT: usize = 8;
/// Vectors in the `rejected_envelope` section.
const REJECTED_ENVELOPE_COUNT: usize = 12;
/// Vectors in the `identifier_derivation` section.
const IDENTIFIER_DERIVATION_COUNT: usize = 2;
/// Vectors in the `grants_hash` section.
const GRANTS_HASH_COUNT: usize = 3;
/// Vectors in the `request_hash` section.
const REQUEST_HASH_COUNT: usize = 1;
/// Vectors in the `sequence_guard` section.
const SEQUENCE_GUARD_COUNT: usize = 6;
/// Vectors in the `wire_version` section.
const WIRE_VERSION_COUNT: usize = 9;
/// Vectors in the `grant_enforcement` section.
const GRANT_ENFORCEMENT_COUNT: usize = 3;
/// Vectors in the `noise_handshake` section.
const NOISE_HANDSHAKE_COUNT: usize = 2;
/// Vectors in the `stream_rendezvous` section (replayed by
/// `stream_vectors.rs`).
const STREAM_RENDEZVOUS_COUNT: usize = 5;

/// Bytes in a SHA-256 digest.
const SHA256_LENGTH: usize = 32;

/// The domain string of the request-hash preimage array (specification
/// Section 8.5), restated here to pin the preimage bytes independently of
/// the crate.
const REQUEST_HASH_DOMAIN: &str = "RAPP-request-v1";

/// The corpus sections this file replays.
#[derive(Deserialize)]
struct Corpus {
    deterministic_cbor: Vec<CborVector>,
    rejected_cbor: Vec<RejectedCborVector>,
    identifier_derivation: Vec<IdentifierVector>,
    grants_hash: Vec<GrantsVector>,
    request_hash: Vec<RequestVector>,
}

/// The corpus metadata and one name per vector, for the stability gate.
#[derive(Deserialize)]
struct Metadata {
    format: String,
    protocol_document_version: String,
    deterministic_cbor: Vec<NamedVector>,
    rejected_cbor: Vec<NamedVector>,
    rejected_envelope: Vec<NamedVector>,
    identifier_derivation: Vec<NamedVector>,
    grants_hash: Vec<NamedVector>,
    request_hash: Vec<NamedVector>,
    sequence_guard: Vec<NamedVector>,
    wire_version: Vec<NamedVector>,
    grant_enforcement: Vec<NamedVector>,
    noise_handshake: Vec<NamedVector>,
    stream_rendezvous: Vec<NamedVector>,
}

/// A vector reduced to its name.
#[derive(Deserialize)]
struct NamedVector {
    name: String,
}

/// One positive deterministic-CBOR vector.
#[derive(Deserialize)]
struct CborVector {
    name: String,
    value: CorpusValue,
    encoded_hex: String,
}

/// The corpus's kind-tagged value description.
#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CorpusValue {
    Unsigned { value: u64 },
    Negative { value: i64 },
    Bytes { hex: String },
    Text { value: String },
    Array { items: Vec<Self> },
    Map { entries: Vec<CorpusMapEntry> },
    Bool { value: bool },
    Null,
}

/// One entry of a corpus map value.
#[derive(Clone, Deserialize)]
struct CorpusMapEntry {
    key: String,
    value: CorpusValue,
}

/// One negative deterministic-CBOR vector.
#[derive(Deserialize)]
struct RejectedCborVector {
    name: String,
    encoded_hex: String,
    error: String,
}

/// One derived-identifier vector.
#[derive(Deserialize)]
struct IdentifierVector {
    name: String,
    handshake_hash_hex: String,
    pair_id_hex: String,
    session_id_hex: String,
    rendezvous_token_hex: String,
}

/// One grants-hash vector.
#[derive(Deserialize)]
struct GrantsVector {
    name: String,
    profiles: Vec<String>,
    canonical_cbor_hex: String,
    sha256_hex: String,
}

/// One request-hash vector.
#[derive(Deserialize)]
struct RequestVector {
    name: String,
    session_id_hex: String,
    operation_id_hex: String,
    profile: String,
    action: String,
    context: CorpusValue,
    payload: CorpusValue,
    preimage_cbor_hex: String,
    sha256_hex: String,
}

/// Parses the corpus sections this file replays.
fn corpus() -> Corpus {
    serde_json::from_str(CORPUS_JSON).expect("the vendored RAPP corpus must be valid JSON")
}

/// Converts a corpus value description into this crate's wire value.
fn to_value(value: &CorpusValue) -> Value {
    match value {
        CorpusValue::Unsigned { value } => Value::Unsigned(*value),
        CorpusValue::Negative { value } => Value::Negative(negative_magnitude(*value)),
        CorpusValue::Bytes { hex } => Value::Bytes(decode_hex(hex)),
        CorpusValue::Text { value } => Value::Text(value.clone()),
        CorpusValue::Bool { value } => Value::Bool(*value),
        CorpusValue::Null => Value::Null,
        CorpusValue::Array { items } => Value::Array(items.iter().map(to_value).collect()),
        CorpusValue::Map { entries } => Value::Map(
            entries
                .iter()
                .map(|entry| (entry.key.clone(), to_value(&entry.value)))
                .collect(),
        ),
    }
}

/// The magnitude `n` of this crate's `Value::Negative(n)`, which encodes the
/// integer `-1 - n`, from the corpus's signed description.
fn negative_magnitude(value: i64) -> u64 {
    u64::try_from(-1 - i128::from(value)).expect("corpus negative values must be negative")
}

/// Converts a corpus map description into this crate's entry list.
fn to_entries(value: &CorpusValue) -> Vec<(String, Value)> {
    match to_value(value) {
        Value::Map(entries) => entries,
        _ => panic!("corpus request context and payload must be maps"),
    }
}

/// Restates every map of a value in wire order — sorted by encoded key
/// bytes, the order this crate's decoder yields. The corpus lists map
/// entries in the reference implementation's storage order instead, and
/// this crate's `Value::Map` equality is order-sensitive.
fn in_wire_order(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(in_wire_order).collect()),
        Value::Map(entries) => {
            let mut ordered: Vec<(String, Value)> = entries
                .iter()
                .map(|(key, entry)| (key.clone(), in_wire_order(entry)))
                .collect();
            ordered.sort_by_key(|entry| encoded_key(&entry.0));
            Value::Map(ordered)
        }
        other => other.clone(),
    }
}

/// The deterministic encoding of one map key, the map sort key.
fn encoded_key(key: &str) -> Vec<u8> {
    Value::Text(key.to_owned())
        .encode()
        .expect("a corpus map key must encode")
}

#[test]
fn corpus_metadata_and_vector_names_are_stable() {
    let metadata: Metadata =
        serde_json::from_str(CORPUS_JSON).expect("the vendored RAPP corpus must be valid JSON");
    assert_eq!(metadata.format, CORPUS_FORMAT);
    assert_eq!(
        metadata.protocol_document_version,
        PROTOCOL_DOCUMENT_VERSION
    );

    let sections: [(&str, &[NamedVector], usize); 11] = [
        (
            "deterministic_cbor",
            &metadata.deterministic_cbor,
            DETERMINISTIC_CBOR_COUNT,
        ),
        (
            "rejected_cbor",
            &metadata.rejected_cbor,
            REJECTED_CBOR_COUNT,
        ),
        (
            "rejected_envelope",
            &metadata.rejected_envelope,
            REJECTED_ENVELOPE_COUNT,
        ),
        (
            "identifier_derivation",
            &metadata.identifier_derivation,
            IDENTIFIER_DERIVATION_COUNT,
        ),
        ("grants_hash", &metadata.grants_hash, GRANTS_HASH_COUNT),
        ("request_hash", &metadata.request_hash, REQUEST_HASH_COUNT),
        (
            "sequence_guard",
            &metadata.sequence_guard,
            SEQUENCE_GUARD_COUNT,
        ),
        ("wire_version", &metadata.wire_version, WIRE_VERSION_COUNT),
        (
            "grant_enforcement",
            &metadata.grant_enforcement,
            GRANT_ENFORCEMENT_COUNT,
        ),
        (
            "noise_handshake",
            &metadata.noise_handshake,
            NOISE_HANDSHAKE_COUNT,
        ),
        (
            "stream_rendezvous",
            &metadata.stream_rendezvous,
            STREAM_RENDEZVOUS_COUNT,
        ),
    ];
    let mut unique = HashSet::new();
    for (section, vectors, expected) in sections {
        assert_eq!(vectors.len(), expected, "{section} vector count");
        for vector in vectors {
            assert!(
                unique.insert(vector.name.as_str()),
                "duplicate corpus vector name {} in {section}",
                vector.name
            );
        }
    }
}

#[test]
fn deterministic_cbor_matches_golden_bytes_and_round_trips() {
    let corpus = corpus();
    assert_eq!(corpus.deterministic_cbor.len(), DETERMINISTIC_CBOR_COUNT);
    for vector in &corpus.deterministic_cbor {
        let golden = decode_hex(&vector.encoded_hex);
        let value = to_value(&vector.value);
        let encoded = value.encode().expect("corpus value must encode");
        assert_eq!(encoded, golden, "{} encoded bytes", vector.name);
        let decoded = Value::decode(&golden).expect("golden CBOR must decode");
        assert_eq!(
            decoded,
            in_wire_order(&value),
            "{} decoded value",
            vector.name
        );
        assert_eq!(
            decoded.encode().expect("decoded value must re-encode"),
            golden,
            "{} canonical re-encoding",
            vector.name
        );
    }
}

#[test]
fn forbidden_and_noncanonical_cbor_is_rejected_by_class() {
    let corpus = corpus();
    assert_eq!(corpus.rejected_cbor.len(), REJECTED_CBOR_COUNT);
    for vector in &corpus.rejected_cbor {
        let expected = expected_decode_error(&vector.name, &vector.error);
        assert_eq!(
            Value::decode(&decode_hex(&vector.encoded_hex)),
            Err(expected),
            "{} rejection class",
            vector.name
        );
    }
}

/// Maps one corpus CBOR rejection, named in the reference implementation's
/// vocabulary, to this crate's `cbor::DecodeError` variant.
///
/// The mapping is per vector because the corpus class `ForbiddenCborType`
/// covers two distinct local variants, and because this decoder reports a
/// duplicate map key as a key-order violation: equal keys can never be in
/// strictly increasing encoded order.
fn expected_decode_error(name: &str, error: &str) -> DecodeError {
    match (name, error) {
        ("non-minimal-integer", "NonCanonical") => DecodeError::NonMinimalEncoding,
        ("duplicate-map-key", "DuplicateMapKey") => DecodeError::MapKeyOrder,
        ("non-text-map-key", "NonTextMapKey") => DecodeError::NonTextMapKey,
        ("invalid-utf8", "InvalidUtf8") => DecodeError::InvalidUtf8,
        ("trailing-data", "TrailingData") => DecodeError::TrailingBytes,
        ("indefinite-length", "ForbiddenCborType") => DecodeError::IndefiniteLength,
        ("unregistered-tag", "ForbiddenCborType") => DecodeError::TagForbidden,
        ("excessive-nesting", "NestingTooDeep") => DecodeError::DepthExceeded,
        (name, error) => panic!("unmapped rejected-cbor vector {name} ({error})"),
    }
}

#[test]
fn derived_identifiers_match_golden_values() {
    let corpus = corpus();
    assert_eq!(
        corpus.identifier_derivation.len(),
        IDENTIFIER_DERIVATION_COUNT
    );
    for vector in &corpus.identifier_derivation {
        let handshake_hash = decode_hex(&vector.handshake_hash_hex);
        assert_eq!(
            derive_pair_id(&handshake_hash).0,
            fixed::<PAIR_ID_LENGTH>(&vector.pair_id_hex),
            "{} pair id",
            vector.name
        );
        assert_eq!(
            derive_session_id(&handshake_hash).0,
            fixed::<SESSION_ID_LENGTH>(&vector.session_id_hex),
            "{} session id",
            vector.name
        );
        assert_eq!(
            derive_rendezvous_token(&handshake_hash).0,
            fixed::<RENDEZVOUS_TOKEN_LENGTH>(&vector.rendezvous_token_hex),
            "{} rendezvous token",
            vector.name
        );
    }
}

#[test]
fn grants_hash_normalizes_profile_order_and_matches_golden_values() {
    let corpus = corpus();
    assert_eq!(corpus.grants_hash.len(), GRANTS_HASH_COUNT);
    for vector in &corpus.grants_hash {
        assert_eq!(
            grants_hash(&vector.profiles).expect("grants hash must compute"),
            fixed::<SHA256_LENGTH>(&vector.sha256_hex),
            "{} digest",
            vector.name
        );

        // The canonical preimage is the deterministic CBOR of the profile
        // names sorted by their UTF-8 bytes.
        let mut sorted = vector.profiles.clone();
        sorted.sort_unstable();
        let preimage = Value::Array(sorted.into_iter().map(Value::Text).collect());
        assert_eq!(
            preimage.encode().expect("grants preimage must encode"),
            decode_hex(&vector.canonical_cbor_hex),
            "{} canonical preimage",
            vector.name
        );
    }
}

#[test]
fn request_hash_preimage_and_digest_match_golden_values() {
    let corpus = corpus();
    assert_eq!(corpus.request_hash.len(), REQUEST_HASH_COUNT);
    for vector in &corpus.request_hash {
        let session_id = fixed::<SESSION_ID_LENGTH>(&vector.session_id_hex);
        let operation_id = fixed::<OPERATION_ID_LENGTH>(&vector.operation_id_hex);
        let context = to_entries(&vector.context);
        let payload = to_entries(&vector.payload);

        let preimage = Value::Array(vec![
            Value::Text(REQUEST_HASH_DOMAIN.into()),
            Value::Bytes(session_id.to_vec()),
            Value::Bytes(operation_id.to_vec()),
            Value::Text(vector.profile.clone()),
            Value::Text(vector.action.clone()),
            Value::Map(context.clone()),
            Value::Map(payload.clone()),
        ]);
        assert_eq!(
            preimage.encode().expect("request preimage must encode"),
            decode_hex(&vector.preimage_cbor_hex),
            "{} preimage",
            vector.name
        );

        assert_eq!(
            request_hash(
                SessionId(session_id),
                OperationId(operation_id),
                &vector.profile,
                &vector.action,
                &context,
                &payload,
            )
            .expect("request hash must compute"),
            fixed::<SHA256_LENGTH>(&vector.sha256_hex),
            "{} digest",
            vector.name
        );
    }
}
