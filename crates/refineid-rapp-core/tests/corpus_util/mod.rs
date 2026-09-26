//! Shared access to the vendored RAPP conformance corpus.
//!
//! Every corpus-driven test crate compiles this module separately, so each
//! crate uses only the subset of helpers it needs.

#![allow(
    dead_code,
    reason = "each conformance test crate uses the subset of helpers it needs"
)]

/// The vendored golden conformance corpus for protocol document 26.9.13.
pub const CORPUS_JSON: &str = include_str!("../../../../docs/protocol/vectors/rapp-v26.9.13.json");

/// Decodes an even-length lowercase hex string from the corpus.
pub fn decode_hex(value: &str) -> Vec<u8> {
    assert!(
        value.len().is_multiple_of(2),
        "corpus hex must have complete bytes"
    );
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digits = core::str::from_utf8(pair).expect("corpus hex must be ASCII");
            u8::from_str_radix(digits, 16).expect("corpus hex must be hexadecimal")
        })
        .collect()
}

/// Decodes a corpus hex string into a fixed-length array.
pub fn fixed<const LENGTH: usize>(value: &str) -> [u8; LENGTH] {
    decode_hex(value)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| {
            panic!("corpus value must hold {LENGTH} bytes, got {}", bytes.len())
        })
}
