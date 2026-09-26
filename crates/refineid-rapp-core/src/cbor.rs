//! Deterministic CBOR for the RAPP wire representation.
//!
//! Specification Section 7.1 requires the core deterministic encoding of
//! RFC 8949 Section 4.2.1 and forbids indefinite-length items, floating-point
//! values, duplicate map keys, invalid UTF-8, and CBOR tags. RAPP uses text
//! map keys throughout, and this module enforces that restriction at the
//! representation level: a map key is always a text string, and map entries
//! are ordered by the bytewise lexicographic order of their encoded keys.
//!
//! The decoder is strict in both directions: it accepts only what the encoder
//! produces. Every integer head must use its shortest form, every length is
//! definite, depth is bounded by [`crate::limits::MAX_NESTING_DEPTH`], text
//! strings are bounded by [`crate::limits::MAX_TEXT_SIZE`], and decoding the
//! whole input must consume every byte.

use crate::limits;

/// CBOR major type 0: unsigned integer.
const MAJOR_UNSIGNED: u8 = 0;
/// CBOR major type 1: negative integer.
const MAJOR_NEGATIVE: u8 = 1;
/// CBOR major type 2: byte string.
const MAJOR_BYTES: u8 = 2;
/// CBOR major type 3: text string.
const MAJOR_TEXT: u8 = 3;
/// CBOR major type 4: array.
const MAJOR_ARRAY: u8 = 4;
/// CBOR major type 5: map.
const MAJOR_MAP: u8 = 5;
/// CBOR major type 6: tag. Forbidden by specification Section 7.1.
const MAJOR_TAG: u8 = 6;
/// CBOR major type 7: simple values and floats.
const MAJOR_SIMPLE: u8 = 7;

/// Argument values below this are encoded directly in the head byte.
const IMMEDIATE_ARGUMENT_LIMIT: u64 = 24;
/// Head argument selecting one following length byte.
const ARGUMENT_ONE_BYTE: u8 = 24;
/// Head argument selecting two following length bytes.
const ARGUMENT_TWO_BYTES: u8 = 25;
/// Head argument selecting four following length bytes.
const ARGUMENT_FOUR_BYTES: u8 = 26;
/// Head argument selecting eight following length bytes.
const ARGUMENT_EIGHT_BYTES: u8 = 27;
/// Simple value false under major type 7.
const SIMPLE_FALSE: u8 = 20;
/// Simple value true under major type 7.
const SIMPLE_TRUE: u8 = 21;
/// Simple-value argument for `null`.
const SIMPLE_NULL: u8 = 22;

/// One RAPP wire value.
///
/// The variants are exactly the shapes the RAPP message schemas use. Floats,
/// tags, null, and undefined are not representable, which is what makes the
/// forbidden encodings unproducible rather than merely unchecked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// An unsigned integer (`uint`).
    Unsigned(u64),
    /// A negative integer encoding `-1 - n` for the carried `n`.
    ///
    /// No RAPP schema field is negative; the variant exists so extension
    /// values inside `any`-typed maps round-trip instead of failing with a
    /// misleading error.
    Negative(u64),
    /// A byte string (`bstr`).
    Bytes(Vec<u8>),
    /// A UTF-8 text string (`tstr`).
    Text(String),
    /// An array.
    Array(Vec<Self>),
    /// A map with text keys, ordered by encoded-key bytes.
    Map(Vec<(String, Self)>),
    /// A boolean.
    Bool(bool),
    /// Null, used by profile schemas for an explicitly absent value.
    Null,
}

/// Why a value could not be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A container exceeded [`limits::MAX_NESTING_DEPTH`].
    DepthExceeded,
    /// A text string exceeded [`limits::MAX_TEXT_SIZE`] UTF-8 bytes.
    TextTooLong,
    /// Two map entries encoded to the same key.
    DuplicateMapKey,
}

/// Why an input could not be decoded as deterministic CBOR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended inside an item.
    Truncated,
    /// Bytes remained after the single top-level item.
    TrailingBytes,
    /// An integer head did not use its shortest form.
    NonMinimalEncoding,
    /// An indefinite-length item was encountered.
    IndefiniteLength,
    /// A tag was encountered; Section 7.1 forbids every tag.
    TagForbidden,
    /// A float, null, undefined, or other forbidden simple value.
    ForbiddenSimpleValue,
    /// A text string held invalid UTF-8.
    InvalidUtf8,
    /// A map key was not a text string.
    NonTextMapKey,
    /// Map keys were not in strictly increasing encoded order.
    MapKeyOrder,
    /// A container exceeded [`limits::MAX_NESTING_DEPTH`].
    DepthExceeded,
    /// A text string exceeded [`limits::MAX_TEXT_SIZE`] UTF-8 bytes.
    TextTooLong,
    /// A declared length exceeded the remaining input.
    LengthOverrun,
}

impl Value {
    /// Encodes the value as deterministic CBOR.
    ///
    /// Map entries are sorted here by encoded key length first, then by
    /// encoded key bytes (RFC 8949 Section 4.2.1), so callers may build
    /// maps in schema order and still emit the canonical order.
    ///
    /// # Errors
    ///
    /// Fails when a container exceeds the nesting limit, a text string
    /// exceeds the text limit, or two map entries share a key.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        encode_into(self, &mut out, 0)?;
        Ok(out)
    }

    /// Decodes exactly one deterministic-CBOR item spanning the whole input.
    ///
    /// # Errors
    ///
    /// Fails on any deviation from the deterministic encoding this module
    /// produces, including forbidden item kinds, non-minimal heads, key
    /// disorder, resource-limit violations, and trailing bytes.
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader { input, at: 0 };
        let value = decode_item(&mut reader, 0)?;
        if reader.at != input.len() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(value)
    }
}

/// Writes one head byte plus its shortest-form argument.
fn encode_head(major: u8, argument: u64, out: &mut Vec<u8>) {
    let shifted = major << 5;
    if argument < IMMEDIATE_ARGUMENT_LIMIT {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the argument is below 24 and fits the head byte"
        )]
        out.push(shifted | argument as u8);
    } else if let Ok(byte) = u8::try_from(argument) {
        out.push(shifted | ARGUMENT_ONE_BYTE);
        out.push(byte);
    } else if let Ok(short) = u16::try_from(argument) {
        out.push(shifted | ARGUMENT_TWO_BYTES);
        out.extend_from_slice(&short.to_be_bytes());
    } else if let Ok(word) = u32::try_from(argument) {
        out.push(shifted | ARGUMENT_FOUR_BYTES);
        out.extend_from_slice(&word.to_be_bytes());
    } else {
        out.push(shifted | ARGUMENT_EIGHT_BYTES);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

/// Encodes one text string, including its head.
fn encode_text(text: &str, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if text.len() > limits::MAX_TEXT_SIZE {
        return Err(EncodeError::TextTooLong);
    }
    encode_head(MAJOR_TEXT, text.len() as u64, out);
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

/// Recursively encodes one value at the given container depth.
fn encode_into(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), EncodeError> {
    match value {
        Value::Unsigned(number) => {
            encode_head(MAJOR_UNSIGNED, *number, out);
            Ok(())
        }
        Value::Negative(magnitude) => {
            encode_head(MAJOR_NEGATIVE, *magnitude, out);
            Ok(())
        }
        Value::Bytes(bytes) => {
            encode_head(MAJOR_BYTES, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
            Ok(())
        }
        Value::Text(text) => encode_text(text, out),
        Value::Array(items) => {
            if depth >= limits::MAX_NESTING_DEPTH {
                return Err(EncodeError::DepthExceeded);
            }
            encode_head(MAJOR_ARRAY, items.len() as u64, out);
            for item in items {
                encode_into(item, out, depth + 1)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            if depth >= limits::MAX_NESTING_DEPTH {
                return Err(EncodeError::DepthExceeded);
            }
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
            for (key, entry) in entries {
                let mut key_bytes = Vec::new();
                encode_text(key, &mut key_bytes)?;
                let mut value_bytes = Vec::new();
                encode_into(entry, &mut value_bytes, depth + 1)?;
                encoded.push((key_bytes, value_bytes));
            }
            encoded.sort_by(|left, right| {
                left.0
                    .len()
                    .cmp(&right.0.len())
                    .then_with(|| left.0.cmp(&right.0))
            });
            if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(EncodeError::DuplicateMapKey);
            }
            encode_head(MAJOR_MAP, encoded.len() as u64, out);
            for (key_bytes, value_bytes) in encoded {
                out.extend_from_slice(&key_bytes);
                out.extend_from_slice(&value_bytes);
            }
            Ok(())
        }
        Value::Bool(flag) => {
            let simple = if *flag { SIMPLE_TRUE } else { SIMPLE_FALSE };
            out.push((MAJOR_SIMPLE << 5) | simple);
            Ok(())
        }
        Value::Null => {
            out.push((MAJOR_SIMPLE << 5) | SIMPLE_NULL);
            Ok(())
        }
    }
}

/// Cursor over the undecoded remainder of the input.
struct Reader<'input> {
    input: &'input [u8],
    at: usize,
}

impl Reader<'_> {
    /// Takes the next byte.
    fn byte(&mut self) -> Result<u8, DecodeError> {
        let byte = *self.input.get(self.at).ok_or(DecodeError::Truncated)?;
        self.at += 1;
        Ok(byte)
    }

    /// Takes the next `count` bytes.
    fn bytes(&mut self, count: usize) -> Result<&[u8], DecodeError> {
        let end = self
            .at
            .checked_add(count)
            .ok_or(DecodeError::LengthOverrun)?;
        if end > self.input.len() {
            return Err(DecodeError::Truncated);
        }
        let slice = &self.input[self.at..end];
        self.at = end;
        Ok(slice)
    }
}

/// Reads one head, returning the major type and shortest-form argument.
fn decode_head(reader: &mut Reader<'_>) -> Result<(u8, u64), DecodeError> {
    let head = reader.byte()?;
    let major = head >> 5;
    let low = head & 0x1F;
    let argument = match low {
        argument if u64::from(argument) < IMMEDIATE_ARGUMENT_LIMIT => u64::from(argument),
        ARGUMENT_ONE_BYTE => {
            let value = u64::from(reader.byte()?);
            if value < IMMEDIATE_ARGUMENT_LIMIT {
                return Err(DecodeError::NonMinimalEncoding);
            }
            value
        }
        ARGUMENT_TWO_BYTES => {
            let raw = reader.bytes(2)?;
            let value = u64::from(u16::from_be_bytes([raw[0], raw[1]]));
            if u8::try_from(value).is_ok() {
                return Err(DecodeError::NonMinimalEncoding);
            }
            value
        }
        ARGUMENT_FOUR_BYTES => {
            let raw = reader.bytes(4)?;
            let value = u64::from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]));
            if u16::try_from(value).is_ok() {
                return Err(DecodeError::NonMinimalEncoding);
            }
            value
        }
        ARGUMENT_EIGHT_BYTES => {
            let raw = reader.bytes(8)?;
            let value = u64::from_be_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]);
            if u32::try_from(value).is_ok() {
                return Err(DecodeError::NonMinimalEncoding);
            }
            value
        }
        _ => return Err(DecodeError::IndefiniteLength),
    };
    Ok((major, argument))
}

/// Converts a declared item length to a checked `usize`.
fn declared_length(argument: u64) -> Result<usize, DecodeError> {
    usize::try_from(argument).map_err(|_| DecodeError::LengthOverrun)
}

/// Recursively decodes one item at the given container depth.
fn decode_item(reader: &mut Reader<'_>, depth: usize) -> Result<Value, DecodeError> {
    if let Some(head) = reader.input.get(reader.at)
        && head >> 5 == MAJOR_SIMPLE
    {
        // Major type 7 carries no integer argument in RAPP: the only legal
        // items are the two boolean simple values and null. Every float and
        // every other simple value is forbidden by Section 7.1.
        reader.at += 1;
        return match head & 0x1F {
            SIMPLE_FALSE => Ok(Value::Bool(false)),
            SIMPLE_TRUE => Ok(Value::Bool(true)),
            SIMPLE_NULL => Ok(Value::Null),
            _ => Err(DecodeError::ForbiddenSimpleValue),
        };
    }
    let (major, argument) = decode_head(reader)?;
    match major {
        MAJOR_UNSIGNED => Ok(Value::Unsigned(argument)),
        MAJOR_NEGATIVE => Ok(Value::Negative(argument)),
        MAJOR_BYTES => {
            let length = declared_length(argument)?;
            Ok(Value::Bytes(reader.bytes(length)?.to_vec()))
        }
        MAJOR_TEXT => {
            let length = declared_length(argument)?;
            if length > limits::MAX_TEXT_SIZE {
                return Err(DecodeError::TextTooLong);
            }
            let raw = reader.bytes(length)?;
            let text = str::from_utf8(raw).map_err(|_| DecodeError::InvalidUtf8)?;
            Ok(Value::Text(text.to_owned()))
        }
        MAJOR_ARRAY => {
            if depth >= limits::MAX_NESTING_DEPTH {
                return Err(DecodeError::DepthExceeded);
            }
            let length = declared_length(argument)?;
            let mut items = Vec::new();
            for _ in 0..length {
                items.push(decode_item(reader, depth + 1)?);
            }
            Ok(Value::Array(items))
        }
        MAJOR_MAP => {
            if depth >= limits::MAX_NESTING_DEPTH {
                return Err(DecodeError::DepthExceeded);
            }
            let length = declared_length(argument)?;
            let mut entries: Vec<(String, Value)> = Vec::new();
            let mut previous_key: Option<(usize, Vec<u8>)> = None;
            for _ in 0..length {
                let key_start = reader.at;
                let Value::Text(key) = decode_item(reader, depth + 1)? else {
                    return Err(DecodeError::NonTextMapKey);
                };
                let key_bytes = reader.input[key_start..reader.at].to_vec();
                // Length-first, then byte-wise (RFC 8949 Section 4.2.1),
                // mirroring the encoder above.
                let order_key = (key_bytes.len(), key_bytes);
                if let Some(previous) = &previous_key
                    && *previous >= order_key
                {
                    return Err(DecodeError::MapKeyOrder);
                }
                previous_key = Some(order_key);
                let value = decode_item(reader, depth + 1)?;
                entries.push((key, value));
            }
            Ok(Value::Map(entries))
        }
        MAJOR_TAG => Err(DecodeError::TagForbidden),
        // Major type 7 is intercepted before the head decoder, so the only
        // remaining pattern is unreachable; refusing it keeps the match total.
        _ => Err(DecodeError::ForbiddenSimpleValue),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test vectors are constructed to be infallible"
)]
mod tests {
    use super::{DecodeError, EncodeError, Value};

    fn round_trip(value: &Value) -> Vec<u8> {
        let encoded = value.encode().unwrap();
        assert_eq!(Value::decode(&encoded).unwrap(), *value);
        encoded
    }

    #[test]
    fn integers_use_shortest_form() {
        assert_eq!(round_trip(&Value::Unsigned(0)), [0x00]);
        assert_eq!(round_trip(&Value::Unsigned(23)), [0x17]);
        assert_eq!(round_trip(&Value::Unsigned(24)), [0x18, 0x18]);
        assert_eq!(round_trip(&Value::Unsigned(255)), [0x18, 0xFF]);
        assert_eq!(round_trip(&Value::Unsigned(256)), [0x19, 0x01, 0x00]);
        assert_eq!(
            round_trip(&Value::Unsigned(65_536)),
            [0x1A, 0x00, 0x01, 0x00, 0x00]
        );
        assert_eq!(
            round_trip(&Value::Unsigned(u64::from(u32::MAX) + 1)),
            [0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(round_trip(&Value::Negative(0)), [0x20]);
    }

    #[test]
    fn non_minimal_heads_are_rejected() {
        assert_eq!(
            Value::decode(&[0x18, 0x17]),
            Err(DecodeError::NonMinimalEncoding)
        );
        assert_eq!(
            Value::decode(&[0x19, 0x00, 0xFF]),
            Err(DecodeError::NonMinimalEncoding)
        );
        assert_eq!(
            Value::decode(&[0x1A, 0x00, 0x00, 0xFF, 0xFF]),
            Err(DecodeError::NonMinimalEncoding)
        );
    }

    #[test]
    fn strings_and_bytes_round_trip() {
        assert_eq!(
            round_trip(&Value::Text("rapp".into())),
            [0x64, b'r', b'a', b'p', b'p']
        );
        assert_eq!(round_trip(&Value::Bytes(vec![1, 2, 3])), [0x43, 1, 2, 3]);
    }

    #[test]
    fn map_entries_are_canonically_ordered_on_encode() {
        let map = Value::Map(vec![
            ("version".into(), Value::Unsigned(1)),
            ("type".into(), Value::Text("error".into())),
        ]);
        let encoded = map.encode().unwrap();
        let decoded = Value::decode(&encoded).unwrap();
        let Value::Map(entries) = decoded else {
            panic!("expected a map");
        };
        assert_eq!(entries[0].0, "type");
        assert_eq!(entries[1].0, "version");
    }

    #[test]
    fn misordered_map_keys_are_rejected() {
        // {"b": 0, "a": 0} violates encoded-key order.
        let raw = [0xA2, 0x61, b'b', 0x00, 0x61, b'a', 0x00];
        assert_eq!(Value::decode(&raw), Err(DecodeError::MapKeyOrder));
    }

    #[test]
    fn map_key_order_is_length_first() {
        // "profiles" (9 encoded bytes) sorts before "pairing_secret"
        // (15 bytes) by length, although "pairing_secret" is smaller
        // byte-wise. RFC 8949 Section 4.2.1 pins length-first.
        let map = Value::Map(vec![
            ("pairing_secret".into(), Value::Unsigned(2)),
            ("profiles".into(), Value::Unsigned(1)),
        ]);
        let encoded = map.encode().unwrap();
        let decoded = Value::decode(&encoded).unwrap();
        let Value::Map(entries) = decoded else {
            panic!("expected a map");
        };
        assert_eq!(entries[0].0, "profiles");
        assert_eq!(entries[1].0, "pairing_secret");
        // The byte-wise order is shorter-key-last, hence not
        // canonical, and must be rejected.
        let mut wrong_order = vec![0xA2];
        wrong_order.push(0x6E);
        wrong_order.extend_from_slice(b"pairing_secret");
        wrong_order.push(0x02);
        wrong_order.push(0x68);
        wrong_order.extend_from_slice(b"profiles");
        wrong_order.push(0x01);
        assert_eq!(Value::decode(&wrong_order), Err(DecodeError::MapKeyOrder));
    }

    #[test]
    fn duplicate_map_keys_are_rejected_both_ways() {
        let map = Value::Map(vec![
            ("a".into(), Value::Unsigned(0)),
            ("a".into(), Value::Unsigned(1)),
        ]);
        assert_eq!(map.encode(), Err(EncodeError::DuplicateMapKey));
        let raw = [0xA2, 0x61, b'a', 0x00, 0x61, b'a', 0x01];
        assert_eq!(Value::decode(&raw), Err(DecodeError::MapKeyOrder));
    }

    #[test]
    fn forbidden_items_are_rejected() {
        // Indefinite-length byte string.
        assert_eq!(Value::decode(&[0x5F]), Err(DecodeError::IndefiniteLength));
        // Tag 0.
        assert_eq!(Value::decode(&[0xC0, 0x00]), Err(DecodeError::TagForbidden));
        // Null round-trips; undefined and floats stay forbidden.
        assert_eq!(Value::decode(&[0xF6]), Ok(Value::Null));
        assert_eq!(
            Value::decode(&[0xF7]),
            Err(DecodeError::ForbiddenSimpleValue)
        );
        assert_eq!(
            Value::decode(&[0xF9, 0x00, 0x00]),
            Err(DecodeError::ForbiddenSimpleValue)
        );
    }

    #[test]
    fn booleans_round_trip() {
        assert_eq!(round_trip(&Value::Bool(false)), [0xF4]);
        assert_eq!(round_trip(&Value::Bool(true)), [0xF5]);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        assert_eq!(
            Value::decode(&[0x00, 0x00]),
            Err(DecodeError::TrailingBytes)
        );
    }

    #[test]
    fn nesting_depth_is_bounded() {
        // Eight containers are the permitted maximum; a ninth is rejected.
        let mut value = Value::Unsigned(0);
        for _ in 0..8 {
            value = Value::Array(vec![value]);
        }
        let encoded = value.encode().unwrap();
        assert_eq!(Value::decode(&encoded).unwrap(), value);
        let deeper = Value::Array(vec![value]);
        assert_eq!(deeper.encode(), Err(EncodeError::DepthExceeded));
        let mut raw = vec![0x81; 9];
        raw.push(0x00);
        assert_eq!(Value::decode(&raw), Err(DecodeError::DepthExceeded));
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert_eq!(Value::decode(&[0x62, b'a']), Err(DecodeError::Truncated));
        assert_eq!(Value::decode(&[0x19, 0x01]), Err(DecodeError::Truncated));
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        assert_eq!(Value::decode(&[0x61, 0xFF]), Err(DecodeError::InvalidUtf8));
    }

    #[test]
    fn non_text_map_keys_are_rejected() {
        let raw = [0xA1, 0x00, 0x00];
        assert_eq!(Value::decode(&raw), Err(DecodeError::NonTextMapKey));
    }
}
