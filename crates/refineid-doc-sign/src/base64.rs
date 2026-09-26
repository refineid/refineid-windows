//! Base64 coding (RFC 4648 sec.4), for the places a signature format
//! insists on it.
//!
//! `ASiC` manifests and `XAdES` carry digests and certificates as base64
//! inside XML, because XML cannot hold arbitrary octets. Encoding serves
//! the writers; the strict decoder serves the offline verifier, which
//! consumes manifests it did not produce.

/// The standard alphabet (RFC 4648 sec.4). Not the URL-safe variant --
/// XML has no objection to `+` or `/`.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Input octets per encoded quantum.
const QUANTUM_IN: usize = 3;

/// Output characters per encoded quantum.
const QUANTUM_OUT: usize = 4;

/// Bits carried by one output character.
const BITS_PER_CHARACTER: usize = 6;

/// Mask selecting one output character's worth of bits.
const CHARACTER_MASK: usize = 0x3F;

/// Bits in an octet.
const BITS_PER_OCTET: usize = 8;

/// Encode `input` as base64 with the standard alphabet and padding.
#[must_use]
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(QUANTUM_IN) * QUANTUM_OUT);
    for chunk in input.chunks(QUANTUM_IN) {
        // Pack the chunk right-aligned into a 24-bit accumulator, so a
        // short final chunk simply leaves the low bits zero.
        let mut packed = 0_usize;
        for index in 0..QUANTUM_IN {
            packed <<= BITS_PER_OCTET;
            packed |= usize::from(chunk.get(index).copied().unwrap_or(0));
        }
        // Every chunk yields four characters; the ones with no input
        // behind them become padding below.
        for index in 0..QUANTUM_OUT {
            let shift = BITS_PER_CHARACTER * (QUANTUM_OUT - 1 - index);
            let sextet = (packed >> shift) & CHARACTER_MASK;
            // `index <= chunk.len()` is the count of characters carrying
            // real input: one more than the octets supplied.
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[sextet]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

const ALPHABET_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode `input` as URL-safe base64 without padding (RFC 4648 sec.5).
#[must_use]
pub fn encode_url_unpadded(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(QUANTUM_IN) * QUANTUM_OUT);
    for chunk in input.chunks(QUANTUM_IN) {
        let mut packed = 0_usize;
        for index in 0..QUANTUM_IN {
            packed <<= BITS_PER_OCTET;
            packed |= usize::from(chunk.get(index).copied().unwrap_or(0));
        }
        let out_chars = match chunk.len() {
            1 => 2,
            2 => 3,
            _ => 4,
        };
        for index in 0..out_chars {
            let shift = BITS_PER_CHARACTER * (QUANTUM_OUT - 1 - index);
            let sextet = (packed >> shift) & CHARACTER_MASK;
            out.push(char::from(ALPHABET_URL[sextet]));
        }
    }
    out
}

/// Decode standard padded base64 (RFC 4648 sec.4).
///
/// Strict: the alphabet plus `=` padding only, length a multiple of
/// four, at most two padding characters, padding only at the end, and
/// the unused trailing bits of a padded quantum must be zero. Leading
/// and trailing ASCII whitespace is tolerated (XML pretty-printing);
/// interior whitespace is rejected.
///
/// # Errors
/// Any alphabet, padding, length, or trailing-bits violation.
pub(crate) fn decode(input: &str) -> Result<Vec<u8>, &'static str> {
    const PAD: u8 = b'=';
    const MAX_PADDING: usize = 2;
    let bytes = input.trim().as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.len().is_multiple_of(QUANTUM_OUT) {
        return Err("base64 length is not a multiple of four");
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == PAD).count();
    if padding > MAX_PADDING {
        return Err("base64 has too much padding");
    }
    let body = bytes
        .get(..bytes.len() - padding)
        .ok_or("base64 padding exceeds input")?;
    if body.contains(&PAD) {
        return Err("base64 padding is not trailing");
    }
    let mut out = Vec::with_capacity(bytes.len() / QUANTUM_OUT * QUANTUM_IN);
    let (quads, remainder) = bytes.as_chunks::<QUANTUM_OUT>();
    debug_assert!(remainder.is_empty(), "length checked above");
    let mut quads = quads.iter();
    let last = quads.next_back().ok_or("base64 input vanished")?;
    for quad in quads {
        decode_quad(quad, 0, &mut out)?;
    }
    decode_quad(last, padding, &mut out)?;
    Ok(out)
}

/// Decode one four-character quantum, of which the last
/// `padding` characters are `=`.
///
/// # Errors
/// Alphabet violations and nonzero trailing bits in a padded
/// quantum (two encodings must never decode to the same bytes).
fn decode_quad(quad: &[u8], padding: usize, out: &mut Vec<u8>) -> Result<(), &'static str> {
    let chars = QUANTUM_OUT - padding.min(QUANTUM_OUT);
    let mut packed = 0_u32;
    for byte in quad.iter().take(chars) {
        let sextet = sextet_value(*byte)?;
        packed = (packed << BITS_PER_CHARACTER) | u32::from(sextet);
    }
    let missing = QUANTUM_OUT - chars;
    // Bits past the last full octet must be zero, or two encodings
    // would decode to the same bytes: two per missing character.
    let spare_bits = 2 * missing;
    let trailing_mask = (1_u32 << spare_bits).wrapping_sub(1);
    if packed & trailing_mask != 0 {
        return Err("base64 has nonzero trailing bits");
    }
    // A padded final quantum carries fewer than 24 bits; shift
    // the accumulator into place so the octet split below lands.
    packed <<= BITS_PER_CHARACTER * missing;
    let octets = QUANTUM_IN - missing.min(QUANTUM_IN);
    for index in 0..octets {
        let shift = BITS_PER_OCTET * (QUANTUM_IN - 1 - index);
        out.push(u8::try_from((packed >> shift) & 0xFF).unwrap_or(0));
    }
    Ok(())
}

/// Value of one standard-alphabet character.
///
/// # Errors
/// Any byte outside the alphabet (padding is handled by the caller).
const fn sextet_value(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("invalid base64 character"),
    }
}

/// Decode URL-safe unpadded base64 (RFC 4648 sec.5).
///
/// # Errors
/// Any byte outside the base64url alphabet.
pub fn decode_url_unpadded(input: &str) -> Result<Vec<u8>, &'static str> {
    let input_bytes = input.as_bytes();
    if input_bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity((input_bytes.len() * 3) / 4);
    let mut buf = 0_u32;
    let mut bits = 0;

    for &b in input_bytes {
        let val = match b {
            b'A'..=b'Z' => u32::from(b - b'A'),
            b'a'..=b'z' => u32::from(b - b'a' + 26),
            b'0'..=b'9' => u32::from(b - b'0' + 52),
            b'-' => 62,
            b'_' => 63,
            b'=' => continue,
            _ => return Err("invalid base64url character"),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            #[allow(
                clippy::cast_possible_truncation,
                reason = "base64 accumulator idiom: the next output byte is the low 8 bits by construction"
            )]
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_4648_vectors() {
        // RFC 4648 sec.10, verbatim.
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64url_round_trip() {
        let test_cases: &[&[u8]] = &[
            b"",
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0xFF, 0x00, 0xAA, 0x55],
        ];
        for tc in test_cases {
            let enc = encode_url_unpadded(tc);
            assert!(!enc.contains('='));
            assert!(!enc.contains('+'));
            assert!(!enc.contains('/'));
            let dec = decode_url_unpadded(&enc).expect("valid base64url");
            assert_eq!(&dec, tc);
        }
    }

    #[test]
    fn encodes_every_octet_value() {
        // All 256 values, so a sign-extension or alphabet-index slip
        // cannot hide in the range nothing else exercises.
        let all: Vec<u8> = (0..=u8::MAX).collect();
        let encoded = encode(&all);
        assert_eq!(encoded.len(), 344);
        assert!(encoded.starts_with("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"));
        assert!(encoded.ends_with("+/w=="));
    }

    #[test]
    fn decodes_rfc_vectors() {
        for (encoded, expected) in [
            ("", b"".as_slice()),
            ("Zg==", b"f".as_slice()),
            ("Zm8=", b"fo".as_slice()),
            ("Zm9v", b"foo".as_slice()),
            ("Zm9vYg==", b"foob".as_slice()),
            ("Zm9vYmE=", b"fooba".as_slice()),
            ("Zm9vYmFy", b"foobar".as_slice()),
        ] {
            assert_eq!(decode(encoded).expect("valid base64"), expected);
        }
    }

    #[test]
    fn decode_round_trips_every_octet_value() {
        let all: Vec<u8> = (0..=u8::MAX).collect();
        let decoded = decode(&encode(&all)).expect("encoder output decodes");
        assert_eq!(decoded, all);
    }

    #[test]
    fn decode_rejects_malformed_input() {
        for bad in [
            "Zg",    // length not a multiple of four
            "Zg===", // too much padding
            "Z=g=",  // padding not trailing
            "====",  // padding only
            "Zm9!",  // alphabet violation
            "Zm9 v", // interior whitespace
            "Zh==",  // nonzero trailing bits (h = 33, low 4 bits set)
            "Zmx=",  // nonzero trailing bits (x = 49, low 2 bits set)
        ] {
            assert!(decode(bad).is_err(), "{bad} must not decode");
        }
        // "Zm9h" is well-formed ("foa") and must keep decoding.
        assert_eq!(decode("Zm9h").expect("control decodes"), b"foa");
    }
}
