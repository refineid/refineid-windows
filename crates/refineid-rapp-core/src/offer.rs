//! The pairing offer and QR URI representations re-exported from `refineid_rapp`.

pub use refineid_rapp::cpace::{CpaceError, derive_manual_offer_id};
pub use refineid_rapp::{
    PairingOffer, PairingOfferDeadline, PairingOfferError, PairingOfferUri, TransportCandidate,
};

use crate::ids::OfferId;

/// Alias for backwards compatibility with earlier adapter names.
pub type OfferError = PairingOfferError;

/// Standard character length of a numeric pairing code.
pub const PAIRING_CODE_LENGTH: usize = 6;
/// Canonical placeholder secret used during initial manual-offer reconstruction before `CPace` derives the mutual 256-bit key material.
///
/// This placeholder matches canonical `refineid-core` (`crates/rapp/src/bindings.rs`) and never reaches the wire;
/// it is overwritten by [`crate::engine::Requester::pair_with_code`] via `CPace` PAKE exchange before the Noise handshake begins.
pub const PRE_CPACE_DUMMY_SECRET: [u8; 32] = [0u8; 32];
/// Number of digits in one formatted group.
pub const PAIRING_CODE_GROUP_SIZE: usize = 3;
/// Maximum byte value accepted when rejection sampling digits (25 * 10 = 250) to prevent modulo bias.
const MODULO_BIAS_LIMIT: u8 = 250;

/// Generates a fresh random 6-digit numeric pairing code using rejection sampling to eliminate modulo bias.
///
/// # Panics
/// Panics if the platform CSPRNG fails.
#[must_use]
pub fn generate_pairing_code() -> String {
    let mut code = String::with_capacity(PAIRING_CODE_LENGTH);
    let mut byte = [0u8; 1];
    while code.len() < PAIRING_CODE_LENGTH {
        getrandom::fill(&mut byte).expect("CSPRNG is available");
        if byte[0] < MODULO_BIAS_LIMIT {
            code.push((b'0' + (byte[0] % 10)) as char);
        }
    }
    code
}

/// Normalizes raw input: extracts only digits and ensures length is within bounds.
///
/// Returns an empty string if input contains illegal characters (letters, punctuation other than space/hyphen).
#[must_use]
pub fn normalize_pairing_code(input: &str) -> String {
    let mut digits = String::with_capacity(PAIRING_CODE_LENGTH);
    for c in input.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else if c != ' ' && c != '-' {
            return String::new();
        }
    }
    digits
}

/// Formats a numeric pairing code with a space after 3 digits (e.g., "123 456").
#[must_use]
pub fn format_pairing_code(input: &str) -> String {
    let digits = normalize_pairing_code(input);
    if digits.len() >= PAIRING_CODE_GROUP_SIZE {
        let (first, second) = digits.split_at(PAIRING_CODE_GROUP_SIZE);
        if second.is_empty() {
            format!("{first} ")
        } else {
            format!("{first} {second}")
        }
    } else {
        digits
    }
}

/// Checks if a string is a valid complete 6-digit pairing code.
#[must_use]
pub fn is_valid_pairing_code(code: &str) -> bool {
    let mut digits = 0;
    for c in code.chars() {
        if c.is_ascii_digit() {
            digits += 1;
        } else if c != ' ' && c != '-' {
            return false;
        }
    }
    digits == PAIRING_CODE_LENGTH
}

/// Derives the pairing offer identifier deterministically from the 6-digit numeric code.
///
/// # Errors
/// Returns [`CpaceError::InvalidCode`] if the code does not contain exactly 6 digits or contains illegal characters.
pub fn offer_id_from_code(code: &str) -> Result<OfferId, CpaceError> {
    if !is_valid_pairing_code(code) {
        return Err(CpaceError::InvalidCode);
    }
    let normalized = normalize_pairing_code(code);
    derive_manual_offer_id(&normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_code_generation_produces_six_digits() {
        let code = generate_pairing_code();
        assert_eq!(code.len(), PAIRING_CODE_LENGTH);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(is_valid_pairing_code(&code));
    }

    #[test]
    fn pairing_code_validation_and_normalization() {
        assert!(is_valid_pairing_code("123456"));
        assert!(is_valid_pairing_code("123 456"));
        assert!(is_valid_pairing_code("123-456"));
        assert_eq!(normalize_pairing_code("123 456"), "123456");
        assert_eq!(normalize_pairing_code("123-456"), "123456");
        assert_eq!(format_pairing_code("123456"), "123 456");

        // Rejection cases
        assert!(!is_valid_pairing_code("12345"));
        assert!(!is_valid_pairing_code("1234567"));
        assert!(!is_valid_pairing_code("12345a"));
        assert!(!is_valid_pairing_code("abcdef"));
        assert!(!is_valid_pairing_code("123 456 abc"));
        assert_eq!(normalize_pairing_code("123 456 abc"), "");
    }

    #[test]
    fn offer_id_from_code_validates_and_derives() {
        let offer_id1 = offer_id_from_code("123456").expect("valid code");
        let offer_id2 = offer_id_from_code("123 456").expect("valid formatted code");
        assert_eq!(offer_id1, offer_id2);

        assert!(offer_id_from_code("12345").is_err());
        assert!(offer_id_from_code("1234567").is_err());
        assert!(offer_id_from_code("12345x").is_err());
        assert!(offer_id_from_code("").is_err());
    }
}
