//! The pairing offer and QR URI representations re-exported from `refineid_rapp`.

pub use refineid_rapp::cpace::derive_manual_offer_id;
pub use refineid_rapp::{
    PairingOffer, PairingOfferDeadline, PairingOfferError, PairingOfferUri, TransportCandidate,
};

use crate::ids::OfferId;

/// Alias for backwards compatibility with earlier adapter names.
pub type OfferError = PairingOfferError;

/// Standard character length of a numeric pairing code.
pub const PAIRING_CODE_LENGTH: usize = 6;
/// Number of digits in one formatted group.
pub const PAIRING_CODE_GROUP_SIZE: usize = 3;

/// Generates a fresh random 6-digit numeric pairing code.
///
/// # Panics
/// Panics if the platform CSPRNG fails.
#[must_use]
pub fn generate_pairing_code() -> String {
    let mut bytes = [0u8; PAIRING_CODE_LENGTH];
    getrandom::fill(&mut bytes).expect("CSPRNG is available");
    bytes.iter().map(|b| (b'0' + (b % 10)) as char).collect()
}

/// Normalizes raw input: extracts only digits and truncates to code length.
#[must_use]
pub fn normalize_pairing_code(input: &str) -> String {
    input
        .chars()
        .filter(char::is_ascii_digit)
        .take(PAIRING_CODE_LENGTH)
        .collect()
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
    code.chars().filter(char::is_ascii_digit).count() == PAIRING_CODE_LENGTH
}

/// Derives the pairing offer identifier deterministically from the 6-digit numeric code.
#[must_use]
pub fn offer_id_from_code(code: &str) -> OfferId {
    let normalized = normalize_pairing_code(code);
    derive_manual_offer_id(&normalized).unwrap_or_else(|_| OfferId::from_array([0u8; 32]))
}
