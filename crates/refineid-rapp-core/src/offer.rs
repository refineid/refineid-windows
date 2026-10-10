//! The pairing code and the offer the custodian serves.
//!
//! In RAPP v26.10.9 the custodian (the phone) shows a six-character code and
//! the requester types it (section 3). The custodian creates the offer with a
//! random `offer_id` and sends it as its first frame after the pairing
//! preamble (section 4.2); nothing derived from the code is ever published.

pub use refineid_rapp::{PairingOffer, PairingOfferError, TransportCandidate, TransportProfile};

use crate::transport::{FrameTransport, TransportError};

/// Alias kept for the engine's error type.
pub type OfferError = PairingOfferError;

/// Characters in one pairing code (section 3.1).
pub const PAIRING_CODE_LENGTH: usize = 6;

/// Characters per display cluster (section 3.2: `XX XX XX`).
pub const PAIRING_CODE_GROUP_SIZE: usize = 2;

/// Crockford Base32 alphabet (section 3.1).
const CODE_ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Low five bits select one of the 32 alphabet symbols uniformly.
const CODE_SYMBOL_MASK: u8 = 0x1f;

/// Applies the section 3.1 canonicalization pipeline.
///
/// Uppercases ASCII letters, strips ASCII whitespace and hyphens, maps the
/// Crockford aliases `I`/`L` to `1` and `O` to `0`, and accepts the result
/// only when it is exactly six alphabet characters. Input outside ASCII is
/// refused rather than NFKC-normalized; every valid code is ASCII.
///
/// Returns `None` for input that is not a pairing code.
#[must_use]
pub fn normalize_pairing_code(input: &str) -> Option<String> {
    let mut code = String::with_capacity(PAIRING_CODE_LENGTH);
    for character in input.chars() {
        if !character.is_ascii() {
            return None;
        }
        let upper = character.to_ascii_uppercase();
        let mapped = match upper {
            ' ' | '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | '-' => continue,
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        if !CODE_ALPHABET.contains(mapped) {
            return None;
        }
        code.push(mapped);
    }
    (code.len() == PAIRING_CODE_LENGTH).then_some(code)
}

/// A fresh uniformly random pairing code, as a custodian shows it (section
/// 3.1). Requesters never generate codes; the mock custodian and tests do.
///
/// # Errors
/// [`getrandom::Error`] when the platform CSPRNG is unavailable.
pub fn generate_pairing_code() -> Result<String, getrandom::Error> {
    let mut entropy = [0_u8; PAIRING_CODE_LENGTH];
    getrandom::fill(&mut entropy)?;
    let alphabet = CODE_ALPHABET.as_bytes();
    Ok(entropy
        .iter()
        .map(|byte| char::from(alphabet[usize::from(byte & CODE_SYMBOL_MASK)]))
        .collect())
}

/// Formats a normalized code in two-character clusters (`7K X4 M9`).
#[must_use]
pub fn format_pairing_code(code: &str) -> String {
    let characters: Vec<char> = code.chars().collect();
    characters
        .chunks(PAIRING_CODE_GROUP_SIZE)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Why the custodian's offer could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapError {
    /// The transport failed before the offer arrived.
    Transport(TransportError),
    /// The connection's transport profile is not a registered one.
    UnregisteredTransport,
    /// The offer frame failed decoding or the section 4.2 step 3 checks.
    Offer(OfferError),
}

/// Reads the offer the custodian sends as its first frame after the
/// pairing preamble, and checks it lists the connection's transport
/// (section 4.2).
///
/// # Errors
/// [`BootstrapError`] when the frame does not arrive, the transport is not
/// registered, or the offer is malformed, of another version, or does not
/// list the connection's transport.
pub fn read_bootstrap<Transport: FrameTransport>(
    transport: &mut Transport,
) -> Result<PairingOffer, BootstrapError> {
    let profile = TransportProfile::parse(transport.profile())
        .ok_or(BootstrapError::UnregisteredTransport)?;
    let bytes = transport
        .receive_frame()
        .map_err(BootstrapError::Transport)?;
    PairingOffer::from_bootstrap(&bytes, profile).map_err(BootstrapError::Offer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_follows_section_3_1() {
        assert_eq!(normalize_pairing_code("7kx4m9").as_deref(), Some("7KX4M9"));
        assert_eq!(
            normalize_pairing_code("7K X4-M9").as_deref(),
            Some("7KX4M9")
        );
        assert_eq!(normalize_pairing_code("ilo123").as_deref(), Some("110123"));
        assert_eq!(normalize_pairing_code("7KX4MU"), None);
        assert_eq!(normalize_pairing_code("7KX4M"), None);
        assert_eq!(normalize_pairing_code("7KX4M99"), None);
        assert_eq!(normalize_pairing_code("7KX4M\u{FF19}"), None);
    }

    fn offer_for(transports: &[TransportProfile]) -> PairingOffer {
        PairingOffer::create(
            refineid_rapp::OfferId::from_array([7; refineid_rapp::OFFER_ID_SIZE]),
            vec![refineid_rapp::ProfileName::CardStatus.as_str().to_owned()],
            transports,
        )
        .expect("offer")
    }

    #[test]
    fn the_bootstrap_offer_is_read_on_a_listed_transport() {
        let offer = offer_for(&[TransportProfile::Stream]);
        let (mut custodian, mut requester) =
            crate::transport::MemoryTransport::pair("stream-1", std::time::Duration::from_secs(1));
        custodian
            .send_frame(&offer.to_cbor().expect("cbor"))
            .expect("send");
        assert_eq!(read_bootstrap(&mut requester), Ok(offer));
    }

    #[test]
    fn an_offer_not_listing_the_transport_is_refused() {
        let offer = offer_for(&[TransportProfile::Ble]);
        let (mut custodian, mut requester) =
            crate::transport::MemoryTransport::pair("stream-1", std::time::Duration::from_secs(1));
        custodian
            .send_frame(&offer.to_cbor().expect("cbor"))
            .expect("send");
        assert!(matches!(
            read_bootstrap(&mut requester),
            Err(BootstrapError::Offer(_))
        ));
    }

    #[test]
    fn a_generated_code_is_a_valid_code() {
        let code = generate_pairing_code().expect("CSPRNG");
        assert_eq!(
            normalize_pairing_code(&code).as_deref(),
            Some(code.as_str())
        );
    }

    #[test]
    fn display_uses_two_character_clusters() {
        assert_eq!(format_pairing_code("7KX4M9"), "7K X4 M9");
    }
}
