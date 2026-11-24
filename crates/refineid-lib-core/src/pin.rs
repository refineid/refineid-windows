// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Secret-code newtype.
//!
//! `PinBytes` owns validated PIN material between the point it's read
//! from a user-input source (echo-off stdin, a GUI prompt, the
//! `C_Login` PKCS#11 surface, ...) and the point it's encoded into
//! a VERIFY APDU. The buffer zeroes on drop so a memory dump after
//! the call doesn't yield residue.
//!
//! - `Debug` is intentionally lossy (`PinBytes([redacted])`); never
//!   log the raw bytes.
//! - The wrapper isn't a strong secrecy boundary against a hostile
//!   in-process attacker, just a hygienic default that keeps stale
//!   PIN bytes out of long-lived heap pages.
//! - The type is `Clone` because PKCS#11 / agent callers
//!   occasionally need to retry a VERIFY without re-prompting the
//!   user. Both clones zeroize independently on drop.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A syntactically valid FINEID PIN-family code: 4-12 ASCII digits.
///
/// Role-specific types and operations may impose tighter bounds. For
/// example, PIN2 requires at least 6 digits and activation PINs have
/// an exact length. Padding to the card's stored length is done
/// downstream in `auth::verify_pin`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PinBytes {
    bytes: [u8; Self::MAX_LENGTH],
    length: u8,
}

impl PinBytes {
    /// Shortest code accepted by any FINEID PIN-family role.
    pub const MIN_LENGTH: usize = 4;
    /// Longest code accepted by any FINEID PIN-family role.
    pub const MAX_LENGTH: usize = 12;

    /// Validate and take ownership of `bytes`.
    ///
    /// The caller's `Vec` is moved in and zeroized after validation.
    /// Valid digits are copied into the type's fixed-capacity storage;
    /// rejected input is zeroized before its allocation is released.
    ///
    /// # Errors
    /// Returns [`PinRoleError`] unless `bytes` contains 4-12 ASCII
    /// digits.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, PinRoleError> {
        if let Err(error) = validate_digits(&bytes, Self::MIN_LENGTH, Self::MAX_LENGTH) {
            bytes.zeroize();
            return Err(error);
        }
        let Ok(length) = u8::try_from(bytes.len()) else {
            let got = bytes.len();
            bytes.zeroize();
            return Err(PinRoleError::WrongLength {
                expected_min: Self::MIN_LENGTH,
                expected_max: Self::MAX_LENGTH,
                got,
            });
        };
        let mut storage = [0; Self::MAX_LENGTH];
        storage[..bytes.len()].copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self {
            bytes: storage,
            length,
        })
    }

    /// Borrow the inner bytes for a verify call. Callers must not
    /// store the slice beyond the lifetime of `self`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.digit_count()]
    }

    /// Number of ASCII digits in the code.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.length as usize
    }
}

impl TryFrom<Vec<u8>> for PinBytes {
    type Error = PinRoleError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

impl<const N: usize> TryFrom<[u8; N]> for PinBytes {
    type Error = PinRoleError;

    fn try_from(mut bytes: [u8; N]) -> Result<Self, Self::Error> {
        if let Err(error) = validate_digits(&bytes, Self::MIN_LENGTH, Self::MAX_LENGTH) {
            bytes.zeroize();
            return Err(error);
        }
        let Ok(length) = u8::try_from(N) else {
            bytes.zeroize();
            return Err(PinRoleError::WrongLength {
                expected_min: Self::MIN_LENGTH,
                expected_max: Self::MAX_LENGTH,
                got: N,
            });
        };
        let mut storage = [0; Self::MAX_LENGTH];
        storage[..N].copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self {
            bytes: storage,
            length,
        })
    }
}

impl core::fmt::Debug for PinBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PinBytes([redacted])")
    }
}

// ---- Role-tagged PIN code newtypes ----
//
// PinBytes is the validated zeroizing secret carrier; the wrappers
// below tag the role so the type system enforces "this is a
// PUK, not an activation PIN" at every API boundary. The
// PIN AUTH / PIN SIG / PIN PUK / activation-PIN distinction is
// type-enforced. PIN1 /
// PIN2 remain paired with `PinSlot` in the auth API (slot
// already disambiguates); PUK and activation PIN get their own
// types because they are semantically distinct roles even on
// cards where the card-side slot is shared.

/// Error returned by the role-tagged PIN newtype constructors.
///
/// Not PIN-bearing: variants carry only structural diagnostics
/// (length bounds, byte offset of a non-digit). `Copy` is
/// forbidden only on types that hold PIN / PUK / activation-PIN / CAN material
/// in their fields; this error enum holds none of those.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRoleError {
    /// Input was empty.
    Empty,
    /// Input had a length outside the allowed range for this
    /// role.
    WrongLength {
        /// Minimum length the role accepts. Tier 0 `usize`.
        expected_min: usize,
        /// Maximum length the role accepts. Tier 0 `usize`.
        expected_max: usize,
        /// Length of the rejected input. Tier 0 `usize`.
        got: usize,
    },
    /// Input contained a non-ASCII-digit byte. `at` is the
    /// zero-based offset of the offending byte.
    NonDigit {
        /// Byte index at which the offending value was found.
        /// Tier 0 `usize`.
        at: usize,
    },
}

impl core::fmt::Display for PinRoleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "PIN code cannot be empty"),
            Self::WrongLength {
                expected_min,
                expected_max,
                got: _,
            } => {
                if expected_min == expected_max {
                    write!(
                        f,
                        "PIN code wrong length: expected exactly {expected_min} digits"
                    )
                } else {
                    write!(
                        f,
                        "PIN code wrong length: expected {expected_min}-{expected_max} digits"
                    )
                }
            }
            // The offending offset stays out of `Display`: this text
            // reaches user-facing surfaces, where positions inside
            // secret material must not appear (`Debug` keeps it for
            // tests). Matches `WrongLength`, which already redacts
            // `got`.
            Self::NonDigit { at: _ } => {
                write!(f, "PIN code must be ASCII digits only")
            }
        }
    }
}

impl core::error::Error for PinRoleError {}

fn validate_digits(bytes: &[u8], min: usize, max: usize) -> Result<(), PinRoleError> {
    if bytes.is_empty() {
        return Err(PinRoleError::Empty);
    }
    if bytes.len() < min || bytes.len() > max {
        return Err(PinRoleError::WrongLength {
            expected_min: min,
            expected_max: max,
            got: bytes.len(),
        });
    }
    if let Some(at) = bytes.iter().position(|b| !b.is_ascii_digit()) {
        return Err(PinRoleError::NonDigit { at });
    }
    Ok(())
}

impl PinBytes {
    /// Validate that the held bytes are between `min` and `max`
    /// (inclusive) bytes long and contain only ASCII digits.
    ///
    /// # Errors
    /// [`PinRoleError`] for empty, wrong-length, or non-digit
    /// input.
    pub fn validate_digits(&self, min: usize, max: usize) -> Result<(), PinRoleError> {
        validate_digits(self.as_bytes(), min, max)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn pin<const N: usize>(bytes: &[u8; N]) -> PinBytes {
        PinBytes::try_from(*bytes).expect("valid test PIN")
    }

    #[test]
    fn debug_does_not_leak_bytes() {
        let p = pin(b"1234");
        let s = format!("{p:?}");
        assert_eq!(s, "PinBytes([redacted])");
    }

    #[test]
    fn len_tracks_inner() {
        let p = pin(b"1234");
        assert_eq!(p.digit_count(), 4);
    }

    #[test]
    fn rejects_empty_short_and_long_inputs() {
        assert!(matches!(
            PinBytes::new(Vec::new()),
            Err(PinRoleError::Empty)
        ));
        assert!(matches!(
            PinBytes::try_from(*b"123"),
            Err(PinRoleError::WrongLength { got: 3, .. })
        ));
        assert!(matches!(
            PinBytes::try_from([b'1'; PinBytes::MAX_LENGTH + 1]),
            Err(PinRoleError::WrongLength { got: 13, .. })
        ));
    }

    #[test]
    fn rejects_non_digit_input() {
        assert!(matches!(
            PinBytes::try_from(*b"12a4"),
            Err(PinRoleError::NonDigit { at: 2 })
        ));
    }

    #[test]
    fn as_bytes_returns_input() {
        let p = pin(b"1234");
        assert_eq!(p.as_bytes(), b"1234");
    }
}
