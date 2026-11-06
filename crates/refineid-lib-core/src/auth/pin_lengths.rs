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

//! The PIN 1, PIN 2 and PUK lengths of the card in session.
//!
//! The card is the authority on its lengths. Where PINs are set --
//! activation, change and reset -- they are read once per session with
//! [`crate::auth::PinOps::read_card_pin_lengths`]:
//!
//! 1. EF.AOD (FINEID S4-1 v4.2 §8.1.5; FINEID S4-2 v4.0 §4.6.10,
//!    §4.7.10): each password object's `pwdReference` names PIN 1, PIN 2
//!    or the PUK under the card's numbering, with or without the
//!    specific-reference bit; its range is `minLength` to `maxLength`,
//!    or to `storedLength` when `maxLength` is absent.
//! 2. The PIN policy in the citizen card's PIN container (FINEID S1
//!    v4.2 §3.15.3), for a credential EF.AOD does not list.
//! 3. The FINEID bounds -- PIN 1 4 to 12 digits, PIN 2 6 to 12, PUK 8 to
//!    12 (FINEID S4-1 v4.2 §4.1, §8.1.5) -- for a credential neither
//!    source lists.
//!
//! A listed range is taken within what the commands carry: PIN 1 and
//! PIN 2 4 to 12 digits, the PUK 8 to 12. Signing and login never read
//! these lengths.

use refineid_pkcs15::{AuthenticationObjects, PasswordLengthRange};

use crate::auth::{
    CredentialReference, FINEID_PIN1_MIN_LENGTH, FINEID_PIN2_MIN_LENGTH, PIN_MAX_LENGTH,
    PIN_MIN_LENGTH, PUK_MAX_LENGTH, PUK_MIN_LENGTH, PinPolicyReason, PinReferenceScheme, PinSlot,
};

/// The ISO/IEC 7816-4 reference qualifier bit marking a specific (local)
/// reference; FINEID S1 v4.2 §3.15.3 Table 19 sets it on local PINs. A
/// card may list a reference in EF.AOD with or without it.
const SPECIFIC_REFERENCE_BIT: u8 = 0x80;

/// The lengths the PIN commands carry.
const PIN_CAPACITY: PasswordLengthRange = length_range(PIN_MIN_LENGTH, PIN_MAX_LENGTH);
/// The lengths the PUK commands carry.
const PUK_CAPACITY: PasswordLengthRange = length_range(PUK_MIN_LENGTH, PUK_MAX_LENGTH);
/// FINEID bounds of PIN 1, taken when the card lists none.
const FINEID_PIN1_BOUNDS: PasswordLengthRange =
    length_range(FINEID_PIN1_MIN_LENGTH, PIN_MAX_LENGTH);
/// FINEID bounds of PIN 2, taken when the card lists none.
const FINEID_PIN2_BOUNDS: PasswordLengthRange =
    length_range(FINEID_PIN2_MIN_LENGTH, PIN_MAX_LENGTH);
/// FINEID bounds of the PUK, taken when the card lists none.
const FINEID_PUK_BOUNDS: PasswordLengthRange = PUK_CAPACITY;

/// A length constant pair as a range, evaluated at compile time: bounds
/// that do not fit one octet or admit nothing fail the build.
const fn length_range(min: usize, max: usize) -> PasswordLengthRange {
    assert!(min <= u8::MAX as usize && max <= u8::MAX as usize);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the assertion above bounds both values to one octet"
    )]
    let range = PasswordLengthRange::new(min as u8, max as u8);
    match range {
        Some(range) => range,
        None => panic!("the bounds admit a length"),
    }
}

/// Whether an EF.AOD reference names the credential a command addresses
/// as `expected`, with or without the specific-reference bit.
const fn names(listed: u8, expected: u8) -> bool {
    listed | SPECIFIC_REFERENCE_BIT == expected | SPECIFIC_REFERENCE_BIT
}

/// The one EF.AOD range for `expected`, or nothing when the directory
/// lists no object for it or more than one.
fn directory_range(objects: &AuthenticationObjects, expected: u8) -> Option<PasswordLengthRange> {
    let mut matching = objects
        .passwords()
        .iter()
        .filter(|object| names(object.reference(), expected));
    let first = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    Some(first.lengths())
}

/// The lengths an entry for one credential may have: the card's range
/// within what the commands carry, or the FINEID bounds when the card
/// lists none. `None` when the card's range shares no length with what
/// the commands carry, and no entry is accepted.
const fn accepted(
    listed: Option<PasswordLengthRange>,
    capacity: PasswordLengthRange,
    fallback: PasswordLengthRange,
) -> Option<PasswordLengthRange> {
    if let Some(range) = listed {
        range.intersection(capacity)
    } else {
        Some(fallback)
    }
}

/// The PIN 1, PIN 2 and PUK lengths of the card in session, under the
/// numbering they were mapped by.
///
/// Produced by [`crate::auth::PinOps::read_card_pin_lengths`]; the change
/// and reset operations take it, address the card under its numbering,
/// and refuse an entry outside its ranges before any command. It
/// describes one card session; a new session reads it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardPinLengths {
    numbering: PinReferenceScheme,
    pin1: Option<PasswordLengthRange>,
    pin2: Option<PasswordLengthRange>,
    puk: Option<PasswordLengthRange>,
}

impl CardPinLengths {
    /// Lengths for a card that lists none: every credential takes its
    /// FINEID bounds.
    #[must_use]
    pub const fn not_listed(numbering: PinReferenceScheme) -> Self {
        Self::from_listed(numbering, None, None, None)
    }

    const fn from_listed(
        numbering: PinReferenceScheme,
        pin1: Option<PasswordLengthRange>,
        pin2: Option<PasswordLengthRange>,
        puk: Option<PasswordLengthRange>,
    ) -> Self {
        Self {
            numbering,
            pin1: accepted(pin1, PIN_CAPACITY, FINEID_PIN1_BOUNDS),
            pin2: accepted(pin2, PIN_CAPACITY, FINEID_PIN2_BOUNDS),
            puk: accepted(puk, PUK_CAPACITY, FINEID_PUK_BOUNDS),
        }
    }

    /// Map EF.AOD's password objects onto PIN 1, PIN 2 and the PUK by the
    /// references `numbering` gives them; objects under other references
    /// are not consulted. `policy` supplies the second source for a
    /// credential the directory does not list.
    pub(crate) fn from_card(
        numbering: PinReferenceScheme,
        objects: Option<&AuthenticationObjects>,
        mut policy: impl FnMut(CredentialReference) -> Option<PasswordLengthRange>,
    ) -> Self {
        let mut listed = |credential: CredentialReference| {
            objects
                .and_then(|objects| directory_range(objects, credential.as_byte()))
                .or_else(|| policy(credential))
        };
        let pin1 = listed(CredentialReference::Pin(numbering, PinSlot::Pin1));
        let pin2 = listed(CredentialReference::Pin(numbering, PinSlot::Pin2));
        let puk = listed(CredentialReference::Puk(numbering));
        Self::from_listed(numbering, pin1, pin2, puk)
    }

    /// The numbering the lengths were mapped by, and the operations
    /// taking them address the card under.
    #[must_use]
    pub const fn numbering(&self) -> PinReferenceScheme {
        self.numbering
    }

    /// The lengths a PIN 1 entry may have.
    #[must_use]
    pub const fn pin1(&self) -> Option<PasswordLengthRange> {
        self.pin1
    }

    /// The lengths a PIN 2 entry may have.
    #[must_use]
    pub const fn pin2(&self) -> Option<PasswordLengthRange> {
        self.pin2
    }

    /// The lengths a PUK entry may have.
    #[must_use]
    pub const fn puk(&self) -> Option<PasswordLengthRange> {
        self.puk
    }

    /// The lengths an entry for the PIN in `slot` may have.
    #[must_use]
    pub const fn slot(&self, slot: PinSlot) -> Option<PasswordLengthRange> {
        match slot {
            PinSlot::Pin1 => self.pin1,
            PinSlot::Pin2 => self.pin2,
        }
    }

    /// Check an entry of `digit_count` digits for the PIN in `slot`.
    ///
    /// # Errors
    /// [`PinPolicyReason`] when the card does not accept the length.
    pub const fn check_pin(
        &self,
        slot: PinSlot,
        digit_count: usize,
    ) -> Result<(), PinPolicyReason> {
        check(self.slot(slot), digit_count)
    }

    /// Check a PUK entry of `digit_count` digits.
    ///
    /// # Errors
    /// [`PinPolicyReason`] when the card does not accept the length.
    pub const fn check_puk(&self, digit_count: usize) -> Result<(), PinPolicyReason> {
        check(self.puk, digit_count)
    }
}

/// Check `digit_count` against an accepted range.
const fn check(
    accepted: Option<PasswordLengthRange>,
    digit_count: usize,
) -> Result<(), PinPolicyReason> {
    match accepted {
        Some(range) if range.contains(digit_count) => Ok(()),
        Some(range) => Err(PinPolicyReason::WrongLength {
            got: digit_count,
            min: range.min(),
            max: range.max(),
        }),
        None => Err(PinPolicyReason::NoAcceptedLength),
    }
}

#[cfg(test)]
mod tests {
    use refineid_pkcs15::PasswordLengthRange;

    use super::CardPinLengths;
    use crate::auth::{
        CredentialReference, PIN1_REFERENCE_ORGANIZATIONAL, PIN1_REFERENCE_PKCS15, PinPolicyReason,
        PinReferenceScheme, PinSlot,
    };

    const SHORT_PIN: usize = 4;
    const EIGHT_DIGITS: usize = 8;
    const TEN_DIGITS: usize = 10;
    const TWELVE_DIGITS: usize = 12;
    const SIX_DIGITS: usize = 6;
    const SEVEN_DIGITS: usize = 7;
    const FIVE_DIGITS: usize = 5;
    const TWENTY_DIGITS: u8 = 20;
    const FOURTEEN_DIGITS: u8 = 14;

    fn range(min: usize, max: usize) -> PasswordLengthRange {
        PasswordLengthRange::new(
            u8::try_from(min).expect("one octet"),
            u8::try_from(max).expect("one octet"),
        )
        .expect("a range")
    }

    #[test]
    fn not_listed_takes_the_fineid_bounds() {
        let lengths = CardPinLengths::not_listed(PinReferenceScheme::Citizen);
        assert_eq!(lengths.pin1(), Some(range(SHORT_PIN, TWELVE_DIGITS)));
        assert_eq!(lengths.pin2(), Some(range(SIX_DIGITS, TWELVE_DIGITS)));
        assert_eq!(lengths.puk(), Some(range(EIGHT_DIGITS, TWELVE_DIGITS)));
    }

    #[test]
    fn a_policy_range_is_taken_within_the_command_capacity() {
        let lengths =
            CardPinLengths::from_card(
                PinReferenceScheme::Citizen,
                None,
                |reference| match reference {
                    CredentialReference::Pin(_, PinSlot::Pin1) => {
                        Some(range(SHORT_PIN, EIGHT_DIGITS))
                    }
                    CredentialReference::Pin(_, PinSlot::Pin2) => PasswordLengthRange::new(
                        u8::try_from(SHORT_PIN).expect("one octet"),
                        TWENTY_DIGITS,
                    ),
                    CredentialReference::Puk(_) => {
                        PasswordLengthRange::new(FOURTEEN_DIGITS, TWENTY_DIGITS)
                    }
                },
            );
        assert_eq!(lengths.pin1(), Some(range(SHORT_PIN, EIGHT_DIGITS)));
        assert_eq!(lengths.pin2(), Some(range(SHORT_PIN, TWELVE_DIGITS)));
        assert_eq!(lengths.puk(), None);
        assert_eq!(
            lengths.check_puk(TWELVE_DIGITS),
            Err(PinPolicyReason::NoAcceptedLength)
        );
    }

    #[test]
    fn checks_name_the_accepted_range() {
        let lengths = CardPinLengths::from_card(PinReferenceScheme::Citizen, None, |reference| {
            matches!(reference, CredentialReference::Pin(_, PinSlot::Pin1))
                .then(|| range(SHORT_PIN, EIGHT_DIGITS))
        });
        assert_eq!(lengths.check_pin(PinSlot::Pin1, SEVEN_DIGITS), Ok(()));
        assert_eq!(
            lengths.check_pin(PinSlot::Pin1, TEN_DIGITS),
            Err(PinPolicyReason::WrongLength {
                got: TEN_DIGITS,
                min: SHORT_PIN,
                max: EIGHT_DIGITS,
            })
        );
        assert_eq!(
            lengths.check_pin(PinSlot::Pin2, FIVE_DIGITS),
            Err(PinPolicyReason::WrongLength {
                got: FIVE_DIGITS,
                min: SIX_DIGITS,
                max: TWELVE_DIGITS,
            })
        );
    }

    #[test]
    fn references_match_with_or_without_the_specific_bit() {
        assert!(super::names(
            PIN1_REFERENCE_ORGANIZATIONAL,
            PIN1_REFERENCE_ORGANIZATIONAL
        ));
        assert!(super::names(
            PIN1_REFERENCE_PKCS15 | super::SPECIFIC_REFERENCE_BIT,
            PIN1_REFERENCE_PKCS15
        ));
        assert!(!super::names(
            PIN1_REFERENCE_ORGANIZATIONAL,
            PIN1_REFERENCE_PKCS15
        ));
    }
}
