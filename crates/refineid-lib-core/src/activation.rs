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

//! Card activation: which procedure a card takes and whether each PIN
//! still awaits it (FINEID S4-1 v4.2 §4.6).
//!
//! - §4.6.1, "activation code is the PUK": PIN 1 and PIN 2 ship
//!   blocked, and `RESET RETRY COUNTER` with the 8-digit activation
//!   code sets each.
//! - §4.6.2, "preset activation PIN": PIN 1 and PIN 2 ship set to one
//!   7-digit activation PIN, and `CHANGE REFERENCE DATA` from it sets
//!   each.
//!
//! An organization card (FINEID S4-2 v4.0 §4.2 numbering) takes
//! §4.6.1 whatever its certificate date. A citizen card takes the
//! procedure its authentication certificate's validity start names:
//! §4.6.2 from 13 January 2026, §4.6.1 before it.

use crate::auth::{PinReferenceScheme, PinStatus};
use crate::pin::{ActivationPinEight, ActivationPinSeven};
use crate::x509::DateTime;

/// Year of the DVV cutover to the preset activation PIN.
const PRESET_PIN_CUTOVER_YEAR: u16 = 2026;
/// Month of the DVV cutover to the preset activation PIN.
const PRESET_PIN_CUTOVER_MONTH: u8 = 1;
/// Day of the DVV cutover to the preset activation PIN.
const PRESET_PIN_CUTOVER_DAY: u8 = 13;

/// How a card is activated (FINEID S4-1 v4.2 §4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationScheme {
    /// §4.6.1: the PINs ship blocked and the 8-digit activation code
    /// is the PUK.
    ActivationCodeIsPuk,
    /// §4.6.2: the PINs ship set to the 7-digit preset activation PIN.
    PresetActivationPin,
}

impl ActivationScheme {
    /// Decide the scheme for a card.
    ///
    /// The organization numbering means §4.6.1. Under the citizen
    /// numbering the authentication certificate's validity start
    /// decides it; without one there is no scheme and no activation
    /// decision.
    #[must_use]
    pub fn for_card(
        numbering: PinReferenceScheme,
        validity_start: Option<DateTime>,
    ) -> Option<Self> {
        match numbering {
            PinReferenceScheme::Organizational => Some(Self::ActivationCodeIsPuk),
            PinReferenceScheme::Citizen => validity_start.map(Self::from_validity_start),
        }
    }

    /// The citizen-card scheme the authentication certificate's
    /// validity start names: §4.6.2 from 13 January 2026, §4.6.1
    /// before it.
    #[must_use]
    pub fn from_validity_start(not_before: DateTime) -> Self {
        let issued = (not_before.year(), not_before.month(), not_before.day());
        let cutover = (
            PRESET_PIN_CUTOVER_YEAR,
            PRESET_PIN_CUTOVER_MONTH,
            PRESET_PIN_CUTOVER_DAY,
        );
        if issued >= cutover {
            Self::PresetActivationPin
        } else {
            Self::ActivationCodeIsPuk
        }
    }

    /// The exact digit count the card accepts for the activation
    /// entry. Any other length burns a try.
    #[must_use]
    pub const fn activation_entry_digit_count(self) -> usize {
        match self {
            Self::ActivationCodeIsPuk => ActivationPinEight::LENGTH,
            Self::PresetActivationPin => ActivationPinSeven::LENGTH,
        }
    }
}

/// Whether one PIN still awaits its activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinActivation {
    /// The PIN still holds its factory state.
    AwaitsActivation,
    /// The PIN does not await activation.
    Activated,
}

impl PinActivation {
    /// Judge one PIN from its counter-safe probes.
    ///
    /// The PIN changed flag (FINEID S1 v4.2 §3.15.3) decides under both
    /// schemes: unchanged awaits activation, changed is activated.
    /// Without the flag, §4.6.1 falls back to the counter: a blocked or
    /// invalidated PIN, or one with no tries left, awaits activation (a
    /// factory-blocked PIN answers either way). Every other answer, and
    /// a §4.6.2 PIN without the flag, is activated.
    #[must_use]
    pub const fn judge(
        scheme: ActivationScheme,
        changed: Option<bool>,
        status: Option<PinStatus>,
    ) -> Self {
        match changed {
            Some(false) => Self::AwaitsActivation,
            Some(true) => Self::Activated,
            None => match (scheme, status) {
                (ActivationScheme::ActivationCodeIsPuk, Some(PinStatus::Locked)) => {
                    Self::AwaitsActivation
                }
                (ActivationScheme::ActivationCodeIsPuk, Some(PinStatus::Remaining(retries)))
                    if retries.is_exhausted() =>
                {
                    Self::AwaitsActivation
                }
                (
                    ActivationScheme::ActivationCodeIsPuk | ActivationScheme::PresetActivationPin,
                    _,
                ) => Self::Activated,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ActivationScheme, PinActivation};
    use crate::apdu::status_word::{PinRetries, StatusWord};
    use crate::auth::{PinReferenceScheme, PinStatus, classify_pin_status_sw};
    use crate::x509::DateTime;

    /// Midnight, for the cutover dates.
    const MIDNIGHT: u8 = 0;
    /// The cutover year.
    const CUTOVER_YEAR: u16 = 2026;
    /// January.
    const JANUARY: u8 = 1;
    /// The cutover day.
    const CUTOVER_DAY: u8 = 13;
    /// The day before the cutover.
    const DAY_BEFORE_CUTOVER: u8 = 12;
    /// A full PIN counter.
    const FULL_COUNTER: u8 = 5;
    /// A counter with no tries left (`63C0`).
    const NO_TRIES: u8 = 0;
    /// A status word outside the modeled set.
    const UNMODELED_SW: u16 = 0x6F00;

    fn date(day: u8) -> Result<DateTime, Box<dyn core::error::Error>> {
        Ok(DateTime::new(
            CUTOVER_YEAR,
            JANUARY,
            day,
            MIDNIGHT,
            MIDNIGHT,
            MIDNIGHT,
        )?)
    }

    fn counter(tries: u8) -> Result<PinStatus, &'static str> {
        PinRetries::from_nibble(tries)
            .map(PinStatus::Remaining)
            .ok_or("retry count fits a nibble")
    }

    #[test]
    fn the_validity_start_decides_the_citizen_scheme() -> Result<(), Box<dyn core::error::Error>> {
        assert_eq!(
            ActivationScheme::for_card(PinReferenceScheme::Citizen, Some(date(CUTOVER_DAY)?)),
            Some(ActivationScheme::PresetActivationPin)
        );
        assert_eq!(
            ActivationScheme::for_card(
                PinReferenceScheme::Citizen,
                Some(date(DAY_BEFORE_CUTOVER)?)
            ),
            Some(ActivationScheme::ActivationCodeIsPuk)
        );
        Ok(())
    }

    #[test]
    fn organization_numbering_gives_the_puk_scheme_whatever_the_date()
    -> Result<(), Box<dyn core::error::Error>> {
        for validity_start in [
            None,
            Some(date(DAY_BEFORE_CUTOVER)?),
            Some(date(CUTOVER_DAY)?),
        ] {
            assert_eq!(
                ActivationScheme::for_card(PinReferenceScheme::Organizational, validity_start),
                Some(ActivationScheme::ActivationCodeIsPuk)
            );
        }
        Ok(())
    }

    #[test]
    fn a_citizen_card_without_a_validity_start_has_no_scheme() {
        assert_eq!(
            ActivationScheme::for_card(PinReferenceScheme::Citizen, None),
            None
        );
    }

    #[test]
    fn the_entry_lengths_follow_the_scheme() {
        assert_eq!(
            ActivationScheme::ActivationCodeIsPuk.activation_entry_digit_count(),
            crate::pin::ActivationPinEight::LENGTH
        );
        assert_eq!(
            ActivationScheme::PresetActivationPin.activation_entry_digit_count(),
            crate::pin::ActivationPinSeven::LENGTH
        );
    }

    #[test]
    fn the_changed_flag_decides_under_both_schemes() -> Result<(), &'static str> {
        for scheme in [
            ActivationScheme::ActivationCodeIsPuk,
            ActivationScheme::PresetActivationPin,
        ] {
            for status in [
                Some(counter(FULL_COUNTER)?),
                Some(PinStatus::Locked),
                Some(counter(NO_TRIES)?),
                None,
            ] {
                assert_eq!(
                    PinActivation::judge(scheme, Some(false), status),
                    PinActivation::AwaitsActivation
                );
                assert_eq!(
                    PinActivation::judge(scheme, Some(true), status),
                    PinActivation::Activated
                );
            }
        }
        Ok(())
    }

    #[test]
    fn a_factory_blocked_puk_scheme_pin_awaits_activation_without_the_flag()
    -> Result<(), &'static str> {
        let exhausted = PinRetries::from_nibble(NO_TRIES).ok_or("zero fits a nibble")?;
        for status_word in [
            StatusWord::AuthenticationBlocked,
            StatusWord::ReferenceDataInvalidated,
            StatusWord::PinIncorrect { retries: exhausted },
        ] {
            assert_eq!(
                PinActivation::judge(
                    ActivationScheme::ActivationCodeIsPuk,
                    None,
                    Some(classify_pin_status_sw(status_word)),
                ),
                PinActivation::AwaitsActivation
            );
        }
        Ok(())
    }

    #[test]
    fn a_usable_puk_scheme_pin_is_activated_without_the_flag() -> Result<(), &'static str> {
        for status in [counter(FULL_COUNTER)?, PinStatus::Verified] {
            assert_eq!(
                PinActivation::judge(ActivationScheme::ActivationCodeIsPuk, None, Some(status)),
                PinActivation::Activated
            );
        }
        Ok(())
    }

    #[test]
    fn an_uninformative_puk_scheme_probe_counts_as_activated() {
        for status in [
            Some(PinStatus::NoInfo),
            Some(PinStatus::Other(UNMODELED_SW)),
            None,
        ] {
            assert_eq!(
                PinActivation::judge(ActivationScheme::ActivationCodeIsPuk, None, status),
                PinActivation::Activated
            );
        }
    }

    #[test]
    fn a_preset_pin_scheme_pin_without_the_flag_counts_as_activated() -> Result<(), &'static str> {
        for status in [
            Some(counter(FULL_COUNTER)?),
            Some(PinStatus::Locked),
            Some(counter(NO_TRIES)?),
            None,
        ] {
            assert_eq!(
                PinActivation::judge(ActivationScheme::PresetActivationPin, None, status),
                PinActivation::Activated
            );
        }
        Ok(())
    }
}
