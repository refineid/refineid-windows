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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The card families the package binds to the Card Module.
//!
//! Windows pairs an inserted card with a Card Module by its answer to
//! reset: it masks the card's ATR with each registration's `ATRMask` under
//! `Calais\SmartCards` and loads the module of the registration whose `ATR`
//! the result equals (Microsoft, "Smart Card Plug and Play", Pairing
//! Process). These registrations are the package's product; the Device
//! Manager names in [`crate::inf`] are derived from them.

use refineid_atr::fineid::FineidCardModel;

/// Where Windows keeps per-card Smart Card Crypto Provider registrations.
pub const CALAIS: &str = r"SOFTWARE\Microsoft\Cryptography\Calais\SmartCards";

/// Registry value name for `SECRET_PURPOSE::AuthenticationPin` PIN prompt
/// overrides under `Calais\SmartCards` (Microsoft Smart Card Minidriver
/// Specification, "PIN Context Strings").
pub const PIN_PROMPT_AUTH_VALUE: &str = "80000100";
/// Registry value name for `SECRET_PURPOSE::DigitalSignaturePin`.
pub const PIN_PROMPT_SIGNATURE_VALUE: &str = "80000101";
/// Registry value name for `SECRET_PURPOSE::NonRepudiationPin` (PIN 2 in
/// `refineid-minidriver`).
pub const PIN_PROMPT_NON_REPUDIATION_VALUE: &str = "80000103";
/// Registry value name for `SECRET_PURPOSE::PrimaryCardPin` (PIN 1 in
/// `refineid-minidriver`).
pub const PIN_PROMPT_PRIMARY_VALUE: &str = "80000105";
/// Registry value name for `SECRET_PURPOSE::UnblockOnlyPin` (PUK in
/// `refineid-minidriver`).
pub const PIN_PROMPT_UNBLOCK_VALUE: &str = "80000106";

/// Localized Windows Security PIN prompt for authentication (PIN 1),
/// formatted as semicolon-separated `locale,message` pairs for the Base CSP
/// and Smart Card KSP.
pub const PIN_PROMPT_PIN1_LOCALIZED: &str = concat!(
    "fi-FI,Anna PIN 1 tunnistautumista varten.;",
    "sv-FI,Ange PIN 1 för identifiering.;",
    "sv-SE,Ange PIN 1 för identifiering.;",
    "et-EE,Isikutuvastuseks sisesta PIN 1.;",
    "en-US,Enter PIN 1 for authentication.;",
    "en-GB,Enter PIN 1 for authentication.;",
    "en-AU,Enter PIN 1 for authentication.;",
    "en-CA,Enter PIN 1 for authentication.;",
    "en-IE,Enter PIN 1 for authentication.;",
    "en-IN,Enter PIN 1 for authentication.;",
    "en-NZ,Enter PIN 1 for authentication.;",
    "en-ZA,Enter PIN 1 for authentication.",
);

/// Localized Windows Security PIN prompt for digital and qualified signing
/// (PIN 2).
pub const PIN_PROMPT_PIN2_LOCALIZED: &str = concat!(
    "fi-FI,Anna PIN 2 allekirjoittamista varten.;",
    "sv-FI,Ange PIN 2 för signering.;",
    "sv-SE,Ange PIN 2 för signering.;",
    "et-EE,Allkirjastamiseks sisesta PIN 2.;",
    "en-US,Enter PIN 2 for signing.;",
    "en-GB,Enter PIN 2 for signing.;",
    "en-AU,Enter PIN 2 for signing.;",
    "en-CA,Enter PIN 2 for signing.;",
    "en-IE,Enter PIN 2 for signing.;",
    "en-IN,Enter PIN 2 for signing.;",
    "en-NZ,Enter PIN 2 for signing.;",
    "en-ZA,Enter PIN 2 for signing.",
);

/// Localized Windows Security prompt for unblocking with the PUK.
pub const PIN_PROMPT_PUK_LOCALIZED: &str = concat!(
    "fi-FI,Anna PUK-koodi.;",
    "sv-FI,Ange PUK-kod.;",
    "sv-SE,Ange PUK-kod.;",
    "et-EE,Sisesta PUK-kood.;",
    "en-US,Enter PUK code.;",
    "en-GB,Enter PUK code.;",
    "en-AU,Enter PUK code.;",
    "en-CA,Enter PUK code.;",
    "en-IE,Enter PUK code.;",
    "en-IN,Enter PUK code.;",
    "en-NZ,Enter PUK code.;",
    "en-ZA,Enter PUK code.",
);

/// Localized PIN prompt `(value_name, value_data)` pairs written under every
/// `Calais\SmartCards` registration.
pub const PIN_PROMPT_VALUES: &[(&str, &str)] = &[
    (PIN_PROMPT_AUTH_VALUE, PIN_PROMPT_PIN1_LOCALIZED),
    (PIN_PROMPT_PRIMARY_VALUE, PIN_PROMPT_PIN1_LOCALIZED),
    (PIN_PROMPT_SIGNATURE_VALUE, PIN_PROMPT_PIN2_LOCALIZED),
    (PIN_PROMPT_NON_REPUDIATION_VALUE, PIN_PROMPT_PIN2_LOCALIZED),
    (PIN_PROMPT_UNBLOCK_VALUE, PIN_PROMPT_PUK_LOCALIZED),
];

/// A card family Windows should bind to this Card Module.
#[derive(Debug, Clone, Copy)]
pub struct CardRegistration {
    /// Registration name, which becomes the Calais subkey.
    pub name: &'static str,
    /// The card's answer to reset, after the mask.
    pub atr: &'static [u8],
    /// Which answer-to-reset bytes must match. A zero byte is a wildcard.
    pub mask: &'static [u8],
    /// The card model whose field-observed answers to reset this
    /// registration binds, or `None` when no reader presents the card
    /// today.
    pub model: Option<FineidCardModel>,
}

impl CardRegistration {
    /// Whether Windows pairs a card answering `atr` to reset with this
    /// registration: the masked ATR equals the registered one.
    #[must_use]
    pub fn binds(&self, atr: &[u8]) -> bool {
        atr.len() == self.atr.len()
            && self.mask.len() == self.atr.len()
            && atr
                .iter()
                .zip(self.mask)
                .zip(self.atr)
                .all(|((byte, mask), registered)| byte & mask == *registered)
    }
}

/// FINEID S4-1 v3.1 answers to reset identically on every card, so the
/// mask requires all twenty bytes. The v4.0 family carries card-specific
/// data in bytes 13 to 17, which the mask therefore ignores.
pub const CARDS: &[CardRegistration] = &[
    CardRegistration {
        name: "FINEID-S4-1-v3.1",
        atr: &[
            0x3b, 0x7f, 0x96, 0x00, 0x00, 0x80, 0x31, 0xb8, 0x65, 0xb0, 0x85, 0x04, 0x02, 0x1b,
            0x12, 0x00, 0xf6, 0x82, 0x90, 0x00,
        ],
        mask: &[0xff; 20],
        model: Some(FineidCardModel::GemaltoMultiAppV4_2),
    },
    CardRegistration {
        name: "FINEID-S4-1-v4.0",
        atr: &[
            0x3b, 0x7f, 0x96, 0x00, 0x00, 0x80, 0x31, 0xb8, 0x65, 0xb0, 0x85, 0x05, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x82, 0x90, 0x00,
        ],
        mask: &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
        ],
        model: Some(FineidCardModel::ThalesMultiAppV5_0),
    },
    // The synthetic answer to reset of the later virtual reader for a
    // paired phone. No reader presents it yet, so Plug and Play never sees
    // it and the INF names no device for it.
    CardRegistration {
        name: "FINEID-RAPP-Remote",
        atr: &[
            0x3b, 0x7f, 0x96, 0x00, 0x00, 0x80, 0x31, 0xb8, 0x65, 0xb0, 0x85, 0x05, 0x52, 0x41,
            0x50, 0x50, 0x00, 0x82, 0x90, 0x00,
        ],
        mask: &[0xff; 20],
        model: None,
    },
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        CARDS, CardRegistration, PIN_PROMPT_PIN1_LOCALIZED, PIN_PROMPT_PIN2_LOCALIZED,
        PIN_PROMPT_PUK_LOCALIZED, PIN_PROMPT_VALUES,
    };

    const REQUIRED_LOCALES: &[&str] = &[
        "fi-FI", "sv-FI", "sv-SE", "et-EE", "en-US", "en-GB", "en-AU", "en-CA", "en-IE", "en-IN",
        "en-NZ", "en-ZA",
    ];

    /// The v4.0 registration.
    fn v4_0() -> &'static CardRegistration {
        CARDS
            .iter()
            .find(|card| card.name == "FINEID-S4-1-v4.0")
            .expect("the v4.0 registration exists")
    }

    #[test]
    fn every_mask_covers_its_answer_to_reset() {
        for card in CARDS {
            assert_eq!(card.mask.len(), card.atr.len(), "{}", card.name);
            assert!(card.binds(card.atr), "{} binds its own ATR", card.name);
        }
    }

    #[test]
    fn every_field_observed_contact_atr_is_bound_by_its_registration() {
        for card in CARDS {
            let Some(model) = card.model else { continue };
            for atr in model.contact_atr_byte_sets() {
                assert!(card.binds(atr), "{} binds a {model:?} ATR", card.name);
            }
        }
    }

    #[test]
    fn a_registration_binds_no_other_model() {
        for card in CARDS {
            for other in CARDS.iter().filter(|other| other.name != card.name) {
                let Some(model) = other.model else { continue };
                for atr in model.contact_atr_byte_sets() {
                    assert!(!card.binds(atr), "{} must not bind {model:?}", card.name);
                }
            }
        }
    }

    #[test]
    fn a_shorter_answer_to_reset_never_binds() {
        let card = v4_0();
        let truncated = card.atr.split_last().map(|(_, rest)| rest).expect("ATR");
        assert!(!card.binds(truncated));
    }

    #[test]
    fn pin_prompt_strings_cover_required_locales_without_quotes_or_duplicates() {
        let mut names = HashSet::new();
        for &(name, value) in PIN_PROMPT_VALUES {
            assert!(names.insert(name), "duplicate registry value name {name}");
            assert!(
                !value.contains('"'),
                "Windows parses quotes literally in {name}"
            );
            let mut seen_locales = HashSet::new();
            for entry in value.split(';') {
                let (locale, message) = entry
                    .split_once(',')
                    .unwrap_or_else(|| panic!("malformed entry in {name}: {entry}"));
                assert!(!locale.is_empty(), "empty locale in {name}");
                assert!(!message.is_empty(), "empty message for {locale} in {name}");
                assert!(
                    message.ends_with('.'),
                    "prompt for {locale} in {name} must end with a period: {message}"
                );
                assert!(
                    seen_locales.insert(locale),
                    "duplicate locale {locale} in {name}"
                );
            }
            for &required in REQUIRED_LOCALES {
                assert!(
                    seen_locales.contains(required),
                    "missing locale {required} in {name}"
                );
            }
        }
        for entry in PIN_PROMPT_PIN1_LOCALIZED.split(';') {
            assert!(entry.contains("PIN 1"), "PIN 1 label missing in {entry}");
        }
        for entry in PIN_PROMPT_PIN2_LOCALIZED.split(';') {
            assert!(entry.contains("PIN 2"), "PIN 2 label missing in {entry}");
        }
        for entry in PIN_PROMPT_PUK_LOCALIZED.split(';') {
            assert!(entry.contains("PUK"), "PUK label missing in {entry}");
        }
    }
}
