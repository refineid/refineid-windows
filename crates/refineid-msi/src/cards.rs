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

use refineid_lib_core::fineid_card::FineidCardModel;

/// Where Windows keeps per-card Smart Card Crypto Provider registrations.
pub const CALAIS: &str = r"SOFTWARE\Microsoft\Cryptography\Calais\SmartCards";

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
    use super::{CARDS, CardRegistration};

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
}
