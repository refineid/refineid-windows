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

//! Scheme-aware PIN and PUK preflight preparation for card operations.
//!
//! Resolves the card's [`PinReferenceScheme`] (citizen vs. organizational)
//! before probing retry counters so organizational cards (FINEID S4-2) are
//! probed under their `0x03` / `0x04` / `0x12` references rather than
//! hardcoded citizen `0x11` / `0x82` / `GET DATA` probes.

use refineid_lib_core::auth::{
    CardPinLengths, PinOps, PinReferenceScheme, PinSlot, PinStatus, PukStatus,
};
use refineid_lib_core::pkcs15::Pkcs15Ops;
use refineid_lib_core::transport::CardTransport;

/// Which step of scheme-aware PIN/PUK preparation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPrepareFailure {
    /// Selecting the PKCS#15 application or resolving the card's numbering failed.
    Session,
    /// Reading the card's accepted PIN/PUK lengths (`EF.AOD` / PIN containers) failed.
    PinLengths,
}

/// Select the PKCS#15 application, resolve the card's credential numbering,
/// and read `slot`'s counter-safe retry status under that numbering.
pub fn prepare_pin_verify<T: CardTransport>(
    tx: &mut T,
    slot: PinSlot,
) -> Result<(PinReferenceScheme, PinStatus), PinPrepareFailure> {
    tx.select_pkcs15_application()
        .map_err(|_error| PinPrepareFailure::Session)?;
    let scheme = tx
        .resolve_pin_reference_scheme()
        .map_err(|_error| PinPrepareFailure::Session)?;
    let status = tx
        .pin_status_with_scheme(scheme, slot)
        .map_err(|_error| PinPrepareFailure::Session)?;
    Ok((scheme, status))
}

/// Select the PKCS#15 application, read the card's accepted PIN lengths
/// (which resolves the card's credential numbering), and probe `slot`'s
/// counter-safe retry status under that resolved numbering.
pub fn prepare_pin_change<T: CardTransport>(
    tx: &mut T,
    slot: PinSlot,
) -> Result<(CardPinLengths, PinStatus), PinPrepareFailure> {
    tx.select_pkcs15_application()
        .map_err(|_error| PinPrepareFailure::Session)?;
    let lengths = tx
        .read_card_pin_lengths()
        .map_err(|_error| PinPrepareFailure::PinLengths)?;
    let status = tx
        .pin_status_with_scheme(lengths.numbering(), slot)
        .map_err(|_error| PinPrepareFailure::Session)?;
    Ok((lengths, status))
}

/// Select the PKCS#15 application, read the card's accepted PIN/PUK lengths
/// (which resolves the card's credential numbering), and probe the PUK's
/// counter-safe retry status under that resolved numbering.
pub fn prepare_pin_unblock<T: CardTransport>(
    tx: &mut T,
) -> Result<(CardPinLengths, PukStatus), PinPrepareFailure> {
    tx.select_pkcs15_application()
        .map_err(|_error| PinPrepareFailure::Session)?;
    let lengths = tx
        .read_card_pin_lengths()
        .map_err(|_error| PinPrepareFailure::PinLengths)?;
    let status = tx
        .puk_status_with_scheme(lengths.numbering())
        .map_err(|_error| PinPrepareFailure::Session)?;
    Ok((lengths, status))
}

#[cfg(test)]
mod tests {
    use core::fmt;

    use refineid_atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
    use refineid_lib_core::apdu::status_word::PinRetries;
    use refineid_lib_core::auth::{
        PIN1_REFERENCE_ORGANIZATIONAL, PIN1_REFERENCE_PKCS15, PIN2_REFERENCE_ORGANIZATIONAL,
        PIN2_REFERENCE_PKCS15, PUK_REFERENCE_ORGANIZATIONAL, PinReferenceScheme, PinSlot,
        PinStatus, PukStatus,
    };
    use refineid_lib_core::pkcs15::PKCS15_AID;
    use refineid_lib_core::transport::{
        CardTransport, CommandApdu, ResponseApdu, TransportErrorExt, TransportErrorKind,
        TransportOutcome,
    };

    use super::{PinPrepareFailure, prepare_pin_change, prepare_pin_unblock, prepare_pin_verify};

    const FIVE_RETRIES: u8 = 5;
    const FOUR_RETRIES: u8 = 4;
    const THREE_RETRIES: u8 = 3;
    const SW1_RETRIES_PREFIX: u8 = 0x63;
    const SW2_RETRIES_BASE: u8 = 0xC0;
    const SW1_OK: u8 = 0x90;
    const SW2_OK: u8 = 0x00;
    const SW1_NOT_FOUND: u8 = 0x6A;
    const SW2_FILE_NOT_FOUND: u8 = 0x82;
    const SW2_REF_DATA_NOT_FOUND: u8 = 0x88;
    const INS_SELECT: u8 = 0xA4;
    const INS_VERIFY: u8 = 0x20;
    const INS_GET_DATA: u8 = 0xCB;
    const P1_SELECT_BY_AID: u8 = 0x04;
    const TAG_PIN_COUNTER: u8 = 0xDF;
    const TAG_PIN_COUNTER_LOW: u8 = 0x21;
    const PIN_ATTRIBUTES_LEN: u8 = 0x04;
    const USAGE_NO_LIMIT: u8 = 0xFF;
    const UNBLOCKING_NO_LIMIT: u8 = 0xA5;
    const PUK_METHOD_BYTE: u8 = 0x83;

    #[derive(Debug)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("mock transport error")
        }
    }

    impl core::error::Error for MockError {}

    impl TransportErrorExt for MockError {
        fn kind(&self) -> TransportErrorKind {
            TransportErrorKind::Backend
        }
    }

    struct ScriptedCard {
        scheme: PinReferenceScheme,
        pin1_retries: u8,
        pin2_retries: u8,
        puk_retries: u8,
        fail_on_call: Option<usize>,
        sent: Vec<Vec<u8>>,
    }

    impl ScriptedCard {
        const fn new(
            scheme: PinReferenceScheme,
            pin1_retries: u8,
            pin2_retries: u8,
            puk_retries: u8,
        ) -> Self {
            Self {
                scheme,
                pin1_retries,
                pin2_retries,
                puk_retries,
                fail_on_call: None,
                sent: Vec::new(),
            }
        }

        const fn failing_on(mut self, call_index: usize) -> Self {
            self.fail_on_call = Some(call_index);
            self
        }

        const fn sw_retries(retries: u8) -> ResponseApdu {
            ResponseApdu {
                body: Vec::new(),
                sw1: SW1_RETRIES_PREFIX,
                sw2: SW2_RETRIES_BASE | retries,
            }
        }
    }

    impl CardTransport for ScriptedCard {
        type Error = MockError;

        fn transmit_outcome(
            &mut self,
            command: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            let call_index = self.sent.len();
            let apdu = command.as_bytes();
            self.sent.push(apdu.to_vec());
            if self.fail_on_call == Some(call_index) {
                return Err(MockError);
            }
            let ins = apdu.get(1).copied().unwrap_or_default();
            let p1 = apdu.get(2).copied().unwrap_or_default();
            let p2 = apdu.get(3).copied().unwrap_or_default();

            let response = if ins == INS_SELECT {
                if p1 == P1_SELECT_BY_AID && apdu.get(5..5 + PKCS15_AID.len()) == Some(PKCS15_AID) {
                    ResponseApdu {
                        body: Vec::new(),
                        sw1: SW1_OK,
                        sw2: SW2_OK,
                    }
                } else {
                    ResponseApdu {
                        body: Vec::new(),
                        sw1: SW1_NOT_FOUND,
                        sw2: SW2_FILE_NOT_FOUND,
                    }
                }
            } else if ins == INS_VERIFY && apdu.len() == 5 && apdu.get(4) == Some(&0) {
                match (self.scheme, p2) {
                    (PinReferenceScheme::Citizen, PIN1_REFERENCE_PKCS15)
                    | (PinReferenceScheme::Organizational, PIN1_REFERENCE_ORGANIZATIONAL) => {
                        Self::sw_retries(self.pin1_retries)
                    }
                    (PinReferenceScheme::Citizen, PIN2_REFERENCE_PKCS15)
                    | (PinReferenceScheme::Organizational, PIN2_REFERENCE_ORGANIZATIONAL) => {
                        Self::sw_retries(self.pin2_retries)
                    }
                    (PinReferenceScheme::Organizational, PUK_REFERENCE_ORGANIZATIONAL) => {
                        Self::sw_retries(self.puk_retries)
                    }
                    _ => ResponseApdu {
                        body: Vec::new(),
                        sw1: SW1_NOT_FOUND,
                        sw2: SW2_REF_DATA_NOT_FOUND,
                    },
                }
            } else if ins == INS_GET_DATA {
                if self.scheme == PinReferenceScheme::Citizen {
                    ResponseApdu {
                        body: vec![
                            TAG_PIN_COUNTER,
                            TAG_PIN_COUNTER_LOW,
                            PIN_ATTRIBUTES_LEN,
                            self.puk_retries,
                            USAGE_NO_LIMIT,
                            UNBLOCKING_NO_LIMIT,
                            PUK_METHOD_BYTE,
                        ],
                        sw1: SW1_OK,
                        sw2: SW2_OK,
                    }
                } else {
                    ResponseApdu {
                        body: Vec::new(),
                        sw1: SW1_NOT_FOUND,
                        sw2: SW2_REF_DATA_NOT_FOUND,
                    }
                }
            } else {
                ResponseApdu {
                    body: Vec::new(),
                    sw1: SW1_NOT_FOUND,
                    sw2: SW2_FILE_NOT_FOUND,
                }
            };

            Ok(TransportOutcome::Response(response))
        }

        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    #[test]
    fn prepare_pin_verify_resolves_organizational_for_pin1_and_pin2() {
        let mut pin1_card = ScriptedCard::new(
            PinReferenceScheme::Organizational,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        );
        let (scheme, status) =
            prepare_pin_verify(&mut pin1_card, PinSlot::Pin1).expect("org pin1 prepare");
        assert_eq!(scheme, PinReferenceScheme::Organizational);
        assert_eq!(
            status,
            PinStatus::Remaining(PinRetries::from_nibble(FIVE_RETRIES).expect("valid retries"))
        );

        let mut pin2_card = ScriptedCard::new(
            PinReferenceScheme::Organizational,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        );
        let (scheme, status) =
            prepare_pin_verify(&mut pin2_card, PinSlot::Pin2).expect("org pin2 prepare");
        assert_eq!(scheme, PinReferenceScheme::Organizational);
        assert_eq!(
            status,
            PinStatus::Remaining(PinRetries::from_nibble(FOUR_RETRIES).expect("valid retries"))
        );
    }

    #[test]
    fn prepare_pin_change_probes_under_resolved_organizational_scheme() {
        let mut card = ScriptedCard::new(
            PinReferenceScheme::Organizational,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        );
        let (lengths, status) =
            prepare_pin_change(&mut card, PinSlot::Pin2).expect("org change prepare");
        assert_eq!(lengths.numbering(), PinReferenceScheme::Organizational);
        assert_eq!(
            status,
            PinStatus::Remaining(PinRetries::from_nibble(FOUR_RETRIES).expect("valid retries"))
        );
        assert!(
            !card.sent.iter().any(|apdu| {
                apdu.get(1) == Some(&INS_VERIFY) && apdu.get(3) == Some(&PIN2_REFERENCE_PKCS15)
            }),
            "organizational PIN 2 change must not probe citizen PIN 2 reference"
        );
    }

    #[test]
    fn prepare_pin_unblock_probes_organizational_puk_via_verify_not_get_data() {
        let mut org_card = ScriptedCard::new(
            PinReferenceScheme::Organizational,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        );
        let (lengths, status) = prepare_pin_unblock(&mut org_card).expect("org unblock prepare");
        assert_eq!(lengths.numbering(), PinReferenceScheme::Organizational);
        assert_eq!(
            status,
            PukStatus::Remaining(PinRetries::from_nibble(THREE_RETRIES).expect("valid retries"))
        );
        assert!(
            !org_card
                .sent
                .iter()
                .any(|apdu| apdu.get(1) == Some(&INS_GET_DATA)),
            "organizational unblock must not probe citizen GET DATA PUK container"
        );

        let mut citizen_card = ScriptedCard::new(
            PinReferenceScheme::Citizen,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        );
        let (lengths, status) =
            prepare_pin_unblock(&mut citizen_card).expect("citizen unblock prepare");
        assert_eq!(lengths.numbering(), PinReferenceScheme::Citizen);
        assert_eq!(
            status,
            PukStatus::Remaining(PinRetries::from_nibble(THREE_RETRIES).expect("valid retries"))
        );
    }

    #[test]
    fn prepare_pin_verify_and_change_work_for_citizen_card() {
        let mut pin1_card = ScriptedCard::new(
            PinReferenceScheme::Citizen,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        );
        let (scheme, status) =
            prepare_pin_verify(&mut pin1_card, PinSlot::Pin1).expect("citizen pin1 prepare");
        assert_eq!(scheme, PinReferenceScheme::Citizen);
        assert_eq!(
            status,
            PinStatus::Remaining(PinRetries::from_nibble(FIVE_RETRIES).expect("valid retries"))
        );

        let mut pin2_card = ScriptedCard::new(
            PinReferenceScheme::Citizen,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        );
        let (scheme, status) =
            prepare_pin_verify(&mut pin2_card, PinSlot::Pin2).expect("citizen pin2 prepare");
        assert_eq!(scheme, PinReferenceScheme::Citizen);
        assert_eq!(
            status,
            PinStatus::Remaining(PinRetries::from_nibble(FOUR_RETRIES).expect("valid retries"))
        );

        let mut change_card = ScriptedCard::new(
            PinReferenceScheme::Citizen,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        );
        let (lengths, status) =
            prepare_pin_change(&mut change_card, PinSlot::Pin1).expect("citizen pin1 change");
        assert_eq!(lengths.numbering(), PinReferenceScheme::Citizen);
        assert_eq!(
            status,
            PinStatus::Remaining(PinRetries::from_nibble(FIVE_RETRIES).expect("valid retries"))
        );
    }

    #[test]
    fn prepare_helpers_distinguish_session_and_pin_lengths_failures() {
        let mut select_fail_change = ScriptedCard::new(
            PinReferenceScheme::Organizational,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        )
        .failing_on(0);
        assert_eq!(
            prepare_pin_change(&mut select_fail_change, PinSlot::Pin1),
            Err(PinPrepareFailure::Session)
        );

        let mut lengths_fail_change = ScriptedCard::new(
            PinReferenceScheme::Organizational,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        )
        .failing_on(1);
        assert_eq!(
            prepare_pin_change(&mut lengths_fail_change, PinSlot::Pin1),
            Err(PinPrepareFailure::PinLengths)
        );

        let mut select_fail_unblock = ScriptedCard::new(
            PinReferenceScheme::Organizational,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        )
        .failing_on(0);
        assert_eq!(
            prepare_pin_unblock(&mut select_fail_unblock),
            Err(PinPrepareFailure::Session)
        );

        let mut lengths_fail_unblock = ScriptedCard::new(
            PinReferenceScheme::Organizational,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        )
        .failing_on(1);
        assert_eq!(
            prepare_pin_unblock(&mut lengths_fail_unblock),
            Err(PinPrepareFailure::PinLengths)
        );

        let mut probe_fail_unblock = ScriptedCard::new(
            PinReferenceScheme::Organizational,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        );
        let (lengths, _) = prepare_pin_unblock(&mut probe_fail_unblock).expect("baseline count");
        assert_eq!(lengths.numbering(), PinReferenceScheme::Organizational);
        let last_call = probe_fail_unblock.sent.len() - 1;
        let mut probe_fail_unblock = ScriptedCard::new(
            PinReferenceScheme::Organizational,
            FIVE_RETRIES,
            FOUR_RETRIES,
            THREE_RETRIES,
        )
        .failing_on(last_call);
        assert_eq!(
            prepare_pin_unblock(&mut probe_fail_unblock),
            Err(PinPrepareFailure::Session)
        );
    }
}
