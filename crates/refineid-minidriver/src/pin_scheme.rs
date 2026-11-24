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
//! Resolves the card's [`PinReferenceScheme`] (citizen, organizational, or
//! Estonian eID) before probing retry counters so organizational cards
//! (FINEID S4-2) are probed under their own references (and inside
//! `DF.ESIGN` for Signature PIN 2) rather than hardcoded citizen probes, and
//! Estonian eID PIN 2 fails closed because it lives in the separate QSCD
//! application.

use refineid_apdu::CardTransport;
use refineid_auth::{CardPinLengths, PinManageOps, PinOps, PinReferenceScheme, PinSlot, PinStatus};
use refineid_pkcs15::Pkcs15Ops;

/// Which step of scheme-aware PIN/PUK preparation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPrepareFailure {
    /// Selecting the PKCS#15 application or resolving the card's numbering failed.
    Session,
    /// Reading the card's accepted PIN/PUK lengths (`EF.AOD` / PIN containers) failed.
    PinLengths,
    /// The requested PIN slot is not supported under the card's resolved numbering.
    UnsupportedSlot,
}

/// Select the PKCS#15 application, resolve the card's credential numbering,
/// and read `slot`'s counter-safe retry status under that numbering.
///
/// For Signature PIN 2 on an organizational card, selects `DF.ESIGN` before
/// probing so the local PIN SIG security-data object is in scope. Fails
/// closed with [`PinPrepareFailure::UnsupportedSlot`] for Estonian eID PIN 2.
pub fn prepare_pin_verify<T: CardTransport>(
    tx: &mut T,
    slot: PinSlot,
) -> Result<(PinReferenceScheme, PinStatus), PinPrepareFailure> {
    tx.select_pkcs15_application()
        .map_err(|_error| PinPrepareFailure::Session)?;
    let (scheme, pin1_status) = tx
        .pin1_status_and_scheme()
        .map_err(|_error| PinPrepareFailure::Session)?;
    if slot == PinSlot::Pin1 {
        return Ok((scheme, pin1_status));
    }
    if scheme == PinReferenceScheme::Estonian {
        return Err(PinPrepareFailure::UnsupportedSlot);
    }
    if scheme == PinReferenceScheme::Organizational {
        tx.select_esign_directory()
            .map_err(|_error| PinPrepareFailure::Session)?;
    }
    let status = tx
        .pin_status_with_scheme(scheme, PinSlot::Pin2)
        .map_err(|_error| PinPrepareFailure::Session)?;
    Ok((scheme, status))
}

/// Select the PKCS#15 application, read the card's accepted PIN lengths
/// (which resolves the card's credential numbering), and probe `slot`'s
/// counter-safe retry status under that resolved numbering.
///
/// For Signature PIN 2 on an organizational card, selects `DF.ESIGN` before
/// probing so both the counter probe and the subsequent `CHANGE REFERENCE DATA`
/// command run with the local PIN SIG object in scope. Fails closed with
/// [`PinPrepareFailure::UnsupportedSlot`] for Estonian eID PIN 2.
pub fn prepare_pin_change<T: CardTransport>(
    tx: &mut T,
    slot: PinSlot,
) -> Result<(CardPinLengths, PinStatus), PinPrepareFailure> {
    tx.select_pkcs15_application()
        .map_err(|_error| PinPrepareFailure::Session)?;
    let lengths = tx
        .read_card_pin_lengths()
        .map_err(|_error| PinPrepareFailure::PinLengths)?;
    if slot == PinSlot::Pin2 && lengths.numbering() == PinReferenceScheme::Estonian {
        return Err(PinPrepareFailure::UnsupportedSlot);
    }
    if slot == PinSlot::Pin2 && lengths.numbering() == PinReferenceScheme::Organizational {
        tx.select_esign_directory()
            .map_err(|_error| PinPrepareFailure::Session)?;
    }
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
) -> Result<(CardPinLengths, PinStatus), PinPrepareFailure> {
    tx.select_pkcs15_application()
        .map_err(|_error| PinPrepareFailure::Session)?;
    let lengths = tx
        .read_card_pin_lengths()
        .map_err(|_error| PinPrepareFailure::PinLengths)?;
    let status = tx
        .probe_puk_status_with_scheme(lengths.numbering())
        .map_err(|_error| PinPrepareFailure::Session)?;
    Ok((lengths, status))
}

#[cfg(test)]
mod tests {
    use core::fmt;

    use refineid_apdu::iso7816::SelectFile;
    use refineid_apdu::{
        CardTransport, CommandApdu, CredentialCommand, FileId, PinRetries, ResponseApdu,
        StatusWord, TransportErrorExt, TransportErrorKind, TransportOutcome,
    };
    use refineid_auth::verify::{
        PIN1_REFERENCE, PIN1_REFERENCE_ESTONIAN, PIN1_REFERENCE_ORGANIZATIONAL, PIN2_REFERENCE,
        PIN2_REFERENCE_ORGANIZATIONAL, PUK_REFERENCE, PUK_REFERENCE_ORGANIZATIONAL, VERIFY_INS,
    };
    use refineid_auth::{PinReferenceScheme, PinSlot, PinStatus};
    use refineid_pkcs15::{ESIGN_AID, PKCS15_AID};

    use super::{PinPrepareFailure, prepare_pin_change, prepare_pin_unblock, prepare_pin_verify};

    const FIVE_RETRIES: u8 = 5;
    const FOUR_RETRIES: u8 = 4;
    const THREE_RETRIES: u8 = 3;
    const INS_GET_DATA: u8 = 0xCB;
    const P1_SELECT_BY_FID: u8 = 0x00;
    const P1_SELECT_BY_AID: u8 = 0x04;
    const INS_INDEX: usize = 1;
    const P1_INDEX: usize = 2;
    const P2_INDEX: usize = 3;
    const HEADER_LEN: usize = 4;
    const DATA_OFFSET: usize = 5;
    const FIRST_CALL_INDEX: usize = 0;
    const SECOND_CALL_INDEX: usize = 1;
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
        selected_esign: bool,
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
                selected_esign: false,
                sent: Vec::new(),
            }
        }

        const fn failing_on(mut self, call_index: usize) -> Self {
            self.fail_on_call = Some(call_index);
            self
        }

        fn sw(status: StatusWord) -> ResponseApdu {
            let [sw1, sw2] = status.as_u16().to_be_bytes();
            ResponseApdu {
                body: Vec::new(),
                sw1,
                sw2,
            }
        }

        fn sw_retries(retries: u8) -> ResponseApdu {
            Self::sw(StatusWord::PinIncorrect {
                retries: PinRetries::from_nibble(retries).expect("valid retry count"),
            })
        }
    }

    impl CardTransport for ScriptedCard {
        type Error = MockError;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let call_index = self.sent.len();
            let apdu = command.as_bytes();
            self.sent.push(apdu.to_vec());
            if self.fail_on_call == Some(call_index) {
                return Err(MockError);
            }
            let ins = apdu.get(INS_INDEX).copied().unwrap_or_default();
            let p1 = apdu.get(P1_INDEX).copied().unwrap_or_default();
            let p2 = apdu.get(P2_INDEX).copied().unwrap_or_default();

            let response = if ins == SelectFile::INS {
                let mf_end = DATA_OFFSET + FileId::MF.as_bytes().len();
                let pkcs15_end = DATA_OFFSET + PKCS15_AID.len();
                let esign_end = DATA_OFFSET + ESIGN_AID.len();
                let selects_pkcs15 =
                    p1 == P1_SELECT_BY_AID && apdu.get(DATA_OFFSET..pkcs15_end) == Some(PKCS15_AID);
                let selects_mf = p1 == P1_SELECT_BY_FID
                    && apdu.get(DATA_OFFSET..mf_end) == Some(FileId::MF.as_bytes());
                if selects_pkcs15 || selects_mf {
                    self.selected_esign = false;
                    Self::sw(StatusWord::Success)
                } else if p1 == P1_SELECT_BY_AID
                    && apdu.get(DATA_OFFSET..esign_end) == Some(ESIGN_AID)
                {
                    self.selected_esign = true;
                    Self::sw(StatusWord::Success)
                } else {
                    Self::sw(StatusWord::FileNotFound)
                }
            } else if ins == VERIFY_INS && apdu.len() == HEADER_LEN {
                match (self.scheme, p2) {
                    (PinReferenceScheme::Citizen, PIN1_REFERENCE)
                    | (PinReferenceScheme::Organizational, PIN1_REFERENCE_ORGANIZATIONAL)
                    | (PinReferenceScheme::Estonian, PIN1_REFERENCE_ESTONIAN) => {
                        Self::sw_retries(self.pin1_retries)
                    }
                    (PinReferenceScheme::Citizen, PIN2_REFERENCE) => {
                        Self::sw_retries(self.pin2_retries)
                    }
                    (PinReferenceScheme::Organizational, PIN2_REFERENCE_ORGANIZATIONAL) => {
                        if self.selected_esign {
                            Self::sw_retries(self.pin2_retries)
                        } else {
                            Self::sw(StatusWord::ReferenceDataNotFound)
                        }
                    }
                    (PinReferenceScheme::Organizational, PUK_REFERENCE_ORGANIZATIONAL) => {
                        Self::sw_retries(self.puk_retries)
                    }
                    (PinReferenceScheme::Citizen, PUK_REFERENCE) => {
                        Self::sw(StatusWord::ReferenceDataNotFound)
                    }
                    _ => Self::sw(StatusWord::ReferenceDataNotFound),
                }
            } else if ins == INS_GET_DATA {
                if self.scheme == PinReferenceScheme::Citizen {
                    let [sw1, sw2] = StatusWord::Success.as_u16().to_be_bytes();
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
                        sw1,
                        sw2,
                    }
                } else {
                    Self::sw(StatusWord::ReferenceDataNotFound)
                }
            } else {
                Self::sw(StatusWord::FileNotFound)
            };

            Ok(TransportOutcome::Response(response))
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err(MockError)
        }
    }

    #[test]
    fn prepare_pin_verify_resolves_organizational_for_pin1_and_enters_esign_for_pin2() {
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
        assert!(!pin1_card.selected_esign);

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
        assert!(
            pin2_card.selected_esign,
            "organizational PIN 2 verify prepare must enter DF.ESIGN before probing PIN 2"
        );
    }

    #[test]
    fn prepare_pin_verify_and_change_reject_estonian_pin2() {
        let mut verify_card = ScriptedCard::new(
            PinReferenceScheme::Estonian,
            THREE_RETRIES,
            THREE_RETRIES,
            THREE_RETRIES,
        );
        assert_eq!(
            prepare_pin_verify(&mut verify_card, PinSlot::Pin2),
            Err(PinPrepareFailure::UnsupportedSlot)
        );
        assert!(!verify_card.sent.iter().any(|apdu| {
            apdu.get(INS_INDEX) == Some(&VERIFY_INS) && apdu.get(P2_INDEX) == Some(&PIN2_REFERENCE)
        }));

        let mut change_card = ScriptedCard::new(
            PinReferenceScheme::Estonian,
            THREE_RETRIES,
            THREE_RETRIES,
            THREE_RETRIES,
        );
        assert_eq!(
            prepare_pin_change(&mut change_card, PinSlot::Pin2),
            Err(PinPrepareFailure::UnsupportedSlot)
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
            card.selected_esign,
            "organizational PIN 2 change prepare must enter DF.ESIGN before probing PIN 2"
        );
        assert!(
            !card.sent.iter().any(|apdu| {
                apdu.get(INS_INDEX) == Some(&VERIFY_INS)
                    && apdu.get(P2_INDEX) == Some(&PIN2_REFERENCE)
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
            PinStatus::Remaining(PinRetries::from_nibble(THREE_RETRIES).expect("valid retries"))
        );
        assert!(
            !org_card
                .sent
                .iter()
                .any(|apdu| apdu.get(INS_INDEX) == Some(&INS_GET_DATA)),
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
            PinStatus::Remaining(PinRetries::from_nibble(THREE_RETRIES).expect("valid retries"))
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
        .failing_on(FIRST_CALL_INDEX);
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
        .failing_on(SECOND_CALL_INDEX);
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
        .failing_on(FIRST_CALL_INDEX);
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
        .failing_on(SECOND_CALL_INDEX);
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
        let last_call = probe_fail_unblock.sent.len() - SECOND_CALL_INDEX;
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
