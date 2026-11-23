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

//! Pure ISO 7816-4 APDU bridging helpers for the Windows minidriver.
//!
//! Kept free of `winscard` FFI so `cargo test` executes every wire-codec
//! test on non-Windows hosts as well as Windows.

use refineid_apdu::{
    ApduClass, CREDENTIAL_BODY_MAX, CommandHeader, CredentialBody, CredentialCommand,
    UnvalidatedCredentialBlock,
};
use refineid_pace::SmError;

/// ISO 7816-4 instruction byte for `VERIFY`.
const INS_VERIFY: u8 = 0x20;
/// ISO 7816-4 instruction byte for `CHANGE REFERENCE DATA`.
const INS_CHANGE_REFERENCE_DATA: u8 = 0x24;
/// ISO 7816-4 instruction byte for `RESET RETRY COUNTER`.
const INS_RESET_RETRY_COUNTER: u8 = 0x2C;

/// Decoded form of a legacy short ISO 7816-4 APDU bridged into `refineid-apdu`.
pub enum BridgedCoreCommand {
    /// Non-credential command routed through `CardTransport::transmit`.
    Plain(refineid_apdu::CommandApdu),
    /// Credential-bearing command routed through `CardTransport::transmit_credential`.
    Credential(CredentialCommand),
}

/// Convert one short ISO 7816 case-4 command into the case-3 command
/// Windows PC/SC accepts for T=0. The card then announces the response
/// with `61xx`, which the transport continues with `GET RESPONSE`.
///
/// Returns `None` for case-1/2/3 commands and extended-length shapes.
pub fn t0_case3_from_short_case4(apdu: &[u8]) -> Option<Vec<u8>> {
    const HEADER_AND_LC_BYTES: usize = 5;
    const TRAILING_LE_BYTES: usize = 1;

    let lc = usize::from(*apdu.get(4)?);
    if lc == 0 {
        return None;
    }
    let case4_len = HEADER_AND_LC_BYTES
        .checked_add(lc)?
        .checked_add(TRAILING_LE_BYTES)?;
    if apdu.len() != case4_len {
        return None;
    }
    Some(apdu[..apdu.len() - 1].to_vec())
}

/// Decode a legacy short-form APDU byte buffer into the typed `refineid-apdu`
/// command required by `refineid_pace::SmTransport`.
///
/// Non-empty data fields on `VERIFY`, `CHANGE REFERENCE DATA`, and
/// `RESET RETRY COUNTER` are always routed through [`CredentialCommand`] so
/// they stay on the zeroizing, single-shot credential transmission path; a
/// credential command whose body exceeds [`CREDENTIAL_BODY_MAX`] or carries
/// a trailing `Le` is rejected instead of downgrading to `Plain`.
pub fn decode_legacy_apdu<E>(bytes: &[u8]) -> Result<BridgedCoreCommand, SmError<E>> {
    const HEADER_LEN: usize = 4;
    const CASE2_LEN: usize = 5;

    let [cla, instruction, p1, p2] = bytes
        .get(..HEADER_LEN)
        .and_then(|slice| <[u8; HEADER_LEN]>::try_from(slice).ok())
        .ok_or(SmError::Malformed("command shorter than 4-byte header"))?;
    let class = match cla {
        b if b == ApduClass::Plain.as_byte() => ApduClass::Plain,
        b if b == ApduClass::ChainedFirst.as_byte() => ApduClass::ChainedFirst,
        b if b == ApduClass::SecureMessaging.as_byte() => ApduClass::SecureMessaging,
        b if b == ApduClass::ChainedSecureMessaging.as_byte() => ApduClass::ChainedSecureMessaging,
        _ => return Err(SmError::Malformed("unsupported APDU class")),
    };
    let header = CommandHeader {
        class,
        instruction,
        p1,
        p2,
    };

    if bytes.len() == HEADER_LEN {
        return Ok(BridgedCoreCommand::Plain(
            refineid_apdu::CommandApdu::case_1(header),
        ));
    }
    if bytes.len() == CASE2_LEN {
        return Ok(BridgedCoreCommand::Plain(
            refineid_apdu::CommandApdu::case_2(header, bytes[HEADER_LEN]),
        ));
    }

    let lc = usize::from(bytes[HEADER_LEN]);
    if lc == 0 {
        return Err(SmError::Malformed("extended-length APDU unsupported"));
    }
    let case3_len = CASE2_LEN
        .checked_add(lc)
        .ok_or(SmError::Malformed("APDU length overflow"))?;
    let case4_len = case3_len
        .checked_add(1)
        .ok_or(SmError::Malformed("APDU length overflow"))?;
    let data = bytes
        .get(CASE2_LEN..case3_len)
        .ok_or(SmError::Malformed("APDU truncated"))?;
    let is_credential_ins = matches!(
        instruction,
        INS_VERIFY | INS_CHANGE_REFERENCE_DATA | INS_RESET_RETRY_COUNTER
    );

    if bytes.len() == case3_len {
        if is_credential_ins {
            if data.len() > CREDENTIAL_BODY_MAX {
                return Err(SmError::Malformed("credential body exceeds maximum length"));
            }
            let mut block = UnvalidatedCredentialBlock::zeroed();
            block.buffer()[..data.len()].copy_from_slice(data);
            block.set_filled(data.len());
            let body = CredentialBody::from_block(block)
                .map_err(|_error| SmError::Malformed("credential body invalid"))?;
            return Ok(BridgedCoreCommand::Credential(CredentialCommand::assemble(
                header, body,
            )));
        }
        let command = refineid_apdu::CommandApdu::case_3(header, data)
            .map_err(|_error| SmError::Malformed("case-3 command data invalid"))?;
        return Ok(BridgedCoreCommand::Plain(command));
    }
    if bytes.len() == case4_len {
        if is_credential_ins {
            return Err(SmError::Malformed(
                "credential command must not carry trailing Le",
            ));
        }
        let le = bytes[case3_len];
        let command = refineid_apdu::CommandApdu::case_4(header, data, le)
            .map_err(|_error| SmError::Malformed("case-4 command data invalid"))?;
        return Ok(BridgedCoreCommand::Plain(command));
    }

    Err(SmError::Malformed("APDU does not match short-form case"))
}

#[cfg(test)]
mod tests {
    use refineid_apdu::CREDENTIAL_BODY_MAX;
    use refineid_pace::SmError;

    use super::{
        BridgedCoreCommand, INS_CHANGE_REFERENCE_DATA, INS_RESET_RETRY_COUNTER, INS_VERIFY,
        decode_legacy_apdu, t0_case3_from_short_case4,
    };

    #[test]
    fn t0_short_case4_strips_trailing_le_and_leaves_other_cases_unchanged() {
        // Short case 4 (Lc = 2, 2 data bytes, trailing Le = 0x00) -> strip Le.
        assert_eq!(
            t0_case3_from_short_case4(&[0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00, 0x00]),
            Some(vec![0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00])
        );
        // Short case 3 (no trailing Le) -> unchanged.
        assert_eq!(
            t0_case3_from_short_case4(&[0x00, 0x20, 0x00, 0x11, 0x04, 0x31, 0x32, 0x33, 0x34]),
            None
        );
        // Case 2 (5 bytes) -> unchanged.
        assert_eq!(
            t0_case3_from_short_case4(&[0x00, 0xB0, 0x00, 0x00, 0x80]),
            None
        );
        // Case 1 (4 bytes) -> unchanged.
        assert_eq!(t0_case3_from_short_case4(&[0x00, 0x20, 0x00, 0x11]), None);
        // Extended-length shape (Lc byte = 0x00) -> unchanged.
        assert_eq!(
            t0_case3_from_short_case4(&[0x00, 0x2A, 0x9E, 0x9A, 0x00, 0x00, 0x02, 0xAA, 0xBB]),
            None
        );
    }

    #[test]
    fn decode_preserves_plain_case_1_2_3_and_4_wire_bytes() {
        let cases: &[&[u8]] = &[
            &[0x00, 0x20, 0x00, 0x11],
            &[0x00, 0x20, 0x00, 0x11, 0x00],
            &[0x00, 0xB0, 0x00, 0x00, 0x80],
            &[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00],
            &[0x10, 0x2A, 0x80, 0x86, 0x03, 0x00, 0xAA, 0xBB],
            &[0x00, 0x2A, 0x80, 0x86, 0x02, 0xCC, 0xDD, 0x00],
            &[0x0C, 0xB0, 0x00, 0x00, 0x10],
            &[0x1C, 0x2A, 0x80, 0x86, 0x02, 0xAA, 0xBB],
        ];
        for wire in cases {
            let decoded = decode_legacy_apdu::<()>(wire).expect("valid short APDU decodes");
            match decoded {
                BridgedCoreCommand::Plain(cmd) => assert_eq!(cmd.as_bytes(), *wire),
                BridgedCoreCommand::Credential(_) => {
                    panic!("expected Plain command for non-credential APDU {wire:02X?}")
                }
            }
        }
    }

    #[test]
    fn decode_routes_credential_case_3_commands_through_credential_path() {
        for ins in [
            INS_VERIFY,
            INS_CHANGE_REFERENCE_DATA,
            INS_RESET_RETRY_COUNTER,
        ] {
            let wire = [0x00, ins, 0x00, 0x11, 0x04, 0x31, 0x32, 0x33, 0x34];
            let decoded = decode_legacy_apdu::<()>(&wire).expect("credential APDU decodes");
            match decoded {
                BridgedCoreCommand::Credential(cmd) => {
                    cmd.expose_wire(|exposed| assert_eq!(exposed, wire));
                }
                BridgedCoreCommand::Plain(_) => {
                    panic!("expected Credential command for INS {ins:#04X}")
                }
            }
        }
    }

    #[test]
    fn decode_rejects_malformed_unsupported_or_oversized_credential_apdus() {
        // Shorter than 4-byte header.
        assert!(matches!(
            decode_legacy_apdu::<()>(&[0x00, 0xA4, 0x00]),
            Err(SmError::Malformed(_))
        ));
        // Unsupported CLA byte.
        assert!(matches!(
            decode_legacy_apdu::<()>(&[0x80, 0xCA, 0x01, 0x00]),
            Err(SmError::Malformed(_))
        ));
        // Extended-length encoding (Lc = 0).
        assert!(matches!(
            decode_legacy_apdu::<()>(&[0x00, 0x2A, 0x9E, 0x9A, 0x00, 0x00, 0x02, 0xAA, 0xBB]),
            Err(SmError::Malformed(_))
        ));
        // Truncated body.
        assert!(matches!(
            decode_legacy_apdu::<()>(&[0x00, 0xA4, 0x00, 0x0C, 0x04, 0x3F, 0x00]),
            Err(SmError::Malformed(_))
        ));
        // Extra trailing bytes past Le.
        assert!(matches!(
            decode_legacy_apdu::<()>(&[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00, 0x00, 0xFF]),
            Err(SmError::Malformed(_))
        ));
        // Oversized credential body must fail closed instead of downgrading to Plain.
        let mut oversized_verify = vec![
            0x00,
            INS_VERIFY,
            0x00,
            0x11,
            u8::try_from(CREDENTIAL_BODY_MAX + 1).expect("fits u8"),
        ];
        oversized_verify.resize(oversized_verify.len() + CREDENTIAL_BODY_MAX + 1, b'1');
        assert!(matches!(
            decode_legacy_apdu::<()>(&oversized_verify),
            Err(SmError::Malformed(_))
        ));
        // Case-4 credential command must fail closed instead of downgrading to Plain.
        assert!(matches!(
            decode_legacy_apdu::<()>(&[
                0x00, INS_VERIFY, 0x00, 0x11, 0x04, 0x31, 0x32, 0x33, 0x34, 0x00
            ]),
            Err(SmError::Malformed(_))
        ));
    }
}
