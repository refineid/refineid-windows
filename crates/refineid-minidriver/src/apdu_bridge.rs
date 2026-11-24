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

//! Pure ISO 7816-4 T=0 APDU wire helpers for the Windows minidriver.
//!
//! Kept free of `winscard` FFI so `cargo test` executes every wire-codec
//! test on non-Windows hosts as well as Windows.

/// Byte index of the short-form `Lc` octet in an ISO 7816-4 command APDU.
const SHORT_LC_INDEX: usize = 4;
/// Byte count of the 4-byte APDU header plus the 1-byte short-form `Lc`.
const HEADER_AND_LC_BYTES: usize = 5;
/// Byte count of the trailing short-form `Le` octet in a case-4 command.
const TRAILING_LE_BYTES: usize = 1;

/// Convert one short ISO 7816 case-4 command into the case-3 command
/// Windows PC/SC accepts for T=0. The card then announces the response
/// with `61xx`, which the transport continues with `GET RESPONSE`.
///
/// Returns `None` for case-1/2/3 commands and extended-length shapes.
pub fn t0_case3_from_short_case4(apdu: &[u8]) -> Option<Vec<u8>> {
    let lc = usize::from(*apdu.get(SHORT_LC_INDEX)?);
    if lc == 0 {
        return None;
    }
    let case4_len = HEADER_AND_LC_BYTES
        .checked_add(lc)?
        .checked_add(TRAILING_LE_BYTES)?;
    if apdu.len() != case4_len {
        return None;
    }
    Some(apdu[..apdu.len() - TRAILING_LE_BYTES].to_vec())
}

#[cfg(test)]
mod tests {
    use refineid_apdu::iso7816::{SelectFile, SelectFileResponseMode, SelectFileTarget};
    use refineid_apdu::{ApduClass, CommandApdu, CommandHeader, FileId};
    use refineid_auth::verify::{PIN1_REFERENCE, VERIFY_INS, VERIFY_P1};
    use refineid_sign::commands::{PSO_CDS_P1, PSO_INS};

    use super::{TRAILING_LE_BYTES, t0_case3_from_short_case4};

    /// ISO 7816-4 `SELECT` P1 for selection by DF name (AID).
    const SELECT_BY_NAME_P1: u8 = 0x04;
    /// ISO 7816-4 `SELECT` P2 requesting FCI return.
    const SELECT_RETURN_FCI_P2: u8 = 0x00;
    /// Short-form maximum `Le` requesting the full short-response window.
    const SHORT_LE_MAX: u8 = 0x00;
    /// ISO 7816-4 `READ BINARY` instruction byte.
    const INS_READ_BINARY: u8 = 0xB0;
    /// Expected read length for the `READ BINARY` case-2 fixture.
    const READ_CHUNK_LEN: u8 = 0x80;
    /// Zero offset byte for the `READ BINARY` case-2 fixture.
    const READ_OFFSET_ZERO: u8 = 0x00;
    /// Synthetic case-3 `VERIFY` payload used purely to check APDU framing.
    const SAMPLE_VERIFY_PAYLOAD: &[u8] = b"1234";
    /// ISO 7816-4 `PSO:COMPUTE DIGITAL SIGNATURE` P2 for the extended fixture.
    const PSO_CDS_P2: u8 = 0x9A;
    /// Extended-length zero marker byte.
    const EXTENDED_LC_MARKER: u8 = 0x00;
    /// High byte of a 2-byte extended-length `Lc`.
    const EXTENDED_LC_HI: u8 = 0x00;
    /// Low byte of a 2-byte extended-length `Lc`.
    const EXTENDED_LC_LO: u8 = 0x02;
    /// Synthetic first payload byte for the extended-length fixture.
    const SAMPLE_EXT_BYTE_A: u8 = 0xAA;
    /// Synthetic second payload byte for the extended-length fixture.
    const SAMPLE_EXT_BYTE_B: u8 = 0xBB;

    #[test]
    fn t0_short_case4_strips_trailing_le_and_leaves_other_cases_unchanged() {
        let case4 = CommandApdu::case_4(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: SelectFile::INS,
                p1: SELECT_BY_NAME_P1,
                p2: SELECT_RETURN_FCI_P2,
            },
            FileId::MF.as_bytes(),
            SHORT_LE_MAX,
        )
        .expect("case-4 fixture encodes");
        let case4_bytes = case4.as_bytes();
        assert_eq!(
            t0_case3_from_short_case4(case4_bytes),
            Some(case4_bytes[..case4_bytes.len() - TRAILING_LE_BYTES].to_vec())
        );

        let case3 = CommandApdu::case_3(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: VERIFY_INS,
                p1: VERIFY_P1,
                p2: PIN1_REFERENCE,
            },
            SAMPLE_VERIFY_PAYLOAD,
        )
        .expect("case-3 fixture encodes");
        assert_eq!(t0_case3_from_short_case4(case3.as_bytes()), None);

        let case2 = CommandApdu::case_2(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: INS_READ_BINARY,
                p1: READ_OFFSET_ZERO,
                p2: READ_OFFSET_ZERO,
            },
            READ_CHUNK_LEN,
        );
        assert_eq!(t0_case3_from_short_case4(case2.as_bytes()), None);

        let case1 = CommandApdu::case_1(CommandHeader {
            class: ApduClass::Plain,
            instruction: VERIFY_INS,
            p1: VERIFY_P1,
            p2: PIN1_REFERENCE,
        });
        assert_eq!(t0_case3_from_short_case4(case1.as_bytes()), None);

        let select_mf = SelectFile {
            class: ApduClass::Plain,
            target: SelectFileTarget::AnyByFileId(Some(FileId::MF)),
            response_mode: SelectFileResponseMode::None,
        }
        .into_apdu();
        assert_eq!(t0_case3_from_short_case4(select_mf.as_bytes()), None);

        let extended = [
            ApduClass::Plain.as_byte(),
            PSO_INS,
            PSO_CDS_P1,
            PSO_CDS_P2,
            EXTENDED_LC_MARKER,
            EXTENDED_LC_HI,
            EXTENDED_LC_LO,
            SAMPLE_EXT_BYTE_A,
            SAMPLE_EXT_BYTE_B,
        ];
        assert_eq!(t0_case3_from_short_case4(&extended), None);
    }
}
