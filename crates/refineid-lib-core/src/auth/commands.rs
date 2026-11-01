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

//! Typed APDU commands for the auth (PIN / PUK) module.
//!
//! Every byte sequence crossing the card boundary has a protocol
//! role ([refinement types]), so each PIN-related
//! command refineid issues has its own struct here.
//! `into_apdu(self) -> CommandApdu` does the byte serialisation
//! at the transport boundary; before that point everything is
//! typed values.
//!
//! All four commands share the ISO 7816-4 §7.5 PIN-management
//! shape `CLA INS P1 P2 Lc <data>`. P2 always comes from a
//! [`CredentialReference`] (the credential under the card's
//! numbering); Lc and `data` are filled by each command's role.
//!
//! [refinement types]: https://github.com/refineid/refineid-core/blob/main/doc/architecture/refinement-types.md

use crate::apdu::iso7816::ApduClass;
use crate::apdu::status_word::PinRetries;
use crate::auth::{
    CredentialPolicyCounters, CredentialReference, PUK_REFERENCE_PKCS15, PinReferenceScheme,
    PinSlot, UnblockingCounter, UsageCounter,
};
use crate::transport::CommandApdu;

/// FINEID S1 v4.2 §3.5.2 VERIFY P1 selector.
///
/// `Verify` (`00h`) compares the supplied PIN against the
/// reference PIN; on success, sets the PIN validated flag.
/// `Unverify` (`FFh`) clears the PIN validated flag (per
/// §3.5 "In 'Unverify' Mode": "a successful execution of the
/// command sets the reference PIN to 'unverified'").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyMode {
    /// `P1=00h` -- verify mode.
    Verify,
    /// `P1=FFh` -- unverify mode (clears PIN-validated flag).
    Unverify,
}

impl VerifyMode {
    /// P1 wire byte per §3.5.2.
    #[must_use]
    pub const fn as_p1(self) -> u8 {
        match self {
            Self::Verify => 0x00,
            Self::Unverify => 0xFF,
        }
    }
}

/// VERIFY data field per FINEID S1 v4.2 §3.5.2.
///
/// Two roles distinguished by Lc presence:
///
/// - [`VerifyData::Probe`]: `Lc` empty. Per §3.5.1.1: "Sending
///   the command with Lc = 00h has a special meaning. It
///   enables you to know if the PIN has already been
///   successfully presented during the current session." The
///   card returns 9000h (already verified) or 63CXh (X
///   attempts remaining). The retry counter is NOT decremented.
/// - [`VerifyData::PinBlock`]: the padded PIN bytes (right-
///   padded to the slot's stored length per ISO/IEC 7816-15).
///   The card compares against the reference PIN; success or
///   failure mutates the retry counter per §3.5.
#[derive(Debug, Clone)]
pub enum VerifyData {
    /// `Lc=00h` -- counter-safe status probe (no PIN bytes).
    Probe,
    /// PIN block, right-padded to the slot's stored length.
    /// `Vec<u8>` is a Tier 0 byte container; a tighter form is
    /// a `PaddedPinBlock<const N: usize>` newtype queued for
    /// future typing work (FINEID S4-1 v3.1 stores PINs at 12
    /// bytes; refineid validates the unpadded length before
    /// constructing this).
    PinBlock(Vec<u8>),
}

/// FINEID S1 v4.2 §3.5 VERIFY: authenticate a user by
/// comparing the supplied PIN against the reference PIN.
///
/// Wire shape per §3.5.2:
/// `CLA 20 <P1> <P2> [Lc <Data>]`. No Le.
///
/// Each field has a specific spec-defined meaning:
///
/// - `CLA`: [`ApduClass`] -- plain (`00h`) or secure messaging
///   (`0Ch`).
/// - `INS`: fixed at `20h`.
/// - `P1`: [`VerifyMode`] -- Verify (`00h`) or Unverify (`FFh`).
/// - `P2`: credential reference under the card's numbering, via
///   [`CredentialReference::as_byte`].
/// - `Lc` + `Data`: see [`VerifyData`].
/// - `Le`: empty.
///
/// Status word semantics per §3.5.3 are documented inline;
/// the typed response parser (next commit) classifies them
/// into the `VerifyOutcome` enum.
#[derive(Debug, Clone)]
pub struct Verify {
    /// CLA byte.
    pub class: ApduClass,
    /// P1 selector: Verify vs Unverify.
    pub mode: VerifyMode,
    /// P2 selector: which credential.
    pub reference: CredentialReference,
    /// Lc + Data: empty (probe) or the credential block.
    pub data: VerifyData,
}

impl Verify {
    /// INS byte per §3.5.2.
    pub const INS: u8 = 0x20;

    /// Serialise into the wire APDU per §3.5.2.
    ///
    /// 4-byte header (`CLA INS P1 P2`) plus either:
    /// - `Lc=00` byte alone (probe form per §3.5.1.1), or
    /// - `Lc=<len> <pin bytes>` (normal verify).
    ///
    /// No Le byte (response is status-only).
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        let pin_bytes: &[u8] = match &self.data {
            VerifyData::Probe => &[],
            VerifyData::PinBlock(bytes) => bytes,
        };
        // PinSlot.stored_length() caps PIN length at 12 bytes
        // (FINEID-S4-1 v3.1); Lc fits in u8 within FINEID's
        // short-form APDU range. The Err arm is the same
        // precondition the spec invariant guarantees.
        let Ok(lc) = u8::try_from(pin_bytes.len()) else {
            unreachable!("VERIFY PIN block exceeds short-form Lc")
        };
        let mut out = Vec::with_capacity(pin_bytes.len().saturating_add(5));
        out.push(self.class.as_byte());
        out.push(Self::INS);
        out.push(self.mode.as_p1());
        out.push(self.reference.as_byte());
        // §3.5.1.1: Lc=00h with no Data is the probe form. We
        // always emit Lc (00 for probe, len for PinBlock) so
        // the wire is a valid short APDU.
        out.push(lc);
        out.extend_from_slice(pin_bytes);
        CommandApdu::new(out)
    }
}

/// ISO 7816-4 `CHANGE REFERENCE DATA` (`INS=0x24 P1=0x00`)
/// with the current and new credential blocks concatenated.
#[derive(Debug, Clone)]
pub struct ChangeReferenceData {
    /// Which PIN the change targets, under the card's numbering.
    pub reference: CredentialReference,
    /// Concatenation `current_block || new_block`.
    pub padded_pair: Vec<u8>,
}

impl ChangeReferenceData {
    /// ISO 7816-4 class byte `0x00`.
    pub const CLA: u8 = 0x00;
    /// ISO 7816-4 `CHANGE REFERENCE DATA` instruction.
    pub const INS: u8 = 0x24;
    /// P1: replace mode (`0x00`; old + new both present).
    pub const P1: u8 = 0x00;

    /// Serialise into the wire APDU
    /// (`00 24 00 <p2> <lc> <current_padded><new_padded>`).
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        // padded_pair = current_block || new_block, each
        // bounded by PinSlot::stored_length() = 12; total 24
        // bytes fits in u8 by the spec invariant.
        let Ok(lc) = u8::try_from(self.padded_pair.len()) else {
            unreachable!("CHANGE REFERENCE DATA padded_pair exceeds short-form Lc")
        };
        let mut out = Vec::with_capacity(self.padded_pair.len().saturating_add(5));
        out.extend_from_slice(&[Self::CLA, Self::INS, Self::P1, self.reference.as_byte(), lc]);
        out.extend_from_slice(&self.padded_pair);
        CommandApdu::new(out)
    }
}

/// FINEID S1 v4.2 §3.15 `GET DATA` for PIN information.
///
/// Wire shape per §3.15.2 / Table 16 (PIN Container):
/// `00 CB 00 FF 05 A0 03 83 01 <slot_ref> 00`.
///
/// - `CLA`: `0x00` (no secure messaging).
/// - `INS`: `0xCB` (`GET DATA`).
/// - `P1 P2`: `0x00 0xFF` (PIN-info template selector).
/// - `Lc`: `0x05` (length of the constructed PIN-Container TLV).
/// - `Data`: `A0 03 83 01 <slot_ref>` where `<slot_ref>` is the
///   PIN's reference byte under the card's numbering
///   ([`CredentialReference::as_byte`]).
/// - `Le`: `0x00` (return all bytes -- per §3.15.2 example
///   patterns).
///
/// Side effects: **none**. This is a counter-safe probe; neither
/// the PIN try counter nor the PIN usage counter is decremented.
/// Mirrors the `VERIFY Lc=0` probe used by `pin_status`.
///
/// The response is a TLV blob per Table 19 -- parse with
/// `PinInfoResponse::changed_flag_from_response_body` to
/// extract the "PIN changed" flag (`DF 2F 01 xx`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetPinInfo {
    /// The card's credential numbering.
    pub scheme: PinReferenceScheme,
    /// Which PIN slot to query.
    pub slot: PinSlot,
}

/// Closed set of FINEID PIN-container references used by `GET DATA`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinInfoReference {
    /// User PIN1 or PIN2 under the card's numbering.
    User(PinReferenceScheme, PinSlot),
    /// Shared recovery PUK.
    Puk,
}

impl PinInfoReference {
    /// Encode the typed reference at the APDU boundary.
    const fn as_byte(self) -> u8 {
        match self {
            Self::User(scheme, slot) => CredentialReference::Pin(scheme, slot).as_byte(),
            Self::Puk => PUK_REFERENCE_PKCS15,
        }
    }
}

impl GetPinInfo {
    /// CLA byte per §3.15.2.
    pub const CLA: u8 = 0x00;
    /// INS byte per §3.15.2 (`GET DATA`).
    pub const INS: u8 = 0xCB;
    /// P1 byte per §3.15.2.
    pub const P1: u8 = 0x00;
    /// P2 byte per §3.15.2.
    pub const P2: u8 = 0xFF;
    /// Lc byte: the constructed PIN-Container template is fixed
    /// at 5 bytes (`A0 03 83 01 <slot_ref>`).
    pub const LC: u8 = 0x05;

    /// Serialise into the wire APDU
    /// (`00 CB 00 FF 05 A0 03 83 01 <slot_ref> 00`).
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        Self::for_reference(PinInfoReference::User(self.scheme, self.slot))
    }

    /// Build the fixed PIN-container query for a validated FINEID
    /// PIN-family reference.
    fn for_reference(reference: PinInfoReference) -> CommandApdu {
        CommandApdu::new(vec![
            Self::CLA,
            Self::INS,
            Self::P1,
            Self::P2,
            Self::LC,
            0xA0,
            0x03,
            0x83,
            0x01,
            reference.as_byte(),
            0x00,
        ])
    }
}

/// Counter-safe FINEID `GET DATA` query for the shared PUK object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetPukInfo;

impl GetPukInfo {
    /// Serialise the S1 v4.2 section 3.15 PIN-container request for
    /// the shared local PUK reference.
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        GetPinInfo::for_reference(PinInfoReference::Puk)
    }
}

/// Helper for parsing the [`GetPinInfo`] response body per
/// FINEID S1 v4.2 §3.15.3 Table 19.
///
/// Hosted on a unit struct (no free
/// functions with borrowed parameters). The
/// struct and its method are `pub(crate)` because the body slice
/// boundary makes it a raw-bytes parser -- per typing-discipline
/// Rule B the public surface uses
/// [`PinOps::pin_changed_flag`](crate::auth::PinOps) instead,
/// which takes a typed transport receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinInfoResponse;

impl PinInfoResponse {
    /// Extract the "PIN changed" flag (`DFh 2Fh 01h <value>`)
    /// from a GET DATA PIN-Container response body.
    ///
    /// Returns `Some(true)` if the flag is `01h` (PIN has been
    /// changed at least once since manufacture), `Some(false)`
    /// if `00h` (PIN still at factory value), or `None` if the
    /// response body did not contain a DF2F TLV.
    ///
    /// The body is searched for the four-byte slice `DF 2F 01 ??`
    /// using [`slice::windows`]. No BER-TLV recursion is needed --
    /// the FINEID PIN Container is flat, the DF2F element is at
    /// the outermost level after the `A0` template, and other
    /// elements either have fixed lengths or use single-byte
    /// length encoding so a sliding four-byte tag-length-value
    /// match is unambiguous against the response shape.
    #[must_use]
    pub(crate) fn changed_flag_from_response_body(body: &[u8]) -> Option<bool> {
        // The card signals the PIN-change outcome in a proprietary
        // DO: tag DF2F, length 1, value 1 = "changed".
        const CHANGED_DO_TAG_HI: u8 = 0xDF;
        const CHANGED_DO_TAG_LO: u8 = 0x2F;
        const CHANGED_DO_LEN: u8 = 1;
        const CHANGED_TRUE: u8 = 1;
        body.windows(4).find_map(|w| match w {
            [CHANGED_DO_TAG_HI, CHANGED_DO_TAG_LO, CHANGED_DO_LEN, value] => {
                Some(*value == CHANGED_TRUE)
            }
            _ => None,
        })
    }

    /// Extract the first byte of `DF 21 04`, the remaining try
    /// counter from the FINEID PIN-attributes object.
    #[must_use]
    pub(crate) fn try_counter_from_response_body(body: &[u8]) -> Option<PinRetries> {
        const ATTRIBUTES_TAG_HI: u8 = 0xDF;
        const ATTRIBUTES_TAG_LO: u8 = 0x21;
        const ATTRIBUTES_LENGTH: u8 = 0x04;
        const ATTRIBUTE_TLV_LENGTH: usize = 7;

        body.windows(ATTRIBUTE_TLV_LENGTH)
            .find_map(|window| match window {
                [
                    ATTRIBUTES_TAG_HI,
                    ATTRIBUTES_TAG_LO,
                    ATTRIBUTES_LENGTH,
                    tries,
                    _,
                    _,
                    _,
                ] => PinRetries::from_nibble(*tries),
                _ => None,
            })
    }

    /// Extract the length range of the PIN policy (`DF 3F 14`, FINEID S1
    /// v4.2 §3.15.3 Table 19): its second octet is the minimum length and
    /// its third the maximum, each within 4 to 64. `None` when the body
    /// carries no policy, or its lengths fall outside that range or
    /// admit nothing.
    #[must_use]
    pub(crate) fn policy_lengths_from_response_body(
        body: &[u8],
    ) -> Option<refineid_pkcs15::PasswordLengthRange> {
        const POLICY_TAG_HI: u8 = 0xDF;
        const POLICY_TAG_LO: u8 = 0x3F;
        const POLICY_LENGTH: u8 = 20;
        const POLICY_HEADER_LENGTH: usize = 3;
        const POLICY_TLV_LENGTH: usize = POLICY_HEADER_LENGTH + POLICY_LENGTH as usize;
        const LENGTH_FLOOR: u8 = 4;
        const LENGTH_CEILING: u8 = 64;

        let in_range = |length: u8| (LENGTH_FLOOR..=LENGTH_CEILING).contains(&length);
        body.windows(POLICY_TLV_LENGTH).find_map(|window| {
            let [
                POLICY_TAG_HI,
                POLICY_TAG_LO,
                POLICY_LENGTH,
                _tries,
                min,
                max,
                ..,
            ] = window
            else {
                return None;
            };
            if !in_range(*min) || !in_range(*max) {
                return None;
            }
            refineid_pkcs15::PasswordLengthRange::new(*min, *max)
        })
    }

    /// Extract the usage and unblocking allowances from `DF 21 04`.
    #[must_use]
    pub(crate) fn policy_counters_from_response_body(
        body: &[u8],
    ) -> Option<CredentialPolicyCounters> {
        const ATTRIBUTES_TAG_HI: u8 = 0xDF;
        const ATTRIBUTES_TAG_LO: u8 = 0x21;
        const ATTRIBUTES_LENGTH: u8 = 0x04;
        const ATTRIBUTE_TLV_LENGTH: usize = 7;
        const USAGE_NO_LIMIT: u8 = u8::MAX;
        const UNBLOCKING_NO_LIMIT: u8 = 0xA5;
        const UNBLOCKING_FINITE_MAX: u8 = 0x0F;

        body.windows(ATTRIBUTE_TLV_LENGTH).find_map(|window| {
            let [
                ATTRIBUTES_TAG_HI,
                ATTRIBUTES_TAG_LO,
                ATTRIBUTES_LENGTH,
                _,
                usage,
                unblocking,
                _,
            ] = window
            else {
                return None;
            };
            let usage = match *usage {
                0 => UsageCounter::Exhausted,
                USAGE_NO_LIMIT => UsageCounter::NoLimit,
                finite => UsageCounter::Limited(std::num::NonZeroU8::new(finite)?),
            };
            let unblocking = match *unblocking {
                0 => UnblockingCounter::Exhausted,
                UNBLOCKING_NO_LIMIT => UnblockingCounter::NoLimit,
                finite if finite <= UNBLOCKING_FINITE_MAX => {
                    UnblockingCounter::Limited(std::num::NonZeroU8::new(finite)?)
                }
                _ => return None,
            };
            Some(CredentialPolicyCounters { usage, unblocking })
        })
    }
}

/// What the `RESET RETRY COUNTER` data field carries (ISO 7816-4
/// §7.5.10 P1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetRetryCounterMode {
    /// The unblocking code followed by the new reference data: the
    /// citizen card's single-command form.
    CodeThenNew,
    /// Only the new reference data; the PUK was verified as its own
    /// object first. The organization card's second command (FINEID
    /// S4-2 v4.0 §4.3.2).
    NewOnly,
}

impl ResetRetryCounterMode {
    /// P1 for the unblocking code followed by the new reference data.
    const P1_CODE_THEN_NEW: u8 = 0x00;
    /// P1 for the new reference data alone.
    const P1_NEW_ONLY: u8 = 0x02;

    /// Encode the mode as the P1 byte.
    #[must_use]
    pub const fn as_p1(self) -> u8 {
        match self {
            Self::CodeThenNew => Self::P1_CODE_THEN_NEW,
            Self::NewOnly => Self::P1_NEW_ONLY,
        }
    }
}

/// ISO 7816-4 `RESET RETRY COUNTER` (`INS=0x2C`) with the PUK and
/// the new PIN, or the new PIN alone.
#[derive(Debug, Clone)]
pub struct ResetRetryCounter {
    /// Which PIN the unblock targets, under the card's numbering (the
    /// new PIN value replaces this PIN's stored value).
    pub target: CredentialReference,
    /// What the data field carries.
    pub mode: ResetRetryCounterMode,
    /// The data field: `puk_block || new_pin_block`, or
    /// `new_pin_block` alone.
    pub padded_pair: Vec<u8>,
}

impl ResetRetryCounter {
    /// ISO 7816-4 class byte `0x00`.
    pub const CLA: u8 = 0x00;
    /// ISO 7816-4 `RESET RETRY COUNTER` instruction.
    pub const INS: u8 = 0x2C;

    /// Serialise into the wire APDU
    /// (`00 2C <p1> <p2> <lc> <data>`).
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        // The data field is at most puk_block (12) || new_pin_block (12)
        // = 24 bytes; fits in u8 by the FINEID stored-length invariant.
        let Ok(lc) = u8::try_from(self.padded_pair.len()) else {
            unreachable!("RESET RETRY COUNTER padded_pair exceeds short-form Lc")
        };
        let mut out = Vec::with_capacity(self.padded_pair.len().saturating_add(5));
        out.extend_from_slice(&[
            Self::CLA,
            Self::INS,
            self.mode.as_p1(),
            self.target.as_byte(),
            lc,
        ]);
        out.extend_from_slice(&self.padded_pair);
        CommandApdu::new(out)
    }
}

#[cfg(test)]
mod tests {

    use super::{GetPinInfo, GetPukInfo, PinInfoResponse, PinReferenceScheme, PinSlot};
    use crate::apdu::status_word::PinRetries;

    #[test]
    fn get_puk_info_apdu_wire_shape() {
        const PLAIN_CLASS: u8 = 0x00;
        const GET_DATA_INSTRUCTION: u8 = 0xCB;
        const GET_DATA_P1: u8 = 0x00;
        const GET_DATA_P2: u8 = 0xFF;
        const TEMPLATE_LENGTH: u8 = 0x05;
        const TEMPLATE_TAG: u8 = 0xA0;
        const TEMPLATE_VALUE_LENGTH: u8 = 0x03;
        const REFERENCE_TAG: u8 = 0x83;
        const REFERENCE_LENGTH: u8 = 0x01;
        const PUK_REFERENCE: u8 = 0x83;
        const MAX_RESPONSE_LENGTH: u8 = 0x00;

        let bytes = GetPukInfo.into_apdu().into_bytes();
        assert_eq!(
            bytes,
            vec![
                PLAIN_CLASS,
                GET_DATA_INSTRUCTION,
                GET_DATA_P1,
                GET_DATA_P2,
                TEMPLATE_LENGTH,
                TEMPLATE_TAG,
                TEMPLATE_VALUE_LENGTH,
                REFERENCE_TAG,
                REFERENCE_LENGTH,
                PUK_REFERENCE,
                MAX_RESPONSE_LENGTH,
            ]
        );
    }

    /// A PIN container carrying a PIN policy of `min` to `max` digits.
    fn container_with_policy(min: u8, max: u8) -> Vec<u8> {
        const POLICY_TAG_HI: u8 = 0xDF;
        const POLICY_TAG_LO: u8 = 0x3F;
        const POLICY_LENGTH: u8 = 20;
        const TRY_LIMIT: u8 = 5;
        const FILLER: u8 = 0;
        let mut body = vec![
            POLICY_TAG_HI,
            POLICY_TAG_LO,
            POLICY_LENGTH,
            TRY_LIMIT,
            min,
            max,
        ];
        body.resize(body.len() + usize::from(POLICY_LENGTH) - 3, FILLER);
        body
    }

    #[test]
    fn pin_info_extracts_policy_lengths() {
        const FOUR: u8 = 4;
        const EIGHT: u8 = 8;
        let range =
            PinInfoResponse::policy_lengths_from_response_body(&container_with_policy(FOUR, EIGHT))
                .expect("a policy range");
        assert_eq!(range.min(), usize::from(FOUR));
        assert_eq!(range.max(), usize::from(EIGHT));
    }

    #[test]
    fn pin_info_refuses_policy_lengths_outside_the_specified_range() {
        const THREE: u8 = 3;
        const EIGHT: u8 = 8;
        const SIXTY_FIVE: u8 = 65;
        assert_eq!(
            PinInfoResponse::policy_lengths_from_response_body(&container_with_policy(
                THREE, EIGHT
            )),
            None
        );
        assert_eq!(
            PinInfoResponse::policy_lengths_from_response_body(&container_with_policy(
                EIGHT, SIXTY_FIVE
            )),
            None
        );
    }

    #[test]
    fn pin_info_extracts_try_counter() {
        const PIN_ATTRIBUTES: [u8; 7] = [0xDF, 0x21, 0x04, 0x05, 0xFF, 0x00, 0x00];
        let five = PinRetries::from_nibble(5).expect("valid retry nibble");
        assert_eq!(
            PinInfoResponse::try_counter_from_response_body(&PIN_ATTRIBUTES),
            Some(five)
        );
    }

    #[test]
    fn pin_info_extracts_no_limit_policy_counters() {
        use crate::auth::{CredentialPolicyCounters, UnblockingCounter, UsageCounter};

        const ATTRIBUTES_TAG_HI: u8 = 0xDF;
        const ATTRIBUTES_TAG_LO: u8 = 0x21;
        const ATTRIBUTES_LENGTH: u8 = 0x04;
        const FIVE_TRIES: u8 = 5;
        const USAGE_NO_LIMIT: u8 = u8::MAX;
        const UNBLOCKING_NO_LIMIT: u8 = 0xA5;
        const PUK_METHOD: u8 = 0x83;
        const PIN_ATTRIBUTES: [u8; 7] = [
            ATTRIBUTES_TAG_HI,
            ATTRIBUTES_TAG_LO,
            ATTRIBUTES_LENGTH,
            FIVE_TRIES,
            USAGE_NO_LIMIT,
            UNBLOCKING_NO_LIMIT,
            PUK_METHOD,
        ];

        assert_eq!(
            PinInfoResponse::policy_counters_from_response_body(&PIN_ATTRIBUTES),
            Some(CredentialPolicyCounters {
                usage: UsageCounter::NoLimit,
                unblocking: UnblockingCounter::NoLimit,
            })
        );
    }

    #[test]
    fn pin_info_rejects_invalid_unblocking_counter() {
        const ATTRIBUTES_TAG_HI: u8 = 0xDF;
        const ATTRIBUTES_TAG_LO: u8 = 0x21;
        const ATTRIBUTES_LENGTH: u8 = 0x04;
        const FIVE_TRIES: u8 = 5;
        const USAGE_NO_LIMIT: u8 = u8::MAX;
        const INVALID_UNBLOCKING_COUNTER: u8 = 0x10;
        const PUK_METHOD: u8 = 0x83;
        const PIN_ATTRIBUTES: [u8; 7] = [
            ATTRIBUTES_TAG_HI,
            ATTRIBUTES_TAG_LO,
            ATTRIBUTES_LENGTH,
            FIVE_TRIES,
            USAGE_NO_LIMIT,
            INVALID_UNBLOCKING_COUNTER,
            PUK_METHOD,
        ];

        assert_eq!(
            PinInfoResponse::policy_counters_from_response_body(&PIN_ATTRIBUTES),
            None
        );
    }

    #[test]
    fn get_pin_info_pin1_apdu_wire_shape() {
        let bytes = GetPinInfo {
            scheme: PinReferenceScheme::Citizen,
            slot: PinSlot::Pin1,
        }
        .into_apdu()
        .into_bytes();
        // S1 v4.2 §3.15.2 + Table 16, PIN1 = 0x11 (global PIN ref).
        assert_eq!(
            bytes,
            vec![
                0x00, 0xCB, 0x00, 0xFF, 0x05, 0xA0, 0x03, 0x83, 0x01, 0x11, 0x00
            ]
        );
    }

    #[test]
    fn get_pin_info_pin2_apdu_wire_shape() {
        let bytes = GetPinInfo {
            scheme: PinReferenceScheme::Citizen,
            slot: PinSlot::Pin2,
        }
        .into_apdu()
        .into_bytes();
        // PIN2 = 0x82 (local PIN ref per FINEID S4-1 v3.1 §4.1).
        assert_eq!(
            bytes,
            vec![
                0x00, 0xCB, 0x00, 0xFF, 0x05, 0xA0, 0x03, 0x83, 0x01, 0x82, 0x00
            ]
        );
    }

    #[test]
    fn changed_flag_extracts_true() {
        // Excerpt of Table 19 response: ... DF 2F 01 01 ...
        let body = [0xA0, 0x10, 0x83, 0x01, 0x11, 0xDF, 0x2F, 0x01, 0x01];
        assert_eq!(
            PinInfoResponse::changed_flag_from_response_body(&body),
            Some(true)
        );
    }

    #[test]
    fn changed_flag_extracts_false() {
        let body = [0xA0, 0x10, 0x83, 0x01, 0x11, 0xDF, 0x2F, 0x01, 0x00];
        assert_eq!(
            PinInfoResponse::changed_flag_from_response_body(&body),
            Some(false)
        );
    }

    #[test]
    fn changed_flag_absent_returns_none() {
        let body = [0xA0, 0x05, 0x83, 0x01, 0x11, 0xDF, 0x21, 0x04, 0x05, 0xFF];
        assert_eq!(
            PinInfoResponse::changed_flag_from_response_body(&body),
            None
        );
    }

    #[test]
    fn changed_flag_empty_body_returns_none() {
        assert_eq!(PinInfoResponse::changed_flag_from_response_body(&[]), None);
    }
}
