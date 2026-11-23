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

//! Card transport port.
//!
//! [`CardTransport`] is the boundary between the protocol layer
//! and the actual card-access mechanism (PC/SC today; future NFC,
//! USB CCID, embedded HAL). Adapters that satisfy this trait live
//! in their own crates so the protocol layer stays unaware of
//! where the bytes are going.

use refineid_atr::{Atr, AtrError};

pub use refineid_apdu::{ResponseApdu, TransportErrorExt, TransportErrorKind, TransportOutcome};

/// One outgoing smart-card command APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandApdu {
    /// Raw ISO 7816-4 command APDU bytes (`CLA INS P1 P2 [Lc
    /// data] [Le]`). The typed command builders construct this
    /// field; downstream code reads through [`Self::as_bytes`]
    /// without re-parsing.
    bytes: Vec<u8>,
    /// Whether a T=0 adapter may correct `Le` once after `6Cxx`.
    /// Raw APDUs and all credential-bearing commands default to
    /// `false`; only typed, read-only case-2 builders opt in.
    wrong_le_retry: bool,
}

impl CommandApdu {
    /// Wrap an owned byte buffer as a `CommandApdu`. No
    /// structural check; the typed command builders
    /// (`MseSetDst::into_apdu`, etc.) are the boundary that
    /// guarantees a well-formed ISO 7816-4 command shape.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            wrong_le_retry: false,
        }
    }

    /// Mark a builder-proven short case-2 command as safe for one
    /// corrected-`Le` retry. This is intentionally crate-private:
    /// transport adapters and callers handling raw APDUs cannot opt
    /// arbitrary commands into replay.
    #[must_use]
    pub(crate) fn allow_wrong_le_retry(mut self) -> Self {
        const SHORT_CASE_2_BYTES: usize = 5;
        debug_assert_eq!(self.bytes.len(), SHORT_CASE_2_BYTES);
        self.wrong_le_retry = self.bytes.len() == SHORT_CASE_2_BYTES;
        self
    }

    /// Return the single corrected command permitted by a typed
    /// read-only builder. The returned command cannot be corrected
    /// again, so adapters cannot replay indefinitely after repeated
    /// `6Cxx` responses.
    #[must_use]
    pub fn corrected_wrong_le(&self, le: u8) -> Option<Self> {
        if !self.wrong_le_retry {
            return None;
        }
        let mut corrected = self.clone();
        let last = corrected.bytes.last_mut()?;
        *last = le;
        corrected.wrong_le_retry = false;
        Some(corrected)
    }

    /// Borrow the underlying APDU bytes for transmission to the
    /// transport adapter.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the command and return the owned APDU bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl From<refineid_apdu::CommandApdu> for CommandApdu {
    fn from(command: refineid_apdu::CommandApdu) -> Self {
        let allows_wrong_le = command.corrected_wrong_le(0).is_some();
        let converted = Self::new(command.as_bytes().to_vec());
        if allows_wrong_le {
            converted.allow_wrong_le_retry()
        } else {
            converted
        }
    }
}

impl From<Vec<u8>> for CommandApdu {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for CommandApdu {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for CommandApdu {
    fn from(bytes: &[u8; N]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl AsRef<[u8]> for CommandApdu {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// "I expected a real APDU response, but the transport had a
/// higher-level state transition or backend failure instead."
#[derive(Debug)]
pub enum TransportDispatchError<E> {
    /// Backend / adapter-specific error (PC/SC return code,
    /// USB CCID I/O, etc.).
    Error(E),
    /// Transport-layer state transition that isn't a real APDU
    /// response (`NoCard`, `CardReset`, ...).
    Outcome(TransportOutcome),
}

impl<E: TransportErrorExt> TransportDispatchError<E> {
    /// Project to the [`TransportErrorKind`] vocabulary. Either
    /// delegates to the adapter's classifier (`Error` variant)
    /// or maps the outcome to its kind (`Outcome` variant).
    pub fn kind(&self) -> TransportErrorKind {
        match self {
            Self::Error(error) => error.kind(),
            Self::Outcome(outcome) => outcome.kind().unwrap_or(TransportErrorKind::Backend),
        }
    }
}

impl<E: core::fmt::Display> core::fmt::Display for TransportDispatchError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Error(error) => write!(f, "{error}"),
            Self::Outcome(outcome) => write!(f, "{outcome}"),
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error
    for TransportDispatchError<E>
{
}

/// Send-and-receive APDU primitive. Implementations are
/// responsible for transport-level retries that do not surface to
/// the protocol layer (`61xx GET RESPONSE` chains, `6Cxx`
/// wrong-`Le` retries, etc.).
pub trait CardTransport {
    /// Adapter-specific error type. Must implement `Display`
    /// (for diagnostics) and [`TransportErrorExt`] (for the
    /// typed fault classifier).
    type Error: core::fmt::Debug + core::fmt::Display + TransportErrorExt;

    /// Synchronously transmit the APDU and return either a
    /// concrete response or a transport-level state transition.
    ///
    /// # Errors
    /// Transport-specific failures other than the
    /// [`TransportOutcome`] state transitions.
    fn transmit_outcome(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, Self::Error>;

    /// Convenience path for higher protocol layers that require a
    /// real APDU response body and SW pair. Non-response transport
    /// outcomes are surfaced explicitly rather than flattened into
    /// a string.
    ///
    /// # Errors
    /// Either a backend error or a transport-level outcome that
    /// is not a real APDU response.
    fn transmit(&mut self, apdu: &[u8]) -> Result<ResponseApdu, TransportDispatchError<Self::Error>>
    where
        Self: Sized,
    {
        let command = CommandApdu::from(apdu);
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "TransportOutcome is #[non_exhaustive]; non-Response state transitions (NoCard, CardReset, ReaderRemoved, ...) and any future variant are lifted into TransportDispatchError::Outcome so the caller can branch on TransportErrorKind."
        )]
        match self
            .transmit_outcome(&command)
            .map_err(TransportDispatchError::Error)?
        {
            TransportOutcome::Response(response) => Ok(response),
            outcome => Err(TransportDispatchError::Outcome(outcome)),
        }
    }

    /// Card's ATR, parsed into the typed [`Atr`]. Upper layers read
    /// the typed structure (convention, historical data objects,
    /// FINEID model) instead of re-parsing raw bytes -- the boundary
    /// hands forward a domain value, not a `&[u8]`.
    ///
    /// # Errors
    /// [`AtrError`] if the card's ATR bytes are outside the
    /// ISO 7816-3 structure (length window, bad TS, truncated chain).
    fn atr(&self) -> Result<Atr, AtrError>;
}

#[cfg(test)]
mod tests {

    use super::{CardTransport, CommandApdu, ResponseApdu, TransportErrorKind, TransportOutcome};
    use refineid_atr::{Atr, AtrError, Convention, MINIMAL_DIRECT_ATR, T0, TdByte};

    /// In-memory transport that replays a canned `(request,
    /// response)` trace. Used by protocol-layer unit tests to
    /// drive PACE and secure messaging against recorded byte
    /// streams without needing a card.
    pub(super) struct MockTransport {
        atr: Vec<u8>,
        script: Vec<(Vec<u8>, ResponseApdu)>,
        cursor: usize,
    }

    impl MockTransport {
        fn new(atr: Vec<u8>, script: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
            Self {
                atr,
                script,
                cursor: 0,
            }
        }
    }

    impl CardTransport for MockTransport {
        type Error = String;

        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            let (expected, response) = self.script.get(self.cursor).ok_or_else(|| {
                format!("MockTransport: script exhausted at step {}", self.cursor)
            })?;
            if expected != apdu.as_bytes() {
                return Err(format!(
                    "MockTransport step {}: expected {} but got {}",
                    self.cursor,
                    hex::encode(expected),
                    hex::encode(apdu.as_bytes()),
                ));
            }
            self.cursor += 1;
            Ok(TransportOutcome::Response(response.clone()))
        }

        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(&self.atr)
        }
    }

    #[test]
    fn apdu_response_status_helpers() {
        let ok = ResponseApdu {
            body: vec![],
            sw1: 0x90,
            sw2: 0x00,
        };
        assert!(ok.is_ok());
        assert_eq!(ok.status_word().as_u16(), 0x9000);

        let pin_wrong = ResponseApdu {
            body: vec![],
            sw1: 0x63,
            sw2: 0xC3,
        };
        assert!(!pin_wrong.is_ok());
        assert_eq!(pin_wrong.status_word().as_u16(), 0x63C3);
    }

    #[test]
    fn transport_outcome_preserves_fault_kind() {
        assert_eq!(
            TransportOutcome::CardReset.kind(),
            Some(TransportErrorKind::CardReset)
        );
        assert_eq!(
            TransportOutcome::Response(ResponseApdu {
                body: vec![],
                sw1: 0x90,
                sw2: 0x00,
            })
            .kind(),
            None
        );
    }

    #[test]
    fn mock_transport_rejects_a_corrupt_tck() {
        // ISO 7816-3 §8: T0 announces TD1, which selects T=1;
        // TCK is the XOR of T0 and TD1 when no historical bytes follow.
        const TD1_PRESENT: u8 = 0x80;
        const PROTOCOL_T1: u8 = 1;
        let t0 = T0::from_byte(TD1_PRESENT).as_byte();
        let td1 = TdByte::new(PROTOCOL_T1).as_byte();
        let tck = t0 ^ td1;
        let mut bytes = vec![Convention::Direct.as_ts(), t0, td1, tck];
        let valid = MockTransport::new(bytes.clone(), vec![]);
        assert!(valid.atr().is_ok());
        if let Some(last) = bytes.last_mut() {
            *last ^= u8::MAX;
        }
        let corrupt = MockTransport::new(bytes, vec![]);
        assert!(matches!(corrupt.atr(), Err(AtrError::TckMismatch { .. })));
    }

    #[test]
    fn mock_transport_drives_a_script() {
        let mut tx = MockTransport::new(
            MINIMAL_DIRECT_ATR.to_vec(),
            vec![(
                vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00],
                ResponseApdu {
                    body: vec![],
                    sw1: 0x90,
                    sw2: 0x00,
                },
            )],
        );
        let r = tx
            .transmit(&[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00])
            .expect("scripted SELECT MF transmit succeeds");
        assert!(r.is_ok());
        assert_eq!(
            tx.atr().expect("mock exposes its ATR").to_wire_bytes(),
            MINIMAL_DIRECT_ATR
        );
    }

    #[test]
    fn from_core_command_apdu_preserves_wrong_le_retry_policy() {
        use crate::apdu::iso7816::{
            ApduClass, DirectOffset15, FileId, GetResponse, ReadBinary, ReadBinaryOffset,
            SelectEfNoFci,
        };

        let get_response: CommandApdu = GetResponse {
            class: ApduClass::Plain,
            le: 0x00,
        }
        .into_apdu()
        .into();
        let retried = get_response
            .corrected_wrong_le(0x20)
            .expect("GetResponse keeps one wrong-Le retry across From conversion");
        assert_eq!(retried.as_bytes(), &[0x00, 0xC0, 0x00, 0x00, 0x20]);
        assert!(
            retried.corrected_wrong_le(0x10).is_none(),
            "corrected command cannot be retried a second time"
        );

        let read_binary: CommandApdu = ReadBinary {
            class: ApduClass::Plain,
            offset: ReadBinaryOffset::Direct(
                DirectOffset15::try_new(0).expect("offset zero fits in DirectOffset15"),
            ),
            le: 0x80,
        }
        .into_apdu()
        .into();
        let retried_read = read_binary
            .corrected_wrong_le(0x40)
            .expect("ReadBinary keeps one wrong-Le retry across From conversion");
        assert_eq!(retried_read.as_bytes(), &[0x00, 0xB0, 0x00, 0x00, 0x40]);

        let select_ef: CommandApdu = SelectEfNoFci {
            fid: FileId::new([0x43, 0x31]),
        }
        .into_apdu()
        .into();
        assert!(
            select_ef.corrected_wrong_le(0x10).is_none(),
            "non-case-2 SelectEfNoFci must not gain wrong-Le retry across From conversion"
        );
    }
}
