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

//! VERIFY PIN1 / PIN2 against a FINEID card.
//!
//! ISO 7816-4 §7.5.6 VERIFY against PKCS#15 PIN references. The
//! ASCII PIN bytes the user typed are right-padded with
//! [`PIN_PAD_BYTE`] (`0x00`) up to the slot's stored length (12)
//! and shipped as the APDU data field. Status-word classification
//! is done locally so callers can branch on
//! [`VerifyOutcome::WrongPin { retries_left }`] /
//! [`VerifyOutcome::Locked`] without re-parsing the SW.
//!
//! Reference FINEID S1 v4.2 §3.5 PIN management; ISO 7816-4 §7.5.6.
//!
//! Wire format (PIN1, slot reference `0x11`):
//!
//! ```text
//!  CLA INS P1 P2  Lc  data...
//!  00  20  00 11  0C  <12 bytes: ASCII PIN + 0x00 padding>
//! ```
//!
//! Local-policy gating (digit-only, length bounds) happens before
//! any APDU goes out -- a malformed PIN never reaches the card, so
//! it doesn't burn a retry counter slot.

pub mod commands;
pub mod pin_lengths;

pub use pin_lengths::CardPinLengths;
pub use refineid_pkcs15::PasswordLengthRange;

use crate::apdu::iso7816::ApduClass;
use crate::apdu::status_word::{PinRetries, StatusWord};
use crate::pin::PinBytes;
use crate::pkcs15::Pkcs15Ops as _;
use crate::transport::{CardTransport, TransportDispatchError};

/// Shortened alias for the transport-error variant produced by a
/// dispatch on a `CardTransport`-implementing type. Used to keep
/// the auth-flow signatures readable when the same nested generic
/// would otherwise repeat on every error-returning function.
type TxError<T> = TransportDispatchError<<T as CardTransport>::Error>;

/// PKCS#15 PIN1 reference -- auth PIN (digital signature for TLS
/// client cert / SSH / agent). FINEID S1 v4.2 §3.5.1.
pub const PIN1_REFERENCE_PKCS15: u8 = 0x11;

/// PKCS#15 PIN2 reference -- qualified-signature PIN (non-
/// repudiation). FINEID S1 v4.2 §3.5.2.
pub const PIN2_REFERENCE_PKCS15: u8 = 0x82;
/// PKCS#15 PUK reference shared by PIN1 and PIN2 recovery.
pub const PUK_REFERENCE_PKCS15: u8 = 0x83;

/// Organization-card PIN1 reference: the PIN AUTH security-data-object
/// identifier (FINEID S4-2 v4.0 §4.2).
pub const PIN1_REFERENCE_ORGANIZATIONAL: u8 = 0x03;
/// Organization-card PIN2 reference: the PIN SIG security-data-object
/// identifier (FINEID S4-2 v4.0 §4.2).
pub const PIN2_REFERENCE_ORGANIZATIONAL: u8 = 0x04;
/// Organization-card PUK reference: the PIN PUK security-data-object
/// identifier (FINEID S4-2 v4.0 §4.3.2).
pub const PUK_REFERENCE_ORGANIZATIONAL: u8 = 0x12;

/// FINEID stored-length for both PIN slots: 12 bytes. PIN1 / PIN2
/// share the same encoding -- the difference is the slot reference,
/// not the length.
pub const PIN1_STORED_LENGTH: usize = 12;
/// See [`PIN1_STORED_LENGTH`].
pub const PIN2_STORED_LENGTH: usize = 12;

/// Padding byte applied to the right of the typed ASCII digits up
/// to [`PIN1_STORED_LENGTH`]. FINEID cards reject any non-`0x00`
/// padding byte with `SW=6A80`.
pub const PIN_PAD_BYTE: u8 = 0x00;

/// Shortest PIN 1 or PIN 2 the commands carry: 4 digits, the shortest
/// length a FINEID card may list (FINEID S4-1 v4.2 §8.1.5). Signing and
/// login send any 4 to 12 digits and the card decides.
pub const PIN_MIN_LENGTH: usize = 4;
/// Longest PIN 1 or PIN 2 the commands carry: the stored length.
pub const PIN_MAX_LENGTH: usize = PIN1_STORED_LENGTH;
/// FINEID bound for the shortest PIN 1 (FINEID S4-1 v4.2 §4.1), taken
/// when the card lists no PIN 1 length.
pub const FINEID_PIN1_MIN_LENGTH: usize = 4;
/// FINEID bound for the shortest PIN 2 (FINEID S4-1 v4.2 §4.1), taken
/// when the card lists no PIN 2 length.
pub const FINEID_PIN2_MIN_LENGTH: usize = 6;

/// PUK stored-length: 12 bytes, padded with [`PIN_PAD_BYTE`] on a
/// citizen card.
///
/// The PUK uses the same 12-byte padded slot as the PIN1 / PIN2
/// references. "PUK" here is the unblocking code the `RESET RETRY
/// COUNTER` surface presents; under the FINEID S4-1 v4.2 §4.6.1
/// activation scheme the activation code from the letter is this PUK.
/// See `pin::ActivationCode` / `pin::Puk`.
pub const PUK_STORED_LENGTH: usize = 12;
/// Minimum PUK length (FINEID S4-1 v4.2 §4.1).
pub const PUK_MIN_LENGTH: usize = 8;
/// Maximum PUK length: the stored (padded) block length.
pub const PUK_MAX_LENGTH: usize = PUK_STORED_LENGTH;

/// Which PIN slot a `verify_pin` call targets.
///
/// `Pin1` is the auth PIN (digital signature, TLS client cert, SSH);
/// `Pin2` is the qualified-signature PIN (non-repudiation). The
/// reference byte each slot answers to depends on the card's
/// [`PinReferenceScheme`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSlot {
    /// PIN1 -- authentication / digital-signature PIN.
    Pin1,
    /// PIN2 -- qualified-signature / non-repudiation PIN.
    Pin2,
}

/// Which credential-reference numbering the card in session uses.
///
/// Citizen cards number their credentials as FINEID S1 v4.2 §3.5.2
/// reads; organization cards number them by their FINEID S4-2 v4.0
/// §4.2 security-data-object identifiers. The numbering is resolved by
/// asking the card with a counter-safe probe
/// ([`PinOps::resolve_pin_reference_scheme`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinReferenceScheme {
    /// FINEID S1 v4.2 numbering: the citizen cards.
    Citizen,
    /// FINEID S4-2 v4.0 numbering: the organization cards.
    Organizational,
}

impl PinReferenceScheme {
    /// The reference byte for `slot` under this numbering.
    #[must_use]
    pub const fn reference(self, slot: PinSlot) -> u8 {
        match (self, slot) {
            (Self::Citizen, PinSlot::Pin1) => PIN1_REFERENCE_PKCS15,
            (Self::Citizen, PinSlot::Pin2) => PIN2_REFERENCE_PKCS15,
            (Self::Organizational, PinSlot::Pin1) => PIN1_REFERENCE_ORGANIZATIONAL,
            (Self::Organizational, PinSlot::Pin2) => PIN2_REFERENCE_ORGANIZATIONAL,
        }
    }

    /// `true` when `slot` under this numbering is the PIN 2 local to
    /// DF.ESIGN: the organizational card's qualified-signature PIN.
    #[must_use]
    pub const fn gates_esign_directory(self, slot: PinSlot) -> bool {
        matches!((self, slot), (Self::Organizational, PinSlot::Pin2))
    }

    /// The PUK reference byte under this numbering.
    #[must_use]
    pub const fn puk_reference(self) -> u8 {
        match self {
            Self::Citizen => PUK_REFERENCE_PKCS15,
            Self::Organizational => PUK_REFERENCE_ORGANIZATIONAL,
        }
    }
}

/// A credential a command names, under the card's numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialReference {
    /// PIN 1 or PIN 2.
    Pin(PinReferenceScheme, PinSlot),
    /// The PUK.
    Puk(PinReferenceScheme),
}

impl CredentialReference {
    /// The reference byte the command carries.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Pin(scheme, slot) => scheme.reference(slot),
            Self::Puk(scheme) => scheme.puk_reference(),
        }
    }
}

impl PinSlot {
    /// Card-side stored length for this slot. Local padding pads
    /// to this many bytes.
    #[must_use]
    pub const fn stored_length(self) -> usize {
        match self {
            Self::Pin1 => PIN1_STORED_LENGTH,
            Self::Pin2 => PIN2_STORED_LENGTH,
        }
    }
}

/// Outcome of a `pin_status` probe (`VERIFY P1=0x00 Lc=0`).
///
/// FINEID-S1 §4.1.2 / IAS-ECC §7.5.6 make this APDU explicitly
/// side-effect-free: neither path decrements the PIN's retry
/// counter or its usage counter, so this is the safe pre-flight
/// probe to run before any operation that would burn a retry on
/// a PIN mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    /// `SW = 0x9000` -- PIN already verified in this card session.
    /// Subsequent PIN-protected ops won't prompt again until a
    /// SELECT or RESET clears the session.
    Verified,
    /// `SW = 0x63CX` -- PIN not currently verified, `X` retries
    /// left before lockout. `X = 0` means *the next* VERIFY
    /// failure will lock the card.
    Remaining(PinRetries),
    /// `SW = 0x6300` -- "verification failed, no retries
    /// information". Some cards return this when retries=0 or
    /// when the PIN is in an indeterminate state (locked but not
    /// yet 6983).
    NoInfo,
    /// `SW = 0x6983` / `0x6984` -- PIN method blocked or usage
    /// counter exhausted. PUK unblock is the only recovery path.
    Locked,
    /// Anything else -- surfaced opaquely for the caller.
    Other(u16),
}

/// Outcome of the counter-safe PUK retry probe through the FINEID
/// PIN-container `GET DATA` command from S1 v4.2 section 3.15.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PukStatus {
    /// PIN-container attributes report X PUK presentations remain.
    Remaining(PinRetries),
    /// The card supplied no parseable retry-counter value.
    NoInfo,
    /// `SW=6983`: the shared PUK is blocked.
    Locked,
    /// `SW=6984`: the target PIN recovery data or PUK is invalidated.
    Invalidated,
    /// Any other status word, preserved for diagnostics.
    Other(u16),
}

/// Card-reported credential usage allowance from FINEID S1 v4.2
/// section 3.15.3, PIN attributes field 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageCounter {
    /// No successful uses remain.
    Exhausted,
    /// A finite number of successful uses remain.
    Limited(std::num::NonZeroU8),
    /// The card reports no usage limit.
    NoLimit,
}

/// Card-reported PIN recovery allowance from FINEID S1 v4.2
/// section 3.15.3, PIN attributes field 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnblockingCounter {
    /// No recoveries remain, or recovery is not applicable to this
    /// credential.
    Exhausted,
    /// A finite number of recoveries remain.
    Limited(std::num::NonZeroU8),
    /// The card reports no recovery limit.
    NoLimit,
}

/// Typed policy counters returned by the card's counter-safe PIN-info
/// `GET DATA` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialPolicyCounters {
    /// Successful-use allowance for the queried credential.
    pub usage: UsageCounter,
    /// Recovery allowance for the queried credential.
    pub unblocking: UnblockingCounter,
}

/// Outcome of a VERIFY round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// `SW = 0x9000` -- PIN accepted. The card stays in the
    /// user-authenticated state until a SELECT or RESET clears it.
    Ok,
    /// `SW = 0x63CX` -- wrong PIN, `X` retries left. `X = 0`
    /// means the next failed VERIFY will lock the slot.
    WrongPin {
        /// Number of attempts remaining before the slot locks
        /// (PIN counter nibble from SW `63Cx`).
        retries_left: PinRetries,
    },
    /// `SW = 0x6983` / `0x6984` -- authentication method blocked.
    /// The card won't accept any VERIFY until a PUK unblock.
    Locked,
    /// Anything else -- surfaced as opaque SW for the caller to map.
    Other(u16),
}

/// Reasons a PIN gets rejected locally, before any APDU goes out.
///
/// The wire-shape variants (`WrongLength`, `NonDigit`) are
/// enforced by `verify_pin` / `change_pin` directly because
/// they describe shapes the card can't even accept. The
/// protocol layer stays policy-light beyond that: PIN quality
/// is the citizen's call (and the consumer UI's, if it wants
/// to advise) -- lib-core ships no strength policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PinPolicyReason {
    /// Typed length is outside the accepted range: the commands'
    /// capacity on a VERIFY, the card's range where PINs are set
    /// ([`CardPinLengths`]).
    WrongLength {
        /// Length of the rejected PIN in bytes.
        got: usize,
        /// Minimum length the slot accepts.
        min: usize,
        /// Maximum length the slot accepts.
        max: usize,
    },
    /// Non-digit ASCII byte at `byte_offset`. PIN bytes must all
    /// be in `b'0'..=b'9'`.
    NonDigit {
        /// Byte index at which the offending value was found.
        byte_offset: usize,
    },
    /// The card's range for the credential shares no length with what
    /// the commands carry ([`CardPinLengths`]).
    NoAcceptedLength,
}

impl core::fmt::Display for PinPolicyReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength { got: _, min, max } => {
                write!(f, "pin length outside accepted range {min}..={max}")
            }
            // The offending offset stays out of `Display`: this text
            // reaches user-facing surfaces through card-operation
            // errors, where positions inside secret material must
            // not appear (`Debug` keeps it for tests).
            Self::NonDigit { byte_offset: _ } => {
                write!(f, "pin contains a non-digit byte")
            }
            Self::NoAcceptedLength => {
                write!(f, "this card lists no pin length that can be set")
            }
        }
    }
}

/// VERIFY-path errors.
#[derive(Debug)]
pub enum AuthError<TE> {
    /// Transport-layer failure -- PC/SC error, reader removed,
    /// card reset, etc.
    Transport(TE),
    /// Locally-rejected PIN; no APDU was sent.
    PinPolicy(PinPolicyReason),
}

impl<TE: core::fmt::Display> core::fmt::Display for AuthError<TE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "auth transport: {e}"),
            Self::PinPolicy(reason) => write!(f, "auth pin policy: {reason}"),
        }
    }
}

impl<TE: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for AuthError<TE> {}

/// Local-policy gate for a PIN-shape ASCII buffer: length within
/// `[min, stored]` and every byte an ASCII digit. Returns the
/// matching [`AuthError::PinPolicy`] variant on failure, `Ok(())`
/// otherwise.
///
/// Centralises the wire-shape check used by `verify_pin`,
/// `change_pin`, and `reset_retry_counter`. Failing locally
/// (before the card sees the APDU) never decrements a card-side
/// retry counter, so this gate is cheap insurance against typos.
///
/// The error type is parameterised by the caller's transport
/// error so a single helper composes into every on-card path.
/// Local-policy gate for `ascii` PIN bytes. Unit struct hosting
/// the validator inside an `impl` block (no free functions with
/// borrowed parameters).
struct PinPolicyCheck;

impl PinPolicyCheck {
    /// `ascii` must be in `[min, stored]` length and contain
    /// only ASCII digits. Maps the failure to [`AuthError`] so
    /// callers can `?` it directly.
    fn validate_ascii<TE>(ascii: &[u8], min: usize, stored: usize) -> Result<(), AuthError<TE>> {
        if ascii.len() < min || ascii.len() > stored {
            return Err(AuthError::PinPolicy(PinPolicyReason::WrongLength {
                got: ascii.len(),
                min,
                max: stored,
            }));
        }
        Self::validate_digits(ascii)
    }

    /// `ascii` must contain only ASCII digits.
    fn validate_digits<TE>(ascii: &[u8]) -> Result<(), AuthError<TE>> {
        if let Some(off) = ascii.iter().position(|b| !b.is_ascii_digit()) {
            return Err(AuthError::PinPolicy(PinPolicyReason::NonDigit {
                byte_offset: off,
            }));
        }
        Ok(())
    }

    /// `ascii` must contain only ASCII digits, and `lengths` must accept
    /// its length through `check`.
    fn validate_for_card<TE>(
        ascii: &[u8],
        check: impl FnOnce(usize) -> Result<(), PinPolicyReason>,
    ) -> Result<(), AuthError<TE>> {
        Self::validate_digits(ascii)?;
        check(ascii.len()).map_err(AuthError::PinPolicy)
    }
}

/// Credential-block assembly for one card numbering.
///
/// The citizen card compares a block right-padded with
/// [`PIN_PAD_BYTE`] to the stored length (FINEID S1 v4.2 §3.5). The
/// organization card compares the bare typed digits at their own
/// length: it publishes no padding, and the card splits a two-block
/// field at the stored length of the current credential (IAS ECC
/// v1.0.1 §9.4.2), so the blocks go back to back.
struct CredentialBlock;

impl CredentialBlock {
    /// Append `digits` to `out` as one credential block for `scheme`,
    /// padded to `stored` on a citizen card.
    fn push(out: &mut Vec<u8>, scheme: PinReferenceScheme, digits: &[u8], stored: usize) {
        out.extend_from_slice(digits);
        if scheme == PinReferenceScheme::Citizen {
            out.resize(
                out.len()
                    .saturating_add(stored.saturating_sub(digits.len())),
                PIN_PAD_BYTE,
            );
        }
    }
}

/// PIN-management operations layered as default-impl methods on
/// every [`CardTransport`].
///
/// The trait is the typed receiver that keeps these APIs out of
/// the "`pub fn` with borrowed parameters" category. Import it via
/// `use refineid_lib_core::auth::PinOps;` to put the methods in
/// scope; the blanket impl below applies to every transport.
///
/// The `_with_scheme` forms speak the numbering the card declared
/// ([`PinOps::resolve_pin_reference_scheme`]); the plain forms speak
/// the citizen numbering. The change and reset operations take the
/// [`CardPinLengths`] the session read with
/// [`PinOps::read_card_pin_lengths`] and act under the numbering it was
/// read by.
pub trait PinOps: CardTransport {
    /// VERIFY under the citizen numbering; see
    /// [`PinOps::verify_pin_with_scheme`].
    ///
    /// # Errors
    /// As [`PinOps::verify_pin_with_scheme`].
    fn verify_pin(
        &mut self,
        slot: PinSlot,
        pin: PinBytes,
    ) -> Result<VerifyOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.verify_pin_with_scheme(PinReferenceScheme::Citizen, slot, pin)
    }

    /// VERIFY APDU `00 20 00 P2 LC <credential block>` for `slot`
    /// under `scheme`.
    ///
    /// Local-policy gates: length must be in [`PIN_MIN_LENGTH`] to
    /// [`PIN_MAX_LENGTH`], every byte must be an ASCII digit; the card
    /// decides any narrower range. A rejection here doesn't burn a
    /// card-side retry counter slot.
    ///
    /// `pin` is consumed by value -- typed receivers and owned
    /// secrets cross the API boundary; the underlying buffer is
    /// `ZeroizeOnDrop` so the caller doesn't leak it by passing
    /// ownership in.
    ///
    /// The organizational qualified-signature key and the PIN 2 that
    /// gates it live in DF.ESIGN, which must be current at VERIFY and
    /// through the MSE:Set and PSO:CDS that follow. PIN 2 under the
    /// organizational numbering therefore selects DF.ESIGN first; when
    /// the card refuses that SELECT the PIN is not presented and its
    /// refusal returns as [`VerifyOutcome::Other`].
    ///
    /// # Errors
    /// [`AuthError::PinPolicy`] when local policy rejects the typed
    /// PIN; [`AuthError::Transport`] when the underlying transport
    /// fails.
    fn verify_pin_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
        slot: PinSlot,
        pin: PinBytes,
    ) -> Result<VerifyOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        if scheme.gates_esign_directory(slot) {
            let entered = self
                .select_esign_directory()
                .map_err(AuthError::Transport)?;
            if !entered.is_success() {
                return Ok(VerifyOutcome::Other(entered.as_u16()));
            }
        }
        let pin_ascii = pin.as_bytes();
        let stored = slot.stored_length();
        PinPolicyCheck::validate_ascii(pin_ascii, PIN_MIN_LENGTH, stored)?;
        let mut block = Vec::with_capacity(stored);
        CredentialBlock::push(&mut block, scheme, pin_ascii, stored);
        let apdu = commands::Verify {
            class: ApduClass::Plain,
            mode: commands::VerifyMode::Verify,
            reference: CredentialReference::Pin(scheme, slot),
            data: commands::VerifyData::PinBlock(block.clone()),
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        zeroize::Zeroize::zeroize(&mut block);
        Ok(classify_verify_sw(r.status_word()))
    }

    /// Convenience for the PIN1 (auth) slot.
    ///
    /// # Errors
    /// See [`PinOps::verify_pin`].
    fn verify_pin1(&mut self, pin: PinBytes) -> Result<VerifyOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.verify_pin(PinSlot::Pin1, pin)
    }

    /// Read the PIN 1, PIN 2 and PUK lengths the card accepts, resolving
    /// the card's numbering first.
    ///
    /// Read once per card session where PINs are set -- activation,
    /// change, reset -- and pass the result to those operations; the
    /// signing and login paths never read it. EF.AOD is read under the
    /// PKCS#15 application, which leaves that application selected. A
    /// citizen card whose EF.AOD does not list a credential is asked for
    /// that credential's PIN container, whose PIN policy is the second
    /// source; the organization card is not asked. An EF.AOD that cannot
    /// be selected, read or decoded lists nothing. Every command here is
    /// a read and touches no retry counter.
    ///
    /// # Errors
    /// Transport failure.
    fn read_card_pin_lengths(&mut self) -> Result<CardPinLengths, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let numbering = self.resolve_pin_reference_scheme()?;
        let objects = match crate::pkcs15::Pkcs15Ops::read_authentication_objects(self) {
            Ok(objects) => Some(objects),
            Err(crate::pkcs15::Pkcs15Error::Transport(error)) => {
                return Err(AuthError::Transport(error));
            }
            Err(
                crate::pkcs15::Pkcs15Error::Sw(_)
                | crate::pkcs15::Pkcs15Error::Aid(_)
                | crate::pkcs15::Pkcs15Error::Empty
                | crate::pkcs15::Pkcs15Error::TooLarge
                | crate::pkcs15::Pkcs15Error::InvalidData(_),
            ) => None,
        };
        let mut failure = None;
        let lengths = CardPinLengths::from_card(numbering, objects.as_ref(), |credential| {
            if failure.is_some() || numbering != PinReferenceScheme::Citizen {
                return None;
            }
            match self.pin_policy_lengths(credential) {
                Ok(range) => range,
                Err(error) => {
                    failure = Some(error);
                    None
                }
            }
        });
        failure.map_or(Ok(lengths), Err)
    }

    /// Read the length range of the PIN policy in the citizen card's PIN
    /// container for `credential` (FINEID S1 v4.2 §3.15.3, Table 19).
    /// `None` when the card refuses the read, the container carries no
    /// policy, or the policy's lengths fall outside the range the
    /// specification gives.
    ///
    /// # Errors
    /// Transport failure.
    fn pin_policy_lengths(
        &mut self,
        credential: CredentialReference,
    ) -> Result<Option<PasswordLengthRange>, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = match credential {
            CredentialReference::Pin(scheme, slot) => {
                commands::GetPinInfo { scheme, slot }.into_apdu()
            }
            CredentialReference::Puk(_) => commands::GetPukInfo.into_apdu(),
        };
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        if !r.is_ok() {
            return Ok(None);
        }
        Ok(commands::PinInfoResponse::policy_lengths_from_response_body(&r.body))
    }

    /// `CHANGE REFERENCE DATA` per ISO 7816-4 §7.5.7 for `slot` under
    /// the numbering `lengths` was read by: the current credential
    /// block, then the new. Both PINs must be digits of a length the
    /// card accepts ([`CardPinLengths`]).
    ///
    /// # Errors
    /// [`AuthError::PinPolicy`] on local rejection, nothing sent;
    /// [`AuthError::Transport`] on transport failure.
    fn change_pin(
        &mut self,
        lengths: &CardPinLengths,
        slot: PinSlot,
        current_pin: PinBytes,
        new_pin: PinBytes,
    ) -> Result<ChangePinOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let current = current_pin.as_bytes();
        let new = new_pin.as_bytes();
        let stored = slot.stored_length();
        let scheme = lengths.numbering();
        PinPolicyCheck::validate_for_card(current, |count| lengths.check_pin(slot, count))?;
        PinPolicyCheck::validate_for_card(new, |count| lengths.check_pin(slot, count))?;

        let mut block = Vec::with_capacity(stored.saturating_mul(2));
        CredentialBlock::push(&mut block, scheme, current, stored);
        CredentialBlock::push(&mut block, scheme, new, stored);
        let apdu = commands::ChangeReferenceData {
            reference: CredentialReference::Pin(scheme, slot),
            padded_pair: block.clone(),
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        zeroize::Zeroize::zeroize(&mut block);
        Ok(classify_change_pin_sw(r.status_word()))
    }

    /// `RESET RETRY COUNTER` per ISO 7816-4 §7.5.10 (PUK-driven
    /// unblock) for `target` under the numbering `lengths` was read by.
    /// See [`UnblockOutcome`] for the side-effect rules. The PUK and the
    /// new PIN must be digits of a length the card accepts
    /// ([`CardPinLengths`]).
    ///
    /// The citizen card unblocks in one command carrying the PUK and
    /// the new PIN. The organization card verifies the PUK as its own
    /// object first, and only an accepted PUK lets the reset --
    /// carrying only the new PIN -- go out (FINEID S4-2 v4.0 §4.3.2);
    /// a refused PUK ends the flow with its own outcome.
    ///
    /// # Errors
    /// [`AuthError::PinPolicy`] on local rejection, nothing sent;
    /// [`AuthError::Transport`] on transport failure.
    fn reset_retry_counter(
        &mut self,
        lengths: &CardPinLengths,
        target: PinSlot,
        puk: PinBytes,
        new_pin: PinBytes,
    ) -> Result<UnblockOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let puk_ascii = puk.as_bytes();
        let new_ascii = new_pin.as_bytes();
        let target_stored = target.stored_length();
        let scheme = lengths.numbering();
        PinPolicyCheck::validate_for_card(puk_ascii, |count| lengths.check_puk(count))?;
        PinPolicyCheck::validate_for_card(new_ascii, |count| lengths.check_pin(target, count))?;

        let mode = match scheme {
            PinReferenceScheme::Citizen => commands::ResetRetryCounterMode::CodeThenNew,
            PinReferenceScheme::Organizational => {
                let mut puk_block = Vec::with_capacity(PUK_STORED_LENGTH);
                CredentialBlock::push(&mut puk_block, scheme, puk_ascii, PUK_STORED_LENGTH);
                let apdu = commands::Verify {
                    class: ApduClass::Plain,
                    mode: commands::VerifyMode::Verify,
                    reference: CredentialReference::Puk(scheme),
                    data: commands::VerifyData::PinBlock(puk_block.clone()),
                }
                .into_apdu();
                let r = self
                    .transmit(apdu.as_bytes())
                    .map_err(AuthError::Transport)?;
                zeroize::Zeroize::zeroize(&mut puk_block);
                let verified = classify_reset_retry_sw(r.status_word());
                if verified != UnblockOutcome::Ok {
                    return Ok(verified);
                }
                commands::ResetRetryCounterMode::NewOnly
            }
        };

        let mut block = Vec::with_capacity(PUK_STORED_LENGTH.saturating_add(target_stored));
        if mode == commands::ResetRetryCounterMode::CodeThenNew {
            CredentialBlock::push(&mut block, scheme, puk_ascii, PUK_STORED_LENGTH);
        }
        CredentialBlock::push(&mut block, scheme, new_ascii, target_stored);
        let apdu = commands::ResetRetryCounter {
            target: CredentialReference::Pin(scheme, target),
            mode,
            padded_pair: block.clone(),
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        zeroize::Zeroize::zeroize(&mut block);
        Ok(classify_reset_retry_sw(r.status_word()))
    }

    /// Resolve the card's credential numbering with counter-safe
    /// probes.
    ///
    /// The citizen PIN1 reference is probed first; a "reference data
    /// not found" answer (`SW=6A88`) re-probes under the organization
    /// numbering, and a recognised PIN state there settles it as
    /// [`PinReferenceScheme::Organizational`]. No retry counter is
    /// touched.
    ///
    /// # Errors
    /// Transport failure.
    fn resolve_pin_reference_scheme(
        &mut self,
    ) -> Result<PinReferenceScheme, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let citizen = self.probe_status_word(CredentialReference::Pin(
            PinReferenceScheme::Citizen,
            PinSlot::Pin1,
        ))?;
        if citizen != StatusWord::ReferenceDataNotFound {
            return Ok(PinReferenceScheme::Citizen);
        }
        let organizational = self.probe_status_word(CredentialReference::Pin(
            PinReferenceScheme::Organizational,
            PinSlot::Pin1,
        ))?;
        Ok(match classify_pin_status_sw(organizational) {
            PinStatus::Verified
            | PinStatus::Remaining(_)
            | PinStatus::NoInfo
            | PinStatus::Locked => PinReferenceScheme::Organizational,
            PinStatus::Other(_) => PinReferenceScheme::Citizen,
        })
    }

    /// Send the counter-safe VERIFY status probe (empty data field)
    /// for `reference` and return the card's status word.
    ///
    /// # Errors
    /// Transport failure.
    fn probe_status_word(
        &mut self,
        reference: CredentialReference,
    ) -> Result<StatusWord, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::Verify {
            class: ApduClass::Plain,
            mode: commands::VerifyMode::Verify,
            reference,
            data: commands::VerifyData::Probe,
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        Ok(r.status_word())
    }

    /// Probe the card's PIN state for `slot` under the citizen
    /// numbering without touching its retry counter. Side-effect-free.
    ///
    /// # Errors
    /// Transport failure.
    fn pin_status(&mut self, slot: PinSlot) -> Result<PinStatus, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.pin_status_with_scheme(PinReferenceScheme::Citizen, slot)
    }

    /// Probe the card's PIN state for `slot` under `scheme` without
    /// touching its retry counter. Side-effect-free.
    ///
    /// # Errors
    /// Transport failure.
    fn pin_status_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
        slot: PinSlot,
    ) -> Result<PinStatus, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let sw = self.probe_status_word(CredentialReference::Pin(scheme, slot))?;
        Ok(classify_pin_status_sw(sw))
    }

    /// Read the citizen card's shared PUK retry counter without
    /// presenting a PUK; see [`PinOps::puk_status_with_scheme`].
    ///
    /// # Errors
    /// Transport failure.
    fn puk_status(&mut self) -> Result<PukStatus, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.puk_status_with_scheme(PinReferenceScheme::Citizen)
    }

    /// Read the PUK retry counter under `scheme` without presenting a
    /// PUK.
    ///
    /// The citizen card reads the PUK PIN-container object with
    /// `GET DATA` (FINEID S1 v4.2 §3.15). The organization card answers
    /// the counter-safe VERIFY status probe under its PUK reference
    /// (ISO 7816-4 §7.5.6). Neither carries credential data or
    /// decrements a retry or usage counter.
    ///
    /// # Errors
    /// Transport failure.
    fn puk_status_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
    ) -> Result<PukStatus, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        if scheme == PinReferenceScheme::Organizational {
            let sw = self.probe_status_word(CredentialReference::Puk(scheme))?;
            return Ok(classify_puk_status_sw(sw));
        }
        let apdu = commands::GetPukInfo.into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        if r.is_ok() {
            return Ok(
                commands::PinInfoResponse::try_counter_from_response_body(&r.body)
                    .map_or(PukStatus::NoInfo, PukStatus::Remaining),
            );
        }
        Ok(classify_puk_status_sw(r.status_word()))
    }

    /// Read PIN1 or PIN2 usage and recovery allowances without
    /// presenting a credential or changing any card counter.
    ///
    /// # Errors
    /// Transport failure while querying the card.
    fn pin_policy_counters(
        &mut self,
        slot: PinSlot,
    ) -> Result<Option<CredentialPolicyCounters>, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::GetPinInfo {
            scheme: PinReferenceScheme::Citizen,
            slot,
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        if !r.is_ok() {
            return Ok(None);
        }
        Ok(commands::PinInfoResponse::policy_counters_from_response_body(&r.body))
    }

    /// Read shared-PUK usage and recovery allowances without
    /// presenting the PUK or changing any card counter.
    ///
    /// # Errors
    /// Transport failure while querying the card.
    fn puk_policy_counters(
        &mut self,
    ) -> Result<Option<CredentialPolicyCounters>, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::GetPukInfo.into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        if !r.is_ok() {
            return Ok(None);
        }
        Ok(commands::PinInfoResponse::policy_counters_from_response_body(&r.body))
    }

    /// The FINEID "PIN changed" flag for `slot` under the citizen
    /// numbering; see [`PinOps::pin_changed_flag_with_scheme`].
    ///
    /// # Errors
    /// Transport failure only.
    fn pin_changed_flag(&mut self, slot: PinSlot) -> Result<Option<bool>, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.pin_changed_flag_with_scheme(PinReferenceScheme::Citizen, slot)
    }

    /// Probe the FINEID "PIN changed" flag for `slot` under `scheme`
    /// per S1 v4.2 §3.15.2 Table 19 (`DF 2F 01 xx`).
    ///
    /// Returns:
    /// - `Ok(Some(true))` if the PIN has been changed since
    ///   manufacture,
    /// - `Ok(Some(false))` if it is still at the factory value,
    /// - `Ok(None)` for any card response that did not yield a
    ///   parseable `DF 2F` flag: a non-success status word, or a
    ///   response body without the DF2F TLV (the card returns the
    ///   flag only if the "Return PIN changed flag" parameter was set
    ///   at personalization, S1 v4.2 §3.15.2 below Table 16).
    ///
    /// Side effects: **none**. Counter-safe -- neither the PIN try
    /// counter nor the PIN usage counter is decremented. Same
    /// risk profile as [`PinOps::pin_status`].
    ///
    /// # Errors
    /// Transport failure only. Non-success status words are
    /// absorbed into the `Ok(None)` arm: the card gave no flag.
    fn pin_changed_flag_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
        slot: PinSlot,
    ) -> Result<Option<bool>, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::GetPinInfo { scheme, slot }.into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        if !r.is_ok() {
            return Ok(None);
        }
        Ok(commands::PinInfoResponse::changed_flag_from_response_body(
            &r.body,
        ))
    }
}

impl<T: CardTransport + ?Sized> PinOps for T {}

/// Outcome of a `CHANGE REFERENCE DATA` (PIN rotation) round trip.
///
/// On `Ok`, the target PIN's retry counter is reset to its maximum
/// and the PIN's reference value has been replaced with `new_pin`.
/// Per IAS-ECC §9.4.2 the card clears the PIN-presentation flag as
/// part of the rotation: callers that want continued access to
/// PIN-protected ops MUST re-VERIFY with the new PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangePinOutcome {
    /// `SW = 0x9000` -- PIN replaced, retry counter reset, PIN
    /// presentation cleared (a fresh VERIFY is required next).
    Ok,
    /// `SW = 0x63CX` -- current PIN was wrong, `X` retries left.
    WrongCurrentPin {
        /// Number of attempts remaining before the slot locks.
        retries_left: PinRetries,
    },
    /// `SW = 0x6983` / `0x6984` -- card is blocked or PIN usage
    /// counter exhausted; PUK-driven unblock is the only recovery.
    Locked,
    /// `SW = 0x6700` -- Lc / data-field length didn't match the
    /// card's stored-length expectation. Indicates a host bug.
    LengthError,
    /// Anything else -- surfaced as opaque SW for the caller.
    Other(u16),
}

/// Outcome of a `RESET RETRY COUNTER` (PUK-driven unblock) round
/// trip.
///
/// On `Ok`, the target PIN's retry counter is reset to its max
/// AND the PIN's reference value has been replaced with the
/// caller-supplied `new_pin`. The card is **not** left in a
/// PIN-presentation-satisfied state -- callers must VERIFY the new
/// PIN before any PIN-protected operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnblockOutcome {
    /// `SW = 0x9000` -- PUK accepted, target PIN reset to the new
    /// value, PIN's retry counter back to its maximum.
    Ok,
    /// `SW = 0x63CX` -- PUK was wrong, `X` retries left on the PUK
    /// itself. When `X = 0` the next failure exhausts the PUK try
    /// counter and the card becomes permanently unrecoverable
    /// (DVV reissue required).
    WrongPuk {
        /// Number of PUK attempts remaining before the card
        /// becomes unrecoverable (the PUK try counter is
        /// `X` after the failure).
        retries_left: PinRetries,
    },
    /// `SW = 0x6983` -- the PUK itself is blocked. No software
    /// recovery; the card is dead.
    PukLocked,
    /// `SW = 0x6984` -- the target PIN's unblocking counter is
    /// exhausted, *or* the PUK's try/usage counter has reached
    /// zero. Both terminal -- card needs DVV reissue.
    Invalidated,
    /// `SW = 0x6700` -- Lc / data-field length mismatch.
    /// Indicates a host bug.
    LengthError,
    /// Anything else -- surface as opaque SW for the caller.
    Other(u16),
}

// `change_pin` / `reset_retry_counter` are methods on [`PinOps`].
// See the trait definition above.

/// Decode the RESET RETRY COUNTER response status word.
#[must_use]
pub const fn classify_reset_retry_sw(sw: StatusWord) -> UnblockOutcome {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "catch-and-wrap: UnblockOutcome::Other(u16) absorbs unenumerated card status words verbatim; enumerating every StatusWord variant would duplicate the StatusWord::Other(u16) escape hatch already documented on the source enum."
    )]
    match sw {
        StatusWord::Success => UnblockOutcome::Ok,
        StatusWord::PinIncorrect { retries } => UnblockOutcome::WrongPuk {
            retries_left: retries,
        },
        StatusWord::AuthenticationBlocked => UnblockOutcome::PukLocked,
        StatusWord::ReferenceDataInvalidated => UnblockOutcome::Invalidated,
        StatusWord::WrongLength => UnblockOutcome::LengthError,
        other => UnblockOutcome::Other(other.as_u16()),
    }
}

/// Decode the counter-safe PUK retry-query response.
#[must_use]
pub const fn classify_puk_status_sw(sw: StatusWord) -> PukStatus {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "PukStatus::Other preserves unenumerated card status words."
    )]
    match sw {
        StatusWord::PinIncorrect { retries } => PukStatus::Remaining(retries),
        StatusWord::AuthenticationFailed => PukStatus::NoInfo,
        StatusWord::AuthenticationBlocked => PukStatus::Locked,
        StatusWord::ReferenceDataInvalidated => PukStatus::Invalidated,
        other => PukStatus::Other(other.as_u16()),
    }
}

/// Decode the CHANGE REFERENCE DATA response status word.
#[must_use]
pub const fn classify_change_pin_sw(sw: StatusWord) -> ChangePinOutcome {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "catch-and-wrap: ChangePinOutcome::Other(u16) absorbs unenumerated card status words verbatim; enumerating every StatusWord variant would duplicate the StatusWord::Other(u16) escape hatch already documented on the source enum."
    )]
    match sw {
        StatusWord::Success => ChangePinOutcome::Ok,
        StatusWord::PinIncorrect { retries } => ChangePinOutcome::WrongCurrentPin {
            retries_left: retries,
        },
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            ChangePinOutcome::Locked
        }
        StatusWord::WrongLength => ChangePinOutcome::LengthError,
        other => ChangePinOutcome::Other(other.as_u16()),
    }
}

// `pin_status` is a method on [`PinOps`]. See the trait definition
// above.

/// Decode the VERIFY (status-check) response status word.
#[must_use]
pub const fn classify_pin_status_sw(sw: StatusWord) -> PinStatus {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "catch-and-wrap: PinStatus::Other(u16) absorbs unenumerated card status words verbatim; enumerating every StatusWord variant would duplicate the StatusWord::Other(u16) escape hatch already documented on the source enum."
    )]
    match sw {
        StatusWord::Success => PinStatus::Verified,
        StatusWord::PinIncorrect { retries } => PinStatus::Remaining(retries),
        StatusWord::AuthenticationFailed => PinStatus::NoInfo,
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            PinStatus::Locked
        }
        other => PinStatus::Other(other.as_u16()),
    }
}

/// Decode the VERIFY response status word into an outcome. Public
/// so other paths (e.g. signing) can classify a PIN-state status
/// word they get back from an unrelated operation.
#[must_use]
pub const fn classify_verify_sw(sw: StatusWord) -> VerifyOutcome {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "catch-and-wrap: VerifyOutcome::Other(u16) absorbs unenumerated card status words verbatim; enumerating every StatusWord variant would duplicate the StatusWord::Other(u16) escape hatch already documented on the source enum."
    )]
    match sw {
        StatusWord::Success => VerifyOutcome::Ok,
        StatusWord::PinIncorrect { retries } => VerifyOutcome::WrongPin {
            retries_left: retries,
        },
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            VerifyOutcome::Locked
        }
        other => VerifyOutcome::Other(other.as_u16()),
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
    use crate::pkcs15::esign_wire;
    use crate::transport::{CommandApdu, ResponseApdu, TransportOutcome};

    struct MockTx {
        expected: Vec<u8>,
        response: ResponseApdu,
        seen: bool,
    }
    impl CardTransport for MockTx {
        type Error = String;
        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            assert_eq!(apdu.as_bytes(), self.expected.as_slice(), "APDU mismatch");
            self.seen = true;
            Ok(TransportOutcome::Response(self.response.clone()))
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    fn ok() -> ResponseApdu {
        ResponseApdu {
            body: vec![],
            sw1: 0x90,
            sw2: 0x00,
        }
    }
    fn sw(sw1: u8, sw2: u8) -> ResponseApdu {
        ResponseApdu {
            body: vec![],
            sw1,
            sw2,
        }
    }
    fn pb<const N: usize>(bytes: &[u8; N]) -> PinBytes {
        PinBytes::try_from(*bytes).expect("valid test PIN")
    }

    #[test]
    fn pin1_padded_to_stored_length() {
        // ASCII "1234" + 8 bytes 0x00 padding = 12 bytes.
        let mut expected = vec![0x00, 0x20, 0x00, 0x11, 0x0C];
        expected.extend_from_slice(b"1234");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .verify_pin1(pb(b"1234"))
            .expect("padded PIN1 verify succeeds");
        assert_eq!(outcome, VerifyOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn pin2_uses_reference_82() {
        let mut expected = vec![0x00, 0x20, 0x00, 0x82, 0x0C];
        expected.extend_from_slice(b"123456");
        expected.extend_from_slice(&[0x00; 6]);
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .verify_pin(PinSlot::Pin2, pb(b"123456"))
            .expect("PIN2 verify succeeds");
        assert_eq!(outcome, VerifyOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn puk_status_probe_returns_counter_without_credential_data() {
        const PLAIN_CLASS: u8 = 0x00;
        const GET_DATA_INSTRUCTION: u8 = 0xCB;
        const GET_DATA_P1: u8 = 0x00;
        const GET_DATA_P2: u8 = 0xFF;
        const PIN_TEMPLATE_LENGTH: u8 = 0x05;
        const PIN_TEMPLATE_TAG: u8 = 0xA0;
        const PIN_TEMPLATE_VALUE_LENGTH: u8 = 0x03;
        const PIN_REFERENCE_TAG: u8 = 0x83;
        const PIN_REFERENCE_LENGTH: u8 = 0x01;
        const PUK_REFERENCE: u8 = 0x83;
        const MAX_RESPONSE_LENGTH: u8 = 0x00;
        const PIN_ATTRIBUTES_TAG_HI: u8 = 0xDF;
        const PIN_ATTRIBUTES_TAG_LO: u8 = 0x21;
        const PIN_ATTRIBUTES_LENGTH: u8 = 0x04;
        const FOUR_RETRIES: u8 = 0x04;
        const UNLIMITED_USAGE: u8 = 0xFF;
        const NO_UNBLOCKING: u8 = 0x00;
        const SUCCESS_STATUS_HI: u8 = 0x90;
        const SUCCESS_STATUS_LO: u8 = 0x00;

        let mut tx = MockTx {
            expected: vec![
                PLAIN_CLASS,
                GET_DATA_INSTRUCTION,
                GET_DATA_P1,
                GET_DATA_P2,
                PIN_TEMPLATE_LENGTH,
                PIN_TEMPLATE_TAG,
                PIN_TEMPLATE_VALUE_LENGTH,
                PIN_REFERENCE_TAG,
                PIN_REFERENCE_LENGTH,
                PUK_REFERENCE,
                MAX_RESPONSE_LENGTH,
            ],
            response: ResponseApdu {
                body: vec![
                    PIN_ATTRIBUTES_TAG_HI,
                    PIN_ATTRIBUTES_TAG_LO,
                    PIN_ATTRIBUTES_LENGTH,
                    FOUR_RETRIES,
                    UNLIMITED_USAGE,
                    NO_UNBLOCKING,
                    NO_UNBLOCKING,
                ],
                sw1: SUCCESS_STATUS_HI,
                sw2: SUCCESS_STATUS_LO,
            },
            seen: false,
        };
        let outcome = tx.puk_status().expect("PUK counter probe succeeds");
        let four = PinRetries::from_nibble(4).expect("nibble");
        assert_eq!(outcome, PukStatus::Remaining(four));
        assert!(tx.seen);
    }

    #[test]
    fn wrong_pin_with_retries_classified() {
        let mut expected = vec![0x00, 0x20, 0x00, 0x11, 0x0C];
        expected.extend_from_slice(b"9999");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: sw(0x63, 0xC2),
            seen: false,
        };
        let outcome = tx
            .verify_pin1(pb(b"9999"))
            .expect("wrong-PIN verify still returns an outcome");
        let two = PinRetries::from_nibble(2).expect("nibble");
        assert_eq!(outcome, VerifyOutcome::WrongPin { retries_left: two });
    }

    #[test]
    fn locked_sw_classified() {
        let mut expected = vec![0x00, 0x20, 0x00, 0x11, 0x0C];
        expected.extend_from_slice(b"1234");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: sw(0x69, 0x83),
            seen: false,
        };
        let outcome = tx
            .verify_pin1(pb(b"1234"))
            .expect("locked-card verify still returns an outcome");
        assert_eq!(outcome, VerifyOutcome::Locked);
    }

    #[test]
    fn other_sw_passes_through() {
        assert_eq!(
            classify_verify_sw(StatusWord::from_u16(0x6A82)),
            VerifyOutcome::Other(0x6A82)
        );
        assert_eq!(
            classify_verify_sw(StatusWord::from_u16(0x9000)),
            VerifyOutcome::Ok
        );
        let zero = PinRetries::from_nibble(0).expect("nibble");
        assert_eq!(
            classify_verify_sw(StatusWord::from_u16(0x63C0)),
            VerifyOutcome::WrongPin { retries_left: zero }
        );
    }

    #[test]
    fn puk_status_classifies_terminal_states() {
        const AUTHENTICATION_BLOCKED: u16 = 0x6983;
        const REFERENCE_DATA_INVALIDATED: u16 = 0x6984;

        assert_eq!(
            classify_puk_status_sw(StatusWord::from_u16(AUTHENTICATION_BLOCKED)),
            PukStatus::Locked
        );
        assert_eq!(
            classify_puk_status_sw(StatusWord::from_u16(REFERENCE_DATA_INVALIDATED)),
            PukStatus::Invalidated
        );
    }

    struct ShouldNotTransmitTx;
    impl CardTransport for ShouldNotTransmitTx {
        type Error = String;
        fn transmit_outcome(
            &mut self,
            _apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            panic!("transport must not be touched on local-policy rejection");
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    /// The FINEID bounds under the citizen numbering.
    fn citizen_lengths() -> CardPinLengths {
        CardPinLengths::not_listed(PinReferenceScheme::Citizen)
    }

    #[test]
    fn four_digit_pin2_goes_to_the_card() {
        let mut tx = RecordingTx::new(&[StatusWord::Success]);
        let outcome = tx
            .verify_pin(PinSlot::Pin2, pb(b"1234"))
            .expect("a four-digit PIN 2 is sent; the card decides");
        assert_eq!(outcome, VerifyOutcome::Ok);
        assert_eq!(tx.sent.len(), ONE_COMMAND);
    }

    #[test]
    fn change_pin1_apdu_layout_4_to_4_digit() {
        // change_pin is policy-light: 1234 -> 4321 is wire-shape-
        // valid and the card sees the APDU. PIN quality is the
        // citizen's call -- lib-core ships no strength policy.
        // 00 24 00 11 18  <12B current-padded || 12B new-padded>
        let mut expected = vec![0x00, 0x24, 0x00, 0x11, 0x18];
        expected.extend_from_slice(b"1234");
        expected.extend_from_slice(&[0x00; 8]);
        expected.extend_from_slice(b"4321");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .change_pin(&citizen_lengths(), PinSlot::Pin1, pb(b"1234"), pb(b"4321"))
            .expect("PIN1 change succeeds");
        assert_eq!(outcome, ChangePinOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn change_pin1_wrong_current_classified() {
        let mut expected = vec![0x00, 0x24, 0x00, 0x11, 0x18];
        expected.extend_from_slice(b"9999");
        expected.extend_from_slice(&[0x00; 8]);
        expected.extend_from_slice(b"4321");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: sw(0x63, 0xC2),
            seen: false,
        };
        let outcome = tx
            .change_pin(&citizen_lengths(), PinSlot::Pin1, pb(b"9999"), pb(b"4321"))
            .expect("wrong-current-PIN change still returns an outcome");
        let two = PinRetries::from_nibble(2).expect("nibble");
        assert_eq!(
            outcome,
            ChangePinOutcome::WrongCurrentPin { retries_left: two }
        );
    }

    #[test]
    fn change_pin1_accepts_weak_new_pin() {
        // 1234 -> 1234 same-as-old is wire-shape-valid; lib-core
        // doesn't reject it -- no strength policy in the library.
        let mut expected = vec![0x00, 0x24, 0x00, 0x11, 0x18];
        expected.extend_from_slice(b"1234");
        expected.extend_from_slice(&[0x00; 8]);
        expected.extend_from_slice(b"1234");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .change_pin(&citizen_lengths(), PinSlot::Pin1, pb(b"1234"), pb(b"1234"))
            .expect("weak new PIN is accepted by the library");
        assert_eq!(outcome, ChangePinOutcome::Ok);
    }

    #[test]
    fn change_pin_sw_classification() {
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(0x9000)),
            ChangePinOutcome::Ok
        );
        let three = PinRetries::from_nibble(3).expect("nibble");
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(0x63C3)),
            ChangePinOutcome::WrongCurrentPin {
                retries_left: three
            }
        );
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(0x6983)),
            ChangePinOutcome::Locked
        );
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(0x6700)),
            ChangePinOutcome::LengthError
        );
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(0x6A82)),
            ChangePinOutcome::Other(0x6A82)
        );
    }

    #[test]
    fn pin_status_sends_empty_lc_verify() {
        // 00 20 00 11 00 -- empty Lc form, no body. Counter-safe.
        let mut tx = MockTx {
            expected: vec![0x00, 0x20, 0x00, 0x11, 0x00],
            response: sw(0x63, 0xC3),
            seen: false,
        };
        let status = tx
            .pin_status(PinSlot::Pin1)
            .expect("PIN1 status query succeeds");
        let three = PinRetries::from_nibble(3).expect("nibble");
        assert_eq!(status, PinStatus::Remaining(three));
        assert!(tx.seen);
    }

    #[test]
    fn pin_status_verified() {
        let mut tx = MockTx {
            expected: vec![0x00, 0x20, 0x00, 0x11, 0x00],
            response: ok(),
            seen: false,
        };
        let status = tx
            .pin_status(PinSlot::Pin1)
            .expect("PIN1 status query succeeds");
        assert_eq!(status, PinStatus::Verified);
    }

    #[test]
    fn pin_status_pin2_uses_reference_82() {
        let mut tx = MockTx {
            expected: vec![0x00, 0x20, 0x00, 0x82, 0x00],
            response: sw(0x63, 0xC2),
            seen: false,
        };
        let status = tx
            .pin_status(PinSlot::Pin2)
            .expect("PIN2 status query succeeds");
        let two = PinRetries::from_nibble(2).expect("nibble");
        assert_eq!(status, PinStatus::Remaining(two));
    }

    #[test]
    fn pin_status_sw_classification() {
        let five = PinRetries::from_nibble(5).expect("nibble");
        let zero = PinRetries::from_nibble(0).expect("nibble");
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x9000)),
            PinStatus::Verified
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x63C5)),
            PinStatus::Remaining(five)
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x63C0)),
            PinStatus::Remaining(zero)
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x6300)),
            PinStatus::NoInfo
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x6983)),
            PinStatus::Locked
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x6984)),
            PinStatus::Locked
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x6A82)),
            PinStatus::Other(0x6A82)
        );
    }

    #[test]
    fn unblock_pin1_apdu_layout_8puk_4pin() {
        // 00 2C 00 11 18  <12B PUK-padded || 12B new-PIN-padded>
        let mut expected = vec![0x00, 0x2C, 0x00, 0x11, 0x18];
        expected.extend_from_slice(b"12345678");
        expected.extend_from_slice(&[0x00; 4]);
        expected.extend_from_slice(b"4321");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .reset_retry_counter(
                &citizen_lengths(),
                PinSlot::Pin1,
                pb(b"12345678"),
                pb(b"4321"),
            )
            .expect("PIN1 unblock succeeds");
        assert_eq!(outcome, UnblockOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn unblock_pin1_apdu_layout_12puk_4pin() {
        const PLAIN_CLASS: u8 = 0x00;
        const RESET_RETRY_COUNTER_INSTRUCTION: u8 = 0x2C;
        const RESET_AND_REPLACE_MODE: u8 = 0x00;
        const PADDED_PAIR_LENGTH: u8 = 0x18;
        const PAD_BYTE: u8 = 0x00;
        let mut expected = vec![
            PLAIN_CLASS,
            RESET_RETRY_COUNTER_INSTRUCTION,
            RESET_AND_REPLACE_MODE,
            PIN1_REFERENCE_PKCS15,
            PADDED_PAIR_LENGTH,
        ];
        expected.extend_from_slice(b"490712349071");
        expected.extend_from_slice(b"4907");
        expected.extend_from_slice(&[PAD_BYTE; 8]);
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .reset_retry_counter(
                &citizen_lengths(),
                PinSlot::Pin1,
                pb(b"490712349071"),
                pb(b"4907"),
            )
            .expect("twelve-digit PUK reaches PIN1 unblock");
        assert_eq!(outcome, UnblockOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn unblock_pin1_wrong_puk_classified() {
        let mut expected = vec![0x00, 0x2C, 0x00, 0x11, 0x18];
        expected.extend_from_slice(b"99999999");
        expected.extend_from_slice(&[0x00; 4]);
        expected.extend_from_slice(b"4321");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: sw(0x63, 0xC4),
            seen: false,
        };
        let outcome = tx
            .reset_retry_counter(
                &citizen_lengths(),
                PinSlot::Pin1,
                pb(b"99999999"),
                pb(b"4321"),
            )
            .expect("wrong-PUK unblock still returns an outcome");
        let four = PinRetries::from_nibble(4).expect("nibble");
        assert_eq!(outcome, UnblockOutcome::WrongPuk { retries_left: four });
    }

    #[test]
    fn unblock_pin1_short_puk_rejected_locally() {
        let mut tx = ShouldNotTransmitTx;
        let err = tx
            .reset_retry_counter(
                &citizen_lengths(),
                PinSlot::Pin1,
                pb(b"123456"),
                pb(b"4321"),
            )
            .expect_err("short PUK is rejected locally");
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "PinPolicyReason is #[non_exhaustive]; an explicit catch-all is required by the language to match nested non-WrongLength variants."
        )]
        match err {
            AuthError::PinPolicy(PinPolicyReason::WrongLength { got, min, max }) => {
                assert_eq!(got, 6);
                assert_eq!(min, PUK_MIN_LENGTH);
                assert_eq!(max, PUK_MAX_LENGTH);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn unblock_pin1_seven_digit_puk_rejected_locally() {
        let mut tx = ShouldNotTransmitTx;
        let err = tx
            .reset_retry_counter(
                &citizen_lengths(),
                PinSlot::Pin1,
                pb(b"1234567"),
                pb(b"4321"),
            )
            .expect_err("a seven-digit code is not a PUK");
        assert!(matches!(
            err,
            AuthError::PinPolicy(PinPolicyReason::WrongLength {
                got: 7,
                min: PUK_MIN_LENGTH,
                max: PUK_MAX_LENGTH
            })
        ));
    }

    #[test]
    fn reset_retry_sw_classification() {
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(0x9000)),
            UnblockOutcome::Ok
        );
        let three = PinRetries::from_nibble(3).expect("nibble");
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(0x63C3)),
            UnblockOutcome::WrongPuk {
                retries_left: three
            }
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(0x6983)),
            UnblockOutcome::PukLocked
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(0x6984)),
            UnblockOutcome::Invalidated
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(0x6700)),
            UnblockOutcome::LengthError
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(0x6A82)),
            UnblockOutcome::Other(0x6A82)
        );
    }

    /// Records every command and answers each with the next status word.
    struct RecordingTx {
        answers: Vec<StatusWord>,
        sent: Vec<Vec<u8>>,
    }

    impl RecordingTx {
        fn new(answers: &[StatusWord]) -> Self {
            Self {
                answers: answers.iter().rev().copied().collect(),
                sent: Vec::new(),
            }
        }
    }

    impl CardTransport for RecordingTx {
        type Error = String;
        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            self.sent.push(apdu.as_bytes().to_vec());
            let status = self.answers.pop().ok_or("no answer scripted")?;
            let [sw1, sw2] = status.as_u16().to_be_bytes();
            Ok(TransportOutcome::Response(ResponseApdu {
                body: vec![],
                sw1,
                sw2,
            }))
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    /// Offset of the instruction byte in a command.
    const INS_INDEX: usize = 1;
    /// Offset of P1 in a command.
    const P1_INDEX: usize = 2;
    /// Offset of P2 in a command.
    const P2_INDEX: usize = 3;
    /// Offset of the first data byte in a short command.
    const DATA_INDEX: usize = 5;
    /// Index of the first recorded command.
    const FIRST: usize = 0;
    /// Index of the second recorded command.
    const SECOND: usize = 1;
    /// Index of the fourth recorded command.
    const FOURTH: usize = 3;
    /// Index of the fifth recorded command.
    const FIFTH: usize = 4;
    /// SELECT MF, SELECT DF.ESIGN and VERIFY: the commands an
    /// organizational PIN 2 VERIFY sends.
    const ESIGN_ENTRY_AND_VERIFY: usize = 3;
    /// One command sent.
    const ONE_COMMAND: usize = 1;
    /// Three commands sent.
    const THREE_COMMANDS: usize = 3;
    /// A counter with no tries left.
    const NO_TRIES: u8 = 0;
    /// A counter with two tries left.
    const TWO_TRIES: u8 = 2;
    /// A counter with three tries left.
    const THREE_TRIES: u8 = 3;
    /// A full counter.
    const FULL_COUNTER: u8 = 5;
    /// Synthetic organization PUK.
    const ORG_PUK: &[u8] = b"00000000";
    /// Synthetic current PIN.
    const ORG_CURRENT: &[u8] = b"0000";
    /// Synthetic new PIN.
    const ORG_NEW: &[u8] = b"111111";

    fn secret(digits: &[u8]) -> PinBytes {
        PinBytes::new(digits.to_vec()).expect("synthetic digits")
    }

    #[test]
    fn citizen_numbering_resolves_on_a_citizen_pin1_answer() {
        let three = PinRetries::from_nibble(THREE_TRIES).expect("nibble");
        let mut tx = RecordingTx::new(&[StatusWord::PinIncorrect { retries: three }]);
        assert_eq!(
            tx.resolve_pin_reference_scheme().expect("resolves"),
            PinReferenceScheme::Citizen
        );
        assert_eq!(tx.sent.len(), ONE_COMMAND);
        assert_eq!(tx.sent[FIRST][P2_INDEX], PIN1_REFERENCE_PKCS15);
    }

    #[test]
    fn organization_numbering_resolves_after_reference_data_not_found() {
        let none_left = PinRetries::from_nibble(NO_TRIES).expect("nibble");
        let mut tx = RecordingTx::new(&[
            StatusWord::ReferenceDataNotFound,
            StatusWord::PinIncorrect { retries: none_left },
        ]);
        assert_eq!(
            tx.resolve_pin_reference_scheme().expect("resolves"),
            PinReferenceScheme::Organizational
        );
        assert_eq!(tx.sent[FIRST][P2_INDEX], PIN1_REFERENCE_PKCS15);
        assert_eq!(tx.sent[SECOND][P2_INDEX], PIN1_REFERENCE_ORGANIZATIONAL);
    }

    #[test]
    fn organization_change_sends_bare_blocks_under_the_organization_reference() {
        let mut tx = RecordingTx::new(&[StatusWord::Success]);
        let outcome = tx
            .change_pin(
                &CardPinLengths::not_listed(PinReferenceScheme::Organizational),
                PinSlot::Pin1,
                secret(ORG_CURRENT),
                secret(ORG_NEW),
            )
            .expect("sent");
        assert_eq!(outcome, ChangePinOutcome::Ok);
        let command = &tx.sent[FIRST];
        assert_eq!(command[INS_INDEX], commands::ChangeReferenceData::INS);
        assert_eq!(command[P2_INDEX], PIN1_REFERENCE_ORGANIZATIONAL);
        let mut expected = ORG_CURRENT.to_vec();
        expected.extend_from_slice(ORG_NEW);
        assert_eq!(&command[DATA_INDEX..], expected.as_slice());
    }

    #[test]
    fn organization_unblock_verifies_the_puk_then_resets_with_the_new_pin_only() {
        let mut tx = RecordingTx::new(&[StatusWord::Success, StatusWord::Success]);
        let outcome = tx
            .reset_retry_counter(
                &CardPinLengths::not_listed(PinReferenceScheme::Organizational),
                PinSlot::Pin2,
                secret(ORG_PUK),
                secret(ORG_NEW),
            )
            .expect("sent");
        assert_eq!(outcome, UnblockOutcome::Ok);
        let verify = &tx.sent[FIRST];
        assert_eq!(verify[INS_INDEX], commands::Verify::INS);
        assert_eq!(verify[P2_INDEX], PUK_REFERENCE_ORGANIZATIONAL);
        assert_eq!(&verify[DATA_INDEX..], ORG_PUK);
        let reset = &tx.sent[SECOND];
        assert_eq!(reset[INS_INDEX], commands::ResetRetryCounter::INS);
        assert_eq!(
            reset[P1_INDEX],
            commands::ResetRetryCounterMode::NewOnly.as_p1()
        );
        assert_eq!(reset[P2_INDEX], PIN2_REFERENCE_ORGANIZATIONAL);
        assert_eq!(&reset[DATA_INDEX..], ORG_NEW);
    }

    #[test]
    fn organization_unblock_stops_when_the_puk_is_refused() {
        let two = PinRetries::from_nibble(TWO_TRIES).expect("nibble");
        let mut tx = RecordingTx::new(&[StatusWord::PinIncorrect { retries: two }]);
        let outcome = tx
            .reset_retry_counter(
                &CardPinLengths::not_listed(PinReferenceScheme::Organizational),
                PinSlot::Pin1,
                secret(ORG_PUK),
                secret(ORG_NEW),
            )
            .expect("sent");
        assert_eq!(outcome, UnblockOutcome::WrongPuk { retries_left: two });
        assert_eq!(tx.sent.len(), ONE_COMMAND, "no reset after a refused PUK");
    }

    #[test]
    fn a_card_listing_nothing_takes_the_fineid_bounds() {
        let three = PinRetries::from_nibble(THREE_TRIES).expect("nibble");
        // PIN 1 probe answers under the citizen numbering; SELECT of the
        // PKCS#15 application is refused, and so is every PIN container.
        let mut tx = RecordingTx::new(&[
            StatusWord::PinIncorrect { retries: three },
            StatusWord::FileNotFound,
            StatusWord::ReferenceDataNotFound,
            StatusWord::ReferenceDataNotFound,
            StatusWord::ReferenceDataNotFound,
        ]);
        let lengths = tx.read_card_pin_lengths().expect("read");
        assert_eq!(lengths, citizen_lengths());
    }

    #[test]
    fn an_organization_card_is_not_asked_for_its_pin_policy() {
        let none_left = PinRetries::from_nibble(NO_TRIES).expect("nibble");
        let mut tx = RecordingTx::new(&[
            StatusWord::ReferenceDataNotFound,
            StatusWord::PinIncorrect { retries: none_left },
            StatusWord::FileNotFound,
        ]);
        let lengths = tx.read_card_pin_lengths().expect("read");
        assert_eq!(
            lengths,
            CardPinLengths::not_listed(PinReferenceScheme::Organizational)
        );
        assert_eq!(tx.sent.len(), THREE_COMMANDS);
    }

    #[test]
    fn a_new_pin_outside_the_card_range_is_refused_before_any_command() {
        let mut tx = ShouldNotTransmitTx;
        let error = tx
            .change_pin(
                &citizen_lengths(),
                PinSlot::Pin2,
                secret(ORG_NEW),
                secret(ORG_CURRENT),
            )
            .expect_err("a four-digit PIN 2 is outside the FINEID bounds");
        assert!(matches!(
            error,
            AuthError::PinPolicy(PinPolicyReason::WrongLength {
                min: FINEID_PIN2_MIN_LENGTH,
                max: PIN_MAX_LENGTH,
                ..
            })
        ));
    }

    /// Synthetic PIN of `len` digits.
    fn digits(len: usize) -> Vec<u8> {
        vec![b'0'; len]
    }

    #[test]
    fn organization_verify_sends_twelve_bare_digits_for_both_pins() {
        for slot in [PinSlot::Pin1, PinSlot::Pin2] {
            let pin = digits(slot.stored_length());
            let mut tx = RecordingTx::new(&[StatusWord::Success; ESIGN_ENTRY_AND_VERIFY]);
            let outcome = tx
                .verify_pin_with_scheme(PinReferenceScheme::Organizational, slot, secret(&pin))
                .expect("sent");
            assert_eq!(outcome, VerifyOutcome::Ok);
            let command = tx.sent.last().expect("VERIFY sent");
            assert_eq!(command[INS_INDEX], commands::Verify::INS);
            assert_eq!(
                command[P2_INDEX],
                PinReferenceScheme::Organizational.reference(slot)
            );
            assert_eq!(&command[DATA_INDEX..], pin.as_slice());
        }
    }

    #[test]
    fn organization_pin2_verify_enters_esign_first() {
        let pin = digits(PIN2_STORED_LENGTH);
        let mut tx = RecordingTx::new(&[StatusWord::Success; ESIGN_ENTRY_AND_VERIFY]);
        let outcome = tx
            .verify_pin_with_scheme(
                PinReferenceScheme::Organizational,
                PinSlot::Pin2,
                secret(&pin),
            )
            .expect("sent");
        assert_eq!(outcome, VerifyOutcome::Ok);
        let verify = commands::Verify {
            class: ApduClass::Plain,
            mode: commands::VerifyMode::Verify,
            reference: CredentialReference::Pin(PinReferenceScheme::Organizational, PinSlot::Pin2),
            data: commands::VerifyData::PinBlock(pin),
        }
        .into_apdu()
        .as_bytes()
        .to_vec();
        assert_eq!(
            tx.sent,
            vec![
                esign_wire::select_mf().into_bytes(),
                esign_wire::select_esign_by_name().into_bytes(),
                verify,
            ]
        );
    }

    #[test]
    fn organization_pin2_falls_back_to_the_esign_identifier() {
        let mut tx = RecordingTx::new(&[
            StatusWord::Success,
            StatusWord::FileNotFound,
            StatusWord::FileNotFound,
            StatusWord::Success,
            StatusWord::Success,
        ]);
        let outcome = tx
            .verify_pin_with_scheme(
                PinReferenceScheme::Organizational,
                PinSlot::Pin2,
                secret(&digits(PIN2_STORED_LENGTH)),
            )
            .expect("sent");
        assert_eq!(outcome, VerifyOutcome::Ok);
        assert_eq!(
            tx.sent[SECOND],
            esign_wire::select_esign_by_name().into_bytes()
        );
        assert_eq!(
            tx.sent[FOURTH],
            esign_wire::select_esign_any_by_fid().into_bytes()
        );
        assert_eq!(tx.sent[FIFTH][INS_INDEX], commands::Verify::INS);
    }

    #[test]
    fn organization_pin2_is_not_presented_outside_esign() {
        let mut tx = RecordingTx::new(&[
            StatusWord::Success,
            StatusWord::FileNotFound,
            StatusWord::FileNotFound,
            StatusWord::FileNotFound,
        ]);
        let outcome = tx
            .verify_pin_with_scheme(
                PinReferenceScheme::Organizational,
                PinSlot::Pin2,
                secret(&digits(PIN2_STORED_LENGTH)),
            )
            .expect("a refused SELECT is an outcome");
        assert_eq!(
            outcome,
            VerifyOutcome::Other(StatusWord::FileNotFound.as_u16())
        );
        assert!(
            tx.sent
                .iter()
                .all(|command| command[INS_INDEX] != commands::Verify::INS)
        );
    }

    #[test]
    fn citizen_pin2_verify_selects_nothing() {
        let mut tx = RecordingTx::new(&[StatusWord::Success]);
        let outcome = tx
            .verify_pin_with_scheme(
                PinReferenceScheme::Citizen,
                PinSlot::Pin2,
                secret(&digits(PIN2_STORED_LENGTH)),
            )
            .expect("sent");
        assert_eq!(outcome, VerifyOutcome::Ok);
        assert_eq!(tx.sent.len(), ONE_COMMAND);
        assert_eq!(tx.sent[FIRST][P2_INDEX], PIN2_REFERENCE_PKCS15);
    }

    #[test]
    fn organization_change_sends_twelve_bare_digits() {
        let current = digits(PIN2_STORED_LENGTH);
        let new = digits(PIN2_STORED_LENGTH);
        let mut tx = RecordingTx::new(&[StatusWord::Success]);
        tx.change_pin(
            &CardPinLengths::not_listed(PinReferenceScheme::Organizational),
            PinSlot::Pin2,
            secret(&current),
            secret(&new),
        )
        .expect("sent");
        let command = &tx.sent[FIRST];
        assert_eq!(command[P2_INDEX], PIN2_REFERENCE_ORGANIZATIONAL);
        let mut expected = current;
        expected.extend_from_slice(&new);
        assert_eq!(&command[DATA_INDEX..], expected.as_slice());
    }

    #[test]
    fn organization_unblock_resets_with_twelve_bare_digits() {
        let new = digits(PIN1_STORED_LENGTH);
        let mut tx = RecordingTx::new(&[StatusWord::Success, StatusWord::Success]);
        tx.reset_retry_counter(
            &CardPinLengths::not_listed(PinReferenceScheme::Organizational),
            PinSlot::Pin1,
            secret(ORG_PUK),
            secret(&new),
        )
        .expect("sent");
        let reset = &tx.sent[SECOND];
        assert_eq!(reset[P2_INDEX], PIN1_REFERENCE_ORGANIZATIONAL);
        assert_eq!(&reset[DATA_INDEX..], new.as_slice());
    }

    #[test]
    fn thirteen_digits_are_refused_before_any_command() {
        for slot in [PinSlot::Pin1, PinSlot::Pin2] {
            let long = digits(slot.stored_length().saturating_add(1));
            assert!(
                PinBytes::new(long).is_err(),
                "no PIN value, so no command, past the stored length"
            );
        }
    }

    #[test]
    fn organization_puk_status_probes_the_organization_puk_reference() {
        let five = PinRetries::from_nibble(FULL_COUNTER).expect("nibble");
        let mut tx = RecordingTx::new(&[StatusWord::PinIncorrect { retries: five }]);
        assert_eq!(
            tx.puk_status_with_scheme(PinReferenceScheme::Organizational)
                .expect("probed"),
            PukStatus::Remaining(five)
        );
        assert_eq!(tx.sent[FIRST][INS_INDEX], commands::Verify::INS);
        assert_eq!(tx.sent[FIRST][P2_INDEX], PUK_REFERENCE_ORGANIZATIONAL);
    }
}
