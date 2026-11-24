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

//! `refineid card change-pin{1,2}` / `card unblock-pin{1,2}` /
//! `card pin-status`.
//!
//! PIN-management surface for both FINEID PIN slots:
//! - PIN1 (auth) gates the auth key.
//! - PIN2 (qualified-signature) gates the QES key.
//!
//! The PUK unblocks either slot. Every command speaks the reference
//! numbering the card declares: the citizen numbering (FINEID S1 v4.2
//! §3.5.2) or the organization numbering (FINEID S4-2 v4.0 §4.2).
//!
//! PIN-bearing operations execute inside [`refineid_pcsc::PcscCard::pin_sequence`]
//! on a [`ReaderAccessCap::PinSequence`] session so one PC/SC transaction spans
//! the whole sequence and ends with a card reset.

use alloc::fmt;

use refineid_apdu::{CardTransport, StatusWord};
use refineid_auth::credentials::{CredentialRole, PIN_MAX_LENGTH, PIN_MIN_LENGTH};
use refineid_auth::{
    ActivationCode, ActivationScheme, AuthError, CardPinLengths, CredentialInputError,
    ManageOutcome, Pin1, Pin2, PinChangeRecord, PinLengthRefusal, PinManageOps as _, PinOps as _,
    PinReferenceScheme, PinSlot, PinStatus, Puk, RetryFloorRefusal, UnvalidatedSecret,
    check_retry_floor, pin_awaits_activation, read_pin_change_record,
};
use refineid_cms::x509::{DateTime, OwnedCert};
use refineid_lib_core::fineid_card::{CardClassificationError, FineidCardModel};
use refineid_lib_core::identity::CredentialIdentity;
use refineid_pcsc::{
    PcscBackend, PcscError, ReaderAccessCap, ReaderBackend as _, ReaderFilter, ReaderId,
    ReaderPickError,
};
use refineid_pkcs15::{CertSlot as CoreCertSlot, Pkcs15Ops as _, TokenSerial, render_token_serial};
use zeroize::{Zeroize as _, Zeroizing};

use crate::reader_pick::{FineidReaderPick, pick_fineid_reader};

/// Which PIN slot a manage-PIN operation targets. Thin layer over
/// [`PinSlot`] that also carries the user-facing label so error
/// messages and reports read naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinManageSlot {
    /// Authentication PIN; gates the authentication key.
    Pin1,
    /// Qualified-signature PIN; gates the non-repudiation signing key.
    Pin2,
}

impl PinManageSlot {
    /// Project to the [`PinSlot`] enum used by `refineid-auth`.
    #[must_use]
    pub const fn as_pin_slot(self) -> PinSlot {
        match self {
            Self::Pin1 => PinSlot::Pin1,
            Self::Pin2 => PinSlot::Pin2,
        }
    }

    /// User-facing name ("Basic PIN 1" / "Signature PIN 2") for prompts
    /// and report strings. `&'static str` from a fixed compile-time set.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pin1 => "Basic PIN 1",
            Self::Pin2 => "Signature PIN 2",
        }
    }
}

/// Whether one PIN still awaits its factory activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinActivation {
    /// The PIN still holds its factory state.
    AwaitsActivation,
    /// The PIN does not await activation.
    Activated,
}

impl PinActivation {
    /// Judge one PIN from its counter-safe probes, delegating to
    /// [`refineid_auth::pin_awaits_activation`].
    #[must_use]
    pub const fn judge(
        scheme: ActivationScheme,
        record: PinChangeRecord,
        status: Option<PinStatus>,
    ) -> Self {
        let effective_status = match status {
            Some(status) => status,
            None => PinStatus::NoInfo,
        };
        if pin_awaits_activation(scheme, record, effective_status) {
            Self::AwaitsActivation
        } else {
            Self::Activated
        }
    }
}

/// Decide the card's [`ActivationScheme`] from its resolved credential
/// numbering and authentication certificate validity start.
#[must_use]
pub(crate) fn activation_scheme_for_card(
    numbering: PinReferenceScheme,
    validity_start: Option<DateTime>,
) -> Option<ActivationScheme> {
    let validity_start_seconds =
        validity_start.and_then(|start| i64::try_from(start.unix_duration().as_secs()).ok());
    ActivationScheme::from_numbering_and_validity_start(numbering, validity_start_seconds)
}

/// Typed credentials for `card change-pin{1,2}`.
#[derive(Debug)]
pub enum ChangePinCredentials {
    /// Rotate Basic PIN 1.
    Pin1 {
        /// Current PIN 1 value.
        current: Pin1,
        /// New PIN 1 value.
        new: Pin1,
    },
    /// Rotate Signature PIN 2.
    Pin2 {
        /// Current PIN 2 value.
        current: Pin2,
        /// New PIN 2 value.
        new: Pin2,
    },
}

impl ChangePinCredentials {
    /// Which PIN slot these credentials target.
    #[must_use]
    pub const fn slot(&self) -> PinManageSlot {
        match self {
            Self::Pin1 { .. } => PinManageSlot::Pin1,
            Self::Pin2 { .. } => PinManageSlot::Pin2,
        }
    }
}

/// Inputs for `card change-pin{1,2}`.
#[derive(Debug)]
pub struct ChangePinOptions {
    /// Typed current and new PIN for the targeted slot.
    pub credentials: ChangePinCredentials,
    /// Optional substring match against reader names. `None` accepts
    /// any single FINEID-responding reader (errors on ambiguity).
    pub reader_filter: Option<String>,
}

/// One reader's worth of change-pin output.
#[derive(Debug, Clone)]
pub struct ChangePinReport {
    /// PC/SC reader name the modify APDU landed against.
    pub reader: String,
    /// `CredentialIdentity::best_serial()` of the bound card.
    pub card_serial: String,
    /// `CredentialIdentity::person_string()` rendering.
    pub person: String,
    /// Which PIN slot the modify APDU targeted.
    pub slot: PinManageSlot,
    /// Card-side outcome from `CHANGE REFERENCE DATA`.
    pub outcome: ManageOutcome,
}

/// Target PIN slot and validated replacement value for `card unblock-pin{1,2}`.
#[derive(Debug)]
pub enum UnblockPinTarget {
    /// Unblock and replace Basic PIN 1.
    Pin1(Pin1),
    /// Unblock and replace Signature PIN 2.
    Pin2(Pin2),
}

impl UnblockPinTarget {
    /// Which PIN slot this unblock targets.
    #[must_use]
    pub const fn slot(&self) -> PinManageSlot {
        match self {
            Self::Pin1(_) => PinManageSlot::Pin1,
            Self::Pin2(_) => PinManageSlot::Pin2,
        }
    }
}

/// Inputs for `card unblock-pin{1,2}`.
#[derive(Debug)]
pub struct UnblockPinOptions {
    /// The PUK code validated through [`Puk::reconstruct`].
    pub puk: Puk,
    /// Target PIN slot and new PIN value to set after the unblock succeeds.
    pub new_pin: UnblockPinTarget,
    /// Optional substring match against reader names.
    pub reader_filter: Option<String>,
}

/// One reader's worth of unblock output.
#[derive(Debug, Clone)]
pub struct UnblockPinReport {
    /// See [`ChangePinReport::reader`].
    pub reader: String,
    /// See [`ChangePinReport::card_serial`].
    pub card_serial: String,
    /// See [`ChangePinReport::person`].
    pub person: String,
    /// Which PIN slot the unblock APDU targeted.
    pub slot: PinManageSlot,
    /// Card-side outcome from `RESET RETRY COUNTER`.
    pub outcome: ManageOutcome,
}

/// Syntactically validated activation code entered before the card's
/// [`ActivationScheme`] has been read.
///
/// Enforces ASCII-digit shape (`4..=12` digits) at the input boundary and
/// zeroizes on drop; exact scheme length (7 or 8 digits) is verified through
/// [`ActivationCode::reconstruct`] once the card session decides the scheme.
pub struct ActivationInput(Zeroizing<Vec<u8>>);

impl ActivationInput {
    /// Validate and take ownership of `bytes` as an activation code candidate.
    ///
    /// # Errors
    /// Returns [`CredentialInputError`] unless `bytes` contains
    /// `PIN_MIN_LENGTH..=PIN_MAX_LENGTH` ASCII digits.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, CredentialInputError> {
        let role = CredentialRole::ActivationCode;
        if bytes.is_empty() {
            bytes.zeroize();
            return Err(CredentialInputError::Empty { role });
        }
        if bytes.len() < PIN_MIN_LENGTH || bytes.len() > PIN_MAX_LENGTH {
            bytes.zeroize();
            return Err(CredentialInputError::WrongLength {
                role,
                expected_min: PIN_MIN_LENGTH,
                expected_max: PIN_MAX_LENGTH,
            });
        }
        if bytes.iter().any(|byte| !byte.is_ascii_digit()) {
            bytes.zeroize();
            return Err(CredentialInputError::NonDigit { role });
        }
        Ok(Self(Zeroizing::new(bytes)))
    }
}

impl fmt::Debug for ActivationInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ActivationInput([redacted])")
    }
}

/// Activation code validated against the card's [`ActivationScheme`] via
/// [`ActivationCode::reconstruct`] and held only inside `card_pin` so both
/// PIN 1 and PIN 2 setup steps can construct their typed `refineid-auth`
/// credentials inside one transaction.
struct ValidatedActivationCode {
    digits: Zeroizing<Vec<u8>>,
    scheme: ActivationScheme,
}

impl ValidatedActivationCode {
    fn for_scheme(scheme: ActivationScheme, input: ActivationInput) -> Result<Self, CardPinError> {
        let _verified: ActivationCode = ActivationCode::reconstruct(
            UnvalidatedSecret::from_owned_bytes(input.0.to_vec()),
            scheme,
        )
        .map_err(|error| match error {
            CredentialInputError::NonDigit { .. } => CardPinError::PinInput(error),
            CredentialInputError::Empty { .. } | CredentialInputError::WrongLength { .. } => {
                CardPinError::ActivationLengthMismatch {
                    scheme,
                    expected: scheme.activation_entry_digit_count(),
                }
            }
        })?;
        Ok(Self {
            digits: input.0,
            scheme,
        })
    }

    fn as_pin1(&self) -> Result<Pin1, CardPinError> {
        Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(self.digits.to_vec()))
            .map_err(CardPinError::PinInput)
    }

    fn as_pin2(&self) -> Result<Pin2, CardPinError> {
        Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(self.digits.to_vec()))
            .map_err(CardPinError::PinInput)
    }

    fn as_puk(&self) -> Result<Puk, CardPinError> {
        Puk::reconstruct(UnvalidatedSecret::from_owned_bytes(self.digits.to_vec()))
            .map_err(CardPinError::PinInput)
    }
}

/// Error returned from the PIN-management entrypoints
/// (`card change-pin*`, `card unblock-pin*`, `card activate`).
#[derive(Debug)]
pub enum CardPinError {
    /// Reader enumeration / filter resolution failed.
    ReaderPick(ReaderPickError),
    /// PC/SC transport / transmit error.
    Pcsc(PcscError),
    /// Local credential-shape rejection before any APDU went out.
    PinInput(CredentialInputError),
    /// Card PIN-length policy rejection before any APDU went out.
    PinLength(PinLengthRefusal),
    /// Couldn't SELECT the PKCS#15 application. FINEID gates the
    /// PIN-management INS bytes behind app SELECT.
    Pkcs15Select(String),
    /// Lower-level transport / APDU failure not specific to PKCS#15
    /// SELECT (cert read, EF.TokenInfo read, ...).
    Transport(String),
    /// PACE refused the access number: the card on the contactless slot
    /// is not the one the stored CAN was proved on, or the CAN was typed
    /// wrong. The card was power-reset so the next attempt starts clean.
    AccessNumberRejected(String),
    /// `card activate` only: the activation PIN the operator
    /// entered doesn't have the length the card's activation scheme
    /// takes. Reported *before* any modify APDU, so the card-side
    /// try counter is untouched.
    ActivationLengthMismatch {
        /// The card's activation scheme.
        scheme: ActivationScheme,
        /// The digit count that scheme takes
        /// ([`ActivationScheme::activation_entry_digit_count`]).
        expected: usize,
    },
    /// The card published no PKCS#15 serial to bind the session to.
    CardSerialUnavailable {
        /// Human-readable detail naming where the serial was missing.
        description: String,
    },
    /// The bound card session was invalidated between session
    /// open and the operation.
    CardSessionRevoked {
        /// Human-readable detail from `re_verify_session`.
        reason: String,
    },
    /// The card's contact-interface ATR doesn't match any
    /// FINEID card model refineid recognises.
    CardModelNotSupported(CardClassificationError),
    /// `card change-pin*` / `card unblock-pin*`: the PIN's
    /// counter-safe probes show a PIN that awaits its activation
    /// ([`PinActivation`]), or the status probe returned no status word.
    CardLooksUnactivated {
        /// Which PIN slot the probe targeted.
        slot: PinManageSlot,
        /// Raw status probe outcome. `None` when the probe APDU
        /// itself failed to return a status word.
        probe: Option<PinStatus>,
    },
    /// The retry floor refused a command that would spend an attempt: the
    /// card reports two or one tries left, or no readable counter. Nothing
    /// was sent.
    RetryFloor(RetryFloorRefusal),
    /// `card activate` only: the new PINs entered are not exactly the
    /// PINs that await activation. Nothing was sent.
    ActivationEntriesMismatch {
        /// Whether PIN1 awaits activation.
        pin1_awaits: bool,
        /// Whether PIN2 awaits activation.
        pin2_awaits: bool,
    },
}

impl fmt::Display for CardPinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReaderPick(e) => write!(f, "{e}"),
            Self::Pcsc(e) => write!(f, "PC/SC: {e}"),
            Self::PinInput(r) => write!(f, "PIN / PUK rejected locally: {r}"),
            Self::PinLength(r) => write!(f, "PIN / PUK rejected locally: {r}"),
            Self::Pkcs15Select(s) => write!(f, "SELECT PKCS#15 app: {s}"),
            Self::Transport(s) => write!(f, "transport: {s}"),
            Self::AccessNumberRejected(s) => write!(f, "access number rejected: {s}"),
            Self::ActivationLengthMismatch {
                scheme: _,
                expected,
            } => write!(
                f,
                "activation PIN length wrong for this card: the card \
                 expects {expected} digits. Sending it anyway would \
                 burn a card-side try; refusing"
            ),
            Self::CardSerialUnavailable { description } => {
                write!(f, "card serial unavailable -- {description}")
            }
            Self::CardSessionRevoked { reason } => write!(
                f,
                "card session revoked before the operation: \
                 {reason}. The session does not survive card removal, reader unplug, \
                 reader rename, or card swap. Re-run the command after restoring \
                 the original reader + card."
            ),
            Self::CardModelNotSupported(e) => write!(f, "{e}"),
            Self::CardLooksUnactivated { slot, probe } => {
                let probe_desc = probe
                    .as_ref()
                    .map_or_else(|| "no probe result".to_owned(), |s| format!("{s:?}"));
                write!(
                    f,
                    "{} looks unactivated (pin_status probe: {probe_desc}); refusing to send \
                     a modify APDU that could land on an unset slot. Run `refineid card activate` \
                     first to set Basic PIN 1 and Signature PIN 2.",
                    slot.label()
                )
            }
            Self::RetryFloor(refusal) => write!(f, "{refusal}"),
            Self::ActivationEntriesMismatch {
                pin1_awaits,
                pin2_awaits,
            } => {
                let awaiting = match (pin1_awaits, pin2_awaits) {
                    (true, true) => "Basic PIN 1 and Signature PIN 2",
                    (true, false) => "Basic PIN 1",
                    (false, true) => "Signature PIN 2",
                    (false, false) => "no PIN",
                };
                write!(
                    f,
                    "{awaiting} awaits activation on this card; enter a new value for exactly \
                     the PINs that await it. Nothing was sent to the card."
                )
            }
        }
    }
}

impl core::error::Error for CardPinError {}

impl From<PcscError> for CardPinError {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

impl From<ReaderPickError> for CardPinError {
    fn from(e: ReaderPickError) -> Self {
        Self::ReaderPick(e)
    }
}

/// Map a `refineid-auth` [`AuthError`] into [`CardPinError`].
fn auth_to_card_pin(e: AuthError<impl fmt::Display>) -> CardPinError {
    match e {
        AuthError::Transport(t) => CardPinError::Transport(format!("{t}")),
        AuthError::Outcome(o) => CardPinError::Transport(format!("{o}")),
        AuthError::Command(c) => CardPinError::Transport(format!("{c}")),
        AuthError::RetryFloor(r) => CardPinError::RetryFloor(r),
        AuthError::PinLength(r) => CardPinError::PinLength(r),
        AuthError::UnsupportedSlot { scheme, slot } => {
            CardPinError::Transport(format!("{slot:?} is not supported under {scheme:?}"))
        }
    }
}

/// Read the citizen card's PIN-changed record (`DF 2F`), returning
/// [`PinChangeRecord::Unreadable`] on non-citizen cards (which do not support
/// the citizen PIN container) or when the card does not report the flag.
pub(crate) fn probe_pin_change_record<T: CardTransport>(
    transport: &mut T,
    numbering: PinReferenceScheme,
    slot: PinSlot,
) -> PinChangeRecord {
    if numbering != PinReferenceScheme::Citizen {
        return PinChangeRecord::Unreadable;
    }
    read_pin_change_record(transport, slot).unwrap_or(PinChangeRecord::Unreadable)
}

/// Bound card session.
///
/// A long-serial has been bound, and the card's reference numbering
/// and activation scheme are known.
/// Activation-state is *not* yet known; downstream
/// operations must promote this into either
/// [`ActivationCardContext`] (for `card activate`) or
/// [`PinManagementCardContext`] (for `card change-pin*` /
/// `card unblock-pin*`).
#[derive(Debug, Clone)]
pub struct BoundCardSession {
    /// PC/SC reader id captured at session open; every
    /// subsequent re-open in the flow uses exactly this id.
    pub reader_id: ReaderId,
    /// Person identity extracted from the auth cert's subject DN.
    pub identity: CredentialIdentity,
    /// PKCS#15 long serial bound at session open; every
    /// subsequent step re-reads and compares against this value
    /// to detect a card swap.
    pub bound_serial: TokenSerial,
    /// ATR-classified FINEID card model from the recognised set.
    pub model: FineidCardModel,
    /// The credential-reference numbering the card answered to.
    pub numbering: PinReferenceScheme,
    /// The card's activation scheme.
    pub scheme: ActivationScheme,
}

impl BoundCardSession {
    /// Promote a bound session into [`PinManagementCardContext`].
    #[must_use]
    pub const fn into_pin_management_context(self) -> PinManagementCardContext {
        PinManagementCardContext { session: self }
    }
}

/// Card session promoted from a bound base into the
/// "operator intends a PIN-management operation on an
/// already-activated card" typestate.
#[derive(Debug, Clone)]
pub struct PinManagementCardContext {
    session: BoundCardSession,
}

impl PinManagementCardContext {
    /// Borrow the reader id this context is bound to.
    #[must_use]
    pub const fn reader_id(&self) -> &ReaderId {
        &self.session.reader_id
    }

    /// Borrow the person identity captured at session open.
    #[must_use]
    pub const fn identity(&self) -> &CredentialIdentity {
        &self.session.identity
    }

    /// Borrow the PKCS#15 long serial bound at session open.
    #[must_use]
    pub const fn bound_serial(&self) -> &TokenSerial {
        &self.session.bound_serial
    }

    /// ATR-classified FINEID card model captured at session open.
    #[must_use]
    pub const fn model(&self) -> FineidCardModel {
        self.session.model
    }

    /// The credential-reference numbering captured at session open.
    #[must_use]
    pub const fn numbering(&self) -> PinReferenceScheme {
        self.session.numbering
    }

    /// The activation scheme captured at session open.
    #[must_use]
    pub const fn scheme(&self) -> ActivationScheme {
        self.session.scheme
    }
}

/// Open and bind a card session on the picked reader.
///
/// # Errors
/// - `CardModelNotSupported` -- ATR didn't classify.
/// - `CardSerialUnavailable` -- PKCS#15 serial unavailable.
/// - PC/SC / SELECT / cert-read failures.
pub fn establish_card_session(
    backend: PcscBackend,
    reader_filter: Option<&ReaderFilter>,
) -> Result<BoundCardSession, CardPinError> {
    let FineidReaderPick {
        reader_id,
        identity,
    } = pick_fineid_reader(&backend, reader_filter)?;
    let mut transport = backend.open_exclusive(&reader_id, ReaderAccessCap::Read)?;

    // ATR classify -- public protocol-level signal; rejects
    // unrecognised cards before any card-side data read.
    let atr = transport
        .atr()
        .map_err(|e| CardPinError::Transport(format!("ATR length: {e}")))?;
    let model = FineidCardModel::from_atr(&atr).map_err(CardPinError::CardModelNotSupported)?;

    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;

    let token = transport
        .read_token_info()
        .map_err(|e| CardPinError::Transport(format!("EF.TokenInfo read: {e}")))?;
    let bound_serial = match token.serial_number_hex().cloned() {
        Some(hex) => render_token_serial(hex),
        None => {
            return Err(CardPinError::CardSerialUnavailable {
                description: "card did not publish a PKCS#15 serial; can't pin session identity"
                    .to_owned(),
            });
        }
    };

    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;
    let numbering = transport
        .resolve_pin_reference_scheme()
        .map_err(auth_to_card_pin)?;
    let validity_start = match numbering {
        PinReferenceScheme::Organizational => None,
        PinReferenceScheme::Citizen => {
            let der = transport
                .read_certificate(CoreCertSlot::Authentication)
                .map_err(|e| CardPinError::Transport(format!("auth cert read: {e}")))?;
            let cert = OwnedCert::from_der(der.as_bytes())
                .map_err(|e| CardPinError::Transport(format!("auth cert parse: {e}")))?;
            Some(cert.view().not_before)
        }
        PinReferenceScheme::Estonian => {
            return Err(CardPinError::Transport(
                "non-FINEID PIN reference scheme is not supported by FINEID PIN management"
                    .to_owned(),
            ));
        }
    };
    let scheme = activation_scheme_for_card(numbering, validity_start)
        .ok_or_else(|| CardPinError::Transport("auth cert gives no validity start".to_owned()))?;

    Ok(BoundCardSession {
        reader_id,
        identity,
        bound_serial,
        model,
        numbering,
        scheme,
    })
}

/// Read one PIN's counter-safe probes under the session's numbering
/// and judge whether it awaits activation.
fn probe_pin_activation<T: CardTransport>(
    transport: &mut T,
    numbering: PinReferenceScheme,
    scheme: ActivationScheme,
    slot: PinSlot,
) -> (Option<PinStatus>, PinActivation) {
    let status = transport.pin_status_with_scheme(numbering, slot).ok();
    let record = probe_pin_change_record(transport, numbering, slot);
    (status, PinActivation::judge(scheme, record, status))
}

/// The status of a PIN that does not await its activation, or the
/// refusal for one that does ([`PinActivation::judge`]) or whose
/// status probe returned no status word.
fn require_activated<T: CardTransport>(
    transport: &mut T,
    ctx: &PinManagementCardContext,
    slot: PinManageSlot,
) -> Result<PinStatus, CardPinError> {
    let (probe, verdict) =
        probe_pin_activation(transport, ctx.numbering(), ctx.scheme(), slot.as_pin_slot());
    match (verdict, probe) {
        (PinActivation::Activated, Some(status)) => Ok(status),
        (PinActivation::AwaitsActivation, _) | (PinActivation::Activated, None) => {
            Err(CardPinError::CardLooksUnactivated { slot, probe })
        }
    }
}

/// Rotate the PIN in `options.credentials`. The card's own outcome
/// (wrong-current-PIN with retries-left, locked, etc.) is
/// surfaced via [`ChangePinReport::outcome`], not as an error.
///
/// Runs inside a single [`refineid_pcsc::PcscCard::pin_sequence`] transaction
/// that resets the card on exit.
///
/// # Errors
/// PC/SC / PKCS#15 / local-policy / transport failures.
pub fn change_pin_first(
    backend: PcscBackend,
    ctx: PinManagementCardContext,
    options: ChangePinOptions,
) -> Result<ChangePinReport, CardPinError> {
    let person = ctx.identity().person_string();
    let card_serial = ctx.identity().best_serial().unwrap_or("").to_owned();
    let reader_name = ctx.reader_id().as_str().to_owned();
    let manage_slot = options.credentials.slot();
    let slot = manage_slot.as_pin_slot();
    let numbering = ctx.numbering();
    if numbering == PinReferenceScheme::Estonian {
        return Err(CardPinError::Transport(
            "non-FINEID PIN reference scheme is not supported by FINEID PIN management".to_owned(),
        ));
    }

    let card = backend.open_exclusive(ctx.reader_id(), ReaderAccessCap::PinSequence)?;
    let outcome = card.pin_sequence(|mut tx| -> Result<ManageOutcome, CardPinError> {
        tx.select_pkcs15_application()
            .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;
        re_verify_session(&mut tx, ctx.bound_serial())?;
        let lengths = tx
            .read_card_pin_lengths_with_scheme(numbering)
            .map_err(auth_to_card_pin)?;

        let status = require_activated(&mut tx, &ctx, manage_slot)?;
        check_retry_floor(slot.into(), status).map_err(CardPinError::RetryFloor)?;

        re_verify_session(&mut tx, ctx.bound_serial())?;

        match options.credentials {
            ChangePinCredentials::Pin1 { current, new } => tx
                .change_pin1(&lengths, current, new)
                .map_err(auth_to_card_pin),
            ChangePinCredentials::Pin2 { current, new } => tx
                .change_pin2(&lengths, current, new)
                .map_err(auth_to_card_pin),
        }
    })??;

    let report = ChangePinReport {
        reader: reader_name,
        card_serial,
        person,
        slot: manage_slot,
        outcome,
    };
    drop(ctx);
    Ok(report)
}

/// PUK-driven unblock + replace PIN in `options.new_pin`.
///
/// Runs inside a single [`refineid_pcsc::PcscCard::pin_sequence`] transaction
/// that resets the card on exit.
///
/// # Errors
/// PC/SC / PKCS#15 / local-policy / transport failures, and
/// [`CardPinError::RetryFloor`] for a PUK at two or one tries left or
/// with a counter the card did not report.
pub fn unblock_pin_first(
    backend: PcscBackend,
    ctx: PinManagementCardContext,
    options: UnblockPinOptions,
) -> Result<UnblockPinReport, CardPinError> {
    let person = ctx.identity().person_string();
    let card_serial = ctx.identity().best_serial().unwrap_or("").to_owned();
    let reader_name = ctx.reader_id().as_str().to_owned();
    let manage_slot = options.new_pin.slot();
    let numbering = ctx.numbering();
    if numbering == PinReferenceScheme::Estonian {
        return Err(CardPinError::Transport(
            "non-FINEID PIN reference scheme is not supported by FINEID PIN management".to_owned(),
        ));
    }

    let card = backend.open_exclusive(ctx.reader_id(), ReaderAccessCap::PinSequence)?;
    let outcome = card.pin_sequence(|mut tx| -> Result<ManageOutcome, CardPinError> {
        tx.select_pkcs15_application()
            .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;
        re_verify_session(&mut tx, ctx.bound_serial())?;
        let lengths = tx
            .read_card_pin_lengths_with_scheme(numbering)
            .map_err(auth_to_card_pin)?;

        require_activated(&mut tx, &ctx, manage_slot)?;
        re_verify_session(&mut tx, ctx.bound_serial())?;

        match options.new_pin {
            UnblockPinTarget::Pin1(new) => tx
                .unblock_pin1(&lengths, options.puk, new)
                .map_err(auth_to_card_pin),
            UnblockPinTarget::Pin2(new) => tx
                .unblock_pin2(&lengths, options.puk, new)
                .map_err(auth_to_card_pin),
        }
    })??;

    let report = UnblockPinReport {
        reader: reader_name,
        card_serial,
        person,
        slot: manage_slot,
        outcome,
    };
    drop(ctx);
    Ok(report)
}

impl fmt::Display for ChangePinReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        if !self.card_serial.is_empty() {
            writeln!(f, "card:   {}", self.card_serial)?;
        }
        if !self.person.is_empty() {
            writeln!(f, "person: {}", self.person)?;
        }
        let label = self.slot.label();
        match &self.outcome {
            ManageOutcome::Ok => writeln!(
                f,
                "{label} changed; retry counter reset; re-VERIFY required for further ops"
            )?,
            ManageOutcome::WrongCredential { retries_left } => {
                writeln!(f, "current {label} was wrong ({retries_left} retries left)")?;
            }
            ManageOutcome::Locked => writeln!(
                f,
                "{label} is blocked -- use the PUK to unblock before retrying"
            )?,
            ManageOutcome::Other(StatusWord::WrongLength) => {
                writeln!(f, "card rejected APDU length (SW=6700) -- host bug")?;
            }
            ManageOutcome::Other(sw) => {
                writeln!(f, "card returned unexpected SW={:#06X}", sw.as_u16())?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for UnblockPinReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        if !self.card_serial.is_empty() {
            writeln!(f, "card:   {}", self.card_serial)?;
        }
        if !self.person.is_empty() {
            writeln!(f, "person: {}", self.person)?;
        }
        let label = self.slot.label();
        match &self.outcome {
            ManageOutcome::Ok => writeln!(
                f,
                "{label} unblocked; retry counter reset to max; re-VERIFY required for further ops"
            )?,
            ManageOutcome::WrongCredential { retries_left } => writeln!(
                f,
                "PUK was wrong ({retries_left} retries left on the PUK itself; \
                 exhausting it permanently bricks the card)"
            )?,
            ManageOutcome::Locked => writeln!(
                f,
                "PUK is itself blocked -- card needs DVV reissue, no software recovery"
            )?,
            ManageOutcome::Other(StatusWord::WrongLength) => {
                writeln!(f, "card rejected APDU length (SW=6700) -- host bug")?;
            }
            ManageOutcome::Other(sw) => {
                writeln!(f, "card returned unexpected SW={:#06X}", sw.as_u16())?;
            }
        }
        Ok(())
    }
}

// ---- card activate -- first-time setup flow --------------------

/// Pre-activation card context.
#[derive(Debug, Clone)]
pub struct ActivationCardContext {
    /// PC/SC reader id captured at session open; subsequent
    /// re-opens in the activate flow use exactly this id.
    pub reader_id: ReaderId,
    /// Person identity extracted from the auth cert's subject DN
    /// at session open. Surfaced in activate report output.
    pub identity: CredentialIdentity,
    /// The credential-reference numbering the card answered to.
    pub numbering: PinReferenceScheme,
    /// The card's activation scheme.
    pub scheme: ActivationScheme,
    /// PKCS#15 EF.TokenInfo serial (long form) captured at
    /// session open.
    pub bound_serial: TokenSerial,
    /// The FINEID card model identified by ATR matching at
    /// session open, from refineid's recognised set.
    pub model: FineidCardModel,
}

impl ActivationCardContext {
    /// Exact activation-code length for the card's scheme.
    #[must_use]
    pub const fn expected_activation_pin_length(&self) -> usize {
        self.scheme.activation_entry_digit_count()
    }
}

/// Open and bind a session on the picked FINEID reader and carry it
/// -- reference numbering and activation scheme included -- into the
/// activation typestate.
///
/// # Errors
/// PC/SC / PKCS#15 / cert-read / reader-pick failures, and
/// `CardSerialUnavailable` when the card publishes no PKCS#15 serial.
pub fn classify_card_for_activation(
    backend: PcscBackend,
    reader_filter: Option<&ReaderFilter>,
) -> Result<ActivationCardContext, CardPinError> {
    let session = establish_card_session(backend, reader_filter)?;
    Ok(ActivationCardContext {
        reader_id: session.reader_id,
        identity: session.identity,
        numbering: session.numbering,
        scheme: session.scheme,
        bound_serial: session.bound_serial,
        model: session.model,
    })
}

/// Re-verify the bound card session: the reader's still the
/// one we picked, the card's still there, and its long serial
/// still matches what we bound at session open.
///
/// # Errors
/// `CardSessionRevoked` on any divergence.
pub(crate) fn re_verify_session<T: CardTransport>(
    transport: &mut T,
    bound_serial: &TokenSerial,
) -> Result<(), CardPinError> {
    let token = transport
        .read_token_info()
        .map_err(|e| CardPinError::CardSessionRevoked {
            reason: format!("re-read EF.TokenInfo failed: {e}"),
        })?;
    let now_serial =
        token
            .serial_number_hex()
            .cloned()
            .ok_or_else(|| CardPinError::CardSessionRevoked {
                reason: "card no longer publishes EF.TokenInfo serial".to_owned(),
            })?;
    let current_full = render_token_serial(now_serial);
    if &current_full != bound_serial {
        return Err(CardPinError::CardSessionRevoked {
            reason: format!(
                "card serial changed mid-flow: bound to {bound_serial:?}, \
                 reader now reports {current_full:?}"
            ),
        });
    }
    Ok(())
}

/// Inputs for `card activate` -- the one-time DVV activation flow.
#[derive(Debug)]
pub struct ActivateOptions {
    /// The activation PIN from the DVV activation letter, as typed.
    pub activation_code: ActivationInput,
    /// New basic PIN (PIN1, of a length the card accepts), given exactly when PIN1
    /// awaits activation.
    pub new_pin1: Option<Pin1>,
    /// New signature PIN (PIN2, of a length the card accepts), given exactly when PIN2
    /// awaits activation.
    pub new_pin2: Option<Pin2>,
    /// Override the pre-flight refusal when no PIN awaits its activation.
    pub allow_reactivate: bool,
}

/// One reader's worth of activate output.
#[derive(Debug, Clone)]
pub struct ActivateReport {
    /// PC/SC reader name the activation APDUs landed against.
    pub reader: String,
    /// The per-PIN pre-flight verdict.
    pub preflight: ActivatePreflightOutcome,
    /// Card's outcome for the PIN1 activation command.
    pub pin1_outcome: Option<ManageOutcome>,
    /// Card's outcome for the PIN2 activation command.
    pub pin2_outcome: Option<ManageOutcome>,
}

/// What the per-PIN pre-flight saw before any modification was
/// attempted ([`PinActivation::judge`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivatePreflightOutcome {
    /// At least one PIN awaits its activation; activation sets each
    /// PIN that does.
    AwaitsActivation {
        /// PIN1 verdict.
        pin1: PinActivation,
        /// PIN2 verdict.
        pin2: PinActivation,
    },
    /// No PIN awaits its activation. Activation is refused unless the
    /// operator passed `--allow-reactivate`.
    NothingAwaits {
        /// PIN1 verdict.
        pin1: PinActivation,
        /// PIN2 verdict.
        pin2: PinActivation,
    },
}

impl ActivatePreflightOutcome {
    /// `true` when no PIN awaits its activation.
    #[must_use]
    pub const fn looks_activated(&self) -> bool {
        matches!(self, Self::NothingAwaits { .. })
    }
}

/// Combine the per-PIN verdicts into the activation pre-flight.
const fn classify_preflight(pin1: PinActivation, pin2: PinActivation) -> ActivatePreflightOutcome {
    if matches!(pin1, PinActivation::AwaitsActivation)
        || matches!(pin2, PinActivation::AwaitsActivation)
    {
        ActivatePreflightOutcome::AwaitsActivation { pin1, pin2 }
    } else {
        ActivatePreflightOutcome::NothingAwaits { pin1, pin2 }
    }
}

/// What the counter-safe probes say about whether the card has been
/// activated, read for a display of the card's state rather than for
/// the activation command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationEvidence {
    /// At least one PIN still awaits its activation.
    Unactivated,
    /// No PIN awaits its activation.
    Activated,
}

/// Judge the card's activation evidence from the per-PIN verdicts
/// ([`PinActivation::judge`]).
#[must_use]
pub const fn judge_activation(pin1: PinActivation, pin2: PinActivation) -> ActivationEvidence {
    match (pin1, pin2) {
        (PinActivation::AwaitsActivation, _) | (_, PinActivation::AwaitsActivation) => {
            ActivationEvidence::Unactivated
        }
        (PinActivation::Activated, PinActivation::Activated) => ActivationEvidence::Activated,
    }
}

/// Which PINs an activation sets, from the per-PIN verdicts and the
/// new PINs entered.
const fn activation_targets(
    pin1: PinActivation,
    pin2: PinActivation,
    pin1_entered: bool,
    pin2_entered: bool,
    allow_reactivate: bool,
) -> Result<(bool, bool), CardPinError> {
    let pin1_awaits = matches!(pin1, PinActivation::AwaitsActivation);
    let pin2_awaits = matches!(pin2, PinActivation::AwaitsActivation);
    let matches_card = pin1_entered == pin1_awaits && pin2_entered == pin2_awaits;
    if (pin1_entered || pin2_entered) && (allow_reactivate || matches_card) {
        Ok((pin1_entered, pin2_entered))
    } else {
        Err(CardPinError::ActivationEntriesMismatch {
            pin1_awaits,
            pin2_awaits,
        })
    }
}

/// Per-slot setup for [`activate_first`]: dispatch the scheme's command under
/// the card's numbering through `refineid-auth` (which enforces the card
/// lengths and retry floor before any credential APDU goes out).
fn activate_slot_setup<T: CardTransport>(
    transport: &mut T,
    lengths: &CardPinLengths,
    activation_code: &ValidatedActivationCode,
    target: UnblockPinTarget,
) -> Result<ManageOutcome, CardPinError> {
    match (activation_code.scheme, target) {
        (ActivationScheme::PresetActivationPin, UnblockPinTarget::Pin1(new)) => transport
            .change_pin1(lengths, activation_code.as_pin1()?, new)
            .map_err(auth_to_card_pin),
        (ActivationScheme::PresetActivationPin, UnblockPinTarget::Pin2(new)) => transport
            .change_pin2(lengths, activation_code.as_pin2()?, new)
            .map_err(auth_to_card_pin),
        (ActivationScheme::ActivationCodeIsPuk, UnblockPinTarget::Pin1(new)) => transport
            .unblock_pin1(lengths, activation_code.as_puk()?, new)
            .map_err(auth_to_card_pin),
        (ActivationScheme::ActivationCodeIsPuk, UnblockPinTarget::Pin2(new)) => transport
            .unblock_pin2(lengths, activation_code.as_puk()?, new)
            .map_err(auth_to_card_pin),
    }
}

/// Check every activation entry against the card's lengths before any command.
fn check_activation_entries(
    lengths: &CardPinLengths,
    activation_code: &ValidatedActivationCode,
    new_pin1: Option<&Pin1>,
    new_pin2: Option<&Pin2>,
) -> Result<(), CardPinError> {
    if let Some(pin1) = new_pin1 {
        match activation_code.scheme {
            ActivationScheme::PresetActivationPin => {
                let current = activation_code.as_pin1()?;
                lengths
                    .check_pin1(&current)
                    .map_err(CardPinError::PinLength)?;
            }
            ActivationScheme::ActivationCodeIsPuk => {
                let puk = activation_code.as_puk()?;
                lengths.check_puk(&puk).map_err(CardPinError::PinLength)?;
            }
        }
        lengths.check_pin1(pin1).map_err(CardPinError::PinLength)?;
    }
    if let Some(pin2) = new_pin2 {
        match activation_code.scheme {
            ActivationScheme::PresetActivationPin => {
                let current = activation_code.as_pin2()?;
                lengths
                    .check_pin2(&current)
                    .map_err(CardPinError::PinLength)?;
            }
            ActivationScheme::ActivationCodeIsPuk => {
                let puk = activation_code.as_puk()?;
                lengths.check_puk(&puk).map_err(CardPinError::PinLength)?;
            }
        }
        lengths.check_pin2(pin2).map_err(CardPinError::PinLength)?;
    }
    Ok(())
}

const fn activation_continues_after_pin1(outcome: ManageOutcome) -> bool {
    matches!(outcome, ManageOutcome::Ok)
}

/// Drive the `card activate` flow: bound card -> activation code -> fresh PIN1/PIN2.
///
/// Runs inside a single [`refineid_pcsc::PcscCard::pin_sequence`] transaction
/// that resets the card on exit.
///
/// # Errors
/// PC/SC, PKCS#15-SELECT, reader-pick, length or local-policy failures.
pub fn activate_first(
    backend: PcscBackend,
    ctx: ActivationCardContext,
    options: ActivateOptions,
) -> Result<ActivateReport, CardPinError> {
    let ActivateOptions {
        activation_code: raw_code,
        new_pin1,
        new_pin2,
        allow_reactivate,
    } = options;
    let reader_label = ctx.reader_id.as_str().to_owned();
    if ctx.numbering == PinReferenceScheme::Estonian {
        return Err(CardPinError::Transport(
            "non-FINEID PIN reference scheme is not supported by FINEID PIN management".to_owned(),
        ));
    }
    let activation_code = ValidatedActivationCode::for_scheme(ctx.scheme, raw_code)?;

    let card = backend.open_exclusive(&ctx.reader_id, ReaderAccessCap::PinSequence)?;
    let report = card.pin_sequence(|mut tx| -> Result<ActivateReport, CardPinError> {
        tx.select_pkcs15_application()
            .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;

        re_verify_session(&mut tx, &ctx.bound_serial)?;
        let lengths = tx
            .read_card_pin_lengths_with_scheme(ctx.numbering)
            .map_err(auth_to_card_pin)?;

        let (_, pin1) = probe_pin_activation(&mut tx, ctx.numbering, ctx.scheme, PinSlot::Pin1);
        let (_, pin2) = probe_pin_activation(&mut tx, ctx.numbering, ctx.scheme, PinSlot::Pin2);
        let preflight = classify_preflight(pin1, pin2);

        if !allow_reactivate && preflight.looks_activated() {
            return Ok(ActivateReport {
                reader: reader_label,
                preflight,
                pin1_outcome: None,
                pin2_outcome: None,
            });
        }
        activation_targets(
            pin1,
            pin2,
            new_pin1.is_some(),
            new_pin2.is_some(),
            allow_reactivate,
        )?;
        check_activation_entries(
            &lengths,
            &activation_code,
            new_pin1.as_ref(),
            new_pin2.as_ref(),
        )?;

        let mut pin1_outcome = None;
        if let Some(new_pin1) = new_pin1 {
            re_verify_session(&mut tx, &ctx.bound_serial)?;
            let outcome = activate_slot_setup(
                &mut tx,
                &lengths,
                &activation_code,
                UnblockPinTarget::Pin1(new_pin1),
            )?;
            pin1_outcome = Some(outcome);
            if !activation_continues_after_pin1(outcome) {
                return Ok(ActivateReport {
                    reader: reader_label,
                    preflight,
                    pin1_outcome,
                    pin2_outcome: None,
                });
            }
        }

        let pin2_outcome = if let Some(new_pin2) = new_pin2 {
            re_verify_session(&mut tx, &ctx.bound_serial)?;
            Some(activate_slot_setup(
                &mut tx,
                &lengths,
                &activation_code,
                UnblockPinTarget::Pin2(new_pin2),
            )?)
        } else {
            None
        };

        Ok(ActivateReport {
            reader: reader_label,
            preflight,
            pin1_outcome,
            pin2_outcome,
        })
    })??;

    drop(activation_code);
    drop(ctx);
    Ok(report)
}

impl fmt::Display for ActivateReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        match &self.preflight {
            ActivatePreflightOutcome::AwaitsActivation { pin1, pin2 } => {
                writeln!(
                    f,
                    "preflight: card awaits activation (Basic PIN 1: {pin1:?}, Signature PIN 2: {pin2:?}); proceeding"
                )?;
            }
            ActivatePreflightOutcome::NothingAwaits { pin1, pin2 } => {
                writeln!(
                    f,
                    "preflight: no PIN awaits activation \
                     (Basic PIN 1: {pin1:?}, Signature PIN 2: {pin2:?})"
                )?;
                if self.pin1_outcome.is_none() && self.pin2_outcome.is_none() {
                    writeln!(
                        f,
                        "  refused without --allow-reactivate; nothing was sent to the card"
                    )?;
                    return Ok(());
                }
            }
        }
        match self.pin1_outcome {
            Some(o) => writeln!(
                f,
                "{} setup: {}",
                PinManageSlot::Pin1.label(),
                CardPinHelpers::fmt_activation(o, PinManageSlot::Pin1.label())
            )?,
            None => writeln!(f, "{} setup: not attempted", PinManageSlot::Pin1.label())?,
        }
        match (self.pin1_outcome, self.pin2_outcome) {
            (_, Some(o)) => writeln!(
                f,
                "{} setup: {}",
                PinManageSlot::Pin2.label(),
                CardPinHelpers::fmt_activation(o, PinManageSlot::Pin2.label())
            )?,
            (Some(o), None) if !activation_continues_after_pin1(o) => writeln!(
                f,
                "{} setup: not attempted ({} setup failed; re-run after fixing \
                 the activation PIN -- each invocation consumes one card-side try)",
                PinManageSlot::Pin2.label(),
                PinManageSlot::Pin1.label()
            )?,
            _ => writeln!(f, "{} setup: not attempted", PinManageSlot::Pin2.label())?,
        }
        Ok(())
    }
}

/// Helpers hosted on a unit struct.
struct CardPinHelpers;

impl CardPinHelpers {
    fn fmt_activation(o: ManageOutcome, label: &str) -> String {
        match o {
            ManageOutcome::Ok => format!("ok ({label} set; retry counter reset to max)"),
            ManageOutcome::WrongCredential { retries_left } => {
                format!(
                    "WRONG activation PIN ({retries_left} card-side tries left; lockout pending)"
                )
            }
            ManageOutcome::Locked => {
                "ACTIVATION PIN LOCKED -- order a PUK from DVV to recover (paid)".to_owned()
            }
            ManageOutcome::Other(StatusWord::WrongLength) => {
                "card rejected APDU length (SW=6700) -- host bug".to_owned()
            }
            ManageOutcome::Other(sw) => format!("card returned unexpected SW={:#06X}", sw.as_u16()),
        }
    }
}

#[cfg(test)]
mod activate_tests {
    use refineid_apdu::{
        CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
        TransportOutcome,
    };
    use refineid_auth::manage::RESET_RETRY_COUNTER_INS;
    use refineid_auth::verify::VERIFY_INS;
    use refineid_auth::{
        ActivationScheme, CardPinLengths, ManageOutcome, PIN1_REFERENCE,
        PIN1_REFERENCE_ORGANIZATIONAL, PUK_REFERENCE_ORGANIZATIONAL, Pin1, PinReferenceScheme,
        PinSlot, RetryFloorRefusal, UnvalidatedSecret,
    };

    use super::{
        ActivatePreflightOutcome, ActivationEvidence, ActivationInput, CardPinError, PinActivation,
        UnblockPinTarget, ValidatedActivationCode, activate_slot_setup,
        activation_continues_after_pin1, activation_targets, classify_preflight, judge_activation,
        probe_pin_activation,
    };
    use crate::test_util::{TestResult, check_true};

    /// GET DATA instruction byte, odd variant (ISO 7816-4 section 11.4.2; FINEID S1 v4.2 section 3.15.2).
    const GET_DATA_ODD_INS: u8 = 0xCB;
    /// Count of served retry-counter levels in [`SERVED`].
    const SERVED_COUNT: usize = 3;
    /// Tries left at which a PIN attempt is served.
    const SERVED: [u8; SERVED_COUNT] = [5, 4, 3];
    /// Count of refused retry-counter levels in [`LAST_TWO_TRIES`].
    const LAST_TWO_TRIES_COUNT: usize = 2;
    /// Tries left at which an activation code is not presented.
    const LAST_TWO_TRIES: [u8; LAST_TWO_TRIES_COUNT] = [2, 1];
    /// A full counter.
    const FULL_COUNTER: u8 = 5;
    /// A counter with three tries remaining.
    const THREE_RETRIES: u8 = 3;
    /// A counter with no tries left (`63C0`).
    const NO_TRIES: u8 = 0;
    /// APDUs a served preset-PIN activation sends: status probe and `CHANGE REFERENCE DATA`.
    const PROBE_AND_CHANGE: usize = 2;
    /// APDUs a refused activation sends on a single-probe path.
    const PROBE_ONLY: usize = 1;
    /// Counter-safe probes on citizen unreadable PUK: Case 1 VERIFY PUK + GET DATA fallback.
    const CITIZEN_UNREADABLE_PUK_PROBES: usize = 2;
    /// Zero credential commands sent on refusal.
    const NO_CREDENTIAL_COMMANDS: usize = 0;
    /// APDUs a served citizen PUK-code activation sends: PUK probe and `RESET RETRY COUNTER`.
    const PROBE_AND_RESET: usize = 2;
    /// APDUs an organization PUK-code activation sends when the PUK is refused.
    const PROBE_AND_VERIFY: usize = 2;
    /// Index of the second recorded command.
    const SECOND_COMMAND: usize = 1;
    /// Offset of the instruction byte in a command.
    const INS_INDEX: usize = 1;
    /// Offset of P2 in a command.
    const P2_INDEX: usize = 3;
    /// A status word outside the modeled set.
    const UNMODELED_SW: u16 = 0x6F00;
    /// Synthetic seven-digit preset activation PIN.
    const PRESET_PIN: &[u8] = b"0000000";
    /// Synthetic eight-digit activation PIN.
    const PUK_CODE: &[u8] = b"00000000";
    /// Synthetic new PIN.
    const NEW_PIN: &[u8] = b"0000";
    /// PIN changed data object tag, high byte (FINEID S1 v4.2 §3.15.3).
    const PIN_CHANGED_TAG_HIGH: u8 = 0xDF;
    /// PIN changed data object tag, low byte.
    const PIN_CHANGED_TAG_LOW: u8 = 0x2F;
    /// PIN changed data object length.
    const PIN_CHANGED_LENGTH: u8 = 1;
    /// PIN changed flag: never changed.
    const PIN_UNCHANGED: u8 = 0;
    /// PIN changed flag: changed.
    const PIN_CHANGED: u8 = 1;

    /// Answers every command with one status word and records plain/credential headers.
    struct FixedStatusTransport {
        status: StatusWord,
        sent: Vec<Vec<u8>>,
        credential_count: usize,
    }

    impl FixedStatusTransport {
        const fn new(status: StatusWord) -> Self {
            Self {
                status,
                sent: Vec::new(),
                credential_count: 0,
            }
        }

        fn reply(&self) -> TransportOutcome {
            let [sw1, sw2] = self.status.as_u16().to_be_bytes();
            TransportOutcome::Response(ResponseApdu {
                body: Vec::new(),
                sw1,
                sw2,
            })
        }
    }

    impl CardTransport for FixedStatusTransport {
        type Error = String;

        fn transmit(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            self.sent.push(apdu.as_bytes().to_vec());
            Ok(self.reply())
        }

        fn transmit_credential(
            &mut self,
            command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            self.credential_count += 1;
            command.expose_wire(|wire| {
                // Record only the 4-byte APDU header (CLA INS P1 P2), never credential bytes.
                let header_len = wire.len().min(P2_INDEX + 1);
                self.sent.push(wire[..header_len].to_vec());
            });
            Ok(self.reply())
        }
    }

    /// Answers the VERIFY status probe with one status word and the PIN
    /// container `GET DATA` with a PIN changed flag, or without one.
    struct ProbeTransport {
        status: StatusWord,
        changed: Option<u8>,
        sent: Vec<Vec<u8>>,
    }

    impl ProbeTransport {
        const fn new(status: StatusWord, changed: Option<u8>) -> Self {
            Self {
                status,
                changed,
                sent: Vec::new(),
            }
        }
    }

    impl CardTransport for ProbeTransport {
        type Error = String;

        fn transmit(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let bytes = apdu.as_bytes().to_vec();
            let instruction = bytes.get(INS_INDEX).copied();
            self.sent.push(bytes);
            let (body, status) = match (instruction, self.changed) {
                (Some(GET_DATA_ODD_INS), Some(flag)) => (
                    vec![
                        PIN_CHANGED_TAG_HIGH,
                        PIN_CHANGED_TAG_LOW,
                        PIN_CHANGED_LENGTH,
                        flag,
                    ],
                    StatusWord::Success,
                ),
                (Some(GET_DATA_ODD_INS), None) => (Vec::new(), StatusWord::ReferenceDataNotFound),
                _ => (Vec::new(), self.status),
            };
            let [sw1, sw2] = status.as_u16().to_be_bytes();
            Ok(TransportOutcome::Response(ResponseApdu { body, sw1, sw2 }))
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("probe transport must never receive credentials".to_owned())
        }
    }

    fn tries(count: u8) -> Result<StatusWord, String> {
        let retries = PinRetries::from_nibble(count).ok_or("retry count fits a nibble")?;
        Ok(StatusWord::PinIncorrect { retries })
    }

    fn code(
        scheme: ActivationScheme,
    ) -> Result<ValidatedActivationCode, Box<dyn core::error::Error>> {
        let digits = match scheme {
            ActivationScheme::PresetActivationPin => PRESET_PIN,
            ActivationScheme::ActivationCodeIsPuk => PUK_CODE,
        };
        Ok(ValidatedActivationCode::for_scheme(
            scheme,
            ActivationInput::new(digits.to_vec())?,
        )?)
    }

    fn setup(
        transport: &mut FixedStatusTransport,
        numbering: PinReferenceScheme,
        scheme: ActivationScheme,
    ) -> Result<Result<ManageOutcome, CardPinError>, Box<dyn core::error::Error>> {
        let new_pin = Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(NEW_PIN.to_vec()))?;
        Ok(activate_slot_setup(
            transport,
            &CardPinLengths::not_listed(numbering),
            &code(scheme)?,
            UnblockPinTarget::Pin1(new_pin),
        ))
    }

    fn judged(
        numbering: PinReferenceScheme,
        scheme: ActivationScheme,
        status: StatusWord,
        changed: Option<u8>,
    ) -> PinActivation {
        let mut transport = ProbeTransport::new(status, changed);
        probe_pin_activation(&mut transport, numbering, scheme, PinSlot::Pin1).1
    }

    #[test]
    fn a_code_of_the_wrong_length_for_the_scheme_is_refused() -> TestResult {
        for (scheme, digits) in [
            (ActivationScheme::PresetActivationPin, PUK_CODE),
            (ActivationScheme::ActivationCodeIsPuk, PRESET_PIN),
        ] {
            let outcome =
                ValidatedActivationCode::for_scheme(scheme, ActivationInput::new(digits.to_vec())?);
            check_true(
                matches!(
                    outcome,
                    Err(CardPinError::ActivationLengthMismatch { expected, .. })
                        if expected == scheme.activation_entry_digit_count()
                ),
                "the scheme's length is required",
            )?;
        }
        Ok(())
    }

    #[test]
    fn preset_pin_activation_is_served_at_five_four_and_three_tries() -> TestResult {
        for count in SERVED {
            let mut transport = FixedStatusTransport::new(tries(count)?);
            let outcome = setup(
                &mut transport,
                PinReferenceScheme::Citizen,
                ActivationScheme::PresetActivationPin,
            )?;
            check_true(outcome.is_ok(), "activation served above the floor")?;
            check_true(
                transport.sent.len() == PROBE_AND_CHANGE,
                "probe and change sent above the floor",
            )?;
        }
        Ok(())
    }

    #[test]
    fn preset_pin_activation_is_refused_at_two_and_one_tries() -> TestResult {
        for count in LAST_TWO_TRIES {
            let mut transport = FixedStatusTransport::new(tries(count)?);
            let outcome = setup(
                &mut transport,
                PinReferenceScheme::Citizen,
                ActivationScheme::PresetActivationPin,
            )?;
            check_true(
                matches!(
                    outcome,
                    Err(CardPinError::RetryFloor(
                        RetryFloorRefusal::TriesBelowFloor { .. }
                    ))
                ),
                "activation refused below the floor",
            )?;
            check_true(
                transport.sent.len() == PROBE_ONLY,
                "only the counter-safe probe sent below the floor",
            )?;
            check_true(
                transport.credential_count == NO_CREDENTIAL_COMMANDS,
                "no credential APDU sent below the floor",
            )?;
        }
        Ok(())
    }

    #[test]
    fn preset_pin_activation_at_zero_tries_reaches_the_card() -> TestResult {
        let mut transport = FixedStatusTransport::new(tries(NO_TRIES)?);
        let outcome = setup(
            &mut transport,
            PinReferenceScheme::Citizen,
            ActivationScheme::PresetActivationPin,
        )?;
        check_true(
            matches!(
                outcome,
                Ok(ManageOutcome::WrongCredential { retries_left })
                    if retries_left.get() == NO_TRIES
            ),
            "the card's own answer is reported",
        )?;
        check_true(
            transport.sent.len() == PROBE_AND_CHANGE,
            "the probe and CHANGE REFERENCE DATA are sent at zero tries",
        )
    }

    #[test]
    fn preset_pin_activation_on_a_blocked_pin_reports_the_cards_answer() -> TestResult {
        for status in [
            StatusWord::AuthenticationBlocked,
            StatusWord::ReferenceDataInvalidated,
        ] {
            let mut transport = FixedStatusTransport::new(status);
            let outcome = setup(
                &mut transport,
                PinReferenceScheme::Citizen,
                ActivationScheme::PresetActivationPin,
            )?;
            check_true(
                matches!(outcome, Ok(ManageOutcome::Locked)),
                "the card's own answer is reported",
            )?;
            check_true(
                transport.sent.len() == PROBE_AND_CHANGE,
                "the probe and CHANGE REFERENCE DATA are sent to a blocked PIN",
            )?;
        }
        Ok(())
    }

    #[test]
    fn preset_pin_activation_is_refused_on_an_unreadable_counter() -> TestResult {
        for status in [
            StatusWord::AuthenticationFailed,
            StatusWord::from_u16(UNMODELED_SW),
        ] {
            let mut transport = FixedStatusTransport::new(status);
            let outcome = setup(
                &mut transport,
                PinReferenceScheme::Citizen,
                ActivationScheme::PresetActivationPin,
            )?;
            check_true(
                matches!(
                    outcome,
                    Err(CardPinError::RetryFloor(
                        RetryFloorRefusal::CounterUnreadable { .. }
                    ))
                ),
                "unreadable counter refused",
            )?;
            check_true(transport.sent.len() == PROBE_ONLY, "only the probe sent")?;
            check_true(
                transport.credential_count == NO_CREDENTIAL_COMMANDS,
                "no credential APDU sent on unreadable counter",
            )?;
        }
        Ok(())
    }

    #[test]
    fn puk_code_activation_is_served_at_five_four_and_three_puk_tries() -> TestResult {
        for count in SERVED {
            let mut transport = FixedStatusTransport::new(tries(count)?);
            let outcome = setup(
                &mut transport,
                PinReferenceScheme::Citizen,
                ActivationScheme::ActivationCodeIsPuk,
            )?;
            check_true(outcome.is_ok(), "PUK-driven reset served above the floor")?;
            check_true(
                transport.sent.len() == PROBE_AND_RESET,
                "PUK probe and RESET RETRY COUNTER sent above the floor",
            )?;
        }
        Ok(())
    }

    #[test]
    fn puk_code_activation_is_refused_at_two_and_one_puk_tries() -> TestResult {
        for count in LAST_TWO_TRIES {
            let mut transport = FixedStatusTransport::new(tries(count)?);
            let outcome = setup(
                &mut transport,
                PinReferenceScheme::Citizen,
                ActivationScheme::ActivationCodeIsPuk,
            )?;
            let Err(error) = outcome else {
                return Err("PUK-driven reset refused below the floor".into());
            };
            check_true(
                matches!(
                    error,
                    CardPinError::RetryFloor(RetryFloorRefusal::TriesBelowFloor { .. })
                ),
                "refused by the retry floor",
            )?;
            let text = error.to_string();
            check_true(text.contains("PUK"), "refusal names the PUK")?;
            check_true(text.contains(&count.to_string()), "refusal names the tries")?;
            check_true(!text.contains("PIN"), "refusal names no other credential")?;
            check_true(
                transport.sent.len() == PROBE_ONLY,
                "only the counter-safe PUK probe sent below the floor",
            )?;
            check_true(
                transport.credential_count == NO_CREDENTIAL_COMMANDS,
                "no credential APDU sent below the PUK floor",
            )?;
        }
        Ok(())
    }

    #[test]
    fn puk_code_activation_at_zero_puk_tries_reaches_the_card() -> TestResult {
        for (numbering, sent) in [
            (PinReferenceScheme::Citizen, PROBE_AND_RESET),
            (PinReferenceScheme::Organizational, PROBE_AND_VERIFY),
        ] {
            let mut transport = FixedStatusTransport::new(tries(NO_TRIES)?);
            let outcome = setup(
                &mut transport,
                numbering,
                ActivationScheme::ActivationCodeIsPuk,
            )?;
            check_true(
                matches!(
                    outcome,
                    Ok(ManageOutcome::WrongCredential { retries_left })
                        if retries_left.get() == NO_TRIES
                ),
                "the card's own answer is reported",
            )?;
            check_true(
                transport.sent.len() == sent,
                "the PUK probe and the PUK presentation are sent at zero tries",
            )?;
        }
        Ok(())
    }

    #[test]
    fn puk_code_activation_on_a_blocked_puk_reports_the_cards_answer() -> TestResult {
        for status in [
            StatusWord::AuthenticationBlocked,
            StatusWord::ReferenceDataInvalidated,
        ] {
            let mut transport = FixedStatusTransport::new(status);
            let outcome = setup(
                &mut transport,
                PinReferenceScheme::Citizen,
                ActivationScheme::ActivationCodeIsPuk,
            )?;
            check_true(
                matches!(outcome, Ok(ManageOutcome::Locked)),
                "the card's own blocked answer is reported",
            )?;
            check_true(
                transport.sent.len() == PROBE_AND_RESET,
                "the PUK probe and RESET RETRY COUNTER are sent to a blocked PUK",
            )?;
        }
        Ok(())
    }

    #[test]
    fn puk_code_activation_is_refused_on_an_unreadable_puk_counter() -> TestResult {
        for status in [StatusWord::Success, StatusWord::from_u16(UNMODELED_SW)] {
            let mut transport = FixedStatusTransport::new(status);
            let outcome = setup(
                &mut transport,
                PinReferenceScheme::Citizen,
                ActivationScheme::ActivationCodeIsPuk,
            )?;
            check_true(
                matches!(
                    outcome,
                    Err(CardPinError::RetryFloor(
                        RetryFloorRefusal::CounterUnreadable { .. }
                    ))
                ),
                "unreadable PUK counter refused",
            )?;
            check_true(
                transport.sent.len() == CITIZEN_UNREADABLE_PUK_PROBES,
                "only counter-safe VERIFY and GET DATA probes sent",
            )?;
            check_true(
                transport.credential_count == NO_CREDENTIAL_COMMANDS,
                "no credential APDU sent on unreadable PUK counter",
            )?;
        }
        Ok(())
    }

    #[test]
    fn organization_activation_speaks_the_organization_numbering() -> TestResult {
        let mut transport = FixedStatusTransport::new(StatusWord::Success);
        let refused = setup(
            &mut transport,
            PinReferenceScheme::Organizational,
            ActivationScheme::ActivationCodeIsPuk,
        )?;
        check_true(
            matches!(
                refused,
                Err(CardPinError::RetryFloor(
                    RetryFloorRefusal::CounterUnreadable { .. }
                ))
            ),
            "a PUK without a counter is not presented",
        )?;
        check_true(
            transport
                .sent
                .first()
                .and_then(|apdu| apdu.get(P2_INDEX))
                .copied()
                == Some(PUK_REFERENCE_ORGANIZATIONAL),
            "the PUK probe targets the organization PUK",
        )?;

        let mut transport = FixedStatusTransport::new(tries(FULL_COUNTER)?);
        let outcome = setup(
            &mut transport,
            PinReferenceScheme::Organizational,
            ActivationScheme::ActivationCodeIsPuk,
        )?;
        check_true(
            matches!(outcome, Ok(ManageOutcome::WrongCredential { .. })),
            "a refused PUK VERIFY ends the flow",
        )?;
        check_true(
            transport.sent.len() == PROBE_AND_VERIFY,
            "no reset after a refused PUK",
        )?;
        check_true(
            transport
                .sent
                .get(SECOND_COMMAND)
                .and_then(|apdu| apdu.get(INS_INDEX))
                .copied()
                == Some(VERIFY_INS),
            "the code is verified as the PUK first",
        )?;
        check_true(
            transport
                .sent
                .iter()
                .all(|apdu| apdu.get(INS_INDEX).copied() != Some(RESET_RETRY_COUNTER_INS)),
            "no RESET RETRY COUNTER was sent",
        )
    }

    #[test]
    fn a_fresh_puk_scheme_pin_awaits_activation_without_the_flag() -> TestResult {
        for status in [StatusWord::AuthenticationBlocked, tries(NO_TRIES)?] {
            for numbering in [
                PinReferenceScheme::Citizen,
                PinReferenceScheme::Organizational,
            ] {
                check_true(
                    judged(
                        numbering,
                        ActivationScheme::ActivationCodeIsPuk,
                        status,
                        None,
                    ) == PinActivation::AwaitsActivation,
                    "6983 and 63C0 await activation",
                )?;
            }
        }
        Ok(())
    }

    #[test]
    fn a_usable_puk_scheme_pin_is_activated_without_the_flag() -> TestResult {
        check_true(
            judged(
                PinReferenceScheme::Citizen,
                ActivationScheme::ActivationCodeIsPuk,
                tries(FULL_COUNTER)?,
                None,
            ) == PinActivation::Activated,
            "a usable counter is activated",
        )
    }

    #[test]
    fn a_blocked_pin_the_flag_shows_changed_is_activated() -> TestResult {
        check_true(
            judged(
                PinReferenceScheme::Citizen,
                ActivationScheme::ActivationCodeIsPuk,
                StatusWord::AuthenticationBlocked,
                Some(PIN_CHANGED),
            ) == PinActivation::Activated,
            "a used-up PIN belongs to recovery, not activation",
        )
    }

    #[test]
    fn a_preset_pin_scheme_pin_follows_the_flag() -> TestResult {
        let fresh = tries(FULL_COUNTER)?;
        check_true(
            judged(
                PinReferenceScheme::Citizen,
                ActivationScheme::PresetActivationPin,
                fresh,
                Some(PIN_UNCHANGED),
            ) == PinActivation::AwaitsActivation,
            "an unchanged flag awaits activation",
        )?;
        check_true(
            judged(
                PinReferenceScheme::Citizen,
                ActivationScheme::PresetActivationPin,
                fresh,
                Some(PIN_CHANGED),
            ) == PinActivation::Activated,
            "a changed flag is activated",
        )?;
        check_true(
            judged(
                PinReferenceScheme::Citizen,
                ActivationScheme::PresetActivationPin,
                fresh,
                None,
            ) == PinActivation::Activated,
            "no flag counts as activated",
        )
    }

    #[test]
    fn the_probes_speak_the_session_numbering() -> TestResult {
        for (numbering, reference) in [
            (PinReferenceScheme::Citizen, PIN1_REFERENCE),
            (
                PinReferenceScheme::Organizational,
                PIN1_REFERENCE_ORGANIZATIONAL,
            ),
        ] {
            let mut transport = ProbeTransport::new(tries(FULL_COUNTER)?, None);
            let _ = probe_pin_activation(
                &mut transport,
                numbering,
                ActivationScheme::ActivationCodeIsPuk,
                PinSlot::Pin1,
            );
            check_true(
                transport
                    .sent
                    .first()
                    .and_then(|apdu| apdu.get(P2_INDEX))
                    .copied()
                    == Some(reference),
                "the status probe uses the session numbering",
            )?;
        }
        Ok(())
    }

    #[test]
    fn the_preflight_proceeds_only_when_a_pin_awaits_activation() -> TestResult {
        use PinActivation::{Activated, AwaitsActivation};
        for (pin1, pin2) in [
            (AwaitsActivation, AwaitsActivation),
            (Activated, AwaitsActivation),
            (AwaitsActivation, Activated),
        ] {
            check_true(
                matches!(
                    classify_preflight(pin1, pin2),
                    ActivatePreflightOutcome::AwaitsActivation { .. }
                ),
                "a waiting PIN proceeds",
            )?;
        }
        check_true(
            classify_preflight(Activated, Activated).looks_activated(),
            "no waiting PIN refuses",
        )
    }

    #[test]
    fn the_card_evidence_follows_the_pins() -> TestResult {
        use PinActivation::{Activated, AwaitsActivation};
        check_true(
            judge_activation(Activated, AwaitsActivation) == ActivationEvidence::Unactivated,
            "one waiting PIN shows the activation",
        )?;
        check_true(
            judge_activation(Activated, Activated) == ActivationEvidence::Activated,
            "no waiting PIN is activated",
        )
    }

    #[test]
    fn activation_takes_exactly_the_pins_that_await_it() -> TestResult {
        use PinActivation::{Activated, AwaitsActivation};
        check_true(
            matches!(
                activation_targets(Activated, AwaitsActivation, false, true, false),
                Ok((false, true))
            ),
            "only the waiting PIN is set",
        )?;
        check_true(
            matches!(
                activation_targets(AwaitsActivation, AwaitsActivation, true, true, false),
                Ok((true, true))
            ),
            "both waiting PINs are set",
        )?;
        for (pin1_entered, pin2_entered) in [(true, true), (false, false), (true, false)] {
            check_true(
                matches!(
                    activation_targets(
                        Activated,
                        AwaitsActivation,
                        pin1_entered,
                        pin2_entered,
                        false
                    ),
                    Err(CardPinError::ActivationEntriesMismatch {
                        pin1_awaits: false,
                        pin2_awaits: true
                    })
                ),
                "an entry for a set PIN, or a missing entry, is refused",
            )?;
        }
        check_true(
            matches!(
                activation_targets(Activated, Activated, true, true, true),
                Ok((true, true))
            ),
            "reactivation sets every PIN entered",
        )?;
        check_true(
            activation_targets(Activated, Activated, false, false, true).is_err(),
            "reactivation needs at least one PIN",
        )
    }

    #[test]
    fn activation_failure_never_proceeds_to_pin2() -> TestResult {
        let three = PinRetries::from_nibble(THREE_RETRIES).ok_or("THREE_RETRIES fits a nibble")?;
        check_true(
            activation_continues_after_pin1(ManageOutcome::Ok),
            "successful PIN1 activation proceeds to PIN2",
        )?;
        for outcome in [
            ManageOutcome::WrongCredential {
                retries_left: three,
            },
            ManageOutcome::Locked,
            ManageOutcome::Other(StatusWord::WrongLength),
            ManageOutcome::Other(StatusWord::from_u16(UNMODELED_SW)),
        ] {
            check_true(
                !activation_continues_after_pin1(outcome),
                "failed PIN1 activation stops before PIN2",
            )?;
        }
        Ok(())
    }
}
