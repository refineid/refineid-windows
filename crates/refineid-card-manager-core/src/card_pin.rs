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
//! PIN bytes never reach argv, env, or any log line; the prompts
//! use rpassword (or stdin bufread when no tty) and the move into
//! [`PinBytes`] is immediate so the buffer zeroes on drop.

use alloc::fmt;

use refineid_lib_core::activation::{ActivationScheme, PinActivation};
use refineid_lib_core::auth::{
    AuthError, ChangePinOutcome, PinOps as _, PinPolicyReason, PinReferenceScheme, PinSlot,
    PinStatus, UnblockOutcome,
};
use refineid_lib_core::backend::{
    ReaderAccessCap, ReaderBackend as _, ReaderFilter, ReaderPickError,
};
use refineid_lib_core::fineid_card::{CardClassificationError, FineidCardModel};
use refineid_lib_core::pin::{ActivationCode, PinBytes, PinRoleError, Puk};
use refineid_lib_core::pin_retry_risk::{
    RetryFloorRefusal, check_puk_retry_floor, check_retry_floor,
};
use refineid_lib_core::pkcs15::{CertSlot, FineidReaderPick};
use refineid_lib_core::pkcs15::{FineidReaderPicker as _, Pkcs15Ops as _};
use refineid_lib_core::x509::{OwnedCert, UnvalidatedCertificate};
use refineid_lib_pcsc::{PcscBackend, PcscError};

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
    /// Project to the lib-core [`PinSlot`] enum used by transport-
    /// level APDU builders. Drops the CLI-only label.
    #[must_use]
    pub const fn as_pin_slot(self) -> PinSlot {
        match self {
            Self::Pin1 => PinSlot::Pin1,
            Self::Pin2 => PinSlot::Pin2,
        }
    }
    /// User-facing label ("PIN1" / "PIN2") for prompts and report
    /// strings. `&'static str` from a fixed compile-time set.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pin1 => "PIN1",
            Self::Pin2 => "PIN2",
        }
    }
}

/// Inputs for `card change-pin{1,2}`.
#[derive(Debug)]
pub struct ChangePinOptions {
    /// Which PIN slot to rotate. Drives both the APDU PIN
    /// reference byte and the spec rule applied to the new PIN
    /// length policy.
    pub slot: PinManageSlot,
    /// Current PIN value (the one the operator typed in the
    /// "current PIN" prompt). Consumed and zeroized at function
    /// return.
    pub current: PinBytes,
    /// New PIN value (the one the operator typed in the
    /// "new PIN" prompt). Consumed and zeroized at function
    /// return.
    pub new: PinBytes,
    /// Optional substring match against reader names; same
    /// semantics as the rest of the client crate. `None` accepts
    /// any single FINEID-responding reader (errors on ambiguity).
    /// Tier 0 `String` -- carried verbatim to
    /// `ReaderFilter::new`; tighter form would be `ReaderFilter`.
    pub reader_filter: Option<String>,
}

/// One reader's worth of change-pin output.
#[derive(Debug, Clone)]
pub struct ChangePinReport {
    /// PC/SC reader name the modify APDU landed against. Tier 0
    /// `String` from `ReaderId::as_str().to_owned()`; tighter
    /// form would be `ReaderId`.
    pub reader: String,
    /// `CredentialIdentity::best_serial()` of the bound
    /// card: PKCS#15 token serial when present, else printed /
    /// PEUIN form. Empty string when nothing was readable.
    /// Surfaced so the operator can confirm which physical card
    /// the PIN op landed against when multiple readers are
    /// connected.
    pub card_serial: String,
    /// `CredentialIdentity::person_string()` rendering --
    /// "SURNAME GIVENS" form (still uppercase per
    /// DVV-emitted cert subject; the typed [`NativeName`]
    /// rendering is a separate concern).
    ///
    /// [`NativeName`]: refineid_lib_core::identity::NativeName
    pub person: String,
    /// Which PIN slot the modify APDU targeted.
    pub slot: PinManageSlot,
    /// Card-side outcome from `CHANGE REFERENCE DATA`
    /// (FINEID S4-1 v3.1 §4.1.3 / ISO 7816-4 §7.5.7): Ok,
    /// `WrongCurrentPin` with retries, Locked, etc.
    pub outcome: ChangePinOutcome,
}

/// Inputs for `card unblock-pin{1,2}`.
#[derive(Debug)]
pub struct UnblockPinOptions {
    /// Which PIN slot to unblock. One PUK recovers both PIN1 and
    /// PIN2.
    pub slot: PinManageSlot,
    /// The PUK code. Typed [`Puk`] forces construction
    /// via [`Puk::new`] at the operator-input boundary, so a
    /// non-PUK `PinBytes` value (e.g. a PIN or the activation PIN)
    /// can't reach the `RESET RETRY COUNTER` APDU by accident.
    pub puk: Puk,
    /// New PIN value to set after the unblock succeeds. Consumed
    /// and zeroized at function return.
    pub new_pin: PinBytes,
    /// Optional substring match against reader names; same
    /// semantics as [`ChangePinOptions::reader_filter`]. Tier 0
    /// `String` -- presentational input to `ReaderFilter::new`.
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
    /// Card-side outcome from `RESET RETRY COUNTER`
    /// (FINEID S4-1 v3.1 §4.1.4 / ISO 7816-4 §7.5.10): Ok,
    /// `WrongPuk` with retries, `PukLocked`, etc.
    pub outcome: UnblockOutcome,
}

/// Error returned from the PIN-management entrypoints
/// (`card change-pin*`, `card unblock-pin*`, `card activate`).
#[derive(Debug)]
pub enum CardPinError {
    /// Reader enumeration / filter resolution failed.
    ReaderPick(ReaderPickError),
    /// PC/SC transport / transmit error.
    Pcsc(PcscError),
    /// Local-policy rejection (length / non-digit) before any
    /// APDU went out. Retry counter is unaffected.
    PinPolicy(PinPolicyReason),
    /// Couldn't SELECT the PKCS#15 application. FINEID gates the
    /// PIN-management INS bytes (0x20 status-form, 0x24, 0x2C)
    /// behind app SELECT -- SW=6D00 otherwise.
    Pkcs15Select(String),
    /// Lower-level transport / APDU failure not specific to PKCS#15
    /// SELECT (cert read, EF.TokenInfo read, ...). Tier 0 `String`
    /// -- presentational rendering of the upstream error.
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
        /// Tier 0 `String`; presentational.
        description: String,
    },
    /// The bound card session was invalidated between session
    /// open and the operation. Possible causes: card
    /// removed from reader mid-flow, reader unplugged, a
    /// different card inserted, the same physical port re-
    /// enumerated as a different reader. The binding does not survive
    /// any of these; the operator must re-run.
    CardSessionRevoked {
        /// Human-readable detail from
        /// `re_verify_session` explaining which invariant
        /// diverged (serial mismatch, EF.TokenInfo unreadable,
        /// ...). Tier 0 `String`; presentational.
        reason: String,
    },
    /// The card's contact-interface ATR doesn't match any
    /// FINEID card model refineid recognises. Expired card models
    /// land here, as does any non-FINEID smartcard inserted in the
    /// reader.
    CardModelNotSupported(CardClassificationError),
    /// `card change-pin*` / `card unblock-pin*`: the PIN's
    /// counter-safe probes (PIN changed flag and status) show a PIN
    /// that awaits its activation ([`PinActivation`]), or the status
    /// probe returned no status word. Refineid refuses before any
    /// modify APDU goes out so a wrong-state attempt cannot burn a
    /// try-counter slot. The operator should run
    /// `refineid card activate` first.
    CardLooksUnactivated {
        /// Which PIN slot the probe targeted.
        slot: PinManageSlot,
        /// Raw status probe outcome. `None` when the probe APDU
        /// itself failed to return a status word.
        probe: Option<PinStatus>,
    },
    /// The retry floor refused a command that would spend a PIN attempt:
    /// the card reports two, one or no tries left, the PIN blocked, or no
    /// readable counter. Nothing was sent.
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
            Self::PinPolicy(r) => write!(f, "PIN / PUK rejected locally: {r}"),
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
                     first to set PIN1 and PIN2.",
                    slot.label()
                )
            }
            Self::RetryFloor(refusal) => write!(f, "{refusal}"),
            Self::ActivationEntriesMismatch {
                pin1_awaits,
                pin2_awaits,
            } => {
                let awaiting = match (pin1_awaits, pin2_awaits) {
                    (true, true) => "PIN1 and PIN2",
                    (true, false) => "PIN1",
                    (false, true) => "PIN2",
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

/// Map a lib-core `AuthError<TE>` into the client-side
/// [`CardPinError`] surface.
///
/// Transport errors stringify through the inner `Display` so
/// the CLI can show the underlying PC/SC message without
/// leaking the typed error to the public surface. PIN-policy
/// reasons (digit-only, length bounds) pass through as
/// `PinPolicy` because they are local-policy hits -- no
/// counter-burning APDU went out.
fn auth_to_card_pin(e: AuthError<impl fmt::Display>) -> CardPinError {
    match e {
        AuthError::Transport(t) => CardPinError::Transport(format!("{t}")),
        AuthError::PinPolicy(r) => CardPinError::PinPolicy(r),
    }
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
///
/// Built by `establish_card_session`: card is identified
/// by ATR against the recognised FINEID model set, and its
/// PKCS#15 long serial is captured so any later step can
/// detect a card swap mid-flow.
#[derive(Debug, Clone)]
pub struct BoundCardSession {
    /// PC/SC reader id captured at session open; every
    /// subsequent re-open in the flow uses exactly this id.
    pub reader_id: refineid_lib_core::backend::ReaderId,
    /// Person identity extracted from the auth cert's subject DN
    /// (FINEID S2 §6.3.8.3). Read once at session open so PIN
    /// reports can show "who" without re-reading the cert.
    pub identity: refineid_lib_core::identity::CredentialIdentity,
    /// PKCS#15 long serial bound at session open; every
    /// subsequent step re-reads and compares against this value
    /// to detect a card swap.
    pub bound_serial: refineid_lib_core::identity::TokenSerial,
    /// ATR-classified FINEID card model from the recognised set.
    pub model: FineidCardModel,
    /// The credential-reference numbering the card answered to.
    pub numbering: PinReferenceScheme,
    /// The card's activation scheme ([`ActivationScheme::for_card`]).
    pub scheme: ActivationScheme,
}

impl BoundCardSession {
    /// Promote a bound session into the
    /// [`PinManagementCardContext`] typestate, the input
    /// shape for `change_pin_first` and
    /// `unblock_pin_first`. By calling this constructor the
    /// caller asserts operator intent: the operator chose a
    /// PIN-management command (not `card activate`), so they
    /// are claiming the card is in an already-activated
    /// state and the modify APDU is appropriate. The compiler
    /// then enforces that no `card activate` code path can
    /// consume this value.
    ///
    /// This split is the type-level half of the safety; the
    /// runtime half (`pin_status` preflight + card-side
    /// counter on wrong PIN attempts) is in the modify
    /// functions themselves. Neither half alone catches every
    /// "operator inserted the wrong card" case; together they
    /// raise the floor.
    #[must_use]
    pub const fn into_pin_management_context(self) -> PinManagementCardContext {
        PinManagementCardContext { session: self }
    }
}

/// Card session promoted from a bound base into the
/// "operator intends a PIN-management operation on an
/// already-activated card" typestate.
///
/// The type is opaque: there is no public field set, only a
/// borrow path back to the inner [`BoundCardSession`].
/// Construct via
/// [`BoundCardSession::into_pin_management_context`] from
/// the CLI's `card change-pin*` / `card unblock-pin*`
/// dispatch. Code in the `card activate` dispatch cannot
/// produce this typestate by construction.
#[derive(Debug, Clone)]
pub struct PinManagementCardContext {
    /// Inner bound session this context was promoted from.
    /// Held privately so callers can only reach
    /// reader id / identity / serial via the inherent methods,
    /// preventing accidental construction of an unrelated
    /// `PinManagementCardContext` from a stale session value.
    session: BoundCardSession,
}

impl PinManagementCardContext {
    /// Borrow the reader id this context is bound to.
    #[must_use]
    pub const fn reader_id(&self) -> &refineid_lib_core::backend::ReaderId {
        &self.session.reader_id
    }
    /// Borrow the person identity captured at session open.
    #[must_use]
    pub const fn identity(&self) -> &refineid_lib_core::identity::CredentialIdentity {
        &self.session.identity
    }
    /// Borrow the PKCS#15 long serial bound at session open.
    /// `re_verify_session` compares the on-card serial against
    /// this value before every modify APDU.
    #[must_use]
    pub const fn bound_serial(&self) -> &refineid_lib_core::identity::TokenSerial {
        &self.session.bound_serial
    }
    /// ATR-classified FINEID card model captured at session
    /// open. `Copy` because [`FineidCardModel`] is a small enum.
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
/// Phases (in order):
/// 1. Pick the FINEID-shape reader (or apply `reader_filter`).
/// 2. Open the transport, read the ATR, classify against the
///    recognised `FineidCardModel` set.
/// 3. SELECT the PKCS#15 application.
/// 4. Capture the PKCS#15 long serial for session binding.
/// 5. Resolve the card's reference numbering with the counter-safe
///    VERIFY probe, and decide its activation scheme: the
///    organization numbering means §4.6.1; under the citizen
///    numbering the authentication certificate's validity start
///    decides it.
///
/// Returns a [`BoundCardSession`] the caller flows into the
/// modify step. The transport from this call is dropped; the
/// caller re-opens against `session.reader_id` and uses
/// `re_verify_session` before each modify APDU.
///
/// # Errors
/// - `CardModelNotSupported` -- ATR didn't classify.
/// - `CardSerialUnavailable` -- PKCS#15 serial unavailable.
/// - PC/SC / SELECT / cert-read failures.
pub fn establish_card_session(
    backend: PcscBackend,
    reader_filter: Option<&ReaderFilter>,
) -> Result<BoundCardSession, CardPinError> {
    use refineid_lib_core::transport::CardTransport as _;

    let FineidReaderPick {
        reader_id,
        identity,
    } = backend.pick_fineid_reader(reader_filter)?;
    let mut transport = backend.open_exclusive(&reader_id, ReaderAccessCap::Read)?;

    // ATR classify -- public protocol-level signal; rejects
    // unrecognised cards before any card-side data read.
    let atr = transport
        .atr()
        .map_err(|e| CardPinError::Transport(format!("ATR length: {e}")))?;
    let model = atr
        .classify()
        .map_err(CardPinError::CardModelNotSupported)?;

    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;

    // Bind the PKCS#15 long serial; `re_verify_session` checks
    // against this on every subsequent step. The serial is
    // session state (binds this transport to a specific
    // physical card for swap detection), not person identity,
    // so it doesn't live on `CredentialIdentity` -- read it
    // here directly from EF.TokenInfo.
    let token = transport
        .read_token_info()
        .map_err(|e| CardPinError::Transport(format!("EF.TokenInfo read: {e}")))?;
    let bound_serial = match token.serial_number_hex {
        Some(hex) => refineid_lib_core::identity::render_token_serial(hex),
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
                .read_certificate(CertSlot::Authentication)
                .map_err(|e| CardPinError::Transport(format!("auth cert read: {e}")))?;
            let cert = OwnedCert::from_der(UnvalidatedCertificate::new(der.as_bytes().to_vec()))
                .map_err(|e| CardPinError::Transport(format!("auth cert parse: {e}")))?;
            Some(cert.view().not_before)
        }
    };
    let scheme = ActivationScheme::for_card(numbering, validity_start)
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
///
/// Returns the raw status probe alongside the verdict so a refusal
/// can carry it.
fn probe_pin_activation<T: refineid_lib_core::transport::CardTransport>(
    transport: &mut T,
    numbering: PinReferenceScheme,
    scheme: ActivationScheme,
    slot: PinSlot,
) -> (Option<PinStatus>, PinActivation) {
    let status = transport.pin_status_with_scheme(numbering, slot).ok();
    let changed = transport
        .pin_changed_flag_with_scheme(numbering, slot)
        .ok()
        .flatten();
    (status, PinActivation::judge(scheme, changed, status))
}

/// The status of a PIN that does not await its activation, or the
/// refusal for one that does ([`PinActivation::judge`]) or whose
/// status probe returned no status word. The retry floor then
/// applies to the returned status.
fn require_activated<T: refineid_lib_core::transport::CardTransport>(
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

/// Rotate the PIN in `options.slot`. The card's own outcome
/// (wrong-current-PIN with retries-left, locked, etc.) is
/// surfaced via [`ChangePinReport::outcome`], not as an error.
///
/// `options` is taken by value so both embedded [`PinBytes`]
/// drop (and zeroize) when this returns.
///
/// # Errors
/// PC/SC / PKCS#15 / local-policy / transport failures.
pub fn change_pin_first(
    backend: PcscBackend,
    ctx: PinManagementCardContext,
    options: ChangePinOptions,
) -> Result<ChangePinReport, CardPinError> {
    // The typestate parameter `ctx` proves the caller is on a
    // PIN-management command path (operator intent: card is
    // activated). The compiler refuses to let
    // `ActivationCardContext` flow into this signature; the
    // `card activate` dispatch cannot reach this function.
    let person = ctx.identity().person_string();
    let card_serial = ctx.identity().best_serial().unwrap_or("").to_owned();

    // Re-open against the bound reader, SELECT, and re-verify
    // the bound serial -- catches a card swap between the
    // session open and the modify APDU.
    let mut transport = backend.open_exclusive(ctx.reader_id(), ReaderAccessCap::Read)?;
    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;
    re_verify_session(&mut transport, ctx.bound_serial())?;

    // Counter-safe probes: the PIN must show activated, and its
    // counter must clear the retry floor.
    let slot = options.slot.as_pin_slot();
    let status = require_activated(&mut transport, &ctx, options.slot)?;
    check_retry_floor(slot.into(), status).map_err(CardPinError::RetryFloor)?;

    re_verify_session(&mut transport, ctx.bound_serial())?;

    let outcome = transport
        .change_pin_with_scheme(
            ctx.numbering(),
            slot,
            options.current.clone(),
            options.new.clone(),
        )
        .map_err(auth_to_card_pin)?;
    let report = ChangePinReport {
        reader: ctx.reader_id().as_str().to_owned(),
        card_serial,
        person,
        slot: options.slot,
        outcome,
    };
    drop(options);
    drop(ctx);
    Ok(report)
}

/// PUK-driven unblock + replace PIN in `options.slot`.
///
/// **Danger:** a wrong PUK decrements the PUK try counter. Once
/// exhausted the card is dead -- no software recovery, DVV
/// reissue required. The card's own outcome (wrong-PUK with
/// retries-left, PUK locked, etc.) is surfaced via
/// [`UnblockPinReport::outcome`]. The PUK is presented only at five,
/// four or three PUK tries left; the target PIN's counter does not gate
/// the reset.
///
/// # Errors
/// PC/SC / PKCS#15 / local-policy / transport failures, and
/// [`CardPinError::RetryFloor`] for a PUK below the floor, blocked or
/// unreadable.
#[expect(
    clippy::needless_pass_by_value,
    reason = "UnblockPinOptions embeds PUK + new-PIN PinBytes; consumed by value so both drop+zeroize at function return."
)]
pub fn unblock_pin_first(
    backend: PcscBackend,
    ctx: PinManagementCardContext,
    options: UnblockPinOptions,
) -> Result<UnblockPinReport, CardPinError> {
    let person = ctx.identity().person_string();
    let card_serial = ctx.identity().best_serial().unwrap_or("").to_owned();

    let mut transport = backend.open_exclusive(ctx.reader_id(), ReaderAccessCap::Read)?;
    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;
    re_verify_session(&mut transport, ctx.bound_serial())?;

    let slot = options.slot.as_pin_slot();
    require_activated(&mut transport, &ctx, options.slot)?;

    re_verify_session(&mut transport, ctx.bound_serial())?;

    puk_retry_floor(&mut transport, ctx.numbering())?;

    // Bridge typed Puk to the auth primitive's PinBytes. The
    // transient PinBytes zeroizes on drop, same as every other
    // secret material.
    let puk_bytes = options.puk.to_pin_bytes();
    let outcome = transport
        .reset_retry_counter_with_scheme(ctx.numbering(), slot, puk_bytes, options.new_pin.clone())
        .map_err(auth_to_card_pin)?;
    Ok(UnblockPinReport {
        reader: ctx.reader_id().as_str().to_owned(),
        card_serial,
        person,
        slot: options.slot,
        outcome,
    })
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
            ChangePinOutcome::Ok => writeln!(
                f,
                "{label} changed; retry counter reset; re-VERIFY required for further ops"
            )?,
            ChangePinOutcome::WrongCurrentPin { retries_left } => {
                writeln!(f, "current {label} was wrong ({retries_left} retries left)")?;
            }
            ChangePinOutcome::Locked => writeln!(
                f,
                "{label} is blocked -- use the PUK to unblock before retrying"
            )?,
            ChangePinOutcome::LengthError => {
                writeln!(f, "card rejected APDU length (SW=6700) -- host bug")?;
            }
            ChangePinOutcome::Other(sw) => writeln!(f, "card returned unexpected SW={sw:#06X}")?,
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
            UnblockOutcome::Ok => writeln!(
                f,
                "{label} unblocked; retry counter reset to max; re-VERIFY required for further ops"
            )?,
            UnblockOutcome::WrongPuk { retries_left } => writeln!(
                f,
                "PUK was wrong ({retries_left} retries left on the PUK itself; \
                 exhausting it permanently bricks the card)"
            )?,
            UnblockOutcome::PukLocked => writeln!(
                f,
                "PUK is itself blocked -- card needs DVV reissue, no software recovery"
            )?,
            UnblockOutcome::Invalidated => writeln!(
                f,
                "PIN unblock counter or PUK usage counter exhausted -- card needs DVV reissue"
            )?,
            UnblockOutcome::LengthError => {
                writeln!(f, "card rejected APDU length (SW=6700) -- host bug")?;
            }
            UnblockOutcome::Other(sw) => writeln!(f, "card returned unexpected SW={sw:#06X}")?,
        }
        Ok(())
    }
}

// ---- card activate -- first-time setup flow --------------------

/// Pre-activation card context.
///
/// The activation flow uses its [`ActivationScheme`] to name the
/// expected activation-code length and to choose the activation
/// command.
///
/// The context also pins the **session identity** -- reader
/// name + card's long serial -- captured at session open.
/// Any subsequent step in the activation flow re-reads the
/// card's serial and refuses to continue if it doesn't match
/// (or if the transport fails outright, which covers card
/// removal / reader unplug / reader rename). The binding does not
/// survive a physical-state change.
#[derive(Debug, Clone)]
pub struct ActivationCardContext {
    /// PC/SC reader id captured at session open; subsequent
    /// re-opens in the activate flow use exactly this id.
    pub reader_id: refineid_lib_core::backend::ReaderId,
    /// Person identity extracted from the auth cert's subject DN
    /// at session open. Surfaced in activate report output.
    pub identity: refineid_lib_core::identity::CredentialIdentity,
    /// The credential-reference numbering the card answered to.
    pub numbering: PinReferenceScheme,
    /// The card's activation scheme ([`ActivationScheme::for_card`]).
    pub scheme: ActivationScheme,
    /// PKCS#15 EF.TokenInfo serial (long form) captured at
    /// session open. Any subsequent operation re-reads this
    /// and must match -- a different value means a card swap
    /// happened mid-flow, which revokes the session.
    pub bound_serial: refineid_lib_core::identity::TokenSerial,
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
/// Called before every card-touching step in the activation
/// flow so a card swap / reader unplug / card removal between
/// session open and the modify APDU is detected and refused.
///
/// # Errors
/// `CardSessionRevoked` on any divergence. The binding cannot
/// be re-established by retrying -- the operator must re-run
/// the whole command.
pub(crate) fn re_verify_session<T: refineid_lib_core::transport::CardTransport>(
    transport: &mut T,
    bound_serial: &refineid_lib_core::identity::TokenSerial,
) -> Result<(), CardPinError> {
    use refineid_lib_core::identity::render_token_serial;
    use refineid_lib_core::pkcs15::Pkcs15Ops as _;
    let token = transport
        .read_token_info()
        .map_err(|e| CardPinError::CardSessionRevoked {
            reason: format!("re-read EF.TokenInfo failed: {e}"),
        })?;
    let now_serial =
        token
            .serial_number_hex
            .as_ref()
            .ok_or_else(|| CardPinError::CardSessionRevoked {
                reason: "card no longer publishes EF.TokenInfo serial".to_owned(),
            })?;
    let current_full = render_token_serial(now_serial.clone());
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

/// Inputs for `card activate` -- the one-time DVV activation flow
/// that consumes the activation PIN (aktivointitunnusluku) from
/// the activation letter and sets the initial values of PIN1 and
/// PIN2.
#[derive(Debug)]
pub struct ActivateOptions {
    /// The activation PIN from the DVV activation letter, as typed.
    /// [`activate_first`] reads it as the card's scheme takes it
    /// ([`ActivationCode::for_scheme`]); a length the scheme does not
    /// take is reported as [`CardPinError::ActivationLengthMismatch`]
    /// before any command is sent.
    pub activation_code: PinBytes,
    /// New basic PIN (PIN1, 4-12 digits), given exactly when PIN1
    /// awaits activation.
    pub new_pin1: Option<PinBytes>,
    /// New signature PIN (PIN2, 6-12 digits), given exactly when PIN2
    /// awaits activation.
    pub new_pin2: Option<PinBytes>,
    /// Override the pre-flight refusal when no PIN awaits its
    /// activation, and set every PIN given. Defaults to refuse; flip
    /// to `true` only when the operator genuinely intends to overwrite
    /// an active card's PINs (requires the activation PIN to still
    /// be valid).
    pub allow_reactivate: bool,
}

/// One reader's worth of activate output.
#[derive(Debug, Clone)]
pub struct ActivateReport {
    /// PC/SC reader name the activation APDUs landed against.
    /// Tier 0 `String` from `ReaderId::as_str().to_owned()`.
    pub reader: String,
    /// The per-PIN pre-flight verdict. Surfaced so the operator
    /// can see what refineid found when it ran.
    pub preflight: ActivatePreflightOutcome,
    /// Card's outcome for the PIN1 activation command. `None` when
    /// no command went to PIN1: the pre-flight refused, or PIN1 did
    /// not await its activation and was not given.
    pub pin1_outcome: Option<UnblockOutcome>,
    /// Same for PIN2. Also `None` when PIN1 setup failed (we don't
    /// burn a second activation attempt against a card that's
    /// already rejected the code).
    pub pin2_outcome: Option<UnblockOutcome>,
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
    /// `true` when no PIN awaits its activation. The CLI uses this
    /// to abort activation unless `--allow-reactivate` was passed.
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
///
/// Without `allow_reactivate` the entries must name exactly the PINs
/// that await activation. With it, every PIN entered is set. Either
/// way at least one PIN must be entered.
///
/// # Errors
/// [`CardPinError::ActivationEntriesMismatch`] when the entries do not
/// match; nothing is sent to the card.
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

/// Map a `CHANGE REFERENCE DATA` outcome onto the
/// `UnblockOutcome` shape so [`ActivateReport`] can carry either
/// scheme's per-slot result behind a single field. The user-
/// facing semantics line up: a wrong "current PIN" on the §4.6.2
/// scheme decrements the same five-try budget that a wrong PUK
/// burns on the §4.6.1 scheme, and the recovery path on either
/// terminal failure is the same DVV PUK-order procedure (S4-1
/// v4.2 §4.6.2 "When PIN(s) is/are blocked").
const fn change_to_unblock(o: ChangePinOutcome) -> UnblockOutcome {
    match o {
        ChangePinOutcome::Ok => UnblockOutcome::Ok,
        ChangePinOutcome::WrongCurrentPin { retries_left } => {
            UnblockOutcome::WrongPuk { retries_left }
        }
        ChangePinOutcome::Locked => UnblockOutcome::PukLocked,
        ChangePinOutcome::LengthError => UnblockOutcome::LengthError,
        ChangePinOutcome::Other(sw) => UnblockOutcome::Other(sw),
    }
}

/// Read the PUK's counter under `numbering` without spending a try
/// and apply the retry floor to it, before anything that presents the
/// PUK is sent.
fn puk_retry_floor<T: refineid_lib_core::transport::CardTransport>(
    transport: &mut T,
    numbering: PinReferenceScheme,
) -> Result<(), CardPinError> {
    let status = transport
        .puk_status_with_scheme(numbering)
        .map_err(auth_to_card_pin)?;
    check_puk_retry_floor(status).map_err(CardPinError::RetryFloor)
}

/// Per-slot setup for [`activate_first`]: dispatch the
/// scheme's command under the card's numbering and return the
/// typed [`UnblockOutcome`].
///
/// - §4.6.2 ([`ActivationScheme::PresetActivationPin`]):
///   `CHANGE REFERENCE DATA` from the preset activation PIN, behind
///   the slot's retry floor.
/// - §4.6.1 ([`ActivationScheme::ActivationCodeIsPuk`]):
///   `RESET RETRY COUNTER` presenting the activation PIN as the
///   PUK, behind the PUK's retry floor.
///
/// `new_pin` is consumed by value so the PIN material drops +
/// zeroizes at function return; the activation PIN's transient copy
/// zeroizes on drop.
fn activate_slot_setup<T: refineid_lib_core::transport::CardTransport>(
    transport: &mut T,
    numbering: PinReferenceScheme,
    slot: PinSlot,
    activation_code: &ActivationCode,
    new_pin: PinBytes,
) -> Result<UnblockOutcome, CardPinError> {
    match activation_code {
        ActivationCode::Seven(_) => {
            // The activation PIN is the slot's current PIN: a wrong one
            // spends that slot's tries, so the retry floor applies.
            let status = transport
                .pin_status_with_scheme(numbering, slot)
                .map_err(auth_to_card_pin)?;
            check_retry_floor(slot.into(), status).map_err(CardPinError::RetryFloor)?;
            transport
                .change_pin_with_scheme(numbering, slot, activation_code.to_pin_bytes(), new_pin)
                .map(change_to_unblock)
                .map_err(auth_to_card_pin)
        }
        ActivationCode::Eight(_) => {
            // The activation PIN is presented as the PUK, under the
            // PUK's counter.
            puk_retry_floor(transport, numbering)?;
            transport
                .reset_retry_counter_with_scheme(
                    numbering,
                    slot,
                    activation_code.to_pin_bytes(),
                    new_pin,
                )
                .map_err(auth_to_card_pin)
        }
    }
}

const fn activation_continues_after_pin1(outcome: UnblockOutcome) -> bool {
    matches!(outcome, UnblockOutcome::Ok)
}

/// Read the typed activation PIN as the card's scheme takes it.
///
/// # Errors
/// [`CardPinError::ActivationLengthMismatch`] for a length the scheme
/// does not take; nothing is sent to the card.
fn activation_code_for(
    scheme: ActivationScheme,
    code: PinBytes,
) -> Result<ActivationCode, CardPinError> {
    ActivationCode::for_scheme(scheme, code).map_err(|error| match error {
        PinRoleError::NonDigit { at } => {
            CardPinError::PinPolicy(PinPolicyReason::NonDigit { byte_offset: at })
        }
        PinRoleError::Empty | PinRoleError::WrongLength { .. } => {
            CardPinError::ActivationLengthMismatch {
                scheme,
                expected: scheme.activation_entry_digit_count(),
            }
        }
    })
}

/// Drive the `card activate` flow: bound card -> activation
/// code from the letter -> fresh PIN1/PIN2.
///
/// Two activation schemes per FINEID S4-1 v4.2 §4.6, sent under the
/// card's reference numbering:
///
/// - **§4.6.1, [`ActivationScheme::ActivationCodeIsPuk`]:** PIN1
///   and PIN2 ship BLOCKED. The 8-digit activation PIN is the
///   PUK that unblocks them: `RESET RETRY COUNTER` per PIN. An
///   organization card takes this scheme.
/// - **§4.6.2, [`ActivationScheme::PresetActivationPin`]:** PIN1
///   and PIN2 ship SET to the same 7-digit activation PIN:
///   `CHANGE REFERENCE DATA` per PIN with
///   `(current=activation_pin, new=new_pin)`.
///
/// Steps:
///
///   1. Read the typed code as the scheme takes it; a wrong length
///      is refused before the reader is opened.
///   2. Open a transport session against the bound reader and
///      re-verify the session binding.
///   3. Judge each PIN from its counter-safe probes (PIN changed
///      flag and status, [`PinActivation::judge`]).
///   4. Refuse without `--allow-reactivate` when no PIN awaits its
///      activation, and refuse when the new PINs entered are not
///      exactly the PINs that await it.
///   5. Set each PIN entered. A PIN1 outcome other than `Ok` stops
///      the flow before PIN2.
///
/// `options` (and the inner [`PinBytes`]) is consumed by value
/// so on return the activation PIN + new PIN1/PIN2 are zeroized.
///
/// # Errors
/// PC/SC, PKCS#15-SELECT, reader-pick, length or local-policy
/// failures. Card-side outcomes (wrong activation PIN, locked, etc.)
/// are surfaced via [`ActivateReport`], not as `Err`.
#[expect(
    clippy::needless_pass_by_value,
    reason = "ActivateOptions embeds activation PIN + new PIN1/PIN2 PinBytes; consumed by value so all drop+zeroize at function return."
)]
pub fn activate_first(
    backend: PcscBackend,
    ctx: ActivationCardContext,
    options: ActivateOptions,
) -> Result<ActivateReport, CardPinError> {
    // Read the code as the scheme takes it *before* opening the
    // reader, so a wrong length costs nothing.
    let reader_label = ctx.reader_id.as_str().to_owned();
    let activation_code = activation_code_for(ctx.scheme, options.activation_code.clone())?;

    let mut transport = backend.open_exclusive(&ctx.reader_id, ReaderAccessCap::Read)?;
    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;

    // Session re-verification: the card we are about to touch
    // must be the same physical card the session was bound to.
    // A card swap / reader rename / reader unplug between session
    // open and here revokes the session before any modify APDU
    // lands.
    re_verify_session(&mut transport, &ctx.bound_serial)?;

    let (_, pin1) = probe_pin_activation(&mut transport, ctx.numbering, ctx.scheme, PinSlot::Pin1);
    let (_, pin2) = probe_pin_activation(&mut transport, ctx.numbering, ctx.scheme, PinSlot::Pin2);
    let preflight = classify_preflight(pin1, pin2);

    if !options.allow_reactivate && preflight.looks_activated() {
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
        options.new_pin1.is_some(),
        options.new_pin2.is_some(),
        options.allow_reactivate,
    )?;

    let mut pin1_outcome = None;
    if let Some(new_pin1) = options.new_pin1 {
        // Re-verify session before the first modify APDU.
        re_verify_session(&mut transport, &ctx.bound_serial)?;
        let outcome = activate_slot_setup(
            &mut transport,
            ctx.numbering,
            PinSlot::Pin1,
            &activation_code,
            new_pin1,
        )?;
        pin1_outcome = Some(outcome);
        // Single-shot: if PIN1 setup rejected the activation PIN
        // (wrong code, locked slot, anything other than Ok), don't
        // burn a second card-side try on the PIN2 slot. The operator
        // re-runs after fixing the input.
        if !activation_continues_after_pin1(outcome) {
            return Ok(ActivateReport {
                reader: reader_label,
                preflight,
                pin1_outcome,
                pin2_outcome: None,
            });
        }
    }

    let pin2_outcome = if let Some(new_pin2) = options.new_pin2 {
        // Re-verify session before the PIN2 modify APDU. A card swap
        // between PIN1 and PIN2 setup is the canonical TOCTOU case
        // this gate defends against.
        re_verify_session(&mut transport, &ctx.bound_serial)?;
        Some(activate_slot_setup(
            &mut transport,
            ctx.numbering,
            PinSlot::Pin2,
            &activation_code,
            new_pin2,
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
}

impl fmt::Display for ActivateReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        match &self.preflight {
            ActivatePreflightOutcome::AwaitsActivation { pin1, pin2 } => {
                writeln!(
                    f,
                    "preflight: card awaits activation (PIN1: {pin1:?}, PIN2: {pin2:?}); proceeding"
                )?;
            }
            ActivatePreflightOutcome::NothingAwaits { pin1, pin2 } => {
                writeln!(
                    f,
                    "preflight: no PIN awaits activation \
                     (PIN1: {pin1:?}, PIN2: {pin2:?})"
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
            Some(o) => writeln!(f, "PIN1 setup: {}", CardPinHelpers::fmt_unblock(o, "PIN1"))?,
            None => writeln!(f, "PIN1 setup: not attempted")?,
        }
        match (self.pin1_outcome, self.pin2_outcome) {
            (_, Some(o)) => writeln!(f, "PIN2 setup: {}", CardPinHelpers::fmt_unblock(o, "PIN2"))?,
            (Some(o), None) if !activation_continues_after_pin1(o) => writeln!(
                f,
                "PIN2 setup: not attempted (PIN1 setup failed; re-run after fixing \
                 the activation PIN -- each invocation consumes one card-side try)"
            )?,
            _ => writeln!(f, "PIN2 setup: not attempted")?,
        }
        Ok(())
    }
}

/// Helpers hosted on a unit struct (no free
/// functions with borrowed parameters).
struct CardPinHelpers;

impl CardPinHelpers {
    /// Render an [`UnblockOutcome`] for the activation / PIN-
    /// change reports.
    ///
    /// Each variant names the card-side condition in a way
    /// the operator can act on: `Ok` confirms counter reset,
    /// `WrongPuk` shows the remaining attempts, `PukLocked`
    /// names the DVV-paid reissue path, etc. `LengthError`
    /// is a host-side bug -- if the card returned `6700`,
    /// refineid sent a malformed APDU.
    fn fmt_unblock(o: UnblockOutcome, label: &str) -> String {
        match o {
            UnblockOutcome::Ok => format!("ok ({label} set; retry counter reset to max)"),
            UnblockOutcome::WrongPuk { retries_left } => {
                format!(
                    "WRONG activation PIN ({retries_left} card-side tries left; lockout pending)"
                )
            }
            UnblockOutcome::PukLocked => {
                "ACTIVATION PIN LOCKED -- order a PUK from DVV to recover (paid)".to_owned()
            }
            UnblockOutcome::Invalidated => {
                "card invalidated the activation PIN -- DVV reissue may be required".to_owned()
            }
            UnblockOutcome::LengthError => {
                "card rejected APDU length (SW=6700) -- host bug".to_owned()
            }
            UnblockOutcome::Other(sw) => format!("card returned unexpected SW={sw:#06X}"),
        }
    }
}

#[cfg(test)]
mod activate_tests {
    use refineid_lib_core::activation::{ActivationScheme, PinActivation};
    use refineid_lib_core::apdu::status_word::{PinRetries, StatusWord};
    use refineid_lib_core::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
    use refineid_lib_core::auth::commands::{GetPinInfo, ResetRetryCounter, Verify};
    use refineid_lib_core::auth::{
        PIN1_REFERENCE_ORGANIZATIONAL, PIN1_REFERENCE_PKCS15, PUK_REFERENCE_ORGANIZATIONAL,
        PinReferenceScheme,
    };
    use refineid_lib_core::pin::{ActivationCode, PinBytes};
    use refineid_lib_core::transport::{
        CardTransport, CommandApdu, ResponseApdu, TransportOutcome,
    };

    use super::{
        ActivatePreflightOutcome, ActivationEvidence, CardPinError, ChangePinOutcome, PinSlot,
        RetryFloorRefusal, UnblockOutcome, activate_slot_setup, activation_code_for,
        activation_continues_after_pin1, activation_targets, change_to_unblock, classify_preflight,
        judge_activation, probe_pin_activation,
    };
    use crate::test_util::{TestResult, check_true};

    /// Tries left at which a PIN attempt is served.
    const SERVED: [u8; 3] = [5, 4, 3];
    /// Tries left at which a PIN attempt is refused.
    const REFUSED: [u8; 3] = [2, 1, 0];
    /// A full counter.
    const FULL_COUNTER: u8 = 5;
    /// A counter with no tries left (`63C0`).
    const NO_TRIES: u8 = 0;
    /// APDUs a served preset-PIN activation sends: the status probe and
    /// `CHANGE REFERENCE DATA`.
    const PROBE_AND_CHANGE: usize = 2;
    /// APDUs a refused activation sends: the counter-safe probe only.
    const PROBE_ONLY: usize = 1;
    /// APDUs a served citizen PUK-code activation sends: the PUK probe
    /// and `RESET RETRY COUNTER`.
    const PROBE_AND_RESET: usize = 2;
    /// APDUs an organization PUK-code activation sends when the PUK is
    /// refused: the PUK probe and the PUK VERIFY.
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

    /// Answers every command with one status word and records them.
    struct FixedStatusTransport {
        status: StatusWord,
        sent: Vec<Vec<u8>>,
    }

    impl FixedStatusTransport {
        const fn new(status: StatusWord) -> Self {
            Self {
                status,
                sent: Vec::new(),
            }
        }
    }

    impl CardTransport for FixedStatusTransport {
        type Error = String;

        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            self.sent.push(apdu.as_bytes().to_vec());
            let [sw1, sw2] = self.status.as_u16().to_be_bytes();
            Ok(TransportOutcome::Response(ResponseApdu {
                body: Vec::new(),
                sw1,
                sw2,
            }))
        }

        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
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

        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            let bytes = apdu.as_bytes().to_vec();
            let instruction = bytes.get(INS_INDEX).copied();
            self.sent.push(bytes);
            let (body, status) = match (instruction, self.changed) {
                (Some(GetPinInfo::INS), Some(flag)) => (
                    vec![
                        PIN_CHANGED_TAG_HIGH,
                        PIN_CHANGED_TAG_LOW,
                        PIN_CHANGED_LENGTH,
                        flag,
                    ],
                    StatusWord::Success,
                ),
                (Some(GetPinInfo::INS), None) => (Vec::new(), StatusWord::ReferenceDataNotFound),
                _ => (Vec::new(), self.status),
            };
            let [sw1, sw2] = status.as_u16().to_be_bytes();
            Ok(TransportOutcome::Response(ResponseApdu { body, sw1, sw2 }))
        }

        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    fn tries(count: u8) -> Result<StatusWord, String> {
        let retries = PinRetries::from_nibble(count).ok_or("retry count fits a nibble")?;
        Ok(StatusWord::PinIncorrect { retries })
    }

    fn code(scheme: ActivationScheme) -> Result<ActivationCode, Box<dyn core::error::Error>> {
        let digits = match scheme {
            ActivationScheme::PresetActivationPin => PRESET_PIN,
            ActivationScheme::ActivationCodeIsPuk => PUK_CODE,
        };
        Ok(activation_code_for(
            scheme,
            PinBytes::new(digits.to_vec())?,
        )?)
    }

    fn setup(
        transport: &mut FixedStatusTransport,
        numbering: PinReferenceScheme,
        scheme: ActivationScheme,
    ) -> Result<Result<UnblockOutcome, CardPinError>, Box<dyn core::error::Error>> {
        let new_pin = PinBytes::new(NEW_PIN.to_vec())?;
        Ok(activate_slot_setup(
            transport,
            numbering,
            PinSlot::Pin1,
            &code(scheme)?,
            new_pin,
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
            let outcome = activation_code_for(scheme, PinBytes::new(digits.to_vec())?);
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
    fn preset_pin_activation_is_refused_at_two_one_and_zero_tries() -> TestResult {
        for count in REFUSED {
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
    fn puk_code_activation_is_refused_at_two_one_and_zero_puk_tries() -> TestResult {
        for count in REFUSED {
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
        }
        Ok(())
    }

    #[test]
    fn puk_code_activation_is_refused_on_a_blocked_puk() -> TestResult {
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
                matches!(
                    outcome,
                    Err(CardPinError::RetryFloor(RetryFloorRefusal::Blocked { .. }))
                ),
                "blocked PUK refused",
            )?;
            check_true(transport.sent.len() == PROBE_ONLY, "only the probe sent")?;
        }
        Ok(())
    }

    #[test]
    fn puk_code_activation_is_refused_on_an_unreadable_puk_counter() -> TestResult {
        // Success with no PIN container body carries no counter.
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
            check_true(transport.sent.len() == PROBE_ONLY, "only the probe sent")?;
        }
        Ok(())
    }

    #[test]
    fn organization_activation_speaks_the_organization_numbering() -> TestResult {
        let mut transport = FixedStatusTransport::new(StatusWord::Success);
        // The organization PUK probe answers with no counter, so the
        // floor refuses after the probe alone.
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
            matches!(outcome, Ok(UnblockOutcome::WrongPuk { .. })),
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
                == Some(Verify::INS),
            "the code is verified as the PUK first",
        )?;
        check_true(
            transport
                .sent
                .iter()
                .all(|apdu| apdu.get(INS_INDEX).copied() != Some(ResetRetryCounter::INS)),
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
            (PinReferenceScheme::Citizen, PIN1_REFERENCE_PKCS15),
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

    /// Preset-PIN setup uses `CHANGE REFERENCE DATA`; the
    /// outcome is `ChangePinOutcome`. `ActivateReport` carries
    /// the unified `UnblockOutcome` form -- check the variant
    /// mapping covers every case.
    #[test]
    fn change_to_unblock_covers_every_variant() -> TestResult {
        let three = PinRetries::from_nibble(3).ok_or("PinRetries::from_nibble(3)")?;
        check_true(
            matches!(change_to_unblock(ChangePinOutcome::Ok), UnblockOutcome::Ok),
            "Ok -> Ok",
        )?;
        check_true(
            matches!(
                change_to_unblock(ChangePinOutcome::WrongCurrentPin {
                    retries_left: three
                }),
                UnblockOutcome::WrongPuk { .. }
            ),
            "WrongCurrentPin -> WrongPuk",
        )?;
        check_true(
            matches!(
                change_to_unblock(ChangePinOutcome::Locked),
                UnblockOutcome::PukLocked
            ),
            "Locked -> PukLocked",
        )?;
        check_true(
            matches!(
                change_to_unblock(ChangePinOutcome::LengthError),
                UnblockOutcome::LengthError
            ),
            "LengthError -> LengthError",
        )?;
        check_true(
            matches!(
                change_to_unblock(ChangePinOutcome::Other(UNMODELED_SW)),
                UnblockOutcome::Other(UNMODELED_SW)
            ),
            "Other -> Other",
        )
    }

    #[test]
    fn activation_failure_never_proceeds_to_pin2() -> TestResult {
        let three = PinRetries::from_nibble(3).ok_or("PinRetries::from_nibble(3)")?;
        check_true(
            activation_continues_after_pin1(UnblockOutcome::Ok),
            "successful PIN1 activation proceeds to PIN2",
        )?;
        for outcome in [
            UnblockOutcome::WrongPuk {
                retries_left: three,
            },
            UnblockOutcome::PukLocked,
            UnblockOutcome::Invalidated,
            UnblockOutcome::LengthError,
            UnblockOutcome::Other(UNMODELED_SW),
        ] {
            check_true(
                !activation_continues_after_pin1(outcome),
                "failed PIN1 activation stops before PIN2",
            )?;
        }
        Ok(())
    }
}
