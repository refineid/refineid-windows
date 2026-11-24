// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! PIN screen backend: status reads plus change, unblock, and
//! activate operations.
//!
//! Secrets cross this module only as validated `refineid-auth` credential
//! values built from raw digit buffers at the UI boundary. They are never held
//! in `String`, never formatted (not even their lengths), and never logged;
//! retry counts are the only numbers that reach the display.

use refineid_apdu::StatusWord;
use refineid_auth::{
    ActivationScheme, CardPinLengths, CredentialInputError, ManageOutcome, PasswordLengthRange,
    Pin1, Pin2, Puk, UnvalidatedSecret,
};
use refineid_card_manager_core::card_pin::{
    ActivateOptions, ActivatePreflightOutcome, ActivateReport, ActivationInput, CardPinError,
    ChangePinCredentials, ChangePinOptions, ChangePinReport, UnblockPinOptions, UnblockPinReport,
    UnblockPinTarget,
};
use refineid_card_manager_core::service;
use zeroize::Zeroize;

use crate::identity::{StateText, credential_label, pin_kind, puk_kind, puk_label, short_error};

/// Number of modes in the PIN operation selector.
const MODE_COUNT: usize = 5;
/// Maximum input rows across all PIN modes.
const MAX_FIELD_COUNT: usize = 5;
/// Mode index: change Basic PIN 1.
const MODE_CHANGE_PIN1: usize = 0;
/// Mode index: change Signature PIN 2.
const MODE_CHANGE_PIN2: usize = 1;
/// Mode index: unblock Basic PIN 1 with the PUK.
const MODE_UNBLOCK_PIN1: usize = 2;
/// Mode index: unblock Signature PIN 2 with the PUK.
const MODE_UNBLOCK_PIN2: usize = 3;
/// Mode index: activate a factory-fresh card.
const MODE_ACTIVATE: usize = 4;
/// Input rows in a change or unblock form (credential + new + repeat).
const THREE_FIELD_COUNT: usize = 3;
/// First form field index.
const FIELD_ZERO: usize = 0;
/// Second form field index.
const FIELD_ONE: usize = 1;
/// Fourth form field index.
const FIELD_THREE: usize = 3;
/// Display cap for flattened single-line operation error messages.
const OP_ERROR_CAP: usize = 400;

/// Combobox entries, in dispatch order. The UI and [`prepare`]
/// share these indices.
pub const MODES: [&str; MODE_COUNT] = [
    "Change Basic PIN 1",
    "Change Signature PIN 2",
    "Unblock Basic PIN 1 (PUK)",
    "Unblock Signature PIN 2 (PUK)",
    "Activate new card",
];

/// The labels of one PIN's fields, as the form shows them and as the
/// validation messages name them.
#[derive(Clone, Copy)]
struct PinFields {
    current: &'static str,
    new: &'static str,
    repeat: &'static str,
}

const PIN1_FIELDS: PinFields = PinFields {
    current: "Current Basic PIN 1",
    new: "New Basic PIN 1",
    repeat: "Basic PIN 1 again",
};

const PIN2_FIELDS: PinFields = PinFields {
    current: "Current Signature PIN 2",
    new: "New Signature PIN 2",
    repeat: "Signature PIN 2 again",
};

/// Field labels per mode, top to bottom. An empty label hides
/// that row.
pub const FIELDS: [[&str; MAX_FIELD_COUNT]; MODE_COUNT] = [
    [
        "Current Basic PIN 1:",
        "New Basic PIN 1:",
        "Basic PIN 1 again:",
        "",
        "",
    ],
    [
        "Current Signature PIN 2:",
        "New Signature PIN 2:",
        "Signature PIN 2 again:",
        "",
        "",
    ],
    ["PUK:", "New Basic PIN 1:", "Basic PIN 1 again:", "", ""],
    [
        "PUK:",
        "New Signature PIN 2:",
        "Signature PIN 2 again:",
        "",
        "",
    ],
    [
        "Activation PIN:",
        "New Basic PIN 1:",
        "Basic PIN 1 again:",
        "New Signature PIN 2:",
        "Signature PIN 2 again:",
    ],
];

/// A validated PIN operation ready for the worker thread. All
/// secrets inside are zeroizing types.
pub enum PinJob {
    Change(ChangePinCredentials),
    Unblock {
        puk: Puk,
        new: UnblockPinTarget,
    },
    Activate {
        code: ActivationInput,
        pin1: Option<Pin1>,
        pin2: Option<Pin2>,
    },
}

/// Structured PIN status panel: one field per UI row.
#[derive(Debug, Clone)]
pub struct PinStatusView {
    /// Holder rendering.
    pub holder: String,
    /// Card serial rendering.
    pub serial: String,
    /// PIN1 state.
    pub pin1: StateText,
    /// PIN2 state.
    pub pin2: StateText,
    /// PUK state.
    pub puk: StateText,
    /// The PIN 1, PIN 2 and PUK lengths the card accepts, which the PIN
    /// form validates its entries against.
    pub lengths: CardPinLengths,
}

/// Read the structured PIN status panel for one reader.
pub fn read_status_view(reader: &str) -> Result<PinStatusView, String> {
    let filter = service::reader_filter(reader.to_owned());
    let snapshot = service::inspect(Some(&filter)).map_err(|error| short_error(&error))?;
    Ok(PinStatusView {
        holder: snapshot.person.clone(),
        serial: snapshot.serial.as_str().to_owned(),
        pin1: StateText {
            text: credential_label(snapshot.pin1.as_ref(), snapshot.pin1_changed),
            kind: pin_kind(snapshot.pin1.as_ref()),
        },
        pin2: StateText {
            text: credential_label(snapshot.pin2.as_ref(), snapshot.pin2_changed),
            kind: pin_kind(snapshot.pin2.as_ref()),
        },
        puk: StateText {
            text: puk_label(snapshot.puk.as_ref()),
            kind: puk_kind(snapshot.puk.as_ref()),
        },
        lengths: snapshot.lengths,
    })
}

/// Validate UI digit buffers into a runnable job. Runs on the UI
/// thread so typos surface without touching the card: no APDU
/// goes out, and no retry counter moves, before this returns
/// `Ok`. Every buffer is either moved into a zeroizing type or
/// wiped on the error path. Each entry is checked against the lengths
/// the card accepts for its credential.
pub fn prepare(
    mode: usize,
    fields: Vec<Vec<u8>>,
    lengths: &CardPinLengths,
) -> Result<PinJob, String> {
    match mode {
        MODE_CHANGE_PIN1 => {
            let (current, new) = prepare_change(
                fields,
                PIN1_FIELDS,
                lengths.pin1().accepted(),
                reconstruct_pin1,
            )?;
            Ok(PinJob::Change(ChangePinCredentials::Pin1 { current, new }))
        }
        MODE_CHANGE_PIN2 => {
            let (current, new) = prepare_change(
                fields,
                PIN2_FIELDS,
                lengths.pin2().accepted(),
                reconstruct_pin2,
            )?;
            Ok(PinJob::Change(ChangePinCredentials::Pin2 { current, new }))
        }
        MODE_UNBLOCK_PIN1 => {
            let (puk, new) = prepare_unblock(
                fields,
                PIN1_FIELDS,
                lengths.puk().accepted(),
                lengths.pin1().accepted(),
                reconstruct_pin1,
            )?;
            Ok(PinJob::Unblock {
                puk,
                new: UnblockPinTarget::Pin1(new),
            })
        }
        MODE_UNBLOCK_PIN2 => {
            let (puk, new) = prepare_unblock(
                fields,
                PIN2_FIELDS,
                lengths.puk().accepted(),
                lengths.pin2().accepted(),
                reconstruct_pin2,
            )?;
            Ok(PinJob::Unblock {
                puk,
                new: UnblockPinTarget::Pin2(new),
            })
        }
        MODE_ACTIVATE => prepare_activate(fields, lengths)
            .map(|(code, pin1, pin2)| PinJob::Activate { code, pin1, pin2 }),
        _ => {
            let mut fields = fields;
            zeroize_all(&mut fields);
            Err(String::from("Unknown PIN operation."))
        }
    }
}

/// Run a prepared job against one reader. The worker thread calls
/// this: a fresh serial is bound first so a card swap between the
/// status read and the execute aborts instead of landing on the
/// wrong card.
pub fn run_job(job: PinJob, reader: &str) -> Result<String, String> {
    match job {
        PinJob::Change(credentials) => run_change(credentials, reader),
        PinJob::Unblock { puk, new } => run_unblock(puk, new, reader),
        PinJob::Activate { code, pin1, pin2 } => run_activate(reader, code, pin1, pin2),
    }
}

fn reconstruct_pin1(bytes: Vec<u8>) -> Result<(Pin1, usize), CredentialInputError> {
    let pin = Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(bytes))?;
    let count = pin.digit_count();
    Ok((pin, count))
}

fn reconstruct_pin2(bytes: Vec<u8>) -> Result<(Pin2, usize), CredentialInputError> {
    let pin = Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(bytes))?;
    let count = pin.digit_count();
    Ok((pin, count))
}

fn reconstruct_puk(bytes: Vec<u8>) -> Result<(Puk, usize), CredentialInputError> {
    let puk = Puk::reconstruct(UnvalidatedSecret::from_owned_bytes(bytes))?;
    let count = puk.digit_count();
    Ok((puk, count))
}

/// The accepted range of a credential, or the refusal when the card
/// accepts no length for it.
fn accepted(
    fields: &mut [Vec<u8>],
    range: Option<PasswordLengthRange>,
) -> Result<PasswordLengthRange, String> {
    range.ok_or_else(|| {
        zeroize_all(fields);
        String::from("This card lists no PIN length that can be set; nothing was sent to the card.")
    })
}

fn prepare_change<T, F>(
    mut fields: Vec<Vec<u8>>,
    labels: PinFields,
    pin: Option<PasswordLengthRange>,
    reconstruct: F,
) -> Result<(T, T), String>
where
    F: Fn(Vec<u8>) -> Result<(T, usize), CredentialInputError>,
{
    if fields.len() != THREE_FIELD_COUNT {
        zeroize_all(&mut fields);
        return Err(String::from("Internal error: wrong field count."));
    }
    let pin = accepted(&mut fields, pin)?;
    let current = take_digit_buffer(&mut fields, FIELD_ZERO, labels.current, pin, &reconstruct)?;
    let new = take_confirmed_pair(
        &mut fields,
        FIELD_ONE,
        labels,
        pin,
        "The new PIN entries do not match; nothing was sent to the card.",
        &reconstruct,
    )?;
    Ok((current, new))
}

fn prepare_unblock<T, F>(
    mut fields: Vec<Vec<u8>>,
    labels: PinFields,
    puk: Option<PasswordLengthRange>,
    pin: Option<PasswordLengthRange>,
    reconstruct: F,
) -> Result<(Puk, T), String>
where
    F: Fn(Vec<u8>) -> Result<(T, usize), CredentialInputError>,
{
    if fields.len() != THREE_FIELD_COUNT {
        zeroize_all(&mut fields);
        return Err(String::from("Internal error: wrong field count."));
    }
    let puk_range = accepted(&mut fields, puk)?;
    let pin = accepted(&mut fields, pin)?;
    let puk = take_digit_buffer(&mut fields, FIELD_ZERO, "PUK", puk_range, reconstruct_puk)?;
    let new = take_confirmed_pair(
        &mut fields,
        FIELD_ONE,
        labels,
        pin,
        "The new PIN entries do not match; nothing was sent to the card.",
        &reconstruct,
    )?;
    Ok((puk, new))
}

/// Validate the activation fields. The code's exact length is the
/// card's to decide ([`run_activate`] checks it against the card's
/// scheme before any command); here it only has to be digits no
/// shorter than any scheme takes. A PIN whose two fields are both
/// empty is not entered; the card service refuses unless the entries
/// name exactly the PINs that await activation.
fn prepare_activate(
    mut fields: Vec<Vec<u8>>,
    lengths: &CardPinLengths,
) -> Result<(ActivationInput, Option<Pin1>, Option<Pin2>), String> {
    if fields.len() != MAX_FIELD_COUNT {
        zeroize_all(&mut fields);
        return Err(String::from("Internal error: wrong field count."));
    }
    let code = take_code_buffer(&mut fields, FIELD_ZERO)?;
    let pin1 = take_optional_pair(
        &mut fields,
        FIELD_ONE,
        PIN1_FIELDS,
        lengths.pin1().accepted(),
        "The Basic PIN 1 entries do not match; nothing was sent to the card.",
        reconstruct_pin1,
    )?;
    let pin2 = take_optional_pair(
        &mut fields,
        FIELD_THREE,
        PIN2_FIELDS,
        lengths.pin2().accepted(),
        "The Signature PIN 2 entries do not match; nothing was sent to the card.",
        reconstruct_pin2,
    )?;
    Ok((code, pin1, pin2))
}

/// Move a new PIN and its repeat, at `index` and the next field, into
/// a validated credential; `None` when both fields are empty. Two
/// entries that differ give `mismatch`.
fn take_optional_pair<T, F>(
    fields: &mut [Vec<u8>],
    index: usize,
    labels: PinFields,
    range: Option<PasswordLengthRange>,
    mismatch: &str,
    reconstruct: F,
) -> Result<Option<T>, String>
where
    F: Fn(Vec<u8>) -> Result<(T, usize), CredentialInputError>,
{
    let repeat_index = index.saturating_add(1);
    let both_empty = fields.get(index).is_some_and(Vec::is_empty)
        && fields.get(repeat_index).is_some_and(Vec::is_empty);
    if both_empty {
        return Ok(None);
    }
    let range = accepted(fields, range)?;
    let pin = take_confirmed_pair(fields, index, labels, range, mismatch, &reconstruct)?;
    Ok(Some(pin))
}

/// Validate a new PIN and its confirmation at `index` and `index + 1`
/// before moving the new PIN into the typed role.
fn take_confirmed_pair<T, F>(
    fields: &mut [Vec<u8>],
    index: usize,
    labels: PinFields,
    range: PasswordLengthRange,
    mismatch: &str,
    reconstruct: &F,
) -> Result<T, String>
where
    F: Fn(Vec<u8>) -> Result<(T, usize), CredentialInputError>,
{
    let repeat_index = index.saturating_add(1);
    let matches = fields
        .get(index)
        .zip(fields.get(repeat_index))
        .is_some_and(|(first, second)| first == second);
    let pin = take_digit_buffer(fields, index, labels.new, range, reconstruct)?;
    let _confirm = take_digit_buffer(fields, repeat_index, labels.repeat, range, reconstruct)?;
    if !matches {
        zeroize_all(fields);
        return Err(String::from(mismatch));
    }
    Ok(pin)
}

/// The accepted length of a credential, as the form states it.
fn digits_hint(range: PasswordLengthRange) -> String {
    format!("{}-{} digits", range.min(), range.max())
}

/// Move one buffer into a validated credential whose length the card
/// accepts, so a typo is rejected before it can burn a card-side retry.
fn take_digit_buffer<T, F>(
    fields: &mut [Vec<u8>],
    index: usize,
    label: &str,
    range: PasswordLengthRange,
    reconstruct: F,
) -> Result<T, String>
where
    F: Fn(Vec<u8>) -> Result<(T, usize), CredentialInputError>,
{
    let hint = digits_hint(range);
    let bytes = take_raw_buffer(fields, index)?;
    let (credential, digit_count) = reconstruct(bytes).map_err(|error| {
        zeroize_all(fields);
        role_error(label, &hint, error)
    })?;
    if digit_count < range.min() {
        zeroize_all(fields);
        return Err(format!("{label} is too short ({hint})."));
    }
    if !range.contains(digit_count) {
        zeroize_all(fields);
        return Err(format!("{label} has the wrong length ({hint})."));
    }
    Ok(credential)
}

/// Move the activation PIN into a validated [`ActivationInput`]. Its exact
/// length is the card's scheme to decide; here it only has to be digits
/// no shorter than any scheme takes.
fn take_code_buffer(fields: &mut [Vec<u8>], index: usize) -> Result<ActivationInput, String> {
    const HINT: &str = "7 or 8 digits";
    const LABEL: &str = "Activation PIN";
    let min_scheme_digits = ActivationScheme::PresetActivationPin.activation_entry_digit_count();
    let bytes = take_raw_buffer(fields, index)?;
    let digit_count = bytes.len();
    let code = ActivationInput::new(bytes).map_err(|error| {
        zeroize_all(fields);
        role_error(LABEL, HINT, error)
    })?;
    if digit_count < min_scheme_digits {
        zeroize_all(fields);
        return Err(format!("{LABEL} is too short ({HINT})."));
    }
    Ok(code)
}

fn take_raw_buffer(fields: &mut [Vec<u8>], index: usize) -> Result<Vec<u8>, String> {
    let Some(slot) = fields.get_mut(index) else {
        zeroize_all(fields);
        return Err(String::from("Internal error: missing PIN field."));
    };
    Ok(std::mem::take(slot))
}

/// Render a credential-policy rejection using only static policy
/// text. Lengths of secret material never reach the display.
fn role_error(label: &str, hint: &str, error: CredentialInputError) -> String {
    match error {
        CredentialInputError::Empty { .. } => format!("{label} is empty ({hint})."),
        CredentialInputError::WrongLength { .. } => {
            format!("{label} has the wrong length ({hint}).")
        }
        CredentialInputError::NonDigit { .. } => format!("{label} must contain digits only."),
    }
}

fn zeroize_all(fields: &mut [Vec<u8>]) {
    for field in fields.iter_mut() {
        field.zeroize();
    }
}

fn run_change(credentials: ChangePinCredentials, reader: &str) -> Result<String, String> {
    let filter = service::reader_filter(reader.to_owned());
    let serial = service::inspect(Some(&filter))
        .map_err(|error| op_error(&error))?
        .serial;
    let options = ChangePinOptions {
        credentials,
        reader_filter: Some(reader.to_owned()),
    };
    let report = service::change_pin(&serial, options).map_err(|error| op_error(&error))?;
    Ok(render_change(&report))
}

fn run_unblock(puk: Puk, new: UnblockPinTarget, reader: &str) -> Result<String, String> {
    let filter = service::reader_filter(reader.to_owned());
    let serial = service::inspect(Some(&filter))
        .map_err(|error| op_error(&error))?
        .serial;
    let options = UnblockPinOptions {
        puk,
        new_pin: new,
        reader_filter: Some(reader.to_owned()),
    };
    let report = service::unblock_pin(&serial, options).map_err(|error| op_error(&error))?;
    Ok(render_unblock(&report))
}

fn run_activate(
    reader: &str,
    code: ActivationInput,
    pin1: Option<Pin1>,
    pin2: Option<Pin2>,
) -> Result<String, String> {
    let filter = service::reader_filter(reader.to_owned());
    let snapshot = service::inspect(Some(&filter)).map_err(|error| op_error(&error))?;
    let serial = snapshot.serial;
    let options = ActivateOptions {
        activation_code: code,
        new_pin1: pin1,
        new_pin2: pin2,
        allow_reactivate: false,
    };
    let report =
        service::activate(&serial, Some(&filter), options).map_err(|error| op_error(&error))?;
    Ok(render_activate(&report))
}

fn render_change(report: &ChangePinReport) -> String {
    let pin = report.slot.label();
    match report.outcome {
        ManageOutcome::Ok => format!(
            "{pin} changed on {} ({}).\r\nThe new PIN is active now.",
            report.person, report.card_serial
        ),
        ManageOutcome::WrongCredential { retries_left } => {
            let left = retries_left.get();
            format!("Wrong current {pin}; {left} tries left. Nothing was changed.")
        }
        ManageOutcome::Locked => {
            format!("{pin} is blocked. Use the Unblock operation with the PUK to set a new one.")
        }
        ManageOutcome::Other(StatusWord::WrongLength) => {
            format!("{pin} change refused: length error (host bug, please report).")
        }
        ManageOutcome::Other(word) => {
            format!(
                "{pin} change failed with card status {:#06X}.",
                word.as_u16()
            )
        }
    }
}

fn render_unblock(report: &UnblockPinReport) -> String {
    let pin = report.slot.label();
    match report.outcome {
        ManageOutcome::Ok => format!(
            "{pin} unblocked on {} ({}) and set to the new value.",
            report.person, report.card_serial
        ),
        ManageOutcome::WrongCredential { retries_left } => {
            let left = retries_left.get();
            if left == 0 {
                String::from(
                    "Wrong PUK; no PUK tries left. Do not guess again: the next wrong PUK makes the card permanently unrecoverable.",
                )
            } else {
                format!("Wrong PUK; {left} PUK tries left. Nothing was changed.")
            }
        }
        ManageOutcome::Locked => String::from(
            "The PUK itself is locked. No software recovery is possible; the card needs DVV reissue.",
        ),
        ManageOutcome::Other(StatusWord::WrongLength) => {
            String::from("Unblock refused: length error (host bug, please report).")
        }
        ManageOutcome::Other(word) => {
            format!("Unblock failed with card status {:#06X}.", word.as_u16())
        }
    }
}

/// The refusal for an activation PIN of the wrong length for the
/// card's scheme.
fn activation_length_error(expected: usize) -> String {
    format!(
        "The activation PIN must have {expected} digits for this card; nothing was sent to the card."
    )
}

fn render_activate(report: &ActivateReport) -> String {
    let mut out = String::new();
    match report.preflight {
        ActivatePreflightOutcome::AwaitsActivation { .. } => {
            out.push_str("Card looks unactivated; activation proceeded.\r\n");
        }
        ActivatePreflightOutcome::NothingAwaits { .. } => {
            out.push_str("Card already looks activated.\r\n");
        }
    }
    out.push_str("Basic PIN 1: ");
    out.push_str(&activate_line(report.pin1_outcome.as_ref()));
    out.push_str("\r\nSignature PIN 2: ");
    out.push_str(&activate_line(report.pin2_outcome.as_ref()));
    out
}

fn activate_line(outcome: Option<&ManageOutcome>) -> String {
    match outcome {
        None => String::from("not attempted"),
        Some(ManageOutcome::Ok) => String::from("set"),
        Some(ManageOutcome::WrongCredential { retries_left }) => {
            format!("wrong activation PIN; {retries_left} tries left")
        }
        Some(ManageOutcome::Locked) => String::from("code locked"),
        Some(ManageOutcome::Other(StatusWord::WrongLength)) => {
            String::from("refused: length error (host bug)")
        }
        Some(ManageOutcome::Other(word)) => {
            format!("failed with card status {:#06X}", word.as_u16())
        }
    }
}

/// Operation failures for the result pane. Two variants get GUI
/// wording (the core texts name CLI commands); the rest use the
/// core `Display`, flattened to one length-capped line. Card
/// errors never carry credentials.
fn op_error(error: &CardPinError) -> String {
    match error {
        CardPinError::CardLooksUnactivated { slot, .. } => format!(
            "{} looks unactivated, so no PIN command was sent. Use the Activate operation on this screen first.",
            slot.label()
        ),
        CardPinError::CardSessionRevoked { .. } => String::from(
            "The card or reader changed during the operation. Check the card and retry.",
        ),
        CardPinError::ActivationLengthMismatch { expected, .. } => {
            activation_length_error(*expected)
        }
        other => flatten(&other.to_string(), OP_ERROR_CAP),
    }
}

pub fn flatten(text: &str, cap: usize) -> String {
    let mut out = String::with_capacity(text.len().min(cap));
    for unit in text.chars() {
        if unit == '\r' || unit == '\n' {
            if !out.ends_with(' ') {
                out.push(' ');
            }
        } else {
            out.push(unit);
        }
    }
    while out.len() > cap {
        out.pop();
    }
    out
}
