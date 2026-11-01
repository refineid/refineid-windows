// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! PIN screen backend: status reads plus change, unblock, and
//! activate operations.
//!
//! Secrets cross this module only as validated [`PinBytes`] or
//! [`Puk`] values built from raw digit buffers at the UI boundary. They are never held in `String`,
//! never formatted (not even their lengths), and never logged;
//! retry counts are the only numbers that reach the display.
use refineid_card_manager_core::card_pin::ActivatePreflightOutcome;
use refineid_card_manager_core::card_pin::{
    ActivateOptions, ActivateReport, CardPinError, ChangePinOptions, ChangePinReport,
    PinManageSlot, UnblockPinOptions, UnblockPinReport,
};
use refineid_card_manager_core::service;
use refineid_lib_core::auth::{
    CardPinLengths, ChangePinOutcome, PasswordLengthRange, UnblockOutcome,
};
use refineid_lib_core::pin::{ActivationPinSeven, PinBytes, PinRoleError, Puk};
use zeroize::Zeroize;

use crate::identity::{StateText, credential_label, pin_kind, puk_kind, puk_label, short_error};

/// Combobox entries, in dispatch order. The UI and [`prepare`]
/// share these indices.
pub const MODES: [&str; 5] = [
    "Change PIN 1",
    "Change PIN 2",
    "Unblock PIN 1 (PUK)",
    "Unblock PIN 2 (PUK)",
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
    current: "Current PIN 1",
    new: "New basic PIN 1",
    repeat: "Repeat PIN 1",
};

const PIN2_FIELDS: PinFields = PinFields {
    current: "Current PIN 2",
    new: "New signature PIN 2",
    repeat: "Repeat PIN 2",
};

/// Field labels per mode, top to bottom. An empty label hides
/// that row.
pub const FIELDS: [[&str; 5]; 5] = [
    [
        "Current PIN 1:",
        "New basic PIN 1:",
        "Repeat PIN 1:",
        "",
        "",
    ],
    [
        "Current PIN 2:",
        "New signature PIN 2:",
        "Repeat PIN 2:",
        "",
        "",
    ],
    ["PUK:", "New basic PIN 1:", "Repeat PIN 1:", "", ""],
    ["PUK:", "New signature PIN 2:", "Repeat PIN 2:", "", ""],
    [
        "Activation code:",
        "New basic PIN 1:",
        "Repeat PIN 1:",
        "New signature PIN 2:",
        "Repeat PIN 2:",
    ],
];

/// A validated PIN operation ready for the worker thread. All
/// secrets inside are zeroizing types.
pub enum PinJob {
    Change {
        slot: PinManageSlot,
        current: PinBytes,
        new: PinBytes,
    },
    Unblock {
        slot: PinManageSlot,
        puk: Puk,
        new: PinBytes,
    },
    Activate {
        code: PinBytes,
        pin1: Option<PinBytes>,
        pin2: Option<PinBytes>,
    },
}

/// Read and render the PIN status panel for one reader.
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
        0 => {
            let (current, new) = prepare_change(fields, PIN1_FIELDS, lengths.pin1())?;
            Ok(PinJob::Change {
                slot: PinManageSlot::Pin1,
                current,
                new,
            })
        }
        1 => {
            let (current, new) = prepare_change(fields, PIN2_FIELDS, lengths.pin2())?;
            Ok(PinJob::Change {
                slot: PinManageSlot::Pin2,
                current,
                new,
            })
        }
        2 => {
            let (puk, new) = prepare_unblock(fields, PIN1_FIELDS, lengths.puk(), lengths.pin1())?;
            Ok(PinJob::Unblock {
                slot: PinManageSlot::Pin1,
                puk,
                new,
            })
        }
        3 => {
            let (puk, new) = prepare_unblock(fields, PIN2_FIELDS, lengths.puk(), lengths.pin2())?;
            Ok(PinJob::Unblock {
                slot: PinManageSlot::Pin2,
                puk,
                new,
            })
        }
        4 => prepare_activate(fields, lengths).map(|(code, pin1, pin2)| PinJob::Activate {
            code,
            pin1,
            pin2,
        }),
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
        PinJob::Change { slot, current, new } => run_change(slot, reader, current, new),
        PinJob::Unblock { slot, puk, new } => run_unblock(slot, reader, puk, new),
        PinJob::Activate { code, pin1, pin2 } => run_activate(reader, code, pin1, pin2),
    }
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

fn prepare_change(
    mut fields: Vec<Vec<u8>>,
    labels: PinFields,
    pin: Option<PasswordLengthRange>,
) -> Result<(PinBytes, PinBytes), String> {
    if fields.len() != 3 {
        zeroize_all(&mut fields);
        return Err(String::from("Internal error: wrong field count."));
    }
    let pin = accepted(&mut fields, pin)?;
    let current = take_digit_buffer(&mut fields, 0, labels.current, pin)?;
    let new = take_digit_buffer(&mut fields, 1, labels.new, pin)?;
    let confirm = take_digit_buffer(&mut fields, 2, labels.repeat, pin)?;
    if new.as_bytes() != confirm.as_bytes() {
        return Err(String::from(
            "The new PIN entries do not match; nothing was sent to the card.",
        ));
    }
    Ok((current, new))
}

fn prepare_unblock(
    mut fields: Vec<Vec<u8>>,
    labels: PinFields,
    puk: Option<PasswordLengthRange>,
    pin: Option<PasswordLengthRange>,
) -> Result<(Puk, PinBytes), String> {
    if fields.len() != 3 {
        zeroize_all(&mut fields);
        return Err(String::from("Internal error: wrong field count."));
    }
    let puk_range = accepted(&mut fields, puk)?;
    let pin = accepted(&mut fields, pin)?;
    let raw = take_digit_buffer(&mut fields, 0, "PUK", puk_range)?;
    let puk = Puk::new(raw).map_err(|error| {
        zeroize_all(&mut fields);
        role_error("The PUK", &digits_hint(puk_range), error)
    })?;
    let new = take_digit_buffer(&mut fields, 1, labels.new, pin)?;
    let confirm = take_digit_buffer(&mut fields, 2, labels.repeat, pin)?;
    if new.as_bytes() != confirm.as_bytes() {
        return Err(String::from(
            "The new PIN entries do not match; nothing was sent to the card.",
        ));
    }
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
) -> Result<(PinBytes, Option<PinBytes>, Option<PinBytes>), String> {
    if fields.len() != 5 {
        zeroize_all(&mut fields);
        return Err(String::from("Internal error: wrong field count."));
    }
    let code = take_code_buffer(&mut fields, 0)?;
    let pin1 = take_optional_pair(
        &mut fields,
        1,
        PIN1_FIELDS,
        lengths.pin1(),
        "The PIN 1 entries do not match; nothing was sent to the card.",
    )?;
    let pin2 = take_optional_pair(
        &mut fields,
        3,
        PIN2_FIELDS,
        lengths.pin2(),
        "The PIN 2 entries do not match; nothing was sent to the card.",
    )?;
    Ok((code, pin1, pin2))
}

/// Move a new PIN and its repeat, at `index` and the next field, into
/// a validated [`PinBytes`]; `None` when both fields are empty. Two
/// entries that differ give `mismatch`.
fn take_optional_pair(
    fields: &mut [Vec<u8>],
    index: usize,
    labels: PinFields,
    range: Option<PasswordLengthRange>,
    mismatch: &str,
) -> Result<Option<PinBytes>, String> {
    let repeat_index = index.saturating_add(1);
    let both_empty = fields.get(index).is_some_and(Vec::is_empty)
        && fields.get(repeat_index).is_some_and(Vec::is_empty);
    if both_empty {
        return Ok(None);
    }
    let range = accepted(fields, range)?;
    let pin = take_digit_buffer(fields, index, labels.new, range)?;
    let repeat = take_digit_buffer(fields, repeat_index, labels.repeat, range)?;
    if pin.as_bytes() != repeat.as_bytes() {
        zeroize_all(fields);
        return Err(String::from(mismatch));
    }
    Ok(Some(pin))
}

/// The accepted length of a credential, as the form states it.
fn digits_hint(range: PasswordLengthRange) -> String {
    format!("{}-{} digits", range.min(), range.max())
}

/// Move one buffer into a validated [`PinBytes`] whose length the card
/// accepts, so a typo is rejected before it can burn a card-side retry.
fn take_digit_buffer(
    fields: &mut [Vec<u8>],
    index: usize,
    label: &str,
    range: PasswordLengthRange,
) -> Result<PinBytes, String> {
    let hint = digits_hint(range);
    let pin = take_buffer(fields, index, label, &hint)?;
    if pin.digit_count() < range.min() {
        zeroize_all(fields);
        return Err(format!("{label} is too short ({hint})."));
    }
    if !range.contains(pin.digit_count()) {
        zeroize_all(fields);
        return Err(format!("{label} has the wrong length ({hint})."));
    }
    Ok(pin)
}

/// Move the activation code into a validated [`PinBytes`]. Its exact
/// length is the card's scheme to decide; here it only has to be digits
/// no shorter than any scheme takes.
fn take_code_buffer(fields: &mut [Vec<u8>], index: usize) -> Result<PinBytes, String> {
    const HINT: &str = "7 or 8 digits";
    const LABEL: &str = "Activation code";
    let code = take_buffer(fields, index, LABEL, HINT)?;
    if code.digit_count() < ActivationPinSeven::LENGTH {
        zeroize_all(fields);
        return Err(format!("{LABEL} is too short ({HINT})."));
    }
    Ok(code)
}

/// Move one buffer into a [`PinBytes`] of digits.
fn take_buffer(
    fields: &mut [Vec<u8>],
    index: usize,
    label: &str,
    hint: &str,
) -> Result<PinBytes, String> {
    let Some(slot) = fields.get_mut(index) else {
        zeroize_all(fields);
        return Err(String::from("Internal error: missing PIN field."));
    };
    let bytes = std::mem::take(slot);
    PinBytes::new(bytes).map_err(|error| {
        zeroize_all(fields);
        role_error(label, hint, error)
    })
}

/// Render a credential-policy rejection using only static policy
/// text. The error's counts (expected lengths, offending offset)
/// are deliberately not formatted: lengths of secret material
/// never reach the display.
fn role_error(label: &str, hint: &str, error: PinRoleError) -> String {
    match error {
        PinRoleError::Empty => format!("{label} is empty ({hint})."),
        PinRoleError::WrongLength { .. } => format!("{label} has the wrong length ({hint})."),
        PinRoleError::NonDigit { .. } => format!("{label} must contain digits only."),
    }
}

fn zeroize_all(fields: &mut [Vec<u8>]) {
    for field in fields.iter_mut() {
        field.zeroize();
    }
}

fn run_change(
    slot: PinManageSlot,
    reader: &str,
    current: PinBytes,
    new: PinBytes,
) -> Result<String, String> {
    let filter = service::reader_filter(reader.to_owned());
    let serial = service::inspect(Some(&filter))
        .map_err(|error| op_error(&error))?
        .serial;
    let options = ChangePinOptions {
        slot,
        current,
        new,
        reader_filter: Some(reader.to_owned()),
    };
    let report = service::change_pin(&serial, options).map_err(|error| op_error(&error))?;
    Ok(render_change(&report))
}

fn run_unblock(
    slot: PinManageSlot,
    reader: &str,
    puk: Puk,
    new: PinBytes,
) -> Result<String, String> {
    let filter = service::reader_filter(reader.to_owned());
    let serial = service::inspect(Some(&filter))
        .map_err(|error| op_error(&error))?
        .serial;
    let options = UnblockPinOptions {
        slot,
        puk,
        new_pin: new,
        reader_filter: Some(reader.to_owned()),
    };
    let report = service::unblock_pin(&serial, options).map_err(|error| op_error(&error))?;
    Ok(render_unblock(&report))
}

fn run_activate(
    reader: &str,
    code: PinBytes,
    pin1: Option<PinBytes>,
    pin2: Option<PinBytes>,
) -> Result<String, String> {
    let filter = service::reader_filter(reader.to_owned());
    let snapshot = service::inspect(Some(&filter)).map_err(|error| op_error(&error))?;
    if code.digit_count() != snapshot.activation_code_length {
        return Err(activation_length_error(snapshot.activation_code_length));
    }
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
        ChangePinOutcome::Ok => format!(
            "{pin} changed on {} ({}).\r\nThe new PIN is active now.",
            report.person, report.card_serial
        ),
        ChangePinOutcome::WrongCurrentPin { retries_left } => {
            let left = retries_left.get();
            if left == 0 {
                format!(
                    "Wrong current {pin}; no tries left. {pin} is now locked; use the Unblock operation with the PUK."
                )
            } else {
                format!("Wrong current {pin}; {left} tries left. Nothing was changed.")
            }
        }
        ChangePinOutcome::Locked => {
            format!("{pin} is locked. Use the Unblock operation with the PUK to set a new one.")
        }
        ChangePinOutcome::LengthError => {
            format!("{pin} change refused: length error (host bug, please report).")
        }
        ChangePinOutcome::Other(word) => {
            format!("{pin} change failed with card status 0x{word:04X}.")
        }
    }
}

fn render_unblock(report: &UnblockPinReport) -> String {
    let pin = report.slot.label();
    match report.outcome {
        UnblockOutcome::Ok => format!(
            "{pin} unblocked on {} ({}) and set to the new value.",
            report.person, report.card_serial
        ),
        UnblockOutcome::WrongPuk { retries_left } => {
            let left = retries_left.get();
            if left == 0 {
                String::from(
                    "Wrong PUK; no PUK tries left. Do not guess again: the next wrong PUK makes the card permanently unrecoverable.",
                )
            } else {
                format!("Wrong PUK; {left} PUK tries left. Nothing was changed.")
            }
        }
        UnblockOutcome::PukLocked => String::from(
            "The PUK itself is locked. No software recovery is possible; the card needs DVV reissue.",
        ),
        UnblockOutcome::Invalidated => String::from(
            "The card reports the unblock counter exhausted. The card needs DVV reissue.",
        ),
        UnblockOutcome::LengthError => {
            String::from("Unblock refused: length error (host bug, please report).")
        }
        UnblockOutcome::Other(word) => {
            format!("Unblock failed with card status 0x{word:04X}.")
        }
    }
}

/// The refusal for an activation code of the wrong length for the
/// card's scheme.
fn activation_length_error(expected: usize) -> String {
    format!(
        "The activation code must have {expected} digits for this card; nothing was sent to the card."
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
    out.push_str("PIN 1: ");
    out.push_str(&activate_line(report.pin1_outcome.as_ref()));
    out.push_str("\r\nPIN2: ");
    out.push_str(&activate_line(report.pin2_outcome.as_ref()));
    out
}

fn activate_line(outcome: Option<&UnblockOutcome>) -> String {
    match outcome {
        None => String::from("not attempted"),
        Some(UnblockOutcome::Ok) => String::from("set"),
        Some(UnblockOutcome::WrongPuk { retries_left }) => {
            format!("wrong activation code; {retries_left} tries left")
        }
        Some(UnblockOutcome::PukLocked) => String::from("code locked"),
        Some(UnblockOutcome::Invalidated) => {
            String::from("code invalidated; card needs DVV reissue")
        }
        Some(UnblockOutcome::LengthError) => String::from("refused: length error (host bug)"),
        Some(UnblockOutcome::Other(word)) => format!("failed with card status 0x{word:04X}"),
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
        other => flatten(&other.to_string(), 400),
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
