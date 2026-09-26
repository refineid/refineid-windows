// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! PIN screen backend: status reads plus change, unblock, and
//! activate operations.
//!
//! Secrets cross this module only as validated [`PinBytes`],
//! [`Puk`], or [`ActivationCode`] values built from raw digit
//! buffers at the UI boundary. They are never held in `String`,
//! never formatted (not even their lengths), and never logged;
//! retry counts are the only numbers that reach the display.
use refineid_card_manager_core::card_pin::ActivatePreflightOutcome;
use refineid_card_manager_core::card_pin::{
    ActivateOptions, ActivateReport, CardPinError, ChangePinOptions, ChangePinReport,
    PinManageSlot, UnblockPinOptions, UnblockPinReport,
};
use refineid_card_manager_core::service;
use refineid_lib_core::auth::{ChangePinOutcome, UnblockOutcome};
use refineid_lib_core::pin::{
    ActivationCode, ActivationPinEight, ActivationPinSeven, PinBytes, PinRoleError, Puk,
};
use zeroize::Zeroize;

use crate::identity::{StateText, credential_label, pin_kind, puk_kind, puk_label, short_error};

/// Combobox entries, in dispatch order. The UI and [`prepare`]
/// share these indices.
pub const MODES: [&str; 5] = [
    "Change PIN1",
    "Change PIN2",
    "Unblock PIN1 (PUK)",
    "Unblock PIN2 (PUK)",
    "Activate new card",
];

/// Field labels per mode, top to bottom. An empty label hides
/// that row.
pub const FIELDS: [[&str; 5]; 5] = [
    ["Current PIN1:", "New PIN:", "Confirm new PIN:", "", ""],
    ["Current PIN2:", "New PIN:", "Confirm new PIN:", "", ""],
    ["PUK:", "New PIN1:", "Confirm new PIN1:", "", ""],
    ["PUK:", "New PIN2:", "Confirm new PIN2:", "", ""],
    [
        "Activation code:",
        "New PIN1:",
        "Confirm PIN1:",
        "New PIN2:",
        "Confirm PIN2:",
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
        code: ActivationCode,
        pin1: PinBytes,
        pin2: PinBytes,
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
    })
}

/// Validate UI digit buffers into a runnable job. Runs on the UI
/// thread so typos surface without touching the card: no APDU
/// goes out, and no retry counter moves, before this returns
/// `Ok`. Every buffer is either moved into a zeroizing type or
/// wiped on the error path.
pub fn prepare(mode: usize, fields: Vec<Vec<u8>>) -> Result<PinJob, String> {
    match mode {
        0 => {
            let (current, new) = prepare_change(fields, "Current PIN1", 4, "4-12 digits")?;
            Ok(PinJob::Change {
                slot: PinManageSlot::Pin1,
                current,
                new,
            })
        }
        1 => {
            let (current, new) = prepare_change(fields, "Current PIN2", 6, "6-12 digits")?;
            Ok(PinJob::Change {
                slot: PinManageSlot::Pin2,
                current,
                new,
            })
        }
        2 => {
            let (puk, new) = prepare_unblock(fields, "New PIN1", 4, "4-12 digits")?;
            Ok(PinJob::Unblock {
                slot: PinManageSlot::Pin1,
                puk,
                new,
            })
        }
        3 => {
            let (puk, new) = prepare_unblock(fields, "New PIN2", 6, "6-12 digits")?;
            Ok(PinJob::Unblock {
                slot: PinManageSlot::Pin2,
                puk,
                new,
            })
        }
        4 => {
            prepare_activate(fields).map(|(code, pin1, pin2)| PinJob::Activate { code, pin1, pin2 })
        }
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

fn prepare_change(
    mut fields: Vec<Vec<u8>>,
    current_label: &str,
    role_min: usize,
    hint: &str,
) -> Result<(PinBytes, PinBytes), String> {
    if fields.len() != 3 {
        zeroize_all(&mut fields);
        return Err(String::from("Internal error: wrong field count."));
    }
    let current = take_digit_buffer(&mut fields, 0, current_label, role_min, hint)?;
    let new = take_digit_buffer(&mut fields, 1, "New PIN", role_min, hint)?;
    let confirm = take_digit_buffer(&mut fields, 2, "Confirm new PIN", role_min, hint)?;
    if new.as_bytes() != confirm.as_bytes() {
        return Err(String::from(
            "New PIN entries do not match; nothing was sent to the card.",
        ));
    }
    Ok((current, new))
}

fn prepare_unblock(
    mut fields: Vec<Vec<u8>>,
    new_label: &str,
    role_min: usize,
    hint: &str,
) -> Result<(Puk, PinBytes), String> {
    if fields.len() != 3 {
        zeroize_all(&mut fields);
        return Err(String::from("Internal error: wrong field count."));
    }
    let raw = take_digit_buffer(&mut fields, 0, "PUK", 7, "7-8 digits")?;
    let puk = Puk::new(raw).map_err(|error| role_error("The PUK", "7-8 digits", error))?;
    let new = take_digit_buffer(&mut fields, 1, new_label, role_min, hint)?;
    let confirm = take_digit_buffer(&mut fields, 2, "Confirm new PIN", role_min, hint)?;
    if new.as_bytes() != confirm.as_bytes() {
        return Err(String::from(
            "New PIN entries do not match; nothing was sent to the card.",
        ));
    }
    Ok((puk, new))
}

fn prepare_activate(
    mut fields: Vec<Vec<u8>>,
) -> Result<(ActivationCode, PinBytes, PinBytes), String> {
    if fields.len() != 5 {
        zeroize_all(&mut fields);
        return Err(String::from("Internal error: wrong field count."));
    }
    let raw = take_digit_buffer(&mut fields, 0, "Activation code", 7, "7 or 8 digits")?;
    let code = match raw.digit_count() {
        7 => ActivationPinSeven::new(raw)
            .map(ActivationCode::Seven)
            .map_err(|error| role_error("The activation code", "7 or 8 digits", error))?,
        8 => ActivationPinEight::new(raw)
            .map(ActivationCode::Eight)
            .map_err(|error| role_error("The activation code", "7 or 8 digits", error))?,
        _ => {
            return Err(String::from(
                "The activation code has the wrong length (7 or 8 digits).",
            ));
        }
    };
    let pin1 = take_digit_buffer(&mut fields, 1, "New PIN1", 4, "4-12 digits")?;
    let confirm1 = take_digit_buffer(&mut fields, 2, "Confirm PIN1", 4, "4-12 digits")?;
    if pin1.as_bytes() != confirm1.as_bytes() {
        return Err(String::from(
            "New PIN1 entries do not match; nothing was sent to the card.",
        ));
    }
    let pin2 = take_digit_buffer(&mut fields, 3, "New PIN2", 6, "6-12 digits")?;
    let confirm2 = take_digit_buffer(&mut fields, 4, "Confirm PIN2", 6, "6-12 digits")?;
    if pin2.as_bytes() != confirm2.as_bytes() {
        return Err(String::from(
            "New PIN2 entries do not match; nothing was sent to the card.",
        ));
    }
    Ok((code, pin1, pin2))
}

/// Move one buffer into a validated [`PinBytes`]. The role minimum
/// (4 for PIN1-family, 6 for PIN2) is enforced locally so a short
/// typo is rejected before it can burn a card-side retry.
fn take_digit_buffer(
    fields: &mut [Vec<u8>],
    index: usize,
    label: &str,
    role_min: usize,
    hint: &str,
) -> Result<PinBytes, String> {
    let Some(slot) = fields.get_mut(index) else {
        zeroize_all(fields);
        return Err(String::from("Internal error: missing PIN field."));
    };
    let bytes = std::mem::take(slot);
    let pin = PinBytes::new(bytes).map_err(|error| {
        zeroize_all(fields);
        role_error(label, hint, error)
    })?;
    if pin.digit_count() < role_min {
        zeroize_all(fields);
        return Err(format!("{label} is too short ({hint})."));
    }
    Ok(pin)
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
    code: ActivationCode,
    pin1: PinBytes,
    pin2: PinBytes,
) -> Result<String, String> {
    let filter = service::reader_filter(reader.to_owned());
    let serial = service::inspect(Some(&filter))
        .map_err(|error| op_error(&error))?
        .serial;
    let options = ActivateOptions {
        activation_pin: code,
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

fn render_activate(report: &ActivateReport) -> String {
    let mut out = String::new();
    match report.preflight {
        ActivatePreflightOutcome::LooksUnactivated { .. } => {
            out.push_str("Card looks unactivated; activation proceeded.\r\n");
        }
        ActivatePreflightOutcome::LooksActivated { .. } => {
            out.push_str("Card already looks activated.\r\n");
        }
    }
    out.push_str("PIN1: ");
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
