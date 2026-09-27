// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Identity screen backend: one-shot snapshot reads, rendered for display.
//! Read-only; the photo path runs PACE with the operator-supplied CAN.
use refineid_card_manager_core::service::{self, CardSnapshot};
use refineid_lib_core::auth::{PinStatus, PukStatus};
use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend as _};
use refineid_lib_core::can::{Can, CanError};
use refineid_lib_core::emrtd::{self, EmrtdError};
use refineid_lib_core::pkcs15::{CardGeneration, FineidReaderPicker as _};
use refineid_lib_pcsc::{PcscBackend, PcscError};
use std::path::PathBuf;
use zeroize::Zeroize;

use crate::pin::flatten;

/// First reader currently reporting a card, if any.
pub fn first_present_reader() -> Option<String> {
    service::present_readers().ok()?.into_iter().next()
}

/// Read and render the identity panel for one reader.
pub fn read_identity(reader: &str) -> Result<String, String> {
    Ok(format_view(&read_identity_view(reader)?))
}

/// Severity of a credential state for status coloring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateKind {
    /// Healthy / ready.
    Ok,
    /// Low retries; warn before acting.
    Warn,
    /// Locked or invalidated.
    Bad,
    /// Unknown or uninformative probe result.
    Neutral,
}

/// A display string plus its severity.
#[derive(Debug, Clone)]
pub struct StateText {
    /// Rendered text (retry counts, never secrets).
    pub text: String,
    /// Severity for status coloring.
    pub kind: StateKind,
}

/// Structured identity panel: one field per UI row.
#[derive(Debug, Clone)]
pub struct IdentityView {
    /// Reader name the card was read from.
    pub reader: String,
    /// Card serial (`best_serial` form).
    pub serial: String,
    /// Holder rendering ("SURNAME GIVENS PEUIN").
    pub holder: String,
    /// Card model rendering.
    pub card: String,
    /// Generation label.
    pub generation: &'static str,
    /// Activation-code length rendering, when known.
    pub activation: Option<String>,
    /// PIN1 state.
    pub pin1: StateText,
    /// PIN2 state.
    pub pin2: StateText,
    /// PUK state.
    pub puk: StateText,
}

/// Read the structured identity panel for one reader.
pub fn read_identity_view(reader: &str) -> Result<IdentityView, String> {
    let filter = service::reader_filter(reader.to_owned());
    let snapshot = service::inspect(Some(&filter)).map_err(|error| short_error(&error))?;
    Ok(view(&snapshot))
}

/// Render a view as the classic multi-line panel. The headless
/// `--smoke` path uses this; the GUI fills rows from the view.
pub fn format_view(view: &IdentityView) -> String {
    let mut out = String::new();
    line(&mut out, "Reader", &view.reader);
    line(&mut out, "Serial", &view.serial);
    line(&mut out, "Holder", &view.holder);
    line(&mut out, "Card", &view.card);
    line(&mut out, "Generation", view.generation);
    if let Some(length) = view.activation.as_ref() {
        line(&mut out, "Activation code", length);
    }
    line(&mut out, "PIN1", &view.pin1.text);
    line(&mut out, "PIN2", &view.pin2.text);
    line(&mut out, "PUK", &view.puk.text);
    out
}

fn view(snapshot: &CardSnapshot) -> IdentityView {
    IdentityView {
        reader: snapshot.reader.clone(),
        serial: snapshot.serial.as_str().to_owned(),
        holder: snapshot.person.clone(),
        card: format!(
            "{} {} v{}",
            snapshot.model.vendor().as_dvv_label(),
            snapshot.model.fineid_specification(),
            snapshot.model.fineid_specification_version()
        ),
        generation: generation_label(snapshot.generation),
        activation: snapshot
            .activation_code_length
            .map(|length| format!("{length} digits")),
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
    }
}

pub const fn pin_kind(status: Option<&PinStatus>) -> StateKind {
    match status {
        Some(PinStatus::Verified) => StateKind::Ok,
        Some(PinStatus::Remaining(retries)) => {
            let left = retries.get();
            if left == 0 {
                StateKind::Bad
            } else if left == 1 {
                StateKind::Warn
            } else {
                StateKind::Ok
            }
        }
        Some(PinStatus::Locked) => StateKind::Bad,
        _ => StateKind::Neutral,
    }
}

pub const fn puk_kind(status: Option<&PukStatus>) -> StateKind {
    match status {
        Some(PukStatus::Remaining(retries)) => {
            let left = retries.get();
            if left == 0 {
                StateKind::Bad
            } else if left == 1 {
                StateKind::Warn
            } else {
                StateKind::Ok
            }
        }
        Some(PukStatus::Locked | PukStatus::Invalidated) => StateKind::Bad,
        _ => StateKind::Neutral,
    }
}

/// Parse a UI digit buffer into a typed CAN, wiping the buffer.
/// Error texts are static: `CanError`'s `Display` renders the
/// offending byte, which must never reach the display.
pub fn parse_can(mut buffer: Vec<u8>) -> Result<Can, String> {
    let result = std::str::from_utf8(&buffer)
        .map_err(|_| String::from("CAN must contain digits only."))
        .and_then(|text| Can::new(text).map_err(can_error));
    buffer.zeroize();
    result
}

fn can_error(error: CanError) -> String {
    match error {
        CanError::Empty => String::from("CAN is empty (6 digits)."),
        CanError::WrongLength { .. } => String::from("CAN must be exactly 6 digits."),
        CanError::NonDigit { .. } => String::from("CAN must contain digits only."),
        CanError::AllZeros => String::from("CAN was all zeros; check the input."),
    }
}

/// Read the identity panel plus the eMRTD photo. A photo failure
/// still returns the identity panel with the photo error appended.
pub fn read_identity_and_photo(reader: &str, can: Can) -> Result<String, String> {
    let identity = read_identity(reader)?;
    let photo = match read_photo(reader, can) {
        Ok(report) => report,
        Err(error) => format!("FAILED: {error}"),
    };
    Ok(format!("{identity}\r\nPhoto: {photo}"))
}

/// Photo outcome: a report line plus, for JPEG faces, the saved
/// file the GUI displays.
pub struct PhotoOutcome {
    /// One-line report (`saved ...`).
    pub report: String,
    /// Saved JPEG path for in-window display. `None` for
    /// JPEG2000 (no OS decoder) and when no face was found.
    pub display_jpeg: Option<PathBuf>,
}

fn read_photo(reader: &str, can: Can) -> Result<String, String> {
    Ok(read_photo_saved(reader, can)?.report)
}

/// Run PACE with the CAN, read DG2, and save the facial image to
/// the per-user temp dir.
pub fn read_photo_saved(reader: &str, can: Can) -> Result<PhotoOutcome, String> {
    let filter = service::reader_filter(reader.to_owned());
    let backend = PcscBackend;
    let pick = backend
        .pick_fineid_reader(Some(&filter))
        .map_err(|error| flatten(&error.to_string(), 300))?;
    // A freshly opened transport sits at MF level, which is the
    // PACE precondition (`run_pace_with_can` docs).
    let transport = backend
        .open_exclusive(&pick.reader_id, ReaderAccessCap::Read)
        .map_err(|error| flatten(&error.to_string(), 300))?;
    let data = emrtd::read_personal_data(transport, can).map_err(|error| emrtd_error(&error))?;
    match data.face.as_ref() {
        Some(image) => {
            let (format, bytes) = match image {
                emrtd::DocumentImage::Jpeg(bytes) => ("JPEG", bytes),
                emrtd::DocumentImage::Jpeg2000(bytes) => ("JPEG2000", bytes),
            };
            let path = std::env::temp_dir().join(format!("refineid-photo.{}", image.extension()));
            std::fs::write(&path, bytes)
                .map_err(|error| format!("could not save photo: {error}"))?;
            let report = format!(
                "saved {} bytes ({format}) to {}",
                bytes.len(),
                path.display()
            );
            let display_jpeg = match image {
                emrtd::DocumentImage::Jpeg(_) => Some(path),
                emrtd::DocumentImage::Jpeg2000(_) => None,
            };
            Ok(PhotoOutcome {
                report,
                display_jpeg,
            })
        }
        None => Ok(PhotoOutcome {
            report: format!(
                "DG2 read ({} raw bytes) but no recognised JPEG/JPEG2000 image.",
                data.dg2_der.len()
            ),
            display_jpeg: None,
        }),
    }
}

fn emrtd_error(error: &EmrtdError<PcscError>) -> String {
    match error {
        EmrtdError::BadCan => {
            String::from("Wrong CAN. The CAN is the 6-digit number on the card front.")
        }
        EmrtdError::CardReset => {
            String::from("Card reset during the read; reinsert the card and retry.")
        }
        other => flatten(&other.to_string(), 400),
    }
}

fn line(out: &mut String, label: &str, value: &str) {
    out.push_str(label);
    out.push_str(": ");
    out.push_str(value);
    out.push_str("\r\n");
}

const fn generation_label(generation: CardGeneration) -> &'static str {
    match generation {
        CardGeneration::Newer => "newer",
        CardGeneration::Older => "older",
        CardGeneration::Unknown => "unknown",
    }
}

pub fn credential_label(status: Option<&PinStatus>, changed: Option<bool>) -> String {
    let base = match status {
        None => String::from("unknown"),
        Some(PinStatus::Verified) => String::from("verified"),
        Some(PinStatus::Remaining(retries)) => format!("ready ({} tries left)", retries.get()),
        Some(PinStatus::NoInfo) => String::from("no information"),
        Some(PinStatus::Locked) => String::from("locked"),
        Some(PinStatus::Other(word)) => format!("other (0x{word:04X})"),
    };
    match changed {
        Some(true) => format!("{base}, changed"),
        Some(false) => format!("{base}, factory"),
        None => base,
    }
}

pub fn puk_label(status: Option<&PukStatus>) -> String {
    match status {
        None => String::from("unknown"),
        Some(PukStatus::Remaining(retries)) => format!("ready ({} tries left)", retries.get()),
        Some(PukStatus::NoInfo) => String::from("no information"),
        Some(PukStatus::Locked) => String::from("locked"),
        Some(PukStatus::Invalidated) => String::from("invalidated"),
        Some(PukStatus::Other(word)) => format!("other (0x{word:04X})"),
    }
}

/// Single-line, length-capped failure text. Card errors never carry
/// credentials; the cap keeps card-status internals out of the UI.
pub fn short_error(error: &impl core::fmt::Debug) -> String {
    let mut text = format!("{error:?}").replace(['\r', '\n'], " ");
    text.truncate(200);
    text.trim().to_owned()
}
