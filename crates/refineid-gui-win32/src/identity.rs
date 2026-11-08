// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Identity screen backend: one-shot snapshot reads, rendered for display.
//! Read-only; the photo path runs PACE with the operator-supplied CAN.
use refineid_card_manager_core::service::{self, CardSnapshot};
use refineid_emrtd::{CardFaceImage, EmrtdOps as _, ImageFormat};
use refineid_lib_core::auth::{PinStatus, PukStatus};
use refineid_pace::{Can, CanError, SmTransport, UnvalidatedCan, read_card_access, run_pace};
use refineid_pcsc::{
    PcscBackend, ReaderAccessCap, ReaderBackend as _, ReaderBackendOps as _, ReaderFilter,
};
use refineid_pkcs15::fs::Pkcs15Ops as _;
use std::path::Path;
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
    /// Activation-code length rendering.
    pub activation: String,
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
    line(&mut out, "Activation PIN", &view.activation);
    line(&mut out, "Basic PIN 1", &view.pin1.text);
    line(&mut out, "Signature PIN 2", &view.pin2.text);
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
        activation: format!("{} digits", snapshot.activation_code_length),
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
/// Error texts are static and never echo the entered digits or
/// their count.
pub fn parse_can(mut buffer: Vec<u8>) -> Result<Can, String> {
    let result = std::str::from_utf8(&buffer)
        .map_err(|_| String::from("CAN must contain digits only."))
        .and_then(|text| {
            Can::reconstruct(UnvalidatedCan::from_owned_text(text.to_owned())).map_err(can_error)
        });
    buffer.zeroize();
    result
}

fn can_error(error: CanError) -> String {
    match error {
        CanError::Empty => String::from("CAN is empty (6 digits)."),
        CanError::WrongLength => String::from("CAN must be exactly 6 digits."),
        CanError::NonDigit => String::from("CAN must contain digits only."),
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

/// Photo outcome: a report line plus, for JPEG faces, the bytes the
/// GUI displays. The face stays in memory: no file holds it.
pub struct PhotoOutcome {
    /// One-line report (`read ...`).
    pub report: String,
    /// The JPEG for in-window display. `None` for JPEG2000 (no OS
    /// decoder) and when no face was found.
    pub display_jpeg: Option<Vec<u8>>,
}

/// The files in the per-user temp directory that hold a holder's face if
/// they exist: `RefineID` writes none, and removes any it finds at start.
const PHOTO_LEFTOVER_FILES: [&str; 2] = ["refineid-photo.jpg", "refineid-photo.jp2"];

/// Removes every face photo left in `directory`. One that cannot be removed
/// is tried again at the next start.
pub fn remove_photo_leftovers(directory: &Path) {
    for file in PHOTO_LEFTOVER_FILES {
        let _ = std::fs::remove_file(directory.join(file));
    }
}

fn read_photo(reader: &str, can: Can) -> Result<String, String> {
    Ok(read_photo_saved(reader, can)?.report)
}

/// Run PACE with the CAN and read DG2 into memory.
pub fn read_photo_saved(reader: &str, can: Can) -> Result<PhotoOutcome, String> {
    let backend = PcscBackend;
    let failed = |error: &dyn core::fmt::Display| flatten(&error.to_string(), 300);
    let picked = backend
        .pick_single_reader(Some(ReaderFilter::new(reader)))
        .map_err(|error| failed(&error))?;
    let mut transport = backend
        .open_exclusive(&picked, ReaderAccessCap::Read)
        .map_err(|error| failed(&error))?;
    // PACE's MSE:Set AT is accepted only in MF context, and EF.CardAccess,
    // which names its domain parameter, is read from there.
    transport.select_mf().map_err(|error| failed(&error))?;
    let card_access = read_card_access(&mut transport).map_err(|error| failed(&error))?;
    let session = run_pace(&mut transport, &card_access, &can).map_err(|error| failed(&error))?;
    drop(can);
    let mut channel = SmTransport::new(transport, session);
    channel
        .select_emrtd_application()
        .map_err(|error| flatten(&error.to_string(), 400))?;
    let face = channel
        .read_face_image()
        .map_err(|error| flatten(&error.to_string(), 400))?;
    Ok(photo_outcome(face.as_ref()))
}

/// What the screen shows of the card's face image.
fn photo_outcome(face: Option<&CardFaceImage>) -> PhotoOutcome {
    let Some(face) = face else {
        return PhotoOutcome {
            report: String::from("DG2 read but no recognised JPEG/JPEG2000 image."),
            display_jpeg: None,
        };
    };
    let bytes = face.image_bytes();
    let format = match face.format() {
        ImageFormat::Jpeg => "JPEG",
        ImageFormat::Jpeg2000 => "JPEG2000",
    };
    PhotoOutcome {
        report: format!("read {} bytes ({format})", bytes.len()),
        display_jpeg: (face.format() == ImageFormat::Jpeg).then(|| bytes.to_vec()),
    }
}

fn line(out: &mut String, label: &str, value: &str) {
    out.push_str(label);
    out.push_str(": ");
    out.push_str(value);
    out.push_str("\r\n");
}

pub fn credential_label(status: Option<&PinStatus>, changed: Option<bool>) -> String {
    let base = match status {
        None => String::from("unknown"),
        Some(PinStatus::Verified) => String::from("verified"),
        Some(PinStatus::Remaining(retries)) => format!("ready ({} tries left)", retries.get()),
        Some(PinStatus::NoInfo) => String::from("no information"),
        Some(PinStatus::Locked) => String::from("blocked"),
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
        Some(PukStatus::Locked) => String::from("blocked"),
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test scaffolding is constructed to be infallible"
)]
mod tests {
    use super::{PHOTO_LEFTOVER_FILES, remove_photo_leftovers};

    #[test]
    fn a_start_removes_every_face_photo_left_and_nothing_else() {
        let directory =
            std::env::temp_dir().join(format!("refineid-photo-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        for file in PHOTO_LEFTOVER_FILES {
            std::fs::write(directory.join(file), b"a face").unwrap();
        }
        let other = directory.join("other.jpg");
        std::fs::write(&other, b"not ours").unwrap();
        remove_photo_leftovers(&directory);
        for file in PHOTO_LEFTOVER_FILES {
            assert!(!directory.join(file).exists());
        }
        assert!(other.exists());
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
