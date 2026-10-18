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

//! Narrow C ABI for the `RefineID` Windows settings application.
//!
//! Raw pointers end in this crate. Reader names and card serials are copied
//! into owned Rust strings before use. Credential buffers are copied once
//! into zeroizing domain types and never enter JSON, logs, error messages, or
//! formatting. The safe card-management crate owns every protocol decision.

#![expect(
    unsafe_code,
    reason = "this crate is the deliberately narrow C ABI boundary used by the C# WinUI process"
)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::c_char;
use std::ffi::CString;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use refineid_card_manager_core::card_pin::{
    ActivateOptions, ActivatePreflightOutcome, ChangePinOptions, PinManageSlot, UnblockPinOptions,
};
use refineid_card_manager_core::service::{self, CardSnapshot, ContactlessSnapshot};
use refineid_doc_sign::asic_verify::{DocumentVerifyReport, verify_document};
use refineid_doc_sign::cades::SigningTime;
use refineid_doc_sign::document::Format;
use refineid_doc_sign::pades::SignatureMetadata;
use refineid_doc_sign::service::{
    DocumentRequest, LocalVerifyOutcome, SignOptions, SignReport, SignSlot, sign_with_slot,
};
use refineid_doc_sign::verify::VerifyOptions;
use refineid_lib_core::apdu::status_word::PinRetries;
use refineid_lib_core::auth::{ChangePinOutcome, PinStatus, PukStatus, UnblockOutcome};
use refineid_lib_core::can::{CAN_DIGITS, Can};
use refineid_lib_core::identity::TokenSerial;
use refineid_lib_core::pin::{
    ActivationCode, ActivationPinEight, ActivationPinSeven, PinBytes, Puk,
};
use refineid_lib_core::pkcs15::CardGeneration;
use refineid_lib_pcsc::PcscBackend;
use refineid_windows_credential_store::save_can;
use refineid_windows_driver_probe::{self, LocalCardSupport};
use serde::Serialize;
use zeroize::Zeroize;

/// JSON-view of the probe result exposed to the `WinUI` apps.
#[derive(Serialize)]
struct LocalCardSupportReport {
    state: &'static str,
    reader_count: Option<usize>,
}

const MAX_READER_NAME_BYTES: usize = 1_024;
const MAX_SERIAL_BYTES: usize = 256;
const MAX_SECRET_BYTES: usize = PinBytes::MAX_LENGTH;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_REASON_BYTES: usize = 256;
const PIN1_SLOT: u8 = 1;
const PIN2_SLOT: u8 = 2;
/// The document formats the signing export takes.
const FORMAT_PADES: u8 = 1;
const FORMAT_ASICE: u8 = 2;

#[derive(Debug)]
struct ApiFailure {
    code: &'static str,
    message: String,
}

impl ApiFailure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Serialize)]
struct ApiError<'a> {
    code: &'a str,
    message: &'a str,
}

#[derive(Serialize)]
struct ApiEnvelope<'a, T> {
    ok: bool,
    data: Option<&'a T>,
    error: Option<ApiError<'a>>,
}

#[derive(Serialize)]
struct ReaderList {
    readers: Vec<String>,
}

#[derive(Serialize)]
struct CardSnapshotDto {
    reader: String,
    serial: String,
    person: String,
    model: String,
    generation: &'static str,
    activation_code_length: Option<usize>,
    pin1: Option<CredentialStatusDto>,
    pin2: Option<CredentialStatusDto>,
    puk: Option<CredentialStatusDto>,
    pin1_changed: Option<bool>,
    pin2_changed: Option<bool>,
}

#[derive(Serialize)]
struct ContactlessSnapshotDto {
    reader: String,
    serial: String,
    person: String,
    generation: &'static str,
    pin1: Option<CredentialStatusDto>,
    pin2: Option<CredentialStatusDto>,
    puk: Option<CredentialStatusDto>,
}

#[derive(Serialize)]
struct CredentialStatusDto {
    state: &'static str,
    attempts_remaining: Option<u8>,
    status_word: Option<u16>,
}

#[derive(Serialize)]
struct MutationResult {
    succeeded: bool,
    outcome: &'static str,
    message: String,
    attempts_remaining: Option<u8>,
    status_word: Option<u16>,
}

impl From<CardSnapshot> for CardSnapshotDto {
    fn from(snapshot: CardSnapshot) -> Self {
        let model = format!(
            "{} {} v{}",
            snapshot.model.vendor().as_dvv_label(),
            snapshot.model.fineid_specification(),
            snapshot.model.fineid_specification_version()
        );
        Self {
            reader: snapshot.reader,
            serial: snapshot.serial.as_str().to_owned(),
            person: snapshot.person,
            model,
            generation: generation_label(snapshot.generation),
            activation_code_length: snapshot.activation_code_length,
            pin1: snapshot.pin1.map(CredentialStatusDto::from),
            pin2: snapshot.pin2.map(CredentialStatusDto::from),
            puk: snapshot.puk.map(CredentialStatusDto::from),
            pin1_changed: snapshot.pin1_changed,
            pin2_changed: snapshot.pin2_changed,
        }
    }
}

impl From<ContactlessSnapshot> for ContactlessSnapshotDto {
    fn from(snapshot: ContactlessSnapshot) -> Self {
        Self {
            reader: snapshot.reader,
            serial: snapshot.serial.as_str().to_owned(),
            person: snapshot.person,
            generation: generation_label(snapshot.generation),
            pin1: snapshot.pin1.map(CredentialStatusDto::from),
            pin2: snapshot.pin2.map(CredentialStatusDto::from),
            puk: snapshot.puk.map(CredentialStatusDto::from),
        }
    }
}

impl From<PinStatus> for CredentialStatusDto {
    fn from(status: PinStatus) -> Self {
        match status {
            PinStatus::Verified => Self::plain("verified"),
            PinStatus::Remaining(retries) => Self::retries("ready", retries),
            PinStatus::NoInfo => Self::plain("no_information"),
            PinStatus::Locked => Self::plain("locked"),
            PinStatus::Other(status_word) => Self::status_word("other", status_word),
        }
    }
}

impl From<PukStatus> for CredentialStatusDto {
    fn from(status: PukStatus) -> Self {
        match status {
            PukStatus::Remaining(retries) => Self::retries("ready", retries),
            PukStatus::NoInfo => Self::plain("no_information"),
            PukStatus::Locked => Self::plain("locked"),
            PukStatus::Invalidated => Self::plain("invalidated"),
            PukStatus::Other(status_word) => Self::status_word("other", status_word),
        }
    }
}

impl CredentialStatusDto {
    const fn plain(state: &'static str) -> Self {
        Self {
            state,
            attempts_remaining: None,
            status_word: None,
        }
    }

    const fn retries(state: &'static str, retries: PinRetries) -> Self {
        Self {
            state,
            attempts_remaining: Some(retries.get()),
            status_word: None,
        }
    }

    const fn status_word(state: &'static str, status_word: u16) -> Self {
        Self {
            state,
            attempts_remaining: None,
            status_word: Some(status_word),
        }
    }
}

const fn generation_label(generation: CardGeneration) -> &'static str {
    match generation {
        CardGeneration::Newer => "newer",
        CardGeneration::Older => "older",
        CardGeneration::Unknown => "unknown",
    }
}

/// Free a UTF-8 JSON string returned by this library.
///
/// `json` must be either null or a pointer returned by one of the
/// `refineid_settings_*` functions in this library.
///
/// # Safety
///
/// A non-null `json` must be an unmodified pointer returned by this library,
/// and the caller must pass it to this function exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_settings_string_free(json: *mut c_char) {
    if json.is_null() {
        return;
    }
    // SAFETY: The C ABI contract above requires a pointer produced by
    // CString::into_raw in reply_json. Reconstructing it exactly once returns
    // the allocation to Rust.
    drop(unsafe { CString::from_raw(json) });
}

/// Enumerate card-present PC/SC readers.
#[unsafe(no_mangle)]
pub extern "C" fn refineid_settings_present_readers() -> *mut c_char {
    reply_json(|| {
        service::present_readers()
            .map(|readers| ReaderList { readers })
            .map_err(|error| ApiFailure::new("reader_enumeration_failed", error.to_string()))
    })
}

/// Probe whether this machine has a usable local FINEID card stack.
///
/// `ready` means the minidriver is registered and a reader is present;
/// `driver_not_installed` means the machine has no FINEID minidriver;
/// `no_reader` means the minidriver exists but no reader is enumerated.
#[unsafe(no_mangle)]
pub extern "C" fn refineid_settings_detect_local_card_support() -> *mut c_char {
    reply_json(|| Ok(detect_local_card_support()))
}

fn detect_local_card_support() -> LocalCardSupportReport {
    match refineid_windows_driver_probe::detect() {
        LocalCardSupport::Ready { reader_count } => LocalCardSupportReport {
            state: "ready",
            reader_count: Some(reader_count),
        },
        LocalCardSupport::NoReader => LocalCardSupportReport {
            state: "no_reader",
            reader_count: Some(0),
        },
        LocalCardSupport::DriverNotInstalled => LocalCardSupportReport {
            state: "driver_not_installed",
            reader_count: None,
        },
    }
}

/// Verify a document signature offline (no card needed).
///
/// `cert`, `message`, and `signature` are UTF-8 file paths. The function
/// loads the certificate (PEM or DER), the original message bytes, and the
/// raw RSA-PKCS1v15-SHA256 signature, then verifies the signature against
/// the certificate's public key. Returns a JSON report with the result.
///
/// # Safety
///
/// Each pointer must point to `*_length` readable bytes of valid UTF-8.
/// The buffers must not exceed the documented maximums.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_settings_verify_document(
    cert: *const u8,
    cert_length: usize,
    message: *const u8,
    message_length: usize,
    signature: *const u8,
    signature_length: usize,
) -> *mut c_char {
    reply_json(|| {
        let cert_path = unsafe { copy_utf8(cert, cert_length, MAX_READER_NAME_BYTES, "cert")? };
        let message_path =
            unsafe { copy_utf8(message, message_length, MAX_READER_NAME_BYTES, "message")? };
        let signature_path = unsafe {
            copy_utf8(
                signature,
                signature_length,
                MAX_READER_NAME_BYTES,
                "signature",
            )?
        };

        let options = VerifyOptions {
            cert: cert_path.into(),
            message: message_path.into(),
            signature: signature_path.into(),
        };

        match refineid_doc_sign::verify::verify_offline(&options) {
            Ok(report) => Ok(VerifyReportJson {
                cert_path: report.cert_path,
                cert_subject_cn: report.cert_subject_cn.map(|cn| cn.to_string()),
                message_path: report.message_path,
                message_len: report.message_len,
                signature_path: report.signature_path,
                signature_len: report.signature_len,
                ok: report.ok,
                failure_reason: report.failure_reason.map(|e| e.to_string()),
            }),
            Err(e) => Err(ApiFailure::new("verify_failed", e.to_string())),
        }
    })
}

#[derive(Serialize)]
struct VerifyReportJson {
    cert_path: PathBuf,
    cert_subject_cn: Option<String>,
    message_path: PathBuf,
    message_len: u64,
    signature_path: PathBuf,
    signature_len: usize,
    ok: bool,
    failure_reason: Option<String>,
}

/// A verified container: every file against its manifest digest and
/// every signature against its signer.
#[derive(Serialize)]
struct ContainerVerifyJson {
    container: String,
    ok: bool,
    files: Vec<ContainerFileJson>,
    signatures: Vec<ContainerSignatureJson>,
    report: String,
}

#[derive(Serialize)]
struct ContainerFileJson {
    name: String,
    algorithm: String,
    digest_ok: bool,
    detail: String,
}

#[derive(Serialize)]
struct ContainerSignatureJson {
    signer_cn: Option<String>,
    valid: bool,
    detail: String,
}

impl From<DocumentVerifyReport> for ContainerVerifyJson {
    fn from(report: DocumentVerifyReport) -> Self {
        let rendered = report.render();
        Self {
            container: report.container,
            ok: report.ok,
            files: report
                .files
                .into_iter()
                .map(|file| ContainerFileJson {
                    name: file.name,
                    algorithm: file.algorithm,
                    digest_ok: file.digest_ok,
                    detail: file.detail,
                })
                .collect(),
            signatures: report
                .signatures
                .into_iter()
                .map(|signature| ContainerSignatureJson {
                    signer_cn: signature.signer_cn,
                    valid: signature.valid,
                    detail: signature.detail,
                })
                .collect(),
            report: rendered,
        }
    }
}

/// Verify a signed container (`.asice`, `.bdoc`) or a signed PDF offline:
/// no card, no PIN, no network.
///
/// # Safety
///
/// `path` must point to `path_length` readable bytes of valid UTF-8 within
/// the documented path bound.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_settings_verify_container(
    path: *const u8,
    path_length: usize,
) -> *mut c_char {
    reply_json(|| {
        // SAFETY: The pointer and bound are validated before the read.
        let path = unsafe { copy_utf8(path, path_length, MAX_PATH_BYTES, "path") }?;
        verify_document(std::path::Path::new(&path))
            .map(ContainerVerifyJson::from)
            .map_err(|error| ApiFailure::new("verify_failed", error.to_string()))
    })
}

/// A signed document: where it was written and what signed it.
#[derive(Serialize)]
struct DocumentSignJson {
    output_path: PathBuf,
    output_len: usize,
    slot: &'static str,
    signer_cn: Option<String>,
    local_verify: String,
}

impl From<SignReport> for DocumentSignJson {
    fn from(report: SignReport) -> Self {
        Self {
            output_path: report.signature_path,
            output_len: report.output_len,
            slot: match report.slot {
                SignSlot::Qualified => "qualified",
                SignSlot::Auth => "authentication",
            },
            signer_cn: report.cert_subject_cn.map(|cn| cn.as_str().to_owned()),
            local_verify: match report.local_verify {
                LocalVerifyOutcome::Ok => "ok".to_owned(),
                LocalVerifyOutcome::Failed(detail) => format!("failed: {detail}"),
                LocalVerifyOutcome::Skipped(reason) => format!("skipped: {reason}"),
            },
        }
    }
}

/// Sign a document with the card in the single attached reader.
///
/// `PAdES` goes into a copy of the PDF beside it, an `ASiC-E` container
/// beside any file. `format` is [`FORMAT_PADES`] or [`FORMAT_ASICE`];
/// `slot` is the PIN slot whose key signs, PIN 2 for the qualified
/// signature and PIN 1 for the authentication key; `reason` may be empty.
///
/// # Safety
///
/// `path` and `reason` must point to as many readable bytes of valid UTF-8
/// as their lengths say, within the documented bounds; `pin` must point to
/// `pin_length` readable bytes within the PIN bound.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_settings_sign_document(
    path: *const u8,
    path_length: usize,
    format: u8,
    slot: u8,
    pin: *const u8,
    pin_length: usize,
    reason: *const u8,
    reason_length: usize,
) -> *mut c_char {
    reply_json(|| {
        // SAFETY: The pointer and bound are validated before the read.
        let path = unsafe { copy_utf8(path, path_length, MAX_PATH_BYTES, "path") }?;
        let format = parse_format(format)?;
        let slot = sign_slot(parse_slot(slot)?);
        // SAFETY: The secret is copied into PinBytes, whose constructor
        // zeroizes its temporary Vec on both success and failure.
        let pin = unsafe { copy_pin(pin, pin_length, "PIN") }?;
        let reason = if reason_length == 0 {
            None
        } else {
            // SAFETY: As for `path`.
            Some(unsafe { copy_utf8(reason, reason_length, MAX_REASON_BYTES, "reason") }?)
        };
        let input = PathBuf::from(path);
        if format == Format::Pades && !is_pdf(&input) {
            return Err(ApiFailure::new(
                "not_pdf",
                "A PDF signature needs a .pdf file; other files go into a container.",
            ));
        }
        let output = derive_output(&input, format);
        let request = DocumentRequest {
            format,
            additional_inputs: Vec::new(),
            signing_time: SigningTime::now(),
            metadata: SignatureMetadata {
                reason,
                location: None,
                contact: None,
                name: None,
                signing_time: None,
                visible_signature: None,
            },
            expected_serial: None,
            visible_signature: None,
            archive: false,
            long_term: false,
            timestamp_authorities: Vec::new(),
            timestamp_credentials: None,
        };
        let options = SignOptions {
            input,
            output,
            pin,
            save_cert: None,
            reader_filter: None,
            can: None,
            document: Some(request),
        };
        sign_with_slot(PcscBackend, slot, options)
            .map(DocumentSignJson::from)
            .map_err(|error| ApiFailure::new("sign_failed", error.to_string()))
    })
}

/// The document format a wire value names.
fn parse_format(format: u8) -> Result<Format, ApiFailure> {
    match format {
        FORMAT_PADES => Ok(Format::Pades),
        FORMAT_ASICE => Ok(Format::AsicECades),
        other => Err(ApiFailure::new(
            "invalid_format",
            format!("format {other} is not a document format"),
        )),
    }
}

/// The signing key a PIN slot guards.
const fn sign_slot(slot: PinManageSlot) -> SignSlot {
    match slot {
        PinManageSlot::Pin1 => SignSlot::Auth,
        PinManageSlot::Pin2 => SignSlot::Qualified,
    }
}

/// Output next to the input: `-signed.pdf` for a PDF signature, `.asice`
/// appended for a container.
fn derive_output(input: &std::path::Path, format: Format) -> PathBuf {
    if format == Format::Pades {
        let stem = input
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("document");
        input.with_file_name(format!("{stem}-signed.pdf"))
    } else {
        let name = input
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("document");
        input.with_file_name(format!("{name}.asice"))
    }
}

fn is_pdf(input: &std::path::Path) -> bool {
    input
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("pdf"))
}

/// Inspect one selected contact-interface card without presenting a secret.
///
/// The returned JSON contains public card metadata and counter-safe
/// credential status only.
///
/// # Safety
///
/// `reader` must point to `reader_length` readable bytes for the duration of
/// the call. The bytes must contain UTF-8 and may not exceed the documented
/// reader-name bound.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_settings_inspect(
    reader: *const u8,
    reader_length: usize,
) -> *mut c_char {
    reply_json(|| {
        // SAFETY: The caller promises a readable buffer for reader_length
        // bytes. copy_utf8 validates the pointer, bound, and UTF-8 before the
        // value leaves this FFI frame.
        let reader = unsafe { copy_utf8(reader, reader_length, MAX_READER_NAME_BYTES, "reader") }?;
        let filter = service::reader_filter(reader);
        service::inspect(Some(&filter))
            .map(CardSnapshotDto::from)
            .map_err(|error| ApiFailure::new("card_inspection_failed", error.to_string()))
    })
}

/// Prove and enable contactless access with the selected reader and printed CAN.
///
/// This follows the current `RefineID-Apple` APDU order: SELECT MF, PACE,
/// then protected PKCS #15 reads. Only after that proof succeeds is the CAN
/// saved in this Windows user's Credential Manager for the Card Module. It
/// sends no PIN-bearing command.
///
/// # Safety
///
/// `reader` and `can` must point to their accompanying number of readable
/// bytes for the duration of the call. Reader bytes must contain UTF-8. CAN
/// bytes must contain exactly six ASCII digits.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_settings_prime_contactless(
    reader: *const u8,
    reader_length: usize,
    can: *const u8,
    can_length: usize,
) -> *mut c_char {
    reply_json(|| {
        // SAFETY: The input is pointer-checked, bounded, and copied.
        let reader = unsafe { copy_utf8(reader, reader_length, MAX_READER_NAME_BYTES, "reader") }?;
        // SAFETY: The input is pointer-checked, bounded, and copied.
        let mut can_bytes = unsafe { copy_bytes(can, can_length, CAN_DIGITS, "CAN") }?;
        let parsed_can = core::str::from_utf8(&can_bytes)
            .map_err(|_| ApiFailure::new("invalid_can", "The CAN must contain six digits."))
            .and_then(|value| {
                Can::new(value).map_err(|error| ApiFailure::new("invalid_can", error.to_string()))
            });
        can_bytes.zeroize();
        let parsed_can = parsed_can?;
        let filter = service::reader_filter(reader);
        let snapshot = service::inspect_contactless(Some(&filter), parsed_can)
            .map_err(|error| ApiFailure::new("contactless_inspection_failed", error.to_string()))?;
        save_can(&snapshot.lookup_atr, &parsed_can)
            .map_err(|error| ApiFailure::new("contactless_storage_failed", error.to_string()))?;
        Ok(ContactlessSnapshotDto::from(snapshot))
    })
}

/// Change PIN1 or PIN2 on the card bound to `serial`.
///
/// All secret buffers are consumed into zeroizing Rust types before the card
/// service is called. No secret appears in the JSON response.
///
/// # Safety
///
/// Each non-null pointer must address the accompanying number of readable
/// bytes for the duration of the call. Reader and serial buffers must be
/// UTF-8. Secret buffers are bounded to the FINEID stored credential length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_settings_change_pin(
    reader: *const u8,
    reader_length: usize,
    serial: *const u8,
    serial_length: usize,
    slot: u8,
    current_pin: *const u8,
    current_pin_length: usize,
    new_pin: *const u8,
    new_pin_length: usize,
    confirmation: *const u8,
    confirmation_length: usize,
) -> *mut c_char {
    reply_json(|| {
        // SAFETY: Every pointer is validated and copied before use.
        let reader = unsafe { copy_utf8(reader, reader_length, MAX_READER_NAME_BYTES, "reader") }?;
        // SAFETY: See the comment above.
        let serial = unsafe { copy_utf8(serial, serial_length, MAX_SERIAL_BYTES, "card serial") }?;
        let slot = parse_slot(slot)?;
        // SAFETY: Secret inputs are copied into PinBytes, whose constructor
        // zeroizes its temporary Vec on both success and failure.
        let current = unsafe { copy_pin(current_pin, current_pin_length, "current PIN") }?;
        // SAFETY: As above.
        let new = unsafe { copy_pin(new_pin, new_pin_length, "new PIN") }?;
        // SAFETY: As above.
        let confirmation =
            unsafe { copy_pin(confirmation, confirmation_length, "PIN confirmation") }?;
        require_confirmation(&new, &confirmation)?;

        let report = service::change_pin(
            &TokenSerial::new(serial),
            ChangePinOptions {
                slot,
                current,
                new,
                reader_filter: Some(reader),
            },
        )
        .map_err(|error| ApiFailure::new("change_pin_failed", error.to_string()))?;
        Ok(change_result(report.outcome, report.slot))
    })
}

/// Unblock PIN1 or PIN2 and replace it with a new value.
///
/// # Safety
///
/// Each non-null pointer must address the accompanying number of readable
/// bytes for the duration of the call. Reader and serial buffers must be
/// UTF-8. Secret buffers are bounded to the FINEID stored credential length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_settings_unblock_pin(
    reader: *const u8,
    reader_length: usize,
    serial: *const u8,
    serial_length: usize,
    slot: u8,
    puk: *const u8,
    puk_length: usize,
    new_pin: *const u8,
    new_pin_length: usize,
    confirmation: *const u8,
    confirmation_length: usize,
) -> *mut c_char {
    reply_json(|| {
        // SAFETY: Every pointer is validated and copied before use.
        let reader = unsafe { copy_utf8(reader, reader_length, MAX_READER_NAME_BYTES, "reader") }?;
        // SAFETY: See the comment above.
        let serial = unsafe { copy_utf8(serial, serial_length, MAX_SERIAL_BYTES, "card serial") }?;
        let slot = parse_slot(slot)?;
        // SAFETY: Secret inputs are copied into zeroizing domain types.
        let puk = unsafe { copy_pin(puk, puk_length, "PUK") }
            .and_then(|bytes| Puk::new(bytes).map_err(pin_role_error))?;
        // SAFETY: As above.
        let new_pin = unsafe { copy_pin(new_pin, new_pin_length, "new PIN") }?;
        // SAFETY: As above.
        let confirmation =
            unsafe { copy_pin(confirmation, confirmation_length, "PIN confirmation") }?;
        require_confirmation(&new_pin, &confirmation)?;

        let report = service::unblock_pin(
            &TokenSerial::new(serial),
            UnblockPinOptions {
                slot,
                puk,
                new_pin,
                reader_filter: Some(reader),
            },
        )
        .map_err(|error| ApiFailure::new("unblock_pin_failed", error.to_string()))?;
        Ok(unblock_result(report.outcome, report.slot))
    })
}

/// Activate a card and set its initial PIN1 and PIN2 values.
///
/// # Safety
///
/// Each non-null pointer must address the accompanying number of readable
/// bytes for the duration of the call. Reader and serial buffers must be
/// UTF-8. Secret buffers are bounded to the FINEID stored credential length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn refineid_settings_activate(
    reader: *const u8,
    reader_length: usize,
    serial: *const u8,
    serial_length: usize,
    activation_code: *const u8,
    activation_code_length: usize,
    new_pin1: *const u8,
    new_pin1_length: usize,
    pin1_confirmation: *const u8,
    pin1_confirmation_length: usize,
    new_pin2: *const u8,
    new_pin2_length: usize,
    pin2_confirmation: *const u8,
    pin2_confirmation_length: usize,
    allow_reactivate: u8,
) -> *mut c_char {
    reply_json(|| {
        // SAFETY: Every pointer is validated and copied before use.
        let reader = unsafe { copy_utf8(reader, reader_length, MAX_READER_NAME_BYTES, "reader") }?;
        // SAFETY: See the comment above.
        let serial = unsafe { copy_utf8(serial, serial_length, MAX_SERIAL_BYTES, "card serial") }?;
        // SAFETY: Secret inputs are copied into zeroizing domain types.
        let activation = unsafe { copy_activation_code(activation_code, activation_code_length) }?;
        // SAFETY: As above.
        let new_pin1 = unsafe { copy_pin(new_pin1, new_pin1_length, "new PIN1") }?;
        // SAFETY: As above.
        let pin1_confirmation = unsafe {
            copy_pin(
                pin1_confirmation,
                pin1_confirmation_length,
                "PIN1 confirmation",
            )
        }?;
        require_confirmation(&new_pin1, &pin1_confirmation)?;
        // SAFETY: As above.
        let new_pin2 = unsafe { copy_pin(new_pin2, new_pin2_length, "new PIN2") }?;
        // SAFETY: As above.
        let pin2_confirmation = unsafe {
            copy_pin(
                pin2_confirmation,
                pin2_confirmation_length,
                "PIN2 confirmation",
            )
        }?;
        require_confirmation(&new_pin2, &pin2_confirmation)?;

        let filter = service::reader_filter(reader);
        let report = service::activate(
            &TokenSerial::new(serial),
            Some(&filter),
            ActivateOptions {
                activation_pin: activation,
                new_pin1,
                new_pin2,
                allow_reactivate: allow_reactivate != 0,
            },
        )
        .map_err(|error| ApiFailure::new("activation_failed", error.to_string()))?;
        Ok(activation_result(&report))
    })
}

fn change_result(outcome: ChangePinOutcome, slot: PinManageSlot) -> MutationResult {
    let label = slot.label();
    match outcome {
        ChangePinOutcome::Ok => MutationResult {
            succeeded: true,
            outcome: "changed",
            message: format!("{label} was changed successfully."),
            attempts_remaining: None,
            status_word: None,
        },
        ChangePinOutcome::WrongCurrentPin { retries_left } => MutationResult {
            succeeded: false,
            outcome: "wrong_current_pin",
            message: format!(
                "The current {label} was rejected. {} attempts remain.",
                retries_left.get()
            ),
            attempts_remaining: Some(retries_left.get()),
            status_word: None,
        },
        ChangePinOutcome::Locked => MutationResult {
            succeeded: false,
            outcome: "locked",
            message: format!("{label} is blocked and must be recovered before it can be changed."),
            attempts_remaining: None,
            status_word: None,
        },
        ChangePinOutcome::LengthError => MutationResult {
            succeeded: false,
            outcome: "host_length_error",
            message: "The card rejected the command shape. This is a software error.".to_owned(),
            attempts_remaining: None,
            status_word: Some(0x6700),
        },
        ChangePinOutcome::Other(status_word) => MutationResult {
            succeeded: false,
            outcome: "card_rejected",
            message: format!("The card rejected the request (status {status_word:#06X})."),
            attempts_remaining: None,
            status_word: Some(status_word),
        },
    }
}

fn unblock_result(outcome: UnblockOutcome, slot: PinManageSlot) -> MutationResult {
    let label = slot.label();
    match outcome {
        UnblockOutcome::Ok => MutationResult {
            succeeded: true,
            outcome: "unblocked",
            message: format!("{label} was recovered and replaced successfully."),
            attempts_remaining: None,
            status_word: None,
        },
        UnblockOutcome::WrongPuk { retries_left } => MutationResult {
            succeeded: false,
            outcome: "wrong_puk",
            message: format!(
                "The recovery code was rejected. {} recovery attempts remain.",
                retries_left.get()
            ),
            attempts_remaining: Some(retries_left.get()),
            status_word: None,
        },
        UnblockOutcome::PukLocked => MutationResult {
            succeeded: false,
            outcome: "puk_locked",
            message: "The recovery code is blocked. The card must be replaced.".to_owned(),
            attempts_remaining: None,
            status_word: None,
        },
        UnblockOutcome::Invalidated => MutationResult {
            succeeded: false,
            outcome: "recovery_invalidated",
            message: "Card recovery is no longer available. The card must be replaced.".to_owned(),
            attempts_remaining: None,
            status_word: None,
        },
        UnblockOutcome::LengthError => MutationResult {
            succeeded: false,
            outcome: "host_length_error",
            message: "The card rejected the command shape. This is a software error.".to_owned(),
            attempts_remaining: None,
            status_word: Some(0x6700),
        },
        UnblockOutcome::Other(status_word) => MutationResult {
            succeeded: false,
            outcome: "card_rejected",
            message: format!("The card rejected the request (status {status_word:#06X})."),
            attempts_remaining: None,
            status_word: Some(status_word),
        },
    }
}

fn activation_result(
    report: &refineid_card_manager_core::card_pin::ActivateReport,
) -> MutationResult {
    let refused = matches!(
        report.preflight,
        ActivatePreflightOutcome::LooksActivated { .. }
    ) && report.pin1_outcome.is_none();
    if refused {
        return MutationResult {
            succeeded: false,
            outcome: "already_activated",
            message: "The card already looks activated. No activation command was sent.".to_owned(),
            attempts_remaining: None,
            status_word: None,
        };
    }
    match (report.pin1_outcome, report.pin2_outcome) {
        (Some(UnblockOutcome::Ok), Some(UnblockOutcome::Ok)) => MutationResult {
            succeeded: true,
            outcome: "activated",
            message: "The card was activated and both PIN values were set.".to_owned(),
            attempts_remaining: None,
            status_word: None,
        },
        (Some(pin1), pin2) => {
            let first = unblock_result(pin1, PinManageSlot::Pin1);
            let second = pin2.map(|value| unblock_result(value, PinManageSlot::Pin2));
            let message = second.as_ref().map_or_else(
                || first.message.clone(),
                |value| format!("{} {}", first.message, value.message),
            );
            let attempts_remaining = first
                .attempts_remaining
                .or_else(|| second.as_ref().and_then(|value| value.attempts_remaining));
            let status_word = first
                .status_word
                .or_else(|| second.as_ref().and_then(|value| value.status_word));
            MutationResult {
                succeeded: false,
                outcome: "activation_incomplete",
                message,
                attempts_remaining,
                status_word,
            }
        }
        (None, _) => MutationResult {
            succeeded: false,
            outcome: "activation_incomplete",
            message: "The card did not accept the activation request.".to_owned(),
            attempts_remaining: None,
            status_word: None,
        },
    }
}

fn parse_slot(slot: u8) -> Result<PinManageSlot, ApiFailure> {
    match slot {
        PIN1_SLOT => Ok(PinManageSlot::Pin1),
        PIN2_SLOT => Ok(PinManageSlot::Pin2),
        _ => Err(ApiFailure::new(
            "invalid_slot",
            "The PIN slot must be PIN1 or PIN2.",
        )),
    }
}

fn require_confirmation(value: &PinBytes, confirmation: &PinBytes) -> Result<(), ApiFailure> {
    if value.as_bytes() == confirmation.as_bytes() {
        Ok(())
    } else {
        Err(ApiFailure::new(
            "confirmation_mismatch",
            "The new PIN and its confirmation do not match.",
        ))
    }
}

fn pin_role_error(error: impl core::fmt::Display) -> ApiFailure {
    ApiFailure::new("invalid_secret_shape", error.to_string())
}

unsafe fn copy_activation_code(
    input: *const u8,
    length: usize,
) -> Result<ActivationCode, ApiFailure> {
    // SAFETY: copy_pin applies the pointer and length checks before reading.
    let bytes = unsafe { copy_pin(input, length, "activation code") }?;
    match length {
        ActivationPinSeven::LENGTH => ActivationPinSeven::new(bytes)
            .map(ActivationCode::Seven)
            .map_err(pin_role_error),
        ActivationPinEight::LENGTH => ActivationPinEight::new(bytes)
            .map(ActivationCode::Eight)
            .map_err(pin_role_error),
        _ => Err(ApiFailure::new(
            "invalid_activation_code_shape",
            "The activation code must contain seven or eight digits.",
        )),
    }
}

unsafe fn copy_pin(
    input: *const u8,
    length: usize,
    label: &'static str,
) -> Result<PinBytes, ApiFailure> {
    // SAFETY: copy_bytes validates null, length, and the public maximum before
    // creating the temporary slice.
    let bytes = unsafe { copy_bytes(input, length, MAX_SECRET_BYTES, label) }?;
    PinBytes::new(bytes).map_err(pin_role_error)
}

unsafe fn copy_utf8(
    input: *const u8,
    length: usize,
    maximum: usize,
    label: &'static str,
) -> Result<String, ApiFailure> {
    // SAFETY: copy_bytes validates the pointer and bound before reading.
    let bytes = unsafe { copy_bytes(input, length, maximum, label) }?;
    String::from_utf8(bytes)
        .map_err(|_| ApiFailure::new("invalid_utf8", format!("{label} was not valid UTF-8")))
}

unsafe fn copy_bytes(
    input: *const u8,
    length: usize,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<u8>, ApiFailure> {
    if length == 0 {
        return Err(ApiFailure::new(
            "empty_input",
            format!("{label} must not be empty"),
        ));
    }
    if length > maximum {
        return Err(ApiFailure::new(
            "input_too_long",
            format!("{label} exceeds the accepted length"),
        ));
    }
    if input.is_null() {
        return Err(ApiFailure::new(
            "null_input",
            format!("{label} pointer was null"),
        ));
    }
    // SAFETY: The caller's C ABI obligation is that input points to at least
    // length readable bytes. The checks above reject null and cap length before
    // the slice is formed; to_vec immediately detaches it from caller memory.
    Ok(unsafe { core::slice::from_raw_parts(input, length) }.to_vec())
}

fn reply_json<T, F>(operation: F) -> *mut c_char
where
    T: Serialize,
    F: FnOnce() -> Result<T, ApiFailure>,
{
    let result = catch_unwind(AssertUnwindSafe(operation));
    let json = match result {
        Ok(Ok(data)) => serialize_envelope(&ApiEnvelope {
            ok: true,
            data: Some(&data),
            error: None,
        }),
        Ok(Err(error)) => serialize_envelope::<T>(&ApiEnvelope {
            ok: false,
            data: None,
            error: Some(ApiError {
                code: error.code,
                message: &error.message,
            }),
        }),
        Err(_) => serialize_envelope::<T>(&ApiEnvelope {
            ok: false,
            data: None,
            error: Some(ApiError {
                code: "internal_panic",
                message: "The native card service stopped unexpectedly.",
            }),
        }),
    };
    CString::new(json).map_or(core::ptr::null_mut(), CString::into_raw)
}

fn serialize_envelope<T: Serialize>(envelope: &ApiEnvelope<'_, T>) -> String {
    serde_json::to_string(envelope).unwrap_or_else(|_| {
        "{\"ok\":false,\"data\":null,\"error\":{\"code\":\"serialization_failed\",\"message\":\"The native response could not be encoded.\"}}".to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::{
        FORMAT_ASICE, FORMAT_PADES, PIN1_SLOT, PIN2_SLOT, derive_output, is_pdf, parse_format,
        parse_slot, sign_slot,
    };
    use refineid_card_manager_core::card_pin::PinManageSlot;
    use refineid_doc_sign::document::Format;
    use refineid_doc_sign::service::SignSlot;
    use std::path::Path;

    #[test]
    fn slot_values_are_closed() {
        assert_eq!(parse_slot(PIN1_SLOT).ok(), Some(PinManageSlot::Pin1));
        assert_eq!(parse_slot(PIN2_SLOT).ok(), Some(PinManageSlot::Pin2));
        assert!(parse_slot(0).is_err());
        assert!(parse_slot(3).is_err());
    }

    #[test]
    fn format_values_are_closed_and_a_slot_names_its_key() {
        assert_eq!(parse_format(FORMAT_PADES).ok(), Some(Format::Pades));
        assert_eq!(parse_format(FORMAT_ASICE).ok(), Some(Format::AsicECades));
        assert!(parse_format(0).is_err());
        assert!(parse_format(3).is_err());
        assert_eq!(sign_slot(PinManageSlot::Pin1), SignSlot::Auth);
        assert_eq!(sign_slot(PinManageSlot::Pin2), SignSlot::Qualified);
    }

    #[test]
    fn the_output_lands_beside_the_input() {
        assert_eq!(
            derive_output(Path::new("C:\\docs\\contract.pdf"), Format::Pades),
            Path::new("C:\\docs\\contract-signed.pdf")
        );
        assert_eq!(
            derive_output(Path::new("C:\\docs\\notes.txt"), Format::AsicECades),
            Path::new("C:\\docs\\notes.txt.asice")
        );
        assert!(is_pdf(Path::new("C:\\docs\\CONTRACT.PDF")));
        assert!(!is_pdf(Path::new("C:\\docs\\notes.txt")));
    }
}
