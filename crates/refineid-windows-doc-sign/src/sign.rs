// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Signing one document: with the card in a reader attached to this
//! computer under the PIN 2 the user typed, or, when no reader holds a
//! card, on the paired phone, which asks for PIN 2 itself.
//!
//! Both paths are core's: `service::reader::sign` drives the card
//! session, `remote::sign_on_phone` the phone through [`crate::phone`],
//! and both finish the document the same way: a signature timestamp
//! from the default authority, the chain and revocation material, an
//! archive timestamp, and for a PDF the round verification seal in the
//! user's interface language. The output is created beside the input
//! under core's signed-document name, which carries the signature's
//! best signature time; an existing file is never replaced.

use core::fmt;
use std::path::PathBuf;

use refineid_doc_sign::cades::SigningTime;
use refineid_doc_sign::document::Format;
use refineid_doc_sign::pades::{SignatureMetadata, StampLanguage, VisibleSignature};
use refineid_doc_sign::pin::{PinBytes, PinEntryError, PromptedPin};
use refineid_doc_sign::remote::PhoneSignOptions;
use refineid_doc_sign::service::reader::{ReaderSignError, SignOptions};
use refineid_doc_sign::service::{
    DEFAULT_TIMESTAMP_AUTHORITY, DocumentRequest, SignErrorKind, SignOutput, SignReport, SignSlot,
};
use refineid_doc_sign::signed_name::PendingSignedName;
use refineid_doc_sign::x509::DateTime;
use refineid_pcsc::PcscBackend;

use crate::phone::{PhoneSignFailure, SigningSource};

/// One document to sign, as the user asked for it.
#[derive(Debug)]
pub struct DocumentSignRequest {
    /// The file to sign.
    pub input: PathBuf,
    /// The signed PDF with its seal, or an `ASiC-E` container.
    pub format: Format,
    /// The reason recorded in a PDF signature, when the user gave one.
    pub reason: Option<String>,
    /// The language of the seal on a PDF: the user's interface language.
    pub stamp_language: StampLanguage,
}

/// Why the document was not signed, by the device that was to sign it.
#[derive(Debug)]
pub enum DocumentSignError {
    /// The card in this computer's reader did not sign.
    Reader(ReaderSignError),
    /// The paired phone did not sign.
    Phone(PhoneSignFailure),
}

impl fmt::Display for DocumentSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reader(error) => write!(f, "{error}"),
            Self::Phone(failure) => write!(f, "{failure}"),
        }
    }
}

impl core::error::Error for DocumentSignError {}

/// The signature the apps ask for: timestamped by the default authority,
/// with validation material and an archive timestamp, and for a PDF the
/// verification seal in `stamp_language`.
#[must_use]
pub fn document_request(
    format: Format,
    reason: Option<String>,
    stamp_language: StampLanguage,
    signing_time: SigningTime,
) -> DocumentRequest {
    DocumentRequest {
        format,
        additional_inputs: Vec::new(),
        signing_time,
        metadata: SignatureMetadata {
            reason,
            visible_signature: (format == Format::Pades)
                .then(|| VisibleSignature::verification(stamp_language)),
            ..SignatureMetadata::default()
        },
        archive: true,
        long_term: true,
        timestamp_authorities: vec![DEFAULT_TIMESTAMP_AUTHORITY.to_owned()],
        timestamp_credentials: None,
    }
}

/// The claimed signing time: `now`, to the second.
#[must_use]
pub fn signing_time_at(now: DateTime) -> SigningTime {
    SigningTime {
        year: now.year(),
        month: now.month(),
        day: now.day(),
        hour: now.hour(),
        minute: now.minutes(),
        second: now.seconds(),
    }
}

/// Sign `request` on `source`. The reader path presents `pin` to the
/// card once it is in hand and its retry counter is served; the phone
/// path takes no PIN here, the phone asks for PIN 2 on its own screen.
///
/// # Errors
/// [`DocumentSignError`] from the device that was to sign: the reader,
/// the card, the PIN, the phone, or the document's own failure.
pub fn sign(
    source: SigningSource,
    request: DocumentSignRequest,
    pin: Option<PinBytes>,
) -> Result<SignReport, DocumentSignError> {
    let outcome = sign_unreported(source, request, pin);
    if let Err(error) = &outcome {
        refineid_dev_errors::report!(DocumentSigning, "document not signed", error);
    }
    outcome
}

/// [`sign`], unreported.
fn sign_unreported(
    source: SigningSource,
    request: DocumentSignRequest,
    mut pin: Option<PinBytes>,
) -> Result<SignReport, DocumentSignError> {
    crate::http::install();
    let now = refineid_doc_sign::now_date_time();
    let output = SignOutput::SignedName(PendingSignedName::new(
        vec![request.input.clone()],
        request.format,
        now,
    ));
    let document = document_request(
        request.format,
        request.reason,
        request.stamp_language,
        signing_time_at(now),
    );
    match source {
        SigningSource::Phone(pair_id) => {
            // The phone takes PIN 2 itself; a PIN typed here is dropped
            // unused and zeroized.
            drop(pin);
            let mut outcomes = crate::phone::sign(
                pair_id,
                vec![PhoneSignOptions {
                    input: request.input,
                    output,
                    document,
                }],
            )
            .map_err(DocumentSignError::Phone)?;
            outcomes
                .pop()
                .unwrap_or(Err(SignErrorKind::NoDocuments))
                .map_err(|kind| DocumentSignError::Phone(PhoneSignFailure { kind, cause: None }))
        }
        SigningSource::Reader => {
            let mut source =
                PromptedPin::new(move |_role| pin.take().ok_or(PinEntryError::Unavailable));
            refineid_doc_sign::service::reader::sign(
                &PcscBackend,
                SignOptions {
                    input: request.input,
                    output,
                    slot: SignSlot::Qualified,
                    save_cert: None,
                    reader_filter: None,
                    can: None,
                    expected_serial: None,
                    document: Some(document),
                },
                &mut source,
            )
            .map_err(DocumentSignError::Reader)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Windows language identifier of Finnish (Finland), winnt.h.
    const FINNISH_FINLAND: u16 = 0x040b;
    /// The Windows language identifier of German (Germany), winnt.h.
    const GERMAN_GERMANY: u16 = 0x0407;
    /// A claimed signing time.
    const SIGNING_TIME: SigningTime = SigningTime {
        year: 2026,
        month: 6,
        day: 15,
        hour: 12,
        minute: 30,
        second: 45,
    };

    #[test]
    fn the_request_is_timestamped_archived_and_sealed() {
        let pdf = document_request(
            Format::Pades,
            None,
            StampLanguage::for_windows_language(FINNISH_FINLAND),
            SIGNING_TIME,
        );
        assert_eq!(
            pdf.timestamp_authorities,
            vec![DEFAULT_TIMESTAMP_AUTHORITY.to_owned()]
        );
        assert!(pdf.archive);
        assert!(pdf.long_term);
        assert_eq!(
            pdf.metadata.visible_signature,
            Some(VisibleSignature::verification(StampLanguage::Finnish))
        );
        assert_eq!(pdf.signing_time, SIGNING_TIME);
        let container = document_request(
            Format::AsicECades,
            Some("review".to_owned()),
            StampLanguage::for_windows_language(GERMAN_GERMANY),
            SIGNING_TIME,
        );
        assert!(container.metadata.visible_signature.is_none());
        assert!(container.archive);
        assert!(container.long_term);
        assert_eq!(container.metadata.reason.as_deref(), Some("review"));
    }

    #[test]
    fn the_claimed_time_is_the_clock_to_the_second() {
        let now = refineid_doc_sign::now_date_time();
        let claimed = signing_time_at(now);
        assert_eq!(claimed.year, now.year());
        assert_eq!(claimed.second, now.seconds());
    }
}
