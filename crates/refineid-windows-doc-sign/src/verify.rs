// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Verifying a signed document: judge the file, ask the network about
//! revocation where the file carried no answer, and render the verdict.
//!
//! The verdict comes from `refineid_doc_sign::verification` and the
//! document's own bytes, under the roots core pins. Only the revocation
//! row may go further: a signer on a verified chain the document says
//! nothing about is looked up over OCSP or CRL at `now`, through
//! `WinHTTP`, and a network that does not answer leaves the row as it
//! was. [`render`] prints one record per signature, `key: value` lines,
//! the everyday view: who signed, when, and whether it holds.

use core::fmt::{self, Display, Write as _};
use std::path::{Path, PathBuf};

use refineid_doc_sign::verification::live::live_revocation;
use refineid_doc_sign::verification::{
    DocumentFailure, DocumentFile, DocumentReport, Revocation, SignatureOutcome, SignatureReport,
    SignatureRow, TrustAnchors,
};
use refineid_doc_sign::x509::DateTime;

/// Why a file yielded no report.
#[derive(Debug)]
pub enum DocumentVerifyError {
    /// The file could not be read.
    Read {
        /// The file.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// The file was read and nothing in it could be judged.
    Failure {
        /// The file.
        path: PathBuf,
        /// What the verifier found instead of signatures.
        failure: DocumentFailure,
    },
}

impl Display for DocumentVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Failure { path, failure } => write!(f, "{}: {failure}", path.display()),
        }
    }
}

impl core::error::Error for DocumentVerifyError {}

/// Judge the document at `path` as of `now`.
///
/// Every signature is verified from the file alone, anchored on the
/// roots core pins, at the earliest time a timestamp proves, else at
/// `now`. A signer on a verified chain whose revocation the file does
/// not answer is then asked about over the network; the answer is
/// judged at `now`, and no answer leaves the row unavailable.
///
/// # Errors
/// [`DocumentVerifyError`] when the file cannot be read or carries
/// nothing to judge. A negative verdict is not an error.
pub fn verify_file(path: &Path, now: DateTime) -> Result<DocumentReport, DocumentVerifyError> {
    let outcome = verify_file_unreported(path, now);
    if let Err(error) = &outcome {
        refineid_dev_errors::report!(DocumentSigning, "document not verified", error);
    }
    outcome
}

/// [`verify_file`], unreported.
fn verify_file_unreported(
    path: &Path,
    now: DateTime,
) -> Result<DocumentReport, DocumentVerifyError> {
    let failure = |failure| DocumentVerifyError::Failure {
        path: path.to_path_buf(),
        failure,
    };
    let bytes = std::fs::read(path).map_err(|source| DocumentVerifyError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let file = DocumentFile::from_file(bytes).map_err(failure)?;
    let anchors = TrustAnchors::pinned();
    let report = refineid_doc_sign::verification::verify(&file, &anchors, now).map_err(failure)?;
    crate::http::install();
    Ok(report.with_live_revocation(|signature| live_revocation(signature, &anchors, now)))
}

/// Between a key and its value.
const KEY_SEPARATOR: &str = ": ";
/// Between two records: one blank line.
const RECORD_SEPARATOR: &str = "\n";
/// A value the signature does not have.
const NONE: &str = "-";

/// The key of one record line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    /// The file as named.
    File,
    /// The signer certificate's common name.
    Signer,
    /// The signer an `XAdES` counter-signature counter-signs.
    Countersigns,
    /// The proven time of the signature.
    Signed,
    /// The verdict.
    Verdict,
    /// One cause of a negative verdict.
    Reason,
    /// The revocation basis, when a valid signature's could not be
    /// checked.
    Revocation,
}

impl Key {
    /// The key as printed.
    const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Signer => "signer",
            Self::Countersigns => "countersigns",
            Self::Signed => "signed",
            Self::Verdict => "verdict",
            Self::Reason => "reason",
            Self::Revocation => "revocation",
        }
    }
}

/// The verdict on one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Every check holds and nothing says the signer is revoked.
    Valid,
    /// At least one check fails.
    NotValid,
    /// A verified answer says the signer is revoked.
    Revoked,
    /// The signature's profile is not implemented.
    Unsupported,
}

impl Verdict {
    /// The verdict as printed.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::NotValid => "not valid",
            Self::Revoked => "revoked",
            Self::Unsupported => "unsupported",
        }
    }
}

/// One cause of a negative verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// The signed content no longer matches.
    DocumentChanged,
    /// The signature does not verify.
    SignatureInvalid,
    /// The signer does not chain to a trust anchor.
    ChainUnverified,
    /// The signature's profile is not implemented.
    ProfileNotSupported,
}

impl Reason {
    /// The reason as printed.
    const fn as_str(self) -> &'static str {
        match self {
            Self::DocumentChanged => "document changed",
            Self::SignatureInvalid => "signature invalid",
            Self::ChainUnverified => "certificate chain unverified",
            Self::ProfileNotSupported => "profile not supported",
        }
    }
}

/// One record: `key: value` lines, each ending in a newline.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Record(String);

impl Record {
    /// Append one `key: value` line, every control character in the
    /// value written as `\x` and two hexadecimal digits so the value
    /// stays on its line.
    fn line(&mut self, key: Key, value: impl Display) {
        self.0.push_str(key.as_str());
        self.0.push_str(KEY_SEPARATOR);
        for character in value.to_string().chars() {
            if character.is_control() {
                let _ = write!(self.0, "\\x{:02x}", u32::from(character));
            } else {
                self.0.push(character);
            }
        }
        self.0.push('\n');
    }
}

/// What one signature row comes to, ready to print.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SignatureView {
    /// The signer's name, or `-`.
    signer: String,
    /// For a counter-signature, the name of the signer it
    /// counter-signs, or `-`.
    countersigns: Option<String>,
    /// The judgement, or why there is none.
    judgement: Judgement,
}

/// A row judged, or not.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Judgement {
    /// The signature's profile is not implemented.
    Unsupported,
    /// The facts behind the verdict.
    Judged(Facts),
}

/// The facts a judged record prints.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Facts {
    /// The proven time.
    signed: Option<DateTime>,
    /// The verdict.
    verdict: Verdict,
    /// Whether the signed content is unchanged.
    intact: bool,
    /// Whether the signature verifies.
    signature: bool,
    /// Whether the signer chains to a trust anchor.
    chained: bool,
    /// The revocation status of the signer.
    revocation: Revocation,
}

impl Facts {
    /// Every cause of a not valid verdict, in check order.
    fn reasons(&self) -> Vec<Reason> {
        [
            (self.intact, Reason::DocumentChanged),
            (self.signature, Reason::SignatureInvalid),
            (self.chained, Reason::ChainUnverified),
        ]
        .into_iter()
        .filter_map(|(holds, reason)| (!holds).then_some(reason))
        .collect()
    }
}

/// The report of `file`, one record per signature in document order,
/// records separated by a blank line, lines ending in `\n`.
#[must_use]
pub fn render(file: &str, report: &DocumentReport) -> String {
    let rows = report.rows();
    let records: Vec<String> = rows
        .iter()
        .map(|row| view(rows, row).record(file).0)
        .collect();
    records.join(RECORD_SEPARATOR)
}

/// The view of `row`, one of `rows`.
fn view(rows: &[SignatureRow], row: &SignatureRow) -> SignatureView {
    let countersigns = row.counter_signs().map(|index| {
        rows.get(index)
            .and_then(SignatureRow::signer)
            .map_or_else(|| NONE.to_owned(), |signer| name_or_none(signer.name()))
    });
    let signer = row
        .signer()
        .map_or_else(|| NONE.to_owned(), |signer| name_or_none(signer.name()));
    let judgement = match row.outcome() {
        SignatureOutcome::Judged(report) => Judgement::Judged(facts(report)),
        SignatureOutcome::Unsupported { .. } => Judgement::Unsupported,
    };
    SignatureView {
        signer,
        countersigns,
        judgement,
    }
}

/// The facts of a judged signature.
fn facts(report: &SignatureReport) -> Facts {
    Facts {
        signed: report.proof_of_existence(),
        verdict: verdict(report),
        intact: report.document_intact(),
        signature: report.signature_valid(),
        chained: report.chain_verified(),
        revocation: report.revocation(),
    }
}

/// The verdict the facts reach: revoked first, then not valid.
fn verdict(signature: &SignatureReport) -> Verdict {
    if signature
        .revocation()
        .revoked_before(signature.proof_of_existence())
    {
        Verdict::Revoked
    } else if signature.is_valid() {
        Verdict::Valid
    } else {
        Verdict::NotValid
    }
}

impl SignatureView {
    /// The record of this signature in `file`.
    fn record(&self, file: &str) -> Record {
        let mut record = Record::default();
        record.line(Key::File, file);
        record.line(Key::Signer, &self.signer);
        if let Some(countersigned) = &self.countersigns {
            record.line(Key::Countersigns, countersigned);
        }
        let facts = match &self.judgement {
            Judgement::Unsupported => {
                record.line(Key::Signed, NONE);
                record.line(Key::Verdict, Verdict::Unsupported.as_str());
                record.line(Key::Reason, Reason::ProfileNotSupported.as_str());
                return record;
            }
            Judgement::Judged(facts) => facts,
        };
        record.line(Key::Signed, time_or_none(facts.signed));
        record.line(Key::Verdict, facts.verdict.as_str());
        if facts.verdict == Verdict::NotValid {
            for reason in facts.reasons() {
                record.line(Key::Reason, reason.as_str());
            }
        }
        if facts.verdict == Verdict::Valid && facts.revocation == Revocation::Unavailable {
            record.line(Key::Revocation, "not checked");
        }
        record
    }
}

/// A name as the certificate spells it, or `-` when it is empty.
fn name_or_none(name: &str) -> String {
    if name.is_empty() {
        NONE.to_owned()
    } else {
        name.to_owned()
    }
}

/// The time, or `-`.
fn time_or_none(time: Option<DateTime>) -> String {
    time.map_or_else(|| NONE.to_owned(), |time| time.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use refineid_doc_sign::testkit::day;

    /// The file as named.
    const FILE: &str = "contract.pdf";
    /// The signer's common name.
    const SIGNER: &str = "SURNAME GIVEN 12345678X";
    /// A name carrying a newline, a carriage return and NUL.
    const NAME_WITH_CONTROLS: &str = "SURNAME\nGIVEN\r\0";
    /// The day of the fixture month the revocation answer is good at.
    const CHECKED_DAY: u8 = 15;

    fn valid() -> Facts {
        Facts {
            signed: None,
            verdict: Verdict::Valid,
            intact: true,
            signature: true,
            chained: true,
            revocation: Revocation::Unavailable,
        }
    }

    fn signed(facts: Facts) -> SignatureView {
        SignatureView {
            signer: SIGNER.to_owned(),
            countersigns: None,
            judgement: Judgement::Judged(facts),
        }
    }

    #[test]
    fn a_valid_signature_is_one_record() {
        let checked = Facts {
            revocation: Revocation::Good {
                at: day(CHECKED_DAY),
            },
            ..valid()
        };
        let text = signed(checked).record(FILE).0;
        assert_eq!(
            text,
            format!("file: {FILE}\nsigner: {SIGNER}\nsigned: -\nverdict: valid\n")
        );
    }

    #[test]
    fn every_reason_of_a_not_valid_signature_is_a_line() {
        let facts = Facts {
            verdict: Verdict::NotValid,
            intact: false,
            signature: true,
            chained: false,
            ..valid()
        };
        let text = signed(facts).record(FILE).0;
        assert!(text.contains("verdict: not valid\n"));
        assert!(text.contains("reason: document changed\n"));
        assert!(text.contains("reason: certificate chain unverified\n"));
        assert!(!text.contains("reason: signature invalid\n"));
    }

    #[test]
    fn an_unchecked_revocation_follows_a_valid_verdict() {
        let text = signed(valid()).record(FILE).0;
        assert!(text.ends_with("verdict: valid\nrevocation: not checked\n"));
        let revoked = Facts {
            verdict: Verdict::Revoked,
            ..valid()
        };
        assert!(
            signed(revoked)
                .record(FILE)
                .0
                .ends_with("verdict: revoked\n")
        );
    }

    #[test]
    fn an_unsupported_signature_names_its_reason() {
        let view = SignatureView {
            signer: SIGNER.to_owned(),
            countersigns: None,
            judgement: Judgement::Unsupported,
        };
        let text = view.record(FILE).0;
        assert!(text.contains("signed: -\nverdict: unsupported\nreason: profile not supported\n"));
    }

    #[test]
    fn a_counter_signature_names_the_signer_it_countersigns() {
        let view = SignatureView {
            signer: "Second Signer".to_owned(),
            countersigns: Some(SIGNER.to_owned()),
            judgement: Judgement::Judged(valid()),
        };
        let text = view.record(FILE).0;
        assert!(text.contains(&format!("signer: Second Signer\ncountersigns: {SIGNER}\n")));
    }

    #[test]
    fn control_characters_stay_on_their_line() {
        let view = SignatureView {
            signer: NAME_WITH_CONTROLS.to_owned(),
            countersigns: None,
            judgement: Judgement::Judged(valid()),
        };
        let text = view.record(FILE).0;
        assert!(text.contains("signer: SURNAME\\x0aGIVEN\\x0d\\x00\n"));
        assert_eq!(
            text.lines().count(),
            signed(valid()).record(FILE).0.lines().count()
        );
    }

    #[test]
    fn an_empty_name_is_none() {
        assert_eq!(name_or_none(""), NONE);
        assert_eq!(name_or_none(SIGNER), SIGNER);
    }

    #[test]
    fn a_file_that_is_no_document_is_a_failure() {
        let dir =
            std::env::temp_dir().join(format!("refineid-windows-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("{error}"));
        let file = dir.join("notes.txt");
        std::fs::write(&file, b"synthetic notes").unwrap_or_else(|error| panic!("{error}"));
        let outcome = verify_file(&file, refineid_doc_sign::now_date_time());
        let _removed = std::fs::remove_dir_all(&dir);
        assert!(matches!(
            outcome,
            Err(DocumentVerifyError::Failure {
                failure: DocumentFailure::NotASignedDocument,
                ..
            })
        ));
    }

    #[test]
    fn a_missing_file_is_a_read_error() {
        let missing = std::env::temp_dir().join("refineid-windows-verify-missing.pdf");
        assert!(matches!(
            verify_file(&missing, refineid_doc_sign::now_date_time()),
            Err(DocumentVerifyError::Read { .. })
        ));
    }
}
