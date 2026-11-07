// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Verifying a signed document: judge the file, ask the network about
//! revocation where the file carried no answer, and render the verdict.
//!
//! The verdict comes from `refineid_doc_sign::verification` and the
//! document's own bytes, under the anchors of the EU trusted lists
//! ([`crate::trusted_lists`]). Only the revocation row may go further:
//! a signer on a verified chain the document says nothing about is
//! looked up over OCSP or CRL at `now`, through `WinHTTP`, and a
//! network that does not answer leaves the row as it was. The verdict
//! has three answers, and [`DocumentVerdict`] carries all three to the
//! screen: nothing shows valid unless core's verdict is valid. [`render`]
//! prints one record per signature, `key: value` lines, the everyday
//! view: who signed, when, and whether it holds.

use core::fmt::{self, Display, Write as _};
use std::path::{Path, PathBuf};

use refineid_doc_sign::verification::live::live_revocation;
use refineid_doc_sign::verification::{
    DocumentFailure, DocumentFile, DocumentReport, Indeterminate, SignatureOutcome,
    SignatureReport, SignatureRow, TrustAnchors, Verdict as CoreVerdict,
};
use refineid_doc_sign::x509::DateTime;

use crate::trusted_lists::{AnchorSource, Refresh, user_anchors};

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

/// The verdict on a whole document, as a screen shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentVerdict {
    /// Every signature is established: chain, revocation and content.
    Valid,
    /// Nothing is proven wrong, but something the verdict needs could
    /// not be established.
    Indeterminate,
    /// Something is proven wrong.
    NotValid,
}

impl DocumentVerdict {
    /// The verdict of `report`.
    #[must_use]
    pub fn of(report: &DocumentReport) -> Self {
        match report.verdict() {
            CoreVerdict::Valid => Self::Valid,
            CoreVerdict::Indeterminate(_) => Self::Indeterminate,
            CoreVerdict::NotValid => Self::NotValid,
        }
    }

    /// The name the settings bridge reports to the `WinUI` app.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Indeterminate => "indeterminate",
            Self::NotValid => "not_valid",
        }
    }
}

/// A judged document and where its anchors came from.
#[derive(Debug)]
pub struct VerifiedDocument {
    /// The report.
    pub report: DocumentReport,
    /// Where the trusted lists stood.
    pub lists: AnchorSource,
}

/// Judge the document at `path` as of `now`, under the anchors of the
/// user's trusted lists, fetched first when they are due.
///
/// # Errors
/// [`DocumentVerifyError`] when the file cannot be read or carries
/// nothing to judge. A negative verdict is not an error.
pub fn verify_file(path: &Path, now: DateTime) -> Result<VerifiedDocument, DocumentVerifyError> {
    let run = user_anchors(now, Refresh::WhenDue);
    let report = verify_file_under(path, &run.anchors, now)?;
    Ok(VerifiedDocument {
        report,
        lists: run.source,
    })
}

/// Judge the document at `path` as of `now` under `anchors`.
///
/// Every signature is verified from the file alone, anchored on
/// `anchors`, at the earliest time a timestamp proves, else at `now`.
/// A signer on a verified chain whose revocation the file does not
/// answer is then asked about over the network; the answer is judged at
/// `now`, and no answer leaves the row unavailable.
///
/// # Errors
/// [`DocumentVerifyError`] when the file cannot be read or carries
/// nothing to judge. A negative verdict is not an error.
pub fn verify_file_under(
    path: &Path,
    anchors: &TrustAnchors,
    now: DateTime,
) -> Result<DocumentReport, DocumentVerifyError> {
    let outcome = verify_file_unreported(path, anchors, now);
    if let Err(error) = &outcome {
        refineid_dev_errors::report!(DocumentSigning, "document not verified", error);
    }
    outcome
}

/// [`verify_file_under`], unreported.
fn verify_file_unreported(
    path: &Path,
    anchors: &TrustAnchors,
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
    let report = refineid_doc_sign::verification::verify(&file, anchors, now).map_err(failure)?;
    crate::http::install();
    Ok(report.with_live_revocation(|signature| live_revocation(signature, anchors, now)))
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
    /// One cause of a verdict other than valid.
    Reason,
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
        }
    }
}

/// The verdict on one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Everything the verdict needs was established.
    Valid,
    /// Nothing is proven wrong, but something could not be established.
    Indeterminate,
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
            Self::Indeterminate => "indeterminate",
            Self::NotValid => "not valid",
            Self::Revoked => "revoked",
            Self::Unsupported => "unsupported",
        }
    }
}

/// One cause of a verdict other than valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// The signed content no longer matches.
    DocumentChanged,
    /// The signature does not verify.
    SignatureInvalid,
    /// The signer does not chain to a trust anchor.
    ChainUnverified,
    /// The search for the signer's chain spent its whole budget of
    /// signature verifications (`SignatureReport::chain_search_exhausted`).
    ChainSearchExhausted,
    /// No verified revocation answer speaks for the signer.
    RevocationUnknown,
    /// The signature's profile is not implemented.
    ProfileNotSupported,
    /// No trusted list was at hand, so nothing anchors a chain.
    NoTrustedLists,
}

impl Reason {
    /// The reason as printed.
    const fn as_str(self) -> &'static str {
        match self {
            Self::DocumentChanged => "document changed",
            Self::SignatureInvalid => "signature invalid",
            Self::ChainUnverified => "certificate chain unverified",
            Self::ChainSearchExhausted => {
                "certificate chain search exhausted: too many issuers in the document"
            }
            Self::RevocationUnknown => "revocation unknown",
            Self::ProfileNotSupported => "profile not supported",
            Self::NoTrustedLists => "trusted lists not fetched: nothing can be anchored",
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
    /// Every cause of a verdict other than valid or revoked, in check
    /// order.
    reasons: Vec<Reason>,
}

/// Every cause `signature` falls short of valid, in check order: what
/// is proven wrong, then what the verdict could not establish.
fn reasons(signature: &SignatureReport, lists: &AnchorSource) -> Vec<Reason> {
    let mut reasons: Vec<Reason> = [
        (signature.document_intact(), Reason::DocumentChanged),
        (signature.signature_valid(), Reason::SignatureInvalid),
    ]
    .into_iter()
    .filter_map(|(holds, reason)| (!holds).then_some(reason))
    .collect();
    if let CoreVerdict::Indeterminate(what) = signature.verdict() {
        reasons.push(match (what, lists) {
            (Indeterminate::NoCertificateChain, AnchorSource::Unavailable(_)) => {
                Reason::NoTrustedLists
            }
            (Indeterminate::NoCertificateChain, AnchorSource::Lists { .. }) => {
                Reason::ChainUnverified
            }
            (Indeterminate::ChainSearchExhausted, _) => Reason::ChainSearchExhausted,
            (Indeterminate::RevocationUnknown, _) => Reason::RevocationUnknown,
        });
    } else if !signature.chain_verified() {
        reasons.push(if signature.chain_search_exhausted() {
            Reason::ChainSearchExhausted
        } else {
            Reason::ChainUnverified
        });
    }
    reasons
}

/// The report of `file`, one record per signature in document order,
/// records separated by a blank line, lines ending in `\n`.
#[must_use]
pub fn render(file: &str, document: &VerifiedDocument) -> String {
    let rows = document.report.rows();
    let records: Vec<String> = rows
        .iter()
        .map(|row| view(rows, row, &document.lists).record(file).0)
        .collect();
    records.join(RECORD_SEPARATOR)
}

/// The view of `row`, one of `rows`, judged under anchors from `lists`.
fn view(rows: &[SignatureRow], row: &SignatureRow, lists: &AnchorSource) -> SignatureView {
    let countersigns = row.counter_signs().map(|index| {
        rows.get(index)
            .and_then(SignatureRow::signer)
            .map_or_else(|| NONE.to_owned(), |signer| name_or_none(signer.name()))
    });
    let signer = row
        .signer()
        .map_or_else(|| NONE.to_owned(), |signer| name_or_none(signer.name()));
    let judgement = match row.outcome() {
        SignatureOutcome::Judged(report) => Judgement::Judged(facts(report, lists)),
        SignatureOutcome::Unsupported { .. } => Judgement::Unsupported,
    };
    SignatureView {
        signer,
        countersigns,
        judgement,
    }
}

/// The facts of a judged signature.
fn facts(report: &SignatureReport, lists: &AnchorSource) -> Facts {
    let verdict = verdict(report);
    Facts {
        signed: report.proof_of_existence(),
        verdict,
        reasons: if verdict == Verdict::Revoked {
            Vec::new()
        } else {
            reasons(report, lists)
        },
    }
}

/// The verdict the facts reach: core's, with a revocation named as such.
fn verdict(signature: &SignatureReport) -> Verdict {
    if signature
        .revocation()
        .revoked_before(signature.proof_of_existence())
    {
        return Verdict::Revoked;
    }
    match signature.verdict() {
        CoreVerdict::Valid => Verdict::Valid,
        CoreVerdict::Indeterminate(_) => Verdict::Indeterminate,
        CoreVerdict::NotValid => Verdict::NotValid,
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
        for reason in &facts.reasons {
            record.line(Key::Reason, reason.as_str());
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

    /// The file as named.
    const FILE: &str = "contract.pdf";
    /// The signer's common name.
    const SIGNER: &str = "SURNAME GIVEN 12345678X";
    /// A name carrying a newline, a carriage return and NUL.
    const NAME_WITH_CONTROLS: &str = "SURNAME\nGIVEN\r\0";

    fn facts(verdict: Verdict, reasons: Vec<Reason>) -> Facts {
        Facts {
            signed: None,
            verdict,
            reasons,
        }
    }

    fn valid() -> Facts {
        facts(Verdict::Valid, Vec::new())
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
        let text = signed(valid()).record(FILE).0;
        assert_eq!(
            text,
            format!("file: {FILE}\nsigner: {SIGNER}\nsigned: -\nverdict: valid\n")
        );
    }

    #[test]
    fn every_reason_of_a_not_valid_signature_is_a_line() {
        let text = signed(facts(
            Verdict::NotValid,
            vec![Reason::DocumentChanged, Reason::ChainUnverified],
        ))
        .record(FILE)
        .0;
        assert!(text.contains("verdict: not valid\n"));
        assert!(text.contains("reason: document changed\n"));
        assert!(text.contains("reason: certificate chain unverified\n"));
        assert!(!text.contains("reason: signature invalid\n"));
    }

    #[test]
    fn an_indeterminate_signature_never_prints_valid_and_says_why() {
        for (reason, line) in [
            (
                Reason::ChainUnverified,
                "reason: certificate chain unverified\n",
            ),
            (
                Reason::ChainSearchExhausted,
                "reason: certificate chain search exhausted: too many issuers in the document\n",
            ),
            (Reason::RevocationUnknown, "reason: revocation unknown\n"),
            (
                Reason::NoTrustedLists,
                "reason: trusted lists not fetched: nothing can be anchored\n",
            ),
        ] {
            let text = signed(facts(Verdict::Indeterminate, vec![reason]))
                .record(FILE)
                .0;
            assert!(text.contains("verdict: indeterminate\n"));
            assert!(!text.contains("verdict: valid"));
            assert!(text.contains(line));
        }
    }

    #[test]
    fn a_revoked_signature_names_no_other_cause() {
        let text = signed(facts(Verdict::Revoked, Vec::new())).record(FILE).0;
        assert!(text.ends_with("verdict: revoked\n"));
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
        let outcome = verify_file_under(
            &file,
            &TrustAnchors::default(),
            refineid_doc_sign::now_date_time(),
        );
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
            verify_file_under(
                &missing,
                &TrustAnchors::default(),
                refineid_doc_sign::now_date_time()
            ),
            Err(DocumentVerifyError::Read { .. })
        ));
    }
}
