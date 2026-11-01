// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Document signing with the paired phone's card over RAPP.
//!
//! The phone shows the document names and takes PIN 2 on its own
//! screen; this computer sends digests and receives signatures, and
//! never asks for, holds or sends a PIN. `refineid_doc_sign::remote`
//! builds, checks and finishes the documents; this module carries its
//! two calls over the paired phone's session: `read_certificate` with
//! kind `signature`, then `sign_document` for one document or
//! `batch_sign_documents` for several (RAPP v26.10.29 section 9.3). The
//! session is this computer's own requester over the stream transport,
//! dialled from the DNS-SD session record the phone advertises.
//!
//! A card in a reader attached to this computer outranks the phone:
//! [`choose_source`] picks the phone only when no reader holds a card.

use core::fmt;
use std::time::Duration;

use refineid_doc_sign::remote::{
    PhoneDocumentOutcome, PhoneRefusal, PhoneSignOptions, PhoneSigningBatch, RemoteSigner,
    UnvalidatedPhoneCertificate, UnvalidatedPhoneSignature, sign_on_phone,
};
use refineid_doc_sign::service::SignErrorKind;
use refineid_pcsc::{PcscBackend, ReaderBackend as _};
use refineid_rapp_core::engine::{
    AdmissionError, OperationOutcome, Requester, RequesterConfig, Session, SessionError,
};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::{CloseReason, ResultError};
use refineid_rapp_core::operations::{
    CardKeyProfile, CardOperation, CardOperationResult, CertificateKind, SignatureAlgorithm,
};
use refineid_rapp_core::profiles::ProfileName;
use refineid_rapp_core::store::{PairingRecord, PairingStore as _};
use refineid_rapp_core::stream::{StreamError, dial_session};
use refineid_rapp_core::transport::TcpFrameTransport;
use refineid_remote::{RemoteKeyProfile, RemoteSignatureAlgorithm};
use refineid_windows_credential_store::{CredentialStoreError, ProtectedPairingStore};

/// One DNS-SD browse for the phone's session service, as the `WinUI`
/// bridge browses before a card read.
const SESSION_BROWSE_WINDOW: Duration = Duration::from_millis(3_000);

/// The lifetime of a signing operation: the holder's consent and PIN 2
/// entry on the phone (RAPP v26.10.29 section 8.1), as the `WinUI` bridge
/// bounds its card reads.
const SIGNING_OPERATION_LIFETIME_MS: u64 = 300_000;

/// Where a signing runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningSource {
    /// A card in a reader attached to this computer, or no source at
    /// all: the reader path reports what is missing.
    Reader,
    /// The card on the paired phone.
    Phone(PairId),
}

/// Whether `record` is a pairing that signs documents: it serves and is
/// granted the document-signing profile.
#[must_use]
pub fn signs_documents(record: &PairingRecord) -> bool {
    record.serves()
        && record
            .granted_profiles()
            .contains(&ProfileName::DocumentSigning)
}

/// The source for a signing: a reader while any reader holds a card,
/// else the phone of `signing_phone`, a pairing that
/// [`signs_documents`], else the reader path.
#[must_use]
pub const fn choose_source(card_in_reader: bool, signing_phone: Option<PairId>) -> SigningSource {
    match (card_in_reader, signing_phone) {
        (false, Some(pair_id)) => SigningSource::Phone(pair_id),
        (true, _) | (false, None) => SigningSource::Reader,
    }
}

/// Whether any reader attached to this computer holds a card. A reader
/// service that cannot be reached holds none.
#[must_use]
pub fn card_in_a_reader() -> bool {
    PcscBackend
        .enumerate()
        .is_ok_and(|readers| readers.iter().any(|reader| reader.card_present))
}

/// The paired phone that signs documents, as the pairing store records
/// it.
#[must_use]
pub fn signing_phone() -> Option<PairId> {
    ProtectedPairingStore::load()
        .ok()?
        .usable_pairing()
        .filter(|record| signs_documents(record))
        .map(PairingRecord::pair_id)
}

/// The source for a signing on this computer now, by [`choose_source`].
#[must_use]
pub fn current_source() -> SigningSource {
    choose_source(card_in_a_reader(), signing_phone())
}

/// Why the paired phone's session gave no result.
#[derive(Debug)]
pub enum PhoneLinkError {
    /// The pairing store could not be opened.
    Store(CredentialStoreError),
    /// The store holds no serving record for the pairing.
    NotPaired,
    /// No session connection could be dialled.
    Dial(StreamError),
    /// The session did not open, or ended.
    Session(SessionError),
    /// The operation was not admitted.
    Admission(AdmissionError),
    /// The operation ended without a completed result.
    Ended(Box<OperationOutcome>),
}

impl fmt::Display for PhoneLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "pairing store: {error}"),
            Self::NotPaired => f.write_str("no phone is paired with this computer"),
            Self::Dial(error) => write!(f, "{error}"),
            Self::Session(error) => write!(f, "{error}"),
            Self::Admission(error) => write!(f, "{error}"),
            Self::Ended(outcome) => write!(f, "operation ended: {outcome:?}"),
        }
    }
}

impl core::error::Error for PhoneLinkError {}

/// One RAPP operation against the paired phone.
pub trait PhoneLink {
    /// Run `operation` and return the phone's result.
    ///
    /// # Errors
    /// [`PhoneLinkError`] when no result arrives.
    fn run(&mut self, operation: &CardOperation) -> Result<CardOperationResult, PhoneLinkError>;
}

/// The paired phone over its session: opened on the first operation,
/// held for the next, closed on drop.
pub struct PairedPhoneLink {
    /// The requester over this computer's pairing store.
    requester: Requester<ProtectedPairingStore>,
    /// The pairing the session serves.
    pair_id: PairId,
    /// The session, once opened.
    session: Option<Session<TcpFrameTransport>>,
}

impl fmt::Debug for PairedPhoneLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairedPhoneLink")
            .field("pair_id", &self.pair_id)
            .field("session_open", &self.session.is_some())
            .finish_non_exhaustive()
    }
}

impl PairedPhoneLink {
    /// The link to the phone of `pair_id`.
    ///
    /// # Errors
    /// [`PhoneLinkError::Store`] when the pairing store cannot be opened.
    pub fn open(pair_id: PairId) -> Result<Self, PhoneLinkError> {
        let store = ProtectedPairingStore::load().map_err(PhoneLinkError::Store)?;
        Ok(Self {
            requester: Requester::new(
                RequesterConfig {
                    // A paired requester introduces itself at pairing
                    // only; a session carries no name.
                    display_name: String::new(),
                    platform: "Windows".to_owned(),
                },
                store,
            ),
            pair_id,
            session: None,
        })
    }

    /// The session, dialled and opened on first use.
    fn session(&mut self) -> Result<&mut Session<TcpFrameTransport>, PhoneLinkError> {
        if self.session.is_none() {
            let keys = self
                .requester
                .store()
                .get(self.pair_id)
                .ok()
                .and_then(PairingRecord::pair_record)
                .ok_or(PhoneLinkError::NotPaired)?;
            let transport = dial_session(keys, &[], &[], SESSION_BROWSE_WINDOW)
                .map_err(PhoneLinkError::Dial)?;
            let session = self
                .requester
                .connect(self.pair_id, transport)
                .map_err(PhoneLinkError::Session)?;
            self.session = Some(session);
        }
        self.session
            .as_mut()
            .ok_or(PhoneLinkError::Session(SessionError::EngineFault))
    }
}

impl PhoneLink for PairedPhoneLink {
    fn run(&mut self, operation: &CardOperation) -> Result<CardOperationResult, PhoneLinkError> {
        self.session()?;
        let Some(session) = self.session.as_mut() else {
            return Err(PhoneLinkError::Session(SessionError::EngineFault));
        };
        match self
            .requester
            .execute(session, operation, SIGNING_OPERATION_LIFETIME_MS)
            .map_err(PhoneLinkError::Admission)?
        {
            OperationOutcome::Completed(result) => Ok(result),
            ended => Err(PhoneLinkError::Ended(Box::new(ended))),
        }
    }
}

impl Drop for PairedPhoneLink {
    fn drop(&mut self) {
        if let Some(mut session) = self.session.take() {
            self.requester
                .disconnect(&mut session, CloseReason::UserDisconnect);
        }
    }
}

/// [`RemoteSigner`] over a [`PhoneLink`], keeping the link's own
/// account of a refusal for the message.
#[derive(Debug)]
pub struct PhoneSigner<Link> {
    /// The phone.
    link: Link,
    /// Why the last operation ended without a result.
    cause: Option<PhoneLinkError>,
}

impl<Link: PhoneLink> PhoneSigner<Link> {
    /// A signer over `link`.
    pub const fn new(link: Link) -> Self {
        Self { link, cause: None }
    }

    /// Run `operation`; a failure is kept as the cause and answered as
    /// its refusal.
    fn run(&mut self, operation: &CardOperation) -> Result<CardOperationResult, PhoneRefusal> {
        self.link.run(operation).map_err(|error| {
            let refusal = refusal_of(&error);
            self.cause = Some(error);
            refusal
        })
    }
}

impl<Link: PhoneLink> RemoteSigner for PhoneSigner<Link> {
    fn signature_certificate(&mut self) -> Result<UnvalidatedPhoneCertificate, PhoneRefusal> {
        match self.run(&CardOperation::ReadCertificate {
            kind: CertificateKind::Signature,
        })? {
            CardOperationResult::Certificate(der) => Ok(UnvalidatedPhoneCertificate::from_der(der)),
            CardOperationResult::Inspection(_)
            | CardOperationResult::Identity(_)
            | CardOperationResult::Signature(_)
            | CardOperationResult::Signatures(_) => Err(PhoneRefusal::PhoneFailed),
        }
    }

    fn sign(
        &mut self,
        batch: &PhoneSigningBatch,
    ) -> Result<Vec<UnvalidatedPhoneSignature>, PhoneRefusal> {
        let several = batch.documents().len() > 1;
        match (several, self.run(&operation_for(batch))?) {
            (false, CardOperationResult::Signature(signature)) => {
                Ok(vec![UnvalidatedPhoneSignature::from_bytes(signature)])
            }
            (true, CardOperationResult::Signatures(signatures)) => Ok(signatures
                .into_iter()
                .map(UnvalidatedPhoneSignature::from_bytes)
                .collect()),
            (
                _,
                CardOperationResult::Inspection(_)
                | CardOperationResult::Identity(_)
                | CardOperationResult::Certificate(_)
                | CardOperationResult::Signature(_)
                | CardOperationResult::Signatures(_),
            ) => Err(PhoneRefusal::PhoneFailed),
        }
    }
}

/// The RAPP operation that signs `batch`: `sign_document` for one
/// document, `batch_sign_documents` for several, with the batch's key
/// profile, algorithm, names and digests unchanged and in order.
fn operation_for(batch: &PhoneSigningBatch) -> CardOperation {
    let key_profile = key_profile(batch.key_profile());
    let algorithm = algorithm(batch.algorithm());
    match batch.documents() {
        [document] => CardOperation::SignDocument {
            document_name: document.name().as_str().to_owned(),
            key_profile,
            algorithm,
            digest: document.digest().to_vec(),
        },
        documents => CardOperation::BatchSignDocuments {
            document_names: documents
                .iter()
                .map(|document| document.name().as_str().to_owned())
                .collect(),
            key_profile,
            algorithm,
            digests: documents
                .iter()
                .map(|document| document.digest().to_vec())
                .collect(),
        },
    }
}

/// The wire's key profile for the batch's.
const fn key_profile(profile: RemoteKeyProfile) -> CardKeyProfile {
    match profile {
        RemoteKeyProfile::EcdsaP256 => CardKeyProfile::EcdsaP256,
        RemoteKeyProfile::EcdsaP384 => CardKeyProfile::EcdsaP384,
        RemoteKeyProfile::Rsa2048 => CardKeyProfile::Rsa2048,
        RemoteKeyProfile::Rsa3072 => CardKeyProfile::Rsa3072,
    }
}

/// The wire's signature algorithm for the batch's.
const fn algorithm(algorithm: RemoteSignatureAlgorithm) -> SignatureAlgorithm {
    match algorithm {
        RemoteSignatureAlgorithm::EcdsaSha224 => SignatureAlgorithm::EcdsaSha224,
        RemoteSignatureAlgorithm::EcdsaSha256 => SignatureAlgorithm::EcdsaSha256,
        RemoteSignatureAlgorithm::EcdsaSha384 => SignatureAlgorithm::EcdsaSha384,
        RemoteSignatureAlgorithm::EcdsaSha512 => SignatureAlgorithm::EcdsaSha512,
        RemoteSignatureAlgorithm::RsaPkcs1Sha256 => SignatureAlgorithm::RsaPkcs1Sha256,
        RemoteSignatureAlgorithm::RsaPkcs1Sha384 => SignatureAlgorithm::RsaPkcs1Sha384,
        RemoteSignatureAlgorithm::RsaPkcs1Sha512 => SignatureAlgorithm::RsaPkcs1Sha512,
        RemoteSignatureAlgorithm::RsaPssSha256 => SignatureAlgorithm::RsaPssSha256,
    }
}

/// The refusal a link failure stands for.
#[must_use]
pub fn refusal_of(error: &PhoneLinkError) -> PhoneRefusal {
    match error {
        PhoneLinkError::Ended(outcome) => match outcome.as_ref() {
            OperationOutcome::Rejected(result) | OperationOutcome::Cancelled(result) => {
                refusal_of_result(*result)
            }
            OperationOutcome::Lost => PhoneRefusal::Unreachable,
            OperationOutcome::Refused(_) | OperationOutcome::Completed(_) => {
                PhoneRefusal::PhoneFailed
            }
        },
        PhoneLinkError::Admission(AdmissionError::ProfileNotGranted) => PhoneRefusal::NotGranted,
        PhoneLinkError::Admission(_) => PhoneRefusal::PhoneFailed,
        PhoneLinkError::Store(_)
        | PhoneLinkError::NotPaired
        | PhoneLinkError::Dial(_)
        | PhoneLinkError::Session(_) => PhoneRefusal::Unreachable,
    }
}

/// The refusal a RAPP section 10.3 error stands for.
const fn refusal_of_result(error: ResultError) -> PhoneRefusal {
    match error {
        ResultError::UserCancelled => PhoneRefusal::Declined,
        ResultError::OperationExpired => PhoneRefusal::Expired,
        ResultError::CardError => PhoneRefusal::CardUnavailable,
        ResultError::RetryFloor => PhoneRefusal::RetryFloor,
        ResultError::Unauthorized => PhoneRefusal::NotGranted,
        ResultError::UnsupportedParameter => PhoneRefusal::Unsupported,
        ResultError::OperationFailed
        | ResultError::Busy
        | ResultError::DuplicateOperation
        | ResultError::InvalidLifetime => PhoneRefusal::PhoneFailed,
    }
}

/// A signing on the phone that wrote nothing, with the link's account
/// of why the phone gave no answer, when it gave none.
#[derive(Debug)]
pub struct PhoneSignFailure {
    /// What the signing flow refused.
    pub kind: SignErrorKind,
    /// The link's failure behind a refusal.
    pub cause: Option<PhoneLinkError>,
}

impl fmt::Display for PhoneSignFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SignErrorKind::Phone(refusal) => match self.cause.as_ref() {
                Some(PhoneLinkError::Session(error)) if pairing_tells(*error) => {
                    write!(f, "{error}")
                }
                Some(PhoneLinkError::NotPaired) => {
                    f.write_str("no phone is paired with this computer")
                }
                Some(PhoneLinkError::Session(_)) => {
                    f.write_str("the connection to the paired phone was lost")
                }
                Some(_) | None => f.write_str(refusal_text(*refusal)),
            },
            SignErrorKind::PhoneCertificate(_) => {
                f.write_str("the certificate on the phone's card cannot be used for signing")
            }
            SignErrorKind::PhoneSignatureCount { .. } => {
                f.write_str(refusal_text(PhoneRefusal::PhoneFailed))
            }
            SignErrorKind::PhoneSignatureInvalid { .. } => f.write_str(
                "the signature from the phone did not match the card's certificate; \
                 nothing was written",
            ),
            kind => write!(f, "{kind}"),
        }
    }
}

impl core::error::Error for PhoneSignFailure {}

/// Whether the session error's own text says best why the phone gave no
/// answer: what became of the pairing.
const fn pairing_tells(error: SessionError) -> bool {
    matches!(
        error,
        SessionError::UnknownPairing
            | SessionError::NotPaired
            | SessionError::Forgotten
            | SessionError::StorageUnconfirmed
            | SessionError::ClosedByPeer(_)
            | SessionError::Withdrawn
    )
}

/// What the user is told for a refusal.
const fn refusal_text(refusal: PhoneRefusal) -> &'static str {
    match refusal {
        PhoneRefusal::Declined => "the signature request was declined on the paired phone",
        PhoneRefusal::Expired => "the request was not approved on the phone in time",
        PhoneRefusal::CardUnavailable => "the card's answer was lost; nothing was written",
        PhoneRefusal::RetryFloor => "RefineID does not use either of the last two PIN 2 attempts",
        PhoneRefusal::NotGranted | PhoneRefusal::Unsupported => {
            "the phone cannot make this kind of signature"
        }
        PhoneRefusal::PhoneFailed => "the phone did not return a signature; nothing was written",
        PhoneRefusal::Unreachable => "the paired phone did not respond",
    }
}

/// Sign `documents` with the card on the phone of `pair_id`: one
/// certificate read, then every document in one request, so the holder
/// enters PIN 2 once, on the phone.
///
/// # Errors
/// [`PhoneSignFailure`] when nothing was written; once the phone's
/// signatures verified, each document's own outcome is at its position.
pub fn sign(
    pair_id: PairId,
    documents: Vec<PhoneSignOptions>,
) -> Result<Vec<PhoneDocumentOutcome>, PhoneSignFailure> {
    crate::http::install();
    let link = PairedPhoneLink::open(pair_id).map_err(|error| PhoneSignFailure {
        kind: SignErrorKind::Phone(refusal_of(&error)),
        cause: Some(error),
    })?;
    sign_over(link, documents)
}

/// [`sign`] over any link.
fn sign_over<Link: PhoneLink>(
    link: Link,
    documents: Vec<PhoneSignOptions>,
) -> Result<Vec<PhoneDocumentOutcome>, PhoneSignFailure> {
    let mut signer = PhoneSigner::new(link);
    sign_on_phone(&mut signer, documents).map_err(|kind| PhoneSignFailure {
        kind,
        cause: signer.cause.take(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use refineid_doc_sign::cades::SigningTime;
    use refineid_doc_sign::document::Format;
    use refineid_doc_sign::pades::SignatureMetadata;
    use refineid_doc_sign::service::{DocumentRequest, SignOutput, SigningDevice};
    use refineid_doc_sign::testkit::{
        CertificateSpec, KEY_USAGE_NON_REPUDIATION, KEY_USAGE_NON_REPUDIATION_UNUSED, TestCurve,
        TestKey, certificate, day, key_usage, minimal_pdf,
    };

    use super::*;

    /// First day of the fixture certificate's validity.
    const NOT_BEFORE: u8 = 1;
    /// Last day of the fixture certificate's validity.
    const NOT_AFTER: u8 = 28;
    /// Serial of the phone's signature certificate.
    const SIGNER_SERIAL: u8 = 7;
    /// The claimed signing time, inside the fixture validity.
    const SIGNING_TIME: SigningTime = SigningTime {
        year: 2026,
        month: 6,
        day: 15,
        hour: 12,
        minute: 0,
        second: 0,
    };
    /// A synthetic pairing.
    const PAIR: PairId = PairId::from_array(*b"synthetic pair 1");

    /// A directory of fixture files, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "refineid-windows-phone-{name}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap_or_else(|error| panic!("{error}"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).unwrap_or_else(|error| panic!("{error}"));
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _removed = std::fs::remove_dir_all(&self.0);
        }
    }

    /// What the scripted phone answers to a signing request.
    enum Answer {
        /// Signs every digest.
        Sign,
        /// Fails the operation as the link reports it.
        Fail(fn() -> PhoneLinkError),
    }

    /// A paired phone whose card holds a P-384 key, answering
    /// `read_certificate` with its certificate and a signing request as
    /// `answer` says. Records every operation it was asked.
    struct ScriptedPhone {
        key: TestKey,
        certificate: Vec<u8>,
        answer: Answer,
        seen: Vec<CardOperation>,
    }

    impl ScriptedPhone {
        fn new(answer: Answer) -> Self {
            let key = TestKey::derive(TestCurve::P384, b"phone-signature");
            let issuer = TestKey::derive(TestCurve::P384, b"phone-signature-issuer");
            let spec = CertificateSpec {
                serial: SIGNER_SERIAL,
                subject: "Test Holder",
                issuer: "Test Signature CA",
                not_before: day(NOT_BEFORE),
                not_after: day(NOT_AFTER),
                extensions: vec![key_usage(
                    KEY_USAGE_NON_REPUDIATION_UNUSED,
                    KEY_USAGE_NON_REPUDIATION,
                )],
            };
            let certificate = certificate(&spec, &key, &issuer);
            Self {
                key,
                certificate,
                answer,
                seen: Vec::new(),
            }
        }
    }

    impl PhoneLink for &mut ScriptedPhone {
        fn run(
            &mut self,
            operation: &CardOperation,
        ) -> Result<CardOperationResult, PhoneLinkError> {
            self.seen.push(operation.clone());
            match (operation, &self.answer) {
                (CardOperation::ReadCertificate { .. }, _) => {
                    Ok(CardOperationResult::Certificate(self.certificate.clone()))
                }
                (_, Answer::Fail(error)) => Err(error()),
                (CardOperation::SignDocument { digest, .. }, Answer::Sign) => Ok(
                    CardOperationResult::Signature(self.key.sign_digest_raw(digest)),
                ),
                (CardOperation::BatchSignDocuments { digests, .. }, Answer::Sign) => {
                    Ok(CardOperationResult::Signatures(
                        digests
                            .iter()
                            .map(|digest| self.key.sign_digest_raw(digest))
                            .collect(),
                    ))
                }
                (_, Answer::Sign) => Err(PhoneLinkError::Ended(Box::new(
                    OperationOutcome::Refused(ResultError::OperationFailed),
                ))),
            }
        }
    }

    /// A level-B request: no authority is reached.
    fn request(format: Format) -> DocumentRequest {
        DocumentRequest {
            format,
            additional_inputs: Vec::new(),
            signing_time: SIGNING_TIME,
            metadata: SignatureMetadata::default(),
            archive: false,
            long_term: false,
            timestamp_authorities: Vec::new(),
            timestamp_credentials: None,
        }
    }

    /// One PDF named `name` in `dir`.
    fn pdf(dir: &TempDir, name: &str) -> PhoneSignOptions {
        PhoneSignOptions {
            input: dir.write(name, &minimal_pdf()),
            output: SignOutput::At(dir.path().join(format!("signed-{name}"))),
            document: request(Format::Pades),
        }
    }

    /// Where `documents` are written.
    fn outputs(documents: &[PhoneSignOptions]) -> Vec<PathBuf> {
        documents
            .iter()
            .map(|document| document.output.path(None))
            .collect()
    }

    fn rejected(error: ResultError) -> PhoneLinkError {
        PhoneLinkError::Ended(Box::new(OperationOutcome::Rejected(error)))
    }

    #[test]
    fn one_document_is_one_sign_document_after_the_certificate() {
        let dir = TempDir::new("one");
        let documents = vec![pdf(&dir, "report.pdf")];
        let written = outputs(&documents);
        let mut phone = ScriptedPhone::new(Answer::Sign);
        let outcomes =
            sign_over(&mut phone, documents).unwrap_or_else(|failure| panic!("{failure}"));
        assert_eq!(outcomes.len(), 1);
        let Some(Ok(report)) = outcomes.first() else {
            panic!("the document was not signed");
        };
        assert_eq!(report.device, SigningDevice::PairedPhone);
        assert!(written.iter().all(|path| path.exists()));
        assert_eq!(phone.seen.len(), 2);
        assert!(matches!(
            phone.seen.first(),
            Some(CardOperation::ReadCertificate {
                kind: CertificateKind::Signature
            })
        ));
        assert!(matches!(
            phone.seen.get(1),
            Some(CardOperation::SignDocument {
                document_name,
                key_profile: CardKeyProfile::EcdsaP384,
                algorithm: SignatureAlgorithm::EcdsaSha384,
                ..
            }) if document_name == "report.pdf"
        ));
    }

    #[test]
    fn several_documents_are_one_batch() {
        let dir = TempDir::new("batch");
        let names = ["first.pdf", "second.pdf", "third.pdf"];
        let documents: Vec<PhoneSignOptions> = names.iter().map(|name| pdf(&dir, name)).collect();
        let written = outputs(&documents);
        let mut phone = ScriptedPhone::new(Answer::Sign);
        let outcomes =
            sign_over(&mut phone, documents).unwrap_or_else(|failure| panic!("{failure}"));
        assert!(outcomes.iter().all(Result::is_ok));
        assert!(written.iter().all(|path| path.exists()));
        assert_eq!(phone.seen.len(), 2);
        let Some(CardOperation::BatchSignDocuments {
            document_names,
            digests,
            ..
        }) = phone.seen.get(1)
        else {
            panic!("no batch_sign_documents");
        };
        assert_eq!(*document_names, names.map(str::to_owned).to_vec());
        assert_eq!(digests.len(), names.len());
    }

    #[test]
    fn a_refused_signing_writes_nothing_and_keeps_its_cause() {
        let dir = TempDir::new("refused");
        let documents = vec![pdf(&dir, "report.pdf")];
        let written = outputs(&documents);
        let mut phone = ScriptedPhone::new(Answer::Fail(|| rejected(ResultError::UserCancelled)));
        let Err(failure) = sign_over(&mut phone, documents) else {
            panic!("a declined signing succeeded");
        };
        assert!(matches!(
            failure.kind,
            SignErrorKind::Phone(PhoneRefusal::Declined)
        ));
        assert_eq!(
            failure.to_string(),
            "the signature request was declined on the paired phone"
        );
        assert!(!written.iter().any(|path| path.exists()));
    }

    #[test]
    fn a_revoked_pairing_says_so_in_the_sessions_words() {
        let dir = TempDir::new("revoked");
        let documents = vec![pdf(&dir, "report.pdf")];
        let mut phone = ScriptedPhone::new(Answer::Fail(|| {
            PhoneLinkError::Session(SessionError::NotPaired)
        }));
        let Err(failure) = sign_over(&mut phone, documents) else {
            panic!("signed over a revoked pairing");
        };
        assert_eq!(failure.to_string(), SessionError::NotPaired.to_string());
    }

    #[test]
    fn each_phone_error_is_its_refusal() {
        let cancelled = |error| PhoneLinkError::Ended(Box::new(OperationOutcome::Cancelled(error)));
        for (error, refusal) in [
            (rejected(ResultError::UserCancelled), PhoneRefusal::Declined),
            (
                cancelled(ResultError::UserCancelled),
                PhoneRefusal::Declined,
            ),
            (
                rejected(ResultError::OperationExpired),
                PhoneRefusal::Expired,
            ),
            (
                rejected(ResultError::CardError),
                PhoneRefusal::CardUnavailable,
            ),
            (rejected(ResultError::RetryFloor), PhoneRefusal::RetryFloor),
            (
                rejected(ResultError::Unauthorized),
                PhoneRefusal::NotGranted,
            ),
            (
                rejected(ResultError::UnsupportedParameter),
                PhoneRefusal::Unsupported,
            ),
            (
                rejected(ResultError::OperationFailed),
                PhoneRefusal::PhoneFailed,
            ),
            (
                PhoneLinkError::Ended(Box::new(OperationOutcome::Refused(ResultError::Busy))),
                PhoneRefusal::PhoneFailed,
            ),
            (
                PhoneLinkError::Ended(Box::new(OperationOutcome::Lost)),
                PhoneRefusal::Unreachable,
            ),
            (
                PhoneLinkError::Admission(AdmissionError::ProfileNotGranted),
                PhoneRefusal::NotGranted,
            ),
            (
                PhoneLinkError::Admission(AdmissionError::OperationActive),
                PhoneRefusal::PhoneFailed,
            ),
            (PhoneLinkError::NotPaired, PhoneRefusal::Unreachable),
            (
                PhoneLinkError::Dial(StreamError::Unreachable),
                PhoneRefusal::Unreachable,
            ),
            (
                PhoneLinkError::Session(SessionError::HandshakeFailed),
                PhoneRefusal::Unreachable,
            ),
        ] {
            assert_eq!(refusal_of(&error), refusal, "{error}");
        }
    }

    #[test]
    fn a_lost_connection_is_told_as_such() {
        let failure = PhoneSignFailure {
            kind: SignErrorKind::Phone(PhoneRefusal::Unreachable),
            cause: Some(PhoneLinkError::Session(SessionError::HandshakeFailed)),
        };
        assert_eq!(
            failure.to_string(),
            "the connection to the paired phone was lost"
        );
        let unpaired = PhoneSignFailure {
            kind: SignErrorKind::Phone(PhoneRefusal::Unreachable),
            cause: Some(PhoneLinkError::NotPaired),
        };
        assert_eq!(
            unpaired.to_string(),
            "no phone is paired with this computer"
        );
    }

    #[test]
    fn a_card_in_a_reader_outranks_the_phone() {
        assert_eq!(choose_source(true, Some(PAIR)), SigningSource::Reader);
        assert_eq!(choose_source(false, Some(PAIR)), SigningSource::Phone(PAIR));
        assert_eq!(choose_source(false, None), SigningSource::Reader);
        assert_eq!(choose_source(true, None), SigningSource::Reader);
    }

    #[test]
    fn every_key_profile_and_algorithm_keeps_its_name() {
        for (remote, wire) in [
            (RemoteKeyProfile::EcdsaP256, CardKeyProfile::EcdsaP256),
            (RemoteKeyProfile::EcdsaP384, CardKeyProfile::EcdsaP384),
            (RemoteKeyProfile::Rsa2048, CardKeyProfile::Rsa2048),
            (RemoteKeyProfile::Rsa3072, CardKeyProfile::Rsa3072),
        ] {
            assert_eq!(key_profile(remote), wire);
        }
        assert_eq!(
            algorithm(RemoteSignatureAlgorithm::EcdsaSha384),
            SignatureAlgorithm::EcdsaSha384
        );
        assert_eq!(
            algorithm(RemoteSignatureAlgorithm::RsaPkcs1Sha256),
            SignatureAlgorithm::RsaPkcs1Sha256
        );
    }
}
