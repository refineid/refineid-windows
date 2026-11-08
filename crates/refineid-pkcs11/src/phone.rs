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

//! The paired phone as the module's token source.
//!
//! The offer is the store's usable pairing and the certificate a session
//! heard present within the grace (RAPP v26.11.2 section 8.4 items 2 and 3),
//! read at every reading of the module: the certificate the agent offers in
//! this user's personal store, or the one a dial of this module read, held
//! in memory only. The pairing store is loaded once and followed after,
//! reading the protected set again only when it changed. A reading granted
//! a wait that finds no certificate dials the phone, as a request with no
//! session open does (section 8.3), and waits at most that wait for a
//! session to confirm the card and read its certificate; a reading granted
//! none dials nothing. A signature dials the phone, runs one
//! `browser_authenticate` and closes the session: this computer only dials,
//! and the phone takes PIN 1 on its own screen. `C_Finalize` ends a dial
//! under way and drops what the module held.

use core::time::Duration;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use refineid_agent_pipe::identity::{calling_program, computer_name, interface_language};
use refineid_agent_pipe::{OPERATION_LIFETIME, RemoteKey, in_process_operation};
use refineid_lib_core::x509::{OwnedCert, UnvalidatedCertificate};
use refineid_pkcs11::remote::{
    RemoteOffer, RemoteSignError, RemoteTokenSource, SessionCertificate,
};
use refineid_pkcs11::slot_kind::RemoteSlotId;
use refineid_rapp_core::clock::unix_time_ms;
use refineid_rapp_core::engine::{
    OperationOutcome, Requester, RequesterConfig, SessionError, Withdrawal,
};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::{
    CardPresence, CardStatusMessage, CertificateFingerprint, CloseReason, ResultError,
};
use refineid_rapp_core::operations::{
    CardKeyProfile, CardOperation, CardOperationResult, CertificateKind, SignatureAlgorithm,
};
use refineid_rapp_core::store::{PairingRecord, PairingStore as _, offer_stands};
use refineid_rapp_core::stream::{DialCause, dial_session};
use refineid_remote::{DisplayText, RemoteKeyProfile, RemoteSignatureAlgorithm, SignatureRequest};
use refineid_windows_credential_store::{ProtectedPairingStore, offered_phone_certificate};

use crate::wake::Wake;

/// The token label of the phone's slot: the PIN it asks for is the phone's.
const TOKEN_LABEL: &str = "Phone Basic PIN 1";

/// How long one DNS-SD browse listens for the paired phone's session record.
const BROWSE_WINDOW: Duration = Duration::from_secs(2);

/// The context when this computer has no name: the product's.
const FALLBACK_CONTEXT: &str = "RefineID";

/// How long a dial's fresh session waits for the phone's first card report
/// (RAPP v26.11.2 section 8.4 item 1): the phone sends it right after
/// `session.ready`.
const FIRST_CARD_REPORT_WAIT: Duration = Duration::from_secs(5);

/// The operation lifetime sent on the wire, in milliseconds.
const OPERATION_LIFETIME_MS: u64 = OPERATION_LIFETIME.as_secs() * 1_000;

/// The paired phone: the pairing store, loaded at the first reading and
/// followed after, and the dials for its card.
pub struct PhoneSource {
    store: Mutex<Option<ProtectedPairingStore>>,
    wake: Arc<Wake<PairId, OwnedCert>>,
    /// Raised by `C_Finalize`, which ends a dial under way.
    withdrawal: Mutex<Withdrawal>,
}

impl core::fmt::Debug for PhoneSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhoneSource").finish_non_exhaustive()
    }
}

impl PhoneSource {
    /// A source that reads nothing until its first reading.
    pub fn new() -> Self {
        Self {
            store: Mutex::new(None),
            wake: Arc::new(Wake::new()),
            withdrawal: Mutex::new(Withdrawal::new()),
        }
    }

    /// The pairing the store serves and the certificate its phone is
    /// offered on now: the one a dial of this module read, while its offer
    /// stands, or else the one the agent offers in the personal store.
    fn standing(&self) -> Option<(PairId, Option<OwnedCert>)> {
        let mut held = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        match held.as_mut() {
            Some(store) => {
                // A set that cannot be read now leaves the records held here
                // as they were.
                if let Err(error) = store.follow() {
                    refineid_dev_errors::report!(Pkcs11, "pairing store not followed", error);
                }
            }
            None => match ProtectedPairingStore::load() {
                Ok(store) => *held = Some(store),
                Err(error) => {
                    refineid_dev_errors::report!(Pkcs11, "pairing store not loaded", error);
                    return None;
                }
            },
        }
        let store = held.as_ref()?;
        let pair_id = store.usable_pairing()?.pair_id();
        let now_ms = unix_time_ms();
        let learned = self.wake.learned(pair_id);
        let standing =
            learned.filter(|certificate| offer_stands(store, pair_id, certificate, now_ms));
        if standing.is_none() {
            self.wake.forget();
        }
        let certificate = standing.or_else(|| offered_phone_certificate(store, pair_id, now_ms));
        drop(held);
        Some((pair_id, certificate))
    }

    /// The withdrawal of the current run.
    fn withdrawal(&self) -> Withdrawal {
        self.withdrawal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RemoteTokenSource for PhoneSource {
    fn offered(&self, wait: Duration) -> Option<RemoteOffer> {
        let asked = Instant::now();
        let (mut pair_id, mut certificate) = self.standing()?;
        if certificate.is_none() && !wait.is_zero() {
            let withdrawal = self.withdrawal();
            self.wake
                .ask(pair_id, wait.saturating_sub(asked.elapsed()), move || {
                    confirmed_certificate(pair_id, &withdrawal)
                });
            (pair_id, certificate) = self.standing()?;
        }
        let slot = RemoteSlotId::parse(&hex_of(pair_id)).ok()?;
        Some(RemoteOffer::new(
            slot,
            TOKEN_LABEL.to_owned(),
            computer_context()?,
            certificate.map(|certificate| SessionCertificate::new(certificate.as_der().to_vec())),
        ))
    }

    fn sign(
        &self,
        pair_id: &RemoteSlotId,
        request: &SignatureRequest,
        _context: &DisplayText,
        deadline: Duration,
    ) -> Result<Vec<u8>, RemoteSignError> {
        let answer = run_signature(pair_id, request, deadline);
        if let Err(error) = &answer {
            refineid_dev_errors::report!(Pkcs11, "remote signature refused", error);
        }
        answer
    }

    /// The host finalizes the module: a dial under way ends, and what the
    /// module held of the store and the card goes before the host may
    /// unload it.
    fn stop(&self) {
        self.withdrawal().raise();
        self.wake.finish();
        self.wake.forget();
        *self.store.lock().unwrap_or_else(PoisonError::into_inner) = None;
        *self
            .withdrawal
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Withdrawal::new();
    }
}

/// Dials the phone of `pair_id` as a local consumer's request (RAPP
/// v26.11.2 section 8.3), and has the session confirm the card the phone
/// reports: its authentication certificate, read on the session, is the
/// one whose fingerprint the phone reported (section 8.4 item 2). `None`
/// when no session confirmed a card. The session is closed after.
fn confirmed_certificate(pair_id: PairId, withdrawal: &Withdrawal) -> Option<OwnedCert> {
    let store = ProtectedPairingStore::load().ok()?;
    let keys = store
        .usable_pairing()
        .filter(|record| record.pair_id() == pair_id)
        .and_then(PairingRecord::serving_record)?;
    let transport = dial_session(keys, &[], BROWSE_WINDOW, DialCause::ConsumerRequest).ok()?;
    let mut requester =
        Requester::new(RequesterConfig::this_computer(), store).following(withdrawal.clone());
    let mut session = requester.connect(pair_id, transport).ok()?;
    let reported = Instant::now();
    while session.end().is_none()
        && session.card_status().is_none()
        && reported.elapsed() < FIRST_CARD_REPORT_WAIT
    {
        // An ended session is noticed by the loop.
        let _ = requester.keep_alive(&mut session);
    }
    let certificate = match session.card_status() {
        Some(CardStatusMessage {
            card: CardPresence::Present(fingerprint),
            ..
        }) if session.end().is_none() => {
            let operation = CardOperation::ReadCertificate {
                kind: CertificateKind::Authentication,
            };
            match requester.execute(&mut session, &operation, OPERATION_LIFETIME_MS) {
                Ok(OperationOutcome::Completed(CardOperationResult::Certificate(der)))
                    if CertificateFingerprint::of_certificate(&der) == fingerprint =>
                {
                    OwnedCert::from_der(UnvalidatedCertificate::new(der)).ok()
                }
                _ => {
                    refineid_dev_errors::report!(
                        Pkcs11,
                        "certificate not read",
                        "the session confirmed no card"
                    );
                    None
                }
            }
        }
        _ => None,
    };
    // A session the phone already closed is not closed again (section 4.6
    // item 4).
    requester.disconnect(&mut session, CloseReason::UserDisconnect);
    certificate
}

/// The identifier as the slot names it: lowercase hexadecimal.
fn hex_of(pair_id: PairId) -> String {
    use core::fmt::Write as _;
    let mut text = String::new();
    for byte in pair_id.as_bytes() {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The computer's name as the phone's consent shows it.
fn computer_context() -> Option<DisplayText> {
    DisplayText::new(computer_name())
        .or_else(|_| DisplayText::new(FALLBACK_CONTEXT.to_owned()))
        .ok()
}

/// One signature on a session of its own.
fn run_signature(
    slot: &RemoteSlotId,
    request: &SignatureRequest,
    deadline: Duration,
) -> Result<Vec<u8>, RemoteSignError> {
    let store = ProtectedPairingStore::load().map_err(|_| RemoteSignError::Unreachable)?;
    let record = store
        .usable_pairing()
        .filter(|record| RemoteSlotId::parse(&hex_of(record.pair_id())).ok().as_ref() == Some(slot))
        .ok_or(RemoteSignError::Withdrawn)?;
    let pair_id = record.pair_id();
    let keys = store
        .get(pair_id)
        .ok()
        .and_then(PairingRecord::serving_record)
        .ok_or(RemoteSignError::Withdrawn)?;
    let program = calling_program().ok_or(RemoteSignError::Unsupported)?;
    let operation = in_process_operation(
        RemoteKey::Authentication,
        &program,
        &computer_name(),
        interface_language(),
        key_profile(request.key_profile()),
        signature_algorithm(request.algorithm()),
        request.digest().to_vec(),
    );
    let transport = dial_session(keys, &[], BROWSE_WINDOW, DialCause::ConsumerRequest)
        .map_err(|_| RemoteSignError::Unreachable)?;
    let mut requester = Requester::new(RequesterConfig::this_computer(), store);
    let mut session = match requester.connect(pair_id, transport) {
        Ok(session) => session,
        Err(SessionError::ClosedByPeer(CloseReason::PairingRevoked)) => {
            return Err(RemoteSignError::Withdrawn);
        }
        Err(_) => return Err(RemoteSignError::Unreachable),
    };
    let lifetime = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX);
    let outcome = requester.execute(&mut session, &operation, lifetime);
    // A session the phone already closed is not closed again (section 4.6
    // item 4).
    requester.disconnect(&mut session, CloseReason::UserDisconnect);
    match outcome.map_err(|_| RemoteSignError::Ambiguous)? {
        OperationOutcome::Completed(CardOperationResult::Signature(signature)) => Ok(signature),
        other => Err(outcome_error(&other)),
    }
}

const fn key_profile(profile: RemoteKeyProfile) -> CardKeyProfile {
    match profile {
        RemoteKeyProfile::EcdsaP256 => CardKeyProfile::EcdsaP256,
        RemoteKeyProfile::EcdsaP384 => CardKeyProfile::EcdsaP384,
        RemoteKeyProfile::Rsa2048 => CardKeyProfile::Rsa2048,
        RemoteKeyProfile::Rsa3072 => CardKeyProfile::Rsa3072,
    }
}

const fn signature_algorithm(algorithm: RemoteSignatureAlgorithm) -> SignatureAlgorithm {
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

/// The module's view of an operation that did not sign.
const fn outcome_error(outcome: &OperationOutcome) -> RemoteSignError {
    match outcome {
        OperationOutcome::Rejected(error) | OperationOutcome::Cancelled(error) => {
            result_error(*error)
        }
        // The session ended with the operation live: whether the card signed
        // is not known here (section 8.1 item 3).
        OperationOutcome::Lost => RemoteSignError::Ambiguous,
        OperationOutcome::Refused(_) | OperationOutcome::Completed(_) => {
            RemoteSignError::Unsupported
        }
    }
}

/// A section 10.3 error name the phone gave, as the module reports it.
const fn result_error(error: ResultError) -> RemoteSignError {
    match error {
        ResultError::UserCancelled => RemoteSignError::Cancelled,
        ResultError::OperationExpired => RemoteSignError::Expired,
        ResultError::RetryFloor => RemoteSignError::CredentialLocked,
        ResultError::InvalidLifetime
        | ResultError::Unauthorized
        | ResultError::UnsupportedParameter => RemoteSignError::Unsupported,
        ResultError::CardError
        | ResultError::Busy
        | ResultError::DuplicateOperation
        | ResultError::OperationFailed => RemoteSignError::Ambiguous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A byte of a synthetic pair identifier.
    const SYNTHETIC_BYTE: u8 = 7;

    #[test]
    fn every_phone_refusal_maps_to_what_the_module_reports() {
        let cases = [
            (ResultError::UserCancelled, RemoteSignError::Cancelled),
            (ResultError::OperationExpired, RemoteSignError::Expired),
            (ResultError::RetryFloor, RemoteSignError::CredentialLocked),
            (ResultError::Unauthorized, RemoteSignError::Unsupported),
            (ResultError::CardError, RemoteSignError::Ambiguous),
        ];
        for (refusal, reported) in cases {
            assert_eq!(result_error(refusal), reported);
            assert_eq!(
                outcome_error(&OperationOutcome::Rejected(refusal)),
                reported
            );
        }
        assert_eq!(
            outcome_error(&OperationOutcome::Lost),
            RemoteSignError::Ambiguous
        );
    }

    #[test]
    fn a_pair_id_names_a_slot() {
        let pair = PairId::from_array(core::array::from_fn(|_| SYNTHETIC_BYTE));
        assert!(RemoteSlotId::parse(&hex_of(pair)).is_ok());
    }
}
