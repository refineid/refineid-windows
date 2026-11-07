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
//! read from the protected pairing store at every slot refresh. A signature
//! dials the phone, runs one `browser_authenticate` and closes the session:
//! this computer only dials, and the phone takes PIN 1 on its own screen.
//! `C_Finalize` has nothing to end, as no thread is kept.

use core::time::Duration;

use refineid_agent_pipe::identity::{ProcessIdentity, computer_name};
use refineid_agent_pipe::{RemoteKey, in_process_operation};
use refineid_pkcs11::remote::{
    RemoteOffer, RemoteSignError, RemoteTokenSource, SessionCertificate,
};
use refineid_pkcs11::slot_kind::RemoteSlotId;
use refineid_rapp_core::clock::unix_time_ms;
use refineid_rapp_core::engine::{OperationOutcome, Requester, RequesterConfig, SessionError};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::{CloseReason, ResultError};
use refineid_rapp_core::operations::{CardKeyProfile, CardOperationResult, SignatureAlgorithm};
use refineid_rapp_core::store::{PairingRecord, PairingStore as _};
use refineid_rapp_core::stream::{DialCause, dial_session};
use refineid_remote::{DisplayText, RemoteKeyProfile, RemoteSignatureAlgorithm, SignatureRequest};
use refineid_windows_credential_store::{ProtectedPairingStore, offered_phone_certificate};

/// The token label of the phone's slot: the PIN it asks for is the phone's.
const TOKEN_LABEL: &str = "Phone Basic PIN 1";

/// How long one DNS-SD browse listens for the paired phone's session record.
const BROWSE_WINDOW: Duration = Duration::from_secs(2);

/// The context when this computer has no name: the product's.
const FALLBACK_CONTEXT: &str = "RefineID";

/// The paired phone, read afresh from the store at every call.
#[derive(Debug, Clone, Copy)]
pub struct PhoneSource;

impl RemoteTokenSource for PhoneSource {
    fn offered(&self) -> Option<RemoteOffer> {
        let store = match ProtectedPairingStore::load() {
            Ok(store) => store,
            Err(error) => {
                refineid_dev_errors::report!(Pkcs11, "pairing store not loaded", error);
                return None;
            }
        };
        let record = store.usable_pairing()?;
        let slot = RemoteSlotId::parse(&hex_of(record.pair_id())).ok()?;
        let certificate = offered_phone_certificate(&store, record.pair_id(), unix_time_ms())
            .map(|certificate| SessionCertificate::new(certificate.as_der().to_vec()));
        Some(RemoteOffer::new(
            slot,
            TOKEN_LABEL.to_owned(),
            computer_context()?,
            certificate,
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

    fn stop(&self) {}
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
    let image = ProcessIdentity::current()
        .map_err(|_| RemoteSignError::Unsupported)?
        .image;
    let operation = in_process_operation(
        RemoteKey::Authentication,
        &image,
        &computer_name(),
        key_profile(request.key_profile()),
        signature_algorithm(request.algorithm()),
        request.digest().to_vec(),
    )
    .map_err(|_| RemoteSignError::Unsupported)?;
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
