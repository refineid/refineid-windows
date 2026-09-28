//! Integration test for RAPP mock proxy pairing and operation exchange.

use std::time::Duration;

use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
use refineid_rapp_cli::mock_proxy::{MockProxyOptions, run_mock_proxy};
use refineid_rapp_core::engine::{OperationOutcome, Requester, RequesterConfig};
use refineid_rapp_core::ids::PairingSecret;
use refineid_rapp_core::limits::OFFER_TTL_MAX_MS;
use refineid_rapp_core::message::CloseReason;
use refineid_rapp_core::offer::{PairingOffer, TransportCandidate, offer_id_from_code};
use refineid_rapp_core::operations::{
    CardOperation, CardOperationResult, CertificateKind, KeyProfile, SignatureAlgorithm,
    SignatureAlgorithmExt as _,
};
use refineid_rapp_core::profiles::{
    PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS, PROFILE_DOCUMENT_SIGNING,
};
use refineid_rapp_core::store::{MemoryJournal, MemoryPairingStore, PairingStore};
use refineid_rapp_core::stream::{StreamAccept, StreamListener, stream_candidate_parameters};
use refineid_rapp_core::transport::STREAM_PROFILE;

const CANDIDATE_ID: &str = "stream-test";
const DEADLINE: Duration = Duration::from_secs(5);
const OPERATION_EXPIRY_MS: u64 = 30_000;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Comprehensive end-to-end integration test for pairing and operations"
)]
fn test_mock_proxy_pairing_and_card_operations() {
    let listener =
        StreamListener::bind("127.0.0.1:0", CANDIDATE_ID, DEADLINE).expect("listener bind failed");
    let port = listener.local_port().expect("listener port failed");
    let endpoint = format!("127.0.0.1:{port}");

    let test_code = "654321";
    let offer_id = offer_id_from_code(test_code).expect("valid code");
    let secret = PairingSecret::from_random_bytes([0u8; 32]);

    let requested_profiles = vec![
        PROFILE_CARD_STATUS.to_owned(),
        PROFILE_AUTHENTICATION.to_owned(),
        PROFILE_DOCUMENT_SIGNING.to_owned(),
    ];

    let stream_params =
        stream_candidate_parameters(std::slice::from_ref(&endpoint)).expect("parameters");
    let offer = PairingOffer::reconstruct(
        offer_id,
        secret,
        vec![refineid_rapp::MANDATORY_PAIRING_SUITE.into()],
        requested_profiles.clone(),
        vec![TransportCandidate {
            profile: STREAM_PROFILE.into(),
            candidate_id: CANDIDATE_ID.into(),
            parameters: stream_params,
        }],
        OFFER_TTL_MAX_MS,
    )
    .expect("offer reconstruct");

    let proxy_endpoint = endpoint;
    let proxy_handle = std::thread::spawn(move || {
        let options = MockProxyOptions {
            connect: Some(proxy_endpoint),
            code: Some(test_code.to_owned()),
            candidate_id: CANDIDATE_ID.to_owned(),
            count: 1,
            identity_name: "MATTI MEIKÄLÄINEN".to_owned(),
            person_id: "010180-999X".to_owned(),
            pin1_attempts: 3,
            pin2_attempts: 4,
            ..MockProxyOptions::default()
        };
        run_mock_proxy(options).expect("mock proxy failed");
    });

    let mut requester = Requester::new(
        RequesterConfig {
            display_name: "Test Requester".into(),
            platform: "Windows".into(),
        },
        MemoryPairingStore::new(),
        MemoryJournal::new(),
    );

    // Accept pairing connection from mock proxy
    let accepted = listener.accept().expect("accept pairing");
    let StreamAccept::Pairing(transport) = accepted else {
        panic!("expected StreamAccept::Pairing");
    };

    let mut offer_slot = Some(offer);
    let pair_id = requester
        .pair_with_code(
            &mut offer_slot,
            test_code,
            &requested_profiles,
            transport,
            |peer, requested| {
                assert_eq!(peer.display_name, "RefineID Mock Phone");
                assert_eq!(peer.platform, "iOS");
                Some(requested.to_vec())
            },
        )
        .expect("requester pairing failed");

    let expected_token = requester
        .store()
        .get(pair_id)
        .expect("stored record")
        .rendezvous_token;

    // Accept session connection from mock proxy
    let accepted = listener.accept().expect("accept session");
    let StreamAccept::Session {
        rendezvous_token,
        transport,
    } = accepted
    else {
        panic!("expected StreamAccept::Session");
    };
    assert_eq!(rendezvous_token, expected_token);

    let mut session = requester
        .connect(pair_id, transport)
        .expect("session connect");

    // 1. InspectCard
    let outcome = requester
        .execute(
            &mut session,
            &CardOperation::InspectCard,
            OPERATION_EXPIRY_MS,
        )
        .expect("execute inspect_card");
    let OperationOutcome::Completed(CardOperationResult::Inspection(inspection)) = outcome else {
        panic!("unexpected outcome for InspectCard: {outcome:?}");
    };
    assert!(!inspection.pin1_factory);
    assert!(!inspection.pin2_factory);
    assert_eq!(inspection.pin1_attempts, Some(3));
    assert_eq!(inspection.pin2_attempts, Some(4));
    assert_eq!(inspection.puk_attempts, None);

    // 2. ReadIdentity
    let outcome = requester
        .execute(
            &mut session,
            &CardOperation::ReadIdentity,
            OPERATION_EXPIRY_MS,
        )
        .expect("execute read_identity");
    let OperationOutcome::Completed(CardOperationResult::Identity {
        display_name,
        person_id,
    }) = outcome
    else {
        panic!("unexpected outcome for ReadIdentity: {outcome:?}");
    };
    assert_eq!(display_name, "MATTI MEIKÄLÄINEN");
    assert_eq!(person_id, "010180-999X");

    // 3. ReadCertificate (Authentication)
    let outcome = requester
        .execute(
            &mut session,
            &CardOperation::ReadCertificate {
                kind: CertificateKind::Authentication,
            },
            OPERATION_EXPIRY_MS,
        )
        .expect("execute read_certificate (auth)");
    let OperationOutcome::Completed(CardOperationResult::Certificate(der)) = outcome else {
        panic!("unexpected outcome for ReadCertificate");
    };
    assert!(!der.is_empty());

    // 3b. ReadCertificate (Signature)
    let outcome_sig_cert = requester
        .execute(
            &mut session,
            &CardOperation::ReadCertificate {
                kind: CertificateKind::Signature,
            },
            OPERATION_EXPIRY_MS,
        )
        .expect("execute read_certificate (sig)");
    let OperationOutcome::Completed(CardOperationResult::Certificate(sig_der)) = outcome_sig_cert
    else {
        panic!("unexpected outcome for ReadCertificate (Signature)");
    };
    assert!(!sig_der.is_empty());

    // 4. BrowserAuthenticate (consequential: prepare -> commit -> signature)
    let digest = vec![0x33u8; SignatureAlgorithm::EcdsaSha384.digest_length()];
    let outcome = requester
        .execute(
            &mut session,
            &CardOperation::BrowserAuthenticate {
                origin: "https://card.refineid.fi".into(),
                key_profile: KeyProfile::EcdsaP384,
                algorithm: SignatureAlgorithm::EcdsaSha384,
                digest: digest.clone(),
            },
            OPERATION_EXPIRY_MS,
        )
        .expect("execute browser_authenticate");
    let OperationOutcome::Completed(CardOperationResult::Signature(sig)) = outcome else {
        panic!("unexpected outcome for BrowserAuthenticate: {outcome:?}");
    };
    assert_eq!(sig.len(), 96);

    // Verify that the generated P-384 signature verifies against the public key in the mock certificate
    let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(
        refineid_lib_core::x509::OwnedCert::from_der(&der)
            .expect("parse cert")
            .view()
            .spki
            .ec_public_key_point()
            .expect("ec point")
            .as_bytes(),
    )
    .expect("verifying key");
    let p384_sig = p384::ecdsa::Signature::from_slice(&sig).expect("parse sig");
    verifying_key
        .verify_prehash(&digest, &p384_sig)
        .expect("signature must verify against cert pubkey");

    // Close session gracefully
    requester.disconnect(&mut session, CloseReason::UserDisconnect);

    proxy_handle.join().expect("proxy thread finished");
}
