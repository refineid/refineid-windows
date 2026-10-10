//! Integration test for RAPP mock proxy pairing and operation exchange.

use std::time::Duration;

use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
use refineid_rapp_cli::mock_proxy::{MockProxyOptions, serve_mock_proxy};
use refineid_rapp_core::engine::{OperationOutcome, PairingError, Requester, RequesterConfig};
use refineid_rapp_core::message::CloseReason;
use refineid_rapp_core::operations::{
    CardOperation, CardOperationResult, CertificateKind, KeyProfile, SignatureAlgorithm,
    SignatureAlgorithmExt as _,
};
use refineid_rapp_core::store::{MemoryJournal, MemoryPairingStore, PairingStore};
use refineid_rapp_core::stream::{
    STREAM_CANDIDATE_ID, StreamListener, StreamRendezvous, dial, dial_session,
};

const DEADLINE: Duration = Duration::from_secs(5);
const OPERATION_EXPIRY_MS: u64 = 30_000;
const TEST_CODE: &str = "654321";

/// Binds the mock custodian on a free loopback port and returns its endpoint.
fn start_custodian(
    options: MockProxyOptions,
) -> (String, std::thread::JoinHandle<Result<(), String>>) {
    let listener = StreamListener::bind("127.0.0.1:0", STREAM_CANDIDATE_ID, DEADLINE)
        .expect("listener bind failed");
    let port = listener.local_port().expect("listener port failed");
    let handle = std::thread::spawn(move || serve_mock_proxy(&listener, options));
    (format!("127.0.0.1:{port}"), handle)
}

fn requester() -> Requester<MemoryPairingStore, MemoryJournal> {
    Requester::new(
        RequesterConfig {
            display_name: "Test Requester".into(),
            platform: "Windows".into(),
        },
        MemoryPairingStore::new(),
        MemoryJournal::new(),
    )
}

#[test]
fn a_mistyped_code_is_refused_by_the_custodian() {
    let (endpoint, _proxy) = start_custodian(MockProxyOptions {
        code: Some(TEST_CODE.to_owned()),
        ..MockProxyOptions::default()
    });
    let transport = dial(
        &[endpoint],
        STREAM_CANDIDATE_ID,
        DEADLINE,
        &StreamRendezvous::Pairing,
    )
    .expect("dial pairing");
    let outcome =
        requester().pair_with_code("654322", transport, |_, requested| Some(requested.to_vec()));
    assert!(
        matches!(
            outcome,
            Err(PairingError::CodeMismatch | PairingError::Transport(_))
        ),
        "unexpected outcome: {outcome:?}"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Comprehensive end-to-end integration test for pairing and operations"
)]
fn test_mock_proxy_pairing_and_card_operations() {
    let (endpoint, proxy_handle) = start_custodian(MockProxyOptions {
        code: Some(TEST_CODE.to_owned()),
        count: 1,
        identity_name: "MATTI MEIKÄLÄINEN".to_owned(),
        person_id: "010180-999X".to_owned(),
        pin1_attempts: 3,
        pin2_attempts: 4,
        ..MockProxyOptions::default()
    });

    let mut requester = requester();

    let transport = dial(
        std::slice::from_ref(&endpoint),
        STREAM_CANDIDATE_ID,
        DEADLINE,
        &StreamRendezvous::Pairing,
    )
    .expect("dial pairing");
    let pair_id = requester
        .pair_with_code(TEST_CODE, transport, |peer, requested| {
            assert_eq!(peer.display_name, "RefineID Mock Phone");
            assert_eq!(peer.platform, "iOS");
            Some(requested.to_vec())
        })
        .expect("requester pairing failed");

    let token = requester
        .store()
        .get(pair_id)
        .expect("stored record")
        .rendezvous_token;
    let transport = dial_session(
        token,
        std::slice::from_ref(&endpoint),
        &[],
        Duration::ZERO,
        DEADLINE,
    )
    .expect("dial session");

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
    let OperationOutcome::Completed(CardOperationResult::Identity(identity)) = outcome else {
        panic!("unexpected outcome for ReadIdentity: {outcome:?}");
    };
    assert_eq!(identity.holder_name, "MATTI MEIKÄLÄINEN");
    assert_eq!(identity.card_id, "010180-999X");

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

    proxy_handle
        .join()
        .expect("proxy thread finished")
        .expect("mock proxy failed");
}
