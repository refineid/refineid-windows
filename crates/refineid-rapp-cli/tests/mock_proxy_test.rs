//! Integration test for RAPP mock proxy pairing and operation exchange.

use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
use refineid_rapp::{
    CPACE_ATTEMPT_WINDOW_MS, CertificateFingerprint, CpaceKc2Initiator, MINIMUM_REMAINING_ATTEMPTS,
    PRE_AUTHENTICATION_SPACING_MS, PairingCode, ProfileName, ResultError, encode_kc2_step1_frame,
    standard_pairing_context_v2,
};
use refineid_rapp_cli::mock_proxy::{MockProxyOptions, serve_mock_proxy};
use refineid_rapp_core::engine::{
    OperationOutcome, PairingConnection, PairingSearchError, Requester, RequesterConfig,
    SESSION_RECEIVE_TICK,
};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::{CardPresence, CardReader, CardStatusMessage, CloseReason};
use refineid_rapp_core::offer::{BootstrapAnswer, read_bootstrap};
use refineid_rapp_core::operations::{
    CardOperation, CardOperationResult, CertificateKind, KeyProfile, SignatureAlgorithm,
};
use refineid_rapp_core::store::{MemoryPairingStore, PairingRecord, PairingStore};
use refineid_rapp_core::stream::{
    DialPurpose, PairingAddress, STREAM_CANDIDATE_ID, StreamListener, dial, dial_session,
};
use sha2::{Digest as _, Sha384};

/// Receive deadline of the pairing connection.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
const OPERATION_EXPIRY_MS: u64 = 30_000;
const TEST_CODE: &str = "654321";
/// A code one character off [`TEST_CODE`].
const MISTYPED_CODE: &str = "654322";
/// Wrong codes typed before the right one.
const FAILED_ATTEMPTS: usize = 4;
/// The login challenge the requester asks the mock card to sign.
const LOGIN_CHALLENGE: &[u8] = b"synthetic login challenge";
/// Uniform bytes one `CPace` scalar is drawn from (section 6.1.1).
const CPACE_SCALAR_ENTROPY_BYTES: usize = 64;
/// The scalar entropy of the requester that holds the attempt.
const HOLDER_ENTROPY: &[u8; CPACE_SCALAR_ENTROPY_BYTES] =
    b"synthetic requester cpace scalar entropy holding the one attempt";
/// Tries a card has left when only the issuer's software may spend them.
const BELOW_THE_FLOOR: u8 = MINIMUM_REMAINING_ATTEMPTS - 1;

/// Binds the mock custodian on a free loopback port and returns its endpoint.
fn start_custodian(
    options: MockProxyOptions,
) -> (String, std::thread::JoinHandle<Result<(), String>>) {
    let listener = StreamListener::bind("127.0.0.1:0", STREAM_CANDIDATE_ID, SESSION_RECEIVE_TICK)
        .expect("listener bind failed");
    let port = listener.local_port().expect("listener port failed");
    let handle = std::thread::spawn(move || serve_mock_proxy(&listener, options));
    (format!("127.0.0.1:{port}"), handle)
}

fn options() -> MockProxyOptions {
    MockProxyOptions {
        code: Some(TEST_CODE.to_owned()),
        ..MockProxyOptions::with_mock_certificate().expect("mock certificate")
    }
}

fn requester() -> Requester<MemoryPairingStore> {
    Requester::new(
        RequesterConfig {
            display_name: "Test Requester".into(),
            platform: "Windows".into(),
        },
        MemoryPairingStore::new(),
    )
}

/// Pairs with the mock custodian at `endpoint` and opens a session.
fn paired_session(
    requester: &mut Requester<MemoryPairingStore>,
    endpoint: &str,
) -> (
    PairId,
    refineid_rapp_core::engine::Session<refineid_rapp_core::transport::TcpFrameTransport>,
) {
    let transport = dial(
        &[endpoint.to_owned()],
        STREAM_CANDIDATE_ID,
        DEADLINE,
        DialPurpose::Pairing,
    )
    .expect("dial pairing");
    let (pair_id, ()) = requester
        .pair_with_code(
            TEST_CODE,
            &mut PairingAddress::new(transport, vec![endpoint.to_owned()], DEADLINE),
            |peer, requested| {
                assert_eq!(peer.display_name, "RefineID Mock Phone");
                assert_eq!(peer.platform, "iOS");
                assert_eq!(requested, ProfileName::ALL);
                Some(requested.to_vec())
            },
        )
        .expect("requester pairing failed");
    let keys = requester
        .store()
        .get(pair_id)
        .ok()
        .and_then(PairingRecord::pair_record)
        .expect("stored record");
    let transport = dial_session(keys, &[endpoint.to_owned()], &[], std::time::Duration::ZERO)
        .expect("dial session");
    let session = requester
        .connect(pair_id, transport)
        .expect("session connect");
    (pair_id, session)
}

fn authentication(digest: &[u8]) -> CardOperation {
    CardOperation::BrowserAuthenticate {
        origin: "https://card.refineid.fi".into(),
        key_profile: KeyProfile::EcdsaP384,
        algorithm: SignatureAlgorithm::EcdsaSha384,
        digest: digest.to_vec(),
    }
}

#[test]
fn a_mistyped_code_is_refused_by_the_custodian() {
    let (endpoint, _proxy) = start_custodian(options());
    let transport = dial(
        std::slice::from_ref(&endpoint),
        STREAM_CANDIDATE_ID,
        DEADLINE,
        DialPurpose::Pairing,
    )
    .expect("dial pairing");
    let outcome = requester().pair_with_code(
        MISTYPED_CODE,
        &mut PairingAddress::new(transport, vec![endpoint], DEADLINE),
        |_, requested| Some(requested.to_vec()),
    );
    assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
}

#[test]
fn the_offer_outlives_failed_attempts() {
    let (endpoint, _proxy) = start_custodian(options());
    for _ in 0..FAILED_ATTEMPTS {
        let transport = dial(
            std::slice::from_ref(&endpoint),
            STREAM_CANDIDATE_ID,
            DEADLINE,
            DialPurpose::Pairing,
        )
        .expect("dial pairing");
        let outcome = requester().pair_with_code(
            MISTYPED_CODE,
            &mut PairingAddress::new(transport, vec![endpoint.clone()], DEADLINE),
            |_, requested| Some(requested.to_vec()),
        );
        assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
    }
    let mut requester = requester();
    let (pair_id, _session) = paired_session(&mut requester, &endpoint);
    assert!(requester.store().get(pair_id).is_ok());
}

#[test]
fn test_mock_proxy_pairing_and_card_operations() {
    let (endpoint, proxy_handle) = start_custodian(MockProxyOptions {
        identity_name: "MATTI MEIKÄLÄINEN".to_owned(),
        person_id: "010180-999X".to_owned(),
        ..options()
    });
    let mut requester = requester();
    let (_pair_id, mut session) = paired_session(&mut requester, &endpoint);

    // 1. InspectCard: the mock exposes no answer to reset.
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
    assert!(inspection.answer_to_reset.is_empty());

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

    // 3. ReadCertificate (Authentication), the one the card status names.
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
    assert_eq!(
        session.card_status(),
        Some(CardStatusMessage {
            card: CardPresence::Present(CertificateFingerprint::of_certificate(&der)),
            reader: CardReader::Absent,
        })
    );

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

    // 4. BrowserAuthenticate: the PIN prompt on the phone, then the signature.
    let digest = Sha384::digest(LOGIN_CHALLENGE);
    let outcome = requester
        .execute(&mut session, &authentication(&digest), OPERATION_EXPIRY_MS)
        .expect("execute browser_authenticate");
    let OperationOutcome::Completed(CardOperationResult::Signature(sig)) = outcome else {
        panic!("unexpected outcome for BrowserAuthenticate: {outcome:?}");
    };

    // The P-384 signature verifies against the public key in the mock
    // certificate.
    let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(
        refineid_lib_core::x509::OwnedCert::from_der(
            refineid_lib_core::x509::UnvalidatedCertificate::new(der),
        )
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

    requester.disconnect(&mut session, CloseReason::UserDisconnect);

    proxy_handle
        .join()
        .expect("proxy thread finished")
        .expect("mock proxy failed");
}

#[test]
fn the_retry_floor_refuses_without_a_verification() {
    let (endpoint, proxy_handle) = start_custodian(MockProxyOptions {
        pin1_attempts: BELOW_THE_FLOOR,
        ..options()
    });
    let mut requester = requester();
    let (pair_id, mut session) = paired_session(&mut requester, &endpoint);
    let outcome = requester
        .execute(
            &mut session,
            &authentication(&Sha384::digest(LOGIN_CHALLENGE)),
            OPERATION_EXPIRY_MS,
        )
        .expect("execute browser_authenticate");
    assert_eq!(outcome, OperationOutcome::Rejected(ResultError::RetryFloor));
    assert!(
        requester
            .store()
            .get(pair_id)
            .is_ok_and(PairingRecord::serves)
    );
    requester.disconnect(&mut session, CloseReason::UserDisconnect);
    proxy_handle
        .join()
        .expect("proxy thread finished")
        .expect("mock proxy failed");
}

#[test]
fn an_absent_card_answers_card_error() {
    let (endpoint, proxy_handle) = start_custodian(MockProxyOptions {
        card_absent: true,
        ..options()
    });
    let mut requester = requester();
    let (_pair_id, mut session) = paired_session(&mut requester, &endpoint);
    let read = requester
        .execute(
            &mut session,
            &CardOperation::ReadCertificate {
                kind: CertificateKind::Authentication,
            },
            OPERATION_EXPIRY_MS,
        )
        .expect("execute read_certificate");
    assert_eq!(read, OperationOutcome::Rejected(ResultError::CardError));
    assert_eq!(
        session.card_status(),
        Some(CardStatusMessage {
            card: CardPresence::Absent,
            reader: CardReader::Absent,
        })
    );
    let signed = requester
        .execute(
            &mut session,
            &authentication(&Sha384::digest(LOGIN_CHALLENGE)),
            OPERATION_EXPIRY_MS,
        )
        .expect("execute browser_authenticate");
    assert_eq!(signed, OperationOutcome::Rejected(ResultError::CardError));
    requester.disconnect(&mut session, CloseReason::UserDisconnect);
    proxy_handle
        .join()
        .expect("proxy thread finished")
        .expect("mock proxy failed");
}

/// Dials a pairing connection to the mock custodian at `endpoint`.
fn dial_pairing(endpoint: &str) -> refineid_rapp_core::transport::TcpFrameTransport {
    dial(
        &[endpoint.to_owned()],
        STREAM_CANDIDATE_ID,
        DEADLINE,
        DialPurpose::Pairing,
    )
    .expect("dial pairing")
}

#[test]
fn a_second_requester_is_answered_busy_during_an_attempt_and_then_pairs() {
    use refineid_rapp_core::transport::FrameTransport as _;

    let (endpoint, proxy_handle) = start_custodian(options());

    // The first requester sends CPace step 1 and holds the attempt open.
    let mut holder = dial_pairing(&endpoint);
    let Ok(BootstrapAnswer::Offer(offer)) = read_bootstrap(&mut holder) else {
        panic!("the first pairing connection is served the offer");
    };
    let context = standard_pairing_context_v2(
        &offer.offer_hash().expect("offer hash"),
        refineid_rapp_core::transport::STREAM_PROFILE,
        STREAM_CANDIDATE_ID,
    )
    .expect("context");
    let (_initiator, step_one) = CpaceKc2Initiator::new(
        &PairingCode::parse(TEST_CODE).expect("pairing code"),
        &context,
        &offer.offer_id,
        HOLDER_ENTROPY,
    )
    .expect("step 1");
    holder
        .send_frame(
            encode_kc2_step1_frame(&step_one)
                .expect("step 1 frame")
                .as_bytes(),
        )
        .expect("send step 1");
    holder
        .receive_frame()
        .expect("step 2: the attempt is admitted");
    std::thread::sleep(std::time::Duration::from_millis(
        PRE_AUTHENTICATION_SPACING_MS,
    ));

    // The second requester is answered busy for the attempt's time left.
    let Ok(PairingConnection::Busy(busy)) =
        refineid_rapp_core::engine::read_bootstrap_answer(dial_pairing(&endpoint))
    else {
        panic!("a pairing connection during an attempt is answered busy");
    };
    assert!(busy.retry_after_ms() > PRE_AUTHENTICATION_SPACING_MS);
    assert!(busy.retry_after_ms() <= CPACE_ATTEMPT_WINDOW_MS);

    // The attempt ends; the second requester waits and pairs.
    drop(holder);
    let mut requester = requester();
    let (pair_id, mut session) = paired_session(&mut requester, &endpoint);
    assert!(requester.store().get(pair_id).is_ok());
    requester.disconnect(&mut session, CloseReason::UserDisconnect);
    proxy_handle
        .join()
        .expect("proxy thread finished")
        .expect("mock proxy failed");
}
