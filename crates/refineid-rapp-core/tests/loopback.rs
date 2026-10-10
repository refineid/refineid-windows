//! Loopback conformance tests: the requester engine against a scripted
//! authorization proxy running the proxy projection over the same wire.
//!
//! The proxy here is test scaffolding, not a product: the real proxies are
//! the holder's phones. It speaks the exact wire so the requester is
//! exercised end to end - code pairing through `CPace` KC2 and
//! `Noise_XXpsk3` with grant agreement, `Noise_KK` sessions with the
//! parameter echo, direct operations and their results, denial, credential
//! rejection revoking the pairing, immediate revocation on the first
//! authenticated violation, and ambiguity on an unanswered consequential
//! request.

#![allow(
    clippy::unwrap_used,
    reason = "test scaffolding is constructed to be infallible"
)]
#![allow(
    clippy::missing_panics_doc,
    reason = "tests panic to fail; documenting each panic adds nothing"
)]

use std::time::Duration;

use refineid_rapp::{
    BinaryFrame, CardInspection, CardKeyProfile as KeyProfile, CardOperation, CardOperationResult,
    CloseReason, CpaceKc2Responder, EndpointRole, EstablishedEndpoint, OperationReference,
    OperationResultMessage, PairId, PairRecord, PairStore, PairStoreError, PairTombstone,
    PairingHandshake, ProxyFailure, ReceiveOutcome, SessionCloseMessage, SessionHandshake,
    SignatureAlgorithm, TransportProfile, TypedMessage, generate_pair_key_material,
    standard_pairing_context_v2,
};
use refineid_rapp_core::engine::{
    OperationOutcome, PairingError, Requester, RequesterConfig, SessionError,
};
use refineid_rapp_core::operations::SignatureAlgorithmExt as _;
use refineid_rapp_core::profiles::{PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS};
use refineid_rapp_core::store::{
    MemoryJournal, MemoryPairingStore, OperationJournal, PairingDisposition, PairingStore,
};
use refineid_rapp_core::stream::{STREAM_CANDIDATE_ID, STREAM_PROFILE};
use refineid_rapp_core::transport::{FrameTransport, MemoryTransport};

/// A generous deadline for scripted exchanges.
const DEADLINE: Duration = Duration::from_secs(2);
/// The candidate identifier every loopback connection reports: the
/// in-memory transport stands in for a stream connection.
const CANDIDATE: &str = STREAM_CANDIDATE_ID;
/// Test monotonic timestamp in milliseconds.
const TEST_MONOTONIC_TIMESTAMP_MS: u64 = 1_000_000;
/// The code the scripted custodian shows.
const SHOWN_CODE: &str = "7KX4M9";
/// Fixed custodian scalar entropy for the scripted exchange.
const CUSTODIAN_ENTROPY: [u8; 64] = [0x24; 64];

/// The requester engine type under test.
type TestRequester = Requester<MemoryPairingStore, MemoryJournal>;

fn test_requester() -> TestRequester {
    Requester::new(
        RequesterConfig {
            display_name: "Workstation".into(),
            platform: "Linux".into(),
        },
        MemoryPairingStore::new(),
        MemoryJournal::new(),
    )
}

/// A registered consequential operation for the authentication tests.
fn authentication_operation() -> CardOperation {
    CardOperation::BrowserAuthenticate {
        origin: "kortti.tunnistautuminen.suomi.fi".into(),
        key_profile: KeyProfile::Rsa3072,
        algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
        digest: vec![0x2a; SignatureAlgorithm::RsaPkcs1Sha256.digest_length()],
    }
}

#[derive(Default)]
struct MockProxyStore;

impl PairStore for MockProxyStore {
    type Error = core::convert::Infallible;
    fn load(&mut self, _pair_id: PairId) -> Result<Option<PairRecord>, Self::Error> {
        Ok(None)
    }
    fn insert(&mut self, _record: PairRecord) -> Result<(), PairStoreError<Self::Error>> {
        Ok(())
    }
    fn revoke(&mut self, _tombstone: PairTombstone) -> Result<(), PairStoreError<Self::Error>> {
        Ok(())
    }
    fn is_revoked(&mut self, _pair_id: PairId) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

/// The custodian's random offer for the stream transport.
fn custodian_offer() -> refineid_rapp::PairingOffer {
    let mut offer_id = [0_u8; refineid_rapp::OFFER_ID_SIZE];
    getrandom::fill(&mut offer_id).unwrap();
    refineid_rapp::PairingOffer::create(
        refineid_rapp::OfferId::from_array(offer_id),
        vec![
            PROFILE_CARD_STATUS.to_owned(),
            PROFILE_AUTHENTICATION.to_owned(),
            "fi.refineid.document-signing.v1".to_owned(),
        ],
        &[TransportProfile::Stream],
    )
    .unwrap()
}

/// Serves the offer bootstrap (RAPP v26.10.9 section 4.2) and returns the
/// offer and its `CPace` context.
fn serve_offer<T: FrameTransport>(transport: &mut T) -> (refineid_rapp::PairingOffer, Vec<u8>) {
    let offer = custodian_offer();
    transport.send_frame(&offer.to_cbor().unwrap()).unwrap();
    let context = standard_pairing_context_v2(
        &offer.offer_hash().unwrap(),
        STREAM_PROFILE,
        STREAM_CANDIDATE_ID,
    )
    .unwrap();
    (offer, context)
}

/// Runs the custodian half of pairing and returns its stored half: the
/// offer bootstrap, `CPace` KC2 as responder, then `Noise_XXpsk3` under its
/// key, then the hello and confirmation exchange.
fn proxy_pair<T: FrameTransport>(mut transport: T, shown_code: &str) -> PairRecord {
    let now_ms = TEST_MONOTONIC_TIMESTAMP_MS;
    let candidate = transport.candidate_id().to_owned();
    let (offer, context) = serve_offer(&mut transport);

    let step_one = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    let (step_two, waiting) = CpaceKc2Responder::process_step1_frame(
        shown_code,
        &context,
        &offer.offer_id,
        &step_one,
        &CUSTODIAN_ENTROPY,
    )
    .unwrap();
    transport.send_frame(step_two.as_bytes()).unwrap();
    let step_three = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    let secret = waiting.process_step3_frame(&step_three).unwrap();

    let local_keys = generate_pair_key_material().unwrap();
    let mut handshake =
        PairingHandshake::begin(EndpointRole::Proxy, offer, &candidate, local_keys, &secret)
            .unwrap();

    let m1 = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    handshake.read_message(&m1).unwrap();
    let m2 = handshake.write_message().unwrap();
    transport.send_frame(m2.as_bytes()).unwrap();
    let m3 = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    handshake.read_message(&m3).unwrap();

    let mut confirmation = handshake.into_confirmation().unwrap();
    let hello = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    confirmation.receive_hello(&hello, now_ms).unwrap();
    let proxy_hello = confirmation
        .send_hello("Phone".into(), "iOS".into())
        .unwrap();
    transport.send_frame(proxy_hello.as_bytes()).unwrap();
    let requester_confirmation =
        BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    let granted = confirmation
        .receive_confirmation(&requester_confirmation, now_ms)
        .unwrap()
        .to_vec();
    let proxy_confirmation = confirmation.send_confirmation(granted).unwrap();
    transport.send_frame(proxy_confirmation.as_bytes()).unwrap();
    confirmation.into_pair_record(now_ms).unwrap()
}

struct ProxySession<T: FrameTransport> {
    endpoint: EstablishedEndpoint,
    transport: T,
}

impl<T: FrameTransport> ProxySession<T> {
    fn send(&mut self, message: &TypedMessage) {
        let frame = self.endpoint.send(message).unwrap();
        self.transport.send_frame(frame.as_bytes()).unwrap();
    }

    fn receive(&mut self) -> TypedMessage {
        let frame_bytes = self.transport.receive_frame().unwrap();
        let frame = BinaryFrame::reconstruct(frame_bytes).unwrap();
        let mut store = MockProxyStore;
        let outcome = self
            .endpoint
            .receive(&mut store, &frame, TEST_MONOTONIC_TIMESTAMP_MS)
            .unwrap();
        match outcome {
            ReceiveOutcome::Message(m) => m,
            other => panic!("expected message, got {other:?}"),
        }
    }
}

/// Accepts one session as the proxy and completes the ready exchange.
fn proxy_accept_session<T: FrameTransport>(
    pair_record: &PairRecord,
    mut transport: T,
) -> ProxySession<T> {
    let now_ms = TEST_MONOTONIC_TIMESTAMP_MS;
    let mut handshake =
        SessionHandshake::begin_proxy(pair_record, TransportProfile::Stream).unwrap();

    // Message 1 (Requester -> Proxy)
    let m1_bytes = transport.receive_frame().unwrap();
    let m1 = BinaryFrame::reconstruct(m1_bytes).unwrap();
    handshake.read_message(&m1).unwrap();

    // Message 2 (Proxy -> Requester)
    let m2 = handshake.write_message().unwrap();
    transport.send_frame(m2.as_bytes()).unwrap();

    let mut auth = handshake.into_authentication().unwrap();

    // Receive Ready
    let req_ready_bytes = transport.receive_frame().unwrap();
    let req_ready_frame = BinaryFrame::reconstruct(req_ready_bytes).unwrap();
    let mut store = MockProxyStore;
    auth.receive_ready(&mut store, &req_ready_frame, now_ms)
        .unwrap();

    // Send Ready
    let proxy_ready = auth.send_ready([0x55; 32]).unwrap();
    transport.send_frame(proxy_ready.as_bytes()).unwrap();

    let endpoint = auth.into_established().unwrap();
    ProxySession {
        endpoint,
        transport,
    }
}

/// Pairs a fresh requester with a custodian thread and returns both halves.
fn paired(requester: &mut TestRequester, granted: &[String]) -> (PairId, PairRecord) {
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || proxy_pair(proxy_transport, SHOWN_CODE));
    let pair_id = requester
        .pair_with_code("7k x4-m9", requester_transport, |peer, _requested| {
            assert_eq!(peer.display_name, "Phone");
            Some(granted.to_vec())
        })
        .unwrap();
    let proxy_record = proxy.join().unwrap();
    assert_eq!(proxy_record.pair_id(), pair_id);
    (pair_id, proxy_record)
}

#[test]
fn pairing_stores_matching_records_on_both_sides() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, _proxy) = paired(&mut requester, &granted);
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.granted_profiles, granted);
    assert_eq!(record.disposition, PairingDisposition::Paired);
    assert_eq!(record.peer_display_name, "Phone");
    assert_ne!(record.rendezvous_token.as_bytes(), &[0u8; 16]);
    assert_ne!(
        record.rendezvous_token.as_bytes(),
        record.pair_id.as_bytes()
    );
}

#[test]
fn a_mistyped_code_fails_at_the_custodian_tag_and_stores_nothing() {
    let mut requester = test_requester();
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let (offer, context) = serve_offer(&mut proxy_transport);
        let step_one = BinaryFrame::reconstruct(proxy_transport.receive_frame().unwrap()).unwrap();
        let (step_two, _waiting) = CpaceKc2Responder::process_step1_frame(
            SHOWN_CODE,
            &context,
            &offer.offer_id,
            &step_one,
            &CUSTODIAN_ENTROPY,
        )
        .unwrap();
        proxy_transport.send_frame(step_two.as_bytes()).unwrap();
        // The requester refuses T_B and never answers with T_A.
        assert!(proxy_transport.receive_frame().is_err());
    });
    let outcome = requester.pair_with_code("7KX4MA", requester_transport, |_, _| {
        panic!("an unauthenticated attempt must never reach confirmation")
    });
    proxy.join().unwrap();
    assert_eq!(outcome, Err(PairingError::CodeMismatch));
    assert!(requester.store().pair_ids().is_empty());
}

#[test]
fn input_that_is_not_a_code_never_touches_the_transport() {
    let mut requester = test_requester();
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let outcome = requester.pair_with_code("7KX4MU", requester_transport, |_, _| None);
    assert_eq!(outcome, Err(PairingError::InvalidCode));
    assert!(proxy_transport.receive_frame().is_err());
}

#[test]
fn card_status_completes_as_a_safe_read() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        assert_eq!(request.profile.as_str(), PROFILE_CARD_STATUS);
        let reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: request.request_hash().unwrap(),
        };
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                reference,
                &CardOperationResult::Inspection(CardInspection {
                    answer_to_reset: Vec::new(),
                    pin1_factory: false,
                    pin2_factory: false,
                    pin1_attempts: Some(5),
                    pin2_attempts: Some(5),
                    puk_attempts: None,
                }),
            ),
        ));
        let TypedMessage::OperationResultAck(ack_ref) = session.receive() else {
            panic!("expected the completed result to be acknowledged");
        };
        assert_eq!(ack_ref, reference);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &CardOperation::InspectCard, 30_000)
        .unwrap();
    proxy.join().unwrap();
    let OperationOutcome::Completed(result) = outcome else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(
        result,
        CardOperationResult::Inspection(CardInspection {
            answer_to_reset: Vec::new(),
            pin1_factory: false,
            pin2_factory: false,
            pin1_attempts: Some(5),
            pin2_attempts: Some(5),
            puk_attempts: None,
        })
    );
}

#[test]
fn authentication_executes_directly_to_its_result() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        let reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: request.request_hash().unwrap(),
        };
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                reference,
                &CardOperationResult::Signature(vec![0xAB; 96]),
            ),
        ));
        let TypedMessage::OperationResultAck(ack_ref) = session.receive() else {
            panic!("expected result ack");
        };
        assert_eq!(ack_ref, reference);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &authentication_operation(), 60_000)
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Completed(CardOperationResult::Signature(vec![0xAB; 96]))
    );
}

#[test]
fn denial_leaves_the_session_healthy() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        for _ in 0..2 {
            let TypedMessage::OperationRequest(request) = session.receive() else {
                panic!("expected an operation request");
            };
            let reference = OperationReference {
                operation_id: request.operation_id,
                request_hash: request.request_hash().unwrap(),
            };
            let failure_msg = OperationResultMessage::failure(reference, ProxyFailure::UserDenied);
            session.send(&TypedMessage::OperationResult(failure_msg));
        }
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    for _ in 0..2 {
        let outcome = requester
            .execute(&mut session, &authentication_operation(), 30_000)
            .unwrap();
        assert_eq!(outcome, OperationOutcome::Denied);
    }
    proxy.join().unwrap();
}

#[test]
fn credential_rejection_revokes_the_pairing() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        let reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: request.request_hash().unwrap(),
        };
        let failure_msg =
            OperationResultMessage::failure(reference, ProxyFailure::CredentialRejected);
        session.send(&TypedMessage::OperationResult(failure_msg));
        session.send(&TypedMessage::SessionClose(SessionCloseMessage {
            reason: CloseReason::CredentialRejected,
            last_received_sequence: 1,
        }));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &authentication_operation(), 30_000)
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::CredentialRejected);
    // Section 13.4: the authenticated credential_rejected result durably
    // revokes the pairing before the terminal outcome is reported.
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.disposition, PairingDisposition::Revoked);
    assert!(record.local_private.is_empty());
    assert!(record.peer_public.is_empty());

    // Recovery requires a new manual pairing ceremony.
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    drop(proxy_transport);
    assert!(matches!(
        requester.connect(pair_id, requester_transport),
        Err(SessionError::NotPaired(PairingDisposition::Revoked))
    ));
}

#[test]
fn unanswered_consequential_close_classifies_as_ambiguous() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        assert!(request.operation.is_consequential());
        // The transport dies with the request delivered and unanswered.
        drop(session);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &authentication_operation(), 30_000)
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::Ambiguous);
    // The journal remembers the prohibition on automatic retry (INV-06).
    let open = requester.journal().open_entries();
    assert!(open.is_empty());
}

#[test]
fn first_sequence_violation_revokes_the_pairing() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);

    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        let bad_reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: refineid_rapp::RequestHash::from_array([0xee; 32]),
        };
        let result_msg = TypedMessage::OperationResult(OperationResultMessage::completed(
            bad_reference,
            &CardOperationResult::Inspection(CardInspection {
                answer_to_reset: Vec::new(),
                pin1_factory: false,
                pin2_factory: false,
                pin1_attempts: Some(5),
                pin2_attempts: Some(5),
                puk_attempts: None,
            }),
        ));
        // Send a message with mismatched request_hash: an authenticated protocol violation on the receiver.
        let f0 = session.endpoint.send(&result_msg).unwrap();
        session.transport.send_frame(f0.as_bytes()).unwrap();
        // The requester answers with its best-effort close.
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &CardOperation::InspectCard, 30_000)
        .unwrap();
    proxy.join().unwrap();
    // An unanswered safe read classifies as cancelled.
    assert_eq!(outcome, OperationOutcome::Cancelled);
    // Section 14.6: the first authenticated violation revokes immediately.
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.disposition, PairingDisposition::Revoked);
    assert!(record.local_private.is_empty());
    assert!(record.peer_public.is_empty());

    // Revoked keys are never restored (INV-07).
    let (requester_transport, _other) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert!(matches!(
        requester.connect(pair_id, requester_transport),
        Err(SessionError::NotPaired(PairingDisposition::Revoked))
    ));
}

#[test]
fn stream_pairing_and_session_route_only_by_their_preambles() {
    use refineid_rapp::StreamRendezvous;
    use refineid_rapp_core::stream::{StreamAccept, StreamListener, dial};

    let listener = StreamListener::bind("127.0.0.1:0", STREAM_CANDIDATE_ID, DEADLINE).unwrap();
    let endpoints = vec![format!("127.0.0.1:{}", listener.local_port().unwrap())];
    let custodian = std::thread::spawn(move || {
        let StreamAccept::Pairing(transport) = listener.accept().unwrap() else {
            panic!("pairing opens with the pairing preamble");
        };
        let record = proxy_pair(transport, SHOWN_CODE);
        let StreamAccept::Session {
            rendezvous_token,
            transport,
        } = listener.accept().unwrap()
        else {
            panic!("a session opens with the session preamble");
        };
        assert_eq!(rendezvous_token, record.rendezvous_token());
        let mut session = proxy_accept_session(&record, transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        let reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: request.request_hash().unwrap(),
        };
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                reference,
                &CardOperationResult::Certificate(vec![0x30, 0x03, 0x02, 0x01, 0x01]),
            ),
        ));
        let TypedMessage::OperationResultAck(acknowledged) = session.receive() else {
            panic!("expected the result to be acknowledged");
        };
        assert_eq!(acknowledged, reference);
    });

    let mut requester = test_requester();
    let pairing = dial(
        &endpoints,
        STREAM_CANDIDATE_ID,
        DEADLINE,
        &StreamRendezvous::Pairing,
    )
    .unwrap();
    let pair_id = requester
        .pair_with_code(SHOWN_CODE, pairing, |_, requested| Some(requested.to_vec()))
        .unwrap();
    let token = requester.store().get(pair_id).unwrap().rendezvous_token;
    let transport = dial(
        &endpoints,
        STREAM_CANDIDATE_ID,
        DEADLINE,
        &StreamRendezvous::Session(token),
    )
    .unwrap();
    let mut session = requester.connect(pair_id, transport).unwrap();
    let outcome = requester
        .execute(
            &mut session,
            &CardOperation::ReadCertificate {
                kind: refineid_rapp::CertificateKind::Authentication,
            },
            30_000,
        )
        .unwrap();
    custodian.join().unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Completed(CardOperationResult::Certificate(vec![
            0x30, 0x03, 0x02, 0x01, 0x01
        ]))
    );
}
