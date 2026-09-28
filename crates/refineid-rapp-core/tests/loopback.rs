//! Loopback conformance tests: the requester engine against a scripted
//! authorization proxy running the proxy projection over the same wire.
//!
//! The proxy here is test scaffolding, not a product: the real proxies are
//! the holder's phones. It speaks the exact wire so the requester is
//! exercised end to end - pairing with grant agreement, sessions with the
//! parameter echo, the prepare/commit/result exchange, denial, credential
//! rejection revoking the pairing, immediate revocation on the first
//! authenticated violation, and ambiguity on a committed close.

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
    CloseReason, EndpointRole, EstablishedEndpoint, OfferId, OperationReference,
    OperationResultMessage, PairId, PairRecord, PairStore, PairStoreError, PairTombstone,
    PairingHandshake, PairingOffer, PairingSecret, ReceiveOutcome, ResultError, ResultStatus,
    SessionCloseMessage, SessionHandshake, SignatureAlgorithm, TransportCandidate, TypedMessage,
    generate_pair_key_material,
};
use refineid_rapp_core::engine::{
    OperationOutcome, PairingError, Requester, RequesterConfig, SessionError,
};
use refineid_rapp_core::operations::SignatureAlgorithmExt as _;
use refineid_rapp_core::profiles::{PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS};
use refineid_rapp_core::store::{
    MemoryJournal, MemoryPairingStore, OperationJournal, PairingDisposition, PairingStore,
};
use refineid_rapp_core::transport::{FrameTransport, MEMORY_PROFILE, MemoryTransport};

/// A generous deadline for scripted exchanges.
const DEADLINE: Duration = Duration::from_secs(2);
/// The candidate identifier used by every loopback test.
const CANDIDATE: &str = "loopback-1";

/// The requester engine type under test.
type TestRequester = Requester<MemoryPairingStore, MemoryJournal>;

fn test_requester() -> TestRequester {
    Requester::new(
        RequesterConfig {
            display_name: "Workstation".into(),
            platform: "Windows".into(),
        },
        MemoryPairingStore::new(),
        MemoryJournal::new(),
    )
}

fn test_offer(secret_bytes: [u8; 32]) -> PairingOffer {
    PairingOffer::reconstruct(
        OfferId::from_array([0x51; 32]),
        PairingSecret::from_random_bytes(secret_bytes),
        vec![refineid_rapp::MANDATORY_PAIRING_SUITE.into()],
        vec![
            PROFILE_CARD_STATUS.to_owned(),
            PROFILE_AUTHENTICATION.to_owned(),
        ],
        vec![TransportCandidate {
            profile: MEMORY_PROFILE.into(),
            candidate_id: CANDIDATE.into(),
            parameters: std::collections::BTreeMap::new(),
        }],
        120_000,
    )
    .unwrap()
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

/// Runs the proxy half of the pairing exchange and returns its stored half.
fn proxy_pair(
    mut transport: MemoryTransport,
    offer: PairingOffer,
    _granted: &[String],
) -> PairRecord {
    let now_ms = 1_000_000;
    let local_keys = generate_pair_key_material().unwrap();
    let mut handshake =
        PairingHandshake::begin(EndpointRole::Proxy, offer, CANDIDATE, local_keys).unwrap();

    // Message 1 (Requester -> Proxy)
    let m1_bytes = transport.receive_frame().unwrap();
    let m1 = BinaryFrame::reconstruct(m1_bytes).unwrap();
    handshake.read_message(&m1).unwrap();

    // Message 2 (Proxy -> Requester)
    let m2 = handshake.write_message().unwrap();
    transport.send_frame(m2.as_bytes()).unwrap();

    // Message 3 (Requester -> Proxy)
    let m3_bytes = transport.receive_frame().unwrap();
    let m3 = BinaryFrame::reconstruct(m3_bytes).unwrap();
    handshake.read_message(&m3).unwrap();

    let mut confirmation = handshake.into_confirmation().unwrap();

    // Message 4: Receive Requester Hello
    let req_hello_bytes = transport.receive_frame().unwrap();
    let req_hello_frame = BinaryFrame::reconstruct(req_hello_bytes).unwrap();
    let _hello = confirmation
        .receive_hello(&req_hello_frame, now_ms)
        .unwrap();

    // Message 5: Send Proxy Hello
    let proxy_hello = confirmation
        .send_hello("Phone".into(), "iOS".into())
        .unwrap();
    transport.send_frame(proxy_hello.as_bytes()).unwrap();

    // Message 6: Receive Requester Confirmation
    let req_conf_bytes = transport.receive_frame().unwrap();
    let req_conf_frame = BinaryFrame::reconstruct(req_conf_bytes).unwrap();
    let req_conf = confirmation
        .receive_confirmation(&req_conf_frame, now_ms)
        .unwrap();
    let granted_profiles = req_conf.to_vec();

    // Message 7: Send Proxy Confirmation
    let proxy_conf = confirmation.send_confirmation(granted_profiles).unwrap();
    transport.send_frame(proxy_conf.as_bytes()).unwrap();

    confirmation.into_pair_record(now_ms).unwrap()
}

struct ProxySession {
    endpoint: EstablishedEndpoint,
    transport: MemoryTransport,
}

impl ProxySession {
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
            .receive(&mut store, &frame, 1_000_000)
            .unwrap();
        match outcome {
            ReceiveOutcome::Message(m) => m,
            other => panic!("expected message, got {other:?}"),
        }
    }
}

/// Accepts one session as the proxy and completes the ready exchange.
fn proxy_accept_session(pair_record: &PairRecord, mut transport: MemoryTransport) -> ProxySession {
    let now_ms = 1_000_000;
    let mut handshake = SessionHandshake::begin_proxy(pair_record).unwrap();

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

/// Pairs a fresh requester with a proxy thread and returns both halves.
fn paired(requester: &mut TestRequester, granted: &[String]) -> (PairId, PairRecord) {
    let secret_bytes = [0x77u8; 32];
    let offer = test_offer(secret_bytes);
    let proxy_offer = test_offer(secret_bytes);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let granted_for_proxy = granted.to_vec();
    let proxy =
        std::thread::spawn(move || proxy_pair(proxy_transport, proxy_offer, &granted_for_proxy));
    let profile_request: Vec<String> = granted.to_vec();
    let mut offer_slot = Some(offer);
    let pair_id = requester
        .pair(
            &mut offer_slot,
            &profile_request,
            requester_transport,
            |peer, _requested| {
                assert_eq!(peer.display_name, "Phone");
                Some(granted.to_vec())
            },
        )
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
fn wrong_secret_fails_pairing_without_storing() {
    let mut requester = test_requester();
    let offer = test_offer([0x02; 32]);
    let proxy_offer = test_offer([0x01; 32]);
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let local_keys = generate_pair_key_material().unwrap();
        let mut handshake =
            PairingHandshake::begin(EndpointRole::Proxy, proxy_offer, CANDIDATE, local_keys)
                .unwrap();
        let m1 = proxy_transport.receive_frame().unwrap();
        let m1_frame = BinaryFrame::reconstruct(m1).unwrap();
        if handshake.read_message(&m1_frame).is_ok()
            && let Ok(m2) = handshake.write_message()
        {
            let _ = proxy_transport.send_frame(m2.as_bytes());
        }
    });
    let mut offer_slot = Some(offer);
    let outcome = requester.pair(
        &mut offer_slot,
        &[PROFILE_CARD_STATUS.to_owned()],
        requester_transport,
        |_, _| panic!("an unauthenticated attempt must never reach confirmation"),
    );
    proxy.join().unwrap();
    assert!(matches!(
        outcome,
        Err(PairingError::HandshakeFailed | PairingError::Transport(_))
    ));
}

#[test]
fn card_status_completes_without_commit() {
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
                CardOperationResult::Inspection(CardInspection {
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
            pin1_factory: false,
            pin2_factory: false,
            pin1_attempts: Some(5),
            pin2_attempts: Some(5),
            puk_attempts: None,
        })
    );
}

#[test]
fn authentication_walks_prepare_commit_result() {
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
        session.send(&TypedMessage::OperationPrepared(reference));
        let TypedMessage::OperationCommit(echoed) = session.receive() else {
            panic!("expected a commit after prepared");
        };
        assert_eq!(echoed, reference);
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                reference,
                CardOperationResult::Signature(vec![0xAB; 96]),
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
            let failure_msg = OperationResultMessage::failure(
                reference,
                ResultStatus::Denied,
                ResultError::UserDenied,
            )
            .unwrap();
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
        let failure_msg = OperationResultMessage::failure(
            reference,
            ResultStatus::CredentialRejected,
            ResultError::CredentialRejected,
        )
        .unwrap();
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
fn committed_close_classifies_as_ambiguous() {
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
        session.send(&TypedMessage::OperationPrepared(reference));
        let TypedMessage::OperationCommit(_) = session.receive() else {
            panic!("expected a commit");
        };
        // The transport dies with the operation committed.
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
            CardOperationResult::Inspection(CardInspection {
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
    // Pre-commit closure classifies the operation as cancelled.
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
