//! Loopback conformance tests: the requester engine against a scripted
//! custodian speaking the same wire through `refineid_rapp`.
//!
//! The custodian here is test scaffolding, not a product: the real
//! custodians are the holder's phones. It speaks the exact wire of RAPP
//! v26.10.22 so the requester is exercised end to end: code pairing through
//! `CPace` KC2 and `Noise_XXpsk3` with grant agreement and the storage
//! confirmation, `Noise_KK` sessions with the Custodian's `session.ready`
//! and card status, operations and their results inside their session,
//! liveness, revocation in both directions, and the sealed
//! `protocol_violation` close that leaves the pairing in place.

#![allow(
    clippy::unwrap_used,
    reason = "test scaffolding is constructed to be infallible"
)]
#![allow(
    clippy::missing_panics_doc,
    reason = "tests panic to fail; documenting each panic adds nothing"
)]

use std::time::{Duration, Instant};

use refineid_rapp::{
    BinaryFrame, CardInspection, CardKeyProfile as KeyProfile, CardOperation, CardOperationResult,
    CardStatusMessage, CertificateFingerprint, CloseReason, CpaceKc2Responder, EndpointRole,
    EstablishedEndpoint, LIVENESS_PING_AFTER_SILENCE_MS, OperationId, OperationProgressMessage,
    OperationResultMessage, PairRecord, PairingHandshake, ProfileName, ProgressEvent,
    ProtocolErrorMessage, ProxyFailure, ReceiveOutcome, ResultError, SESSION_READY_NONCE_SIZE,
    SessionCloseMessage, SessionHandshake, SignatureAlgorithm, TransportProfile, TypedMessage,
    generate_pair_key_material, standard_pairing_context_v2,
};
use refineid_rapp_core::engine::{
    OperationOutcome, PairingError, Requester, RequesterConfig, SessionEnd, SessionError,
};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::presence::CardSighting;
use refineid_rapp_core::store::{MemoryPairingStore, PairingState, PairingStore};
use refineid_rapp_core::stream::{STREAM_CANDIDATE_ID, STREAM_PROFILE};
use refineid_rapp_core::transport::{FrameTransport, MemoryTransport, TransportError};
use sha2::{Digest as _, Sha256};

/// A generous deadline for scripted exchanges.
const DEADLINE: Duration = Duration::from_secs(2);
/// The candidate identifier every loopback connection reports: the
/// in-memory transport stands in for a stream connection.
const CANDIDATE: &str = STREAM_CANDIDATE_ID;
/// Test monotonic timestamp in milliseconds.
const TEST_MONOTONIC_TIMESTAMP_MS: u64 = 1_000_000;
/// The code the scripted custodian shows.
const SHOWN_CODE: &str = "7KX4M9";
/// Uniform bytes one `CPace` scalar is drawn from (section 6.1.1).
const CPACE_SCALAR_ENTROPY_BYTES: usize = 64;
/// Fixed custodian scalar entropy for the scripted exchange.
const CUSTODIAN_ENTROPY: &[u8; CPACE_SCALAR_ENTROPY_BYTES] =
    b"synthetic custodian cpace scalar entropy for a scripted pairing.";
/// The `session.ready` nonce the scripted custodian sends.
const READY_NONCE: [u8; SESSION_READY_NONCE_SIZE] = *b"synthetic custodian ready nonce!";
/// The authentication certificate the scripted custodian's card carries:
/// the CLI mock custodian's self-issued test certificate.
const CARD_CERTIFICATE: &[u8] = include_bytes!("../../refineid-rapp-cli/src/mock_cert.der");
/// The answer to reset the scripted custodian's card reports.
const CARD_ATR: &[u8] = b"synthetic answer to reset";
/// The signature the scripted custodian's card makes.
const CARD_SIGNATURE: &[u8] = b"synthetic signature";
/// The login challenge the requester asks the card to sign.
const LOGIN_CHALLENGE: &[u8] = b"synthetic login challenge";
/// An operation the requester never started.
const OTHER_OPERATION: OperationId = OperationId::from_array(*b"other operation!");
/// Lifetime of every scripted operation.
const OPERATION_LIFETIME_MS: u64 = 30_000;
/// Keep-alive rounds a requester waits for a scripted custodian's message.
const KEEP_ALIVE_ROUNDS: usize = 10;
/// The wall-clock time an earlier session heard the card present.
const EARLIER_SIGHTING_AT_MS: u64 = 1_700_000_000_000;

/// The requester engine type under test.
type TestRequester = Requester<MemoryPairingStore>;

fn test_requester() -> TestRequester {
    Requester::new(
        RequesterConfig {
            display_name: "Workstation".into(),
            platform: "Linux".into(),
        },
        MemoryPairingStore::new(),
    )
}

/// The fingerprint of the scripted card.
fn card_fingerprint() -> CertificateFingerprint {
    CertificateFingerprint::of_certificate(CARD_CERTIFICATE)
}

/// A registered consequential operation for the authentication tests.
fn authentication_operation() -> CardOperation {
    CardOperation::BrowserAuthenticate {
        origin: "kortti.tunnistautuminen.suomi.fi".into(),
        key_profile: KeyProfile::Rsa3072,
        algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
        digest: Sha256::digest(LOGIN_CHALLENGE).to_vec(),
    }
}

/// The custodian's random offer for the stream transport.
fn custodian_offer() -> refineid_rapp::PairingOffer {
    let mut offer_id = [0_u8; refineid_rapp::OFFER_ID_SIZE];
    getrandom::fill(&mut offer_id).unwrap();
    refineid_rapp::PairingOffer::create(
        refineid_rapp::OfferId::from_array(offer_id),
        ProfileName::ALL
            .iter()
            .map(|profile| profile.as_str().to_owned())
            .collect(),
        &[TransportProfile::Stream],
    )
    .unwrap()
}

/// Serves the offer bootstrap (RAPP v26.10.22 section 4.2) and returns the
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

/// Runs the custodian half of pairing and returns its stored half.
fn proxy_pair<T: FrameTransport>(transport: T, shown_code: &str) -> PairRecord {
    proxy_pair_confirming(transport, shown_code, true).unwrap()
}

/// The custodian half of pairing: the offer bootstrap, `CPace` KC2 as
/// responder, `Noise_XXpsk3` under its key, then the hello, confirmation,
/// and storage confirmation exchange. With `confirm_storage` false it stops
/// after its grant confirmation, as a custodian that died before storing
/// its record would, and returns nothing.
fn proxy_pair_confirming<T: FrameTransport>(
    mut transport: T,
    shown_code: &str,
    confirm_storage: bool,
) -> Option<PairRecord> {
    let now_ms = TEST_MONOTONIC_TIMESTAMP_MS;
    let candidate = transport.candidate_id().to_owned();
    let (offer, context) = serve_offer(&mut transport);

    let step_one = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    let (step_two, waiting) = CpaceKc2Responder::process_step1_frame(
        shown_code,
        &context,
        &offer.offer_id,
        &step_one,
        CUSTODIAN_ENTROPY,
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
    let (record, mut storage) = confirmation.into_storage(now_ms).unwrap();
    assert!(!record.is_storage_confirmed());
    if !confirm_storage {
        return None;
    }
    let stored = storage.send_stored().unwrap();
    transport.send_frame(stored.as_bytes()).unwrap();
    let requester_stored = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    storage.receive_stored(&requester_stored, now_ms).unwrap();
    Some(storage.into_active().unwrap().confirm(record).unwrap())
}

/// The scripted custodian's side of one established session.
struct ProxySession<T: FrameTransport> {
    endpoint: EstablishedEndpoint,
    transport: T,
}

impl<T: FrameTransport> ProxySession<T> {
    fn send(&mut self, message: &TypedMessage) {
        let frame = self.endpoint.send(message).unwrap();
        self.transport.send_frame(frame.as_bytes()).unwrap();
    }

    fn receive_outcome(&mut self, wait: Duration) -> ReceiveOutcome {
        let started = Instant::now();
        let frame_bytes = loop {
            match self.transport.receive_frame() {
                Ok(bytes) => break bytes,
                Err(TransportError::TimedOut) if started.elapsed() < wait => {}
                Err(error) => panic!("the requester sent nothing: {error:?}"),
            }
        };
        let frame = BinaryFrame::reconstruct(frame_bytes).unwrap();
        self.endpoint
            .receive(&frame, TEST_MONOTONIC_TIMESTAMP_MS)
            .unwrap()
    }

    fn receive(&mut self) -> TypedMessage {
        match self.receive_outcome(DEADLINE) {
            ReceiveOutcome::Message(message) => message,
            other => panic!("expected a message, got {other:?}"),
        }
    }

    fn receive_request(&mut self) -> refineid_rapp::OperationRequest {
        let TypedMessage::OperationRequest(request) = self.receive() else {
            panic!("expected an operation request");
        };
        request
    }
}

/// Runs the custodian's `Noise_KK` handshake as responder.
fn proxy_handshake<T: FrameTransport>(
    pair_record: &PairRecord,
    transport: &mut T,
) -> refineid_rapp::SessionAuthentication {
    let mut handshake =
        SessionHandshake::begin_proxy(pair_record, TransportProfile::Stream).unwrap();
    let m1 = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    handshake.read_message(&m1).unwrap();
    let m2 = handshake.write_message().unwrap();
    transport.send_frame(m2.as_bytes()).unwrap();
    handshake.into_authentication().unwrap()
}

/// Accepts one session as the custodian: the handshake, `session.ready`,
/// then the card status (section 8.4 item 1).
fn proxy_accept_session_with_card<T: FrameTransport>(
    pair_record: &PairRecord,
    mut transport: T,
    card: CardStatusMessage,
) -> ProxySession<T> {
    let mut authentication = proxy_handshake(pair_record, &mut transport);
    let ready = authentication.send_ready(READY_NONCE).unwrap();
    transport.send_frame(ready.as_bytes()).unwrap();
    let mut session = ProxySession {
        endpoint: authentication.into_established().unwrap(),
        transport,
    };
    session.send(&TypedMessage::CardStatus(card));
    session
}

/// Accepts one session as the custodian with its card present.
fn proxy_accept_session<T: FrameTransport>(
    pair_record: &PairRecord,
    transport: T,
) -> ProxySession<T> {
    proxy_accept_session_with_card(
        pair_record,
        transport,
        CardStatusMessage::Present(card_fingerprint()),
    )
}

/// Pairs a fresh requester with a custodian thread and returns both halves.
fn paired(requester: &mut TestRequester, granted: &[ProfileName]) -> (PairId, PairRecord) {
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
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy) = paired(&mut requester, &granted);
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.granted_profiles(), granted);
    assert_eq!(record.state(), PairingState::Serving);
    assert_eq!(record.peer().display_name, "Phone");
    assert!(record.serves());
    assert!(proxy.is_storage_confirmed());
    assert_eq!(
        record.pair_record().map(PairRecord::grants_hash),
        Some(proxy.grants_hash())
    );
}

#[test]
fn a_custodian_that_never_confirms_storage_leaves_nothing_stored() {
    let mut requester = test_requester();
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        assert!(proxy_pair_confirming(proxy_transport, SHOWN_CODE, false).is_none());
    });
    let outcome = requester.pair_with_code(SHOWN_CODE, requester_transport, |_, requested| {
        Some(requested.to_vec())
    });
    proxy.join().unwrap();
    assert_eq!(outcome, Err(PairingError::StorageUnconfirmed));
    assert!(requester.store().pair_ids().is_empty());
}

#[test]
fn the_card_status_is_noted_on_the_session() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session_with_card(
            &proxy_pairing,
            proxy_transport,
            CardStatusMessage::Absent,
        );
        session.send(&TypedMessage::CardStatus(CardStatusMessage::Present(
            card_fingerprint(),
        )));
        session
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    assert_eq!(session.card_status(), None);
    let expected = [
        CardStatusMessage::Absent,
        CardStatusMessage::Present(card_fingerprint()),
    ];
    let mut seen = Vec::new();
    for _ in 0..KEEP_ALIVE_ROUNDS {
        requester.keep_alive(&mut session).unwrap();
        if let Some(status) = session.card_status()
            && seen.last() != Some(&status)
        {
            seen.push(status);
        }
        if seen.len() == expected.len() {
            break;
        }
    }
    let _proxy_session = proxy.join().unwrap();
    assert_eq!(seen, expected);
    // The card heard present bounds what every local consumer is offered
    // (section 8.4 item 3).
    assert_eq!(
        requester
            .store()
            .card_sighting(pair_id)
            .map(|sighting| sighting.fingerprint()),
        Some(card_fingerprint())
    );
}

#[test]
fn a_card_reported_absent_leaves_the_last_sighting_as_it_was() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let earlier = CardSighting::new(card_fingerprint(), EARLIER_SIGHTING_AT_MS);
    requester
        .store_mut()
        .record_card_sighting(pair_id, earlier)
        .unwrap();
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        proxy_accept_session_with_card(&proxy_pairing, proxy_transport, CardStatusMessage::Absent)
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    while session.card_status().is_none() {
        requester.keep_alive(&mut session).unwrap();
    }
    let _proxy_session = proxy.join().unwrap();
    assert_eq!(session.card_status(), Some(CardStatusMessage::Absent));
    // Absence is never recorded: the offer ages out over the grace from the
    // last time the card was heard (section 8.4 item 3).
    assert_eq!(requester.store().card_sighting(pair_id), Some(earlier));
}

#[test]
fn a_silent_custodian_is_pinged_and_its_pong_keeps_the_session() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let wait = Duration::from_millis(LIVENESS_PING_AFTER_SILENCE_MS) + DEADLINE;
        let ReceiveOutcome::Message(TypedMessage::LivenessPing(ping)) =
            session.receive_outcome(wait)
        else {
            panic!("expected a liveness ping");
        };
        // The pong echoes the ping's challenge exactly (section 7.1 item 7).
        session.send(&TypedMessage::LivenessPong(ping));
        let ReceiveOutcome::Message(TypedMessage::SessionClose(close)) =
            session.receive_outcome(wait)
        else {
            panic!("expected the requester's close");
        };
        assert_eq!(close.reason, CloseReason::UserDisconnect);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let silence = Duration::from_millis(LIVENESS_PING_AFTER_SILENCE_MS);
    let started = Instant::now();
    while started.elapsed() < silence + DEADLINE {
        requester.keep_alive(&mut session).unwrap();
    }
    requester.disconnect(&mut session, CloseReason::UserDisconnect);
    proxy.join().unwrap();
    assert_eq!(session.end(), Some(SessionEnd::LocalClose));
}

#[test]
fn the_pin_prompt_is_reported_while_a_request_waits() {
    let mut requester = test_requester();
    let granted = [ProfileName::Authentication];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let request = session.receive_request();
        session.send(&TypedMessage::OperationProgress(OperationProgressMessage {
            operation_id: request.operation_id,
            event: ProgressEvent::ConsentShown,
        }));
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::failure(request.operation_id, ProxyFailure::UserDenied),
        ));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let mut seen = Vec::new();
    let outcome = requester
        .execute_observed(
            &mut session,
            &authentication_operation(),
            OPERATION_LIFETIME_MS,
            &mut |event| seen.push(event),
        )
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Rejected(ResultError::UserCancelled)
    );
    assert_eq!(seen, [ProgressEvent::ConsentShown]);
    assert_eq!(
        session.card_status(),
        Some(CardStatusMessage::Present(card_fingerprint()))
    );
}

#[test]
fn progress_for_another_operation_is_not_shown() {
    let mut requester = test_requester();
    let granted = [ProfileName::Authentication];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let request = session.receive_request();
        session.send(&TypedMessage::OperationProgress(OperationProgressMessage {
            operation_id: OTHER_OPERATION,
            event: ProgressEvent::ConsentShown,
        }));
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::failure(request.operation_id, ProxyFailure::UserDenied),
        ));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let mut seen = Vec::new();
    let outcome = requester
        .execute_observed(
            &mut session,
            &authentication_operation(),
            OPERATION_LIFETIME_MS,
            &mut |event| seen.push(event),
        )
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Rejected(ResultError::UserCancelled)
    );
    assert!(seen.is_empty());
}

#[test]
fn card_inspection_completes_as_a_read() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let request = session.receive_request();
        assert_eq!(request.profile, ProfileName::CardStatus);
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                request.operation_id,
                &CardOperationResult::Inspection(CardInspection {
                    answer_to_reset: CARD_ATR.to_vec(),
                }),
            ),
        ));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(
            &mut session,
            &CardOperation::InspectCard,
            OPERATION_LIFETIME_MS,
        )
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Completed(CardOperationResult::Inspection(CardInspection {
            answer_to_reset: CARD_ATR.to_vec(),
        }))
    );
}

#[test]
fn authentication_completes_with_its_signature() {
    let mut requester = test_requester();
    let granted = [ProfileName::Authentication];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let request = session.receive_request();
        assert!(request.operation.is_consequential());
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                request.operation_id,
                &CardOperationResult::Signature(CARD_SIGNATURE.to_vec()),
            ),
        ));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(
            &mut session,
            &authentication_operation(),
            OPERATION_LIFETIME_MS,
        )
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Completed(CardOperationResult::Signature(CARD_SIGNATURE.to_vec()))
    );
}

#[test]
fn a_denial_leaves_the_session_for_the_next_operation() {
    let mut requester = test_requester();
    let granted = [ProfileName::Authentication];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let first = session.receive_request();
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::failure(first.operation_id, ProxyFailure::UserDenied),
        ));
        let second = session.receive_request();
        assert_ne!(first.operation_id, second.operation_id);
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::failure(second.operation_id, ProxyFailure::RetryFloor),
        ));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let denied = requester
        .execute(
            &mut session,
            &authentication_operation(),
            OPERATION_LIFETIME_MS,
        )
        .unwrap();
    let floored = requester
        .execute(
            &mut session,
            &authentication_operation(),
            OPERATION_LIFETIME_MS,
        )
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(
        denied,
        OperationOutcome::Rejected(ResultError::UserCancelled)
    );
    assert_eq!(floored, OperationOutcome::Rejected(ResultError::RetryFloor));
}

#[test]
fn a_busy_custodian_refuses_the_request() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let request = session.receive_request();
        session.send(&TypedMessage::Error(ProtocolErrorMessage::busy(
            request.operation_id,
        )));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(
            &mut session,
            &CardOperation::InspectCard,
            OPERATION_LIFETIME_MS,
        )
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::Refused(ResultError::Busy));
}

#[test]
fn an_operation_ends_with_its_session_and_the_pairing_stays() {
    let mut requester = test_requester();
    let granted = [ProfileName::Authentication];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let _request = session.receive_request();
        // The transport dies with the request delivered and unanswered.
        drop(session);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(
            &mut session,
            &authentication_operation(),
            OPERATION_LIFETIME_MS,
        )
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::Lost);
    assert_eq!(session.end(), Some(SessionEnd::TransportLoss));
    assert!(requester.store().get(pair_id).unwrap().serves());
}

#[test]
fn a_violation_is_closed_with_its_notice_and_the_pairing_stays() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let request = session.receive_request();
        // A certificate does not answer an inspection.
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                request.operation_id,
                &CardOperationResult::Certificate(CARD_CERTIFICATE.to_vec()),
            ),
        ));
        let TypedMessage::SessionClose(close) = session.receive() else {
            panic!("expected the protocol_violation close");
        };
        assert_eq!(close.reason, CloseReason::ProtocolViolation);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(
            &mut session,
            &CardOperation::InspectCard,
            OPERATION_LIFETIME_MS,
        )
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::Lost);
    assert_eq!(session.end(), Some(SessionEnd::Violation));
    // No failure revokes a pairing (section 10.1).
    assert!(requester.store().get(pair_id).unwrap().serves());
}

#[test]
fn a_custodian_revocation_close_revokes_the_pairing() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let _request = session.receive_request();
        session.send(&TypedMessage::SessionClose(SessionCloseMessage {
            reason: CloseReason::PairingRevoked,
        }));
        // The requester answers with no close of its own (section 4.6 item 4).
        assert!(session.transport.receive_frame().is_err());
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(
            &mut session,
            &CardOperation::InspectCard,
            OPERATION_LIFETIME_MS,
        )
        .unwrap();
    drop(session);
    proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::Lost);
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.state(), PairingState::Revoked { by_peer: true });
    assert!(record.pair_record().is_none());
    let (requester_transport, _other) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert!(matches!(
        requester.connect(pair_id, requester_transport),
        Err(SessionError::NotPaired)
    ));
}

#[test]
fn a_revoking_custodian_closes_in_place_of_ready() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut authentication = proxy_handshake(&proxy_pairing, &mut proxy_transport);
        let notice = authentication.send_revocation_notice().unwrap();
        proxy_transport.send_frame(notice.as_bytes()).unwrap();
    });
    let outcome = requester.connect(pair_id, requester_transport);
    proxy.join().unwrap();
    assert!(matches!(
        outcome,
        Err(SessionError::ClosedByPeer(CloseReason::PairingRevoked))
    ));
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.state(), PairingState::Revoked { by_peer: true });
    assert!(record.pair_record().is_none());
}

#[test]
fn forgetting_in_session_sends_the_close_and_destroys_the_keys() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::SessionClose(close) = session.receive() else {
            panic!("expected the revocation close");
        };
        assert_eq!(close.reason, CloseReason::PairingRevoked);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    requester.forget_pairing_in_session(&mut session).unwrap();
    proxy.join().unwrap();
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.state(), PairingState::Revoked { by_peer: false });
    assert!(record.pair_record().is_none());
}

#[test]
fn a_forgotten_pairing_sends_the_close_as_its_next_sessions_first_message() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    requester.forget_pairing(pair_id).unwrap();
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.state(), PairingState::Forgotten);
    assert!(record.owes_revocation_notice());
    assert!(record.pair_record().is_some());
    let (requester_transport, _other) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert!(matches!(
        requester.connect(pair_id, requester_transport),
        Err(SessionError::Forgotten)
    ));

    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::SessionClose(close) = session.receive() else {
            panic!("expected the revocation close first");
        };
        assert_eq!(close.reason, CloseReason::PairingRevoked);
    });
    requester
        .deliver_revocation_notice(pair_id, requester_transport)
        .unwrap();
    proxy.join().unwrap();
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.state(), PairingState::Revoked { by_peer: false });
    assert!(record.pair_record().is_none());
    let (requester_transport, _other) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert_eq!(
        requester.deliver_revocation_notice(pair_id, requester_transport),
        Err(SessionError::NotForgotten)
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
            CUSTODIAN_ENTROPY,
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
fn stream_pairing_and_session_route_only_by_their_preambles() {
    use refineid_rapp::{RoutingKey, route_session};
    use refineid_rapp_core::stream::{DialPurpose, StreamAccept, StreamListener, dial};

    let listener = StreamListener::bind("127.0.0.1:0", STREAM_CANDIDATE_ID, DEADLINE).unwrap();
    let endpoints = vec![format!("127.0.0.1:{}", listener.local_port().unwrap())];
    let custodian = std::thread::spawn(move || {
        let StreamAccept::Pairing(transport) = listener.accept().unwrap() else {
            panic!("pairing opens with the pairing preamble");
        };
        let record = proxy_pair(transport, SHOWN_CODE);
        let StreamAccept::Session { routing, transport } = listener.accept().unwrap() else {
            panic!("a session opens with the session preamble");
        };
        let key = RoutingKey::derive(&record).unwrap();
        assert_eq!(
            route_session(&[key], TransportProfile::Stream, &routing),
            Some(0)
        );
        let mut session = proxy_accept_session(&record, transport);
        let request = session.receive_request();
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                request.operation_id,
                &CardOperationResult::Certificate(CARD_CERTIFICATE.to_vec()),
            ),
        ));
    });

    let mut requester = test_requester();
    let pairing = dial(
        &endpoints,
        STREAM_CANDIDATE_ID,
        DEADLINE,
        DialPurpose::Pairing,
    )
    .unwrap();
    let pair_id = requester
        .pair_with_code(SHOWN_CODE, pairing, |_, requested| Some(requested.to_vec()))
        .unwrap();
    let key = RoutingKey::derive(
        requester
            .store()
            .get(pair_id)
            .unwrap()
            .pair_record()
            .unwrap(),
    )
    .unwrap();
    let transport = dial(
        &endpoints,
        STREAM_CANDIDATE_ID,
        DEADLINE,
        DialPurpose::Session(&key),
    )
    .unwrap();
    let mut session = requester.connect(pair_id, transport).unwrap();
    let outcome = requester
        .execute(
            &mut session,
            &CardOperation::ReadCertificate {
                kind: refineid_rapp::CertificateKind::Authentication,
            },
            OPERATION_LIFETIME_MS,
        )
        .unwrap();
    custodian.join().unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Completed(CardOperationResult::Certificate(CARD_CERTIFICATE.to_vec()))
    );
}
