//! Loopback conformance tests: the requester engine against a scripted
//! custodian speaking the same wire through `refineid_rapp`.
//!
//! The custodian here is test scaffolding, not a product: the real
//! custodians are the holder's phones. It speaks the exact wire of RAPP
//! v26.10.29 so the requester is exercised end to end: code pairing through
//! `CPace` KC2 and `Noise_XXpsk3` with grant agreement and the storage
//! confirmation, `Noise_KK` sessions with the Custodian's `session.ready`
//! and card status, operations and their results inside their session,
//! liveness, revocation in both directions, the sealed
//! `protocol_violation` close that leaves the pairing in place, and the
//! session times idle expiry counts from.

#![allow(
    clippy::unwrap_used,
    reason = "test scaffolding is constructed to be infallible"
)]
#![allow(
    clippy::missing_panics_doc,
    reason = "tests panic to fail; documenting each panic adds nothing"
)]

use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use refineid_rapp::{
    BinaryFrame, CPACE_ATTEMPT_WINDOW_MS, CardInspection, CardKeyProfile as KeyProfile,
    CardOperation, CardOperationResult, CardPresence, CardReader, CardStatusMessage,
    CertificateFingerprint, CloseReason, CpaceKc2Responder, EndpointRole, EstablishedEndpoint,
    LIVENESS_PING_AFTER_SILENCE_MS, OFFER_ID_SIZE, OfferId, OperationId, OperationProgressMessage,
    OperationResultMessage, PAIRING_CANDIDATES_MAX, PAIRING_IDLE_EXPIRY_MS,
    PRE_AUTHENTICATION_SPACING_MS, PairRecord, PairingBusy, PairingHandshake, PairingOffer,
    ProfileName, ProgressEvent, ProtocolErrorMessage, ProxyFailure, QUIT_WITHDRAWAL_BOUND_MS,
    ReceiveOutcome, ResultError, SESSION_READY_NONCE_SIZE, SessionCloseMessage, SessionHandshake,
    SignatureAlgorithm, TransportProfile, TypedMessage, generate_pair_key_material,
    standard_pairing_context_v2,
};
use refineid_rapp_core::clock::unix_time_ms;
use refineid_rapp_core::engine::{
    OpenedConnection, OperationOutcome, PairingCandidateSource, PairingConnection, PairingError,
    PairingSearchError, Requester, RequesterConfig, SESSION_RECEIVE_TICK, SessionEnd, SessionError,
    Withdrawal, read_bootstrap_answer,
};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::offer::{BootstrapAnswer, read_bootstrap};
use refineid_rapp_core::presence::CardSighting;
use refineid_rapp_core::store::{
    MemoryPairingStore, PairingRecord, PairingState, PairingStore, StoreError, SweepError,
    SweepOutcome, sweep_pairings,
};
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
/// The code another phone in pairing mode shows.
const OTHER_CODE: &str = "7KX4MA";
/// The offer one custodian serves on each endpoint it is found on.
const SHARED_OFFER_ID: [u8; OFFER_ID_SIZE] = *b"synthetic offer of one custodian";
/// The endpoint of the first scripted custodian a search finds.
const FIRST_ENDPOINT: usize = 0;
/// The endpoint of the second scripted custodian a search finds.
const SECOND_ENDPOINT: usize = 1;
/// The wait a busy scripted custodian asks for: its admission spacing.
const BUSY_WAIT_MS: u64 = PRE_AUTHENTICATION_SPACING_MS;
/// The discovery round that finds the custodians present at the start.
const FIRST_ROUND: usize = 1;
/// The discovery round that finds the custodians that arrive later.
const SECOND_ROUND: usize = 2;
/// The least wait a busy custodian may ask for.
const LEAST_BUSY_WAIT_MS: u64 = refineid_rapp::PAIRING_BUSY_RETRY_AFTER_MIN_MS;
/// How long a scripted custodian waits for the requester while it tries
/// another custodian first: longer than the attempt deadline.
const OUTLASTS_ATTEMPT: Duration = Duration::from_secs(10);
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

/// The custodian's report of the scripted card, read over NFC with no card
/// reader attached.
fn card_present() -> CardStatusMessage {
    CardStatusMessage {
        card: CardPresence::Present(card_fingerprint()),
        reader: CardReader::Absent,
    }
}

/// The custodian's report of no card, with `reader` as its card reader
/// stands.
const fn card_absent(reader: CardReader) -> CardStatusMessage {
    CardStatusMessage {
        card: CardPresence::Absent,
        reader,
    }
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
fn custodian_offer() -> PairingOffer {
    let mut offer_id = [0_u8; OFFER_ID_SIZE];
    getrandom::fill(&mut offer_id).unwrap();
    custodian_offer_with(OfferId::from_array(offer_id))
}

/// As [`custodian_offer`], under `offer_id`.
fn custodian_offer_with(offer_id: OfferId) -> PairingOffer {
    PairingOffer::create(
        offer_id,
        ProfileName::ALL
            .iter()
            .map(|profile| profile.as_str().to_owned())
            .collect(),
        &[TransportProfile::Stream],
    )
    .unwrap()
}

/// Serves a random offer's bootstrap (RAPP v26.10.29 section 4.2) and
/// returns the offer and its `CPace` context.
fn serve_offer<T: FrameTransport>(transport: &mut T) -> (PairingOffer, Vec<u8>) {
    let offer = custodian_offer();
    let context = serve_this_offer(transport, &offer);
    (offer, context)
}

/// Serves the bootstrap of `offer` and returns its `CPace` context.
fn serve_this_offer<T: FrameTransport>(transport: &mut T, offer: &PairingOffer) -> Vec<u8> {
    transport.send_frame(&offer.to_cbor().unwrap()).unwrap();
    standard_pairing_context_v2(
        &offer.offer_hash().unwrap(),
        STREAM_PROFILE,
        STREAM_CANDIDATE_ID,
    )
    .unwrap()
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
    proxy_accept_session_with_card(pair_record, transport, card_present())
}

/// Pairs a fresh requester with a custodian thread and returns both halves.
fn paired<Store: PairingStore>(
    requester: &mut Requester<Store>,
    granted: &[ProfileName],
) -> (PairId, PairRecord) {
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || proxy_pair(proxy_transport, SHOWN_CODE));
    let (pair_id, ()) = requester
        .pair_with_code(
            "7k x4-m9",
            &mut OpenedConnection::new(requester_transport),
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
    let outcome = requester.pair_with_code(
        SHOWN_CODE,
        &mut OpenedConnection::new(requester_transport),
        |_, requested| Some(requested.to_vec()),
    );
    proxy.join().unwrap();
    assert_eq!(
        outcome,
        Err(PairingSearchError::Ceremony(
            PairingError::StorageUnconfirmed
        ))
    );
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
            card_absent(CardReader::Absent),
        );
        session.send(&TypedMessage::CardStatus(card_absent(CardReader::Attached)));
        session.send(&TypedMessage::CardStatus(card_present()));
        session
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    assert_eq!(session.card_status(), None);
    // A reader attached to the phone is a report of its own (section 8.4
    // item 1).
    let expected = [
        card_absent(CardReader::Absent),
        card_absent(CardReader::Attached),
        card_present(),
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
        proxy_accept_session_with_card(
            &proxy_pairing,
            proxy_transport,
            card_absent(CardReader::Absent),
        )
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    while session.card_status().is_none() {
        requester.keep_alive(&mut session).unwrap();
    }
    let _proxy_session = proxy.join().unwrap();
    assert_eq!(session.card_status(), Some(card_absent(CardReader::Absent)));
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
    assert_eq!(session.card_status(), Some(card_present()));
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

/// The quit bound of RAPP v26.10.29 section 4.5 item 8.
const QUIT_BOUND: Duration = Duration::from_millis(QUIT_WITHDRAWAL_BOUND_MS);

/// A requester that follows `withdrawal`.
fn withdrawing_requester(withdrawal: &Withdrawal) -> TestRequester {
    test_requester().following(withdrawal.clone())
}

/// Receives the requester's close on the custodian's side of a session.
fn receive_close<T: FrameTransport>(session: &mut ProxySession<T>) -> CloseReason {
    let TypedMessage::SessionClose(close) = session.receive() else {
        panic!("expected the requester's close");
    };
    close.reason
}

#[test]
fn a_withdrawal_closes_the_open_session_and_keeps_the_pairing() {
    let withdrawal = Withdrawal::new();
    let mut requester = withdrawing_requester(&withdrawal);
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        receive_close(&mut session)
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    withdrawal.raise();
    assert_eq!(
        requester.keep_alive(&mut session),
        Err(SessionError::Ended(SessionEnd::LocalClose))
    );
    assert_eq!(proxy.join().unwrap(), CloseReason::ServiceWithdrawn);
    assert!(requester.store().get(pair_id).unwrap().serves());
}

#[test]
fn a_withdrawal_ends_the_operation_whose_prompt_is_up() {
    let withdrawal = Withdrawal::new();
    let mut requester = withdrawing_requester(&withdrawal);
    let granted = [ProfileName::Authentication];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let request = session.receive_request();
        withdrawal.raise();
        session.send(&TypedMessage::OperationProgress(OperationProgressMessage {
            operation_id: request.operation_id,
            event: ProgressEvent::ConsentShown,
        }));
        receive_close(&mut session)
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(
            &mut session,
            &authentication_operation(),
            OPERATION_LIFETIME_MS,
        )
        .unwrap();
    assert_eq!(proxy.join().unwrap(), CloseReason::ServiceWithdrawn);
    assert_eq!(outcome, OperationOutcome::Lost);
    assert_eq!(session.end(), Some(SessionEnd::LocalClose));
    assert!(requester.store().get(pair_id).unwrap().serves());
}

#[test]
fn a_quitting_requester_waits_only_until_its_close_is_written() {
    let withdrawal = Withdrawal::new();
    let mut requester = withdrawing_requester(&withdrawal);
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        receive_close(&mut session)
    });
    requester_transport
        .set_receive_deadline(SESSION_RECEIVE_TICK)
        .unwrap();
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let holder = std::thread::spawn(move || {
        while requester.keep_alive(&mut session).is_ok() {}
        (requester, session.end())
    });
    assert!(withdrawal.raise_and_wait(QUIT_BOUND));
    let (requester, end) = holder.join().unwrap();
    assert_eq!(end, Some(SessionEnd::LocalClose));
    assert_eq!(proxy.join().unwrap(), CloseReason::ServiceWithdrawn);
    assert!(requester.store().get(pair_id).unwrap().serves());
}

#[test]
fn a_quitting_requester_with_no_session_open_does_not_wait() {
    let withdrawal = Withdrawal::new();
    let started = Instant::now();
    assert!(withdrawal.raise_and_wait(QUIT_BOUND));
    assert!(started.elapsed() < QUIT_BOUND);
    assert!(withdrawal.is_raised());
}

#[test]
fn a_session_ready_as_the_requester_withdraws_gets_the_close() {
    let withdrawal = Withdrawal::new();
    let mut requester = withdrawing_requester(&withdrawal);
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut authentication = proxy_handshake(&proxy_pairing, &mut proxy_transport);
        withdrawal.raise();
        let ready = authentication.send_ready(READY_NONCE).unwrap();
        proxy_transport.send_frame(ready.as_bytes()).unwrap();
        let mut session = ProxySession {
            endpoint: authentication.into_established().unwrap(),
            transport: proxy_transport,
        };
        receive_close(&mut session)
    });
    assert!(matches!(
        requester.connect(pair_id, requester_transport),
        Err(SessionError::Withdrawn)
    ));
    assert_eq!(proxy.join().unwrap(), CloseReason::ServiceWithdrawn);
    assert!(requester.store().get(pair_id).unwrap().serves());
}

#[test]
fn a_withdrawn_requester_dials_no_session_and_no_revocation_notice() {
    let withdrawal = Withdrawal::new();
    let mut requester = withdrawing_requester(&withdrawal);
    let granted = [ProfileName::CardStatus];
    let (pair_id, _proxy_pairing) = paired(&mut requester, &granted);
    withdrawal.raise();
    assert!(requester.withdrawn());

    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert!(matches!(
        requester.connect(pair_id, requester_transport),
        Err(SessionError::Withdrawn)
    ));
    assert_eq!(proxy_transport.receive_frame(), Err(TransportError::Eof));
    assert!(requester.store().get(pair_id).unwrap().serves());

    requester.forget_pairing(pair_id).unwrap();
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert_eq!(
        requester.deliver_revocation_notice(pair_id, requester_transport),
        Err(SessionError::Withdrawn)
    );
    assert_eq!(proxy_transport.receive_frame(), Err(TransportError::Eof));
    assert!(
        requester
            .store()
            .get(pair_id)
            .unwrap()
            .owes_revocation_notice()
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
    let outcome = requester.pair_with_code(
        OTHER_CODE,
        &mut OpenedConnection::new(requester_transport),
        |_, _| panic!("an unauthenticated attempt must never reach confirmation"),
    );
    proxy.join().unwrap();
    assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
    assert!(requester.store().pair_ids().is_empty());
}

#[test]
fn input_that_is_not_a_code_never_touches_the_transport() {
    let mut requester = test_requester();
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let outcome = requester.pair_with_code(
        "7KX4MU",
        &mut OpenedConnection::new(requester_transport),
        |_, _| None,
    );
    assert_eq!(outcome, Err(PairingSearchError::InvalidCode));
    assert!(proxy_transport.receive_frame().is_err());
}

/// What a scripted custodian does on its half of one pairing connection.
type CustodianScript = Box<dyn FnOnce(MemoryTransport) + Send>;

/// Custodians in pairing mode at scripted endpoints, found in the first
/// discovery round except those in `found_later`, which the second round
/// finds. Each endpoint holds the connections it answers, in the order
/// they are opened.
struct ScriptedCustodians {
    connections: Vec<Vec<MemoryTransport>>,
    found_later: Vec<usize>,
    rounds: usize,
    /// The endpoints opened, in the order opened.
    opened: Vec<usize>,
}

impl PairingCandidateSource for ScriptedCustodians {
    type Endpoint = usize;
    type Transport = MemoryTransport;

    fn discover(&mut self) -> Option<Vec<usize>> {
        self.rounds += 1;
        match self.rounds {
            FIRST_ROUND => Some(
                (0..self.connections.len())
                    .filter(|endpoint| !self.found_later.contains(endpoint))
                    .collect(),
            ),
            SECOND_ROUND if !self.found_later.is_empty() => {
                Some(std::mem::take(&mut self.found_later))
            }
            _ => None,
        }
    }

    fn open(&mut self, endpoint: &usize) -> Option<PairingConnection<MemoryTransport>> {
        let connections = self.connections.get_mut(*endpoint)?;
        if connections.is_empty() {
            return None;
        }
        let transport = connections.remove(FIRST_ENDPOINT);
        self.opened.push(*endpoint);
        read_bootstrap_answer(transport).ok()
    }
}

/// One scripted endpoint per script, each custodian on its own thread.
fn scripted(scripts: Vec<CustodianScript>) -> (ScriptedCustodians, Vec<JoinHandle<()>>) {
    scripted_endpoints(scripts.into_iter().map(|script| vec![script]).collect())
}

/// One scripted endpoint per list of scripts, one script for each
/// connection opened to it, each on its own thread.
fn scripted_endpoints(
    endpoints: Vec<Vec<CustodianScript>>,
) -> (ScriptedCustodians, Vec<JoinHandle<()>>) {
    let mut connections = Vec::new();
    let mut custodians = Vec::new();
    for scripts in endpoints {
        let mut endpoint = Vec::new();
        for script in scripts {
            let (requester_side, custodian_side) = MemoryTransport::pair(CANDIDATE, DEADLINE);
            endpoint.push(requester_side);
            custodians.push(std::thread::spawn(move || script(custodian_side)));
        }
        connections.push(endpoint);
    }
    let source = ScriptedCustodians {
        connections,
        found_later: Vec::new(),
        rounds: 0,
        opened: Vec::new(),
    };
    (source, custodians)
}

fn join(custodians: Vec<JoinHandle<()>>) {
    for custodian in custodians {
        custodian.join().unwrap();
    }
}

/// A custodian showing `shown_code` and serving `offer`: it answers `CPace`
/// step 1, and the requester, refusing its `T_B`, closes the connection.
fn refusing_custodian(mut transport: MemoryTransport, offer: &PairingOffer, shown_code: &str) {
    let context = serve_this_offer(&mut transport, offer);
    let step_one = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    let (step_two, _waiting) = CpaceKc2Responder::process_step1_frame(
        shown_code,
        &context,
        &offer.offer_id,
        &step_one,
        CUSTODIAN_ENTROPY,
    )
    .unwrap();
    transport.send_frame(step_two.as_bytes()).unwrap();
    assert_eq!(transport.receive_frame(), Err(TransportError::Eof));
}

/// A custodian showing another code, as a script.
fn refusing() -> CustodianScript {
    Box::new(|transport| refusing_custodian(transport, &custodian_offer(), OTHER_CODE))
}

/// The custodian showing the code, as a script that waits out the tries
/// of the custodians before it.
fn accepting() -> CustodianScript {
    Box::new(|mut transport| {
        transport.set_receive_deadline(OUTLASTS_ATTEMPT).unwrap();
        proxy_pair(transport, SHOWN_CODE);
    })
}

/// A custodian serving `offer` whose connection the requester closes
/// without sending `CPace` step 1.
fn untried_custodian(mut transport: MemoryTransport, offer: &PairingOffer) {
    serve_this_offer(&mut transport, offer);
    assert_eq!(transport.receive_frame(), Err(TransportError::Eof));
}

#[test]
fn a_refusal_moves_on_to_the_phone_that_shows_the_code() {
    let mut requester = test_requester();
    let (mut custodians, threads) = scripted(vec![refusing(), accepting()]);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |peer, requested| {
        assert_eq!(peer.display_name, "Phone");
        Some(requested.to_vec())
    });
    join(threads);
    let (pair_id, endpoint) = outcome.unwrap();
    assert_eq!(endpoint, SECOND_ENDPOINT);
    assert!(requester.store().get(pair_id).unwrap().serves());
}

#[test]
fn the_code_is_not_accepted_only_after_every_phone_refused_it() {
    let mut requester = test_requester();
    let (mut custodians, threads) = scripted(vec![refusing(), refusing()]);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, _| {
        panic!("no phone showing another code reaches confirmation")
    });
    join(threads);
    assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
    assert_eq!(custodians.opened.len(), custodians.connections.len());
    assert_eq!(
        PairingSearchError::NotAccepted.to_string(),
        "the code was not accepted"
    );
    assert!(requester.store().pair_ids().is_empty());
}

#[test]
fn a_phone_found_on_two_endpoints_receives_one_guess() {
    let mut requester = test_requester();
    let offer = custodian_offer_with(OfferId::from_array(SHARED_OFFER_ID));
    let again = offer.clone();
    let (mut custodians, threads) = scripted(vec![
        Box::new(move |transport| refusing_custodian(transport, &offer, OTHER_CODE)),
        Box::new(move |transport| untried_custodian(transport, &again)),
    ]);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, _| {
        panic!("a refused phone never reaches confirmation")
    });
    join(threads);
    assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
}

#[test]
fn a_phone_silent_past_the_attempt_deadline_is_passed_over() {
    let mut requester = test_requester();
    let silent: CustodianScript = Box::new(|mut transport| {
        transport.set_receive_deadline(OUTLASTS_ATTEMPT).unwrap();
        serve_offer(&mut transport);
        assert!(transport.receive_frame().is_ok());
        assert_eq!(transport.receive_frame(), Err(TransportError::Eof));
    });
    let (mut custodians, threads) = scripted(vec![silent, accepting()]);
    let started = Instant::now();
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, requested| {
        Some(requested.to_vec())
    });
    join(threads);
    assert_eq!(outcome.map(|(_, endpoint)| endpoint), Ok(SECOND_ENDPOINT));
    assert!(started.elapsed() >= Duration::from_millis(CPACE_ATTEMPT_WINDOW_MS));
}

#[test]
fn a_search_opens_at_most_the_limit_of_connections() {
    let mut requester = test_requester();
    let mut scripts: Vec<CustodianScript> =
        (0..PAIRING_CANDIDATES_MAX).map(|_| refusing()).collect();
    scripts.push(Box::new(drop));
    let (mut custodians, threads) = scripted(scripts);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, _| {
        panic!("no phone showing another code reaches confirmation")
    });
    join(threads);
    assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
    assert_eq!(custodians.opened.len(), PAIRING_CANDIDATES_MAX);
}

/// A custodian that cannot admit an attempt: it answers `pairing-busy`
/// asking for `wait_ms` at bootstrap and closes the connection.
fn busy_at_bootstrap(wait_ms: u64) -> CustodianScript {
    Box::new(move |mut transport| {
        let busy = PairingBusy::new(wait_ms).unwrap();
        transport.send_frame(&busy.to_cbor().unwrap()).unwrap();
    })
}

/// A custodian that served its offer and then admitted another attempt:
/// it answers `CPace` step 1 with `pairing-busy` in place of step 2.
fn busy_in_place_of_step_two() -> CustodianScript {
    Box::new(|mut transport| {
        serve_offer(&mut transport);
        assert!(transport.receive_frame().is_ok());
        let busy = PairingBusy::new(BUSY_WAIT_MS).unwrap();
        transport.send_frame(&busy.to_cbor().unwrap()).unwrap();
    })
}

#[test]
fn a_busy_phone_is_asked_again_after_the_others_and_its_wait() {
    let mut requester = test_requester();
    let (mut custodians, threads) = scripted_endpoints(vec![
        vec![busy_at_bootstrap(BUSY_WAIT_MS), accepting()],
        vec![refusing()],
    ]);
    let started = Instant::now();
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, requested| {
        Some(requested.to_vec())
    });
    join(threads);
    assert_eq!(outcome.map(|(_, endpoint)| endpoint), Ok(FIRST_ENDPOINT));
    assert_eq!(
        custodians.opened,
        [FIRST_ENDPOINT, SECOND_ENDPOINT, FIRST_ENDPOINT]
    );
    assert!(started.elapsed() >= Duration::from_millis(BUSY_WAIT_MS));
}

#[test]
fn a_phone_found_during_a_busy_wait_is_opened_before_the_busy_one() {
    let mut requester = test_requester();
    let (mut custodians, threads) = scripted_endpoints(vec![
        vec![busy_at_bootstrap(BUSY_WAIT_MS), Box::new(drop)],
        vec![accepting()],
    ]);
    custodians.found_later = vec![SECOND_ENDPOINT];
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, requested| {
        Some(requested.to_vec())
    });
    assert_eq!(outcome.map(|(_, endpoint)| endpoint), Ok(SECOND_ENDPOINT));
    assert_eq!(custodians.opened, [FIRST_ENDPOINT, SECOND_ENDPOINT]);
    join(threads);
}

#[test]
fn a_busy_answer_in_place_of_step_two_is_not_a_try() {
    let mut requester = test_requester();
    let (mut custodians, threads) =
        scripted_endpoints(vec![vec![busy_in_place_of_step_two(), accepting()]]);
    let started = Instant::now();
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, requested| {
        Some(requested.to_vec())
    });
    join(threads);
    assert_eq!(outcome.map(|(_, endpoint)| endpoint), Ok(FIRST_ENDPOINT));
    assert_eq!(custodians.opened, [FIRST_ENDPOINT, FIRST_ENDPOINT]);
    assert!(started.elapsed() >= Duration::from_millis(BUSY_WAIT_MS));
}

#[test]
fn a_phone_busy_at_the_limit_has_not_accepted_the_code() {
    let mut requester = test_requester();
    let (mut custodians, threads) = scripted_endpoints(vec![
        (0..=PAIRING_CANDIDATES_MAX)
            .map(|_| busy_at_bootstrap(LEAST_BUSY_WAIT_MS))
            .collect(),
    ]);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, _| {
        panic!("a busy phone never reaches confirmation")
    });
    join(threads);
    assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
    assert_eq!(custodians.opened.len(), PAIRING_CANDIDATES_MAX);
}

/// One custodian that answers busy for the longest wait, and a user who
/// stops the search `stop_after` the connection.
struct StoppedWhileBusy {
    connection: Option<MemoryTransport>,
    stop_after: Duration,
    stop_at: Option<Instant>,
}

impl PairingCandidateSource for StoppedWhileBusy {
    type Endpoint = ();
    type Transport = MemoryTransport;

    fn stopped(&self) -> bool {
        self.stop_at
            .is_some_and(|stop_at| Instant::now() >= stop_at)
    }

    fn discover(&mut self) -> Option<Vec<()>> {
        self.connection.is_some().then(|| vec![()])
    }

    fn open(&mut self, _endpoint: &()) -> Option<PairingConnection<MemoryTransport>> {
        let transport = self.connection.take()?;
        self.stop_at = Some(Instant::now() + self.stop_after);
        read_bootstrap_answer(transport).ok()
    }
}

#[test]
fn stopping_during_a_busy_wait_ends_the_search_within_a_tick() {
    let (requester_side, custodian_side) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let custodian = std::thread::spawn(move || {
        busy_at_bootstrap(refineid_rapp::PAIRING_BUSY_RETRY_AFTER_MAX_MS)(custodian_side);
    });
    let stop_after = Duration::from_millis(BUSY_WAIT_MS);
    let mut source = StoppedWhileBusy {
        connection: Some(requester_side),
        stop_after,
        stop_at: None,
    };
    let started = Instant::now();
    let outcome = test_requester().pair_with_code(SHOWN_CODE, &mut source, |_, _| {
        panic!("a busy phone never reaches confirmation")
    });
    custodian.join().unwrap();
    assert_eq!(outcome, Err(PairingSearchError::Stopped));
    assert!(started.elapsed() < stop_after + SESSION_RECEIVE_TICK + SESSION_RECEIVE_TICK);
}

/// A connection whose custodian, while `refusing`, refuses every write, as
/// a BLE custodian refuses a `CPace` step 1 it cannot admit with the ATT
/// error `0x80`.
struct StepOneRefusal {
    transport: MemoryTransport,
    refusing: bool,
}

impl FrameTransport for StepOneRefusal {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if self.refusing {
            return Err(TransportError::Refused);
        }
        self.transport.send_frame(frame)
    }

    fn receive_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        self.transport.receive_frame()
    }

    fn set_receive_deadline(&mut self, deadline: Duration) -> Result<Duration, TransportError> {
        self.transport.set_receive_deadline(deadline)
    }

    fn profile(&self) -> &str {
        self.transport.profile()
    }

    fn candidate_id(&self) -> &str {
        self.transport.candidate_id()
    }
}

/// One BLE-like custodian: its first connection serves an offer, refuses
/// `CPace` step 1, and answers the bootstrap read that follows with
/// `then`; its second connection is the custodian showing the code.
struct RefusingStepOne {
    first: Option<(MemoryTransport, MemoryTransport)>,
    then: Option<BootstrapAnswer>,
    second: Option<MemoryTransport>,
}

impl RefusingStepOne {
    fn new(then: BootstrapAnswer) -> (Self, JoinHandle<()>) {
        let (second, custodian) = MemoryTransport::pair(CANDIDATE, DEADLINE);
        let accepting = std::thread::spawn(move || accepting()(custodian));
        let source = Self {
            first: Some(MemoryTransport::pair(CANDIDATE, DEADLINE)),
            then: Some(then),
            second: Some(second),
        };
        (source, accepting)
    }
}

impl PairingCandidateSource for RefusingStepOne {
    type Endpoint = ();
    type Transport = StepOneRefusal;

    fn discover(&mut self) -> Option<Vec<()>> {
        self.first.is_some().then(|| vec![()])
    }

    fn open(&mut self, _endpoint: &()) -> Option<PairingConnection<StepOneRefusal>> {
        let Some((requester_side, mut custodian)) = self.first.take() else {
            return read_bootstrap_answer(StepOneRefusal {
                transport: self.second.take()?,
                refusing: false,
            })
            .ok();
        };
        serve_offer(&mut custodian);
        let again = match self.then.take()? {
            BootstrapAnswer::Offer(offer) => offer.to_cbor().unwrap(),
            BootstrapAnswer::Busy(busy) => busy.to_cbor().unwrap(),
        };
        custodian.send_frame(&again).unwrap();
        read_bootstrap_answer(StepOneRefusal {
            transport: requester_side,
            refusing: true,
        })
        .ok()
    }

    fn bootstrap_again(&mut self, transport: &mut StepOneRefusal) -> Option<BootstrapAnswer> {
        read_bootstrap(&mut transport.transport).ok()
    }
}

#[test]
fn a_refused_step_one_reads_the_bootstrap_again_as_a_busy_refusal() {
    for then in [
        BootstrapAnswer::Busy(PairingBusy::new(BUSY_WAIT_MS).unwrap()),
        BootstrapAnswer::Offer(custodian_offer()),
    ] {
        let mut requester = test_requester();
        let (mut custodian, accepting) = RefusingStepOne::new(then);
        let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodian, |_, requested| {
            Some(requested.to_vec())
        });
        accepting.join().unwrap();
        assert!(outcome.is_ok());
    }
}

#[test]
fn a_search_that_tried_no_phone_finds_none_in_pairing_mode() {
    let mut requester = test_requester();
    let (mut nobody, _) = scripted(Vec::new());
    assert_eq!(
        requester.pair_with_code(SHOWN_CODE, &mut nobody, |_, _| None),
        Err(PairingSearchError::NoneInPairingMode)
    );
    let (mut offerless, threads) = scripted(vec![Box::new(drop)]);
    assert_eq!(
        requester.pair_with_code(SHOWN_CODE, &mut offerless, |_, _| None),
        Err(PairingSearchError::NoneInPairingMode)
    );
    join(threads);
    assert_eq!(
        PairingSearchError::NoneInPairingMode.to_string(),
        "no phone in pairing mode was found"
    );
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
    let (pair_id, ()) = requester
        .pair_with_code(
            SHOWN_CODE,
            &mut OpenedConnection::new(pairing),
            |_, requested| Some(requested.to_vec()),
        )
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

/// The last moment before a limit is reached.
const JUST_BEFORE_MS: u64 = 1;

/// A pairing store that notes each idle-expiry check made on it, and
/// refuses them while `refusing`, as a backing store that cannot write
/// does; everything else is the in-memory store's.
#[derive(Debug, Default)]
struct WatchedStore {
    inner: MemoryPairingStore,
    /// Each check made: on which pairing, and whether as in session.
    checks: Vec<(PairId, bool)>,
    refusing: bool,
}

impl PairingStore for WatchedStore {
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
        self.inner.insert(record)
    }

    fn get(&self, pair_id: PairId) -> Result<&PairingRecord, StoreError> {
        self.inner.get(pair_id)
    }

    fn update(
        &mut self,
        pair_id: PairId,
        change: &mut dyn FnMut(&mut PairingRecord),
    ) -> Result<(), StoreError> {
        self.inner.update(pair_id, change)
    }

    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        self.inner.remove(pair_id)
    }

    fn pair_ids(&self) -> Vec<PairId> {
        self.inner.pair_ids()
    }

    fn card_sighting(&self, pair_id: PairId) -> Option<CardSighting> {
        self.inner.card_sighting(pair_id)
    }

    fn record_card_sighting(
        &mut self,
        pair_id: PairId,
        sighting: CardSighting,
    ) -> Result<(), StoreError> {
        self.inner.record_card_sighting(pair_id, sighting)
    }

    fn sweep(
        &mut self,
        pair_id: PairId,
        now_ms: u64,
        session_established: bool,
    ) -> Result<SweepOutcome, SweepError<StoreError>> {
        self.checks.push((pair_id, session_established));
        if self.refusing {
            return Err(SweepError::Store(StoreError::WriteRefused));
        }
        self.inner.sweep(pair_id, now_ms, session_established)
    }
}

/// A requester over a [`WatchedStore`].
fn watched_requester() -> Requester<WatchedStore> {
    Requester::new(
        RequesterConfig {
            display_name: "Workstation".into(),
            platform: "Linux".into(),
        },
        WatchedStore::default(),
    )
}

/// The latest time a session to `pair_id` was recorded established.
fn last_session_at_ms<Store: PairingStore>(
    requester: &Requester<Store>,
    pair_id: PairId,
) -> Option<u64> {
    requester
        .store()
        .get(pair_id)
        .ok()?
        .pair_record()?
        .last_session_at_ms()
}

#[test]
fn a_session_records_its_time_when_established_and_when_it_ends() {
    let mut requester = watched_requester();
    let (pair_id, proxy_pairing) = paired(&mut requester, &[ProfileName::CardStatus]);
    assert_eq!(last_session_at_ms(&requester, pair_id), None);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || proxy_accept_session(&proxy_pairing, proxy_transport));
    let before_ms = unix_time_ms();
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let _custodian = proxy.join().unwrap();
    assert_eq!(requester.store().checks, [(pair_id, true)]);
    let established_at_ms = last_session_at_ms(&requester, pair_id).unwrap();
    assert!(established_at_ms >= before_ms);

    requester.keep_alive(&mut session).unwrap();
    assert_eq!(
        requester.store().checks.len(),
        1,
        "an open session records again only a day later"
    );

    requester.disconnect(&mut session, CloseReason::UserDisconnect);
    assert_eq!(requester.store().checks, [(pair_id, true), (pair_id, true)]);
    assert!(last_session_at_ms(&requester, pair_id).unwrap() >= established_at_ms);
    requester.disconnect(&mut session, CloseReason::UserDisconnect);
    assert_eq!(
        requester.store().checks.len(),
        2,
        "an ended session records its end once"
    );
    assert!(requester.store().get(pair_id).unwrap().serves());
}

#[test]
fn a_session_lost_with_its_transport_records_its_end() {
    let mut requester = watched_requester();
    let (pair_id, proxy_pairing) = paired(&mut requester, &[ProfileName::CardStatus]);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        drop(proxy_accept_session(&proxy_pairing, proxy_transport));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    proxy.join().unwrap();
    for _ in 0..KEEP_ALIVE_ROUNDS {
        if requester.keep_alive(&mut session).is_err() {
            break;
        }
    }
    assert_eq!(session.end(), Some(SessionEnd::TransportLoss));
    assert_eq!(requester.store().checks, [(pair_id, true), (pair_id, true)]);
}

#[test]
fn a_session_record_the_store_refused_is_tried_again_on_the_next_event() {
    let mut requester = watched_requester();
    let (pair_id, proxy_pairing) = paired(&mut requester, &[ProfileName::CardStatus]);
    requester.store_mut().refusing = true;
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || proxy_accept_session(&proxy_pairing, proxy_transport));
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let _custodian = proxy.join().unwrap();
    assert_eq!(requester.store().checks, [(pair_id, true)]);
    assert_eq!(last_session_at_ms(&requester, pair_id), None);

    requester.store_mut().refusing = false;
    requester.keep_alive(&mut session).unwrap();
    assert_eq!(requester.store().checks, [(pair_id, true), (pair_id, true)]);
    assert!(last_session_at_ms(&requester, pair_id).is_some());
    requester.disconnect(&mut session, CloseReason::UserDisconnect);
}

#[test]
fn a_pairing_idle_for_the_limit_expires_silently_and_opens_no_session() {
    let mut requester = test_requester();
    let (pair_id, _proxy_pairing) = paired(&mut requester, &[ProfileName::CardStatus]);
    let created_at_ms = requester
        .store()
        .get(pair_id)
        .unwrap()
        .pair_record()
        .unwrap()
        .created_at_ms();
    let idle_expired_at_ms = created_at_ms + PAIRING_IDLE_EXPIRY_MS;
    assert!(
        sweep_pairings(
            requester.store_mut(),
            idle_expired_at_ms - JUST_BEFORE_MS,
            |_| false
        )
        .is_empty()
    );
    assert_eq!(
        sweep_pairings(requester.store_mut(), idle_expired_at_ms, |_| false),
        vec![pair_id]
    );
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.state(), PairingState::Forgotten);
    assert!(record.owes_revocation_notice());
    let (requester_transport, _other) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert!(matches!(
        requester.connect(pair_id, requester_transport),
        Err(SessionError::Forgotten)
    ));
}
