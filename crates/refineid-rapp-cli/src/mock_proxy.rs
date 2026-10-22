//! Mock RAPP custodian for automated verification and testing.
//!
//! Listens like a phone does (RAPP v26.10.21 section 2.2.2), shows a pairing
//! code, serves a random offer after the pairing preamble, answers `CPace`
//! KC2 as responder and `Noise_XXpsk3` with the hello, confirmation, and
//! storage confirmation exchange, then accepts sessions routed by their
//! routing tag, each on its own thread. Every session sends `session.ready`
//! and the card's status (section 8.4), keeps liveness (section 8.3), and
//! serves its operations through the engine's custodian side (section 8):
//! reads at once, a consequential operation after reporting its consent view
//! and approving it, behind the retry floor (section 10.2). It publishes no
//! DNS-SD record: requesters dial it by address.

use std::sync::Arc;
use std::time::{Duration, Instant};

use refineid_lib_core::x509::OwnedCert;
use refineid_rapp::{
    BinaryFrame, CardIdentity, CardInspection, CardOperation, CardOperationResult,
    CardStatusMessage, CertificateFingerprint, CpaceKc2Responder, DEFAULT_OPERATION_LIFETIME_MS,
    EndpointRole, EstablishedSessionRuntime, MAXIMUM_CPACE_ATTEMPTS, OfferId, OperationRequest,
    OperationResultMessage, OperationViolation, PairRecord, PairingHandshake, PairingOffer,
    PingChallenge, ProfileName, ProgressEvent, ProxyDispatch, ProxyEngineError, ProxyFailure,
    ProxyOperationEngine, RetryDecision, RoutingKey, RuntimePoll, RuntimeReceive,
    SESSION_READY_NONCE_SIZE, SessionHandshake, SignatureAlgorithm, TransportProfile, TypedMessage,
    UserApproval, decode_pair_record, encode_pair_record, generate_pair_key_material,
    route_session, standard_pairing_context_v2,
};
use refineid_rapp_core::clock::{continuous_ms, unix_time_ms};
use refineid_rapp_core::engine::SESSION_RECEIVE_TICK;
use refineid_rapp_core::ids::{Challenge, RandomIdExt as _};
use refineid_rapp_core::offer::{format_pairing_code, generate_pairing_code};
use refineid_rapp_core::stream::{STREAM_CANDIDATE_ID, StreamAccept, StreamListener};
use refineid_rapp_core::transport::{
    FrameTransport, STREAM_PROFILE, TcpFrameTransport, TransportError,
};
use zeroize::Zeroizing;

/// How long the mock waits for each frame of a pairing: the requester's
/// user confirms the grants in between.
const PAIRING_STEP_WAIT: Duration = Duration::from_secs(10);

/// Default listen address: the local mock custodian endpoint requesters
/// fall back to.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:47110";

/// Validity dates the mock identity answer reports (section 9.1 form).
const MOCK_ISSUANCE_DATE: &str = "2026-01-01";
const MOCK_EXPIRATION_DATE: &str = "2031-01-01";

/// Uniform bytes one `CPace` scalar is drawn from (section 6.1.1).
const CPACE_SCALAR_ENTROPY_BYTES: usize = 64;

/// Mock signature lengths in bytes, when the mock key cannot sign.
const MOCK_ECDSA_P224_SIG_BYTES: usize = 56;
const MOCK_ECDSA_P256_SIG_BYTES: usize = 64;
const MOCK_ECDSA_P384_SIG_BYTES: usize = 96;
const MOCK_ECDSA_P521_SIG_BYTES: usize = 132;
const MOCK_RSA_2048_SIG_BYTES: usize = 256;
const MOCK_FALLBACK_SIGNATURE_BYTE: u8 = 0xAB;

/// Default mock certificate DER payload: the self-issued P-384 test
/// certificate checked in as `mock_cert.der`.
pub const DEFAULT_MOCK_CERT_DER: &[u8] = include_bytes!("mock_cert.der");

/// The private scalar of `mock_key.der`, the SEC1 key of the self-issued
/// mock certificate `mock_cert.der`.
pub const DEFAULT_MOCK_PRIVATE_KEY_SCALAR: &[u8; 48] = &[
    0x33, 0x51, 0xea, 0xcb, 0x1f, 0x41, 0x18, 0x9a, 0x6c, 0xdb, 0xbd, 0xae, 0x48, 0x27, 0xf1, 0xc1,
    0x47, 0x25, 0x4d, 0x3a, 0x56, 0x30, 0x53, 0xff, 0x6f, 0xd4, 0xd3, 0x76, 0xf8, 0x66, 0x8b, 0x2d,
    0x88, 0x78, 0xc4, 0xce, 0x86, 0x5a, 0xbb, 0xfd, 0xb3, 0x80, 0x1c, 0xae, 0x5b, 0x8e, 0x3d, 0xad,
];

/// The PIN tries a mock card reports unless told otherwise.
const DEFAULT_PIN_ATTEMPTS: u8 = 5;

/// Options configuring the mock proxy.
#[derive(Clone, Debug)]
pub struct MockProxyOptions {
    /// Address to listen on for pairing and session connections.
    pub listen: String,
    /// The pairing code to show; a fresh random one when absent.
    pub code: Option<String>,
    /// Display name sent to requester.
    pub name: String,
    /// Platform string sent to requester.
    pub platform: String,
    /// Number of sessions to serve before exiting (default: 1; 0 means infinite).
    pub count: usize,
    /// Display name to return for identity operations.
    pub identity_name: String,
    /// Person identifier to return for identity operations.
    pub person_id: String,
    /// The card's certificate, for authentication and signatures alike.
    pub certificate: OwnedCert,
    /// PIN 1 remaining attempts, checked against the retry floor.
    pub pin1_attempts: u8,
    /// PIN 2 remaining attempts, checked against the retry floor.
    pub pin2_attempts: u8,
    /// Path to load existing proxy pairing state from.
    pub resume_state: Option<String>,
    /// Path to save proxy pairing state to.
    pub save_state: Option<String>,
    /// Report the card as absent on every session (section 8.4), so a
    /// requester under test withdraws what it offers.
    pub card_absent: bool,
}

impl MockProxyOptions {
    /// The default options with the checked-in mock certificate.
    ///
    /// # Errors
    /// When the checked-in certificate does not parse.
    pub fn with_mock_certificate() -> Result<Self, String> {
        let certificate = OwnedCert::from_der(DEFAULT_MOCK_CERT_DER)
            .map_err(|error| format!("the mock certificate does not parse: {error:?}"))?;
        Ok(Self {
            listen: DEFAULT_LISTEN.to_owned(),
            code: None,
            name: "RefineID Mock Phone".to_owned(),
            platform: "iOS".to_owned(),
            count: 1,
            identity_name: "TESTI TESTAAJA".to_owned(),
            person_id: "010101-999X".to_owned(),
            certificate,
            pin1_attempts: DEFAULT_PIN_ATTEMPTS,
            pin2_attempts: DEFAULT_PIN_ATTEMPTS,
            resume_state: None,
            save_state: None,
            card_absent: false,
        })
    }

    /// The card status every session reports.
    fn card_status(&self) -> CardStatusMessage {
        if self.card_absent {
            CardStatusMessage::Absent
        } else {
            CardStatusMessage::Present(CertificateFingerprint::of_certificate(
                self.certificate.as_der(),
            ))
        }
    }
}

/// The proxy's stored pairing state.
#[derive(Debug)]
pub struct ProxyPairing {
    /// Canonical core pair record.
    pub record: PairRecord,
}

impl ProxyPairing {
    /// Saves the proxy pairing state to a simple hex-encoded text file.
    ///
    /// # Errors
    /// When the record cannot be encoded or the file written.
    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let cbor = Zeroizing::new(
            encode_pair_record(&self.record)
                .map_err(|e| format!("cannot serialize pair record: {e:?}"))?,
        );
        std::fs::write(path, format!("{}\n", hex::encode(&*cbor)))
            .map_err(|e| format!("cannot save state to {path}: {e}"))
    }

    /// Loads the proxy pairing state from a simple hex-encoded text file.
    ///
    /// # Errors
    /// When the file cannot be read or does not hold a custodian's record.
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let line = text.lines().next().ok_or("state file is empty")?;
        let cbor =
            Zeroizing::new(hex::decode(line.trim()).map_err(|e| format!("invalid hex: {e}"))?);
        let record =
            decode_pair_record(&cbor).map_err(|e| format!("invalid pair record: {e:?}"))?;
        if record.role() != EndpointRole::Proxy {
            return Err("the state file holds a requester's record".to_owned());
        }
        Ok(Self { record })
    }
}

/// Runs the mock proxy workflow according to the provided options.
///
/// # Errors
/// When the listener cannot be bound or the workflow fails.
pub fn run_mock_proxy(options: MockProxyOptions) -> Result<(), String> {
    println!("starting RAPP mock custodian on {}...", options.listen);
    let listener = StreamListener::bind(&options.listen, STREAM_CANDIDATE_ID, SESSION_RECEIVE_TICK)
        .map_err(|e| format!("cannot listen on {}: {e:?}", options.listen))?;
    serve_mock_proxy(&listener, options)
}

/// Runs the mock proxy workflow on a listener the caller bound, with
/// [`SESSION_RECEIVE_TICK`] as its receive deadline; `listen` in the options
/// is ignored.
///
/// # Errors
/// When pairing fails or no session can be accepted.
pub fn serve_mock_proxy(
    listener: &StreamListener,
    options: MockProxyOptions,
) -> Result<(), String> {
    let pairing = if let Some(state_path) = &options.resume_state {
        println!("resuming from state file: {state_path}");
        ProxyPairing::load_from_file(state_path)?
    } else {
        let p = run_pairing(listener, &options)?;
        if let Some(save_path) = &options.save_state {
            p.save_to_file(save_path)?;
            println!("saved proxy state to: {save_path}");
        }
        p
    };

    println!(
        "pairing active (pair_id: {})",
        hex::encode(pairing.record.pair_id().as_bytes())
    );

    // A requester holds one session while it offers the card to its
    // browsers (section 8.4) and may open another for an operation, so
    // sessions are served concurrently, each on its own thread.
    let pairing = Arc::new(pairing);
    let options = Arc::new(options);
    let mut sessions_served = 0;
    let mut workers = Vec::new();
    while options.count == 0 || sessions_served < options.count {
        let transport = accept_session(listener, &pairing)?;
        sessions_served += 1;
        println!("serving session {sessions_served}...");
        let pairing = Arc::clone(&pairing);
        let options = Arc::clone(&options);
        workers.push(std::thread::spawn(move || {
            if let Err(error) = serve_one_session(transport, &pairing, &options) {
                println!("session ended with an error: {error}");
            }
        }));
    }
    for worker in workers {
        let _ = worker.join();
    }
    println!("mock proxy finished successfully (served {sessions_served} sessions)");
    Ok(())
}

/// The mock custodian's random offer for the stream transport.
fn custodian_offer() -> Result<PairingOffer, String> {
    PairingOffer::create(
        OfferId::random().map_err(|_| "rng failed".to_owned())?,
        ProfileName::ALL
            .iter()
            .map(|profile| profile.as_str().to_owned())
            .collect(),
        &[TransportProfile::Stream],
    )
    .map_err(|e| format!("offer creation failed: {e:?}"))
}

/// Shows the code and accepts pairing connections until one pairs or the
/// custodian's three `CPace` attempts are spent (section 3.3).
fn run_pairing(
    listener: &StreamListener,
    options: &MockProxyOptions,
) -> Result<ProxyPairing, String> {
    let code = match &options.code {
        Some(code) => code.clone(),
        None => generate_pairing_code().map_err(|e| format!("rng failed: {e}"))?,
    };
    let offer = custodian_offer()?;
    println!("pairing code: {}", format_pairing_code(&code));
    let mut attempts = 0_u8;
    while attempts < MAXIMUM_CPACE_ATTEMPTS {
        let accepted = listener
            .accept()
            .map_err(|e| format!("accept failed: {e:?}"))?;
        let StreamAccept::Pairing(transport) = accepted else {
            println!("ignored a session connection while pairing");
            continue;
        };
        attempts += 1;
        match pair_once(transport, &offer, &code, options) {
            Ok(record) => return Ok(ProxyPairing { record }),
            Err(error) => println!("pairing attempt {attempts} failed: {error}"),
        }
    }
    Err("pairing attempts exhausted".into())
}

/// Receives one pairing frame, waiting through the connection's receive
/// ticks for at most [`PAIRING_STEP_WAIT`].
fn receive_pairing_frame(
    transport: &mut TcpFrameTransport,
    step: &str,
) -> Result<BinaryFrame, String> {
    let started = Instant::now();
    loop {
        match transport.receive_frame() {
            Ok(bytes) => {
                return BinaryFrame::reconstruct(bytes)
                    .map_err(|e| format!("{step} frame invalid: {e:?}"));
            }
            Err(TransportError::TimedOut) if started.elapsed() < PAIRING_STEP_WAIT => {}
            Err(e) => return Err(format!("receive {step} failed: {e:?}")),
        }
    }
}

/// Sends one frame of a pairing.
fn send_pairing_frame(
    transport: &mut TcpFrameTransport,
    frame: &BinaryFrame,
    step: &str,
) -> Result<(), String> {
    transport
        .send_frame(frame.as_bytes())
        .map_err(|e| format!("send {step} failed: {e:?}"))
}

/// One pairing connection: the offer bootstrap, `CPace` KC2 as responder,
/// `Noise_XXpsk3`, then the hello, confirmation, and storage exchange.
fn pair_once(
    mut transport: TcpFrameTransport,
    offer: &PairingOffer,
    code: &str,
    options: &MockProxyOptions,
) -> Result<PairRecord, String> {
    let bootstrap = offer
        .to_cbor()
        .map_err(|e| format!("offer encoding failed: {e:?}"))?;
    transport
        .send_frame(&bootstrap)
        .map_err(|e| format!("send offer failed: {e:?}"))?;
    let offer_hash = offer
        .offer_hash()
        .map_err(|e| format!("offer hash failed: {e:?}"))?;
    let context = standard_pairing_context_v2(&offer_hash, STREAM_PROFILE, STREAM_CANDIDATE_ID)
        .map_err(|e| format!("context failed: {e:?}"))?;

    let step_one = receive_pairing_frame(&mut transport, "Y_A")?;
    let mut entropy = Zeroizing::new([0_u8; CPACE_SCALAR_ENTROPY_BYTES]);
    getrandom::fill(entropy.as_mut()).map_err(|e| format!("rng failed: {e}"))?;
    let (step_two, waiting) = CpaceKc2Responder::process_step1_frame(
        code,
        &context,
        &offer.offer_id,
        &step_one,
        &entropy,
    )
    .map_err(|e| format!("Y_A refused: {e:?}"))?;
    drop(entropy);
    send_pairing_frame(&mut transport, &step_two, "Y_B")?;
    let step_three = receive_pairing_frame(&mut transport, "T_A (mistyped code?)")?;
    let pairing_secret = waiting
        .process_step3_frame(&step_three)
        .map_err(|e| format!("T_A refused: {e:?}"))?;

    let keys = generate_pair_key_material().map_err(|e| format!("key generation failed: {e:?}"))?;
    let mut handshake = PairingHandshake::begin(
        EndpointRole::Proxy,
        offer.clone(),
        STREAM_CANDIDATE_ID,
        keys,
        &pairing_secret,
    )
    .map_err(|fail| format!("pairing handshake failed: {:?}", fail.error()))?;

    let first = receive_pairing_frame(&mut transport, "handshake 1")?;
    handshake
        .read_message(&first)
        .map_err(|e| format!("handshake read 1 failed: {e:?}"))?;
    let second = handshake
        .write_message()
        .map_err(|e| format!("handshake write 2 failed: {e:?}"))?;
    send_pairing_frame(&mut transport, &second, "handshake 2")?;
    let third = receive_pairing_frame(&mut transport, "handshake 3")?;
    handshake
        .read_message(&third)
        .map_err(|e| format!("handshake read 3 failed: {e:?}"))?;
    if !handshake.is_complete() {
        return Err("handshake incomplete".into());
    }

    let mut confirmation = handshake
        .into_confirmation()
        .map_err(|e| format!("confirmation failed: {e:?}"))?;
    let hello = receive_pairing_frame(&mut transport, "hello")?;
    let requester_hello = confirmation
        .receive_hello(&hello, continuous_ms())
        .map_err(|e| format!("verify hello failed: {e:?}"))?;
    println!(
        "requester hello from: {} ({})",
        requester_hello.display_name, requester_hello.platform
    );
    let proxy_hello = confirmation
        .send_hello(options.name.clone(), options.platform.clone())
        .map_err(|e| format!("send hello failed: {e:?}"))?;
    send_pairing_frame(&mut transport, &proxy_hello, "hello")?;

    let requester_confirmation = receive_pairing_frame(&mut transport, "confirm")?;
    let granted_profiles = confirmation
        .receive_confirmation(&requester_confirmation, continuous_ms())
        .map_err(|e| format!("verify confirm failed: {e:?}"))?
        .to_vec();
    println!("requester granted profiles: {granted_profiles:?}");
    let proxy_confirmation = confirmation
        .send_confirmation(granted_profiles)
        .map_err(|e| format!("send confirm failed: {e:?}"))?;
    send_pairing_frame(&mut transport, &proxy_confirmation, "confirm")?;

    // The record is stored (here: held) before its confirmation is sent,
    // and is active only once the requester's confirmation arrives
    // (section 4.3 item 4).
    let (record, mut storage) = confirmation
        .into_storage(unix_time_ms())
        .map_err(|e| format!("into_storage failed: {e:?}"))?;
    let stored = storage
        .send_stored()
        .map_err(|e| format!("send stored failed: {e:?}"))?;
    send_pairing_frame(&mut transport, &stored, "stored")?;
    let requester_stored = receive_pairing_frame(&mut transport, "stored")?;
    storage
        .receive_stored(&requester_stored, continuous_ms())
        .map_err(|e| format!("verify stored failed: {e:?}"))?;
    storage
        .into_active()
        .map_err(|e| format!("pairing not active: {e:?}"))?
        .confirm(record)
        .map_err(|e| format!("confirm failed: {e:?}"))
}

/// Accepts connections until one opens a session for this pairing; others
/// are closed without changing state.
fn accept_session(
    listener: &StreamListener,
    pairing: &ProxyPairing,
) -> Result<TcpFrameTransport, String> {
    loop {
        match listener
            .accept()
            .map_err(|e| format!("accept failed: {e:?}"))?
        {
            StreamAccept::Session { routing, transport }
                if RoutingKey::derive(&pairing.record).is_ok_and(|key| {
                    route_session(
                        core::slice::from_ref(&key),
                        TransportProfile::Stream,
                        &routing,
                    )
                    .is_some()
                }) =>
            {
                return Ok(transport);
            }
            StreamAccept::Session { .. } => println!("closed a session for an unknown pairing"),
            StreamAccept::Pairing(_) => println!("closed a pairing connection; no offer is open"),
        }
    }
}

/// One established session as the custodian holds it.
struct CustodianSession {
    transport: TcpFrameTransport,
    runtime: EstablishedSessionRuntime,
    operations: ProxyOperationEngine,
}

impl CustodianSession {
    /// Seals and sends one message.
    fn send(&mut self, message: &TypedMessage) -> Result<(), String> {
        let frame = self
            .runtime
            .endpoint_mut()
            .send(message)
            .map_err(|e| format!("seal failed: {e:?}"))?;
        self.deliver(&frame)
    }

    /// Sends one sealed frame.
    fn deliver(&mut self, frame: &BinaryFrame) -> Result<(), String> {
        self.transport
            .send_frame(frame.as_bytes())
            .map_err(|e| format!("send failed: {e:?}"))
    }

    /// Sends the message an engine step hands out.
    fn send_dispatch(&mut self, dispatch: ProxyDispatch) -> Result<(), String> {
        match dispatch {
            ProxyDispatch::Send(message) => self.send(&message),
            other => Err(format!("unexpected engine step: {other:?}")),
        }
    }
}

/// The custodian's `Noise_KK` handshake, `session.ready`, and card status;
/// then the session's messages until it ends.
fn serve_one_session(
    mut transport: TcpFrameTransport,
    pairing: &ProxyPairing,
    options: &MockProxyOptions,
) -> Result<(), String> {
    println!("running Noise_KK session handshake...");
    let mut handshake = SessionHandshake::begin_proxy(&pairing.record, TransportProfile::Stream)
        .map_err(|e| format!("session handshake failed: {e:?}"))?;
    let first = receive_pairing_frame(&mut transport, "session handshake 1")?;
    handshake
        .read_message(&first)
        .map_err(|e| format!("read message 1 failed: {e:?}"))?;
    let second = handshake
        .write_message()
        .map_err(|e| format!("write message 2 failed: {e:?}"))?;
    send_pairing_frame(&mut transport, &second, "session handshake 2")?;
    let mut authentication = handshake
        .into_authentication()
        .map_err(|e| format!("into_authentication failed: {e:?}"))?;
    let mut nonce = [0_u8; SESSION_READY_NONCE_SIZE];
    getrandom::fill(&mut nonce).map_err(|e| format!("nonce failed: {e:?}"))?;
    let ready = authentication
        .send_ready(nonce)
        .map_err(|e| format!("send ready failed: {e:?}"))?;
    send_pairing_frame(&mut transport, &ready, "ready")?;
    let endpoint = authentication
        .into_established()
        .map_err(|e| format!("into_established failed: {e:?}"))?;
    let mut session = CustodianSession {
        transport,
        runtime: EstablishedSessionRuntime::new(endpoint, continuous_ms()),
        operations: ProxyOperationEngine::new(pairing.record.serving_profiles().to_vec()),
    };
    session.send(&ProxyOperationEngine::report_card_status(
        options.card_status(),
    ))?;
    println!("session ready; awaiting operation requests...");
    let outcome = serve_messages(&mut session, options);
    session.operations.session_closed();
    outcome
}

/// Keeps liveness and serves every message until the session ends.
fn serve_messages(
    session: &mut CustodianSession,
    options: &MockProxyOptions,
) -> Result<(), String> {
    loop {
        let challenge = Challenge::random().map_err(|_| "rng failed".to_owned())?;
        match session.runtime.poll(
            continuous_ms(),
            PingChallenge::reconstruct(*challenge.as_bytes()),
        ) {
            Ok(RuntimePoll::NoAction) => {}
            Ok(RuntimePoll::Send(ping)) => session.deliver(&ping)?,
            Ok(RuntimePoll::SessionClosed(_) | RuntimePoll::AlreadyClosed) | Err(_) => {
                println!("the requester went silent");
                return Ok(());
            }
        }
        let bytes = match session.transport.receive_frame() {
            Ok(bytes) => bytes,
            Err(TransportError::TimedOut) => continue,
            Err(e) => {
                println!("channel ended or closed: {e:?}");
                return Ok(());
            }
        };
        let frame = BinaryFrame::reconstruct(bytes).map_err(|e| format!("frame invalid: {e:?}"))?;
        match session.runtime.receive(&frame, continuous_ms()) {
            Ok(RuntimeReceive::Message(message)) => {
                let request = match &message {
                    TypedMessage::OperationRequest(request) => Some(request.clone()),
                    _ => None,
                };
                match session.operations.receive(message) {
                    Ok(ProxyDispatch::InspectPrerequisites(_)) => {
                        if let Some(request) = request {
                            serve_operation(session, &request, options)?;
                        }
                    }
                    Ok(ProxyDispatch::NotOperation(_)) => {}
                    Ok(dispatch) => session.send_dispatch(dispatch)?,
                    Err(ProxyEngineError::AuthenticatedProtocolViolation(violation)) => {
                        let closed = session
                            .runtime
                            .close_for_operation_violation(OperationViolation::Proxy(violation));
                        if let RuntimeReceive::ViolationClosed {
                            notice: Some(notice),
                            ..
                        } = closed
                        {
                            session.deliver(&notice)?;
                        }
                        return Ok(());
                    }
                    Err(e) => return Err(format!("engine refused: {e:?}")),
                }
            }
            Ok(RuntimeReceive::Send(pong)) => session.deliver(&pong)?,
            Ok(RuntimeReceive::LivenessConfirmed | RuntimeReceive::IgnoredStalePong) => {}
            Ok(RuntimeReceive::PeerClosed(reason)) => {
                println!("requester closed the session: {reason:?}");
                return Ok(());
            }
            Ok(RuntimeReceive::ViolationClosed { notice, .. }) => {
                if let Some(notice) = notice {
                    session.deliver(&notice)?;
                }
                println!("the requester violated the protocol");
                return Ok(());
            }
            Ok(RuntimeReceive::SessionClosed(_)) | Err(_) => {
                println!("a frame failed authentication");
                return Ok(());
            }
        }
    }
}

/// Serves one admitted operation: a read at once; a consequential one after
/// its consent view, approved at once, behind the retry floor.
fn serve_operation(
    session: &mut CustodianSession,
    request: &OperationRequest,
    options: &MockProxyOptions,
) -> Result<(), String> {
    let operation_id = request.operation_id;
    let prerequisites = session
        .operations
        .prerequisites_complete(operation_id, continuous_ms(), DEFAULT_OPERATION_LIFETIME_MS)
        .map_err(|e| format!("prerequisites refused: {e:?}"))?;
    let dispatch = match prerequisites {
        ProxyDispatch::ExecuteSafeRead { read, .. } => {
            println!("serving {:?}", read.operation);
            let result = perform(&read.operation, options)?;
            session.operations.finish_completed(
                operation_id,
                OperationResultMessage::completed(operation_id, &result),
            )
        }
        ProxyDispatch::AwaitConsent(_) => {
            let shown = session
                .operations
                .report_progress(operation_id, ProgressEvent::ConsentShown)
                .map_err(|e| format!("progress refused: {e:?}"))?;
            session.send(&shown)?;
            let approval = UserApproval::for_request(request, continuous_ms());
            match session
                .operations
                .approve(
                    operation_id,
                    approval,
                    continuous_ms(),
                    DEFAULT_OPERATION_LIFETIME_MS,
                )
                .map_err(|e| format!("approval refused: {e:?}"))?
            {
                ProxyDispatch::ExecuteCardCommand { command, .. } => {
                    command.execute(|command| {
                        execute(session, operation_id, &command.operation, options)
                    })?
                }
                expired => Ok(expired),
            }
        }
        expired => Ok(expired),
    };
    let dispatch = dispatch.map_err(|e| format!("result refused: {e:?}"))?;
    session.send_dispatch(dispatch)
}

/// The one card command an approval gives, behind the retry floor (section
/// 10.2).
fn execute(
    session: &mut CustodianSession,
    operation_id: refineid_rapp::OperationId,
    operation: &CardOperation,
    options: &MockProxyOptions,
) -> Result<Result<ProxyDispatch, ProxyEngineError>, String> {
    let remaining = match operation {
        CardOperation::BrowserAuthenticate { .. } => options.pin1_attempts,
        _ => options.pin2_attempts,
    };
    if RetryDecision::for_decrementing_counter(Some(remaining)) != RetryDecision::Permit {
        println!("refusing {operation:?}: the retry floor");
        return Ok(session
            .operations
            .finish_failure(operation_id, ProxyFailure::RetryFloor));
    }
    println!("serving {operation:?}");
    match perform(operation, options)? {
        CardOperationResult::Signatures(signatures) => {
            for signature in signatures {
                if let Err(error) = session
                    .operations
                    .record_batch_signature(operation_id, signature)
                {
                    return Ok(Err(error));
                }
            }
            Ok(session.operations.complete_batch(operation_id))
        }
        result => Ok(session.operations.finish_completed(
            operation_id,
            OperationResultMessage::completed(operation_id, &result),
        )),
    }
}

/// What the mock card answers to `operation`.
fn perform(
    operation: &CardOperation,
    options: &MockProxyOptions,
) -> Result<CardOperationResult, String> {
    Ok(match operation {
        // The mock exposes neither an answer to reset nor its historical
        // bytes (section 9.1).
        CardOperation::InspectCard => CardOperationResult::Inspection(CardInspection {
            answer_to_reset: Vec::new(),
        }),
        CardOperation::ReadIdentity => CardOperationResult::Identity(
            CardIdentity::reconstruct(
                options.identity_name.clone(),
                options.person_id.clone(),
                MOCK_ISSUANCE_DATE.to_owned(),
                MOCK_EXPIRATION_DATE.to_owned(),
                vec![options.certificate.as_der().to_vec()],
                None,
            )
            .map_err(|e| format!("identity out of bounds: {e:?}"))?,
        ),
        CardOperation::ReadCertificate { .. } => {
            CardOperationResult::Certificate(options.certificate.as_der().to_vec())
        }
        CardOperation::BrowserAuthenticate {
            algorithm, digest, ..
        }
        | CardOperation::SignDocument {
            algorithm, digest, ..
        } => CardOperationResult::Signature(sign_digest(digest, *algorithm)),
        CardOperation::BatchSignDocuments {
            algorithm, digests, ..
        } => CardOperationResult::Signatures(
            digests
                .iter()
                .map(|digest| sign_digest(digest, *algorithm))
                .collect(),
        ),
    })
}

fn sign_digest(digest: &[u8], algorithm: SignatureAlgorithm) -> Vec<u8> {
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    if let Ok(signing_key) = p384::ecdsa::SigningKey::from_slice(DEFAULT_MOCK_PRIVATE_KEY_SCALAR)
        && let Ok(signature) =
            PrehashSigner::<p384::ecdsa::Signature>::sign_prehash(&signing_key, digest)
    {
        return signature.to_bytes().to_vec();
    }
    let sig_len = match algorithm {
        SignatureAlgorithm::EcdsaSha224 => MOCK_ECDSA_P224_SIG_BYTES,
        SignatureAlgorithm::EcdsaSha256 => MOCK_ECDSA_P256_SIG_BYTES,
        SignatureAlgorithm::EcdsaSha384 => MOCK_ECDSA_P384_SIG_BYTES,
        SignatureAlgorithm::EcdsaSha512 => MOCK_ECDSA_P521_SIG_BYTES,
        SignatureAlgorithm::RsaPkcs1Sha256
        | SignatureAlgorithm::RsaPkcs1Sha384
        | SignatureAlgorithm::RsaPkcs1Sha512
        | SignatureAlgorithm::RsaPssSha256 => MOCK_RSA_2048_SIG_BYTES,
    };
    vec![MOCK_FALLBACK_SIGNATURE_BYTE; sig_len]
}
