//! Mock RAPP custodian for automated verification and testing.
//!
//! Listens like a phone does (RAPP v26.10.10 section 2.2.2), shows a pairing
//! code, serves a random offer after the pairing preamble, answers `CPace`
//! KC2 as responder and `Noise_XXpsk3` with the hello and confirmation
//! exchange, then accepts sessions routed by their routing tag and
//! serves typed card operations (inspection, identity, certificate, and
//! signatures). It publishes no DNS-SD record: requesters dial it by
//! address.

#![expect(
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::collapsible_if,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::uninlined_format_args,
    reason = "Mock proxy test harness with mock state serialization and session handling"
)]

use std::time::Duration;

use refineid_rapp::{
    BinaryFrame, CardInspection, CardOperation, CardOperationResult, CpaceKc2Responder,
    EndpointRole, EstablishedEndpoint, LivenessMessage, MAXIMUM_CPACE_ATTEMPTS, OfferId,
    OperationReference, OperationRequest, OperationResultMessage, PairRecord, PairStore,
    PairStoreError, PairTombstone, PairingHandshake, PairingOffer, ReceiveOutcome, RoutingKey,
    SessionHandshake, TransportProfile, TypedMessage, decode_pair_record, encode_pair_record,
    generate_pair_key_material, route_session, standard_pairing_context_v2,
};
use refineid_rapp_core::offer::{format_pairing_code, generate_pairing_code};
use refineid_rapp_core::stream::{STREAM_CANDIDATE_ID, StreamAccept, StreamListener};
use refineid_rapp_core::transport::{FrameTransport, STREAM_PROFILE, TcpFrameTransport};
use zeroize::Zeroizing;

/// Socket receive deadline on an accepted connection.
const DEADLINE: Duration = Duration::from_secs(10);

/// Default listen address: the local mock custodian endpoint requesters
/// fall back to.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:47110";

/// Validity dates the mock identity answer reports (section 9.1 form).
const MOCK_ISSUANCE_DATE: &str = "2026-01-01";
const MOCK_EXPIRATION_DATE: &str = "2031-01-01";

/// Mock signature lengths in bytes.
const MOCK_ECDSA_P224_SIG_BYTES: usize = 56;
const MOCK_ECDSA_P256_SIG_BYTES: usize = 64;
const MOCK_ECDSA_P384_SIG_BYTES: usize = 96;
const MOCK_ECDSA_P521_SIG_BYTES: usize = 132;
const MOCK_RSA_2048_SIG_BYTES: usize = 256;
const MOCK_FALLBACK_SIGNATURE_BYTE: u8 = 0xAB;

/// Default mock certificate DER payload.
pub const DEFAULT_MOCK_CERT_DER: &[u8] = include_bytes!("mock_cert.der");

/// Default mock P-384 private key scalar corresponding to `DEFAULT_MOCK_CERT_DER`.
pub const DEFAULT_MOCK_PRIVATE_KEY_SCALAR: &[u8; 48] = &[
    0x33, 0x51, 0xea, 0xcb, 0x1f, 0x41, 0x18, 0x9a, 0x6c, 0xdb, 0xbd, 0xae, 0x48, 0x27, 0xf1, 0xc1,
    0x47, 0x25, 0x4d, 0x3a, 0x56, 0x30, 0x53, 0xff, 0x6f, 0xd4, 0xd3, 0x76, 0xf8, 0x66, 0x8b, 0x2d,
    0x88, 0x78, 0xc4, 0xce, 0x86, 0x5a, 0xbb, 0xfd, 0xb3, 0x80, 0x1c, 0xae, 0x5b, 0x8e, 0x3d, 0xad,
];

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
    /// Certificate DER bytes to return.
    pub cert_der: Vec<u8>,
    /// Root CA certificate DER bytes to return (optional).
    pub root_ca_der: Option<Vec<u8>>,
    /// Intermediate CA certificate DER bytes to return (optional).
    pub intermediate_ca_der: Option<Vec<u8>>,
    /// PIN 1 remaining attempts.
    pub pin1_attempts: u8,
    /// PIN 2 remaining attempts.
    pub pin2_attempts: u8,
    /// Path to load existing proxy pairing state from.
    pub resume_state: Option<String>,
    /// Path to save proxy pairing state to.
    pub save_state: Option<String>,
}

impl Default for MockProxyOptions {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.to_owned(),
            code: None,
            name: "RefineID Mock Phone".to_owned(),
            platform: "iOS".to_owned(),
            count: 1,
            identity_name: "TESTI TESTAAJA".to_owned(),
            person_id: "010101-999X".to_owned(),
            cert_der: DEFAULT_MOCK_CERT_DER.to_vec(),
            root_ca_der: None,
            intermediate_ca_der: None,
            pin1_attempts: 5,
            pin2_attempts: 5,
            resume_state: None,
            save_state: None,
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
    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let cbor = encode_pair_record(&self.record)
            .map_err(|e| format!("cannot serialize pair record: {e:?}"))?;
        std::fs::write(path, format!("{}\n", hex::encode(cbor)))
            .map_err(|e| format!("cannot save state to {path}: {e}"))
    }

    /// Loads the proxy pairing state from a simple hex-encoded text file.
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let line = text.lines().next().ok_or("state file is empty")?;
        let cbor = hex::decode(line.trim()).map_err(|e| format!("invalid hex: {e}"))?;
        let record =
            decode_pair_record(&cbor).map_err(|e| format!("invalid pair record: {e:?}"))?;
        Ok(Self { record })
    }
}

/// Runs the mock proxy workflow according to the provided options.
pub fn run_mock_proxy(options: MockProxyOptions) -> Result<(), String> {
    println!("starting RAPP mock custodian on {}...", options.listen);
    let listener = StreamListener::bind(&options.listen, STREAM_CANDIDATE_ID, DEADLINE)
        .map_err(|e| format!("cannot listen on {}: {e:?}", options.listen))?;
    serve_mock_proxy(&listener, options)
}

/// Runs the mock proxy workflow on a listener the caller bound; `listen` in
/// the options is ignored.
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

    let mut sessions_served = 0;
    while options.count == 0 || sessions_served < options.count {
        let transport = accept_session(listener, &pairing)?;
        sessions_served += 1;
        println!("serving session {sessions_served}...");
        serve_one_session(transport, &pairing, &options)?;
    }
    println!("mock proxy finished successfully (served {sessions_served} sessions)");
    Ok(())
}

/// The mock custodian's random offer for the stream transport.
fn custodian_offer() -> Result<PairingOffer, String> {
    let mut offer_id = [0_u8; refineid_rapp::OFFER_ID_SIZE];
    getrandom::fill(&mut offer_id).map_err(|e| format!("rng failed: {e}"))?;
    PairingOffer::create(
        OfferId::from_array(offer_id),
        vec![
            refineid_rapp::ProfileName::CardStatus.as_str().to_owned(),
            refineid_rapp::ProfileName::Authentication
                .as_str()
                .to_owned(),
            refineid_rapp::ProfileName::DocumentSigning
                .as_str()
                .to_owned(),
        ],
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

/// One pairing connection: the offer bootstrap, `CPace` KC2 as responder,
/// `Noise_XXpsk3`, then the hello and confirmation exchange.
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

    let step_one = BinaryFrame::reconstruct(
        transport
            .receive_frame()
            .map_err(|e| format!("receive Y_A failed: {e:?}"))?,
    )
    .map_err(|e| format!("Y_A frame invalid: {e:?}"))?;
    let mut entropy = Zeroizing::new([0_u8; 64]);
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
    transport
        .send_frame(step_two.as_bytes())
        .map_err(|e| format!("send Y_B failed: {e:?}"))?;
    let step_three = BinaryFrame::reconstruct(
        transport
            .receive_frame()
            .map_err(|e| format!("receive T_A failed (mistyped code?): {e:?}"))?,
    )
    .map_err(|e| format!("T_A frame invalid: {e:?}"))?;
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

    let m1 = BinaryFrame::reconstruct(
        transport
            .receive_frame()
            .map_err(|e| format!("receive frame 1 failed: {e:?}"))?,
    )
    .map_err(|e| format!("frame 1 decode failed: {e:?}"))?;
    handshake
        .read_message(&m1)
        .map_err(|e| format!("handshake read 1 failed: {e:?}"))?;
    let m2 = handshake
        .write_message()
        .map_err(|e| format!("handshake write 2 failed: {e:?}"))?;
    transport
        .send_frame(m2.as_bytes())
        .map_err(|e| format!("send frame 2 failed: {e:?}"))?;
    let m3 = BinaryFrame::reconstruct(
        transport
            .receive_frame()
            .map_err(|e| format!("receive frame 3 failed: {e:?}"))?,
    )
    .map_err(|e| format!("frame 3 decode failed: {e:?}"))?;
    handshake
        .read_message(&m3)
        .map_err(|e| format!("handshake read 3 failed: {e:?}"))?;
    if !handshake.is_complete() {
        return Err("handshake incomplete".into());
    }

    let mut confirmation = handshake
        .into_confirmation()
        .map_err(|e| format!("confirmation failed: {e:?}"))?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);

    let req_hello_frame = BinaryFrame::reconstruct(
        transport
            .receive_frame()
            .map_err(|e| format!("receive hello failed: {e:?}"))?,
    )
    .map_err(|e| format!("hello frame decode failed: {e:?}"))?;
    let req_hello = confirmation
        .receive_hello(&req_hello_frame, now_ms)
        .map_err(|e| format!("verify hello failed: {e:?}"))?;
    println!(
        "requester hello from: {} ({})",
        req_hello.display_name, req_hello.platform
    );
    let proxy_hello = confirmation
        .send_hello(options.name.clone(), options.platform.clone())
        .map_err(|e| format!("send hello failed: {e:?}"))?;
    transport
        .send_frame(proxy_hello.as_bytes())
        .map_err(|e| format!("send hello frame failed: {e:?}"))?;

    let req_conf_frame = BinaryFrame::reconstruct(
        transport
            .receive_frame()
            .map_err(|e| format!("receive confirm failed: {e:?}"))?,
    )
    .map_err(|e| format!("confirm frame decode failed: {e:?}"))?;
    let granted_profiles = confirmation
        .receive_confirmation(&req_conf_frame, now_ms)
        .map_err(|e| format!("verify confirm failed: {e:?}"))?
        .to_vec();
    println!("requester granted profiles: {:?}", granted_profiles);
    let proxy_conf = confirmation
        .send_confirmation(granted_profiles)
        .map_err(|e| format!("send confirm failed: {e:?}"))?;
    transport
        .send_frame(proxy_conf.as_bytes())
        .map_err(|e| format!("send confirm frame failed: {e:?}"))?;

    confirmation
        .into_pair_record(now_ms)
        .map_err(|e| format!("into_pair_record failed: {e:?}"))
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

#[derive(Default)]
struct MockProxyStore;

impl PairStore for MockProxyStore {
    type Error = core::convert::Infallible;
    fn load(&mut self, _pair_id: refineid_rapp::PairId) -> Result<Option<PairRecord>, Self::Error> {
        Ok(None)
    }
    fn insert(&mut self, _record: PairRecord) -> Result<(), PairStoreError<Self::Error>> {
        Ok(())
    }
    fn revoke(&mut self, _tombstone: PairTombstone) -> Result<(), PairStoreError<Self::Error>> {
        Ok(())
    }
    fn is_revoked(&mut self, _pair_id: refineid_rapp::PairId) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

fn serve_one_session(
    mut transport: TcpFrameTransport,
    pairing: &ProxyPairing,
    options: &MockProxyOptions,
) -> Result<(), String> {
    println!("running Noise_KK session handshake...");
    let mut handshake = SessionHandshake::begin_proxy(&pairing.record, TransportProfile::Stream)
        .map_err(|e| format!("session handshake failed: {e:?}"))?;

    // Message 1 (Requester -> Proxy)
    let m1_bytes = transport
        .receive_frame()
        .map_err(|e| format!("receive frame 1 failed: {e:?}"))?;
    let m1 =
        BinaryFrame::reconstruct(m1_bytes).map_err(|e| format!("frame 1 decode failed: {e:?}"))?;
    handshake
        .read_message(&m1)
        .map_err(|e| format!("read message 1 failed: {e:?}"))?;

    // Message 2 (Proxy -> Requester)
    let m2 = handshake
        .write_message()
        .map_err(|e| format!("write message 2 failed: {e:?}"))?;
    transport
        .send_frame(m2.as_bytes())
        .map_err(|e| format!("send frame 2 failed: {e:?}"))?;

    if !handshake.is_complete() {
        return Err("handshake incomplete".into());
    }

    let mut auth = handshake
        .into_authentication()
        .map_err(|e| format!("into_auth failed: {e:?}"))?;

    // Exchange Ready
    let req_ready_bytes = transport
        .receive_frame()
        .map_err(|e| format!("receive ready failed: {e:?}"))?;
    let req_ready_frame = BinaryFrame::reconstruct(req_ready_bytes)
        .map_err(|e| format!("ready frame decode failed: {e:?}"))?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);

    let mut store = MockProxyStore;
    auth.receive_ready(&mut store, &req_ready_frame, now_ms)
        .map_err(|e| format!("receive ready failed: {e:?}"))?;

    let mut proxy_nonce = [0u8; 32];
    getrandom::fill(&mut proxy_nonce).map_err(|e| format!("nonce failed: {e:?}"))?;
    let proxy_ready = auth
        .send_ready(proxy_nonce)
        .map_err(|e| format!("send ready failed: {e:?}"))?;
    transport
        .send_frame(proxy_ready.as_bytes())
        .map_err(|e| format!("send ready frame failed: {e:?}"))?;

    let mut endpoint = auth
        .into_established()
        .map_err(|e| format!("into_established failed: {e:?}"))?;
    println!("session ready; awaiting operation requests...");

    loop {
        let frame_bytes = match transport.receive_frame() {
            Ok(b) => b,
            Err(e) => {
                println!("channel ended or closed: {e:?}");
                break;
            }
        };
        let frame = match BinaryFrame::reconstruct(frame_bytes) {
            Ok(f) => f,
            Err(e) => {
                println!("frame decode error: {e:?}");
                break;
            }
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);

        let outcome = match endpoint.receive(&mut store, &frame, now_ms) {
            Ok(o) => o,
            Err(e) => {
                println!("endpoint receive error: {e:?}");
                break;
            }
        };

        match outcome {
            ReceiveOutcome::Message(TypedMessage::OperationRequest(request)) => {
                println!("received operation request: {:?}", request.operation);
                handle_operation_request(
                    &mut transport,
                    &mut endpoint,
                    &mut store,
                    request,
                    options,
                )?;
            }
            ReceiveOutcome::Message(TypedMessage::LivenessPing(ping)) => {
                let pong = TypedMessage::LivenessPong(LivenessMessage {
                    challenge: ping.challenge,
                    last_received_sequence: endpoint.last_received_sequence().unwrap_or(0),
                });
                if let Ok(pong_frame) = endpoint.send(&pong) {
                    let _ = transport.send_frame(pong_frame.as_bytes());
                }
            }
            ReceiveOutcome::Message(TypedMessage::SessionClose(close)) => {
                println!("requester closed session gracefully: {:?}", close.reason);
                break;
            }
            other => {
                println!("unexpected outcome in session: {other:?}");
                break;
            }
        }
    }
    Ok(())
}

fn handle_operation_request<T: FrameTransport>(
    transport: &mut T,
    endpoint: &mut EstablishedEndpoint,
    store: &mut MockProxyStore,
    request: OperationRequest,
    options: &MockProxyOptions,
) -> Result<(), String> {
    let operation_id = request.operation_id;
    let request_hash = request
        .request_hash()
        .map_err(|e| format!("hash failed: {e:?}"))?;
    let op_ref = OperationReference {
        operation_id,
        request_hash,
    };

    match request.operation {
        CardOperation::InspectCard => {
            println!("serving inspect_card operation");
            let result = CardOperationResult::Inspection(CardInspection {
                answer_to_reset: Vec::new(),
                pin1_factory: false,
                pin2_factory: false,
                pin1_attempts: Some(options.pin1_attempts),
                pin2_attempts: Some(options.pin2_attempts),
                puk_attempts: None,
            });
            let msg =
                TypedMessage::OperationResult(OperationResultMessage::completed(op_ref, &result));
            let frame = endpoint
                .send(&msg)
                .map_err(|e| format!("send result failed: {e:?}"))?;
            transport
                .send_frame(frame.as_bytes())
                .map_err(|e| format!("send frame failed: {e:?}"))?;

            // Await Ack
            let ack_bytes = transport
                .receive_frame()
                .map_err(|e| format!("receive ack failed: {e:?}"))?;
            let ack_frame = BinaryFrame::reconstruct(ack_bytes)
                .map_err(|e| format!("ack frame failed: {e:?}"))?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64);
            if let Ok(ReceiveOutcome::Message(TypedMessage::OperationResultAck(ack_ref))) =
                endpoint.receive(store, &ack_frame, now_ms)
            {
                if ack_ref == op_ref {
                    println!("inspect_card completed and acknowledged");
                }
            }
        }
        CardOperation::ReadIdentity => {
            println!(
                "serving read_identity: {} ({})",
                options.identity_name, options.person_id
            );
            let result = CardOperationResult::Identity(
                refineid_rapp::CardIdentity::reconstruct(
                    options.identity_name.clone(),
                    options.person_id.clone(),
                    MOCK_ISSUANCE_DATE.to_owned(),
                    MOCK_EXPIRATION_DATE.to_owned(),
                    vec![options.cert_der.clone()],
                    None,
                )
                .map_err(|e| format!("identity out of bounds: {e:?}"))?,
            );
            let msg =
                TypedMessage::OperationResult(OperationResultMessage::completed(op_ref, &result));
            let frame = endpoint
                .send(&msg)
                .map_err(|e| format!("send result failed: {e:?}"))?;
            transport
                .send_frame(frame.as_bytes())
                .map_err(|e| format!("send frame failed: {e:?}"))?;

            // Await Ack
            let ack_bytes = transport
                .receive_frame()
                .map_err(|e| format!("receive ack failed: {e:?}"))?;
            let ack_frame = BinaryFrame::reconstruct(ack_bytes)
                .map_err(|e| format!("ack frame failed: {e:?}"))?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64);
            if let Ok(ReceiveOutcome::Message(TypedMessage::OperationResultAck(ack_ref))) =
                endpoint.receive(store, &ack_frame, now_ms)
            {
                if ack_ref == op_ref {
                    println!("read_identity completed and acknowledged");
                }
            }
        }
        CardOperation::ReadCertificate { kind } => {
            let der = match kind {
                refineid_rapp::CertificateKind::Authentication
                | refineid_rapp::CertificateKind::Signature => &options.cert_der,
            };
            println!("serving read_certificate");
            let result = CardOperationResult::Certificate(der.clone());
            let msg =
                TypedMessage::OperationResult(OperationResultMessage::completed(op_ref, &result));
            let frame = endpoint
                .send(&msg)
                .map_err(|e| format!("send result failed: {e:?}"))?;
            transport
                .send_frame(frame.as_bytes())
                .map_err(|e| format!("send frame failed: {e:?}"))?;

            // Await Ack
            let ack_bytes = transport
                .receive_frame()
                .map_err(|e| format!("receive ack failed: {e:?}"))?;
            let ack_frame = BinaryFrame::reconstruct(ack_bytes)
                .map_err(|e| format!("ack frame failed: {e:?}"))?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64);
            if let Ok(ReceiveOutcome::Message(TypedMessage::OperationResultAck(ack_ref))) =
                endpoint.receive(store, &ack_frame, now_ms)
            {
                if ack_ref == op_ref {
                    println!("read_certificate completed and acknowledged");
                }
            }
        }
        CardOperation::BrowserAuthenticate {
            origin,
            algorithm,
            digest,
            ..
        } => {
            println!("serving browser_authenticate: origin='{origin}'");
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64);

            let sig_bytes = sign_digest(&digest, algorithm);
            let result = CardOperationResult::Signature(sig_bytes);
            let res_msg =
                TypedMessage::OperationResult(OperationResultMessage::completed(op_ref, &result));
            let res_frame = endpoint
                .send(&res_msg)
                .map_err(|e| format!("send res failed: {e:?}"))?;
            transport
                .send_frame(res_frame.as_bytes())
                .map_err(|e| format!("send res frame failed: {e:?}"))?;

            // Await Ack
            let ack_bytes = transport
                .receive_frame()
                .map_err(|e| format!("receive ack failed: {e:?}"))?;
            let ack_frame = BinaryFrame::reconstruct(ack_bytes)
                .map_err(|e| format!("ack frame failed: {e:?}"))?;
            if let Ok(ReceiveOutcome::Message(TypedMessage::OperationResultAck(ack_ref))) =
                endpoint.receive(store, &ack_frame, now_ms)
            {
                if ack_ref == op_ref {
                    println!("browser_authenticate completed and acknowledged");
                }
            }
        }
        CardOperation::SignDocument {
            document_name,
            algorithm,
            digest,
            ..
        } => {
            println!("serving sign_document: document='{document_name}'");
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64);

            let sig_bytes = sign_digest(&digest, algorithm);
            let result = CardOperationResult::Signature(sig_bytes);
            let res_msg =
                TypedMessage::OperationResult(OperationResultMessage::completed(op_ref, &result));
            let res_frame = endpoint
                .send(&res_msg)
                .map_err(|e| format!("send res failed: {e:?}"))?;
            transport
                .send_frame(res_frame.as_bytes())
                .map_err(|e| format!("send res frame failed: {e:?}"))?;

            // Await Ack
            let ack_bytes = transport
                .receive_frame()
                .map_err(|e| format!("receive ack failed: {e:?}"))?;
            let ack_frame = BinaryFrame::reconstruct(ack_bytes)
                .map_err(|e| format!("ack frame failed: {e:?}"))?;
            if let Ok(ReceiveOutcome::Message(TypedMessage::OperationResultAck(ack_ref))) =
                endpoint.receive(store, &ack_frame, now_ms)
            {
                if ack_ref == op_ref {
                    println!("sign_document completed and acknowledged");
                }
            }
        }
        CardOperation::BatchSignDocuments {
            document_names,
            algorithm,
            digests,
            ..
        } => {
            println!(
                "serving batch_sign_documents: {} documents",
                document_names.len()
            );
            let signatures = digests
                .iter()
                .map(|digest| sign_digest(digest, algorithm))
                .collect();
            let result = CardOperationResult::Signatures(signatures);
            let res_msg =
                TypedMessage::OperationResult(OperationResultMessage::completed(op_ref, &result));
            let res_frame = endpoint
                .send(&res_msg)
                .map_err(|e| format!("send res failed: {e:?}"))?;
            transport
                .send_frame(res_frame.as_bytes())
                .map_err(|e| format!("send res frame failed: {e:?}"))?;
            let ack_bytes = transport
                .receive_frame()
                .map_err(|e| format!("receive ack failed: {e:?}"))?;
            let ack_frame = BinaryFrame::reconstruct(ack_bytes)
                .map_err(|e| format!("ack frame failed: {e:?}"))?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64);
            if let Ok(ReceiveOutcome::Message(TypedMessage::OperationResultAck(ack_ref))) =
                endpoint.receive(store, &ack_frame, now_ms)
                && ack_ref == op_ref
            {
                println!("batch_sign_documents completed and acknowledged");
            }
        }
    }
    Ok(())
}

fn sign_digest(digest: &[u8], algorithm: refineid_rapp::SignatureAlgorithm) -> Vec<u8> {
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    if let Ok(signing_key) = p384::ecdsa::SigningKey::from_slice(DEFAULT_MOCK_PRIVATE_KEY_SCALAR) {
        if let Ok(sig) = signing_key.sign_prehash(digest) {
            let signature: p384::ecdsa::Signature = sig;
            return signature.to_bytes().to_vec();
        }
    }
    let sig_len = match algorithm {
        refineid_rapp::SignatureAlgorithm::EcdsaSha224 => MOCK_ECDSA_P224_SIG_BYTES,
        refineid_rapp::SignatureAlgorithm::EcdsaSha256 => MOCK_ECDSA_P256_SIG_BYTES,
        refineid_rapp::SignatureAlgorithm::EcdsaSha384 => MOCK_ECDSA_P384_SIG_BYTES,
        refineid_rapp::SignatureAlgorithm::EcdsaSha512 => MOCK_ECDSA_P521_SIG_BYTES,
        refineid_rapp::SignatureAlgorithm::RsaPkcs1Sha256
        | refineid_rapp::SignatureAlgorithm::RsaPkcs1Sha384
        | refineid_rapp::SignatureAlgorithm::RsaPkcs1Sha512
        | refineid_rapp::SignatureAlgorithm::RsaPssSha256 => MOCK_RSA_2048_SIG_BYTES,
    };
    vec![MOCK_FALLBACK_SIGNATURE_BYTE; sig_len]
}
