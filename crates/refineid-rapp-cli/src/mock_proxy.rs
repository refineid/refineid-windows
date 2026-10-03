//! Mock authorization proxy for RAPP automated verification and testing.
//!
//! Connects to a RAPP requester (such as `refineid-rapp pair-demo` or the
//! `RefineID` Windows Settings app), performs `Noise_XXpsk3` pairing with a
//! 6-digit numeric pairing code or pairing offer URI, and serves typed card
//! operations (inspection, identity, certificate, and authentication).

#![expect(
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::assigning_clones,
    clippy::cloned_ref_to_slice_refs,
    clippy::collapsible_if,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::uninlined_format_args,
    reason = "Mock proxy test harness with mock state serialization and session handling"
)]

use std::time::{Duration, Instant};

use refineid_rapp::cpace::CpaceState;
use refineid_rapp::{
    BinaryFrame, CardInspection, CardOperation, CardOperationResult, EndpointRole,
    EstablishedEndpoint, LivenessMessage, OperationReference, OperationRequest,
    OperationResultMessage, PairRecord, PairStore, PairStoreError, PairTombstone, PairingHandshake,
    PairingOffer, PairingOfferUri, PairingSecret, ReceiveOutcome, SessionHandshake, TypedMessage,
    decode_pair_record, encode_pair_record, generate_pair_key_material,
};
use refineid_rapp_core::stream::{StreamRendezvous, dial};
use refineid_rapp_core::transport::FrameTransport;
use zeroize::Zeroize;

/// Default socket receive deadline.
const DEADLINE: Duration = Duration::from_secs(10);

/// Default candidate identifier.
const DEFAULT_CANDIDATE_ID: &str = "stream-1";

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
    /// Explicit endpoint to connect to (e.g. "127.0.0.1:47110").
    pub connect: Option<String>,
    /// 6-digit numeric pairing code.
    pub code: Option<String>,
    /// Full RAPP pairing offer URI (`rapp:...`).
    pub uri: Option<String>,
    /// Candidate ID (default: "stream-1").
    pub candidate_id: String,
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
            connect: None,
            code: None,
            uri: None,
            candidate_id: DEFAULT_CANDIDATE_ID.to_owned(),
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
    /// Connected remote endpoint address.
    pub endpoint: String,
}

impl ProxyPairing {
    /// Saves the proxy pairing state to a simple hex-encoded text file.
    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let cbor = encode_pair_record(&self.record)
            .map_err(|e| format!("cannot serialize pair record: {e:?}"))?;
        let content = format!("{}\n{}\n", hex::encode(cbor), self.endpoint);
        std::fs::write(path, content).map_err(|e| format!("cannot save state to {path}: {e}"))
    }

    /// Loads the proxy pairing state from a simple hex-encoded text file.
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let lines: Vec<&str> = text.lines().collect();
        if lines.len() < 2 {
            return Err("state file is truncated".into());
        }
        let cbor = hex::decode(lines[0].trim()).map_err(|e| format!("invalid hex: {e}"))?;
        let record =
            decode_pair_record(&cbor).map_err(|e| format!("invalid pair record: {e:?}"))?;
        let endpoint = lines[1].trim().to_owned();
        Ok(Self { record, endpoint })
    }
}

/// Runs the mock proxy workflow according to the provided options.
pub fn run_mock_proxy(options: MockProxyOptions) -> Result<(), String> {
    println!("starting RAPP mock proxy...");
    let pairing = if let Some(state_path) = &options.resume_state {
        println!("resuming from state file: {state_path}");
        let mut p = ProxyPairing::load_from_file(state_path)?;
        if let Some(connect) = &options.connect {
            p.endpoint = connect.clone();
        }
        p
    } else {
        let p = run_pairing(&options)?;
        if let Some(save_path) = &options.save_state {
            p.save_to_file(save_path)?;
            println!("saved proxy state to: {save_path}");
        }
        p
    };

    println!(
        "pairing active (pair_id: {}, rendezvous_token: {})",
        hex::encode(pairing.record.pair_id().as_bytes()),
        hex::encode(pairing.record.rendezvous_token().as_bytes())
    );

    let mut sessions_served = 0;
    while options.count == 0 || sessions_served < options.count {
        sessions_served += 1;
        println!(
            "connecting session {sessions_served}{}...",
            if options.count > 0 {
                format!("/{}", options.count)
            } else {
                String::new()
            }
        );
        serve_one_session(&pairing, &options)?;
    }
    println!("mock proxy finished successfully (served {sessions_served} sessions)");
    Ok(())
}

fn resolve_offer(options: &MockProxyOptions) -> Result<(PairingOffer, String), String> {
    if let Some(uri_str) = &options.uri {
        let offer = PairingOffer::from_uri(PairingOfferUri::from_scanned_text(uri_str.clone()))
            .map_err(|e| format!("invalid offer URI: {e:?}"))?;
        let endpoint = if let Some(explicit) = &options.connect {
            explicit.clone()
        } else {
            let candidate = offer
                .transports
                .iter()
                .find(|t| t.profile == refineid_rapp_core::transport::STREAM_PROFILE)
                .ok_or("offer contains no stream candidate")?;
            let params =
                refineid_rapp::StreamCandidateParameters::from_parameters(&candidate.parameters)
                    .map_err(|e| format!("invalid candidate parameters: {e:?}"))?;
            params
                .endpoints()
                .first()
                .cloned()
                .ok_or("offer has empty endpoint list")?
        };
        Ok((offer, endpoint))
    } else if let Some(code) = &options.code {
        let endpoint = options
            .connect
            .clone()
            .ok_or("--connect <host:port> is required when pairing with --code")?;
        let normalized = refineid_rapp_core::offer::normalize_pairing_code(code);
        let offer_id = refineid_rapp::cpace::derive_manual_offer_id(&normalized)
            .map_err(|e| format!("invalid code: {e:?}"))?;
        let candidate_params =
            refineid_rapp::StreamCandidateParameters::new(vec![endpoint.clone()])
                .map_err(|e| format!("candidate parameters failed: {e:?}"))?;
        let offer = PairingOffer::reconstruct(
            offer_id,
            vec![refineid_rapp::MANDATORY_PAIRING_SUITE.to_owned()],
            vec![
                refineid_rapp::ProfileName::CardStatus.as_str().to_owned(),
                refineid_rapp::ProfileName::Authentication
                    .as_str()
                    .to_owned(),
                refineid_rapp::ProfileName::DocumentSigning
                    .as_str()
                    .to_owned(),
            ],
            vec![refineid_rapp::TransportCandidate {
                profile: refineid_rapp_core::transport::STREAM_PROFILE.to_owned(),
                candidate_id: options.candidate_id.clone(),
                parameters: candidate_params.to_parameters(),
            }],
            refineid_rapp_core::limits::OFFER_TTL_MAX_MS,
        )
        .map_err(|e| format!("offer reconstruct failed: {e:?}"))?;
        Ok((offer, endpoint))
    } else {
        Err(
            "either --uri <rapp:...> or (--connect <host:port> and --code <code>) must be specified"
                .into(),
        )
    }
}

fn run_pairing(options: &MockProxyOptions) -> Result<ProxyPairing, String> {
    let (offer, endpoint) = resolve_offer(options)?;
    println!("dialing pairing connection to {endpoint}...");
    let mut transport = dial(
        &[endpoint.clone()],
        &options.candidate_id,
        DEADLINE,
        &StreamRendezvous::Pairing,
    )
    .map_err(|e| format!("cannot connect to requester at {endpoint}: {e:?}"))?;

    let pairing_secret = if let Some(code) = &options.code {
        let mut entropy = [0u8; 64];
        getrandom::fill(&mut entropy).map_err(|e| format!("rng failed: {e}"))?;
        let cpace = CpaceState::new(
            refineid_rapp::HandshakeRole::Responder,
            code,
            &offer.offer_id,
            &entropy,
        )
        .map_err(|e| format!("cpace init failed: {e:?}"))?;
        entropy.zeroize();

        // Send Responder's CPace frame
        let my_frame = cpace
            .write_message()
            .map_err(|e| format!("cpace write frame failed: {e:?}"))?;
        transport
            .send_frame(my_frame.as_bytes())
            .map_err(|e| format!("send cpace frame failed: {e:?}"))?;

        // Receive Initiator's CPace frame
        let peer_frame_bytes = transport
            .receive_frame()
            .map_err(|e| format!("receive cpace frame failed: {e:?}"))?;
        let peer_frame = BinaryFrame::reconstruct(peer_frame_bytes)
            .map_err(|e| format!("decode cpace frame failed: {e:?}"))?;
        cpace
            .read_message(&peer_frame)
            .map_err(|e| format!("cpace derive secret failed: {e:?}"))?
    } else {
        PairingSecret::from_random_bytes([0u8; 32])
    };

    let keys = generate_pair_key_material().map_err(|e| format!("key generation failed: {e:?}"))?;
    let mut handshake = PairingHandshake::begin(
        EndpointRole::Proxy,
        offer,
        &options.candidate_id,
        keys,
        &pairing_secret,
    )
    .map_err(|fail| format!("pairing handshake failed: {:?}", fail.error()))?;

    // Message 1 (Requester -> Proxy)
    let m1_bytes = transport
        .receive_frame()
        .map_err(|e| format!("receive frame 1 failed: {e:?}"))?;
    let m1 =
        BinaryFrame::reconstruct(m1_bytes).map_err(|e| format!("frame 1 decode failed: {e:?}"))?;
    handshake
        .read_message(&m1)
        .map_err(|e| format!("handshake read 1 failed: {e:?}"))?;

    // Message 2 (Proxy -> Requester)
    let m2 = handshake
        .write_message()
        .map_err(|e| format!("handshake write 2 failed: {e:?}"))?;
    transport
        .send_frame(m2.as_bytes())
        .map_err(|e| format!("send frame 2 failed: {e:?}"))?;

    // Message 3 (Requester -> Proxy)
    let m3_bytes = transport
        .receive_frame()
        .map_err(|e| format!("receive frame 3 failed: {e:?}"))?;
    let m3 =
        BinaryFrame::reconstruct(m3_bytes).map_err(|e| format!("frame 3 decode failed: {e:?}"))?;
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

    // Receive Requester Hello
    let req_hello_bytes = transport
        .receive_frame()
        .map_err(|e| format!("receive hello failed: {e:?}"))?;
    let req_hello_frame = BinaryFrame::reconstruct(req_hello_bytes)
        .map_err(|e| format!("hello frame decode failed: {e:?}"))?;
    let req_hello = confirmation
        .receive_hello(&req_hello_frame, now_ms)
        .map_err(|e| format!("verify hello failed: {e:?}"))?;
    println!(
        "requester hello from: {} ({})",
        req_hello.display_name, req_hello.platform
    );

    // Send Proxy Hello
    let proxy_hello = confirmation
        .send_hello(options.name.clone(), options.platform.clone())
        .map_err(|e| format!("send hello failed: {e:?}"))?;
    transport
        .send_frame(proxy_hello.as_bytes())
        .map_err(|e| format!("send hello frame failed: {e:?}"))?;

    // Receive Requester Confirmation
    let req_conf_bytes = transport
        .receive_frame()
        .map_err(|e| format!("receive confirm failed: {e:?}"))?;
    let req_conf_frame = BinaryFrame::reconstruct(req_conf_bytes)
        .map_err(|e| format!("confirm frame decode failed: {e:?}"))?;
    let req_conf = confirmation
        .receive_confirmation(&req_conf_frame, now_ms)
        .map_err(|e| format!("verify confirm failed: {e:?}"))?;
    let granted_profiles = req_conf.to_vec();
    println!("requester granted profiles: {:?}", granted_profiles);

    // Send Proxy Confirmation
    let proxy_conf = confirmation
        .send_confirmation(granted_profiles)
        .map_err(|e| format!("send confirm failed: {e:?}"))?;
    transport
        .send_frame(proxy_conf.as_bytes())
        .map_err(|e| format!("send confirm frame failed: {e:?}"))?;

    let record = confirmation
        .into_pair_record(now_ms)
        .map_err(|e| format!("into_pair_record failed: {e:?}"))?;

    Ok(ProxyPairing { record, endpoint })
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

fn serve_one_session(pairing: &ProxyPairing, options: &MockProxyOptions) -> Result<(), String> {
    println!("dialing session connection to {}...", pairing.endpoint);
    let deadline = Instant::now() + Duration::from_secs(3600);
    let mut transport = loop {
        match dial(
            &[pairing.endpoint.clone()],
            &options.candidate_id,
            Duration::from_secs(2),
            &StreamRendezvous::Session(pairing.record.rendezvous_token()),
        ) {
            Ok(t) => break t,
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(format!("session connect timeout: {e:?}"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };

    println!("running Noise_KK session handshake...");
    let mut handshake = SessionHandshake::begin_proxy(&pairing.record)
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
                pin1_factory: false,
                pin2_factory: false,
                pin1_attempts: Some(options.pin1_attempts),
                pin2_attempts: Some(options.pin2_attempts),
                puk_attempts: None,
            });
            let msg =
                TypedMessage::OperationResult(OperationResultMessage::completed(op_ref, result));
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
            let result = CardOperationResult::Identity {
                display_name: options.identity_name.clone(),
                person_id: options.person_id.clone(),
            };
            let msg =
                TypedMessage::OperationResult(OperationResultMessage::completed(op_ref, result));
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
                TypedMessage::OperationResult(OperationResultMessage::completed(op_ref, result));
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
            println!("serving browser_authenticate: origin='{origin}' sending OperationPrepared");
            let prep_msg = TypedMessage::OperationPrepared(op_ref);
            let frame = endpoint
                .send(&prep_msg)
                .map_err(|e| format!("send prep failed: {e:?}"))?;
            transport
                .send_frame(frame.as_bytes())
                .map_err(|e| format!("send prep frame failed: {e:?}"))?;

            // Await Commit
            let commit_bytes = transport
                .receive_frame()
                .map_err(|e| format!("receive commit failed: {e:?}"))?;
            let commit_frame = BinaryFrame::reconstruct(commit_bytes)
                .map_err(|e| format!("commit frame failed: {e:?}"))?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64);
            let outcome = endpoint
                .receive(store, &commit_frame, now_ms)
                .map_err(|e| format!("commit receive failed: {e:?}"))?;
            let ReceiveOutcome::Message(TypedMessage::OperationCommit(comm_ref)) = outcome else {
                return Err("expected OperationCommit".into());
            };
            if comm_ref != op_ref {
                return Err("commit mismatch".into());
            }

            let sig_bytes = sign_digest(&digest, algorithm);
            let result = CardOperationResult::Signature(sig_bytes);
            let res_msg =
                TypedMessage::OperationResult(OperationResultMessage::completed(op_ref, result));
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
            println!("serving sign_document: document='{document_name}' sending OperationPrepared");
            let prep_msg = TypedMessage::OperationPrepared(op_ref);
            let frame = endpoint
                .send(&prep_msg)
                .map_err(|e| format!("send prep failed: {e:?}"))?;
            transport
                .send_frame(frame.as_bytes())
                .map_err(|e| format!("send prep frame failed: {e:?}"))?;

            // Await Commit
            let commit_bytes = transport
                .receive_frame()
                .map_err(|e| format!("receive commit failed: {e:?}"))?;
            let commit_frame = BinaryFrame::reconstruct(commit_bytes)
                .map_err(|e| format!("commit frame failed: {e:?}"))?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64);
            let outcome = endpoint
                .receive(store, &commit_frame, now_ms)
                .map_err(|e| format!("commit receive failed: {e:?}"))?;
            let ReceiveOutcome::Message(TypedMessage::OperationCommit(comm_ref)) = outcome else {
                return Err("expected OperationCommit".into());
            };
            if comm_ref != op_ref {
                return Err("commit mismatch".into());
            }

            let sig_bytes = sign_digest(&digest, algorithm);
            let result = CardOperationResult::Signature(sig_bytes);
            let res_msg =
                TypedMessage::OperationResult(OperationResultMessage::completed(op_ref, result));
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
