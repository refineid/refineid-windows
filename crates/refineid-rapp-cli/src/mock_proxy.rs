//! Mock RAPP custodian for automated verification and testing.
//!
//! Listens like a phone does (RAPP v26.10.29 section 2.2.2), shows a pairing
//! code, serves a random offer after the pairing preamble, or `pairing-busy`
//! while it cannot admit an attempt (section 4.2, "Busy Refusal"), answers
//! `CPace` KC2 as responder and `Noise_XXpsk3` with the hello, confirmation, and
//! storage confirmation exchange, then accepts sessions routed by their
//! routing tag, each on its own thread. Every session sends `session.ready`
//! and the card's status (section 8.4), keeps liveness (section 8.3), and
//! serves its operations through the engine's custodian side (section 8):
//! reads at once, a consequential operation after reporting its PIN prompt
//! and approving it, behind the retry floor (section 10.2). It publishes no
//! DNS-SD record: requesters dial it by address.

use std::io::Write as _;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use refineid_lib_core::apdu::status_word::PinRetries;
use refineid_lib_core::auth::{PinSlot, PinStatus};
use refineid_lib_core::pin_retry_risk::check_retry_floor;
use refineid_lib_core::x509::{OwnedCert, UnvalidatedCertificate};
use refineid_rapp::{
    BinaryFrame, CardIdentity, CardInspection, CardOperation, CardOperationResult, CardPresence,
    CardReader, CardStatusMessage, CertificateFingerprint, CpaceAttemptSlot, CpaceKc2Responder,
    DEFAULT_OPERATION_LIFETIME_MS, EncodedPairRecord, EndpointRole, EstablishedSessionRuntime,
    OfferId, OperationRequest, OperationResultMessage, OperationViolation, PairRecord, PairingBusy,
    PairingCode, PairingHandshake, PairingOffer, PingChallenge, PreAuthenticationRateLimit,
    ProfileName, ProgressEvent, ProxyDispatch, ProxyEngineError, ProxyFailure,
    ProxyOperationEngine, RoutingKey, RuntimePoll, RuntimeReceive, SESSION_READY_NONCE_SIZE,
    SessionHandshake, SignatureAlgorithm, TransportProfile, TypedMessage, UserApproval,
    decode_pair_record, encode_pair_record, generate_pair_key_material, route_session,
    standard_pairing_context_v2,
};
use refineid_rapp_core::clock::{continuous_ms, unix_time_ms};
use refineid_rapp_core::engine::SESSION_RECEIVE_TICK;
use refineid_rapp_core::ids::{Challenge, RandomIdExt as _};
use refineid_rapp_core::limits::OFFER_TTL_MS;
use refineid_rapp_core::offer::{format_pairing_code, generate_pairing_code};
use refineid_rapp_core::stream::{STREAM_CANDIDATE_ID, StreamAccept, StreamListener};
use refineid_rapp_core::transport::{
    FrameTransport, STREAM_PROFILE, TcpFrameTransport, TransportError,
};
use zeroize::Zeroizing;

/// How long the mock waits for each frame of a pairing: the requester's
/// user confirms the grants in between.
const PAIRING_STEP_WAIT: Duration = Duration::from_secs(10);

/// How long the mock serves one pairing offer (section 3.3).
const OFFER_LIFETIME: Duration = Duration::from_millis(OFFER_TTL_MS);

/// How long one wait for a pairing connection lasts before the mock looks
/// at whether an attempt paired.
const PAIRING_ACCEPT_TICK: Duration = SESSION_RECEIVE_TICK;

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

/// The SEC1 `ECPrivateKey` of the self-issued mock certificate
/// `mock_cert.der`, checked in as `mock_key.der`.
const DEFAULT_MOCK_KEY_DER: &[u8] = include_bytes!("mock_key.der");

/// The session count that serves sessions until the process ends.
pub const SERVE_FOREVER: usize = 0;

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
    /// Number of sessions to serve before exiting (default: 1), or
    /// [`SERVE_FOREVER`].
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
    /// Hold no card: every session reports the card absent (section 8.4
    /// item 1), so a requester under test withdraws its offer once the grace
    /// of item 3 has passed; every operation ends with `card_error`, as no
    /// card answers, and presence stays as reported (section 10.3).
    pub card_absent: bool,
}

impl MockProxyOptions {
    /// The default options with the checked-in mock certificate.
    ///
    /// # Errors
    /// When the checked-in certificate does not parse.
    pub fn with_mock_certificate() -> Result<Self, String> {
        let certificate =
            OwnedCert::from_der(UnvalidatedCertificate::new(DEFAULT_MOCK_CERT_DER.to_vec()))
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

    /// The card status every session reports. The mock phone reads cards
    /// over NFC only, so it reports no card reader (section 8.4 item 1).
    fn card_status(&self) -> CardStatusMessage {
        let card = if self.card_absent {
            CardPresence::Absent
        } else {
            CardPresence::Present(CertificateFingerprint::of_certificate(
                self.certificate.as_der(),
            ))
        };
        CardStatusMessage {
            card,
            reader: CardReader::Absent,
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
        let encoded = encode_pair_record(&self.record)
            .map_err(|e| format!("cannot serialize pair record: {e:?}"))?;
        let text = Zeroizing::new(hex::encode(encoded.as_bytes()));
        let mut file =
            std::fs::File::create(path).map_err(|e| format!("cannot save state to {path}: {e}"))?;
        file.write_all(text.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|e| format!("cannot save state to {path}: {e}"))
    }

    /// Loads the proxy pairing state from a simple hex-encoded text file.
    ///
    /// # Errors
    /// When the file cannot be read or does not hold a custodian's record.
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let text = Zeroizing::new(
            std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?,
        );
        let line = text.lines().next().ok_or("state file is empty")?;
        let encoded = EncodedPairRecord::from_stored(
            hex::decode(line.trim()).map_err(|e| format!("invalid hex: {e}"))?,
        );
        let record =
            decode_pair_record(&encoded).map_err(|e| format!("invalid pair record: {e:?}"))?;
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
    let (pairing, mut early_session) = if let Some(state_path) = &options.resume_state {
        println!("resuming from state file: {state_path}");
        (ProxyPairing::load_from_file(state_path)?, None)
    } else {
        let (p, early_session) = run_pairing(listener, &options)?;
        if let Some(save_path) = &options.save_state {
            p.save_to_file(save_path)?;
            println!("saved proxy state to: {save_path}");
        }
        (p, early_session)
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
    while options.count == SERVE_FOREVER || sessions_served < options.count {
        let transport = accept_session(listener, &pairing, early_session.take())?;
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

/// What the mock custodian admits under its one offer (section 3.3 items 2
/// to 6): one attempt at a time, pairing connections and `CPace` step 1
/// submissions each at most once per 500 ms.
struct Admission {
    offer_expires_ms: u64,
    slot: CpaceAttemptSlot,
    /// The number of the attempt holding the slot.
    holder: Option<u64>,
    attempts: u64,
    connections: PreAuthenticationRateLimit,
    step_one: PreAuthenticationRateLimit,
}

/// How an attempt the mock admitted ended.
enum AttemptEnd {
    /// The code was refused or the attempt failed before `T_A` verified;
    /// the offer stays as it was.
    Failed(String),
    /// `T_A` verified and consumed the offer; the pairing that followed.
    Consumed(Result<PairRecord, String>),
}

impl Admission {
    fn new(now_ms: u64) -> Self {
        Self {
            offer_expires_ms: now_ms.saturating_add(OFFER_TTL_MS),
            slot: CpaceAttemptSlot::default(),
            holder: None,
            attempts: 0,
            connections: PreAuthenticationRateLimit::default(),
            step_one: PreAuthenticationRateLimit::default(),
        }
    }

    /// Frees the slot of an attempt whose deadline passed.
    fn expire(&mut self, now_ms: u64) {
        if self.slot.has_active_attempt() && !self.slot.attempt_is_live(now_ms) {
            self.slot.end_active_attempt();
            self.holder = None;
        }
    }

    /// The `pairing-busy` for a connection refused at `now_ms`: the larger
    /// of the active attempt's time left, the step 1 spacing left, and
    /// `spacing_wait_ms` (section 4.2, "`PairingBusy` Schema").
    fn busy(&self, now_ms: u64, spacing_wait_ms: u64) -> PairingBusy {
        PairingBusy::until_admissible(
            self.slot
                .active_attempt_wait_ms(now_ms)
                .max(self.step_one.wait_ms(now_ms))
                .max(spacing_wait_ms),
        )
    }

    /// Admits a pairing connection at `now_ms` to be served the offer, or
    /// answers it busy (section 4.2, Bootstrap Read Flow item 2). A refused
    /// connection does not move the connection spacing, and its busy
    /// answer carries the larger of the attempt's time left and every
    /// spacing left.
    fn admit_connection(&mut self, now_ms: u64) -> Result<(), PairingBusy> {
        self.expire(now_ms);
        let spacing_wait_ms = self.connections.wait_ms(now_ms);
        if self.slot.has_active_attempt()
            || self.step_one.wait_ms(now_ms) > 0
            || !self.connections.admit(now_ms)
        {
            return Err(self.busy(now_ms, spacing_wait_ms));
        }
        Ok(())
    }

    /// Admits the attempt a `CPace` step 1 arriving at `now_ms` starts and
    /// returns its number, or answers it busy (section 4.2, "Busy Refusal"
    /// item 2).
    fn admit_step_one(&mut self, now_ms: u64) -> Result<u64, PairingBusy> {
        self.expire(now_ms);
        if self.slot.has_active_attempt()
            || !self.step_one.admit(now_ms)
            || !self.slot.admit(now_ms, self.offer_expires_ms)
        {
            return Err(self.busy(now_ms, 0));
        }
        self.attempts += 1;
        self.holder = Some(self.attempts);
        Ok(self.attempts)
    }

    /// Ends `attempt` as failed, unless another holds the slot.
    fn fail(&mut self, attempt: u64) {
        if self.holder == Some(attempt) {
            self.slot.end_active_attempt();
            self.holder = None;
        }
    }

    /// Ends `attempt` as the one whose `T_A` verified at `now_ms`, which
    /// consumes the offer, or refuses it once its deadline passed.
    fn consume(&mut self, attempt: u64, now_ms: u64) -> bool {
        if self.holder != Some(attempt) || !self.slot.attempt_is_live(now_ms) {
            return false;
        }
        self.slot.consume();
        self.holder = None;
        true
    }
}

/// Locks the admission state; a worker that panicked leaves it usable.
fn admission(admission: &Mutex<Admission>) -> std::sync::MutexGuard<'_, Admission> {
    admission.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Sends a `pairing-busy` and closes the connection (section 4.2, "Busy
/// Refusal").
fn answer_busy(mut transport: TcpFrameTransport, busy: PairingBusy) {
    match busy.to_cbor() {
        Ok(bytes) => {
            if let Err(error) = transport.send_frame(&bytes) {
                println!("busy answer not sent: {error:?}");
            }
        }
        Err(error) => println!("busy answer not encoded: {error:?}"),
    }
}

/// Shows the code and serves the offer to every pairing connection it can
/// admit, each on its own thread, until one pairs or the offer's lifetime
/// ends (section 3.3). One attempt runs at a time; a connection or a
/// `CPace` step 1 it cannot admit is answered `pairing-busy` (section 4.2,
/// "Busy Refusal"). A failed attempt frees the slot and leaves the offer as
/// it was; a verified `T_A` consumes it. A session connection that arrives
/// once the offer is consumed is handed back with the pairing.
fn run_pairing(
    listener: &StreamListener,
    options: &MockProxyOptions,
) -> Result<(ProxyPairing, Option<StreamAccept>), String> {
    let code = match &options.code {
        Some(code) => code.clone(),
        None => generate_pairing_code().map_err(|e| format!("rng failed: {e}"))?,
    };
    let offer = custodian_offer()?;
    println!("pairing code: {}", format_pairing_code(&code));
    let code = PairingCode::parse(&code).map_err(|e| format!("not a pairing code: {e}"))?;
    let offer_ends = Instant::now() + OFFER_LIFETIME;
    let admission_state = Mutex::new(Admission::new(continuous_ms()));
    let (ended, endings) = channel();
    std::thread::scope(|workers| {
        loop {
            while let Ok(end) = endings.try_recv() {
                match end {
                    AttemptEnd::Failed(error) => println!("pairing attempt failed: {error}"),
                    AttemptEnd::Consumed(record) => {
                        return record.map(|record| (ProxyPairing { record }, None));
                    }
                }
            }
            let remaining = offer_ends.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("pairing offer expired".into());
            }
            let accepted = listener
                .accept_timeout(remaining.min(PAIRING_ACCEPT_TICK))
                .map_err(|e| format!("accept failed: {e:?}"))?;
            let Some(accepted) = accepted else {
                continue;
            };
            let StreamAccept::Pairing(transport) = accepted else {
                if admission(&admission_state).slot.is_consumed() {
                    let record = consumed_pairing(&endings)?;
                    return Ok((ProxyPairing { record }, Some(accepted)));
                }
                println!("ignored a session connection while pairing");
                continue;
            };
            let admitted = {
                let mut state = admission(&admission_state);
                if state.slot.is_consumed() {
                    println!("closed a pairing connection; the offer is consumed");
                    continue;
                }
                state.admit_connection(continuous_ms())
            };
            if let Err(busy) = admitted {
                println!("answered a pairing connection busy");
                answer_busy(transport, busy);
                continue;
            }
            let ended = ended.clone();
            let (offer, code, admission_state) = (&offer, &code, &admission_state);
            workers.spawn(move || {
                pair_once(transport, offer, code, options, admission_state, &ended);
            });
        }
    })
}

/// Waits for the attempt that consumed the offer to end its pairing.
fn consumed_pairing(endings: &std::sync::mpsc::Receiver<AttemptEnd>) -> Result<PairRecord, String> {
    loop {
        match endings.recv() {
            Ok(AttemptEnd::Consumed(record)) => return record,
            Ok(AttemptEnd::Failed(error)) => println!("pairing attempt failed: {error}"),
            Err(_) => return Err("the consuming attempt ended without a pairing".into()),
        }
    }
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

/// One admitted pairing connection: the offer bootstrap, then `CPace` KC2
/// as responder once its step 1 is admitted, or `pairing-busy` in place of
/// step 2 when it is not; after a verified `T_A`, `Noise_XXpsk3` and the
/// hello, confirmation, and storage exchange. How an admitted attempt ended
/// goes to `ended`.
fn pair_once(
    mut transport: TcpFrameTransport,
    offer: &PairingOffer,
    code: &PairingCode,
    options: &MockProxyOptions,
    admission_state: &Mutex<Admission>,
    ended: &Sender<AttemptEnd>,
) {
    let step_one = match serve_offer(&mut transport, offer) {
        Ok(step_one) => step_one,
        Err(error) => {
            println!("pairing connection closed before an attempt: {error}");
            return;
        }
    };
    let admitted = {
        let mut state = admission(admission_state);
        if state.slot.is_consumed() {
            println!("closed a pairing attempt; the offer is consumed");
            return;
        }
        state.admit_step_one(continuous_ms())
    };
    let attempt = match admitted {
        Ok(attempt) => attempt,
        Err(busy) => {
            println!("answered a pairing attempt busy");
            answer_busy(transport, busy);
            return;
        }
    };
    let verified = run_cpace(&mut transport, offer, code, &step_one);
    let end = match verified {
        Ok(pairing_secret) if admission(admission_state).consume(attempt, continuous_ms()) => {
            AttemptEnd::Consumed(finish_pairing(transport, offer, &pairing_secret, options))
        }
        Ok(_) => {
            admission(admission_state).fail(attempt);
            AttemptEnd::Failed("T_A arrived after the attempt deadline".into())
        }
        Err(error) => {
            admission(admission_state).fail(attempt);
            AttemptEnd::Failed(error)
        }
    };
    let _ = ended.send(end);
}

/// Sends the offer and receives `CPace` step 1.
fn serve_offer(
    transport: &mut TcpFrameTransport,
    offer: &PairingOffer,
) -> Result<BinaryFrame, String> {
    let bootstrap = offer
        .to_cbor()
        .map_err(|e| format!("offer encoding failed: {e:?}"))?;
    transport
        .send_frame(&bootstrap)
        .map_err(|e| format!("send offer failed: {e:?}"))?;
    receive_pairing_frame(transport, "Y_A")
}

/// `CPace` KC2 as responder on an admitted step 1, up to a verified `T_A`.
fn run_cpace(
    transport: &mut TcpFrameTransport,
    offer: &PairingOffer,
    code: &PairingCode,
    step_one: &BinaryFrame,
) -> Result<refineid_rapp::PairingSecret, String> {
    let offer_hash = offer
        .offer_hash()
        .map_err(|e| format!("offer hash failed: {e:?}"))?;
    let context = standard_pairing_context_v2(&offer_hash, STREAM_PROFILE, STREAM_CANDIDATE_ID)
        .map_err(|e| format!("context failed: {e:?}"))?;
    let mut entropy = Zeroizing::new([0_u8; CPACE_SCALAR_ENTROPY_BYTES]);
    getrandom::fill(entropy.as_mut()).map_err(|e| format!("rng failed: {e}"))?;
    let (step_two, waiting) =
        CpaceKc2Responder::process_step1_frame(code, &context, &offer.offer_id, step_one, &entropy)
            .map_err(|e| format!("Y_A refused: {e:?}"))?;
    drop(entropy);
    send_pairing_frame(transport, &step_two, "Y_B")?;
    let step_three = receive_pairing_frame(transport, "T_A (mistyped code?)")?;
    waiting
        .process_step3_frame(&step_three)
        .map_err(|e| format!("T_A refused: {e:?}"))
}

/// `Noise_XXpsk3` under the `CPace` key, then the hello, confirmation, and
/// storage exchange.
fn finish_pairing(
    mut transport: TcpFrameTransport,
    offer: &PairingOffer,
    pairing_secret: &refineid_rapp::PairingSecret,
    options: &MockProxyOptions,
) -> Result<PairRecord, String> {
    let keys = generate_pair_key_material().map_err(|e| format!("key generation failed: {e:?}"))?;
    let mut handshake = PairingHandshake::begin(
        EndpointRole::Proxy,
        offer.clone(),
        STREAM_CANDIDATE_ID,
        keys,
        pairing_secret,
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

/// Accepts connections, `early` first when given, until one opens a
/// session for this pairing; others are closed without changing state.
fn accept_session(
    listener: &StreamListener,
    pairing: &ProxyPairing,
    mut early: Option<StreamAccept>,
) -> Result<TcpFrameTransport, String> {
    loop {
        let accepted = match early.take() {
            Some(accepted) => accepted,
            None => listener
                .accept()
                .map_err(|e| format!("accept failed: {e:?}"))?,
        };
        match accepted {
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
/// its PIN prompt, approved at once, behind the retry floor. With no card
/// held, the card answers nothing and the operation ends with `card_error`,
/// presence unchanged (sections 8.4 item 1 and 10.3).
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
        ProxyDispatch::ExecuteSafeRead { read, .. } if options.card_absent => {
            println!("no card for {:?}", read.operation);
            session
                .operations
                .finish_failure(operation_id, ProxyFailure::CardError)
        }
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

/// The one card command an approval gives: `card_error` with no card
/// present, else behind the retry floor (section 10.2).
fn execute(
    session: &mut CustodianSession,
    operation_id: refineid_rapp::OperationId,
    operation: &CardOperation,
    options: &MockProxyOptions,
) -> Result<Result<ProxyDispatch, ProxyEngineError>, String> {
    if options.card_absent {
        println!("no card for {operation:?}");
        return Ok(session
            .operations
            .finish_failure(operation_id, ProxyFailure::CardError));
    }
    let (slot, remaining) = match operation {
        CardOperation::BrowserAuthenticate { .. } => (PinSlot::Pin1, options.pin1_attempts),
        _ => (PinSlot::Pin2, options.pin2_attempts),
    };
    let status = PinRetries::from_nibble(remaining).map_or(PinStatus::NoInfo, PinStatus::Remaining);
    if check_retry_floor(slot.into(), status).is_err() {
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
    if let Ok(key) = sec1::EcPrivateKey::try_from(DEFAULT_MOCK_KEY_DER)
        && let Ok(signing_key) = p384::ecdsa::SigningKey::from_slice(key.private_key)
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

#[cfg(test)]
mod tests {
    use super::Admission;
    use refineid_rapp::{CPACE_ATTEMPT_WINDOW_MS, PRE_AUTHENTICATION_SPACING_MS};

    /// The monotonic time the offer is shown at.
    const SHOWN_AT_MS: u64 = 10_000;

    #[test]
    fn a_connection_during_an_attempt_is_busy_and_moves_no_spacing() {
        let mut admission = Admission::new(SHOWN_AT_MS);
        assert!(admission.admit_connection(SHOWN_AT_MS).is_ok());
        let attempt = admission.admit_step_one(SHOWN_AT_MS).expect("admitted");

        let probe_ms = SHOWN_AT_MS + PRE_AUTHENTICATION_SPACING_MS;
        let busy = admission
            .admit_connection(probe_ms)
            .expect_err("an attempt is active");
        assert_eq!(
            busy.retry_after_ms(),
            CPACE_ATTEMPT_WINDOW_MS - PRE_AUTHENTICATION_SPACING_MS
        );

        admission.fail(attempt);
        assert!(admission.admit_connection(probe_ms).is_ok());
    }

    #[test]
    fn a_busy_answer_carries_the_connection_spacing_left() {
        let mut admission = Admission::new(SHOWN_AT_MS);
        assert!(admission.admit_connection(SHOWN_AT_MS).is_ok());
        let busy = admission
            .admit_connection(SHOWN_AT_MS)
            .expect_err("the spacing has not passed");
        assert_eq!(busy.retry_after_ms(), PRE_AUTHENTICATION_SPACING_MS);
    }
}
