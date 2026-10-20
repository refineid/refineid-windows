//! The agent's two threads: the pipe server and the phone session.

use std::process::ExitCode;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread;
use std::time::{Duration, Instant};

use refineid_agent_pipe::identity::computer_name;
use refineid_agent_pipe::server::{AgentLock, PipeServer};
use refineid_agent_pipe::wire::{SignAnswer, SignRequest};
use refineid_agent_pipe::{
    OPERATION_LIFETIME, PipeError, REACH_WINDOW, SIGNATURE_DEADLINE, TRANSFER_MARGIN,
    program_label, requester_context,
};
use refineid_rapp::RoutingKey;
use refineid_rapp_ble::gatt::BleLink;
use refineid_rapp_ble::link::ProximityGate;
use refineid_rapp_ble::reach::{Attempt, reach_session};
use refineid_rapp_core::engine::{
    OperationOutcome, Requester, RequesterConfig, Session, SessionEnd,
};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::CloseReason;
use refineid_rapp_core::operations::{CardOperation, CardOperationResult, CertificateKind};
use refineid_rapp_core::store::{MemoryJournal, PairingStore};
use refineid_windows_credential_store::{
    ProtectedPairingStore, install_browser_certificate, remove_browser_certificates,
};

/// How often an open session is checked for liveness while idle.
const LIVENESS_INTERVAL: Duration = Duration::from_secs(10);
/// How long the agent waits before looking for the phone again after a
/// search found nothing, unless a signature request arrives first.
const SEARCH_PAUSE: Duration = Duration::from_secs(5);
/// How long the agent waits before reading the pairing store again when it
/// holds no usable pairing.
const STORE_PAUSE: Duration = Duration::from_secs(10);
/// How long a failed pipe waits before it is served again.
const PIPE_PAUSE: Duration = Duration::from_secs(1);
/// Frame receive deadline on the link: an operation's lifetime and the
/// transfer of its result.
const RECEIVE_DEADLINE: Duration =
    Duration::from_secs(OPERATION_LIFETIME.as_secs() + TRANSFER_MARGIN.as_secs());
/// The operation lifetime sent on the wire, in milliseconds.
const OPERATION_LIFETIME_MS: u64 = OPERATION_LIFETIME.as_secs() * 1_000;

/// One signature request on its way from the pipe to the session.
struct Job {
    request: SignRequest,
    /// What the phone shows as the asking party (W-R-10).
    requester: String,
    reply: Sender<SignAnswer>,
}

impl Job {
    fn answer(self, answer: SignAnswer) {
        // The pipe side may have given up waiting; nothing is owed then.
        let _ = self.reply.send(answer);
    }
}

fn log(started: Instant, line: &str) {
    eprintln!("[{:>8.1}s] {line}", started.elapsed().as_secs_f64());
}

/// Serves the pipe until the process ends.
pub fn run() -> ExitCode {
    let started = Instant::now();
    let lock = match AgentLock::acquire() {
        Ok(lock) => lock,
        Err(error) => {
            log(started, &error.to_string());
            return ExitCode::FAILURE;
        }
    };
    let mut server = match PipeServer::bind(&lock) {
        Ok(server) => server,
        Err(error) => {
            log(
                started,
                &format!("the agent pipe cannot be created: {error}"),
            );
            return ExitCode::FAILURE;
        }
    };
    let (jobs, inbox) = channel();
    thread::spawn(move || serve_phone(started, &inbox));
    let computer = computer_name();
    log(started, "serving the key storage provider");
    loop {
        let mut client = match server.accept() {
            Ok(client) => client,
            Err(PipeError::Stranger) => {
                log(started, "refused a client of another user or session");
                continue;
            }
            Err(error) => {
                log(started, &format!("pipe: {error}"));
                thread::sleep(PIPE_PAUSE);
                continue;
            }
        };
        let program = program_label(&client.identity().image);
        let answer = match client.request() {
            Ok(request) => {
                log(started, &format!("signature requested by {program}"));
                let (reply, answered) = channel();
                let job = Job {
                    request,
                    requester: requester_context(&program, &computer),
                    reply,
                };
                if jobs.send(job).is_err() {
                    SignAnswer::Failed
                } else {
                    answered
                        .recv_timeout(SIGNATURE_DEADLINE)
                        .unwrap_or(SignAnswer::Cancelled)
                }
            }
            Err(error) => {
                log(started, &format!("refused a request: {error}"));
                SignAnswer::Failed
            }
        };
        log(started, &format!("answer: {}", describe(&answer)));
        if let Err(error) = client.answer(&answer) {
            log(started, &format!("the answer was not delivered: {error}"));
        }
    }
}

fn describe(answer: &SignAnswer) -> String {
    match answer {
        SignAnswer::Signature(bytes) => format!("signature, {} bytes", bytes.len()),
        other => format!("{other:?}"),
    }
}

/// The stored pairing the agent serves, with its routing key.
struct Pairing {
    requester: Requester<ProtectedPairingStore, MemoryJournal>,
    pair_id: PairId,
    key: RoutingKey,
}

fn load_pairing(started: Instant, offered: &mut Option<PairId>) -> Option<Pairing> {
    let store = match ProtectedPairingStore::load() {
        Ok(store) => store,
        Err(error) => {
            log(
                started,
                &format!("the pairing store cannot be loaded: {error}"),
            );
            return None;
        }
    };
    let record = store.usable_pairing()?.clone();
    let key = RoutingKey::derive(&record.to_core_pair_record().ok()?).ok()?;
    // W-R-8: the certificate is offered whenever the pairing is usable and
    // its certificate known, before a session is open.
    if let Some(certificate) = &record.auth_cert
        && *offered != Some(record.pair_id)
    {
        offer_certificate(started, certificate, record.pair_id, offered);
    }
    Some(Pairing {
        requester: Requester::new(
            RequesterConfig {
                display_name: "RefineID Windows".to_owned(),
                platform: "Windows".to_owned(),
            },
            store,
            MemoryJournal::new(),
        ),
        pair_id: record.pair_id,
        key,
    })
}

fn offer_certificate(
    started: Instant,
    certificate: &[u8],
    pair_id: PairId,
    offered: &mut Option<PairId>,
) {
    match install_browser_certificate(certificate, pair_id) {
        Ok(()) => {
            log(started, "the phone's certificate is offered to browsers");
            *offered = Some(pair_id);
        }
        Err(error) => log(
            started,
            &format!("the certificate was not offered: {error}"),
        ),
    }
}

fn withdraw_certificates(started: Instant, offered: &mut Option<PairId>) {
    match remove_browser_certificates() {
        Ok(count) => log(started, &format!("withdrew {count} offered certificates")),
        Err(error) => log(started, &format!("certificates not withdrawn: {error}")),
    }
    *offered = None;
}

/// The session thread: keeps the phone's session and runs every job.
fn serve_phone(started: Instant, inbox: &Receiver<Job>) {
    // W-R-8: certificates offered by an earlier run are purged first.
    let mut offered = None;
    withdraw_certificates(started, &mut offered);
    let mut pending: Option<Job> = None;
    loop {
        let Some(mut pairing) = load_pairing(started, &mut offered) else {
            if let Some(job) = pending.take() {
                job.answer(SignAnswer::Failed);
            }
            match inbox.recv_timeout(STORE_PAUSE) {
                Ok(job) => job.answer(SignAnswer::Failed),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            continue;
        };
        let reached = reach_session(
            &mut pairing.requester,
            pairing.pair_id,
            &pairing.key,
            ProximityGate::SPECIFICATION,
            REACH_WINDOW,
            RECEIVE_DEADLINE,
            |attempt| match attempt {
                Attempt::Routing(advertiser) => log(
                    started,
                    &format!(
                        "routing a session to an advertiser at {} dBm",
                        advertiser.reading.rssi().dbm()
                    ),
                ),
                Attempt::LinkFailed(error) => log(started, &format!("  {error}")),
                Attempt::Refused(error) => log(started, &format!("  no session: {error:?}")),
            },
        );
        let mut session = match reached {
            Ok(session) => session,
            Err(error) => {
                if let Some(job) = pending.take() {
                    log(
                        started,
                        &format!("no phone for the waiting request: {error}"),
                    );
                    job.answer(SignAnswer::NoPhone);
                }
                match inbox.recv_timeout(SEARCH_PAUSE) {
                    Ok(job) => pending = Some(job),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return,
                }
                continue;
            }
        };
        log(started, "session open over Bluetooth");
        if offered != Some(pairing.pair_id) {
            learn_certificate(started, &mut pairing, &mut session, &mut offered);
        }
        if let Some(job) = pending.take() {
            sign(started, &mut pairing, &mut session, job);
        }
        loop {
            match inbox.recv_timeout(LIVENESS_INTERVAL) {
                Ok(job) => sign(started, &mut pairing, &mut session, job),
                Err(RecvTimeoutError::Timeout) => {
                    if pairing.requester.check_liveness(&mut session).is_err() {
                        break;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    pairing
                        .requester
                        .disconnect(&mut session, CloseReason::UserDisconnect);
                    return;
                }
            }
            if Requester::<ProtectedPairingStore, MemoryJournal>::session_end(&session).is_some() {
                break;
            }
        }
        let end = Requester::<ProtectedPairingStore, MemoryJournal>::session_end(&session);
        log(started, &format!("session ended: {end:?}"));
        if matches!(
            end,
            Some(SessionEnd::PeerClose(CloseReason::PairingRevoked) | SessionEnd::Violation)
        ) {
            withdraw_certificates(started, &mut offered);
        }
    }
}

/// Reads the authentication certificate, keeps it on the pairing record
/// for the key storage provider, and offers it to browsers.
fn learn_certificate(
    started: Instant,
    pairing: &mut Pairing,
    session: &mut Session<BleLink>,
    offered: &mut Option<PairId>,
) {
    let operation = CardOperation::ReadCertificate {
        kind: CertificateKind::Authentication,
    };
    let certificate = match pairing
        .requester
        .execute(session, &operation, OPERATION_LIFETIME_MS)
    {
        Ok(OperationOutcome::Completed(CardOperationResult::Certificate(der))) => der,
        Ok(outcome) => {
            log(
                started,
                &format!("the certificate was not read: {outcome:?}"),
            );
            return;
        }
        Err(error) => {
            log(started, &format!("the certificate was not read: {error:?}"));
            return;
        }
    };
    log(
        started,
        &format!(
            "read the authentication certificate, {} bytes",
            certificate.len()
        ),
    );
    let stored = pairing
        .requester
        .store_mut()
        .update(pairing.pair_id, &mut |record| {
            record.auth_cert = Some(certificate.clone());
        });
    if let Err(error) = stored {
        log(
            started,
            &format!("the certificate was not stored: {error:?}"),
        );
        return;
    }
    offer_certificate(started, &certificate, pairing.pair_id, offered);
}

/// Runs one job as a `browser_authenticate` and answers it.
fn sign(started: Instant, pairing: &mut Pairing, session: &mut Session<BleLink>, job: Job) {
    if job.request.pair_id() != pairing.pair_id {
        log(started, "refused a request for another pairing");
        job.answer(SignAnswer::Failed);
        return;
    }
    let operation = CardOperation::BrowserAuthenticate {
        origin: job.requester.clone(),
        key_profile: job.request.key_profile(),
        algorithm: job.request.algorithm(),
        digest: job.request.digest().to_vec(),
    };
    log(started, "asking the phone to sign");
    let answer = match pairing
        .requester
        .execute(session, &operation, OPERATION_LIFETIME_MS)
    {
        Ok(OperationOutcome::Completed(CardOperationResult::Signature(signature))) => {
            SignAnswer::Signature(signature)
        }
        Ok(OperationOutcome::Completed(_)) => SignAnswer::Failed,
        Ok(OperationOutcome::Denied) => SignAnswer::Denied,
        Ok(OperationOutcome::Cancelled) => SignAnswer::Cancelled,
        Ok(OperationOutcome::Rejected(_)) => SignAnswer::Rejected,
        Ok(OperationOutcome::Ambiguous) => SignAnswer::Ambiguous,
        Ok(OperationOutcome::CredentialRejected) => SignAnswer::CredentialRejected,
        Err(error) => {
            log(
                started,
                &format!("the phone did not admit the request: {error:?}"),
            );
            SignAnswer::Failed
        }
    };
    job.answer(answer);
}
