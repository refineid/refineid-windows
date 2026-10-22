//! The agent's two threads: the pipe server and the phone session.

use std::process::ExitCode;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError, channel};
use std::thread;
use std::time::{Duration, Instant};

use refineid_agent_pipe::identity::computer_name;
use refineid_agent_pipe::server::{AgentLock, PipeServer};
use refineid_agent_pipe::wire::{SignAnswer, SignRequest};
use refineid_agent_pipe::{
    OPERATION_LIFETIME, PipeError, REACH_WINDOW, SIGNATURE_DEADLINE, program_label,
    requester_context,
};
use refineid_lib_core::x509::OwnedCert;
use refineid_rapp::RoutingKey;
use refineid_rapp_ble::gatt::BleLink;
use refineid_rapp_ble::reach::{Attempt, ReachError, reach_revocation_notice, reach_session};
use refineid_rapp_core::engine::{
    OperationOutcome, Requester, RequesterConfig, Session, SessionEnd, SessionError,
};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::{
    CardStatusMessage, CertificateFingerprint, CloseReason, ResultError,
};
use refineid_rapp_core::operations::{CardOperation, CardOperationResult, CertificateKind};
use refineid_rapp_core::store::{PairingRecord, PairingStore};
use refineid_windows_credential_store::{
    ProtectedPairingStore, install_browser_certificate, remove_browser_certificates,
};

/// How long the agent waits before looking for the phone again after a
/// search found nothing, unless a signature request arrives first.
const SEARCH_PAUSE: Duration = Duration::from_secs(5);
/// How long the agent waits before reading the pairing store again when it
/// holds no usable pairing.
const STORE_PAUSE: Duration = Duration::from_secs(10);
/// How long a failed pipe waits before it is served again.
const PIPE_PAUSE: Duration = Duration::from_secs(1);
/// How long the agent looks for the phone of a forgotten pairing to give
/// it the `pairing_revoked` close, each time it looks for its phone.
const NOTICE_REACH_WINDOW: Duration = Duration::from_secs(5);
/// How often an open session reads the pairing store again, so a pairing
/// the user forgot meanwhile is closed with its `pairing_revoked` close.
const STORE_CHECK_INTERVAL: Duration = Duration::from_secs(10);
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
                    match answered.recv_timeout(SIGNATURE_DEADLINE) {
                        Ok(answer) => answer,
                        Err(RecvTimeoutError::Timeout) => SignAnswer::Cancelled,
                        Err(RecvTimeoutError::Disconnected) => SignAnswer::Failed,
                    }
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

/// The requester engine over this user's protected pairing store.
type AgentRequester = Requester<ProtectedPairingStore>;

/// The stored pairing the agent serves, with its routing key.
struct Pairing {
    requester: AgentRequester,
    pair_id: PairId,
    key: RoutingKey,
}

fn requester_over(store: ProtectedPairingStore) -> AgentRequester {
    Requester::new(
        RequesterConfig {
            display_name: "RefineID Windows".to_owned(),
            platform: "Windows".to_owned(),
        },
        store,
    )
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
    let mut requester = requester_over(store);
    deliver_revocation_notices(started, &mut requester);
    let record = requester.store().usable_pairing()?;
    let pair_id = record.pair_id();
    let key = RoutingKey::derive(record.pair_record()?).ok()?;
    // W-R-8: the certificate is offered whenever the pairing is usable and
    // its certificate known, before a session is open; one offered for
    // another pairing is withdrawn first.
    if offered.is_some_and(|offered_id| offered_id != pair_id) {
        withdraw_certificates(started, offered);
    }
    if let Some(certificate) = record.authentication_certificate()
        && *offered != Some(pair_id)
    {
        offer_certificate(started, certificate, pair_id, offered);
    }
    Some(Pairing {
        requester,
        pair_id,
        key,
    })
}

/// Gives the phone of each pairing the user forgot while it was out of
/// reach its `pairing_revoked` close, as the first message of a session
/// (RAPP v26.10.21 section 4.6 item 2); a phone not found now is tried
/// again on the next round, for at most 30 days.
fn deliver_revocation_notices(started: Instant, requester: &mut AgentRequester) {
    let owed: Vec<(PairId, RoutingKey)> = requester
        .store()
        .forgotten_pairings()
        .filter_map(|record| {
            let key = RoutingKey::derive(record.pair_record()?).ok()?;
            Some((record.pair_id(), key))
        })
        .collect();
    for (pair_id, key) in owed {
        match reach_revocation_notice(requester, pair_id, &key, NOTICE_REACH_WINDOW, |_| {}) {
            Ok(()) => log(started, "told a phone this computer forgot it"),
            Err(error) => log(
                started,
                &format!("a forgotten phone was not told yet: {error}"),
            ),
        }
    }
}

fn offer_certificate(
    started: Instant,
    certificate: &OwnedCert,
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
            // W-R-8: no usable pairing, so nothing stays offered.
            if offered.is_some() {
                withdraw_certificates(started, &mut offered);
            }
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
            REACH_WINDOW,
            |attempt| match attempt {
                Attempt::Routing(advertiser) => log(
                    started,
                    &format!(
                        "routing a session to an advertiser at {} dBm",
                        advertiser.rssi.dbm()
                    ),
                ),
                Attempt::LinkFailed(error) => log(started, &format!("  {error}")),
                Attempt::Refused(error) => log(started, &format!("  no session: {error}")),
            },
        );
        let mut session = match reached {
            Ok(session) => session,
            Err(error) => {
                if matches!(
                    error,
                    ReachError::Pairing(SessionError::ClosedByPeer(CloseReason::PairingRevoked))
                ) {
                    log(started, "the phone forgot this computer");
                    withdraw_certificates(started, &mut offered);
                }
                // Every request that arrived during the search waited for it.
                for job in pending.take().into_iter().chain(inbox.try_iter()) {
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
            if session.end().is_some() {
                job.answer(SignAnswer::NoPhone);
            } else {
                sign(started, &mut pairing, &mut session, job);
            }
        }
        if !hold_session(started, &mut pairing, &mut session, &mut offered, inbox) {
            return;
        }
        let end = session.end();
        log(started, &format!("session ended: {end:?}"));
        if end == Some(SessionEnd::PeerClose(CloseReason::PairingRevoked)) {
            withdraw_certificates(started, &mut offered);
        }
    }
}

/// Holds an open session: runs every job that arrives, keeps the session
/// alive in between (RAPP v26.10.21 section 8.3), reads the certificate
/// again when the phone reports another card (section 8.4 item 2), and
/// closes with `pairing_revoked` when the user forgot the pairing
/// meanwhile (section 4.6 item 1). Returns false when the pipe is gone and
/// the agent stops.
fn hold_session(
    started: Instant,
    pairing: &mut Pairing,
    session: &mut Session<BleLink>,
    offered: &mut Option<PairId>,
    inbox: &Receiver<Job>,
) -> bool {
    let mut store_checked = Instant::now();
    let mut card_checked: Option<CertificateFingerprint> = None;
    while session.end().is_none() {
        match inbox.try_recv() {
            Ok(job) => {
                // A pairing the user forgot meanwhile signs nothing (RAPP
                // v26.10.21 section 4.6).
                store_checked = Instant::now();
                close_if_forgotten(started, pairing, session, offered);
                if session.end().is_some() {
                    job.answer(SignAnswer::Failed);
                } else {
                    sign(started, pairing, session, job);
                }
            }
            Err(TryRecvError::Empty) => {
                // An ended session is noticed by the loop.
                let _ = pairing.requester.keep_alive(session);
            }
            Err(TryRecvError::Disconnected) => {
                pairing
                    .requester
                    .disconnect(session, CloseReason::UserDisconnect);
                return false;
            }
        }
        if let Some(CardStatusMessage::Present(fingerprint)) = session.card_status()
            && card_checked != Some(fingerprint)
        {
            card_checked = Some(fingerprint);
            let known = pairing
                .requester
                .store()
                .get(pairing.pair_id)
                .ok()
                .and_then(PairingRecord::authentication_certificate)
                .map(|certificate| CertificateFingerprint::of_certificate(certificate.as_der()));
            if known != Some(fingerprint) {
                log(started, "the phone serves another card");
                learn_certificate(started, pairing, session, offered);
            }
        }
        if store_checked.elapsed() >= STORE_CHECK_INTERVAL {
            store_checked = Instant::now();
            close_if_forgotten(started, pairing, session, offered);
        }
    }
    true
}

/// Closes the session when its pairing no longer serves: one the user
/// forgot gets the `pairing_revoked` close now and loses its keys (RAPP
/// v26.10.21 section 4.6 item 1); one already revoked or removed is closed.
/// A store that cannot be read changes nothing.
fn close_if_forgotten(
    started: Instant,
    pairing: &mut Pairing,
    session: &mut Session<BleLink>,
    offered: &mut Option<PairId>,
) {
    if pairing.requester.store_mut().refresh().is_err() {
        return;
    }
    let record = pairing.requester.store().get(pairing.pair_id).ok();
    if record.is_some_and(PairingRecord::serves) {
        return;
    }
    if record.is_some_and(PairingRecord::owes_revocation_notice) {
        match pairing.requester.forget_pairing_in_session(session) {
            Ok(()) => log(started, "told the phone this computer forgot it"),
            Err(error) => log(started, &format!("the forget was not recorded: {error}")),
        }
    } else {
        pairing
            .requester
            .disconnect(session, CloseReason::UserDisconnect);
    }
    withdraw_certificates(started, offered);
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
    let der = match pairing
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
            log(started, &format!("the certificate was not read: {error}"));
            return;
        }
    };
    log(
        started,
        &format!("read the authentication certificate, {} bytes", der.len()),
    );
    let Ok(certificate) = OwnedCert::from_der(der) else {
        log(started, "the phone's certificate does not parse");
        return;
    };
    let stored = pairing
        .requester
        .store_mut()
        .update(pairing.pair_id, &mut |record| {
            record.remember_authentication_certificate(certificate.clone());
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
        Ok(outcome) => answer_for(outcome),
        Err(error) => {
            log(
                started,
                &format!("the phone did not admit the request: {error}"),
            );
            SignAnswer::Failed
        }
    };
    job.answer(answer);
}

/// The pipe answer for an operation's outcome.
fn answer_for(outcome: OperationOutcome) -> SignAnswer {
    match outcome {
        OperationOutcome::Completed(CardOperationResult::Signature(signature)) => {
            SignAnswer::Signature(signature)
        }
        OperationOutcome::Completed(_) => SignAnswer::Failed,
        OperationOutcome::Rejected(ResultError::UserCancelled) => SignAnswer::Denied,
        OperationOutcome::Refused(ResultError::Busy) => SignAnswer::Busy,
        OperationOutcome::Rejected(_) | OperationOutcome::Refused(_) => SignAnswer::Rejected,
        OperationOutcome::Cancelled(_) => SignAnswer::Cancelled,
        OperationOutcome::Lost => SignAnswer::Lost,
    }
}
