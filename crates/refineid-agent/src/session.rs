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
use refineid_rapp_ble::reach::{ReachError, reach_revocation_notice, reach_session};
use refineid_rapp_core::clock::unix_time_ms;
use refineid_rapp_core::engine::{
    OperationOutcome, Requester, RequesterConfig, Session, SessionEnd, SessionError,
};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::{
    CardPresence, CardStatusMessage, CertificateFingerprint, CloseReason, ResultError,
};
use refineid_rapp_core::operations::{CardOperation, CardOperationResult, CertificateKind};
use refineid_rapp_core::store::{PairingRecord, PairingStore, offered_certificate};
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
/// How long a fresh session waits for the phone's first card report before
/// a waiting request runs (RAPP v26.10.22 section 8.4 item 1): the phone
/// sends it right after `session.ready`.
const FIRST_CARD_REPORT_WAIT: Duration = Duration::from_secs(5);

/// A signature request waiting for the phone, and since when.
struct Waiting {
    job: Job,
    since: Instant,
}

impl Waiting {
    fn from_now(job: Job) -> Self {
        Self {
            job,
            since: Instant::now(),
        }
    }
}

/// The certificate the agent has offered to browsers: which pairing's, and
/// which card's.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Offered {
    pair_id: PairId,
    card: CertificateFingerprint,
}

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

/// Reports a pipe failure in a development build, by the Windows error it
/// carries where it carries one.
macro_rules! report_pipe {
    ($event:literal, $error:expr) => {
        match $error {
            PipeError::Identity(code) | PipeError::Pipe(code) => {
                refineid_dev_errors::report!(Agent, $event, status code);
            }
            other => refineid_dev_errors::report!(Agent, $event, other),
        }
    };
}

/// Serves the pipe until the process ends.
pub fn run() -> ExitCode {
    let lock = match AgentLock::acquire() {
        Ok(lock) => lock,
        Err(error) => {
            report_pipe!("agent not started", error);
            return ExitCode::FAILURE;
        }
    };
    let mut server = match PipeServer::bind(&lock) {
        Ok(server) => server,
        Err(error) => {
            report_pipe!("agent pipe not created", error);
            return ExitCode::FAILURE;
        }
    };
    let (jobs, inbox) = channel();
    thread::spawn(move || serve_phone(&inbox));
    let computer = computer_name();
    loop {
        let mut client = match server.accept() {
            Ok(client) => client,
            Err(error) => {
                report_pipe!("agent pipe client refused", error);
                if error != PipeError::Stranger {
                    thread::sleep(PIPE_PAUSE);
                }
                continue;
            }
        };
        let program = program_label(&client.identity().image);
        let answer = match client.request() {
            Ok(request) => {
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
                report_pipe!("signature request refused", error);
                SignAnswer::Failed
            }
        };
        if !matches!(answer, SignAnswer::Signature(_)) {
            refineid_dev_errors::report!(Agent, "signature not made", answer);
        }
        if let Err(error) = client.answer(&answer) {
            report_pipe!("signature answer not delivered", error);
        }
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

fn load_pairing(offered: &mut Option<Offered>) -> Option<Pairing> {
    let store = match ProtectedPairingStore::load() {
        Ok(store) => store,
        Err(error) => {
            refineid_dev_errors::report!(Agent, "pairing store not loaded", error);
            return None;
        }
    };
    let mut requester = requester_over(store);
    deliver_revocation_notices(&mut requester);
    let record = requester.store().usable_pairing()?;
    let pair_id = record.pair_id();
    let key = RoutingKey::derive(record.pair_record()?).ok()?;
    sync_offer(&requester, pair_id, offered);
    Some(Pairing {
        requester,
        pair_id,
        key,
    })
}

/// Gives the phone of each pairing the user forgot while it was out of
/// reach its `pairing_revoked` close, as the first message of a session
/// (RAPP v26.10.22 section 4.6 item 2); a phone not found now is tried
/// again on the next round, for at most 30 days.
fn deliver_revocation_notices(requester: &mut AgentRequester) {
    let owed: Vec<(PairId, RoutingKey)> = requester
        .store()
        .forgotten_pairings()
        .filter_map(|record| {
            let key = RoutingKey::derive(record.pair_record()?).ok()?;
            Some((record.pair_id(), key))
        })
        .collect();
    for (pair_id, key) in owed {
        // A phone not found now is told on a later round; the scan and the
        // session report their own failures.
        let _ = reach_revocation_notice(requester, pair_id, &key, NOTICE_REACH_WINDOW, |_| {});
    }
}

/// W-R-8: brings the browsers' offer in line with the certificate the
/// pairing's identity is offered on now (RAPP v26.10.22 section 8.4 item
/// 3). The offer stands before and between sessions on a certificate whose
/// card a session heard present within the grace, and goes at once when the
/// pairing is forgotten or revoked or a session hears another card; another
/// card's certificate is withdrawn before this one is installed, as
/// installing adds a certificate beside it.
fn sync_offer(requester: &AgentRequester, pair_id: PairId, offered: &mut Option<Offered>) {
    let Some(certificate) = offered_certificate(requester.store(), pair_id, unix_time_ms()) else {
        if offered.is_some() {
            withdraw_certificates(offered);
        }
        return;
    };
    let wanted = Offered {
        pair_id,
        card: CertificateFingerprint::of_certificate(certificate.as_der()),
    };
    if *offered == Some(wanted) {
        return;
    }
    if offered.is_some() {
        withdraw_certificates(offered);
    }
    match install_browser_certificate(certificate, pair_id) {
        Ok(()) => *offered = Some(wanted),
        Err(error) => {
            refineid_dev_errors::report!(Agent, "certificate not offered to browsers", error);
        }
    }
}

/// How long the standing offer has until it lapses, when one is offered: no
/// step between sessions may last longer, so the withdrawal lands when the
/// grace ends and never before (RAPP v26.10.22 section 8.4 item 3).
fn until_offer_lapses(
    requester: &AgentRequester,
    pair_id: PairId,
    offered: Option<Offered>,
) -> Option<Duration> {
    offered?;
    let lapses_at = requester
        .store()
        .card_sighting(pair_id)?
        .offer_lapses_at_ms();
    Some(Duration::from_millis(
        lapses_at.saturating_sub(unix_time_ms()),
    ))
}

/// At most `step`, and no longer than the standing offer has left.
fn bounded_by_offer(step: Duration, until_lapse: Option<Duration>) -> Duration {
    until_lapse.map_or(step, |left| step.min(left))
}

fn withdraw_certificates(offered: &mut Option<Offered>) {
    if let Err(error) = remove_browser_certificates() {
        refineid_dev_errors::report!(Agent, "offered certificates not withdrawn", error);
    }
    *offered = None;
}

/// The session thread: keeps the phone's session and runs every job.
fn serve_phone(inbox: &Receiver<Job>) {
    // W-R-8: certificates offered by an earlier run are purged first.
    let mut offered = None;
    withdraw_certificates(&mut offered);
    let mut pending: Option<Waiting> = None;
    loop {
        let Some(mut pairing) = load_pairing(&mut offered) else {
            // W-R-8: no usable pairing, so nothing stays offered.
            if offered.is_some() {
                withdraw_certificates(&mut offered);
            }
            if let Some(waiting) = pending.take() {
                waiting.job.answer(SignAnswer::Failed);
            }
            match inbox.recv_timeout(STORE_PAUSE) {
                Ok(job) => job.answer(SignAnswer::Failed),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            continue;
        };
        // A waiting request searches for what is left of its window; no
        // search outlasts the standing offer, which is judged again after.
        let until_lapse = until_offer_lapses(&pairing.requester, pairing.pair_id, offered);
        let search = pending.as_ref().map_or(REACH_WINDOW, |waiting| {
            REACH_WINDOW.saturating_sub(waiting.since.elapsed())
        });
        let reached = reach_session(
            &mut pairing.requester,
            pairing.pair_id,
            &pairing.key,
            bounded_by_offer(search, until_lapse),
            |_| {},
        );
        let mut session = match reached {
            Ok(session) => session,
            Err(error) => {
                match after_failed_search(&error, &pairing, &mut offered, &mut pending, inbox) {
                    AfterSearch::Again => continue,
                    AfterSearch::Stop => return,
                }
            }
        };
        // A waiting request runs only once the phone has said which card it
        // holds and the offer follows it (RAPP v26.10.22 section 8.4).
        await_card_report(&mut pairing, &mut session);
        let mut card_checked = None;
        follow_card(&mut pairing, &mut session, &mut offered, &mut card_checked);
        if let Some(waiting) = pending.take() {
            if session.end().is_some() {
                waiting.job.answer(SignAnswer::NoPhone);
            } else {
                sign(&mut pairing, &mut session, waiting.job);
            }
        }
        if !hold_session(
            &mut pairing,
            &mut session,
            &mut offered,
            inbox,
            card_checked,
        ) {
            return;
        }
        if session.end() == Some(SessionEnd::PeerClose(CloseReason::PairingRevoked)) {
            withdraw_certificates(&mut offered);
        }
    }
}

/// What a failed search leaves the agent to do.
enum AfterSearch {
    /// Search for the phone again.
    Again,
    /// The pipe is gone; the agent stops.
    Stop,
}

/// After a search that found no session: a waiting request searches on for
/// what is left of its window, or is answered with every request queued
/// behind it; then the agent pauses, never past the moment the standing
/// offer lapses (RAPP v26.10.22 section 8.4 item 3).
fn after_failed_search(
    error: &ReachError,
    pairing: &Pairing,
    offered: &mut Option<Offered>,
    pending: &mut Option<Waiting>,
    inbox: &Receiver<Job>,
) -> AfterSearch {
    if matches!(
        error,
        ReachError::Pairing(SessionError::ClosedByPeer(CloseReason::PairingRevoked))
    ) {
        withdraw_certificates(offered);
    }
    if pending.is_none() {
        *pending = inbox.try_recv().ok().map(Waiting::from_now);
    }
    let search_over = !matches!(error, ReachError::NotReached);
    match pending.take() {
        Some(waiting) if !search_over && waiting.since.elapsed() < REACH_WINDOW => {
            *pending = Some(waiting);
            return AfterSearch::Again;
        }
        Some(waiting) => {
            // Every request that arrived during the search waited for it.
            for job in core::iter::once(waiting.job).chain(inbox.try_iter()) {
                refineid_dev_errors::report!(Agent, "no phone for a signature request", error);
                job.answer(SignAnswer::NoPhone);
            }
        }
        None => {}
    }
    let until_lapse = until_offer_lapses(&pairing.requester, pairing.pair_id, *offered);
    match inbox.recv_timeout(bounded_by_offer(SEARCH_PAUSE, until_lapse)) {
        Ok(job) => *pending = Some(Waiting::from_now(job)),
        Err(RecvTimeoutError::Timeout) => {}
        Err(RecvTimeoutError::Disconnected) => return AfterSearch::Stop,
    }
    AfterSearch::Again
}

/// Keeps a fresh session alive until the phone's first card report
/// arrives, the session ends, or [`FIRST_CARD_REPORT_WAIT`] passes.
fn await_card_report(pairing: &mut Pairing, session: &mut Session<BleLink>) {
    let waiting = Instant::now();
    while session.end().is_none()
        && session.card_status().is_none()
        && waiting.elapsed() < FIRST_CARD_REPORT_WAIT
    {
        // An ended session is noticed by the loop.
        let _ = pairing.requester.keep_alive(session);
    }
}

/// Follows the card the session reports (RAPP v26.10.22 section 8.4): a
/// card whose certificate is not the cached one has the earlier offer
/// withdrawn at once and its certificate read on the session, and the
/// offer is then brought in line with what the session heard.
fn follow_card(
    pairing: &mut Pairing,
    session: &mut Session<BleLink>,
    offered: &mut Option<Offered>,
    card_checked: &mut Option<CertificateFingerprint>,
) {
    if let Some(CardStatusMessage {
        card: CardPresence::Present(fingerprint),
        ..
    }) = session.card_status()
        && *card_checked != Some(fingerprint)
    {
        *card_checked = Some(fingerprint);
        let known = pairing
            .requester
            .store()
            .get(pairing.pair_id)
            .ok()
            .and_then(PairingRecord::authentication_certificate)
            .map(|certificate| CertificateFingerprint::of_certificate(certificate.as_der()));
        if known != Some(fingerprint) {
            // The session recorded the card it hears, so the earlier card's
            // offer goes before this one's certificate is read.
            sync_offer(&pairing.requester, pairing.pair_id, offered);
            learn_certificate(pairing, session);
        }
    }
    sync_offer(&pairing.requester, pairing.pair_id, offered);
}

/// Holds an open session: runs every job that arrives, keeps the session
/// alive in between (RAPP v26.10.22 section 8.3), reads the certificate
/// when the phone reports a card whose certificate is not the cached one
/// (section 8.4 item 2), keeps the offer in line with what the session
/// hears (section 8.4 item 3), and closes with `pairing_revoked` when the
/// user forgot the pairing meanwhile (section 4.6 item 1). Returns false
/// when the pipe is gone and the agent stops.
fn hold_session(
    pairing: &mut Pairing,
    session: &mut Session<BleLink>,
    offered: &mut Option<Offered>,
    inbox: &Receiver<Job>,
    mut card_checked: Option<CertificateFingerprint>,
) -> bool {
    let mut store_checked = Instant::now();
    while session.end().is_none() {
        match inbox.try_recv() {
            Ok(job) => {
                // A pairing the user forgot meanwhile signs nothing (RAPP
                // v26.10.22 section 4.6).
                store_checked = Instant::now();
                close_if_forgotten(pairing, session, offered);
                if session.end().is_some() {
                    job.answer(SignAnswer::Failed);
                } else {
                    sign(pairing, session, job);
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
        if store_checked.elapsed() >= STORE_CHECK_INTERVAL {
            store_checked = Instant::now();
            close_if_forgotten(pairing, session, offered);
        }
        follow_card(pairing, session, offered, &mut card_checked);
    }
    true
}

/// Closes the session when its pairing no longer serves: one the user
/// forgot gets the `pairing_revoked` close now and loses its keys (RAPP
/// v26.10.22 section 4.6 item 1); one already revoked or removed is closed.
/// A store that cannot be read changes nothing.
fn close_if_forgotten(
    pairing: &mut Pairing,
    session: &mut Session<BleLink>,
    offered: &mut Option<Offered>,
) {
    if pairing.requester.store_mut().refresh().is_err() {
        return;
    }
    let record = pairing.requester.store().get(pairing.pair_id).ok();
    if record.is_some_and(PairingRecord::serves) {
        return;
    }
    if record.is_some_and(PairingRecord::owes_revocation_notice) {
        if let Err(error) = pairing.requester.forget_pairing_in_session(session) {
            refineid_dev_errors::report!(Agent, "forgotten pairing not recorded", error);
        }
    } else {
        pairing
            .requester
            .disconnect(session, CloseReason::UserDisconnect);
    }
    withdraw_certificates(offered);
}

/// Reads the authentication certificate and keeps it on the pairing record,
/// for the key storage provider and for the offer, which stands once a
/// session has heard its card.
fn learn_certificate(pairing: &mut Pairing, session: &mut Session<BleLink>) {
    let operation = CardOperation::ReadCertificate {
        kind: CertificateKind::Authentication,
    };
    let der = match pairing
        .requester
        .execute(session, &operation, OPERATION_LIFETIME_MS)
    {
        Ok(OperationOutcome::Completed(CardOperationResult::Certificate(der))) => der,
        Ok(OperationOutcome::Completed(_)) => {
            refineid_dev_errors::report!(Agent, "certificate not read", "another result came");
            return;
        }
        // The engine reports an operation that ended without its result,
        // and one it did not admit.
        Ok(_) | Err(_) => return,
    };
    let Ok(certificate) = OwnedCert::from_der(der) else {
        refineid_dev_errors::report!(Agent, "certificate not read", "it does not parse");
        return;
    };
    let stored = pairing
        .requester
        .store_mut()
        .update(pairing.pair_id, &mut |record| {
            record.remember_authentication_certificate(certificate.clone());
        });
    if let Err(error) = stored {
        refineid_dev_errors::report!(Agent, "certificate not stored", error);
    }
}

/// Runs one job as a `browser_authenticate` and answers it.
fn sign(pairing: &mut Pairing, session: &mut Session<BleLink>, job: Job) {
    if job.request.pair_id() != pairing.pair_id {
        refineid_dev_errors::report!(Agent, "signature request refused", "another pairing");
        job.answer(SignAnswer::Failed);
        return;
    }
    let operation = CardOperation::BrowserAuthenticate {
        origin: job.requester.clone(),
        key_profile: job.request.key_profile(),
        algorithm: job.request.algorithm(),
        digest: job.request.digest().to_vec(),
    };
    // The engine reports a request it did not admit.
    let answer = pairing
        .requester
        .execute(session, &operation, OPERATION_LIFETIME_MS)
        .map_or(SignAnswer::Failed, answer_for);
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
