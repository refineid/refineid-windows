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
use refineid_lib_core::x509::{OwnedCert, UnvalidatedCertificate};
use refineid_rapp::{RequesterSessionEnd, RoutingKey};
use refineid_rapp_ble::gatt::BleLink;
use refineid_rapp_ble::reach::{ReachError, reach_revocation_notice, reach_session};
use refineid_rapp_core::clock::unix_time_ms;
use refineid_rapp_core::engine::{
    OperationOutcome, Requester, RequesterConfig, Session, SessionError, TRANSPORT_LABEL_BLUETOOTH,
    Withdrawal, stored_peer_label,
};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::{
    CardPresence, CardStatusMessage, CertificateFingerprint, CloseReason, ResultError,
};
use refineid_rapp_core::operations::{CardOperation, CardOperationResult, CertificateKind};
use refineid_rapp_core::store::{
    PairingRecord, PairingStore, expire_revocation_notices, offer_stands, sweep_pairings,
};
use refineid_rapp_core::stream::DialCause;
use refineid_windows_credential_store::{
    ProtectedPairingStore, install_browser_certificate, remove_browser_certificates,
};

use crate::offer_gate::OfferGate;
use crate::{cards, console};

/// How long the agent waits before looking for the phone again after a
/// search found nothing, unless a signature request arrives first.
const SEARCH_PAUSE: Duration = Duration::from_secs(5);
/// How long the agent waits before reading the pairing store again when it
/// holds no usable pairing.
const STORE_PAUSE: Duration = Duration::from_secs(10);
/// How long a failed pipe waits before it is served again.
const PIPE_PAUSE: Duration = Duration::from_secs(1);
/// How long one backlog pass looks for the phone of each forgotten pairing
/// to give it the `pairing_revoked` close.
const NOTICE_REACH_WINDOW: Duration = Duration::from_secs(5);
/// How often an open session reads the pairing store again, so a pairing
/// the user forgot meanwhile is closed with its `pairing_revoked` close.
const STORE_CHECK_INTERVAL: Duration = Duration::from_secs(10);
/// The operation lifetime sent on the wire, in milliseconds.
const OPERATION_LIFETIME_MS: u64 = OPERATION_LIFETIME.as_secs() * 1_000;
/// How long a fresh session waits for the phone's first card report before
/// a waiting request runs (RAPP v26.11.2 section 8.4 item 1): the phone
/// sends it right after `session.ready`.
const FIRST_CARD_REPORT_WAIT: Duration = Duration::from_secs(5);
/// How long a quitting agent waits for its `service_withdrawn` closes to be
/// written before it exits (RAPP v26.11.2 section 4.5 item 8).
const QUIT_WITHDRAWAL_BOUND: Duration =
    Duration::from_millis(refineid_rapp::QUIT_WITHDRAWAL_BOUND_MS);
/// How often the agent checks every pairing for idle expiry while it holds
/// a session: one day, the least often RAPP v26.11.2 section 4.6 item 5
/// allows. Between sessions it checks each time it reads the pairing store.
const IDLE_CHECK_INTERVAL: Duration = Duration::from_millis(
    refineid_rapp::PAIRING_IDLE_EXPIRY_MS / refineid_rapp::PAIRING_IDLE_EXPIRY_DAYS,
);

/// The gate every change to the browsers' offer passes through, closed by
/// the agent's quit.
static OFFER_GATE: OfferGate = OfferGate::new();

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

/// The card's authentication certificate as the phone last answered it on a
/// session, held in memory only: no store keeps it (refineid-core
/// `doc/security/certificate-custody.md`).
struct Learned {
    pair_id: PairId,
    certificate: OwnedCert,
}

/// What the agent offers browsers, and the certificate it learned.
#[derive(Default)]
struct Offer {
    /// The certificate installed in the personal store, if any.
    offered: Option<Offered>,
    /// The certificate read on the latest session, while its offer may
    /// stand.
    learned: Option<Learned>,
}

impl Offer {
    const fn is_offered(&self) -> bool {
        self.offered.is_some()
    }
}

/// One signature request on its way from the pipe to the session.
struct Job {
    request: SignRequest,
    /// The asking party the operation context carries (W-R-10).
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
    let withdrawal = Withdrawal::new();
    let quitting = withdrawal.clone();
    if console::attach()
        && let Err(code) = console::on_quit(move || quit(&quitting))
    {
        refineid_dev_errors::report!(Agent, "quit not handled", status code);
    }
    thread::spawn(cards::watch);
    let (jobs, inbox) = channel();
    thread::spawn(move || serve_phone(&inbox, &withdrawal));
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
            Ok(request) => program.map_or_else(
                || {
                    refineid_dev_errors::report!(
                        Agent,
                        "signature request refused",
                        "the client's image names no file"
                    );
                    SignAnswer::Failed
                },
                |program| relay(&jobs, request, requester_context(&program, &computer)),
            ),
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

/// Hands one request to the phone's thread and waits for its answer.
fn relay(jobs: &Sender<Job>, request: SignRequest, requester: String) -> SignAnswer {
    let (reply, answered) = channel();
    let job = Job {
        request,
        requester,
        reply,
    };
    if jobs.send(job).is_err() {
        return SignAnswer::Failed;
    }
    match answered.recv_timeout(SIGNATURE_DEADLINE) {
        Ok(answer) => answer,
        Err(RecvTimeoutError::Timeout) => SignAnswer::Cancelled,
        Err(RecvTimeoutError::Disconnected) => SignAnswer::Failed,
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

/// The user quit the agent (RAPP v26.11.2 section 4.5 item 8): each open
/// session gets the `service_withdrawn` close, written within the quit
/// bound or dropped, and the offer to browsers goes, as nothing serves it
/// after (section 8.4 item 3): the offer's gate closes, so the removal runs
/// after any install under way and no install follows it. The pairing
/// stays.
fn quit(withdrawal: &Withdrawal) {
    if !withdrawal.raise_and_wait(QUIT_WITHDRAWAL_BOUND) {
        refineid_dev_errors::report!(Agent, "withdrawal not delivered", "the quit bound passed");
    }
    OFFER_GATE.close(remove_offer);
}

fn requester_over(store: ProtectedPairingStore, withdrawal: &Withdrawal) -> AgentRequester {
    Requester::new(RequesterConfig::this_computer(), store).following(withdrawal.clone())
}

/// Loads the pairing store over a fresh requester and expires what is due;
/// `None` when the store cannot be read.
fn load_requester(withdrawal: &Withdrawal, offered: &mut Offer) -> Option<AgentRequester> {
    let store = match ProtectedPairingStore::load() {
        Ok(store) => store,
        Err(error) => {
            refineid_dev_errors::report!(Agent, "pairing store not loaded", error);
            return None;
        }
    };
    let mut requester = requester_over(store, withdrawal);
    check_idle_expiry(&mut requester, None, offered);
    Some(requester)
}

/// The usable pairing's identifier and routing key, with the requester it
/// was read from. Runs no discovery: the caller runs the revocation
/// backlog alongside the active pairing's own, in every phase, on the
/// requester that comes back.
fn load_pairing(
    requester: AgentRequester,
    offered: &mut Offer,
) -> (AgentRequester, Option<(PairId, RoutingKey)>) {
    let usable = requester.store().usable_pairing().and_then(|record| {
        let pair_id = record.pair_id();
        let key = RoutingKey::derive(record.pair_record()?).ok()?;
        Some((pair_id, key))
    });
    let Some((pair_id, key)) = usable else {
        return (requester, None);
    };
    sync_offer(&requester, pair_id, offered);
    (requester, Some((pair_id, key)))
}

/// Checks every stored pairing for idle expiry (RAPP v26.11.2 section 4.6
/// item 5), `held` being the pairing whose session the agent holds, if any.
/// A pairing that expired is forgotten and its identity is offered no
/// longer, so the browsers' offer of it is withdrawn; nothing is sent to its
/// phone and nothing is shown. A check the store refused is repeated on the
/// next one.
fn check_idle_expiry(requester: &mut AgentRequester, held: Option<PairId>, offered: &mut Offer) {
    let expired = sweep_pairings(requester.store_mut(), unix_time_ms(), |pair_id| {
        Some(pair_id) == held
    });
    let held = offered
        .learned
        .as_ref()
        .map(|learned| learned.pair_id)
        .or_else(|| offered.offered.map(|offer| offer.pair_id));
    if held.is_some_and(|pair_id| expired.contains(&pair_id)) {
        withdraw_certificates(offered);
    }
}

/// Gives the phone of each forgotten pairing its `pairing_revoked` close:
/// one pass of the requester's revocation backlog over Bluetooth (RAPP
/// v26.11.2 section 4.6 item 6). Only an appearance dials: an advertiser
/// first seen, or seen again after absence for the loss hold. At most one
/// connection opens per appearance, carrying the close as its first
/// message. The keys and the record go only on the phone's echo; anything
/// else keeps the pairing until its next appearance, and a phone that never
/// appears again leaves it to its idle expiry, 30 days after its last
/// established session. A forgotten pairing that outlived that expiry is
/// revoked untold instead.
fn deliver_revocation_notices(requester: &mut AgentRequester) {
    expire_revocation_notices(requester.store_mut(), unix_time_ms());
    let owed: Vec<(PairId, RoutingKey)> = requester
        .store()
        .forgotten_pairings()
        .filter_map(|record| {
            let key = RoutingKey::derive(record.pair_record()?).ok()?;
            Some((record.pair_id(), key))
        })
        .collect();
    // The process's appearance memory goes to every pass, so a phone that
    // stays in sight across passes spaced further apart than the loss hold
    // still dials only once.
    let mut sightings = refineid_rapp_core::backlog::shared();
    for (pair_id, key) in owed {
        // The scan and the session report their own failures.
        let _ = reach_revocation_notice(
            requester,
            pair_id,
            &key,
            NOTICE_REACH_WINDOW,
            &mut sightings,
            |_| {},
        );
    }
}

/// W-R-8: brings the browsers' offer in line with the certificate the
/// pairing's identity is offered on now (RAPP v26.11.2 section 8.4 item
/// 3). The offer stands before and between sessions on a certificate whose
/// card a session heard present within the grace, and goes at once when the
/// pairing is forgotten or revoked or a session hears another card; another
/// card's certificate is withdrawn before this one is installed, as
/// installing adds a certificate beside it. Once the agent withdrew, the
/// offer is left to its quit, which withdraws it; an install that passed
/// this check runs through the offer's gate, so the quit removes it after.
fn sync_offer(requester: &AgentRequester, pair_id: PairId, offered: &mut Offer) {
    if requester.withdrawn() {
        return;
    }
    let standing = offered.learned.as_ref().filter(|learned| {
        learned.pair_id == pair_id
            && offer_stands(
                requester.store(),
                pair_id,
                &learned.certificate,
                unix_time_ms(),
            )
    });
    let Some(learned) = standing else {
        // The phone is gone past the grace, or the pairing or the card
        // changed: nothing of the certificate is kept.
        if offered.is_offered() || offered.learned.is_some() {
            withdraw_certificates(offered);
        }
        return;
    };
    let certificate = learned.certificate.clone();
    let wanted = Offered {
        pair_id,
        card: CertificateFingerprint::of_certificate(certificate.as_der()),
    };
    if offered.offered == Some(wanted) {
        return;
    }
    if offered.is_offered() {
        OFFER_GATE.change(remove_offer);
        offered.offered = None;
    }
    match OFFER_GATE.change(|| install_browser_certificate(&certificate, pair_id)) {
        Some(Ok(())) => offered.offered = Some(wanted),
        Some(Err(error)) => {
            refineid_dev_errors::report!(Agent, "certificate not offered to browsers", error);
        }
        None => {}
    }
}

/// How long the standing offer has until it lapses, when one is offered: no
/// step between sessions may last longer, so the withdrawal lands when the
/// grace ends and never before (RAPP v26.11.2 section 8.4 item 3).
fn until_offer_lapses(
    requester: &AgentRequester,
    pair_id: PairId,
    offered: &Offer,
) -> Option<Duration> {
    offered.offered?;
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

/// Withdraws the offer to browsers and forgets the learned certificate.
fn withdraw_certificates(offered: &mut Offer) {
    OFFER_GATE.change(remove_offer);
    *offered = Offer::default();
}

/// Removes every certificate offered to browsers.
fn remove_offer() {
    if let Err(error) = remove_browser_certificates() {
        refineid_dev_errors::report!(Agent, "offered certificates not withdrawn", error);
    }
}

/// The session thread: keeps the phone's session and runs every job until
/// the agent withdraws (RAPP v26.11.2 section 4.5 item 8).
fn serve_phone(inbox: &Receiver<Job>, withdrawal: &Withdrawal) {
    // W-R-8: certificates offered by an earlier run are purged first.
    let mut offered = Offer::default();
    withdraw_certificates(&mut offered);
    let mut pending: Option<Waiting> = None;
    while !withdrawal.is_raised() {
        let Some(requester) = load_requester(withdrawal, &mut offered) else {
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
        let (mut requester, usable) = load_pairing(requester, &mut offered);
        let Some((pair_id, key)) = usable else {
            // W-R-8: no usable pairing, so nothing stays offered. The
            // revocation backlog is the only remote activity.
            if offered.is_offered() || offered.learned.is_some() {
                withdraw_certificates(&mut offered);
            }
            if let Some(waiting) = pending.take() {
                waiting.job.answer(SignAnswer::Failed);
            }
            deliver_revocation_notices(&mut requester);
            match inbox.recv_timeout(STORE_PAUSE) {
                Ok(job) => job.answer(SignAnswer::Failed),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            continue;
        };
        let mut pairing = Pairing {
            requester,
            pair_id,
            key,
        };
        // A waiting request searches for what is left of its window; no
        // search outlasts the standing offer, which is judged again after.
        let until_lapse = until_offer_lapses(&pairing.requester, pairing.pair_id, &offered);
        let search = pending.as_ref().map_or(REACH_WINDOW, |waiting| {
            REACH_WINDOW.saturating_sub(waiting.since.elapsed())
        });
        // A waiting request is a local consumer's; otherwise the phone is
        // dialed when it appears or within the redial window (RAPP v26.11.2
        // section 8.3).
        let cause = if pending.is_some() {
            DialCause::ConsumerRequest
        } else {
            DialCause::Holding
        };
        let reached = reach_session(
            &mut pairing.requester,
            pairing.pair_id,
            &pairing.key,
            bounded_by_offer(search, until_lapse),
            cause,
            |_| {},
        );
        let mut session = match reached {
            Ok(session) => session,
            Err(_) if pairing.requester.withdrawn() => break,
            Err(error) => {
                // The active pairing's phone is not in reach: the backlog
                // runs its discovery alongside, without touching the active
                // pairing.
                deliver_revocation_notices(&mut pairing.requester);
                match after_failed_search(&error, &pairing, &mut offered, &mut pending, inbox) {
                    AfterSearch::Again => continue,
                    AfterSearch::Stop => return,
                }
            }
        };
        // A waiting request runs only once the phone has said which card it
        // holds and the offer follows it (RAPP v26.11.2 section 8.4).
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
        // A revocation, a withdrawal or `card_unavailable` withdraws the
        // identity at once, without the grace (RAPP v26.11.2 section 4.5
        // item 6).
        if session
            .treatment()
            .is_some_and(RequesterSessionEnd::withdraws_identity_at_once)
        {
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
/// offer lapses (RAPP v26.11.2 section 8.4 item 3).
fn after_failed_search(
    error: &ReachError,
    pairing: &Pairing,
    offered: &mut Offer,
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
            let peer = stored_peer_label(pairing.requester.store(), pairing.pair_id);
            for job in core::iter::once(waiting.job).chain(inbox.try_iter()) {
                refineid_dev_errors::report!(
                    Agent,
                    "no phone for a signature request",
                    error,
                    peer.as_str(),
                    TRANSPORT_LABEL_BLUETOOTH
                );
                job.answer(SignAnswer::NoPhone);
            }
        }
        None => {}
    }
    let until_lapse = until_offer_lapses(&pairing.requester, pairing.pair_id, offered);
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

/// Follows the card the session reports (RAPP v26.11.2 section 8.4): the
/// certificate of the card the phone reports is read on every session, as
/// no store keeps it; a card that is not the one learned before has the
/// earlier offer withdrawn at once, and the offer is then brought in line
/// with what the session heard.
fn follow_card(
    pairing: &mut Pairing,
    session: &mut Session<BleLink>,
    offered: &mut Offer,
    card_checked: &mut Option<CertificateFingerprint>,
) {
    if let Some(CardStatusMessage {
        card: CardPresence::Present(fingerprint),
        ..
    }) = session.card_status()
        && *card_checked != Some(fingerprint)
    {
        *card_checked = Some(fingerprint);
        // The session recorded the card it hears, so another card's offer
        // goes before this one's certificate is read.
        sync_offer(&pairing.requester, pairing.pair_id, offered);
        if let Some(certificate) = learn_certificate(pairing, session, fingerprint) {
            offered.learned = Some(Learned {
                pair_id: pairing.pair_id,
                certificate,
            });
        }
    }
    sync_offer(&pairing.requester, pairing.pair_id, offered);
}

/// Holds an open session: runs every job that arrives, keeps the session
/// alive in between (RAPP v26.11.2 section 8.3), reads the certificate
/// when the phone reports a card on the session
/// (section 8.4 item 2), keeps the offer in line with what the session
/// hears (section 8.4 item 3), closes with `pairing_revoked` when the user
/// forgot the pairing meanwhile (section 4.6 item 1), and checks every
/// pairing for idle expiry once a day, the held one as in session (section
/// 4.6 item 5). Returns false when the pipe is gone and the agent stops.
fn hold_session(
    pairing: &mut Pairing,
    session: &mut Session<BleLink>,
    offered: &mut Offer,
    inbox: &Receiver<Job>,
    mut card_checked: Option<CertificateFingerprint>,
) -> bool {
    let mut store_checked = Instant::now();
    let mut idle_checked = Instant::now();
    while session.end().is_none() {
        match inbox.try_recv() {
            Ok(job) => {
                // A pairing the user forgot meanwhile signs nothing (RAPP
                // v26.11.2 section 4.6).
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
            // While the active session stands, the backlog still tells a
            // forgotten phone that appears; the active session is untouched.
            deliver_revocation_notices(&mut pairing.requester);
        }
        if idle_checked.elapsed() >= IDLE_CHECK_INTERVAL && session.end().is_none() {
            idle_checked = Instant::now();
            check_idle_expiry(&mut pairing.requester, Some(pairing.pair_id), offered);
        }
        follow_card(pairing, session, offered, &mut card_checked);
    }
    true
}

/// Closes the session when its pairing no longer serves: one the user
/// forgot gets the `pairing_revoked` close now and loses its keys on the
/// phone's echo, else stays forgotten in the revocation backlog (RAPP
/// v26.11.2 section 4.6 items 1 and 6); one already revoked or removed is
/// closed. A store that cannot be read changes nothing.
fn close_if_forgotten(pairing: &mut Pairing, session: &mut Session<BleLink>, offered: &mut Offer) {
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

/// Reads the authentication certificate on the session; `None` unless it is
/// the certificate of the card whose fingerprint the session reports.
fn learn_certificate(
    pairing: &mut Pairing,
    session: &mut Session<BleLink>,
    fingerprint: CertificateFingerprint,
) -> Option<OwnedCert> {
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
            return None;
        }
        // The engine reports an operation that ended without its result,
        // and one it did not admit.
        Ok(_) | Err(_) => return None,
    };
    if CertificateFingerprint::of_certificate(&der) != fingerprint {
        refineid_dev_errors::report!(Agent, "certificate not read", "another card's came");
        return None;
    }
    let Ok(certificate) = OwnedCert::from_der(UnvalidatedCertificate::new(der)) else {
        refineid_dev_errors::report!(Agent, "certificate not read", "it does not parse");
        return None;
    };
    Some(certificate)
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
