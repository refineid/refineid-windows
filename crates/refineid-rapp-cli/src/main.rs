//! Development requester CLI for the RAPP remote-card path.
//!
//! `refineid-rapp pair-demo` proves the full stream-profile path against a
//! real phone custodian in one process: it takes the code the phone shows,
//! finds the phone advertising pairing, dials it, confirms grants on both
//! devices, then dials sessions and runs typed card operations that the
//! holder approves on the phone. Its pair keys live only for the process
//! lifetime unless `--durable` stores them.
//!
//! `refineid-rapp reconnect` proves the durable path the minidriver will use:
//! it loads a pairing the settings app already stored in the Windows
//! protected pairing store and dials sessions against it, with no fresh pairing
//! ceremony. Both share one session loop.
//!
//! This is a development tool. It prints operation results to the terminal
//! and must not be distributed to end users.

#[cfg(windows)]
mod ble;

use std::io::Write as _;
use std::time::{Duration, Instant};

use refineid_lib_core::x509::{OwnedCert, UnvalidatedCertificate};
use refineid_rapp::ProfileName;
use refineid_rapp_cli::mock_proxy::{
    DEFAULT_LISTEN, MockProxyOptions, SERVE_FOREVER, run_mock_proxy,
};
use refineid_rapp_core::clock::unix_time_ms;
use refineid_rapp_core::engine::{
    OperationOutcome, PairingError, PairingSearchError, PeerIntroduction, Requester,
    RequesterConfig,
};
use refineid_rapp_core::ids::{Challenge, PairId};
use refineid_rapp_core::message::{CloseReason, ResultError};
use refineid_rapp_core::offer::normalize_pairing_code;
use refineid_rapp_core::operations::{
    CardOperation, CardOperationExt, CardOperationResult, CertificateKind, KeyProfile,
    SignatureAlgorithm, SignatureAlgorithmExt,
};
use refineid_rapp_core::persistence::{decode_pairing_records, encode_pairing_records};
use refineid_rapp_core::store::{
    MemoryPairingStore, PairingRecord, PairingState, PairingStore, forget_pairing,
};
use refineid_rapp_core::stream::{
    DialCause, DialPurpose, PairingAddress, PairingServices, STREAM_CANDIDATE_ID, StreamError,
    attempt_revocations, dial, dial_session,
};
use refineid_rapp_core::transport::TcpFrameTransport;
use refineid_windows_credential_store::ProtectedPairingStore;

/// Frame receive deadline on a dialed pairing connection.
const RECEIVE_DEADLINE: Duration = Duration::from_mins(3);

/// How long the requester keeps looking for a custodian in pairing mode;
/// the custodian's offer lives this long (section 3.3).
const PAIRING_WINDOW: Duration = Duration::from_millis(refineid_rapp::OFFER_TTL_MS);

/// One DNS-SD browse round.
const BROWSE_WINDOW: Duration = Duration::from_secs(3);

/// How long one browse of a revocation attempt listens for the phone.
const FORGET_BROWSE_WINDOW: Duration = Duration::from_millis(1_500);

/// Pause between session dial rounds that found no custodian.
const SESSION_RETRY: Duration = Duration::from_secs(2);

/// Operation expiry sent on the wire; the holder approves within this.
const OPERATION_EXPIRY_MS: u64 = 300_000;

/// Visible prefix of a personal identifier in development output.
const PERSON_ID_VISIBLE_CHARS: usize = 6;

/// The pairing code `setup-mock-pairing` gives its mock custodian.
const MOCK_PAIRING_CODE: &str = "654321";

/// How long `setup-mock-pairing` tries to reach its mock custodian, and
/// the receive deadline of the pairing connection.
const MOCK_DIAL_WINDOW: Duration = Duration::from_secs(10);

/// Pause between dials while the mock custodian starts.
const MOCK_DIAL_RETRY: Duration = Duration::from_millis(100);

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match arguments.first().map(String::as_str) {
        Some("pair-demo") => pair_demo(&arguments[1..]),
        Some("reconnect") => reconnect(&arguments[1..]),
        Some("mock-proxy") => mock_proxy_cmd(&arguments[1..]),
        Some("setup-mock-pairing") => setup_mock_pairing(&arguments[1..]),
        Some("clear-pairing") => clear_pairing(),
        Some("forget-pairing") => forget_pairing_cmd(&arguments[1..]),
        Some("list-pairing") => list_pairing(),
        Some("export-pairing") => export_pairing(&arguments[1..]),
        Some("import-pairing") => import_pairing(&arguments[1..]),
        #[cfg(windows)]
        Some("ble-scan") => ble::ble_scan(&arguments[1..]),
        #[cfg(windows)]
        Some("ble-pair") => ble::ble_pair(&arguments[1..]),
        #[cfg(windows)]
        Some("ble-session") => ble::ble_session(&arguments[1..]),
        _ => {
            eprintln!("usage:");
            eprintln!("  refineid-rapp pair-demo --code <code> [--connect <host:port>] \\");
            eprintln!("      [--auto-confirm] [--count <n>] \\");
            eprintln!("      [--sign-profile rsa3072|ecdsa384] [--durable]");
            eprintln!("  refineid-rapp reconnect [--connect <host:port>] \\");
            eprintln!("      [--sign-profile rsa3072|ecdsa384] [--count <n>]");
            eprintln!("  refineid-rapp mock-proxy [--listen <bind-address>] [--code <code>] \\");
            eprintln!("      [--resume <state>] [--save-state <path>] \\");
            eprintln!("      [--cert <path>] [--pin1-attempts <n>] [--pin2-attempts <n>] \\");
            eprintln!(
                "      [--count <n>] [--identity-name <name>] [--person-id <id>] [--card-absent]"
            );
            eprintln!(
                "  refineid-rapp setup-mock-pairing [--cert <path>] [--state <path>] [--serve]"
            );
            eprintln!("  refineid-rapp forget-pairing <pair-id>");
            eprintln!("  refineid-rapp clear-pairing   (local wipe; no phone is told)");
            eprintln!("  refineid-rapp list-pairing");
            eprintln!("  refineid-rapp export-pairing [<path>]");
            eprintln!("  refineid-rapp import-pairing <path>");
            #[cfg(windows)]
            {
                eprintln!("  refineid-rapp ble-scan [--seconds <n>]");
                eprintln!("  refineid-rapp ble-pair --code <code> [--auto-confirm]");
                eprintln!("  refineid-rapp ble-session");
            }
            std::process::exit(2);
        }
    };
    if let Err(message) = outcome {
        eprintln!("error: {message}");
        std::process::exit(1);
    }
}

struct DemoOptions {
    connect: Option<String>,
    code: Option<String>,
    auto_confirm: bool,
    count: Option<usize>,
    sign_profile: Option<(KeyProfile, SignatureAlgorithm)>,
    durable: bool,
}

fn parse_options(arguments: &[String]) -> Result<DemoOptions, String> {
    let mut connect = None;
    let mut code = None;
    let mut auto_confirm = false;
    let mut count = None;
    let mut sign_profile = None;
    let mut durable = false;
    let mut cursor = arguments.iter();
    while let Some(flag) = cursor.next() {
        let mut value = || {
            cursor
                .next()
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match flag.as_str() {
            "--connect" => connect = Some(value()?),
            "--code" => {
                code = Some(
                    normalize_pairing_code(&value()?)
                        .ok_or("the pairing code is six characters from the phone")?,
                );
            }
            "--auto-confirm" | "--yes" | "-y" => auto_confirm = true,
            "--durable" | "--save" => durable = true,
            "--count" => {
                let val = value()?;
                count = Some(
                    val.parse::<usize>()
                        .map_err(|_| format!("invalid session count: {val}"))?,
                );
            }
            "--sign-profile" => {
                sign_profile = Some(match value()?.as_str() {
                    "rsa3072" => (KeyProfile::Rsa3072, SignatureAlgorithm::RsaPkcs1Sha256),
                    "ecdsa384" => (KeyProfile::EcdsaP384, SignatureAlgorithm::EcdsaSha384),
                    other => return Err(format!("unknown sign profile {other}")),
                });
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(DemoOptions {
        connect,
        code,
        auto_confirm,
        count,
        sign_profile,
        durable,
    })
}

fn pair_demo(arguments: &[String]) -> Result<(), String> {
    let options = parse_options(arguments)?;
    if options.durable {
        let store = ProtectedPairingStore::load()
            .map_err(|error| format!("cannot load ProtectedPairingStore: {error}"))?;
        run_pair_demo(&options, store)
    } else {
        run_pair_demo(&options, MemoryPairingStore::new())
    }
}

fn run_pair_demo<S: PairingStore>(options: &DemoOptions, store: S) -> Result<(), String> {
    let code = options.code.as_deref().ok_or("--code is required")?;
    let mut requester = Requester::new(RequesterConfig::this_computer(), store);
    let auto_confirm = options.auto_confirm;
    let confirm = move |peer: &PeerIntroduction, requested: &[ProfileName]| {
        if auto_confirm {
            println!();
            println!(
                "auto-confirming pairing request from {} ({})",
                peer.display_name.as_str(),
                peer.platform
            );
            println!("granted: {}", profile_list(requested));
            Some(requested.to_vec())
        } else {
            confirm_grants(peer, requested)
        }
    };

    println!("looking for the phone showing the code...");
    flush_now();
    let paired = if let Some(endpoint) = options.connect.as_ref() {
        let transport = dial_for_pairing(
            std::slice::from_ref(endpoint),
            RECEIVE_DEADLINE,
            PAIRING_WINDOW,
            SESSION_RETRY,
            || true,
        )
        .map_err(|error| format!("cannot reach {endpoint}: {error:?}"))?;
        requester
            .pair_with_code(
                code,
                &mut PairingAddress::new(transport, vec![endpoint.clone()], RECEIVE_DEADLINE),
                confirm,
            )
            .map(|(pair_id, ())| pair_id)
    } else {
        let mut services =
            PairingServices::new(PAIRING_WINDOW, BROWSE_WINDOW, RECEIVE_DEADLINE, || false);
        requester
            .pair_with_code(code, &mut services, confirm)
            .map(|(pair_id, _)| pair_id)
    };
    let pair_id = paired.map_err(pairing_failure)?;

    {
        let record = requester
            .store()
            .get(pair_id)
            .map_err(|error| format!("stored pairing unreadable: {error:?}"))?;
        println!(
            "paired with {} ({}); granted: {}",
            record.peer_display_name().as_str(),
            record.peer_platform(),
            profile_list(record.granted_profiles())
        );
    }
    flush_now();

    forget_replaced_pairings_and_tell(&mut requester, pair_id);

    serve_sessions(
        &mut requester,
        options.connect.as_deref(),
        pair_id,
        options.sign_profile,
        options.count,
    )
}

/// Forgets every stored pairing but the fresh one and tells each replaced
/// phone once: this computer holds one pairing (RAPP v26.11.2 section 4.6
/// item 6). Shared by `pair-demo` and `ble-pair`.
fn forget_replaced_pairings_and_tell<S: PairingStore>(requester: &mut Requester<S>, fresh: PairId) {
    let replaced = forget_replaced_pairings(requester, fresh);
    if replaced.is_empty() {
        return;
    }
    for stored in &replaced {
        println!(
            "Forgot pairing {}; telling its phone once",
            hex::encode(stored.as_bytes())
        );
    }
    flush_now();
    // One bounded attempt tells each replaced phone (RAPP v26.11.2
    // section 4.6 item 6), the same the settings app makes.
    attempt_revocations(requester, FORGET_BROWSE_WINDOW);
    clear_revoked_pairings(requester, &replaced);
}

/// Forgets every stored pairing but the fresh one: this computer holds
/// one pairing (RAPP v26.11.2 section 4.6 item 6). Returns the forgotten.
fn forget_replaced_pairings<S: PairingStore>(
    requester: &mut Requester<S>,
    fresh: PairId,
) -> Vec<PairId> {
    let replaced: Vec<PairId> = requester
        .store()
        .pair_ids()
        .into_iter()
        .filter(|stored| *stored != fresh)
        .collect();
    for stored in &replaced {
        let _ = requester.forget_pairing(*stored);
    }
    replaced
}

/// Removes what is left of `forgotten` once its phones were told, or its
/// attempt passed: a pairing the attempt revoked is removed.
fn clear_revoked_pairings<S: PairingStore>(requester: &mut Requester<S>, forgotten: &[PairId]) {
    for pair_id in forgotten {
        let revoked = requester
            .store()
            .get(*pair_id)
            .is_ok_and(|record| matches!(record.state(), PairingState::Revoked { .. }));
        if revoked {
            let _ = requester.forget_pairing(*pair_id);
        }
    }
}

/// What a typed code that paired with no phone tells the user; it names no
/// phone, since none has authenticated itself before a code is accepted.
pub(crate) fn pairing_failure(error: PairingSearchError) -> String {
    match error {
        PairingSearchError::Ceremony(PairingError::DeniedLocally) => "pairing declined".to_owned(),
        error => error.to_string(),
    }
}

/// Dials `endpoints` for pairing until one answers or `window` passes,
/// pausing `pause` between dials while `waiting` holds.
fn dial_for_pairing(
    endpoints: &[String],
    receive_deadline: Duration,
    window: Duration,
    pause: Duration,
    waiting: impl Fn() -> bool,
) -> Result<TcpFrameTransport, StreamError> {
    let deadline = Instant::now() + window;
    loop {
        match dial(
            endpoints,
            STREAM_CANDIDATE_ID,
            receive_deadline,
            DialPurpose::Pairing,
        ) {
            Ok(transport) => return Ok(transport),
            Err(_) if Instant::now() < deadline && waiting() => std::thread::sleep(pause),
            Err(error) => return Err(error),
        }
    }
}

/// Reconnects to a pairing the settings app already stored in the Windows
/// protected pairing store and serves sessions against it -- the durable path the
/// minidriver will use. No pairing ceremony runs; the requester finds the
/// phone by its session advertisement.
fn reconnect(arguments: &[String]) -> Result<(), String> {
    let options = parse_options(arguments)?;

    let store = ProtectedPairingStore::load()
        .map_err(|error| format!("cannot read the stored pairing: {error}"))?;
    if store.is_empty() {
        return Err("no pairing is stored; pair first in the settings app".into());
    }

    let mut requester = Requester::new(RequesterConfig::this_computer(), store);

    let pair_id = {
        let record = requester
            .store()
            .usable_pairing()
            .ok_or("the stored pairing serves nothing; pair again in the settings app")?;
        println!(
            "reconnecting to {} ({}); granted: {}",
            record.peer_display_name().as_str(),
            record.peer_platform(),
            profile_list(record.granted_profiles())
        );
        record.pair_id()
    };
    flush_now();

    serve_sessions(
        &mut requester,
        options.connect.as_deref(),
        pair_id,
        options.sign_profile,
        options.count,
    )
}

/// The profile names of `profiles`, for the terminal.
pub(crate) fn profile_list(profiles: &[ProfileName]) -> String {
    profiles
        .iter()
        .map(|profile| profile.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Dials sessions for one pairing until interrupted: each session runs the
/// read operations and an optional signature, then disconnects. Shared by
/// `pair-demo` and `reconnect`.
fn serve_sessions<S: PairingStore>(
    requester: &mut Requester<S>,
    connect: Option<&str>,
    pair_id: PairId,
    sign_profile: Option<(KeyProfile, SignatureAlgorithm)>,
    count: Option<usize>,
) -> Result<(), String> {
    let preferred: Vec<String> = connect.map(str::to_owned).into_iter().collect();
    let mut served = 0;
    loop {
        let keys = requester
            .store()
            .get(pair_id)
            .ok()
            .and_then(PairingRecord::serving_record)
            .ok_or("the pairing serves nothing; pair again")?;
        let Ok(transport) = dial_session(keys, &preferred, BROWSE_WINDOW, DialCause::Holding)
        else {
            std::thread::sleep(SESSION_RETRY);
            continue;
        };

        let mut session = match requester.connect(pair_id, transport) {
            Ok(session) => session,
            Err(error) => {
                println!("session establishment failed: {error:?}");
                continue;
            }
        };
        println!("session healthy; running operations (approve each on the phone)");
        flush_now();

        let mut operations = vec![
            CardOperation::InspectCard,
            CardOperation::ReadIdentity,
            CardOperation::ReadCertificate {
                kind: CertificateKind::Authentication,
            },
        ];
        if let Some((key_profile, algorithm)) = sign_profile {
            operations.push(CardOperation::BrowserAuthenticate {
                origin: DEMO_REQUESTER_CONTEXT.into(),
                key_profile,
                algorithm,
                digest: demo_digest(algorithm)?,
            });
        }
        for operation in &operations {
            print!("{} ... ", operation.action());
            let _ = std::io::stdout().flush();
            match requester.execute(&mut session, operation, OPERATION_EXPIRY_MS) {
                Ok(outcome) => {
                    report(operation, &outcome);
                    flush_now();
                }
                Err(error) => {
                    println!("not admitted: {error:?}");
                    break;
                }
            }
            if !requester
                .store()
                .get(pair_id)
                .is_ok_and(PairingRecord::serves)
            {
                return Err("the pairing serves nothing; pair again".into());
            }
        }
        requester.disconnect(&mut session, CloseReason::UserDisconnect);
        served += 1;
        println!("session closed; waiting for the next connection (Ctrl-C to quit)");
        flush_now();
        if let Some(target) = count
            && served >= target
        {
            println!("served {served} sessions; demo complete");
            break Ok(());
        }
    }
}

fn mock_proxy_cmd(arguments: &[String]) -> Result<(), String> {
    let mut options = MockProxyOptions::with_mock_certificate()?;
    let mut cursor = arguments.iter();
    while let Some(flag) = cursor.next() {
        let mut value = || {
            cursor
                .next()
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match flag.as_str() {
            "--code" => {
                options.code = Some(
                    normalize_pairing_code(&value()?)
                        .ok_or("a pairing code is six Crockford base32 characters")?,
                );
            }
            "--name" => options.name = value()?,
            "--platform" => options.platform = value()?,
            "--count" => {
                let val = value()?;
                options.count = val
                    .parse::<usize>()
                    .map_err(|_| format!("invalid session count: {val}"))?;
            }
            "--identity-name" => options.identity_name = value()?,
            "--person-id" => options.person_id = value()?,
            "--cert" => options.certificate = read_certificate(&value()?, "certificate")?,
            "--pin1-attempts" => {
                let val = value()?;
                options.pin1_attempts = val
                    .parse::<u8>()
                    .map_err(|_| format!("invalid pin1 attempts: {val}"))?;
            }
            "--pin2-attempts" => {
                let val = value()?;
                options.pin2_attempts = val
                    .parse::<u8>()
                    .map_err(|_| format!("invalid pin2 attempts: {val}"))?;
            }
            "--listen" => options.listen = value()?,
            "--card-absent" => options.card_absent = true,
            "--resume" => options.resume_state = Some(value()?),
            "--save-state" => options.save_state = Some(value()?),
            other => return Err(format!("unknown flag {other}")),
        }
    }
    run_mock_proxy(options)
}

/// Pushes buffered output through redirected stdout, which is block
/// buffered, so progress is visible while the process waits.
fn flush_now() {
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

/// The grant confirmation of RAPP v26.11.2 section 4.3 item 3.
fn confirm_grants(peer: &PeerIntroduction, requested: &[ProfileName]) -> Option<Vec<ProfileName>> {
    println!();
    println!(
        "pairing request from {} ({})",
        peer.display_name.as_str(),
        peer.platform
    );
    println!("grants to confirm: {}", profile_list(requested));
    print!("confirm this exact pairing? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return None;
    }
    if line.trim().eq_ignore_ascii_case("y") {
        Some(requested.to_vec())
    } else {
        None
    }
}

/// A fresh random digest of the algorithm's registered length.
/// The asking party the demo's authentication names: this tool, not a site.
const DEMO_REQUESTER_CONTEXT: &str = "refineid-rapp";

fn demo_digest(algorithm: SignatureAlgorithm) -> Result<Vec<u8>, String> {
    let mut digest = Vec::new();
    while digest.len() < algorithm.digest_length() {
        let challenge = Challenge::random().map_err(|_| "secure random unavailable")?;
        digest.extend_from_slice(&challenge.0);
    }
    digest.truncate(algorithm.digest_length());
    Ok(digest)
}

fn report(operation: &CardOperation, outcome: &OperationOutcome) {
    match outcome {
        OperationOutcome::Completed(result) => match result {
            CardOperationResult::Inspection(inspection) => {
                println!(
                    "ok: answer to reset, {} bytes",
                    inspection.answer_to_reset.len()
                );
            }
            CardOperationResult::Identity(identity) => {
                println!(
                    "ok: {} ({})",
                    identity.holder_name,
                    masked(&identity.card_id)
                );
            }
            CardOperationResult::Certificate(der) => {
                println!("ok: certificate, {} bytes DER", der.len());
            }
            CardOperationResult::Signature(bytes) => {
                println!("ok: signature, {} bytes", bytes.len());
            }
            CardOperationResult::Signatures(signatures) => {
                println!("ok: {} signatures", signatures.len());
            }
        },
        OperationOutcome::Rejected(ResultError::UserCancelled) => {
            println!("denied on the phone");
        }
        OperationOutcome::Rejected(error) => println!("rejected: {}", error.as_str()),
        OperationOutcome::Cancelled(error) => println!("cancelled: {}", error.as_str()),
        OperationOutcome::Refused(error) => println!("refused: {}", error.as_str()),
        OperationOutcome::Lost => println!(
            "lost: the session ended before {} was answered",
            operation.action()
        ),
    }
}

fn masked(person_id: &str) -> String {
    let visible: String = person_id.chars().take(PERSON_ID_VISIBLE_CHARS).collect();
    format!("{visible}…")
}

/// Reads a DER certificate file, parsed at this border.
fn read_certificate(path: &str, label: &str) -> Result<OwnedCert, String> {
    let der = std::fs::read(path).map_err(|e| format!("cannot read {label} at {path}: {e}"))?;
    OwnedCert::from_der(UnvalidatedCertificate::new(der))
        .map_err(|e| format!("the {label} at {path} does not parse: {e:?}"))
}

/// Reads a certificate when a path was given.
fn read_optional(path: Option<&str>, label: &str) -> Result<Option<OwnedCert>, String> {
    path.map(|path| read_certificate(path, label)).transpose()
}

fn setup_mock_pairing(arguments: &[String]) -> Result<(), String> {
    let mut cert_path = None;
    let mut state_path = "mock-proxy.state".to_owned();
    let mut serve = false;
    let mut cursor = arguments.iter();
    while let Some(flag) = cursor.next() {
        let mut value = || {
            cursor
                .next()
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match flag.as_str() {
            "--cert" => cert_path = Some(value()?),
            "--state" => state_path = value()?,
            "--serve" => serve = true,
            other => return Err(format!("unknown flag {other}")),
        }
    }

    let defaults = MockProxyOptions::with_mock_certificate()?;
    let certificate =
        read_optional(cert_path.as_deref(), "certificate")?.unwrap_or(defaults.certificate);

    let options = MockProxyOptions {
        code: Some(MOCK_PAIRING_CODE.to_owned()),
        count: if serve { SERVE_FOREVER } else { defaults.count },
        certificate: certificate.clone(),
        save_state: Some(state_path.clone()),
        ..defaults
    };
    let proxy_handle = std::thread::spawn(move || run_mock_proxy(options));

    let store = ProtectedPairingStore::load()
        .map_err(|e| format!("cannot load ProtectedPairingStore: {e}"))?;

    let mut requester = Requester::new(RequesterConfig::this_computer(), store);

    let transport = dial_for_pairing(
        &[DEFAULT_LISTEN.to_owned()],
        MOCK_DIAL_WINDOW,
        MOCK_DIAL_WINDOW,
        MOCK_DIAL_RETRY,
        || !proxy_handle.is_finished(),
    )
    .map_err(|error| format!("cannot reach the mock custodian: {error:?}"))?;

    let (pair_id, ()) = requester
        .pair_with_code(
            MOCK_PAIRING_CODE,
            &mut PairingAddress::new(transport, vec![DEFAULT_LISTEN.to_owned()], MOCK_DIAL_WINDOW),
            |_peer, requested| Some(requested.to_vec()),
        )
        .map_err(|e| format!("pairing failed: {e:?}"))?;

    println!("Mock pairing established and stored in Windows Credential Store:");
    println!("  pair_id: {}", hex::encode(pair_id.as_bytes()));
    println!("  auth_cert: {} bytes", certificate.as_der().len());
    println!("  proxy state saved to: {state_path}");

    if serve {
        println!("Proxy serving active sessions (press Ctrl-C to exit)...");
        let _ = proxy_handle.join();
    }
    Ok(())
}

/// Deletes this user's whole pairing set, keys included, and tells no
/// phone: a local wipe for a development machine, for instance of a set
/// that no longer decodes. `forget-pairing` is the user's forget action of
/// RAPP v26.11.2 section 4.6.
fn clear_pairing() -> Result<(), String> {
    refineid_windows_credential_store::delete_pairing_set()
        .map_err(|e| format!("failed to clear pairing: {e:?}"))?;
    println!("Deleted RefineID pairing set from Windows Credential Store.");
    Ok(())
}

/// The user's forget action on one pairing (RAPP v26.11.2 section 4.6): a
/// confirmed pairing keeps its keys only for the `pairing_revoked` close
/// its phone is given on the next session, and serves nothing from now on;
/// an unconfirmed or revoked one is removed.
fn forget_pairing_cmd(arguments: &[String]) -> Result<(), String> {
    let pair_id_str = arguments.first().ok_or("pair ID required")?;
    let raw = hex::decode(pair_id_str).map_err(|e| format!("invalid hex: {e}"))?;
    let pair_id = PairId::reconstruct(&raw).map_err(|_| {
        format!(
            "a pair ID is {} bytes in hexadecimal",
            refineid_rapp::PAIR_ID_SIZE
        )
    })?;
    let mut store = ProtectedPairingStore::load()
        .map_err(|e| format!("cannot load ProtectedPairingStore: {e}"))?;
    let state = store
        .get(pair_id)
        .map_err(|e| format!("no such pairing: {e:?}"))?
        .state();
    forget_pairing(&mut store, pair_id, unix_time_ms())
        .map_err(|e| format!("failed to forget pairing: {e:?}"))?;
    let shown = hex::encode(pair_id.as_bytes());
    match state {
        PairingState::Serving | PairingState::Forgotten => {
            println!("Forgot pairing {shown}; its phone is told on the next session");
        }
        PairingState::Unconfirmed | PairingState::Revoked { .. } => {
            println!("Removed pairing {shown}");
        }
    }
    Ok(())
}

fn list_pairing() -> Result<(), String> {
    let store = ProtectedPairingStore::load()
        .map_err(|e| format!("cannot load ProtectedPairingStore: {e}"))?;
    if store.is_empty() {
        println!("No pairings stored in Windows Credential Store.");
        return Ok(());
    }
    println!(
        "Stored pairings in Windows Credential Store ({}):",
        store.len()
    );
    for (index, record) in store.records().iter().enumerate() {
        let is_current = store
            .usable_pairing()
            .is_some_and(|u| u.pair_id() == record.pair_id());
        let marker = if is_current { "* " } else { "  " };
        println!(
            "{marker}[{index}] Pair ID: {}",
            hex::encode(record.pair_id().as_bytes())
        );
        println!(
            "      Peer: {} ({})",
            record.peer_display_name().as_str(),
            record.peer_platform()
        );
        println!("      State: {:?}", record.state());
        println!(
            "      Profiles: {}",
            profile_list(record.granted_profiles())
        );
    }
    Ok(())
}

fn export_pairing(arguments: &[String]) -> Result<(), String> {
    let out_path = arguments
        .first()
        .cloned()
        .unwrap_or_else(|| "pairing.blob".to_owned());
    let store = ProtectedPairingStore::load()
        .map_err(|e| format!("cannot load ProtectedPairingStore: {e}"))?;
    let record = store.usable_pairing().ok_or("no usable pairing found")?;
    let blob = encode_pairing_records(core::iter::once(record))
        .map_err(|e| format!("cannot encode the pairing: {e}"))?;
    std::fs::write(&out_path, &*blob).map_err(|e| format!("failed to write {out_path}: {e}"))?;
    println!("Exported the usable pairing record to {out_path}");
    Ok(())
}

fn import_pairing(arguments: &[String]) -> Result<(), String> {
    let in_path = arguments
        .first()
        .ok_or_else(|| "usage: refineid-rapp import-pairing <path>".to_owned())?;
    let bytes = std::fs::read(in_path).map_err(|e| format!("cannot read {in_path}: {e}"))?;
    let records = decode_pairing_records(&bytes)
        .map_err(|e| format!("cannot decode pairing records from {in_path}: {e:?}"))?
        .records;
    let mut store = ProtectedPairingStore::load()
        .map_err(|e| format!("cannot load ProtectedPairingStore: {e}"))?;
    let count = records.len();
    for record in records {
        store
            .insert(record)
            .map_err(|e| format!("cannot save pairing: {e:?}"))?;
    }
    println!("Imported {count} pairing record(s) into Windows Credential Store");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{clear_revoked_pairings, forget_replaced_pairings};
    use refineid_rapp::noise::x25519_public_key;
    use refineid_rapp::{
        DisplayName, EndpointRole, PairRecord, ProfileName, X25519_KEY_SIZE, compute_grants_hash,
    };
    use refineid_rapp_core::engine::{Requester, RequesterConfig};
    use refineid_rapp_core::ids::PairId;
    use refineid_rapp_core::store::{
        MemoryPairingStore, PairingRecord, PairingStore, revoke_pairing,
    };

    /// A synthetic held pairing.
    const FIRST_PAIR: PairId = PairId::from_array(*b"cli held pair 01");
    /// A synthetic fresh pairing.
    const SECOND_PAIR: PairId = PairId::from_array(*b"cli fresh pair 1");

    /// A synthetic requester static private key.
    const REQUESTER_PRIVATE: [u8; X25519_KEY_SIZE] = *b"synthetic requester private key.";
    /// A synthetic custodian static private key.
    const CUSTODIAN_PRIVATE: [u8; X25519_KEY_SIZE] = *b"synthetic custodian private key.";
    /// The pairing creation time the fixtures record.
    const CREATED_AT_MS: u64 = 1_700_000_000_000;

    /// A confirmed pairing record granting card status.
    fn record(pair_id: PairId) -> PairingRecord {
        let profiles = vec![ProfileName::CardStatus];
        let grants_hash = compute_grants_hash(&profiles).expect("grants hash");
        let keys = PairRecord::new(
            pair_id,
            EndpointRole::Requester,
            REQUESTER_PRIVATE,
            x25519_public_key(&REQUESTER_PRIVATE),
            x25519_public_key(&CUSTODIAN_PRIVATE),
            grants_hash,
            profiles,
            DisplayName::parse("Phone".to_owned()).expect("a display name"),
            CREATED_AT_MS,
        )
        .expect("a pair record");
        PairingRecord::new(keys, "iOS".to_owned())
    }

    fn requester(first: bool) -> Requester<MemoryPairingStore> {
        let mut store = MemoryPairingStore::new();
        if first {
            store.insert(record(FIRST_PAIR)).expect("insert held");
        }
        store.insert(record(SECOND_PAIR)).expect("insert fresh");
        Requester::new(RequesterConfig::this_computer(), store)
    }

    #[test]
    fn pairing_again_forgets_the_pairing_held_before() {
        let mut requester = requester(true);
        let replaced = forget_replaced_pairings(&mut requester, SECOND_PAIR);
        assert_eq!(replaced, vec![FIRST_PAIR]);
        assert!(
            !requester
                .store()
                .get(FIRST_PAIR)
                .expect("held record")
                .serves(),
            "the held pairing serves nothing from now on"
        );
        assert!(
            requester
                .store()
                .get(SECOND_PAIR)
                .expect("fresh record")
                .serves()
        );
    }

    #[test]
    fn a_first_pairing_forgets_nothing() {
        let mut requester = requester(false);
        assert!(forget_replaced_pairings(&mut requester, SECOND_PAIR).is_empty());
        assert!(
            requester
                .store()
                .get(SECOND_PAIR)
                .expect("fresh record")
                .serves()
        );
    }

    #[test]
    fn clearing_removes_only_what_the_attempt_revoked() {
        let mut requester = requester(true);
        revoke_pairing(requester.store_mut(), FIRST_PAIR, false, CREATED_AT_MS)
            .expect("revoke held");
        clear_revoked_pairings(&mut requester, &[FIRST_PAIR, SECOND_PAIR]);
        assert!(requester.store().get(FIRST_PAIR).is_err());
        assert!(requester.store().get(SECOND_PAIR).is_ok());
    }
}
