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

use refineid_lib_core::x509::OwnedCert;
use refineid_rapp::ProfileName;
use refineid_rapp_cli::mock_proxy::{
    DEFAULT_LISTEN, MockProxyOptions, SERVE_FOREVER, run_mock_proxy,
};
use refineid_rapp_core::clock::unix_time_ms;
use refineid_rapp_core::engine::{
    OperationOutcome, PairingError, PeerIntroduction, Requester, RequesterConfig,
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
    DialPurpose, DiscoveryMode, STREAM_CANDIDATE_ID, browse, dial, dial_session,
};
use refineid_windows_credential_store::ProtectedPairingStore;

/// Frame receive deadline on a dialed pairing connection.
const RECEIVE_DEADLINE: Duration = Duration::from_mins(3);

/// How long the requester keeps looking for the custodian showing the code;
/// the custodian's offer lives this long (section 3.3).
const PAIRING_WINDOW: Duration = Duration::from_millis(refineid_rapp::OFFER_TTL_MS);

/// One DNS-SD browse round.
const BROWSE_WINDOW: Duration = Duration::from_secs(3);

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
        Some("export-cert") => export_cert(&arguments[1..]),
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
            eprintln!("      [--name <label>] [--auto-confirm] [--count <n>] \\");
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
                "  refineid-rapp setup-mock-pairing [--cert <path>] [--root-ca <path>] [--intermediate-ca <path>] [--state <path>] [--serve]"
            );
            eprintln!("  refineid-rapp forget-pairing <pair-id>");
            eprintln!("  refineid-rapp clear-pairing   (local wipe; no phone is told)");
            eprintln!("  refineid-rapp list-pairing");
            eprintln!("  refineid-rapp export-cert [<path>]");
            eprintln!("  refineid-rapp export-pairing [<path>]");
            eprintln!("  refineid-rapp import-pairing <path>");
            #[cfg(windows)]
            {
                eprintln!("  refineid-rapp ble-scan [--seconds <n>]");
                eprintln!(
                    "  refineid-rapp ble-pair --code <code> [--name <label>] [--auto-confirm]"
                );
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
    name: String,
    code: Option<String>,
    auto_confirm: bool,
    count: Option<usize>,
    sign_profile: Option<(KeyProfile, SignatureAlgorithm)>,
    durable: bool,
}

fn parse_options(arguments: &[String]) -> Result<DemoOptions, String> {
    let mut connect = None;
    let mut name = "RefineID Windows".to_owned();
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
            "--name" => name = value()?,
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
        name,
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
    let mut requester = Requester::new(
        RequesterConfig {
            display_name: options.name.clone(),
            platform: "Windows".into(),
        },
        store,
    );
    let auto_confirm = options.auto_confirm;
    let confirm = move |peer: &PeerIntroduction, requested: &[ProfileName]| {
        if auto_confirm {
            println!();
            println!(
                "auto-confirming pairing request from {} ({})",
                peer.display_name, peer.platform
            );
            println!("granted: {}", profile_list(requested));
            Some(requested.to_vec())
        } else {
            confirm_grants(peer, requested)
        }
    };

    println!("looking for the phone showing the code...");
    flush_now();
    let deadline = Instant::now() + PAIRING_WINDOW;
    let pair_id = 'search: loop {
        if Instant::now() >= deadline {
            return Err("no phone accepted the code; show a new code and try again".into());
        }
        let candidates: Vec<Vec<String>> = options.connect.as_ref().map_or_else(
            || {
                browse(DiscoveryMode::Pairing, BROWSE_WINDOW)
                    .into_iter()
                    .map(|service| service.endpoints)
                    .collect()
            },
            |endpoint| vec![vec![endpoint.clone()]],
        );
        for endpoints in candidates {
            let Ok(transport) = dial(
                &endpoints,
                STREAM_CANDIDATE_ID,
                RECEIVE_DEADLINE,
                DialPurpose::Pairing,
            ) else {
                continue;
            };
            println!("dialed {endpoints:?}");
            flush_now();
            match requester.pair_with_code(code, transport, confirm) {
                Ok(pair_id) => break 'search pair_id,
                Err(PairingError::CodeMismatch) => {
                    return Err("the phone refused the code; check it and try again".into());
                }
                Err(PairingError::DeniedLocally) => return Err("pairing declined".into()),
                Err(error) => println!("pairing attempt failed: {error:?}"),
            }
        }
        if options.connect.is_some() {
            std::thread::sleep(SESSION_RETRY);
        }
    };

    {
        let record = requester
            .store()
            .get(pair_id)
            .map_err(|error| format!("stored pairing unreadable: {error:?}"))?;
        println!(
            "paired with {} ({}); granted: {}",
            record.peer().display_name,
            record.peer().platform,
            profile_list(record.granted_profiles())
        );
    }
    flush_now();

    serve_sessions(
        &mut requester,
        options.connect.as_deref(),
        pair_id,
        options.sign_profile,
        options.count,
    )
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

    let mut requester = Requester::new(
        RequesterConfig {
            display_name: options.name.clone(),
            platform: "Windows".into(),
        },
        store,
    );

    let pair_id = {
        let record = requester
            .store()
            .usable_pairing()
            .ok_or("the stored pairing serves nothing; pair again in the settings app")?;
        println!(
            "reconnecting to {} ({}); granted: {}",
            record.peer().display_name,
            record.peer().platform,
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

fn record_certificate_outcome<S: PairingStore>(
    requester: &mut Requester<S>,
    pair_id: PairId,
    operation: &CardOperation,
    outcome: &OperationOutcome,
) {
    let OperationOutcome::Completed(CardOperationResult::Certificate(der)) = outcome else {
        return;
    };
    if !matches!(
        operation,
        CardOperation::ReadCertificate {
            kind: CertificateKind::Authentication,
        }
    ) {
        return;
    }
    let Ok(certificate) = OwnedCert::from_der(der) else {
        println!("warning: the phone's certificate does not parse");
        return;
    };
    let update_res = requester.store_mut().update(pair_id, &mut |rec| {
        rec.remember_authentication_certificate(certificate.clone());
    });
    if let Err(e) = update_res {
        println!("warning: could not keep the certificate in the pairing store: {e:?}");
    } else {
        println!(
            "persisted authentication certificate ({} bytes) to store",
            der.len()
        );
    }
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
        let Ok(transport) = dial_session(keys, &preferred, &[], BROWSE_WINDOW) else {
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
                origin: "rapp-demo.refineid.fi".into(),
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
                    record_certificate_outcome(requester, pair_id, operation, &outcome);
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

/// The grant confirmation of RAPP v26.10.22 section 4.3 item 3.
fn confirm_grants(peer: &PeerIntroduction, requested: &[ProfileName]) -> Option<Vec<ProfileName>> {
    println!();
    println!(
        "pairing request from {} ({})",
        peer.display_name, peer.platform
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
    OwnedCert::from_der(der).map_err(|e| format!("the {label} at {path} does not parse: {e:?}"))
}

/// Reads a certificate when a path was given.
fn read_optional(path: Option<&str>, label: &str) -> Result<Option<OwnedCert>, String> {
    path.map(|path| read_certificate(path, label)).transpose()
}

fn setup_mock_pairing(arguments: &[String]) -> Result<(), String> {
    let mut cert_path = None;
    let mut root_ca_path = None;
    let mut intermediate_ca_path = None;
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
            "--root-ca" => root_ca_path = Some(value()?),
            "--intermediate-ca" => intermediate_ca_path = Some(value()?),
            "--state" => state_path = value()?,
            "--serve" => serve = true,
            other => return Err(format!("unknown flag {other}")),
        }
    }

    let defaults = MockProxyOptions::with_mock_certificate()?;
    let certificate =
        read_optional(cert_path.as_deref(), "certificate")?.unwrap_or(defaults.certificate);
    let root = read_optional(root_ca_path.as_deref(), "root CA")?;
    let intermediate = read_optional(intermediate_ca_path.as_deref(), "intermediate CA")?;

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

    let mut requester = Requester::new(
        RequesterConfig {
            display_name: "RefineID Windows".into(),
            platform: "Windows".into(),
        },
        store,
    );

    let endpoints = [DEFAULT_LISTEN.to_owned()];
    let deadline = Instant::now() + MOCK_DIAL_WINDOW;
    let transport = loop {
        match dial(
            &endpoints,
            STREAM_CANDIDATE_ID,
            MOCK_DIAL_WINDOW,
            DialPurpose::Pairing,
        ) {
            Ok(transport) => break transport,
            Err(_) if Instant::now() < deadline && !proxy_handle.is_finished() => {
                std::thread::sleep(MOCK_DIAL_RETRY);
            }
            Err(error) => return Err(format!("cannot reach the mock custodian: {error:?}")),
        }
    };

    let pair_id = requester
        .pair_with_code(MOCK_PAIRING_CODE, transport, |_peer, requested| {
            Some(requested.to_vec())
        })
        .map_err(|e| format!("pairing failed: {e:?}"))?;

    requester
        .store_mut()
        .update(pair_id, &mut |rec| {
            rec.remember_authentication_certificate(certificate.clone());
            rec.remember_signature_certificate(certificate.clone());
            if let Some(root) = &root {
                rec.remember_root_certificate(root.clone());
            }
            if let Some(intermediate) = &intermediate {
                rec.remember_intermediate_certificate(intermediate.clone());
            }
        })
        .map_err(|e| format!("failed to update pairing record: {e:?}"))?;

    println!("Mock pairing established and stored in Windows Credential Store:");
    println!("  pair_id: {}", hex::encode(pair_id.as_bytes()));
    println!("  auth_cert: {} bytes", certificate.as_der().len());
    if let Some(r) = &root {
        println!("  root_ca: {} bytes", r.as_der().len());
    }
    if let Some(i) = &intermediate {
        println!("  intermediate_ca: {} bytes", i.as_der().len());
    }
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
/// RAPP v26.10.22 section 4.6.
fn clear_pairing() -> Result<(), String> {
    refineid_windows_credential_store::delete_pairing_set()
        .map_err(|e| format!("failed to clear pairing: {e:?}"))?;
    println!("Deleted RefineID pairing set from Windows Credential Store.");
    Ok(())
}

/// The user's forget action on one pairing (RAPP v26.10.22 section 4.6): a
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
            record.peer().display_name,
            record.peer().platform
        );
        println!("      State: {:?}", record.state());
        println!(
            "      Profiles: {}",
            profile_list(record.granted_profiles())
        );
        println!(
            "      Has Auth Cert: {}",
            record.authentication_certificate().is_some()
        );
        println!("      Has Root CA: {}", record.root_certificate().is_some());
        println!(
            "      Has Intermediate CA: {}",
            record.intermediate_certificate().is_some()
        );
    }
    Ok(())
}

fn export_cert(arguments: &[String]) -> Result<(), String> {
    let out_path = arguments
        .first()
        .cloned()
        .unwrap_or_else(|| "auth_cert.der".to_owned());
    let store = ProtectedPairingStore::load()
        .map_err(|e| format!("cannot load ProtectedPairingStore: {e}"))?;
    let record = store.usable_pairing().ok_or("no usable pairing found")?;
    let auth_der = record
        .authentication_certificate()
        .ok_or("no auth cert stored in pairing")?
        .as_der();
    std::fs::write(&out_path, auth_der).map_err(|e| format!("failed to write {out_path}: {e}"))?;
    println!(
        "Exported auth cert ({} bytes) to {out_path}",
        auth_der.len()
    );
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
        .map_err(|e| format!("cannot decode pairing records from {in_path}: {e:?}"))?;
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
