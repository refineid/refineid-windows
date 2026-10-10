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
//! credential vault and dials sessions against it, with no fresh pairing
//! ceremony. Both share one session loop.
//!
//! This is a development tool. It prints operation results to the terminal
//! and must not be distributed to end users.

use std::io::Write as _;
use std::time::{Duration, Instant};

use refineid_rapp_cli::mock_proxy::{DEFAULT_LISTEN, MockProxyOptions, run_mock_proxy};
use refineid_rapp_core::engine::{
    OperationOutcome, PairingError, PeerIntroduction, Requester, RequesterConfig,
};
use refineid_rapp_core::ids::{Challenge, PairId, RendezvousToken};
use refineid_rapp_core::message::CloseReason;
use refineid_rapp_core::offer::normalize_pairing_code;
use refineid_rapp_core::operations::{
    CardOperation, CardOperationExt, CardOperationResult, CertificateKind, KeyProfile,
    SignatureAlgorithm, SignatureAlgorithmExt,
};
use refineid_rapp_core::persistence::{decode_pairing_records, encode_pairing_records};
use refineid_rapp_core::store::{MemoryJournal, MemoryPairingStore, PairingStore};
use refineid_rapp_core::stream::{
    DiscoveryMode, STREAM_CANDIDATE_ID, StreamRendezvous, browse, dial, dial_session,
};
use refineid_windows_credential_store::CredentialPairingStore;

/// Frame receive deadline on a dialed connection.
const RECEIVE_DEADLINE: Duration = Duration::from_mins(3);

/// How long the requester keeps looking for the custodian showing the code;
/// the custodian's offer lives this long (section 3.3).
const PAIRING_WINDOW: Duration = Duration::from_millis(refineid_rapp::OFFER_TTL_MS);

/// One DNS-SD browse round.
const BROWSE_WINDOW: Duration = Duration::from_secs(3);

/// Pause between session dial rounds that found no custodian.
const SESSION_RETRY: Duration = Duration::from_secs(2);

/// Operation expiry sent on the wire; the holder approves within this.
const OPERATION_EXPIRY_MS: u64 = 120_000;

/// Visible prefix of a personal identifier in development output.
const PERSON_ID_VISIBLE_CHARS: usize = 6;

/// The pairing code `setup-mock-pairing` gives its mock custodian.
const MOCK_PAIRING_CODE: &str = "654321";

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match arguments.first().map(String::as_str) {
        Some("pair-demo") => pair_demo(&arguments[1..]),
        Some("reconnect") => reconnect(&arguments[1..]),
        Some("mock-proxy") => mock_proxy_cmd(&arguments[1..]),
        Some("setup-mock-pairing") => setup_mock_pairing(&arguments[1..]),
        Some("clear-pairing") => clear_pairing(),
        Some("remove-pairing") => remove_pairing(&arguments[1..]),
        Some("list-pairing") => list_pairing(),
        Some("export-cert") => export_cert(&arguments[1..]),
        Some("export-pairing") => export_pairing(&arguments[1..]),
        Some("import-pairing") => import_pairing(&arguments[1..]),
        _ => {
            eprintln!("usage:");
            eprintln!("  refineid-rapp pair-demo --code <code> [--connect <host:port>] \\");
            eprintln!("      [--name <label>] [--auto-confirm] [--count <n>] \\");
            eprintln!("      [--sign-profile rsa3072|ecdsa384] [--durable]");
            eprintln!("  refineid-rapp reconnect [--connect <host:port>] \\");
            eprintln!("      [--sign-profile rsa3072|ecdsa384] [--count <n>]");
            eprintln!("  refineid-rapp mock-proxy [--listen <bind-address>] [--code <code>] \\");
            eprintln!("      [--resume <state>] [--save-state <path>] \\");
            eprintln!("      [--cert <path>] [--root-ca <path>] [--intermediate-ca <path>] \\");
            eprintln!("      [--count <n>] [--identity-name <name>] [--person-id <id>]");
            eprintln!(
                "  refineid-rapp setup-mock-pairing [--cert <path>] [--root-ca <path>] [--intermediate-ca <path>] [--state <path>] [--serve]"
            );
            eprintln!("  refineid-rapp clear-pairing");
            eprintln!("  refineid-rapp list-pairing");
            eprintln!("  refineid-rapp export-cert [<path>]");
            eprintln!("  refineid-rapp export-pairing [<path>]");
            eprintln!("  refineid-rapp import-pairing <path>");
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
        let store = CredentialPairingStore::load()
            .map_err(|error| format!("cannot load CredentialPairingStore: {error}"))?;
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
        MemoryJournal::new(),
    );
    let auto_confirm = options.auto_confirm;
    let confirm = move |peer: &PeerIntroduction, requested: &[String]| {
        if auto_confirm {
            println!();
            println!(
                "auto-confirming pairing request from {} ({})",
                peer.display_name, peer.platform
            );
            println!("granted: {}", requested.join(", "));
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
                &StreamRendezvous::Pairing,
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

    let expected_token = {
        let record = requester
            .store()
            .get(pair_id)
            .map_err(|error| format!("stored pairing unreadable: {error:?}"))?;
        println!(
            "paired with {} ({}); granted: {}",
            record.peer_display_name,
            record.peer_platform,
            record.granted_profiles.join(", ")
        );
        record.rendezvous_token
    };
    flush_now();

    serve_sessions(
        &mut requester,
        options.connect.as_deref(),
        pair_id,
        expected_token,
        options.sign_profile,
        options.count,
    )
}

/// Reconnects to a pairing the settings app already stored in the Windows
/// credential vault and serves sessions against it -- the durable path the
/// minidriver will use. No pairing ceremony runs; the requester finds the
/// phone by its session advertisement.
fn reconnect(arguments: &[String]) -> Result<(), String> {
    let options = parse_options(arguments)?;

    let store = CredentialPairingStore::load()
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
        MemoryJournal::new(),
    );

    let (pair_id, expected_token) = {
        let record = requester
            .store()
            .usable_pairing()
            .ok_or("the stored pairing is revoked; pair again in the settings app")?;
        println!(
            "reconnecting to {} ({}); granted: {}",
            record.peer_display_name,
            record.peer_platform,
            record.granted_profiles.join(", ")
        );
        (record.pair_id, record.rendezvous_token)
    };
    flush_now();

    serve_sessions(
        &mut requester,
        options.connect.as_deref(),
        pair_id,
        expected_token,
        options.sign_profile,
        options.count,
    )
}

fn record_certificate_outcome<S: PairingStore>(
    requester: &mut Requester<S, MemoryJournal>,
    pair_id: PairId,
    operation: &CardOperation,
    outcome: &OperationOutcome,
) {
    let OperationOutcome::Completed(CardOperationResult::Certificate(der)) = outcome else {
        return;
    };
    if matches!(
        operation,
        CardOperation::ReadCertificate {
            kind: CertificateKind::Authentication,
        }
    ) {
        let update_res = requester.store_mut().update(pair_id, &mut |rec| {
            rec.auth_cert = Some(der.clone());
        });
        if let Err(e) = update_res {
            println!("warning: could not update auth_cert in pairing store: {e:?}");
        } else {
            println!(
                "persisted authentication certificate ({} bytes) to store",
                der.len()
            );
        }
    }
}

/// Dials sessions for one pairing until interrupted: each session runs the
/// read operations and an optional signature, then disconnects. Shared by
/// `pair-demo` and `reconnect`.
fn serve_sessions<S: PairingStore>(
    requester: &mut Requester<S, MemoryJournal>,
    connect: Option<&str>,
    pair_id: PairId,
    expected_token: RendezvousToken,
    sign_profile: Option<(KeyProfile, SignatureAlgorithm)>,
    count: Option<usize>,
) -> Result<(), String> {
    let preferred: Vec<String> = connect.map(str::to_owned).into_iter().collect();
    let mut served = 0;
    loop {
        let Ok(transport) = dial_session(
            expected_token,
            &preferred,
            &[],
            BROWSE_WINDOW,
            RECEIVE_DEADLINE,
        ) else {
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
            if requester.store().get(pair_id).is_err() {
                return Err("the pairing is gone; pair again".into());
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
    let mut options = MockProxyOptions::default();
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
            "--cert" => {
                let path = value()?;
                let bytes = std::fs::read(&path)
                    .map_err(|e| format!("cannot read certificate at {path}: {e}"))?;
                options.cert_der = bytes;
            }
            "--root-ca" => {
                let path = value()?;
                let bytes = std::fs::read(&path)
                    .map_err(|e| format!("cannot read root CA at {path}: {e}"))?;
                options.root_ca_der = Some(bytes);
            }
            "--intermediate-ca" => {
                let path = value()?;
                let bytes = std::fs::read(&path)
                    .map_err(|e| format!("cannot read intermediate CA at {path}: {e}"))?;
                options.intermediate_ca_der = Some(bytes);
            }
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

/// The both-device grant confirmation of specification Section 9.3 step 7.
fn confirm_grants(peer: &PeerIntroduction, requested: &[String]) -> Option<Vec<String>> {
    println!();
    println!(
        "pairing request from {} ({})",
        peer.display_name, peer.platform
    );
    println!("grants to confirm: {}", requested.join(", "));
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
                    "ok: pin1 factory {}, pin2 factory {}, attempts {}",
                    inspection.pin1_factory,
                    inspection.pin2_factory,
                    attempts_label(
                        inspection.pin1_attempts,
                        inspection.pin2_attempts,
                        inspection.puk_attempts
                    )
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
        },
        OperationOutcome::Denied => println!("denied on the phone"),
        OperationOutcome::Cancelled => println!("cancelled or expired"),
        OperationOutcome::Rejected(reason) => {
            println!("rejected: {}", reason.as_deref().unwrap_or("unnamed"));
        }
        OperationOutcome::CredentialRejected => {
            println!("credential rejected; the pairing is revoked on both devices");
        }
        OperationOutcome::Ambiguous => {
            println!(
                "ambiguous: {} may or may not have executed; it will not be retried",
                operation.action()
            );
        }
    }
}

fn attempts_label(pin1: Option<u8>, pin2: Option<u8>, puk: Option<u8>) -> String {
    let label = |value: Option<u8>| value.map_or_else(|| "?".to_owned(), |count| count.to_string());
    format!(
        "pin1 {}, pin2 {}, puk {}",
        label(pin1),
        label(pin2),
        label(puk)
    )
}

fn masked(person_id: &str) -> String {
    let visible: String = person_id.chars().take(PERSON_ID_VISIBLE_CHARS).collect();
    format!("{visible}…")
}

/// Reads a DER file when a path was given.
fn read_optional(path: Option<&str>, label: &str) -> Result<Option<Vec<u8>>, String> {
    path.map(|path| std::fs::read(path).map_err(|e| format!("cannot read {label} at {path}: {e}")))
        .transpose()
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

    let cert_der = read_optional(cert_path.as_deref(), "certificate")?
        .unwrap_or_else(|| refineid_rapp_cli::mock_proxy::DEFAULT_MOCK_CERT_DER.to_vec());
    let root_ca_der = read_optional(root_ca_path.as_deref(), "root CA")?;
    let intermediate_ca_der = read_optional(intermediate_ca_path.as_deref(), "intermediate CA")?;

    let proxy_cert = cert_der.clone();
    let proxy_root = root_ca_der.clone();
    let proxy_inter = intermediate_ca_der.clone();
    let save_file = state_path.clone();

    let proxy_handle = std::thread::spawn(move || {
        let options = MockProxyOptions {
            code: Some(MOCK_PAIRING_CODE.to_owned()),
            count: usize::from(!serve),
            cert_der: proxy_cert,
            root_ca_der: proxy_root,
            intermediate_ca_der: proxy_inter,
            save_state: Some(save_file),
            ..Default::default()
        };
        run_mock_proxy(options)
    });

    let store = CredentialPairingStore::load()
        .map_err(|e| format!("cannot load CredentialPairingStore: {e}"))?;

    let mut requester = Requester::new(
        RequesterConfig {
            display_name: "RefineID Windows".into(),
            platform: "Windows".into(),
        },
        store,
        MemoryJournal::new(),
    );

    let endpoints = [DEFAULT_LISTEN.to_owned()];
    let deadline = Instant::now() + Duration::from_secs(10);
    let transport = loop {
        match dial(
            &endpoints,
            STREAM_CANDIDATE_ID,
            Duration::from_secs(10),
            &StreamRendezvous::Pairing,
        ) {
            Ok(transport) => break transport,
            Err(_) if Instant::now() < deadline && !proxy_handle.is_finished() => {
                std::thread::sleep(Duration::from_millis(100));
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
            rec.auth_cert = Some(cert_der.clone());
            rec.signature_cert = Some(cert_der.clone());
            rec.root_ca.clone_from(&root_ca_der);
            rec.intermediate_ca.clone_from(&intermediate_ca_der);
        })
        .map_err(|e| format!("failed to update pairing record: {e:?}"))?;

    println!("Mock pairing established and stored in Windows Credential Store:");
    println!("  pair_id: {}", hex::encode(pair_id.as_bytes()));
    println!("  auth_cert: {} bytes", cert_der.len());
    if let Some(r) = &root_ca_der {
        println!("  root_ca: {} bytes", r.len());
    }
    if let Some(i) = &intermediate_ca_der {
        println!("  intermediate_ca: {} bytes", i.len());
    }
    println!("  proxy state saved to: {state_path}");

    if serve {
        println!("Proxy serving active sessions (press Ctrl-C to exit)...");
        let _ = proxy_handle.join();
    }
    Ok(())
}

fn clear_pairing() -> Result<(), String> {
    refineid_windows_credential_store::delete_pairing_set()
        .map_err(|e| format!("failed to clear pairing: {e:?}"))?;
    println!("Deleted RefineID pairing set from Windows Credential Store.");
    Ok(())
}

fn remove_pairing(arguments: &[String]) -> Result<(), String> {
    let pair_id_str = arguments.first().ok_or("pair ID required")?;
    let raw = hex::decode(pair_id_str).map_err(|e| format!("invalid hex: {e}"))?;
    if raw.len() != 16 {
        return Err("pair ID must be 16 bytes (32 hex chars)".into());
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&raw);
    let pair_id = PairId::from_array(arr);
    let mut store = CredentialPairingStore::load()
        .map_err(|e| format!("cannot load CredentialPairingStore: {e}"))?;
    store
        .remove(pair_id)
        .map_err(|e| format!("failed to remove pairing: {e:?}"))?;
    println!("Removed pairing {}", hex::encode(arr));
    Ok(())
}

fn list_pairing() -> Result<(), String> {
    let store = CredentialPairingStore::load()
        .map_err(|e| format!("cannot load CredentialPairingStore: {e}"))?;
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
            .is_some_and(|u| u.pair_id == record.pair_id);
        let marker = if is_current { "* " } else { "  " };
        println!(
            "{marker}[{index}] Pair ID: {}",
            hex::encode(record.pair_id.as_bytes())
        );
        println!(
            "      Peer: {} ({})",
            record.peer_display_name, record.peer_platform
        );
        println!(
            "      Rendezvous Token: {}",
            hex::encode(record.rendezvous_token.as_bytes())
        );
        println!("      Profiles: {}", record.granted_profiles.join(", "));
        println!("      Has Auth Cert: {}", record.auth_cert.is_some());
        println!("      Has Root CA: {}", record.root_ca.is_some());
        println!(
            "      Has Intermediate CA: {}",
            record.intermediate_ca.is_some()
        );
    }
    Ok(())
}

fn export_cert(arguments: &[String]) -> Result<(), String> {
    let out_path = arguments
        .first()
        .cloned()
        .unwrap_or_else(|| "auth_cert.der".to_owned());
    let store = CredentialPairingStore::load()
        .map_err(|e| format!("cannot load CredentialPairingStore: {e}"))?;
    let record = store.usable_pairing().ok_or("no usable pairing found")?;
    let auth_der = record
        .auth_cert
        .as_ref()
        .ok_or("no auth cert stored in pairing")?;
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
    let store = CredentialPairingStore::load()
        .map_err(|e| format!("cannot load CredentialPairingStore: {e}"))?;
    let records: Vec<_> = store.usable_pairing().into_iter().cloned().collect();
    if records.is_empty() {
        return Err("no usable pairing found".to_owned());
    }
    let blob = encode_pairing_records(&records);
    std::fs::write(&out_path, &*blob).map_err(|e| format!("failed to write {out_path}: {e}"))?;
    println!("Exported {} pairing record(s) to {out_path}", records.len());
    Ok(())
}

fn import_pairing(arguments: &[String]) -> Result<(), String> {
    let in_path = arguments
        .first()
        .ok_or_else(|| "usage: refineid-rapp import-pairing <path>".to_owned())?;
    let bytes = std::fs::read(in_path).map_err(|e| format!("cannot read {in_path}: {e}"))?;
    let records = decode_pairing_records(&bytes)
        .map_err(|e| format!("cannot decode pairing records from {in_path}: {e:?}"))?;
    let mut store = CredentialPairingStore::load()
        .map_err(|e| format!("cannot load CredentialPairingStore: {e}"))?;
    let count = records.len();
    for record in records {
        store
            .insert(record)
            .map_err(|e| format!("cannot save pairing: {e:?}"))?;
    }
    println!("Imported {count} pairing record(s) into Windows Credential Store");
    Ok(())
}
