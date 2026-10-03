//! Development requester CLI for the RAPP remote-card path.
//!
//! `refineid-rapp pair-demo` proves the full stream-profile path against a
//! real phone proxy in one process: it displays the pairing QR, accepts the
//! phone's connection, confirms grants on both devices, then serves inbound
//! sessions and runs typed card operations that the holder approves on the
//! phone. Its pair keys live only for the process lifetime.
//!
//! `refineid-rapp reconnect` proves the durable path the minidriver will use:
//! it loads a pairing the settings app already stored in the Windows
//! credential vault and serves sessions against it, with no fresh pairing
//! ceremony. Both share one session-serving loop.
//!
//! This is a development tool. It prints operation results to the terminal
//! and must not be distributed to end users.

use std::io::Write as _;
use std::time::{Duration, Instant};

use refineid_rapp_cli::mock_proxy::{MockProxyOptions, run_mock_proxy};
use refineid_rapp_core::engine::{OperationOutcome, PeerIntroduction, Requester, RequesterConfig};
use refineid_rapp_core::ids::{
    Challenge, OfferId, PairId, PairingSecret, RandomIdExt as _, RendezvousToken,
};
use refineid_rapp_core::limits::OFFER_TTL_MAX_MS;
use refineid_rapp_core::message::CloseReason;
use refineid_rapp_core::offer::{
    PairingOffer, TransportCandidate, format_pairing_code, is_valid_pairing_code,
    normalize_pairing_code, offer_id_from_code,
};
use refineid_rapp_core::operations::{
    CardOperation, CardOperationExt, CardOperationResult, CertificateKind, KeyProfile,
    SignatureAlgorithm, SignatureAlgorithmExt,
};
use refineid_rapp_core::persistence::{decode_pairing_records, encode_pairing_records};
use refineid_rapp_core::profiles::{
    PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS, PROFILE_DOCUMENT_SIGNING,
};
use refineid_rapp_core::store::{MemoryJournal, MemoryPairingStore, PairingStore};
use refineid_rapp_core::stream::{StreamAccept, StreamListener, stream_candidate_parameters};
use refineid_rapp_core::transport::STREAM_PROFILE;
use refineid_windows_credential_store::CredentialPairingStore;

/// The one stream candidate this CLI advertises.
const CANDIDATE_ID: &str = "stream-1";

/// Frame receive deadline; also the accept-loop poll bound.
const RECEIVE_DEADLINE: Duration = Duration::from_mins(3);

/// Operation expiry sent on the wire; the holder approves within this.
const OPERATION_EXPIRY_MS: u64 = 120_000;

/// Visible prefix of a personal identifier in development output.
const PERSON_ID_VISIBLE_CHARS: usize = 6;

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
        Some("firewall-check") => {
            firewall_check_cmd(&arguments[1..]);
            Ok(())
        }
        _ => {
            eprintln!("usage:");
            eprintln!("  refineid-rapp pair-demo --listen <bind-address> \\");
            eprintln!("      --advertise <host:port> [--advertise <host:port> ...] \\");
            eprintln!("      [--name <label>] [--code <code>] [--auto-confirm] [--count <n>] \\");
            eprintln!("      [--sign-profile rsa3072|ecdsa384] [--durable] \\");
            eprintln!("      [--root-ca <path>] [--intermediate-ca <path>]");
            eprintln!("  refineid-rapp reconnect --listen <bind-address> \\");
            eprintln!("      [--sign-profile rsa3072|ecdsa384] [--count <n>]");
            eprintln!("  refineid-rapp firewall-check [<port>]");
            eprintln!(
                "  refineid-rapp mock-proxy (--connect <host:port> --code <code> | --uri <rapp-uri> | --resume <state>) \\"
            );
            eprintln!("      [--cert <path>] [--root-ca <path>] [--intermediate-ca <path>] \\");
            eprintln!(
                "      [--save-state <path>] [--count <n>] [--identity-name <name>] [--person-id <id>]"
            );
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
    listen: String,
    advertise: Vec<String>,
    name: String,
    code: Option<String>,
    auto_confirm: bool,
    count: Option<usize>,
    sign_profile: Option<(KeyProfile, SignatureAlgorithm)>,
    durable: bool,
}

fn parse_options(arguments: &[String]) -> Result<DemoOptions, String> {
    let mut listen = None;
    let mut advertise = Vec::new();
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
            "--listen" => listen = Some(value()?),
            "--advertise" => advertise.push(value()?),
            "--name" => name = value()?,
            "--code" => {
                let val = value()?;
                if !is_valid_pairing_code(&val) {
                    return Err(format!("invalid 6-digit pairing code: {val}"));
                }
                code = Some(normalize_pairing_code(&val));
            }
            "--auto-confirm" | "--yes" | "-y" => auto_confirm = true,
            "--durable" | "--save" => durable = true,
            "--root-ca" | "--intermediate-ca" => {
                let _ = value()?;
            }
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
        listen: listen.ok_or("--listen is required")?,
        advertise,
        name,
        code,
        auto_confirm,
        count,
        sign_profile,
        durable,
    })
}

#[cfg(windows)]
fn check_firewall(port: u16) {
    let output = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=RefineID RAPP",
        ])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            println!("[firewall] Inbound firewall rule 'RefineID RAPP' is configured.");
        }
        _ => {
            println!(
                "[firewall] Warning: Inbound firewall rule for port {port} may not be configured."
            );
            println!("[firewall] To allow the phone to connect, run as Administrator:");
            println!(
                "           netsh advfirewall firewall add rule name=\"RefineID RAPP\" dir=in action=allow protocol=TCP localport=40000-60000"
            );
        }
    }
}

#[cfg(not(windows))]
const fn check_firewall(_port: u16) {}

fn firewall_check_cmd(arguments: &[String]) {
    let port = arguments
        .first()
        .and_then(|arg| arg.parse::<u16>().ok())
        .unwrap_or(47110);
    check_firewall(port);
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

#[allow(
    clippy::too_many_lines,
    reason = "the demo is one linear ceremony and reads best unsplit"
)]
fn run_pair_demo<S: PairingStore>(options: &DemoOptions, store: S) -> Result<(), String> {
    if options.advertise.is_empty() {
        return Err("--advertise is required at least once".into());
    }
    let listener = StreamListener::bind(&options.listen, CANDIDATE_ID, RECEIVE_DEADLINE)
        .map_err(|error| format!("cannot bind {}: {error:?}", options.listen))?;
    let port = listener
        .local_port()
        .map_err(|error| format!("cannot read bound port: {error:?}"))?;
    println!("listening on {} (port {port})", options.listen);
    check_firewall(port);

    let mut requester = Requester::new(
        RequesterConfig {
            display_name: options.name.clone(),
            platform: "Windows".into(),
        },
        store,
        MemoryJournal::new(),
    );

    let requested_profiles = vec![
        PROFILE_CARD_STATUS.to_owned(),
        PROFILE_AUTHENTICATION.to_owned(),
        PROFILE_DOCUMENT_SIGNING.to_owned(),
    ];

    let (offer, pairing_service, manual_code, qr_secret) = if let Some(code) = &options.code {
        let raw_code = normalize_pairing_code(code);
        let pairing_code = format_pairing_code(&raw_code);
        let offer_id = offer_id_from_code(&raw_code).map_err(|e| format!("invalid code: {e:?}"))?;
        let candidate_params = stream_candidate_parameters(&options.advertise)
            .map_err(|error| format!("invalid advertised endpoints: {error:?}"))?;
        let offer = PairingOffer::reconstruct(
            offer_id,
            vec![refineid_rapp::MANDATORY_PAIRING_SUITE.into()],
            requested_profiles.clone(),
            vec![TransportCandidate {
                profile: STREAM_PROFILE.into(),
                candidate_id: CANDIDATE_ID.into(),
                parameters: candidate_params,
            }],
            OFFER_TTL_MAX_MS,
        )
        .map_err(|error| format!("offer reconstruct failed: {error:?}"))?;
        let uri = offer
            .to_uri()
            .map_err(|error| format!("offer encoding failed: {error:?}"))?;
        let service = refineid_rapp_core::stream::stream_rendezvous_name(uri.expose().as_bytes());
        println!(
            "manual-code pairing mode: enter code in RefineID on the phone; expires in 3 minutes"
        );
        println!("pairing code: {pairing_code}");
        flush_now();
        (offer, service, Some(raw_code), None)
    } else {
        let offer_id =
            OfferId::random().map_err(|_| "csprng failed: random offer_id".to_owned())?;
        let secret = PairingSecret::random()
            .map_err(|_| "csprng failed: random pairing_secret".to_owned())?;
        let candidate_params = stream_candidate_parameters(&options.advertise)
            .map_err(|error| format!("invalid advertised endpoints: {error:?}"))?;
        let offer = PairingOffer::reconstruct(
            offer_id,
            vec![refineid_rapp::MANDATORY_PAIRING_SUITE.into()],
            requested_profiles.clone(),
            vec![TransportCandidate {
                profile: STREAM_PROFILE.into(),
                candidate_id: CANDIDATE_ID.into(),
                parameters: candidate_params,
            }],
            OFFER_TTL_MAX_MS,
        )
        .map_err(|error| format!("offer reconstruct failed: {error:?}"))?;
        let uri = offer
            .to_uri()
            .map_err(|error| format!("offer encoding failed: {error:?}"))?;
        let qr = qrcode::QrCode::new(uri.expose().as_bytes())
            .map_err(|error| format!("QR encoding failed: {error}"))?;
        println!(
            "{}",
            qr.render::<qrcode::render::unicode::Dense1x2>().build()
        );
        println!("scan QR with RefineID on the phone; the offer expires in three minutes");
        println!();
        println!("offer text (the QR encodes exactly this):");
        println!("{}", uri.expose());
        flush_now();
        let service = refineid_rapp_core::stream::stream_rendezvous_name(uri.expose().as_bytes());
        (offer, service, None, Some(secret))
    };
    println!("pairing service instance: {pairing_service}");
    flush_now();

    let mut offer_slot = Some(offer);
    let deadline = Instant::now() + Duration::from_millis(OFFER_TTL_MAX_MS);
    let pair_id = loop {
        if Instant::now() >= deadline {
            return Err("the pairing offer expired".into());
        }
        if offer_slot.is_none() {
            return Err("the pairing offer was consumed by a failed attempt".into());
        }

        // 1. Discover if the proxy is listening under the offer's derived service name
        let discovered = refineid_rapp_core::stream::discover_stream_endpoints(
            Some(&pairing_service),
            Duration::from_millis(600),
        );
        if !discovered.is_empty() {
            println!(
                "discovered proxy advertising {pairing_service} at {discovered:?}, dialing..."
            );
            flush_now();
            if let Ok(transport) = refineid_rapp_core::stream::dial(
                &discovered,
                CANDIDATE_ID,
                Duration::from_secs(10),
                &refineid_rapp_core::stream::StreamRendezvous::Pairing,
            ) {
                let auto_confirm = options.auto_confirm;
                let outcome = if let Some(code) = &manual_code {
                    requester.pair_with_code(
                        &mut offer_slot,
                        code,
                        &requested_profiles,
                        transport,
                        |peer, requested| {
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
                        },
                    )
                } else if let Some(secret) = &qr_secret {
                    requester.pair_with_secret(
                        &mut offer_slot,
                        secret,
                        &requested_profiles,
                        transport,
                        |peer, requested| {
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
                        },
                    )
                } else {
                    return Err("no pairing secret or code available".into());
                };
                match outcome {
                    Ok(pair_id) => break pair_id,
                    Err(error) => {
                        println!("pairing attempt failed: {error:?}");
                    }
                }
            }
        }

        // 2. Check on listener for reverse-dial harness
        match listener.accept_timeout(Duration::from_millis(200)) {
            Ok(Some(StreamAccept::Pairing(transport))) => {
                let auto_confirm = options.auto_confirm;
                let outcome = if let Some(code) = &manual_code {
                    requester.pair_with_code(
                        &mut offer_slot,
                        code,
                        &requested_profiles,
                        transport,
                        |peer, requested| {
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
                        },
                    )
                } else {
                    requester.pair(
                        &mut offer_slot,
                        &requested_profiles,
                        transport,
                        |peer, requested| {
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
                        },
                    )
                };
                match outcome {
                    Ok(pair_id) => break pair_id,
                    Err(error) => {
                        println!("pairing attempt failed: {error:?}");
                    }
                }
            }
            Ok(Some(StreamAccept::Session { .. })) => {
                println!("discarded a session attempt before any pairing exists");
            }
            Ok(None) => {}
            Err(error) => {
                println!("discarded connection: {error:?}");
            }
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
        &listener,
        pair_id,
        expected_token,
        options.sign_profile,
        options.count,
    )
}

/// Reconnects to a pairing the settings app already stored in the Windows
/// credential vault and serves sessions against it -- the durable path the
/// minidriver will use. No pairing ceremony runs; the phone dials the same
/// listener address it stored at pairing.
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

    let listener = StreamListener::bind(&options.listen, CANDIDATE_ID, RECEIVE_DEADLINE)
        .map_err(|error| format!("cannot bind {}: {error:?}", options.listen))?;
    serve_sessions(
        &mut requester,
        &listener,
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

/// Serves inbound sessions for one pairing until interrupted: for each session
/// the phone dials, it connects, runs the read operations and an optional
/// signature, and disconnects. Shared by `pair-demo` and `reconnect`.
#[allow(
    clippy::too_many_lines,
    reason = "serving sessions involves linear operation dispatch and loop handling"
)]
fn serve_sessions<S: PairingStore>(
    requester: &mut Requester<S, MemoryJournal>,
    listener: &StreamListener,
    pair_id: PairId,
    expected_token: RendezvousToken,
    sign_profile: Option<(KeyProfile, SignatureAlgorithm)>,
    count: Option<usize>,
) -> Result<(), String> {
    let service_name =
        refineid_rapp_core::stream::stream_rendezvous_name(expected_token.as_bytes());
    println!("session service instance: {service_name}");
    flush_now();
    let mut served = 0;
    loop {
        let mut transport_opt = None;

        // 1. Try dialing the proxy directly if it is advertising via mDNS
        let discovered = refineid_rapp_core::stream::discover_stream_endpoints(
            Some(&service_name),
            Duration::from_millis(800),
        );
        if !discovered.is_empty() {
            println!("dialing proxy for session at {discovered:?}...");
            flush_now();
            if let Ok(transport) = refineid_rapp_core::stream::dial(
                &discovered,
                CANDIDATE_ID,
                Duration::from_secs(10),
                &refineid_rapp_core::stream::StreamRendezvous::Session(expected_token),
            ) {
                transport_opt = Some(transport);
            }
        }

        // 2. Check listener for reverse-dial harness
        if transport_opt.is_none() {
            match listener.accept_timeout(Duration::from_millis(500)) {
                Ok(Some(StreamAccept::Session {
                    rendezvous_token,
                    transport,
                })) => {
                    if rendezvous_token == expected_token {
                        transport_opt = Some(transport);
                    } else {
                        println!("discarded a session for an unknown rendezvous token");
                    }
                }
                Ok(Some(StreamAccept::Pairing(_))) => {
                    println!("discarded a pairing attempt; no offer is active");
                }
                Ok(None) => {}
                Err(error) => {
                    println!("discarded connection: {error:?}");
                }
            }
        }

        let Some(transport) = transport_opt else {
            std::thread::sleep(Duration::from_millis(200));
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
            "--connect" => options.connect = Some(value()?),
            "--code" => {
                let val = value()?;
                if !is_valid_pairing_code(&val) {
                    return Err(format!("invalid 6-digit pairing code: {val}"));
                }
                options.code = Some(normalize_pairing_code(&val));
            }
            "--uri" => options.uri = Some(value()?),
            "--candidate-id" => options.candidate_id = value()?,
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
            "--listen" => options.listen = Some(value()?),
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
            CardOperationResult::Identity {
                display_name,
                person_id,
            } => {
                println!("ok: {display_name} ({})", masked(person_id));
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

#[expect(
    clippy::too_many_lines,
    reason = "CLI helper orchestrating local mock pairing setup"
)]
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

    let cert_der = if let Some(path) = cert_path {
        std::fs::read(&path).map_err(|e| format!("cannot read cert at {path}: {e}"))?
    } else {
        refineid_rapp_cli::mock_proxy::DEFAULT_MOCK_CERT_DER.to_vec()
    };
    let root_ca_der = if let Some(path) = root_ca_path {
        Some(std::fs::read(&path).map_err(|e| format!("cannot read root CA at {path}: {e}"))?)
    } else {
        None
    };
    let intermediate_ca_der = if let Some(path) = intermediate_ca_path {
        Some(
            std::fs::read(&path)
                .map_err(|e| format!("cannot read intermediate CA at {path}: {e}"))?,
        )
    } else {
        None
    };

    let test_code = "654321";
    let offer_id = offer_id_from_code(test_code).map_err(|e| format!("invalid code: {e:?}"))?;

    let requested_profiles = vec![
        PROFILE_CARD_STATUS.to_owned(),
        PROFILE_AUTHENTICATION.to_owned(),
        PROFILE_DOCUMENT_SIGNING.to_owned(),
    ];

    let listener = StreamListener::bind("127.0.0.1:0", CANDIDATE_ID, Duration::from_secs(10))
        .map_err(|e| format!("cannot bind listener: {e:?}"))?;
    let port = listener
        .local_port()
        .map_err(|e| format!("cannot get port: {e:?}"))?;
    let local_endpoint = format!("127.0.0.1:{port}");

    let stream_params = stream_candidate_parameters(std::slice::from_ref(&local_endpoint))
        .map_err(|e| format!("parameters: {e:?}"))?;
    let offer = PairingOffer::reconstruct(
        offer_id,
        vec![refineid_rapp::MANDATORY_PAIRING_SUITE.into()],
        requested_profiles.clone(),
        vec![TransportCandidate {
            profile: STREAM_PROFILE.into(),
            candidate_id: CANDIDATE_ID.into(),
            parameters: stream_params,
        }],
        OFFER_TTL_MAX_MS,
    )
    .map_err(|e| format!("offer reconstruct failed: {e:?}"))?;

    let proxy_endpoint = local_endpoint;
    let proxy_cert = cert_der.clone();
    let proxy_root = root_ca_der.clone();
    let proxy_inter = intermediate_ca_der.clone();
    let save_file = state_path.clone();

    let proxy_handle = std::thread::spawn(move || {
        let options = MockProxyOptions {
            connect: Some(proxy_endpoint),
            listen: if serve {
                Some("127.0.0.1:47110".to_owned())
            } else {
                None
            },
            code: Some(test_code.to_owned()),
            candidate_id: CANDIDATE_ID.to_owned(),
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

    let accepted = listener
        .accept()
        .map_err(|e| format!("accept pairing: {e:?}"))?;
    let StreamAccept::Pairing(transport) = accepted else {
        return Err("expected StreamAccept::Pairing".into());
    };

    let mut offer_slot = Some(offer);
    let pair_id = requester
        .pair_with_code(
            &mut offer_slot,
            test_code,
            &requested_profiles,
            transport,
            |_peer, requested| Some(requested.to_vec()),
        )
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
        println!(
            "      Service Name: {}",
            refineid_rapp_core::stream::stream_rendezvous_name(record.rendezvous_token.as_bytes())
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
