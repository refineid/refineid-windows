//! The BLE commands over `"fi.refineid.rapp.ble"`: `ble-scan` lists RAPP
//! advertisers, `ble-pair` pairs with the phone showing a code and stores
//! the pairing, and `ble-session` opens a session with the stored pairing's
//! phone and reads its card.
//!
//! Nothing personal is printed: a read identity is reported as read, not
//! shown, and certificates by their size.

use std::io::Write as _;
use std::time::{Duration, Instant};

use refineid_rapp::{ProfileName, RoutingKey};
use refineid_rapp_ble::gatt::BleLink;
use refineid_rapp_ble::link::AdvertiserAddress;
use refineid_rapp_ble::reach::{Attempt, reach_session};
use refineid_rapp_ble::scan::{ScannedAdvertiser, scan};
use refineid_rapp_core::engine::{
    OperationOutcome, PairingCandidateSource, PairingConnection, PeerIntroduction, Requester,
    RequesterConfig,
};
use refineid_rapp_core::message::{CloseReason, ResultError};
use refineid_rapp_core::offer::{BootstrapAnswer, normalize_pairing_code};
use refineid_rapp_core::operations::{
    CardOperation, CardOperationExt, CardOperationResult, CertificateKind,
};
use refineid_rapp_core::store::{PairingRecord, PairingStore};
use refineid_rapp_core::stream::DialPurpose;
use refineid_windows_credential_store::ProtectedPairingStore;

/// One scan for advertisers before each round of pairing connections.
const SCAN_WINDOW: Duration = Duration::from_secs(4);
/// How long `ble-scan` listens unless told otherwise.
const DEFAULT_SCAN_SECONDS: u64 = 10;
/// Frame receive deadline on a pairing link: the user confirms the grants
/// while it waits.
const RECEIVE_DEADLINE: Duration = Duration::from_secs(60);
/// How long the requester keeps looking for a phone in pairing mode; the
/// custodian's offer lives this long (section 3.3).
const PAIRING_WINDOW: Duration = Duration::from_millis(refineid_rapp::OFFER_TTL_MS);
/// How long `ble-session` looks for the stored pairing's phone.
const SESSION_WINDOW: Duration = Duration::from_secs(60);
/// Operation lifetime sent on the wire (section 8.1 item 2).
const OPERATION_EXPIRY_MS: u64 = 60_000;

struct BleOptions {
    code: Option<String>,
    name: String,
    auto_confirm: bool,
    seconds: u64,
}

fn parse(arguments: &[String]) -> Result<BleOptions, String> {
    let mut options = BleOptions {
        code: None,
        name: "RefineID Windows".to_owned(),
        auto_confirm: false,
        seconds: DEFAULT_SCAN_SECONDS,
    };
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
                        .ok_or("the pairing code is six characters from the phone")?,
                );
            }
            "--name" => options.name = value()?,
            "--seconds" => {
                let raw = value()?;
                options.seconds = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid scan length: {raw}"))?;
            }
            "--auto-confirm" | "--yes" | "-y" => options.auto_confirm = true,
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(options)
}

fn describe(advertiser: &ScannedAdvertiser) -> String {
    format!("{}  {} dBm", advertiser.address, advertiser.rssi.dbm())
}

fn requester(name: &str) -> Result<Requester<ProtectedPairingStore>, String> {
    let store = ProtectedPairingStore::load()
        .map_err(|error| format!("the pairing store cannot be loaded: {error}"))?;
    Ok(Requester::new(
        RequesterConfig {
            display_name: name.to_owned(),
            platform: "Windows".into(),
        },
        store,
    ))
}

/// The RAPP advertisers in range, scanned round by round until the pairing
/// window passes, strongest first. An advertisement does not show the
/// mode: a peripheral is in pairing mode when it serves an offer or a
/// `pairing-busy` on a pairing connection (section 4.2, "Trying Each Custodian in Pairing
/// Mode" item 1).
struct Advertisers {
    search_until: Instant,
    /// Why a scan failed, which ends the search.
    scan_failure: Option<String>,
}

impl PairingCandidateSource for Advertisers {
    type Endpoint = AdvertiserAddress;
    type Transport = BleLink;

    fn discover(&mut self) -> Option<Vec<AdvertiserAddress>> {
        if Instant::now() >= self.search_until {
            return None;
        }
        let advertisers = scan(SCAN_WINDOW)
            .map_err(|error| self.scan_failure = Some(error.to_string()))
            .ok()?;
        if advertisers.is_empty() {
            println!("no RAPP advertiser was seen; keep RefineID open on the phone");
        }
        Some(
            advertisers
                .into_iter()
                .map(|advertiser| advertiser.address)
                .collect(),
        )
    }

    fn open(&mut self, address: &AdvertiserAddress) -> Option<PairingConnection<BleLink>> {
        println!("connecting to {address}");
        let link = BleLink::open(*address, DialPurpose::Pairing, RECEIVE_DEADLINE)
            .inspect_err(|error| println!("  {error}"))
            .ok()?;
        println!(
            "  link up: ATT MTU {} bytes, {} payload bytes per fragment",
            link.mtu().bytes(),
            link.capacity().bytes()
        );
        match link
            .read_bootstrap()
            .inspect_err(|error| println!("  {error}"))
            .ok()?
        {
            BootstrapAnswer::Offer(offer) => {
                println!("  read the pairing offer");
                Some(PairingConnection::Offer(link, offer))
            }
            BootstrapAnswer::Busy(busy) => Some(PairingConnection::Busy(busy)),
        }
    }

    fn bootstrap_again(&mut self, link: &mut BleLink) -> Option<BootstrapAnswer> {
        link.read_bootstrap().ok()
    }
}

/// `ble-scan`: lists every RAPP advertiser in range with its signal
/// strength.
pub fn ble_scan(arguments: &[String]) -> Result<(), String> {
    let options = parse(arguments)?;
    println!("scanning {} s for RAPP advertisers...", options.seconds);
    let advertisers =
        scan(Duration::from_secs(options.seconds)).map_err(|error| error.to_string())?;
    if advertisers.is_empty() {
        println!(
            "no RAPP advertiser was seen; over Bluetooth the phone is found only while \
             RefineID is open on it"
        );
    }
    for advertiser in &advertisers {
        println!("{}", describe(advertiser));
    }
    Ok(())
}

/// `ble-pair`: pairs with the phone showing `--code`, trying each
/// advertiser in pairing mode once, strongest first, a busy one again
/// after its wait, and stores the pairing.
pub fn ble_pair(arguments: &[String]) -> Result<(), String> {
    let options = parse(arguments)?;
    let code = options.code.as_deref().ok_or("--code is required")?;
    let mut requester = requester(&options.name)?;
    let auto_confirm = options.auto_confirm;
    let confirm = move |peer: &PeerIntroduction, requested: &[ProfileName]| {
        println!(
            "the phone introduced itself as {} ({})",
            peer.display_name, peer.platform
        );
        if auto_confirm {
            println!("granting: {}", crate::profile_list(requested));
            Some(requested.to_vec())
        } else {
            crate::confirm_grants(peer, requested)
        }
    };

    let mut advertisers = Advertisers {
        search_until: Instant::now() + PAIRING_WINDOW,
        scan_failure: None,
    };
    let (pair_id, _) = requester
        .pair_with_code(code, &mut advertisers, confirm)
        .map_err(|error| {
            advertisers
                .scan_failure
                .take()
                .unwrap_or_else(|| crate::pairing_failure(error))
        })?;

    let record = requester
        .store()
        .get(pair_id)
        .map_err(|error| format!("stored pairing unreadable: {error:?}"))?;
    println!(
        "paired over Bluetooth with {} ({}); granted: {}",
        record.peer().display_name,
        record.peer().platform,
        crate::profile_list(record.granted_profiles())
    );
    println!("the pairing is stored, protected to this Windows user");
    Ok(())
}

/// `ble-session`: opens a session with the stored pairing's phone over BLE
/// and reads its card: status, identity, and the authentication
/// certificate.
pub fn ble_session(arguments: &[String]) -> Result<(), String> {
    let options = parse(arguments)?;
    let mut requester = requester(&options.name)?;
    let (pair_id, key) = {
        let record = requester
            .store()
            .usable_pairing()
            .ok_or("no usable pairing is stored; pair with ble-pair first")?;
        let keys = record
            .pair_record()
            .ok_or("the stored pairing holds no keys; pair again")?;
        let key = RoutingKey::derive(keys)
            .map_err(|error| format!("stored pairing cannot route: {error:?}"))?;
        (PairingRecord::pair_id(record), key)
    };

    let mut session =
        reach_session(
            &mut requester,
            pair_id,
            &key,
            SESSION_WINDOW,
            |attempt| match attempt {
                Attempt::Routing(advertiser) => {
                    println!("routing a session to {}", describe(advertiser));
                }
                Attempt::LinkFailed(error) => println!("  {error}"),
                Attempt::Refused(error) => println!("  no session: {error:?}"),
            },
        )
        .map_err(|error| error.to_string())?;
    println!("session open over Bluetooth");

    let operations = [
        CardOperation::InspectCard,
        CardOperation::ReadIdentity,
        CardOperation::ReadCertificate {
            kind: CertificateKind::Authentication,
        },
    ];
    let mut refusal = None;
    for operation in &operations {
        print!("{} ... ", operation.action());
        let _ = std::io::stdout().flush();
        match requester.execute(&mut session, operation, OPERATION_EXPIRY_MS) {
            Ok(outcome) => println!("{}", summary(&outcome)),
            Err(error) => {
                println!("not admitted");
                refusal = Some(format!(
                    "{} was not admitted: {error:?}",
                    operation.action()
                ));
                break;
            }
        }
    }
    requester.disconnect(&mut session, CloseReason::UserDisconnect);
    println!("session closed");
    refusal.map_or(Ok(()), Err)
}

/// What an operation did, without anything personal.
fn summary(outcome: &OperationOutcome) -> String {
    match outcome {
        OperationOutcome::Completed(result) => match result {
            CardOperationResult::Inspection(inspection) => format!(
                "ok: answer to reset, {} bytes",
                inspection.answer_to_reset.len()
            ),
            CardOperationResult::Identity(_) => "ok: identity read (not shown)".to_owned(),
            CardOperationResult::Certificate(der) => {
                format!("ok: certificate, {} bytes DER", der.len())
            }
            CardOperationResult::Signature(bytes) => {
                format!("ok: signature, {} bytes", bytes.len())
            }
            CardOperationResult::Signatures(signatures) => {
                format!("ok: {} signatures", signatures.len())
            }
        },
        OperationOutcome::Rejected(ResultError::UserCancelled) => "denied on the phone".to_owned(),
        OperationOutcome::Rejected(error) => format!("rejected: {}", error.as_str()),
        OperationOutcome::Cancelled(error) => format!("cancelled: {}", error.as_str()),
        OperationOutcome::Refused(error) => format!("refused: {}", error.as_str()),
        OperationOutcome::Lost => "lost: the session ended before the answer".to_owned(),
    }
}
