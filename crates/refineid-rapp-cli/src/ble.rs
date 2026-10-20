//! The BLE commands: `ble-scan` lists RAPP advertisers, and `ble-pair`
//! pairs with the phone showing a code over `"fi.refineid.rapp.ble.v1"`.
//!
//! `ble-pair` keeps the pairing in memory for the life of the process: the
//! durable pairing store still writes the static key outside protected
//! storage (issue #35), so no BLE pairing is written there.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use refineid_rapp_ble::gatt::BleLink;
use refineid_rapp_ble::link::{AdvertiserAddress, ProximityGate};
use refineid_rapp_ble::scan::{ScannedAdvertiser, scan};
use refineid_rapp_core::engine::{PairingError, PeerIntroduction, Requester, RequesterConfig};
use refineid_rapp_core::offer::normalize_pairing_code;
use refineid_rapp_core::store::{MemoryJournal, MemoryPairingStore, PairingStore};
use refineid_rapp_core::stream::DialPurpose;

/// One scan for advertisers before each round of dials.
const SCAN_WINDOW: Duration = Duration::from_secs(4);
/// How long `ble-scan` listens unless told otherwise.
const DEFAULT_SCAN_SECONDS: u64 = 10;
/// Frame receive deadline on an open link.
const RECEIVE_DEADLINE: Duration = Duration::from_secs(30);
/// How long the requester keeps trying the code; the custodian's offer
/// lives this long (section 3.3).
const PAIRING_WINDOW: Duration = Duration::from_millis(refineid_rapp::OFFER_TTL_MS);

struct BleOptions {
    code: Option<String>,
    name: String,
    gate: ProximityGate,
    auto_confirm: bool,
    seconds: u64,
}

fn parse(arguments: &[String]) -> Result<BleOptions, String> {
    let mut options = BleOptions {
        code: None,
        name: "RefineID Windows".to_owned(),
        gate: ProximityGate::SPECIFICATION,
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
            "--gate" => {
                let raw = value()?;
                let dbm = raw
                    .parse::<i16>()
                    .map_err(|_| format!("invalid proximity threshold: {raw}"))?;
                options.gate =
                    ProximityGate::development(dbm).map_err(|error| error.to_string())?;
            }
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
    format!(
        "{}  {} dBm  {}",
        advertiser.address,
        advertiser.reading.rssi().dbm(),
        if advertiser.admitted {
            "within the proximity gate"
        } else {
            "outside the proximity gate"
        }
    )
}

/// `ble-scan`: lists every RAPP advertiser in range with its filtered
/// signal strength.
pub fn ble_scan(arguments: &[String]) -> Result<(), String> {
    let options = parse(arguments)?;
    println!(
        "scanning {} s for RAPP advertisers (gate {} dBm)...",
        options.seconds,
        options.gate.threshold().dbm()
    );
    let advertisers = scan(Duration::from_secs(options.seconds), options.gate)
        .map_err(|error| error.to_string())?;
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

/// `ble-pair`: pairs with the phone showing `--code`, trying each admitted
/// advertiser once per scan, strongest first (core STPA R-53).
pub fn ble_pair(arguments: &[String]) -> Result<(), String> {
    let options = parse(arguments)?;
    let code = options.code.as_deref().ok_or("--code is required")?;
    let mut requester = Requester::new(
        RequesterConfig {
            display_name: options.name.clone(),
            platform: "Windows".into(),
        },
        MemoryPairingStore::new(),
        MemoryJournal::new(),
    );
    let auto_confirm = options.auto_confirm;
    let confirm = move |peer: &PeerIntroduction, requested: &[String]| {
        println!(
            "the phone introduced itself as {} ({})",
            peer.display_name, peer.platform
        );
        if auto_confirm {
            println!("granting: {}", requested.join(", "));
            Some(requested.to_vec())
        } else {
            crate::confirm_grants(peer, requested)
        }
    };

    let deadline = Instant::now() + PAIRING_WINDOW;
    let mut refused: BTreeSet<AdvertiserAddress> = BTreeSet::new();
    let pair_id = 'search: loop {
        if Instant::now() >= deadline {
            return Err("no phone accepted the code; show a new code and try again".into());
        }
        let advertisers = scan(SCAN_WINDOW, options.gate).map_err(|error| error.to_string())?;
        let admitted: Vec<&ScannedAdvertiser> = advertisers
            .iter()
            .filter(|advertiser| advertiser.admitted && !refused.contains(&advertiser.address))
            .collect();
        if admitted.is_empty() {
            println!(
                "no RAPP advertiser within the proximity gate; keep the phone close and RefineID open"
            );
            continue;
        }
        for advertiser in admitted {
            println!("connecting to {}", describe(advertiser));
            let link =
                match BleLink::open(advertiser.address, DialPurpose::Pairing, RECEIVE_DEADLINE) {
                    Ok(link) => link,
                    Err(error) => {
                        println!("  {error}");
                        refused.insert(advertiser.address);
                        continue;
                    }
                };
            println!(
                "  link up: ATT MTU {} bytes, {} payload bytes per fragment",
                link.mtu().bytes(),
                link.capacity().bytes()
            );
            let offer = match link.read_bootstrap() {
                Ok(offer) => offer,
                Err(error) => {
                    println!("  {error}");
                    refused.insert(advertiser.address);
                    continue;
                }
            };
            println!("  read the pairing offer");
            match requester.pair_with_offer(code, offer, link, confirm) {
                Ok(pair_id) => break 'search pair_id,
                Err(PairingError::CodeMismatch) => {
                    return Err("the phone refused the code; check it and try again".into());
                }
                Err(PairingError::DeniedLocally) => return Err("pairing declined".into()),
                Err(error) => {
                    println!("  pairing attempt failed: {error:?}");
                    refused.insert(advertiser.address);
                }
            }
        }
    };

    let record = requester
        .store()
        .get(pair_id)
        .map_err(|error| format!("stored pairing unreadable: {error:?}"))?;
    println!(
        "paired over Bluetooth with {} ({}); granted: {}",
        record.peer_display_name,
        record.peer_platform,
        record.granted_profiles.join(", ")
    );
    println!("the pairing lives in this process only and ends with it");
    Ok(())
}
