//! The scan for RAPP advertisers (RAPP v26.10.22 section 4.1).
//!
//! The advertisement carries the RAPP Service UUID and nothing else, so a
//! scan cannot tell this pairing's phone from another person's: it reports
//! every advertiser, strongest signal first, and the caller routes a
//! preamble to find out (section 2.2.1). Signal strength only orders the
//! attempts; it proves nothing about distance (section 4.4).

use std::collections::BTreeMap;
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher,
    BluetoothLEAdvertisementWatcherStatus, BluetoothLEScanningMode,
};
use windows::Foundation::TypedEventHandler;

use crate::gatt::SERVICE_UUID;
use crate::link::{AdvertiserAddress, Rssi};

/// How often a scan waiting for advertisements checks whether the radio
/// aborted it, so a radio switched off ends the scan within this time.
const ABORT_CHECK_INTERVAL: Duration = Duration::from_millis(250);

/// Whether the watcher was aborted; a status it cannot report counts as
/// aborted, since nothing more will arrive from it.
fn watcher_aborted(watcher: &BluetoothLEAdvertisementWatcher) -> bool {
    !matches!(
        watcher.Status(),
        Ok(status) if status != BluetoothLEAdvertisementWatcherStatus::Aborted
    )
}

/// One advertiser of the RAPP service seen during a scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScannedAdvertiser {
    /// The address it advertised under during this scan.
    pub address: AdvertiserAddress,
    /// The strongest signal it was received with during this scan.
    pub rssi: Rssi,
}

/// Why a scan could not run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanError {
    /// The Bluetooth radio is off, absent, or refused to this program.
    RadioUnavailable,
    /// A Windows Runtime call failed with this `HRESULT`.
    Platform(i32),
}

impl core::fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RadioUnavailable => write!(formatter, "Bluetooth is off or unavailable"),
            Self::Platform(code) => write!(formatter, "Windows Bluetooth error {code:#010X}"),
        }
    }
}

impl core::error::Error for ScanError {}

impl From<windows::core::Error> for ScanError {
    fn from(error: windows::core::Error) -> Self {
        Self::Platform(error.code().0)
    }
}

/// Scans for `window` and reports every RAPP advertiser seen, strongest
/// first.
///
/// An advertisement whose address or signal strength its border refuses is
/// not counted.
///
/// # Errors
/// [`ScanError::RadioUnavailable`] when the radio is off or the scan was
/// aborted, and [`ScanError::Platform`] for other Windows Runtime failures.
pub fn scan(window: Duration) -> Result<Vec<ScannedAdvertiser>, ScanError> {
    let scanned = scanned(window);
    match &scanned {
        Ok(_) => {}
        Err(ScanError::Platform(code)) => {
            refineid_dev_errors::report!(Bluetooth, "Bluetooth scan failed", status code);
        }
        Err(error) => refineid_dev_errors::report!(Bluetooth, "Bluetooth scan failed", error),
    }
    scanned
}

/// [`scan`], unreported.
fn scanned(window: Duration) -> Result<Vec<ScannedAdvertiser>, ScanError> {
    let watcher = BluetoothLEAdvertisementWatcher::new()?;
    watcher.SetScanningMode(BluetoothLEScanningMode::Active)?;
    watcher
        .AdvertisementFilter()?
        .Advertisement()?
        .ServiceUuids()?
        .Append(SERVICE_UUID)?;
    let (sender, received) = channel();
    let token = watcher.Received(&TypedEventHandler::<
        BluetoothLEAdvertisementWatcher,
        BluetoothLEAdvertisementReceivedEventArgs,
    >::new(move |_, args| {
        if let Some(args) = args.as_ref() {
            let _ = sender.send((args.BluetoothAddress()?, args.RawSignalStrengthInDBm()?));
        }
        Ok(())
    }))?;
    watcher.Start()?;
    let deadline = Instant::now() + window;
    let mut strongest: BTreeMap<AdvertiserAddress, Rssi> = BTreeMap::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || watcher_aborted(&watcher) {
            break;
        }
        let (raw_address, raw_rssi) =
            match received.recv_timeout(remaining.min(ABORT_CHECK_INTERVAL)) {
                Ok(advertisement) => advertisement,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            };
        let (Ok(address), Ok(rssi)) = (
            AdvertiserAddress::from_bluetooth_address(raw_address),
            Rssi::from_dbm(raw_rssi),
        ) else {
            continue;
        };
        strongest
            .entry(address)
            .and_modify(|seen| *seen = (*seen).max(rssi))
            .or_insert(rssi);
    }
    let aborted = watcher_aborted(&watcher);
    // An aborted watcher may refuse `Stop`; the scan is over either way,
    // and the handler is unhooked regardless.
    let stopped = watcher.Stop();
    let unhooked = watcher.RemoveReceived(token);
    if aborted {
        return Err(ScanError::RadioUnavailable);
    }
    stopped?;
    unhooked?;

    let mut advertisers: Vec<ScannedAdvertiser> = strongest
        .into_iter()
        .map(|(address, rssi)| ScannedAdvertiser { address, rssi })
        .collect();
    advertisers.sort_by_key(|advertiser| core::cmp::Reverse(advertiser.rssi));
    Ok(advertisers)
}
