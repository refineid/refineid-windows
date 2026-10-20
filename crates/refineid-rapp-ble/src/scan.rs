//! The scan for RAPP advertisers (RAPP v26.10.18 sections 4.1 and 4.4).
//!
//! The advertisement carries the RAPP Service UUID and nothing else, so a
//! scan cannot tell this pairing's phone from another person's: it reports
//! every advertiser with its filtered signal strength and whether the
//! proximity gate admits it, strongest first, and the caller routes a
//! preamble to find out (section 2.2.1).

use std::collections::BTreeMap;
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher,
    BluetoothLEAdvertisementWatcherStatus, BluetoothLEScanningMode,
};
use windows::Foundation::TypedEventHandler;

use crate::gatt::SERVICE_UUID;
use crate::link::{AdvertiserAddress, ProximityGate, ProximityReading, Rssi};

/// One advertiser of the RAPP service seen during a scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScannedAdvertiser {
    /// The address it advertised under during this scan.
    pub address: AdvertiserAddress,
    /// Its filtered signal strength.
    pub reading: ProximityReading,
    /// Whether the proximity gate admits it.
    pub admitted: bool,
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

/// Scans for `window` and reports every RAPP advertiser that sent enough
/// advertisements for a reading, strongest first.
///
/// An advertisement whose address or signal strength its border refuses is
/// not counted.
///
/// # Errors
/// [`ScanError::RadioUnavailable`] when the radio is off or the scan was
/// aborted, and [`ScanError::Platform`] for other Windows Runtime failures.
pub fn scan(window: Duration, gate: ProximityGate) -> Result<Vec<ScannedAdvertiser>, ScanError> {
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
    let mut samples: BTreeMap<AdvertiserAddress, Vec<Rssi>> = BTreeMap::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok((raw_address, raw_rssi)) = received.recv_timeout(remaining) else {
            break;
        };
        let (Ok(address), Ok(rssi)) = (
            AdvertiserAddress::from_bluetooth_address(raw_address),
            Rssi::from_dbm(raw_rssi),
        ) else {
            continue;
        };
        samples.entry(address).or_default().push(rssi);
    }
    let aborted = watcher.Status()? == BluetoothLEAdvertisementWatcherStatus::Aborted;
    watcher.Stop()?;
    watcher.RemoveReceived(token)?;
    if aborted {
        return Err(ScanError::RadioUnavailable);
    }

    let mut advertisers: Vec<ScannedAdvertiser> = samples
        .into_iter()
        .filter_map(|(address, measured)| {
            let reading = ProximityReading::median_of(&measured)?;
            Some(ScannedAdvertiser {
                address,
                reading,
                admitted: gate.admits(reading, false),
            })
        })
        .collect();
    advertisers.sort_by_key(|advertiser| core::cmp::Reverse(advertiser.reading.rssi()));
    Ok(advertisers)
}
