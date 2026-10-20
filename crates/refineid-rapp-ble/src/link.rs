//! The values a BLE link reports, each refined at the border it crosses.
//!
//! The Windows Runtime hands the requester an advertiser address as a `u64`, a signal
//! strength as an `i16`, and a negotiated MTU as a `u16`. None of those
//! carries its predicate. Each type here has one constructor that checks
//! the predicate its source states, so a value is proof of it, and the
//! fragment capacity can be built only from an MTU already proven large
//! enough. Nothing here touches the radio; the module builds on every host.

use core::fmt;

use refineid_rapp::ble_sar::{BLE_MINIMUM_ATT_MTU, BleSarError, payload_capacity};

/// Bits in a Bluetooth device address (Bluetooth Core v5.4, Vol 2, Part B,
/// §1.2: a 48-bit `BD_ADDR`).
const DEVICE_ADDRESS_BITS: u32 = 48;
/// The largest value a 48-bit device address holds.
const DEVICE_ADDRESS_MAX: u64 = (1 << DEVICE_ADDRESS_BITS) - 1;
/// Octets in a device address, for display.
const DEVICE_ADDRESS_OCTETS: u32 = DEVICE_ADDRESS_BITS / u8::BITS;

/// The weakest signal strength an LE advertising report carries, in dBm
/// (Bluetooth Core v5.4, Vol 4, Part E, §7.7.65.2, `RSSI`: -127 to +20).
const RSSI_MINIMUM_DBM: i16 = -127;
/// The strongest signal strength an LE advertising report carries, in dBm.
const RSSI_MAXIMUM_DBM: i16 = 20;
/// The `RSSI` value meaning that no measurement is available (same section).
const RSSI_NOT_AVAILABLE: i16 = 127;

/// The proximity threshold RAPP v26.10.18 section 4.4 item 1 requires, in dBm.
const PROXIMITY_GATE_SPECIFICATION_DBM: i16 = -55;
/// The weakest threshold section 4.4 item 1 allows, strictly in isolated
/// development environments, in dBm.
const PROXIMITY_GATE_DEVELOPMENT_FLOOR_DBM: i16 = -85;
/// The advertisements a filtered reading needs (section 4.4 item 2).
pub const PROXIMITY_MINIMUM_SAMPLES: usize = 3;
/// The hysteresis an admitted advertiser keeps, in dB (section 4.4 item 2).
const PROXIMITY_HYSTERESIS_DB: i16 = 3;

/// A value from the link that its border refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkValueError {
    /// The advertiser address is zero or wider than 48 bits.
    AddressOutOfRange,
    /// The advertising report carried no signal-strength measurement.
    RssiUnavailable,
    /// The signal strength lies outside -127 to +20 dBm.
    RssiOutOfRange,
    /// A development proximity threshold lies outside -85 to -55 dBm.
    GateOutOfRange,
    /// The negotiated ATT MTU is below the 512 bytes section 5.2 requires.
    MtuBelowMinimum {
        /// The MTU the two Bluetooth stacks negotiated.
        negotiated: u16,
    },
    /// The SAR layer refused the capacity the MTU allows.
    Capacity(BleSarError),
}

impl fmt::Display for LinkValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressOutOfRange => write!(formatter, "advertiser address out of range"),
            Self::RssiUnavailable => write!(formatter, "signal strength not available"),
            Self::RssiOutOfRange => write!(formatter, "signal strength out of range"),
            Self::GateOutOfRange => write!(
                formatter,
                "proximity threshold outside {PROXIMITY_GATE_DEVELOPMENT_FLOOR_DBM} to \
                 {PROXIMITY_GATE_SPECIFICATION_DBM} dBm"
            ),
            Self::MtuBelowMinimum { negotiated } => write!(
                formatter,
                "this computer's Bluetooth link negotiated an ATT MTU of {negotiated} bytes; \
                 RAPP needs at least {BLE_MINIMUM_ATT_MTU}"
            ),
            Self::Capacity(error) => write!(formatter, "fragment capacity refused: {error}"),
        }
    }
}

impl core::error::Error for LinkValueError {}

/// The Bluetooth device address an advertisement came from.
///
/// Phones advertise under a resolvable private address that rotates (RAPP
/// v26.10.18 section 4.1), so an address names an advertiser for as long as
/// it is advertised, not a phone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdvertiserAddress(u64);

impl AdvertiserAddress {
    /// Refines the address the Windows Runtime reports for an advertisement.
    ///
    /// # Errors
    /// [`LinkValueError::AddressOutOfRange`] for zero or a value wider than
    /// 48 bits.
    pub const fn from_bluetooth_address(raw: u64) -> Result<Self, LinkValueError> {
        if raw == 0 || raw > DEVICE_ADDRESS_MAX {
            return Err(LinkValueError::AddressOutOfRange);
        }
        Ok(Self(raw))
    }

    /// The address in the form the Windows Runtime takes it back.
    #[must_use]
    pub const fn bluetooth_address(self) -> u64 {
        self.0
    }
}

impl fmt::Display for AdvertiserAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let octets = self.0.to_be_bytes();
        let skipped = octets.len() - DEVICE_ADDRESS_OCTETS as usize;
        let mut separator = "";
        for octet in &octets[skipped..] {
            write!(formatter, "{separator}{octet:02X}")?;
            separator = ":";
        }
        Ok(())
    }
}

/// One signal-strength measurement of an advertisement, in dBm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rssi(i16);

impl Rssi {
    /// Refines the signal strength the Windows Runtime reports for an advertisement.
    ///
    /// # Errors
    /// [`LinkValueError::RssiUnavailable`] for the "not available" value and
    /// [`LinkValueError::RssiOutOfRange`] outside -127 to +20 dBm.
    pub const fn from_dbm(raw: i16) -> Result<Self, LinkValueError> {
        if raw == RSSI_NOT_AVAILABLE {
            return Err(LinkValueError::RssiUnavailable);
        }
        if raw < RSSI_MINIMUM_DBM || raw > RSSI_MAXIMUM_DBM {
            return Err(LinkValueError::RssiOutOfRange);
        }
        Ok(Self(raw))
    }

    /// The measurement in dBm.
    #[must_use]
    pub const fn dbm(self) -> i16 {
        self.0
    }
}

/// The filtered signal strength of one advertiser: the median of at least
/// [`PROXIMITY_MINIMUM_SAMPLES`] measurements (section 4.4 item 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProximityReading(Rssi);

impl ProximityReading {
    /// The median of `samples`, taking the weaker of the two middle values
    /// when their count is even.
    ///
    /// Returns `None` for fewer than [`PROXIMITY_MINIMUM_SAMPLES`]
    /// measurements: such an advertiser has no reading yet.
    #[must_use]
    pub fn median_of(samples: &[Rssi]) -> Option<Self> {
        if samples.len() < PROXIMITY_MINIMUM_SAMPLES {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        sorted.get((sorted.len() - 1) / 2).copied().map(Self)
    }

    /// The filtered strength.
    #[must_use]
    pub const fn rssi(self) -> Rssi {
        self.0
    }
}

/// The advisory proximity gate a requester applies before it connects
/// (section 4.4 item 1). It is a discovery heuristic, never a proof of
/// proximity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProximityGate {
    threshold: Rssi,
}

impl ProximityGate {
    /// The threshold the specification requires: -55 dBm.
    pub const SPECIFICATION: Self = Self {
        threshold: Rssi(PROXIMITY_GATE_SPECIFICATION_DBM),
    };

    /// A weaker threshold for an isolated development environment.
    ///
    /// # Errors
    /// [`LinkValueError::GateOutOfRange`] outside -85 to -55 dBm.
    pub const fn development(threshold_dbm: i16) -> Result<Self, LinkValueError> {
        if threshold_dbm < PROXIMITY_GATE_DEVELOPMENT_FLOOR_DBM
            || threshold_dbm > PROXIMITY_GATE_SPECIFICATION_DBM
        {
            return Err(LinkValueError::GateOutOfRange);
        }
        Ok(Self {
            threshold: Rssi(threshold_dbm),
        })
    }

    /// The threshold.
    #[must_use]
    pub const fn threshold(self) -> Rssi {
        self.threshold
    }

    /// Whether an advertiser with `reading` passes. One that passed before
    /// keeps passing until it falls 3 dB below the threshold.
    #[must_use]
    pub const fn admits(self, reading: ProximityReading, admitted_before: bool) -> bool {
        let threshold = if admitted_before {
            self.threshold.0 - PROXIMITY_HYSTERESIS_DB
        } else {
            self.threshold.0
        };
        reading.0.0 >= threshold
    }
}

/// An ATT MTU the profile accepts: one the two Bluetooth stacks negotiated
/// that is at least 512 bytes (section 5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttMtu(u16);

impl AttMtu {
    /// Refines the MTU the Windows Runtime reports once the exchange with the phone has
    /// completed (`GattSession.MaxPduSize`).
    ///
    /// # Errors
    /// [`LinkValueError::MtuBelowMinimum`] below 512 bytes, carrying the
    /// value so the user is told which link fell short.
    pub fn from_negotiated(max_pdu_size: u16) -> Result<Self, LinkValueError> {
        if usize::from(max_pdu_size) < BLE_MINIMUM_ATT_MTU {
            return Err(LinkValueError::MtuBelowMinimum {
                negotiated: max_pdu_size,
            });
        }
        Ok(Self(max_pdu_size))
    }

    /// The MTU in bytes.
    #[must_use]
    pub const fn bytes(self) -> u16 {
        self.0
    }
}

/// The payload bytes one SAR fragment carries on a link, built only from an
/// [`AttMtu`] (section 5.3: `min(MTU - 3, 512) - 6`).
///
/// Both ends derive it from the same negotiated MTU, so a fragment one end
/// sends fits the capacity the other end checks it against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SarCapacity(usize);

impl SarCapacity {
    /// The capacity `mtu` allows.
    ///
    /// # Errors
    /// [`LinkValueError::Capacity`] when the SAR layer refuses it, which an
    /// MTU of at least 512 does not cause.
    pub fn of(mtu: AttMtu) -> Result<Self, LinkValueError> {
        payload_capacity(usize::from(mtu.0), None)
            .map(Self)
            .map_err(LinkValueError::Capacity)
    }

    /// The capacity in payload bytes per fragment.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM_STATIC_ADDRESS: u64 = 0xC0_11_22_33_44_55;
    const STRONG_DBM: i16 = -40;
    const AT_GATE_DBM: i16 = -55;
    const BELOW_GATE_DBM: i16 = -56;
    const WITHIN_HYSTERESIS_DBM: i16 = -58;
    const BEYOND_HYSTERESIS_DBM: i16 = -59;
    const WINDOWS_TYPICAL_MTU: u16 = 527;
    const CLASSIC_DEFAULT_MTU: u16 = 23;
    const LARGEST_FRAGMENT_PAYLOAD: usize = 506;
    /// Bytes the ATT PDU header takes from the MTU (Bluetooth Core v5.4,
    /// Vol 3, Part F, §3.4.7.1: opcode and attribute handle).
    const ATT_HEADER_BYTES: usize = 3;

    fn rssi(dbm: i16) -> Rssi {
        Rssi::from_dbm(dbm).expect("in range")
    }

    #[test]
    fn an_address_is_forty_eight_bits_and_not_zero() {
        assert_eq!(
            AdvertiserAddress::from_bluetooth_address(0),
            Err(LinkValueError::AddressOutOfRange)
        );
        assert_eq!(
            AdvertiserAddress::from_bluetooth_address(DEVICE_ADDRESS_MAX + 1),
            Err(LinkValueError::AddressOutOfRange)
        );
        let address =
            AdvertiserAddress::from_bluetooth_address(RANDOM_STATIC_ADDRESS).expect("valid");
        assert_eq!(address.bluetooth_address(), RANDOM_STATIC_ADDRESS);
        assert_eq!(address.to_string(), "C0:11:22:33:44:55");
    }

    #[test]
    fn signal_strength_follows_the_advertising_report_range() {
        assert_eq!(
            Rssi::from_dbm(RSSI_NOT_AVAILABLE),
            Err(LinkValueError::RssiUnavailable)
        );
        assert_eq!(
            Rssi::from_dbm(RSSI_MINIMUM_DBM - 1),
            Err(LinkValueError::RssiOutOfRange)
        );
        assert_eq!(
            Rssi::from_dbm(RSSI_MAXIMUM_DBM + 1),
            Err(LinkValueError::RssiOutOfRange)
        );
        assert_eq!(rssi(RSSI_MINIMUM_DBM).dbm(), RSSI_MINIMUM_DBM);
        assert_eq!(rssi(RSSI_MAXIMUM_DBM).dbm(), RSSI_MAXIMUM_DBM);
    }

    #[test]
    fn a_reading_needs_three_samples_and_takes_the_weaker_middle() {
        assert_eq!(ProximityReading::median_of(&[rssi(STRONG_DBM); 2]), None);
        let reading = ProximityReading::median_of(&[
            rssi(STRONG_DBM),
            rssi(BELOW_GATE_DBM),
            rssi(AT_GATE_DBM),
        ])
        .expect("three samples");
        assert_eq!(reading.rssi(), rssi(AT_GATE_DBM));
        let even = ProximityReading::median_of(&[
            rssi(STRONG_DBM),
            rssi(AT_GATE_DBM),
            rssi(BELOW_GATE_DBM),
            rssi(STRONG_DBM),
        ])
        .expect("four samples");
        assert_eq!(even.rssi(), rssi(AT_GATE_DBM));
    }

    #[test]
    fn the_gate_admits_at_the_threshold_and_keeps_a_hysteresis() {
        let gate = ProximityGate::SPECIFICATION;
        let reading = |dbm| ProximityReading::median_of(&[rssi(dbm); 3]).expect("reading");
        assert!(gate.admits(reading(AT_GATE_DBM), false));
        assert!(!gate.admits(reading(BELOW_GATE_DBM), false));
        assert!(gate.admits(reading(WITHIN_HYSTERESIS_DBM), true));
        assert!(!gate.admits(reading(BEYOND_HYSTERESIS_DBM), true));
    }

    #[test]
    fn a_development_gate_stays_within_the_allowed_range() {
        assert_eq!(
            ProximityGate::development(PROXIMITY_GATE_DEVELOPMENT_FLOOR_DBM - 1),
            Err(LinkValueError::GateOutOfRange)
        );
        assert_eq!(
            ProximityGate::development(PROXIMITY_GATE_SPECIFICATION_DBM + 1),
            Err(LinkValueError::GateOutOfRange)
        );
        let gate = ProximityGate::development(PROXIMITY_GATE_DEVELOPMENT_FLOOR_DBM)
            .expect("the floor is allowed");
        assert_eq!(gate.threshold().dbm(), PROXIMITY_GATE_DEVELOPMENT_FLOOR_DBM);
    }

    #[test]
    fn an_mtu_below_the_profile_minimum_is_refused_with_its_value() {
        assert_eq!(
            AttMtu::from_negotiated(CLASSIC_DEFAULT_MTU),
            Err(LinkValueError::MtuBelowMinimum {
                negotiated: CLASSIC_DEFAULT_MTU
            })
        );
        let minimum = u16::try_from(BLE_MINIMUM_ATT_MTU).expect("fits");
        assert_eq!(
            AttMtu::from_negotiated(minimum - 1),
            Err(LinkValueError::MtuBelowMinimum {
                negotiated: minimum - 1
            })
        );
        assert_eq!(
            AttMtu::from_negotiated(minimum).expect("minimum").bytes(),
            minimum
        );
    }

    #[test]
    fn the_capacity_follows_section_5_3() {
        let typical = AttMtu::from_negotiated(WINDOWS_TYPICAL_MTU).expect("mtu");
        assert_eq!(
            SarCapacity::of(typical).expect("capacity").bytes(),
            LARGEST_FRAGMENT_PAYLOAD
        );
        let minimum = AttMtu::from_negotiated(u16::try_from(BLE_MINIMUM_ATT_MTU).expect("fits"))
            .expect("mtu");
        let expected =
            BLE_MINIMUM_ATT_MTU - ATT_HEADER_BYTES - refineid_rapp::ble_sar::BLE_SAR_HEADER_SIZE;
        assert_eq!(
            SarCapacity::of(minimum).expect("capacity").bytes(),
            expected
        );
    }
}
