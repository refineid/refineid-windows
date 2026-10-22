//! The GATT central link of `"fi.refineid.rapp.ble"` over the Windows Runtime
//! (RAPP v26.10.22 sections 4.2, 5.1 to 5.3).
//!
//! [`BleLink::open`] runs the connection the custodian's peripheral expects,
//! in order: connect without bonding, discover the RAPP service uncached,
//! wait for the ATT MTU exchange, subscribe to indications on the Channel
//! Characteristic (the custodian fixes its fragment capacity at that
//! moment), and write the routing preamble. For pairing,
//! [`BleLink::read_bootstrap`] then reads the offer. Every protocol frame
//! after that moves through the link's [`FrameTransport`] implementation.

use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use refineid_rapp::ble_sar::{BleSarError, BleSarReassembler, segment};
use refineid_rapp::{BLE_CANDIDATE_ID, BLE_PROFILE, BinaryFrame, PairingOffer, PairingOfferError};
use refineid_rapp_core::limits;
use refineid_rapp_core::offer::TransportProfile;
use refineid_rapp_core::stream::{DialPurpose, StreamError};
use refineid_rapp_core::transport::{FrameTransport, TransportError};
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristic, GattClientCharacteristicConfigurationDescriptorValue,
    GattCommunicationStatus, GattDeviceService, GattSession, GattValueChangedEventArgs,
    GattWriteOption,
};
use windows::Devices::Bluetooth::{BluetoothCacheMode, BluetoothLEDevice};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::{DataReader, DataWriter, IBuffer};
use windows::core::{GUID, IInspectable, Ref};

use crate::link::{AdvertiserAddress, AttMtu, LinkValueError, SarCapacity};

/// The RAPP primary service (section 5.1; hierarchy specification §3.2).
pub const SERVICE_UUID: GUID = GUID::from_u128(0x7E39_FD01_A6B5_4D78_9E11_37E2_8E95_45F1);
/// The Channel Characteristic: requester writes, custodian indicates
/// (section 5.1).
pub const CHANNEL_UUID: GUID = GUID::from_u128(0x7E39_FD02_A6B5_4D78_9E11_37E2_8E95_45F1);
/// The Bootstrap Characteristic: the pairing offer, read-only (section 4.2).
pub const BOOTSTRAP_UUID: GUID = GUID::from_u128(0x7E39_FD03_A6B5_4D78_9E11_37E2_8E95_45F1);

/// How long the link waits for the ATT MTU exchange to complete after the
/// service discovery that starts it.
pub const MTU_EXCHANGE_WAIT: Duration = Duration::from_secs(5);
/// How often a blocked receive checks the 5.0-second reassembly timer of
/// section 5.3 while a frame is in progress.
const REASSEMBLY_CHECK_INTERVAL: Duration = Duration::from_millis(250);

/// The ATT MTU before any exchange (Bluetooth Core v5.4, Vol 3, Part F,
/// §3.2.8: `ATT_MTU` default for LE). `GattSession.MaxPduSize` reports it
/// until the exchange with the phone completes.
const DEFAULT_LE_ATT_MTU: u16 = 23;
/// The hard cap on any attribute value (Bluetooth Core v5.4, Vol 3, Part F,
/// §3.2.9); no indication fragment is longer.
const ATTRIBUTE_VALUE_LIMIT: usize = 512;

/// A characteristic of the RAPP service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RappCharacteristic {
    /// The Channel Characteristic.
    Channel,
    /// The Bootstrap Characteristic.
    Bootstrap,
}

/// Why the link could not be opened or used, each cause told apart so the
/// user is shown the one that applies (core STPA R-51, R-52).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BleLinkError {
    /// Windows could not reach the advertiser at all.
    Unreachable,
    /// The advertiser does not serve the RAPP service.
    ServiceMissing,
    /// The RAPP service lacks one of its characteristics.
    CharacteristicMissing(RappCharacteristic),
    /// The ATT MTU exchange did not complete within [`MTU_EXCHANGE_WAIT`].
    MtuNotExchanged {
        /// The MTU Windows reported when the wait ended.
        reported: u16,
    },
    /// The link's MTU or capacity was refused at its border.
    Link(LinkValueError),
    /// The custodian refused the indication subscription.
    SubscriptionRefused,
    /// The routing preamble could not be built.
    Preamble(StreamError),
    /// A GATT write was not acknowledged.
    WriteRefused,
    /// The Bootstrap Characteristic could not be read: no pairing offer is
    /// open on the phone.
    BootstrapUnreadable,
    /// The offer read from the Bootstrap Characteristic was refused.
    Offer(PairingOfferError),
    /// A Windows Runtime call failed with this `HRESULT`.
    Platform(i32),
}

impl core::fmt::Display for BleLinkError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unreachable => write!(formatter, "the phone could not be reached over Bluetooth"),
            Self::ServiceMissing => write!(formatter, "the device does not serve RAPP"),
            Self::CharacteristicMissing(which) => {
                write!(
                    formatter,
                    "the RAPP service lacks its {which:?} characteristic"
                )
            }
            Self::MtuNotExchanged { reported } => write!(
                formatter,
                "the Bluetooth link did not complete its MTU exchange (still {reported} bytes)"
            ),
            Self::Link(error) => write!(formatter, "{error}"),
            Self::SubscriptionRefused => write!(formatter, "the phone refused the subscription"),
            Self::Preamble(error) => write!(formatter, "routing preamble: {error:?}"),
            Self::WriteRefused => write!(formatter, "the phone did not acknowledge a write"),
            Self::BootstrapUnreadable => {
                write!(formatter, "no pairing offer is open on the phone")
            }
            Self::Offer(error) => write!(
                formatter,
                "the phone's pairing offer was refused: {error:?}"
            ),
            Self::Platform(code) => write!(formatter, "Windows Bluetooth error {code:#010X}"),
        }
    }
}

impl core::error::Error for BleLinkError {}

impl From<windows::core::Error> for BleLinkError {
    fn from(error: windows::core::Error) -> Self {
        Self::Platform(error.code().0)
    }
}

/// What the indication handler hands to the receiving side: a reassembled
/// frame, or the refusal that ends the link.
type Arrival = Result<Vec<u8>, BleSarError>;

/// The receive half the indication handler drives.
struct Reassembly {
    reassembler: BleSarReassembler,
    capacity: SarCapacity,
    epoch: Instant,
    refused: bool,
}

impl Reassembly {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// One connection to one custodian over GATT.
pub struct BleLink {
    connection: Connection,
    channel: GattCharacteristic,
    bootstrap: GattCharacteristic,
    capacity: SarCapacity,
    mtu: AttMtu,
    reassembly: Arc<Mutex<Reassembly>>,
    arrivals: Receiver<Arrival>,
    value_changed: i64,
    receive_deadline: Duration,
}

impl core::fmt::Debug for BleLink {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BleLink")
            .field("mtu", &self.mtu)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

/// A device and its GATT session held open; dropping it releases the
/// connection, so every refusal while a link is being opened lets it go.
struct Connection {
    device: BluetoothLEDevice,
    session: GattSession,
}

impl Drop for Connection {
    fn drop(&mut self) {
        // The connection is going away; a failure to release it changes
        // nothing the caller could act on.
        let _ = self.session.SetMaintainConnection(false);
        let _ = self.session.Close();
        let _ = self.device.Close();
    }
}

impl BleLink {
    /// Connects to `address` and sends the routing preamble for `purpose`.
    ///
    /// # Errors
    /// [`BleLinkError`] naming the step that failed.
    pub fn open(
        address: AdvertiserAddress,
        purpose: DialPurpose<'_>,
        receive_deadline: Duration,
    ) -> Result<Self, BleLinkError> {
        let device = BluetoothLEDevice::FromBluetoothAddressAsync(address.bluetooth_address())?
            .join()
            .map_err(|_| BleLinkError::Unreachable)?;
        let session = GattSession::FromDeviceIdAsync(&device.BluetoothDeviceId()?)?.join()?;
        let connection = Connection { device, session };
        connection.session.SetMaintainConnection(true)?;
        let (mtu_sender, mtu_changes) = channel();
        let mtu_token =
            connection.session.MaxPduSizeChanged(
                &TypedEventHandler::<GattSession, IInspectable>::new(move |sender, _| {
                    if let Some(session) = sender.as_ref() {
                        let _ = mtu_sender.send(session.MaxPduSize()?);
                    }
                    Ok(())
                }),
            )?;

        let opened = Self::discover(&connection.device).and_then(
            |(service, channel_characteristic, bootstrap)| {
                let mtu = wait_for_mtu(&connection.session, &mtu_changes)?;
                drop(service);
                Ok((channel_characteristic, bootstrap, mtu))
            },
        );
        connection.session.RemoveMaxPduSizeChanged(mtu_token)?;
        let (channel_characteristic, bootstrap, mtu) = opened?;
        let capacity = SarCapacity::of(mtu).map_err(BleLinkError::Link)?;

        let (arrival_sender, arrivals) = channel();
        let reassembly = Arc::new(Mutex::new(Reassembly {
            reassembler: BleSarReassembler::new(),
            capacity,
            epoch: Instant::now(),
            refused: false,
        }));
        let value_changed = channel_characteristic
            .ValueChanged(&indication_handler(Arc::clone(&reassembly), arrival_sender))?;
        let subscribed = channel_characteristic
            .WriteClientCharacteristicConfigurationDescriptorWithResultAsync(
                GattClientCharacteristicConfigurationDescriptorValue::Indicate,
            )
            .and_then(|operation| operation.join())
            .and_then(|result| result.Status());
        if !matches!(subscribed, Ok(GattCommunicationStatus::Success)) {
            // The subscription is refused; the handler goes with it, and a
            // failure to unhook changes nothing the caller could act on.
            let _ = channel_characteristic.RemoveValueChanged(value_changed);
            return Err(match subscribed {
                Err(error) => error.into(),
                Ok(_) => BleLinkError::SubscriptionRefused,
            });
        }

        // From here the link owns the connection and the handler, and its
        // drop releases both.
        let mut link = Self {
            connection,
            channel: channel_characteristic,
            bootstrap,
            capacity,
            mtu,
            reassembly,
            arrivals,
            value_changed,
            receive_deadline,
        };
        let preamble = purpose
            .preamble(TransportProfile::Ble)
            .map_err(BleLinkError::Preamble)?;
        link.send_frame(preamble.as_bytes())
            .map_err(|_| BleLinkError::WriteRefused)?;
        Ok(link)
    }

    /// The negotiated MTU of this link.
    #[must_use]
    pub const fn mtu(&self) -> AttMtu {
        self.mtu
    }

    /// The fragment capacity of this link.
    #[must_use]
    pub const fn capacity(&self) -> SarCapacity {
        self.capacity
    }

    /// Reads the custodian's pairing offer from the Bootstrap Characteristic
    /// and decodes it for this transport (section 4.2 steps 1 and 3).
    ///
    /// # Errors
    /// [`BleLinkError::BootstrapUnreadable`] when the read fails, and
    /// [`BleLinkError::Offer`] when the offer is refused at its border.
    pub fn read_bootstrap(&self) -> Result<PairingOffer, BleLinkError> {
        let read = self
            .bootstrap
            .ReadValueWithCacheModeAsync(BluetoothCacheMode::Uncached)?
            .join()?;
        if read.Status()? != GattCommunicationStatus::Success {
            return Err(BleLinkError::BootstrapUnreadable);
        }
        match attribute_value(&read.Value()?, refineid_rapp::MAX_OFFER_SIZE)? {
            AttributeValue::Within(bytes) => {
                PairingOffer::from_bootstrap(&bytes, TransportProfile::Ble)
                    .map_err(BleLinkError::Offer)
            }
            AttributeValue::Oversized(got) => {
                Err(BleLinkError::Offer(PairingOfferError::Oversized { got }))
            }
        }
    }

    fn discover(
        device: &BluetoothLEDevice,
    ) -> Result<(GattDeviceService, GattCharacteristic, GattCharacteristic), BleLinkError> {
        let services = device
            .GetGattServicesForUuidWithCacheModeAsync(SERVICE_UUID, BluetoothCacheMode::Uncached)?
            .join()?;
        if services.Status()? != GattCommunicationStatus::Success {
            return Err(BleLinkError::Unreachable);
        }
        let services = services.Services()?;
        if services.Size()? == 0 {
            return Err(BleLinkError::ServiceMissing);
        }
        let service = services.GetAt(0)?;
        let channel_characteristic =
            characteristic(&service, CHANNEL_UUID, RappCharacteristic::Channel)?;
        let bootstrap = characteristic(&service, BOOTSTRAP_UUID, RappCharacteristic::Bootstrap)?;
        Ok((service, channel_characteristic, bootstrap))
    }

    fn write_fragment(&self, fragment: &[u8]) -> Result<(), TransportError> {
        let writer = DataWriter::new().map_err(|_| TransportError::Failed)?;
        writer
            .WriteBytes(fragment)
            .map_err(|_| TransportError::Failed)?;
        let buffer = writer.DetachBuffer().map_err(|_| TransportError::Failed)?;
        let written = self
            .channel
            .WriteValueWithResultAndOptionAsync(&buffer, GattWriteOption::WriteWithResponse)
            .and_then(|operation| operation.join())
            .map_err(|_| TransportError::Failed)?;
        match written.Status() {
            Ok(GattCommunicationStatus::Success) => Ok(()),
            _ => Err(TransportError::Failed),
        }
    }

    fn reassembly_timed_out(&self) -> bool {
        let mut reassembly = self
            .reassembly
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = reassembly.now_ms();
        if reassembly.reassembler.check_timer(now).is_err() {
            reassembly.refused = true;
        }
        reassembly.refused
    }
}

impl FrameTransport for BleLink {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > limits::NOISE_MAX_MESSAGE {
            return Err(TransportError::OversizedFrame);
        }
        let fragments =
            segment(frame, self.capacity.bytes()).map_err(|_| TransportError::OversizedFrame)?;
        for fragment in &fragments {
            self.write_fragment(fragment)?;
        }
        Ok(())
    }

    fn receive_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        let deadline = Instant::now() + self.receive_deadline;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::TimedOut);
            }
            match self
                .arrivals
                .recv_timeout(remaining.min(REASSEMBLY_CHECK_INTERVAL))
            {
                Ok(Ok(frame)) if frame.len() > limits::NOISE_MAX_MESSAGE => {
                    return Err(TransportError::OversizedFrame);
                }
                Ok(Ok(frame)) => return Ok(frame),
                Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
                    return Err(TransportError::Failed);
                }
                Err(RecvTimeoutError::Timeout) => {
                    if self.reassembly_timed_out() {
                        return Err(TransportError::Failed);
                    }
                }
            }
        }
    }

    fn profile(&self) -> &str {
        BLE_PROFILE
    }

    fn candidate_id(&self) -> &str {
        BLE_CANDIDATE_ID
    }
}

impl refineid_rapp::FrameTransport for BleLink {
    type Error = TransportError;

    fn candidate_id(&self) -> &str {
        BLE_CANDIDATE_ID
    }

    fn send(&mut self, frame: BinaryFrame) -> Result<(), Self::Error> {
        self.send_frame(frame.as_bytes())
    }

    fn receive(&mut self) -> Result<Option<BinaryFrame>, Self::Error> {
        let bytes = self.receive_frame()?;
        // `receive_frame` already refused anything over the frame limit, so
        // a frame the border refuses here is a broken channel.
        BinaryFrame::reconstruct(bytes)
            .map(Some)
            .map_err(|_| TransportError::Failed)
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        self.connection
            .session
            .SetMaintainConnection(false)
            .map_err(|_| TransportError::Failed)
    }
}

impl Drop for BleLink {
    fn drop(&mut self) {
        // The link is going away; a failure to unhook changes nothing the
        // caller could act on. The connection releases itself after this.
        let _ = self.channel.RemoveValueChanged(self.value_changed);
    }
}

/// Feeds every indication fragment through the reassembler and hands
/// complete frames, or the refusal that ends the link, to the receiver.
fn indication_handler(
    reassembly: Arc<Mutex<Reassembly>>,
    arrivals: Sender<Arrival>,
) -> TypedEventHandler<GattCharacteristic, GattValueChangedEventArgs> {
    TypedEventHandler::new(
        move |_: Ref<'_, GattCharacteristic>, args: Ref<'_, GattValueChangedEventArgs>| {
            let Some(args) = args.as_ref() else {
                return Ok(());
            };
            let value = args.CharacteristicValue()?;
            let delivered = attribute_value(&value, ATTRIBUTE_VALUE_LIMIT)?;
            let outcome = {
                let mut state = reassembly.lock().unwrap_or_else(PoisonError::into_inner);
                if state.refused {
                    return Ok(());
                }
                let outcome = match delivered {
                    AttributeValue::Within(fragment) => {
                        let now = state.now_ms();
                        let capacity = state.capacity.bytes();
                        state.reassembler.receive(&fragment, capacity, now)
                    }
                    AttributeValue::Oversized(_) => Err(BleSarError::FragmentOverCapacity),
                };
                state.refused = outcome.is_err();
                outcome
            };
            // The receiver may have gone with the link; nothing is owed then.
            match outcome {
                Ok(Some(frame)) => {
                    let _ = arrivals.send(Ok(frame));
                }
                Ok(None) => {}
                Err(error) => {
                    let _ = arrivals.send(Err(error));
                }
            }
            Ok(())
        },
    )
}

/// Waits for the MTU exchange and refines its result.
fn wait_for_mtu(session: &GattSession, changes: &Receiver<u16>) -> Result<AttMtu, BleLinkError> {
    let mut reported = session.MaxPduSize()?;
    if reported == DEFAULT_LE_ATT_MTU {
        let deadline = Instant::now() + MTU_EXCHANGE_WAIT;
        while reported == DEFAULT_LE_ATT_MTU {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match changes.recv_timeout(remaining) {
                Ok(value) => reported = value,
                Err(_) => return Err(BleLinkError::MtuNotExchanged { reported }),
            }
        }
    }
    AttMtu::from_negotiated(reported).map_err(BleLinkError::Link)
}

fn characteristic(
    service: &GattDeviceService,
    uuid: GUID,
    which: RappCharacteristic,
) -> Result<GattCharacteristic, BleLinkError> {
    let found = service
        .GetCharacteristicsForUuidWithCacheModeAsync(uuid, BluetoothCacheMode::Uncached)?
        .join()?;
    if found.Status()? != GattCommunicationStatus::Success {
        return Err(BleLinkError::Unreachable);
    }
    let characteristics = found.Characteristics()?;
    if characteristics.Size()? == 0 {
        return Err(BleLinkError::CharacteristicMissing(which));
    }
    Ok(characteristics.GetAt(0)?)
}

/// An attribute value as a Windows Runtime buffer delivered it.
enum AttributeValue {
    /// The value, within the caller's limit. The bytes are transit: they go
    /// to one border, the SAR reassembler or the offer decoder.
    Within(Vec<u8>),
    /// A value longer than the caller's limit, refused before anything was
    /// allocated for it.
    Oversized(usize),
}

/// Copies an attribute value of at most `limit` bytes out of a Windows Runtime buffer.
fn attribute_value(buffer: &IBuffer, limit: usize) -> windows::core::Result<AttributeValue> {
    let length = usize::try_from(buffer.Length()?).unwrap_or(usize::MAX);
    if length > limit {
        return Ok(AttributeValue::Oversized(length));
    }
    let reader = DataReader::FromBuffer(buffer)?;
    let mut bytes = vec![0; length];
    reader.ReadBytes(&mut bytes)?;
    Ok(AttributeValue::Within(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_uuid_is_the_core_constant() {
        let core = GUID::try_from(refineid_rapp::BLE_SERVICE_UUID).expect("a GUID");
        assert_eq!(core, SERVICE_UUID);
    }

    #[test]
    fn the_characteristics_share_the_service_base() {
        const SHORT_ID_SHIFT: u32 = 96;
        const SHORT_ID_MASK: u128 = !(0xFFFF_u128 << SHORT_ID_SHIFT);
        let base = SERVICE_UUID.to_u128() & SHORT_ID_MASK;
        assert_eq!(CHANNEL_UUID.to_u128() & SHORT_ID_MASK, base);
        assert_eq!(BOOTSTRAP_UUID.to_u128() & SHORT_ID_MASK, base);
    }
}
