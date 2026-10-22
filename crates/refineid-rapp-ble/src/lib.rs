//! The RAPP Bluetooth Low Energy transport profile
//! `"fi.refineid.rapp.ble"` for the Windows requester (RAPP v26.10.22
//! sections 2.2, 4.1 and 5).
//!
//! The requester is the GATT central. It scans for the RAPP Service UUID,
//! connects to an advertiser, waits for the ATT MTU exchange, subscribes to
//! indications on the Channel Characteristic, writes the routing preamble,
//! and, for pairing, reads the offer from the Bootstrap Characteristic.
//! Frames then move as segmentation-and-reassembly fragments (section 5.3):
//! writes with response from the central, indications from the custodian.
//!
//! Every value the radio hands over crosses one border constructor in
//! [`link`] before anything relies on it: the advertiser address, the
//! signal strength, the negotiated MTU and the fragment capacity it allows.
//! Signal strength orders the advertisers a search tries; it admits or
//! refuses none (section 4.4).
//! The Windows Runtime link itself is in [`gatt`], the scan in [`scan`],
//! and the search for a stored pairing's phone in [`reach`].
//!
//! RAPP authenticates on the application layer alone (section 5.1): the
//! requester never asks Windows to pair or bond with the phone and never
//! asks for an encrypted link.

pub mod link;

#[cfg(windows)]
pub mod gatt;
#[cfg(windows)]
pub mod reach;
#[cfg(windows)]
pub mod scan;
