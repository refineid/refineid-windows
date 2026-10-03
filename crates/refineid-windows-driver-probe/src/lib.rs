// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Probe for a usable local `RefineID` smart-card stack on Windows.
//!
//! The Store lane may run on machines that never received the FINEID
//! minidriver. This crate tells the caller which lane the installed
//! system supports: one registry check (Calais card registration) and
//! one PC/SC reader enumeration. It never opens a card, never sends an
//! APDU, and never touches PIN or CAN data.

#![cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "RegOpenKeyExW/RegEnumKeyExW/RegCloseKey are a small registry FFI boundary"
    )
)]

/// Result of asking the Windows machine whether its local-card lane is usable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalCardSupport {
    /// Our minidriver is registered in Calais and at least one reader is
    /// visible. Local-card operations are enabled.
    Ready {
        /// Number of PC/SC readers currently visible.
        reader_count: usize,
    },
    /// The registry registration is missing; the machine only has the
    /// PC/SC and OS stack. No local-card lane; RAPP lane unchanged.
    DriverNotInstalled,
    /// Our minidriver is registered, but zero readers are enumerated.
    /// Show a "plug in a reader" hint; RAPP lane unchanged.
    NoReader,
}

/// Ask Windows whether the local FINEID card lane is enabled.
///
/// Best-effort, non-mutating probe: it reads a registry key or
/// enumerates readers. It never opens a card, never sends an APDU, and
/// never touches PIN or CAN data.
#[must_use]
pub fn detect() -> LocalCardSupport {
    if !fine_id_minidriver_registered() {
        return LocalCardSupport::DriverNotInstalled;
    }
    pcsc::Context::establish(pcsc::Scope::User).map_or(LocalCardSupport::NoReader, |context| {
        probe_reader_count(&context)
            .filter(|&count| count > 0)
            .map_or(LocalCardSupport::NoReader, |reader_count| {
                LocalCardSupport::Ready { reader_count }
            })
    })
}

fn probe_reader_count(context: &pcsc::Context) -> Option<usize> {
    let mut buffer = [0_u8; 4096];
    match context.list_readers(&mut buffer) {
        Ok(readers) => Some(readers.count()),
        Err(pcsc::Error::NoReadersAvailable) => Some(0),
        Err(_) => None,
    }
}

#[cfg(windows)]
fn fine_id_minidriver_registered() -> bool {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW,
    };

    const PATH: &str = "SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards";
    // Upper bound so the iteration provably terminates; a real install
    // has far fewer Calais subkeys than this.
    const MAX_SUBKEYS: u32 = 1 << 20;
    let mut hkey: HKEY = std::ptr::null_mut();

    let path: Vec<u16> = PATH.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: HKEY_LOCAL_MACHINE + null-terminated path is valid input;
    // `hkey` is a fresh zeroed HKEY storage cell; all error paths are
    // handled by the Win32 return code.
    let open = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            KEY_READ,
            std::ptr::addr_of_mut!(hkey),
        )
    };
    if open != 0 {
        return false;
    }

    let found = (0..MAX_SUBKEYS).any(|index| {
        let mut name = [0u16; 260];
        let mut length = u32::try_from(name.len()).unwrap_or(u32::MAX);
        // SAFETY: `hkey` is open (checked above), `name` is a 260-element
        // zeroed buffer with sufficient capacity, and the FFI transfers
        // `length` as a valid sz.
        let rc = unsafe {
            RegEnumKeyExW(
                hkey,
                index,
                name.as_mut_ptr(),
                std::ptr::addr_of_mut!(length),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return false;
        }
        let name_lossy = String::from_utf16_lossy(&name[..length as usize]);
        name_lossy.starts_with("FINEID-")
    });

    // SAFETY: `hkey` was successfully opened above and is released here.
    unsafe {
        RegCloseKey(hkey);
    }
    found
}

#[cfg(not(windows))]
const fn fine_id_minidriver_registered() -> bool {
    // Non-Windows host: no Calais registry; the Store lane never runs
    // outside Windows, but keep this path silent and total so the crate
    // still builds for host-side `cargo check`.
    false
}
