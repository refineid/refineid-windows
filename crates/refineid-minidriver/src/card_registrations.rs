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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Removing the Calais registrations that bind a card to this Card Module.
//!
//! Windows binds an inserted card to the Card Module its registration under
//! `Calais\SmartCards` names in the `80000001` value (Microsoft, "Smart
//! Card Minidriver Specification", registry entries). A registration is
//! this module's exactly when that value names its file, whoever wrote it:
//! the MSI, a development install or an earlier build. Every other
//! vendor's registration is left as it is.
//!
//! The driver MSI calls the entry point with elevation on a first
//! installation, before it writes its own registrations, and on uninstall.
//! What is left after an installation is then exactly the package's own
//! registrations, and after an uninstall none.
#![expect(
    clippy::redundant_pub_crate,
    reason = "the exported entry points keep the pub(crate) spelling of the sibling Card Module entry points"
)]

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_SAM_FLAGS,
    RRF_RT_REG_SZ, RegCloseKey, RegDeleteTreeW, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
};

/// Where Windows keeps per-card Smart Card Crypto Provider registrations
/// (`refineid_msi::cards::CALAIS`).
const CALAIS: &str = r"SOFTWARE\Microsoft\Cryptography\Calais\SmartCards";
/// The value naming a registration's Card Module.
const CARD_MODULE_VALUE: &str = "80000001";
/// This Card Module's file name, as the registrations name it.
const MODULE_FILE: &str = "refineid_minidriver.dll";
/// The separator before a file name in a path.
const PATH_SEPARATOR: char = '\\';
/// The longest registry key name, in UTF-16 units, with its terminator
/// (Microsoft, "Registry Element Size Limits").
const KEY_NAME_UNITS: usize = 256;
/// The longest `80000001` value read, in UTF-16 units with its terminator;
/// a longer value names no file of this module's.
const MODULE_VALUE_UNITS: usize = 260;
/// Bytes in one UTF-16 unit.
const UNIT_BYTES: usize = size_of::<u16>();
/// Both registry views: a 32-bit tool writes the redirected one.
const VIEWS: [REG_SAM_FLAGS; 2] = [KEY_WOW64_64KEY, KEY_WOW64_32KEY];

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Whether a registration's `80000001` value names this module: its file
/// name, bare or at the end of a path, in any case.
fn names_this_module(value: &str) -> bool {
    value
        .rsplit(PATH_SEPARATOR)
        .next()
        .is_some_and(|file| file.trim().eq_ignore_ascii_case(MODULE_FILE))
}

/// An open registry key, closed on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `RegOpenKeyExW` and is closed
        // once.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Opens `Calais\SmartCards` in `view` for enumeration, reading and
/// deleting.
fn open_calais(view: REG_SAM_FLAGS) -> Result<Key, WIN32_ERROR> {
    let path = wide(CALAIS);
    let mut key: HKEY = core::ptr::null_mut();
    // SAFETY: a NUL-terminated path that lives for the call and a live
    // out-pointer.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            KEY_ALL_ACCESS | view,
            &raw mut key,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(status);
    }
    Ok(Key(key))
}

/// The names of the registrations under `calais`, `NUL`-terminated.
fn registration_names(calais: &Key) -> Result<Vec<Vec<u16>>, WIN32_ERROR> {
    let mut names = Vec::new();
    for index in 0.. {
        let mut name = vec![0u16; KEY_NAME_UNITS];
        let mut length = u32::try_from(name.len()).unwrap_or(u32::MAX);
        // SAFETY: `name` holds `length` units; the class and time are not
        // asked for.
        let status = unsafe {
            RegEnumKeyExW(
                calais.0,
                index,
                name.as_mut_ptr(),
                &raw mut length,
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != ERROR_SUCCESS {
            return Err(status);
        }
        name.truncate(length as usize);
        name.push(0);
        names.push(name);
    }
    Ok(names)
}

/// The `80000001` value of the registration `name`, if it has a string
/// one short enough to name a file.
fn module_value(calais: &Key, name: &[u16]) -> Option<String> {
    let value_name = wide(CARD_MODULE_VALUE);
    let mut data = vec![0u16; MODULE_VALUE_UNITS];
    let mut bytes = u32::try_from(data.len() * UNIT_BYTES).ok()?;
    // SAFETY: `name` and `value_name` are NUL-terminated; `data` holds
    // `bytes` bytes, and the type is not asked for.
    let status = unsafe {
        RegGetValueW(
            calais.0,
            name.as_ptr(),
            value_name.as_ptr(),
            RRF_RT_REG_SZ,
            core::ptr::null_mut(),
            data.as_mut_ptr().cast(),
            &raw mut bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let units = (bytes as usize / UNIT_BYTES).min(data.len());
    let text = &data[..units];
    let end = text
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(text.len());
    String::from_utf16(&text[..end]).ok()
}

/// Removes every registration naming this module in `view`. Returns the
/// first failure, after trying every registration.
fn remove_in_view(view: REG_SAM_FLAGS) -> Result<(), WIN32_ERROR> {
    let calais = open_calais(view)?;
    let mut outcome = Ok(());
    for name in registration_names(&calais)? {
        if !module_value(&calais, &name).is_some_and(|value| names_this_module(&value)) {
            continue;
        }
        // SAFETY: `name` is a NUL-terminated subkey of the open key.
        let status = unsafe { RegDeleteTreeW(calais.0, name.as_ptr()) };
        if status != ERROR_SUCCESS && outcome.is_ok() {
            outcome = Err(status);
        }
    }
    outcome
}

/// Windows Installer custom action: remove every Calais registration that
/// names this module, in both registry views. Runs deferred, without
/// impersonation. A failure never fails the installation or the
/// uninstall: a registration left behind binds a card to this module and
/// nothing else.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn RefineIdRemoveCardRegistrations(_hInstall: u32) -> u32 {
    for view in VIEWS {
        if let Err(status) = remove_in_view(view) {
            refineid_dev_errors::report!(
                CardModule,
                "card registrations not removed",
                status status
            );
        }
    }
    ERROR_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::names_this_module;

    #[test]
    fn the_bare_file_name_names_this_module_in_any_case() {
        assert!(names_this_module("refineid_minidriver.dll"));
        assert!(names_this_module("RefineID_Minidriver.DLL"));
    }

    #[test]
    fn a_path_ending_in_the_file_name_names_this_module() {
        assert!(names_this_module(
            r"C:\Windows\System32\refineid_minidriver.dll"
        ));
    }

    #[test]
    fn another_vendors_module_is_not_this_one() {
        assert!(!names_this_module("msclmd.dll"));
        assert!(!names_this_module("refineid_minidriver.dll.bak"));
        assert!(!names_this_module(r"C:\refineid_minidriver.dll\other.dll"));
        assert!(!names_this_module(""));
    }
}
