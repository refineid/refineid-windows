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

//! Registering the key storage provider with CNG.
//!
//! CNG keeps its provider configuration cached; a registration written
//! straight to the registry is not seen until the next boot. The documented
//! way is `BCryptRegisterProvider` plus `BCryptAddContextFunctionProvider`,
//! which write the same keys and tell CNG about them. This module wraps the
//! pair, and the reverse pair, behind two entry points: a Windows Installer
//! custom action the driver MSI runs with elevation, and a `rundll32` entry
//! the development installer runs the same way.
#![expect(
    clippy::redundant_pub_crate,
    reason = "the exported entry points keep the pub(crate) spelling of the sibling Card Module entry points"
)]

use refineid_windows_credential_store::KEY_STORAGE_PROVIDER;
use windows_sys::Win32::Foundation::{HMODULE, HWND, NTSTATUS, STATUS_NOT_FOUND, STATUS_SUCCESS};
use windows_sys::Win32::Security::Cryptography::{
    BCryptAddContextFunctionProvider, BCryptRegisterProvider, BCryptRemoveContextFunctionProvider,
    BCryptUnregisterProvider, CRYPT_IMAGE_REG, CRYPT_INTERFACE_REG, CRYPT_LOCAL, CRYPT_OVERWRITE,
    CRYPT_PRIORITY_BOTTOM, CRYPT_PROVIDER_REG, NCRYPT_KEY_STORAGE_INTERFACE,
};
use windows_sys::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    GetModuleFileNameW, GetModuleHandleExW,
};
use windows_sys::core::PWSTR;

use crate::cardmod::Log;

/// The function class a key storage provider registers under.
const KEY_STORAGE_FUNCTION: &str = "KEY_STORAGE";
/// `ERROR_SUCCESS`, the custom action return value for success.
const ERROR_SUCCESS: u32 = 0;
/// `ERROR_INSTALL_FAILURE`, which makes Windows Installer roll back.
const ERROR_INSTALL_FAILURE: u32 = 1603;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// The full path of this DLL, as CNG must load it.
fn module_path() -> Option<Vec<u16>> {
    let mut module: HMODULE = core::ptr::null_mut();
    // SAFETY: the address of a function in this module identifies it;
    // the refcount flag keeps the lookup from pinning the DLL.
    let found = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (module_path as *const ()).cast(),
            &raw mut module,
        )
    };
    if found == 0 || module.is_null() {
        return None;
    }
    let mut path = vec![0u16; 1024];
    // SAFETY: `path` holds the number of units passed.
    let length = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), 1024) };
    if length == 0 || length as usize >= path.len() {
        return None;
    }
    path.truncate(length as usize + 1);
    Some(path)
}

/// Registers this DLL as the key storage provider, the way Microsoft's
/// `register` samples do: the provider image with its one interface, then
/// the provider at the bottom of the machine's `KEY_STORAGE` list.
fn register() -> Result<(), NTSTATUS> {
    let image = module_path().ok_or(STATUS_NOT_FOUND)?;
    let name = wide(KEY_STORAGE_PROVIDER);
    let mut function = wide(KEY_STORAGE_FUNCTION);
    let mut functions: [PWSTR; 1] = [function.as_mut_ptr()];
    let mut interface = CRYPT_INTERFACE_REG {
        dwInterface: NCRYPT_KEY_STORAGE_INTERFACE,
        dwFlags: 0,
        cFunctions: 1,
        rgpszFunctions: functions.as_mut_ptr(),
    };
    let mut interfaces: [*mut CRYPT_INTERFACE_REG; 1] = [&raw mut interface];
    let mut image_ptr = image;
    let mut user_mode = CRYPT_IMAGE_REG {
        pszImage: image_ptr.as_mut_ptr(),
        cInterfaces: 1,
        rgpInterfaces: interfaces.as_mut_ptr(),
    };
    let registration = CRYPT_PROVIDER_REG {
        cAliases: 0,
        rgpszAliases: core::ptr::null_mut(),
        pUM: &raw mut user_mode,
        pKM: core::ptr::null_mut(),
    };
    // SAFETY: every structure and string the registration points at lives
    // until both calls return.
    let status =
        unsafe { BCryptRegisterProvider(name.as_ptr(), CRYPT_OVERWRITE, &raw const registration) };
    if status < STATUS_SUCCESS {
        return Err(status);
    }
    // SAFETY: NUL-terminated wide strings for the whole call; a null
    // context is the default context.
    let status = unsafe {
        BCryptAddContextFunctionProvider(
            CRYPT_LOCAL,
            core::ptr::null(),
            NCRYPT_KEY_STORAGE_INTERFACE,
            function.as_ptr(),
            name.as_ptr(),
            CRYPT_PRIORITY_BOTTOM,
        )
    };
    if status < STATUS_SUCCESS {
        return Err(status);
    }
    Ok(())
}

/// Removes the registration; an absent one counts as removed.
fn unregister() -> Result<(), NTSTATUS> {
    let name = wide(KEY_STORAGE_PROVIDER);
    let function = wide(KEY_STORAGE_FUNCTION);
    // SAFETY: NUL-terminated wide strings for the whole call.
    let status = unsafe {
        BCryptRemoveContextFunctionProvider(
            CRYPT_LOCAL,
            core::ptr::null(),
            NCRYPT_KEY_STORAGE_INTERFACE,
            function.as_ptr(),
            name.as_ptr(),
        )
    };
    if status < STATUS_SUCCESS && status != STATUS_NOT_FOUND {
        return Err(status);
    }
    // SAFETY: a NUL-terminated wide string for the whole call.
    let status = unsafe { BCryptUnregisterProvider(name.as_ptr()) };
    if status < STATUS_SUCCESS && status != STATUS_NOT_FOUND {
        return Err(status);
    }
    Ok(())
}

/// Windows Installer custom action: register the provider. Runs deferred,
/// without impersonation, after the DLL is in place.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn RefineIdRegisterKeyStorageProvider(_hInstall: u32) -> u32 {
    match register() {
        Ok(()) => {
            Log::dbg("KSP: registered with CNG");
            ERROR_SUCCESS
        }
        Err(status) => {
            Log::dbg(&format!("KSP: registration failed with status {status:#x}"));
            ERROR_INSTALL_FAILURE
        }
    }
}

/// Windows Installer custom action: remove the registration. A failure is
/// logged but never blocks an uninstall.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn RefineIdUnregisterKeyStorageProvider(_hInstall: u32) -> u32 {
    if let Err(status) = unregister() {
        Log::dbg(&format!(
            "KSP: unregistration failed with status {status:#x}"
        ));
    }
    ERROR_SUCCESS
}

/// `rundll32` entry for the development installer: register the provider.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn RefineIdRegisterProvider(
    _hwnd: HWND,
    _hinstance: HMODULE,
    _command_line: *mut u8,
    _show: i32,
) {
    let _ = unsafe { RefineIdRegisterKeyStorageProvider(0) };
}

/// `rundll32` entry for the development installer: remove the registration.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn RefineIdUnregisterProvider(
    _hwnd: HWND,
    _hinstance: HMODULE,
    _command_line: *mut u8,
    _show: i32,
) {
    let _ = unsafe { RefineIdUnregisterKeyStorageProvider(0) };
}
