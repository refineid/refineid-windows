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

//! Installing the Plug and Play driver package that names FINEID cards in
//! Device Manager.
//!
//! The driver MSI installs the package's INF and catalog beside the agent
//! and calls these entry points with elevation. `DiInstallDriverW` adds the
//! package to the driver store and installs it on the cards present where
//! it is a better match than their current driver; `DiUninstallDriverW`
//! removes it. The package changes only the name Device Manager shows: the
//! Card Module is bound through `Calais\SmartCards`, which the MSI writes
//! itself. So a package Windows refuses, such as one whose catalog
//! signature it does not accept, never fails the installation.
//!
//! `newdev.dll` is loaded only for the call, so the Card Module, which the
//! Base CSP loads into every process that uses a card, does not import it.
#![expect(
    clippy::redundant_pub_crate,
    reason = "the exported entry points keep the pub(crate) spelling of the sibling Card Module entry points"
)]

use refineid_agent_pipe::identity::installed_agent_image;
use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HMODULE, HWND};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::core::{BOOL, PCWSTR};

/// The INF's file name beside the agent (`refineid_msi::inf::INF_FILE`).
const INF_FILE: &str = "refineid_card.inf";
/// The system library that exports the driver package functions.
const NEWDEV: &str = "newdev.dll";
/// `DiInstallDriverW`, as `GetProcAddress` takes it.
const INSTALL_DRIVER: &core::ffi::CStr = c"DiInstallDriverW";
/// `DiUninstallDriverW`, as `GetProcAddress` takes it.
const UNINSTALL_DRIVER: &core::ffi::CStr = c"DiUninstallDriverW";
/// No flags: install only where the package is the better match, and
/// remove the package with its INF.
const NO_FLAGS: u32 = 0;
/// `ERROR_SUCCESS`, the custom action return value for success.
const ERROR_SUCCESS: u32 = 0;

/// `DiInstallDriverW` and `DiUninstallDriverW` share this signature.
type DriverPackageFunction = unsafe extern "system" fn(HWND, PCWSTR, u32, *mut BOOL) -> BOOL;

/// Why a driver package call did not succeed.
#[derive(Debug, Clone, Copy)]
enum DriverPackageError {
    /// Windows cannot report the Program Files directory.
    NoInstallDirectory,
    /// `newdev.dll` did not load.
    LibraryNotLoaded,
    /// `newdev.dll` does not export the function.
    FunctionMissing,
    /// The call failed with this Windows error.
    Failed(u32),
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// The INF's full path, as a NUL-terminated wide string.
fn inf_path() -> Option<Vec<u16>> {
    let agent = installed_agent_image()?;
    let inf = agent.parent()?.join(INF_FILE);
    let text = inf.to_str()?;
    Some(wide(text))
}

/// Calls the `newdev.dll` function `name` on the installed INF.
fn call(name: &core::ffi::CStr) -> Result<(), DriverPackageError> {
    let inf = inf_path().ok_or(DriverPackageError::NoInstallDirectory)?;
    let library = wide(NEWDEV);
    // SAFETY: a NUL-terminated wide name; the flag restricts the search to
    // the system directory.
    let module: HMODULE = unsafe {
        LoadLibraryExW(
            library.as_ptr(),
            core::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return Err(DriverPackageError::LibraryNotLoaded);
    }
    // SAFETY: `module` is the loaded library and `name` a NUL-terminated
    // export name.
    let address = unsafe { GetProcAddress(module, name.as_ptr().cast()) };
    let result = address.map_or(Err(DriverPackageError::FunctionMissing), |address| {
        // SAFETY: both exports have the documented signature
        // `BOOL (HWND, PCWSTR, DWORD, PBOOL)` (newdev.h).
        let function: DriverPackageFunction = unsafe { core::mem::transmute(address) };
        let mut need_reboot: BOOL = 0;
        // SAFETY: a null window, a NUL-terminated path that lives for the
        // call, and a live reboot flag, which keeps the call from showing
        // a restart prompt.
        let succeeded = unsafe {
            function(
                core::ptr::null_mut(),
                inf.as_ptr(),
                NO_FLAGS,
                &raw mut need_reboot,
            )
        };
        if succeeded == 0 {
            // SAFETY: reads this thread's last error, set by the call.
            Err(DriverPackageError::Failed(unsafe { GetLastError() }))
        } else {
            Ok(())
        }
    });
    // SAFETY: releases the reference this function took.
    unsafe { FreeLibrary(module) };
    result
}

/// Windows Installer custom action: add the driver package to the driver
/// store and install it on the cards present. Runs deferred, without
/// impersonation, after the files are in place. A refusal leaves the
/// installation successful.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn RefineIdInstallCardDriver(_hInstall: u32) -> u32 {
    match call(INSTALL_DRIVER) {
        Ok(()) => {}
        Err(DriverPackageError::Failed(code)) => {
            refineid_dev_errors::report!(CardModule, "card driver package not installed", status code);
        }
        Err(error) => {
            refineid_dev_errors::report!(CardModule, "card driver package not installed", error);
        }
    }
    ERROR_SUCCESS
}

/// Windows Installer custom action: remove the driver package. Runs on
/// uninstall and as the rollback of the installation; a failure never
/// blocks either.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn RefineIdUninstallCardDriver(_hInstall: u32) -> u32 {
    match call(UNINSTALL_DRIVER) {
        Ok(()) => {}
        Err(DriverPackageError::Failed(code)) => {
            refineid_dev_errors::report!(CardModule, "card driver package not removed", status code);
        }
        Err(error) => {
            refineid_dev_errors::report!(CardModule, "card driver package not removed", error);
        }
    }
    ERROR_SUCCESS
}
