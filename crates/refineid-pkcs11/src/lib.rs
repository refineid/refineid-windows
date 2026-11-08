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

//! PKCS#11 v2.40 module for FINEID: the local readers through
//! `refineid-core`, and on Windows the phone paired with this computer as one
//! more slot, served by `phone::PhoneSource`.

#[cfg(windows)]
mod phone;
#[cfg(any(windows, test))]
mod wake;

use refineid_pkcs11::ck::{CkFunctionListPtrPtr, CkRv};

/// The one symbol a PKCS#11 host resolves by name (OASIS PKCS#11 v2.40
/// s5.6.4). The phone source is installed on the first call, before the
/// function list is handed out, so every later call can find it.
///
/// # Safety
/// `list` must be a valid, writable location for one
/// `CK_FUNCTION_LIST_PTR`, per the PKCS#11 caller contract.
#[allow(
    unsafe_code,
    reason = "the exported symbol and the forward to the core entry point are the module's one FFI boundary"
)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn C_GetFunctionList(list: CkFunctionListPtrPtr) -> CkRv {
    // A second call finds the source installed already; that is the same
    // source, so the refusal carries nothing.
    #[cfg(windows)]
    {
        let _ = refineid_pkcs11::remote::install_remote_source(Box::new(phone::PhoneSource::new()));
    }
    // SAFETY: `list` validity is the caller's PKCS#11 contract; the core
    // entry point null-checks it before writing.
    unsafe { refineid_pkcs11::get_function_list(list) }
}
