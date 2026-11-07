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

//! The installer's removal of the root certificates Windows propagated
//! from a card's `msroots` file, which this module no longer serves
//! (`refineid_windows_credential_store::card_roots`).
#![expect(
    clippy::redundant_pub_crate,
    reason = "the exported entry point keeps the pub(crate) spelling of the sibling Card Module entry points"
)]

/// `ERROR_SUCCESS`, the custom action return value for success.
const ERROR_SUCCESS: u32 = 0;

/// Windows Installer custom action: remove the Card Module's propagated
/// roots from every loaded user profile. Runs deferred, without
/// impersonation, as `LocalSystem`, which alone may change what
/// propagation wrote. A failure never blocks the installation, which
/// would leave the earlier build serving `msroots`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn RefineIdRemoveCardRoots(_hInstall: u32) -> u32 {
    if let Err(error) = refineid_windows_credential_store::card_roots::remove_card_module_roots() {
        refineid_dev_errors::report!(CardModule, "propagated card roots not removed", error);
    }
    ERROR_SUCCESS
}
