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

//! Legacy FINEID smartcard protocol core retained only while
//! `refineid-minidriver` completes its migration onto `refineid-core`.
//!
//! The [`transport`] module defines the card transport port legacy callers
//! still depend on. All other workspace crates now consume `refineid-core`
//! directly.

// `clippy::pub_use` fires on every `pub use submodule::Item;` at
// the crate root.  Those re-exports are the library-facade
// pattern: external consumers reach `refineid_lib_core::Item`
// without depending on which submodule defines it.  Per-item
// `#[expect(clippy::pub_use)]` is rejected by rustc as a useless
// lint attribute (the lint fires at crate scope, not on the
// use-item), so the suppression lives here as a crate-level
// inner attribute carrying the rationale for the whole cluster.
#![expect(
    clippy::pub_use,
    reason = "library-facade pattern: crate root re-exports the public API surface of submodules so external consumers don't depend on the internal module layout"
)]

#[cfg(test)]
extern crate alloc;

pub mod apdu;
pub mod auth;
pub(crate) use refineid_ber as ber;
pub mod crypto;
pub mod hex;
pub mod pin;
pub mod pin_cache;
pub mod pin_retry_risk;
pub mod pkcs15;
pub mod rng;
pub mod sign;
pub mod transport;

/// Crate version surfaced to upper layers.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
