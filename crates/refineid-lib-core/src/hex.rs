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

//! Hex encode helpers.
//!
//! Tiny in-tree implementation; no runtime crate dep. Used
//! where bytes need to be printed for operator-facing output
//! (serial numbers, fingerprints, raw error context).

/// Hex encode/decode namespace.
///
/// All entry points are associated functions on this unit
/// struct so callers read as `Hex::encode(bytes)`. The unit
/// struct exists only to host the methods inside an `impl`
/// block (no free
/// functions with borrowed parameters).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Hex;

impl Hex {
    /// Encode bytes as lowercase ASCII hex with no separator.
    ///
    /// Output capacity uses `saturating_mul` -- on a hypothetical
    /// `usize::MAX/2`-byte input the capacity hint saturates
    /// rather than overflowing; the actual `write!` calls grow
    /// the buffer as needed.
    #[inline]
    #[must_use]
    pub(crate) fn encode(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            // write! to String is infallible.
            if write!(out, "{byte:02x}").is_err() {
                break;
            }
        }
        out
    }
}
