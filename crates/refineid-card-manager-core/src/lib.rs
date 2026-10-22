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

//! Safe Rust service behind the native Windows card-management UI.
//!
//! The service owns PC/SC, card classification, trust gating, retry
//! floors, activation, PIN changes, and PUK recovery. The C ABI lives
//! in a separate crate so raw pointers cannot spread into this layer.

#![forbid(unsafe_code)]

extern crate alloc;

pub mod card_pin;
pub mod service;
mod trust_roots;

#[cfg(test)]
pub mod test_util {
    //! Small assertion helpers shared by imported card-management tests.

    use core::error::Error;

    /// Result shape used by card-management unit tests.
    pub type TestResult = Result<(), Box<dyn Error>>;

    /// Return an assertion failure as an error instead of panicking.
    ///
    /// # Errors
    ///
    /// Returns `label` as an owned error when `condition` is false.
    pub fn check_true(condition: bool, label: &str) -> TestResult {
        if condition {
            Ok(())
        } else {
            Err(label.to_owned().into())
        }
    }
}
