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

//! Expose the build stamp to the GUI as `REFINEID_FULL_VERSION`; parsing
//! lives in `src/version.rs`.

use refineid_stamp::Stamp;

fn main() {
    let stamp = Stamp::from_build_environment();
    println!("cargo:rustc-env=REFINEID_FULL_VERSION={stamp}");
}
