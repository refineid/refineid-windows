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

//! Generate the PKCS#11 token firmware version from the build stamp.

use std::env;
use std::fs;
use std::path::PathBuf;

use refineid_stamp::Stamp;

fn main() {
    let stamp = Stamp::from_build_environment();
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let source = format!(
        "const TOKEN_FIRMWARE_VERSION: CkVersion = CkVersion {{ major: {}, minor: {} }};\n",
        stamp.day, stamp.bucket
    );
    fs::write(out.join("token-version.rs"), source).expect("write token version");
}
