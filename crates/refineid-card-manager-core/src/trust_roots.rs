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

//! Pinned DVV roots used before any card-management command.

use refineid_lib_core::crypto::digest::Sha256;

const PINNED_ROOTS: &[(&str, &[u8])] = &[
    (
        "DVV Gov. Root CA - G3 RSA",
        include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-rsa.der"),
    ),
    (
        "DVV Gov. Root CA - G3 ECC",
        include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-ecc.der"),
    ),
];

/// Return the official label for a root fingerprint, when it is one of
/// the pinned DVV roots. The in-memory certificate cache is never
/// consulted.
#[must_use]
pub fn pinned_root_label(fingerprint: Sha256) -> Option<&'static str> {
    if fingerprint == refineid_lib_core::trust_roots::PINNED_DVV_G3_RSA_SHA256 {
        return Some("DVV Gov. Root CA - G3 RSA");
    }
    if fingerprint == refineid_lib_core::trust_roots::PINNED_DVV_G3_ECC_SHA256 {
        return Some("DVV Gov. Root CA - G3 ECC");
    }
    PINNED_ROOTS
        .iter()
        .find(|(_, der)| Sha256::of(*der) == fingerprint)
        .map(|(label, _)| *label)
}

#[cfg(test)]
mod tests {
    use super::{PINNED_ROOTS, pinned_root_label};
    use refineid_lib_core::crypto::digest::Sha256;

    #[test]
    fn every_embedded_root_round_trips_through_its_fingerprint() {
        for (label, der) in PINNED_ROOTS {
            assert_eq!(pinned_root_label(Sha256::of(*der)), Some(*label));
        }
    }
}
