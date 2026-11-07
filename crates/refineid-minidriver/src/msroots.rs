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

//! The Windows `msroots` file: a PKCS#7 (CMS) certs-only bundle of
//! the card's root and issuing CA certificates.
//!
//! After reading the card's key-exchange and signature certificates
//! (`kscNN` / `kxcNN`), the Base CSP reads the special `msroots`
//! file to obtain the issuing CA chain as a PKCS#7 `SignedData` with
//! no signer -- exactly the convention `OpenSC`'s minidriver follows.
//! Windows uses it to build and validate the certificate chain.
//!
//! The bundle holds what the card itself carries, read when the context
//! is acquired. A card that discloses no CA certificate has no `msroots`
//! file: no certificate ships in this module (AGENTS.md, "Certificates
//! and trust").
#![expect(
    clippy::redundant_pub_crate,
    reason = "This private helper module still uses pub(crate) for consistency with the other minidriver support modules"
)]

use std::sync::OnceLock;

/// Dynamic cache holding CA certificates fetched from the card or proxy.
static ROOT_CERTIFICATES_CACHE: OnceLock<Box<RootCertificates>> = OnceLock::new();

#[derive(Clone, Debug)]
pub(crate) struct RootCertificates {
    pub(crate) pkcs7_bundle: Vec<u8>,
}

impl RootCertificates {
    pub(crate) const fn new(bundle: Vec<u8>) -> Self {
        Self {
            pkcs7_bundle: bundle,
        }
    }
}

/// Dynamically caches root/intermediate CA certificates.
pub(crate) fn set_root_certificates(bundle: Vec<u8>) {
    let _ = ROOT_CERTIFICATES_CACHE.set(Box::new(RootCertificates::new(bundle)));
}

/// The msroots PKCS#7 DER bundle the card disclosed, if it did.
pub(crate) fn active_msroots_pkcs7_der() -> Option<&'static [u8]> {
    ROOT_CERTIFICATES_CACHE
        .get()
        .map(|cached| cached.pkcs7_bundle.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic bundle.
    const BUNDLE: &[u8] = b"synthetic bundle";

    #[test]
    fn a_disclosed_bundle_is_served_and_nothing_stands_in_for_it() {
        assert_eq!(active_msroots_pkcs7_der(), None);
        set_root_certificates(BUNDLE.to_vec());
        assert_eq!(active_msroots_pkcs7_der(), Some(BUNDLE));
    }
}
