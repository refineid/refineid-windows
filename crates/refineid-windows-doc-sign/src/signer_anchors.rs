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

//! The anchors a signing request's long-term material may end at:
//! `DocumentRequest::signer_anchors`.
//!
//! refineid-core ships no root and refuses an LT or LTA request that
//! names no anchor before the reader is opened
//! (`MaterialError::NoTrustAnchor`), so every request leaves here
//! with what this computer has: the card's issuing CA and root, read
//! from the card in a reader on every signing and cached, the CA cache
//! ([`crate::ca_certificates`]), and the
//! certificate-issuing anchors of the EU trusted lists
//! ([`crate::trusted_lists`]). The paired phone's card is not in a
//! reader here, so a phone request carries the cache and the lists.

use refineid_doc_sign::x509::DateTime;
use refineid_pcsc::{PcscBackend, ReaderAccessCap, ReaderBackend as _, ReaderBackendOps as _};
use refineid_pkcs15::fs::{CertSlot, Pkcs15Ops as _};
use refineid_x509::UnvalidatedCertificate;

use crate::ca_certificates::CaCache;
use crate::trusted_lists::{AnchorSource, Refresh};

/// The anchors of one signing run and where the lists stood.
#[derive(Debug)]
pub struct SignerAnchors {
    /// The DER of every anchor, each once.
    pub ders: Vec<Vec<u8>>,
    /// Where the trusted lists' anchors came from.
    pub lists: AnchorSource,
}

impl SignerAnchors {
    /// Whether no anchor is at hand: core refuses a long-term
    /// request so.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ders.is_empty()
    }
}

/// The anchors for signing with the paired phone at `now`: the
/// cached CA certificates and the lists' certificate-issuing anchors.
#[must_use]
pub fn for_phone(now: DateTime) -> SignerAnchors {
    let cached = CaCache::user().map_or_else(Vec::new, |cache| cache.load(now));
    collect(&cached, now)
}

/// The anchors for signing with the card in a reader at `now`.
///
/// They are the issuing CA and root the card itself holds, admitted
/// under the custody rule and cached, the cached CA certificates, and
/// the lists' certificate-issuing anchors.
///
/// The card's own CA certificates are read on every signing, not only
/// when the cache is empty: a cache filled from another card, a
/// citizen card's say, holds nothing that anchors an organisation or
/// test card's path, and its signing would be refused before PIN 2 for
/// want of an anchor the card carries.
#[must_use]
pub fn for_card(now: DateTime) -> SignerAnchors {
    let cache = CaCache::user();
    let (issuing_ca, root) = read_card_ca_certificates();
    let mut certificates = crate::ca_certificates::admit(
        issuing_ca.as_ref().map(UnvalidatedCertificate::as_bytes),
        root.as_ref().map(UnvalidatedCertificate::as_bytes),
        now,
    );
    if let Some(cache) = &cache
        && let Err(error) = cache.store(&certificates)
    {
        let kind = error.kind();
        refineid_dev_errors::report!(DocumentSigning, "CA certificates not cached", kind);
    }
    certificates.extend(
        cache
            .as_ref()
            .map_or_else(Vec::new, |cache| cache.load(now)),
    );
    collect(&certificates, now)
}

/// `certificates` and the lists' certificate-issuing anchors, each
/// DER once.
fn collect(certificates: &[refineid_doc_sign::x509::OwnedCert], now: DateTime) -> SignerAnchors {
    let run = crate::trusted_lists::user_anchors(now, Refresh::WhenDue);
    let mut ders: Vec<Vec<u8>> = Vec::new();
    for der in certificates
        .iter()
        .map(|certificate| certificate.as_der().to_vec())
        .chain(crate::trusted_lists::certificate_issuing_ders(
            &run.anchors,
            now,
        ))
    {
        if !ders.contains(&der) {
            ders.push(der);
        }
    }
    SignerAnchors {
        ders,
        lists: run.source,
    }
}

/// The issuing CA (`EF.4336`) and root (`EF.4334`) of the card in the
/// single reader that holds one, each when the card holds and serves
/// it. Both live under the MF, which a PACE channel cannot reach, so
/// a contactless card yields nothing and its anchors are the cache
/// and the lists.
fn read_card_ca_certificates() -> (
    Option<UnvalidatedCertificate>,
    Option<UnvalidatedCertificate>,
) {
    let backend = PcscBackend;
    let reader = match backend.pick_single_reader(None) {
        Ok(reader) => reader,
        Err(error) => {
            refineid_dev_errors::report!(
                DocumentSigning,
                "no card to read CA certificates from",
                error
            );
            return (None, None);
        }
    };
    let mut transport = match backend.open_session(&reader, ReaderAccessCap::Read) {
        Ok(transport) => transport,
        Err(error) => {
            refineid_dev_errors::report!(
                DocumentSigning,
                "card not opened for CA certificates",
                error
            );
            return (None, None);
        }
    };
    if let Err(error) = transport.select_pkcs15_application() {
        refineid_dev_errors::report!(DocumentSigning, "PKCS#15 application not selected", error);
        return (None, None);
    }
    let issuing_ca = transport.read_certificate(CertSlot::IssuingCaEcc).ok();
    let root = transport.read_certificate(CertSlot::RootCa).ok();
    (issuing_ca, root)
}
