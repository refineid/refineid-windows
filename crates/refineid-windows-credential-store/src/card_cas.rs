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

//! The CA certificates of the FINEID cards in readers, in
//! `CurrentUser\CA` while the card is there (Windows STPA W-R-26).
//!
//! The Card Module serves no `msroots` (W-R-24), so Windows finds a card's
//! issuing CA only where its own stores hold it, or by fetching it from the
//! authentication certificate's Authority Information Access. A browser that
//! looks for a client certificate's chain in the local stores alone fetches
//! nothing: Chromium on Windows asks `CertFindChainInStore` for chains from
//! the cached stores and the URL cache only, matches the server's CA names
//! against them, and sends the intermediates of the chain it gets.
//!
//! So the issuing CA (`EF.4336`) of every FINEID card in a reader stands in
//! the user's Intermediate Certification Authorities store while the card is
//! there, and leaves when the card does. That store makes nothing a trust
//! anchor: it is path material, the certificate Windows would otherwise
//! fetch, and a chain through it is trusted exactly when its root is, which
//! for a production card is DVV's root from the Microsoft Trusted Root
//! Program. The entry carries no property of trust or usage of its own, so
//! the CA's own extensions govern every use, as for a fetched copy. The
//! user's Root store is never written, so no card makes any root trusted.
//!
//! The issuing CA is taken only when the card's root (`EF.4334`) is
//! self-issued, self-signed and a CA, and the issuing CA is a CA that root
//! issued and signed. The root itself never enters a store in a release
//! build. A development build also puts the root of a DVV test card there,
//! since DVV's test roots are in no root program: one named with the word
//! `TEST`, valid for TLS client authentication alone through
//! `CERT_ENHKEY_USAGE_PROP_ID`. Nothing is shipped to recognise a card's CA:
//! no certificate, no fingerprint.
//!
//! An entry is this module's only when it carries [`PRESENTED_MARK`] in its
//! own property; any other entry, the same certificate added by Windows or
//! another program included, is neither marked nor touched.

use refineid_lib_core::x509::{Certificate, OwnedCert, UnvalidatedCertificate};
use refineid_lib_core::x509::{Name, extract_basic_constraints};

/// The word DVV puts in the name of every test CA, as in the issuing CA
/// "DVV TEST Certificates - G5R" of test organization cards.
const TEST_WORD: &str = "TEST";

/// What marks an entry as this module's.
pub const PRESENTED_MARK: &[u8] = b"refineid-card-ca";

/// Whether this build presents a DVV test card's root: development builds
/// (`debug_assertions`, the switch refineid-core's `SigningBuild` uses) do.
const PRESENTS_TEST_ROOTS: bool = cfg!(debug_assertions);

/// What a store entry of a card's CA may be used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    /// Whatever the certificate itself allows: the issuing CA.
    AsIssued,
    /// TLS client authentication alone: a DVV test root.
    ClientAuthentication,
}

/// One certificate a card in a reader wants in the store, and its usage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardCa {
    /// The certificate's DER, as the card holds it.
    pub der: Vec<u8>,
    /// What its entry may be used for.
    pub usage: Usage,
}

/// The CA certificates of one FINEID card that stand in the store while it
/// is in a reader: its issuing CA, and in a development build its root when
/// that is a DVV test root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardCas(Vec<CardCa>);

impl CardCas {
    /// The CAs of a card whose root file holds `root` and whose issuing CA
    /// file holds `issuing`, if any; `None` when `root` is no self-signed CA
    /// or the card has nothing to present.
    #[must_use]
    pub fn from_card(root: &[u8], issuing: Option<&[u8]>) -> Option<Self> {
        Self::presented(root, issuing, PRESENTS_TEST_ROOTS)
    }

    /// [`Self::from_card`], with a test root presented when
    /// `presents_test_roots`.
    fn presented(root: &[u8], issuing: Option<&[u8]>, presents_test_roots: bool) -> Option<Self> {
        let root = OwnedCert::from_der(UnvalidatedCertificate::new(root.to_vec())).ok()?;
        let root_view = root.view();
        if root_view.subject != root_view.issuer
            || !is_ca(root_view)
            || root_view.verify_signed_by(root_view).is_err()
        {
            return None;
        }
        let mut certificates = Vec::new();
        if presents_test_roots && is_test_name(root_view.subject) {
            certificates.push(CardCa {
                der: root.as_der().to_vec(),
                usage: Usage::ClientAuthentication,
            });
        }
        let issuing = issuing
            .and_then(|der| OwnedCert::from_der(UnvalidatedCertificate::new(der.to_vec())).ok())
            .filter(|issuing| {
                let view = issuing.view();
                let root_name = root_view.subject;
                view.issuer == root_name
                    && view.subject != root_name
                    && is_ca(view)
                    && view.verify_signed_by(root_view).is_ok()
            });
        certificates.extend(issuing.map(|issuing| CardCa {
            der: issuing.as_der().to_vec(),
            usage: Usage::AsIssued,
        }));
        (!certificates.is_empty()).then_some(Self(certificates))
    }

    /// The certificates, a test root first.
    #[must_use]
    pub fn certificates(&self) -> &[CardCa] {
        &self.0
    }
}

/// Whether `certificate` is a CA.
fn is_ca(certificate: Certificate<'_>) -> bool {
    certificate
        .extensions
        .is_some_and(|extensions| extract_basic_constraints(extensions).ca)
}

/// Whether `name`'s common name or organization holds [`TEST_WORD`] as a
/// word of its own.
fn is_test_name(name: Name<'_>) -> bool {
    let has_word = |text: &str| {
        text.split(|character: char| !character.is_alphanumeric())
            .any(|word| word == TEST_WORD)
    };
    name.common_name()
        .is_some_and(|common| has_word(common.as_str()))
        || name
            .organization_name()
            .is_some_and(|organization| has_word(organization.as_str()))
}

/// The certificates that should stand in the store when the cards in
/// readers hold `present`, each once.
#[must_use]
pub fn wanted_certificates(present: &[CardCas]) -> Vec<&CardCa> {
    let mut wanted: Vec<&CardCa> = Vec::new();
    for certificate in present.iter().flat_map(CardCas::certificates) {
        if !wanted.iter().any(|stood| stood.der == certificate.der) {
            wanted.push(certificate);
        }
    }
    wanted
}

#[cfg(windows)]
pub use windows_store::present_card_cas;

#[cfg(windows)]
mod windows_store {
    use windows_sys::Win32::Foundation::{CRYPT_E_EXISTS, GetLastError};
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_FIRST_USER_PROP_ID, CERT_STORE_ADD_NEW, CERT_STORE_OPEN_EXISTING_FLAG,
        CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, CRYPT_INTEGER_BLOB, CTL_USAGE,
        CertAddEncodedCertificateToStore, CertCloseStore, CertDeleteCertificateFromStore,
        CertDuplicateCertificateContext, CertEnumCertificatesInStore, CertFreeCertificateContext,
        CertGetCertificateContextProperty, CertOpenStore, CertSetCertificateContextProperty,
        CertSetEnhancedKeyUsage, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        szOID_PKIX_KP_CLIENT_AUTH,
    };

    use super::{CardCas, PRESENTED_MARK, Usage, wanted_certificates};
    use crate::CredentialStoreError;

    /// The user's Intermediate Certification Authorities store (Microsoft,
    /// "System Store Locations").
    const INTERMEDIATE_STORE: &str = "CA";
    /// The application property identifiers this crate took before this
    /// one: `card_certificates` dates Personal entries with the first.
    const PROPERTIES_TAKEN: u32 = 1;
    /// The property that holds [`PRESENTED_MARK`].
    const PRESENTED_PROPERTY: u32 = CERT_FIRST_USER_PROP_ID + PROPERTIES_TAKEN;
    /// The bytes of [`PRESENTED_MARK`], as Windows counts a property.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the mark is a short ASCII constant"
    )]
    const MARK_BYTES: u32 = PRESENTED_MARK.len() as u32;
    /// The encoding of a certificate in a store.
    const ENCODING: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    /// The user's CA store, open for writing.
    struct IntermediateStore(HCERTSTORE);

    impl IntermediateStore {
        fn open() -> Result<Self, CredentialStoreError> {
            let name: Vec<u16> = INTERMEDIATE_STORE.encode_utf16().chain([0]).collect();
            // SAFETY: the provider constant selects the system store opened by
            // a NUL-terminated wide name, which `name` is for the whole call.
            let store = unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_W,
                    0,
                    0,
                    CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
                    name.as_ptr().cast(),
                )
            };
            if store.is_null() {
                return Err(last_store_error());
            }
            Ok(Self(store))
        }
    }

    impl Drop for IntermediateStore {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful `CertOpenStore` and is
            // closed exactly once.
            unsafe {
                let _ = CertCloseStore(self.0, 0);
            }
        }
    }

    /// The certificate store failure Windows just reported.
    fn last_store_error() -> CredentialStoreError {
        // SAFETY: `GetLastError` is read before any other Windows call.
        CredentialStoreError::CertificateStore {
            code: unsafe { GetLastError() },
        }
    }

    /// Makes the user's CA store hold the CAs of the cards in readers,
    /// `present`, and no other entry of this module's.
    ///
    /// # Errors
    /// A Windows certificate store failure.
    pub fn present_card_cas(present: &[CardCas]) -> Result<(), CredentialStoreError> {
        let store = IntermediateStore::open()?;
        let wanted = wanted_certificates(present);
        let mut standing: Vec<Vec<u8>> = Vec::new();
        let mut context: *const CERT_CONTEXT = core::ptr::null();
        loop {
            // SAFETY: `context` is null or the context the previous iteration
            // received from this same enumeration, which frees it.
            context = unsafe { CertEnumCertificatesInStore(store.0, context) };
            if context.is_null() {
                break;
            }
            if !is_presented(context) {
                continue;
            }
            // SAFETY: the context is live; its encoded certificate is
            // `cbCertEncoded` bytes at `pbCertEncoded`.
            let certificate = unsafe {
                core::slice::from_raw_parts(
                    (*context).pbCertEncoded,
                    (*context).cbCertEncoded as usize,
                )
            };
            if wanted.iter().any(|wanted| wanted.der == certificate) {
                standing.push(certificate.to_vec());
                continue;
            }
            // SAFETY: deleting frees the context passed in, so a duplicate
            // goes to the delete while the enumeration keeps its own.
            if unsafe { CertDeleteCertificateFromStore(CertDuplicateCertificateContext(context)) }
                == 0
            {
                let error = last_store_error();
                // SAFETY: the enumeration's context is freed once, here.
                unsafe { CertFreeCertificateContext(context) };
                return Err(error);
            }
        }
        for certificate in wanted {
            if !standing.contains(&certificate.der) {
                add(&store, &certificate.der, certificate.usage)?;
            }
        }
        Ok(())
    }

    /// Whether the entry `context` carries [`PRESENTED_MARK`].
    fn is_presented(context: *const CERT_CONTEXT) -> bool {
        let mut mark = [0u8; PRESENTED_MARK.len()];
        let mut length = MARK_BYTES;
        // SAFETY: `mark` holds `length` bytes; Windows writes at most that and
        // reports the length it wrote.
        let read = unsafe {
            CertGetCertificateContextProperty(
                context,
                PRESENTED_PROPERTY,
                mark.as_mut_ptr().cast(),
                &raw mut length,
            )
        };
        read != 0 && length as usize == PRESENTED_MARK.len() && mark == PRESENTED_MARK
    }

    /// Adds `certificate` to `store` for `usage`, marked as this module's. A
    /// certificate the store already holds is someone else's entry and is
    /// left as it is.
    fn add(
        store: &IntermediateStore,
        certificate: &[u8],
        usage: Usage,
    ) -> Result<(), CredentialStoreError> {
        let length = u32::try_from(certificate.len())
            .map_err(|_| CredentialStoreError::CertificateStore { code: 0 })?;
        let mut added: *mut CERT_CONTEXT = core::ptr::null_mut();
        // SAFETY: `certificate` holds `length` bytes for the call; `added`
        // receives a context this function frees.
        if unsafe {
            CertAddEncodedCertificateToStore(
                store.0,
                ENCODING,
                certificate.as_ptr(),
                length,
                CERT_STORE_ADD_NEW,
                &raw mut added,
            )
        } == 0
        {
            // SAFETY: `GetLastError` is read before any other Windows call.
            let code = unsafe { GetLastError() };
            return if code == CRYPT_E_EXISTS.cast_unsigned() {
                Ok(())
            } else {
                Err(CredentialStoreError::CertificateStore { code })
            };
        }
        let outcome = match usage {
            Usage::AsIssued => Ok(()),
            Usage::ClientAuthentication => restrict(added),
        }
        .and_then(|()| mark(added));
        if outcome.is_err() {
            // SAFETY: deleting frees `added`, which the store just returned.
            unsafe { CertDeleteCertificateFromStore(added) };
        } else {
            // SAFETY: `added` is freed once, here.
            unsafe { CertFreeCertificateContext(added) };
        }
        outcome
    }

    /// Sets the entry `context` valid for TLS client authentication alone
    /// (`CERT_ENHKEY_USAGE_PROP_ID`).
    fn restrict(context: *const CERT_CONTEXT) -> Result<(), CredentialStoreError> {
        let mut client_authentication = szOID_PKIX_KP_CLIENT_AUTH.cast_mut();
        let usage = CTL_USAGE {
            cUsageIdentifier: 1,
            rgpszUsageIdentifier: &raw mut client_authentication,
        };
        // SAFETY: `context` is a live store context; `usage` names one
        // NUL-terminated object identifier for the whole call.
        if unsafe { CertSetEnhancedKeyUsage(context, &raw const usage) } == 0 {
            return Err(last_store_error());
        }
        Ok(())
    }

    /// Marks the entry `context` as this module's.
    fn mark(context: *const CERT_CONTEXT) -> Result<(), CredentialStoreError> {
        let mark = CRYPT_INTEGER_BLOB {
            cbData: MARK_BYTES,
            pbData: PRESENTED_MARK.as_ptr().cast_mut(),
        };
        // SAFETY: `context` is a live store context; `mark` points at
        // `cbData` bytes Windows copies.
        if unsafe {
            CertSetCertificateContextProperty(
                context,
                PRESENTED_PROPERTY,
                0,
                (&raw const mark).cast(),
            )
        } == 0
        {
            return Err(last_store_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use refineid_doc_sign::testkit::{
        CertificateSpec, TestCurve, TestKey, ca_extensions, certificate, day,
    };

    use super::*;

    const ROOT_NAME: &str = "Example TEST Root CA";
    const ISSUING_NAME: &str = "Example TEST Certificates";
    const SERIAL: u8 = 1;
    const FIRST_DAY: u8 = 1;
    const LAST_DAY: u8 = 28;

    fn key(seed: &str) -> TestKey {
        TestKey::derive(TestCurve::P256, seed.as_bytes())
    }

    fn ca(subject: &str, issuer: &str, subject_key: &TestKey, issuer_key: &TestKey) -> Vec<u8> {
        ca_with(subject, issuer, subject_key, issuer_key, ca_extensions())
    }

    fn ca_with(
        subject: &str,
        issuer: &str,
        subject_key: &TestKey,
        issuer_key: &TestKey,
        extensions: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        certificate(
            &CertificateSpec {
                serial: SERIAL,
                subject,
                issuer,
                not_before: day(FIRST_DAY),
                not_after: day(LAST_DAY),
                extensions,
            },
            subject_key,
            issuer_key,
        )
    }

    fn pair() -> (Vec<u8>, Vec<u8>) {
        let root_key = key("root");
        let issuing_key = key("issuing");
        (
            ca(ROOT_NAME, ROOT_NAME, &root_key, &root_key),
            ca(ISSUING_NAME, ROOT_NAME, &issuing_key, &root_key),
        )
    }

    const PRODUCTION_ROOT_NAME: &str = "Example Root CA";
    const PRODUCTION_ISSUING_NAME: &str = "Example Certificates";

    fn production_pair() -> (Vec<u8>, Vec<u8>) {
        let root_key = key("root");
        let issuing_key = key("issuing");
        (
            ca(
                PRODUCTION_ROOT_NAME,
                PRODUCTION_ROOT_NAME,
                &root_key,
                &root_key,
            ),
            ca(
                PRODUCTION_ISSUING_NAME,
                PRODUCTION_ROOT_NAME,
                &issuing_key,
                &root_key,
            ),
        )
    }

    fn issuing(der: &[u8]) -> CardCa {
        CardCa {
            der: der.to_vec(),
            usage: Usage::AsIssued,
        }
    }

    fn test_root(der: &[u8]) -> CardCa {
        CardCa {
            der: der.to_vec(),
            usage: Usage::ClientAuthentication,
        }
    }

    #[test]
    fn a_production_card_presents_its_issuing_ca_alone_in_every_build() {
        let (root, issuing_ca) = production_pair();
        for presents_test_roots in [false, true] {
            let cas = CardCas::presented(&root, Some(&issuing_ca), presents_test_roots)
                .expect("an issuing CA");
            assert_eq!(cas.certificates(), [issuing(&issuing_ca)]);
        }
    }

    #[test]
    fn a_test_root_joins_its_issuing_ca_in_development_builds_only() {
        let (root, issuing_ca) = pair();
        let development = CardCas::presented(&root, Some(&issuing_ca), true).expect("a test card");
        assert_eq!(
            development.certificates(),
            [test_root(&root), issuing(&issuing_ca)]
        );
        let release = CardCas::presented(&root, Some(&issuing_ca), false).expect("a test card");
        assert_eq!(release.certificates(), [issuing(&issuing_ca)]);
    }

    #[test]
    fn a_test_root_alone_is_presented_in_development_builds_only() {
        let (root, _) = pair();
        let cas = CardCas::presented(&root, None, true).expect("a test root");
        assert_eq!(cas.certificates(), [test_root(&root)]);
        assert_eq!(CardCas::presented(&root, None, false), None);
    }

    #[test]
    fn a_root_without_the_word_test_is_never_presented() {
        let root_key = key("root");
        for name in [
            "Example Root CA",
            "Example TESTING Root CA",
            "Example test Root CA",
        ] {
            let root = ca(name, name, &root_key, &root_key);
            assert_eq!(CardCas::presented(&root, None, true), None, "{name}");
        }
    }

    #[test]
    fn a_root_that_is_not_self_signed_or_not_a_ca_presents_nothing() {
        let root_key = key("root");
        let other_key = key("other");
        let issuing_key = key("issuing");
        let issuing_ca = ca(ISSUING_NAME, ROOT_NAME, &issuing_key, &root_key);
        let signed_by_another = ca(ROOT_NAME, ROOT_NAME, &root_key, &other_key);
        let issued_by_another = ca(ROOT_NAME, ISSUING_NAME, &root_key, &root_key);
        let not_a_ca = ca_with(ROOT_NAME, ROOT_NAME, &root_key, &root_key, Vec::new());
        for root in [
            signed_by_another,
            issued_by_another,
            not_a_ca,
            b"not a certificate".to_vec(),
        ] {
            for presents_test_roots in [false, true] {
                assert_eq!(
                    CardCas::presented(&root, Some(&issuing_ca), presents_test_roots),
                    None
                );
            }
        }
    }

    #[test]
    fn an_issuing_ca_the_root_did_not_issue_and_sign_stays_out() {
        let (root, _) = production_pair();
        let issuing_key = key("issuing");
        let root_key = key("root");
        let forged = ca(
            PRODUCTION_ISSUING_NAME,
            PRODUCTION_ROOT_NAME,
            &issuing_key,
            &key("other"),
        );
        let issued_by_another = ca(
            PRODUCTION_ISSUING_NAME,
            ISSUING_NAME,
            &issuing_key,
            &root_key,
        );
        let not_a_ca = ca_with(
            PRODUCTION_ISSUING_NAME,
            PRODUCTION_ROOT_NAME,
            &issuing_key,
            &root_key,
            Vec::new(),
        );
        for issuing_ca in [forged, issued_by_another, not_a_ca, root.clone()] {
            assert_eq!(CardCas::presented(&root, Some(&issuing_ca), true), None);
        }
        assert_eq!(CardCas::presented(&root, None, true), None);
    }

    #[test]
    fn two_cards_of_one_root_want_each_certificate_once() {
        let (root, issuing_ca) = pair();
        let card = CardCas::presented(&root, Some(&issuing_ca), true).expect("a test card");
        let cards = [card.clone(), card];
        let wanted = wanted_certificates(&cards);
        assert_eq!(wanted, [&test_root(&root), &issuing(&issuing_ca)]);
        assert!(wanted_certificates(&[]).is_empty());
    }
}
