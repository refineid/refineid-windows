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

//! A DVV test card's CA certificates in `CurrentUser\CA`, in development
//! builds only (Windows STPA W-R-26).
//!
//! The Card Module serves no `msroots` (W-R-24), so Windows finds a card's
//! root and issuing CA only where its own stores hold them. The production
//! roots are in the Microsoft Trusted Root Program; DVV's test roots are not,
//! and a browser that looks for a client certificate's chain in the local
//! stores alone finds no issuer for a test card's authentication
//! certificate: Chromium on Windows asks `CertFindChainInStore` for chains
//! from the cached stores and the URL cache only, and sends the
//! intermediates of the chain it gets.
//!
//! A development build puts the test card's root (`EF.4334`) and issuing CA
//! (`EF.4336`) in the user's Intermediate Certification Authorities store
//! while the card is in a reader, and takes them out when it is not. That
//! store makes nothing a trust anchor: it only lets Windows build the chain,
//! which still ends at an untrusted root. Each entry also carries
//! `CERT_ENHKEY_USAGE_PROP_ID` with TLS client authentication alone, so a
//! chain through it is valid for nothing else. The user's Root store is
//! never written, so no card makes any root trusted for any purpose.
//!
//! A card's CAs are a test card's only when its root is self-issued and
//! self-signed, a CA, and named with the word `TEST`; the issuing CA joins
//! it only when the root signed it and it is a CA named with `TEST` too.
//! Nothing is shipped to recognise them: no certificate, no fingerprint.
//!
//! An entry is this module's only when it carries [`PRESENTED_MARK`] in its
//! own property; any other entry, the same certificate added by Windows or
//! another program included, is neither marked nor touched.
//!
//! Release builds do not compile this module.

use refineid_lib_core::x509::{Certificate, OwnedCert, UnvalidatedCertificate};
use refineid_lib_core::x509::{Name, extract_basic_constraints};

/// The word DVV puts in the name of every test CA, as in the issuing CA
/// "DVV TEST Certificates - G5R" of test organization cards.
const TEST_WORD: &str = "TEST";

/// What marks an entry as this module's.
pub const PRESENTED_MARK: &[u8] = b"refineid-test-card-ca";

/// A DVV test card's CA certificates: its root, then its issuing CA when
/// the card holds one that the root signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestCardCas(Vec<Vec<u8>>);

impl TestCardCas {
    /// The test CAs of a card whose root file holds `root` and whose
    /// issuing CA file holds `issuing`, if any. `None` when `root` is not a
    /// test root.
    #[must_use]
    pub fn from_card(root: &[u8], issuing: Option<&[u8]>) -> Option<Self> {
        let root = OwnedCert::from_der(UnvalidatedCertificate::new(root.to_vec())).ok()?;
        let root_view = root.view();
        if root_view.subject != root_view.issuer
            || !is_test_ca(root_view)
            || root_view.verify_signed_by(root_view).is_err()
        {
            return None;
        }
        let issuing = issuing
            .and_then(|der| OwnedCert::from_der(UnvalidatedCertificate::new(der.to_vec())).ok())
            .filter(|issuing| {
                let view = issuing.view();
                let root_name = root_view.subject;
                view.issuer == root_name
                    && view.subject != root_name
                    && is_test_ca(view)
                    && view.verify_signed_by(root_view).is_ok()
            });
        let mut certificates = vec![root.as_der().to_vec()];
        certificates.extend(issuing.map(|issuing| issuing.as_der().to_vec()));
        Some(Self(certificates))
    }

    /// The certificates, root first.
    #[must_use]
    pub fn certificates(&self) -> &[Vec<u8>] {
        &self.0
    }
}

/// Whether `certificate` is a CA whose name says it is a test CA.
fn is_test_ca(certificate: Certificate<'_>) -> bool {
    certificate
        .extensions
        .is_some_and(|extensions| extract_basic_constraints(extensions).ca)
        && is_test_name(certificate.subject)
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
pub fn wanted_certificates(present: &[TestCardCas]) -> Vec<&[u8]> {
    let mut wanted: Vec<&[u8]> = Vec::new();
    for certificate in present.iter().flat_map(TestCardCas::certificates) {
        if !wanted.contains(&certificate.as_slice()) {
            wanted.push(certificate);
        }
    }
    wanted
}

#[cfg(windows)]
pub use windows_store::present_test_card_cas;

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

    use super::{PRESENTED_MARK, TestCardCas, wanted_certificates};
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

    /// Makes the user's CA store hold the test CAs of the cards in readers,
    /// `present`, and no other entry of this module's.
    ///
    /// # Errors
    /// A Windows certificate store failure.
    pub fn present_test_card_cas(present: &[TestCardCas]) -> Result<(), CredentialStoreError> {
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
            if wanted.contains(&certificate) {
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
            if !standing.iter().any(|stood| stood.as_slice() == certificate) {
                add(&store, certificate)?;
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

    /// Adds `certificate` to `store`, valid for TLS client authentication
    /// alone and marked as this module's. A certificate the store already
    /// holds is someone else's entry and is left as it is.
    fn add(store: &IntermediateStore, certificate: &[u8]) -> Result<(), CredentialStoreError> {
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
        let outcome = restrict_and_mark(added);
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
    /// (`CERT_ENHKEY_USAGE_PROP_ID`) and marks it.
    fn restrict_and_mark(context: *const CERT_CONTEXT) -> Result<(), CredentialStoreError> {
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

    #[test]
    fn a_test_root_and_the_ca_it_signed_are_presented() {
        let (root, issuing) = pair();
        let cas = TestCardCas::from_card(&root, Some(&issuing)).expect("a test root");
        assert_eq!(cas.certificates(), [root, issuing]);
    }

    #[test]
    fn a_root_alone_is_presented_alone() {
        let (root, _) = pair();
        let cas = TestCardCas::from_card(&root, None).expect("a test root");
        assert_eq!(cas.certificates(), [root]);
    }

    #[test]
    fn a_root_without_the_word_test_is_not_a_test_root() {
        let root_key = key("root");
        for name in [
            "Example Root CA",
            "Example TESTING Root CA",
            "Example test Root CA",
        ] {
            let root = ca(name, name, &root_key, &root_key);
            assert_eq!(TestCardCas::from_card(&root, None), None, "{name}");
        }
    }

    #[test]
    fn a_root_that_is_not_self_signed_or_not_a_ca_is_refused() {
        let root_key = key("root");
        let other_key = key("other");
        let signed_by_another = ca(ROOT_NAME, ROOT_NAME, &root_key, &other_key);
        assert_eq!(TestCardCas::from_card(&signed_by_another, None), None);
        let issued_by_another = ca(ROOT_NAME, ISSUING_NAME, &root_key, &root_key);
        assert_eq!(TestCardCas::from_card(&issued_by_another, None), None);
        let not_a_ca = ca_with(ROOT_NAME, ROOT_NAME, &root_key, &root_key, Vec::new());
        assert_eq!(TestCardCas::from_card(&not_a_ca, None), None);
        assert_eq!(TestCardCas::from_card(b"not a certificate", None), None);
    }

    #[test]
    fn an_issuing_ca_the_root_did_not_sign_stays_out() {
        let (root, _) = pair();
        let issuing_key = key("issuing");
        let other_key = key("other");
        let forged = ca(ISSUING_NAME, ROOT_NAME, &issuing_key, &other_key);
        let production = ca(
            "Example Certificates",
            ROOT_NAME,
            &issuing_key,
            &key("root"),
        );
        for issuing in [forged, production] {
            let cas = TestCardCas::from_card(&root, Some(&issuing)).expect("a test root");
            assert_eq!(cas.certificates(), core::slice::from_ref(&root));
        }
    }

    #[test]
    fn two_cards_of_one_root_want_each_certificate_once() {
        let (root, issuing) = pair();
        let card = TestCardCas::from_card(&root, Some(&issuing)).expect("a test root");
        let cards = [card.clone(), card];
        let wanted = wanted_certificates(&cards);
        assert_eq!(wanted, [root.as_slice(), issuing.as_slice()]);
        assert!(wanted_certificates(&[]).is_empty());
    }
}
