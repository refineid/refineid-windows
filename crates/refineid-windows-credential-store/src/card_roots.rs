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

//! Root certificates a FINEID card propagated into a user's Root store.
//!
//! When a card module serves an `msroots` file, Windows' Certificate
//! Propagation Service copies its certificates into the user's
//! `SmartCardRoot` store, the `.SmartCard` physical store of the user's
//! Root store, and Windows trusts them for every purpose. The Card Module
//! serves no `msroots` (Windows STPA W-R-24); builds before it served the
//! card's root (`EF.4334`) and issuing CA (`EF.4336`). This module removes
//! what those builds left.
//!
//! An entry is the Card Module's only when both of these hold, and every
//! other entry is neither read further nor touched:
//!
//! - it is in the user's `SmartCardRoot` store, which root propagation
//!   alone writes. The user's own Root registry store, the machine's
//!   stores and `AuthRoot`, where Windows keeps the roots of the Microsoft
//!   Trusted Root Program, are never opened, so a root the Microsoft root
//!   update or another program added stays even when its bytes are the
//!   same;
//! - Windows recorded which cards propagated it
//!   (`CERT_SMART_CARD_ROOT_INFO_PROP_ID`), and every one of them is a card
//!   whose identifier the Card Module gave: the [`CardId`] of a FINEID
//!   authentication certificate in the same user's Personal store. An
//!   entry another card module propagated as well stays.
//!
//! Microsoft does not document the property's layout. Windows writes a
//! DER OCTET STRING holding one record per card: the card module's 16-byte
//! `cardid`, then the 8-byte identifier of the logon session in which it
//! propagated. An entry whose property is not so is left.
//!
//! Windows writes each propagated entry under a registry key that only
//! `SYSTEM` may change, so no process of the user, the sign-in sweep
//! included, can remove one. The installer's custom action runs as
//! `LocalSystem` and removes the Card Module's entries from every user
//! profile loaded at the time. Unless Group Policy says otherwise
//! ("Configure root certificate clean-up"), Windows itself removes
//! propagated roots when the user signs out.

use crate::card_certificates::{CARD_ID_BYTES, CardId};

/// The DER tag of an OCTET STRING (X.690 section 8.7, universal class 4).
const OCTET_STRING_TAG: u8 = 0x04;
/// A DER length octet below this value is the length itself (X.690
/// section 8.1.3.4); at or above it, its low bits count the length octets
/// that follow (section 8.1.3.5).
const LONG_FORM_LENGTH: u8 = 0x80;
/// The most length octets a root-information property needs.
const MAX_LENGTH_OCTETS: u8 = 2;
/// Bits in an octet.
const BITS_PER_OCTET: u32 = 8;
/// The bytes of a logon session identifier (`LUID`) in a record.
const LOGON_SESSION_BYTES: usize = 8;
/// The bytes of one record: a card identifier, then a logon session.
const RECORD_BYTES: usize = CARD_ID_BYTES + LOGON_SESSION_BYTES;

/// The cards Windows recorded as having propagated a root, read from the
/// entry's `CERT_SMART_CARD_ROOT_INFO_PROP_ID`. `None` when the bytes are
/// not one DER OCTET STRING of whole records, or hold none.
#[must_use]
pub fn propagating_cards(property: &[u8]) -> Option<Vec<CardId>> {
    let (&tag, rest) = property.split_first()?;
    if tag != OCTET_STRING_TAG {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (length, content) = if first < LONG_FORM_LENGTH {
        (usize::from(first), rest)
    } else {
        let octets = first & !LONG_FORM_LENGTH;
        if octets == 0 || octets > MAX_LENGTH_OCTETS {
            return None;
        }
        let (length_octets, content) = rest.split_at_checked(usize::from(octets))?;
        let length = length_octets.iter().fold(0usize, |length, &octet| {
            (length << BITS_PER_OCTET) | usize::from(octet)
        });
        (length, content)
    };
    let (records, partial) = content.as_chunks::<RECORD_BYTES>();
    if content.len() != length || records.is_empty() || !partial.is_empty() {
        return None;
    }
    records
        .iter()
        .map(|record| {
            let (identifier, _logon_session) = record.split_first_chunk::<CARD_ID_BYTES>()?;
            Some(CardId::from_bytes(*identifier))
        })
        .collect()
}

/// Whether a propagated root whose root information is `property` is the
/// Card Module's alone: every card that propagated it is one of
/// `module_cards`.
#[must_use]
pub fn is_card_module_root(property: &[u8], module_cards: &[CardId]) -> bool {
    propagating_cards(property)
        .is_some_and(|cards| cards.iter().all(|card| module_cards.contains(card)))
}

#[cfg(windows)]
pub use windows_store::remove_card_module_roots;

#[cfg(windows)]
mod windows_store {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, GetLastError, WIN32_ERROR,
    };
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_SMART_CARD_ROOT_INFO_PROP_ID, CERT_STORE_PROV_REG,
        CERT_STORE_READONLY_FLAG, CertCloseStore, CertDeleteCertificateFromStore,
        CertDuplicateCertificateContext, CertEnumCertificatesInStore, CertFreeCertificateContext,
        CertGetCertificateContextProperty, CertOpenStore, HCERTSTORE,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_USERS, KEY_ALL_ACCESS, KEY_READ, REG_SAM_FLAGS, RegCloseKey, RegEnumKeyExW,
        RegOpenKeyExW,
    };

    use super::is_card_module_root;
    use crate::CredentialStoreError;
    use crate::card_certificates::{
        CardId, FINEID_AUTHENTICATION_CONTAINER, is_fineid_entry, key_provider_info,
    };

    /// A user's propagated roots, under the user's hive.
    const SMART_CARD_ROOT_KEY: &str = r"Software\Microsoft\SystemCertificates\SmartCardRoot";
    /// A user's Personal store, under the user's hive.
    const PERSONAL_KEY: &str = r"Software\Microsoft\SystemCertificates\My";
    /// The suffix of the hive Windows loads beside a user's for the user's
    /// file classes, which holds no certificate store.
    const CLASSES_HIVE_SUFFIX: &str = "_Classes";
    /// The longest registry key name, in UTF-16 units with its NUL.
    const MAX_KEY_NAME_UNITS: usize = 256;

    /// An open registry key, closed on drop.
    struct Key(HKEY);

    impl Key {
        /// `path` under `parent` with `access`; `Ok(None)` when it does not
        /// exist.
        fn open(parent: HKEY, path: &str, access: REG_SAM_FLAGS) -> Result<Option<Self>, u32> {
            let path = wide(path);
            let mut key: HKEY = core::ptr::null_mut();
            // SAFETY: `path` is NUL-terminated for the call and `key` receives
            // the handle.
            let status = unsafe { RegOpenKeyExW(parent, path.as_ptr(), 0, access, &raw mut key) };
            match status {
                ERROR_SUCCESS => Ok(Some(Self(key))),
                ERROR_FILE_NOT_FOUND => Ok(None),
                other => Err(other),
            }
        }
    }

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful `RegOpenKeyExW` and is
            // closed once.
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }

    /// A certificate store over a registry key, closed on drop.
    struct Store(HCERTSTORE);

    impl Store {
        /// The store `key` holds, read-only when `read_only`.
        fn over(key: &Key, read_only: bool) -> Result<Self, CredentialStoreError> {
            let flags = if read_only {
                CERT_STORE_READONLY_FLAG
            } else {
                0
            };
            // SAFETY: the registry provider takes an open key handle, which
            // lives for the call; the store keeps its own.
            let store = unsafe { CertOpenStore(CERT_STORE_PROV_REG, 0, 0, flags, key.0.cast()) };
            if store.is_null() {
                // SAFETY: read before any other Windows call.
                let code = unsafe { GetLastError() };
                return Err(CredentialStoreError::CertificateStore { code });
            }
            Ok(Self(store))
        }

        /// Calls `visit` with each entry until it returns `false`.
        fn each(&self, mut visit: impl FnMut(*const CERT_CONTEXT) -> bool) {
            let mut context: *const CERT_CONTEXT = core::ptr::null();
            loop {
                // SAFETY: `context` is null or the context the previous
                // iteration received from this enumeration, which frees it.
                context = unsafe { CertEnumCertificatesInStore(self.0, context) };
                if context.is_null() {
                    return;
                }
                if !visit(context) {
                    // SAFETY: the enumeration stops here, so its context is
                    // ours to free.
                    unsafe { CertFreeCertificateContext(context) };
                    return;
                }
            }
        }
    }

    impl Drop for Store {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful `CertOpenStore` and
            // is closed once.
            unsafe {
                let _ = CertCloseStore(self.0, 0);
            }
        }
    }

    /// Wide, NUL-terminated copy of `text`.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(core::iter::once(0)).collect()
    }

    /// The encoded certificate of a live `context`.
    const fn encoded<'a>(context: *const CERT_CONTEXT) -> &'a [u8] {
        // SAFETY: the context is live while the caller holds it; its encoded
        // certificate is `cbCertEncoded` bytes at `pbCertEncoded`. The slice
        // does not outlive the visit that reads it.
        unsafe {
            core::slice::from_raw_parts((*context).pbCertEncoded, (*context).cbCertEncoded as usize)
        }
    }

    /// The identifiers the Card Module gives the cards whose
    /// authentication certificates propagation put in `personal`.
    fn module_cards(personal: &Store) -> Vec<CardId> {
        let mut cards = Vec::new();
        personal.each(|context| {
            if let Some((provider, container)) = key_provider_info(context) {
                let certificate = encoded(context);
                if container.eq_ignore_ascii_case(FINEID_AUTHENTICATION_CONTAINER)
                    && is_fineid_entry(&provider, &container, certificate)
                {
                    cards.push(CardId::of_authentication_certificate(certificate));
                }
            }
            true
        });
        cards
    }

    /// An entry's root information, or `None` when it has none.
    fn root_information(context: *const CERT_CONTEXT) -> Option<Vec<u8>> {
        let mut size = 0u32;
        // SAFETY: a size query with a null buffer and a valid size pointer.
        let sized = unsafe {
            CertGetCertificateContextProperty(
                context,
                CERT_SMART_CARD_ROOT_INFO_PROP_ID,
                core::ptr::null_mut(),
                &raw mut size,
            )
        };
        if sized == 0 {
            return None;
        }
        let mut property = vec![0u8; size as usize];
        // SAFETY: `property` holds `size` bytes.
        let read = unsafe {
            CertGetCertificateContextProperty(
                context,
                CERT_SMART_CARD_ROOT_INFO_PROP_ID,
                property.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        if read == 0 {
            return None;
        }
        property.truncate(size as usize);
        Some(property)
    }

    /// Removes the Card Module's entries from the propagated roots of the
    /// user whose hive is `user`. Returns how many it removed.
    fn remove_from_user(user: &Key) -> Result<usize, CredentialStoreError> {
        let registry = |code: WIN32_ERROR| CredentialStoreError::Registry { code };
        let Some(roots_key) =
            Key::open(user.0, SMART_CARD_ROOT_KEY, KEY_ALL_ACCESS).map_err(registry)?
        else {
            return Ok(0);
        };
        let Some(personal_key) = Key::open(user.0, PERSONAL_KEY, KEY_READ).map_err(registry)?
        else {
            return Ok(0);
        };
        let cards = module_cards(&Store::over(&personal_key, true)?);
        if cards.is_empty() {
            return Ok(0);
        }
        let roots = Store::over(&roots_key, false)?;
        let mut removed = 0;
        let mut failure = None;
        roots.each(|context| {
            let ours = root_information(context)
                .is_some_and(|property| is_card_module_root(&property, &cards));
            if !ours {
                return true;
            }
            // SAFETY: deletion consumes a context of its own, so the
            // enumeration keeps the original and continues from it.
            let deleted =
                unsafe { CertDeleteCertificateFromStore(CertDuplicateCertificateContext(context)) };
            if deleted == 0 {
                // SAFETY: read before any other Windows call.
                let code = unsafe { GetLastError() };
                failure = Some(CredentialStoreError::CertificateStore { code });
                return false;
            }
            removed += 1;
            true
        });
        failure.map_or(Ok(removed), Err)
    }

    /// Removes the Card Module's propagated roots from every user profile
    /// loaded now, and returns how many entries it removed.
    ///
    /// It needs the right to change what propagation wrote, which `SYSTEM`
    /// has and a user's process does not. A user whose stores fail does not
    /// stop the others; the first failure is returned once all were tried.
    ///
    /// # Errors
    /// A registry or certificate store failure.
    pub fn remove_card_module_roots() -> Result<usize, CredentialStoreError> {
        let mut removed = 0;
        let mut first_failure = None;
        let mut index = 0u32;
        loop {
            let mut name = [0u16; MAX_KEY_NAME_UNITS];
            let mut length = u32::try_from(name.len()).unwrap_or(u32::MAX);
            // SAFETY: `name` holds `length` units; the optional outputs are
            // null.
            let status = unsafe {
                RegEnumKeyExW(
                    HKEY_USERS,
                    index,
                    name.as_mut_ptr(),
                    &raw mut length,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };
            index += 1;
            match status {
                ERROR_SUCCESS => {}
                ERROR_NO_MORE_ITEMS => break,
                code => {
                    first_failure.get_or_insert(CredentialStoreError::Registry { code });
                    break;
                }
            }
            let name = String::from_utf16_lossy(name.get(..length as usize).unwrap_or_default());
            if name.ends_with(CLASSES_HIVE_SUFFIX) {
                continue;
            }
            let outcome = match Key::open(HKEY_USERS, &name, KEY_READ) {
                Ok(Some(user)) => remove_from_user(&user),
                Ok(None) => Ok(0),
                Err(code) => Err(CredentialStoreError::Registry { code }),
            };
            match outcome {
                Ok(count) => removed += count,
                Err(error) => {
                    first_failure.get_or_insert(error);
                }
            }
        }
        first_failure.map_or(Ok(removed), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic authentication certificate of a card this module read.
    const MODULE_CARD_CERTIFICATE: &[u8] = b"synthetic authentication certificate";
    /// One of a card another card module served.
    const OTHER_CARD_CERTIFICATE: &[u8] = b"another vendor's synthetic certificate";
    /// A synthetic logon session identifier.
    const LOGON_SESSION: &[u8; LOGON_SESSION_BYTES] = b"session!";
    /// The length octets a long-form length of up to 255 needs.
    const ONE_LENGTH_OCTET: u8 = 1;
    /// Enough records that their length takes the long form.
    const LONG_FORM_RECORDS: usize = 6;

    fn module_card() -> CardId {
        CardId::of_authentication_certificate(MODULE_CARD_CERTIFICATE)
    }

    fn other_card() -> CardId {
        CardId::of_authentication_certificate(OTHER_CARD_CERTIFICATE)
    }

    /// The property as Windows writes it for `cards`.
    fn property(cards: &[CardId]) -> Vec<u8> {
        let mut content = Vec::new();
        for card in cards {
            content.extend_from_slice(card.as_bytes());
            content.extend_from_slice(LOGON_SESSION);
        }
        let mut encoded = vec![OCTET_STRING_TAG];
        let length = u8::try_from(content.len()).expect("a short property");
        if length >= LONG_FORM_LENGTH {
            encoded.push(LONG_FORM_LENGTH | ONE_LENGTH_OCTET);
        }
        encoded.push(length);
        encoded.extend_from_slice(&content);
        encoded
    }

    #[test]
    fn the_records_name_the_propagating_cards() {
        let cards = [module_card(), other_card()];
        assert_eq!(propagating_cards(&property(&cards)), Some(cards.to_vec()));
    }

    #[test]
    fn a_long_form_length_is_read() {
        let cards = [module_card(); LONG_FORM_RECORDS];
        let encoded = property(&cards);
        assert_eq!(encoded[1], LONG_FORM_LENGTH | ONE_LENGTH_OCTET);
        assert_eq!(propagating_cards(&encoded), Some(cards.to_vec()));
    }

    #[test]
    fn anything_else_is_no_record() {
        let encoded = property(&[module_card()]);
        assert_eq!(propagating_cards(&[]), None);
        assert_eq!(propagating_cards(&property(&[])), None);
        assert_eq!(propagating_cards(&encoded[..encoded.len() - 1]), None);
        let mut other_tag = encoded.clone();
        other_tag[0] = OCTET_STRING_TAG + 1;
        assert_eq!(propagating_cards(&other_tag), None);
        let mut partial = encoded;
        partial.push(OCTET_STRING_TAG);
        partial[1] += 1;
        assert_eq!(propagating_cards(&partial), None, "a partial record");
    }

    #[test]
    fn only_a_root_every_propagating_card_of_which_is_the_modules_goes() {
        let ours = [module_card()];
        assert!(is_card_module_root(&property(&[module_card()]), &ours));
        assert!(!is_card_module_root(
            &property(&[module_card(), other_card()]),
            &ours
        ));
        assert!(!is_card_module_root(&property(&[other_card()]), &ours));
        assert!(!is_card_module_root(b"not a property", &ours));
        assert!(!is_card_module_root(&property(&[module_card()]), &[]));
    }
}
