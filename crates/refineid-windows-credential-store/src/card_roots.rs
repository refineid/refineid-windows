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
//! `SYSTEM` may change, so no process of the user, the agent
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

/// Splits a Windows registry path into non-empty segments delimited by backslash (`\`).
#[cfg(any(windows, test))]
#[must_use]
pub(crate) fn split_registry_path(path: &str) -> Vec<&str> {
    path.split('\\').filter(|s| !s.is_empty()).collect()
}

#[cfg(windows)]
pub use windows_store::remove_card_module_roots;

#[cfg(windows)]
mod windows_store {
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
        ERROR_SUCCESS, WIN32_ERROR,
    };
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_SMART_CARD_ROOT_INFO_PROP_ID, CertGetCertificateContextProperty,
    };
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_USERS, KEY_ALL_ACCESS, KEY_QUERY_VALUE, KEY_READ, REG_LINK,
        REG_OPTION_OPEN_LINK, REG_SAM_FLAGS, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW,
        RegQueryValueExW,
    };

    use super::{is_card_module_root, split_registry_path};
    use crate::CredentialStoreError;
    use crate::card_certificates::{CardId, FINEID_AUTHENTICATION_CONTAINER, is_fineid_entry};
    use crate::win_store::{CertStore, encode_wide};

    /// A user's propagated roots, under the user's hive.
    const SMART_CARD_ROOT_KEY: &str = r"Software\Microsoft\SystemCertificates\SmartCardRoot";
    /// A user's Personal store, under the user's hive.
    const PERSONAL_KEY: &str = r"Software\Microsoft\SystemCertificates\My";
    /// The suffix of the hive Windows loads beside a user's for the user's
    /// file classes, which holds no certificate store.
    const CLASSES_HIVE_SUFFIX: &str = "_Classes";
    /// The longest registry key name, in UTF-16 units with its NUL.
    const MAX_KEY_NAME_UNITS: usize = 256;

    /// Checks whether `key` is a registry symbolic link (`REG_LINK`).
    fn is_symlink(key: HKEY) -> bool {
        let value_name = encode_wide("SymbolicLinkValue");
        let mut val_type = 0u32;
        // SAFETY: querying value type with null data buffer.
        let status = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                core::ptr::null_mut(),
                &raw mut val_type,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if (status == ERROR_SUCCESS || status == ERROR_MORE_DATA) && val_type == REG_LINK {
            return true;
        }

        is_symlink_nt(key)
    }

    /// Checks whether `key` is marked as a symbolic link via NT `KeyFlagsInformation`.
    fn is_symlink_nt(key: HKEY) -> bool {
        const KEY_FLAGS_INFORMATION: u32 = 5;
        const KEY_CTRL_FL_SYM_LINK: u32 = 0x0002;

        #[allow(
            clippy::struct_field_names,
            reason = "matches Windows NT KEY_FLAGS_INFORMATION ABI layout"
        )]
        #[repr(C)]
        struct KeyFlagsInformation {
            wow64_flags: u32,
            key_flags: u32,
            control_flags: u32,
        }

        type NtQueryKeyFn =
            unsafe extern "system" fn(HKEY, u32, *mut core::ffi::c_void, u32, *mut u32) -> i32;

        let ntdll_name = encode_wide("ntdll.dll");
        // SAFETY: ntdll.dll is guaranteed to be loaded in any Windows process.
        let ntdll = unsafe { GetModuleHandleW(ntdll_name.as_ptr()) };
        if ntdll.is_null() {
            return false;
        }
        // SAFETY: querying NtQueryKey symbol from loaded ntdll.
        let proc = unsafe { GetProcAddress(ntdll, c"NtQueryKey".as_ptr().cast()) };
        let Some(proc) = proc else {
            return false;
        };
        let nt_query_key: NtQueryKeyFn = unsafe { core::mem::transmute(proc) };

        let mut info = KeyFlagsInformation {
            wow64_flags: 0,
            key_flags: 0,
            control_flags: 0,
        };
        let mut result_length = 0u32;
        let buffer_size = u32::try_from(size_of::<KeyFlagsInformation>()).unwrap_or(0);
        // SAFETY: info buffer is correctly sized for KeyFlagsInformation.
        let status = unsafe {
            nt_query_key(
                key,
                KEY_FLAGS_INFORMATION,
                (&raw mut info).cast(),
                buffer_size,
                &raw mut result_length,
            )
        };
        if status == 0 {
            (info.control_flags & KEY_CTRL_FL_SYM_LINK) != 0
        } else {
            false
        }
    }

    /// An open registry key, closed on drop.
    #[derive(Debug, PartialEq, Eq)]
    struct Key(HKEY);

    impl Key {
        /// Opens `path` under `parent` safely without traversing any registry
        /// symbolic links (`REG_LINK`).
        ///
        /// Every path segment is opened sequentially with `REG_OPTION_OPEN_LINK`
        /// and checked against both `SymbolicLinkValue` and `NtQueryKey`. If any
        /// intermediate or final key is a symbolic link, `Err(ERROR_ACCESS_DENIED)`
        /// is returned. If any key does not exist, `Ok(None)` is returned.
        fn open(parent: HKEY, path: &str, access: REG_SAM_FLAGS) -> Result<Option<Self>, u32> {
            let segments = split_registry_path(path);
            if segments.is_empty() {
                return Ok(None);
            }
            let mut current_parent = parent;
            #[allow(
                clippy::collection_is_never_read,
                reason = "holder maintains intermediate key handle RAII lifetime across loop iterations"
            )]
            let mut _current_key_holder: Option<Self> = None;

            for (i, &segment) in segments.iter().enumerate() {
                let is_last = i == segments.len() - 1;
                let segment_access = if is_last {
                    access | KEY_QUERY_VALUE
                } else {
                    KEY_READ
                };
                let wide_segment = encode_wide(segment);
                let mut next_key: HKEY = core::ptr::null_mut();
                // SAFETY: `wide_segment` is NUL-terminated and `next_key` receives the handle.
                // `REG_OPTION_OPEN_LINK` ensures that if this segment is a symbolic link,
                // the link itself is opened rather than being resolved/traversed.
                let status = unsafe {
                    RegOpenKeyExW(
                        current_parent,
                        wide_segment.as_ptr(),
                        REG_OPTION_OPEN_LINK,
                        segment_access,
                        &raw mut next_key,
                    )
                };
                match status {
                    ERROR_SUCCESS => {}
                    ERROR_FILE_NOT_FOUND => return Ok(None),
                    other => return Err(other),
                }

                if is_symlink(next_key) {
                    // SAFETY: `next_key` is a live open key handle that must be closed before returning.
                    let _ = unsafe { RegCloseKey(next_key) };
                    return Err(ERROR_ACCESS_DENIED);
                }

                if is_last {
                    return Ok(Some(Self(next_key)));
                }

                let next_holder = Self(next_key);
                current_parent = next_holder.0;
                _current_key_holder = Some(next_holder);
            }

            Ok(None)
        }
    }

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful `RegOpenKeyExW` and is
            // closed once.
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }

    /// The identifiers the Card Module gives the cards whose
    /// authentication certificates propagation put in `personal`.
    fn module_cards(personal: &CertStore) -> Vec<CardId> {
        let mut cards = Vec::new();
        personal.for_each(|context| {
            if let Some((provider, container)) = context.key_provider_info() {
                let certificate = context.encoded_der();
                if container.eq_ignore_ascii_case(FINEID_AUTHENTICATION_CONTAINER)
                    && is_fineid_entry(&provider, &container, certificate)
                {
                    cards.push(CardId::of_authentication_certificate(certificate));
                }
            }
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
        if sized == 0 || size == 0 {
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
        // SAFETY: `personal_key` holds an open registry key handle.
        let personal_store = match unsafe { CertStore::open_registry(personal_key.0, true) } {
            Ok(store) => store,
            Err(CredentialStoreError::CertificateStore { code })
                if code == ERROR_FILE_NOT_FOUND =>
            {
                return Ok(0);
            }
            Err(e) => return Err(e),
        };
        let cards = module_cards(&personal_store);
        if cards.is_empty() {
            return Ok(0);
        }
        // SAFETY: `roots_key` holds an open registry key handle.
        let roots = match unsafe { CertStore::open_registry(roots_key.0, false) } {
            Ok(store) => store,
            Err(CredentialStoreError::CertificateStore { code })
                if code == ERROR_FILE_NOT_FOUND =>
            {
                return Ok(0);
            }
            Err(e) => return Err(e),
        };
        let mut removed = 0;
        roots.try_for_each(|context| {
            let ours = root_information(context.as_raw())
                .is_some_and(|property| is_card_module_root(&property, &cards));
            if !ours {
                return Ok(());
            }
            context.delete_duplicated()?;
            removed += 1;
            Ok(())
        })?;
        Ok(removed)
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

    #[cfg(test)]
    mod windows_tests {
        use super::*;

        #[test]
        fn symlink_detection_on_root_hive() {
            // HKEY_USERS is a standard root hive and not a symlink.
            assert!(!is_symlink(HKEY_USERS));
        }

        #[test]
        fn key_open_safely_handles_nonexistent_paths() {
            // Opening a nonexistent path returns Ok(None).
            let outcome = Key::open(
                HKEY_USERS,
                r"NonExistentSid12345\Software\Microsoft\SystemCertificates\SmartCardRoot",
                KEY_READ,
            );
            assert_eq!(outcome, Ok(None));
        }

        #[test]
        fn key_open_empty_path_returns_none() {
            assert_eq!(Key::open(HKEY_USERS, "", KEY_READ), Ok(None));
            assert_eq!(Key::open(HKEY_USERS, r"\\\\", KEY_READ), Ok(None));
        }
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

    #[test]
    fn split_registry_path_breaks_keys_into_individual_segments() {
        assert_eq!(
            split_registry_path(r"Software\Microsoft\SystemCertificates\SmartCardRoot"),
            vec![
                "Software",
                "Microsoft",
                "SystemCertificates",
                "SmartCardRoot"
            ]
        );
        assert_eq!(
            split_registry_path(r"Software\Microsoft\SystemCertificates\My"),
            vec!["Software", "Microsoft", "SystemCertificates", "My"]
        );
        assert_eq!(split_registry_path(r"\A\\B\C\"), vec!["A", "B", "C"]);
        assert_eq!(split_registry_path(""), Vec::<&str>::new());
        assert_eq!(split_registry_path(r"\\\\"), Vec::<&str>::new());
        assert_eq!(split_registry_path("SingleKey"), vec!["SingleKey"]);
    }
}
