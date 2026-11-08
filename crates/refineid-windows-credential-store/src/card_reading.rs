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

//! The FINEID certificates a card in a reader holds, read the way the
//! Certificate Propagation Service reads them.
//!
//! Windows' card database (`Calais\SmartCards`) says by the card's answer
//! to reset which card module serves it; a card no registration gives to
//! `refineid_minidriver.dll` holds no FINEID entry, and is not touched. A
//! card the Card Module serves is read through the Microsoft Smart Card Key
//! Storage Provider, silently, one key container at a time: the provider
//! asks the Card Module for the container's certificate, as it does for
//! propagation, so the bytes are the ones propagation wrote. The provider
//! shares the card with every other program and leaves it as it was; no
//! credential is asked for and none is presented.
//!
//! The provider answers a container it does not find with the same error
//! whether the card lacks it or the reader's name was not the card's, so a
//! card the Card Module serves counts as read only when at least one of its
//! containers gave a certificate. A card from which none came is unread, and
//! keeps every entry.

use crate::card_certificates::{CardCertificate, CardRead, ReaderName};

/// The Card Module's file name, as a card's registration names it
/// (`refineid-minidriver` `card_registrations`).
const CARD_MODULE_FILE: &str = "refineid_minidriver.dll";
/// The separator of a registration's path.
const PATH_SEPARATOR: char = '\\';

/// Whether a registration's card module value `value` names the Card
/// Module: its file name, bare or at the end of a path, in any case.
fn names_card_module(value: &str) -> bool {
    value
        .rsplit(PATH_SEPARATOR)
        .next()
        .is_some_and(|file| file.trim().eq_ignore_ascii_case(CARD_MODULE_FILE))
}

/// The name the Smart Card Key Storage Provider opens a key container on a
/// reader by: `\\.\<reader>\<container>` (Microsoft, "Smart Card Key
/// Storage Provider", fully qualified container names).
fn qualified_container(reader: &ReaderName, container: &str) -> String {
    format!(r"\\.\{}\{container}", reader.as_str())
}

/// What reading one container gave.
#[derive(Debug, PartialEq, Eq)]
enum ContainerRead {
    /// The container's certificate.
    Certificate(CardCertificate),
    /// The provider found no such container or certificate.
    Absent,
    /// The container was not read.
    Unread,
}

/// What a card holds, from what its containers gave. See the module's
/// description.
fn card_read(containers: Vec<ContainerRead>) -> CardRead {
    let mut certificates = Vec::new();
    for container in containers {
        match container {
            ContainerRead::Certificate(certificate) => certificates.push(certificate),
            ContainerRead::Absent => {}
            ContainerRead::Unread => return CardRead::Unread,
        }
    }
    if certificates.is_empty() {
        CardRead::Unread
    } else {
        CardRead::Certificates(certificates)
    }
}

#[cfg(windows)]
pub use windows_reading::read_card;

#[cfg(windows)]
mod windows_reading {
    use windows_sys::Win32::Foundation::{
        NTE_BAD_KEYSET, NTE_NO_KEY, NTE_NOT_FOUND, S_OK, SCARD_E_FILE_NOT_FOUND, SCARD_E_NO_FILE,
        SCARD_E_NO_KEY_CONTAINER, SCARD_E_NO_SUCH_CERTIFICATE,
    };
    use windows_sys::Win32::Security::Credentials::{
        SCardGetCardTypeProviderNameW, SCardListCardsW,
    };
    use windows_sys::Win32::Security::Cryptography::{
        MS_SMART_CARD_KEY_STORAGE_PROVIDER, NCRYPT_CERTIFICATE_PROPERTY, NCRYPT_HANDLE,
        NCRYPT_SILENT_FLAG, NCryptFreeObject, NCryptGetProperty, NCryptOpenKey,
        NCryptOpenStorageProvider,
    };
    use windows_sys::core::HRESULT;

    use super::{
        CardCertificate, CardRead, ContainerRead, ReaderName, card_read, names_card_module,
        qualified_container,
    };
    use crate::card_certificates::{
        AnswerToReset, FINEID_AUTHENTICATION_CONTAINER, FINEID_QUALIFIED_CONTAINER,
    };

    /// `SCARD_S_SUCCESS` (`winscard.h`): a smart card call succeeded.
    const SCARD_S_SUCCESS: i32 = 0;
    /// `SCARD_PROVIDER_CARD_MODULE` (`winscard.h`): the provider kind of a
    /// card's registration that names its card module, the `80000001`
    /// value.
    const SCARD_PROVIDER_CARD_MODULE: u32 = 0x8000_0001;
    /// Room for a card module's path, in UTF-16 units with its NUL.
    const PROVIDER_NAME_UNITS: usize = windows_sys::Win32::Foundation::MAX_PATH as usize;
    /// No legacy key specification: the provider finds the key by its name.
    const NO_LEGACY_KEY_SPEC: u32 = 0;
    /// No provider flags.
    const NO_FLAGS: u32 = 0;
    /// The provider's answers for a container or certificate it did not
    /// find.
    const NOT_FOUND: [HRESULT; 7] = [
        NTE_BAD_KEYSET,
        NTE_NO_KEY,
        NTE_NOT_FOUND,
        SCARD_E_NO_KEY_CONTAINER,
        SCARD_E_NO_SUCH_CERTIFICATE,
        SCARD_E_FILE_NOT_FOUND,
        SCARD_E_NO_FILE,
    ];

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(core::iter::once(0)).collect()
    }

    /// Reads the FINEID certificates of the card whose answer to reset is
    /// `card`, in `reader`. See the module's description.
    #[must_use]
    pub fn read_card(reader: &ReaderName, card: &AnswerToReset) -> CardRead {
        match served_by_card_module(card) {
            Some(true) => {}
            Some(false) => return CardRead::NotServed,
            None => return CardRead::Unread,
        }
        let Some(provider) = Handle::provider() else {
            return CardRead::Unread;
        };
        card_read(
            [FINEID_AUTHENTICATION_CONTAINER, FINEID_QUALIFIED_CONTAINER]
                .iter()
                .map(|container| provider.certificate(&qualified_container(reader, container)))
                .collect(),
        )
    }

    /// Whether Windows' card database gives a card with `card` as its
    /// answer to reset to the Card Module; `None` when it does not answer.
    fn served_by_card_module(card: &AnswerToReset) -> Option<bool> {
        let atr = card.as_bytes();
        if atr.is_empty() {
            return Some(false);
        }
        let mut units = 0u32;
        // SAFETY: a size query with no context, a readable answer to reset
        // and no output buffer.
        let status = unsafe {
            SCardListCardsW(
                0,
                atr.as_ptr(),
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
                &raw mut units,
            )
        };
        if status != SCARD_S_SUCCESS {
            return None;
        }
        let mut names = vec![0u16; units as usize];
        // SAFETY: `names` holds `units` UTF-16 units.
        let status = unsafe {
            SCardListCardsW(
                0,
                atr.as_ptr(),
                core::ptr::null(),
                0,
                names.as_mut_ptr(),
                &raw mut units,
            )
        };
        if status != SCARD_S_SUCCESS {
            return None;
        }
        let listed = names.get(..units as usize)?;
        for name in listed
            .split(|&unit| unit == 0)
            .filter(|name| !name.is_empty())
        {
            let name: Vec<u16> = name.iter().copied().chain(core::iter::once(0)).collect();
            let mut provider = [0u16; PROVIDER_NAME_UNITS];
            let mut length = u32::try_from(provider.len()).ok()?;
            // SAFETY: `name` is NUL-terminated and `provider` holds `length`
            // units.
            let status = unsafe {
                SCardGetCardTypeProviderNameW(
                    0,
                    name.as_ptr(),
                    SCARD_PROVIDER_CARD_MODULE,
                    provider.as_mut_ptr(),
                    &raw mut length,
                )
            };
            if status != SCARD_S_SUCCESS {
                continue;
            }
            let value = provider.get(..length as usize).unwrap_or_default();
            let value = value.split(|&unit| unit == 0).next().unwrap_or_default();
            if names_card_module(&String::from_utf16_lossy(value)) {
                return Some(true);
            }
        }
        Some(false)
    }

    /// A key storage provider object, freed on drop.
    struct Handle(NCRYPT_HANDLE);

    impl Handle {
        /// The Microsoft Smart Card Key Storage Provider.
        fn provider() -> Option<Self> {
            let mut handle = 0;
            // SAFETY: the provider name is a static NUL-terminated string and
            // `handle` receives the provider.
            let status = unsafe {
                NCryptOpenStorageProvider(
                    &raw mut handle,
                    MS_SMART_CARD_KEY_STORAGE_PROVIDER,
                    NO_FLAGS,
                )
            };
            (status == S_OK).then_some(Self(handle))
        }

        /// The certificate of the key container this provider opens as
        /// `name`, read silently.
        fn certificate(&self, name: &str) -> ContainerRead {
            let name = wide(name);
            let mut key = 0;
            // SAFETY: the provider is open, `name` is NUL-terminated for the
            // call and `key` receives the key.
            let status = unsafe {
                NCryptOpenKey(
                    self.0,
                    &raw mut key,
                    name.as_ptr(),
                    NO_LEGACY_KEY_SPEC,
                    NCRYPT_SILENT_FLAG,
                )
            };
            if status != S_OK {
                return container_failure(status);
            }
            let key = Self(key);
            let mut size = 0u32;
            // SAFETY: a size query on the open key with no output buffer.
            let status = unsafe {
                NCryptGetProperty(
                    key.0,
                    NCRYPT_CERTIFICATE_PROPERTY,
                    core::ptr::null_mut(),
                    0,
                    &raw mut size,
                    NCRYPT_SILENT_FLAG,
                )
            };
            if status != S_OK {
                return container_failure(status);
            }
            let mut certificate = vec![0u8; size as usize];
            // SAFETY: `certificate` holds `size` bytes.
            let status = unsafe {
                NCryptGetProperty(
                    key.0,
                    NCRYPT_CERTIFICATE_PROPERTY,
                    certificate.as_mut_ptr(),
                    size,
                    &raw mut size,
                    NCRYPT_SILENT_FLAG,
                )
            };
            if status != S_OK {
                return container_failure(status);
            }
            certificate.truncate(size as usize);
            if certificate.is_empty() {
                return ContainerRead::Absent;
            }
            ContainerRead::Certificate(CardCertificate::new(certificate))
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful open and is freed
            // once.
            let _ = unsafe { NCryptFreeObject(self.0) };
        }
    }

    /// What a provider failure says of a container.
    fn container_failure(status: HRESULT) -> ContainerRead {
        if NOT_FOUND.contains(&status) {
            ContainerRead::Absent
        } else {
            ContainerRead::Unread
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card_certificates::{FINEID_AUTHENTICATION_CONTAINER, FINEID_QUALIFIED_CONTAINER};

    fn certificate(text: &str) -> CardCertificate {
        CardCertificate::new(text.as_bytes().to_vec())
    }

    #[test]
    fn the_module_is_named_bare_or_at_the_end_of_a_path_in_any_case() {
        assert!(names_card_module("refineid_minidriver.dll"));
        assert!(names_card_module("REFINEID_MINIDRIVER.DLL"));
        assert!(names_card_module(
            r"C:\Windows\System32\refineid_minidriver.dll"
        ));
        assert!(!names_card_module("othervendor_minidriver.dll"));
        assert!(!names_card_module(r"C:\refineid_minidriver.dll\other.dll"));
    }

    #[test]
    fn a_container_is_opened_on_its_reader() {
        let reader = ReaderName::new("Synthetic Reader 0".to_owned());
        assert_eq!(
            qualified_container(&reader, FINEID_QUALIFIED_CONTAINER),
            format!(r"\\.\Synthetic Reader 0\{FINEID_QUALIFIED_CONTAINER}")
        );
        assert!(
            qualified_container(&reader, FINEID_AUTHENTICATION_CONTAINER)
                .ends_with(FINEID_AUTHENTICATION_CONTAINER)
        );
    }

    #[test]
    fn a_card_is_read_when_a_container_gave_a_certificate() {
        assert_eq!(
            card_read(vec![
                ContainerRead::Certificate(certificate("authentication")),
                ContainerRead::Absent,
            ]),
            CardRead::Certificates(vec![certificate("authentication")])
        );
    }

    #[test]
    fn a_card_none_of_whose_containers_gave_one_is_unread() {
        assert_eq!(
            card_read(vec![ContainerRead::Absent, ContainerRead::Absent]),
            CardRead::Unread
        );
        assert_eq!(
            card_read(vec![
                ContainerRead::Certificate(certificate("authentication")),
                ContainerRead::Unread,
            ]),
            CardRead::Unread
        );
    }
}
