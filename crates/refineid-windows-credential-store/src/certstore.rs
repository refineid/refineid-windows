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

//! The current user's personal certificate store, for browser login through
//! the phone.
//!
//! Edge, Chrome, and Schannel pick a client certificate from
//! `Cert:\CurrentUser\My` and reach its private key through the key storage
//! provider named in the certificate's key provider information. For a paired
//! phone that provider is the `RefineID` key storage provider exported by the
//! minidriver DLL, and the key name carries the pair identifier, so the
//! provider can find the pairing and sign through RAPP. This module writes
//! and removes those certificates; it never touches a private key, because
//! there is none on this computer.
//!
//! An entry stands only while the phone is present: its pairing serves and a
//! session on this computer heard the entry's card within the grace (RAPP
//! v26.11.2 section 8.4 item 3). The process that holds the session writes
//! the entry and removes it when the grace passes; the pairing store judges
//! every entry by [`stale_browser_entries`] at each load and after each
//! change it writes, so an entry goes also after a crash, as soon as any
//! `RefineID` process of this user runs. The entry is the one copy of the
//! certificate on this computer outside a process's memory, and every other
//! local consumer reads the offered certificate from it.

use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::CertificateFingerprint;
use refineid_rapp_core::presence::CardSighting;
use refineid_rapp_core::store::PairingRecord;

#[cfg(windows)]
use crate::CredentialStoreError;
#[cfg(windows)]
use refineid_lib_core::x509::{OwnedCert, UnvalidatedCertificate};
#[cfg(windows)]
use refineid_rapp_core::store::{PairingStore, offer_stands};

/// Name under which the minidriver DLL registers its CNG key storage
/// provider. The driver MSI writes the same name into the CNG provider
/// registry, so the three must agree.
pub const KEY_STORAGE_PROVIDER: &str = "RefineID Key Storage Provider";

/// Prefix of every key name the provider serves. The rest is the pair
/// identifier in lowercase hexadecimal.
pub const BROWSER_KEY_PREFIX: &str = "rapp:";

/// Friendly name shown for the certificate in Windows certificate dialogs.
#[cfg(windows)]
const FRIENDLY_NAME: &str = "RefineID (phone)";

/// The key name the provider serves for one pairing.
#[must_use]
pub fn browser_key_name(pair_id: PairId) -> String {
    use core::fmt::Write as _;

    let mut name = String::with_capacity(BROWSER_KEY_PREFIX.len() + pair_id.as_bytes().len() * 2);
    name.push_str(BROWSER_KEY_PREFIX);
    for byte in pair_id.as_bytes() {
        // Writing into a String cannot fail.
        let _ = write!(name, "{byte:02x}");
    }
    name
}

/// The pairing a key name refers to, or `None` when the name is not one the
/// provider serves.
#[must_use]
pub fn browser_key_pair_id(name: &str) -> Option<PairId> {
    let hex = name.strip_prefix(BROWSER_KEY_PREFIX)?;
    if hex.len() % 2 != 0 || !hex.is_ascii() {
        return None;
    }
    let bytes = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect::<Option<Vec<u8>>>()?;
    PairId::reconstruct(&bytes).ok()
}

/// One `RefineID` entry of the personal store: the key name it is bound to
/// and its certificate's DER.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserEntry {
    /// The key name of its `RefineID` provider binding.
    pub name: String,
    /// Its certificate, as stored.
    pub certificate: Vec<u8>,
}

/// The entries among `entries` that must leave the personal store at
/// `now_ms`: each is bound to no name the provider serves, or its pairing is
/// not in `records` or serves no longer, or no session heard its card within
/// the grace, as `sighting` gives the last card heard for a pairing.
pub fn stale_browser_entries(
    entries: &[BrowserEntry],
    records: &[&PairingRecord],
    sighting: &dyn Fn(PairId) -> Option<CardSighting>,
    now_ms: u64,
) -> Vec<BrowserEntry> {
    entries
        .iter()
        .filter(|entry| {
            !browser_key_pair_id(&entry.name).is_some_and(|pair_id| {
                records
                    .iter()
                    .any(|record| record.pair_id() == pair_id && record.serves())
                    && sighting(pair_id).is_some_and(|heard| {
                        heard.fingerprint()
                            == CertificateFingerprint::of_certificate(&entry.certificate)
                            && !heard.lapsed_at(now_ms)
                    })
            })
        })
        .cloned()
        .collect()
}

/// Wide, NUL-terminated copy of `text`.
#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// The current user's personal store, closed on drop.
#[cfg(windows)]
pub struct PersonalStore(pub *mut core::ffi::c_void);

#[cfg(windows)]
impl PersonalStore {
    pub fn open() -> Result<Self, CredentialStoreError> {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::Security::Cryptography::{
            CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W,
            CERT_SYSTEM_STORE_CURRENT_USER, CertOpenStore,
        };

        let name = wide("My");
        // SAFETY: the provider constant selects the system store opened by a
        // NUL-terminated wide name, which `name` is for the whole call.
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
            // SAFETY: `GetLastError` is read before any other Windows call.
            let code = unsafe { GetLastError() };
            return Err(CredentialStoreError::CertificateStore { code });
        }
        Ok(Self(store))
    }
}

#[cfg(windows)]
impl Drop for PersonalStore {
    fn drop(&mut self) {
        use windows_sys::Win32::Security::Cryptography::CertCloseStore;

        // SAFETY: the handle came from a successful `CertOpenStore` and is
        // closed exactly once.
        unsafe {
            let _ = CertCloseStore(self.0, 0);
        }
    }
}

/// Put the pairing's authentication certificate into the current user's
/// personal store, bound to the `RefineID` key storage provider.
///
/// Replaces an earlier copy of the same certificate. The certificate is
/// public data; the private key stays on the card in the phone.
///
/// # Errors
/// A Windows certificate store failure, or a certificate too large to
/// describe to Windows.
#[cfg(windows)]
pub fn install_browser_certificate(
    certificate: &OwnedCert,
    pair_id: PairId,
) -> Result<(), CredentialStoreError> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{
        CERT_FRIENDLY_NAME_PROP_ID, CERT_KEY_PROV_INFO_PROP_ID, CERT_STORE_ADD_REPLACE_EXISTING,
        CRYPT_INTEGER_BLOB, CRYPT_KEY_PROV_INFO, CertAddEncodedCertificateToStore,
        CertFreeCertificateContext, CertSetCertificateContextProperty, X509_ASN_ENCODING,
    };

    let der = certificate.as_der();
    let length = u32::try_from(der.len())
        .map_err(|_error| CredentialStoreError::CertificateStore { code: 0 })?;
    let store = PersonalStore::open()?;
    let mut context = core::ptr::null_mut();
    // SAFETY: `der` is readable for `length` bytes and `context` is a valid
    // out pointer; a returned context is released below.
    let added = unsafe {
        CertAddEncodedCertificateToStore(
            store.0,
            X509_ASN_ENCODING,
            der.as_ptr(),
            length,
            CERT_STORE_ADD_REPLACE_EXISTING,
            &raw mut context,
        )
    };
    if added == 0 || context.is_null() {
        // SAFETY: `GetLastError` is read before any other Windows call.
        let code = unsafe { GetLastError() };
        return Err(CredentialStoreError::CertificateStore { code });
    }

    let mut container = wide(&browser_key_name(pair_id));
    let mut provider = wide(KEY_STORAGE_PROVIDER);
    let key_info = CRYPT_KEY_PROV_INFO {
        pwszContainerName: container.as_mut_ptr(),
        pwszProvName: provider.as_mut_ptr(),
        dwProvType: 0,
        dwFlags: 0,
        cProvParam: 0,
        rgProvParam: core::ptr::null_mut(),
        dwKeySpec: 0,
    };
    let mut friendly = wide(FRIENDLY_NAME);
    let friendly_bytes = u32::try_from(friendly.len() * 2).unwrap_or(0);
    let friendly_blob = CRYPT_INTEGER_BLOB {
        cbData: friendly_bytes,
        pbData: friendly.as_mut_ptr().cast(),
    };
    // SAFETY: `context` is the live context added above; the property
    // structures and every buffer they point at outlive both calls.
    let result = unsafe {
        let bound = CertSetCertificateContextProperty(
            context,
            CERT_KEY_PROV_INFO_PROP_ID,
            0,
            (&raw const key_info).cast(),
        );
        let code = if bound == 0 { GetLastError() } else { 0 };
        if bound != 0 {
            // The friendly name is cosmetic; its failure is not the caller's.
            let _ = CertSetCertificateContextProperty(
                context,
                CERT_FRIENDLY_NAME_PROP_ID,
                0,
                (&raw const friendly_blob).cast(),
            );
        }
        let _ = CertFreeCertificateContext(context);
        if bound == 0 {
            Err(CredentialStoreError::CertificateStore { code })
        } else {
            Ok(())
        }
    };
    drop(store);
    result
}

/// Remove every certificate in the current user's personal store whose
/// private key is served by the `RefineID` key storage provider.
///
/// Returns how many were removed. Certificates bound to any other provider,
/// including a physical card's, are left alone.
///
/// # Errors
/// A Windows certificate store failure other than reaching the end of the
/// store.
#[cfg(windows)]
pub fn remove_browser_certificates() -> Result<usize, CredentialStoreError> {
    visit_browser_entries(&mut |_entry| true)
}

/// The current user's `RefineID` entries in the personal store. A store that
/// cannot be read holds none here; the next judgement sees them again.
#[cfg(windows)]
#[must_use]
pub fn browser_entries() -> Vec<BrowserEntry> {
    let mut entries = Vec::new();
    let listed = visit_browser_entries(&mut |entry| {
        entries.push(entry.clone());
        false
    });
    if let Err(error) = listed {
        refineid_dev_errors::report!(Rapp, "offered certificates not listed", error);
    }
    entries
}

/// The certificate the phone of `pair_id` is offered on at `now_ms`.
///
/// It is the one its entry in the personal store holds, while the offer
/// stands by `store`'s pairing and card sighting
/// ([`refineid_rapp_core::store::offer_stands`]). The process holding the
/// phone's session writes the entry; every other local consumer reads the
/// offer here.
#[cfg(windows)]
pub fn offered_phone_certificate<S: PairingStore + ?Sized>(
    store: &S,
    pair_id: PairId,
    now_ms: u64,
) -> Option<OwnedCert> {
    let name = browser_key_name(pair_id);
    browser_entries()
        .into_iter()
        .filter(|entry| entry.name == name)
        .filter_map(|entry| {
            OwnedCert::from_der(UnvalidatedCertificate::new(entry.certificate)).ok()
        })
        .find(|certificate| offer_stands(store, pair_id, certificate, now_ms))
}

/// Removes the `RefineID` entries of the personal store that are among
/// `stale`. One that cannot be removed stays for the next judgement.
#[cfg(windows)]
pub fn remove_browser_entries(stale: &[BrowserEntry]) {
    let removed = visit_browser_entries(&mut |entry| stale.contains(entry));
    if let Err(error) = removed {
        refineid_dev_errors::report!(Rapp, "offered certificates not withdrawn", error);
    }
}

/// Nothing is offered to browsers off Windows.
#[cfg(not(windows))]
#[must_use]
pub const fn browser_entries() -> Vec<BrowserEntry> {
    Vec::new()
}

/// Nothing is offered to browsers off Windows.
#[cfg(not(windows))]
pub const fn remove_browser_entries(_stale: &[BrowserEntry]) {}

/// Calls `remove` with each entry of the current user's personal store whose
/// private key the `RefineID` provider serves, and deletes the entry when it
/// answers true. Returns how many it deleted. Certificates bound to any other
/// provider are neither named nor touched.
#[cfg(windows)]
fn visit_browser_entries(
    remove: &mut dyn FnMut(&BrowserEntry) -> bool,
) -> Result<usize, CredentialStoreError> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID, CRYPT_KEY_PROV_INFO,
        CertDeleteCertificateFromStore, CertDuplicateCertificateContext,
        CertEnumCertificatesInStore, CertFreeCertificateContext, CertGetCertificateContextProperty,
    };

    let store = PersonalStore::open()?;
    let provider = wide(KEY_STORAGE_PROVIDER);
    let mut removed = 0;
    let mut context: *mut CERT_CONTEXT = core::ptr::null_mut();
    loop {
        // SAFETY: `context` is null or the context the previous iteration
        // received from this same enumeration, which frees it.
        context = unsafe { CertEnumCertificatesInStore(store.0, context) };
        if context.is_null() {
            break;
        }
        let mut size = 0u32;
        // SAFETY: a size query with a null buffer and a valid size pointer.
        let sized = unsafe {
            CertGetCertificateContextProperty(
                context,
                CERT_KEY_PROV_INFO_PROP_ID,
                core::ptr::null_mut(),
                &raw mut size,
            )
        };
        if sized == 0 || (size as usize) < size_of::<CRYPT_KEY_PROV_INFO>() {
            continue;
        }
        let units = (size as usize).div_ceil(size_of::<u64>());
        let mut buffer = vec![0u64; units];
        // SAFETY: `buffer` holds at least `size` bytes with the alignment
        // the structure needs; the property is a `CRYPT_KEY_PROV_INFO`
        // whose string pointers point into this same buffer, or are null.
        let name = unsafe {
            let read = CertGetCertificateContextProperty(
                context,
                CERT_KEY_PROV_INFO_PROP_ID,
                buffer.as_mut_ptr().cast(),
                &raw mut size,
            );
            if read == 0 {
                None
            } else {
                let info = buffer
                    .as_ptr()
                    .cast::<CRYPT_KEY_PROV_INFO>()
                    .read_unaligned();
                if !info.pwszProvName.is_null() && wide_equals(info.pwszProvName, &provider) {
                    Some(wide_text(info.pwszContainerName, size as usize))
                } else {
                    None
                }
            }
        };
        let Some(name) = name else {
            continue;
        };
        // SAFETY: the context is live; its encoded certificate is
        // `cbCertEncoded` bytes at `pbCertEncoded`, null only when empty.
        let certificate = unsafe {
            let encoded = (*context).pbCertEncoded;
            if encoded.is_null() {
                Vec::new()
            } else {
                core::slice::from_raw_parts(encoded, (*context).cbCertEncoded as usize).to_vec()
            }
        };
        if !remove(&BrowserEntry { name, certificate }) {
            continue;
        }
        // SAFETY: deletion consumes a context of its own, so the enumeration
        // keeps the original and continues from it.
        let deleted =
            unsafe { CertDeleteCertificateFromStore(CertDuplicateCertificateContext(context)) };
        if deleted == 0 {
            // SAFETY: `GetLastError` is read before any other Windows call;
            // the enumeration context is ours to free once the loop ends.
            let code = unsafe {
                let code = GetLastError();
                CertFreeCertificateContext(context);
                code
            };
            return Err(CredentialStoreError::CertificateStore { code });
        }
        removed += 1;
    }
    Ok(removed)
}

/// The NUL-terminated wide string at `text`, read no further than
/// `limit_bytes`; a null pointer is an empty string.
///
/// # Safety
/// `text` must be null or point at a wide string readable up to its NUL or
/// `limit_bytes`, whichever comes first.
#[cfg(windows)]
pub unsafe fn wide_text(text: *const u16, limit_bytes: usize) -> String {
    if text.is_null() {
        return String::new();
    }
    let limit = limit_bytes / size_of::<u16>();
    let mut units = Vec::new();
    for index in 0..limit {
        // SAFETY: every unit read so far was non-NUL and `index` is within
        // the bound the caller guarantees.
        let unit = unsafe { text.add(index).read() };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

/// Whether the NUL-terminated wide string at `text` equals `expected`,
/// reading no further than `expected` is long.
///
/// # Safety
/// `text` must point at a readable NUL-terminated wide string.
#[cfg(windows)]
unsafe fn wide_equals(text: *const u16, expected: &[u16]) -> bool {
    for (index, &unit) in expected.iter().enumerate() {
        // SAFETY: every unit read so far was non-NUL, so the string
        // continues at least one unit further.
        let actual = unsafe { text.add(index).read() };
        if actual != unit {
            return false;
        }
        if unit == 0 {
            return true;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{BrowserEntry, browser_key_name, browser_key_pair_id, stale_browser_entries};
    use crate::pairing::test_records::{CREATED_AT_MS, PAIR, certificate, paired_record};
    use refineid_rapp_core::ids::PairId;
    use refineid_rapp_core::message::CertificateFingerprint;
    use refineid_rapp_core::presence::CardSighting;
    use refineid_rapp_core::store::{MemoryPairingStore, PairingStore as _, forget_pairing};

    /// A key name the provider does not serve.
    const FOREIGN_KEY_NAME: &str = "rapp:zz";
    /// The moment a session heard the card.
    const HEARD_AT_MS: u64 = CREATED_AT_MS;
    /// The offer grace (RAPP v26.11.2 section 8.4 item 3).
    const GRACE_MS: u64 = refineid_rapp::IDENTITY_OFFER_GRACE_MS;
    /// One millisecond.
    const ONE_MS: u64 = 1;

    fn pair_id() -> PairId {
        let bytes: Vec<u8> = (0u8..16).collect();
        PairId::reconstruct(&bytes).expect("pair id size")
    }

    fn entry(name: String) -> BrowserEntry {
        BrowserEntry {
            name,
            certificate: certificate().as_der().to_vec(),
        }
    }

    /// A session heard the fixtures' card at [`HEARD_AT_MS`].
    fn heard_sighting() -> CardSighting {
        CardSighting::new(
            CertificateFingerprint::of_certificate(certificate().as_der()),
            HEARD_AT_MS,
        )
    }

    #[test]
    fn the_key_name_carries_the_pair_id_in_hex() {
        let name = browser_key_name(pair_id());
        assert!(name.starts_with("rapp:000102"));
        assert_eq!(browser_key_pair_id(&name), Some(pair_id()));
    }

    #[test]
    fn foreign_key_names_are_rejected() {
        assert_eq!(browser_key_pair_id("card:0001"), None);
        assert_eq!(browser_key_pair_id("rapp:zz"), None);
        assert_eq!(browser_key_pair_id("rapp:0001"), None);
    }

    #[test]
    fn an_entry_stands_while_a_session_heard_its_card_within_the_grace() {
        let entries = vec![entry(browser_key_name(PAIR))];
        let paired = paired_record();
        assert!(
            stale_browser_entries(
                &entries,
                &[&paired],
                &|_| Some(heard_sighting()),
                HEARD_AT_MS
            )
            .is_empty()
        );
        assert!(
            stale_browser_entries(
                &entries,
                &[&paired],
                &|_| Some(heard_sighting()),
                HEARD_AT_MS + GRACE_MS - ONE_MS
            )
            .is_empty()
        );
        assert_eq!(
            stale_browser_entries(
                &entries,
                &[&paired],
                &|_| Some(heard_sighting()),
                HEARD_AT_MS + GRACE_MS
            ),
            entries
        );
    }

    #[test]
    fn an_entry_goes_when_no_session_heard_its_card_or_another_card() {
        let entries = vec![entry(browser_key_name(PAIR))];
        let paired = paired_record();
        assert_eq!(
            stale_browser_entries(&entries, &[&paired], &|_| None, HEARD_AT_MS),
            entries
        );
        let other_card = |_| {
            Some(CardSighting::new(
                CertificateFingerprint::from_array(*b"the fingerprint of another card."),
                HEARD_AT_MS,
            ))
        };
        assert_eq!(
            stale_browser_entries(&entries, &[&paired], &other_card, HEARD_AT_MS),
            entries
        );
    }

    #[test]
    fn an_entry_goes_when_its_record_is_gone_or_forgotten_and_a_foreign_name_goes_too() {
        let gone = vec![entry(browser_key_name(PAIR))];
        assert_eq!(
            stale_browser_entries(&gone, &[], &|_| Some(heard_sighting()), HEARD_AT_MS),
            gone
        );
        let mut store = MemoryPairingStore::new();
        store.insert(paired_record()).expect("inserted");
        forget_pairing(&mut store, PAIR, HEARD_AT_MS).expect("forgotten");
        let entries = vec![
            entry(browser_key_name(PAIR)),
            entry(FOREIGN_KEY_NAME.to_owned()),
        ];
        let forgotten = store.get(PAIR).expect("held");
        assert_eq!(
            stale_browser_entries(
                &entries,
                &[forgotten],
                &|_| Some(heard_sighting()),
                HEARD_AT_MS
            ),
            entries
        );
    }
}
