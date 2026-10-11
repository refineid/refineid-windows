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

use refineid_rapp_core::ids::PairId;

#[cfg(windows)]
use crate::CredentialStoreError;

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

/// Wide, NUL-terminated copy of `text`.
#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// The current user's personal store, closed on drop.
#[cfg(windows)]
struct PersonalStore(*mut core::ffi::c_void);

#[cfg(windows)]
impl PersonalStore {
    fn open() -> Result<Self, CredentialStoreError> {
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
    der: &[u8],
    pair_id: PairId,
) -> Result<(), CredentialStoreError> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{
        CERT_FRIENDLY_NAME_PROP_ID, CERT_KEY_PROV_INFO_PROP_ID, CERT_STORE_ADD_REPLACE_EXISTING,
        CRYPT_INTEGER_BLOB, CRYPT_KEY_PROV_INFO, CertAddEncodedCertificateToStore,
        CertFreeCertificateContext, CertSetCertificateContextProperty, X509_ASN_ENCODING,
    };

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
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID, CRYPT_KEY_PROV_INFO,
        CertDeleteCertificateFromStore, CertDuplicateCertificateContext,
        CertEnumCertificatesInStore, CertGetCertificateContextProperty,
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
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buffer` holds at least `size` bytes with the alignment
        // the structure needs; the property is a `CRYPT_KEY_PROV_INFO`
        // whose string pointers point into this same buffer.
        let serves_ours = unsafe {
            let read = CertGetCertificateContextProperty(
                context,
                CERT_KEY_PROV_INFO_PROP_ID,
                buffer.as_mut_ptr().cast(),
                &raw mut size,
            );
            read != 0 && {
                let info = buffer
                    .as_ptr()
                    .cast::<CRYPT_KEY_PROV_INFO>()
                    .read_unaligned();
                !info.pwszProvName.is_null() && wide_equals(info.pwszProvName, &provider)
            }
        };
        if !serves_ours {
            continue;
        }
        // SAFETY: deletion consumes a context of its own, so the enumeration
        // keeps the original and continues from it.
        let deleted =
            unsafe { CertDeleteCertificateFromStore(CertDuplicateCertificateContext(context)) };
        if deleted == 0 {
            // SAFETY: `GetLastError` is read before any other Windows call.
            let code = unsafe { GetLastError() };
            return Err(CredentialStoreError::CertificateStore { code });
        }
        removed += 1;
    }
    Ok(removed)
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
    use super::{browser_key_name, browser_key_pair_id};
    use refineid_rapp_core::ids::PairId;

    fn pair_id() -> PairId {
        let bytes: Vec<u8> = (0u8..16).collect();
        PairId::reconstruct(&bytes).expect("pair id size")
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
}
