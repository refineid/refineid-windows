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

//! Shared Windows `HCERTSTORE`, `CERT_CONTEXT`, and `CRYPT_KEY_PROV_INFO`
//! boundary for the crate's certificate store modules.

#[cfg(windows)]
use windows_sys::Win32::Foundation::GetLastError;
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_REG,
    CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER,
    CRYPT_KEY_PROV_INFO, CertCloseStore, CertDeleteCertificateFromStore,
    CertDuplicateCertificateContext, CertEnumCertificatesInStore, CertFreeCertificateContext,
    CertGetCertificateContextProperty, CertOpenStore, HCERTSTORE, HCRYPTPROV_LEGACY,
};
#[cfg(windows)]
use windows_sys::Win32::System::Registry::HKEY;

#[cfg(windows)]
use crate::CredentialStoreError;

/// Bytes in one UTF-16 code unit (`WCHAR`).
const UTF16_UNIT_BYTES: usize = size_of::<u16>();

/// Two zero bytes forming a UTF-16 NUL code unit in host byte order.
const UTF16_NUL_BYTES: [u8; UTF16_UNIT_BYTES] = [0; UTF16_UNIT_BYTES];

/// Trailing UTF-16 NUL code unit appended to wide Win32 strings.
const WIDE_NUL_TERMINATOR: u16 = 0;

/// Current user's Personal certificate store name (`Cert:\CurrentUser\My`).
#[cfg(windows)]
pub const PERSONAL_STORE_NAME: &str = "My";

/// Encoding argument when `CertOpenStore` ignores encoding.
#[cfg(windows)]
const NO_STORE_ENCODING: u32 = 0;

/// Cryptographic provider handle when `CertOpenStore` uses the default provider.
#[cfg(windows)]
const DEFAULT_CRYPTO_PROVIDER: HCRYPTPROV_LEGACY = 0;

/// Store flags for a writable registry-backed store.
#[cfg(windows)]
const WRITABLE_STORE_FLAGS: u32 = 0;

/// Default flags passed to `CertCloseStore`.
#[cfg(windows)]
const DEFAULT_CLOSE_FLAGS: u32 = 0;

/// Fallback status code when a pointer invariant fails without a fresh Win32
/// last-error value.
#[cfg(windows)]
pub const UNSPECIFIED_STORE_ERROR_CODE: u32 = 0;

/// Encodes `text` as a NUL-terminated UTF-16 buffer for Win32 wide APIs.
pub fn encode_wide(text: &str) -> Vec<u16> {
    text.encode_utf16()
        .chain(core::iter::once(WIDE_NUL_TERMINATOR))
        .collect()
}

/// Reads a NUL-terminated host-endian UTF-16 string starting at byte `offset`
/// within `buffer`.
///
/// Returns `None` when `offset` exceeds `buffer.len()` or no two-byte NUL
/// terminator appears within the remaining bytes of `buffer`.
fn wide_from_buffer(buffer: &[u8], offset: usize) -> Option<String> {
    let tail = buffer.get(offset..)?;
    let (chunks, _remainder) = tail.as_chunks::<UTF16_UNIT_BYTES>();
    let nul_position = chunks.iter().position(|&pair| pair == UTF16_NUL_BYTES)?;
    let units: Vec<u16> = chunks[..nul_position]
        .iter()
        .map(|&pair| u16::from_ne_bytes(pair))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// Resolves an optional `LPWSTR` address inside a self-contained Win32 property
/// buffer starting at `base_addr` after a `header_bytes`-byte fixed header.
///
/// `None` (a null pointer) decodes to an empty string. A non-null pointer must
/// lie within `buffer` at or after `header_bytes` and terminate with a UTF-16
/// NUL before `buffer` ends; otherwise `None` is returned.
fn decode_property_wide_string(
    buffer: &[u8],
    base_addr: usize,
    header_bytes: usize,
    ptr_addr: Option<usize>,
) -> Option<String> {
    let Some(addr) = ptr_addr else {
        return Some(String::new());
    };
    let offset = addr.checked_sub(base_addr)?;
    if offset < header_bytes {
        return None;
    }
    wide_from_buffer(buffer, offset)
}

/// Decodes the provider and container names from a `CRYPT_KEY_PROV_INFO`
/// property buffer starting at `base_addr` with a `header_bytes` struct header.
fn decode_key_provider_strings(
    buffer: &[u8],
    base_addr: usize,
    header_bytes: usize,
    provider_addr: Option<usize>,
    container_addr: Option<usize>,
) -> Option<(String, String)> {
    if buffer.len() < header_bytes {
        return None;
    }
    let provider = decode_property_wide_string(buffer, base_addr, header_bytes, provider_addr)?;
    let container = decode_property_wide_string(buffer, base_addr, header_bytes, container_addr)?;
    Some((provider, container))
}

/// Captures `GetLastError()` into [`CredentialStoreError::CertificateStore`].
#[cfg(windows)]
pub fn last_certificate_store_error() -> CredentialStoreError {
    // SAFETY: `GetLastError` reads the calling thread's last-error slot and is
    // called immediately after the failing Win32 call.
    let code = unsafe { GetLastError() };
    CredentialStoreError::CertificateStore { code }
}

/// An open Windows `HCERTSTORE`, closed on drop.
#[cfg(windows)]
pub struct CertStore(HCERTSTORE);

#[cfg(windows)]
impl core::fmt::Debug for CertStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CertStore")
    }
}

#[cfg(windows)]
impl CertStore {
    /// Opens an existing `CurrentUser` system store named `store_name` (such as
    /// `"My"` or `"CA"`).
    pub fn open_current_user(store_name: &str) -> Result<Self, CredentialStoreError> {
        let wide_name = encode_wide(store_name);
        // SAFETY: `CERT_STORE_PROV_SYSTEM_W` opens a system store named by a
        // NUL-terminated UTF-16 string at `pvPara`; `wide_name` outlives the call.
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                NO_STORE_ENCODING,
                DEFAULT_CRYPTO_PROVIDER,
                CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
                wide_name.as_ptr().cast(),
            )
        };
        if store.is_null() {
            return Err(last_certificate_store_error());
        }
        Ok(Self(store))
    }

    /// Opens the current user's Personal store (`CurrentUser\My`).
    pub fn open_personal() -> Result<Self, CredentialStoreError> {
        Self::open_current_user(PERSONAL_STORE_NAME)
    }

    /// Opens the certificate store backed by an open registry `key`, read-only
    /// when `read_only` is true.
    ///
    /// # Safety
    /// `key` must be a valid open registry key handle (`HKEY`) for the duration
    /// of the call.
    pub unsafe fn open_registry(key: HKEY, read_only: bool) -> Result<Self, CredentialStoreError> {
        if key.is_null() {
            return Err(CredentialStoreError::CertificateStore {
                code: UNSPECIFIED_STORE_ERROR_CODE,
            });
        }
        let flags = if read_only {
            CERT_STORE_READONLY_FLAG
        } else {
            WRITABLE_STORE_FLAGS
        };
        // SAFETY: caller guarantees `key` is an open registry key handle for
        // the call; `CERT_STORE_PROV_REG` keeps its own state once opened.
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_REG,
                NO_STORE_ENCODING,
                DEFAULT_CRYPTO_PROVIDER,
                flags,
                key.cast(),
            )
        };
        if store.is_null() {
            return Err(last_certificate_store_error());
        }
        Ok(Self(store))
    }

    /// Opens an isolated in-memory certificate store for unit tests.
    #[cfg(test)]
    pub fn open_memory() -> Result<Self, CredentialStoreError> {
        use windows_sys::Win32::Security::Cryptography::CERT_STORE_PROV_MEMORY;

        // SAFETY: `CERT_STORE_PROV_MEMORY` ignores `pvPara` when null and
        // returns a fresh handle owned by `Self`.
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_MEMORY,
                NO_STORE_ENCODING,
                DEFAULT_CRYPTO_PROVIDER,
                WRITABLE_STORE_FLAGS,
                core::ptr::null(),
            )
        };
        if store.is_null() {
            return Err(last_certificate_store_error());
        }
        Ok(Self(store))
    }

    /// Closes this store with `CERT_CLOSE_STORE_CHECK_FLAG`, returning `true`
    /// only when zero certificate contexts remain leaked.
    #[cfg(test)]
    pub fn close_checked(self) -> bool {
        use windows_sys::Win32::Security::Cryptography::CERT_CLOSE_STORE_CHECK_FLAG;

        let store = core::mem::ManuallyDrop::new(self);
        // SAFETY: `ManuallyDrop` suppresses `Drop`, so `store.0` is closed
        // once here with leak checking enabled.
        unsafe { CertCloseStore(store.0, CERT_CLOSE_STORE_CHECK_FLAG) != 0 }
    }

    /// Raw Win32 `HCERTSTORE` handle, valid while `self` is alive.
    pub const fn as_raw(&self) -> HCERTSTORE {
        self.0
    }

    /// Visits every certificate in this store using `CertEnumCertificatesInStore`.
    ///
    /// When `visit` returns `Err`, the active enumeration context is freed with
    /// `CertFreeCertificateContext` before returning the error.
    pub fn try_for_each<E, F>(&self, mut visit: F) -> Result<(), E>
    where
        F: for<'a> FnMut(CertContext<'a>) -> Result<(), E>,
    {
        let mut context: *const CERT_CONTEXT = core::ptr::null();
        loop {
            // SAFETY: `self.0` is an open `HCERTSTORE`, and `context` is either
            // null on the first iteration or the live context returned by the
            // previous `CertEnumCertificatesInStore` call on `self.0`, which
            // frees that previous context before returning the next one or null.
            context = unsafe { CertEnumCertificatesInStore(self.0, context) };
            if context.is_null() {
                return Ok(());
            }
            if let Err(error) = visit(CertContext {
                raw: context,
                _lifetime: core::marker::PhantomData,
            }) {
                // SAFETY: breaking out before `CertEnumCertificatesInStore`
                // reaches null leaves ownership of `context` with the caller;
                // free it once here after `visit` has captured any `GetLastError`.
                unsafe {
                    let _ = CertFreeCertificateContext(context);
                }
                return Err(error);
            }
        }
    }

    /// Visits every certificate in this store to completion.
    pub fn for_each<F>(&self, mut visit: F)
    where
        F: for<'a> FnMut(CertContext<'a>),
    {
        let Ok(()) = self.try_for_each(|context| -> Result<(), core::convert::Infallible> {
            visit(context);
            Ok(())
        });
    }
}

#[cfg(windows)]
impl Drop for CertStore {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful `CertOpenStore` and is closed
        // once on drop.
        unsafe {
            let _ = CertCloseStore(self.0, DEFAULT_CLOSE_FLAGS);
        }
    }
}

/// A borrowed `CERT_CONTEXT` valid for the current enumeration step `'a`.
#[cfg(windows)]
#[derive(Clone, Copy)]
pub struct CertContext<'a> {
    raw: *const CERT_CONTEXT,
    _lifetime: core::marker::PhantomData<&'a CERT_CONTEXT>,
}

#[cfg(windows)]
impl core::fmt::Debug for CertContext<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CertContext")
    }
}

#[cfg(windows)]
impl<'a> CertContext<'a> {
    /// Raw `CERT_CONTEXT` pointer valid for `'a`.
    pub const fn as_raw(self) -> *const CERT_CONTEXT {
        self.raw
    }

    /// DER-encoded certificate bytes of this entry, or `&[]` when empty or null.
    pub const fn encoded_der(self) -> &'a [u8] {
        // SAFETY: `self.raw` is a live `CERT_CONTEXT` for `'a`.
        unsafe { encoded_der(self.raw) }
    }

    /// Key provider name and container name from `CERT_KEY_PROV_INFO_PROP_ID`,
    /// or `None` when the entry has no valid key provider property.
    pub fn key_provider_info(self) -> Option<(String, String)> {
        // SAFETY: `self.raw` is a live `CERT_CONTEXT` for `'a`.
        unsafe { key_provider_info(self.raw) }
    }

    /// Deletes this entry from its store by duplicating the context first so
    /// the enumeration cursor remains valid for the next step.
    pub fn delete_duplicated(self) -> Result<(), CredentialStoreError> {
        // SAFETY: `self.raw` is a live `CERT_CONTEXT` belonging to the store
        // being enumerated.
        unsafe { delete_duplicated_context(self.raw) }
    }
}

/// Returns the DER-encoded certificate bytes of `context`, or `&[]` when
/// `context` is null, `pbCertEncoded` is null, or `cbCertEncoded` is zero.
///
/// # Safety
/// `context` must be null or point to a live `CERT_CONTEXT` valid for `'a`.
#[cfg(windows)]
pub const unsafe fn encoded_der<'a>(context: *const CERT_CONTEXT) -> &'a [u8] {
    if context.is_null() {
        return &[];
    }
    // SAFETY: caller guarantees `context` points to a live `CERT_CONTEXT`.
    let (encoded, length) =
        unsafe { ((*context).pbCertEncoded, (*context).cbCertEncoded as usize) };
    if encoded.is_null() || length == 0 {
        &[]
    } else {
        // SAFETY: Windows maintains `cbCertEncoded` readable bytes at a
        // non-null `pbCertEncoded` for the lifetime of `context`.
        unsafe { core::slice::from_raw_parts(encoded, length) }
    }
}

/// Duplicates `context` and passes the duplicate to `CertDeleteCertificateFromStore`
/// so `context` stays valid as an enumeration cursor.
///
/// # Safety
/// `context` must be null or point to a live `CERT_CONTEXT` in an open store.
#[cfg(windows)]
pub unsafe fn delete_duplicated_context(
    context: *const CERT_CONTEXT,
) -> Result<(), CredentialStoreError> {
    if context.is_null() {
        return Err(CredentialStoreError::CertificateStore {
            code: UNSPECIFIED_STORE_ERROR_CODE,
        });
    }
    // SAFETY: `context` is a live `CERT_CONTEXT`; duplicating increments its
    // reference count so `CertDeleteCertificateFromStore` consumes the
    // duplicate while enumeration retains `context`.
    let duplicate = unsafe { CertDuplicateCertificateContext(context) };
    if duplicate.is_null() {
        return Err(last_certificate_store_error());
    }
    // SAFETY: `CertDeleteCertificateFromStore` always frees `duplicate`, even
    // when deletion fails, so `duplicate` must never be freed again here.
    let deleted = unsafe { CertDeleteCertificateFromStore(duplicate) };
    if deleted == 0 {
        return Err(last_certificate_store_error());
    }
    Ok(())
}

/// Reads `(provider_name, container_name)` from `CERT_KEY_PROV_INFO_PROP_ID` on
/// `context`, or `None` when the context has no valid key provider property.
///
/// # Safety
/// `context` must be null or point to a live `CERT_CONTEXT`.
#[cfg(windows)]
pub unsafe fn key_provider_info(context: *const CERT_CONTEXT) -> Option<(String, String)> {
    if context.is_null() {
        return None;
    }
    let mut size = 0_u32;
    // SAFETY: `context` is live; passing a null buffer queries the property's
    // byte size into `size`.
    let sized = unsafe {
        CertGetCertificateContextProperty(
            context,
            CERT_KEY_PROV_INFO_PROP_ID,
            core::ptr::null_mut(),
            &raw mut size,
        )
    };
    let header_bytes = size_of::<CRYPT_KEY_PROV_INFO>();
    let requested_bytes = size as usize;
    if sized == 0 || requested_bytes < header_bytes {
        return None;
    }
    let mut buffer = vec![0_u64; requested_bytes.div_ceil(size_of::<u64>())];
    let capacity_bytes = buffer.len() * size_of::<u64>();
    // SAFETY: `context` is live and `buffer` provides at least `size` writable
    // bytes aligned to `u64`.
    let read = unsafe {
        CertGetCertificateContextProperty(
            context,
            CERT_KEY_PROV_INFO_PROP_ID,
            buffer.as_mut_ptr().cast(),
            &raw mut size,
        )
    };
    let written_bytes = size as usize;
    if read == 0 || written_bytes < header_bytes || written_bytes > capacity_bytes {
        return None;
    }
    // SAFETY: `CertGetCertificateContextProperty` initialized `written_bytes`
    // bytes in `buffer`, and `written_bytes >= size_of::<CRYPT_KEY_PROV_INFO>()`.
    let (info, bytes) = unsafe {
        let info = buffer
            .as_ptr()
            .cast::<CRYPT_KEY_PROV_INFO>()
            .read_unaligned();
        let bytes = core::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), written_bytes);
        (info, bytes)
    };
    decode_key_provider_strings(
        bytes,
        bytes.as_ptr().addr(),
        header_bytes,
        (!info.pwszProvName.is_null()).then(|| info.pwszProvName.addr()),
        (!info.pwszContainerName.is_null()).then(|| info.pwszContainerName.addr()),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        UTF16_UNIT_BYTES, WIDE_NUL_TERMINATOR, decode_key_provider_strings, encode_wide,
        wide_from_buffer,
    };

    /// Synthetic base address representing a heap-allocated property buffer.
    const SYNTHETIC_BASE_ADDR: usize = 4096;
    /// Fixed header size representing `CRYPT_KEY_PROV_INFO` in host tests.
    const SYNTHETIC_HEADER_BYTES: usize = size_of::<[usize; 6]>();
    /// Start of a buffer.
    const START_OFFSET: usize = 0;
    /// One byte step for off-by-one and odd-alignment checks.
    const ONE_BYTE: usize = 1;
    /// Non-zero filler byte for synthetic headers and padding.
    const FILLER_BYTE: u8 = b'x';

    fn append_wide_bytes(buffer: &mut Vec<u8>, text: &str) -> usize {
        let offset = buffer.len();
        for unit in encode_wide(text) {
            buffer.extend_from_slice(&unit.to_ne_bytes());
        }
        offset
    }

    #[test]
    fn encode_wide_appends_nul_and_round_trips_from_buffer() {
        assert_eq!(encode_wide(""), vec![WIDE_NUL_TERMINATOR]);
        let sample = "RefineID § provider";
        let mut bytes = Vec::new();
        let offset = append_wide_bytes(&mut bytes, sample);
        assert_eq!(offset, START_OFFSET);
        assert_eq!(
            wide_from_buffer(&bytes, START_OFFSET).as_deref(),
            Some(sample)
        );
    }

    #[test]
    fn key_provider_strings_decode_packed_strings_and_null_pointers() {
        let mut buffer = vec![FILLER_BYTE; SYNTHETIC_HEADER_BYTES];
        let provider_offset = append_wide_bytes(&mut buffer, "RefineID Key Storage Provider");
        let container_offset = append_wide_bytes(&mut buffer, "rapp:abcdef");

        let decoded = decode_key_provider_strings(
            &buffer,
            SYNTHETIC_BASE_ADDR,
            SYNTHETIC_HEADER_BYTES,
            Some(SYNTHETIC_BASE_ADDR + provider_offset),
            Some(SYNTHETIC_BASE_ADDR + container_offset),
        );
        assert_eq!(
            decoded,
            Some((
                "RefineID Key Storage Provider".to_owned(),
                "rapp:abcdef".to_owned()
            ))
        );

        assert_eq!(
            decode_key_provider_strings(
                &buffer,
                SYNTHETIC_BASE_ADDR,
                SYNTHETIC_HEADER_BYTES,
                None,
                Some(SYNTHETIC_BASE_ADDR + container_offset),
            ),
            Some((String::new(), "rapp:abcdef".to_owned()))
        );
        assert_eq!(
            decode_key_provider_strings(
                &buffer,
                SYNTHETIC_BASE_ADDR,
                SYNTHETIC_HEADER_BYTES,
                Some(SYNTHETIC_BASE_ADDR + provider_offset),
                None,
            ),
            Some(("RefineID Key Storage Provider".to_owned(), String::new()))
        );
    }

    #[test]
    fn key_provider_strings_decode_unaligned_utf16_offsets() {
        let mut buffer = vec![FILLER_BYTE; SYNTHETIC_HEADER_BYTES + ONE_BYTE];
        let provider_offset = append_wide_bytes(&mut buffer, "Unaligned Provider");
        let container_offset = append_wide_bytes(&mut buffer, "Unaligned Container");
        buffer.push(FILLER_BYTE);

        assert_eq!(provider_offset % UTF16_UNIT_BYTES, ONE_BYTE);
        assert_eq!(
            decode_key_provider_strings(
                &buffer,
                SYNTHETIC_BASE_ADDR,
                SYNTHETIC_HEADER_BYTES,
                Some(SYNTHETIC_BASE_ADDR + provider_offset),
                Some(SYNTHETIC_BASE_ADDR + container_offset),
            ),
            Some((
                "Unaligned Provider".to_owned(),
                "Unaligned Container".to_owned()
            ))
        );
    }

    #[test]
    fn key_provider_strings_reject_short_buffers_and_out_of_range_pointers() {
        let short_buffer = vec![FILLER_BYTE; SYNTHETIC_HEADER_BYTES - ONE_BYTE];
        assert_eq!(
            decode_key_provider_strings(
                &short_buffer,
                SYNTHETIC_BASE_ADDR,
                SYNTHETIC_HEADER_BYTES,
                None,
                None,
            ),
            None
        );

        let mut buffer = vec![0_u8; SYNTHETIC_HEADER_BYTES];
        let valid_offset = append_wide_bytes(&mut buffer, "Valid");
        let valid_addr = Some(SYNTHETIC_BASE_ADDR + valid_offset);

        for bad_addr in [
            SYNTHETIC_BASE_ADDR - ONE_BYTE,
            SYNTHETIC_BASE_ADDR,
            SYNTHETIC_BASE_ADDR + SYNTHETIC_HEADER_BYTES - ONE_BYTE,
            SYNTHETIC_BASE_ADDR + buffer.len(),
            SYNTHETIC_BASE_ADDR + buffer.len() + UTF16_UNIT_BYTES,
        ] {
            assert_eq!(
                decode_key_provider_strings(
                    &buffer,
                    SYNTHETIC_BASE_ADDR,
                    SYNTHETIC_HEADER_BYTES,
                    Some(bad_addr),
                    valid_addr,
                ),
                None
            );
            assert_eq!(
                decode_key_provider_strings(
                    &buffer,
                    SYNTHETIC_BASE_ADDR,
                    SYNTHETIC_HEADER_BYTES,
                    valid_addr,
                    Some(bad_addr),
                ),
                None
            );
        }
    }

    #[test]
    fn key_provider_strings_reject_strings_without_nul_inside_buffer() {
        let mut buffer = vec![FILLER_BYTE; SYNTHETIC_HEADER_BYTES];
        let provider_offset = append_wide_bytes(&mut buffer, "Provider");
        let container_offset = append_wide_bytes(&mut buffer, "Truncated");

        // Half a UTF-16 NUL code unit (1 byte left) is not a NUL terminator.
        buffer.pop();
        assert_eq!(
            decode_key_provider_strings(
                &buffer,
                SYNTHETIC_BASE_ADDR,
                SYNTHETIC_HEADER_BYTES,
                Some(SYNTHETIC_BASE_ADDR + provider_offset),
                Some(SYNTHETIC_BASE_ADDR + container_offset),
            ),
            None
        );

        // No trailing zero bytes at all.
        buffer.pop();
        assert_eq!(
            decode_key_provider_strings(
                &buffer,
                SYNTHETIC_BASE_ADDR,
                SYNTHETIC_HEADER_BYTES,
                Some(SYNTHETIC_BASE_ADDR + provider_offset),
                Some(SYNTHETIC_BASE_ADDR + container_offset),
            ),
            None
        );
    }

    #[cfg(windows)]
    mod windows_tests {
        use windows_sys::Win32::Security::Cryptography::{
            CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID, CERT_STORE_ADD_ALWAYS, CRYPT_KEY_PROV_INFO,
            CertAddEncodedCertificateToStore, CertFreeCertificateContext,
            CertSetCertificateContextProperty, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        };

        use super::super::{CertStore, encode_wide, encoded_der};

        const FIRST_CERT: &[u8] = include_bytes!("../../refineid-rapp-cli/src/mock_cert.der");
        const SECOND_CERT: &[u8] = include_bytes!("../../refineid-rapp-cli/src/mock_ca.der");
        const TEST_PROVIDER: &str = "RefineID Key Storage Provider";
        const TEST_CONTAINER: &str = "rapp:synthetic";
        const NON_EMPTY_CLAIM: u32 = 16;
        const ZERO_FLAGS: u32 = 0;

        fn add_certificate(store: &CertStore, der: &[u8], key_info: Option<(&str, &str)>) {
            let mut context: *mut CERT_CONTEXT = core::ptr::null_mut();
            let length = u32::try_from(der.len()).expect("synthetic certificate size");
            // SAFETY: `store` is open and `der` is readable for `length` bytes.
            unsafe {
                assert_ne!(
                    CertAddEncodedCertificateToStore(
                        store.as_raw(),
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        der.as_ptr(),
                        length,
                        CERT_STORE_ADD_ALWAYS,
                        &raw mut context,
                    ),
                    0
                );
                if let Some((provider, container)) = key_info {
                    let mut provider_wide = encode_wide(provider);
                    let mut container_wide = encode_wide(container);
                    let info = CRYPT_KEY_PROV_INFO {
                        pwszContainerName: container_wide.as_mut_ptr(),
                        pwszProvName: provider_wide.as_mut_ptr(),
                        dwProvType: 0,
                        dwFlags: 0,
                        cProvParam: 0,
                        rgProvParam: core::ptr::null_mut(),
                        dwKeySpec: 0,
                    };
                    assert_ne!(
                        CertSetCertificateContextProperty(
                            context,
                            CERT_KEY_PROV_INFO_PROP_ID,
                            ZERO_FLAGS,
                            (&raw const info).cast(),
                        ),
                        0
                    );
                }
                let _ = CertFreeCertificateContext(context);
            }
        }

        #[test]
        fn early_exit_from_enumeration_frees_active_context() {
            let store = CertStore::open_memory().expect("in-memory store");
            add_certificate(&store, FIRST_CERT, None);
            add_certificate(&store, SECOND_CERT, None);

            let outcome = store.try_for_each(|_context| Err("early stop"));
            assert_eq!(outcome, Err("early stop"));
            assert!(store.close_checked(), "active context must be freed");
        }

        #[test]
        fn encoded_der_returns_empty_slice_for_null_pointers() {
            // SAFETY: null context is explicitly handled.
            assert!(unsafe { encoded_der(core::ptr::null()) }.is_empty());

            // SAFETY: `CERT_CONTEXT` is a plain C struct; zeroed fields give
            // `pbCertEncoded == null`.
            let mut empty_context: CERT_CONTEXT = unsafe { core::mem::zeroed() };
            empty_context.cbCertEncoded = NON_EMPTY_CLAIM;
            // SAFETY: `empty_context` is live on the stack with null `pbCertEncoded`.
            assert!(unsafe { encoded_der(&raw const empty_context) }.is_empty());
        }

        #[test]
        fn memory_store_reads_key_provider_and_deletes_during_enumeration() {
            let store = CertStore::open_memory().expect("in-memory store");
            add_certificate(&store, FIRST_CERT, Some((TEST_PROVIDER, TEST_CONTAINER)));
            add_certificate(&store, SECOND_CERT, None);

            let mut removed = 0_usize;
            let mut kept = Vec::new();
            store
                .try_for_each(|context| -> Result<(), crate::CredentialStoreError> {
                    if let Some((provider, container)) = context.key_provider_info() {
                        assert_eq!(provider, TEST_PROVIDER);
                        assert_eq!(container, TEST_CONTAINER);
                        assert_eq!(context.encoded_der(), FIRST_CERT);
                        context.delete_duplicated()?;
                        removed += 1;
                    } else {
                        kept.push(context.encoded_der().to_vec());
                    }
                    Ok(())
                })
                .expect("enumeration and deletion succeed");

            assert_eq!(removed, 1);
            assert_eq!(kept, vec![SECOND_CERT.to_vec()]);
            assert!(store.close_checked());
        }
    }
}
