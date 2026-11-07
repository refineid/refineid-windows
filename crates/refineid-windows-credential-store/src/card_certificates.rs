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

//! A physical card's certificates in `CurrentUser\My`.
//!
//! Windows' Certificate Propagation Service reads an inserted card through
//! the Card Module and writes its certificates to the user's Personal store,
//! where they stay when the card leaves. The login sweep removes a FINEID
//! entry not seen for [`CERTIFICATE_RETENTION_DAYS`], the bound a pairing's
//! certificate has (Windows STPA W-R-22).
//!
//! An entry is FINEID's only when all three of these hold, and every other
//! entry is neither read further nor touched:
//!
//! - its key provider is one of Microsoft's two smart card providers;
//! - its container is one the Card Module names; the authentication
//!   container embeds a PIV tag Windows needs at a fixed offset, so that name
//!   alone could recur on another vendor's card;
//! - the certificate carries an object identifier of DVV's arc.
//!
//! When an entry was seen is kept on the entry itself, as a certificate
//! property, and leaves with it. A sweep that finds no date on an entry dates
//! it now, so a store entry written afresh by propagation counts as seen, and
//! an entry whose certificate is on a card in a reader at the sweep is seen.

use refineid_rapp_core::store::CERTIFICATE_RETENTION_DAYS;

#[cfg(windows)]
use crate::CredentialStoreError;
#[cfg(windows)]
use crate::certstore::{PersonalStore, wide_text};

/// The container of the card's authentication key, which the Card Module
/// reports to Windows (`refineid-minidriver` `cardmod`).
pub const FINEID_AUTHENTICATION_CONTAINER: &str = "{00000000-0000-0000-0000-000005fc10a0}";
/// The container of the card's qualified signature key, as the Card Module
/// reports it.
pub const FINEID_QUALIFIED_CONTAINER: &str = "{7A6D5E7C-FE1D-4F1A-B8C2-FA1B1B7C3A02}";

/// The providers that hold a card's keys for Windows: the Calais registration
/// of the FINEID cards names both (`refineid-msi`).
const SMART_CARD_PROVIDERS: [&str; 2] = [
    "Microsoft Base Smart Card Crypto Provider",
    "Microsoft Smart Card Key Storage Provider",
];

/// The DER body of the object identifier arc 1.2.246.517, DVV's, under which
/// the FINEID certificate policies lie: the DVV citizen CA's policy is
/// 1.2.246.517.1.10.351.1 (`http://www.fineid.fi/cps61/`). An opaque registered
/// identifier, per X.690 section 8.19.
const DVV_ARC_DER: &[u8] = b"\x2a\x81\x76\x84\x05";

/// Seconds in a day.
const SECONDS_PER_DAY: u64 = 86_400;
/// How long an entry stays unseen.
pub const CARD_CERTIFICATE_RETENTION_SECONDS: u64 = CERTIFICATE_RETENTION_DAYS * SECONDS_PER_DAY;

/// Whether an entry with key `provider`, key `container` and certificate
/// `certificate` is FINEID's. See the module's description.
#[must_use]
pub fn is_fineid_entry(provider: &str, container: &str, certificate: &[u8]) -> bool {
    SMART_CARD_PROVIDERS.contains(&provider)
        && [FINEID_AUTHENTICATION_CONTAINER, FINEID_QUALIFIED_CONTAINER]
            .iter()
            .any(|name| name.eq_ignore_ascii_case(container))
        && certificate
            .windows(DVV_ARC_DER.len())
            .any(|window| window == DVV_ARC_DER)
}

/// What a sweep does with a FINEID entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryAction {
    /// Date it `now`: it has no date, its date lies ahead, or it is on a card
    /// in a reader.
    MarkSeen,
    /// Leave it and its date.
    Keep,
    /// It has not been seen for the retention: remove it.
    Remove,
}

/// What to do at `now`, in seconds, with an entry dated `seen` and which is
/// or is not on a card in a reader.
#[must_use]
pub const fn entry_action(seen: Option<u64>, now: u64, on_a_card: bool) -> EntryAction {
    if on_a_card {
        return EntryAction::MarkSeen;
    }
    match seen {
        None => EntryAction::MarkSeen,
        Some(seen) if seen > now => EntryAction::MarkSeen,
        Some(seen) if now - seen > CARD_CERTIFICATE_RETENTION_SECONDS => EntryAction::Remove,
        Some(_) => EntryAction::Keep,
    }
}

/// The certificate property holding when an entry was seen: the first
/// identifier an application may use.
#[cfg(windows)]
const SEEN_PROPERTY: u32 = windows_sys::Win32::Security::Cryptography::CERT_FIRST_USER_PROP_ID;

/// Sweeps the current user's Personal store at `now`, in seconds; `on_cards`
/// are the certificates on the cards in readers. Returns how many entries it
/// removed.
///
/// # Errors
/// A Windows certificate store failure.
#[cfg(windows)]
pub fn sweep_card_certificates(
    now: u64,
    on_cards: &[Vec<u8>],
) -> Result<usize, CredentialStoreError> {
    let store = PersonalStore::open()?;
    sweep_store(store.0, now, on_cards, &is_fineid_entry)
}

/// [`sweep_card_certificates`] over the open `store`, judging entries by
/// `is_fineid`.
#[cfg(windows)]
fn sweep_store(
    store: *mut core::ffi::c_void,
    now: u64,
    on_cards: &[Vec<u8>],
    is_fineid: &dyn Fn(&str, &str, &[u8]) -> bool,
) -> Result<usize, CredentialStoreError> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CertDeleteCertificateFromStore, CertDuplicateCertificateContext,
        CertEnumCertificatesInStore, CertFreeCertificateContext,
    };

    let mut removed = 0;
    let mut context: *const CERT_CONTEXT = core::ptr::null();
    loop {
        // SAFETY: `context` is null or the context the previous iteration
        // received from this same enumeration, which frees it.
        context = unsafe { CertEnumCertificatesInStore(store, context) };
        if context.is_null() {
            return Ok(removed);
        }
        let Some((provider, container)) = key_provider_info(context) else {
            continue;
        };
        // SAFETY: the context is live; its encoded certificate is
        // `cbCertEncoded` bytes at `pbCertEncoded`.
        let certificate = unsafe {
            core::slice::from_raw_parts((*context).pbCertEncoded, (*context).cbCertEncoded as usize)
        };
        if !is_fineid(&provider, &container, certificate) {
            continue;
        }
        let on_a_card = on_cards.iter().any(|der| der.as_slice() == certificate);
        match entry_action(read_seen(context), now, on_a_card) {
            EntryAction::Keep => {}
            EntryAction::MarkSeen => {
                // A date not written is written by a later sweep; the entry
                // only stays longer.
                let _written = write_seen(context, now);
            }
            EntryAction::Remove => {
                // SAFETY: deletion consumes a context of its own, so the
                // enumeration keeps the original and continues from it.
                let deleted = unsafe {
                    CertDeleteCertificateFromStore(CertDuplicateCertificateContext(context))
                };
                if deleted == 0 {
                    // SAFETY: read before any other Windows call; the
                    // enumeration context is ours to free once the loop ends.
                    let code = unsafe {
                        let code = GetLastError();
                        CertFreeCertificateContext(context);
                        code
                    };
                    return Err(CredentialStoreError::CertificateStore { code });
                }
                removed += 1;
            }
        }
    }
}

/// The key provider and container of an entry, or `None` when it has none.
#[cfg(windows)]
fn key_provider_info(
    context: *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
) -> Option<(String, String)> {
    use windows_sys::Win32::Security::Cryptography::{
        CERT_KEY_PROV_INFO_PROP_ID, CRYPT_KEY_PROV_INFO, CertGetCertificateContextProperty,
    };

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
        return None;
    }
    let mut buffer = vec![0u64; (size as usize).div_ceil(size_of::<u64>())];
    // SAFETY: `buffer` holds at least `size` bytes with the alignment the
    // structure needs; its string pointers point into the same buffer or are
    // null, and `wide_text` reads them within `size`.
    unsafe {
        if CertGetCertificateContextProperty(
            context,
            CERT_KEY_PROV_INFO_PROP_ID,
            buffer.as_mut_ptr().cast(),
            &raw mut size,
        ) == 0
        {
            return None;
        }
        let info = buffer
            .as_ptr()
            .cast::<CRYPT_KEY_PROV_INFO>()
            .read_unaligned();
        Some((
            wide_text(info.pwszProvName, size as usize),
            wide_text(info.pwszContainerName, size as usize),
        ))
    }
}

/// When the entry was seen, in seconds, as the last sweep wrote it.
#[cfg(windows)]
fn read_seen(
    context: *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
) -> Option<u64> {
    use windows_sys::Win32::Security::Cryptography::CertGetCertificateContextProperty;

    let mut bytes = [0u8; size_of::<u64>()];
    let mut size = u32::try_from(bytes.len()).ok()?;
    // SAFETY: `bytes` holds `size` bytes; a property of another size fails.
    let read = unsafe {
        CertGetCertificateContextProperty(
            context,
            SEEN_PROPERTY,
            bytes.as_mut_ptr().cast(),
            &raw mut size,
        )
    };
    (read != 0 && size as usize == bytes.len()).then(|| u64::from_le_bytes(bytes))
}

/// Dates the entry `now`, in seconds. Returns whether it was written.
#[cfg(windows)]
fn write_seen(
    context: *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
    now: u64,
) -> bool {
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CertSetCertificateContextProperty,
    };

    let mut bytes = now.to_le_bytes();
    let Ok(length) = u32::try_from(bytes.len()) else {
        return false;
    };
    let blob = CRYPT_INTEGER_BLOB {
        cbData: length,
        pbData: bytes.as_mut_ptr(),
    };
    // SAFETY: `blob` and `bytes` live for the call, which copies them.
    unsafe {
        CertSetCertificateContextProperty(context, SEEN_PROPERTY, 0, (&raw const blob).cast()) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A provider that is not a smart card's.
    const OTHER_PROVIDER: &str = "Microsoft Software Key Storage Provider";
    /// A container no FINEID card has.
    const OTHER_CONTAINER: &str = "{11111111-2222-3333-4444-555555555555}";
    /// The moment of a sweep.
    const NOW: u64 = 2_000_000_000;
    /// One second.
    const SECOND: u64 = 1;

    fn certificate_with_dvv_arc() -> Vec<u8> {
        let mut certificate = b"synthetic before ".to_vec();
        certificate.extend_from_slice(DVV_ARC_DER);
        certificate.extend_from_slice(b" synthetic after");
        certificate
    }

    #[test]
    fn a_fineid_entry_needs_provider_container_and_arc() {
        let fineid = certificate_with_dvv_arc();
        for provider in SMART_CARD_PROVIDERS {
            for container in [FINEID_AUTHENTICATION_CONTAINER, FINEID_QUALIFIED_CONTAINER] {
                assert!(is_fineid_entry(provider, container, &fineid));
            }
        }
        let provider = SMART_CARD_PROVIDERS[0];
        assert!(!is_fineid_entry(
            OTHER_PROVIDER,
            FINEID_QUALIFIED_CONTAINER,
            &fineid
        ));
        assert!(!is_fineid_entry(provider, OTHER_CONTAINER, &fineid));
        assert!(!is_fineid_entry(
            provider,
            FINEID_AUTHENTICATION_CONTAINER,
            b"another vendor's PIV card under the same container name"
        ));
    }

    #[test]
    fn an_entry_goes_only_past_the_retention() {
        let limit = NOW - CARD_CERTIFICATE_RETENTION_SECONDS;
        assert_eq!(entry_action(Some(limit), NOW, false), EntryAction::Keep);
        assert_eq!(
            entry_action(Some(limit - SECOND), NOW, false),
            EntryAction::Remove
        );
    }

    #[test]
    fn an_undated_future_or_present_entry_is_seen_now() {
        assert_eq!(entry_action(None, NOW, false), EntryAction::MarkSeen);
        assert_eq!(
            entry_action(Some(NOW + SECOND), NOW, false),
            EntryAction::MarkSeen
        );
        assert_eq!(entry_action(Some(0), NOW, true), EntryAction::MarkSeen);
    }

    #[cfg(windows)]
    mod store {
        use super::super::*;
        use super::NOW;
        use windows_sys::Win32::Security::Cryptography::{
            CERT_CLOSE_STORE_FORCE_FLAG, CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID,
            CERT_STORE_ADD_ALWAYS, CERT_STORE_PROV_MEMORY, CRYPT_KEY_PROV_INFO,
            CertAddEncodedCertificateToStore, CertCloseStore, CertEnumCertificatesInStore,
            CertFreeCertificateContext, CertOpenStore, CertSetCertificateContextProperty,
            PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        };

        /// A synthetic certificate standing in for a FINEID entry.
        const SWEPT: &[u8] = include_bytes!("../../refineid-rapp-cli/src/mock_cert.der");
        /// A synthetic certificate standing in for another vendor's.
        const OTHER: &[u8] = include_bytes!("../../refineid-rapp-cli/src/mock_ca.der");
        /// The provider both carry.
        const PROVIDER: &str = "Microsoft Base Smart Card Crypto Provider";
        /// The container of the entry the test sweeps.
        const SWEPT_CONTAINER: &str = FINEID_QUALIFIED_CONTAINER;
        /// The container of the entry it must leave.
        const OTHER_CONTAINER: &str = "{11111111-2222-3333-4444-555555555555}";

        fn wide(text: &str) -> Vec<u16> {
            text.encode_utf16().chain(core::iter::once(0)).collect()
        }

        fn add(store: *mut core::ffi::c_void, der: &[u8], container: &str) {
            let mut context: *mut CERT_CONTEXT = core::ptr::null_mut();
            let provider = wide(PROVIDER);
            let container = wide(container);
            // SAFETY: the store is open, `der` a certificate, and the
            // property's strings live for the calls, which copy them.
            unsafe {
                assert_ne!(
                    CertAddEncodedCertificateToStore(
                        store,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        der.as_ptr(),
                        u32::try_from(der.len()).expect("a small certificate"),
                        CERT_STORE_ADD_ALWAYS,
                        &raw mut context,
                    ),
                    0
                );
                let mut info: CRYPT_KEY_PROV_INFO = core::mem::zeroed();
                info.pwszContainerName = container.as_ptr().cast_mut();
                info.pwszProvName = provider.as_ptr().cast_mut();
                assert_ne!(
                    CertSetCertificateContextProperty(
                        context,
                        CERT_KEY_PROV_INFO_PROP_ID,
                        0,
                        (&raw const info).cast(),
                    ),
                    0
                );
                CertFreeCertificateContext(context);
            }
        }

        fn count(store: *mut core::ffi::c_void) -> usize {
            let mut seen = 0;
            let mut context: *const CERT_CONTEXT = core::ptr::null();
            loop {
                // SAFETY: the enumeration frees the context it is given.
                context = unsafe { CertEnumCertificatesInStore(store, context) };
                if context.is_null() {
                    return seen;
                }
                seen += 1;
            }
        }

        #[test]
        fn a_sweep_dates_then_removes_and_leaves_every_other_entry() {
            // SAFETY: an in-memory store with no parameter; closed below. The
            // user's own Personal store is never opened by this test.
            let store =
                unsafe { CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, core::ptr::null()) };
            assert!(!store.is_null());
            add(store, SWEPT, SWEPT_CONTAINER);
            add(store, OTHER, OTHER_CONTAINER);
            let is_fineid = |_: &str, container: &str, _: &[u8]| container == SWEPT_CONTAINER;
            let late = NOW + CARD_CERTIFICATE_RETENTION_SECONDS + 1;

            let run = |now, on_cards: &[Vec<u8>]| {
                sweep_store(store, now, on_cards, &is_fineid).expect("the sweep runs")
            };
            assert_eq!(run(NOW, &[]), 0, "the first sweep only dates it");
            assert_eq!(run(NOW, &[]), 0, "a fresh date keeps it");
            assert_eq!(
                run(late, &[SWEPT.to_vec()]),
                0,
                "on a card in a reader it is seen"
            );
            assert_eq!(count(store), 2);
            let later = late + CARD_CERTIFICATE_RETENTION_SECONDS + 1;
            assert_eq!(run(later, &[]), 1, "past the retention it goes");
            assert_eq!(count(store), 1, "the other entry stays");
            // SAFETY: closes the store opened above, once.
            unsafe { CertCloseStore(store, CERT_CLOSE_STORE_FORCE_FLAG) };
        }
    }
}
