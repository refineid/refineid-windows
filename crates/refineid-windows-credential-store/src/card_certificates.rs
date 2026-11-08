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
//! where Microsoft documents they remain when the card is removed. A FINEID
//! card's entries stand only while that card is in a reader of this
//! computer (Windows STPA W-R-22): the agent, started at every sign-in,
//! removes every entry whose card is not in a reader when it starts, and
//! again whenever a card leaves.
//!
//! An entry is FINEID's only when all three of these hold, and every other
//! entry is neither read further nor touched:
//!
//! - its key provider is one of Microsoft's two smart card providers;
//! - its container is one the Card Module names; the authentication
//!   container embeds a PIV tag Windows needs at a fixed offset, so that name
//!   alone could recur on another vendor's card;
//! - the certificate carries an object identifier of DVV's arc, which holds
//!   the production policies and the DVV TEST hierarchy's alike.
//!
//! A card is in a reader when the reader reports it present, and the
//! entries it holds are the certificates Windows reads from it through the
//! Card Module, which are the ones propagation wrote. A pass judges by one
//! reading of the readers, reads every card in them, and removes only when
//! a second reading of the readers, taken after the store was read, is the
//! same: a card that arrived or left in between makes it judge again. A card
//! the pass cannot read keeps every entry until a later pass reads it.

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
/// 1.2.246.517.1.10.351.1 (`http://www.fineid.fi/cps61/`), and the DVV TEST
/// hierarchy's lie under 1.2.246.517.99, as in the policy
/// 1.2.246.517.99.10.352.1 that `DVV TEST Certificates - G5E` certificates
/// carry. An opaque registered identifier, per X.690 section 8.19.
const DVV_ARC_DER: &[u8] = b"\x2a\x81\x76\x84\x05";

/// The bytes the Card Module puts before a card's authentication certificate
/// when it derives the card's identifier.
const CARD_ID_DOMAIN: &[u8] = b"refineid-card-id-v8-two-container-freshness";
/// The length of a card identifier: the minidriver specification's `cardid`
/// file holds a GUID.
pub const CARD_ID_BYTES: usize = 16;

/// The identifier the Card Module gives a card in its `cardid` file. Windows
/// records it with each root certificate the card propagated
/// ([`crate::card_roots`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardId([u8; CARD_ID_BYTES]);

impl CardId {
    /// The identifier of the card whose authentication certificate is
    /// `certificate`: the first [`CARD_ID_BYTES`] of the SHA-256 of
    /// the `refineid-card-id` domain string followed by the certificate.
    #[must_use]
    pub fn of_authentication_certificate(certificate: &[u8]) -> Self {
        let mut seeded = Vec::with_capacity(CARD_ID_DOMAIN.len() + certificate.len());
        seeded.extend_from_slice(CARD_ID_DOMAIN);
        seeded.extend_from_slice(certificate);
        let digest = refineid_lib_core::crypto::digest::Sha256::of(seeded);
        let mut identifier = [0; CARD_ID_BYTES];
        identifier.copy_from_slice(&digest.as_bytes()[..CARD_ID_BYTES]);
        Self(identifier)
    }

    /// An identifier read back from Windows.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CARD_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// The `cardid` file's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CARD_ID_BYTES] {
        &self.0
    }
}

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

/// A certificate's DER as a card holds it or the Personal store keeps it:
/// transit bytes, compared whole and never parsed here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardCertificate(Vec<u8>);

impl CardCertificate {
    /// The certificate whose DER is `der`.
    #[must_use]
    pub const fn new(der: Vec<u8>) -> Self {
        Self(der)
    }

    /// The certificate's DER.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A reader's name as PC/SC reports it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReaderName(String);

impl ReaderName {
    /// The reader PC/SC names `name`.
    #[must_use]
    pub const fn new(name: String) -> Self {
        Self(name)
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The answer to reset a reader reports for the card in it: transit bytes
/// handed to Windows' card database unread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerToReset(Vec<u8>);

impl AnswerToReset {
    /// The answer to reset whose bytes are `bytes`.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Its bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One reader, as one reading of the readers found it. Reading a reader's
/// state touches no card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderReading {
    /// The reader.
    pub name: ReaderName,
    /// How many card insertions and removals Windows has counted for the
    /// reader: the upper half of `dwEventState` that `SCardGetStatusChange`
    /// reports. A card that left and another that arrived between two
    /// readings change it although both readings see a card.
    pub card_events: u32,
    /// The card in the reader, by its answer to reset; `None` when the
    /// reader is empty.
    pub card: Option<AnswerToReset>,
}

/// One reading of every reader of this computer, in name order, so two
/// readings that saw the same are equal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadersReading(Vec<ReaderReading>);

impl ReadersReading {
    /// The reading of `readers`.
    #[must_use]
    pub fn new(mut readers: Vec<ReaderReading>) -> Self {
        readers.sort_by(|one, other| one.name.cmp(&other.name));
        Self(readers)
    }

    /// The readers, in name order.
    #[must_use]
    pub fn readers(&self) -> &[ReaderReading] {
        &self.0
    }
}

/// What reading a card's certificates gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardRead {
    /// The Card Module serves the card and Windows read these certificates
    /// from it.
    Certificates(Vec<CardCertificate>),
    /// The Card Module does not serve the card, so it holds no FINEID entry.
    NotServed,
    /// The card was not read: what it holds is not known.
    Unread,
}

/// The readers of this computer and the cards in them.
pub trait CardReaders {
    /// Reads every reader's state now, touching no card; `None` when the
    /// readers cannot be read.
    fn reading(&mut self) -> Option<ReadersReading>;

    /// Reads the certificates of the card whose answer to reset is `card`,
    /// in `reader`.
    fn certificates(&mut self, reader: &ReaderName, card: &AnswerToReset) -> CardRead;
}

/// The FINEID entries of a certificate store.
pub trait FineidEntries {
    /// A store failure.
    type Error;

    /// The certificate of every FINEID entry.
    ///
    /// # Errors
    /// The store cannot be read.
    fn certificates(&mut self) -> Result<Vec<CardCertificate>, Self::Error>;

    /// Removes every FINEID entry whose certificate is `certificate`, and
    /// returns how many it removed.
    ///
    /// # Errors
    /// The store refused a removal.
    fn remove(&mut self, certificate: &CardCertificate) -> Result<usize, Self::Error>;
}

/// How many times one pass judges before it leaves the decision to the
/// next: it judges again only when a card arrived or left while it judged.
pub const JUDGEMENTS_PER_PASS: usize = 3;

/// What a pass did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pass {
    /// It judged by `readers` and removed `removed` entries.
    Judged {
        /// The entries it removed.
        removed: usize,
        /// The reading it judged by.
        readers: ReadersReading,
    },
    /// It removed nothing and leaves the decision to a later pass: a card
    /// was not read, the readers were not, or cards kept arriving or
    /// leaving.
    Deferred {
        /// The last reading it took, if any.
        readers: Option<ReadersReading>,
    },
}

impl Pass {
    /// The last reading of the readers the pass took.
    #[must_use]
    pub const fn readers(&self) -> Option<&ReadersReading> {
        match self {
            Self::Judged { readers, .. } => Some(readers),
            Self::Deferred { readers } => readers.as_ref(),
        }
    }
}

/// Removes every FINEID entry of `entries` whose card is not in a reader
/// of `readers`. See the module's description.
///
/// # Errors
/// The store failed; entries removed before the failure stay removed.
pub fn remove_entries_of_absent_cards<R, S>(
    readers: &mut R,
    entries: &mut S,
) -> Result<Pass, S::Error>
where
    R: CardReaders + ?Sized,
    S: FineidEntries + ?Sized,
{
    let mut last = None;
    for _ in 0..JUDGEMENTS_PER_PASS {
        let Some(before) = readers.reading() else {
            return Ok(Pass::Deferred { readers: last });
        };
        let mut on_cards = Vec::new();
        for reader in before.readers() {
            let Some(card) = &reader.card else {
                continue;
            };
            match readers.certificates(&reader.name, card) {
                CardRead::Certificates(certificates) => on_cards.extend(certificates),
                CardRead::NotServed => {}
                CardRead::Unread => {
                    return Ok(Pass::Deferred {
                        readers: Some(before),
                    });
                }
            }
        }
        let absent: Vec<CardCertificate> = entries
            .certificates()?
            .into_iter()
            .filter(|certificate| !on_cards.contains(certificate))
            .collect();
        if absent.is_empty() {
            return Ok(Pass::Judged {
                removed: 0,
                readers: before,
            });
        }
        if readers.reading().as_ref() != Some(&before) {
            last = Some(before);
            continue;
        }
        let mut removed = 0;
        for certificate in &absent {
            removed += entries.remove(certificate)?;
        }
        return Ok(Pass::Judged {
            removed,
            readers: before,
        });
    }
    Ok(Pass::Deferred { readers: last })
}

/// The current user's Personal store, as its FINEID entries.
#[cfg(windows)]
pub struct PersonalCardEntries(PersonalStore);

#[cfg(windows)]
impl core::fmt::Debug for PersonalCardEntries {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PersonalCardEntries")
    }
}

#[cfg(windows)]
impl PersonalCardEntries {
    /// Opens the current user's Personal store.
    ///
    /// # Errors
    /// The store cannot be opened.
    pub fn open() -> Result<Self, CredentialStoreError> {
        PersonalStore::open().map(Self)
    }
}

#[cfg(windows)]
impl FineidEntries for PersonalCardEntries {
    type Error = CredentialStoreError;

    fn certificates(&mut self) -> Result<Vec<CardCertificate>, Self::Error> {
        Ok(fineid_certificates_in(self.0.0, &is_fineid_entry))
    }

    fn remove(&mut self, certificate: &CardCertificate) -> Result<usize, Self::Error> {
        remove_fineid_entries(self.0.0, &is_fineid_entry, certificate)
    }
}

/// An entry's certificate filter: provider, container, certificate.
#[cfg(windows)]
type EntryFilter = dyn Fn(&str, &str, &[u8]) -> bool;

/// Calls `visit` with each entry of the open `store` that `is_fineid`
/// accepts, and its certificate, until `visit` returns `false`.
#[cfg(windows)]
fn each_fineid_entry(
    store: *mut core::ffi::c_void,
    is_fineid: &EntryFilter,
    mut visit: impl FnMut(
        *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
        &[u8],
    ) -> bool,
) {
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CertEnumCertificatesInStore, CertFreeCertificateContext,
    };

    let mut context: *const CERT_CONTEXT = core::ptr::null();
    loop {
        // SAFETY: `context` is null or the context the previous iteration
        // received from this same enumeration, which frees it.
        context = unsafe { CertEnumCertificatesInStore(store, context) };
        if context.is_null() {
            return;
        }
        let Some((provider, container)) = key_provider_info(context) else {
            continue;
        };
        // SAFETY: the context is live; its encoded certificate is
        // `cbCertEncoded` bytes at `pbCertEncoded`, null only when empty.
        let certificate = unsafe {
            let encoded = (*context).pbCertEncoded;
            if encoded.is_null() {
                continue;
            }
            core::slice::from_raw_parts(encoded, (*context).cbCertEncoded as usize)
        };
        if is_fineid(&provider, &container, certificate) && !visit(context, certificate) {
            // SAFETY: the enumeration stops here, so its context is ours to
            // free.
            unsafe { CertFreeCertificateContext(context) };
            return;
        }
    }
}

/// The certificates of the FINEID entries of the open `store`.
#[cfg(windows)]
fn fineid_certificates_in(
    store: *mut core::ffi::c_void,
    is_fineid: &EntryFilter,
) -> Vec<CardCertificate> {
    let mut certificates = Vec::new();
    each_fineid_entry(store, is_fineid, |_, certificate| {
        certificates.push(CardCertificate::new(certificate.to_vec()));
        true
    });
    certificates
}

/// Removes the FINEID entries of the open `store` whose certificate is
/// `certificate`, and returns how many it removed.
#[cfg(windows)]
fn remove_fineid_entries(
    store: *mut core::ffi::c_void,
    is_fineid: &EntryFilter,
    certificate: &CardCertificate,
) -> Result<usize, CredentialStoreError> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{
        CertDeleteCertificateFromStore, CertDuplicateCertificateContext,
    };

    let mut removed = 0;
    let mut failure = None;
    each_fineid_entry(store, is_fineid, |context, der| {
        if der != certificate.as_bytes() {
            return true;
        }
        // SAFETY: deletion consumes a context of its own, so the enumeration
        // keeps the original and continues from it.
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

/// The key provider and container of an entry, or `None` when it has none.
#[cfg(windows)]
pub(crate) fn key_provider_info(
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    /// A provider that is not a smart card's.
    const OTHER_PROVIDER: &str = "Microsoft Software Key Storage Provider";
    /// A container no FINEID card has.
    const OTHER_CONTAINER: &str = "{11111111-2222-3333-4444-555555555555}";
    /// The DER body of 1.2.246.517.99.10.352.1, the policy of the
    /// `DVV TEST Certificates - G5E` CA's end-entity certificates, as such a
    /// certificate carries it (X.690 section 8.19).
    const DVV_TEST_POLICY_DER: &[u8] = b"\x2a\x81\x76\x84\x05\x63\x0a\x82\x60\x01";
    /// The DER body of 1.2.246.517.1.10.352.1, the policy of the
    /// `DVV Citizen Certificates - G4E` CA's end-entity certificates.
    const DVV_CITIZEN_POLICY_DER: &[u8] = b"\x2a\x81\x76\x84\x05\x01\x0a\x82\x60\x01";
    /// The reader of the tests.
    const READER: &str = "Synthetic Reader 0";
    /// A second reader.
    const OTHER_READER: &str = "Synthetic Reader 1";
    /// The card events a reader has counted when a test starts.
    const EVENTS: u32 = 4;
    /// One more card insertion or removal.
    const ONE_EVENT: u32 = 1;
    /// How many times one judgement reads the readers.
    const READINGS_PER_JUDGEMENT: usize = 2;

    fn certificate_with(policy: &[u8]) -> Vec<u8> {
        let mut certificate = b"synthetic before ".to_vec();
        certificate.extend_from_slice(policy);
        certificate.extend_from_slice(b" synthetic after");
        certificate
    }

    fn certificate(text: &str) -> CardCertificate {
        CardCertificate::new(text.as_bytes().to_vec())
    }

    fn atr(text: &str) -> AnswerToReset {
        AnswerToReset::new(text.as_bytes().to_vec())
    }

    fn reader(name: &str, card_events: u32, card: Option<&str>) -> ReaderReading {
        ReaderReading {
            name: ReaderName::new(name.to_owned()),
            card_events,
            card: card.map(atr),
        }
    }

    fn readers(list: Vec<ReaderReading>) -> ReadersReading {
        ReadersReading::new(list)
    }

    /// Readers whose readings follow `readings` (the last one repeats) and
    /// whose cards, by answer to reset, read as `cards`.
    struct FakeReaders {
        readings: VecDeque<Option<ReadersReading>>,
        cards: Vec<(AnswerToReset, CardRead)>,
    }

    impl FakeReaders {
        fn new<T: Into<Option<ReadersReading>>>(
            readings: Vec<T>,
            cards: Vec<(&str, CardRead)>,
        ) -> Self {
            Self {
                readings: readings.into_iter().map(Into::into).collect(),
                cards: cards
                    .into_iter()
                    .map(|(answer, read)| (atr(answer), read))
                    .collect(),
            }
        }
    }

    impl CardReaders for FakeReaders {
        fn reading(&mut self) -> Option<ReadersReading> {
            if self.readings.len() > 1 {
                self.readings.pop_front().flatten()
            } else {
                self.readings.front().cloned().flatten()
            }
        }

        fn certificates(&mut self, _reader: &ReaderName, card: &AnswerToReset) -> CardRead {
            self.cards
                .iter()
                .find(|(answer, _)| answer == card)
                .map_or(CardRead::Unread, |(_, read)| read.clone())
        }
    }

    /// A store holding FINEID entries only.
    #[derive(Default)]
    struct FakeStore {
        entries: Vec<CardCertificate>,
    }

    impl FineidEntries for FakeStore {
        type Error = ();

        fn certificates(&mut self) -> Result<Vec<CardCertificate>, ()> {
            Ok(self.entries.clone())
        }

        fn remove(&mut self, certificate: &CardCertificate) -> Result<usize, ()> {
            let before = self.entries.len();
            self.entries.retain(|entry| entry != certificate);
            Ok(before - self.entries.len())
        }
    }

    fn store(entries: &[&str]) -> FakeStore {
        FakeStore {
            entries: entries.iter().map(|text| certificate(text)).collect(),
        }
    }

    fn removed(pass: &Pass) -> Option<usize> {
        match pass {
            Pass::Judged { removed, .. } => Some(*removed),
            Pass::Deferred { .. } => None,
        }
    }

    #[test]
    fn a_fineid_entry_needs_provider_container_and_arc() {
        let fineid = certificate_with(DVV_ARC_DER);
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
    fn production_and_dvv_test_policies_are_both_fineid() {
        let provider = SMART_CARD_PROVIDERS[1];
        for policy in [DVV_CITIZEN_POLICY_DER, DVV_TEST_POLICY_DER] {
            assert!(is_fineid_entry(
                provider,
                FINEID_AUTHENTICATION_CONTAINER,
                &certificate_with(policy)
            ));
        }
    }

    #[test]
    fn a_card_in_a_reader_keeps_its_entries_and_an_absent_one_loses_them() {
        let mut readers = FakeReaders::new(
            vec![readers(vec![
                reader(READER, EVENTS, Some("present card")),
                reader(OTHER_READER, EVENTS, None),
            ])],
            vec![(
                "present card",
                CardRead::Certificates(vec![
                    certificate("present authentication"),
                    certificate("present signature"),
                ]),
            )],
        );
        let mut entries = store(&[
            "present authentication",
            "present signature",
            "absent authentication",
            "absent signature",
        ]);
        let pass = remove_entries_of_absent_cards(&mut readers, &mut entries);
        assert_eq!(pass.as_ref().map(removed), Ok(Some(2)));
        assert_eq!(
            entries.entries,
            vec![
                certificate("present authentication"),
                certificate("present signature")
            ]
        );
    }

    #[test]
    fn with_no_reader_every_entry_goes() {
        let mut readers = FakeReaders::new(vec![readers(Vec::new())], Vec::new());
        let mut entries = store(&["one card", "another card"]);
        let pass = remove_entries_of_absent_cards(&mut readers, &mut entries);
        assert_eq!(pass.as_ref().map(removed), Ok(Some(2)));
        assert!(entries.entries.is_empty());
    }

    #[test]
    fn a_card_the_module_does_not_serve_keeps_nothing() {
        let mut readers = FakeReaders::new(
            vec![readers(vec![reader(READER, EVENTS, Some("bank card"))])],
            vec![("bank card", CardRead::NotServed)],
        );
        let mut entries = store(&["absent card"]);
        let pass = remove_entries_of_absent_cards(&mut readers, &mut entries);
        assert_eq!(pass.as_ref().map(removed), Ok(Some(1)));
        assert!(entries.entries.is_empty());
    }

    #[test]
    fn a_card_not_read_keeps_every_entry() {
        let mut readers = FakeReaders::new(
            vec![readers(vec![
                reader(READER, EVENTS, Some("busy card")),
                reader(OTHER_READER, EVENTS, Some("present card")),
            ])],
            vec![
                ("busy card", CardRead::Unread),
                (
                    "present card",
                    CardRead::Certificates(vec![certificate("present")]),
                ),
            ],
        );
        let mut entries = store(&["present", "absent"]);
        let pass = remove_entries_of_absent_cards(&mut readers, &mut entries);
        assert_eq!(pass.as_ref().map(removed), Ok(None));
        assert_eq!(entries.entries.len(), 2);
    }

    #[test]
    fn readers_not_read_keep_every_entry() {
        let mut readers = FakeReaders::new(vec![None::<ReadersReading>], Vec::new());
        let mut entries = store(&["absent"]);
        let pass = remove_entries_of_absent_cards(&mut readers, &mut entries);
        assert_eq!(pass, Ok(Pass::Deferred { readers: None }));
        assert_eq!(entries.entries.len(), 1);
    }

    #[test]
    fn a_card_inserted_while_the_pass_judges_keeps_its_entry() {
        // The first reading sees an empty reader; the card arrives, and
        // propagation has written its entry, before the second reading.
        let empty = readers(vec![reader(READER, EVENTS, None)]);
        let inserted = readers(vec![reader(READER, EVENTS + ONE_EVENT, Some("card"))]);
        let mut readers = FakeReaders::new(
            vec![empty, inserted],
            vec![("card", CardRead::Certificates(vec![certificate("card")]))],
        );
        let mut entries = store(&["card"]);
        let pass = remove_entries_of_absent_cards(&mut readers, &mut entries);
        assert_eq!(pass.as_ref().map(removed), Ok(Some(0)));
        assert_eq!(entries.entries, vec![certificate("card")]);
    }

    #[test]
    fn a_card_swapped_between_readings_is_judged_again() {
        // Both readings see a card in the reader, but its count moved: one
        // card left and another arrived.
        let first = readers(vec![reader(READER, EVENTS, Some("first card"))]);
        let swapped = readers(vec![reader(
            READER,
            EVENTS + ONE_EVENT + ONE_EVENT,
            Some("second card"),
        )]);
        let mut readers = FakeReaders::new(
            vec![first, swapped],
            vec![
                (
                    "first card",
                    CardRead::Certificates(vec![certificate("first")]),
                ),
                (
                    "second card",
                    CardRead::Certificates(vec![certificate("second")]),
                ),
            ],
        );
        let mut entries = store(&["first", "second"]);
        let pass = remove_entries_of_absent_cards(&mut readers, &mut entries);
        assert_eq!(pass.as_ref().map(removed), Ok(Some(1)));
        assert_eq!(entries.entries, vec![certificate("second")]);
    }

    #[test]
    fn readers_that_keep_changing_defer_the_removal() {
        // Each judgement reads the readers twice, and every reading differs.
        let readings = (0..=READINGS_PER_JUDGEMENT * JUDGEMENTS_PER_PASS)
            .map(|step| {
                let step = u32::try_from(step).expect("a few steps");
                readers(vec![reader(READER, EVENTS + step, None)])
            })
            .collect();
        let mut readers = FakeReaders::new(readings, Vec::new());
        let mut entries = store(&["absent"]);
        let pass = remove_entries_of_absent_cards(&mut readers, &mut entries);
        assert_eq!(pass.as_ref().map(removed), Ok(None));
        assert_eq!(entries.entries.len(), 1);
    }

    #[test]
    fn an_entry_propagation_writes_again_stays_while_its_card_is_present() {
        let mut entries = store(&["card"]);
        let mut absent = FakeReaders::new(
            vec![readers(vec![reader(READER, EVENTS, None)])],
            Vec::new(),
        );
        let pass = remove_entries_of_absent_cards(&mut absent, &mut entries);
        assert_eq!(pass.as_ref().map(removed), Ok(Some(1)));

        // The card is inserted again and propagation writes its entry anew.
        entries.entries.push(certificate("card"));
        let mut present = FakeReaders::new(
            vec![readers(vec![reader(
                READER,
                EVENTS + ONE_EVENT,
                Some("card"),
            )])],
            vec![("card", CardRead::Certificates(vec![certificate("card")]))],
        );
        let pass = remove_entries_of_absent_cards(&mut present, &mut entries);
        assert_eq!(pass.as_ref().map(removed), Ok(Some(0)));
        assert_eq!(entries.entries, vec![certificate("card")]);
    }

    #[test]
    fn readings_compare_in_name_order() {
        let one = ReadersReading::new(vec![
            reader(READER, EVENTS, None),
            reader(OTHER_READER, EVENTS, Some("card")),
        ]);
        let other = ReadersReading::new(vec![
            reader(OTHER_READER, EVENTS, Some("card")),
            reader(READER, EVENTS, None),
        ]);
        assert_eq!(one, other);
    }

    #[cfg(windows)]
    mod store {
        use super::super::*;
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
        /// The container of the entry the test removes.
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
        fn only_the_fineid_entry_with_the_certificate_goes() {
            // SAFETY: an in-memory store with no parameter; closed below. The
            // user's own Personal store is never opened by this test.
            let store =
                unsafe { CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, core::ptr::null()) };
            assert!(!store.is_null());
            add(store, SWEPT, SWEPT_CONTAINER);
            add(store, OTHER, OTHER_CONTAINER);
            let is_fineid = |_: &str, container: &str, _: &[u8]| container == SWEPT_CONTAINER;

            let swept = CardCertificate::new(SWEPT.to_vec());
            assert_eq!(
                fineid_certificates_in(store, &is_fineid),
                vec![swept.clone()]
            );
            let other = CardCertificate::new(OTHER.to_vec());
            assert_eq!(
                remove_fineid_entries(store, &is_fineid, &other).expect("the store answers"),
                0,
                "another vendor's entry is not FINEID's"
            );
            assert_eq!(
                remove_fineid_entries(store, &is_fineid, &swept).expect("the store answers"),
                1
            );
            assert_eq!(count(store), 1, "the other entry stays");
            assert!(fineid_certificates_in(store, &is_fineid).is_empty());
            // SAFETY: closes the store opened above, once.
            unsafe { CertCloseStore(store, CERT_CLOSE_STORE_FORCE_FLAG) };
        }
    }
}
