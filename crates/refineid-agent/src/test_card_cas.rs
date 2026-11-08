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

//! A development build's presentation of DVV test cards' CA certificates
//! (Windows STPA W-R-26): after every pass of the card watch, the user's
//! CA store holds the test CAs of the cards in readers and none of a card
//! that left (`refineid-windows-credential-store` `test_card_cas`).
//! Release builds do not compile this module.

use refineid_pcsc::{PcscBackend, ReaderAccessCap, ReaderBackend as _};
use refineid_pkcs15::UnvalidatedCertificate;
use refineid_pkcs15::fs::{CertSlot, Pkcs15Ops as _};
use refineid_windows_credential_store::test_card_cas::{TestCardCas, present_test_card_cas};

/// Reads the root and issuing CA of every card in a reader, without a
/// credential, and presents those of the test cards.
pub fn present() {
    let backend = PcscBackend;
    let mut present = Vec::new();
    if let Ok(readers) = backend.enumerate() {
        for reader in readers.iter().filter(|reader| reader.card_present) {
            let Ok(mut card) = backend.open_session(&reader.id, ReaderAccessCap::Read) else {
                continue;
            };
            if card.select_pkcs15_application().is_err() {
                continue;
            }
            let Ok(root) = card.read_certificate(CertSlot::RootCa) else {
                continue;
            };
            let issuing = card.read_certificate(CertSlot::IssuingCaEcc).ok();
            present.extend(TestCardCas::from_card(
                root.as_bytes(),
                issuing.as_ref().map(UnvalidatedCertificate::as_bytes),
            ));
        }
    }
    if let Err(error) = present_test_card_cas(&present) {
        refineid_dev_errors::report!(Agent, "test card CAs not presented", error);
    }
}
