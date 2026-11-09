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

//! Read-only hardware acceptance for ATR parsing and FINEID classification.

use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend as _};
use refineid_lib_core::fineid_card::FineidCardModel;
use refineid_lib_core::transport::CardTransport as _;
use refineid_lib_pcsc::PcscBackend;

#[test]
#[ignore = "requires a FINEID card and reader"]
fn present_fineid_card_atr_is_parsed_and_classified() {
    let backend = PcscBackend;
    let readers = backend
        .enumerate()
        .unwrap_or_else(|_| panic!("reader enumeration failed"));
    let mut recognized = false;
    for reader in readers.into_iter().filter(|reader| reader.card_present) {
        let card = backend
            .open_session(&reader.id, ReaderAccessCap::Read)
            .unwrap_or_else(|_| panic!("card connection failed"));
        let atr = card.atr().unwrap_or_else(|_| panic!("ATR parsing failed"));
        if FineidCardModel::from_atr(&atr).is_ok() {
            recognized = true;
        }
    }
    assert!(recognized, "no recognized FINEID card present");
}
