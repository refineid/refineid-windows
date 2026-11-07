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

//! The login sweep (Windows STPA W-R-21, W-R-22): at every sign-in, what a
//! computer keeps of a holder is held to its bounds even when no other
//! `RefineID` process would run. It loads the protected pairing set, checks
//! idle expiry when no agent holds a session, removes physical cards' FINEID
//! certificates not seen for the retention, and exits. It shows nothing.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    sweep::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the RefineID login sweep runs on Windows only");
}

#[cfg(windows)]
mod sweep {
    use std::time::{SystemTime, UNIX_EPOCH};

    use refineid_agent_pipe::PipeError;
    use refineid_agent_pipe::server::AgentLock;
    use refineid_pcsc::{PcscBackend, ReaderAccessCap, ReaderBackend as _};
    use refineid_pkcs15::fs::{CertSlot, Pkcs15Ops as _};
    use refineid_rapp_core::clock::unix_time_ms;
    use refineid_rapp_core::store::sweep_pairings;
    use refineid_windows_credential_store::ProtectedPairingStore;
    use refineid_windows_credential_store::card_certificates::sweep_card_certificates;

    /// The slots of the certificates propagation copies from a card.
    const HOLDER_SLOTS: [CertSlot; 4] = [
        CertSlot::Authentication,
        CertSlot::Signature,
        CertSlot::AuthenticationAlt,
        CertSlot::SignatureAlt,
    ];

    /// Runs the sweep once.
    pub fn run() {
        sweep_pairing_set();
        sweep_cards();
    }

    /// Loading the set applies W-R-21. An agent running now checks idle
    /// expiry itself, knowing which session it holds.
    fn sweep_pairing_set() {
        let lock = AgentLock::acquire();
        let mut store = match ProtectedPairingStore::load() {
            Ok(store) => store,
            Err(error) => {
                refineid_dev_errors::report!(Agent, "pairing store not loaded", error);
                return;
            }
        };
        match lock {
            Ok(_held_for_the_check) => {
                let _expired = sweep_pairings(&mut store, unix_time_ms(), |_| false);
            }
            Err(PipeError::AgentRunning) => {}
            Err(error) => refineid_dev_errors::report!(Agent, "agent lock not read", error),
        }
    }

    fn sweep_cards() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        if let Err(error) = sweep_card_certificates(now, &certificates_on_cards()) {
            refineid_dev_errors::report!(Agent, "card certificates not swept", error);
        }
    }

    /// The holder certificates on the cards in readers, read without a
    /// credential. A reader that does not answer holds none here; a sweep
    /// then dates by the store alone.
    fn certificates_on_cards() -> Vec<Vec<u8>> {
        let backend = PcscBackend;
        let Ok(readers) = backend.enumerate() else {
            return Vec::new();
        };
        let mut certificates = Vec::new();
        for reader in readers.iter().filter(|reader| reader.card_present) {
            let Ok(mut card) = backend.open_session(&reader.id, ReaderAccessCap::Read) else {
                continue;
            };
            if card.select_pkcs15_application().is_err() {
                continue;
            }
            certificates.extend(
                HOLDER_SLOTS
                    .iter()
                    .filter_map(|slot| card.read_certificate(*slot).ok())
                    .map(|certificate| certificate.as_bytes().to_vec()),
            );
        }
        certificates
    }
}
