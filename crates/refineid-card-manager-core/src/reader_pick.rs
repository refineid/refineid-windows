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

//! FINEID and contactless (PACE-first) reader selection over [`refineid_pcsc`].

use refineid_cms::x509::Certificate;
use refineid_pace::read_card_access;
use refineid_pcsc::{
    ReaderAccessCap, ReaderBackend, ReaderFilter, ReaderId, ReaderInfo, ReaderPickError,
};
use refineid_pkcs15::{
    CertSlot as CoreCertSlot, Pkcs15Ops as _, derive_printed_serial, render_token_serial,
};

use crate::card_pin::CredentialIdentity;

/// Output of [`pick_fineid_reader`]: a reader plus the best-effort identity of
/// the card currently inserted in it.
#[derive(Debug, Clone)]
pub struct FineidReaderPick {
    /// PC/SC reader id of the matched reader.
    pub reader_id: ReaderId,
    /// Credential identity captured at pick time.
    pub identity: CredentialIdentity,
}

/// Extract a [`CredentialIdentity`] from a parsed X.509 certificate's subject.
#[must_use]
pub fn identity_from_certificate(certificate: &Certificate<'_>) -> CredentialIdentity {
    CredentialIdentity::from_subject(certificate.subject.subject_identity())
}

/// Pick exactly one FINEID-responding reader, enforcing multi-card safety.
///
/// Probes every card-present reader with `SELECT PKCS#15` + `EF.TokenInfo` so
/// non-FINEID tokens are skipped before ambiguity checks.
///
/// # Errors
/// Returns [`ReaderPickError`] when no readers, no cards, no FINEID cards, or
/// ambiguous / unmatched readers are found.
pub fn pick_fineid_reader<B: ReaderBackend>(
    backend: &B,
    filter: Option<&ReaderFilter>,
) -> Result<FineidReaderPick, ReaderPickError>
where
    B::Error: core::fmt::Display,
{
    let readers = backend
        .enumerate()
        .map_err(|_backend_err| ReaderPickError::NoReaders)?;
    if readers.is_empty() {
        return Err(ReaderPickError::NoReaders);
    }
    let present: Vec<ReaderInfo> = readers.into_iter().filter(|r| r.card_present).collect();
    if present.is_empty() {
        return Err(ReaderPickError::NoCardPresent);
    }

    let mut all_names: Vec<String> = Vec::with_capacity(present.len());
    let mut probed: Vec<(ReaderInfo, CredentialIdentity)> = Vec::with_capacity(present.len());
    for info in &present {
        all_names.push(info.id.as_str().to_owned());
        if let Some(identity) = probe_fineid_identity(backend, &info.id) {
            probed.push((info.clone(), identity));
        }
    }

    if probed.is_empty() {
        return Err(ReaderPickError::NoFineidCard {
            available: all_names,
        });
    }

    let matched: Vec<&(ReaderInfo, CredentialIdentity)> = filter.map_or_else(
        || probed.iter().collect(),
        |f| {
            let needle = f.as_str();
            probed
                .iter()
                .filter(|(r, _)| r.id.as_str().contains(needle))
                .collect()
        },
    );

    let winner = match (filter, matched.as_slice()) {
        (_, [single]) => *single,
        (Some(f), []) => {
            return Err(ReaderPickError::NoMatchingReader {
                filter: f.as_str().to_owned(),
                available: probed
                    .iter()
                    .map(|(r, _)| r.id.as_str().to_owned())
                    .collect(),
            });
        }
        (Some(f), many) => {
            return Err(ReaderPickError::AmbiguousFilter {
                filter: f.as_str().to_owned(),
                matched: many.iter().map(|(r, _)| r.id.as_str().to_owned()).collect(),
            });
        }
        (None, many) => {
            return Err(ReaderPickError::MultipleReadersNoFilter {
                available: many.iter().map(|(r, _)| r.id.as_str().to_owned()).collect(),
            });
        }
    };

    Ok(FineidReaderPick {
        reader_id: winner.0.id.clone(),
        identity: winner.1.clone(),
    })
}

/// Probe a single reader by opening + `SELECT PKCS#15` + `EF.TokenInfo` +
/// best-effort auth-cert read.
fn probe_fineid_identity<B: ReaderBackend>(
    backend: &B,
    reader_id: &ReaderId,
) -> Option<CredentialIdentity>
where
    B::Error: core::fmt::Display,
{
    let mut transport = backend
        .open_exclusive(reader_id, ReaderAccessCap::Read)
        .ok()?;
    let token = transport.read_token_info().ok()?;
    let serial_hex = token.serial_number_hex()?.clone();
    let token_full = render_token_serial(serial_hex);
    let printed_serial = derive_printed_serial(&token_full);

    let mut identity = transport
        .read_certificate(CoreCertSlot::Authentication)
        .ok()
        .and_then(|der| {
            Certificate::from_der(der.as_bytes())
                .ok()
                .map(|cert| identity_from_certificate(&cert))
        })
        .unwrap_or_default();
    if let Some(serial) = printed_serial {
        identity = identity.with_printed_serial(serial);
    }
    Some(identity)
}

/// Probe a single reader for a card that serves `EF.CardAccess` pre-PACE.
fn probe_card_access<B: ReaderBackend>(backend: &B, reader_id: &ReaderId) -> bool
where
    B::Error: core::fmt::Display,
{
    let Ok(mut transport) = backend.open_exclusive(reader_id, ReaderAccessCap::Read) else {
        return false;
    };
    if transport.select_mf().is_err() {
        return false;
    }
    read_card_access(&mut transport).is_ok()
}

/// Pick exactly one contactless (PACE-capable) reader serving `EF.CardAccess`.
///
/// # Errors
/// Returns [`ReaderPickError`] when no readers, no cards, no `EF.CardAccess`
/// cards, or ambiguous / unmatched readers are found.
pub fn pick_contactless_reader<B: ReaderBackend>(
    backend: &B,
    filter: Option<&ReaderFilter>,
) -> Result<ReaderId, ReaderPickError>
where
    B::Error: core::fmt::Display,
{
    let readers = backend
        .enumerate()
        .map_err(|_backend_err| ReaderPickError::NoReaders)?;
    if readers.is_empty() {
        return Err(ReaderPickError::NoReaders);
    }
    let present: Vec<ReaderInfo> = readers.into_iter().filter(|r| r.card_present).collect();
    if present.is_empty() {
        return Err(ReaderPickError::NoCardPresent);
    }

    let mut all_names: Vec<String> = Vec::with_capacity(present.len());
    let mut candidates: Vec<&ReaderInfo> = Vec::with_capacity(present.len());
    for info in &present {
        all_names.push(info.id.as_str().to_owned());
        if probe_card_access(backend, &info.id) {
            candidates.push(info);
        }
    }
    if candidates.is_empty() {
        return Err(ReaderPickError::NoFineidCard {
            available: all_names,
        });
    }

    let matched: Vec<&ReaderInfo> = filter.map_or_else(
        || candidates.clone(),
        |f| {
            let needle = f.as_str();
            candidates
                .iter()
                .copied()
                .filter(|r| r.id.as_str().contains(needle))
                .collect()
        },
    );

    match (filter, matched.as_slice()) {
        (_, [single]) => Ok(single.id.clone()),
        (Some(f), []) => Err(ReaderPickError::NoMatchingReader {
            filter: f.as_str().to_owned(),
            available: candidates
                .iter()
                .map(|r| r.id.as_str().to_owned())
                .collect(),
        }),
        (Some(f), many) => Err(ReaderPickError::AmbiguousFilter {
            filter: f.as_str().to_owned(),
            matched: many.iter().map(|r| r.id.as_str().to_owned()).collect(),
        }),
        (None, many) => Err(ReaderPickError::MultipleReadersNoFilter {
            available: many.iter().map(|r| r.id.as_str().to_owned()).collect(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use const_oid::ObjectIdentifier;
    use refineid_apdu::iso7816::{
        ReadBinary, SelectByAidNoFci, SelectEfNoFci, SelectFile, SelectFileResponseMode,
        SelectFileTarget,
    };
    use refineid_apdu::{
        Aid, ApduClass, CardTransport, CommandApdu, CredentialCommand, FileId, ResponseApdu,
        StatusWord, TransportOutcome,
    };
    use refineid_ber::{BerEncoder, BerTag, Integer, OctetString, Oid, Sequence, Set};
    use refineid_pace::{EF_CARD_ACCESS_FID, PaceDomain};
    use refineid_pcsc::{
        ReaderAccessCap, ReaderBackend, ReaderFilter, ReaderId, ReaderInfo, ReaderPickError,
    };
    use refineid_pkcs15::{EF_AUTH_CERT_FID, EF_TOKEN_INFO_FID, PKCS15_AID};

    use super::{pick_contactless_reader, pick_fineid_reader};
    use crate::test_util::{TestResult, check_true};

    /// `id-PACE-ECDH-GM-AES-CBC-CMAC-256` (BSI TR-03110-3 section A.1.1.1).
    const PACE_ECDH_GM_AES_256_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("0.4.0.127.0.7.2.2.4.2.4");
    /// `PACEInfo` protocol version 2 (BSI TR-03110-3 section A.1.1.1).
    const PACE_INFO_VERSION_TWO: u8 = 2;
    /// Synthetic PKCS#15 `TokenInfo.version` (`0`).
    const TOKEN_INFO_VERSION: u8 = 0;
    /// Synthetic token serial bytes for `EF.TokenInfo`.
    const TEST_TOKEN_SERIAL_BYTES: &[u8] = b"1234567890";
    /// Initial card-event counter in synthetic `ReaderInfo` entries.
    const INITIAL_CARD_EVENTS: u32 = 0;
    /// Offset of the INS byte in a command APDU.
    const INS_INDEX: usize = 1;
    /// Expected number of matched readers in the ambiguity test.
    const TWO_READERS: usize = 2;

    enum ExpectedStep {
        Exact {
            command: CommandApdu,
            response: ResponseApdu,
        },
        AnyReadBinary {
            response: ResponseApdu,
        },
    }

    struct ScriptedTransport {
        steps: Vec<ExpectedStep>,
        cursor: usize,
    }

    impl ScriptedTransport {
        const fn new(steps: Vec<ExpectedStep>) -> Self {
            Self { steps, cursor: 0 }
        }
    }

    impl CardTransport for ScriptedTransport {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let step = self
                .steps
                .get(self.cursor)
                .ok_or_else(|| format!("script exhausted at step {}", self.cursor))?;
            let response = match step {
                ExpectedStep::Exact {
                    command: expected,
                    response,
                } => {
                    if expected.as_bytes() != command.as_bytes() {
                        return Err(format!(
                            "step {}: unexpected APDU (got {} bytes, expected {} bytes)",
                            self.cursor,
                            command.as_bytes().len(),
                            expected.as_bytes().len(),
                        ));
                    }
                    response.clone()
                }
                ExpectedStep::AnyReadBinary { response } => {
                    if command.as_bytes().get(INS_INDEX).copied() != Some(ReadBinary::INS) {
                        return Err(format!("step {}: expected READ BINARY", self.cursor));
                    }
                    response.clone()
                }
            };
            self.cursor += 1;
            Ok(TransportOutcome::Response(response))
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("reader picker must never transmit credentials".to_owned())
        }
    }

    type ReaderScriptFactory = fn() -> Vec<ExpectedStep>;

    struct ScriptedBackend {
        readers: Vec<(ReaderInfo, ReaderScriptFactory)>,
    }

    impl ReaderBackend for ScriptedBackend {
        type Transport = ScriptedTransport;
        type Error = String;

        fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error> {
            Ok(self.readers.iter().map(|(info, _)| info.clone()).collect())
        }

        fn card_events(&self, _reader: &ReaderId) -> Result<u32, Self::Error> {
            Ok(INITIAL_CARD_EVENTS)
        }

        fn open_exclusive(
            &self,
            reader: &ReaderId,
            access: ReaderAccessCap,
        ) -> Result<Self::Transport, Self::Error> {
            if access != ReaderAccessCap::Read {
                return Err("reader picker must open read-only sessions".to_owned());
            }
            self.readers
                .iter()
                .find(|(info, _)| info.id == *reader)
                .map(|(_, factory)| ScriptedTransport::new(factory()))
                .ok_or_else(|| format!("no script for reader {}", reader.as_str()))
        }
    }

    fn response(body: Vec<u8>, status: StatusWord) -> ResponseApdu {
        let [sw1, sw2] = status.as_u16().to_be_bytes();
        ResponseApdu { body, sw1, sw2 }
    }

    fn ok(body: Vec<u8>) -> ResponseApdu {
        response(body, StatusWord::Success)
    }

    fn sw_only(status: StatusWord) -> ResponseApdu {
        response(Vec::new(), status)
    }

    fn present(name: &str) -> ReaderInfo {
        ReaderInfo {
            id: ReaderId::new(name.to_owned()),
            card_present: true,
            card_events: INITIAL_CARD_EVENTS,
        }
    }

    fn tag_byte(marker: u16) -> u8 {
        u8::try_from(marker).unwrap_or_default()
    }

    fn select_mf_any() -> CommandApdu {
        SelectFile {
            class: ApduClass::Plain,
            target: SelectFileTarget::AnyByFileId(Some(FileId::MF)),
            response_mode: SelectFileResponseMode::None,
        }
        .into_apdu()
    }

    fn select_mf_by_name() -> CommandApdu {
        Aid::from_slice(FileId::MF.as_bytes())
            .or_else(|_| Aid::from_slice(PKCS15_AID))
            .map_or_else(
                |_| select_mf_any(),
                |aid| SelectByAidNoFci { aid }.into_apdu(),
            )
    }

    fn select_pkcs15_aid() -> CommandApdu {
        Aid::from_slice(PKCS15_AID).map_or_else(
            |_| select_mf_any(),
            |aid| SelectByAidNoFci { aid }.into_apdu(),
        )
    }

    fn select_ef(fid: FileId) -> CommandApdu {
        SelectEfNoFci { fid }.into_apdu()
    }

    fn encoded_card_access() -> Vec<u8> {
        let mut pace_info = BerEncoder::default();
        let _ = pace_info.push_tlv(
            tag_byte(<Oid as BerTag>::TAG),
            PACE_ECDH_GM_AES_256_OID.as_bytes(),
        );
        let _ = pace_info.push_tlv(tag_byte(<Integer as BerTag>::TAG), [PACE_INFO_VERSION_TWO]);
        let _ = pace_info.push_tlv(
            tag_byte(<Integer as BerTag>::TAG),
            [PaceDomain::BrainpoolP384r1.parameter_id()],
        );
        let mut seq = BerEncoder::default();
        let _ = seq.push_tlv(tag_byte(<Sequence as BerTag>::TAG), pace_info.finish());
        let mut set = BerEncoder::default();
        let _ = set.push_tlv(tag_byte(<Set as BerTag>::TAG), seq.finish());
        set.finish()
    }

    fn encoded_token_info() -> Vec<u8> {
        let mut fields = BerEncoder::default();
        let _ = fields.push_tlv(tag_byte(<Integer as BerTag>::TAG), [TOKEN_INFO_VERSION]);
        let _ = fields.push_tlv(
            tag_byte(<OctetString as BerTag>::TAG),
            TEST_TOKEN_SERIAL_BYTES,
        );
        let mut seq = BerEncoder::default();
        let _ = seq.push_tlv(tag_byte(<Sequence as BerTag>::TAG), fields.finish());
        seq.finish()
    }

    fn card_access_script() -> Vec<ExpectedStep> {
        vec![
            ExpectedStep::Exact {
                command: select_mf_any(),
                response: ok(Vec::new()),
            },
            ExpectedStep::Exact {
                command: select_ef(FileId::from_u16(EF_CARD_ACCESS_FID)),
                response: ok(Vec::new()),
            },
            ExpectedStep::AnyReadBinary {
                response: ok(encoded_card_access()),
            },
        ]
    }

    fn refusing_mf_script() -> Vec<ExpectedStep> {
        vec![
            ExpectedStep::Exact {
                command: select_mf_any(),
                response: sw_only(StatusWord::FileNotFound),
            },
            ExpectedStep::Exact {
                command: select_mf_by_name(),
                response: sw_only(StatusWord::FileNotFound),
            },
        ]
    }

    fn non_fineid_script() -> Vec<ExpectedStep> {
        vec![ExpectedStep::Exact {
            command: select_pkcs15_aid(),
            response: sw_only(StatusWord::FileNotFound),
        }]
    }

    fn fineid_token_info_only_script() -> Vec<ExpectedStep> {
        vec![
            ExpectedStep::Exact {
                command: select_pkcs15_aid(),
                response: ok(Vec::new()),
            },
            ExpectedStep::Exact {
                command: select_ef(EF_TOKEN_INFO_FID),
                response: ok(Vec::new()),
            },
            ExpectedStep::AnyReadBinary {
                response: ok(encoded_token_info()),
            },
            // Best-effort auth cert read: absent cert still counts as FINEID.
            ExpectedStep::Exact {
                command: select_pkcs15_aid(),
                response: ok(Vec::new()),
            },
            ExpectedStep::Exact {
                command: select_ef(EF_AUTH_CERT_FID),
                response: sw_only(StatusWord::FileNotFound),
            },
            ExpectedStep::Exact {
                command: SelectFile {
                    class: ApduClass::Plain,
                    target: SelectFileTarget::AnyByFileId(Some(EF_AUTH_CERT_FID)),
                    response_mode: SelectFileResponseMode::None,
                }
                .into_apdu(),
                response: sw_only(StatusWord::FileNotFound),
            },
        ]
    }

    #[test]
    fn contactless_pick_selects_the_card_access_server() -> TestResult {
        let backend = ScriptedBackend {
            readers: vec![
                (present("Dual Reader SAM"), refusing_mf_script),
                (present("Dual Reader PICC"), card_access_script),
            ],
        };
        let id = pick_contactless_reader(&backend, None)?;
        check_true(id.as_str() == "Dual Reader PICC", "picks the PICC reader")
    }

    #[test]
    fn contactless_pick_without_servers_is_no_fineid_card() -> TestResult {
        let backend = ScriptedBackend {
            readers: vec![(present("Dual Reader SAM"), refusing_mf_script)],
        };
        check_true(
            matches!(
                pick_contactless_reader(&backend, None),
                Err(ReaderPickError::NoFineidCard { available }) if available == ["Dual Reader SAM"]
            ),
            "reports NoFineidCard when no reader serves EF.CardAccess",
        )
    }

    #[test]
    fn contactless_pick_ambiguity_follows_the_contact_rules() -> TestResult {
        let backend = ScriptedBackend {
            readers: vec![
                (present("Reader A PICC"), card_access_script),
                (present("Reader B PICC"), card_access_script),
            ],
        };
        check_true(
            matches!(
                pick_contactless_reader(&backend, None),
                Err(ReaderPickError::MultipleReadersNoFilter { available })
                    if available.len() == TWO_READERS
            ),
            "multiple contactless readers require a filter",
        )?;
        let filter = ReaderFilter::new("B PICC");
        let id = pick_contactless_reader(&backend, Some(&filter))?;
        check_true(id.as_str() == "Reader B PICC", "filter disambiguates")
    }

    #[test]
    fn fineid_pick_skips_non_fineid_tokens() -> TestResult {
        let backend = ScriptedBackend {
            readers: vec![
                (present("Security Key CCID"), non_fineid_script),
                (present("Contact Reader 0"), fineid_token_info_only_script),
            ],
        };
        let pick = pick_fineid_reader(&backend, None)?;
        check_true(
            pick.reader_id.as_str() == "Contact Reader 0",
            "picks the lone FINEID reader",
        )
    }
}
