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

//! UI-toolkit-independent card-management facade.

use refineid_lib_core::auth::{PinOps as _, PinSlot, PinStatus, PukStatus};
use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend as _, ReaderFilter};
use refineid_lib_core::can::Can;
use refineid_lib_core::crypto::digest::Sha256;
use refineid_lib_core::fineid_card::FineidCardModel;
use refineid_lib_core::identity::{CredentialIdentity, TokenSerial, render_token_serial};
use refineid_lib_core::pace::run_pace_with_can;
use refineid_lib_core::pkcs15::{
    CardGeneration, CertSlot, FineidReaderPicker as _, Pkcs15Ops as _,
    classify_card_generation_by_issuance,
};
use refineid_lib_core::secure_messaging::SmTransport;
use refineid_lib_core::transport::CardTransport as _;
use refineid_lib_core::x509::{OwnedCert, UnvalidatedCertificate};
use refineid_lib_pcsc::{PcscBackend, PcscError};

use crate::card_pin::{
    ActivateOptions, ActivatePreflightOutcome, ActivateReport, CardPinError, ChangePinOptions,
    ChangePinReport, UnblockPinOptions, UnblockPinReport,
};

/// Read-only state shown by the Windows settings app.
#[derive(Debug, Clone)]
pub struct CardSnapshot {
    /// Exact PC/SC reader name.
    pub reader: String,
    /// Full PKCS #15 card serial used for operation binding.
    pub serial: TokenSerial,
    /// Certificate-derived holder label.
    pub person: String,
    /// ATR-classified FINEID card model.
    pub model: FineidCardModel,
    /// Activation scheme selected from the authenticated certificate.
    pub generation: CardGeneration,
    /// Expected activation-code length, when classification succeeded.
    pub activation_code_length: Option<usize>,
    /// Whether the card looks activated, judged exactly as the activation
    /// command's preflight judges it, so the app can open the activation
    /// flow for a card that activation would accept.
    pub activation: ActivatePreflightOutcome,
    /// Side-effect-free PIN1 status.
    pub pin1: Option<PinStatus>,
    /// Side-effect-free PIN2 status.
    pub pin2: Option<PinStatus>,
    /// Side-effect-free shared-PUK status.
    pub puk: Option<PukStatus>,
    /// New-card PIN1 changed flag, when supported.
    pub pin1_changed: Option<bool>,
    /// New-card PIN2 changed flag, when supported.
    pub pin2_changed: Option<bool>,
}

/// Read-only result of proving contactless access with the printed CAN.
#[derive(Debug, Clone)]
pub struct ContactlessSnapshot {
    /// Exact PC/SC reader name.
    pub reader: String,
    /// Complete PC/SC contactless ATR used for the pre-PACE credential lookup.
    ///
    /// This identifies a card family, not a physical card. It is kept out of
    /// the UI DTO and used only as the Windows Credential Manager key.
    pub lookup_atr: Vec<u8>,
    /// Full PKCS #15 card serial read inside secure messaging.
    pub serial: TokenSerial,
    /// Certificate-derived holder label.
    pub person: String,
    /// Activation generation derived from the trusted auth certificate.
    pub generation: CardGeneration,
    /// Side-effect-free PIN1 status inside secure messaging.
    pub pin1: Option<PinStatus>,
    /// Side-effect-free PIN2 status inside secure messaging.
    pub pin2: Option<PinStatus>,
    /// Always `None`: the Apple reference deliberately does not query
    /// the PUK over contactless secure messaging because FINEID cards
    /// can reject that query and end the secure channel.
    pub puk: Option<PukStatus>,
}

/// Enumerate readers that currently report a card.
///
/// # Errors
/// Returns PC/SC context or enumeration failures.
pub fn present_readers() -> Result<Vec<String>, PcscError> {
    let mut readers = PcscBackend
        .enumerate()?
        .into_iter()
        .filter(|reader| reader.card_present)
        .map(|reader| reader.id.as_str().to_owned())
        .collect::<Vec<_>>();
    readers.sort_unstable();
    Ok(readers)
}

/// Inspect one FINEID card without sending credential-bearing commands.
///
/// # Errors
/// Returns reader, card-classification, trust, certificate, or PC/SC failures.
pub fn inspect(reader_filter: Option<&ReaderFilter>) -> Result<CardSnapshot, CardPinError> {
    inspected(reader_filter).inspect_err(|error| {
        refineid_dev_errors::report!(CardService, "card inspection failed", error);
    })
}

fn inspected(reader_filter: Option<&ReaderFilter>) -> Result<CardSnapshot, CardPinError> {
    let context = crate::card_pin::classify_card_for_activation(PcscBackend, reader_filter)?;
    let mut transport = PcscBackend.open_exclusive(&context.reader_id, ReaderAccessCap::Read)?;
    transport
        .select_pkcs15_application()
        .map_err(|error| CardPinError::Pkcs15Select(format!("{error}")))?;
    crate::card_pin::re_verify_session(&mut transport, &context.bound_serial)?;

    let pin1 = transport.pin_status(PinSlot::Pin1).ok();
    let pin2 = transport.pin_status(PinSlot::Pin2).ok();
    let puk = transport.puk_status().ok();
    let pin1_changed = transport.pin_changed_flag(PinSlot::Pin1).ok().flatten();
    let pin2_changed = transport.pin_changed_flag(PinSlot::Pin2).ok().flatten();
    let activation_code_length = context.expected_activation_pin_length();
    let activation = crate::card_pin::classify_preflight(
        pin1,
        pin2,
        context.generation,
        pin1_changed,
        pin2_changed,
    );

    Ok(CardSnapshot {
        reader: context.reader_id.as_str().to_owned(),
        serial: context.bound_serial,
        person: context.identity.person_string(),
        model: context.model,
        generation: context.generation,
        activation_code_length,
        activation,
        pin1,
        pin2,
        puk,
        pin1_changed,
        pin2_changed,
    })
}

/// Prove the contactless path using the current Apple-reference sequence:
/// SELECT MF, PACE with CAN, then protected PKCS #15 reads.
///
/// No PIN, PUK, activation, or PIN-changing command is sent. The supplied
/// CAN is consumed by PACE and does not enter logs or the returned snapshot.
///
/// # Errors
/// Returns reader, PACE, secure-messaging, trust, certificate, or PC/SC
/// failures.
pub fn inspect_contactless(
    reader_filter: Option<&ReaderFilter>,
    can: Can,
) -> Result<ContactlessSnapshot, CardPinError> {
    inspected_contactless(reader_filter, can).inspect_err(|error| {
        refineid_dev_errors::report!(CardService, "contactless inspection failed", error);
    })
}

fn inspected_contactless(
    reader_filter: Option<&ReaderFilter>,
    can: Can,
) -> Result<ContactlessSnapshot, CardPinError> {
    let backend = PcscBackend;
    let reader_id = backend.pick_contactless_reader(reader_filter)?;
    let mut transport = backend.open_exclusive(&reader_id, ReaderAccessCap::Read)?;
    let lookup_atr = transport
        .atr()
        .map_err(|error| CardPinError::Transport(format!("contactless ATR failed: {error}")))?
        .to_wire_bytes();

    // RefineID-Apple deliberately attempts both proven SELECT MF variants
    // before PACE and still lets MSE:Set AT be the authority if a reader
    // rejects the plain selection.
    let _master_file_selection = transport.select_mf();
    let pace_session = match run_pace_with_can(&mut transport, can) {
        Ok(session) => session,
        Err(error) => {
            let pace_error = CardPinError::Transport(format!("contactless PACE failed: {error}"));
            transport.reset().map_err(|reset_error| {
                CardPinError::Transport(format!(
                    "contactless PACE failed: {error}; card power reset failed: {reset_error}"
                ))
            })?;
            return Err(pace_error);
        }
    };
    let mut transport = SmTransport::new(transport, pace_session);

    let result = (|| {
        transport
            .select_pkcs15_application()
            .map_err(|error| CardPinError::Pkcs15Select(format!("{error}")))?;

        let root_der = transport
            .read_certificate(CertSlot::RootCa)
            .map_err(|error| CardPinError::CardDataUntrusted {
                description: format!("protected root certificate read failed: {error}"),
            })?;
        let root_sha256 = Sha256::of(root_der.as_bytes());
        if crate::trust_roots::pinned_root_label(root_sha256).is_none() {
            return Err(CardPinError::CardDataUntrusted {
                description: format!(
                    "protected root certificate did not match a pinned DVV root (sha256 {root_sha256})"
                ),
            });
        }

        transport
            .select_pkcs15_application()
            .map_err(|error| CardPinError::Pkcs15Select(format!("{error}")))?;
        let token = transport.read_token_info().map_err(|error| {
            CardPinError::Transport(format!("protected EF.TokenInfo read: {error}"))
        })?;
        let serial = token
            .serial_number_hex
            .map(render_token_serial)
            .ok_or_else(|| CardPinError::CardDataUntrusted {
                description: "protected EF.TokenInfo did not publish a card serial".to_owned(),
            })?;

        let auth_der = transport
            .read_certificate(CertSlot::Authentication)
            .map_err(|error| {
                CardPinError::Transport(format!("protected auth cert read: {error}"))
            })?;
        let cert_owned =
            OwnedCert::from_der(UnvalidatedCertificate::new(auth_der.as_bytes().to_vec()))
                .map_err(|error| {
                    CardPinError::Transport(format!("protected auth cert parse: {error}"))
                })?;
        let cert = cert_owned.view();
        let generation = classify_card_generation_by_issuance(cert.not_before);
        let person = identity_from_certificate(&cert).person_string();

        transport
            .select_pkcs15_application()
            .map_err(|error| CardPinError::Pkcs15Select(format!("{error}")))?;
        let pin1 = transport.pin_status(PinSlot::Pin1).ok();
        let pin2 = transport.pin_status(PinSlot::Pin2).ok();
        // Keep parity with RefineID-Apple: PIN1 and PIN2 are safe probes,
        // but the PUK GET DATA query can answer 6988 over contactless and
        // make the next protected command fail with 6999.
        let puk = None;

        Ok(ContactlessSnapshot {
            reader: reader_id.as_str().to_owned(),
            lookup_atr,
            serial,
            person,
            generation,
            pin1,
            pin2,
            puk,
        })
    })();

    let mut raw_transport = transport.into_inner();
    let reset_result = raw_transport.reset().map_err(|error| {
        CardPinError::Transport(format!("contactless cleanup power reset failed: {error}"))
    });
    match (result, reset_result) {
        (Err(error), _) => Err(error),
        (Ok(snapshot), Ok(())) => Ok(snapshot),
        (Ok(_snapshot), Err(error)) => Err(error),
    }
}

fn identity_from_certificate(
    certificate: &refineid_lib_core::x509::Certificate<'_>,
) -> CredentialIdentity {
    let subject = certificate.subject;
    let given_names = subject.given_names();
    let mut identity = CredentialIdentity::new();
    if let Some(value) = subject.surname() {
        identity = identity.with_surname(value);
    }
    if let Some(value) = given_names.first {
        identity = identity.with_first_name(value);
    }
    if let Some(value) = given_names.second {
        identity = identity.with_second_name(value);
    }
    identity = identity.with_additional_names(given_names.additional);
    if let Some(value) = subject.peuin() {
        identity = identity.with_peuin(value);
    }
    identity
}

/// Activate the card after binding the action to the displayed serial.
///
/// # Errors
/// Returns trust, card-swap, policy, PC/SC, or activation failures.
pub fn activate(
    expected_serial: &TokenSerial,
    reader_filter: Option<&ReaderFilter>,
    options: ActivateOptions,
) -> Result<ActivateReport, CardPinError> {
    activated(expected_serial, reader_filter, options)
        .inspect_err(|error| refineid_dev_errors::report!(CardService, "activation failed", error))
}

fn activated(
    expected_serial: &TokenSerial,
    reader_filter: Option<&ReaderFilter>,
    options: ActivateOptions,
) -> Result<ActivateReport, CardPinError> {
    let context = crate::card_pin::classify_card_for_activation(PcscBackend, reader_filter)?;
    ensure_serial(expected_serial, &context.bound_serial)?;
    crate::card_pin::activate_first(PcscBackend, context, options)
}

/// Change PIN1 or PIN2 on the card currently shown by the UI.
///
/// # Errors
/// Returns trust, card-swap, retry-floor, policy, PC/SC, or card failures.
pub fn change_pin(
    expected_serial: &TokenSerial,
    options: ChangePinOptions,
) -> Result<ChangePinReport, CardPinError> {
    changed_pin(expected_serial, options)
        .inspect_err(|error| refineid_dev_errors::report!(CardService, "PIN change failed", error))
}

fn changed_pin(
    expected_serial: &TokenSerial,
    options: ChangePinOptions,
) -> Result<ChangePinReport, CardPinError> {
    let reader_filter = options.reader_filter.as_deref().map(ReaderFilter::new);
    let session = crate::card_pin::establish_trusted_session(PcscBackend, reader_filter.as_ref())?;
    ensure_serial(expected_serial, &session.bound_serial)?;
    crate::card_pin::change_pin_first(PcscBackend, session.into_pin_management_context(), options)
}

/// Unblock PIN1 or PIN2 with the shared recovery code.
///
/// # Errors
/// Returns trust, card-swap, policy, PC/SC, or recovery failures.
pub fn unblock_pin(
    expected_serial: &TokenSerial,
    options: UnblockPinOptions,
) -> Result<UnblockPinReport, CardPinError> {
    unblocked_pin(expected_serial, options)
        .inspect_err(|error| refineid_dev_errors::report!(CardService, "PIN unblock failed", error))
}

fn unblocked_pin(
    expected_serial: &TokenSerial,
    options: UnblockPinOptions,
) -> Result<UnblockPinReport, CardPinError> {
    let reader_filter = options.reader_filter.as_deref().map(ReaderFilter::new);
    let session = crate::card_pin::establish_trusted_session(PcscBackend, reader_filter.as_ref())?;
    ensure_serial(expected_serial, &session.bound_serial)?;
    crate::card_pin::unblock_pin_first(PcscBackend, session.into_pin_management_context(), options)
}

fn ensure_serial(expected: &TokenSerial, live: &TokenSerial) -> Result<(), CardPinError> {
    if expected == live {
        return Ok(());
    }
    Err(CardPinError::CardSessionRevoked {
        reason: "the displayed card no longer matches the card in the reader".to_owned(),
    })
}

/// Build an exact reader filter from a UI-selected reader name.
#[must_use]
pub fn reader_filter(reader: String) -> ReaderFilter {
    ReaderFilter::new(reader)
}

#[cfg(test)]
mod tests {
    use refineid_lib_core::identity::TokenSerial;

    use super::ensure_serial;

    #[test]
    fn serial_match_is_accepted() {
        let serial = TokenSerial::new("same-card".to_owned());
        assert!(ensure_serial(&serial, &serial).is_ok());
    }

    #[test]
    fn serial_mismatch_is_refused() {
        let expected = TokenSerial::new("displayed-card".to_owned());
        let live = TokenSerial::new("different-card".to_owned());
        assert!(ensure_serial(&expected, &live).is_err());
    }
}
