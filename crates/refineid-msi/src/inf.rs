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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The Plug and Play driver package that names FINEID cards in Device
//! Manager.
//!
//! When a card is inserted, the smart card filter driver gives it a device
//! whose hardware ID is `SCFILTER\CID_` followed by the card's ATR
//! historical bytes, all of them, in hexadecimal (Microsoft, "Discovery
//! Process", Smart Card Plug and Play Process and "Use of the ATR
//! Historical Bytes"). A card no INF names falls to the inbox
//! `scunknown.inf`, which matches the compatible ID
//! `SCFILTER\CID_87D25E32-AC0D-4EF0-B1E0-502C6B7DFB77` with a null service
//! and shows "Unknown Smart Card".
//!
//! This INF matches each field-observed FINEID card by its exact hardware
//! ID. An INF hardware ID is an exact identifier, with no wildcard, so the
//! v4.0 family, whose historical bytes vary per chip revision, needs one
//! line per revision; a revision not yet recorded keeps working through
//! the Calais mask and only shows as "Unknown Smart Card". The install
//! sections are those of Microsoft's inbox `msclmd.inf`: the device gets
//! the inbox `UmPass` service and nothing else. The Calais registrations
//! stay with the Windows Installer package, which is their one writer; the
//! INF carries no `AddReg`, no files and no `DefaultInstall`.

use core::fmt::{self, Write as _};

use refineid_lib_core::fineid_card::{Atr, AtrError};

use crate::cards::CardRegistration;

/// The INF's file name. The Card Module's install action finds the INF
/// beside the agent under this name
/// (`refineid_minidriver::card_driver::INF_FILE`).
pub const INF_FILE: &str = "refineid_card.inf";

/// The catalog file the INF's `CatalogFile` directive names.
pub const CATALOG_FILE: &str = "refineid_card.cat";

/// The hardware ID prefix the smart card filter driver gives a card,
/// followed by the historical bytes.
const CARD_ID_PREFIX: &str = r"SCFILTER\CID_";

/// The smart card device setup class (Microsoft's sample INF and the inbox
/// `msclmd.inf` and `scunknown.inf`).
const SMART_CARD_CLASS: &str = "SmartCard";
/// The smart card device setup class GUID, as Microsoft's INFs spell it.
const SMART_CARD_CLASS_GUID: &str = "{990A2BD7-E738-46c7-B26F-1CF8FB9F1391}";

/// The models section name.
const MODELS: &str = "RefineID";
/// The target-OS decorations of the models section: Windows 10 and later
/// on x64 and on Arm64, the two architectures the packages target.
const DECORATIONS: &[&str] = &["NTamd64.10.0", "NTarm64.10.0"];
/// The install section every card device uses, as a models line names
/// it.
const INSTALL_SECTION: &str = "RefineID_Card";
/// The platform extension of the install sections: Windows looks up
/// `RefineID_Card.NT` from a models line naming `RefineID_Card`.
const NT_EXTENSION: &str = ".NT";
/// The inbox INF whose `UmPass` sections the install section includes.
const UMPASS_INF: &str = "umpass.inf";
/// Each install section suffix and the `UmPass` section it needs.
/// `umpass.inf` requires an including INF to reference all five.
const UMPASS_SECTIONS: &[(&str, &str)] = &[
    ("", "UmPass"),
    (".HW", "UmPass.HW"),
    (".CoInstallers", "UmPass.CoInstallers"),
    (".Interfaces", "UmPass.Interfaces"),
    (".Services", "UmPass.Services"),
];
/// The provider shown in Device Manager.
const PROVIDER: &str = "RefineID";
/// The string key of the provider.
const PROVIDER_KEY: &str = "Provider";

/// `DriverVer` writes a four-digit year; the project version counts years
/// from this one.
const CENTURY: u16 = 2000;

/// INF lines end with a carriage return and a line feed.
const LINE_END: &str = "\r\n";

/// A card's identifier as the smart card filter driver derives it: its
/// ATR historical bytes in lowercase hexadecimal, as Device Manager shows
/// them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CardIdentifier(String);

impl CardIdentifier {
    /// The identifier of a card answering `atr` to reset, or `None` when
    /// the ATR carries no historical bytes and the filter driver derives
    /// none from it.
    #[must_use]
    pub fn from_atr(atr: &Atr) -> Option<Self> {
        let historical = atr.historical_bytes();
        if historical.is_empty() {
            return None;
        }
        let mut text = String::with_capacity(historical.len() * 2);
        for byte in historical.as_bytes() {
            // Writing into a String cannot fail.
            let _ = write!(text, "{byte:02x}");
        }
        Some(Self(text))
    }

    /// The device's hardware ID.
    #[must_use]
    pub fn hardware_id(&self) -> String {
        format!("{CARD_ID_PREFIX}{}", self.0)
    }
}

/// The `DriverVer` of the package: the build's UTC day and its
/// `YY.M.D.HHMM` version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverVersion {
    /// Years since 2000.
    pub year: u8,
    /// Month, 1 to 12.
    pub month: u8,
    /// Day of month, 1 to 31.
    pub day: u8,
    /// The time of day as `hour * 100 + minute`.
    pub time_of_day: u32,
}

impl fmt::Display for DriverVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02}/{:02}/{},{}.{}.{}.{}",
            self.month,
            self.day,
            CENTURY + u16::from(self.year),
            self.year,
            self.month,
            self.day,
            self.time_of_day
        )
    }
}

/// The INF could not be derived from the card registrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfError {
    /// A recorded answer to reset is not a well-formed ATR.
    Atr {
        /// The registration whose model records it.
        registration: &'static str,
        /// Why it does not parse.
        error: AtrError,
    },
    /// A recorded answer to reset carries no historical bytes.
    NoHistoricalBytes {
        /// The registration whose model records it.
        registration: &'static str,
    },
    /// A recorded answer to reset is not bound by its registration, so the
    /// INF would name a card no Card Module serves.
    Unbound {
        /// The registration whose model records it.
        registration: &'static str,
    },
}

impl fmt::Display for InfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Atr {
                registration,
                error,
            } => write!(
                f,
                "{registration}: a recorded ATR does not parse: {error:?}"
            ),
            Self::NoHistoricalBytes { registration } => {
                write!(f, "{registration}: a recorded ATR has no historical bytes")
            }
            Self::Unbound { registration } => write!(
                f,
                "{registration}: a recorded ATR is outside the registration's mask"
            ),
        }
    }
}

impl std::error::Error for InfError {}

/// One device line of the INF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardDevice {
    /// The Calais registration that binds the card.
    pub registration: &'static str,
    /// The name Device Manager shows.
    pub description: String,
    /// The card's identifier.
    pub identifier: CardIdentifier,
}

/// The devices the INF names: every field-observed contact ATR of each
/// registration's model, each checked to be bound by that registration.
///
/// # Errors
///
/// Returns an error if a recorded ATR does not parse, carries no
/// historical bytes, or is outside its registration's mask.
pub fn card_devices(cards: &[CardRegistration]) -> Result<Vec<CardDevice>, InfError> {
    let mut devices: Vec<CardDevice> = Vec::new();
    for card in cards {
        let Some(model) = card.model else { continue };
        let description = format!(
            "FINEID {} v{} card",
            model.fineid_specification(),
            model.fineid_specification_version()
        );
        for bytes in model.contact_atr_byte_sets() {
            if !card.binds(bytes) {
                return Err(InfError::Unbound {
                    registration: card.name,
                });
            }
            let atr = Atr::new(bytes).map_err(|error| InfError::Atr {
                registration: card.name,
                error,
            })?;
            let identifier = CardIdentifier::from_atr(&atr).ok_or(InfError::NoHistoricalBytes {
                registration: card.name,
            })?;
            if devices.iter().all(|device| device.identifier != identifier) {
                devices.push(CardDevice {
                    registration: card.name,
                    description: description.clone(),
                    identifier,
                });
            }
        }
    }
    Ok(devices)
}

/// The INF string key of a registration's device name.
fn string_key(registration: &str) -> String {
    registration
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Appends one INF line.
fn line(text: &mut String, content: &str) {
    text.push_str(content);
    text.push_str(LINE_END);
}

/// The INF text for `cards`, stamped with `version`.
///
/// # Errors
///
/// Returns an error if [`card_devices`] does.
pub fn card_inf(cards: &[CardRegistration], version: DriverVersion) -> Result<String, InfError> {
    let devices = card_devices(cards)?;
    let mut text = String::new();
    for header in [
        "; Copyright 2026 Petri Koistinen",
        "; Licensed under the Apache License, Version 2.0:",
        "; https://www.apache.org/licenses/LICENSE-2.0",
        ";",
        "; Names FINEID cards in Device Manager. Generated by refineid-msi from the",
        "; card registrations its package writes under Calais\\SmartCards.",
        "",
        "[Version]",
        "Signature=\"$Windows NT$\"",
    ] {
        line(&mut text, header);
    }
    line(&mut text, &format!("Class={SMART_CARD_CLASS}"));
    line(&mut text, &format!("ClassGuid={SMART_CARD_CLASS_GUID}"));
    line(&mut text, &format!("Provider=%{PROVIDER_KEY}%"));
    line(&mut text, &format!("CatalogFile={CATALOG_FILE}"));
    line(&mut text, &format!("DriverVer={version}"));
    line(&mut text, "PnpLockdown=1");
    line(&mut text, "");
    line(&mut text, "[Manufacturer]");
    line(
        &mut text,
        &format!("%{PROVIDER_KEY}%={MODELS},{}", DECORATIONS.join(",")),
    );
    for decoration in DECORATIONS {
        line(&mut text, "");
        line(&mut text, &format!("[{MODELS}.{decoration}]"));
        for device in &devices {
            line(
                &mut text,
                &format!(
                    "%{}%={INSTALL_SECTION},{}",
                    string_key(device.registration),
                    device.identifier.hardware_id()
                ),
            );
        }
    }
    for (suffix, needs) in UMPASS_SECTIONS {
        line(&mut text, "");
        line(
            &mut text,
            &format!("[{INSTALL_SECTION}{NT_EXTENSION}{suffix}]"),
        );
        line(&mut text, &format!("Include={UMPASS_INF}"));
        line(&mut text, &format!("Needs={needs}"));
    }
    line(&mut text, "");
    line(&mut text, "[Strings]");
    line(&mut text, &format!("{PROVIDER_KEY}=\"{PROVIDER}\""));
    let mut named: Vec<&str> = Vec::new();
    for device in &devices {
        if !named.contains(&device.registration) {
            named.push(device.registration);
            line(
                &mut text,
                &format!(
                    "{}=\"{}\"",
                    string_key(device.registration),
                    device.description
                ),
            );
        }
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::{
        CATALOG_FILE, CardIdentifier, DECORATIONS, DriverVersion, INSTALL_SECTION, LINE_END,
        NT_EXTENSION, SMART_CARD_CLASS_GUID, UMPASS_SECTIONS, card_devices, card_inf,
    };
    use crate::cards::{CARDS, CardRegistration};
    use refineid_lib_core::fineid_card::{Atr, FineidCardModel};

    /// The hardware ID Device Manager showed for a FINEID S4-1 v4.0 card
    /// (chip revision 2.0.0) in an ACS ACR1581 contact slot on Windows 11
    /// Arm64, quoted from its Hardware Ids property.
    const OBSERVED_V4_0_HARDWARE_ID: &str = r"SCFILTER\CID_8031b865b085051024122460829000";

    /// A build stamp.
    const VERSION: DriverVersion = DriverVersion {
        year: 26,
        month: 11,
        day: 7,
        time_of_day: 905,
    };

    fn inf() -> String {
        card_inf(CARDS, VERSION).expect("the registrations yield an INF")
    }

    #[test]
    fn the_observed_card_is_named() {
        let devices = card_devices(CARDS).expect("devices");
        assert!(devices.iter().any(|device| device.identifier.hardware_id()
            == OBSERVED_V4_0_HARDWARE_ID
            && device.registration == "FINEID-S4-1-v4.0"
            && device.description == "FINEID S4-1 v4.0 card"));
        assert!(inf().contains(OBSERVED_V4_0_HARDWARE_ID));
    }

    #[test]
    fn every_recorded_citizen_card_is_named_under_both_architectures() {
        let text = inf();
        for model in [
            FineidCardModel::GemaltoMultiAppV4_2,
            FineidCardModel::ThalesMultiAppV5_0,
        ] {
            for bytes in model.contact_atr_byte_sets() {
                let atr = Atr::new(bytes).expect("recorded ATR parses");
                let id = CardIdentifier::from_atr(&atr)
                    .expect("historical bytes")
                    .hardware_id();
                assert_eq!(
                    text.matches(&id).count(),
                    DECORATIONS.len(),
                    "{id} once per architecture"
                );
            }
        }
    }

    #[test]
    fn a_model_the_package_does_not_register_is_not_named() {
        let text = inf();
        for bytes in FineidCardModel::IdemiaCosmoX.contact_atr_byte_sets() {
            let atr = Atr::new(bytes).expect("recorded ATR parses");
            let id = CardIdentifier::from_atr(&atr)
                .expect("historical bytes")
                .hardware_id();
            assert!(!text.contains(&id), "{id} has no Card Module");
        }
    }

    #[test]
    fn a_registration_without_a_model_names_nothing() {
        let devices = card_devices(CARDS).expect("devices");
        assert!(
            devices
                .iter()
                .all(|device| device.registration != "FINEID-RAPP-Remote")
        );
    }

    #[test]
    fn a_recorded_atr_outside_the_mask_is_refused() {
        let narrow = CardRegistration {
            name: "narrow",
            atr: CARDS[0].atr,
            mask: CARDS[0].mask,
            model: Some(FineidCardModel::ThalesMultiAppV5_0),
        };
        assert!(card_devices(&[narrow]).is_err());
    }

    #[test]
    fn the_header_declares_the_smart_card_class_and_the_catalog() {
        let text = inf();
        assert!(text.contains("Class=SmartCard\r\n"));
        assert!(text.contains(&format!("ClassGuid={SMART_CARD_CLASS_GUID}\r\n")));
        assert!(text.contains(&format!("CatalogFile={CATALOG_FILE}\r\n")));
        assert!(text.contains("DriverVer=11/07/2026,26.11.7.905\r\n"));
        assert!(text.contains("PnpLockdown=1\r\n"));
    }

    #[test]
    fn every_umpass_section_is_included() {
        let text = inf();
        for (suffix, needs) in UMPASS_SECTIONS {
            let section = format!(
                "[{INSTALL_SECTION}{NT_EXTENSION}{suffix}]\r\nInclude=umpass.inf\r\nNeeds={needs}\r\n"
            );
            assert!(text.contains(&section), "{section}");
        }
    }

    #[test]
    fn the_package_writes_no_registry_and_copies_no_files() {
        let text = inf();
        for directive in ["AddReg", "CopyFiles", "DefaultInstall", "SourceDisksFiles"] {
            assert!(!text.contains(directive), "{directive}");
        }
    }

    #[test]
    fn every_line_ends_with_carriage_return_and_line_feed() {
        let text = inf();
        assert!(text.ends_with(LINE_END));
        assert_eq!(text.matches('\n').count(), text.matches(LINE_END).count());
    }
}
