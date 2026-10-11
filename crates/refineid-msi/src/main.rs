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

//! Builds the `RefineID` Card Driver package.
//!
//! The card registrations below are the whole reason the package exists:
//! Windows reads them to decide which Card Module to load for an inserted
//! card, so their bytes are the product.

#[cfg(not(windows))]
fn main() {
    eprintln!("refineid-msi builds a Windows Installer package and runs on Windows only.");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_main::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod windows_main {
    use std::path::PathBuf;

    use refineid_msi::{
        Architecture, Guid, Package, RegistryData, RegistryValue, SystemFile, Version, build,
    };

    /// Where Windows keeps per-card Smart Card Crypto Provider registrations.
    const CALAIS: &str = r"SOFTWARE\Microsoft\Cryptography\Calais\SmartCards";

    /// The Card Module file name. Windows loads it by bare name from the
    /// system directory, so this must match the `80000001` value exactly.
    const MODULE_FILE: &str = "refineid_minidriver.dll";

    /// The one authored identifier; every other GUID derives from it.
    const UPGRADE_CODE: &str = "{DBD5521A-AA2C-45D1-B79C-8535E2C262A5}";

    /// Microsoft's own upper layers. A minidriver exists precisely so these
    /// two providers, rather than a bespoke CSP, drive the card.
    const BASE_CSP: &str = "Microsoft Base Smart Card Crypto Provider";
    const BASE_KSP: &str = "Microsoft Smart Card Key Storage Provider";

    /// Where CNG keeps its provider registrations.
    const CNG_PROVIDERS: &str = r"SYSTEM\CurrentControlSet\Control\Cryptography\Providers";
    /// The machine-wide list of key storage providers CNG consults.
    const CNG_KEY_STORAGE_FUNCTIONS: &str = r"SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\Default\00010001\KEY_STORAGE";
    /// The key storage provider exported by the same module for a paired
    /// phone. The name must match what the `RefineID` app binds certificates
    /// to (`refineid_windows_credential_store::KEY_STORAGE_PROVIDER`).
    const KEY_STORAGE_PROVIDER: &str = "RefineID Key Storage Provider";

    /// A card family Windows should bind to this Card Module.
    struct CardRegistration {
        /// Registration name, which becomes the Calais subkey.
        name: &'static str,
        /// The card's answer to reset.
        atr: &'static [u8],
        /// Which answer-to-reset bytes must match. A zero byte is a wildcard.
        mask: &'static [u8],
    }

    /// FINEID S4-1 v3.1 answers to reset identically on every card, so the
    /// mask requires all twenty bytes. The v4.0 family carries card-specific
    /// data in bytes 13 to 17, which the mask therefore ignores.
    const CARDS: &[CardRegistration] = &[
        CardRegistration {
            name: "FINEID-S4-1-v3.1",
            atr: &[
                0x3b, 0x7f, 0x96, 0x00, 0x00, 0x80, 0x31, 0xb8, 0x65, 0xb0, 0x85, 0x04, 0x02, 0x1b,
                0x12, 0x00, 0xf6, 0x82, 0x90, 0x00,
            ],
            mask: &[0xff; 20],
        },
        CardRegistration {
            name: "FINEID-S4-1-v4.0",
            atr: &[
                0x3b, 0x7f, 0x96, 0x00, 0x00, 0x80, 0x31, 0xb8, 0x65, 0xb0, 0x85, 0x05, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x82, 0x90, 0x00,
            ],
            mask: &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
                0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
            ],
        },
        CardRegistration {
            name: "FINEID-RAPP-Remote",
            atr: &[
                0x3b, 0x7f, 0x96, 0x00, 0x00, 0x80, 0x31, 0xb8, 0x65, 0xb0, 0x85, 0x05, 0x52, 0x41,
                0x50, 0x50, 0x00, 0x82, 0x90, 0x00,
            ],
            mask: &[0xff; 20],
        },
    ];

    struct Arguments {
        architecture: Architecture,
        minidriver: PathBuf,
        output: PathBuf,
        version: Version,
    }

    fn usage() -> String {
        "usage: refineid-msi --architecture <x64|arm64> --minidriver <path> \
         --output <path> --version <YY.M.D.B>"
            .to_owned()
    }

    fn parse_arguments() -> Result<Arguments, String> {
        let mut architecture = None;
        let mut minidriver = None;
        let mut output = None;
        let mut version = None;
        let mut arguments = std::env::args().skip(1);
        while let Some(flag) = arguments.next() {
            let mut value = || {
                arguments
                    .next()
                    .ok_or_else(|| format!("{flag} needs a value\n{}", usage()))
            };
            match flag.as_str() {
                "--architecture" => {
                    architecture = Some(match value()?.as_str() {
                        "x64" => Architecture::X64,
                        "arm64" => Architecture::Arm64,
                        other => return Err(format!("unknown architecture '{other}'")),
                    });
                }
                "--minidriver" => minidriver = Some(PathBuf::from(value()?)),
                "--output" => output = Some(PathBuf::from(value()?)),
                "--version" => {
                    version = Some(Version::parse(&value()?).map_err(|error| error.to_string())?);
                }
                "--help" | "-h" => return Err(usage()),
                other => return Err(format!("unknown argument '{other}'\n{}", usage())),
            }
        }
        Ok(Arguments {
            architecture: architecture.ok_or_else(|| format!("--architecture\n{}", usage()))?,
            minidriver: minidriver.ok_or_else(|| format!("--minidriver\n{}", usage()))?,
            output: output.ok_or_else(|| format!("--output\n{}", usage()))?,
            version: version.ok_or_else(|| format!("--version\n{}", usage()))?,
        })
    }

    pub fn run() -> Result<(), String> {
        let arguments = parse_arguments()?;
        let version = arguments.version;
        let upgrade_code = Guid::parse(UPGRADE_CODE).map_err(|error| error.to_string())?;

        let keys: Vec<String> = CARDS
            .iter()
            .map(|card| format!("{CALAIS}\\{}", card.name))
            .collect();
        let provider_key = format!("{CNG_PROVIDERS}\\{KEY_STORAGE_PROVIDER}\\UM\\00010001");
        let mut registry = Vec::with_capacity(CARDS.len() * 5 + 4);
        for (card, key) in CARDS.iter().zip(&keys) {
            registry.extend([
                RegistryValue {
                    key,
                    name: "ATR",
                    data: RegistryData::Binary(card.atr),
                },
                RegistryValue {
                    key,
                    name: "ATRMask",
                    data: RegistryData::Binary(card.mask),
                },
                RegistryValue {
                    key,
                    name: "Crypto Provider",
                    data: RegistryData::Text(BASE_CSP),
                },
                RegistryValue {
                    key,
                    name: "Smart Card Key Storage Provider",
                    data: RegistryData::Text(BASE_KSP),
                },
                RegistryValue {
                    key,
                    name: "80000001",
                    data: RegistryData::Text(MODULE_FILE),
                },
            ]);
        }

        // The paired phone reaches browsers through CNG rather than through a
        // reader, so the module also registers as a user-mode key storage
        // provider, the way `BCryptRegisterProvider` and
        // `BCryptAddContextFunctionProvider` would.
        registry.extend([
            RegistryValue {
                key: &provider_key,
                name: "Image",
                data: RegistryData::Text("[System64Folder]refineid_minidriver.dll"),
            },
            RegistryValue {
                key: &provider_key,
                name: "Flags",
                data: RegistryData::Dword(0),
            },
            RegistryValue {
                key: &provider_key,
                name: "Functions",
                data: RegistryData::MultiText(&["KEY_STORAGE"]),
            },
            RegistryValue {
                key: CNG_KEY_STORAGE_FUNCTIONS,
                name: "Functions",
                data: RegistryData::AppendText(KEY_STORAGE_PROVIDER),
            },
        ]);

        let package = Package {
            product_name: "RefineID Card Driver",
            manufacturer: "RefineID",
            description: "Windows smart-card minidriver for FINEID cards",
            version,
            upgrade_code,
            architecture: arguments.architecture,
            file: SystemFile {
                key: "MinidriverDll",
                name: MODULE_FILE,
                source: &arguments.minidriver,
            },
            registry: &registry,
            // Windows caches the card database, so it must be restarted for a
            // new or removed registration to take effect.
            restart_service: Some("SCardSvr"),
        };

        let scratch = arguments
            .output
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("cabinet");
        build(&package, &arguments.output, &scratch).map_err(|error| error.to_string())?;
        let _ = std::fs::remove_dir(&scratch);

        println!("{}", arguments.output.display());
        Ok(())
    }
}
