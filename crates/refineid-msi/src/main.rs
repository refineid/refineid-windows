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
//! The card registrations in [`refineid_msi::cards`] are the whole reason
//! the package exists: Windows reads them to decide which Card Module to
//! load for an inserted card, so their bytes are the product. The INF that
//! names the cards in Device Manager is derived from them.

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
    use std::path::{Path, PathBuf};

    use refineid_msi::cards::{CALAIS, CARDS};
    use refineid_msi::inf::{self, DriverVersion};
    use refineid_msi::{
        Architecture, CustomAction, DriverPackage, Guid, Package, RegistryData, RegistryValue,
        Schedule, Strays, SystemFile, Version, build,
    };

    /// The Card Module file name. Windows loads it by bare name from the
    /// system directory, so this must match the `80000001` value exactly.
    const MODULE_FILE: &str = "refineid_minidriver.dll";

    /// The per-user agent's file name, under `Program Files\RefineID`.
    const AGENT_FILE: &str = "refineid-agent.exe";

    /// Where Windows starts a program at every user's sign-in, and removes
    /// it from with the package. The agent stays in the user's session and
    /// ends with it; no service runs.
    const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    /// The Run value of the agent.
    const RUN_VALUE: &str = "RefineIDAgent";
    /// The agent's command line: Windows Installer writes the installed
    /// file's path in place of the bracketed key.
    const AGENT_COMMAND: &str = "\"[#AgentExe]\"";

    /// The one authored identifier; every other GUID derives from it.
    const UPGRADE_CODE: &str = "{DBD5521A-AA2C-45D1-B79C-8535E2C262A5}";

    /// Microsoft's own upper layers. A minidriver exists precisely so these
    /// two providers, rather than a bespoke CSP, drive the card.
    const BASE_CSP: &str = "Microsoft Base Smart Card Crypto Provider";
    const BASE_KSP: &str = "Microsoft Smart Card Key Storage Provider";

    /// The entry point that removes the module's key storage provider
    /// registration. It runs on uninstall and as the rollback of the
    /// registration.
    const UNREGISTER_ENTRY_POINT: &str = "RefineIdUnregisterKeyStorageProvider";

    /// The entry point that removes the root certificates Windows
    /// propagated from the `msroots` file of builds that served one. It runs
    /// as `LocalSystem`, which alone may change what propagation wrote, on
    /// install, repair and upgrade, and again on uninstall; with no undo,
    /// since trust a card chose is never put back.
    const REMOVE_CARD_ROOTS_ENTRY_POINT: &str = "RefineIdRemoveCardRoots";

    /// The module's own entry points that register it with CNG as the key
    /// storage provider for a paired phone, and remove that registration.
    /// CNG caches its configuration, so a registry write alone is not seen
    /// until the next boot; these call `BCryptRegisterProvider` and
    /// `BCryptAddContextFunctionProvider` (and their reverse) instead.
    const KEY_STORAGE_PROVIDER_ACTIONS: &[CustomAction<'static>] = &[
        CustomAction {
            name: "RegisterKeyStorageProvider",
            entry_point: "RefineIdRegisterKeyStorageProvider",
            schedule: Schedule::Install {
                rollback_entry_point: UNREGISTER_ENTRY_POINT,
            },
        },
        CustomAction {
            name: "UnregisterKeyStorageProvider",
            entry_point: UNREGISTER_ENTRY_POINT,
            schedule: Schedule::Uninstall,
        },
        CustomAction {
            name: "RemoveCardRoots",
            entry_point: REMOVE_CARD_ROOTS_ENTRY_POINT,
            schedule: Schedule::InstallWithoutUndo,
        },
        CustomAction {
            name: "RemoveCardRootsOnUninstall",
            entry_point: REMOVE_CARD_ROOTS_ENTRY_POINT,
            schedule: Schedule::Uninstall,
        },
    ];

    /// The module's entry point that removes every Calais registration
    /// naming the Card Module, in both registry views, whoever wrote it. On
    /// a first installation it runs before the package writes its own
    /// registrations, so what is left are those; on uninstall it takes
    /// the ones a development install added.
    const REMOVE_CARD_REGISTRATIONS_ENTRY_POINT: &str = "RefineIdRemoveCardRegistrations";

    const CARD_REGISTRATION_CLEANUP_ACTIONS: &[CustomAction<'static>] = &[
        CustomAction {
            name: "RemoveEarlierCardRegistrations",
            entry_point: REMOVE_CARD_REGISTRATIONS_ENTRY_POINT,
            schedule: Schedule::FirstInstall,
        },
        CustomAction {
            name: "RemoveCardRegistrations",
            entry_point: REMOVE_CARD_REGISTRATIONS_ENTRY_POINT,
            schedule: Schedule::Uninstall,
        },
    ];

    /// What the development installer of earlier builds
    /// (`scripts/install-dev.ps1`) left outside the package: its backup of
    /// the Card Module it replaced, under `ProgramData`, and the event
    /// source development builds report to, which a release build never
    /// uses.
    const STRAYS: Strays<'static> = Strays {
        program_data_files: &[r"RefineID\backup\refineid_minidriver.dll"],
        machine_keys: &[r"SYSTEM\CurrentControlSet\Services\EventLog\Application\RefineID"],
    };

    /// The entry point that removes the driver package from the driver
    /// store. It runs on uninstall and as the rollback of the installation.
    const UNINSTALL_DRIVER_ENTRY_POINT: &str = "RefineIdUninstallCardDriver";

    /// The module's entry points that add the driver package to the driver
    /// store and install it on the cards present (`DiInstallDriverW`), and
    /// remove it (`DiUninstallDriverW`). A package Windows refuses, such as
    /// one whose catalog signature it does not accept, leaves the
    /// installation successful: the name in Device Manager is all the
    /// package changes.
    const DRIVER_PACKAGE_ACTIONS: &[CustomAction<'static>] = &[
        CustomAction {
            name: "InstallCardDriver",
            entry_point: "RefineIdInstallCardDriver",
            schedule: Schedule::Install {
                rollback_entry_point: UNINSTALL_DRIVER_ENTRY_POINT,
            },
        },
        CustomAction {
            name: "UninstallCardDriver",
            entry_point: UNINSTALL_DRIVER_ENTRY_POINT,
            schedule: Schedule::Uninstall,
        },
    ];

    /// What the command line asks for.
    enum Command {
        /// Write the driver package's INF and stop.
        WriteInf { output: PathBuf, version: Version },
        /// Build the installer package.
        Package(Arguments),
    }

    struct Arguments {
        architecture: Architecture,
        minidriver: PathBuf,
        agent: PathBuf,
        driver_package: Option<PathBuf>,
        output: PathBuf,
        version: Version,
    }

    fn usage() -> String {
        "usage: refineid-msi --architecture <x64|arm64> --minidriver <path> \
         --agent <path> [--driver-package <directory>] \
         --output <path> --version <YY.M.D.HHMM>\n       \
         refineid-msi --write-inf <path> --version <YY.M.D.HHMM>"
            .to_owned()
    }

    fn parse_arguments() -> Result<Command, String> {
        let mut architecture = None;
        let mut minidriver = None;
        let mut agent = None;
        let mut driver_package = None;
        let mut write_inf = None;
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
                "--agent" => agent = Some(PathBuf::from(value()?)),
                "--driver-package" => driver_package = Some(PathBuf::from(value()?)),
                "--write-inf" => write_inf = Some(PathBuf::from(value()?)),
                "--output" => output = Some(PathBuf::from(value()?)),
                "--version" => {
                    version = Some(Version::parse(&value()?).map_err(|error| error.to_string())?);
                }
                "--help" | "-h" => return Err(usage()),
                other => return Err(format!("unknown argument '{other}'\n{}", usage())),
            }
        }
        let version = version.ok_or_else(|| format!("--version\n{}", usage()))?;
        if let Some(output) = write_inf {
            return Ok(Command::WriteInf { output, version });
        }
        Ok(Command::Package(Arguments {
            architecture: architecture.ok_or_else(|| format!("--architecture\n{}", usage()))?,
            minidriver: minidriver.ok_or_else(|| format!("--minidriver\n{}", usage()))?,
            agent: agent.ok_or_else(|| format!("--agent\n{}", usage()))?,
            driver_package,
            output: output.ok_or_else(|| format!("--output\n{}", usage()))?,
            version,
        }))
    }

    /// The INF's `DriverVer` for a build stamped `version`.
    fn driver_version(version: Version) -> DriverVersion {
        DriverVersion {
            year: version.year,
            month: version.month,
            day: version.day,
            time_of_day: version.time_of_day(),
        }
    }

    /// The INF for a build stamped `version`.
    fn card_inf(version: Version) -> Result<String, String> {
        inf::card_inf(CARDS, driver_version(version)).map_err(|error| error.to_string())
    }

    /// Checks that the INF in `directory` is the one these registrations
    /// produce, so the names in Device Manager cannot drift from the cards
    /// the package binds. A signing service may stamp its own `DriverVer`,
    /// so that line is left out of the comparison.
    fn check_driver_package(directory: &Path, version: Version) -> Result<(), String> {
        let inf_path = directory.join(inf::INF_FILE);
        let supplied = std::fs::read_to_string(&inf_path)
            .map_err(|error| format!("{}: {error}", inf_path.display()))?;
        let expected = card_inf(version)?;
        let without_driver_ver = |text: &str| -> Vec<String> {
            text.lines()
                .filter(|line| !line.starts_with("DriverVer="))
                .map(str::to_owned)
                .collect()
        };
        if without_driver_ver(&supplied) != without_driver_ver(&expected) {
            return Err(format!(
                "{} is not the INF of these card registrations; regenerate it with --write-inf",
                inf_path.display()
            ));
        }
        let catalog = directory.join(inf::CATALOG_FILE);
        if !catalog.is_file() {
            return Err(format!("{} is missing", catalog.display()));
        }
        Ok(())
    }

    /// The Calais registration of every card, under `keys` in the order of
    /// [`CARDS`], and the agent's Run value.
    fn registry_values(keys: &[String]) -> Vec<RegistryValue<'_>> {
        let mut registry = Vec::with_capacity(CARDS.len() * 5);
        for (card, key) in CARDS.iter().zip(keys) {
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
        registry.push(RegistryValue {
            key: RUN_KEY,
            name: RUN_VALUE,
            data: RegistryData::Text(AGENT_COMMAND),
        });
        registry
    }

    pub fn run() -> Result<(), String> {
        let arguments = match parse_arguments()? {
            Command::WriteInf { output, version } => {
                std::fs::write(&output, card_inf(version)?)
                    .map_err(|error| format!("{}: {error}", output.display()))?;
                println!("{}", output.display());
                return Ok(());
            }
            Command::Package(arguments) => arguments,
        };
        let version = arguments.version;
        let upgrade_code = Guid::parse(UPGRADE_CODE).map_err(|error| error.to_string())?;

        let keys: Vec<String> = CARDS
            .iter()
            .map(|card| format!("{CALAIS}\\{}", card.name))
            .collect();
        let registry = registry_values(&keys);

        if let Some(directory) = &arguments.driver_package {
            check_driver_package(directory, version)?;
        }
        let driver_files = arguments.driver_package.as_ref().map(|directory| {
            (
                directory.join(inf::INF_FILE),
                directory.join(inf::CATALOG_FILE),
            )
        });
        let driver_package = driver_files
            .as_ref()
            .map(|(inf_path, catalog_path)| DriverPackage {
                inf: SystemFile {
                    key: "CardDriverInf",
                    name: inf::INF_FILE,
                    source: inf_path,
                },
                catalog: SystemFile {
                    key: "CardDriverCatalog",
                    name: inf::CATALOG_FILE,
                    source: catalog_path,
                },
            });
        let mut custom_actions = KEY_STORAGE_PROVIDER_ACTIONS.to_vec();
        custom_actions.extend_from_slice(CARD_REGISTRATION_CLEANUP_ACTIONS);
        if driver_package.is_some() {
            custom_actions.extend_from_slice(DRIVER_PACKAGE_ACTIONS);
        }

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
            agent: SystemFile {
                key: "AgentExe",
                name: AGENT_FILE,
                source: &arguments.agent,
            },
            driver_package,
            registry: &registry,
            owned_keys: &keys,
            strays: STRAYS,
            custom_actions: &custom_actions,
            // Windows caches the card database, so it must be restarted for a
            // new or removed registration to take effect.
            restart_service: Some("SCardSvr"),
        };

        let scratch = arguments
            .output
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("cabinet");
        build(&package, &arguments.output, &scratch).map_err(|error| error.to_string())?;
        let _ = std::fs::remove_dir(&scratch);

        println!("{}", arguments.output.display());
        Ok(())
    }
}
