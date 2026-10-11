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

//! The package description and the code that writes it to a database.

use core::fmt::{self, Write as _};
use std::path::Path;

use crate::cabinet::{self, CabinetError, Member};
use crate::guid::Guid;
use crate::handle::{Database, MsiError, Record, SummaryValue};
use crate::schema;

/// The cabinet holding the payload, embedded as a database stream.
const CABINET_NAME: &str = "payload.cab";
/// Component holding the Card Module itself.
const COMPONENT_FILE: &str = "MinidriverDll";
/// Component holding the card registrations.
const COMPONENT_REGISTRY: &str = "CardRegistration";
/// The package's single feature.
const FEATURE: &str = "Main";
/// Standard directory property for the native system directory.
const SYSTEM_DIRECTORY: &str = "System64Folder";
/// Property set when an older package is found.
const OLDER_VERSION: &str = "OLDERVERSIONBEINGUPGRADED";
/// Property set when a newer package is found.
const NEWER_VERSION: &str = "NEWERVERSIONDETECTED";
/// `msidbFileAttributesVital`.
const FILE_VITAL: i32 = 512;

/// The processor architecture a package targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    /// 64-bit x86.
    X64,
    /// 64-bit Arm.
    Arm64,
}

impl Architecture {
    /// The summary information template, which Windows Installer checks
    /// before it will install a package on a machine.
    const fn template(self) -> &'static str {
        match self {
            Self::X64 => "x64;1033",
            Self::Arm64 => "Arm64;1033",
        }
    }

    /// The name used in output file names and on the command line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
        }
    }
}

/// The project's `YY.M.D.B` calendar version.
///
/// `B` is a within-day ten-minute bucket, `hour * 10 + minute / 10`, so it
/// ranges 0 to 235.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Years since 2000.
    pub year: u8,
    /// Month, 1 to 12.
    pub month: u8,
    /// Day of month, 1 to 31.
    pub day: u8,
    /// Ten-minute bucket within the day, 0 to 235.
    pub bucket: u16,
}

/// A version string was not a usable `YY.M.D.B`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionParseError;

impl fmt::Display for VersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "expected YY.M.D.B with month 1-12, day 1-31, and bucket 0-235 \
             (hour * 10 + minute / 10)",
        )
    }
}

impl std::error::Error for VersionParseError {}

impl Version {
    /// Parses the canonical four-component form, as stored in `VERSION`.
    ///
    /// # Errors
    ///
    /// Returns an error if the text is not four numbers in range.
    pub fn parse(text: &str) -> Result<Self, VersionParseError> {
        let parts: Vec<&str> = text.trim().split('.').collect();
        let [year, month, day, bucket] = parts.as_slice() else {
            return Err(VersionParseError);
        };
        let version = Self {
            year: year.parse().map_err(|_| VersionParseError)?,
            month: month.parse().map_err(|_| VersionParseError)?,
            day: day.parse().map_err(|_| VersionParseError)?,
            bucket: bucket.parse().map_err(|_| VersionParseError)?,
        };
        if !(1..=12).contains(&version.month)
            || !(1..=31).contains(&version.day)
            || version.bucket > MAXIMUM_BUCKET
        {
            return Err(VersionParseError);
        }
        Ok(version)
    }

    /// Projects onto the three fields Windows Installer actually compares.
    ///
    /// `ProductVersion` has no fourth field, and a fourth is ignored during
    /// upgrade detection, so the day and the bucket are folded into the
    /// build field as `day * 1000 + bucket`. That keeps the printed form
    /// readable, stays inside the 65535 limit at its largest value of
    /// 31235, and preserves ordering: within a month the build field rises
    /// with the day and then the time, and across a month or year boundary
    /// the higher fields carry the comparison.
    #[must_use]
    pub const fn product_version(self) -> ProductVersion {
        ProductVersion {
            major: self.year,
            minor: self.month,
            build: self.day as u16 * 1000 + self.bucket,
        }
    }
}

/// The largest ten-minute bucket in a day, at 23:50.
const MAXIMUM_BUCKET: u16 = 235;

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.year, self.month, self.day, self.bucket
        )
    }
}

/// The three-field version written into the package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProductVersion {
    /// Major field.
    pub major: u8,
    /// Minor field.
    pub minor: u8,
    /// Build field, carrying both the day and the bucket.
    pub build: u16,
}

impl fmt::Display for ProductVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

/// A file installed into the native system directory.
#[derive(Debug, Clone, Copy)]
pub struct SystemFile<'a> {
    /// Identifier used as the `File` key and as the name inside the cabinet.
    pub key: &'a str,
    /// The installed file name.
    pub name: &'a str,
    /// Path to the built file on disk.
    pub source: &'a Path,
}

/// The data written to a registry value.
#[derive(Debug, Clone, Copy)]
pub enum RegistryData<'a> {
    /// A `REG_SZ` value.
    Text(&'a str),
    /// A `REG_BINARY` value.
    Binary(&'a [u8]),
    /// A `REG_DWORD` value.
    Dword(u32),
    /// A `REG_MULTI_SZ` value, written whole.
    MultiText(&'a [&'a str]),
    /// One string appended to an existing `REG_MULTI_SZ` value, and removed
    /// from it again on uninstall. The value is created when absent.
    AppendText(&'a str),
}

/// One value under `HKEY_LOCAL_MACHINE`.
#[derive(Debug, Clone, Copy)]
pub struct RegistryValue<'a> {
    /// Subkey path, without the root.
    pub key: &'a str,
    /// Value name; empty for the key's default value (the installer stores
    /// an empty string as a null `Name` column).
    pub name: &'a str,
    /// Value data.
    pub data: RegistryData<'a>,
}

/// Everything needed to produce one architecture's package.
#[derive(Debug, Clone, Copy)]
pub struct Package<'a> {
    /// Name shown in Installed Apps.
    pub product_name: &'a str,
    /// Publisher shown in Installed Apps.
    pub manufacturer: &'a str,
    /// One-line description recorded in the package summary.
    pub description: &'a str,
    /// Product version, which drives upgrade detection.
    pub version: Version,
    /// The only authored identifier. Every other GUID derives from it, so it
    /// must never change for this product.
    pub upgrade_code: Guid,
    /// Target architecture.
    pub architecture: Architecture,
    /// The Card Module.
    pub file: SystemFile<'a>,
    /// Registry values binding the module to supported cards.
    pub registry: &'a [RegistryValue<'a>],
    /// A service stopped before installation and started afterwards.
    pub restart_service: Option<&'a str>,
}

/// Building a package failed.
#[derive(Debug)]
pub enum BuildError {
    /// A Windows Installer call failed.
    Msi(MsiError),
    /// The cabinet could not be built.
    Cabinet(CabinetError),
    /// A payload file could not be read.
    Io(std::io::Error),
    /// The package description is not installable as written.
    Invalid(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Msi(error) => write!(f, "{error}"),
            Self::Cabinet(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Invalid(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<MsiError> for BuildError {
    fn from(error: MsiError) -> Self {
        Self::Msi(error)
    }
}

impl From<CabinetError> for BuildError {
    fn from(error: CabinetError) -> Self {
        Self::Cabinet(error)
    }
}

impl From<std::io::Error> for BuildError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Encodes registry data the way the `Registry` table expects it.
///
/// A leading `#x` marks hexadecimal binary and a leading `#` a decimal
/// `DWORD`; plain text is stored as written. `[~]` separates the strings of
/// a `REG_MULTI_SZ`: a value that both starts and ends with it is written
/// whole, and one that only starts with it is appended to what is there.
fn encode_registry(data: RegistryData<'_>) -> String {
    match data {
        RegistryData::Text(text) => text.to_owned(),
        RegistryData::Binary(bytes) => {
            let mut encoded = String::with_capacity(2 + bytes.len() * 2);
            encoded.push_str("#x");
            for byte in bytes {
                // Writing into a String cannot fail.
                let _ = write!(encoded, "{byte:02x}");
            }
            encoded
        }
        RegistryData::Dword(value) => format!("#{value}"),
        RegistryData::MultiText(strings) => format!("[~]{}[~]", strings.join("[~]")),
        RegistryData::AppendText(text) => format!("[~]{text}"),
    }
}

/// The `Registry` table key for the value at `index`.
///
/// The first one is also the registry component's key path, so both places
/// must agree on how it is spelled.
fn registry_identifier(index: usize) -> String {
    format!("Registry{index}")
}

/// Derives an 8.3 name for a file whose real name is longer.
///
/// Windows Installer wants a short name alongside the long one. The payload
/// is a single known file, so a deterministic truncation is sufficient and
/// avoids carrying a collision table for names that do not exist.
fn short_name(name: &str) -> String {
    let (stem, extension) = name.rsplit_once('.').unwrap_or((name, ""));
    let squeeze = |text: &str, limit: usize| -> String {
        text.chars()
            .filter(char::is_ascii_alphanumeric)
            .take(limit)
            .collect::<String>()
            .to_uppercase()
    };
    let stem = squeeze(stem, 8);
    let extension = squeeze(extension, 3);
    if extension.is_empty() {
        stem
    } else {
        format!("{stem}.{extension}")
    }
}

fn insert(database: &Database, sql: &str, values: &[Value<'_>]) -> Result<(), BuildError> {
    let mut record = Record::new(u32::try_from(values.len()).unwrap_or(u32::MAX))?;
    for (index, value) in values.iter().enumerate() {
        let field = u32::try_from(index + 1).unwrap_or(u32::MAX);
        match value {
            Value::Text(text) => record.set_string(field, text)?,
            Value::Integer(number) => record.set_integer(field, *number)?,
            Value::Stream(path) => record.set_stream(field, path)?,
        }
    }
    database.execute_with(sql, &record)?;
    Ok(())
}

/// A bound parameter.
enum Value<'a> {
    Text(&'a str),
    Integer(i32),
    Stream(&'a Path),
}

fn sequence_rows(
    database: &Database,
    table: &str,
    rows: &[schema::SequencedAction],
) -> Result<(), BuildError> {
    let sql = format!("INSERT INTO `{table}` (`Action`,`Condition`,`Sequence`) VALUES (?,?,?)");
    for (action, condition, order) in rows {
        insert(
            database,
            &sql,
            &[
                Value::Text(action),
                Value::Text(condition.unwrap_or_default()),
                Value::Integer(*order),
            ],
        )?;
    }
    Ok(())
}

/// Writes `package` to `output`, replacing any existing file.
///
/// `scratch` holds the cabinet while it is built; it is created if missing.
///
/// # Errors
///
/// Returns an error if the description is not installable, the payload
/// cannot be read, the cabinet cannot be built, or any database write fails.
pub fn build(package: &Package<'_>, output: &Path, scratch: &Path) -> Result<(), BuildError> {
    if package.registry.is_empty() {
        return Err(BuildError::Invalid(
            "the package must register at least one card, or nothing binds the module".to_owned(),
        ));
    }
    let payload = std::fs::metadata(package.file.source)?;
    let payload_size = i32::try_from(payload.len())
        .map_err(|_| BuildError::Invalid("the payload exceeds 2 GiB".to_owned()))?;

    let cabinet = cabinet::build(
        scratch,
        CABINET_NAME,
        &[Member {
            source: package.file.source,
            key: package.file.key,
        }],
    )?;

    let product_code = package
        .upgrade_code
        .derive(&format!("ProductCode/{}", package.version));
    // A package code identifies one built image, so it varies with the
    // architecture as well as the version.
    let package_code = package.upgrade_code.derive(&format!(
        "PackageCode/{}/{}",
        package.version,
        package.architecture.name()
    ));
    // The database carries the three-field projection, because that is what
    // Windows Installer compares; the full YY.M.D.B stays in the derived
    // identifiers and the file name so a rebuilt package is still distinct.
    let version = package.version.product_version().to_string();

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let database = Database::create(output)?;

    for statement in schema::TABLES {
        database.execute(statement)?;
    }

    let upgrade_code = package.upgrade_code.to_string();
    write_identity(
        &database,
        package,
        &product_code.to_string(),
        &version,
        &upgrade_code,
    )?;
    write_layout(&database, package)?;
    write_payload(&database, package, &cabinet, payload_size)?;
    write_registry(&database, package)?;
    write_service(&database, package)?;
    write_upgrade_rules(&database, package, &upgrade_code, &version)?;
    write_sequences(&database)?;

    let package_code_text = package_code.to_string();
    database.write_summary_information(&[
        (2, SummaryValue::Text("Installation Database")),
        (3, SummaryValue::Text(package.product_name)),
        (4, SummaryValue::Text(package.manufacturer)),
        (5, SummaryValue::Text("Installer,MSI,Smart Card,Minidriver")),
        (6, SummaryValue::Text(package.description)),
        (7, SummaryValue::Text(package.architecture.template())),
        (9, SummaryValue::Text(&package_code_text)),
        // Windows Installer 5.0, which every supported Windows provides.
        (14, SummaryValue::Integer(500)),
        // The payload is compressed inside the package.
        (15, SummaryValue::Integer(2)),
        (18, SummaryValue::Text("refineid-msi")),
        // Read-only recommended.
        (19, SummaryValue::Integer(2)),
    ])?;

    database.commit()?;
    let _ = std::fs::remove_file(&cabinet);
    Ok(())
}

/// Writes the product identity Windows uses to track the installation.
fn write_identity(
    database: &Database,
    package: &Package<'_>,
    product_code: &str,
    version: &str,
    upgrade_code: &str,
) -> Result<(), BuildError> {
    let properties: &[(&str, &str)] = &[
        ("ProductCode", product_code),
        ("ProductName", package.product_name),
        ("ProductVersion", version),
        ("ProductLanguage", "1033"),
        ("Manufacturer", package.manufacturer),
        ("UpgradeCode", upgrade_code),
        // Per-machine: the module lands in a system directory.
        ("ALLUSERS", "1"),
        // There are no optional features, so offer no Change button.
        ("ARPNOMODIFY", "1"),
    ];
    for (name, value) in properties {
        insert(
            database,
            "INSERT INTO `Property` (`Property`,`Value`) VALUES (?,?)",
            &[Value::Text(name), Value::Text(value)],
        )?;
    }
    Ok(())
}

/// Writes the directory, component, and feature rows the payload hangs from.
fn write_layout(database: &Database, package: &Package<'_>) -> Result<(), BuildError> {
    let directory_sql =
        "INSERT INTO `Directory` (`Directory`,`Directory_Parent`,`DefaultDir`) VALUES (?,?,?)";
    insert(
        database,
        directory_sql,
        &[
            Value::Text("TARGETDIR"),
            Value::Text(""),
            Value::Text("SourceDir"),
        ],
    )?;
    insert(
        database,
        directory_sql,
        &[
            Value::Text(SYSTEM_DIRECTORY),
            Value::Text("TARGETDIR"),
            Value::Text("."),
        ],
    )?;

    let file_component_id = package.upgrade_code.derive(COMPONENT_FILE).to_string();
    let registry_component_id = package.upgrade_code.derive(COMPONENT_REGISTRY).to_string();
    let first_registry_key = registry_identifier(0);
    let component_sql = "INSERT INTO `Component` \
        (`Component`,`ComponentId`,`Directory_`,`Attributes`,`Condition`,`KeyPath`) \
        VALUES (?,?,?,?,?,?)";
    insert(
        database,
        component_sql,
        &[
            Value::Text(COMPONENT_FILE),
            Value::Text(&file_component_id),
            Value::Text(SYSTEM_DIRECTORY),
            Value::Integer(schema::COMPONENT_64BIT),
            Value::Text(""),
            Value::Text(package.file.key),
        ],
    )?;
    insert(
        database,
        component_sql,
        &[
            Value::Text(COMPONENT_REGISTRY),
            Value::Text(&registry_component_id),
            Value::Text(SYSTEM_DIRECTORY),
            Value::Integer(schema::COMPONENT_64BIT | schema::COMPONENT_REGISTRY_KEY_PATH),
            Value::Text(""),
            Value::Text(&first_registry_key),
        ],
    )?;

    insert(
        database,
        "INSERT INTO `Feature` \
            (`Feature`,`Feature_Parent`,`Title`,`Description`,`Display`,`Level`,`Directory_`,`Attributes`) \
            VALUES (?,?,?,?,?,?,?,?)",
        &[
            Value::Text(FEATURE),
            Value::Text(""),
            Value::Text(package.product_name),
            Value::Text(package.description),
            Value::Integer(1),
            Value::Integer(1),
            Value::Text(""),
            Value::Integer(0),
        ],
    )?;
    for component in [COMPONENT_FILE, COMPONENT_REGISTRY] {
        insert(
            database,
            "INSERT INTO `FeatureComponents` (`Feature_`,`Component_`) VALUES (?,?)",
            &[Value::Text(FEATURE), Value::Text(component)],
        )?;
    }
    Ok(())
}

/// Writes the file row and embeds the cabinet that carries it.
fn write_payload(
    database: &Database,
    package: &Package<'_>,
    cabinet: &Path,
    payload_size: i32,
) -> Result<(), BuildError> {
    let file_name = format!("{}|{}", short_name(package.file.name), package.file.name);
    insert(
        database,
        "INSERT INTO `File` \
            (`File`,`Component_`,`FileName`,`FileSize`,`Version`,`Language`,`Attributes`,`Sequence`) \
            VALUES (?,?,?,?,?,?,?,?)",
        &[
            Value::Text(package.file.key),
            Value::Text(COMPONENT_FILE),
            Value::Text(&file_name),
            Value::Integer(payload_size),
            Value::Text(""),
            Value::Text(""),
            Value::Integer(FILE_VITAL),
            Value::Integer(1),
        ],
    )?;

    // A leading '#' names a stream inside the package rather than a file
    // beside it, which is what makes this a single-file installer.
    let embedded = format!("#{CABINET_NAME}");
    insert(
        database,
        "INSERT INTO `Media` \
            (`DiskId`,`LastSequence`,`DiskPrompt`,`Cabinet`,`VolumeLabel`,`Source`) \
            VALUES (?,?,?,?,?,?)",
        &[
            Value::Integer(1),
            Value::Integer(1),
            Value::Text(""),
            Value::Text(&embedded),
            Value::Text(""),
            Value::Text(""),
        ],
    )?;
    insert(
        database,
        "INSERT INTO `_Streams` (`Name`,`Data`) VALUES (?,?)",
        &[Value::Text(CABINET_NAME), Value::Stream(cabinet)],
    )?;
    Ok(())
}

/// Writes the card registrations that bind Windows to the Card Module.
fn write_registry(database: &Database, package: &Package<'_>) -> Result<(), BuildError> {
    for (index, value) in package.registry.iter().enumerate() {
        let identifier = registry_identifier(index);
        let data = encode_registry(value.data);
        insert(
            database,
            "INSERT INTO `Registry` \
                (`Registry`,`Root`,`Key`,`Name`,`Value`,`Component_`) VALUES (?,?,?,?,?,?)",
            &[
                Value::Text(&identifier),
                Value::Integer(schema::REGISTRY_ROOT_LOCAL_MACHINE),
                Value::Text(value.key),
                Value::Text(value.name),
                Value::Text(&data),
                Value::Text(COMPONENT_REGISTRY),
            ],
        )?;
    }

    Ok(())
}

/// Writes the service restart, if the package asks for one.
fn write_service(database: &Database, package: &Package<'_>) -> Result<(), BuildError> {
    if let Some(service) = package.restart_service {
        insert(
            database,
            "INSERT INTO `ServiceControl` \
                (`ServiceControl`,`Name`,`Event`,`Arguments`,`Wait`,`Component_`) \
                VALUES (?,?,?,?,?,?)",
            &[
                Value::Text("RestartCardService"),
                Value::Text(service),
                Value::Integer(
                    schema::SERVICE_EVENT_START
                        | schema::SERVICE_EVENT_STOP
                        | schema::SERVICE_EVENT_UNINSTALL_STOP,
                ),
                Value::Text(""),
                Value::Integer(1),
                Value::Text(COMPONENT_FILE),
            ],
        )?;
    }

    Ok(())
}

/// Writes major-upgrade detection and the downgrade guard.
fn write_upgrade_rules(
    database: &Database,
    package: &Package<'_>,
    upgrade_code: &str,
    version: &str,
) -> Result<(), BuildError> {
    let upgrade_sql = "INSERT INTO `Upgrade` \
        (`UpgradeCode`,`VersionMin`,`VersionMax`,`Language`,`Attributes`,`Remove`,`ActionProperty`) \
        VALUES (?,?,?,?,?,?,?)";
    // Anything below this version is removed on install; the maximum is
    // exclusive so a package never detects itself as an older product.
    insert(
        database,
        upgrade_sql,
        &[
            Value::Text(upgrade_code),
            Value::Text("0.0.0"),
            Value::Text(version),
            Value::Text(""),
            Value::Integer(schema::UPGRADE_VERSION_MIN_INCLUSIVE),
            Value::Text(""),
            Value::Text(OLDER_VERSION),
        ],
    )?;
    // Anything strictly above is only detected, so a downgrade fails the
    // launch condition instead of silently replacing newer files.
    insert(
        database,
        upgrade_sql,
        &[
            Value::Text(upgrade_code),
            Value::Text(version),
            Value::Text(""),
            Value::Text(""),
            Value::Integer(schema::UPGRADE_ONLY_DETECT),
            Value::Text(""),
            Value::Text(NEWER_VERSION),
        ],
    )?;

    let downgrade_message = format!(
        "A newer version of {} is already installed.",
        package.product_name
    );
    let downgrade_condition = format!("NOT {NEWER_VERSION}");
    insert(
        database,
        "INSERT INTO `LaunchCondition` (`Condition`,`Description`) VALUES (?,?)",
        &[
            Value::Text(&downgrade_condition),
            Value::Text(&downgrade_message),
        ],
    )?;
    Ok(())
}

/// Writes the standard action sequences.
fn write_sequences(database: &Database) -> Result<(), BuildError> {
    sequence_rows(
        database,
        "InstallExecuteSequence",
        schema::INSTALL_EXECUTE_SEQUENCE,
    )?;
    sequence_rows(database, "InstallUISequence", schema::INSTALL_UI_SEQUENCE)?;
    sequence_rows(
        database,
        "AdminExecuteSequence",
        schema::ADMIN_EXECUTE_SEQUENCE,
    )?;
    sequence_rows(
        database,
        "AdvtExecuteSequence",
        schema::ADVT_EXECUTE_SEQUENCE,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RegistryData, Version, encode_registry, short_name};

    #[test]
    fn binary_registry_data_uses_the_hexadecimal_prefix() {
        let encoded = encode_registry(RegistryData::Binary(&[0x3b, 0x7f, 0x00, 0xff]));
        assert_eq!(encoded, "#x3b7f00ff");
    }

    #[test]
    fn text_registry_data_is_stored_verbatim() {
        let encoded = encode_registry(RegistryData::Text("refineid_minidriver.dll"));
        assert_eq!(encoded, "refineid_minidriver.dll");
    }

    #[test]
    fn empty_binary_data_still_carries_the_prefix() {
        assert_eq!(encode_registry(RegistryData::Binary(&[])), "#x");
    }

    #[test]
    fn dword_data_is_decimal_behind_a_hash() {
        assert_eq!(encode_registry(RegistryData::Dword(0)), "#0");
        assert_eq!(encode_registry(RegistryData::Dword(65537)), "#65537");
    }

    #[test]
    fn multi_strings_are_delimited_at_both_ends() {
        assert_eq!(
            encode_registry(RegistryData::MultiText(&["KEY_STORAGE"])),
            "[~]KEY_STORAGE[~]"
        );
        assert_eq!(
            encode_registry(RegistryData::MultiText(&["a", "b"])),
            "[~]a[~]b[~]"
        );
    }

    #[test]
    fn an_appended_string_is_delimited_only_in_front() {
        assert_eq!(
            encode_registry(RegistryData::AppendText("RefineID Key Storage Provider")),
            "[~]RefineID Key Storage Provider"
        );
    }

    #[test]
    fn parses_the_canonical_four_component_form() {
        let version = Version::parse("26.8.7.153").expect("parses");
        assert_eq!(
            version,
            Version {
                year: 26,
                month: 8,
                day: 7,
                bucket: 153,
            }
        );
        assert_eq!(version.to_string(), "26.8.7.153");
    }

    #[test]
    fn rejects_out_of_range_components() {
        for text in [
            "26.8.7",     // three components
            "26.13.7.0",  // month
            "26.8.32.0",  // day
            "26.8.7.236", // bucket above 23:50
            "26.8.7.0.1", // five components
            "twentysix.8.7.0",
        ] {
            assert!(Version::parse(text).is_err(), "{text} must be rejected");
        }
    }

    #[test]
    fn the_projection_folds_the_day_and_bucket() {
        let version = Version::parse("26.8.7.153").expect("parses");
        assert_eq!(version.product_version().to_string(), "26.8.7153");
    }

    #[test]
    fn the_projection_stays_inside_the_installer_limit() {
        // The largest value the fold can produce: day 31 at 23:50. Windows
        // Installer caps the build field at 65535, so this leaves headroom
        // and the u16 arithmetic in the fold cannot wrap.
        let latest = Version::parse("99.12.31.235").expect("parses");
        assert_eq!(latest.product_version().build, 31_235);
    }

    #[test]
    fn the_projection_preserves_ordering() {
        let ordered = [
            "26.8.7.0",
            "26.8.7.153",
            "26.8.7.235",
            "26.8.8.0",
            "26.8.31.235",
            "26.9.1.0",
            "26.12.31.235",
            "27.1.1.0",
        ];
        let projected: Vec<_> = ordered
            .iter()
            .map(|text| Version::parse(text).expect("parses").product_version())
            .collect();
        for pair in projected.windows(2) {
            assert!(
                pair[0] < pair[1],
                "{:?} must precede {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn short_names_fit_the_eight_three_limit() {
        assert_eq!(short_name("refineid_minidriver.dll"), "REFINEID.DLL");
        assert_eq!(short_name("a.b"), "A.B");
        assert_eq!(short_name("noextension"), "NOEXTENS");
    }
}
