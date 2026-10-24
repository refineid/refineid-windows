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

//! Installer database schema and standard action sequences.
//!
//! Column types and widths follow Microsoft's Windows Installer database
//! tables reference. Only the tables this package actually populates are
//! created, so an unused table cannot drift out of step with the schema.

/// `CREATE TABLE` statements, in creation order.
pub const TABLES: &[&str] = &[
    "CREATE TABLE `Property` (\
        `Property` CHAR(72) NOT NULL, \
        `Value` CHAR(0) NOT NULL LOCALIZABLE \
        PRIMARY KEY `Property`)",
    "CREATE TABLE `Directory` (\
        `Directory` CHAR(72) NOT NULL, \
        `Directory_Parent` CHAR(72), \
        `DefaultDir` CHAR(255) NOT NULL LOCALIZABLE \
        PRIMARY KEY `Directory`)",
    "CREATE TABLE `Component` (\
        `Component` CHAR(72) NOT NULL, \
        `ComponentId` CHAR(38), \
        `Directory_` CHAR(72) NOT NULL, \
        `Attributes` SHORT NOT NULL, \
        `Condition` CHAR(255), \
        `KeyPath` CHAR(72) \
        PRIMARY KEY `Component`)",
    "CREATE TABLE `Feature` (\
        `Feature` CHAR(38) NOT NULL, \
        `Feature_Parent` CHAR(38), \
        `Title` CHAR(64) LOCALIZABLE, \
        `Description` CHAR(255) LOCALIZABLE, \
        `Display` SHORT, \
        `Level` SHORT NOT NULL, \
        `Directory_` CHAR(72), \
        `Attributes` SHORT NOT NULL \
        PRIMARY KEY `Feature`)",
    "CREATE TABLE `FeatureComponents` (\
        `Feature_` CHAR(38) NOT NULL, \
        `Component_` CHAR(72) NOT NULL \
        PRIMARY KEY `Feature_`, `Component_`)",
    "CREATE TABLE `File` (\
        `File` CHAR(72) NOT NULL, \
        `Component_` CHAR(72) NOT NULL, \
        `FileName` CHAR(255) NOT NULL LOCALIZABLE, \
        `FileSize` LONG NOT NULL, \
        `Version` CHAR(72), \
        `Language` CHAR(20), \
        `Attributes` SHORT, \
        `Sequence` LONG NOT NULL \
        PRIMARY KEY `File`)",
    "CREATE TABLE `Media` (\
        `DiskId` SHORT NOT NULL, \
        `LastSequence` LONG NOT NULL, \
        `DiskPrompt` CHAR(64) LOCALIZABLE, \
        `Cabinet` CHAR(255), \
        `VolumeLabel` CHAR(32), \
        `Source` CHAR(72) \
        PRIMARY KEY `DiskId`)",
    "CREATE TABLE `CustomAction` (\
        `Action` CHAR(72) NOT NULL, \
        `Type` SHORT NOT NULL, \
        `Source` CHAR(72), \
        `Target` CHAR(255) \
        PRIMARY KEY `Action`)",
    "CREATE TABLE `Registry` (\
        `Registry` CHAR(72) NOT NULL, \
        `Root` SHORT NOT NULL, \
        `Key` CHAR(255) NOT NULL LOCALIZABLE, \
        `Name` CHAR(255) LOCALIZABLE, \
        `Value` CHAR(0) LOCALIZABLE, \
        `Component_` CHAR(72) NOT NULL \
        PRIMARY KEY `Registry`)",
    "CREATE TABLE `ServiceControl` (\
        `ServiceControl` CHAR(72) NOT NULL, \
        `Name` CHAR(255) NOT NULL LOCALIZABLE, \
        `Event` SHORT NOT NULL, \
        `Arguments` CHAR(255) LOCALIZABLE, \
        `Wait` SHORT, \
        `Component_` CHAR(72) NOT NULL \
        PRIMARY KEY `ServiceControl`)",
    "CREATE TABLE `Upgrade` (\
        `UpgradeCode` CHAR(38) NOT NULL, \
        `VersionMin` CHAR(20), \
        `VersionMax` CHAR(20), \
        `Language` CHAR(255), \
        `Attributes` LONG NOT NULL, \
        `Remove` CHAR(255), \
        `ActionProperty` CHAR(72) NOT NULL \
        PRIMARY KEY `UpgradeCode`, `VersionMin`, `VersionMax`, `Language`, `Attributes`)",
    "CREATE TABLE `LaunchCondition` (\
        `Condition` CHAR(255) NOT NULL, \
        `Description` CHAR(255) NOT NULL LOCALIZABLE \
        PRIMARY KEY `Condition`)",
    "CREATE TABLE `InstallExecuteSequence` (\
        `Action` CHAR(72) NOT NULL, \
        `Condition` CHAR(255), \
        `Sequence` SHORT \
        PRIMARY KEY `Action`)",
    "CREATE TABLE `InstallUISequence` (\
        `Action` CHAR(72) NOT NULL, \
        `Condition` CHAR(255), \
        `Sequence` SHORT \
        PRIMARY KEY `Action`)",
    "CREATE TABLE `AdminExecuteSequence` (\
        `Action` CHAR(72) NOT NULL, \
        `Condition` CHAR(255), \
        `Sequence` SHORT \
        PRIMARY KEY `Action`)",
    "CREATE TABLE `AdvtExecuteSequence` (\
        `Action` CHAR(72) NOT NULL, \
        `Condition` CHAR(255), \
        `Sequence` SHORT \
        PRIMARY KEY `Action`)",
];

/// One row of a sequence table: action, optional condition, sequence number.
pub type SequencedAction = (&'static str, Option<&'static str>, i32);

/// Actions run for install, repair, and uninstall.
///
/// `RemoveExistingProducts` sits immediately after `InstallInitialize`, so an
/// upgrade fully removes the previous package before laying down the new one.
/// For a single system DLL that ordering is the least surprising.
pub const INSTALL_EXECUTE_SEQUENCE: &[SequencedAction] = &[
    ("LaunchConditions", None, 100),
    ("FindRelatedProducts", None, 200),
    ("CostInitialize", None, 800),
    ("FileCost", None, 900),
    ("CostFinalize", None, 1000),
    ("InstallValidate", None, 1400),
    ("InstallInitialize", None, 1500),
    ("RemoveExistingProducts", None, 1510),
    ("ProcessComponents", None, 1600),
    ("UnpublishFeatures", None, 1800),
    ("StopServices", None, 1900),
    ("RemoveRegistryValues", None, 2600),
    ("RemoveFiles", None, 3500),
    ("RemoveFolders", None, 3600),
    ("CreateFolders", None, 3700),
    ("InstallFiles", None, 4000),
    ("WriteRegistryValues", None, 5000),
    ("StartServices", None, 5900),
    ("RegisterProduct", None, 6100),
    ("PublishFeatures", None, 6300),
    ("PublishProduct", None, 6400),
    ("InstallFinalize", None, 6600),
];

/// Costing plus the handoff to the execute sequence.
///
/// The package authors no dialogs, so a full-UI invocation falls back to the
/// basic progress display rather than showing a wizard.
pub const INSTALL_UI_SEQUENCE: &[SequencedAction] = &[
    ("LaunchConditions", None, 100),
    ("FindRelatedProducts", None, 200),
    ("CostInitialize", None, 800),
    ("FileCost", None, 900),
    ("CostFinalize", None, 1000),
    ("ExecuteAction", None, 1300),
];

/// Administrative installation, which only lays down a source image.
pub const ADMIN_EXECUTE_SEQUENCE: &[SequencedAction] = &[
    ("CostInitialize", None, 800),
    ("FileCost", None, 900),
    ("CostFinalize", None, 1000),
    ("InstallValidate", None, 1400),
    ("InstallInitialize", None, 1500),
    ("InstallAdminPackage", None, 3900),
    ("InstallFiles", None, 4000),
    ("InstallFinalize", None, 6600),
];

/// Advertisement, which this package does not support beyond publishing.
pub const ADVT_EXECUTE_SEQUENCE: &[SequencedAction] = &[
    ("CostInitialize", None, 800),
    ("CostFinalize", None, 1000),
    ("InstallValidate", None, 1400),
    ("InstallInitialize", None, 1500),
    ("PublishFeatures", None, 6300),
    ("PublishProduct", None, 6400),
    ("InstallFinalize", None, 6600),
];

/// `HKEY_LOCAL_MACHINE` in the `Registry` table's `Root` column.
pub const REGISTRY_ROOT_LOCAL_MACHINE: i32 = 2;

/// A custom action that calls an entry point of an installed DLL
/// (`msidbCustomActionTypeDll | msidbCustomActionTypeSourceFile`), deferred
/// into the installation script and run without impersonation, so it has
/// the installer's elevation after the file is in place.
pub const CUSTOM_ACTION_INSTALLED_DLL_DEFERRED: i32 = 1 | 0x10 | 0x400 | 0x800;

/// Sequence number of the first uninstall custom action: after services
/// stop and before registry values and files go.
pub const UNINSTALL_ACTION_SEQUENCE: i32 = 2500;

/// Sequence number of the first install custom action: after the files are
/// in place.
pub const INSTALL_ACTION_SEQUENCE: i32 = 4100;

/// Component installs locally and its key path is a registry value.
pub const COMPONENT_REGISTRY_KEY_PATH: i32 = 4;

/// Component is written to the 64-bit file and registry views.
pub const COMPONENT_64BIT: i32 = 256;

/// Start the service during installation.
pub const SERVICE_EVENT_START: i32 = 1;
/// Stop the service during installation.
pub const SERVICE_EVENT_STOP: i32 = 2;
/// Stop the service during uninstallation.
pub const SERVICE_EVENT_UNINSTALL_STOP: i32 = 32;

/// Treat `VersionMin` as inclusive when detecting a related product.
pub const UPGRADE_VERSION_MIN_INCLUSIVE: i32 = 256;
/// Treat `VersionMax` as inclusive when detecting a related product.
pub const UPGRADE_VERSION_MAX_INCLUSIVE: i32 = 512;
/// Detect a related product without removing it.
pub const UPGRADE_ONLY_DETECT: i32 = 2;
