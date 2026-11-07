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

//! Authors the Windows Installer package for the Card Module.
//!
//! An MSI is a relational database in a compound file, and Windows ships the
//! API that writes one. This crate uses that API directly, so building the
//! installer needs nothing beyond Windows itself and `makecab.exe`.
//!
//! The package this describes is deliberately small: one system DLL, the
//! registry values that bind it to a card, the agent, a service restart
//! and, when a signed one is supplied, the Plug and Play driver package
//! that names the cards in Device Manager. Its only custom actions are the
//! Card Module's own entry points. Every newer package replaces the one
//! installed, and installing one removes what installations outside the
//! package left (`doc/installer-upgrade.md`).

#![cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "the Windows Installer database API is a C boundary with no safe wrapper in windows-sys"
    )
)]

pub mod cards;
pub mod inf;

#[cfg(windows)]
mod cabinet;
#[cfg(windows)]
mod guid;
#[cfg(windows)]
mod handle;
#[cfg(windows)]
mod schema;

#[cfg(windows)]
pub use crate::guid::{Guid, GuidParseError};

#[cfg(windows)]
mod build;
#[cfg(windows)]
pub use crate::build::{
    Architecture, BuildError, CustomAction, DriverPackage, Package, ProductVersion, RegistryData,
    RegistryValue, Schedule, Strays, SystemFile, Version, VersionParseError, build,
};
