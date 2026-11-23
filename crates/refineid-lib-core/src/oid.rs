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

//! ASN.1 OBJECT IDENTIFIER wrapper and known-OID table, re-exported from
//! [`refineid_cms::oid`].

pub use refineid_cms::oid::{Oid, OidError};

/// Known OBJECT IDENTIFIER constants, re-exported from
/// [`refineid_cms::oid::known`] alongside FINEID-specific attributes.
pub mod known {
    pub use refineid_cms::oid::known::*;

    /// X.520 `organizationName` (`O`, OID `2.5.4.10`).
    pub const ORGANIZATION_NAME: super::Oid<'static> =
        super::Oid::const_new(const_oid::ObjectIdentifier::new_unwrap("2.5.4.10").as_bytes());
}
