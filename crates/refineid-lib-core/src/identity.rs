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

//! Credential-and-holder identity derived from X.509 subject attributes
//! and [`PrintedSerial`].

use core::fmt;
use core::ops::Deref;

use refineid_pkcs15::PrintedSerial;

/// Total ASCII length of a Finnish PEUIN / SATU identifier (8 digits + 1 checksum).
const PEUIN_LEN: usize = 9;
/// Number of leading ASCII digit positions in a PEUIN.
const PEUIN_DIGITS_LEN: usize = 8;
/// Zero-based index of the alphanumeric checksum character in a PEUIN.
const PEUIN_CHECKSUM_INDEX: usize = 8;

/// Personal Electronic Unique Identification Number (DVV `SATU` / `FINUID`).
///
/// Constructor enforces the shape (9 ASCII bytes: 8 digits followed by one
/// alphanumeric checksum character).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Peuin([u8; PEUIN_LEN]);

/// Construction errors emitted by `Peuin::new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeuinError {
    /// Input was not exactly 9 bytes (8 ASCII digits + 1 checksum character).
    WrongLength {
        /// Number of bytes actually given.
        got: usize,
    },
    /// One of positions `0..8` was not an ASCII digit.
    NonDigit {
        /// Byte offset (0-based) where the bad character lives.
        at: usize,
        /// The offending byte value at `at`.
        byte: u8,
    },
    /// Position 8 (the checksum) was not ASCII alphanumeric.
    BadChecksum {
        /// The byte value at position 8 that failed the check.
        byte: u8,
    },
}

impl fmt::Display for PeuinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { got } => write!(
                f,
                "PEUIN must be exactly {PEUIN_LEN} characters ({PEUIN_DIGITS_LEN} digits + 1 checksum), got {got}"
            ),
            Self::NonDigit { at, byte } => write!(
                f,
                "PEUIN positions 0..{PEUIN_DIGITS_LEN} must be ASCII digits; non-digit at offset {at}: {byte:#04x}"
            ),
            Self::BadChecksum { byte } => write!(
                f,
                "PEUIN checksum (position {PEUIN_CHECKSUM_INDEX}) must be ASCII alphanumeric; got {byte:#04x}"
            ),
        }
    }
}

impl core::error::Error for PeuinError {}

impl Peuin {
    /// Parse `s` as a PEUIN: 9 ASCII bytes (positions `0..=7` digits,
    /// position `8` alphanumeric).
    ///
    /// # Errors
    /// [`PeuinError`] variants for wrong length, non-digit in the body, or a
    /// bad checksum character.
    pub(crate) fn new(s: &str) -> Result<Self, PeuinError> {
        let bytes = s.as_bytes();
        if bytes.len() != PEUIN_LEN {
            return Err(PeuinError::WrongLength { got: bytes.len() });
        }
        let mut buf = [0_u8; PEUIN_LEN];
        buf.copy_from_slice(bytes);
        for (i, &b) in buf.iter().take(PEUIN_DIGITS_LEN).enumerate() {
            if !b.is_ascii_digit() {
                return Err(PeuinError::NonDigit { at: i, byte: b });
            }
        }
        let checksum_byte = buf[PEUIN_CHECKSUM_INDEX];
        if !checksum_byte.is_ascii_alphanumeric() {
            return Err(PeuinError::BadChecksum {
                byte: checksum_byte,
            });
        }
        Ok(Self(buf))
    }

    /// String view. Always valid UTF-8 because the constructor rejected every
    /// non-ASCII byte.
    ///
    /// # Panics
    /// Never under correct construction.
    #[must_use]
    pub fn as_str(&self) -> &str {
        #[expect(
            clippy::expect_used,
            reason = "Peuin::new accepts only ASCII alphanumerics, which are always valid UTF-8."
        )]
        core::str::from_utf8(&self.0).expect("Peuin bytes are ASCII by construction")
    }

    /// Borrow the underlying 9-byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PEUIN_LEN] {
        &self.0
    }
}

impl Deref for Peuin {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for Peuin {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Peuin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<str> for Peuin {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Peuin {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// Construction error shared by every free-text identity newtype.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeTextError {
    /// Input was zero bytes.
    Empty,
    /// Input exceeded the per-field byte budget.
    TooLong {
        /// Length of the rejected input in UTF-8 bytes.
        got: usize,
        /// The per-field byte cap that was breached.
        max: usize,
    },
}

impl fmt::Display for FreeTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("free-text value cannot be empty"),
            Self::TooLong { got, max } => {
                write!(f, "free-text length {got} bytes exceeds maximum {max}")
            }
        }
    }
}

impl core::error::Error for FreeTextError {}

/// Maximum byte length accepted by every free-text newtype.
pub const FREE_TEXT_MAX_BYTES: usize = 1024;

/// Validate a free-text value at the identity boundary.
const fn validate_free_text(value: &str) -> Result<(), FreeTextError> {
    if value.is_empty() {
        return Err(FreeTextError::Empty);
    }
    if value.len() > FREE_TEXT_MAX_BYTES {
        return Err(FreeTextError::TooLong {
            got: value.len(),
            max: FREE_TEXT_MAX_BYTES,
        });
    }
    Ok(())
}

/// Family name as it appears in the cert subject DN (X.520 `surName`, OID `2.5.4.4`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Surname(String);

impl Surname {
    /// # Errors
    /// [`FreeTextError::Empty`] if `s` is empty,
    /// [`FreeTextError::TooLong`] if `s` exceeds [`FREE_TEXT_MAX_BYTES`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        validate_free_text(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying surname string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for Surname {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Surname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Surname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for Surname {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Surname {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// X.509 `commonName` attribute value (X.520 `cn`, OID `2.5.4.3`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommonName(String);

impl CommonName {
    /// # Errors
    /// [`FreeTextError::Empty`] if `s` is empty,
    /// [`FreeTextError::TooLong`] if `s` exceeds [`FREE_TEXT_MAX_BYTES`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        validate_free_text(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying common-name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for CommonName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CommonName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CommonName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for CommonName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for CommonName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// X.509 subject `organizationName` attribute value (OID `2.5.4.10`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrganizationName(String);

impl OrganizationName {
    /// # Errors
    /// [`FreeTextError::Empty`] if `s` is empty,
    /// [`FreeTextError::TooLong`] if `s` exceeds [`FREE_TEXT_MAX_BYTES`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        validate_free_text(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying organization-name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for OrganizationName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for OrganizationName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OrganizationName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Result of splitting a cert `id-at-givenName` attribute into per-slot
/// newtypes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SplitGivenNames {
    /// First given name; `None` when the source attribute had no tokens.
    pub first: Option<FirstName>,
    /// Second given name when the source attribute had at least two tokens.
    pub second: Option<SecondName>,
    /// Third and subsequent given names, one per token in source order.
    pub additional: Vec<AdditionalName>,
}

/// Validated source text containing one or more given-name tokens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct GivenNamesText(String);

impl GivenNamesText {
    /// Validate a raw cert given-name attribute before splitting.
    ///
    /// # Errors
    /// [`FreeTextError`] if the source is empty or too long.
    pub(crate) fn new(value: String) -> Result<Self, FreeTextError> {
        validate_free_text(&value)?;
        Ok(Self(value))
    }

    /// Split into the three per-slot given-name types.
    #[must_use]
    pub(crate) fn split(&self) -> SplitGivenNames {
        let mut out = SplitGivenNames::default();
        let mut slot = 0_usize;
        for tok in self.0.split_whitespace() {
            if tok.is_empty() {
                continue;
            }
            let owned = tok.to_owned();
            match slot {
                0 => {
                    if let Ok(n) = FirstName::new(owned) {
                        out.first = Some(n);
                        slot = 1;
                    }
                }
                1 => {
                    if let Ok(n) = SecondName::new(owned) {
                        out.second = Some(n);
                        slot = 2;
                    }
                }
                _ => {
                    if let Ok(n) = AdditionalName::new(owned) {
                        out.additional.push(n);
                    }
                }
            }
        }
        out
    }
}

/// First given name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FirstName(String);

impl FirstName {
    /// # Errors
    /// [`FreeTextError::Empty`] if empty, [`FreeTextError::TooLong`]
    /// if it exceeds [`FREE_TEXT_MAX_BYTES`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        validate_free_text(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying first-name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for FirstName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for FirstName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FirstName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Second given name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecondName(String);

impl SecondName {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        validate_free_text(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying second-name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for SecondName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SecondName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecondName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Third-or-further given name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AdditionalName(String);

impl AdditionalName {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        validate_free_text(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying additional-name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for AdditionalName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for AdditionalName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AdditionalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Cardholder + credential-instance identifier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialIdentity {
    /// First given name split from X.520 `givenName` (OID `2.5.4.42`).
    pub first_name: Option<FirstName>,
    /// Second given name split from X.520 `givenName`.
    pub second_name: Option<SecondName>,
    /// Third-and-further given names split from X.520 `givenName`.
    pub additional_names: Vec<AdditionalName>,
    /// X.520 `surName` (OID `2.5.4.4`).
    pub surname: Option<Surname>,
    /// Personal Electronic Unique Identification Number (`serialNumber` DN attribute).
    pub peuin: Option<Peuin>,
    /// Identifier as printed on the card's physical surface.
    pub printed_serial: Option<PrintedSerial>,
    /// X.520 `organizationName` (OID `2.5.4.10`) from the certificate subject.
    pub organization: Option<OrganizationName>,
}

/// What joins the holder's name to the organization on the holder line.
const ORGANIZATION_SEPARATOR: &str = ", ";

/// The holder line a window shows: the holder's name, followed by the
/// organization when the certificate names one. A name alone when there is no
/// organization; empty when there is no name.
#[must_use]
pub fn holder_line(person: String, organization: Option<&OrganizationName>) -> String {
    match organization {
        Some(organization) if !person.is_empty() => {
            format!("{person}{ORGANIZATION_SEPARATOR}{organization}")
        }
        _ => person,
    }
}

impl CredentialIdentity {
    /// Empty identity. Equivalent to [`Default::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set [`first_name`](Self::first_name) and return `self`.
    #[must_use]
    pub fn with_first_name(mut self, value: FirstName) -> Self {
        self.first_name = Some(value);
        self
    }

    /// Set [`second_name`](Self::second_name) and return `self`.
    #[must_use]
    pub fn with_second_name(mut self, value: SecondName) -> Self {
        self.second_name = Some(value);
        self
    }

    /// Append one entry to [`additional_names`](Self::additional_names).
    #[must_use]
    pub fn with_additional_name(mut self, value: AdditionalName) -> Self {
        self.additional_names.push(value);
        self
    }

    /// Replace [`additional_names`](Self::additional_names) wholesale.
    #[must_use]
    pub fn with_additional_names(mut self, values: Vec<AdditionalName>) -> Self {
        self.additional_names = values;
        self
    }

    /// Set [`surname`](Self::surname) and return `self`.
    #[must_use]
    pub fn with_surname(mut self, value: Surname) -> Self {
        self.surname = Some(value);
        self
    }

    /// Set [`organization`](Self::organization) and return `self`.
    #[must_use]
    pub fn with_organization(mut self, value: OrganizationName) -> Self {
        self.organization = Some(value);
        self
    }

    /// Set [`peuin`](Self::peuin) and return `self`.
    #[must_use]
    pub const fn with_peuin(mut self, value: Peuin) -> Self {
        self.peuin = Some(value);
        self
    }

    /// Set [`printed_serial`](Self::printed_serial) and return `self`.
    #[must_use]
    pub fn with_printed_serial(mut self, value: PrintedSerial) -> Self {
        self.printed_serial = Some(value);
        self
    }

    /// Best available serial for human-facing render paths (the printed form).
    #[must_use]
    pub fn best_serial(&self) -> Option<&str> {
        self.printed_serial.as_deref()
    }

    /// Surname and given names, space-separated, `None` fields elided.
    #[must_use]
    pub fn person_string(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if let Some(s) = self.surname.as_deref()
            && !s.is_empty()
        {
            parts.push(s);
        }
        for given in self.iter_given_names() {
            if !given.is_empty() {
                parts.push(given);
            }
        }
        parts.join(" ")
    }

    /// The holder line a window shows: [`person_string`](Self::person_string)
    /// followed by the organization when present.
    #[must_use]
    pub fn holder_line(&self) -> String {
        holder_line(self.person_string(), self.organization.as_ref())
    }

    /// Iterate every given-name slot in canonical order: first, second, then
    /// each additional name.
    pub fn iter_given_names(&self) -> impl Iterator<Item = &str> {
        self.first_name
            .as_deref()
            .into_iter()
            .chain(self.second_name.as_deref())
            .chain(self.additional_names.iter().map(AsRef::as_ref))
    }

    /// `true` when every field is `None` / empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.first_name.is_none()
            && self.second_name.is_none()
            && self.additional_names.is_empty()
            && self.surname.is_none()
            && self.peuin.is_none()
            && self.printed_serial.is_none()
            && self.organization.is_none()
    }
}

impl fmt::Display for CredentialIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut emit = |s: &str, f: &mut fmt::Formatter<'_>| -> fmt::Result {
            if s.is_empty() {
                return Ok(());
            }
            if !first {
                f.write_str(" ")?;
            }
            f.write_str(s)?;
            first = false;
            Ok(())
        };
        if let Some(s) = self.surname.as_deref() {
            emit(s, f)?;
        }
        for given in self.iter_given_names() {
            emit(given, f)?;
        }
        if let Some(s) = self.peuin.as_deref() {
            emit(s, f)?;
        }
        if let Some(s) = self.best_serial() {
            emit(s, f)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use refineid_pkcs15::PrintedSerial;

    use super::*;

    const SAMPLE_SURNAME: &str = "SPECIMEN-TRAVEL";
    const SAMPLE_GIVEN: &str = "VILMA SOFIA";
    const SAMPLE_FIRST: &str = "VILMA";
    const SAMPLE_SECOND: &str = "SOFIA";
    const SAMPLE_PEUIN: &str = "12345678X";
    const SAMPLE_PRINTED: &str = "XA1000084";

    fn sample_identity() -> CredentialIdentity {
        CredentialIdentity::new()
            .with_surname(Surname::new(SAMPLE_SURNAME.to_owned()).expect("sample surname is valid"))
            .with_first_name(
                FirstName::new(SAMPLE_FIRST.to_owned()).expect("sample first name is valid"),
            )
            .with_second_name(
                SecondName::new(SAMPLE_SECOND.to_owned()).expect("sample second name is valid"),
            )
            .with_peuin(Peuin::new(SAMPLE_PEUIN).expect("sample PEUIN is valid"))
    }

    #[test]
    fn an_organization_card_holder_line_names_the_organization() {
        let id = sample_identity().with_organization(
            OrganizationName::new("Testiorganisaatio Oy".to_owned())
                .expect("sample organization is valid"),
        );
        assert_eq!(id.person_string(), "SPECIMEN-TRAVEL VILMA SOFIA");
        assert_eq!(
            id.holder_line(),
            "SPECIMEN-TRAVEL VILMA SOFIA, Testiorganisaatio Oy"
        );
    }

    #[test]
    fn a_citizen_card_holder_line_is_the_name_alone() {
        let id = sample_identity();
        assert_eq!(id.holder_line(), id.person_string());
    }

    #[test]
    fn an_organization_without_a_name_shows_nothing() {
        let id = CredentialIdentity::new().with_organization(
            OrganizationName::new("Testiorganisaatio Oy".to_owned())
                .expect("sample organization is valid"),
        );
        assert_eq!(id.holder_line(), "");
    }

    #[test]
    fn display_renders_printed_serial_and_skips_none_fields() {
        let with_serial =
            sample_identity().with_printed_serial(PrintedSerial::new(SAMPLE_PRINTED.to_owned()));
        assert_eq!(
            format!("{with_serial}"),
            format!("{SAMPLE_SURNAME} {SAMPLE_GIVEN} {SAMPLE_PEUIN} {SAMPLE_PRINTED}")
        );
        assert_eq!(
            format!("{}", sample_identity()),
            format!("{SAMPLE_SURNAME} {SAMPLE_GIVEN} {SAMPLE_PEUIN}")
        );
        let empty = CredentialIdentity::default();
        assert_eq!(format!("{empty}"), "");
        assert!(empty.is_empty());
    }

    #[test]
    fn peuin_validates_shape_and_characters() {
        let alpha = Peuin::new("12345678X").expect("eight digits plus alpha checksum parses");
        assert_eq!(alpha.as_str(), "12345678X");
        assert_eq!(alpha, "12345678X");
        let digit = Peuin::new("123456789").expect("digit checksum parses");
        assert_eq!(format!("{digit}"), "123456789");
        assert!(matches!(
            Peuin::new("1234567"),
            Err(PeuinError::WrongLength { got: 7 })
        ));
        assert!(matches!(
            Peuin::new("12X45678Y"),
            Err(PeuinError::NonDigit { at: 2, byte: b'X' })
        ));
        assert!(matches!(
            Peuin::new("12345678!"),
            Err(PeuinError::BadChecksum { byte: b'!' })
        ));
    }

    #[test]
    fn free_text_and_given_name_splitting_validate_bounds() {
        assert!(matches!(
            Surname::new(String::new()),
            Err(FreeTextError::Empty)
        ));
        let huge = "a".repeat(FREE_TEXT_MAX_BYTES + 1);
        assert!(matches!(
            Surname::new(huge),
            Err(FreeTextError::TooLong { .. })
        ));
        let split = GivenNamesText::new("ANNA MARIA HELENA SOFIA".to_owned())
            .expect("four given names are valid")
            .split();
        assert_eq!(split.first.as_deref(), Some("ANNA"));
        assert_eq!(split.second.as_deref(), Some("MARIA"));
        assert_eq!(split.additional.len(), 2);
        assert_eq!(split.additional[0].as_str(), "HELENA");
        assert_eq!(split.additional[1].as_str(), "SOFIA");
        let hyphenated = GivenNamesText::new("Marie-Claire Sofia".to_owned())
            .expect("hyphenated given name is valid")
            .split();
        assert_eq!(hyphenated.first.as_deref(), Some("Marie-Claire"));
        assert_eq!(hyphenated.second.as_deref(), Some("Sofia"));
        let cn = CommonName::new("DVV Citizen Certificates - G4R".to_owned())
            .expect("common name parses");
        assert_eq!(cn.as_str(), "DVV Citizen Certificates - G4R");
    }
}
