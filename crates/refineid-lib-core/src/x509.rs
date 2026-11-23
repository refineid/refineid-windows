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

//! X.509 certificate parsing and verification re-exported from
//! [`refineid_cms::x509`], plus FINEID-typed distinguished-name accessors.

pub use refineid_cms::x509::*;

use crate::oid::{Oid, known};
use spki::der::asn1::AnyRef;

/// FINEID-typed attribute accessors over an X.509 [`Name`].
pub trait FineidNameExt {
    /// `commonName` (X.520 `cn`, OID `2.5.4.3`).
    #[must_use]
    fn common_name(&self) -> Option<crate::identity::CommonName>;

    /// `surname` (X.520 `sn`, OID `2.5.4.4`).
    #[must_use]
    fn surname(&self) -> Option<crate::identity::Surname>;

    /// `givenName` (X.520 `gn`, OID `2.5.4.42`), split into typed slots.
    #[must_use]
    fn given_names(&self) -> crate::identity::SplitGivenNames;

    /// `organizationName` (X.520 `o`, OID `2.5.4.10`), verbatim. Present
    /// on an organization card's certificate, absent on a citizen's.
    #[must_use]
    fn organization_name(&self) -> Option<crate::identity::OrganizationName>;

    /// PEUIN / SATU from the `serialNumber` DN attribute (OID `2.5.4.5`).
    #[must_use]
    fn peuin(&self) -> Option<crate::identity::Peuin>;

    /// `countryName` (OID `2.5.4.6`) as a typed ISO 3166-1 alpha-2.
    #[must_use]
    fn country(&self) -> Option<crate::country::IsoAlpha2>;
}

impl FineidNameExt for Name<'_> {
    #[inline]
    fn common_name(&self) -> Option<crate::identity::CommonName> {
        crate::identity::CommonName::new(dn_attribute(*self, known::COMMON_NAME)?).ok()
    }

    #[inline]
    fn surname(&self) -> Option<crate::identity::Surname> {
        crate::identity::Surname::new(dn_attribute(*self, known::SURNAME)?).ok()
    }

    #[inline]
    fn given_names(&self) -> crate::identity::SplitGivenNames {
        dn_attribute(*self, known::GIVEN_NAME).map_or_else(
            crate::identity::SplitGivenNames::default,
            |raw| {
                crate::identity::GivenNamesText::new(raw).map_or_else(
                    |_err| crate::identity::SplitGivenNames::default(),
                    |text| text.split(),
                )
            },
        )
    }

    #[inline]
    fn organization_name(&self) -> Option<crate::identity::OrganizationName> {
        crate::identity::OrganizationName::new(dn_attribute(*self, known::ORGANIZATION_NAME)?).ok()
    }

    #[inline]
    fn peuin(&self) -> Option<crate::identity::Peuin> {
        crate::identity::Peuin::new(&dn_attribute(*self, known::SERIAL_NUMBER)?).ok()
    }

    #[inline]
    fn country(&self) -> Option<crate::country::IsoAlpha2> {
        crate::country::IsoAlpha2::new(dn_attribute(*self, known::COUNTRY_NAME)?.trim()).ok()
    }
}

/// Return the last matching `DirectoryString` DN attribute whose OID body
/// matches `oid_body`.
fn dn_attribute(name: Name<'_>, oid_body: Oid<'_>) -> Option<String> {
    use spki::der::{Decode as _, Reader as _, SliceReader, Tag, Tagged as _};

    let seq = AnyRef::from_der(name.as_der()).ok()?;
    if seq.tag() != Tag::Sequence {
        return None;
    }
    let mut rdns = SliceReader::new(seq.value()).ok()?;
    let mut found: Option<String> = None;
    while !rdns.is_finished() {
        let rdn = AnyRef::from_der(rdns.tlv_bytes().ok()?).ok()?;
        if rdn.tag() != Tag::Set {
            continue;
        }
        let mut atvs = SliceReader::new(rdn.value()).ok()?;
        while !atvs.is_finished() {
            let atv = AnyRef::from_der(atvs.tlv_bytes().ok()?).ok()?;
            if atv.tag() != Tag::Sequence {
                continue;
            }
            let mut fields = SliceReader::new(atv.value()).ok()?;
            let oid = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
            let val = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
            if oid.tag() == Tag::ObjectIdentifier
                && oid.value() == oid_body.as_bytes()
                && let Some(s) = decode_directory_string(val)
            {
                found = Some(s);
            }
        }
    }
    found
}

/// Decode an X.520 `DirectoryString` (or `IA5String`) attribute value.
fn decode_directory_string(value: AnyRef<'_>) -> Option<String> {
    use spki::der::{Tag, Tagged as _};
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "der::Tag has ~25 variants; only the DirectoryString string types decode to text, every other ASN.1 tag is None"
    )]
    match value.tag() {
        Tag::Utf8String => core::str::from_utf8(value.value()).ok().map(String::from),
        Tag::PrintableString | Tag::Ia5String | Tag::TeletexString => value
            .value()
            .iter()
            .all(u8::is_ascii)
            .then(|| String::from_utf8_lossy(value.value()).into_owned()),
        Tag::BmpString => {
            if !value.value().len().is_multiple_of(2) {
                return None;
            }
            let cap = value.value().len().div_euclid(2);
            let mut out = String::with_capacity(cap);
            for &[hi, lo] in value.value().as_chunks::<2>().0 {
                let code = u32::from(u16::from_be_bytes([hi, lo]));
                out.push(char::from_u32(code)?);
            }
            Some(out)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{FineidNameExt as _, Name};
    use crate::oid::{Oid, known};
    use spki::der::asn1::{ObjectIdentifier, Utf8StringRef};
    use spki::der::{Encode as _, Header, Length, Tag};

    fn to_tlv(tag: Tag, value: &[u8]) -> Vec<u8> {
        let len = Length::try_from(value.len()).expect("fixture length fits in DER Length");
        let mut out = Header::new(tag, len).to_der().expect("header encodes");
        out.extend_from_slice(value);
        out
    }

    fn to_utf8_attribute(oid: Oid<'_>, value: &str) -> Vec<u8> {
        let mut atv_body = ObjectIdentifier::from_bytes(oid.as_bytes())
            .expect("fixture OID is valid")
            .to_der()
            .expect("OID encodes");
        atv_body.extend(
            Utf8StringRef::new(value)
                .expect("fixture value is UTF-8")
                .to_der()
                .expect("UTF8String encodes"),
        );
        to_tlv(Tag::Set, &to_tlv(Tag::Sequence, &atv_body))
    }

    fn to_name(relative_names: &[Vec<u8>]) -> Vec<u8> {
        to_tlv(Tag::Sequence, &relative_names.concat())
    }

    #[test]
    fn an_organization_card_subject_names_its_organization() {
        let dn = to_name(&[
            to_utf8_attribute(known::COUNTRY_NAME, "FI"),
            to_utf8_attribute(known::ORGANIZATION_NAME, "Testiorganisaatio Oy"),
            to_utf8_attribute(known::GIVEN_NAME, "Denis"),
            to_utf8_attribute(known::SURNAME, "Juutilainen"),
            to_utf8_attribute(known::COMMON_NAME, "Juutilainen Denis 99905322A"),
        ]);
        let name = Name::try_from(dn.as_slice()).expect("Name parses");
        assert_eq!(
            name.organization_name().as_deref(),
            Some("Testiorganisaatio Oy")
        );
        assert_eq!(
            name.common_name().as_deref(),
            Some("Juutilainen Denis 99905322A")
        );
        assert_eq!(name.surname().as_deref(), Some("Juutilainen"));
        assert_eq!(name.given_names().first.as_deref(), Some("Denis"));
        assert_eq!(
            name.country().map(|c| c.as_str().to_owned()).as_deref(),
            Some("FI")
        );
    }

    #[test]
    fn a_citizen_subject_names_no_organization() {
        let dn = to_name(&[
            to_utf8_attribute(known::COUNTRY_NAME, "FI"),
            to_utf8_attribute(known::SURNAME, "MEIKALAINEN"),
            to_utf8_attribute(known::COMMON_NAME, "MEIKALAINEN MATTI 12345678A"),
        ]);
        let name = Name::try_from(dn.as_slice()).expect("Name parses");
        assert_eq!(name.organization_name(), None);
    }
}
