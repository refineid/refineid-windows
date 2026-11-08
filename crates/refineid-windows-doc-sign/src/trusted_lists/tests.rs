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

//! Tests of the trusted-list store over synthetic lists: a list of
//! the lists pointing at one national list with one qualified
//! certificate service, every signer a testkit key, served by a
//! scripted fetch in place of the network. They cover the cache
//! layout, the refresh policy (due by next update, by age,
//! by request, by a list that no longer reads), a fetch that fails
//! with and without a cache, and the source the run reports.

use core::cell::Cell;

use refineid_doc_sign::base64;
use refineid_doc_sign::testkit::{
    CertificateSpec, TestCurve, TestKey, ca_extensions, certificate, day,
};
use refineid_doc_sign::verification::trusted_list::LOTL_LOCATION;
use refineid_doc_sign::verification::xml::{Canonicalization, Comments, XmlDocument};
use sha2::Sha256;

use super::*;
use crate::test_util::{TempDir, TestResult, check, check_true};

/// Where the synthetic national list is published.
const NATIONAL_LOCATION: &str = "https://trusted-list.example/national.xml";
/// The list type of the EU list of the lists (TS 119 612 annex D.5.1).
const TSL_TYPE_LOTL: &str = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";
/// The list type of an EU member state's list (TS 119 612 annex D.5.1).
const TSL_TYPE_NATIONAL: &str = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";
/// The qualified certificate-issuing service type (TS 119 612 clause
/// 5.5.1.1 (a)).
const SERVICE_TYPE_CA_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
/// The `granted` status (TS 119 612 annex D.5.6).
const STATUS_GRANTED: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
/// The media type of a machine-processable list (TS 119 612 clause 6.2).
const MIME_XML: &str = "application/vnd.etsi.tsl+xml";
/// The trusted-list namespace (TS 119 612 annex B.0).
const NAMESPACE_TSL: &str = "http://uri.etsi.org/02231/v2#";
/// The additional-types namespace (TS 119 612 annex B.0).
const NAMESPACE_TSL_ADDITIONAL: &str = "http://uri.etsi.org/02231/v2/additionaltypes#";
/// The XML Signature namespace (XML Signature 1.1 sec.4).
const NAMESPACE_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
/// The `XAdES` 1.3.2 namespace (ETSI EN 319 132-1 annex A).
const NAMESPACE_XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
/// SHA-256 (XML Encryption 1.1 sec.5.7.2).
const DIGEST_METHOD_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
/// ECDSA with SHA-256 (RFC 6931 sec.2.3.6).
const SIGNATURE_METHOD_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
/// Exclusive canonicalisation without comments (Exclusive XML
/// Canonicalization 1.0 sec.5).
const CANONICALIZATION_EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// The type of a reference to signed properties (ETSI EN 319 132-1
/// sec.4.3.1).
const TYPE_SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";
/// The enveloped-signature transform (XML Signature 1.1 sec.6.6.4).
const TRANSFORM_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// The `Id` of the signed properties.
const PROPERTIES_ID: &str = "xades-props";
/// The `Id` of the signature.
const SIGNATURE_ID: &str = "sig";
/// The list's closing tag, before which its signature goes.
const LIST_CLOSE: &str = "</TrustServiceStatusList>";

/// The territory of the list of the lists.
const EU: &str = "EU";
/// The territory of the national list.
const TERRITORY: &str = "XX";
/// The scheme operator of the list of the lists.
const LOTL_OPERATOR: &str = "Synthetic Commission";
/// The scheme operator of the national list.
const NATIONAL_OPERATOR: &str = "Synthetic Supervisory Body";
/// The listed provider.
const PROVIDER: &str = "Synthetic Trust Service Provider";
/// The listed certificate service.
const CA: &str = "Synthetic Listed Qualified CA";

/// Serial of the list-of-the-lists signer.
const LOTL_SERIAL: u8 = 1;
/// Serial of the national signer.
const NATIONAL_SERIAL: u8 = 2;
/// Serial of the listed CA.
const CA_SERIAL: u8 = 3;

/// Day every certificate starts and every list is issued.
const ISSUED: u8 = 1;
/// Day the CA was granted from.
const GRANTED: u8 = 3;
/// Day the lists are first fetched.
const FETCHED: u8 = 20;
/// A day after the first fetch, before the next update.
const LATER: u8 = 22;
/// The lists' next update.
const NEXT_UPDATE: u8 = 25;
/// A day after the next update.
const OVERDUE: u8 = 27;
/// The day after the next update, a day before [`OVERDUE`].
const JUST_OVERDUE: u8 = 26;
/// Hours in a day.
const HOURS_PER_DAY: u32 = 24;
/// Day every certificate ends.
const ENDS: u8 = 28;
/// The year of a fetch long before the fixture month.
const LONG_AGO_YEAR: u16 = 2026;
/// The month of that fetch, two before the fixture month.
const LONG_AGO_MONTH: u8 = 4;
/// Its day.
const LONG_AGO_DAY: u8 = 1;
/// Its hour.
const LONG_AGO_HOUR: u8 = 12;

/// The calls of a fetch that was not asked.
const NOT_FETCHED: usize = 0;
/// The calls of a fetch asked once.
const FETCHED_ONCE: usize = 1;
/// The anchors the synthetic national list adds: its one service's one
/// certificate.
const LISTED_ANCHORS: usize = 1;
/// Files a stored set holds: the list of the lists and the national
/// list.
const STORED_FILES: usize = 2;

/// Keys and certificates of one test world.
struct World {
    /// The list-of-the-lists signer.
    lotl_key: TestKey,
    /// Its certificate.
    lotl: Vec<u8>,
    /// The national list signer.
    national_key: TestKey,
    /// Its certificate.
    national: Vec<u8>,
    /// The listed CA.
    ca: Vec<u8>,
}

/// A certificate valid from [`ISSUED`] to [`ENDS`].
fn spec(serial: u8, subject: &str, extensions: Vec<Vec<u8>>) -> CertificateSpec<'_> {
    CertificateSpec {
        serial,
        subject,
        issuer: subject,
        not_before: day(ISSUED),
        not_after: day(ENDS),
        extensions,
    }
}

impl World {
    fn new() -> Self {
        let lotl_key = TestKey::derive(TestCurve::P256, b"list of the lists");
        let national_key = TestKey::derive(TestCurve::P256, b"national operator");
        let ca_key = TestKey::derive(TestCurve::P256, b"listed ca");
        Self {
            lotl: certificate(
                &spec(LOTL_SERIAL, LOTL_OPERATOR, Vec::new()),
                &lotl_key,
                &lotl_key,
            ),
            national: certificate(
                &spec(NATIONAL_SERIAL, NATIONAL_OPERATOR, Vec::new()),
                &national_key,
                &national_key,
            ),
            ca: certificate(&spec(CA_SERIAL, CA, ca_extensions()), &ca_key, &ca_key),
            lotl_key,
            national_key,
        }
    }

    /// The certificates entitled to sign the list of the lists.
    fn signers(&self) -> Result<Vec<OwnedCert>, Box<dyn core::error::Error>> {
        Ok(vec![OwnedCert::from_der(&self.lotl)?])
    }

    /// The signed list of the lists.
    fn lotl_bytes(&self) -> Vec<u8> {
        sign_list(&lotl_xml(&self.national), &self.lotl_key, &self.lotl)
    }

    /// The signed list of the lists, pointing at no list.
    fn lotl_without_pointers(&self) -> Vec<u8> {
        sign_list(
            &document(&scheme_information(TSL_TYPE_LOTL, EU, LOTL_OPERATOR, "")),
            &self.lotl_key,
            &self.lotl,
        )
    }

    /// The signed national list.
    fn national_bytes(&self) -> Vec<u8> {
        sign_list(&national_xml(&self.ca), &self.national_key, &self.national)
    }

    /// The lists as the network serves them, read at `now`.
    fn serve(&self, now: DateTime) -> Result<(TrustedLists, Vec<CachedList>), TrustedListError> {
        let national = self.national_bytes();
        let signers = self.signers().map_err(|_| TrustedListError::NotFetched)?;
        TrustedLists::read(
            self.lotl_bytes(),
            &signers,
            |location| (location.to_string() == NATIONAL_LOCATION).then(|| national.clone()),
            now,
        )
    }
}

/// `time` as an `xsd:dateTime` in UTC.
fn stamp(time: DateTime) -> String {
    time.to_string()
}

/// A `ServiceDigitalIdentity` over one certificate.
fn identity(certificate: &[u8]) -> String {
    format!(
        "<ServiceDigitalIdentity><DigitalId><X509Certificate>{}</X509Certificate></DigitalId></ServiceDigitalIdentity>",
        base64::encode(certificate)
    )
}

/// The scheme information of a list.
fn scheme_information(list_type: &str, territory: &str, operator: &str, pointers: &str) -> String {
    format!(
        "<SchemeInformation><TSLVersionIdentifier>6</TSLVersionIdentifier><TSLSequenceNumber>1</TSLSequenceNumber><TSLType>{list_type}</TSLType><SchemeOperatorName><Name xml:lang=\"en\">{operator}</Name></SchemeOperatorName><SchemeTerritory>{territory}</SchemeTerritory>{pointers}<ListIssueDateTime>{}</ListIssueDateTime><NextUpdate><dateTime>{}</dateTime></NextUpdate></SchemeInformation>",
        stamp(day(ISSUED)),
        stamp(day(NEXT_UPDATE))
    )
}

/// The document element around `body`.
fn document(body: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><TrustServiceStatusList xmlns=\"{NAMESPACE_TSL}\" xmlns:ns3=\"{NAMESPACE_TSL_ADDITIONAL}\" Id=\"list\">{body}{LIST_CLOSE}"
    )
}

/// An unsigned list of the lists pointing at the national list signed
/// by `national`.
fn lotl_xml(national: &[u8]) -> String {
    let pointer = format!(
        "<PointersToOtherTSL><OtherTSLPointer><ServiceDigitalIdentities>{}</ServiceDigitalIdentities><TSLLocation>{NATIONAL_LOCATION}</TSLLocation><AdditionalInformation><OtherInformation><TSLType>{TSL_TYPE_NATIONAL}</TSLType></OtherInformation><OtherInformation><SchemeTerritory>{TERRITORY}</SchemeTerritory></OtherInformation><OtherInformation><ns3:MimeType>{MIME_XML}</ns3:MimeType></OtherInformation></AdditionalInformation></OtherTSLPointer></PointersToOtherTSL>",
        identity(national)
    );
    document(&scheme_information(
        TSL_TYPE_LOTL,
        EU,
        LOTL_OPERATOR,
        &pointer,
    ))
}

/// An unsigned national list carrying one qualified certificate
/// service over `ca`, granted since [`GRANTED`].
fn national_xml(ca: &[u8]) -> String {
    let scheme = scheme_information(TSL_TYPE_NATIONAL, TERRITORY, NATIONAL_OPERATOR, "");
    document(&format!(
        "{scheme}<TrustServiceProviderList><TrustServiceProvider><TSPInformation><TSPName><Name xml:lang=\"en\">{PROVIDER}</Name></TSPName></TSPInformation><TSPServices><TSPService><ServiceInformation><ServiceTypeIdentifier>{SERVICE_TYPE_CA_QC}</ServiceTypeIdentifier><ServiceName><Name xml:lang=\"en\">{CA}</Name></ServiceName>{}<ServiceStatus>{STATUS_GRANTED}</ServiceStatus><StatusStartingTime>{}</StatusStartingTime></ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList>",
        identity(ca),
        stamp(day(GRANTED))
    ))
}

/// Exclusive canonicalisation without comments.
fn exclusive() -> Canonicalization {
    Canonicalization::exclusive(Comments::Omitted)
}

/// The exclusive canonical form of the element with `id` in `xml`, or
/// of its root.
fn canonical(xml: &str, id: Option<&str>) -> Vec<u8> {
    let document = XmlDocument::parse(xml.as_bytes().to_vec()).expect("fixture XML parses");
    let element = id.map_or_else(
        || document.root(),
        |id| {
            document
                .elements()
                .find(|element| element.attribute("Id") == Some(id))
                .expect("the element exists")
        },
    );
    element.canonicalize(&exclusive())
}

/// The SHA-256 of `octets`, base64.
fn digest(octets: &[u8]) -> String {
    base64::encode(&Sha256::digest(octets))
}

/// Sign `unsigned`, a complete list without a signature, with `key`
/// under `certificate`, as TS 119 612 annex B.1 says: an enveloped
/// reference to the list under the enveloped-signature transform and
/// exclusive canonicalisation, and a reference to the signed
/// properties.
fn sign_list(unsigned: &str, key: &TestKey, certificate: &[u8]) -> Vec<u8> {
    let list_digest = digest(&canonical(unsigned, None));
    let properties = format!(
        "<xades:SignedProperties Id=\"{PROPERTIES_ID}\"><xades:SignedSignatureProperties><xades:SigningTime>{}</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"{DIGEST_METHOD_SHA256}\"/><ds:DigestValue>{}</ds:DigestValue></xades:CertDigest></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties></xades:SignedProperties>",
        stamp(day(ISSUED)),
        digest(certificate)
    );
    let object = format!(
        "<ds:Object><xades:QualifyingProperties xmlns:xades=\"{NAMESPACE_XADES}\" Target=\"#{SIGNATURE_ID}\">{properties}</xades:QualifyingProperties></ds:Object>"
    );
    let properties_digest = digest(&canonical(
        &format!("<ds:Signature xmlns:ds=\"{NAMESPACE_DSIG}\">{object}</ds:Signature>"),
        Some(PROPERTIES_ID),
    ));
    let signed_info = format!(
        "<ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\"/><ds:SignatureMethod Algorithm=\"{SIGNATURE_METHOD_ECDSA_SHA256}\"/><ds:Reference URI=\"\"><ds:Transforms><ds:Transform Algorithm=\"{TRANSFORM_ENVELOPED}\"/><ds:Transform Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{DIGEST_METHOD_SHA256}\"/><ds:DigestValue>{list_digest}</ds:DigestValue></ds:Reference><ds:Reference Type=\"{TYPE_SIGNED_PROPERTIES}\" URI=\"#{PROPERTIES_ID}\"><ds:Transforms><ds:Transform Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{DIGEST_METHOD_SHA256}\"/><ds:DigestValue>{properties_digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
    );
    let wrapped = canonical(
        &format!("<ds:Signature xmlns:ds=\"{NAMESPACE_DSIG}\">{signed_info}</ds:Signature>"),
        None,
    );
    let wrapped = XmlDocument::parse(wrapped).expect("canonical form parses");
    let signed_info_canonical = wrapped
        .root()
        .children()
        .next()
        .expect("SignedInfo")
        .canonicalize(&exclusive());
    let value = base64::encode(&key.sign_raw(&signed_info_canonical));
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{NAMESPACE_DSIG}\" Id=\"{SIGNATURE_ID}\">{signed_info}<ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>{object}</ds:Signature>",
        base64::encode(certificate)
    );
    let close = unsigned.rfind(LIST_CLOSE).expect("the list closes");
    let mut signed = unsigned.to_owned();
    signed.insert_str(close, &signature);
    signed.into_bytes()
}

/// A scripted transport serving `served`, location and bytes, and
/// nothing else, counting the requests for the list of the lists in
/// `calls`.
fn transport<'a>(
    served: Vec<(&'static str, Vec<u8>)>,
    calls: &'a Cell<usize>,
) -> impl FnMut(&Uri) -> Option<Vec<u8>> + 'a {
    move |location| {
        let location = location.to_string();
        if location == LOTL_LOCATION {
            calls.set(calls.get() + FETCHED_ONCE);
        }
        served
            .iter()
            .find(|(at, _)| *at == location)
            .map(|(_, bytes)| bytes.clone())
    }
}

/// A network that does not answer.
fn offline(calls: &Cell<usize>) -> impl FnMut(&Uri) -> Option<Vec<u8>> + '_ {
    transport(Vec::new(), calls)
}

/// A network serving `world`'s lists.
fn online<'a>(world: &World, calls: &'a Cell<usize>) -> impl FnMut(&Uri) -> Option<Vec<u8>> + 'a {
    transport(
        vec![
            (LOTL_LOCATION, world.lotl_bytes()),
            (NATIONAL_LOCATION, world.national_bytes()),
        ],
        calls,
    )
}

/// How many anchors a run without lists has: none.
fn unlisted_count() -> usize {
    without_lists().anchors().len()
}

/// A fetch time more than [`REFRESH_AFTER`] before [`LATER`], in a
/// month before the fixture month.
fn long_ago() -> Result<DateTime, Box<dyn core::error::Error>> {
    Ok(DateTime::new(
        LONG_AGO_YEAR,
        LONG_AGO_MONTH,
        LONG_AGO_DAY,
        LONG_AGO_HOUR,
        0,
        0,
    )?)
}

#[test]
fn a_forced_refresh_fetches_although_the_cache_is_fresh() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-forced")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    cache.store(&world.serve(day(FETCHED))?.1)?;
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(LATER),
        Refresh::Now,
        &world.signers()?,
        online(&world, &calls),
    );
    check(&calls.get(), &FETCHED_ONCE, "fetched")?;
    check(
        &run.source,
        &AnchorSource::Lists {
            fetched_at: day(LATER),
            stale: false,
        },
        "the new fetch sets the time",
    )
}

#[test]
fn a_cache_older_than_the_refresh_bound_is_fetched_again() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-aged")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    cache.store(&world.serve(long_ago()?)?.1)?;
    check_true(
        age(long_ago()?, day(LATER)) > REFRESH_AFTER,
        "the fixture cache is older than the bound",
    )?;
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(LATER),
        Refresh::WhenDue,
        &world.signers()?,
        online(&world, &calls),
    );
    check(&calls.get(), &FETCHED_ONCE, "fetched")?;
    check(
        &run.source,
        &AnchorSource::Lists {
            fetched_at: day(LATER),
            stale: false,
        },
        "source",
    )
}

#[test]
fn an_aged_cache_is_used_when_the_fetch_fails() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-aged-offline")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    cache.store(&world.serve(long_ago()?)?.1)?;
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(LATER),
        Refresh::WhenDue,
        &world.signers()?,
        offline(&calls),
    );
    check(&calls.get(), &FETCHED_ONCE, "a refresh was tried")?;
    check(
        &run.source,
        &AnchorSource::Lists {
            fetched_at: long_ago()?,
            stale: false,
        },
        "the aged lists are used, not stale before their next update",
    )
}

#[test]
fn the_source_says_when_the_lists_were_fetched_or_why_there_are_none() -> TestResult {
    check(
        &AnchorSource::Lists {
            fetched_at: day(FETCHED),
            stale: false,
        }
        .to_string(),
        &"trusted lists fetched 2026-06-20T12:00:00Z".to_owned(),
        "fetched",
    )?;
    check(
        &AnchorSource::Lists {
            fetched_at: day(FETCHED),
            stale: true,
        }
        .to_string(),
        &"trusted lists fetched 2026-06-20T12:00:00Z, past their next update".to_owned(),
        "stale",
    )?;
    check(
        &AnchorSource::Unavailable(TrustedListError::NotFetched).to_string(),
        &"trusted lists not fetched yet, nothing can be anchored: \
          the list of the lists was not fetched"
            .to_owned(),
        "unavailable",
    )
}

#[test]
fn a_first_run_fetches_and_stores_one_file_per_list() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-first")?;
    let cache = ListCache::at(dir.path().join(LISTS_DIRECTORY));
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(FETCHED),
        Refresh::WhenDue,
        &world.signers()?,
        online(&world, &calls),
    );
    check(&calls.get(), &FETCHED_ONCE, "fetched once")?;
    check(
        &run.source,
        &AnchorSource::Lists {
            fetched_at: day(FETCHED),
            stale: false,
        },
        "source",
    )?;
    check(
        &run.anchors.anchors().len(),
        &(unlisted_count() + LISTED_ANCHORS),
        "the listed CA is the anchor",
    )?;
    let entries = fs::read_dir(dir.path().join(LISTS_DIRECTORY))?.collect::<Result<Vec<_>, _>>()?;
    check(&entries.len(), &STORED_FILES, "one file per list")
}

#[test]
fn stored_records_read_back_as_they_were() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-round-trip")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    let (_lists, records) = world.serve(day(FETCHED))?;
    cache.store(&records)?;
    let mut loaded = cache.load();
    loaded.sort_by_key(|record| record.location().to_string());
    let mut expected = records;
    expected.sort_by_key(|record| record.location().to_string());
    check(&loaded, &expected, "records")
}

#[test]
fn a_fresh_cache_is_used_without_a_fetch() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-fresh")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    cache.store(&world.serve(day(FETCHED))?.1)?;
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(LATER),
        Refresh::WhenDue,
        &world.signers()?,
        offline(&calls),
    );
    check(&calls.get(), &NOT_FETCHED, "no fetch")?;
    check(
        &run.source,
        &AnchorSource::Lists {
            fetched_at: day(FETCHED),
            stale: false,
        },
        "source",
    )?;
    check(
        &run.anchors.anchors().len(),
        &(unlisted_count() + LISTED_ANCHORS),
        "anchors",
    )
}

#[test]
fn an_overdue_cache_is_used_stale_when_the_fetch_fails() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-stale")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    cache.store(&world.serve(day(FETCHED))?.1)?;
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(OVERDUE),
        Refresh::WhenDue,
        &world.signers()?,
        offline(&calls),
    );
    check(&calls.get(), &FETCHED_ONCE, "a refresh was tried")?;
    check(
        &run.source,
        &AnchorSource::Lists {
            fetched_at: day(FETCHED),
            stale: true,
        },
        "source",
    )?;
    check(
        &run.anchors.anchors().len(),
        &(unlisted_count() + LISTED_ANCHORS),
        "the stale anchors count",
    )?;
    check(&cache.load().len(), &STORED_FILES, "the cache is kept")
}

#[test]
fn a_list_still_overdue_after_a_fetch_is_not_fetched_again_for_a_day() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-retry")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    cache.store(&world.serve(day(JUST_OVERDUE))?.1)?;
    let calls = Cell::new(NOT_FETCHED);
    for now in [JUST_OVERDUE, OVERDUE] {
        let run = run_anchors(
            Some(&cache),
            day(now),
            Refresh::WhenDue,
            &world.signers()?,
            offline(&calls),
        );
        check(
            &run.source,
            &AnchorSource::Lists {
                fetched_at: day(JUST_OVERDUE),
                stale: true,
            },
            "the overdue lists are used, said stale",
        )?;
    }
    check(
        &calls.get(),
        &NOT_FETCHED,
        "no fetch within a day of the last",
    )
}

#[test]
fn a_late_or_unread_list_is_fetched_again_once_a_day_passed() -> TestResult {
    let hour = RETRY_AFTER / HOURS_PER_DAY;
    check_true(!refresh_due(true, RETRY_AFTER), "not at a day")?;
    check_true(refresh_due(true, RETRY_AFTER + hour), "after a day")?;
    check_true(
        !refresh_due(false, RETRY_AFTER + hour),
        "lists in date wait",
    )?;
    check_true(
        refresh_due(false, REFRESH_AFTER + hour),
        "an old cache is fetched",
    )
}

#[test]
fn an_overdue_cache_is_replaced_by_a_fetch() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-refresh")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    cache.store(&world.serve(day(FETCHED))?.1)?;
    let calls = Cell::new(NOT_FETCHED);
    let _run = run_anchors(
        Some(&cache),
        day(OVERDUE),
        Refresh::WhenDue,
        &world.signers()?,
        online(&world, &calls),
    );
    check(&calls.get(), &FETCHED_ONCE, "refreshed")?;
    let loaded = cache.load();
    check(&loaded.len(), &STORED_FILES, "same lists")?;
    check_true(
        loaded
            .iter()
            .all(|record| record.fetched_at() == day(OVERDUE)),
        "every record is the new fetch",
    )
}

#[test]
fn no_cache_and_no_network_leaves_the_lists_unavailable() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-offline")?;
    let cache = ListCache::at(dir.path().join(LISTS_DIRECTORY));
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(FETCHED),
        Refresh::WhenDue,
        &world.signers()?,
        offline(&calls),
    );
    check(&calls.get(), &FETCHED_ONCE, "a fetch was tried")?;
    check(
        &run.source,
        &AnchorSource::Unavailable(TrustedListError::NotFetched),
        "source",
    )?;
    check(&run.anchors.anchors().len(), &unlisted_count(), "anchors")?;
    check_true(
        !dir.path().join(LISTS_DIRECTORY).exists(),
        "nothing written",
    )
}

/// `records` with every `from` in their bytes replaced by `to`, which
/// breaks the signature of each list that carries it.
fn tampered(records: &[CachedList], from: &str, to: &str) -> Vec<CachedList> {
    records
        .iter()
        .map(|record| {
            CachedList::new(
                record.location().clone(),
                record.fetched_at(),
                record.next_update(),
                String::from_utf8_lossy(record.bytes())
                    .replace(from, to)
                    .into_bytes(),
            )
        })
        .collect()
}

#[test]
fn a_cached_national_list_that_no_longer_reads_is_fetched_again() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-tampered-national")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    cache.store(&tampered(&world.serve(day(FETCHED))?.1, CA, PROVIDER))?;
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(LATER),
        Refresh::WhenDue,
        &world.signers()?,
        offline(&calls),
    );
    check(&calls.get(), &FETCHED_ONCE, "a fetch was tried")?;
    check(
        &run.anchors.anchors().len(),
        &unlisted_count(),
        "the national list yields nothing",
    )
}

#[test]
fn a_cached_list_of_the_lists_that_no_longer_reads_leaves_the_lists_unavailable() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-tampered-lotl")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    cache.store(&tampered(
        &world.serve(day(FETCHED))?.1,
        LOTL_OPERATOR,
        PROVIDER,
    ))?;
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(LATER),
        Refresh::WhenDue,
        &world.signers()?,
        offline(&calls),
    );
    check(&calls.get(), &FETCHED_ONCE, "a fetch was tried")?;
    check(
        &run.source,
        &AnchorSource::Unavailable(TrustedListError::NotFetched),
        "source",
    )
}

#[test]
fn a_file_without_a_record_does_not_read() -> TestResult {
    let dir = TempDir::new("trusted-lists-garbage")?;
    dir.write("garbage.list", b"synthetic bytes without a record")?;
    dir.write(
        "partial.list",
        format!("{KEY_LOCATION}{KEY_SEPARATOR}{LOTL_LOCATION}\n\nlist").as_bytes(),
    )?;
    check_true(
        ListCache::at(dir.path().to_path_buf()).load().is_empty(),
        "nothing reads",
    )
}

#[test]
fn the_cache_is_under_the_local_application_data() -> TestResult {
    let base = std::env::temp_dir();
    let resolved = |value: Option<OsString>| {
        directory_from(|name| (name == LOCAL_APP_DATA).then(|| value.clone()).flatten())
    };
    check(
        &resolved(Some(base.clone().into_os_string())),
        &Some(base.join("RefineID").join("trusted-lists")),
        "local application data",
    )?;
    check(
        &resolved(Some(OsString::from("relative"))),
        &None,
        "a relative path does not count",
    )?;
    check(&resolved(None), &None, "unset")
}

#[test]
fn a_national_list_that_fails_in_a_refresh_keeps_its_cached_copy() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-keep-national")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    cache.store(&world.serve(day(FETCHED))?.1)?;
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(OVERDUE),
        Refresh::WhenDue,
        &world.signers()?,
        transport(vec![(LOTL_LOCATION, world.lotl_bytes())], &calls),
    );
    check(&calls.get(), &FETCHED_ONCE, "refreshed")?;
    check(
        &run.anchors.anchors().len(),
        &(unlisted_count() + LISTED_ANCHORS),
        "the cached national list still yields its anchor",
    )?;
    check(
        &run.source,
        &AnchorSource::Lists {
            fetched_at: day(FETCHED),
            stale: true,
        },
        "the oldest list sets the time",
    )?;
    let loaded = cache.load();
    let fetched_at = |location: &str| {
        loaded
            .iter()
            .find(|record| record.location().to_string() == location)
            .map(CachedList::fetched_at)
    };
    check(
        &fetched_at(LOTL_LOCATION),
        &Some(day(OVERDUE)),
        "new list of the lists",
    )?;
    check(
        &fetched_at(NATIONAL_LOCATION),
        &Some(day(FETCHED)),
        "kept national list",
    )
}

#[test]
fn a_list_no_longer_pointed_at_leaves_the_cache() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-unpointed")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    cache.store(&world.serve(day(FETCHED))?.1)?;
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(OVERDUE),
        Refresh::WhenDue,
        &world.signers()?,
        transport(vec![(LOTL_LOCATION, world.lotl_without_pointers())], &calls),
    );
    check(
        &run.anchors.anchors().len(),
        &unlisted_count(),
        "no national list",
    )?;
    let loaded = cache.load();
    check(
        &loaded.len(),
        &LISTS_OF_THE_LISTS,
        "only the list of the lists",
    )?;
    check_true(
        loaded
            .iter()
            .all(|record| record.location().to_string() == LOTL_LOCATION),
        "the national list is gone",
    )
}

/// The live lists, over the network, into a scratch cache. Run by hand:
/// `cargo test -p refineid-windows-doc-sign live_lists -- --ignored --nocapture`.
#[test]
#[ignore = "fetches the live EU trusted lists over the network"]
fn live_lists_fetch_read_and_anchor() -> TestResult {
    use refineid_doc_sign::verification::trusted_list::{MAX_LIST_BYTES, lotl_signers};

    crate::http::install();
    let now = refineid_doc_sign::now_date_time();
    let lotl = Uri::parse(LOTL_LOCATION.to_owned())?;
    let bytes = refineid_doc_sign::http::get(&lotl, MAX_LIST_BYTES)
        .map_err(|error| format!("list of the lists: {error}"))?;
    println!("list of the lists: {} bytes", bytes.len());
    let dir = TempDir::new("trusted-lists-live")?;
    let cache = ListCache::at(dir.path().to_path_buf());
    let run = run_anchors(
        Some(&cache),
        now,
        Refresh::Now,
        &lotl_signers(),
        fetch_over_http,
    );
    println!("{}", run.source);
    println!("{} anchors", run.anchors.anchors().len());
    let records = cache.load();
    let lists = TrustedLists::from_cache(&records, &lotl_signers())?;
    for list in lists.national() {
        match list.outcome() {
            Ok(read) => println!(
                "{} read: {} services, next update {:?}",
                list.territory(),
                read.services().len(),
                read.next_update()
            ),
            Err(failure) => {
                let why = list
                    .location()
                    .map(|location| refineid_doc_sign::http::get(location, MAX_LIST_BYTES))
                    .and_then(Result::err)
                    .map_or_else(String::new, |error| format!(" ({error})"));
                println!("{} not read: {failure}{why}", list.territory());
            }
        }
    }
    check_true(
        lists
            .national()
            .iter()
            .any(|list| list.territory() == "FI" && list.outcome().is_ok()),
        "the Finnish list read",
    )?;
    check_true(
        matches!(run.source, AnchorSource::Lists { .. }),
        "anchors come from the lists",
    )
}

#[test]
fn cache_only_uses_overdue_lists_without_fetching() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-cache-only")?;
    let cache = ListCache::at(dir.path().join(LISTS_DIRECTORY));
    let calls = Cell::new(NOT_FETCHED);
    let _first = run_anchors(
        Some(&cache),
        day(FETCHED),
        Refresh::WhenDue,
        &world.signers()?,
        online(&world, &calls),
    );
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(OVERDUE),
        Refresh::CacheOnly,
        &world.signers()?,
        offline(&calls),
    );
    check(&calls.get(), &NOT_FETCHED, "nothing fetched")?;
    check(
        &run.anchors.anchors().len(),
        &LISTED_ANCHORS,
        "the cached list's anchor",
    )?;
    check(
        &certificate_issuing_ders(&run.anchors, day(FETCHED)).len(),
        &LISTED_ANCHORS,
        "the listed CA as a signer anchor",
    )
}

#[test]
fn cache_only_without_a_cache_fetches_nothing_and_has_no_anchor() -> TestResult {
    let world = World::new();
    let dir = TempDir::new("trusted-lists-cache-only-empty")?;
    let cache = ListCache::at(dir.path().join(LISTS_DIRECTORY));
    let calls = Cell::new(NOT_FETCHED);
    let run = run_anchors(
        Some(&cache),
        day(FETCHED),
        Refresh::CacheOnly,
        &world.signers()?,
        offline(&calls),
    );
    check(&calls.get(), &NOT_FETCHED, "nothing fetched")?;
    check(
        &run.source,
        &AnchorSource::Unavailable(TrustedListError::NotFetched),
        "source",
    )?;
    check_true(run.anchors.anchors().is_empty(), "no anchor")
}
