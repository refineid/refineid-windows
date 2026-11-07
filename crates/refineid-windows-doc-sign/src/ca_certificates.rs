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

//! The card's CA certificates, kept until they expire.
//!
//! refineid-core's `doc/security/certificate-custody.md` rules that
//! the issuing CA (`EF.4336`) and the root (`EF.4334`) a card carries
//! are cached per user until their own validity ends, in storage only
//! the owner can read, and read from the card only when the cache
//! holds no unexpired issuer. Nothing in them is personal.
//!
//! The cache is the directory the PKCS#11 module keeps:
//! `%REFINEID_CA_CACHE_DIR%` when set, else
//! `%LOCALAPPDATA%\\refineid\\ca-certificates\\`, else the same under
//! `%APPDATA%`. One file per certificate, named by the lowercase hex
//! SHA-256 of its DER with the extension `der`, holding the DER alone,
//! written to a temporary name and renamed into place. A file that does
//! not parse, is not a CA certificate, is expired or exceeds
//! [`MAX_CERTIFICATE_BYTES`] is removed when found. Either side reads
//! what the other wrote.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use refineid_doc_sign::x509::{Certificate, DateTime, OwnedCert, extract_basic_constraints};
use sha2::{Digest as _, Sha256};

/// The variable that names the cache directory outright.
const CACHE_DIRECTORY_VARIABLE: &str = "REFINEID_CA_CACHE_DIR";
/// The variables naming per-user application data, in order.
const APPLICATION_DATA_VARIABLES: [&str; 2] = ["LOCALAPPDATA", "APPDATA"];
/// The application's directory under the cache directory.
const APPLICATION_DIRECTORY: &str = "refineid";
/// The certificates' directory under the application's.
const CERTIFICATES_DIRECTORY: &str = "ca-certificates";
/// File extension of one stored certificate.
const CERTIFICATE_EXTENSION: &str = "der";
/// Most certificates read back from the cache.
const MAX_CERTIFICATES: usize = 16;
/// Most directory entries examined to find them.
const MAX_ENTRIES: usize = MAX_CERTIFICATES * 4;
/// Largest file read back as a certificate.
pub const MAX_CERTIFICATE_BYTES: u64 = 65_536;

/// The CA certificates' cache directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaCache {
    /// The directory.
    directory: PathBuf,
}

impl CaCache {
    /// The cache in `directory`.
    #[must_use]
    pub const fn at(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// The per-user cache, or `None` when no variable names a
    /// directory.
    #[must_use]
    pub fn user() -> Option<Self> {
        directory_from(|name| std::env::var_os(name).filter(|value| !value.is_empty()))
            .map(Self::at)
    }

    /// Every stored certificate that is a CA certificate valid at
    /// `now`; a file that is not one is removed.
    #[must_use]
    pub fn load(&self, now: DateTime) -> Vec<OwnedCert> {
        let Ok(entries) = fs::read_dir(&self.directory) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case(CERTIFICATE_EXTENSION))
            })
            .take(MAX_ENTRIES)
            .collect();
        paths.sort();
        let mut certificates = Vec::new();
        for path in paths {
            if certificates.len() >= MAX_CERTIFICATES {
                break;
            }
            match read_certificate(&path, now) {
                Some(certificate) => certificates.push(certificate),
                None => {
                    let _removed = fs::remove_file(&path);
                }
            }
        }
        certificates
    }

    /// Store `certificates`, each under its fingerprint; one already
    /// stored is left as it is.
    ///
    /// # Errors
    /// The I/O error of the first file that could not be written.
    pub fn store(&self, certificates: &[OwnedCert]) -> std::io::Result<()> {
        if certificates.is_empty() {
            return Ok(());
        }
        fs::create_dir_all(&self.directory)?;
        for certificate in certificates {
            let der = certificate.as_der();
            let name = hex::encode(Sha256::digest(der));
            let path = self
                .directory
                .join(name)
                .with_extension(CERTIFICATE_EXTENSION);
            if path.exists() {
                continue;
            }
            write_atomically(&path, der)?;
        }
        Ok(())
    }
}

/// The CA certificates a card supplied that the custody rule admits.
///
/// The issuing CA when it is a CA certificate valid at `now`, and the
/// root when it is one too, self-signed, and the verified issuer of
/// that issuing CA.
#[must_use]
pub fn admit(issuing_ca: Option<&[u8]>, root: Option<&[u8]>, now: DateTime) -> Vec<OwnedCert> {
    let mut admitted = Vec::new();
    let Some(issuing_ca) = issuing_ca.and_then(|der| ca_certificate(der, now)) else {
        return admitted;
    };
    if let Some(root) = root.and_then(|der| ca_certificate(der, now)) {
        let root_view = root.view();
        let self_signed = root_view.issuer.as_der() == root_view.subject.as_der()
            && root_view.verify_signed_by(root_view).is_ok();
        if self_signed && issuing_ca.view().verify_signed_by(root_view).is_ok() {
            admitted.push(root);
        }
    }
    admitted.insert(0, issuing_ca);
    admitted
}

/// `der` as a CA certificate valid at `now`, or nothing.
fn ca_certificate(der: &[u8], now: DateTime) -> Option<OwnedCert> {
    let certificate = OwnedCert::from_der(der).ok()?;
    is_ca_valid_at(certificate.view(), now).then_some(certificate)
}

/// Whether `certificate` asserts `basicConstraints` CA and `now` lies
/// in its validity, both ends inclusive (RFC 5280 clauses 4.1.2.5 and
/// 4.2.1.9).
fn is_ca_valid_at(certificate: Certificate<'_>, now: DateTime) -> bool {
    let ca = certificate
        .extensions
        .is_some_and(|extensions| extract_basic_constraints(extensions).ca);
    ca && certificate.not_before <= now && now <= certificate.not_after
}

/// The certificate at `path` when it is a CA certificate valid at
/// `now` in a regular file of admissible size.
fn read_certificate(path: &Path, now: DateTime) -> Option<OwnedCert> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || metadata.len() > MAX_CERTIFICATE_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    ca_certificate(&bytes, now)
}

/// [`CaCache::user`] over the environment `variable` reads.
fn directory_from(variable: impl Fn(&str) -> Option<std::ffi::OsString>) -> Option<PathBuf> {
    if let Some(named) = variable(CACHE_DIRECTORY_VARIABLE) {
        return Some(PathBuf::from(named));
    }
    let data = APPLICATION_DATA_VARIABLES
        .iter()
        .find_map(|name| variable(name))
        .map(PathBuf::from)?;
    Some(
        data.join(APPLICATION_DIRECTORY)
            .join(CERTIFICATES_DIRECTORY),
    )
}

/// Write `bytes` to `path` atomically.
///
/// # Errors
/// The I/O error of the write; the temporary file is removed.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "certificate file name",
        ));
    };
    let temporary = path.with_file_name(format!(".{name}.tmp.{}", std::process::id()));
    let written = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _removed = fs::remove_file(&temporary);
    }
    written
}

#[cfg(test)]
mod tests {
    use refineid_doc_sign::testkit::{
        CertificateSpec, TestCurve, TestKey, ca_extensions, certificate, day,
    };

    use super::*;
    use crate::test_util::{TempDir, TestResult, check, check_true};

    /// Day every certificate starts.
    const STARTS: u8 = 1;
    /// A day inside every certificate's validity.
    const WITHIN: u8 = 15;
    /// Day every certificate ends.
    const ENDS: u8 = 20;
    /// A day after every certificate has ended.
    const AFTER: u8 = 25;
    /// Serial of the root.
    const ROOT_SERIAL: u8 = 1;
    /// Serial of the issuing CA.
    const ISSUING_SERIAL: u8 = 2;
    /// Serial of the unrelated root.
    const OTHER_SERIAL: u8 = 3;
    /// Subject of the root.
    const ROOT_NAME: &str = "Synthetic Root CA";
    /// Subject of the issuing CA.
    const ISSUING_NAME: &str = "Synthetic Issuing CA";
    /// Subject of the unrelated root.
    const OTHER_NAME: &str = "Synthetic Other Root CA";
    /// Both of a pair admitted.
    const BOTH: usize = 2;
    /// The issuing CA alone admitted.
    const ONE: usize = 1;

    /// A root, an issuing CA it issued and a root that did not issue it.
    struct Chain {
        /// The root's DER.
        root: Vec<u8>,
        /// The issuing CA's DER.
        issuing: Vec<u8>,
        /// The unrelated root's DER.
        other: Vec<u8>,
    }

    fn spec(serial: u8, subject: &'static str, issuer: &'static str) -> CertificateSpec<'static> {
        CertificateSpec {
            serial,
            subject,
            issuer,
            not_before: day(STARTS),
            not_after: day(ENDS),
            extensions: ca_extensions(),
        }
    }

    fn chain() -> Chain {
        let root_key = TestKey::derive(TestCurve::P256, b"synthetic root");
        let issuing_key = TestKey::derive(TestCurve::P256, b"synthetic issuing");
        let other_key = TestKey::derive(TestCurve::P256, b"synthetic other");
        Chain {
            root: certificate(
                &spec(ROOT_SERIAL, ROOT_NAME, ROOT_NAME),
                &root_key,
                &root_key,
            ),
            issuing: certificate(
                &spec(ISSUING_SERIAL, ISSUING_NAME, ROOT_NAME),
                &issuing_key,
                &root_key,
            ),
            other: certificate(
                &spec(OTHER_SERIAL, OTHER_NAME, OTHER_NAME),
                &other_key,
                &other_key,
            ),
        }
    }

    #[test]
    fn the_issuing_ca_and_its_root_are_admitted() -> TestResult {
        let world = chain();
        let admitted = admit(Some(&world.issuing), Some(&world.root), day(WITHIN));
        check(&admitted.len(), &BOTH, "both admitted")?;
        check_true(
            admitted
                .first()
                .is_some_and(|c| c.as_der() == world.issuing),
            "the issuing CA first",
        )
    }

    #[test]
    fn a_root_that_did_not_issue_the_issuing_ca_is_not_admitted() -> TestResult {
        let world = chain();
        let admitted = admit(Some(&world.issuing), Some(&world.other), day(WITHIN));
        check(&admitted.len(), &ONE, "the issuing CA alone")
    }

    #[test]
    fn a_root_alone_or_expired_certificates_are_not_admitted() -> TestResult {
        let world = chain();
        check_true(
            admit(None, Some(&world.root), day(WITHIN)).is_empty(),
            "no issuing CA",
        )?;
        check_true(
            admit(Some(&world.issuing), Some(&world.root), day(AFTER)).is_empty(),
            "expired",
        )
    }

    #[test]
    fn stored_certificates_read_back_and_a_bad_file_goes() -> TestResult {
        let world = chain();
        let dir = TempDir::new("ca-cache")?;
        let cache = CaCache::at(dir.path().to_path_buf());
        cache.store(&admit(Some(&world.issuing), Some(&world.root), day(WITHIN)))?;
        let junk = dir
            .path()
            .join("junk")
            .with_extension(CERTIFICATE_EXTENSION);
        fs::write(&junk, b"not a certificate")?;
        check(&cache.load(day(WITHIN)).len(), &BOTH, "both read back")?;
        check_true(!junk.exists(), "the bad file removed")?;
        check(&cache.load(day(AFTER)).len(), &0, "expired ones go")
    }

    #[test]
    fn the_cache_directory_follows_the_module_s() -> TestResult {
        let resolved = |pairs: &'static [(&'static str, &'static str)]| {
            directory_from(|name| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| std::ffi::OsString::from(value))
            })
        };
        let under = |base: &str| Some(PathBuf::from(base).join("refineid").join("ca-certificates"));
        check(
            &resolved(&[("LOCALAPPDATA", "local"), ("APPDATA", "roaming")]),
            &under("local"),
            "local first",
        )?;
        check(
            &resolved(&[("APPDATA", "roaming")]),
            &under("roaming"),
            "roaming",
        )?;
        check(
            &resolved(&[
                (CACHE_DIRECTORY_VARIABLE, "named"),
                ("LOCALAPPDATA", "local"),
            ]),
            &Some(PathBuf::from("named")),
            "named",
        )?;
        check(&resolved(&[]), &None, "none")
    }
}
