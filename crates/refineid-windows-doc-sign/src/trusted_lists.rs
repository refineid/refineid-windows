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

//! The EU trusted lists the trust anchors come from, fetched over
//! `WinHTTP` and kept in the user's local application data.
//!
//! `refineid_doc_sign::verification::trusted_list` reads and verifies
//! the lists and writes no file; this module fetches them, stores what
//! was fetched and hands it back. The cache is one directory,
//! `%LOCALAPPDATA%\RefineID\trusted-lists\`, whose inherited access
//! list leaves it to the user, holding one file per list: its record as
//! `key: value` lines (`location`, `fetched-at`, `next-update`), one
//! blank line, then the list's bytes as fetched. Each file is written
//! atomically (temporary file, flush, rename). The lists are public and
//! every signature is verified again on each read, so the directory
//! needs no secrecy and no integrity of its own.
//!
//! On each run the cached lists are read back, every signature
//! verified again, and used as they are while none is due: the lists
//! are fetched afresh when there is no cache, a cached list no longer
//! reads, one is past its `NextUpdate`, the cache is older than
//! [`REFRESH_AFTER`], or the caller asks ([`Refresh::Now`]). A national
//! list that fails in a refresh keeps its last cached copy; a list of
//! the lists that fails leaves every cached list in use and the report
//! says how old they are. With no list at all there is no anchor, and
//! [`AnchorSource::Unavailable`] says why: the software ships no root
//! (AGENTS.md, "Certificates and trust").

use core::time::Duration;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use refineid_doc_sign::uri::Uri;
use refineid_doc_sign::verification::trusted_list::{
    CachedList, LOTL_LOCATION, NationalList, TrustedListError, TrustedLists, fetch_over_http,
    lotl_signers,
};
use refineid_doc_sign::verification::{AnchorRole, TrustAnchors};
use refineid_doc_sign::x509::{DateTime, OwnedCert};
use sha2::{Digest as _, Sha256};

/// Seconds in a day.
const SECONDS_PER_DAY: u64 = 86_400;
/// Days a cache is used before it is fetched again although no list
/// is past its `NextUpdate`.
const REFRESH_AFTER_DAYS: u64 = 30;
/// How old the cache may grow before a run fetches the lists again.
///
/// A fetch follows although no list is past its `NextUpdate`. `ETSI TS 119 612` clause
/// 5.3.15 lets an operator set the next update up to six months ahead,
/// and operators reissue a list whenever a service's status changes,
/// often monthly; a month-old cache therefore misses a withdrawal the
/// list's own schedule would announce only later.
pub const REFRESH_AFTER: Duration = Duration::from_secs(REFRESH_AFTER_DAYS * SECONDS_PER_DAY);

/// The variable naming the user's local application data.
const LOCAL_APP_DATA: &str = "LOCALAPPDATA";
/// The application's directory under the local application data.
const APPLICATION_DIRECTORY: &str = "RefineID";
/// The lists' directory under the application's.
const LISTS_DIRECTORY: &str = "trusted-lists";
/// File extension of one stored list.
const LIST_EXTENSION: &str = "list";
/// File extension of a list being written.
const TEMPORARY_EXTENSION: &str = "tmp";

/// The record key of the list's location.
const KEY_LOCATION: &str = "location";
/// The record key of the fetch time.
const KEY_FETCHED_AT: &str = "fetched-at";
/// The record key of the list's next update.
const KEY_NEXT_UPDATE: &str = "next-update";
/// The separator of a record key and its value.
const KEY_SEPARATOR: &str = ": ";
/// The value of `next-update` for a closed list.
const NO_NEXT_UPDATE: &str = "-";
/// How many lists of the lists one set holds.
const LISTS_OF_THE_LISTS: usize = 1;
/// What ends the record, its last line and one blank line, and starts
/// the list's bytes.
const RECORD_END: &[u8] = b"\n\n";

/// When a run fetches the lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresh {
    /// When the cache is missing, unreadable, past a list's
    /// `NextUpdate` or older than [`REFRESH_AFTER`].
    WhenDue,
    /// Before judging anything, whatever the cache holds.
    Now,
    /// Never: the cached lists as they are, stale or not, and no
    /// anchor when there are none.
    CacheOnly,
}

/// Where the anchors of one run came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorSource {
    /// The trusted lists fetched at `fetched_at`.
    Lists {
        /// When the lists were fetched; the oldest list's time when
        /// a refresh kept a cached national list.
        fetched_at: DateTime,
        /// Whether a list is past its `NextUpdate`.
        stale: bool,
    },
    /// No list is at hand: none was ever fetched, or the cache no
    /// longer reads and the fetch failed as the error says. Nothing
    /// anchors anything.
    Unavailable(TrustedListError),
}

impl core::fmt::Display for AnchorSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Lists { fetched_at, stale } => {
                write!(f, "trusted lists fetched {fetched_at}")?;
                if *stale {
                    f.write_str(", past their next update")?;
                }
                Ok(())
            }
            Self::Unavailable(error) => {
                write!(
                    f,
                    "trusted lists not fetched yet, nothing can be anchored: {error}"
                )
            }
        }
    }
}

/// The anchors of one run and where they came from.
#[derive(Debug)]
pub struct RunAnchors {
    /// The anchors.
    pub anchors: TrustAnchors,
    /// Where they came from.
    pub source: AnchorSource,
}

/// The lists' cache directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListCache {
    /// The directory.
    directory: PathBuf,
}

impl ListCache {
    /// The cache in `directory`.
    #[must_use]
    pub const fn at(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// The per-user cache: `%LOCALAPPDATA%\RefineID\trusted-lists`.
    /// `None` when the variable is unset, empty or relative.
    #[must_use]
    pub fn user() -> Option<Self> {
        directory_from(|name| std::env::var_os(name)).map(Self::at)
    }

    /// Every stored record that reads; files that do not are skipped.
    #[must_use]
    pub fn load(&self) -> Vec<CachedList> {
        let Ok(entries) = fs::read_dir(&self.directory) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == LIST_EXTENSION))
            .filter_map(|path| fs::read(path).ok())
            .filter_map(|bytes| decode(&bytes))
            .collect()
    }

    /// Replace the stored lists by `records`: each written atomically,
    /// then every stored list not among them removed.
    ///
    /// # Errors
    /// The I/O error of the first file that could not be written.
    pub fn store(&self, records: &[CachedList]) -> std::io::Result<()> {
        fs::create_dir_all(&self.directory)?;
        let mut kept = Vec::new();
        for record in records {
            let path = self.path_for(record.location());
            write_atomically(&path, &encode(record))?;
            kept.push(path);
        }
        for entry in fs::read_dir(&self.directory)?.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == LIST_EXTENSION) && !kept.contains(&path) {
                let _removed = fs::remove_file(path);
            }
        }
        Ok(())
    }

    /// The file of the list at `location`: the SHA-256 of the location
    /// in lowercase hex.
    fn path_for(&self, location: &Uri) -> PathBuf {
        let name = hex::encode(Sha256::digest(location.to_string().as_bytes()));
        self.directory.join(name).with_extension(LIST_EXTENSION)
    }
}

/// The anchors of a run at `now`.
///
/// The lists in `cache` are read under `signers`, every signature
/// verified again, and used as they are unless a fetch is due:
/// `refresh` is [`Refresh::Now`], there are no lists, one no longer
/// reads, one is past its `NextUpdate`, or the cache is older than
/// [`REFRESH_AFTER`]. A due fetch reads the lists again with `get` and
/// the cache takes the result; a list of the lists that does not
/// arrive or read leaves the cached lists in use. Under
/// [`Refresh::CacheOnly`] nothing is fetched and `get` is never
/// called. Without lists there is no anchor.
pub fn run_anchors(
    cache: Option<&ListCache>,
    now: DateTime,
    refresh: Refresh,
    signers: &[OwnedCert],
    get: impl FnMut(&Uri) -> Option<Vec<u8>>,
) -> RunAnchors {
    let records = cache.map(ListCache::load).unwrap_or_default();
    let cached = (!records.is_empty())
        .then(|| match TrustedLists::from_cache(&records, signers) {
            Ok(lists) => Some(lists),
            Err(error) => {
                refineid_dev_errors::report!(
                    DocumentSigning,
                    "cached trusted lists not read",
                    error
                );
                None
            }
        })
        .flatten();
    let due = |lists: &TrustedLists| match refresh {
        Refresh::Now => true,
        Refresh::CacheOnly => false,
        Refresh::WhenDue => {
            lists.is_stale(now)
                || age(lists.fetched_at(), now) > REFRESH_AFTER
                || read_count(lists) != records.len()
        }
    };
    let lists = match cached {
        Some(lists) if !due(&lists) => Ok(lists),
        None if refresh == Refresh::CacheOnly => Err(TrustedListError::NotFetched),
        cached => match fetch(get, now, signers, &records) {
            Ok((lists, fetched)) => {
                if let Some(cache) = cache
                    && let Err(error) = cache.store(&fetched)
                {
                    let kind = error.kind();
                    refineid_dev_errors::report!(DocumentSigning, "trusted lists not cached", kind);
                }
                Ok(lists)
            }
            Err(error) => {
                refineid_dev_errors::report!(DocumentSigning, "trusted lists not fetched", error);
                cached.ok_or(error)
            }
        },
    };
    match lists {
        Ok(lists) => RunAnchors {
            anchors: TrustAnchors::from_trusted_lists(&lists),
            source: AnchorSource::Lists {
                fetched_at: lists.fetched_at(),
                stale: lists.is_stale(now),
            },
        },
        Err(error) => RunAnchors {
            anchors: without_lists(),
            source: AnchorSource::Unavailable(error),
        },
    }
}

/// The anchors a run has with no list at hand: none. The software
/// ships no root a chain could end at.
fn without_lists() -> TrustAnchors {
    TrustAnchors::default()
}

/// The DER of every anchor in `anchors` trusted for
/// [`AnchorRole::CertificateIssuing`] at `now`: what a signing
/// request's `signer_anchors` takes from the lists.
#[must_use]
pub fn certificate_issuing_ders(anchors: &TrustAnchors, now: DateTime) -> Vec<Vec<u8>> {
    anchors
        .anchors()
        .iter()
        .filter(|anchor| anchor.role() == AnchorRole::CertificateIssuing)
        .filter(|anchor| anchors.is_anchor(anchor.certificate().view(), anchor.role(), now))
        .map(|anchor| anchor.certificate().as_der().to_vec())
        .collect()
}

/// How long ago `then` was at `now`; nothing when `then` is later.
fn age(then: DateTime, now: DateTime) -> Duration {
    now.unix_duration().saturating_sub(then.unix_duration())
}

/// Fetch the lists afresh with `get` at `now`: the list of the lists
/// from [`LOTL_LOCATION`], read under `signers`, then each national
/// list it points at. A national list that does not arrive or read
/// keeps its record among `previous`, when there is one, and every
/// list is then read again from the records. A list the new list of
/// the lists no longer points at is not among the records returned.
///
/// # Errors
/// [`TrustedListError`] when the list of the lists does not arrive or
/// does not read.
fn fetch(
    mut get: impl FnMut(&Uri) -> Option<Vec<u8>>,
    now: DateTime,
    signers: &[OwnedCert],
    previous: &[CachedList],
) -> Result<(TrustedLists, Vec<CachedList>), TrustedListError> {
    let lotl_location =
        Uri::parse(LOTL_LOCATION.to_owned()).map_err(|_| TrustedListError::NotFetched)?;
    let lotl = get(&lotl_location).ok_or(TrustedListError::NotFetched)?;
    let (fresh, fetched) = TrustedLists::read(lotl, signers, &mut get, now)?;
    let kept: Vec<CachedList> = fresh
        .national()
        .iter()
        .filter(|list| list.outcome().is_err())
        .filter_map(NationalList::location)
        .filter_map(|location| previous.iter().find(|record| record.location() == location))
        .cloned()
        .collect();
    if kept.is_empty() {
        return Ok((fresh, fetched));
    }
    let mut records = fetched.clone();
    records.extend(kept);
    let Ok(lists) = TrustedLists::from_cache(&records, signers) else {
        return Ok((fresh, fetched));
    };
    records.retain(|record| {
        *record.location() == lotl_location
            || lists
                .national()
                .iter()
                .any(|list| list.location() == Some(record.location()) && list.outcome().is_ok())
    });
    Ok((lists, records))
}

/// [`run_anchors`] over the user's cache, the Official Journal's
/// list-signing certificates core ships and the `WinHTTP` transport.
#[must_use]
pub fn user_anchors(now: DateTime, refresh: Refresh) -> RunAnchors {
    crate::http::install();
    run_anchors(
        ListCache::user().as_ref(),
        now,
        refresh,
        &lotl_signers(),
        fetch_over_http,
    )
}

/// How many of `lists` read: the list of the lists and every national
/// list that did. Only lists that read are stored, so a cache that
/// yields fewer than it holds has a list that no longer reads.
fn read_count(lists: &TrustedLists) -> usize {
    LISTS_OF_THE_LISTS
        + lists
            .national()
            .iter()
            .filter(|list| list.outcome().is_ok())
            .count()
}

/// [`ListCache::user`] over the environment `variable` reads.
fn directory_from(variable: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let local = variable(LOCAL_APP_DATA)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())?;
    Some(local.join(APPLICATION_DIRECTORY).join(LISTS_DIRECTORY))
}

/// The stored form of `record`.
fn encode(record: &CachedList) -> Vec<u8> {
    let next_update = record
        .next_update()
        .map_or_else(|| NO_NEXT_UPDATE.to_owned(), |due| due.to_string());
    let mut out = String::new();
    for (key, value) in [
        (KEY_LOCATION, record.location().to_string()),
        (KEY_FETCHED_AT, record.fetched_at().to_string()),
        (KEY_NEXT_UPDATE, next_update),
    ] {
        out.push_str(key);
        out.push_str(KEY_SEPARATOR);
        out.push_str(&value);
        out.push('\n');
    }
    out.push('\n');
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(record.bytes());
    bytes
}

/// The record `bytes` store, if they read.
fn decode(bytes: &[u8]) -> Option<CachedList> {
    let end = bytes
        .windows(RECORD_END.len())
        .position(|window| window == RECORD_END)?;
    let (head, rest) = bytes.split_at(end);
    let list = rest.get(RECORD_END.len()..)?.to_vec();
    let head = core::str::from_utf8(head).ok()?;
    let mut lines = head.lines().map(|line| line.split_once(KEY_SEPARATOR));
    let mut value = |key: &str| match lines.next() {
        Some(Some((found, value))) if found == key => Some(value),
        _ => None,
    };
    let location = Uri::parse(value(KEY_LOCATION)?.to_owned()).ok()?;
    let fetched_at = value(KEY_FETCHED_AT)?.parse().ok()?;
    let next_update = match value(KEY_NEXT_UPDATE)? {
        NO_NEXT_UPDATE => None,
        due => Some(due.parse().ok()?),
    };
    if lines.next().is_some() {
        return None;
    }
    Some(CachedList::new(location, fetched_at, next_update, list))
}

/// Write `bytes` to `path` atomically.
///
/// # Errors
/// The I/O error of the write; the temporary file is removed.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("{}.{TEMPORARY_EXTENSION}", std::process::id()));
    let written = (|| {
        let mut file: File = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
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
mod tests;
