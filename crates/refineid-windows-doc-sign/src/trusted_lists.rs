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

//! The EU trusted lists over this computer's cache and HTTP stack.
//!
//! Fetching, storing, refreshing and anchoring live in
//! [`refineid_doc_sign::verification::trusted_list::cache`]; this
//! module is the Windows edge around it: the per-user cache directory
//! and this crate's `WinHTTP` transport.

use std::ffi::OsString;
use std::path::PathBuf;

pub use refineid_doc_sign::verification::trusted_list::cache::{
    AnchorSource, FINNISH_TERRITORY, FinnishListGap, ListCache, Refresh, RunAnchors,
    certificate_issuing_ders,
};
use refineid_doc_sign::verification::trusted_list::cache::{
    CacheEvent, prefetching_get, run_anchors,
};
use refineid_doc_sign::verification::trusted_list::{fetch_over_http, lotl_signers};
use refineid_doc_sign::x509::DateTime;

/// The variable naming the user's local application data.
const LOCAL_APP_DATA: &str = "LOCALAPPDATA";
/// The application's directory under the local application data.
const APPLICATION_DIRECTORY: &str = "RefineID";
/// The lists' directory under the application's.
const LISTS_DIRECTORY: &str = "trusted-lists";

/// The per-user cache: `%LOCALAPPDATA%\RefineID\trusted-lists`.
/// `None` when the variable is unset, empty or relative.
fn user_cache() -> Option<ListCache> {
    directory_from(|name| std::env::var_os(name)).map(ListCache::at)
}

/// [`user_cache`] over the environment `variable` reads.
fn directory_from(variable: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let local = variable(LOCAL_APP_DATA)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())?;
    Some(local.join(APPLICATION_DIRECTORY).join(LISTS_DIRECTORY))
}

/// [`run_anchors`] over the user's cache, the Official Journal's
/// list-signing certificates core ships and the `WinHTTP` transport.
/// Diagnostics go to the document-signing log.
#[must_use]
pub fn user_anchors(now: DateTime, refresh: Refresh) -> RunAnchors {
    crate::http::install();
    let signers = lotl_signers();
    let mut report = |event: CacheEvent| match event {
        CacheEvent::CachedListsUnreadable { error } => {
            refineid_dev_errors::report!(DocumentSigning, "cached trusted lists not read", error);
        }
        CacheEvent::ListsNotCached { error } => {
            refineid_dev_errors::report!(DocumentSigning, "trusted lists not cached", error);
        }
        CacheEvent::ListsNotFetched { error } => {
            refineid_dev_errors::report!(DocumentSigning, "trusted lists not fetched", error);
        }
        CacheEvent::AttemptNotRecorded { error } => {
            refineid_dev_errors::report!(
                DocumentSigning,
                "trusted-list fetch time not recorded",
                error
            );
        }
    };
    run_anchors(
        user_cache().as_ref(),
        now,
        refresh,
        &signers,
        prefetching_get(&signers, fetch_over_http, &|_, _| {}),
        &mut report,
    )
}

#[cfg(test)]
mod tests;
