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

//! Tests of the Windows edge: the cache directory resolution and, by
//! hand, the live lists over this crate's HTTP stack. Fetching,
//! storing and refreshing are core's to test.

use super::*;
use crate::test_util::{TempDir, TestResult, check, check_true};
use refineid_doc_sign::uri::Uri;
use refineid_doc_sign::verification::trusted_list::{
    LOTL_LOCATION, MAX_LIST_BYTES, TrustedLists, fetch_over_http, lotl_signers,
};

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

/// The live lists, over the network, into a scratch cache. Run by hand:
/// `cargo test -p refineid-windows-doc-sign live_lists -- --ignored --nocapture`.
#[test]
#[ignore = "fetches the live EU trusted lists over the network"]
fn live_lists_fetch_read_and_anchor() -> TestResult {
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
        &mut |_| {},
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
            .any(|list| list.territory() == FINNISH_TERRITORY && list.outcome().is_ok()),
        "the Finnish list read",
    )?;
    check_true(
        matches!(run.source, AnchorSource::Lists { .. }),
        "anchors come from the lists",
    )
}
