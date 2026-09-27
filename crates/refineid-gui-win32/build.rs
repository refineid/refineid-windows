// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Expose the workspace build stamp to the GUI.
//!
//! The `VERSION` file at the workspace root carries `version.build`
//! (e.g. `26.9.24.210`); the OC builder publishes that same string.
//! This script passes it through as `REFINEID_FULL_VERSION` so the
//! Status tab shows the identical build number. Parsing lives in
//! `src/version.rs`, where host tests cover it; this script stays
//! a dumb pipe with a package-version fallback.

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let version_file = std::path::Path::new(&manifest_dir)
        .join("../../VERSION")
        .canonicalize()
        .ok();
    let full = version_file
        .as_deref()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_default());
    println!("cargo:rerun-if-changed=../../VERSION");
    println!("cargo:rustc-env=REFINEID_FULL_VERSION={full}");
}
