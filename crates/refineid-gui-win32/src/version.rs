// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! The build stamp shown on the Status tab.
//!
//! Mirrors the Android companion's `VERSION_NAME (BUILD_NUMBER)`
//! shape: the workspace `VERSION` file carries `version.build`
//! (e.g. `26.9.24.210`) and the OC builder publishes that same
//! string, so the GUI shows the identical number. Unconditional
//! module (no Win32 dependency) so host tests cover the parsing.

/// Compile-time full version from `build.rs`, e.g. `26.9.24.210`.
const FULL_VERSION: &str = match option_env!("REFINEID_FULL_VERSION") {
    Some(full) => full,
    None => env!("CARGO_PKG_VERSION"),
};

/// Fallback build tag when no build number is stamped.
const DEV_BUILD: &str = "dev";

/// Split `version.build` into display name and build number.
///
/// A four-part stamp splits at the last dot; anything else keeps
/// the whole string as the name and reports a dev build.
fn split_name_build(full: &str) -> (String, String) {
    let trimmed = full.trim();
    let mut parts = trimmed.rsplit('.');
    let (Some(build), Some(_), Some(_), Some(_)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        let name = if trimmed.is_empty() {
            env!("CARGO_PKG_VERSION").to_owned()
        } else {
            trimmed.to_owned()
        };
        return (name, DEV_BUILD.to_owned());
    };
    let name_len = trimmed.len() - build.len() - 1;
    (trimmed[..name_len].to_owned(), build.to_owned())
}

/// The Status tab stamp, e.g. `RefineID 26.9.24 (210)`.
#[must_use]
pub fn build_label() -> String {
    let (name, build) = split_name_build(FULL_VERSION);
    format!("RefineID {name} ({build})")
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test expectations are constructed to be infallible"
)]
mod tests {
    use super::{DEV_BUILD, build_label, split_name_build};

    #[test]
    fn four_part_stamp_splits_at_last_dot() {
        assert_eq!(
            split_name_build("26.9.24.210"),
            ("26.9.24".to_owned(), "210".to_owned())
        );
    }

    #[test]
    fn three_part_version_reports_dev_build() {
        let (name, build) = split_name_build("26.9.24");
        assert_eq!(name, "26.9.24");
        assert_eq!(build, DEV_BUILD);
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(
            split_name_build("  26.9.24.210\r\n"),
            ("26.9.24".to_owned(), "210".to_owned())
        );
    }

    #[test]
    fn empty_stamp_falls_back_to_package_version() {
        let (name, build) = split_name_build("");
        assert_eq!(name, env!("CARGO_PKG_VERSION"));
        assert_eq!(build, DEV_BUILD);
    }

    #[test]
    fn label_carries_name_and_build() {
        let label = build_label();
        assert!(label.starts_with("RefineID "), "label: {label}");
        assert!(label.ends_with(')'), "label: {label}");
        assert!(label.contains(" ("), "label: {label}");
    }
}
