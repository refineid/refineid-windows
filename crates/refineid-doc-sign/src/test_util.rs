// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Test-only assertion helpers shared by every `*::tests`
//! module. Vendored from the sibling `refineid-unix` client
//! `lib.rs` (Apache-2.0, same copyright holder).
//!
//! Tests return `Result<(), Box<dyn core::error::Error>>`
//! and propagate mismatches through `?` rather than letting
//! `assert_eq!` / `assert!` panic.
use core::error::Error;
use core::fmt::Debug;
use core::sync::atomic::{AtomicU64, Ordering};
use std::path::{Path, PathBuf};

/// `Result` shape every `#[test]` in client `tests` modules
/// returns.
pub type TestResult = Result<(), Box<dyn Error>>;

/// Self-cleaning temporary directory for tests that drive the
/// file-path-taking entrypoints.
///
/// Uniqueness comes from PID + a monotonic counter so parallel
/// `cargo test` threads never collide. The tree is removed on
/// `Drop`; a failed removal is swallowed because a leaked temp
/// dir must not turn a passing test red.
pub struct TempDir {
    /// Absolute path to the created directory.
    path: PathBuf,
}

impl TempDir {
    /// Create a fresh, empty directory under the OS temp dir.
    ///
    /// # Errors
    /// Propagates the `create_dir_all` I/O error.
    pub fn new(tag: &str) -> std::io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("refineid-test-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// Borrow the directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write `bytes` to `name` inside the directory and return
    /// the full path to the new file.
    ///
    /// # Errors
    /// Propagates the `write` I/O error.
    pub fn write(&self, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
        let p = self.path.join(name);
        std::fs::write(&p, bytes)?;
        Ok(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best-effort cleanup: a leaked temp dir is harmless and
        // must never fail an otherwise-passing test.
        let _ignored = std::fs::remove_dir_all(&self.path);
    }
}

/// `assert_eq!`-style check that maps the failure to an
/// `Err(...)` instead of a panic.
///
/// # Errors
/// Returns an `Err` when `actual != expected`.
#[inline]
pub fn check<T: PartialEq + Debug + ?Sized>(actual: &T, expected: &T, label: &str) -> TestResult {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: expected {expected:?}, got {actual:?}").into())
    }
}

/// `assert!`-style check that maps `cond == false` to `Err`.
///
/// # Errors
/// Returns an `Err` carrying `label` when `cond` is false.
#[inline]
pub fn check_true(cond: bool, label: &str) -> TestResult {
    if cond {
        Ok(())
    } else {
        Err(format!("{label}: condition was false").into())
    }
}
