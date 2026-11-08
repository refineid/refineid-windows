// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Document signing and verification on Windows over `refineid_doc_sign`.
//!
//! The Windows side of the shared signing service: [`http`] registers
//! `WinHTTP` as core's transport, [`phone`] carries core's phone signing
//! over this computer's RAPP requester, [`sign`] signs one document with
//! the card in a local reader or, when no reader holds a card, on the
//! paired phone, and [`verify`] judges a signed document and renders the
//! verdict. [`trusted_lists`] and [`signer_anchors`] bring the anchors,
//! every one of them from the EU lists at runtime or from a card; none
//! ships here. The Win32 companion and the settings bridge of the `WinUI`
//! app both call in here.

// The WinHTTP fetch path calls the WinHTTP C API over raw `HINTERNET`
// handles; the non-windows stub is safe-only. `expect` (not `allow`)
// keeps the exception visible and makes a vanished exception noisy.
#![cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "the WinHTTP fetch path calls the WinHTTP C API over raw HINTERNET handles"
    )
)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod ca_certificates;
pub mod http;
pub mod phone;
pub mod sign;
pub mod signer_anchors;
pub mod trusted_lists;
pub mod verify;

#[cfg(test)]
mod test_util {
    //! Test helpers shared by the crate's test modules.

    use core::error::Error;
    use core::fmt::Debug;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::path::{Path, PathBuf};

    /// The result of a test.
    pub type TestResult = Result<(), Box<dyn Error>>;

    /// A temporary directory removed on drop.
    pub struct TempDir {
        /// The directory.
        path: PathBuf,
    }

    impl TempDir {
        /// A fresh directory under the system's; `tag` names it.
        pub fn new(tag: &str) -> std::io::Result<Self> {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "refineid-test-{tag}-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        /// The directory.
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Write `bytes` to the file `name` in the directory.
        pub fn write(&self, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
            let path = self.path.join(name);
            std::fs::write(&path, bytes)?;
            Ok(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _removed = std::fs::remove_dir_all(&self.path);
        }
    }

    /// `actual` is `expected`.
    pub fn check<T: PartialEq + Debug + ?Sized>(
        actual: &T,
        expected: &T,
        label: &str,
    ) -> TestResult {
        if actual == expected {
            Ok(())
        } else {
            Err(format!("{label}: expected {expected:?}, got {actual:?}").into())
        }
    }

    /// `condition` holds.
    pub fn check_true(condition: bool, label: &str) -> TestResult {
        if condition {
            Ok(())
        } else {
            Err(format!("{label}: condition was false").into())
        }
    }
}
