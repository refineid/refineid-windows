// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Document signing for the Windows companion: ASiC-E and `PAdES` over
//! the FINEID card.
//!
//! Adapted from the `sign` modules of the sibling `refineid-unix`
//! workspace (`refineid-lib-core/src/sign/`, Apache-2.0, same
//! copyright holder). The modules are vendored here because the
//! Windows port of `refineid-lib-core` does not carry them; path
//! roots were rewritten (`crate::` to `refineid_lib_core::`,
//! `crate::sign::` to `crate::`) and nothing else.
// The WinHTTP fetch path calls the WinHTTP C API over raw
// `HINTERNET` handles; the non-windows stub is safe-only.
// `expect` (not `allow`) keeps the exception visible and makes a
// vanished exception noisy.
#![cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "the WinHTTP fetch path calls the WinHTTP C API over raw HINTERNET handles"
    )
)]
#![deny(unsafe_op_in_unsafe_fn)]
pub mod asic;
pub mod asic_verify;
pub mod base64;
pub mod ber;
pub mod cades;
pub mod cms;
pub mod container;
pub mod digest;
pub mod document;
pub mod ecdsa;
pub mod email;
pub mod hexcodec;
pub mod http;
pub mod material;
pub mod oids;
pub mod pades;
pub mod rsa;
pub mod service;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
pub(crate) mod test_util;
pub mod text;
pub mod timestamp;
pub mod trust;
pub mod validation;
pub mod verify;
pub mod xades;
