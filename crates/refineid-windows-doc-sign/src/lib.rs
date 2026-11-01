// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Document signing and verification on Windows over `refineid_doc_sign`.
//!
//! The Windows side of the shared signing service: [`http`] registers
//! `WinHTTP` as core's transport, [`phone`] carries core's phone signing
//! over this computer's RAPP requester, [`sign`] signs one document with
//! the card in a local reader or, when no reader holds a card, on the
//! paired phone, and [`verify`] judges a signed document and renders the
//! verdict. The Win32 companion and the settings bridge of the `WinUI`
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

pub mod http;
pub mod phone;
pub mod sign;
pub mod verify;
