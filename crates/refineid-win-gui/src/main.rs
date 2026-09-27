// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Native Win32 companion: card status, identity, PIN, documents, remote.
//!
//! Windows-target-only: the UI is Win32 FFI end to end, and the
//! `windows` crate's Win32 feature set does not compile for
//! non-Windows hosts. Off Windows this crate builds a stub that
//! exits with a message, so workspace-wide host commands
//! (`check`, `clippy`, `fmt`) stay green everywhere.
#![windows_subsystem = "windows"]
// Unsafe Windows calls stay inside explicit blocks, matching the
// refineid-minidriver house rule.
#![deny(unsafe_op_in_unsafe_fn)]
// The message loop, GDI painting, and dialog controls are raw-handle
// Win32 FFI by construction. `expect` (not `allow`) keeps the
// exception visible and makes a vanished exception noisy.
#![cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "Win32 message loop, GDI painting, and dialog controls are raw-handle FFI by construction"
    )
)]

#[cfg(windows)]
#[path = "win_main.rs"]
pub(crate) mod win_main;

#[cfg(any(windows, test))]
mod version;

#[cfg(windows)]
mod card;
#[cfg(windows)]
mod identity;
#[cfg(windows)]
mod pin;

#[cfg(windows)]
fn main() {
    win_main::run();
}

/// Non-Windows stub: the GUI is Win32-only.
#[cfg(not(windows))]
fn main() {
    eprintln!("refineid-win-gui runs on Windows only.");
    std::process::exit(2);
}
