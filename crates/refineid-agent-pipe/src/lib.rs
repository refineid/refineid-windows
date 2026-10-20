//! The named pipe between the `RefineID` key storage provider and the
//! per-user agent that holds the phone's Bluetooth session (Windows STPA
//! W-R-1, W-R-3, W-R-4, W-R-15).
//!
//! The provider runs inside whichever program signs, and opens no transport
//! of its own: it sends one [`wire::SignRequest`] per signature on this pipe
//! and reads one [`wire::SignAnswer`]. The agent creates the pipe as the
//! first instance of its name, grants the current user alone, refuses remote
//! clients, and serves a client only when Windows reports it running as the
//! same user in the same logon session. The provider in turn talks only to a
//! server Windows reports the same way.
//!
//! [`wire`] is the safe message codec and builds on any host. The Windows
//! system calls, and the only `unsafe` code here, are in the
//! Windows-only modules.

#![cfg_attr(
    windows,
    allow(unsafe_code, reason = "the Windows pipe and token boundary")
)]

pub mod wire;

#[cfg(windows)]
pub mod client;
#[cfg(windows)]
pub mod identity;
#[cfg(windows)]
pub mod server;

/// The pipe name prefix; the user's SID completes it, so each user's agent
/// has its own name.
pub const PIPE_NAME_PREFIX: &str = r"\\.\pipe\RefineID.Agent.";

/// The name of the session-local mutex only one agent per user holds
/// (W-R-15).
pub const AGENT_MUTEX_NAME: &str = r"Local\RefineID.Agent";

/// The pipe name of the user whose SID is `user_sid`.
#[must_use]
pub fn pipe_name(user_sid: &str) -> String {
    format!("{PIPE_NAME_PREFIX}{user_sid}")
}

/// Why the pipe could not be used. A Windows error carries its code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeError {
    /// Windows could not report a process's identity.
    Identity(u32),
    /// The pipe could not be created, opened or served.
    Pipe(u32),
    /// No agent serves this user.
    NoAgent,
    /// Another agent already serves this user (W-R-15).
    AgentRunning,
    /// The process at the other end runs as another user or in another
    /// session.
    Stranger,
    /// The other end did not answer in time.
    TimedOut,
    /// A message was refused at the border.
    Wire(wire::WireError),
}

impl PipeError {
    /// `make` applied to the calling thread's last Windows error.
    #[cfg(windows)]
    pub(crate) fn last(make: fn(u32) -> Self) -> Self {
        // SAFETY: no arguments; reads the thread's last error.
        make(unsafe { windows_sys::Win32::Foundation::GetLastError() })
    }
}

impl core::fmt::Display for PipeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Identity(code) => write!(formatter, "process identity unreadable (error {code})"),
            Self::Pipe(code) => write!(formatter, "agent pipe failed (error {code})"),
            Self::NoAgent => write!(formatter, "the RefineID agent is not running"),
            Self::AgentRunning => write!(formatter, "another RefineID agent serves this user"),
            Self::Stranger => write!(
                formatter,
                "the other end of the pipe runs as another user or session"
            ),
            Self::TimedOut => write!(formatter, "the agent did not answer in time"),
            Self::Wire(error) => write!(formatter, "{error}"),
        }
    }
}

impl core::error::Error for PipeError {}

/// `text` as a NUL-terminated UTF-16 string for a Windows call.
#[cfg(windows)]
pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

impl From<wire::WireError> for PipeError {
    fn from(error: wire::WireError) -> Self {
        Self::Wire(error)
    }
}
