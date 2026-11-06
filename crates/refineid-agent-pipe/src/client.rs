//! The key storage provider's end of the pipe (Windows STPA W-R-4, W-R-12).
//!
//! The provider sends one request and waits at most the caller's deadline
//! for the answer. It talks only to a server Windows reports as running as
//! this user in this Windows session; a pipe served by anyone else counts as
//! no agent at all. The connection asks for identification-level
//! impersonation only, so the server can learn who calls and act as no one.

use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeServerProcessId, PIPE_READMODE_MESSAGE, SetNamedPipeHandleState, WaitNamedPipeW,
};

use crate::identity::ProcessIdentity;
use crate::overlapped::{self, Event};
use crate::wire::{MAX_MESSAGE, SignAnswer, SignRequest};
use crate::{PipeError, pipe_name, wide};

/// How long a provider waits for a busy pipe instance before each retry.
const BUSY_WAIT_MS: u32 = 1_000;

/// Asks the user's agent for one signature and waits at most `deadline`.
///
/// # Errors
/// [`PipeError::NoAgent`] when no agent serves this user,
/// [`PipeError::Stranger`] when the pipe's server is not this user in this
/// session, [`PipeError::TimedOut`] when no answer comes in time, and
/// [`PipeError`] for a failed or refused exchange.
pub fn request_signature(
    request: &SignRequest,
    deadline: Duration,
) -> Result<SignAnswer, PipeError> {
    let answer = requested_signature(request, deadline);
    match &answer {
        Ok(_) => {}
        Err(PipeError::Identity(code) | PipeError::Pipe(code)) => {
            refineid_dev_errors::report!(AgentPipe, "signature request failed", status code);
        }
        Err(error) => refineid_dev_errors::report!(AgentPipe, "signature request failed", error),
    }
    answer
}

/// [`request_signature`], unreported.
fn requested_signature(request: &SignRequest, deadline: Duration) -> Result<SignAnswer, PipeError> {
    let ends = Instant::now() + deadline;
    let identity = ProcessIdentity::current()?;
    let name = wide(&pipe_name(&identity.user.to_sddl()?, identity.session));
    let pipe = open(&name, ends)?;
    let mut server_pid = 0u32;
    // SAFETY: `pipe` is open; `server_pid` receives the server's id.
    if unsafe { GetNamedPipeServerProcessId(pipe.0, &raw mut server_pid) } == 0 {
        return Err(PipeError::last(PipeError::Identity));
    }
    if !identity.same_user_and_session(&ProcessIdentity::of(server_pid)?) {
        return Err(PipeError::Stranger);
    }
    let mut mode = PIPE_READMODE_MESSAGE;
    // SAFETY: `pipe` is open; only the read mode is set.
    if unsafe {
        SetNamedPipeHandleState(
            pipe.0,
            &raw mut mode,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    } == 0
    {
        return Err(PipeError::last(PipeError::Pipe));
    }
    let event = Event::new()?;
    let message = request.encode();
    overlapped::write(pipe.0, &message, &event, ends)?;
    let answer = overlapped::read(pipe.0, MAX_MESSAGE, &event, ends)?;
    Ok(SignAnswer::decode(&answer)?)
}

/// Opens the pipe, waiting while its one instance serves another client.
pub(crate) fn open(name: &[u16], ends: Instant) -> Result<Pipe, PipeError> {
    loop {
        // SAFETY: `name` is NUL-terminated; the handle is owned by `Pipe`.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                core::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                core::ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            let pipe = Pipe(handle);
            // A pipe that opened only after the deadline is too late to use.
            return if Instant::now() < ends {
                Ok(pipe)
            } else {
                Err(PipeError::TimedOut)
            };
        }
        // SAFETY: no arguments.
        match unsafe { GetLastError() } {
            ERROR_FILE_NOT_FOUND => return Err(PipeError::NoAgent),
            ERROR_PIPE_BUSY if Instant::now() < ends => {
                // SAFETY: `name` is NUL-terminated. A failed wait is
                // answered by the next open attempt.
                unsafe { WaitNamedPipeW(name.as_ptr(), BUSY_WAIT_MS) };
            }
            ERROR_PIPE_BUSY => return Err(PipeError::TimedOut),
            error => return Err(PipeError::Pipe(error)),
        }
    }
}

/// An open client handle, closed when dropped.
pub(crate) struct Pipe(pub(crate) HANDLE);

impl Drop for Pipe {
    fn drop(&mut self) {
        // SAFETY: the handle is owned here and closed once.
        unsafe { CloseHandle(self.0) };
    }
}
