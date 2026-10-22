//! The key storage provider's end of the pipe (Windows STPA W-R-4, W-R-12).
//!
//! The provider sends one request and waits at most the caller's deadline
//! for the answer. It talks only to a server Windows reports as running as
//! this user in this Windows session; a pipe served by anyone else counts as
//! no agent at all. The connection asks for identification-level
//! impersonation only, so the server can learn who calls and act as no one.

use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_PIPE_BUSY,
    GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, ReadFile, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeServerProcessId, PIPE_READMODE_MESSAGE, SetNamedPipeHandleState, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use crate::identity::ProcessIdentity;
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
    pipe.write(&message, &event, ends)?;
    let answer = pipe.read(&event, ends)?;
    Ok(SignAnswer::decode(&answer)?)
}

/// Opens the pipe, waiting while its one instance serves another client.
fn open(name: &[u16], ends: Instant) -> Result<Pipe, PipeError> {
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
struct Pipe(HANDLE);

impl Drop for Pipe {
    fn drop(&mut self) {
        // SAFETY: the handle is owned here and closed once.
        unsafe { CloseHandle(self.0) };
    }
}

impl Pipe {
    fn write(&self, bytes: &[u8], event: &Event, ends: Instant) -> Result<(), PipeError> {
        let length = u32::try_from(bytes.len()).map_err(|_| PipeError::Pipe(0))?;
        let mut overlapped = event.overlapped();
        // SAFETY: `bytes` and `overlapped` outlive the operation, which
        // `complete` waits for or cancels before returning.
        let started = unsafe {
            WriteFile(
                self.0,
                bytes.as_ptr(),
                length,
                core::ptr::null_mut(),
                &raw mut overlapped,
            )
        } != 0;
        self.complete(started, &mut overlapped, event, ends)?;
        Ok(())
    }

    fn read(&self, event: &Event, ends: Instant) -> Result<Vec<u8>, PipeError> {
        let mut buffer = vec![0u8; MAX_MESSAGE];
        let capacity = u32::try_from(buffer.len()).map_err(|_| PipeError::Pipe(0))?;
        let mut overlapped = event.overlapped();
        // SAFETY: `buffer` and `overlapped` outlive the operation, which
        // `complete` waits for or cancels before returning.
        let started = unsafe {
            ReadFile(
                self.0,
                buffer.as_mut_ptr(),
                capacity,
                core::ptr::null_mut(),
                &raw mut overlapped,
            )
        } != 0;
        let read = self.complete(started, &mut overlapped, event, ends)?;
        buffer.truncate(read as usize);
        Ok(buffer)
    }

    /// Waits for an overlapped operation until `ends`, cancelling it when
    /// the time runs out, and returns the bytes it moved.
    fn complete(
        &self,
        started: bool,
        overlapped: &mut OVERLAPPED,
        event: &Event,
        ends: Instant,
    ) -> Result<u32, PipeError> {
        if !started {
            // SAFETY: no arguments.
            let error = unsafe { GetLastError() };
            if error == ERROR_MORE_DATA {
                return Err(PipeError::Wire(crate::wire::WireError::Oversized));
            }
            if error != ERROR_IO_PENDING {
                return Err(PipeError::Pipe(error));
            }
        }
        let remaining = ends.saturating_duration_since(Instant::now());
        let wait = u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: the event belongs to this operation.
        if unsafe { WaitForSingleObject(event.0, wait) } != WAIT_OBJECT_0 {
            // SAFETY: cancels this handle's operation; the wait below
            // returns once it has stopped using the buffers.
            unsafe { CancelIoEx(self.0, overlapped) };
            let mut ignored = 0u32;
            // SAFETY: waits for the cancelled operation to finish.
            unsafe { GetOverlappedResult(self.0, overlapped, &raw mut ignored, 1) };
            return Err(PipeError::TimedOut);
        }
        let mut moved = 0u32;
        // SAFETY: the operation completed; this reads its result.
        if unsafe { GetOverlappedResult(self.0, overlapped, &raw mut moved, 0) } == 0 {
            // SAFETY: no arguments.
            let error = unsafe { GetLastError() };
            return Err(if error == ERROR_MORE_DATA {
                PipeError::Wire(crate::wire::WireError::Oversized)
            } else {
                PipeError::Pipe(error)
            });
        }
        Ok(moved)
    }
}

/// A manual-reset event for one overlapped operation at a time.
struct Event(HANDLE);

impl Event {
    fn new() -> Result<Self, PipeError> {
        // SAFETY: an unnamed manual-reset event, initially clear.
        let handle = unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
        if handle.is_null() {
            return Err(PipeError::last(PipeError::Pipe));
        }
        Ok(Self(handle))
    }

    const fn overlapped(&self) -> OVERLAPPED {
        // SAFETY: an all-zero OVERLAPPED is its documented initial state.
        let mut overlapped: OVERLAPPED = unsafe { core::mem::zeroed() };
        overlapped.hEvent = self.0;
        overlapped
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: the handle is owned here and closed once.
        unsafe { CloseHandle(self.0) };
    }
}
