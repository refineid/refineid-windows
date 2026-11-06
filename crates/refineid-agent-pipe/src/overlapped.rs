//! Pipe reads and writes with a deadline, used by both ends of the pipe.

use std::time::Instant;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, ERROR_MORE_DATA, GetLastError, HANDLE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use crate::PipeError;
use crate::wire::WireError;

/// Writes `bytes` to `pipe`, waiting until `ends`.
pub fn write(pipe: HANDLE, bytes: &[u8], event: &Event, ends: Instant) -> Result<(), PipeError> {
    let length = u32::try_from(bytes.len()).map_err(|_| PipeError::Pipe(0))?;
    let mut overlapped = event.overlapped();
    // SAFETY: `bytes` and `overlapped` outlive the operation, which
    // `complete` waits for or cancels before returning.
    let started = unsafe {
        WriteFile(
            pipe,
            bytes.as_ptr(),
            length,
            core::ptr::null_mut(),
            &raw mut overlapped,
        )
    } != 0;
    complete(pipe, started, &mut overlapped, event, ends)?;
    Ok(())
}

/// Reads one message of at most `capacity` bytes from `pipe`, waiting until
/// `ends`.
pub fn read(
    pipe: HANDLE,
    capacity: usize,
    event: &Event,
    ends: Instant,
) -> Result<Vec<u8>, PipeError> {
    let mut buffer = vec![0u8; capacity];
    let length = u32::try_from(buffer.len()).map_err(|_| PipeError::Pipe(0))?;
    let mut overlapped = event.overlapped();
    // SAFETY: `buffer` and `overlapped` outlive the operation, which
    // `complete` waits for or cancels before returning.
    let started = unsafe {
        ReadFile(
            pipe,
            buffer.as_mut_ptr(),
            length,
            core::ptr::null_mut(),
            &raw mut overlapped,
        )
    } != 0;
    let read = complete(pipe, started, &mut overlapped, event, ends)?;
    buffer.truncate(read as usize);
    Ok(buffer)
}

/// Waits for an overlapped operation until `ends`, cancelling it when the
/// time runs out, and returns the bytes it moved.
fn complete(
    pipe: HANDLE,
    started: bool,
    overlapped: &mut OVERLAPPED,
    event: &Event,
    ends: Instant,
) -> Result<u32, PipeError> {
    if !started {
        // SAFETY: no arguments.
        let error = unsafe { GetLastError() };
        if error == ERROR_MORE_DATA {
            return Err(PipeError::Wire(WireError::Oversized));
        }
        if error != ERROR_IO_PENDING {
            return Err(PipeError::Pipe(error));
        }
    }
    let remaining = ends.saturating_duration_since(Instant::now());
    let wait = u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: the event belongs to this operation.
    if unsafe { WaitForSingleObject(event.0, wait) } != WAIT_OBJECT_0 {
        // SAFETY: cancels this handle's operation; the wait below returns
        // once it has stopped using the buffers.
        unsafe { CancelIoEx(pipe, overlapped) };
        let mut ignored = 0u32;
        // SAFETY: waits for the cancelled operation to finish.
        unsafe { GetOverlappedResult(pipe, overlapped, &raw mut ignored, 1) };
        return Err(PipeError::TimedOut);
    }
    let mut moved = 0u32;
    // SAFETY: the operation completed; this reads its result.
    if unsafe { GetOverlappedResult(pipe, overlapped, &raw mut moved, 0) } == 0 {
        // SAFETY: no arguments.
        let error = unsafe { GetLastError() };
        return Err(if error == ERROR_MORE_DATA {
            PipeError::Wire(WireError::Oversized)
        } else {
            PipeError::Pipe(error)
        });
    }
    Ok(moved)
}

/// A manual-reset event for one overlapped operation at a time.
pub struct Event(pub HANDLE);

impl Event {
    pub fn new() -> Result<Self, PipeError> {
        // SAFETY: an unnamed manual-reset event, initially clear.
        let handle = unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
        if handle.is_null() {
            return Err(PipeError::last(PipeError::Pipe));
        }
        Ok(Self(handle))
    }

    pub const fn overlapped(&self) -> OVERLAPPED {
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
