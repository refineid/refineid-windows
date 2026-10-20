//! The agent's end of the pipe (Windows STPA W-R-3, W-R-15).
//!
//! One pipe instance serves one client at a time, so a second provider
//! waits in `WaitNamedPipeW` until the first is answered (W-R-6).

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_MORE_DATA, ERROR_PIPE_CONNECTED, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FlushFileBuffers, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::CreateMutexW;

use crate::identity::ProcessIdentity;
use crate::wire::{MAX_MESSAGE, SignAnswer, SignRequest};
use crate::{AGENT_MUTEX_PREFIX, PipeError, pipe_name, wide};

/// One pipe instance: clients are served one after another.
const MAX_INSTANCES: u32 = 1;
/// Kernel buffer sizes for each direction, one message's worth.
const BUFFER_BYTES: u32 = 4096;
/// How long a client's `WaitNamedPipeW` waits by default, in milliseconds.
const DEFAULT_WAIT_MS: u32 = 5_000;

/// Proof that this process is the user's only agent (W-R-15). Released
/// when dropped.
#[derive(Debug)]
pub struct AgentLock(HANDLE);

impl AgentLock {
    /// Takes this user's session-local agent mutex.
    ///
    /// # Errors
    /// [`PipeError::AgentRunning`] when another agent holds it.
    pub fn acquire() -> Result<Self, PipeError> {
        let sid = ProcessIdentity::current()?.user.to_sddl()?;
        let name = wide(&format!("{AGENT_MUTEX_PREFIX}{sid}"));
        // SAFETY: a named mutex with default security and initial ownership.
        let handle = unsafe { CreateMutexW(core::ptr::null(), 1, name.as_ptr()) };
        // SAFETY: no arguments; read right after the call it describes.
        let error = unsafe { GetLastError() };
        if handle.is_null() {
            return Err(PipeError::Pipe(error));
        }
        if error == ERROR_ALREADY_EXISTS {
            // SAFETY: the handle was just opened here and is closed once.
            unsafe { CloseHandle(handle) };
            return Err(PipeError::AgentRunning);
        }
        Ok(Self(handle))
    }
}

impl Drop for AgentLock {
    fn drop(&mut self) {
        // SAFETY: the handle is owned here and closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// The agent's pipe, granted to the current user alone.
#[derive(Debug)]
pub struct PipeServer {
    pipe: HANDLE,
    identity: ProcessIdentity,
}

// SAFETY: the pipe handle is a kernel handle usable from any thread, and
// the server is used by one thread at a time through `&mut self`.
unsafe impl Send for PipeServer {}

/// A client the server accepted: Windows reports it as the agent's user in
/// the agent's session.
#[derive(Debug)]
pub struct Client<'a> {
    server: &'a mut PipeServer,
    identity: ProcessIdentity,
}

impl PipeServer {
    /// Creates the user's pipe. It must be the first instance of its name,
    /// so a pipe someone else created first is never served.
    ///
    /// # Errors
    /// [`PipeError`] when the identity, security descriptor or pipe cannot
    /// be made.
    pub fn bind(_lock: &AgentLock) -> Result<Self, PipeError> {
        let identity = ProcessIdentity::current()?;
        let sid = identity.user.to_sddl()?;
        let session = identity.session;
        // Protected DACL: generic all for the user, nothing inherited, and
        // nobody else.
        let sddl = wide(&format!("D:P(A;;GA;;;{sid})"));
        let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated; the descriptor is LocalAlloc'd
        // and freed below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                core::ptr::null_mut(),
            )
        } == 0
        {
            return Err(PipeError::last(PipeError::Pipe));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| PipeError::Pipe(0))?,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let name = wide(&pipe_name(&sid, session));
        // SAFETY: every pointer is valid for the call; the descriptor
        // outlives it.
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                MAX_INSTANCES,
                BUFFER_BYTES,
                BUFFER_BYTES,
                DEFAULT_WAIT_MS,
                &raw const attributes,
            )
        };
        let error = PipeError::last(PipeError::Pipe);
        // SAFETY: the descriptor came from the conversion above.
        unsafe { LocalFree(descriptor) };
        if pipe == INVALID_HANDLE_VALUE {
            return Err(error);
        }
        Ok(Self { pipe, identity })
    }

    /// Waits for the next client and accepts it if Windows reports it as
    /// this user in this session; any other client is disconnected unread.
    ///
    /// # Errors
    /// [`PipeError::Stranger`] for a refused client, and [`PipeError`] when
    /// the pipe fails.
    pub fn accept(&mut self) -> Result<Client<'_>, PipeError> {
        // SAFETY: a synchronous connect on the server's own pipe.
        if unsafe { ConnectNamedPipe(self.pipe, core::ptr::null_mut()) } == 0 {
            // SAFETY: no arguments.
            let error = unsafe { GetLastError() };
            if error != ERROR_PIPE_CONNECTED {
                return Err(PipeError::Pipe(error));
            }
        }
        let mut pid = 0u32;
        // SAFETY: the pipe is connected; `pid` receives the client's id.
        let known = unsafe { GetNamedPipeClientProcessId(self.pipe, &raw mut pid) } != 0;
        let identity = if known {
            ProcessIdentity::of(pid)
        } else {
            Err(PipeError::last(PipeError::Identity))
        };
        match identity {
            Ok(identity) if self.identity.same_user_and_session(&identity) => Ok(Client {
                server: self,
                identity,
            }),
            Ok(_) => {
                self.disconnect();
                Err(PipeError::Stranger)
            }
            Err(error) => {
                self.disconnect();
                Err(error)
            }
        }
    }

    fn disconnect(&self) {
        // SAFETY: the server's own pipe; a failure leaves it for the next
        // connect to report.
        unsafe { DisconnectNamedPipe(self.pipe) };
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        // SAFETY: the handle is owned here and closed once.
        unsafe { CloseHandle(self.pipe) };
    }
}

impl Client<'_> {
    /// What Windows reports about the client.
    #[must_use]
    pub const fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// Reads the client's one request.
    ///
    /// # Errors
    /// [`PipeError::Wire`] when the message is refused at its border, and
    /// [`PipeError::Pipe`] when the read fails.
    pub fn request(&mut self) -> Result<SignRequest, PipeError> {
        let mut buffer = vec![0u8; MAX_MESSAGE];
        let mut read = 0u32;
        let capacity = u32::try_from(buffer.len()).map_err(|_| PipeError::Pipe(0))?;
        // SAFETY: `buffer` holds `capacity` bytes for a synchronous read.
        if unsafe {
            ReadFile(
                self.server.pipe,
                buffer.as_mut_ptr(),
                capacity,
                &raw mut read,
                core::ptr::null_mut(),
            )
        } == 0
        {
            // SAFETY: no arguments.
            let error = unsafe { GetLastError() };
            return Err(if error == ERROR_MORE_DATA {
                PipeError::Wire(crate::wire::WireError::Oversized)
            } else {
                PipeError::Pipe(error)
            });
        }
        buffer.truncate(read as usize);
        Ok(SignRequest::decode(&buffer)?)
    }

    /// Writes the answer and ends the client's connection.
    ///
    /// # Errors
    /// [`PipeError::Pipe`] when the write fails.
    pub fn answer(self, answer: &SignAnswer) -> Result<(), PipeError> {
        let bytes = answer.encode();
        let mut written = 0u32;
        let length = u32::try_from(bytes.len()).map_err(|_| PipeError::Pipe(0))?;
        // SAFETY: `bytes` holds `length` bytes for a synchronous write.
        let wrote = unsafe {
            WriteFile(
                self.server.pipe,
                bytes.as_ptr(),
                length,
                &raw mut written,
                core::ptr::null_mut(),
            )
        } != 0;
        if !wrote {
            return Err(PipeError::last(PipeError::Pipe));
        }
        // SAFETY: waits until the client has read the answer.
        if unsafe { FlushFileBuffers(self.server.pipe) } == 0 {
            return Err(PipeError::last(PipeError::Pipe));
        }
        Ok(())
    }
}

impl Drop for Client<'_> {
    fn drop(&mut self) {
        self.server.disconnect();
    }
}
