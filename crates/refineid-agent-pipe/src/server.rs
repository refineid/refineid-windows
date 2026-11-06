//! The agent's end of the pipe (Windows STPA W-R-3, W-R-15).
//!
//! One pipe instance serves one client at a time, so a second provider
//! waits in `WaitNamedPipeW` until the first is answered (W-R-6).

use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED,
    GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::IO::GetOverlappedResult;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::CreateMutexW;

use crate::identity::ProcessIdentity;
use crate::overlapped::{self, Event};
use crate::wire::{MAX_MESSAGE, SignAnswer, SignRequest};
use crate::{AGENT_MUTEX_PREFIX, PipeError, pipe_name, wide};

/// One pipe instance: clients are served one after another.
const MAX_INSTANCES: u32 = 1;
/// Kernel buffer sizes for each direction, one message's worth.
const BUFFER_BYTES: u32 = 4096;
/// How long a client's `WaitNamedPipeW` waits by default, in milliseconds.
const DEFAULT_WAIT_MS: u32 = 5_000;
/// How long a connected client has for each step: sending its request, and
/// taking the answer. It sends at once and is already waiting for the answer,
/// so one that takes longer has stalled, and every other provider waits behind
/// it until the signature deadline.
const CLIENT_STEP_DEADLINE: Duration = Duration::from_secs(5);
/// What a read for the client's close asks for. The client sends nothing more:
/// the read ends when it closes.
const CLOSE_READ_BYTES: usize = 1;

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
    step_deadline: Duration,
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
        let name = pipe_name(&identity.user.to_sddl()?, identity.session);
        Self::bind_as(&name, identity, CLIENT_STEP_DEADLINE)
    }

    /// Creates the pipe `name` for `identity`'s user alone.
    fn bind_as(
        name: &str,
        identity: ProcessIdentity,
        step_deadline: Duration,
    ) -> Result<Self, PipeError> {
        let sid = identity.user.to_sddl()?;
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
        let name = wide(name);
        // SAFETY: every pointer is valid for the call; the descriptor
        // outlives it.
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
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
        Ok(Self {
            pipe,
            identity,
            step_deadline,
        })
    }

    /// Waits for the next client and accepts it if Windows reports it as
    /// this user in this session; any other client is disconnected unread.
    ///
    /// # Errors
    /// [`PipeError::Stranger`] for a refused client, and [`PipeError`] when
    /// the pipe fails.
    pub fn accept(&mut self) -> Result<Client<'_>, PipeError> {
        self.connect()?;
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

    /// Waits, for as long as it takes, until a client connects.
    fn connect(&self) -> Result<(), PipeError> {
        let event = Event::new()?;
        let mut overlapped = event.overlapped();
        // SAFETY: the server's own pipe; `overlapped` outlives the operation,
        // which is waited for below.
        if unsafe { ConnectNamedPipe(self.pipe, &raw mut overlapped) } != 0 {
            return Ok(());
        }
        // SAFETY: no arguments.
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => Ok(()),
            ERROR_IO_PENDING => {
                let mut ignored = 0u32;
                // SAFETY: waits for the connect started above to finish.
                if unsafe {
                    GetOverlappedResult(self.pipe, &raw const overlapped, &raw mut ignored, 1)
                } == 0
                {
                    return Err(PipeError::last(PipeError::Pipe));
                }
                Ok(())
            }
            error => Err(PipeError::Pipe(error)),
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
    /// [`PipeError::TimedOut`] when the client sends none in time,
    /// [`PipeError::Wire`] when the message is refused at its border, and
    /// [`PipeError::Pipe`] when the read fails.
    pub fn request(&mut self) -> Result<SignRequest, PipeError> {
        let event = Event::new()?;
        let ends = Instant::now() + self.server.step_deadline;
        let message = overlapped::read(self.server.pipe, MAX_MESSAGE, &event, ends)?;
        Ok(SignRequest::decode(&message)?)
    }

    /// Writes the answer, waits for the client to close, and ends the
    /// connection: a disconnect before the client has read would discard the
    /// answer.
    ///
    /// # Errors
    /// [`PipeError::TimedOut`] when the client does not take the answer in
    /// time, and [`PipeError::Pipe`] when the write fails.
    pub fn answer(self, answer: &SignAnswer) -> Result<(), PipeError> {
        let event = Event::new()?;
        let ends = Instant::now() + self.server.step_deadline;
        let pipe = self.server.pipe;
        overlapped::write(pipe, &answer.encode(), &event, ends)?;
        match overlapped::read(pipe, CLOSE_READ_BYTES, &event, ends) {
            Err(PipeError::TimedOut) => Err(PipeError::TimedOut),
            Err(PipeError::Pipe(error)) if error != ERROR_BROKEN_PIPE => {
                Err(PipeError::Pipe(error))
            }
            Ok(_) | Err(_) => Ok(()),
        }
    }
}

impl Drop for Client<'_> {
    fn drop(&mut self) {
        self.server.disconnect();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::channel;

    use refineid_rapp_core::ids::PairId;
    use refineid_rapp_core::operations::{KeyProfile, SignatureAlgorithm};

    use super::*;
    use crate::client::{Pipe, open};
    use crate::wire::WireError;

    /// The step deadline of the servers in these tests.
    const STEP: Duration = Duration::from_millis(200);
    /// Past any step deadline here, well short of the signature deadline: a
    /// server still waiting this long has no deadline at all.
    const BOUND: Duration = Duration::from_secs(10);
    /// How long a test client may take to connect.
    const CONNECT: Duration = Duration::from_secs(5);
    /// What ECDSA with SHA-384 signs.
    const DIGEST: &[u8; 48] = b"synthetic digest of forty-eight bytes for tests.";
    /// A synthetic pairing.
    const PAIR: [u8; refineid_rapp::PAIR_ID_SIZE] = *b"synthetic pair 1";
    /// A synthetic signature.
    const SIGNATURE: &[u8] = b"synthetic signature";

    fn sign_request() -> SignRequest {
        SignRequest::new(
            PairId::from_array(PAIR),
            KeyProfile::EcdsaP384,
            SignatureAlgorithm::EcdsaSha384,
            DIGEST,
        )
        .expect("a digest as long as the algorithm signs")
    }

    /// A pipe of this test's own, so no test meets a running agent.
    fn test_pipe(label: &str) -> (PipeServer, Vec<u16>) {
        let name = format!(
            "{}test.{}.{label}",
            crate::PIPE_NAME_PREFIX,
            std::process::id()
        );
        let identity = ProcessIdentity::current().expect("identity");
        let server = PipeServer::bind_as(&name, identity, STEP).expect("bind");
        (server, wide(&name))
    }

    fn connect(name: &[u16]) -> Pipe {
        open(name, Instant::now() + CONNECT).expect("open")
    }

    /// Runs `serve` on its own thread, and fails the test if it outlasts
    /// [`BOUND`] rather than hanging the run.
    fn within_bound<T: Send + 'static>(serve: impl FnOnce() -> T + Send + 'static) -> T {
        let (done, result) = channel();
        std::thread::spawn(move || {
            let _receiver_gone_means_the_test_failed = done.send(serve());
        });
        result
            .recv_timeout(BOUND)
            .expect("a stalled client held the server past its deadline")
    }

    #[test]
    fn a_client_that_sends_nothing_is_ended_at_the_deadline() {
        let (mut server, name) = test_pipe("silent");
        let _silent = connect(&name);
        let refused = within_bound(move || {
            let mut client = server.accept().expect("accept");
            client.request().map(|_| ())
        });
        assert_eq!(refused, Err(PipeError::TimedOut));
    }

    #[test]
    fn a_client_that_never_takes_its_answer_is_ended_at_the_deadline() {
        let (mut server, name) = test_pipe("no-read");
        let silent = connect(&name);
        let event = Event::new().expect("event");
        let ends = Instant::now() + CONNECT;
        overlapped::write(silent.0, &sign_request().encode(), &event, ends).expect("send");
        let refused = within_bound(move || {
            let mut client = server.accept().expect("accept");
            client.request().expect("request");
            client.answer(&SignAnswer::Signature(SIGNATURE.to_vec()))
        });
        assert_eq!(refused, Err(PipeError::TimedOut));
        drop(silent);
    }

    #[test]
    fn the_next_client_is_served_after_one_stalls() {
        let (mut server, name) = test_pipe("next");
        let silent = connect(&name);
        let (stall_ended, heard) = channel();
        let serving = std::thread::spawn(move || {
            let mut stalled = server.accept().expect("accept");
            assert_eq!(stalled.request().map(|_| ()), Err(PipeError::TimedOut));
            drop(stalled);
            stall_ended.send(()).expect("test waiting");
            let mut client = server.accept().expect("accept the next");
            assert_eq!(client.request(), Ok(sign_request()));
            client
                .answer(&SignAnswer::Signature(SIGNATURE.to_vec()))
                .expect("answer");
        });
        heard.recv_timeout(BOUND).expect("the stalled client ended");
        drop(silent);
        let next = connect(&name);
        let event = Event::new().expect("event");
        let ends = Instant::now() + BOUND;
        overlapped::write(next.0, &sign_request().encode(), &event, ends).expect("send");
        let answer = overlapped::read(next.0, MAX_MESSAGE, &event, ends).expect("read");
        assert_eq!(
            SignAnswer::decode(&answer),
            Ok(SignAnswer::Signature(SIGNATURE.to_vec()))
        );
        drop(next);
        serving.join().expect("server thread");
    }

    #[test]
    fn an_oversized_request_is_refused_at_the_border() {
        let (mut server, name) = test_pipe("oversized");
        let sender = connect(&name);
        let event = Event::new().expect("event");
        let ends = Instant::now() + CONNECT;
        let oversized = vec![0u8; MAX_MESSAGE + 1];
        overlapped::write(sender.0, &oversized, &event, ends).expect("send");
        let refused = within_bound(move || {
            let mut client = server.accept().expect("accept");
            client.request().map(|_| ())
        });
        assert_eq!(refused, Err(PipeError::Wire(WireError::Oversized)));
    }
}
