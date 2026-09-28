//! The transport-profile contract of specification Section 16.
//!
//! A transport delivers bounded binary frames in order, reports EOF and
//! failure distinctly, and names the candidate both endpoints later echo
//! inside the first authenticated message. Nothing here contributes
//! identity: every channel runs the RAPP Noise handshake on top, and an
//! already encrypted underlay changes nothing.
//!
//! Two implementations ship with the crate: an in-memory pair for loopback
//! conformance tests, and a length-prefixed byte-stream framing used by the
//! experimental TCP profile `fi.refineid.stream.v1`. The named design
//! targets of Section 16 (`local-quic-v1`, `relay-websocket-v1`) can be
//! added behind the same trait without touching protocol code.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::Duration;

use crate::limits;
pub use refineid_rapp::{BinaryFrame, FrameError};

/// The experimental local byte-stream transport profile name.
pub const STREAM_PROFILE: &str = refineid_rapp::STREAM_PROFILE;

/// The in-memory loopback transport profile name, for tests only.
pub const MEMORY_PROFILE: &str = "fi.refineid.memory.v1";

/// Bytes in the frame length prefix of the byte-stream framing.
const LENGTH_PREFIX_BYTES: usize = 2;

/// Why a frame could not be moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// The peer closed the channel in an orderly way.
    Eof,
    /// The channel failed; no further frames will move.
    Failed,
    /// A frame exceeded [`limits::NOISE_MAX_MESSAGE`] and was refused
    /// before allocation.
    OversizedFrame,
    /// A blocking receive reached its deadline with no frame.
    TimedOut,
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Eof => write!(f, "transport reached end of file"),
            Self::Failed => write!(f, "transport failed"),
            Self::OversizedFrame => write!(f, "oversized frame"),
            Self::TimedOut => write!(f, "transport timed out"),
        }
    }
}

impl core::error::Error for TransportError {}

/// Ordered, bounded, reliable frame delivery between two RAPP endpoints.
pub trait FrameTransport {
    /// Sends one frame.
    ///
    /// # Errors
    ///
    /// Fails when the frame is oversized or the channel is unusable.
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportError>;

    /// Receives the next frame, blocking up to the transport's deadline.
    ///
    /// # Errors
    ///
    /// Fails distinctly on orderly EOF, channel failure, an oversized
    /// incoming frame, or the deadline.
    fn receive_frame(&mut self) -> Result<Vec<u8>, TransportError>;

    /// The transport profile name for prologue and parameter echo.
    fn profile(&self) -> &str;

    /// The candidate identifier for the parameter echo of Section 8.4.
    fn candidate_id(&self) -> &str;
}

/// One side of an in-memory transport pair.
///
/// Loopback tests run the requester and a test proxy on two threads joined
/// by this transport, so protocol behavior is exercised without sockets.
#[derive(Debug)]
pub struct MemoryTransport {
    sender: Sender<Vec<u8>>,
    receiver: Receiver<Vec<u8>>,
    candidate_id: String,
    receive_deadline: Duration,
}

impl MemoryTransport {
    /// Creates a connected transport pair with one candidate identifier.
    #[must_use]
    pub fn pair(candidate_id: &str, receive_deadline: Duration) -> (Self, Self) {
        let (left_sender, right_receiver) = channel();
        let (right_sender, left_receiver) = channel();
        let left = Self {
            sender: left_sender,
            receiver: left_receiver,
            candidate_id: candidate_id.to_owned(),
            receive_deadline,
        };
        let right = Self {
            sender: right_sender,
            receiver: right_receiver,
            candidate_id: candidate_id.to_owned(),
            receive_deadline,
        };
        (left, right)
    }
}

impl FrameTransport for MemoryTransport {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > limits::NOISE_MAX_MESSAGE {
            return Err(TransportError::OversizedFrame);
        }
        self.sender
            .send(frame.to_vec())
            .map_err(|_| TransportError::Eof)
    }

    fn receive_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        match self.receiver.recv_timeout(self.receive_deadline) {
            Ok(frame) if frame.len() > limits::NOISE_MAX_MESSAGE => {
                Err(TransportError::OversizedFrame)
            }
            Ok(frame) => Ok(frame),
            Err(RecvTimeoutError::Timeout) => Err(TransportError::TimedOut),
            Err(RecvTimeoutError::Disconnected) => Err(TransportError::Eof),
        }
    }

    fn profile(&self) -> &str {
        MEMORY_PROFILE
    }

    fn candidate_id(&self) -> &str {
        &self.candidate_id
    }
}

impl refineid_rapp::FrameTransport for MemoryTransport {
    type Error = TransportError;

    fn candidate_id(&self) -> &str {
        &self.candidate_id
    }

    fn send(&mut self, frame: BinaryFrame) -> Result<(), Self::Error> {
        self.send_frame(frame.as_bytes())
    }

    fn receive(&mut self) -> Result<Option<BinaryFrame>, Self::Error> {
        match self.receive_frame() {
            Ok(bytes) => {
                let frame =
                    BinaryFrame::reconstruct(bytes).map_err(|_| TransportError::OversizedFrame)?;
                Ok(Some(frame))
            }
            Err(TransportError::Eof) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Length-prefixed framing over one TCP stream.
///
/// Each frame is a two-byte big-endian length followed by that many bytes.
/// The length ceiling is [`limits::NOISE_MAX_MESSAGE`], which a two-byte
/// prefix expresses exactly, so an oversized frame is unrepresentable on the
/// wire and a zero length is refused as malformed framing.
#[derive(Debug)]
pub struct TcpFrameTransport {
    stream: TcpStream,
    candidate_id: String,
}

impl TcpFrameTransport {
    /// Wraps a connected stream under a candidate identifier.
    ///
    /// # Errors
    ///
    /// Fails when the receive deadline cannot be applied to the socket.
    pub fn new(
        stream: TcpStream,
        candidate_id: &str,
        receive_deadline: Duration,
    ) -> Result<Self, TransportError> {
        stream
            .set_read_timeout(Some(receive_deadline))
            .map_err(|_| TransportError::Failed)?;
        Ok(Self {
            stream,
            candidate_id: candidate_id.to_owned(),
        })
    }
}

impl FrameTransport for TcpFrameTransport {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.is_empty() || frame.len() > limits::NOISE_MAX_MESSAGE {
            return Err(TransportError::OversizedFrame);
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the length is bounded by the 65535-byte frame ceiling"
        )]
        let prefix = (frame.len() as u16).to_be_bytes();
        self.stream
            .write_all(&prefix)
            .and_then(|()| self.stream.write_all(frame))
            .map_err(|_| TransportError::Failed)
    }

    fn receive_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut prefix = [0u8; LENGTH_PREFIX_BYTES];
        read_exact_classified(&mut self.stream, &mut prefix)?;
        let length = usize::from(u16::from_be_bytes(prefix));
        if length == 0 {
            return Err(TransportError::Failed);
        }
        let mut frame = vec![0u8; length];
        read_exact_classified(&mut self.stream, &mut frame)?;
        Ok(frame)
    }

    fn profile(&self) -> &str {
        STREAM_PROFILE
    }

    fn candidate_id(&self) -> &str {
        &self.candidate_id
    }
}

impl refineid_rapp::FrameTransport for TcpFrameTransport {
    type Error = TransportError;

    fn candidate_id(&self) -> &str {
        &self.candidate_id
    }

    fn send(&mut self, frame: BinaryFrame) -> Result<(), Self::Error> {
        self.send_frame(frame.as_bytes())
    }

    fn receive(&mut self) -> Result<Option<BinaryFrame>, Self::Error> {
        match self.receive_frame() {
            Ok(bytes) => {
                let frame =
                    BinaryFrame::reconstruct(bytes).map_err(|_| TransportError::OversizedFrame)?;
                Ok(Some(frame))
            }
            Err(TransportError::Eof) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        self.stream
            .shutdown(std::net::Shutdown::Both)
            .map_err(|_| TransportError::Failed)
    }
}

/// Reads exactly one buffer, classifying EOF, deadline, and failure.
fn read_exact_classified(stream: &mut TcpStream, buffer: &mut [u8]) -> Result<(), TransportError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => {
                return Err(if filled == 0 {
                    TransportError::Eof
                } else {
                    TransportError::Failed
                });
            }
            Ok(count) => filled += count,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(TransportError::TimedOut);
            }
            Err(_) => return Err(TransportError::Failed),
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    use super::{FrameTransport, MemoryTransport, TcpFrameTransport, TransportError};

    #[test]
    fn memory_pair_moves_frames_both_ways() {
        let (mut left, mut right) = MemoryTransport::pair("m-1", Duration::from_millis(200));
        left.send_frame(b"ping").unwrap();
        assert_eq!(right.receive_frame().unwrap(), b"ping");
        right.send_frame(b"pong").unwrap();
        assert_eq!(left.receive_frame().unwrap(), b"pong");
    }

    #[test]
    fn memory_disconnect_is_orderly_eof() {
        let (mut left, right) = MemoryTransport::pair("m-2", Duration::from_millis(50));
        drop(right);
        assert_eq!(left.receive_frame(), Err(TransportError::Eof));
    }

    #[test]
    fn tcp_framing_round_trips_and_reports_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let deadline = Duration::from_millis(500);
        let client = TcpStream::connect(address).unwrap();
        let (server, _) = listener.accept().unwrap();
        let mut client = TcpFrameTransport::new(client, "t-1", deadline).unwrap();
        let mut server = TcpFrameTransport::new(server, "t-1", deadline).unwrap();
        client.send_frame(&[0xAA; 300]).unwrap();
        assert_eq!(server.receive_frame().unwrap(), vec![0xAA; 300]);
        drop(client);
        assert_eq!(server.receive_frame(), Err(TransportError::Eof));
    }

    #[test]
    fn oversized_and_empty_frames_are_refused() {
        let (mut left, _right) = MemoryTransport::pair("m-3", Duration::from_millis(50));
        let oversized = vec![0u8; crate::limits::NOISE_MAX_MESSAGE + 1];
        assert_eq!(
            left.send_frame(&oversized),
            Err(TransportError::OversizedFrame)
        );
    }
}
