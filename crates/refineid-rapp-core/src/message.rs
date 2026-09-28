//! Typed RAPP wire messages re-exported from `refineid_rapp`.

pub use refineid_rapp::CloseReason;
pub use refineid_rapp::ResultStatus;
pub use refineid_rapp::{
    CancelMessage, LivenessMessage, MessageError, NegotiatedParameters, PairingAbortMessage,
    PairingConfirmMessage, PairingHelloMessage, ProtocolErrorMessage, SessionCloseMessage,
    SessionParameters, SessionReadyMessage, StatusReport, TypedMessage,
};
pub use refineid_rapp::{Envelope, MessageType, SequenceGuard, WireError, WireValue};

/// Error status string when peer is busy.
pub const ERROR_BUSY: &str = "busy";
/// Error status string when requested operation is unknown.
pub const ERROR_UNKNOWN_OPERATION: &str = "unknown_operation";
