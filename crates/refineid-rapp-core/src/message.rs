//! Typed RAPP wire messages re-exported from `refineid_rapp`.

pub use refineid_rapp::CloseReason;
pub use refineid_rapp::ResultStatus;
pub use refineid_rapp::{
    CancelMessage, LivenessMessage, MessageError, NegotiatedParameters, PairingAbortMessage,
    PairingConfirmMessage, PairingHelloMessage, ProtocolErrorMessage, SessionCloseMessage,
    SessionParameters, SessionReadyMessage, StatusReport, TypedMessage,
};
pub use refineid_rapp::{Envelope, MessageType, SequenceGuard, WireError, WireValue};
