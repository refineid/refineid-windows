//! The common envelope and message bodies of specification Sections 7.3,
//! 9.4, 10, 11, 12, and 15.
//!
//! Every post-handshake plaintext is one deterministic-CBOR `rapp-message`
//! envelope. Decoding is schema-strict: an unknown message type, a missing
//! or extra body field, a wrong field type, or an unknown field named in
//! `critical` is reported as a schema violation, which the session layer
//! classifies as an authenticated protocol violation (policy class 4).
//! Unknown non-critical extensions are carried but ignored.

use crate::cbor::Value;
use crate::ids::{
    CHALLENGE_LENGTH, Challenge, OPERATION_ID_LENGTH, OperationId, SESSION_ID_LENGTH, SessionId,
};

/// Envelope key of the wire version.
const KEY_VERSION: &str = "version";
/// Envelope key of the message type.
const KEY_TYPE: &str = "type";
/// Envelope key of the channel session identifier.
const KEY_SESSION_ID: &str = "session_id";
/// Envelope key of the per-direction sequence number.
const KEY_SEQUENCE: &str = "sequence";
/// Envelope key of the body map.
const KEY_BODY: &str = "body";
/// Envelope key of the critical-extension list.
const KEY_CRITICAL: &str = "critical";
/// Envelope key of the extension map.
const KEY_EXTENSIONS: &str = "extensions";

/// Body key: negotiated or session parameters.
const KEY_PARAMETERS: &str = "parameters";
/// Body key: display name.
const KEY_DISPLAY_NAME: &str = "display_name";
/// Body key: platform description.
const KEY_PLATFORM: &str = "platform";
/// Body key: profiles the requester asks for.
const KEY_REQUESTED_PROFILES: &str = "requested_profiles";
/// Body key: profiles the proxy user granted.
const KEY_GRANTED_PROFILES: &str = "granted_profiles";
/// Body key: an abort, cancel, or close reason.
const KEY_REASON: &str = "reason";
/// Body key: the ready nonce.
const KEY_NONCE: &str = "nonce";
/// Body key: the highest sequence received.
const KEY_LAST_RECEIVED_SEQUENCE: &str = "last_received_sequence";
/// Body key: a liveness challenge.
const KEY_CHALLENGE: &str = "challenge";
/// Body key: an operation identifier.
const KEY_OPERATION_ID: &str = "operation_id";
/// Body key: a credential profile name.
const KEY_PROFILE: &str = "profile";
/// Body key: a profile action name.
const KEY_ACTION: &str = "action";
/// Body key: the request hash echo.
const KEY_REQUEST_HASH: &str = "request_hash";
/// Body key: the pre-commit expiry budget.
const KEY_EXPIRES_AFTER_MS: &str = "expires_after_ms";
/// Body key: requester-asserted and verified consent context.
const KEY_CONTEXT: &str = "context";
/// Body key: the profile payload.
const KEY_PAYLOAD: &str = "payload";
/// Body key: an operation result status.
const KEY_STATUS: &str = "status";
/// Body key: a failure name inside a result.
const KEY_ERROR: &str = "error";
/// Body key: whether a queried operation is known.
const KEY_KNOWN: &str = "known";
/// Body key: the journaled state of a queried operation.
const KEY_STATE: &str = "state";
/// Parameter key: the negotiated suite.
const KEY_SUITE: &str = "suite";
/// Parameter key: the bound offer hash.
const KEY_OFFER_HASH: &str = "offer_hash";
/// Parameter key: the transport profile in use.
const KEY_TRANSPORT_PROFILE: &str = "transport_profile";
/// Parameter key: the connected candidate.
const KEY_CANDIDATE_ID: &str = "candidate_id";
/// Parameter key: the bound grants hash.
const KEY_GRANTS_HASH: &str = "grants_hash";

/// The registered error name for a displaced second session.
pub const ERROR_BUSY: &str = "busy";
/// The registered error name for a stale operation reference.
pub const ERROR_UNKNOWN_OPERATION: &str = "unknown_operation";

/// A schema violation found while reading a decrypted message.
///
/// The session layer treats every variant as an authenticated protocol
/// violation, so the variants exist for diagnostics and tests rather than
/// for divergent handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaViolation {
    /// The plaintext was not a deterministic-CBOR map.
    NotAMap,
    /// A required field is missing.
    MissingField,
    /// A field has the wrong type or an impossible value.
    WrongFieldType,
    /// A field outside the schema appeared outside `extensions`.
    UnknownField,
    /// The message type is not registered.
    UnknownMessageType,
    /// A field named in `critical` is not understood.
    UnknownCriticalField,
    /// A close reason, result status, or reason text is not registered.
    UnknownDiscriminant,
    /// The value could not be encoded within limits.
    Encoding,
}

/// The registered close reasons of Section 10.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The local user disconnected.
    UserDisconnect,
    /// Local policy closed the session.
    Policy,
    /// The card rejected CAN, PIN 1, or PIN 2 (Section 13.4); the pairing
    /// is revoked on both peers.
    CredentialRejected,
    /// An authenticated protocol violation closed the session and revoked
    /// the pairing; the peer must mark its record revoked (Section 14.6).
    ProtocolViolation,
    /// The pairing was revoked; the peer must mark its record revoked.
    PairingRevoked,
    /// The endpoint is shutting down.
    Shutdown,
}

impl CloseReason {
    /// The wire text of the reason.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::UserDisconnect => "user_disconnect",
            Self::Policy => "policy",
            Self::CredentialRejected => "credential_rejected",
            Self::ProtocolViolation => "protocol_violation",
            Self::PairingRevoked => "pairing_revoked",
            Self::Shutdown => "shutdown",
        }
    }

    /// Reads a registered reason from its wire text.
    fn from_wire(text: &str) -> Result<Self, SchemaViolation> {
        Ok(match text {
            "user_disconnect" => Self::UserDisconnect,
            "policy" => Self::Policy,
            "credential_rejected" => Self::CredentialRejected,
            "protocol_violation" => Self::ProtocolViolation,
            "pairing_revoked" => Self::PairingRevoked,
            "shutdown" => Self::Shutdown,
            _ => return Err(SchemaViolation::UnknownDiscriminant),
        })
    }
}

/// The registered result statuses of Section 12.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultStatus {
    /// The operation completed; an acknowledgment is required.
    Completed,
    /// The user denied before commit.
    Denied,
    /// Cancellation or expiry proven before physical transmission.
    Cancelled,
    /// A non-credential policy or card rejection.
    Rejected,
    /// The card rejected CAN, PIN 1, or PIN 2.
    CredentialRejected,
    /// Card completion cannot be proven; retry is forbidden.
    Ambiguous,
}

impl ResultStatus {
    /// The wire text of the status.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
            Self::CredentialRejected => "credential_rejected",
            Self::Ambiguous => "ambiguous",
        }
    }

    /// Reads a registered status from its wire text.
    fn from_wire(text: &str) -> Result<Self, SchemaViolation> {
        Ok(match text {
            "completed" => Self::Completed,
            "denied" => Self::Denied,
            "cancelled" => Self::Cancelled,
            "rejected" => Self::Rejected,
            "credential_rejected" => Self::CredentialRejected,
            "ambiguous" => Self::Ambiguous,
            _ => return Err(SchemaViolation::UnknownDiscriminant),
        })
    }
}

/// The negotiated-parameter echo of `pairing.hello` (Section 9.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedParameters {
    /// The bound wire version.
    pub version: (u64, u64, u64),
    /// The bound cryptographic suite name.
    pub suite: String,
    /// The bound offer hash.
    pub offer_hash: [u8; 32],
    /// The transport profile in use.
    pub transport_profile: String,
    /// The connected candidate identifier.
    pub candidate_id: String,
}

/// The parameter echo of `session.ready` (Section 10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionParameters {
    /// The bound wire version.
    pub version: (u64, u64, u64),
    /// The bound cryptographic suite name.
    pub suite: String,
    /// The transport profile in use.
    pub transport_profile: String,
    /// The connected candidate identifier.
    pub candidate_id: String,
    /// The bound grants hash.
    pub grants_hash: [u8; 32],
}

/// One typed message body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// `pairing.hello`.
    PairingHello {
        /// The negotiated-parameter echo.
        parameters: NegotiatedParameters,
        /// A display label, not an identity.
        display_name: String,
        /// A platform description label.
        platform: String,
        /// The requester's requested profiles; absent from the proxy.
        requested_profiles: Option<Vec<String>>,
    },
    /// `pairing.confirm`.
    PairingConfirm {
        /// The granted profile set.
        granted_profiles: Vec<String>,
    },
    /// `pairing.abort`.
    PairingAbort {
        /// A registered or descriptive reason label.
        reason: String,
    },
    /// `session.ready`.
    SessionReady {
        /// The parameter echo.
        parameters: SessionParameters,
        /// A fresh random nonce.
        nonce: [u8; 32],
    },
    /// `session.close`.
    SessionClose {
        /// The registered close reason.
        reason: CloseReason,
        /// The highest sequence received before closing.
        last_received_sequence: u64,
    },
    /// `liveness.ping`.
    LivenessPing {
        /// The random challenge the pong must echo.
        challenge: Challenge,
        /// The highest sequence received.
        last_received_sequence: u64,
    },
    /// `liveness.pong`.
    LivenessPong {
        /// The echoed challenge.
        challenge: Challenge,
        /// The highest sequence received.
        last_received_sequence: u64,
    },
    /// `operation.request`.
    OperationRequest {
        /// The random operation identifier.
        operation_id: OperationId,
        /// The credential profile name.
        profile: String,
        /// The profile action name.
        action: String,
        /// The request hash every later message echoes.
        request_hash: [u8; 32],
        /// The pre-commit expiry budget in milliseconds.
        expires_after_ms: u64,
        /// Consent context as encoded on the wire.
        context: Vec<(String, Value)>,
        /// Profile payload as encoded on the wire.
        payload: Vec<(String, Value)>,
    },
    /// `operation.prepared`.
    OperationPrepared {
        /// The operation identifier.
        operation_id: OperationId,
        /// The request hash echo.
        request_hash: [u8; 32],
    },
    /// `operation.commit`.
    OperationCommit {
        /// The operation identifier.
        operation_id: OperationId,
        /// The request hash echo.
        request_hash: [u8; 32],
    },
    /// `operation.cancel`.
    OperationCancel {
        /// The operation identifier.
        operation_id: OperationId,
        /// The request hash echo.
        request_hash: [u8; 32],
        /// An optional reason label.
        reason: Option<String>,
    },
    /// `operation.result`.
    OperationResult {
        /// The operation identifier.
        operation_id: OperationId,
        /// The request hash echo.
        request_hash: [u8; 32],
        /// The result status.
        status: ResultStatus,
        /// A failure name when the status carries one.
        error: Option<String>,
        /// The profile-defined result body.
        body: Vec<(String, Value)>,
    },
    /// `operation.result_ack`.
    OperationResultAck {
        /// The operation identifier.
        operation_id: OperationId,
        /// The request hash echo.
        request_hash: [u8; 32],
    },
    /// `operation.status_request`.
    OperationStatusRequest {
        /// The queried operation identifier.
        operation_id: OperationId,
    },
    /// `operation.status`.
    OperationStatus {
        /// The queried operation identifier.
        operation_id: OperationId,
        /// Whether the proxy journal knows the operation.
        known: bool,
        /// The journaled terminal state name, when known.
        state: Option<String>,
        /// The journaled request hash, when known.
        request_hash: Option<[u8; 32]>,
    },
    /// `error`.
    Error {
        /// The registered error name.
        error: String,
        /// The referenced operation, when one exists.
        operation_id: Option<OperationId>,
    },
}

impl Body {
    /// The registered wire name of the body's message type.
    #[must_use]
    pub const fn message_type(&self) -> &'static str {
        match self {
            Self::PairingHello { .. } => "pairing.hello",
            Self::PairingConfirm { .. } => "pairing.confirm",
            Self::PairingAbort { .. } => "pairing.abort",
            Self::SessionReady { .. } => "session.ready",
            Self::SessionClose { .. } => "session.close",
            Self::LivenessPing { .. } => "liveness.ping",
            Self::LivenessPong { .. } => "liveness.pong",
            Self::OperationRequest { .. } => "operation.request",
            Self::OperationPrepared { .. } => "operation.prepared",
            Self::OperationCommit { .. } => "operation.commit",
            Self::OperationCancel { .. } => "operation.cancel",
            Self::OperationResult { .. } => "operation.result",
            Self::OperationResultAck { .. } => "operation.result_ack",
            Self::OperationStatusRequest { .. } => "operation.status_request",
            Self::OperationStatus { .. } => "operation.status",
            Self::Error { .. } => "error",
        }
    }
}

/// One complete envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// The wire version.
    pub version: (u64, u64, u64),
    /// The derived identifier of the carrying channel.
    pub session_id: SessionId,
    /// The per-direction sequence number.
    pub sequence: u64,
    /// The typed body.
    pub body: Body,
}

impl Envelope {
    /// Encodes the envelope as deterministic CBOR.
    ///
    /// RAPP 0.1 sends no `critical` list and no `extensions` map.
    ///
    /// # Errors
    ///
    /// Fails only when a component exceeds an encoding limit.
    pub fn encode(&self) -> Result<Vec<u8>, SchemaViolation> {
        let entries = vec![
            (
                KEY_VERSION.into(),
                Value::Array(vec![
                    Value::Unsigned(self.version.0),
                    Value::Unsigned(self.version.1),
                    Value::Unsigned(self.version.2),
                ]),
            ),
            (
                KEY_TYPE.into(),
                Value::Text(self.body.message_type().into()),
            ),
            (
                KEY_SESSION_ID.into(),
                Value::Bytes(self.session_id.0.to_vec()),
            ),
            (KEY_SEQUENCE.into(), Value::Unsigned(self.sequence)),
            (KEY_BODY.into(), encode_body(&self.body)),
        ];
        Value::Map(entries)
            .encode()
            .map_err(|_| SchemaViolation::Encoding)
    }

    /// Decodes and schema-validates one envelope.
    ///
    /// # Errors
    ///
    /// Every failure is a schema violation the session layer classifies as
    /// an authenticated protocol violation.
    pub fn decode(plaintext: &[u8]) -> Result<Self, SchemaViolation> {
        let value = Value::decode(plaintext).map_err(|_| SchemaViolation::NotAMap)?;
        let Value::Map(entries) = value else {
            return Err(SchemaViolation::NotAMap);
        };
        let mut version = None;
        let mut message_type = None;
        let mut session_id = None;
        let mut sequence = None;
        let mut body = None;
        for (key, entry) in &entries {
            match (key.as_str(), entry) {
                (KEY_VERSION, value) => version = Some(read_version(value)?),
                (KEY_TYPE, Value::Text(text)) => message_type = Some(text.clone()),
                (KEY_SESSION_ID, value) => {
                    session_id = Some(SessionId(read_fixed::<SESSION_ID_LENGTH>(value)?));
                }
                (KEY_SEQUENCE, Value::Unsigned(number)) => sequence = Some(*number),
                (KEY_BODY, value @ Value::Map(_)) => body = Some(value.clone()),
                (KEY_CRITICAL, Value::Array(names)) => {
                    // RAPP 0.1 defines no critical extensions, so any named
                    // field is unknown and must be rejected.
                    if !names.is_empty() {
                        return Err(SchemaViolation::UnknownCriticalField);
                    }
                }
                (KEY_EXTENSIONS, Value::Map(_)) => {
                    // Unknown non-critical extensions are ignored.
                }
                _ => return Err(SchemaViolation::UnknownField),
            }
        }
        let message_type = message_type.ok_or(SchemaViolation::MissingField)?;
        let body_value = body.ok_or(SchemaViolation::MissingField)?;
        Ok(Self {
            version: version.ok_or(SchemaViolation::MissingField)?,
            session_id: session_id.ok_or(SchemaViolation::MissingField)?,
            sequence: sequence.ok_or(SchemaViolation::MissingField)?,
            body: decode_body(&message_type, &body_value)?,
        })
    }
}

/// Reads a `[major, minor, patch]` version array.
const fn read_version(value: &Value) -> Result<(u64, u64, u64), SchemaViolation> {
    let Value::Array(parts) = value else {
        return Err(SchemaViolation::WrongFieldType);
    };
    if let [
        Value::Unsigned(major),
        Value::Unsigned(minor),
        Value::Unsigned(patch),
    ] = parts.as_slice()
    {
        Ok((*major, *minor, *patch))
    } else {
        Err(SchemaViolation::WrongFieldType)
    }
}

/// Reads a fixed-length byte string.
fn read_fixed<const LENGTH: usize>(value: &Value) -> Result<[u8; LENGTH], SchemaViolation> {
    let Value::Bytes(bytes) = value else {
        return Err(SchemaViolation::WrongFieldType);
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| SchemaViolation::WrongFieldType)
}

/// Reads a text field.
fn read_text(value: &Value) -> Result<String, SchemaViolation> {
    match value {
        Value::Text(text) => Ok(text.clone()),
        _ => Err(SchemaViolation::WrongFieldType),
    }
}

/// Reads an unsigned field.
const fn read_unsigned(value: &Value) -> Result<u64, SchemaViolation> {
    match value {
        Value::Unsigned(number) => Ok(*number),
        _ => Err(SchemaViolation::WrongFieldType),
    }
}

/// Reads a non-empty array of text items.
fn read_text_array(value: &Value) -> Result<Vec<String>, SchemaViolation> {
    let Value::Array(items) = value else {
        return Err(SchemaViolation::WrongFieldType);
    };
    if items.is_empty() {
        return Err(SchemaViolation::WrongFieldType);
    }
    items.iter().map(read_text).collect()
}

/// Reads a map field into its entry list.
fn read_map(value: &Value) -> Result<Vec<(String, Value)>, SchemaViolation> {
    match value {
        Value::Map(entries) => Ok(entries.clone()),
        _ => Err(SchemaViolation::WrongFieldType),
    }
}

/// Encodes the negotiated-parameter echo.
fn encode_negotiated(parameters: &NegotiatedParameters) -> Value {
    Value::Map(vec![
        (
            KEY_VERSION.into(),
            Value::Array(vec![
                Value::Unsigned(parameters.version.0),
                Value::Unsigned(parameters.version.1),
                Value::Unsigned(parameters.version.2),
            ]),
        ),
        (KEY_SUITE.into(), Value::Text(parameters.suite.clone())),
        (
            KEY_OFFER_HASH.into(),
            Value::Bytes(parameters.offer_hash.to_vec()),
        ),
        (
            KEY_TRANSPORT_PROFILE.into(),
            Value::Text(parameters.transport_profile.clone()),
        ),
        (
            KEY_CANDIDATE_ID.into(),
            Value::Text(parameters.candidate_id.clone()),
        ),
    ])
}

/// Reads the negotiated-parameter echo.
fn decode_negotiated(value: &Value) -> Result<NegotiatedParameters, SchemaViolation> {
    let Value::Map(entries) = value else {
        return Err(SchemaViolation::WrongFieldType);
    };
    let mut version = None;
    let mut suite = None;
    let mut offer_hash = None;
    let mut transport_profile = None;
    let mut candidate_id = None;
    for (key, entry) in entries {
        match key.as_str() {
            KEY_VERSION => version = Some(read_version(entry)?),
            KEY_SUITE => suite = Some(read_text(entry)?),
            KEY_OFFER_HASH => offer_hash = Some(read_fixed::<32>(entry)?),
            KEY_TRANSPORT_PROFILE => transport_profile = Some(read_text(entry)?),
            KEY_CANDIDATE_ID => candidate_id = Some(read_text(entry)?),
            _ => return Err(SchemaViolation::UnknownField),
        }
    }
    Ok(NegotiatedParameters {
        version: version.ok_or(SchemaViolation::MissingField)?,
        suite: suite.ok_or(SchemaViolation::MissingField)?,
        offer_hash: offer_hash.ok_or(SchemaViolation::MissingField)?,
        transport_profile: transport_profile.ok_or(SchemaViolation::MissingField)?,
        candidate_id: candidate_id.ok_or(SchemaViolation::MissingField)?,
    })
}

/// Encodes the session-parameter echo.
fn encode_session_parameters(parameters: &SessionParameters) -> Value {
    Value::Map(vec![
        (
            KEY_VERSION.into(),
            Value::Array(vec![
                Value::Unsigned(parameters.version.0),
                Value::Unsigned(parameters.version.1),
                Value::Unsigned(parameters.version.2),
            ]),
        ),
        (KEY_SUITE.into(), Value::Text(parameters.suite.clone())),
        (
            KEY_TRANSPORT_PROFILE.into(),
            Value::Text(parameters.transport_profile.clone()),
        ),
        (
            KEY_CANDIDATE_ID.into(),
            Value::Text(parameters.candidate_id.clone()),
        ),
        (
            KEY_GRANTS_HASH.into(),
            Value::Bytes(parameters.grants_hash.to_vec()),
        ),
    ])
}

/// Reads the session-parameter echo.
fn decode_session_parameters(value: &Value) -> Result<SessionParameters, SchemaViolation> {
    let Value::Map(entries) = value else {
        return Err(SchemaViolation::WrongFieldType);
    };
    let mut version = None;
    let mut suite = None;
    let mut transport_profile = None;
    let mut candidate_id = None;
    let mut grants_hash = None;
    for (key, entry) in entries {
        match key.as_str() {
            KEY_VERSION => version = Some(read_version(entry)?),
            KEY_SUITE => suite = Some(read_text(entry)?),
            KEY_TRANSPORT_PROFILE => transport_profile = Some(read_text(entry)?),
            KEY_CANDIDATE_ID => candidate_id = Some(read_text(entry)?),
            KEY_GRANTS_HASH => grants_hash = Some(read_fixed::<32>(entry)?),
            _ => return Err(SchemaViolation::UnknownField),
        }
    }
    Ok(SessionParameters {
        version: version.ok_or(SchemaViolation::MissingField)?,
        suite: suite.ok_or(SchemaViolation::MissingField)?,
        transport_profile: transport_profile.ok_or(SchemaViolation::MissingField)?,
        candidate_id: candidate_id.ok_or(SchemaViolation::MissingField)?,
        grants_hash: grants_hash.ok_or(SchemaViolation::MissingField)?,
    })
}

/// Encodes a profile list in canonical byte-wise name order, so all
/// peers emit identical arrays regardless of caller order.
fn profile_array(profiles: &[String]) -> Value {
    let mut sorted = profiles.to_vec();
    sorted.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Value::Array(sorted.into_iter().map(Value::Text).collect())
}

/// Encodes one body as its wire map.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per registered message type keeps the schema in one place"
)]
fn encode_body(body: &Body) -> Value {
    match body {
        Body::PairingHello {
            parameters,
            display_name,
            platform,
            requested_profiles,
        } => {
            let mut entries = vec![
                (KEY_PARAMETERS.into(), encode_negotiated(parameters)),
                (KEY_DISPLAY_NAME.into(), Value::Text(display_name.clone())),
                (KEY_PLATFORM.into(), Value::Text(platform.clone())),
            ];
            if let Some(profiles) = requested_profiles {
                entries.push((KEY_REQUESTED_PROFILES.into(), profile_array(profiles)));
            }
            Value::Map(entries)
        }
        Body::PairingConfirm { granted_profiles } => Value::Map(vec![(
            KEY_GRANTED_PROFILES.into(),
            profile_array(granted_profiles),
        )]),
        Body::PairingAbort { reason } => {
            Value::Map(vec![(KEY_REASON.into(), Value::Text(reason.clone()))])
        }
        Body::SessionReady { parameters, nonce } => Value::Map(vec![
            (KEY_PARAMETERS.into(), encode_session_parameters(parameters)),
            (KEY_NONCE.into(), Value::Bytes(nonce.to_vec())),
        ]),
        Body::SessionClose {
            reason,
            last_received_sequence,
        } => Value::Map(vec![
            (KEY_REASON.into(), Value::Text(reason.wire_name().into())),
            (
                KEY_LAST_RECEIVED_SEQUENCE.into(),
                Value::Unsigned(*last_received_sequence),
            ),
        ]),
        Body::LivenessPing {
            challenge,
            last_received_sequence,
        }
        | Body::LivenessPong {
            challenge,
            last_received_sequence,
        } => Value::Map(vec![
            (KEY_CHALLENGE.into(), Value::Bytes(challenge.0.to_vec())),
            (
                KEY_LAST_RECEIVED_SEQUENCE.into(),
                Value::Unsigned(*last_received_sequence),
            ),
        ]),
        Body::OperationRequest {
            operation_id,
            profile,
            action,
            request_hash,
            expires_after_ms,
            context,
            payload,
        } => Value::Map(vec![
            (
                KEY_OPERATION_ID.into(),
                Value::Bytes(operation_id.0.to_vec()),
            ),
            (KEY_PROFILE.into(), Value::Text(profile.clone())),
            (KEY_ACTION.into(), Value::Text(action.clone())),
            (KEY_REQUEST_HASH.into(), Value::Bytes(request_hash.to_vec())),
            (
                KEY_EXPIRES_AFTER_MS.into(),
                Value::Unsigned(*expires_after_ms),
            ),
            (KEY_CONTEXT.into(), Value::Map(context.clone())),
            (KEY_PAYLOAD.into(), Value::Map(payload.clone())),
        ]),
        Body::OperationPrepared {
            operation_id,
            request_hash,
        }
        | Body::OperationCommit {
            operation_id,
            request_hash,
        }
        | Body::OperationResultAck {
            operation_id,
            request_hash,
        } => Value::Map(vec![
            (
                KEY_OPERATION_ID.into(),
                Value::Bytes(operation_id.0.to_vec()),
            ),
            (KEY_REQUEST_HASH.into(), Value::Bytes(request_hash.to_vec())),
        ]),
        Body::OperationCancel {
            operation_id,
            request_hash,
            reason,
        } => {
            let mut entries = vec![
                (
                    KEY_OPERATION_ID.into(),
                    Value::Bytes(operation_id.0.to_vec()),
                ),
                (KEY_REQUEST_HASH.into(), Value::Bytes(request_hash.to_vec())),
            ];
            if let Some(reason) = reason {
                entries.push((KEY_REASON.into(), Value::Text(reason.clone())));
            }
            Value::Map(entries)
        }
        Body::OperationResult {
            operation_id,
            request_hash,
            status,
            error,
            body,
        } => {
            let mut entries = vec![
                (
                    KEY_OPERATION_ID.into(),
                    Value::Bytes(operation_id.0.to_vec()),
                ),
                (KEY_REQUEST_HASH.into(), Value::Bytes(request_hash.to_vec())),
                (KEY_STATUS.into(), Value::Text(status.wire_name().into())),
                (KEY_BODY.into(), Value::Map(body.clone())),
            ];
            if let Some(error) = error {
                entries.push((KEY_ERROR.into(), Value::Text(error.clone())));
            }
            Value::Map(entries)
        }
        Body::OperationStatusRequest { operation_id } => Value::Map(vec![(
            KEY_OPERATION_ID.into(),
            Value::Bytes(operation_id.0.to_vec()),
        )]),
        Body::OperationStatus {
            operation_id,
            known,
            state,
            request_hash,
        } => {
            let mut entries = vec![
                (
                    KEY_OPERATION_ID.into(),
                    Value::Bytes(operation_id.0.to_vec()),
                ),
                (KEY_KNOWN.into(), Value::Bool(*known)),
            ];
            if let Some(state) = state {
                entries.push((KEY_STATE.into(), Value::Text(state.clone())));
            }
            if let Some(hash) = request_hash {
                entries.push((KEY_REQUEST_HASH.into(), Value::Bytes(hash.to_vec())));
            }
            Value::Map(entries)
        }
        Body::Error {
            error,
            operation_id,
        } => {
            let mut entries = vec![(KEY_ERROR.into(), Value::Text(error.clone()))];
            if let Some(operation_id) = operation_id {
                entries.push((
                    KEY_OPERATION_ID.into(),
                    Value::Bytes(operation_id.0.to_vec()),
                ));
            }
            Value::Map(entries)
        }
    }
}

/// Reads one body from its wire map under its registered type name.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per registered message type keeps the schema in one place"
)]
fn decode_body(message_type: &str, value: &Value) -> Result<Body, SchemaViolation> {
    let Value::Map(entries) = value else {
        return Err(SchemaViolation::WrongFieldType);
    };
    match message_type {
        "pairing.hello" => {
            let mut parameters = None;
            let mut display_name = None;
            let mut platform = None;
            let mut requested_profiles = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_PARAMETERS => parameters = Some(decode_negotiated(entry)?),
                    KEY_DISPLAY_NAME => display_name = Some(read_text(entry)?),
                    KEY_PLATFORM => platform = Some(read_text(entry)?),
                    KEY_REQUESTED_PROFILES => requested_profiles = Some(read_text_array(entry)?),
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            Ok(Body::PairingHello {
                parameters: parameters.ok_or(SchemaViolation::MissingField)?,
                display_name: display_name.ok_or(SchemaViolation::MissingField)?,
                platform: platform.ok_or(SchemaViolation::MissingField)?,
                requested_profiles,
            })
        }
        "pairing.confirm" => {
            let mut granted_profiles = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_GRANTED_PROFILES => granted_profiles = Some(read_text_array(entry)?),
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            Ok(Body::PairingConfirm {
                granted_profiles: granted_profiles.ok_or(SchemaViolation::MissingField)?,
            })
        }
        "pairing.abort" => {
            let mut reason = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_REASON => reason = Some(read_text(entry)?),
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            Ok(Body::PairingAbort {
                reason: reason.ok_or(SchemaViolation::MissingField)?,
            })
        }
        "session.ready" => {
            let mut parameters = None;
            let mut nonce = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_PARAMETERS => parameters = Some(decode_session_parameters(entry)?),
                    KEY_NONCE => nonce = Some(read_fixed::<32>(entry)?),
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            Ok(Body::SessionReady {
                parameters: parameters.ok_or(SchemaViolation::MissingField)?,
                nonce: nonce.ok_or(SchemaViolation::MissingField)?,
            })
        }
        "session.close" => {
            let mut reason = None;
            let mut last_received_sequence = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_REASON => reason = Some(CloseReason::from_wire(&read_text(entry)?)?),
                    KEY_LAST_RECEIVED_SEQUENCE => {
                        last_received_sequence = Some(read_unsigned(entry)?);
                    }
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            Ok(Body::SessionClose {
                reason: reason.ok_or(SchemaViolation::MissingField)?,
                last_received_sequence: last_received_sequence
                    .ok_or(SchemaViolation::MissingField)?,
            })
        }
        "liveness.ping" | "liveness.pong" => {
            let mut challenge = None;
            let mut last_received_sequence = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_CHALLENGE => {
                        challenge = Some(Challenge(read_fixed::<CHALLENGE_LENGTH>(entry)?));
                    }
                    KEY_LAST_RECEIVED_SEQUENCE => {
                        last_received_sequence = Some(read_unsigned(entry)?);
                    }
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            let challenge = challenge.ok_or(SchemaViolation::MissingField)?;
            let last_received_sequence =
                last_received_sequence.ok_or(SchemaViolation::MissingField)?;
            Ok(if message_type == "liveness.ping" {
                Body::LivenessPing {
                    challenge,
                    last_received_sequence,
                }
            } else {
                Body::LivenessPong {
                    challenge,
                    last_received_sequence,
                }
            })
        }
        "operation.request" => {
            let mut operation_id = None;
            let mut profile = None;
            let mut action = None;
            let mut request_hash = None;
            let mut expires_after_ms = None;
            let mut context = None;
            let mut payload = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_OPERATION_ID => {
                        operation_id = Some(OperationId(read_fixed::<OPERATION_ID_LENGTH>(entry)?));
                    }
                    KEY_PROFILE => profile = Some(read_text(entry)?),
                    KEY_ACTION => action = Some(read_text(entry)?),
                    KEY_REQUEST_HASH => request_hash = Some(read_fixed::<32>(entry)?),
                    KEY_EXPIRES_AFTER_MS => expires_after_ms = Some(read_unsigned(entry)?),
                    KEY_CONTEXT => context = Some(read_map(entry)?),
                    KEY_PAYLOAD => payload = Some(read_map(entry)?),
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            Ok(Body::OperationRequest {
                operation_id: operation_id.ok_or(SchemaViolation::MissingField)?,
                profile: profile.ok_or(SchemaViolation::MissingField)?,
                action: action.ok_or(SchemaViolation::MissingField)?,
                request_hash: request_hash.ok_or(SchemaViolation::MissingField)?,
                expires_after_ms: expires_after_ms.ok_or(SchemaViolation::MissingField)?,
                context: context.ok_or(SchemaViolation::MissingField)?,
                payload: payload.ok_or(SchemaViolation::MissingField)?,
            })
        }
        "operation.prepared" | "operation.commit" | "operation.result_ack" => {
            let mut operation_id = None;
            let mut request_hash = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_OPERATION_ID => {
                        operation_id = Some(OperationId(read_fixed::<OPERATION_ID_LENGTH>(entry)?));
                    }
                    KEY_REQUEST_HASH => request_hash = Some(read_fixed::<32>(entry)?),
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            let operation_id = operation_id.ok_or(SchemaViolation::MissingField)?;
            let request_hash = request_hash.ok_or(SchemaViolation::MissingField)?;
            Ok(match message_type {
                "operation.prepared" => Body::OperationPrepared {
                    operation_id,
                    request_hash,
                },
                "operation.commit" => Body::OperationCommit {
                    operation_id,
                    request_hash,
                },
                _ => Body::OperationResultAck {
                    operation_id,
                    request_hash,
                },
            })
        }
        "operation.cancel" => {
            let mut operation_id = None;
            let mut request_hash = None;
            let mut reason = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_OPERATION_ID => {
                        operation_id = Some(OperationId(read_fixed::<OPERATION_ID_LENGTH>(entry)?));
                    }
                    KEY_REQUEST_HASH => request_hash = Some(read_fixed::<32>(entry)?),
                    KEY_REASON => reason = Some(read_text(entry)?),
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            Ok(Body::OperationCancel {
                operation_id: operation_id.ok_or(SchemaViolation::MissingField)?,
                request_hash: request_hash.ok_or(SchemaViolation::MissingField)?,
                reason,
            })
        }
        "operation.result" => {
            let mut operation_id = None;
            let mut request_hash = None;
            let mut status = None;
            let mut error = None;
            let mut body = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_OPERATION_ID => {
                        operation_id = Some(OperationId(read_fixed::<OPERATION_ID_LENGTH>(entry)?));
                    }
                    KEY_REQUEST_HASH => request_hash = Some(read_fixed::<32>(entry)?),
                    KEY_STATUS => status = Some(ResultStatus::from_wire(&read_text(entry)?)?),
                    KEY_ERROR => error = Some(read_text(entry)?),
                    KEY_BODY => body = Some(read_map(entry)?),
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            Ok(Body::OperationResult {
                operation_id: operation_id.ok_or(SchemaViolation::MissingField)?,
                request_hash: request_hash.ok_or(SchemaViolation::MissingField)?,
                status: status.ok_or(SchemaViolation::MissingField)?,
                error,
                body: body.ok_or(SchemaViolation::MissingField)?,
            })
        }
        "operation.status_request" => {
            let mut operation_id = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_OPERATION_ID => {
                        operation_id = Some(OperationId(read_fixed::<OPERATION_ID_LENGTH>(entry)?));
                    }
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            Ok(Body::OperationStatusRequest {
                operation_id: operation_id.ok_or(SchemaViolation::MissingField)?,
            })
        }
        "operation.status" => {
            let mut operation_id = None;
            let mut known = None;
            let mut state = None;
            let mut request_hash = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_OPERATION_ID => {
                        operation_id = Some(OperationId(read_fixed::<OPERATION_ID_LENGTH>(entry)?));
                    }
                    KEY_KNOWN => match entry {
                        Value::Bool(flag) => known = Some(*flag),
                        _ => return Err(SchemaViolation::WrongFieldType),
                    },
                    KEY_STATE => state = Some(read_text(entry)?),
                    KEY_REQUEST_HASH => request_hash = Some(read_fixed::<32>(entry)?),
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            Ok(Body::OperationStatus {
                operation_id: operation_id.ok_or(SchemaViolation::MissingField)?,
                known: known.ok_or(SchemaViolation::MissingField)?,
                state,
                request_hash,
            })
        }
        "error" => {
            let mut error = None;
            let mut operation_id = None;
            for (key, entry) in entries {
                match key.as_str() {
                    KEY_ERROR => error = Some(read_text(entry)?),
                    KEY_OPERATION_ID => {
                        operation_id = Some(OperationId(read_fixed::<OPERATION_ID_LENGTH>(entry)?));
                    }
                    _ => return Err(SchemaViolation::UnknownField),
                }
            }
            Ok(Body::Error {
                error: error.ok_or(SchemaViolation::MissingField)?,
                operation_id,
            })
        }
        _ => Err(SchemaViolation::UnknownMessageType),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test vectors are constructed to be infallible"
)]
mod tests {
    use super::{
        Body, CloseReason, Envelope, NegotiatedParameters, ResultStatus, SchemaViolation,
        SessionParameters,
    };
    use crate::WIRE_VERSION;
    use crate::cbor::Value;
    use crate::ids::{Challenge, OperationId, SessionId};

    fn round_trip(body: Body) {
        let envelope = Envelope {
            version: WIRE_VERSION,
            session_id: SessionId([0xAB; 16]),
            sequence: 7,
            body,
        };
        let encoded = envelope.encode().unwrap();
        assert_eq!(Envelope::decode(&encoded).unwrap(), envelope);
    }

    #[test]
    fn every_message_type_round_trips() {
        round_trip(Body::PairingHello {
            parameters: NegotiatedParameters {
                version: WIRE_VERSION,
                suite: crate::PAIRING_SUITE.into(),
                offer_hash: [1; 32],
                transport_profile: "fi.refineid.memory.v1".into(),
                candidate_id: "c-1".into(),
            },
            display_name: "Workstation".into(),
            platform: "Windows".into(),
            requested_profiles: Some(vec!["fi.refineid.card-status.v1".into()]),
        });
        round_trip(Body::PairingConfirm {
            granted_profiles: vec!["fi.refineid.card-status.v1".into()],
        });
        round_trip(Body::PairingAbort {
            reason: "denied".into(),
        });
        round_trip(Body::SessionReady {
            parameters: SessionParameters {
                version: WIRE_VERSION,
                suite: crate::SESSION_SUITE.into(),
                transport_profile: "fi.refineid.memory.v1".into(),
                candidate_id: "c-1".into(),
                grants_hash: [2; 32],
            },
            nonce: [3; 32],
        });
        round_trip(Body::SessionClose {
            reason: CloseReason::UserDisconnect,
            last_received_sequence: 41,
        });
        round_trip(Body::LivenessPing {
            challenge: Challenge([4; 32]),
            last_received_sequence: 9,
        });
        round_trip(Body::LivenessPong {
            challenge: Challenge([4; 32]),
            last_received_sequence: 10,
        });
        round_trip(Body::OperationRequest {
            operation_id: OperationId([5; 16]),
            profile: "fi.refineid.authentication.v1".into(),
            action: "sign".into(),
            request_hash: [6; 32],
            expires_after_ms: 60_000,
            context: vec![("origin".into(), Value::Text("example.fi".into()))],
            payload: vec![("digest".into(), Value::Bytes(vec![7; 32]))],
        });
        round_trip(Body::OperationPrepared {
            operation_id: OperationId([5; 16]),
            request_hash: [6; 32],
        });
        round_trip(Body::OperationCommit {
            operation_id: OperationId([5; 16]),
            request_hash: [6; 32],
        });
        round_trip(Body::OperationCancel {
            operation_id: OperationId([5; 16]),
            request_hash: [6; 32],
            reason: Some("expired".into()),
        });
        round_trip(Body::OperationResult {
            operation_id: OperationId([5; 16]),
            request_hash: [6; 32],
            status: ResultStatus::Completed,
            error: None,
            body: vec![("signature".into(), Value::Bytes(vec![8; 64]))],
        });
        round_trip(Body::OperationResultAck {
            operation_id: OperationId([5; 16]),
            request_hash: [6; 32],
        });
        round_trip(Body::OperationStatusRequest {
            operation_id: OperationId([5; 16]),
        });
        round_trip(Body::OperationStatus {
            operation_id: OperationId([5; 16]),
            known: true,
            state: Some("completed".into()),
            request_hash: Some([6; 32]),
        });
        round_trip(Body::Error {
            error: super::ERROR_UNKNOWN_OPERATION.into(),
            operation_id: Some(OperationId([5; 16])),
        });
    }

    fn envelope_value(body_entries: Vec<(String, Value)>, message_type: &str) -> Vec<u8> {
        Value::Map(vec![
            (
                "version".into(),
                Value::Array(vec![
                    Value::Unsigned(0),
                    Value::Unsigned(1),
                    Value::Unsigned(2),
                ]),
            ),
            ("type".into(), Value::Text(message_type.into())),
            ("session_id".into(), Value::Bytes(vec![0xAB; 16])),
            ("sequence".into(), Value::Unsigned(0)),
            ("body".into(), Value::Map(body_entries)),
        ])
        .encode()
        .unwrap()
    }

    #[test]
    fn unknown_message_types_and_fields_are_schema_violations() {
        let unknown_type = envelope_value(vec![], "operation.mystery");
        assert_eq!(
            Envelope::decode(&unknown_type),
            Err(SchemaViolation::UnknownMessageType)
        );
        let extra_field = envelope_value(
            vec![
                ("reason".into(), Value::Text("denied".into())),
                ("surprise".into(), Value::Unsigned(1)),
            ],
            "pairing.abort",
        );
        assert_eq!(
            Envelope::decode(&extra_field),
            Err(SchemaViolation::UnknownField)
        );
        let missing_field = envelope_value(vec![], "pairing.abort");
        assert_eq!(
            Envelope::decode(&missing_field),
            Err(SchemaViolation::MissingField)
        );
    }

    #[test]
    fn unknown_critical_entries_are_rejected_and_extensions_ignored() {
        let with_critical = Value::Map(vec![
            (
                "version".into(),
                Value::Array(vec![
                    Value::Unsigned(0),
                    Value::Unsigned(1),
                    Value::Unsigned(2),
                ]),
            ),
            ("type".into(), Value::Text("pairing.abort".into())),
            ("session_id".into(), Value::Bytes(vec![0xAB; 16])),
            ("sequence".into(), Value::Unsigned(0)),
            (
                "body".into(),
                Value::Map(vec![("reason".into(), Value::Text("denied".into()))]),
            ),
            (
                "critical".into(),
                Value::Array(vec![Value::Text("novel".into())]),
            ),
        ])
        .encode()
        .unwrap();
        assert_eq!(
            Envelope::decode(&with_critical),
            Err(SchemaViolation::UnknownCriticalField)
        );

        let with_extension = Value::Map(vec![
            (
                "version".into(),
                Value::Array(vec![
                    Value::Unsigned(0),
                    Value::Unsigned(1),
                    Value::Unsigned(2),
                ]),
            ),
            ("type".into(), Value::Text("pairing.abort".into())),
            ("session_id".into(), Value::Bytes(vec![0xAB; 16])),
            ("sequence".into(), Value::Unsigned(0)),
            (
                "body".into(),
                Value::Map(vec![("reason".into(), Value::Text("denied".into()))]),
            ),
            (
                "extensions".into(),
                Value::Map(vec![("novel".into(), Value::Unsigned(1))]),
            ),
        ])
        .encode()
        .unwrap();
        assert!(Envelope::decode(&with_extension).is_ok());
    }

    #[test]
    fn unregistered_discriminants_are_rejected() {
        let bad_reason = envelope_value(
            vec![
                ("reason".into(), Value::Text("novel_reason".into())),
                ("last_received_sequence".into(), Value::Unsigned(0)),
            ],
            "session.close",
        );
        assert_eq!(
            Envelope::decode(&bad_reason),
            Err(SchemaViolation::UnknownDiscriminant)
        );
    }

    #[test]
    fn wrong_identifier_sizes_are_rejected() {
        let short_id = envelope_value(
            vec![("operation_id".into(), Value::Bytes(vec![1; 8]))],
            "operation.status_request",
        );
        assert_eq!(
            Envelope::decode(&short_id),
            Err(SchemaViolation::WrongFieldType)
        );
    }
}
