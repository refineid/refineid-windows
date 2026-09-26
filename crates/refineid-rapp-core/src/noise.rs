//! Noise channels of specification Section 8.
//!
//! Pairing runs `Noise_XXpsk3_25519_ChaChaPoly_SHA256` with the offer's
//! bearer secret as the third-message pre-shared key; sessions run
//! `Noise_KK_25519_ChaChaPoly_SHA256` with the stored pair-specific static
//! keys. Every handshake binds a prologue both peers can compute before the
//! handshake begins (Section 8.3), and every handshake message carries an
//! empty payload; a non-empty payload aborts, because nothing before the
//! pre-shared key is mixed authenticates the peer.
//!
//! A completed handshake yields the handshake hash for the derived
//! identifiers of Section 8.5 and a [`SecureChannel`] that moves exactly one
//! encrypted envelope per frame.

use zeroize::Zeroizing;

use crate::cbor::Value;
use crate::ids::{PairId, PairingSecret};
use crate::limits;
use crate::transport::{FrameTransport, TransportError};
use crate::{PAIRING_SUITE, SESSION_SUITE};

/// Domain string of the pairing prologue array.
const PAIRING_PROLOGUE_DOMAIN: &str = "RAPP-pairing-v1";
/// Domain string of the session prologue array.
const SESSION_PROLOGUE_DOMAIN: &str = "RAPP-session-v1";
/// The pre-shared key slot of `Noise_XXpsk3`.
const PAIRING_PSK_SLOT: u8 = 3;

/// Why a handshake did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// The transport failed, ended, or timed out.
    Transport(TransportError),
    /// A received handshake message carried a non-empty payload.
    NonEmptyHandshakePayload,
    /// The handshake failed cryptographically or structurally.
    Failed,
    /// A prologue component exceeded an encoding limit.
    Prologue,
}

/// Why an established channel could not move a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelError {
    /// The transport failed, ended, or timed out.
    Transport(TransportError),
    /// A frame failed authenticated decryption or framing: the
    /// session-integrity failure of policy class 2.
    Integrity,
    /// A plaintext exceeded [`limits::MAX_FRAME_PLAINTEXT`].
    PlaintextTooLarge,
}

/// A fresh pair-specific X25519 key pair (Section 8.2).
pub struct PairKeys {
    /// The private key, destroyed on drop.
    pub private: Zeroizing<Vec<u8>>,
    /// The public key transmitted inside the pairing handshake.
    pub public: Vec<u8>,
}

impl core::fmt::Debug for PairKeys {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PairKeys(private redacted)")
    }
}

/// Generates a fresh pair-specific static key pair.
///
/// # Errors
///
/// Fails only when key generation is unavailable.
pub fn generate_pair_keys() -> Result<PairKeys, HandshakeError> {
    let builder = snow::Builder::new(pairing_parameters()?);
    let keypair = builder
        .generate_keypair()
        .map_err(|_| HandshakeError::Failed)?;
    Ok(PairKeys {
        private: Zeroizing::new(keypair.private),
        public: keypair.public,
    })
}

/// Parses the mandatory pairing suite name.
fn pairing_parameters() -> Result<snow::params::NoiseParams, HandshakeError> {
    PAIRING_SUITE.parse().map_err(|_| HandshakeError::Failed)
}

/// Parses the mandatory session suite name.
fn session_parameters() -> Result<snow::params::NoiseParams, HandshakeError> {
    SESSION_SUITE.parse().map_err(|_| HandshakeError::Failed)
}

/// The deterministic-CBOR pairing prologue of Section 8.3.
///
/// # Errors
///
/// Fails only when a component exceeds an encoding limit.
pub fn pairing_prologue(
    version: (u64, u64, u64),
    offer_hash: &[u8; 32],
    transport_profile: &str,
) -> Result<Vec<u8>, HandshakeError> {
    Value::Array(vec![
        Value::Text(PAIRING_PROLOGUE_DOMAIN.into()),
        Value::Array(vec![
            Value::Unsigned(version.0),
            Value::Unsigned(version.1),
            Value::Unsigned(version.2),
        ]),
        Value::Text(PAIRING_SUITE.into()),
        Value::Bytes(offer_hash.to_vec()),
        Value::Text(transport_profile.into()),
    ])
    .encode()
    .map_err(|_| HandshakeError::Prologue)
}

/// The deterministic-CBOR session prologue of Section 8.3.
///
/// # Errors
///
/// Fails only when a component exceeds an encoding limit.
pub fn session_prologue(
    version: (u64, u64, u64),
    pair_id: PairId,
    grants_hash: &[u8; 32],
    transport_profile: &str,
) -> Result<Vec<u8>, HandshakeError> {
    Value::Array(vec![
        Value::Text(SESSION_PROLOGUE_DOMAIN.into()),
        Value::Array(vec![
            Value::Unsigned(version.0),
            Value::Unsigned(version.1),
            Value::Unsigned(version.2),
        ]),
        Value::Text(SESSION_SUITE.into()),
        Value::Bytes(pair_id.0.to_vec()),
        Value::Bytes(grants_hash.to_vec()),
        Value::Text(transport_profile.into()),
    ])
    .encode()
    .map_err(|_| HandshakeError::Prologue)
}

/// What a completed handshake hands to the layer above.
pub struct CompletedHandshake<Transport: FrameTransport> {
    /// The encrypted channel.
    pub channel: SecureChannel<Transport>,
    /// The Noise handshake hash for the derived identifiers of Section 8.5.
    pub handshake_hash: Vec<u8>,
    /// The peer's static public key, present after a pairing handshake.
    pub peer_static_public: Option<Vec<u8>>,
}

impl<Transport: FrameTransport> core::fmt::Debug for CompletedHandshake<Transport> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CompletedHandshake")
    }
}

/// The two ends of a handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRole {
    /// The requester is always the Noise initiator (Sections 3.1 and 3.2).
    Initiator,
    /// The proxy is always the Noise responder.
    Responder,
}

/// Runs the pairing handshake over a transport.
///
/// The bearer secret is consumed here: its only protocol purpose is the
/// pre-shared key of this handshake, and dropping it on return implements
/// the destruction Section 9.3 step 5 requires.
///
/// # Errors
///
/// Fails on transport loss, a non-empty handshake payload, or cryptographic
/// failure. Per Section 9.3 a failed pairing handshake does not consume the
/// offer; that policy lives with the caller.
pub fn run_pairing_handshake<Transport: FrameTransport>(
    role: HandshakeRole,
    transport: Transport,
    local_keys: &PairKeys,
    pairing_secret: PairingSecret,
    prologue: &[u8],
) -> Result<CompletedHandshake<Transport>, HandshakeError> {
    let builder = snow::Builder::new(pairing_parameters()?)
        .prologue(prologue)
        .map_err(|_| HandshakeError::Failed)?
        .local_private_key(&local_keys.private)
        .map_err(|_| HandshakeError::Failed)?
        .psk(PAIRING_PSK_SLOT, &pairing_secret.0)
        .map_err(|_| HandshakeError::Failed)?;
    let state = match role {
        HandshakeRole::Initiator => builder.build_initiator(),
        HandshakeRole::Responder => builder.build_responder(),
    }
    .map_err(|_| HandshakeError::Failed)?;
    drop(pairing_secret);
    run_handshake(state, transport, true)
}

/// Runs the session handshake over a transport with stored pair keys.
///
/// # Errors
///
/// Fails on transport loss, a non-empty handshake payload, or cryptographic
/// failure — including the peer not holding the expected pair key, which is
/// how a revoked peer is discovered (Section 14.6).
pub fn run_session_handshake<Transport: FrameTransport>(
    role: HandshakeRole,
    transport: Transport,
    local_private: &[u8],
    peer_public: &[u8],
    prologue: &[u8],
) -> Result<CompletedHandshake<Transport>, HandshakeError> {
    let builder = snow::Builder::new(session_parameters()?)
        .prologue(prologue)
        .map_err(|_| HandshakeError::Failed)?
        .local_private_key(local_private)
        .map_err(|_| HandshakeError::Failed)?
        .remote_public_key(peer_public)
        .map_err(|_| HandshakeError::Failed)?;
    let state = match role {
        HandshakeRole::Initiator => builder.build_initiator(),
        HandshakeRole::Responder => builder.build_responder(),
    }
    .map_err(|_| HandshakeError::Failed)?;
    run_handshake(state, transport, false)
}

/// Drives a handshake to completion with empty payloads in both directions.
fn run_handshake<Transport: FrameTransport>(
    mut state: snow::HandshakeState,
    mut transport: Transport,
    expect_peer_static: bool,
) -> Result<CompletedHandshake<Transport>, HandshakeError> {
    let mut buffer = vec![0u8; limits::NOISE_MAX_MESSAGE];
    while !state.is_handshake_finished() {
        if state.is_my_turn() {
            let length = state
                .write_message(&[], &mut buffer)
                .map_err(|_| HandshakeError::Failed)?;
            transport
                .send_frame(&buffer[..length])
                .map_err(HandshakeError::Transport)?;
        } else {
            let frame = transport
                .receive_frame()
                .map_err(HandshakeError::Transport)?;
            let payload_length = state
                .read_message(&frame, &mut buffer)
                .map_err(|_| HandshakeError::Failed)?;
            if payload_length != 0 {
                return Err(HandshakeError::NonEmptyHandshakePayload);
            }
        }
    }
    let handshake_hash = state.get_handshake_hash().to_vec();
    let peer_static_public = state.get_remote_static().map(<[u8]>::to_vec);
    if expect_peer_static && peer_static_public.is_none() {
        return Err(HandshakeError::Failed);
    }
    let noise = state
        .into_transport_mode()
        .map_err(|_| HandshakeError::Failed)?;
    Ok(CompletedHandshake {
        channel: SecureChannel { transport, noise },
        handshake_hash,
        peer_static_public,
    })
}

/// An established Noise channel moving one envelope per frame.
pub struct SecureChannel<Transport: FrameTransport> {
    transport: Transport,
    noise: snow::TransportState,
}

impl<Transport: FrameTransport> core::fmt::Debug for SecureChannel<Transport> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecureChannel")
    }
}

impl<Transport: FrameTransport> SecureChannel<Transport> {
    /// Encrypts and sends one plaintext as one frame.
    ///
    /// # Errors
    ///
    /// Fails when the plaintext exceeds the frame ceiling or the transport
    /// is unusable.
    pub fn send_plaintext(&mut self, plaintext: &[u8]) -> Result<(), ChannelError> {
        if plaintext.len() > limits::MAX_FRAME_PLAINTEXT {
            return Err(ChannelError::PlaintextTooLarge);
        }
        let mut buffer = vec![0u8; limits::NOISE_MAX_MESSAGE];
        let length = self
            .noise
            .write_message(plaintext, &mut buffer)
            .map_err(|_| ChannelError::Integrity)?;
        self.transport
            .send_frame(&buffer[..length])
            .map_err(ChannelError::Transport)
    }

    /// Receives and decrypts the next frame.
    ///
    /// A frame that fails authenticated decryption is the session-integrity
    /// failure of policy class 2: the caller closes the session and the
    /// pairing is untouched.
    ///
    /// # Errors
    ///
    /// Fails on transport loss or authenticated-decryption failure.
    pub fn receive_plaintext(&mut self) -> Result<Vec<u8>, ChannelError> {
        let frame = self
            .transport
            .receive_frame()
            .map_err(ChannelError::Transport)?;
        let mut buffer = vec![0u8; limits::NOISE_MAX_MESSAGE];
        let length = self
            .noise
            .read_message(&frame, &mut buffer)
            .map_err(|_| ChannelError::Integrity)?;
        buffer.truncate(length);
        Ok(buffer)
    }

    /// The transport profile name of the underlying channel.
    pub fn transport_profile(&self) -> &str {
        self.transport.profile()
    }

    /// The candidate identifier of the underlying channel.
    pub fn candidate_id(&self) -> &str {
        self.transport.candidate_id()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::time::Duration;

    use super::{
        HandshakeError, HandshakeRole, generate_pair_keys, pairing_prologue, run_pairing_handshake,
        run_session_handshake, session_prologue,
    };
    use crate::ids::{PairingSecret, derive_pair_id, derive_session_id};
    use crate::transport::MemoryTransport;
    use crate::{WIRE_VERSION, transport::MEMORY_PROFILE};

    fn paired_keys() -> (super::PairKeys, super::PairKeys) {
        (generate_pair_keys().unwrap(), generate_pair_keys().unwrap())
    }

    #[test]
    fn pairing_handshake_completes_and_agrees() {
        let (requester_transport, proxy_transport) =
            MemoryTransport::pair("m-h", Duration::from_millis(500));
        let (requester_keys, proxy_keys) = paired_keys();
        let offer_hash = [7u8; 32];
        let prologue = pairing_prologue(WIRE_VERSION, &offer_hash, MEMORY_PROFILE).unwrap();
        let proxy_prologue = prologue.clone();
        let proxy_thread = std::thread::spawn(move || {
            run_pairing_handshake(
                HandshakeRole::Responder,
                proxy_transport,
                &proxy_keys,
                PairingSecret([9u8; 32]),
                &proxy_prologue,
            )
            .map(|done| {
                (
                    done.handshake_hash,
                    done.peer_static_public,
                    proxy_keys.public.clone(),
                )
            })
        });
        let requester_done = run_pairing_handshake(
            HandshakeRole::Initiator,
            requester_transport,
            &requester_keys,
            PairingSecret([9u8; 32]),
            &prologue,
        )
        .unwrap();
        let (proxy_hash, proxy_seen_static, proxy_public) = proxy_thread.join().unwrap().unwrap();
        assert_eq!(requester_done.handshake_hash, proxy_hash);
        assert_eq!(
            requester_done.peer_static_public.as_deref(),
            Some(proxy_public.as_slice())
        );
        assert_eq!(
            proxy_seen_static.as_deref(),
            Some(requester_keys.public.as_slice())
        );
        assert_eq!(
            derive_pair_id(&requester_done.handshake_hash),
            derive_pair_id(&proxy_hash)
        );
    }

    #[test]
    fn wrong_pairing_secret_fails_without_completing() {
        let (requester_transport, proxy_transport) =
            MemoryTransport::pair("m-w", Duration::from_millis(500));
        let (requester_keys, proxy_keys) = paired_keys();
        let prologue = pairing_prologue(WIRE_VERSION, &[7u8; 32], MEMORY_PROFILE).unwrap();
        let proxy_prologue = prologue.clone();
        let proxy_thread = std::thread::spawn(move || {
            run_pairing_handshake(
                HandshakeRole::Responder,
                proxy_transport,
                &proxy_keys,
                PairingSecret([1u8; 32]),
                &proxy_prologue,
            )
            .map(|_| ())
        });
        let requester = run_pairing_handshake(
            HandshakeRole::Initiator,
            requester_transport,
            &requester_keys,
            PairingSecret([2u8; 32]),
            &prologue,
        );
        assert!(requester.is_err() || proxy_thread.join().unwrap().is_err());
    }

    #[test]
    fn session_handshake_requires_the_stored_pair_keys() {
        let (requester_keys, proxy_keys) = paired_keys();
        let grants_hash = [3u8; 32];
        let pair_id = derive_pair_id(&[5u8; 32]);
        let prologue =
            session_prologue(WIRE_VERSION, pair_id, &grants_hash, MEMORY_PROFILE).unwrap();

        // With the stored keys the session completes and both sides derive
        // one session identifier.
        let (requester_transport, proxy_transport) =
            MemoryTransport::pair("m-s", Duration::from_millis(500));
        let proxy_prologue = prologue.clone();
        let proxy_private = proxy_keys.private.clone();
        let requester_public = requester_keys.public.clone();
        let proxy_thread = std::thread::spawn(move || {
            run_session_handshake(
                HandshakeRole::Responder,
                proxy_transport,
                &proxy_private,
                &requester_public,
                &proxy_prologue,
            )
            .map(|done| done.handshake_hash)
        });
        let requester_done = run_session_handshake(
            HandshakeRole::Initiator,
            requester_transport,
            &requester_keys.private,
            &proxy_keys.public,
            &prologue,
        )
        .unwrap();
        let proxy_hash = proxy_thread.join().unwrap().unwrap();
        assert_eq!(
            derive_session_id(&requester_done.handshake_hash),
            derive_session_id(&proxy_hash)
        );

        // With a different key on one side the handshake fails: this is how
        // a peer that revoked with no channel is discovered.
        let (requester_transport, proxy_transport) =
            MemoryTransport::pair("m-x", Duration::from_millis(500));
        let stranger = generate_pair_keys().unwrap();
        let proxy_prologue = prologue.clone();
        let proxy_private = proxy_keys.private.clone();
        let stranger_public = stranger.public;
        let proxy_thread = std::thread::spawn(move || {
            run_session_handshake(
                HandshakeRole::Responder,
                proxy_transport,
                &proxy_private,
                &stranger_public,
                &proxy_prologue,
            )
            .map(|_| ())
        });
        let requester = run_session_handshake(
            HandshakeRole::Initiator,
            requester_transport,
            &requester_keys.private,
            &proxy_keys.public,
            &prologue,
        );
        assert!(requester.is_err() || proxy_thread.join().unwrap().is_err());
    }

    #[test]
    fn established_channel_moves_and_protects_plaintext() {
        let (requester_transport, proxy_transport) =
            MemoryTransport::pair("m-c", Duration::from_millis(500));
        let (requester_keys, proxy_keys) = paired_keys();
        let prologue = pairing_prologue(WIRE_VERSION, &[4u8; 32], MEMORY_PROFILE).unwrap();
        let proxy_prologue = prologue.clone();
        let proxy_thread = std::thread::spawn(move || {
            let mut done = run_pairing_handshake(
                HandshakeRole::Responder,
                proxy_transport,
                &proxy_keys,
                PairingSecret([6u8; 32]),
                &proxy_prologue,
            )
            .unwrap();
            let received = done.channel.receive_plaintext().unwrap();
            done.channel.send_plaintext(&received).unwrap();
        });
        let mut requester = run_pairing_handshake(
            HandshakeRole::Initiator,
            requester_transport,
            &requester_keys,
            PairingSecret([6u8; 32]),
            &prologue,
        )
        .unwrap();
        requester.channel.send_plaintext(b"envelope").unwrap();
        assert_eq!(requester.channel.receive_plaintext().unwrap(), b"envelope");
        proxy_thread.join().unwrap();
    }

    #[test]
    fn mismatched_prologue_fails_the_handshake() {
        let (requester_transport, proxy_transport) =
            MemoryTransport::pair("m-p", Duration::from_millis(500));
        let (requester_keys, proxy_keys) = paired_keys();
        let requester_prologue =
            pairing_prologue(WIRE_VERSION, &[1u8; 32], MEMORY_PROFILE).unwrap();
        let proxy_prologue = pairing_prologue(WIRE_VERSION, &[2u8; 32], MEMORY_PROFILE).unwrap();
        let proxy_thread = std::thread::spawn(move || {
            run_pairing_handshake(
                HandshakeRole::Responder,
                proxy_transport,
                &proxy_keys,
                PairingSecret([8u8; 32]),
                &proxy_prologue,
            )
            .map(|_| ())
        });
        let requester = run_pairing_handshake(
            HandshakeRole::Initiator,
            requester_transport,
            &requester_keys,
            PairingSecret([8u8; 32]),
            &requester_prologue,
        );
        assert!(requester.is_err() || proxy_thread.join().unwrap().is_err());
        let _ = HandshakeError::Failed;
    }
}
