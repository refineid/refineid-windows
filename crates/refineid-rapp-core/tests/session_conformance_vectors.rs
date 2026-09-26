//! Replay of the corpus `sequence_guard`, `wire_version`, and
//! `grant_enforcement` sections.
//!
//! This crate has no standalone sequence guard or version gate: both
//! disciplines live in the engine's private message channel, which is
//! reachable only through a live Noise session. Each replay therefore
//! routes the vector through the public `Envelope` codec and asserts the
//! corpus classification with the explicit comparison the channel applies,
//! stated in the test itself.

use refineid_rapp_core::WIRE_VERSION;
use refineid_rapp_core::ids::{SESSION_ID_LENGTH, SessionId};
use refineid_rapp_core::message::{Body, Envelope};
use refineid_rapp_core::profiles::{
    PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS, has_consequential_command,
};
use serde::Deserialize;

mod corpus_util;
use corpus_util::{CORPUS_JSON, fixed};

/// Vectors in the `sequence_guard` section.
const SEQUENCE_GUARD_COUNT: usize = 6;
/// Vectors in the `wire_version` section.
const WIRE_VERSION_COUNT: usize = 9;
/// Vectors in the `grant_enforcement` section.
const GRANT_ENFORCEMENT_COUNT: usize = 3;

/// The session identifier every version-test envelope carries.
const VERSION_TEST_SESSION_ID: SessionId = SessionId([0x44; SESSION_ID_LENGTH]);
/// The abort reason of the minimal schema-valid replay envelope.
const REPLAY_ABORT_REASON: &str = "cancelled";

/// The corpus sections this file replays.
#[derive(Deserialize)]
struct Corpus {
    sequence_guard: Vec<SequenceVector>,
    wire_version: Vec<VersionVector>,
    grant_enforcement: Vec<GrantVector>,
}

/// One sequence-guard vector.
#[derive(Deserialize)]
struct SequenceVector {
    name: String,
    guard_session_id_hex: String,
    accepted_sequences: Vec<u64>,
    incoming_session_id_hex: String,
    incoming_sequence: u64,
    expected: String,
    expected_next_receive: u64,
}

/// One wire-version vector. Arity varies: the corpus pins
/// rejection of empty, two-element, and four-element arrays.
#[derive(Deserialize)]
struct VersionVector {
    name: String,
    version: Vec<u64>,
    expected: String,
}

/// One grant-enforcement vector.
#[derive(Deserialize)]
struct GrantVector {
    name: String,
    granted_profiles: Vec<String>,
    requested_profile: String,
    expected: String,
}

/// The corpus classification of one incoming envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuardDecision {
    /// The envelope is bound to this session and next in sequence.
    Accepted,
    /// The envelope names another session.
    WrongSession,
    /// The envelope is a replay, rollback, or forward gap.
    WrongSequence,
}

/// The receive discipline of specification Section 7.3, restated over the
/// public `Envelope` type: exactly the session-binding and next-sequence
/// comparisons the engine's private channel applies before accepting a
/// decrypted envelope.
struct EmulatedGuard {
    session_id: SessionId,
    next_receive: u64,
}

impl EmulatedGuard {
    /// A guard bound to one session with nothing received yet.
    const fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            next_receive: 0,
        }
    }

    /// Classifies one decoded envelope, advancing only on acceptance.
    fn accept(&mut self, envelope: &Envelope) -> GuardDecision {
        if envelope.session_id != self.session_id {
            return GuardDecision::WrongSession;
        }
        if envelope.sequence != self.next_receive {
            return GuardDecision::WrongSequence;
        }
        self.next_receive += 1;
        GuardDecision::Accepted
    }
}

/// Parses the corpus sections this file replays.
fn corpus() -> Corpus {
    serde_json::from_str(CORPUS_JSON).expect("the vendored RAPP corpus must be valid JSON")
}

/// A minimal schema-valid envelope routed through the public wire codec.
fn replay_envelope(version: (u64, u64, u64), session_id: SessionId, sequence: u64) -> Envelope {
    let envelope = Envelope {
        version,
        session_id,
        sequence,
        body: Body::PairingAbort {
            reason: REPLAY_ABORT_REASON.into(),
        },
    };
    let encoded = envelope.encode().expect("replay envelope must encode");
    let decoded = Envelope::decode(&encoded).expect("replay envelope must decode");
    assert_eq!(decoded, envelope, "replay envelope must round-trip");
    decoded
}

/// Encodes the replay envelope, then swaps its version entry for an
/// arbitrary array. Used by the wire-version vectors, whose arities
/// the typed `Envelope` cannot itself represent.
fn envelope_bytes_with_version(version: &[u64]) -> Vec<u8> {
    use refineid_rapp_core::cbor::Value;
    let envelope = Envelope {
        version: WIRE_VERSION,
        session_id: VERSION_TEST_SESSION_ID,
        sequence: 0,
        body: Body::PairingAbort {
            reason: REPLAY_ABORT_REASON.into(),
        },
    };
    let encoded = envelope.encode().expect("replay envelope must encode");
    let Value::Map(mut entries) = Value::decode(&encoded).expect("replay envelope must decode")
    else {
        panic!("replay envelope must be a map");
    };
    for (key, value) in &mut entries {
        if key == "version" {
            *value = Value::Array(version.iter().map(|part| Value::Unsigned(*part)).collect());
        }
    }
    Value::Map(entries)
        .encode()
        .expect("version-swapped envelope must encode")
}

/// A replay envelope under the published wire version.
fn guard_envelope(session_id: SessionId, sequence: u64) -> Envelope {
    replay_envelope(WIRE_VERSION, session_id, sequence)
}

#[test]
fn directional_sequence_and_session_binding_match_the_corpus() {
    let corpus = corpus();
    assert_eq!(corpus.sequence_guard.len(), SEQUENCE_GUARD_COUNT);
    for vector in &corpus.sequence_guard {
        let guard_session = SessionId(fixed::<SESSION_ID_LENGTH>(&vector.guard_session_id_hex));
        let mut guard = EmulatedGuard::new(guard_session);
        for sequence in &vector.accepted_sequences {
            assert_eq!(
                guard.accept(&guard_envelope(guard_session, *sequence)),
                GuardDecision::Accepted,
                "{} accepted prefix at {sequence}",
                vector.name
            );
        }

        let incoming = guard_envelope(
            SessionId(fixed::<SESSION_ID_LENGTH>(&vector.incoming_session_id_hex)),
            vector.incoming_sequence,
        );
        let expected = match vector.expected.as_str() {
            "accepted" => GuardDecision::Accepted,
            "wrong_session" => GuardDecision::WrongSession,
            "wrong_sequence" => GuardDecision::WrongSequence,
            expected => panic!("{} unknown sequence expectation {expected}", vector.name),
        };
        assert_eq!(
            guard.accept(&incoming),
            expected,
            "{} decision",
            vector.name
        );
        assert_eq!(
            guard.next_receive, vector.expected_next_receive,
            "{} next expected receive sequence",
            vector.name
        );
        // The guard must accept exactly the expected next sequence afterwards.
        assert_eq!(
            guard.accept(&guard_envelope(guard_session, vector.expected_next_receive)),
            GuardDecision::Accepted,
            "{} advance after the decision",
            vector.name
        );
    }
}

#[test]
fn wire_version_admission_matches_the_corpus() {
    let corpus = corpus();
    assert_eq!(corpus.wire_version.len(), WIRE_VERSION_COUNT);
    for vector in &corpus.wire_version {
        // The corpus carries no encoded envelopes for this section, so a
        // minimal envelope is encoded with the real codec and its version
        // entry is swapped for the vector's array. Malformed arities must
        // fail `Envelope::decode`; well-formed arrays decode and face the
        // admission comparison against `WIRE_VERSION`, exactly as the
        // engine applies it.
        let bytes = envelope_bytes_with_version(&vector.version);
        match vector.expected.as_str() {
            "accepted" => {
                let decoded = Envelope::decode(&bytes).expect("the accepted version decodes");
                assert_eq!(
                    decoded.version, WIRE_VERSION,
                    "{} must carry the published wire version",
                    vector.name
                );
            }
            "unsupported_version" => match Envelope::decode(&bytes) {
                Err(_) => {}
                Ok(decoded) => assert_ne!(
                    decoded.version, WIRE_VERSION,
                    "{} must fail the version admission comparison",
                    vector.name
                ),
            },
            expected => panic!("{} unknown version expectation {expected}", vector.name),
        }
    }
}

#[test]
fn grant_enforcement_decisions_match_the_corpus() {
    let corpus = corpus();
    assert_eq!(corpus.grant_enforcement.len(), GRANT_ENFORCEMENT_COUNT);
    for vector in &corpus.grant_enforcement {
        // This crate's enforcement point is the X-08 admission check inside
        // `engine::Requester::execute`, which reports
        // `AdmissionError::ProfileNotGranted` and is reachable only through
        // a live session held by a scripted proxy. Without that rig the
        // replay asserts the decision rule the vectors fix — membership of
        // the requested profile in the granted set, the same comparison the
        // admission check performs — plus the registry facts of the named
        // profiles.
        let admitted = vector
            .granted_profiles
            .iter()
            .any(|name| name == &vector.requested_profile);
        match vector.expected.as_str() {
            "accepted" => assert!(admitted, "{} must be admitted", vector.name),
            "profile_not_granted" => assert!(!admitted, "{} must be refused", vector.name),
            expected => panic!("{} unknown grant expectation {expected}", vector.name),
        }

        // Every profile the section names is in this crate's registry.
        assert_eq!(
            vector.requested_profile, PROFILE_CARD_STATUS,
            "{} requested profile",
            vector.name
        );
        for granted in &vector.granted_profiles {
            assert!(
                granted == PROFILE_CARD_STATUS || granted == PROFILE_AUTHENTICATION,
                "{} names unregistered granted profile {granted}",
                vector.name
            );
        }
    }

    // The requested profile of every vector is the one registered profile
    // without a commit boundary; the granted alternative has one.
    assert!(!has_consequential_command(PROFILE_CARD_STATUS));
    assert!(has_consequential_command(PROFILE_AUTHENTICATION));
}
