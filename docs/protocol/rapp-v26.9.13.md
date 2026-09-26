# Remote Authorization Proxy Protocol (RAPP)

Status: External-review draft  
Intended status: Experimental  
Document version: 26.9.13  
Supersedes: 26.9.7.70  
Protocol wire version: 26.9.13  
Date: 2026-09-13  
Change controller: RefineID project  
Companion model: [RAPP state machine 26.9.13](rapp-state-machine-v26.9.13.yaml)  
Conformance corpus: [RAPP vectors 26.9.13](vectors/rapp-v26.9.13.json)

## Abstract

The Remote Authorization Proxy Protocol (RAPP) lets a requester use a
credential held by another device without exporting the credential's private
key or its access codes. A typical deployment has a computer requesting a TLS
client-authentication signature, a phone acting as the authorization proxy,
and an identity card communicating with the phone over NFC. The same protocol
is intended to support macOS, iOS, Android, Windows, Linux, FreeBSD, local
networks, and an untrusted Internet relay.

RAPP pairs devices through a manually initiated 6-digit numeric pairing code. It then
uses end-to-end mutually authenticated sessions independently of the selected
network transport. Every credential operation is typed, explicitly authorized
on the proxy, bound to one session and operation identifier, and executed at
most once. RAPP never exposes CAN, PIN, or PUK values to the requester. A card
rejection of CAN, PIN 1, or PIN 2 immediately terminates the RAPP session and
prohibits automatic recovery.

Network faults that cannot be attributed to the authenticated peer close at
most the current session. Destruction of a stored pairing requires either an
explicit local decision or a protocol violation proven to originate from the
authenticated peer.

This document defines the roles, trust boundaries, wire representation,
cryptographic construction, pairing and session protocols, operation model,
credential profiles, transport contract, distributed state machines, failure
semantics, user-visible behavior, privacy properties, extension rules, and
conformance requirements. It is a review draft, not a production-ready
standard.

## 1. Status and requirements language

This draft exists to obtain protocol, cryptographic, privacy, accessibility,
and interoperability review before independent implementations are trusted.
It intentionally makes unresolved decisions visible in Section 24.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and
**OPTIONAL** are to be interpreted as described by
[BCP 14](https://www.rfc-editor.org/info/bcp14) when they appear in capitals.

An implementation claiming conformance to this draft MUST implement the core
protocol, the mandatory cryptographic suite, the machine-readable transition
model including its unexpected-input policy, and at least one credential
profile and one transport profile. It MUST identify itself as an experimental
implementation. This draft MUST NOT be used as the sole basis for a production
security claim before external review and interoperability test vectors are
complete.

## 2. Design goals

RAPP has the following goals:

- keep private keys inside the credential holder;
- keep CAN, PIN, activation, and PUK values on the authorization proxy;
- require intelligible, explicit human authorization for consequential use;
- support authentication, document signing, activation, and PIN management
  through typed operations rather than arbitrary APDU tunneling;
- provide end-to-end confidentiality, integrity, mutual authentication,
  forward secrecy, downgrade resistance, and replay resistance;
- work over local, platform-native, and relayed transports without trusting a
  transport to establish RAPP identity;
- make connection and security state visible on both participating devices;
- fail stop on protocol anomalies proven to originate from the authenticated
  peer, while treating unattributable network faults as session-level events;
- prevent automatic repetition after ambiguous card completion;
- preserve a strict physical-transmission count for credential commands;
- minimize cross-service and cross-peer correlation; and
- make every legal state transition, and every unexpected-input class,
  executable by model-based tests.

### 2.1 Non-goals

RAPP is not:

- a generic remote APDU tunnel;
- card emulation;
- a remote desktop protocol;
- a secret synchronization protocol;
- a replacement for card, application, or relying-party policy;
- an availability guarantee against a party able to drop traffic;
- a recovery mechanism for a compromised requester or proxy; or
- permission for unattended or invisible signing.

## 3. Roles and trust boundaries

### 3.1 Requester

The **Requester** asks for a typed credential operation. Examples include a
browser authentication agent, a document-signing application, or an
administrator requesting a PIN-management operation. The requester is the
Noise initiator in RAPP 26.9.

### 3.2 Authorization Proxy

The **Authorization Proxy** presents the operation to the user, obtains any
required credential locally, communicates with the credential holder, and
returns only the profile-defined result. A phone is the expected first proxy.
The proxy is the Noise responder in RAPP 26.9.

### 3.3 Credential Holder

The **Credential Holder** contains or controls the private key and credential
retry counters. A Finnish identity card is the initial holder. It communicates
only with the authorization proxy, normally over NFC or a directly attached
reader.

### 3.4 Human Authorizer

The **Human Authorizer** controls pairing and approves operations on the
authorization proxy. Device possession alone is not consent to an operation.

### 3.5 Rendezvous Relay

The OPTIONAL **Rendezvous Relay** routes opaque RAPP ciphertext when peers
cannot communicate directly. The relay is outside the cryptographic trust
boundary. It MUST NOT receive pairing secrets, session keys, card access
codes, operation plaintext, card identifiers, certificates, or results. A
relay can delay or destroy sessions; it MUST NOT be able to destroy a stored
pairing.

### 3.6 Relying Party

The **Relying Party** consumes the result, such as a TLS service accepting a
client certificate or a verifier accepting a document signature. It is not a
RAPP peer unless it also implements the requester role.

### 3.7 Pairing is device trust, not card identity

A RAPP pairing identifies one requester installation and one proxy
installation. It MUST NOT imply that a particular card is present, activated,
usable, or owned by the same person at a later time. Card state is established
from a fresh, profile-defined inspection when an operation requires it.

## 4. Threat model

### 4.1 Adversary capabilities

RAPP assumes an adversary may:

- observe, delay, drop, duplicate, reorder, truncate, or inject network data;
- control the rendezvous relay and transport discovery infrastructure;
- cause ordinary network transitions and temporary loss;
- replay an old pairing code, handshake, frame, request, commit, or result;
- present an attacker-controlled pairing code to either user;
- connect to an advertised pairing transport without knowing the pairing secret derived from the code;
- submit malformed CBOR and unsupported extensions;
- attempt version, cipher-suite, profile, or transport downgrade;
- trigger concurrent sessions and duplicate operations;
- remove a card or interrupt NFC at any command boundary; and
- learn traffic timing, approximate sizes, and relay endpoints.

### 4.2 Assumptions

RAPP assumes:

- the user controls both device displays during initial pairing;
- the pairing code entry is not secretly observed by an attacker during pairing;
- each endpoint has a cryptographically secure random-number generator;
- each endpoint can protect a device-only, non-synchronized pairing key;
- the authorization proxy UI and credential transport are trusted while used;
- the credential holder correctly protects its private key and retry counters;
- cryptographic primitive implementations are correct; and
- compromised endpoints are outside the confidentiality guarantee.

### 4.3 Protected properties

RAPP protects operation confidentiality and integrity, peer authenticity after
pairing, operation freshness, typed authorization context, credential custody,
and at-most-once credential transmission. It limits a malicious paired
requester through explicit proxy consent and profile grants. It prevents an
unauthenticated party, including the relay, from consuming a pairing offer,
revoking a stored pairing, or learning pairing-payload content.

### 4.4 Explicit residual risks

RAPP cannot prevent denial of service, endpoint compromise, misleading context
provided by an unattested requester, shoulder-surfing of a pairing code, or
traffic analysis by a relay. A relay or on-path attacker can force any number
of session closures; RAPP bounds the damage to reconnection effort and never
to pairing loss. A profile MUST distinguish independently verified context
from requester-asserted display text.

## 5. Layered architecture

RAPP is divided into four layers:

1. **RAPP Core** defines pairing, secure sessions, framing, liveness,
   operations, failures, and extension rules.
2. **Credential Profiles** define typed requests, consent context, card
   interaction, results, and retry policy.
3. **Transport Profiles** provide an ordered, reliable frame channel and
   rendezvous without supplying RAPP identity.
4. **Presentation Policy** localizes and presents state, consent, warnings, and
   recovery without changing protocol semantics.

No transport certificate, Apple account, relay account, IP address, Bluetooth
identifier, or device name is a RAPP identity. The RAPP cryptographic handshake
is REQUIRED over every transport, including transports that are already
encrypted.

## 6. Identifiers and versioning

| Name | Size | Generation | Scope |
| --- | ---: | --- | --- |
| `offer_id` | 32 bytes | random | one pairing offer |
| `pairing_secret` | 32 bytes | random | one pairing offer |
| `pair_id` | 16 bytes | derived, Section 8.5 | one stored peer relationship |
| `session_id` | 16 bytes | derived, Section 8.5 | one authenticated channel |
| `operation_id` | 16 bytes | random | one semantic operation |
| `challenge` | 32 bytes | random | one liveness exchange |

Random identifiers are generated from a cryptographically secure
random-number generator. Derived identifiers are computed independently by
both peers from the Noise handshake hash as defined in Section 8.5; they are
never transmitted during the handshake that creates them.

Identifiers MUST NOT be derived from a card identifier, certificate, person,
account, hardware serial number, or globally stable device identifier.

The wire version is a two-element `[major, minor]` array. A major-version
difference is incompatible. A minor version may add non-critical fields only.
Version and capability selection are authenticated as part of the Noise
handshake transcript. RAPP 26.9 permits no silent downgrade and no 0-RTT
operation data.

## 7. Wire representation

### 7.1 Deterministic CBOR

RAPP uses CBOR as defined by [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html).
Every encoded object MUST satisfy the core deterministic encoding requirements
in RFC 8949 Section 4.2.1. Indefinite-length items, floating-point values,
duplicate map keys, invalid UTF-8, and unregistered CBOR tags are forbidden.

Text keys and text discriminants are intentional in this review draft. They
avoid anonymous numeric wire values and make packet review less error-prone.
An eventual compact registry MUST retain meaningful symbolic names in source.

### 7.2 Framing

A transport profile delivers bounded binary frames (Section 16). Frame content
depends on channel phase:

- before the Noise handshake completes, each frame is exactly one Noise
  handshake message;
- after the handshake completes, each frame is exactly one Noise transport
  message whose plaintext is one deterministic-CBOR `rapp-message` envelope.

Noise handshake message payloads MUST be empty (Section 8.3). There is no
plaintext RAPP message at any phase, and no RAPP message spans frames.

### 7.3 Common envelope

The plaintext of every post-handshake message has this CDDL shape. CDDL is
defined by [RFC 8610](https://www.rfc-editor.org/rfc/rfc8610.html).

```cddl
rapp-message = {
  "version": [uint, uint],
  "type": message-type,
  "session_id": bstr .size 16,
  "sequence": uint,
  "body": { * tstr => any },
  ? "critical": [* tstr],
  ? "extensions": { * tstr => any }
}

message-type =
    "pairing.hello"
  / "pairing.confirm"
  / "pairing.abort"
  / "session.ready"
  / "session.close"
  / "liveness.ping"
  / "liveness.pong"
  / "operation.request"
  / "operation.prepared"
  / "operation.commit"
  / "operation.cancel"
  / "operation.result"
  / "operation.result_ack"
  / "operation.status_request"
  / "operation.status"
  / "operation.progress"
  / "error"
```

Every registered message type has a normative body schema: pairing bodies in
Section 9.4, session bodies in Section 10, liveness bodies in Section 11,
operation bodies in Section 12, and the error body in Section 15. A conforming
implementation MUST NOT send a body field outside the schema except through
`extensions`.

`session_id` is the derived identifier of the current authenticated channel
(Section 8.5); this includes the pairing channel. `sequence` starts at zero
independently in each direction and increases by exactly one per message.

Because Noise transport nonces are strictly sequential, any frame that a
network element drops, duplicates, or reorders fails authenticated decryption
and is handled as a session-integrity failure (Section 14.5). A `sequence`
violation can therefore be observed only inside a successfully decrypted
frame, which makes it attributable to the authenticated peer: a gap,
duplicate, decrease, or wrap in `sequence`, or a `session_id` that does not
match the channel, is an authenticated protocol violation.

An implementation MUST reject an unknown field named in `critical`. It MAY
ignore an unknown non-critical extension. Unknown message types, wrong field
types, impossible values, and schema violations in a successfully decrypted
message are authenticated protocol violations, except where Section 14.5
defines a discard response for stale-reference races.

### 7.4 Resource limits

The following named limits apply:

| Limit | Draft value |
| --- | ---: |
| `NOISE_MAX_MESSAGE` | 65,535 bytes per frame |
| `MAX_FRAME_PLAINTEXT` | 65,519 bytes per envelope |
| `MAX_NESTING_DEPTH` | 8 containers |
| `MAX_TEXT_SIZE` | 4,096 UTF-8 bytes |
| `PAIRING_CODE_LENGTH` | 6 decimal digits (formatted in two 3-digit groups) |
| `MAX_OFFER_SIZE` | 1,024 bytes |
| `MAX_TRANSPORT_CANDIDATES` | 8 |
| `MAX_ACTIVE_OPERATIONS` | 1 per proxy |
| `OFFER_TTL_MAX` | 180,000 ms |

`MAX_FRAME_PLAINTEXT` equals the maximum Noise transport payload, so one
envelope always fits one frame. Credential profiles SHOULD transport digests
and bounded display metadata, not whole documents. A transport profile MUST
define an unambiguous length prefix and reject an oversized frame before
allocation.

## 8. Cryptographic construction

### 8.1 Mandatory draft suite

The mandatory suite is:

```text
Pairing: Noise_XXpsk3_25519_ChaChaPoly_SHA256
Session: Noise_KK_25519_ChaChaPoly_SHA256
```

The construction follows the [Noise Protocol Framework, revision
34](https://noiseprotocol.org/noise.html). X25519 is specified by
[RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html), ChaCha20-Poly1305 by
[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html), and HKDF-SHA-256 by
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).

The Noise revision currently labels itself official/unstable. Selection of
this exact construction is therefore provisional and is an explicit external
review question, not an assertion of production suitability.

### 8.2 Pair-specific keys

Each pairing MUST generate a fresh static X25519 key pair on each endpoint.
Static keys MUST NOT be reused with another peer. This provides pairwise device
identities and limits correlation. Private pairing keys MUST be stored in the
strongest device-only platform key store available, excluded from backup and
cloud synchronization, and inaccessible to extensions that do not require
them.

### 8.3 Transcript binding and handshake payloads

Every value in a Noise prologue MUST be known to both peers before the
handshake begins. The prologue is the deterministic-CBOR encoding of a
fixed-order array:

For the pairing handshake:

```cddl
pairing-prologue = [
  "RAPP-pairing-v1",
  [uint, uint],          ; wire version
  tstr,                  ; cryptographic suite name
  bstr .size 32,         ; offer_hash, Section 8.5
  tstr                   ; transport profile name
]
```

For a session handshake:

```cddl
session-prologue = [
  "RAPP-session-v1",
  [uint, uint],          ; wire version
  tstr,                  ; cryptographic suite name
  bstr .size 16,         ; pair_id, Section 8.5
  bstr .size 32,         ; grants_hash, Section 8.5
  tstr                   ; transport profile name
]
```

Changing any bound value makes the handshake fail. The selected transport
candidate is not in the prologue because a listening endpoint may not know
which advertised candidate an incoming connection used; the transport profile
MUST make the candidate identifier available to both endpoints, and it is
echoed and compared inside the first authenticated message of the channel
(`pairing.hello` or `session.ready`).

In `Noise_XXpsk3` the pre-shared key is mixed only at the third handshake
message, so earlier handshake payloads are readable or decryptable by an
active unauthenticated initiator. For this reason every RAPP handshake
message, in both patterns, MUST carry an empty payload. Names, platform
descriptions, grants, and parameter echoes are exchanged only after the
handshake completes, inside ordinary encrypted envelopes. A received
handshake message with a non-empty payload MUST abort the handshake.

### 8.4 Derived values are compared explicitly

Immediately after a handshake completes, each peer sends the first
authenticated message of the channel (`pairing.hello` or `session.ready`)
echoing the negotiated parameters it believes were bound. A mismatch is an
authenticated protocol violation. This detects implementation disagreement
that a transcript failure cannot explain to a user.

### 8.5 Derived identifiers and defined hashes

Let `h` be the Noise handshake hash of a completed handshake as defined by the
Noise framework. Both peers derive, in this order:

```text
session_id       = first 16 bytes of SHA-256("RAPP-session-id-v1" || h)
pair_id          = first 16 bytes of SHA-256("RAPP-pair-id-v1" || h)
rendezvous_token = first 16 bytes of SHA-256("RAPP-rendezvous-v1" || h)
```

`session_id` is derived from every completed handshake, including the pairing
handshake, and scopes the envelope of that channel. `pair_id` is derived only
from the pairing handshake and permanently names the stored relationship.
`rendezvous_token` is likewise derived only from the pairing handshake and is
stored beside the pairing for transport profiles that need pair-specific
rendezvous (Sections 16.1 and 17). It exists so that a transport can name a
pairing on the wire without ever exposing `pair_id`, which remains a local
identifier; the two values are computationally unlinkable without `h`.
Destroying a pairing destroys its rendezvous token.
Because `h` mixes the prologue, which contains `offer_hash` over content that
never crosses the network, a network observer cannot compute either value.

`offer_hash` is SHA-256 over the deterministic-CBOR encoding of the
`pairing-offer` map (Section 9.2) with the `pairing_secret` entry removed.
The bearer secret contributes to the handshake only as the pre-shared key.

`grants_hash` is SHA-256 over the deterministic-CBOR encoding of the array of
granted credential-profile names sorted lexicographically by their UTF-8
bytes. Both peers store it at pairing confirmation and bind it in every later
session prologue, so a grant mismatch fails the session handshake.

`request_hash` is SHA-256 over the deterministic-CBOR encoding of the
fixed-order array:

```cddl
request-hash-preimage = [
  "RAPP-request-v1",
  bstr .size 16,         ; session_id
  bstr .size 16,         ; operation_id
  tstr,                  ; profile
  tstr,                  ; action
  { * tstr => any },     ; context, as encoded on the wire
  { * tstr => any }      ; payload, as encoded on the wire
]
```

### 8.6 Key lifecycle

Pairing secrets and handshake ephemeral keys MUST be destroyed immediately
after their protocol purpose ends. Session traffic keys MUST be destroyed on
close, revocation, process termination, logout, or device lock.
Pairing-key deletion is required on forget or revocation, after
the best-effort peer notice of Section 14.6 has been attempted. A result
retained under Section 12.5 is protected by local platform storage encryption,
never by session keys. Secure deletion on flash storage is best effort;
encryption-at-rest keys and references MUST also be destroyed.

Session rekey limits will be set after cryptographic review. An implementation
MUST close rather than exceed a Noise nonce or a locally configured
conservative message limit.

## 9. Pairing protocol

### 9.1 Manual initiation

Pairing starts only after an explicit action on the requester. The requester
creates one offer and displays a 6-digit numeric pairing code (formatted as two
3-digit groups, e.g. `123 456`). Background discovery MUST NOT create a pairing
or extend an offer's life.

### 9.2 Pairing code and offer derivation

The pairing code is a 6-digit decimal number (`000000`–`999999`) generated randomly
by the initiating peer and entered manually on the other peer.

The offer identifier and pairing secret are deterministically derived from the code:
- `pairing_secret` = `SHA-256("refineid-rapp-pairing-secret-v1:" || code)`
- `offer_id` = `SHA-256("refineid-rapp-offer-id-v1:" || code)[0..16]`

When serialized for programmatic or URI transport, the offer encodes deterministic CBOR using a `rapp:` URI carrying base64url data without padding, as defined by
[RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html). Its logical content is:

```cddl
pairing-offer = {
  "scheme": "rapp",
  "version": [uint, uint],
  "offer_id": bstr .size 16,
  "pairing_secret": bstr .size 32,
  "suites": [1* tstr],
  "profiles": [1* tstr],
  "transports": [1* transport-candidate],
  "offer_ttl_ms": uint
}

transport-candidate = {
  "profile": tstr,
  "candidate_id": tstr,
  "parameters": { * tstr => any }
}
```

The encoded offer MUST NOT exceed `MAX_OFFER_SIZE`. `offer_ttl_ms` MUST NOT exceed
`OFFER_TTL_MAX`; each side independently clamps it to local policy, the
requester enforcing expiry with a monotonic clock and the proxy treating the
value as an upper-bound hint without trusting the sender's wall clock.

The pairing secret is a bearer secret. It MUST NOT be logged, copied to a
clipboard, synchronized, backed up, included in analytics, or retained after
its use as the handshake pre-shared key ends.

### 9.3 Pairing exchange

1. The requester creates an offer, enters `offer_active`, and displays the 6-digit pairing code.
2. The proxy user inputs the 6-digit code, and the proxy validates its structure, supported
   version, suite, profile intersection, and local transport policy.
3. The proxy selects exactly one offered transport candidate and connects.
   Logical Noise roles remain requester-initiator and proxy-responder
   regardless of which side opened the underlying socket.
4. The peers run the pairing Noise handshake with `pairing_secret` (derived from the code) as the
   `psk3` value, the prologue of Section 8.3, and empty handshake payloads.
5. When the handshake completes, both peers derive the channel identifiers of
   Section 8.5, and both destroy the pairing secret. The requester hides the
   pairing code and stops accepting further candidates for this offer.
6. Both peers exchange `pairing.hello`: the negotiated-parameter echo, a
   display name, a platform description, and the requester's requested
   profiles. Names are labels, not identities.
7. Both devices display the peer and the proposed grants. The proxy user
   selects the granted profile set; both devices then display it with an
   explicit confirmation control and exchange `pairing.confirm`. The two
   granted sets MUST be equal.
8. Only after both confirmations does each endpoint atomically store the
   pair-specific keys, `pair_id`, granted profiles, `grants_hash`, and local
   metadata. The pairing channel is then closed; operations use fresh
   sessions.
9. The requester invalidates the offer on the first completed authenticated
   handshake, user cancellation, or local monotonic expiry — and on nothing
   else.

A connection attempt that fails the handshake — including any attempt by a
party that does not know `pairing_secret` — is discarded without consuming
the offer: the requester returns to `offer_active` and continues to accept
candidates until the offer expires or is cancelled. The 256-bit secret makes
exhaustive guessing infeasible; the requester processes at most one handshake
at a time per offer and MAY rate-limit attempts. A denial or abort during
confirmation invalidates the offer and requires a new manual offer.

### 9.4 Pairing messages

Exchanged over the authenticated pairing channel:

```cddl
pairing-hello = {
  "parameters": negotiated-parameters,
  "display_name": tstr,
  "platform": tstr,
  ? "requested_profiles": [1* tstr]    ; sent by the requester
}

negotiated-parameters = {
  "version": [uint, uint],
  "suite": tstr,
  "offer_hash": bstr .size 32,
  "transport_profile": tstr,
  "candidate_id": tstr
}

pairing-confirm = {
  "granted_profiles": [1* tstr]
}

pairing-abort = {
  "reason": tstr
}
```

The granted set MUST be a subset of the intersection of the offer's profiles
and the requester's requested profiles. `pairing.abort` (or an authenticated
`session.close` on the pairing channel) before both confirmations destroys
the candidate keys, invalidates the offer, and returns both peers to
`unpaired`. A confirmation phase that exceeds local policy time aborts the
same way.

### 9.5 Pairing confirmation and out-of-band verification

The pairing secret derived from the 6-digit code authenticates the out-of-band
exchange. Both endpoints still require explicit confirmation to prevent an
unexpected peer from silently becoming trusted. A presentation profile MAY
derive an accessible comparison representation from the final Noise handshake
hash. Such a representation is an additional human check and MUST NOT reduce
the cryptographic entropy used by the protocol.

## 10. Session establishment

A paired requester opens a new transport only after explicit user or
application action. RAPP 26.9 does not automatically reconnect a closed
session.

1. The requester selects one mutually stored transport profile and initiates
   the session over it. Which endpoint opens the underlying connection is a
   property of the transport profile (Section 16): the requester dials on a
   profile whose stored candidate names a proxy-side rendezvous, and it
   accepts on a profile whose stored candidate names a requester-side
   listener. Logical Noise roles are unaffected by connection direction.
2. The accepting endpoint associates the connection with a stored pairing
   through the transport's pair-specific rendezvous (for example, its relay
   token, candidate parameters, or rendezvous preamble). If the transport
   cannot indicate the pairing and the accepting endpoint is the proxy, it
   MAY trial-process the first handshake message against each stored
   pairing; exactly one can authenticate. An accepting requester has no
   trial-processing option, because the requester sends the first handshake
   message; its transport profile MUST indicate the pairing before the
   handshake begins.
3. The peers run the mandatory `Noise_KK` handshake with their pair-specific
   static keys, fresh ephemeral keys, the session prologue of Section 8.3, and
   empty handshake payloads.
4. Both peers derive `session_id` (Section 8.5) and each sends an encrypted
   `session.ready`:

   ```cddl
   session-ready = {
     "parameters": session-parameters,
     "nonce": bstr .size 32
   }

   session-parameters = {
     "version": [uint, uint],
     "suite": tstr,
     "transport_profile": tstr,
     "candidate_id": tstr,
     "grants_hash": bstr .size 32
   }
   ```

5. The session becomes `healthy` only after each peer has verified that the
   received parameters equal its own view. A mismatch is an authenticated
   protocol violation.

No application operation is permitted during connection or authentication.
RAPP 26.9 has no 0-RTT data, session resumption, connection migration, or
mid-session transport fallback. A new transport requires a new session and
fresh handshake.

Only the requester initiates a normal session. If a proxy with a live session
for a pairing receives a second session attempt for the same pairing, it
completes the handshake, sends an authenticated `error` with name `busy`, and
closes the new session; the existing session is not displaced.

A `session.close` body is:

```cddl
session-close = {
  "reason": close-reason,
  "last_received_sequence": uint
}

close-reason =
    "user_disconnect"
  / "policy"
  / "credential_rejected"
  / "protocol_violation"
  / "pairing_revoked"
  / "shutdown"
```

A peer that receives `session.close` enters `closing`, stops sending
application messages, and completes its own close. The reasons
`pairing_revoked` and `protocol_violation` additionally carry the pairing
revocation notice of Section 14.6.

## 11. Visible liveness

Both peers MUST continuously expose one of these localized states while RAPP is
active:

- Paired, disconnected
- Connecting
- Verifying secure connection
- Connected
- Checking connection
- Disconnecting
- Connection stopped
- Pairing revoked

Color and animation MAY supplement but MUST NOT be the only distinction.
Reduced-motion settings and assistive technologies MUST receive equivalent
state information.

While healthy, either peer may send:

```cddl
liveness-ping = {
  "challenge": bstr .size 32,
  "last_received_sequence": uint
}

liveness-pong = {
  "challenge": bstr .size 32,
  "last_received_sequence": uint
}
```

A pong MUST echo the exact challenge of the ping it answers, and the ping
sender MUST verify that equality. A pong whose challenge matches no
outstanding ping is discarded and is not liveness proof. The encrypted
sequence, verified challenge, and current Noise keys provide recent
cryptographic liveness. A socket, relay subscription, push token, or
transport keepalive alone MUST NOT produce a Connected state.

An unanswered liveness exchange moves the session to `checking`, blocks new
operations, and uses exponential backoff with jitter. A valid response restores
`healthy`. A local hard deadline closes the session. Exact heartbeat intervals,
backoff limits, and deadlines are injected policy values to be determined by
measurement; they are not UI delays and MUST use a monotonic clock.

Ordinary connectivity loss closes the session but preserves pairing. Recovery
requires an explicit new session. It MUST NOT silently change transports.

## 12. Operation protocol

### 12.1 Typed requests

Every operation names a registered credential profile and action. A proxy MUST
reject an ungranted profile, an unknown action, arbitrary APDU bytes, or a
request that cannot be presented intelligibly to the user.

```cddl
operation-request = {
  "operation_id": bstr .size 16,
  "profile": tstr,
  "action": tstr,
  "request_hash": bstr .size 32,
  "expires_after_ms": uint,
  "context": { * tstr => any },
  "payload": { * tstr => any }
}
```

`request_hash` is defined in Section 8.5. Every later message for the
operation echoes this hash, and a receiver MUST verify the echo. Expiry is
enforced from local monotonic receipt time, is capped by local policy, and
applies only until commit; wall clocks are not a security dependency.

### 12.2 Prepare and commit

Operations whose profile defines a consequential command use this exchange:

```text
Requester                              Authorization Proxy
    |--- operation.request ----------------->|
    |                                        | validate request
    |                                        | safe prerequisite reads
    |                                        | display consent
    |                                        | collect local credential
    |<-- operation.prepared -----------------|
    |--- operation.commit ------------------>| durable commit record
    |                                        | at most one card transmission
    |<-- operation.result -------------------|
    |--- operation.result_ack -------------->|
```

```cddl
operation-prepared = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32
}

operation-commit = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32
}

operation-cancel = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32,
  ? "reason": tstr
}

operation-result = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32,
  "status": result-status,
  ? "error": tstr,
  "body": { * tstr => any }
}

result-status =
    "completed"
  / "denied"
  / "cancelled"
  / "rejected"
  / "credential_rejected"
  / "ambiguous"

operation-result-ack = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32
}
```

`operation.prepared` means the proxy has validated the request, received human
authorization, and is ready to execute exactly the committed request. It does
not mean that a credential command was sent.

`operation.commit` is the requester's point of no return. Before commit,
session closure safely cancels and destroys collected credentials. After
commit, the requester MUST assume that the credential operation may execute.

Before physical transmission, the proxy MUST durably store a non-secret
write-ahead record containing the pair, session, operation identifier, request
hash, and `committed` state. It MUST then consume a non-clonable command object
through an at-most-once transport. A process restart that finds a committed or
executing record without a terminal result marks it `ambiguous` and MUST NOT
repeat the card command.

A duplicate `operation.commit` whose hash matches the committed record is
discarded without effect; commit is idempotent and never causes a second
transmission. `operation.result_ack` is REQUIRED for a result with status
`completed`; other statuses are informational and need no acknowledgment.

A profile whose action defines no consequential command (for example, card
status inspection) omits prepare and commit: after validation, profile-defined
consent, and safe reads, the proxy answers directly with `operation.result`.

### 12.3 Physical-transmission contract

For every `operation_id`:

- `requested`, `awaiting_consent`, and `prepared` have zero credential-command
  transmissions;
- `committed` permits, but does not prove, one transmission;
- `executing` has at most one transmission;
- no terminal state may return to `committed` or `executing`; and
- replaying a commit never causes another transmission.

Safe, explicitly registered status reads are separate from credential commands
and MUST NOT be used to hide credential retries. Profiles define their exact
status-read budget.

### 12.4 Cancellation and expiry

Either peer may send `operation.cancel` at any point before the operation is
terminal. Before commit — in `requested`, `awaiting_consent`, or `prepared` —
cancellation destroys all operation credentials, dismisses any consent
prompt, and produces `cancelled`; the session remains healthy. Local expiry
of `expires_after_ms` in the same states produces `cancelled` the same way.

After commit, cancellation is advisory: if physical transmission can be proven
not to have begun, the result is `cancelled`; otherwise the cancel is recorded
and the operation continues to its card-determined result. A cancel or any
other operation message that references an unknown or already terminal
`operation_id` is a normal race, answered with `error` name
`unknown_operation` and no state change (Section 14.5).

### 12.5 Result delivery

The result is bound to the operation identifier and request hash. Losing the
session after a `completed`-status result exists but before acknowledgment
produces `delivery_uncertain` on the proxy. The proxy may retain such a result
encrypted under local platform storage for later status reporting, but RAPP
0.1 does not automatically reopen a session or redeliver it. It never repeats
the card command.

### 12.6 Status reconciliation

After a reconnection, a requester holding a non-terminal journal entry or an
`ambiguous` record from an earlier session MAY query the proxy:

```cddl
operation-status-request = {
  "operation_id": bstr .size 16
}

operation-status = {
  "operation_id": bstr .size 16,
  "known": bool,
  ? "state": tstr,
  ? "request_hash": bstr .size 32
}
```

The proxy answers from its durable journal; a status query never touches the
card. `state` is the journaled terminal state name. The requester's terminal
record keeps its own state; the authenticated report is stored as a journal
annotation that resolves the practical question — whether the card command
executed — without transitioning any machine. New work requires a new
`operation_id` and fresh consent in every case.

### 12.7 Operation progress (advisory)

An authorization proxy MAY send `operation.progress` to inform the requester of
user-visible progress during operation execution:

```cddl
operation-progress-body = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32,
  "event": "waiting_for_card" / "card_wait_ended" / tstr,
}
```

Registered progress event names:
* `waiting_for_card`: The proxy is waiting for the user to present a physical card to NFC or insert into a reader.
* `card_wait_ended`: The card presentation wait has ended (e.g. card tapped/inserted or wait timed out).

`operation.progress` is strictly advisory and unidirectional (proxy to requester).
It MUST NOT mutate durable operation state, advance transaction stages, or alter
retry/transmission invariants.

To maintain forward compatibility, an unknown or unexpected `event` value MUST
be ignored as a no-op advisory and MUST NOT terminate the session or revoke the
pairing. Similarly, progress messages referencing an unknown, completed, or
cancelled operation MUST be silently ignored without generating an error response.

## 13. Credential profiles

### 13.1 Common requirements

Every profile MUST define:

- actions and schemas;
- requester-asserted and independently verified consent context;
- credential role and entry policy;
- safe prerequisite reads and their maximum count;
- whether an action has a consequential command, and its exact boundary;
- retry-counter interpretation and refusal threshold for counter-bearing
  credentials;
- success, rejection, removal, transport ambiguity, and partial-state results;
- which result data the requester may receive; and
- credential and cache invalidation behavior.

The requester MUST never receive CAN, activation PIN, PIN 1, PIN 2, or PUK.
Secrets MUST never occur in a RAPP message, request hash, relay token, crash
report, production log, or operation journal.

### 13.2 Initial profile registry

| Profile | Purpose | Consequential command |
| --- | --- | --- |
| `fi.refineid.card-status.v1` | inspect supported card and retry state | none |
| `fi.refineid.authentication.v1` | browser or application authentication | PIN 1 verify and private-key operation |
| `fi.refineid.document-signing.v1` | sign a document digest | PIN 2 verify and private-key operation |

The card-status, authentication, and document-signing actions are defined below.
PIN management (PIN changes and PUK unblocking) is strictly local to the card
reader or host application and is out of scope for RAPP: PINs and PUKs never
cross the network boundary.

#### 13.2.1 Registered actions and payloads

The initial action registry is closed:

| Action | Owning profile | Consequential command |
| --- | --- | --- |
| `inspect_card` | `fi.refineid.card-status.v1` | none |
| `read_identity` | `fi.refineid.card-status.v1` | none |
| `read_certificate` | key-matching profile, below | none |
| `browser_authenticate` | `fi.refineid.authentication.v1` | PIN 1 verify and private-key operation |
| `sign_document` | `fi.refineid.document-signing.v1` | PIN 2 verify and private-key operation |

`inspect_card` and `read_identity` carry empty context and payload maps.
`read_certificate` carries exactly one payload field, `kind`, whose registered
values are `authentication` and `signature`. The action is owned by the
profile whose key the certificate serves: reading the authentication
certificate requires the `fi.refineid.authentication.v1` grant, and reading the
signature certificate requires the `fi.refineid.document-signing.v1` grant, so a
requester never learns a certificate whose key it could not ask to use. All
three reads are safe reads and omit prepare and commit (Section 12.2).

`browser_authenticate` under `fi.refineid.authentication.v1` carries:

| Map | Field | Type | Meaning |
| --- | --- | --- | --- |
| context | `origin` | bounded non-empty text | relying-party origin displayed by the authorizer |
| payload | `key_profile` | registered text | expected authentication-certificate key profile |
| payload | `algorithm` | registered text | exact signature algorithm |
| payload | `digest` | bytes | already-hashed challenge of the registered length |

`sign_document` under `fi.refineid.document-signing.v1` has the same payload fields
and carries bounded non-empty `document_name` in its context map instead of
`origin`. Documents and unhashed browser input MUST NOT cross RAPP.

The initial `key_profile` registry is closed:

| Name | Expected key |
| --- | --- |
| `ecdsa_p256` | ECDSA P-256 |
| `ecdsa_p384` | ECDSA P-384 |
| `rsa_2048` | RSA 2048-bit |
| `rsa_3072` | RSA 3072-bit |

The initial `algorithm` registry is also closed:

| Name | Digest length | Compatible key profiles |
| --- | ---: | --- |
| `ecdsa_sha224` | 28 | `ecdsa_p256`, `ecdsa_p384` |
| `ecdsa_sha256` | 32 | `ecdsa_p256`, `ecdsa_p384` |
| `ecdsa_sha384` | 48 | `ecdsa_p256`, `ecdsa_p384` |
| `ecdsa_sha512` | 64 | `ecdsa_p256`, `ecdsa_p384` |
| `rsa_pkcs1_sha256` | 32 | `rsa_2048`, `rsa_3072` |
| `rsa_pkcs1_sha384` | 48 | `rsa_2048`, `rsa_3072` |
| `rsa_pkcs1_sha512` | 64 | `rsa_2048`, `rsa_3072` |
| `rsa_pss_sha256` | 32 | `rsa_2048`, `rsa_3072` |

A receiver MUST reject an unknown value, an incorrect digest length, an
incompatible key/algorithm combination, an extra field, or a missing field.
The expected profile is an authenticated requester assertion, not trusted card
state: before approval, the proxy MUST independently resolve the selected card
certificate and require it to match `key_profile`. A mismatch is terminal and
MUST NOT transmit a PIN verification or private-key command.

All four fields participate in the deterministic request commitment. Changing
the displayed context, key profile, algorithm, or digest therefore changes the
request hash and invalidates any approval bound to the previous request.

### 13.3 Retry protection

The counter-bearing credentials of the initial card family are the activation
PIN, PIN 1, PIN 2, and PUK, whose try counters are defined by the FINEID S1
specification. Before a command that can decrement such a counter, the profile
MUST inspect the counter that a failed command would decrement. If that
counter is unavailable, the proxy refuses the operation. The command is
permitted only with at least three attempts remaining on that counter.

A target PIN counter of zero does not prohibit a PUK-based reset: per FINEID
S1, only a failed RESET RETRY COUNTER decrements the PUK try counter, and a
successful reset restores counters rather than consuming an attempt. The
three-attempt floor on the PUK itself protects against a mistyped PUK being
entered repeatedly. The same floor applies independently to the activation
PIN, PIN 1, and PIN 2 before commands that verify or change them.

The CAN has no try counter in FINEID S1 or in ICAO Doc 9303 Part 11; it is a
PACE password whose throttling, if any, is internal to the card. Counter
inspection and the three-attempt floor therefore do not apply to the CAN, and
an unavailable CAN counter is not a refusal reason. An invalid CAN is instead
handled by Section 13.4.

No retry check makes a credential command safe to repeat. Status reads,
credential command construction, and physical transmission remain separate
typed boundaries.

### 13.4 Credential rejection terminates RAPP

If the credential holder reports that PIN 1, PIN 2, or the CAN is bad or
rejected — during safe prerequisite reads, secure-channel establishment, or
the consequential command — it is an indication of a critical security violation
or corrupted credential state. The authorization proxy device MUST:

1. make no further card transmission;
2. mark the active operation `credential_rejected`;
3. immediately drop and permanently close all active RAPP connections and sessions;
4. durably destroy all pairing keys and write tombstones for all pairings on the
   device, permanently preventing reconnect until explicitly re-paired;
5. purge all stored local identities, credentials, cached PINs, CANs, and
   card-derived state;
6. reset the authorization proxy software on the device to an initial "factory reset" state;
7. send only the profile's bounded `credential_rejected` result to the active
   peer if the authenticated channel is still usable prior to closing; and
8. move the RAPP session immediately to `closing`.

The authenticated requester that receives `credential_rejected` MUST also
durably destroy its pairing keys and write a tombstone before reporting the
terminal result. Recovery requires a completely new manual pairing ceremony
once the device has been re-initialized and re-paired; there is no automatic
reconnect, grace policy, or retry counter recovery.

### 13.5 Activation and partial completion

PIN 1 and PIN 2 activation are independent side effects with independent card
state. They MUST be separate operations and separate at-most-once credential
commands. Before each operation, the profile reads the applicable factory
state. It changes only a PIN still in factory state. After confirmed success,
it verifies only the minimum status needed to update that PIN's state; it does
not add certificate reads or unrelated card traffic.

If communication becomes ambiguous after PIN 1, the proxy MUST NOT attempt PIN
1 again. A later explicit flow first inspects factory state and offers only the
still-uninitialized PIN. A locked activation PIN may be recovered with PUK only
when the card generation and authoritative card profile permit it.

## 14. Distributed state machine

The normative state of each endpoint is the product:

```text
RAPPState = PairingState x SessionState x OperationState
```

The companion YAML file is the machine-readable transition source for
model-based tests. The prose below explains its security meaning. If the prose
and model disagree, an implementation MUST stop; the discrepancy requires a
specification revision rather than an implementation guess.

### 14.1 Instances and roles

The machines describe instances, not singletons:

- a **pairing instance** exists per stored or in-progress peer relationship;
  `unpaired` is the absence of an instance, and a new offer or pairing code entry creates a
  new instance with fresh keys;
- a **session instance** exists per connection attempt; `absent` means no
  live instance for the pairing, and a new instance may be created whenever
  none is in a live state;
- an **operation instance** exists per `operation_id`; `none` is the
  admission state of a new instance, terminal states are permanent journal
  records, and the single active slot (`MAX_ACTIVE_OPERATIONS`) frees when an
  instance reaches a terminal state.

Every transition in the model carries a role — `requester`, `proxy`, or
`both`. An endpoint implements exactly the transitions whose role includes
it; the two projections are the per-endpoint machines, and conformance
testing (Section 22) exercises each projection separately. States that only
one role occupies (for example `offer_active` on the requester,
`awaiting_consent` and `executing` on the proxy) are annotated in the model.

The two endpoints legitimately journal different terminal states for one
`operation_id` when the link fails mid-operation — for example requester
`ambiguous` beside proxy `result_pending` then `delivery_uncertain`. Section
12.6 reconciliation resolves the practical outcome without rewriting either
journal.

### 14.2 Pairing states

| State | Meaning |
| --- | --- |
| `unpaired` | no peer keys exist |
| `offer_active` | one manual pairing offer is live (requester only) |
| `handshaking` | pairing Noise handshake is in progress |
| `confirming` | authenticated exchange awaits both approvals |
| `paired_disconnected` | durable pairing exists; no healthy session |
| `paired_connected` | durable pairing exists with a healthy/checking session |
| `revoked` | the pairing was deliberately terminated, locally or by authenticated peer notice |

`revoked` is a fail-stop state. Existing keys cannot be reactivated. The user
may forget the record and perform a completely new pairing with a new code and keys.
Unauthenticated traffic, failed handshakes, and frames that fail authenticated
decryption can never revoke a stored pairing.

### 14.3 Session states

| State | Permitted activity |
| --- | --- |
| `absent` | no channel |
| `connecting` | transport establishment only (requester side) |
| `authenticating` | Noise handshake and `session.ready` comparison only |
| `healthy` | liveness and at most one operation |
| `checking` | liveness recovery only; new operations blocked |
| `closing` | operation classification, best-effort close notice, key destruction |
| `closed` | terminal session record; no traffic |

Ordinary EOF, transport failure, liveness timeout, or decrypt failure closes
only the session. The first authenticated protocol violation immediately
revokes the pairing (Section 14.6). A peer `session.close`
is consumed from every post-handshake state: `authenticating`, `healthy`,
`checking`, and `closing`.

### 14.4 Operation states

| State | Meaning |
| --- | --- |
| `none` | admission state of a new operation instance |
| `requested` | valid request sent (requester) or received (proxy) |
| `awaiting_consent` | proxy is inspecting prerequisites, presenting context, or collecting credential |
| `prepared` | user approved; physical credential command count is zero |
| `committed` | durable point of no return written |
| `executing` | at-most-one card command may be in flight |
| `result_pending` | terminal card result exists, not acknowledged |
| `completed` | result acknowledged |
| `denied` | user denied before commit |
| `cancelled` | cancellation or expiry proven before physical transmission |
| `rejected` | non-credential policy or card rejection |
| `credential_rejected` | invalid CAN, PIN 1, or PIN 2; session must close |
| `ambiguous` | card completion cannot be proven; retry forbidden |
| `delivery_uncertain` | result exists but delivery was not acknowledged |

Terminal operation states never transition again. A new human action creates a
new `operation_id`; it does not resurrect the old one. Messages referencing a
terminal or unknown operation are races, not violations, and take the discard
response of Section 14.5.

### 14.5 Unexpected-input policy

The machine is total: every input in every state is covered by a transition
or by exactly one of these policy classes, which are themselves part of the
machine-readable model and its generated tests:

1. **Pre-authentication invalid input** — malformed, unexpected, or
   unauthenticated data during pairing offers, connection, or handshakes:
   discard and close only the candidate connection. Stored pairing state is
   never altered.
2. **Established-channel integrity failure** — a frame on an authenticated
   session that fails authenticated decryption or framing: close the session
   as `session_integrity_failed`. This is network-attributable (Section 7.3)
   and has no pairing effect.
3. **Stale-reference race** — a successfully decrypted operation message for
   an unknown or terminal `operation_id`, a duplicate commit matching the
   committed hash, or a pong whose challenge matches no outstanding ping:
   discard; answer with `error` name `unknown_operation` where a reply is
   useful; no state change.
4. **Authenticated protocol violation** — a successfully decrypted message
   with a schema violation, sequence violation, parameter-echo mismatch, or
   no legal transition outside class 3: close the session, classify the active
   operation per Section 14.7, immediately revoke the pairing, destroy its
   keys, and require a new manual pairing (Section 14.6). On the pairing
   channel, before a pairing is stored, the violation instead aborts the
   pairing attempt and records nothing.
5. **Local internal fault** — stop local RAPP, destroy session material, and
   classify a committed operation as ambiguous without blaming the peer.
6. **Traffic after `closed`** — discard without response.

### 14.6 Immediate revocation and peer notice

A successfully decrypted protocol violation proves that the peer holding the
pair keys sent nonconforming traffic. The first such violation closes the
session, moves the pairing immediately to `revoked`, destroys the pair keys,
and requires a completely new manual pairing. RAPP 26.9 has no violation
counter, grace event, automatic recovery, or restoration of revoked keys.

Entering `revoked` sends, while an authenticated channel still exists, one
best-effort `session.close` with reason `pairing_revoked` or
`protocol_violation`, and then destroys the pair keys. A peer receiving either
reason on an authenticated channel marks its own pairing `revoked`, records
that the peer initiated it, closes the session, and destroys its keys; the
pairing is dead on both sides and both users see why. When no channel exists at
revocation time, the other peer
discovers the loss as failed session handshakes: after three consecutive
candidate authentication failures for one pairing an implementation SHOULD
suggest re-pairing, while leaving stored keys untouched per invariant
`INV-18`.

`revoked` is entered deliberately: by local user action, or by the
authenticated peer notice above. Local revocation with no channel simply
destroys keys; the peer discovers the loss as described.

### 14.7 Global event precedence

When events race, implementations process them in this order:

1. local forget, revocation, or process security shutdown;
2. authenticated peer revocation notice;
3. credential rejection or card-command ambiguity;
4. authenticated peer close;
5. transport loss, integrity failure, or liveness deadline;
6. operation transitions;
7. ordinary liveness traffic.

Session closure classifies the active operation exactly once, unless the
operation already reached a terminal state through an earlier-ranked event.
Closure before commit produces `cancelled` on both endpoints. Closure with a
committed operation produces `ambiguous` on the requester; on the proxy,
where `committed` proves zero transmissions, it produces `cancelled`.
Closure during `executing` never interrupts the card exchange: the proxy
lets the exchange finish and journals its outcome, which becomes
`delivery_uncertain` when a completed result can no longer be delivered.
Closure with an unacknowledged `completed` result produces
`delivery_uncertain`. Entering `checking` blocks new operations but
classifies nothing; classification happens only when `closing` begins.

## 15. Failure taxonomy

Failure conditions use stable symbolic names. On the wire they are carried by
`operation.result` statuses, the `error` message, or a `session.close`
reason; they MUST NOT contain arbitrary exception text, card status words,
secret values, filesystem paths, stack traces, or transport internals.

```cddl
error-body = {
  "error": tstr,
  ? "operation_id": bstr .size 16
}
```

Registered `error` names in RAPP 26.9.13: `busy`, `unknown_operation`.

| Condition | Wire carrier | Session effect | Pairing effect | Credential attempts |
| --- | --- | --- | --- | --- |
| `user_denied` | result status `denied` | remains healthy | none | none |
| `request_expired` | result status `cancelled` | remains healthy | none | none |
| `cancelled` | result status `cancelled` | remains healthy | none | none |
| `request_invalid_or_unsupported` | result status `rejected` | remains healthy | none | none |
| `unknown_operation` | `error` | remains healthy | none | none |
| `busy` | `error`, then close | new candidate session closes | none | none |
| `retry_policy_refused` | result status `rejected` | closes explicitly | none | none |
| `credential_rejected` | result status `credential_rejected` | closes immediately | revoked immediately on both peers | at most one consumed |
| `card_removed_before_transmit` | result status `cancelled` | may remain healthy | none | none |
| `card_completion_ambiguous` | result status `ambiguous`, best effort | closes immediately | none | never repeated |
| `transport_failed` | none; observed locally | closing, then closed | none | by commit boundary |
| `session_integrity_failed` | none; channel unusable | closes immediately | none | by commit boundary |
| `authenticated_protocol_violation` | `session.close` reason `protocol_violation`, best effort | closes | revoked immediately; peer marks revoked | never repeated |
| `pairing_revoked` | `session.close` reason `pairing_revoked`, best effort | closes | revoked; peer marks revoked | never repeated |
| `local_security_shutdown` | none | closes | none | ambiguous if committed |

An ordinary user denial is not an anomaly. It MUST NOT revoke a pairing.

Advisory progress failures (such as unknown event names, stale operation races, or reference mismatches) MUST NOT be treated as protocol violations and MUST NOT revoke pairings.

An authorization proxy MAY enforce a rolling rate limit on inbound operation requests (e.g. 30 requests per minute, sized for human-interactive pace) to weed out broken or looping clients. When the rate limit is exceeded, the proxy answers with `error: busy`, preserving the session and stored pairings intact.

## 16. Transport profiles

A transport profile MUST provide:

- reliable, ordered delivery of bounded binary frames;
- connection cancellation and EOF reporting on every endpoint and phase;
- peer-reachable candidate parameters;
- a candidate identifier available to both endpoints of an established
  connection, for the parameter echo of Section 8.4;
- pair-specific rendezvous, so an accepting endpoint can associate an
  incoming connection with a stored pairing;
- a clear distinction between transport establishment and RAPP health;
- no hidden reconnection or message replay; and
- enough metadata to satisfy the prologue of Section 8.3.

The initial transport profile registry is:

| Profile | Underlay | Status |
| --- | --- | --- |
| `apple-peer-v1` | Apple-native nearby connectivity | defined; implemented |
| `fi.refineid.stream.v1` | one reliable ordered byte stream, initially TCP | defined in Section 16.1; implemented |
| `local-quic-v1` | local QUIC | reserved design target |
| `relay-websocket-v1` | untrusted Internet relay | defined in [rapp-relay-websocket-v1.md](rapp-relay-websocket-v1.md); folds into Section 16.2 at rollup |

A future ICE-based direct profile using
[RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html) is anticipated but
not reserved by name.

QUIC, TLS, WebSocket, Bluetooth, and Apple frameworks are underlays. Their
security never replaces the RAPP Noise session. A profile may attempt multiple
candidates before authentication only according to an explicit user-visible
connection action. Once Noise authentication begins, fallback requires a new
session; during or after a committed operation it is forbidden.

### 16.1 The stream profile

`fi.refineid.stream.v1` carries RAPP frames over a single reliable ordered
byte stream between the requester and the proxy, initially TCP over a network
where the two devices can reach each other directly. The underlay contributes
no security (Section 5); the profile exists to satisfy the frame contract of
this section with the smallest possible mechanism, so that a requester
platform without Apple-native connectivity can participate.

**Connection direction.** The requester runs the listener; the proxy dials.
This matches device reality: a desktop requester has a stable address and
lifetime, while a phone proxy does not. The proxy dials both for pairing
(Section 9.3, where the offer carries the listener's parameters) and for
session establishment (Section 10, after an explicit action on the proxy
whose holder is about to present the card anyway). Logical Noise roles are
unchanged: the requester initiates every handshake over the accepted
connection.

**Framing.** Every frame is a 2-byte big-endian length prefix followed by
exactly that many payload bytes. A declared length of zero is malformed. The
16-bit prefix cannot express a length above `NOISE_MAX_MESSAGE`, and a
receiver enforces its bounds from the prefix alone, before allocation.

**Candidate parameters.** The offer's `transport-candidate.parameters` map
for this profile is:

```cddl
stream-parameters = {
  "endpoints": [1* tstr]    ; listener addresses, "host:port";
                            ; an IPv6 host uses bracket form
}
```

`candidate_id` is chosen by the requester and distinguishes multiple stream
candidates within one offer. The proxy stores the selected candidate,
including its endpoint list, at pairing confirmation and dials those
endpoints for later sessions.

**Rendezvous preamble.** Immediately after connecting, before any Noise
message, the proxy sends exactly one plaintext preamble frame containing the
deterministic-CBOR encoding of:

```cddl
stream-rendezvous = [
  "RAPP-stream-v1",
  tstr,                     ; purpose: "pairing" / "session"
  bstr                      ; purpose "pairing": empty
                            ; purpose "session": rendezvous_token, Section 8.5
]
```

On accepting a connection, the requester reads exactly one bounded preamble
frame. Purpose `pairing` is honored only while the listener has an active
offer (Section 9.3); the requester then sends the first pairing handshake
message. Purpose `session` is honored only when `rendezvous_token` equals the
stored token of exactly one non-revoked pairing; the requester then initiates
the session handshake with that pairing's keys. Any other preamble — unknown
purpose, unknown token, malformed CBOR, oversized frame, or a second preamble
— is pre-authentication invalid input (Section 14.5, class 1): the connection
closes and no stored state changes.

The preamble is unauthenticated routing metadata, exactly like a relay token
(Section 17). Possession of a token lets an attacker elicit the first
`Noise_KK` handshake message, which contains a fresh ephemeral public key and
no identity, and lets a network observer link the connection to an
unidentified recurring pairing; it enables nothing else. The requester
processes one inbound connection's handshake at a time and MAY rate-limit
connection attempts.

**Strictness.** The profile inherits the protocol's single-connection
discipline unchanged: one live session per pairing (`busy` otherwise), no
hidden reconnection, no candidate fallback after authentication begins, and
every anomaly fails the connection closed. A requester whose listener address
has changed since pairing is unreachable until the user pairs anew or a
reviewed extension defines candidate refresh; the profile deliberately
prefers breakage to silent endpoint changes.

## 17. Rendezvous relay

The relay routes by a high-entropy, pair-specific opaque rendezvous token. The
token is not a RAPP identity or key. Relay authentication MAY control abuse and
billing but MUST NOT be accepted as requester or proxy authentication.

The relay MUST:

- handle only encrypted frames and bounded routing metadata;
- prevent one peer from enumerating other peers;
- apply size, rate, lifetime, and connection limits before buffering;
- avoid durable store-and-forward in RAPP 26.9;
- ensure push notifications contain only an opaque wake hint;
- delete queued ciphertext when a session closes or expires; and
- document retained metadata and deletion periods.

A relay that corrupts, drops, duplicates, or reorders frames causes session
integrity failures and reconnection effort, never pairing loss
(Section 14.5). End-to-end encryption does not hide timing, endpoints,
connection duration, or approximate message size from the relay. Padding and
traffic-shaping are future extensions and must be evaluated against mobile
power use.

## 18. Authorization and user interface contract

The proxy MUST show, before preparation:

- which paired requester is asking;
- the credential profile and action;
- the relying-party origin, document identity, or equivalent purpose;
- which context is independently verified and which is requester asserted;
- which credential role will be consumed;
- whether the operation can change card state or consume a retry; and
- explicit approve and deny controls.

The requester and proxy MUST both show RAPP connection status. The proxy is the
authoritative UI for credentials, retries, card placement, and consent. The
requester MUST NOT render or collect CAN, PIN 1, PIN 2, activation PIN, or PUK
for forwarding through RAPP.

Accessibility is normative. Status cannot rely on color, animation, shape, or
sound alone. Controls require meaningful labels, logical focus order, scalable
text, sufficient contrast, reduced-motion behavior, and equivalent screen
reader announcements. A continuously animated security warning MUST have a
non-animated semantic equivalent.

## 19. Credential custody and diagnostics

Credential values are non-clonable, zeroize-on-drop inputs local to the proxy.
They MUST NOT be serialized into general application models. A credential
command is a separate consuming type and cannot enter a generic transport or
debug formatter.

Production builds MUST NOT persist RAPP diagnostic logs. They MUST NOT emit
credentials, plaintext messages, card identifiers, operation context,
certificates, request or result bodies, Noise keys, pairing secrets, or raw
APDUs to logs, telemetry, analytics, crash annotations, or operating-system
signposts.

Explicit development builds MAY provide volatile protocol instrumentation for
controlled hardware diagnosis. Such instrumentation must be compile-time
excluded from production and clearly indicate that it is unsafe for real
credentials. External review and conformance evidence use synthetic fixtures
unless a separately approved physical-card procedure requires otherwise.

## 20. Privacy model

RAPP uses pair-specific keys, pair identifiers, and relay tokens. It has no
global user or device identifier. Pair records are device-only and not included
in cloud backups. The relay cannot discover card identity from protocol
plaintext because it receives none.

`pair_id` and `session_id` are derived from handshake hashes whose inputs
include offer content that never crosses the network, so a network observer
cannot compute them; neither identifier appears in plaintext on the wire.
Where a transport profile requires plaintext rendezvous, it carries the
separately derived `rendezvous_token` (Section 8.5), never `pair_id`. An
observer of one network path can recognize that token's recurrence, which is
inherent to rendezvous, but cannot connect it to `pair_id`, to the other
identifiers, or to tokens observed for other pairings.

The requester receives only profile-required results. An authentication or
signing profile may necessarily return a certificate chain, public key,
signature, or verified identity attribute. The consent UI must make that
disclosure clear. Status profiles should return coarse capability states rather
than unnecessary personal or retry data.

Implementations SHOULD minimize requester and proxy names on the wire, retain
them locally, and disclose relay metadata behavior. Telemetry is outside RAPP
and MUST NOT be required for conformance.

## 21. Security invariants

The following invariants are normative and are duplicated by identifier in the
machine-readable model:

| ID | Invariant |
| --- | --- |
| `INV-01` | No operation exists without a confirmed pairing. |
| `INV-02` | New operations start only while the session is healthy. |
| `INV-03` | No credential command occurs before exact consent and commit. |
| `INV-04` | A proxy has at most one active credential operation. |
| `INV-05` | One operation identifier causes at most one credential-command transmission. |
| `INV-06` | Ambiguous completion is never retried automatically. |
| `INV-07` | Revoked keys are never automatically restored. |
| `INV-08` | Version, suite, grants, and transport are transcript-bound. |
| `INV-09` | A relay never receives RAPP plaintext or credential material. |
| `INV-10` | A requester never receives CAN, PIN, activation, or PUK values. |
| `INV-11` | Connected requires recent authenticated liveness proof. |
| `INV-12` | Security-relevant connection state is visible on both peers. |
| `INV-13` | There is no automatic downgrade or mid-operation fallback. |
| `INV-14` | Session keys and credential buffers are destroyed on close. |
| `INV-15` | Local policy may be stricter than negotiated policy, never weaker. |
| `INV-16` | Invalid CAN, PIN 1, or PIN 2 closes the RAPP session. |
| `INV-17` | Credential rejection never automatically reconnects or repeats. |
| `INV-18` | Unauthenticated or unattributable input never revokes a stored pairing. |

## 22. Conformance and verification

### 22.1 Model-based verification

Implementations MUST map every application state to the companion transition
model, implement exactly the transitions of their role projection, and handle
every input without a matching transition exactly as the unexpected-input
policy of Section 14.5 specifies. CI must generate legal event sequences,
exercise every transition, every terminal state, and every unexpected-input
policy class in both role projections, and compare observed state with the
model. UI tests then verify the visible projection of those same states.

A TLA+/PlusCal model is RECOMMENDED before protocol stabilization to verify
safety under reordered messages, concurrent close, crashes, and ambiguous
completion. The YAML model is intended for implementation and model-based test
generation; it is not a substitute for distributed-systems model checking.

### 22.2 Required test classes

Conformance evidence includes:

- deterministic-CBOR positive and negative vectors, including every message
  body schema and every defined hash preimage;
- Noise handshake, prologue, and derived-identifier known-answer vectors;
- cross-platform pairing and session interoperability;
- replay, duplicate, gap, downgrade, and unknown-critical-field rejection;
- offer non-consumption under handshake garbage, and offer consumption on
  authenticated completion, cancellation, and expiry;
- parser fuzzing with allocation and nesting bounds;
- generated coverage of every state transition, both role projections, every
  unexpected-input class, and every global event;
- immediate authenticated-violation revocation and both-sided revocation
  visibility;
- physical-transmission instrumentation proving exact command counts;
- fault injection before commit, before transmit, during transmit, after card
  response, before result, and before result acknowledgment;
- crash recovery from every durable operation-journal state;
- status-reconciliation vectors for ambiguous and delivery-uncertain records;
- retry-floor tests for the activation PIN, PIN 1, PIN 2, and PUK, and
  rejection-path tests for the CAN;
- card removal and NFC interruption tests;
- relay compromise, corruption, metadata, queue-expiry, and abuse-limit tests;
- accessibility tests for every visible state and consent path; and
- production-artifact inspection proving unsafe diagnostics are absent.

The machine-readable corpus at
`vectors/rapp-v26.9.13.json` fixes the deterministic CBOR,
envelope-rejection, sequence, downgrade, grant, hash, and mandatory Noise
XXpsk3/KK known-answer vectors for this document version. Fields prefixed
`test_only_` are public deterministic test material and MUST NOT be used as
runtime keys or pairing secrets.

No card-mutating path may be described as working from simulator evidence
alone. Exact released binaries require observed hardware evidence.

## 23. Extensibility and registries

The protocol uses symbolic registries for:

- cryptographic suites;
- credential profiles and actions;
- transport profiles;
- message types;
- error names;
- close reasons; and
- critical extensions.

Core names require specification review. Credential profiles are namespaced
by jurisdiction or vendor using a reverse-domain prefix; experimental private
names use the same convention. A new extension must define negotiation,
transcript binding, state-machine effects, privacy impact, resource limits,
downgrade behavior, and test vectors. It cannot weaken a core invariant.

Unknown non-critical fields may be ignored. Unknown critical fields cause a
clean pre-operation rejection. Receiving an unknown authenticated message type
or an extension that changes state without negotiation is a protocol violation.

## 24. Questions for external review

Review is specifically requested on:

1. whether Noise revision 34 and the proposed `XXpsk3`/`KK` patterns are the
   right stable basis, or whether a standardized alternative is preferable;
2. whether the pairing code entry assumption and two-sided confirmation adequately
   address observation and pairing races;
3. the correct accessible human-verification representation, if one is needed
   in addition to the 6-digit code;
4. whether pair-specific static X25519 keys provide the desired privacy and key
   lifecycle across all target platforms;
5. operation-journal durability, and whether Section 12.6 status
   reconciliation is sufficient without result redelivery;
6. confused-deputy protection and independent origin verification for browser
   authentication;
7. whether remote activation and PIN management should be separate optional
   grants or prohibited outside local-only profiles;
8. metadata leakage and practical padding for an Internet relay;
9. liveness policy values under mobile power and background-execution limits;
10. whether preserving an offer across failed handshakes enables griefing
    that per-offer serialization and rate limits do not already bound;
11. post-quantum migration and hybrid pairing strategy;
12. handling of local implementation faults without enabling peer-triggered
    denial of service; and
13. completeness of the composite state machine and formal verification plan.

### 24.1 Review checklist

An external reviewer should be able to answer:

- What exact fact authenticates each peer during pairing and later sessions?
- Which fields are bound to the cryptographic transcript, and can both peers
  possess every bound value before the handshake?
- Does any handshake message carry a payload readable before the pre-shared
  key is mixed?
- What can a malicious relay learn, modify, or permanently destroy?
- Can network garbage, a corrupted frame, or a failed handshake force
  permanent loss of a valid pairing or consume a live offer?
- When can a credential or mutating card command physically occur?
- How is a duplicate commit prevented after process failure?
- Which failures close only a session and which destroy a pairing, and how
  does the innocent peer learn of destruction?
- What happens if NFC fails immediately before or after card transmission?
- Does any path automatically retry an ambiguous operation, and how is an
  ambiguous record later resolved without card replay?
- What information reaches the requester, proxy, relay, and relying party?
- Are all states visible and accessible without relying only on color or
  motion?
- Can an implementation accept an input that neither matches a modeled
  transition nor an unexpected-input policy class?

## 25. References

- Bradner, S., and J. Leiba, [Key words for use in RFCs to Indicate Requirement
  Levels](https://www.rfc-editor.org/info/bcp14), BCP 14.
- Bormann, C., and P. Hoffman, [Concise Binary Object Representation
  (CBOR)](https://www.rfc-editor.org/rfc/rfc8949.html), RFC 8949.
- Birkholz, H., Vigano, C., and C. Bormann, [Concise Data Definition Language
  (CDDL)](https://www.rfc-editor.org/rfc/rfc8610.html), RFC 8610.
- Josefsson, S., [The Base16, Base32, and Base64 Data
  Encodings](https://www.rfc-editor.org/rfc/rfc4648.html), RFC 4648.
- Perrin, T., [The Noise Protocol Framework, revision
  34](https://noiseprotocol.org/noise.html).
- Langley, A., Hamburg, M., and S. Turner, [Elliptic Curves for
  Security](https://www.rfc-editor.org/rfc/rfc7748.html), RFC 7748.
- Nir, Y., and A. Langley, [ChaCha20 and Poly1305 for IETF
  Protocols](https://www.rfc-editor.org/rfc/rfc8439.html), RFC 8439.
- Krawczyk, H., and P. Eronen, [HMAC-based Extract-and-Expand Key Derivation
  Function](https://www.rfc-editor.org/rfc/rfc5869.html), RFC 5869.
- Keranen, A., Holmberg, C., and J. Rosenberg, [Interactive Connectivity
  Establishment](https://www.rfc-editor.org/rfc/rfc8445.html), RFC 8445.
- Iyengar, J., and M. Thomson, [QUIC: A UDP-Based Multiplexed and Secure
  Transport](https://www.rfc-editor.org/rfc/rfc9000.html), RFC 9000.
- Digital and Population Data Services Agency,
  [FINEID Specification S1: Electronic ID Application of the Finnish
  Identity Card](https://dvv.fi/en/fineid-specifications).
- International Civil Aviation Organization,
  [Doc 9303: Machine Readable Travel Documents, Part 11 — Security Mechanisms
  for MRTDs](https://www.icao.int/publications/pages/publication.aspx?docnum=9303).


