# STPA of the Windows requester over Bluetooth

**Status:** prospective, for owner review
**Date:** 2026-10-20
**Applies to:** RAPP v26.10.18, the BLE transport profile
`"fi.refineid.rapp.ble.v1"`, and this repository's requester: the key
storage provider in `refineid_minidriver.dll`, the agent that holds the
phone's session, the pairing and certificate stores, and the WinUI
application

---

## 1. Purpose and relation to the system analysis

The system-level STPA in refineid-core (`docs/security/stpa-rapp.md`)
draws the requester as one box. Its section 16 analyses a browser login
over BLE alone, with a Windows requester and an iPhone custodian whose
card sits in a wired reader. This document opens the requester box for
Windows. It keeps the system analysis's losses (L-1 to L-5), hazards
(H-1 to H-7) and identifiers, and adds its own with a `W-` prefix. A
requirement here refines a system requirement where it names one; where
it names none, it is local to this platform.

The design analysed is the one chosen on 2026-10-20: a per-user agent
holds the BLE link and the RAPP session, and the key storage provider,
which Windows loads into whichever program signs, asks the agent for
each signature over a named pipe.

## 2. Control structure

```
  Cardholder ── clicks "log in with identity card" ──► Browser (Edge, Chrome)
                                                         │  NCryptSignHash
                                                         ▼
                                                    CNG router (ncrypt.dll)
                                                         │  provider call, in-process
                                                         ▼
                                          RefineID KSP (refineid_minidriver.dll)
                                                         │  sign request, named pipe
                                                         ▼
   WinUI app ── pair, forget, toggle ──►  RefineID agent (one per user)
        ▲                                   │      │        │
        │ state                             │      │        └─ certificate store (CurrentUser\My)
        └───────────────────────────────────┘      └─ pairing store (Credential Manager)
                                                    │  GATT write / indication
                                                    ▼
                                      WinRT Bluetooth LE stack ── radio ── iPhone custodian
```

Downward arrows are control actions; the returns are feedback.

| Control action | Controller | Feedback present | Feedback absent |
| :--- | :--- | :--- | :--- |
| Ask for a client certificate signature | Browser | The KSP's status and signature | Nothing it needs from below |
| Sign a hash | KSP | The agent's answer on the pipe | Whether the pipe's server is the agent; which site the browser is signing for (CNG carries no origin) |
| Relay a signature request to the phone | Agent | `operation.progress`, `operation.result`, the close reason, the session's liveness | Which program called the KSP, beyond the pipe client's process identity |
| Hold the BLE link and session | Agent | GATT connection status, liveness, `card.status` | Whether the phone is findable if the link drops (core 16.1) |
| Negotiate the link | WinRT stack | `GattSession.MaxPduSize` after connection | A negotiated value before the connection is up |
| Store and load the pairing | Agent, WinUI app | The store call's result | Whether another process rewrote the record |
| Install and remove the phone's certificate | Agent | The store call's result | Whether the browser cached the certificate choice |
| Pair, forget, turn the remote reader off | Cardholder through the WinUI app | The app's view of the agent's state | The agent's state when the app is closed |

## 3. Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| W-UCA-1 | KSP | Open its own transport to the phone for a signature | P | At all over BLE: inside the browser's process it cannot hold the link between signatures, races the agent for the phone's one connection, and pays a connection and a handshake per signature. The current KSP dials a stream session per `SignHash`. | H-7, H-5 |
| W-UCA-2 | KSP | Abort its host process | P | On an internal state the code did not expect: the minidriver's remote transport calls `panic!` (`crates/refineid-minidriver/src/transport.rs`, `raw` and `raw_mut`), and release builds abort on panic, which ends the browser, or LSASS when Windows logon uses the card module. | H-5 |
| W-UCA-3 | KSP | Dial a fixed loopback address as the custodian | P | In a release build: the remote transport falls back to `127.0.0.1:47110`, so any local process that listens there receives the requester's routing preamble and handshake and stalls the login, and a development mock pairing makes it a working fake custodian. | H-7, H-5 |
| W-UCA-4 | KSP | Send a signature request on the pipe | P | When the pipe's server is not the agent: a process that created the pipe name first receives every digest and answers with a refusal or a forged signature. | H-5, H-3 |
| W-UCA-5 | Agent | Accept a request from a pipe client | P | When the client is another user's process or a remote client, so a program outside the cardholder's session makes the card sign. | H-1 |
| W-UCA-6 | KSP | Hand a signature to CNG | P | Without checking it against the public key of the certificate the browser chose: a card other than the cached one, or a forged answer on the pipe, becomes a handshake the server rejects with a message that names nothing (core R-19). | H-5, H-3 |
| W-UCA-7 | Agent | Send a second `operation.request` on the session | P | While one is live: the phone refuses it with `operation_failed` (RAPP §10.4), and a browser that asked for two signatures in one login sees the second fail. | H-7, H-5 |
| W-UCA-8 | Agent or store | Write the pairing's static private key | P | Outside protected storage: the store writes the whole pairing set, private key included, as plaintext to `%LOCALAPPDATA%\RefineID\pairing_set.blob` and `%ProgramData%\RefineID\pairing_set.blob` (`crates/refineid-windows-credential-store/src/pairing.rs`); `%ProgramData%` is readable by every local user, so another account copies the key and acts as this computer towards the phone (issue #35). | H-1, H-6 |
| W-UCA-9 | Store | Report the pairing stored | P | When the Credential Manager write failed and only a plaintext file exists, so the requester believes in a record that is not protected and the core's pairing confirmation (RAPP §4.3 item 4) rests on it. | H-4 |
| W-UCA-10 | Agent | Install the phone's certificate | T | Only once the session is open, when the browser's first request for a client certificate comes earlier, so the browser completes that handshake without a certificate and may not ask the same site again in its session (core UCA-50). | H-7 |
| W-UCA-11 | Agent or app | Remove the phone's certificate | N | When the pairing is forgotten, revoked by the phone, or found unusable at start, so the browser keeps offering an identity no phone will serve. | H-3 |
| W-UCA-12 | Minidriver | Treat a card as remote | P | When its ATR is the development test card's: `is_remote_card` matches `DEV_TEST_CARD_ATR` in every build, so a local card with that ATR is routed to a phone. | H-5, H-3 |
| W-UCA-13 | KSP | Send an origin in the operation context | P | Built from the caller's executable name or `REFINEID_RP_ORIGIN`, when the provider cannot know the site (core UCA-58). | H-1, H-5 |
| W-UCA-14 | Agent | Let Windows release an idle GATT connection | P | While the pairing is usable: without `GattSession.MaintainConnection` the stack closes a connection no one is using, and the locked phone cannot be found again (core UCA-52). | H-7 |
| W-UCA-15 | Agent | Ask Windows to pair with the phone | P | At all (core UCA-56, R-54). | H-5, H-6 |
| W-UCA-16 | Agent | Proceed on a link below the minimum MTU | P | When `GattSession.MaxPduSize` is below 512, so SAR refuses mid-flight and the cause is lost (core UCA-54). | H-5 |
| W-UCA-17 | Engine | Treat a send as done | P | When the send failed: the stream engine discards send results with `let _ =` (`crates/refineid-rapp-core/src/engine.rs`), so a `result_ack` or a `pairing_revoked` close the requester believes delivered never left. | H-4, H-5 |
| W-UCA-18 | KSP | Run each operation on a fresh in-memory copy of the store | P | So the operation journal and candidate state written during the operation are lost when it ends (`crates/refineid-minidriver/src/transport.rs`); an outcome left ambiguous by a lost link cannot be reconciled after a restart (RAPP §8.3). | H-2, H-4 |
| W-UCA-19 | Agent | Start a second instance for the same user | P | While one runs, so two processes hold sessions under one static key (core UCA-31). | H-4 |
| W-UCA-20 | KSP | Wait for the phone | T | Longer than the browser's handshake: the remote transport waits 120 s, so a signature can arrive after the server closed the connection (core UCA-20). | H-5 |

## 4. Loss scenarios

**The browser that dies with the card (W-UCA-2).** A program asks the
minidriver for a raw transport on a remote card, a path the code
believed unreachable. The `panic!` aborts the process. In a browser the
user loses every tab; at a smart card logon, LSASS ends and Windows
restarts. The user sees a crash, never a card error, and the safe
outcome, a refused operation, was one `Result` away.

**The key on the shared disk (W-UCA-8, W-UCA-9).** The pairing set is
written to `%ProgramData%`, which every account on the computer can
read. A second account, or a program running as it, copies the file,
takes the static private key, and routes a session to the phone as this
computer. With PIN 1 stored on the phone, a login runs without a prompt
(core R-56); the phone's history names this computer, so the cardholder
looks for the cause in the wrong place. The private key is the
pairing's identity, and RAPP §4.3 item 4 requires it non-exportable in
platform-protected storage.

**The pipe that answers first (W-UCA-4, W-UCA-5, W-UCA-6).** A program
running as the user creates the agent's pipe name before the agent
starts. The KSP connects and sends the digest of every login; the
program answers with garbage or a refusal, and every login fails with a
TLS error. Had the KSP accepted any well-formed answer, the failure
would look like the phone's.

**The certificate that came too late (W-UCA-10).** The browser starts
and loads a site that asks for a client certificate before the agent
has reached the phone. No certificate is in the store, the browser
completes the handshake without one, and reloading reuses that
handshake. The phone arrives a few seconds later; the login keeps
failing until the browser restarts.

## 5. Requirements

| ID | Requirement | Closes | Refines |
| :--- | :--- | :--- | :--- |
| W-R-1 | The KSP never opens a transport. Every remote signature is one request on the agent's pipe, answered with a typed outcome; the KSP's remote dial path, its loopback fallback and the stream dial are removed. | W-UCA-1, W-UCA-3 | R-50 |
| W-R-2 | No code path the minidriver or KSP can reach panics. An unexpected state returns the provider's failure status (`NTE_INTERNAL_ERROR` for the KSP, `SCARD_E_UNEXPECTED` for the card module). | W-UCA-2 | |
| W-R-3 | The agent creates its pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`, under a DACL that grants the current user's SID alone. It accepts a client only when the client's token user SID and session are its own. | W-UCA-5, W-UCA-4 | R-56 |
| W-R-4 | The KSP connects only to a pipe server whose process runs as the same user in the same session and whose image is the installed agent, and treats any other server as absent. | W-UCA-4 | |
| W-R-5 | The KSP verifies every signature against the public key of the certificate the browser chose before returning it; a signature that does not verify is the KSP's own refusal, distinct from a phone refusal, and the agent is told so it drops its cached certificate (core R-19, R-48, R-49). | W-UCA-6 | R-19 |
| W-R-6 | The agent holds one session per pairing and queues requests: one `operation.request` is live at a time, the next is sent when the previous reached a terminal result, and each queued request keeps its own deadline. | W-UCA-7 | R-47 |
| W-R-7 | The pairing's static private key exists only inside a DPAPI blob protected to the user, stored in Credential Manager; nothing is written to a file, a failed write is a failed pairing, and the store reads Credential Manager alone. The agent deletes the plaintext files wherever it finds them, without reading them; a pairing that existed only there is gone and is paired again. Hardware binding: RAPP §4.3 item 4 asks for a non-exportable key in platform secure hardware. CNG names Curve25519 as an ECDH curve, but whether the Microsoft Platform Crypto Provider (the TPM key storage provider) generates and uses an X25519 key is not established; it is to be tested on this computer's TPM before the store is written. If it cannot, the key stays a DPAPI blob, wrapping that blob with a TPM-held key is an owner decision, and the deviation is stated in the release notes. | W-UCA-8, W-UCA-9 | |
| W-R-8 | The phone's certificate is installed while the pairing is usable and its certificate is cached, before and between sessions; a signature that arrives with no session waits for one within the deadline of W-R-12 (core R-46). It is removed when the pairing is forgotten or revoked, or when W-R-5 refused a signature, and at every agent start the agent removes any RefineID-provider certificate whose pairing is gone. | W-UCA-10, W-UCA-11 | R-46 |
| W-R-9 | `DEV_TEST_CARD_ATR` exists only in test builds; no release build routes a local card to a phone. | W-UCA-12 | |
| W-R-10 | The operation context names this computer and the calling program, labelled as such; nothing is put where the phone shows a site (core R-55). `REFINEID_RP_ORIGIN` is removed. | W-UCA-13 | R-55 |
| W-R-11 | The agent sets `GattSession.MaintainConnection` while a pairing is usable, never calls the Windows pairing API for the phone, reads `GattSession.MaxPduSize` before the first frame through a refined `AttMtu` type whose constructor refuses values below 512, and reports a refusal with the value. | W-UCA-14, W-UCA-15, W-UCA-16 | R-50, R-52, R-54 |
| W-R-12 | The remote signature deadline is one named constant below the browsers' handshake timeouts, sent to the phone as the operation lifetime; a result after it is reconciled through the durable journal and never resent (core R-20). | W-UCA-20 | R-20 |
| W-R-13 | Every engine send returns a result its caller handles; a failed send of a message the protocol counts on (`result_ack`, a close) is retried on the next session or recorded for reconciliation, never assumed. | W-UCA-17 | |
| W-R-14 | The agent owns one durable requester store per pairing, the journal included, and the KSP holds none. | W-UCA-18 | |
| W-R-15 | One agent runs per user, enforced by a session-local named mutex taken before the pipe is created. | W-UCA-19 | R-29 |

## 6. Verification on the first run

The hardware of the first run: this computer's Intel Bluetooth adapter,
an iPhone with Wi-Fi and cellular data off and RefineID installed from
the development build, the cardholder's FINEID card in an ACR39 reader
wired to the iPhone, and Edge at kortti.tunnistautuminen.suomi.fi.

Each step is observed, not assumed, and recorded here with the date
when it has been:

1. The negotiated ATT MTU between this adapter and the iPhone (W-R-11).
2. Pairing over BLE with the six-character code, with no Windows
   pairing dialog (R-54).
3. A session routed by its preamble, `card.status` reporting the wired
   reader's card, and `read_identity` returning the certificates.
4. The link and session surviving the iPhone's screen lock for the
   length of a login (core 16.1).
5. A login at kortti.tunnistautuminen.suomi.fi in Edge, with the
   signature verified by the KSP before it reached CNG (W-R-5), and the
   algorithm the server asked for recorded (core R-48).
6. A login after the iPhone was locked with the link held (R-50), and
   the message shown when the link was dropped on purpose (R-51).
