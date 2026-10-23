# STPA of the Windows requester over Bluetooth

**Status:** prospective, for owner review
**Date:** 2026-10-20
**Applies to:** RAPP v26.10.22, the BLE transport profile
`"fi.refineid.rapp.ble"`, and this repository's requester: the key
storage provider in `refineid_minidriver.dll`, the agent that holds the
phone's session, the pairing and certificate stores, and the WinUI
application

---

## 1. Purpose and relation to the system analysis

The system-level STPA in refineid-core (`doc/security/stpa-rapp.md`)
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
        └───────────────────────────────────┘      └─ pairing store (DPAPI file)
                                                    │  GATT write / indication
                                                    ▼
                                      WinRT Bluetooth LE stack ── radio ── iPhone custodian
```

Downward arrows are control actions; the returns are feedback.

| Control action | Controller | Feedback present | Feedback absent |
| :--- | :--- | :--- | :--- |
| Ask for a client certificate signature | Browser | The KSP's status and signature | Whether a failure came from the KSP, the agent, the link or the phone; the browser reports every one as a failed handshake |
| Sign a hash | KSP | The agent's answer on the pipe | Whether the pipe's server is the agent; which site the browser is signing for (CNG carries no origin) |
| Relay a signature request to the phone | Agent | `operation.progress`, `operation.result`, the close reason, the session's liveness | Which program called the KSP, beyond the pipe client's process identity |
| Hold the BLE link and session | Agent | GATT connection status, liveness, `card.status` | Whether the phone is findable if the link drops (core 16.1) |
| Negotiate the link | WinRT stack | `GattSession.MaxPduSize` after connection | A negotiated value before the connection is up |
| Store and load the pairing | Agent, WinUI app | The store call's result | Whether another process rewrote the record |
| Install and remove the phone's certificate | Agent | The store call's result | Whether the browser cached the certificate choice |
| Pair, forget, turn the remote reader off | Cardholder through the WinUI app | The app's view of the agent's state | The agent's state when the app is closed |
| Answer the Base CSP and KSP for a card | Card module (`refineid_minidriver.dll`, the same DLL as the KSP) | The PC/SC card's answers | Which process loaded it: a browser for a client certificate, or LSASS at smart card logon, where no user session and no agent exist |
| Send and receive protocol messages | RAPP engine (inside the agent) | The transport's result for every send | Whether a send the engine did not check reached the phone |
| Read and write records | Pairing store (DPAPI-protected file) | The API's result | Whether a record it reports written is protected |

## 3. Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| W-UCA-1 | KSP | Open its own transport to the phone for a signature | P | At all over BLE: inside the browser's process it cannot hold the link between signatures, races the agent for the phone's one connection, and pays a connection and a handshake per signature. The current KSP dials a stream session per `SignHash`. | H-7, H-5 |
| W-UCA-2 | KSP | Abort its host process | P | On an internal state the code did not expect: the minidriver's remote transport calls `panic!` (`crates/refineid-minidriver/src/transport.rs`, `raw` and `raw_mut`), and release builds abort on panic, which ends the browser, or LSASS when Windows logon uses the card module. | H-5 |
| W-UCA-3 | KSP | Dial a fixed loopback address as the custodian | P | In a release build: the remote transport falls back to `127.0.0.1:47110`, so any local process that listens there receives the requester's routing preamble and handshake and stalls the login, and a development mock pairing makes it a working fake custodian. | H-7, H-5 |
| W-UCA-4 | KSP | Send a signature request on the pipe | P | When the pipe's server is not the agent: a process that created the pipe name first receives every digest and answers with a refusal or a forged signature. | H-5, H-3 |
| W-UCA-5 | Agent | Accept a request from a pipe client | P | When the client is another user's process or a remote client, so a program outside the cardholder's session makes the card sign. | H-1 |
| W-UCA-6 | KSP | Hand a signature to CNG | P | Without checking it against the public key of the certificate the browser chose: a card other than the cached one, or a forged answer on the pipe, becomes a handshake the server rejects with a message that names nothing (core CC-19). | H-5, H-3 |
| W-UCA-7 | Agent | Send a second `operation.request` on the session | P | While one is live: the phone refuses it with the `error` `busy` (RAPP §8.1 item 1), and a browser that asked for two signatures in one login sees the second fail. | H-7, H-5 |
| W-UCA-8 | Pairing store | Write the pairing's static private key | P | Outside protected storage: the store writes the whole pairing set, private key included, as plaintext to `%LOCALAPPDATA%\RefineID\pairing_set.blob` and `%ProgramData%\RefineID\pairing_set.blob` (`crates/refineid-windows-credential-store/src/pairing.rs`); `%ProgramData%` is readable by every local user, so another account copies the key and acts as this computer towards the phone (issue #35). | H-1, H-6 |
| W-UCA-9 | Store | Report the pairing stored | P | When the Credential Manager write failed and only a plaintext file exists, so the requester believes in a record that is not protected and the core's pairing confirmation (RAPP §4.3 item 4) rests on it. | H-4 |
| W-UCA-10 | Agent | Install the phone's certificate | T | Only once the session is open, when the browser's first request for a client certificate comes earlier, so the browser completes that handshake without a certificate and may not ask the same site again in its session (core UCA-50). | H-7 |
| W-UCA-11 | Agent or app | Remove the phone's certificate | N | When the pairing is forgotten, revoked by the phone, or found unusable at start, when a session hears another card, or when no session has heard the card for the grace of RAPP §8.4 item 3, so the browser keeps offering an identity no phone will serve. | H-3 |
| W-UCA-12 | Card module | Treat a card as remote | P | When its ATR is the development test card's: `is_remote_card` matches `DEV_TEST_CARD_ATR` in every build, so a local card with that ATR is routed to a phone. | H-5, H-3 |
| W-UCA-13 | KSP | Send an origin in the operation context | P | Built from the caller's executable name or `REFINEID_RP_ORIGIN`, when the provider cannot know the site (core UCA-58). | H-1, H-5 |
| W-UCA-14 | Agent | Maintain the GATT connection (`GattSession.MaintainConnection`) | N | While the pairing is usable: without it the stack closes a connection no one is using, and the locked phone cannot be found again (core UCA-52). | H-7 |
| W-UCA-15 | Agent | Ask Windows to pair with the phone | P | At all (core UCA-56, CC-54). | H-5, H-6 |
| W-UCA-16 | Agent | Judge the link's MTU | T | Too early: `GattSession.MaxPduSize` reports the default ATT MTU until the exchange with the phone completes and `MaxPduSizeChanged` fires, so a judgement made at connection refuses every link; or never, so a link below 512 proceeds, SAR refuses mid-flight, and the cause is lost (core UCA-54). | H-5, H-7 |
| W-UCA-17 | Engine | Treat a send as done | P | When the send failed, so a `pairing_revoked` close the requester believes delivered never left, and the phone goes on serving a pairing this computer forgot (RAPP §4.6). | H-4, H-5 |
| W-UCA-18 | Card module, KSP | Run each operation over a copy of the pairing store | P | So a `pairing_revoked` close received during the operation revokes only the copy, and the pairing goes on serving here after the phone forgot it (RAPP §4.6 item 4). | H-3, H-4 |
| W-UCA-19 | Agent | Start a second instance for the same user | P | While one runs, so two processes hold sessions under one static key (core UCA-31). | H-4 |
| W-UCA-20 | KSP | Return the signature outcome to CNG | T | Too late, after the browser's handshake deadline: the remote transport sends a 120 s operation lifetime and waits for the result as long as the session lives, so a signature can arrive after the server closed the connection (core UCA-20). | H-5 |
| W-UCA-21 | KSP | Connect to the agent's pipe | N | When the browser signs from a sandboxed process (an AppContainer or less-privileged AppContainer token) that a DACL granting the user's SID alone refuses, or that cannot open the agent's process to check its image, so every login fails as if no phone were paired. Which process loads the KSP for a client certificate, and with which token, is not established for Edge and Chrome. | H-7 |
| W-UCA-22 | Card module | Run the remote arm | P | In LSASS at smart card logon, or in any process without the user's agent: the per-user agent and its pipe do not exist there, so the arm can only fail or dial on its own (W-UCA-1). | H-5, H-7 |
| W-UCA-23 | Agent or app | Remove the phone's certificate | T | Too early: when a session merely ended or the phone reported its card absent, before the grace of RAPP §8.4 item 3 passed, so a login a moment later finds no certificate and the browser does not ask the site again (core UCA-62). | H-7 |

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
computer. With PIN 1 held in the phone's memory, a login runs without a prompt
(core CC-56, CC-66); the phone's history names this computer, so the cardholder
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
| W-R-1 | Neither the KSP nor the card module opens a transport. Every remote signature is one KSP request on the agent's pipe, answered with a typed outcome; the remote dial path, its loopback fallback and the stream dial are removed, and the card module's remote arm with them, so a card module in LSASS or in a process without the agent serves local cards only. | W-UCA-1, W-UCA-3, W-UCA-22 | CC-50 |
| W-R-2 | No code path the minidriver or KSP can reach panics. An unexpected state returns the provider's failure status (`NTE_INTERNAL_ERROR` for the KSP, `SCARD_E_UNEXPECTED` for the card module). | W-UCA-2 | |
| W-R-3 | The agent creates its pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`, under a DACL that grants the current user's SID alone. It accepts a client only when the client's token user SID and session are its own. | W-UCA-5 | CC-56 |
| W-R-4 | The KSP connects only to a pipe server whose process runs as the same user in the same session and whose image is the installed agent (`GetNamedPipeServerProcessId`), and treats any other server as absent. | W-UCA-4 | |
| W-R-4a | Before the pipe's DACL and the server check are written, the first run records which process loads the KSP for a client certificate in Edge and in Chrome and the integrity level and AppContainer state of its token. If it is sandboxed, the DACL grants that sandbox's capability SID and no broader package group, and the server check uses what that token may query; the identity rules of W-R-3 and W-R-4 hold either way. | W-UCA-21 | |
| W-R-5 | The KSP verifies every signature against the public key of the certificate the browser chose before returning it; a signature that does not verify is the KSP's own refusal, distinct from a phone refusal, and the agent is told so it drops its cached certificate (core CC-19, CC-48, CC-49). | W-UCA-6 | CC-19 |
| W-R-6 | The agent holds one session per pairing and queues requests: one `operation.request` is live at a time, the next is sent when the previous reached a terminal result, and each queued request keeps its own deadline. | W-UCA-7 | CC-47 |
| W-R-7 | (a) The pairing store protects the whole pairing set with DPAPI to the current user under a purpose entropy and writes it as one file in the user's local application data, through a temporary file and a rename; it writes no plaintext anywhere, a failed write is a failed pairing, and it reads that file alone. A Credential Manager credential cannot hold the set: a record carries its cached certificates, and a generic credential holds at most `CRED_MAX_CREDENTIAL_BLOB_SIZE` (2560) bytes. (b) The store deletes the plaintext files and the unprotected generic credential wherever it finds them, without reading them; a pairing that existed only there is gone and is paired again. (c) If the Microsoft Platform Crypto Provider (the TPM key storage provider) can generate and use an X25519 key on this computer's TPM, which is tested before a key is generated there, the key is TPM-resident and non-exportable, as RAPP §4.3 item 4 asks. (d) If it cannot, (a) stands, wrapping the blob with a TPM-held key is an owner decision, and the deviation from §4.3 item 4 is stated in the release notes. | W-UCA-8, W-UCA-9 | |
| W-R-8 | Every consumer this computer offers the phone's identity to (the certificate the agent and the app install in `CurrentUser\My`, the PKCS#11 remote slot, the card module's remote card) is offered on the certificate whose card a session heard present, before and between sessions: the engine records the card each session hears present, again every 10 seconds while it stays present, as the pairing's card sighting beside the pairing store, and every consumer offers by that one sighting. A signature that arrives with no session waits for one within the deadline of W-R-12. The offer goes once no session has heard the card for `IDENTITY_OFFER_GRACE_MS` (120 seconds; a report of absence is not another card and starts no shorter clock); at once when a session hears another card, whose certificate is then read on that session and offered once stored (RAPP §8.4 item 2); at once when the pairing is forgotten or revoked; when W-R-5 refused a signature; and when the app's offering watch ends, as nothing would withdraw it after. The agent and the app judge the offer at the present moment and wait between sessions no longer than the standing offer has left, so it is withdrawn when the grace ends, within one search or browse, and never before. A request that finds a session freshly opened runs only after the phone's first `card.status` on it has been followed. At every agent start the agent removes any RefineID-provider certificate whose pairing is gone. | W-UCA-10, W-UCA-11, W-UCA-23 | CC-64 |
| W-R-9 | `DEV_TEST_CARD_ATR` exists only in test builds; no release build routes a local card to a phone. | W-UCA-12 | |
| W-R-10 | The operation context names this computer and the calling program, labelled as such; nothing is put where the phone shows a site (core CC-55). `REFINEID_RP_ORIGIN` is removed. | W-UCA-13 | CC-55 |
| W-R-11 | The agent sets `GattSession.MaintainConnection` while a pairing is usable, never starts operating-system pairing with the phone (`DeviceInformation.Pairing`, its `PairAsync` and custom pairing) and never requests an encrypted or authenticated GATT protection level, judges the MTU once the exchange has completed (`GattSession.MaxPduSizeChanged`, or a `MaxPduSize` already above the default when the session opens), within a named bounded wait, and before the first frame, through a refined `AttMtu` type whose constructor refuses values below 512; a refusal, or a wait that ends without an exchange, is reported with the value. | W-UCA-14, W-UCA-15, W-UCA-16 | CC-50, CC-52, CC-54 |
| W-R-12 | The remote signature deadline is one named constant below the browsers' handshake timeouts, sent to the phone as the operation lifetime; an operation whose result does not arrive ends with its session and is never resent (RAPP §8.1 item 3; core CC-20). | W-UCA-20 | CC-20 |
| W-R-13 | Every engine send returns a result its caller handles; a `pairing_revoked` close whose send failed leaves the pairing forgotten, keys kept, so the next session carries it as its first message (RAPP §4.6 item 2); it is never assumed delivered. | W-UCA-17 | |
| W-R-14 | The agent and the card module's remote arm run the requester over the protected pairing store itself, so a `pairing_revoked` close received on any session revokes the stored pairing at once (RAPP §4.6 item 4); nothing of an operation is stored (§8.1 item 3), and the KSP holds no store. | W-UCA-18 | |
| W-R-15 | One agent runs per user, enforced by a session-local named mutex taken before the pipe is created. | W-UCA-19 | CC-29 |

## 6. Verification on the first run

The hardware of the first run: this computer's Intel Bluetooth adapter,
an iPhone with Wi-Fi and cellular data off and RefineID installed from
the development build, the cardholder's FINEID card in an ACR39 reader
wired to the iPhone, and Edge at kortti.tunnistautuminen.suomi.fi.

Each step is observed, not assumed, and recorded here with the date
when it has been:

1. The negotiated ATT MTU between this adapter and the iPhone, and how
   long after connection `MaxPduSizeChanged` fires (W-R-11). Observed
   2026-10-21: an ATT MTU of 527 bytes, a fragment capacity of 506 bytes,
   in two connections; the delay before `MaxPduSizeChanged` is not yet
   measured.
2. Which process loads the KSP for a client certificate in Edge and in
   Chrome, with its token's integrity level and AppContainer state
   (W-R-4a). Observed 2026-10-21 for Edge: the browser process
   (`msedge.exe` without `--type`) loads the provider when the site asks
   for a client certificate, at medium integrity (`0x2000`), not in an
   AppContainer; the pipe's DACL for the user's SID admits it, and no
   capability SID is granted. Chrome is not yet observed.
3. Pairing over BLE with the six-character code, with no Windows
   pairing dialog (CC-54). Observed 2026-10-21: two pairings with the
   iPhone's development harness completed `CPace`, `Noise_XXpsk3`, the grant
   exchange and the storage confirmation over BLE alone; Windows showed no
   pairing dialog and listed no bonded device afterwards. The phone
   advertised under a different address in the second run, as the
   rotating private address of RAPP §4.1 predicts (core CC-53).
4. A session routed by its preamble, `card.status` reporting the wired
   reader's card, and `read_identity` returning the certificates.
   Observed 2026-10-21: sessions routed to a fresh address each time
   returned the card's status, its identity and the 1066-byte
   authentication certificate. The agent then offered that certificate in
   `CurrentUser\My`, Edge chose it for card.refineid.fi and called the
   provider, and a provider built from this tree sent the signature
   request through the agent to the phone, which asked the holder for
   PIN 1.
5. The link and session surviving the iPhone's screen lock for the
   length of a login (core 16.1).
6. A login at kortti.tunnistautuminen.suomi.fi in Edge, with the
   signature verified by the KSP before it reached CNG (W-R-5), and the
   algorithm the server asked for recorded (core CC-48). Observed
   2026-10-21: with the iPhone's Wi-Fi and cellular data off and Bluetooth
   its only link, the holder logged in to suomi.fi with the certificate
   card in Edge, and to card.refineid.fi; each signature was one ECDSA
   signature of 96 bytes (P-384) the phone returned within a second once PIN 1
   was cached, verified by the KSP before Edge received it. The digest
   algorithm the server asked for is not yet recorded.
7. A login after the iPhone was locked with the link held (CC-50), and
   the message shown when the link was dropped on purpose (CC-51).
