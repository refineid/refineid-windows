# STPA of the Windows requester over Bluetooth

**Status:** prospective, for owner review
**Date:** 2026-10-20
**Applies to:** RAPP v26.11.2, the BLE transport profile
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
| Install and remove the phone's certificate | Agent, WinUI app (whichever holds the phone's session) | The store call's result; the session's `card.status` and the certificate read on it | Whether the browser cached the certificate choice; a browser's handshake that found no entry, which calls no provider |
| Pair, forget, turn the remote reader off | Cardholder through the WinUI app | The app's view of the agent's state | The agent's state when the app is closed |
| Answer the Base CSP and KSP for a card | Card module (`refineid_minidriver.dll`, the same DLL as the KSP) | The PC/SC card's answers | Which process loaded it: a browser for a client certificate, or LSASS at smart card logon, where no user session and no agent exist |
| Send and receive protocol messages | RAPP engine (inside the agent) | The transport's result for every send | Whether a send the engine did not check reached the phone |
| Withdraw from the phone when the user quits the agent | Agent, through the RAPP engine | Each open session's end, its `service_withdrawn` close written or its link failed, within the quit bound | Whether a close not written within the bound reached the phone |
| Expire an idle pairing; record that a session is established | Agent (expiry), RAPP engine in every process that holds a session (session times) | The latest time a session to the pairing was established, kept in the stored record and read against the wall clock; the store's result for each write | A session another process holds, except through the times it records; the phone, which has been out of reach |
| Read and write records | Pairing store (DPAPI-protected file) | The API's result | Whether a record it reports written is protected |
| Propagate the root certificates of a card's `msroots` file into the user's `SmartCardRoot` store, part of `CurrentUser\Root` | Certificate Propagation Service (Windows), on the card module's answer | The card module's `msroots` file, or `SCARD_E_FILE_NOT_FOUND` | Who chose the certificates: a card is not a trust authority, and the file carries no purpose to narrow them to |
| Remove the roots earlier builds had propagated | Installer custom action `RemoveCardRoots`, as `LocalSystem` | Each user's `SmartCardRoot` entries with the cards Windows recorded as propagating them, and each deletion's result | Profiles not loaded while it runs; a card whose authentication certificate already left the Personal store |
| Propagate a card's certificates into `CurrentUser\My` | Certificate Propagation Service (Windows), when a card the Card Module serves is inserted | The Card Module's containers and their certificates | That the card left: the entries stay when it is removed |
| Remove the propagated entries of cards not in a reader | Agent's card thread, in the user's session from sign-in to sign-out | Every reader's state and card insertion and removal count (`SCardGetStatusChange`, which touches no card); the card database's module for each card's answer to reset; each card's certificates through the Smart Card Key Storage Provider | When propagation writes an entry; whether a card it could not read is FINEID's |

## 3. Unsafe control actions

One hazard is this platform's own: **W-H-1**, the user's trust anchors are not
the ones their owners chose. A card puts a certification authority among them,
whose key then vouches for any web server the user's programs reach (L-4), or
RefineID takes away one the Microsoft root update, an administrator or another
program placed, and logins and connections that chain to it fail (L-3).

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
| W-UCA-13 | KSP, card module, PKCS#11 module | Send a site in the operation context | P | Taken from the launching process's environment or a fixed default, when the provider cannot know the site (core UCA-58). | H-1, H-5 |
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
| W-UCA-24 | Agent | Stop using the phone without telling it | P | When the user quits the agent (Ctrl+C, Ctrl+Break, or closing its console window): the phone still treats the computer as available, and a PIN prompt for the agent's operation stays up until the session's silence limit ends it (core UCA-95). | H-5 |
| W-UCA-25 | Agent | Expire an idle pairing | P | While a session to it is open, in the agent or in another process (the app's offering watch, the PKCS#11 module), or less than 30 days after the last one: a check made apart from the session's state, or one that reads no time for a session nobody recorded, ends a working pairing and the holder pairs again (core UCA-98). | H-7, H-4 |
| W-UCA-26 | Agent | Expire an idle pairing | N | When it has had no session for 30 days: an agent that checks only at start, or not while it holds another pairing's session, keeps a pairing whose phone is gone usable (core UCA-99). | H-6, H-1 |
| W-UCA-27 | Pairing store | Report an expiry or a session time done | P | When its write failed: the process acts on a record that is not stored, the next process reads the pairing as it was, and the write is never repeated. | H-4, H-3 |
| W-UCA-28 | Pairing store | Refuse the whole stored set | P | When one record in it is in a format this build no longer reads (no migration): every pairing is lost to every process, and the agent fails the same load every round. | H-7 |
| W-UCA-29 | Agent, app, card module, KSP | Dial the phone | P | While the phone is withdrawn or closed with `card_unavailable` and has not announced itself again, after a protocol violation with no appearance and no request, or on a pause timer outside the redial window: a phone that cannot serve is dialed again and again, and a version mismatch loops (core UCA-113, CC-114, CC-115). | H-5, H-6 |
| W-UCA-30 | Agent, app, card module, KSP | Keep offering the phone's identity | D | After a `service_withdrawn` or `card_unavailable` close, or a verified withdrawn record, held for the grace as after a loss (core UCA-112, CC-114). | H-3 |
| W-UCA-31 | Engine | Treat its goodbye as delivered | P | When the phone never echoed the close: a `pairing_revoked` sent in a bounded attempt or a withdrawal on quit is taken as acted on (core UCA-124, CC-123). | H-4, H-5 |
| W-UCA-32 | App, agent | Keep a forgotten pairing's keys | D | Past the 10-second bounded attempt, or send a close on idle expiry (core UCA-123, CC-118). | H-4, H-6 |
| W-UCA-33 | Card module | Send `sign_document` for a hash handed to it | P | With a file name it made up or one the calling program supplied: the minidriver and CNG signing calls carry no document name, and the holder consents under the name the phone shows (RAPP §11 item 1). | H-1, H-5 |
| W-UCA-34 | Pairing store | Keep a holder's certificate | P | At all, on a computer several people share one Windows user on: anyone with that user's rights unprotects the set and reads who used the computer (L-4). | H-6 |
| W-UCA-35 | Pairing store, agent, app | Keep a pairing's `CurrentUser\My` entry | D | After its record is forgotten, revoked, expired or replaced, or once no session heard its card for the grace, when the process that would remove it crashed or never ran: the store acts on an old reading, and the entry names the holder in every program that lists the store (L-4). | H-6 |
| W-UCA-36 | Pairing store | Keep a card sighting or a revoked record | D | After its pairing left, or for longer than it bounds an offer or carries a notice: the plain file says which card was here and when, and the record names the phone (L-4). | H-6 |
| W-UCA-37 | Card module | Ask the Base CSP for its global cache | P | For a holder's certificates: Microsoft documents a global cache keyed by the card and does not state whether it outlives the card or a restart, so the module cannot know what it leaves behind (L-4). | H-6 |
| W-UCA-38 | GUI | Write a holder's face to the temp directory | P | At all: the file outlives the read, the program and the person (L-4). | H-6 |
| W-UCA-39 | Card module | Serve the card's root and issuing CA as `msroots` | P | At all: Windows propagates them into `CurrentUser\Root`, trusted for every purpose including TLS server authentication, chosen by whichever card is inserted. | W-H-1 |
| W-UCA-40 | Installer | Leave a root an earlier build had propagated | N | After the build that stops serving `msroots` is installed: the entry stays until the user signs out, and for good where Group Policy turns root clean-up off. | W-H-1 |
| W-UCA-41 | Installer | Remove a root | P | When the Microsoft root update, an administrator, another program or another card module put it there, the same bytes included. | W-H-1 |
| W-UCA-42 | Agent (card thread) | Remove a card's propagated entries | N | After the card left a reader of this computer: the entry names its holder in every program that lists the store, and on one Windows user shared by several people every holder who ever inserted a card stays listed (L-4). Windows does not remove them. | H-6 |
| W-UCA-43 | Agent (card thread) | Remove a card's propagated entries | P | While the card is in a reader: a reading of the readers taken before a card arrived, a card it could not read taken for absent, or a reader name the key storage provider does not resolve taken for an empty card. The browser then offers no certificate for the card in the reader, and propagation does not write it again until the card is inserted again (L-3; H-7 with the card in the reader in place of the phone). | H-7 |
| W-UCA-44 | Agent (card thread) | Remove an entry | P | When another vendor's card module or another program wrote it, a PIV card's under the same container name included (L-3). | H-7 |
| W-UCA-45 | Agent, app | Install the phone's certificate | T | Only after the browser asked: a browser that found no entry completes the handshake without a certificate and does not ask the site again (core UCA-50). The provider is not called then, so it cannot wake the phone. | H-7 |
| W-UCA-46 | Agent (card thread) | Put a card's CA where Windows reads it | P | In a trust store; or a root in a release build; or a development build's test root valid for any purpose but TLS client authentication; or for a card whose root is not a self-signed CA, or an issuing CA that root did not issue and sign; or leave it after the card left. | W-H-1 |
| W-UCA-47 | Agent (card thread) | Not put a card's issuing CA where Windows reads it | N | While a FINEID card is in a reader: a browser that matches client certificates in the local stores finds no issuer for its authentication certificate, so a server naming that CA sees no certificate and one needing the intermediate does not get it. | W-H-1 |
| W-UCA-48 | PKCS#11 module | Answer whether the phone's token is there | N | From the `CurrentUser\My` entry alone, without asking the phone: a browser that reads the phone's slot through the module during a handshake, without listing the slots, finds no token and keeps that answer (core UCA-125). | H-7 |
| W-UCA-49 | PKCS#11 module | Dial the phone | P | At a call refineid-core grants no wait (`C_Initialize`, the non-blocking slot-event poll), or so that a call outlasts its wait: the browser is held past the bound of core CC-124. | H-5 |

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

The State column records what the code does today against each
requirement; an empty cell records no state.

| ID | Requirement | Closes | Refines | State |
| :--- | :--- | :--- | :--- | :--- |
| W-R-1 | Neither the KSP nor the card module opens a transport. Every remote signature is one KSP request on the agent's pipe, answered with a typed outcome; the remote dial path, its loopback fallback and the stream dial are removed, and the card module's remote arm with them, so a card module in LSASS or in a process without the agent serves local cards only. | W-UCA-1, W-UCA-3, W-UCA-22 | CC-50 | Not yet: the card module keeps its remote arm and dial path (#117). |
| W-R-2 | No code path the minidriver or KSP can reach panics. An unexpected state returns the provider's failure status (`NTE_FAIL` for the KSP, `SCARD_F_INTERNAL_ERROR` for the card module). | W-UCA-2 | | Not yet: `raw()` and `raw_mut()` panic for a remote card (#117). |
| W-R-3 | The agent creates its pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`, under a DACL that grants the current user's SID alone. It accepts a client only when the client's token user SID and session are its own. | W-UCA-5 | CC-56 | Implemented; the client is identified by its process token (#118 tracks the impersonation token). |
| W-R-4 | The KSP connects only to a pipe server whose process runs as the same user in the same session and whose image is the installed agent (`GetNamedPipeServerProcessId`), and treats any other server as absent. | W-UCA-4 | | Yes: `client.rs` compares the server's image, as Windows reports it, with `RefineID\refineid-agent.exe` under the Program Files directory Windows reports, where the MSI installs it, before it writes anything. A development agent runs from there too. The machine's `Run` value `RefineIDAgent`, which the installer writes and removes, starts the agent at every sign-in. |
| W-R-4a | Before the pipe's DACL and the server check are written, the first run records which process loads the KSP for a client certificate in Edge and in Chrome and the integrity level and AppContainer state of its token. If it is sandboxed, the DACL grants that sandbox's capability SID and no broader package group, and the server check uses what that token may query; the identity rules of W-R-3 and W-R-4 hold either way. | W-UCA-21 | | |
| W-R-5 | The KSP verifies every signature against the public key of the certificate the browser chose before returning it; a signature that does not verify is the KSP's own refusal, distinct from a phone refusal, and the agent is told so it drops its cached certificate (core CC-19, CC-48, CC-49). | W-UCA-6 | CC-19 | In part: the KSP verifies and refuses; the agent is not told (no issue yet). |
| W-R-6 | The agent holds one session per pairing and queues requests: one `operation.request` is live at a time, the next is sent when the previous reached a terminal result, and each queued request keeps its own deadline. | W-UCA-7 | CC-47 | |
| W-R-7 | (a) The pairing store protects the whole pairing set with DPAPI to the current user under a purpose entropy and writes it as one file in the user's local application data, through a temporary file and a rename; it writes no plaintext anywhere, a failed write is a failed pairing, and it reads that file alone. A Credential Manager credential cannot hold the set: a record carries its cached certificate, and a generic credential holds at most `CRED_MAX_CREDENTIAL_BLOB_SIZE` (2560) bytes. (b) The store deletes the plaintext files and the unprotected generic credential wherever it finds them, without reading them; a pairing that existed only there is gone and is paired again. (c) If the Microsoft Platform Crypto Provider (the TPM key storage provider) can generate and use an X25519 key on this computer's TPM, which is tested before a key is generated there, the key is TPM-resident and non-exportable, as RAPP §4.3 item 4 asks. (d) If it cannot, (a) stands, wrapping the blob with a TPM-held key is an owner decision, and the deviation from §4.3 item 4 is stated in the release notes. | W-UCA-8, W-UCA-9 | | |
| W-R-8 | Every consumer this computer offers the phone's identity to (the certificate the agent and the app install in `CurrentUser\My`, the PKCS#11 remote slot, the card module's remote card) is offered on the certificate whose card a session heard present, before and between sessions: the engine records the card each session hears present, again every 10 seconds while it stays present, as the pairing's card sighting beside the pairing store, and every consumer offers by that one sighting. The process that holds the session reads the certificate on every session, keeps it in memory only, and offers it only when the phone confirmed its fingerprint; the KSP, through the agent, and the card module's remote arm read it from the `CurrentUser\My` entry while the sighting stands for it. The PKCS#11 module reads that entry too, and at a call that can show the phone's token while none stands and refineid-core grants a wait (core CC-124, at most 3 seconds), it dials the phone as a local consumer's request (RAPP §8.3), has the session confirm the card and read its certificate within that wait, and holds that certificate in its own memory, offered by the same sighting; a dial that outlasts the wait goes on and serves the calls after it, and a call granted no wait dials nothing. It follows the pairing store at each call, reading the protected set again only when its file changed. The agent runs from sign-in and dials the phone when it appears (W-R-18), so the entry is in place while the phone is in reach. A signature that arrives with no session waits for one within the deadline of W-R-12. The offer goes, and the certificate leaves the process's memory, once no session has heard the card for `IDENTITY_OFFER_GRACE_MS` (120 seconds; a report of absence is not another card and starts no shorter clock); at once when a session hears another card, whose certificate is then read on that session (RAPP §8.4 item 2); at once when the pairing is forgotten, expires (W-R-17) or is revoked; at once when the agent quits (W-R-16); when W-R-5 refused a signature; and when the app's offering watch ends, as nothing would withdraw it after. The agent and the app judge the offer at the present moment and wait between sessions no longer than the standing offer has left, so it is withdrawn when the grace ends, within one search or browse, and never before. A request that finds a session freshly opened runs only after the phone's first `card.status` on it has been followed. At every agent start the agent removes every RefineID-provider certificate, and every load and written change of the pairing store removes each one no sighting within the grace stands for (W-R-21). A browser chooses its client certificate from `CurrentUser\My` before it calls any key storage provider, so with no entry standing nothing of RefineID is asked and no handshake can wake the phone. | W-UCA-10, W-UCA-11, W-UCA-23, W-UCA-45, W-UCA-48, W-UCA-49 | CC-64, CC-124 | Host tests in `refineid-pkcs11` (`wake`, with fake phones: a dial within the wait, one out of reach, one shared, none at a zero wait). Host tests in `refineid-rapp-core` (`store`, `offer_stands`) and `refineid-windows-credential-store` (`certstore`, the entry judgement with fake sightings). Needs the phone: the entry appears within a session of the phone coming into reach and goes 120 seconds after it left. |
| W-R-9 | `DEV_TEST_CARD_ATR` exists only in test builds; no release build routes a local card to a phone. | W-UCA-12 | | Not yet: every build accepts `DEV_TEST_CARD_ATR` as a remote card (#117). |
| W-R-10 | The operation context names this computer and the calling program and never a site (core CC-25, CC-55); RAPP §9.2 requires the field, and the phone does not show it (§11 item 1). The agent labels the pipe client from the image path Windows reports, with a product name only below Program Files. The card module and the PKCS#11 module run inside the caller, whose environment names those directories, so they send the image's file name. An image path that names no file is refused, not described. `REFINEID_RP_ORIGIN`, `REFINEID_ORIGIN` and the fixed default are removed. | W-UCA-13 | CC-25, CC-55 | Implemented 2026-11-07; the card module and PKCS#11 arms are built, not run on Windows. |
| W-R-11 | The agent sets `GattSession.MaintainConnection` while a pairing is usable, never starts operating-system pairing with the phone (`DeviceInformation.Pairing`, its `PairAsync` and custom pairing) and never requests an encrypted or authenticated GATT protection level, judges the MTU once the exchange has completed (`GattSession.MaxPduSizeChanged`, or a `MaxPduSize` already above the default when the session opens), within a named bounded wait, and before the first frame, through a refined `AttMtu` type whose constructor refuses values below 512; a refusal, or a wait that ends without an exchange, is reported with the value. | W-UCA-14, W-UCA-15, W-UCA-16 | CC-50, CC-52, CC-54 | |
| W-R-12 | The remote signature deadline is one named constant below the browsers' handshake timeouts, sent to the phone as the operation lifetime; an operation whose result does not arrive ends with its session and is never resent (RAPP §8.1 item 3; core CC-20). | W-UCA-20 | CC-20 | |
| W-R-13 | Every engine send returns a result its caller handles; a `pairing_revoked` close whose send failed leaves the pairing forgotten, keys kept for the one bounded attempt of RAPP §4.6 item 6; it is never assumed delivered. Every close the engine sends waits for the phone's echo within its bound (1 second with a session open; the rest of the 10-second attempt for a revocation in place of `session.hello`), ignoring everything but a close; every close the engine receives is answered with its echo; a close that crosses the engine's own is its acknowledgement and is acted on (RAPP §7.1 item 7). A forget with a session open destroys the keys after that wait; with none open, the app or the agent makes one attempt of at most 10 seconds, opening at most one connection, and the keys are destroyed when the echo arrives or the bound passes. | W-UCA-17, W-UCA-31, W-UCA-32 | CC-118, CC-123 | |
| W-R-14 | The agent and the card module's remote arm run the requester over the protected pairing store itself, so a `pairing_revoked` close received on any session revokes the stored pairing at once (RAPP §4.6 item 4); nothing of an operation is stored (§8.1 item 3), and the KSP holds no store. | W-UCA-18 | | Yes: the KSP asks the agent which key it offers and receives a pair id and a public certificate over the pipe; the store loads in the agent alone. The card module's remote arm is a separate path and still loads the store in-process, as this constraint allows. |
| W-R-15 | One agent runs per user, enforced by a session-local named mutex taken before the pipe is created. | W-UCA-19 | CC-29 | Implemented. |
| W-R-16 | An agent started from a console attaches to it, and Ctrl+C, Ctrl+Break and closing that console are the user quitting the agent; the agent Windows starts at sign-in has no console and shows nothing. Quitting withdraws (RAPP §4.5 item 8): the engine closes each open session with `service_withdrawn` within one receive tick (`SESSION_RECEIVE_TICK`, a quarter of the quit bound), ending an operation in flight with it, dials no session or revocation notice after it, and keeps the pairing; the agent waits at most `QUIT_WITHDRAWAL_BOUND_MS` (1 second) for the closes to be written, withdraws the browsers' offer (§8.4 item 3), and exits. A connection whose session is not yet open closes without a notice. Log-off, shutdown, sleep, network loss and a killed process send nothing. | W-UCA-24 | CC-98 | |
| W-R-17 | The engine records on a pairing that a session to it is established when the phone's `session.ready` is verified, once a day while the session lasts, and when it ends, in every process that holds a session (RAPP §4.6 item 5). The agent checks every pairing for idle expiry each time it reads the pairing store, at start and between sessions, and once a day while it holds a session, the held pairing counting as in session. A pairing with no established session for 30 days, counted from its creation while it has had none, expires: its keys are destroyed at once, its identity is withdrawn from every consumer (W-R-8), and nothing is sent or shown (RAPP §4.6 item 6). Each check writes the whole stored set with the changed record before the record held in memory changes; a refused write changes nothing and is repeated at the next check or session event. A stored record the codec refuses for its format is left out when the set is read, and the set is written back without it, so it is refused once; development builds report each refusal. | W-UCA-25, W-UCA-26, W-UCA-27, W-UCA-28 | CC-101, CC-103 | |
| W-R-18 | Every process that dials keeps the requester's view of the phone per pairing (RAPP §4.7, `requester_view_of_custodian`) and dials only as it admits (§8.3): when the phone appears (a `mode=session` record under an instance name not in sight at the previous browse, or a BLE advertiser newly in sight), for a local consumer's request, or within the 120-second redial window opened by a loss or by the first failed dial since the phone appeared; never while the phone is withdrawn. A session ends as §4.5 item 6 says: `pairing_revoked` forgets, `service_withdrawn` and `card_unavailable` make the view withdrawn and drop the card sighting at once so every consumer withdraws the identity without the grace, a protocol violation keeps the pairing and opens no window, and anything else is a loss. Browsing and scanning are not dialing; none of it is shown. | W-UCA-29, W-UCA-30 | CC-114, CC-115, CC-116 | |
| W-R-19 | This computer names itself `Windows - ` and its host name, shortened at a character boundary to 256 bytes, in `pairing.hello` and in `session.hello` at the start of every session; the phone's name from `session.ready` replaces the stored one when it changed, and the one line that names the phone, after its `pairing_revoked` close, uses the stored name. No pairing is found by a name. | | CC-119, CC-120 | |
| W-R-20 | A remote signature with the qualified key that the card module is handed as a hash goes to the phone as `sign_document` with the description RAPP §9.3 prescribes for a program that names no document, in the user's Windows interface language (English, Finnish or Swedish): the program, the computer, and that the program did not name the document, such as "Microsoft Word on work-laptop asks for a signature (the program did not name the document)". The program is the image Windows reports for the process, known by its version resource's `FileDescription`, else its file stem; nothing from the signing call names it. An image path with no file name is refused with `SCARD_E_UNSUPPORTED_FEATURE`. The RefineID app sends its documents' file names (refineid-core `doc-sign`). | W-UCA-33 | | Host tests in `refineid-agent-pipe` (`calling_program`, `in_process_operation`). Version resource reading built for Windows; not yet run with a phone. |
| W-R-21 | A computer keeps a holder's certificates in memory only (refineid-core `doc/security/certificate-custody.md`): no pairing record, file or credential holds one. The card's authentication certificate is read from the phone at every session and held by the process that holds the session while the offer stands (W-R-8); the `CurrentUser\My` entry of W-R-8 is the one copy outside a process, and stands only while the phone is present. A pairing record of an earlier revision, which could hold the certificate, is refused at load and paired again. Every load and written change of the pairing store, in any process, judges by the store's clock: every `CurrentUser\My` entry of the RefineID provider whose pairing does not serve or for whose certificate no sighting within the grace stands leaves that store, a card sighting whose pairing does not serve or whose grace passed is deleted, and a temporary file a stopped write left is deleted. A record this computer revoked or that expired is erased; one the phone revoked keeps the phone's name only, for the notice of RAPP §4.7, for `REVOCATION_NOTICE_DAYS` (7). | W-UCA-34, W-UCA-35, W-UCA-36 | | Tests in `refineid-rapp-core` (`store`, `persistence`) and `refineid-windows-credential-store`. The store acts only when a RefineID process of this user runs; the agent (W-R-22) runs from every sign-in: see section 7. |
| W-R-22 | A FINEID card's propagated entries are in `CurrentUser\My` only while that card is in a reader of this computer. The agent, started at every sign-in by the machine's `Run` value `RefineIDAgent` that the installer writes and removes, loads the protected pairing set, which applies W-R-21, checks idle expiry, and stays in the user's session until sign-out; its card thread, at its start and whenever a reader's state changes (`SCardGetStatusChange` on every reader and on the Plug and Play notification reader) it removes every FINEID entry whose certificate no card in a reader holds. An entry is FINEID's only by its smart card provider, its Card Module container and DVV's object identifier arc 1.2.246.517 in the certificate together, the DVV TEST arc 1.2.246.517.99 included; no other entry is touched. A card is in a reader when the reader reports it present; the card database (`SCardListCards`, `SCardGetCardTypeProviderName`) says by its answer to reset whether the Card Module serves it, and a card it serves is read through the Smart Card Key Storage Provider, silently, for the certificates of the Card Module's two containers, the bytes propagation wrote. A pass judges by one reading of the readers with their insertion and removal counts, and removes only when a second reading, taken after the store was read, equals it; otherwise it judges again, at most `JUDGEMENTS_PER_PASS` (3) times. A card it cannot read, a card the Card Module serves from which no certificate came, a reader whose state is unavailable, or readers it cannot read keep every entry, and it tries again within `RETRY_PAUSE` (10 seconds). The watch waits from the pass's own reading, so a change in between is not missed. No service runs; the card thread opens no pipe and no listener of its own. | W-UCA-35, W-UCA-42, W-UCA-43, W-UCA-44 | | The decision with a fake reader source and a fake store, the store adapter over an in-memory store, and the container answers in host and Windows tests of `refineid-windows-credential-store` (`card_certificates`, `card_reading`). Needs a card: propagation's entry bytes equal the provider's answer; a card's removal removes its entries within a second; a card inserted while another leaves keeps its entries; the provider's answer for an unactivated card. |
| W-R-22 | The card module answers `CP_CARD_CACHE_MODE` with session-only, which the minidriver specification (v7.07, Cache Modes) describes as per-process and cleared when the card is removed or reinserted, and designs for read-only cards. The Base CSP and KSP keep no card file in the global cache keyed by the card. | W-UCA-37 | | Not yet run with a card. |
| W-R-23 | A holder's face photo is held in memory and displayed from there; no file holds it, and the GUI removes at start any `refineid-photo` file left in the temp directory. | W-UCA-38 | | |
| W-R-24 | The card module serves no `msroots`: `CardReadFile` and `CardGetFileInfo` answer `SCARD_E_FILE_NOT_FOUND` for `mscp\msroots` and `CardEnumFiles` does not list it, as the minidriver specification (v7.07) allows a read-only card and prescribes for a nonexistent file. No card CA reaches a Windows trust store through RefineID; the DVV roots come from the Microsoft Trusted Root Program and the issuing CA from the authentication certificate's Authority Information Access. Unlike Unix, where the PKCS#11 module presents the card's CAs to NSS only while the card is present and with trust records that limit them to TLS client authentication and e-mail, Windows has no record that narrows a propagated root's purposes. | W-UCA-39 | | Host test `mscp_has_no_roots_bundle` in `refineid-minidriver`. Not yet run with a card. |
| W-R-25 | The driver package's `RemoveCardRoots` custom action runs as `LocalSystem` on install, repair, upgrade and uninstall and, in every loaded user profile, removes from `SmartCardRoot` an entry only when every card Windows recorded as propagating it (`CERT_SMART_CARD_ROOT_INFO_PROP_ID`) carries the `cardid` the card module derives from a FINEID authentication certificate in that user's Personal store. It never opens the user's own Root registry store, a machine store or `AuthRoot`, and a failure never fails the installation. No user process removes these entries: Windows lets only `SYSTEM` change them. | W-UCA-40, W-UCA-41 | | Decision and property parsing in host tests of `refineid-windows-credential-store` (`card_roots`). The property's layout, `cardid` then logon session per card, is Windows' undocumented one as read on two computers, where every recorded `cardid` matched the card module's. Deletion as `LocalSystem` through the registry provider observed on a test computer; denied to the user, elevated or not. The package's action is not yet run. |
| W-R-26 | In every build the agent's card thread, after every pass, puts the issuing CA (`EF.4336`) of each FINEID card in a reader into the user's Intermediate Certification Authorities store (`CurrentUser\CA`), marked as RefineID's and with no usage property, when the card's root (`EF.4334`) is self-issued, self-signed and a CA and the issuing CA is a CA that root issued and signed; and removes its marked entries of cards no longer in a reader. The CA store makes nothing a trust anchor: it holds the path material Windows would otherwise fetch from the Authority Information Access, and a chain through it is trusted exactly when its root is. No root enters a store in a release build. A development build (`debug_assertions`) also puts a DVV test card's root (self-signed, a CA, named with the word `TEST`) there, valid for TLS client authentication alone (`CERT_ENHKEY_USAGE_PROP_ID`); its chain still ends at an untrusted root. No Root store is written. An entry the store already held is left unmarked and untouched. | W-UCA-46, W-UCA-47 | | Decision in host tests of `refineid-windows-credential-store` (`card_cas`). That an EKU property on a root narrows its chains to that usage was observed on a test computer with a synthetic root in `LocalMachine\Root`; that `SmartCardRoot` refuses a user's write, too. Not yet run with a card. |

Residual, accepted (core STPA section 28): a session whose handshake is
still in flight when the agent quits closes without a notice, as RAPP
§4.5 item 8 allows, and the phone shows it lost rather than off, as it
does a close not written within the quit bound.

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

## 7. Open: what lies outside the store's reach

**Card CAs propagated by earlier builds (W-R-25).** Removal reaches the
profiles loaded while the package installs. A user who is signed out then
has nothing propagated in a profile Windows cleaned at sign-out, which it
does unless the machine policy "Configure root certificate clean-up" is set
to keep roots; under that policy the entry stays until the package next
installs while the user is signed in. The agent cannot remove one,
since Windows lets only `SYSTEM` change what propagation wrote. An entry
whose card's authentication certificate has already left the Personal store
(W-R-22) cannot be told from another card module's and stays.

**A computer on which no RefineID process runs.** The bounds of W-R-21 are
applied by a RefineID process of the user. The agent (W-R-22) is that
process from every sign-in, so after a crash a `CurrentUser\My` entry stays
only until the next sign-in; a computer nobody signs in to stays as it is.

**A phone not in reach when a browser asks.** The phone's certificate is in the
Personal store only while a session heard its card within the grace (W-R-8).
A browser picks its client certificate from that store before it calls any key
storage provider, so a login started before the phone came into reach finds no
certificate, and the browser does not ask that site again in its session (core
UCA-50, W-UCA-45). The agent dials the phone as soon as it appears, which keeps
the window short; it cannot close it, as nothing of RefineID is asked during
such a handshake. A browser that reads the phone's slot through the PKCS#11
module does ask during its handshake, and the module dials the phone then and
waits up to 3 seconds for its certificate (W-R-8, W-UCA-48).

**A physical card's propagated certificates.** Registering the FINEID cards
with the Calais database makes Windows' Certificate Propagation Service read
each inserted card through the minidriver and write its certificates to the
user's Personal store, and Microsoft documents that "they remain in the user's
certificate store" when the card is removed. On one shared Windows user, that
store would accumulate every holder who inserted a card; RefineID does not
write these entries. By the owner's decision, an entry stands only while its
card is in a reader of this computer, and the agent removes it when the
card leaves (W-R-22). What stays outside its reach: a card it cannot read
holds back every removal while it is in a reader; propagation writes an
entry after reading a card it counted as inserted, and the gap between the
agent's second reading and its removal is far shorter than that read, but it
is not closed; an entry of a card that left while no user process of the
holder ran, such as one left at sign-out, stays until the next sign-in; and the
installer's root removal (W-R-25) finds a card's propagated root only while
that card's authentication certificate is in the Personal store, so for a card
that has left it now finds none. A running agent keeps the build it started
with until the user signs out: an upgrade replaces its file and the next
sign-in starts the new one.
