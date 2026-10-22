# The remote-card bridge

How Windows software reaches a FINEID card held by the holder's phone,
so that nothing above the middleware has to care where the card
physically is. This document records the architecture and its staging;
the requester protocol core, the stream transport, and the development
CLI exist today, and the operating-system bridge is built in the order
below.

## Altitude

RAPP is not an APDU tunnel: the proxy rejects arbitrary APDU bytes, and
every operation is a typed request from a registered profile, authorized
on the phone when it uses a key (RAPP v26.10.21 sections 8 and 9). The card-protocol stack in `refineid-lib-core` is
deliberately the opposite altitude: everything is built over a raw-APDU
`CardTransport`. A remote card therefore cannot be a `CardTransport`
implementation, and must not be — that seam exists so a *local* card's
protocol bytes stay reviewable.

The bridge sits at the operation altitude instead. The minidriver's
`CardSessionTransport` today has a plain arm and a PACE
secure-messaging arm; the remote card becomes a third arm whose
operations — read certificate, verify presence of a PIN, sign a digest
— map one to one onto the typed RAPP registry, executed by the
requester engine over a stream session, approved by the holder on the
phone. PIN collection never happens on Windows: the Card Module reports
the PIN as externally verified, the way a reader with a secure PIN pad
does, and the phone is that pad.

## Presence

A minidriver loads when Windows sees a card arrive in a reader. A
remote card has no reader, so the bridge has two doors.

The first needs no presence at all. CNG asks a key storage provider for
a signature whenever a certificate in the user's store names it, so the
same DLL exports a provider that answers for a paired phone: the
RefineID app places the authentication certificate in the store after a
read, and Edge, Chrome and every Schannel client sign through the
provider, which runs the operation over RAPP. This is what ships today.

The second is the end state for software that only speaks the smart-card
stack: a virtual reader device reports a synthetic ATR when a paired
phone is available, which makes the existing minidriver load, publish
the remote certificate, and serve Windows exactly as it does for a local
card. The virtual reader carries presence only; card semantics flow
through RAPP, never as APDUs over the virtual reader. With it, Windows
logon, RDP and EAP-TLS use the remote card without knowing it is remote.
A TPM virtual smart card was tried as a stand-in and dropped: its
registration claimed every TPM virtual card on the machine, and a
Hyper-V guest cannot create one.

## Staging

1. **Wire path** — done. `refineid-rapp-core` implements the requester
   role of RAPP v26.10.21 through the `refineid_rapp` engine;
   `refineid-rapp pair-demo` proves pairing, sessions, and typed
   operations against a real phone from a terminal.
   *Transport & Discovery Model*: Governed normatively by
   [remote-transport-and-discovery-architecture.md](remote-transport-and-discovery-architecture.md).
   Windows operates strictly as an outbound client connecting to the phone's
   ephemeral listener discovered via mDNS/DNS-SD (`Windows.Devices.Enumeration` / Win32 `DnsServiceBrowse`),
   eliminating inbound listening ports, Windows Firewall modifications, and UAC elevation.
2. **Durable pairing** — next. A `PairingStore` implementation over the
   Windows credential store (pair keys device-only, never roaming; a
   forgotten pairing keeps its keys only for its `pairing_revoked` close,
   and a revoked record keeps none), and the pairing ceremony in
   RefineID: code entry, both-device grant confirmation, the
   paired-phones list, forget and revoke.
3. **Minidriver remote arm** — the `CardSessionTransport::Remote`
   variant backed by the requester engine, certificate caching at
   pairing time so `CardAcquireContext` can build its model without a
   session, `sync_transport_handle` as a no-op for the remote arm, and
   the externally-verified PIN report.
4. **Browser integration** — done. For Chromium browsers (Edge, Chrome)
   and Schannel, the key storage provider in `refineid_minidriver.dll`
   (`ksp.rs`) signs for the certificate the app places in the user's
   store. For Firefox, `refineid_pkcs11.dll` discovers paired devices
   directly from the vault and exposes them as virtual PKCS#11 slots in
   user space. See
   [browser-architecture-and-rapp.md](browser-architecture-and-rapp.md) for details.
5. **Virtual reader** — later. A user-mode driver presenting the
   synthetic ATR on phone availability, so the minidriver's remote arm
   also serves Windows logon, RDP and EAP-TLS. Needs driver signing.

## What never changes

The requester never renders or collects CAN, PIN, or PUK. No failure
revokes a pairing: an authenticated protocol violation closes the session
with a sealed `protocol_violation` close, and only a user's forget
revokes, telling the other side with the `pairing_revoked` close. An
operation lives inside its session and ends with it; a result that never
came is not waited for on another session. The strictness is the
security design: when in doubt, the session closes visibly and the
pairing stays.
