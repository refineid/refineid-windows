# The remote-card bridge

How Windows software reaches a FINEID card held by the holder's phone,
so that nothing above the middleware has to care where the card
physically is. This document records the architecture and its staging;
the requester protocol core, the stream transport, and the development
CLI exist today, and the operating-system bridge is built in the order
below.

## Altitude

RAPP is not an APDU tunnel: the proxy rejects arbitrary APDU bytes, and
every operation is a typed, phone-authorized request (specification
Section 12.1). The card-protocol stack in `refineid-lib-core` is
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
remote card has no reader, so presence is simulated: a virtual reader
device reports a synthetic ATR when a paired phone is available, which
makes the existing minidriver load, publish the remote certificate, and
serve Windows exactly as it does for a local card. The virtual reader
carries presence only; card semantics flow through RAPP, never as APDUs
over the virtual reader. This is the end state: any Windows software —
Edge, Schannel, RDP, EAP-TLS — uses the remote card without knowing it
is remote.

## Staging

1. **Wire path** — done. `refineid-rapp-core` implements the requester
   role against vendored draft 26.8.17.233 with the conformance corpus
   replayed; `refineid-rapp pair-demo` proves pairing, sessions, and
   typed operations against a real phone from a terminal.
   *Transport & Discovery Model*: Governed normatively by
   [remote-transport-and-discovery-architecture.md](remote-transport-and-discovery-architecture.md).
   Windows operates strictly as an outbound client connecting to the phone's
   ephemeral listener discovered via mDNS/DNS-SD (`Windows.Devices.Enumeration` / Win32 `DnsServiceBrowse`),
   eliminating inbound listening ports, Windows Firewall modifications, and UAC elevation.
2. **Durable pairing** — next. A `PairingStore` implementation over the
   Windows credential store (pair keys device-only, never roaming, the
   revoked record kept as the tombstone), and the pairing ceremony in
   RefineID: code entry, both-device grant confirmation, the
   paired-phones list, forget and revoke.
3. **Minidriver remote arm** — the `CardSessionTransport::Remote`
   variant backed by the requester engine, certificate caching at
   pairing time so `CardAcquireContext` can build its model without a
   session, `sync_transport_handle` as a no-op for the remote arm, and
   the externally-verified PIN report.
4. **Virtual reader / Browser Integration** — For Chromium browsers (Edge, Chrome),
   a user-mode driver presenting the synthetic ATR on phone availability triggers
   the minidriver's remote arm, or a user-mode CNG KSP (`refineid_ksp.dll`) surfaces
   the certificate directly. For Firefox, no virtual reader driver is required:
   `refineid_pkcs11.dll` discovers paired devices directly from the vault and
   exposes them as virtual PKCS#11 slots in user space. See
   [browser-architecture-and-rapp.md](browser-architecture-and-rapp.md) for details.

## What never changes

The requester never renders or collects CAN, PIN, or PUK; a credential
rejection or an authenticated protocol violation revokes the pairing on
both peers; an ambiguous operation is never retried; and one pairing
serves one session at a time. The strictness is the security design:
when in doubt, the bridge breaks visibly and the holder pairs again.
