# RefineID Windows: Remote Transport & Discovery Architecture

- **Document Version**: `26.10.3`
- **Protocol Version**: `26.10.22`
- **Status**: Normative Architecture & Migration Plan
- **Applies To**: `RefineID-Windows` (`RefineID-winui`, `refineid-minidriver`, `refineid-pkcs11`, `refineid-rapp-core`)
- **Companion Specification**: [RAPP Transport and Discovery Hierarchy Specification](https://github.com/refineid/refineid-core/blob/main/doc/protocols/rapp-transport-and-discovery-hierarchy.md)

---

## 1. Executive Summary

This document specifies the architecture for remote card operations on Windows, reversing the connection direction of the stream transport, eliminating unauthenticated listening ports on Windows, retiring `FirewallService.cs`, and establishing strict workstation UX hygiene rules.

### Core Architectural Decisions

1. **Phone as Sovereign Custodian**:
   - The mobile phone (iOS / Android) holds physical custody of the FINEID smart card over NFC.
   - The phone acts as the **listener and advertiser**.
   - The phone ONLY opens an ephemeral network port and advertises via mDNS (`_refineid-stream._tcp.local.`) if the user has explicitly turned on **"Allow Remote Card Reader"** in mobile settings.
2. **Windows as Outbound Requester (Zero Open Ports)**:
   - Windows 10 and 11 workstations act strictly as **outbound clients**.
   - Windows **MUST NOT** bind incoming network listeners, open TCP ports, or prompt users for UAC elevation to punch firewall holes.
   - Outbound connections are established on demand to the phone's advertised endpoint using `System.Net.Sockets.TcpClient` or Rust `TcpStream`.
   - **Retirement of FirewallService**: `FirewallService.cs` and all `netsh advfirewall` invocations (previously opening inbound ports 40000–60000) are deprecated and scheduled for complete removal.
3. **Workstation UX Hygiene: Local Card Reader First**:
   - By default, RefineID on Windows operates strictly as **Local Card Reader Software** (interfacing with local PC/SC hardware via `winscard`, such as built-in laptop slots or USB CCID readers).
   - Zero background network scanning, zero mDNS browsing, and zero popups occur out of the box.
   - An explicit UI toggle in `RefineID-winui` (**"Enable Remote Phone Reader"**, default: `false`) is required before Windows activates background discovery.
4. **Normative 3-Tier Discovery & Transport Hierarchy**:
   - **Tier 1: Apple Native (Direct P2P)**: Exclusively Apple-to-Apple; not applicable on Windows.
   - **Tier 2: Bluetooth / BLE Proximity Transport (`fi.refineid.rapp.ble`)**: Implemented via Windows WinRT `Windows.Devices.Bluetooth.GenericAttributeProfile` for GATT-based RAPP communication. The Requester routes a session preamble to each advertiser of a scan, strongest signal first; signal strength only orders the attempts, admits or refuses none, and proves nothing about proximity (RAPP v26.10.22 §4.4). (Note: Windows user-space does not expose public APIs for BLE L2CAP Connection-Oriented Channels). On legacy hardware lacking BLE (e.g. ThinkPad R61 Broadcom BCM2045B Bluetooth 2.0+EDR), unauthenticated Classic RFCOMM is supported as a proximity fallback.
   - **Tier 3: Local IP Stream via mDNS / DNS-SD Fallback (`fi.refineid.stream`)**: Discovered using supported `Windows.Devices.Enumeration` or Win32 `DnsServiceBrowse` APIs, establishing an outbound TCP connection to the phone.

---

## 2. Component Architecture & Boundaries

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                     WINDOWS 10 / 11 WORKSTATION                         │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                     RefineID-winui Desktop App                    │  │
│  │                                                                   │  │
│  │   • Default: Local Card Reader (winscard / PC/SC)                 │  │
│  │   • Opt-in Setting: [x] Enable Remote Phone Reader                │  │
│  │   • Discovery: Windows.Devices.Enumeration / Win32 DNS-SD         │  │
│  │   • Pairing Ceremony: Prompts for 6-char Crockford Base32 code    │  │
│  │   • Zero inbound ports, zero firewall rules, zero UAC prompts     │  │
│  └───────────────────────────────────┬───────────────────────────────┘  │
│                                      │                                  │
│             ┌────────────────────────┴───────────────────────┐          │
│             ▼                                                ▼          │
│  ┌─────────────────────────┐                    ┌────────────────────┐  │
│  │   refineid_minidriver   │                    │  refineid_pkcs11   │  │
│  │ (Edge, Chrome, OS Apps) │                    │ (Mozilla Firefox)  │  │
│  └──────────┬──────────────┘                    └────────────┬───────┘  │
│             │                                                │          │
│             └────────────────────────┬───────────────────────┘          │
│                                      │ Dispatches via RappDeviceVault   │
│                                      ▼                                  │
│                         ┌──────────────────────────┐                    │
│                         │    refineid-rapp-core    │                    │
│                         │  • Safe Rust Engine      │                    │
│                         │  • Noise_KK / CPace PAKE │                    │
│                         │  • Outbound TcpStream    │                    │
│                         └────────────┬─────────────┘                    │
└──────────────────────────────────────┼──────────────────────────────────┘
                                        │ Outbound Connection
                                        │ (Zero listening ports on Windows)
                                        │ (Zero Windows Firewall holes)
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    SOVEREIGN CUSTODIAN (PHONE)                          │
│                         (iOS / Android)                                 │
│                                                                         │
│  • Gated by "Allow Remote Card Reader" user setting                     │
│  • Ephemeral TCP listener + mDNS announcement (_refineid-stream._tcp)   │
│  • Holds physical custody of FINEID card over NFC                       │
│  • Displays authorization prompts & executes APDUs                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Migration Plan from Inbound Listener to Outbound Browser

### 3.1 Deprecation of Legacy Inbound Model
In the legacy codebase:
- `MainPage.xaml.cs` set `ListenPort = 47110`.
- `FirewallService.cs` ran `netsh advfirewall firewall add rule name="RefineID RAPP" dir=in action=allow protocol=TCP localport=40000-60000`.
- The user was interrupted with UAC elevation dialogs.

### 3.2 Target Outbound Implementation
1. **Discovery using Supported Windows DNS-SD APIs**:
   - Note: Microsoft explicitly marks `DnssdServiceWatcher` unsupported on modern Windows releases. Windows implementations MUST use one of the two supported discovery mechanisms:
     - **Option A: WinRT `Windows.Devices.Enumeration`** (C# / WinUI):
       ```csharp
       string aqs = "System.Devices.AepService.ProtocolId:=\"{4526e8c1-8aac-4153-9b16-55e86ada0e54}\" AND System.Devices.Dnssd.ServiceName:=\"_refineid-stream._tcp\"";
       string[] requestedProperties = {
           "System.Devices.IpAddress",
           "System.Devices.Dnssd.PortNumber",
           "System.Devices.Dnssd.HostName",
           "System.Devices.Dnssd.InstanceName",
           "System.Devices.Dnssd.ServiceName",
           "System.Devices.Dnssd.TextAttributes"
       };
       var watcher = DeviceInformation.CreateWatcher(
           aqs,
           requestedProperties,
           DeviceInformationKind.AssociationEndpointService
       );
       watcher.Added += OnServiceAdded;
       watcher.Updated += OnServiceUpdated;
       watcher.Removed += OnServiceRemoved;
       watcher.Start();
       ```
     - **Option B: Win32 DNS-SD Native API** (`windns.h` / `dnsapi.dll`):
       ```c
       DNS_SERVICE_BROWSE_REQUEST request = { 0 };
       request.Version = DNS_QUERY_REQUEST_VERSION1;
       request.QueryName = L"_refineid-stream._tcp.local";
       request.pBrowseCallback = OnDnsServiceBrowseCallback;
       DnsServiceBrowse(&request, &cancel);
       ```
   - Resolves the phone's advertised IP address and dynamic port without requiring administrative privileges.
   - When the user toggles "Enable Remote Phone Reader" off, `watcher.Stop()` is invoked immediately, stopping discovery and releasing all resources.
   - TXT records are handed to `refineid_rapp` unparsed: `DiscoveryRecord::parse` and `DiscoveryKey::matches_record` decide whether a `mode=session` record names a stored pairing, and `WithdrawnRecord::parse` with `WithdrawalKey::matches` decides whether a `mode=withdrawn` record announces that its custodian stopped serving (RAPP v26.10.22 §4.5).
   - A verified withdrawal, or an authenticated `session.close` with reason `service_withdrawn`, marks the pairing withdrawn: discovered phones are not dialed for it again until a `mode=session` record that names it, or one publishing no hints, shows its custodian serving. Configured endpoints (`REFINEID_RAPP_ENDPOINT`, `--connect`, the local mock custodian) are always dialed. A custodian that disappears without announcing it is simply not found at the next dial; the pairing is unchanged either way.
   - An authenticated `session.close` with reason `pairing_revoked`, in place of `session.ready` or at any point of a session, revokes the pairing here at once (RAPP v26.10.22 §4.6 item 4): its keys are destroyed, its certificate is withdrawn from browsers, no close is sent back, nothing is dialed for it again, and the user is told that the phone forgot this computer. No failure revokes a pairing (§10.1); a protocol violation closes the session with a sealed `protocol_violation` close and the pairing stays.
   - The computer's own forget action (§4.6): a session open to the phone sends the `pairing_revoked` close at once and the keys are destroyed. Otherwise the pairing serves nothing from then on and keeps its keys for that close alone; the next session with the phone, dialed as before, carries the close as its first message and then destroys the keys, and after 30 days the keys go untold.
   - Idle expiry (§4.6 item 5): the engine records on the pairing that a session to it is established when the phone's `session.ready` is verified, once a day while the session lasts, and when it ends, in whichever process holds the session. The agent checks every pairing each time it reads the pairing store and once a day while it holds a session, the held pairing counting as in session. A pairing that has had no established session for 30 days, counted from its creation while it has had none, expires silently: nothing is sent or shown, its certificate is withdrawn from every local consumer, and it is forgotten as above. The record is written before it changes in memory, so a write the store refuses changes nothing and is repeated at the next check.
   - Stored pairings are not migrated: a record written in an earlier format is left out when the store is read, and the store is written back without it, so it is refused once and its phone pairs again.
   - Every local consumer (the certificate in the user's store, the PKCS#11 remote slot, the card module's remote card) is offered the phone's certificate on the same evidence (§8.4): the session's `card.status` says whether the phone holds a card and names it by the SHA-256 fingerprint of its authentication certificate, and the session records the card it hears present, every 10 seconds while it stays present, as the pairing's card sighting beside the pairing store. A certificate is offered, before and between sessions, while its card was heard within 120 seconds (`IDENTITY_OFFER_GRACE_MS`); the offer goes once that lapses, at once when a session hears another card, and at once when the pairing is forgotten or revoked. A report of absence is never another card: the offer stands through the grace, and an operation the card does not answer (`card_error`) is a failed operation that changes no presence.
2. **Outbound Stream Connection**:
   - Establish outbound connection using standard `System.Net.Sockets.TcpClient`:
     ```csharp
     using var client = new TcpClient();
     await client.ConnectAsync(phoneIp, phonePort);
     ```
   - No inbound firewall rule is required for established outbound connections.
   - The first frame is the routing preamble: `pairing` for a pairing ceremony, or for a session a fresh 16-byte nonce and a 16-byte tag keyed by the pairing's static agreement (`RoutingKey::route`). Each connection attempt builds a new one, so no value on the wire names a pairing twice.
3. **Removal of `FirewallService.cs`**:
   - Delete `apps/RefineID-winui/FirewallService.cs`.
   - Remove firewall check dialogs from `MainPage.xaml.cs`.

---

## 4. Workstation UX Hygiene Contract

1. **Local Smart Card Mode (Default)**:
   - On application startup, RefineID inspects local smart card readers via `LocalCardService`.
   - If a physical card is present in an integrated reader (e.g. ThinkPad R61 smart card slot) or USB CCID dongle, it displays the holder's identity and enables Document Signing immediately.
   - Network discovery scanners remain completely idle.
2. **Explicit Remote Phone Reader Setting**:
   - The UI includes an explicit toggle in settings and on the main card view:
     ```text
     [ ] Enable Remote Phone Reader
         Allow discovering and using your phone as a wireless card reader.
     ```
   - When unchecked, the application generates zero network traffic and listens on zero sockets.
   - When checked, DNS-SD service browsing and BLE scanning activate to discover announced mobile readers.
3. **One-Time Pairing UI**:
   - When pairing a new phone, the desktop prompts for the 6-character Crockford Base32 code displayed on the phone (per RAPP v26.10.22 §3).
   - Once paired, the trust record is stored in Windows Credential Store (`refineid-windows-credential-store`).

---

## 5. Security Guarantees & Constraints

* **Rule #1 (Zero PIN Transport)**: PIN codes NEVER travel across the network. PIN1 is verified on the mobile device; PIN2 prompts appear exclusively on the phone's screen.
* **Rule #2 (Zero PIN Data / Candidate Length Logging)**: Diagnostic logs, error messages, and UI text must NEVER format, trace, or log PIN bytes or candidate digit counts.
* **Safe Rust Protocol Ownership**: Safe Rust (`refineid-rapp-core`) owns all protocol state machines, cryptographic operations, and secret zeroization.
* **Windows ABI Integrity**: All Windows ABI pointer dereferences validate nullability and length before access.
