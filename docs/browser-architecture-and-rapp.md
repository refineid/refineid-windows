# Browser Architecture and RAPP on Windows

This document details how Windows software and web browsers access Finnish FINEID
identity cards (both physical smart cards and wireless cards via the Remote
Authorization Proxy Protocol, **RAPP**). It records the browser cryptographic split,
the unified core design, and Plug-and-Play (PnP) integration.

---

## 1. The Windows Browser Cryptographic Split

Web browsers and desktop applications on Windows fall into two distinct cryptographic
architectures:

```text
               ┌────────────────────────────────────────────────────────┐
               │                  Paired Smartphone                     │
               │               (RefineID App / RAPP)                    │
               └───────────────────────────┬────────────────────────────┘
                                           │ (Wi-Fi / BLE TCP Stream)
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │                     refineid-core                      │
               │   - RAPP Protocol Engine (Noise XX, CBOR deterministic)│
               │   - Pairing Store & Vault                              │
               │   - Card Operations (BrowserAuthenticate, ReadCert)    │
               │   - Card Edge & Crypto (FINEID S4/ECC P-384, X.509)    │
               └─────────────┬────────────────────────────┬─────────────┘
                             │                            │
             ┌───────────────┘                            └───────────────┐
             ▼                                                            ▼
┌─────────────────────────┐                                  ┌─────────────────────────┐
│     refineid_pkcs11     │                                  │   refineid_minidriver   │
│    (User-mode DLL)      │                                  │    (Card Module DLL)    │
└────────────┬────────────┘                                  └────────────┬────────────┘
             │                                                            │
             │ PKCS#11 ABI                                                │ Base CSP / KSP
             ▼                                                            ▼
┌─────────────────────────┐                                  ┌─────────────────────────┐
│  Firefox / Thunderbird  │                                  │   Edge / Chrome / OS    │
└─────────────────────────┘                                  └─────────────────────────┘
```

### A. Edge, Chrome, Brave, Opera, and Windows OS Apps
- Rely on Windows Cryptography Next Generation (CNG) and CryptoAPI (CAPI).
- Query the Windows Personal Certificate Store (`Cert:\CurrentUser\My`).
- Delegate cryptographic operations through the **Microsoft Base Smart Card CSP**
  and **Microsoft Smart Card Key Storage Provider (KSP)** to `refineid_minidriver.dll`.
- Do **not** consume PKCS#11 modules on Windows.

### B. Mozilla Firefox and Thunderbird
- Rely on Mozilla Network Security Services (NSS).
- **The `osclientcerts` Limitation**: Testing enterprise policies on Windows 11
  demonstrated that enabling `security.osclientcerts.autoload: true` via
  `distribution\policies.json` applies cleanly in `about:policies`, but fails to
  bridge hardware smart card KSPs during TLS client authentication. When navigating
  to strict mutual TLS endpoints, Firefox immediately aborts with
  `SSL_ERROR_HANDSHAKE_FAILURE_ALERT` because the KSP is not invoked for hardware PIN
  prompting.
- **Requirement**: Firefox on Windows strictly requires a standard PKCS#11 module
  (`refineid_pkcs11.dll`) for physical cards and RAPP remote devices. Field-tested on Ubuntu with Chrome & Firefox.

---

## 2. Target Architecture: Unified Core

A critical design requirement is preventing architectural divergence across operating
systems. The smart-card minidriver and the PKCS#11 module are thin, protocol-specific
adapters over the shared `refineid-core`.

### Why PKCS#11 Does NOT Wrap the Minidriver
1. **Severe Impedance Mismatch**: PKCS#11 (Cryptoki) has stateful session semantics
   (`C_OpenSession`, `C_Login`, `C_FindObjectsInit`, `C_SignInit`, token flags, object
   handles). The minidriver operates on container and file abstractions (`CardReadFile`,
   `CardSignData`, `CardAuthenticatePin`). Wrapping minidriver entry points introduces
   fragile state emulation.
2. **User-Space RAPP**: On Unix and Windows, `refineid-pkcs11` discovers paired RAPP
   devices from the vault and registers them directly as virtual slots (`rapp:<device_id>`)
   in user space. Wrapping the minidriver would require Windows PC/SC presence simulation
   before Firefox could see a remote card.
3. **Cross-Platform Parity**: `refineid_pkcs11.dll` (Windows) and `librefineid_pkcs11.so`
   (Linux) share the exact same Rust crate logic.

---

## 3. RAPP Remote Cards on Windows

RAPP allows Windows to authenticate using a FINEID card held by the holder's phone.

### A. In Firefox
- The PKCS#11 module exposes paired phones as virtual slots (`rapp:<device_id>`).
- When client certificate authentication is requested, Firefox selects the certificate
  and calls `C_Sign`.
- The module invokes `CardOperation::BrowserAuthenticate` over the local network stream.
- The phone prompts the user for biometric or PIN confirmation and returns the signature.
- **100% user-space**: zero kernel or virtual reader drivers needed.

### B. In Edge and Chrome
- Chromium browsers query `Cert:\CurrentUser\My` populated by the minidriver.
- The minidriver contains the remote arm (`CardSessionTransport::Remote` in `transport.rs`).
- When a remote card is selected, the minidriver's `execute_operation` sends
  `CardOperation::BrowserAuthenticate` to the phone.
- Presence is signaled either via:
  1. **User-Mode Virtual Smart Card Reader (UMDF)**: Simulating the synthetic ATR
     `REMOTE_SYNTHETIC_ATR` when a paired phone is in range.
  2. **Direct CNG Key Storage Provider (`refineid_ksp.dll`)**: A lightweight user-mode
     CNG provider pointing certificates in `Cert:\CurrentUser\My` directly to the RAPP
     requester.

---

## 4. Windows Plug and Play (PnP) Device Branding

### The Problem: "Unknown Smart Card"
When a smart card is inserted into a reader, the Windows Smart Card Reader Filter Driver
(`scfilter.sys`) derives a Hardware ID from the historical bytes:
- Physical FINEID ECC Card: `SCFILTER\CID_8031b865b085051024122460829000`
- RAPP Remote Card: `SCFILTER\CID_8031b865b085055241505000829000`
- Legacy S3/S4 Card: `SCFILTER\CID_8031b865b08504021b1200f6829000`

Without a registered `.inf` driver package in the Windows Driver Store, Windows PnP
assigns the generic null driver `scunknown.inf`, rendering the card as
**"Unknown Smart Card"** with a warning icon in Device Manager.

### The Solution: PnP Branding via SetupAPI and INF
1. **Runtime PnP Branding (Immediate & Driver-Free)**:
   The RefineID service enumerates `SmartCard` devnodes (`{990A2BD7-E738-46C7-B26F-1CF8FB9F1391}`)
   and applies SetupAPI properties:
   - `SPDRP_FRIENDLYNAME` (0x0000000C) → `"FINEID Identity Card"`
   - `SPDRP_DEVICEDESC` (0x00000000) → `"FINEID Identity Card"`
   Device Manager immediately refreshes, displaying the clean smart-card icon and
   official device name with healthy status.
2. **Production Driver Store Package (`refineid.inf`)**:
   A signed INF package matching `SCFILTER\CID_...` submitted to Microsoft Windows
   Hardware Compatibility Program (WHQL) allows Windows Update to automatically
   install and brand the card upon first insertion.

---

## 5. Technical Details for Windows PKCS#11

1. **Data Model (`CK_ULONG`)**:
   - Unix LP64: `CK_ULONG` is 64-bit (`u64`).
   - Windows LLP64 (MSVC x64 / ARM64): `unsigned long` is 32-bit (`u32`).
   - `ck.rs` must conditionally define `CK_ULONG` as `std::os::raw::c_ulong`.
2. **Calling Convention & Export**:
   - Export `C_GetFunctionList` with standard Windows `extern "system"` calling convention.
3. **Firefox Zero-Profile Registration**:
   - Deployed machine-wide via `distribution\policies.json`:
     ```json
     {
       "policies": {
         "SecurityDevices": {
           "RefineID": "C:\\Windows\\System32\\refineid_pkcs11.dll"
         }
       }
     }
     ```
   - Or standard registry: `HKLM\SOFTWARE\Mozilla\PKCS11Modules\RefineID`.

---

## 6. Virtual Smart Card Reader & BaseCSP Integration (Edge & Chrome)

On Windows, Microsoft Edge and Google Chrome authenticate client certificates through
the CryptoAPI/CNG smart card subsystem. When accessing mutual-TLS sites (such as
`https://suomi.fi` or `https://card.refineid.fi`):

1. **Virtual Smart Card Device (`ROOT\SMARTCARDREADER\0000`)**:
   - Windows manages virtual smart cards through the Microsoft Virtual Smart Card Reader
     (`MICROSOFT_VIRTUAL_SMART_CARD_0` / `VSC01`).
   - The virtual card exposes the standard RAPP Virtual ATR:
     `3B 8D 01 80 FB A0 00 00 03 97 42 54 46 59 04 01 CF`
2. **Registry Smart Card Binding (`Calais\SmartCards`)**:
   - The registration under `HKLM\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\FINEID-RAPP-Virtual`
     associates this ATR with:
     - `Crypto Provider`: `Microsoft Base Smart Card Crypto Provider`
     - `Smart Card Key Storage Provider`: `Microsoft Smart Card Key Storage Provider`
     - `80000001`: `refineid_minidriver.dll`
3. **Minidriver Execution & Zero-PIN Wire**:
   - Windows Smart Card Service (`SCardSvr`) loads `refineid_minidriver.dll`.
   - When the browser requests signing (`CardSignData`), the minidriver uses RAPP over
     mDNS / TCP stream to the user's paired smartphone.
   - The smartphone prompts for biometric/PIN confirmation.
   - Zero PIN transport occurs over the network, and zero PIN logging occurs on either host.

---

## 7. Windows Installer (MSI) Packaging

Packaging is implemented natively in Rust via `crates/refineid-msi`:
- Generates standalone architecture-specific MSIs (`RefineID.CardDriver-<version>-<arch>.msi`)
  using the Windows Installer Win32 API and `makecab.exe` without third-party dependencies.
- Installs `refineid_minidriver.dll` to `C:\Windows\System32`.
- Registers all four FINEID card identities in `Calais\SmartCards`:
  1. `FINEID-S4-1-v3.1` (Physical card)
  2. `FINEID-S4-1-v4.0` (Physical card)
  3. `FINEID-RAPP-Remote` (Remote wireless card)
  4. `FINEID-RAPP-Virtual` (Virtual reader card)
- Automatically notifies and restarts `SCardSvr` upon installation.

---

## 8. RefineID WinUI 3 Desktop App

The Windows desktop application (`apps/RefineID`) is built with modern WinUI 3 and
Windows App SDK:
- Fluent Design with Mica backdrop and system styling.
- Local smart card verification (PC/SC) by default, pairing management, and outbound phone reader discovery (deprecating inbound firewall rules and UAC elevation per [remote-transport-and-discovery-architecture.md](remote-transport-and-discovery-architecture.md)).
- Native builds for `win-arm64` and `win-x64` targeting .NET 10.
