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
- Chromium browsers pick client certificates from `Cert:\CurrentUser\My` and sign
  through CNG, so a paired phone needs no reader at all.
- The RefineID app places the phone's authentication certificate in that store
  when it reads the card, bound to the **RefineID Key Storage Provider**
  (`ksp.rs` in the minidriver DLL, key name `rapp:<pair id>`).
- The browser's `NCryptSignHash` lands in the provider's `SignHash`, which sends
  `CardOperation::BrowserAuthenticate` to the phone over RAPP and returns the
  signature. The phone prompts the holder; Windows collects no PIN.
- **100% user-space**: the provider is a DLL loaded into the browser process; no
  driver, no virtual reader, no elevation at run time.
- A user-mode virtual reader presenting `REMOTE_SYNTHETIC_ATR` remains the later
  stage for software that only speaks the smart-card stack (Windows logon, RDP,
  EAP-TLS); it reuses the minidriver's remote arm unchanged.

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

## 6. Key Storage Provider for a Paired Phone (Edge & Chrome)

On Windows, Microsoft Edge and Google Chrome authenticate client certificates through
CryptoAPI and CNG. For a mutual-TLS site (such as `https://suomi.fi` or
`https://card.refineid.fi`) the path to the phone is:

1. **Certificate in the user store**:
   - The `read_identity` answer carries the authentication certificate: the
     one whose SHA-256 fingerprint the session's `card.status` names (RAPP
     v26.10.29 section 8.4). The RefineID app keeps it on the pairing record,
     and its offering session adds it to `Cert:\CurrentUser\My` with
     `CERT_KEY_PROV_INFO` naming the provider `RefineID Key Storage Provider`
     and the key `rapp:<pair id>` once a session hears that card present.
     It stays offered between sessions while a session heard the card within
     120 seconds, and is removed once that lapses, at once when a session
     hears another card, and when the app's watch ends.
   - Forgetting the pairing removes every certificate bound to the provider.
2. **Provider registration**:
   - The DLL registers itself through `BCryptRegisterProvider` and
     `BCryptAddContextFunctionProvider` (`ksp_register.rs`), which write
     `HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\RefineID Key Storage Provider`
     and append the name to the machine's `KEY_STORAGE` provider list, and
     tell CNG about them. A registration written straight to the registry is
     not seen until the next boot, because CNG caches its configuration.
   - The driver MSI calls the DLL's `RefineIdRegisterKeyStorageProvider`
     custom action after the file is installed and
     `RefineIdUnregisterKeyStorageProvider` before it is removed. The same
     unregister entry point is the registration's rollback action,
     sequenced before it, so a first installation that fails after
     registering leaves no provider entry behind; `install-dev.ps1` runs the same code
     through `rundll32`.
3. **Signing**:
   - The browser calls `CryptAcquireCertificatePrivateKey`; `ncrypt.dll` loads the
     DLL into the browser process, resolves `GetKeyStorageInterface`, and opens the
     key. `OpenKey` finds the pairing by its id in the Credential Manager store and
     fails with `NTE_BAD_KEYSET` unless it serves (confirmed by the phone, neither
     revoked nor forgotten) and carries the certificate.
   - `SignHash` maps the hash and padding to a RAPP signature algorithm
     (ECDSA by digest length; RSA PKCS#1 v1.5 with SHA-256/384/512; RSA-PSS with
     SHA-256), sends `CardOperation::BrowserAuthenticate` to the phone, and
     returns `r || s` or the big-endian RSA integer. A denial on the phone is
     `NTE_USER_CANCELLED`.
   - The provider is read-only: no key creation, import, decryption or secret
     agreement; every such entry answers `NTE_NOT_SUPPORTED`.
   - Zero PIN transport occurs over the network, and zero PIN logging occurs on either host.

The TPM virtual smart card of earlier builds is gone: its registration claimed every
TPM virtual card on the machine (issue #71), and Hyper-V guests cannot create one.

---

## 7. Windows Installer (MSI) Packaging

Packaging is implemented natively in Rust via `crates/refineid-msi`:
- Generates standalone architecture-specific MSIs (`RefineID.CardDriver-<version>-<arch>.msi`)
  using the Windows Installer Win32 API and `makecab.exe` without third-party dependencies.
- Installs `refineid_minidriver.dll` to `C:\Windows\System32`.
- Registers the three FINEID card identities in `Calais\SmartCards`:
  1. `FINEID-S4-1-v3.1` (Physical card)
  2. `FINEID-S4-1-v4.0` (Physical card)
  3. `FINEID-RAPP-Remote` (Remote wireless card, for the later virtual reader)
- Registers the same DLL as the `RefineID Key Storage Provider` for CNG
  through two custom actions in the DLL itself (section 6), removes the
  registration on uninstall, and rolls it back when an installation fails
  after it.
- Automatically notifies and restarts `SCardSvr` upon installation.

---

## 8. RefineID WinUI 3 Desktop App

The Windows desktop application (`apps/RefineID`) is built with modern WinUI 3 and
Windows App SDK:
- Fluent Design with Mica backdrop and system styling.
- Local smart card verification (PC/SC) by default, pairing management, and outbound phone reader discovery (deprecating inbound firewall rules and UAC elevation per [remote-transport-and-discovery-architecture.md](remote-transport-and-discovery-architecture.md)).
- Native builds for `win-arm64` and `win-x64` targeting .NET 10.
