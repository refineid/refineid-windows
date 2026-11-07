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

## 4. Windows Plug and Play (PnP) Device Names

### "Unknown Smart Card"
When a card is inserted, the smart card filter driver gives it a device in
the SmartCard class (`{990A2BD7-E738-46c7-B26F-1CF8FB9F1391}`) whose hardware
ID is `SCFILTER\CID_` followed by all of the ATR historical bytes in
hexadecimal (Microsoft, [Discovery Process](https://learn.microsoft.com/windows-hardware/drivers/smartcard/discovery-process)):

| Card | Hardware ID |
| --- | --- |
| FINEID S4-1 v3.1 | `SCFILTER\CID_8031b865b08504021b1200f6829000` |
| FINEID S4-1 v4.0, chip 1.0.0 | `SCFILTER\CID_8031b865b085050011122460829000` |
| FINEID S4-1 v4.0, chip 2.0.0 | `SCFILTER\CID_8031b865b085051024122460829000` |
| Organisation card (FINEID S1 v5.0), contact and contactless | `SCFILTER\CID_0031b8640429ecc17394018083` |

With no INF naming that ID, Windows installs the inbox `scunknown.inf`, which
matches the compatible ID `SCFILTER\CID_87D25E32-AC0D-4EF0-B1E0-502C6B7DFB77`
with a null service and the name "Unknown Smart Card". Microsoft documents
that pairing a card with its minidriver uses only the ATR and `ATRMask`
under `Calais\SmartCards` ([Smart Card Plug and Play](https://learn.microsoft.com/windows-hardware/drivers/smartcard/smart-card-plug-and-play),
Pairing Process; Discovery Process, Winscard Discovery Process), so the
name has no documented effect on the Base CSP, the smart card KSP,
certificate propagation or client authentication.

### The INF
`refineid-msi` derives `refineid_card.inf` from the same card table that
writes the Calais registrations (`crates/refineid-msi/src/cards.rs`): one
exact hardware ID per field-observed contact ATR of each registered model
(`FineidCardModel::contact_atr_byte_sets`), each checked to fall inside its
registration's mask, decorated `NTamd64.10.0` and `NTarm64.10.0`. An INF
hardware ID has no wildcard, and the v4.0 historical bytes carry the chip
revision, so a revision not yet recorded keeps working through the Calais
mask and shows as "Unknown Smart Card" until a release records it. The only
identifier Windows offers for a card family is the Windows Smart Card
Framework card identifier (`GET DATA` tag `7F68` under the SC PnP AID),
which the card itself must carry. The install sections are those of the
inbox `msclmd.inf`: `Include=umpass.inf` with all five `UmPass` sections.
The INF writes no registry, copies no files and has no `DefaultInstall`: the
MSI stays the one writer of the Calais registrations. The organisation card
has no registration, so the INF does not name it. A contactless citizen card
has the same historical bytes as the contact one, so the INF names it too,
although the MSI's contact-ATR registrations do not bind it.

### Signing
Windows stages a driver package only with a signed catalog
([PnP Device Installation Signing Requirements](https://learn.microsoft.com/windows-hardware/drivers/install/pnp-device-installation-signing-requirements--windows-vista-and-later-)):

- On x64, a catalog signed by a trusted code-signing certificate is enough,
  and ranks with WHQL ([Signature Score](https://learn.microsoft.com/windows-hardware/drivers/install/signature-score--windows-vista-and-later-)).
- On Arm64, a release-signed catalog must be signed by WHQL (same page).
  The certified route is a Partner Center submission with an EV
  certificate; attestation signing is offered for testing only and cannot
  publish to Windows Update for retail ([Driver Signing Options](https://learn.microsoft.com/windows-hardware/drivers/dashboard/driver-signing-offerings)).

`packaging/windows/build-msi.ps1 -DriverPackage <dir>` embeds a signed
package; with only `-CertificateThumbprint` it generates the INF, catalogs it
with `makecat.exe` and signs the catalog. An unsigned build carries no INF.
The MSI installs the INF and catalog beside the agent, and the Card Module's
`RefineIdInstallCardDriver` custom action calls `DiInstallDriverW` on them;
`RefineIdUninstallCardDriver` (`DiUninstallDriverW`) removes the package on
uninstall and on rollback. A package Windows refuses leaves the installation
successful and is reported in a development build.

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
     v26.11.2 section 8.4). The RefineID app keeps it on the pairing record,
     and its offering session adds it to `Cert:\CurrentUser\My` with
     `CERT_KEY_PROV_INFO` naming the provider `RefineID Key Storage Provider`
     and the key `rapp:<pair id>` once a session hears that card present.
     It stays offered between sessions while a session heard the card within
     120 seconds, and is removed once that lapses, at once when a session
     hears another card, and when the app's watch ends.
   - An entry stands only while its pairing's record may hold the certificate
     (refineid-core `doc/security/certificate-custody.md`): every load and
     written change of the pairing store, in any RefineID process, removes an
     entry whose pairing is forgotten, revoked, expired, replaced or past the
     7-day retention, so one a crash left goes as soon as a process runs.
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
- When given a signed driver package, installs `refineid_card.inf` and its
  catalog beside the agent and adds them to the driver store (section 4).

---

## 8. RefineID WinUI 3 Desktop App

The Windows desktop application (`apps/RefineID`) is built with modern WinUI 3 and
Windows App SDK:
- Fluent Design with Mica backdrop and system styling.
- Local smart card verification (PC/SC) by default, pairing management, and outbound phone reader discovery (deprecating inbound firewall rules and UAC elevation per [remote-transport-and-discovery-architecture.md](remote-transport-and-discovery-architecture.md)).
- Native builds for `win-arm64` and `win-x64` targeting .NET 10.

## 9. Remote use is off by default

RAPP ships present but disabled until pairing completes. An unconfigured
machine runs no agent process, no named pipe, no listener and no startup
entry: nothing to attack. While the app is open it dials out to the
phone itself and is the sole writer of the phone's certificates into
the Windows certificate store; the phone is usable only while the app
is open. After a first successful
RAPP setup the app offers a startup task once, in settings rather than
as a prompt. Local drivers (minidriver, KSP) ride in a separate admin
installer, not the Store app.
