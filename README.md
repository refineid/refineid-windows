# RefineID for Windows

Public, native Windows middleware for Finnish FINEID citizen cards.

The first component is a Rust smart-card minidriver. It implements the
Microsoft Card Module ABI and connects the Windows Base Smart Card CSP/KSP
stack to a FINEID card through PC/SC.

```text
Edge / Chrome / VPN / RDP                   Firefox / Thunderbird
            |                                         |
 Microsoft Base CSP/KSP                               |
            |                                    PKCS#11 ABI
 refineid_minidriver.dll                           refineid_pkcs11.dll
            \                                         /
             +───────────────+───────────────────────+
                             |
                       refineid-core
                             |
               +─────────────+─────────────+
               |                           |
             PC/SC                    RAPP Stream
               |                           |
          FINEID card                 Paired phone
```

This is a user-mode DLL, not a kernel driver. No C++ compatibility layer is
used. Windows requires a small `unsafe extern "system"` boundary for the Card
Module function table and caller-owned pointers; the protocol, parsing, PIN
handling, and cryptographic state machines remain safe Rust.

Status: beta. The imported reference implementation has been hardware-tested
with FINEID S4-1 v3.1 and v4.0 cards, including:

- authentication and qualified-signature certificate enumeration;
- PIN1 and PIN2 verification;
- RSA-3072 PKCS#1 v1.5 and RSA-PSS signing;
- ECDSA P-384 signing;
- Windows certificate propagation and Edge client authentication;
- Field-tested on Ubuntu with Chrome & Firefox.

This public port has revalidated the contact path locally with a real FINEID
S4-1 v3.1 RSA card and an ACR39U reader:

- `certutil -scinfo -silent` selected the RefineID Card Module without an
  unknown-card error;
- the PIN page restored PIN2 with the recovery code and the card reported
  five attempts plus the changed-from-factory flag afterwards; and
- Microsoft KSP calls completed and locally verified RSA-3072 PKCS #1 v1.5 and
  RSA-PSS signatures with both PIN1 and PIN2.

CI still cannot replace that hardware proof, and the separate NFC acceptance
boundary is documented below.

### Contactless NFC status

The browser and Windows KSP acceptance tests above currently use the contact
interface. The repository now contains an experimental end-to-end contactless
path:

- the PIN page proves the printed six-digit CAN with the Apple-reference
  `SELECT MF`, PACE, and protected PKCS #15 sequence before saving it;
- only the CAN is stored in the current Windows user's Credential Manager,
  keyed by the complete PC/SC contactless ATR; no PIN or PUK is stored;
- the minidriver retrieves that CAN before certificate discovery and opens a
  fresh PACE secure-messaging session whenever Windows replaces the PC/SC
  handle; and
- the development installer can register the exact observed contactless ATR
  with an all-bytes mask.

The FINEID S4-1 v4.0 PACE and protected-read sequence has passed separately with
an ACS ACR1581 PICC reader. The new Windows Credential Manager-to-minidriver
handoff still needs real-reader acceptance before contactless browser use can be
called supported. Contact mode remains the supported path meanwhile.

### PINs

The PINs entry of `apps/RefineID-winui`, shown while a card reader is
connected, opens the PIN page, a narrow C# UI over the Rust card-service DLL
(`refineid_settings_ffi`). It can:

- inspect a card and show counter-safe PIN1, PIN2, and recovery status;
- change PIN1 or PIN2;
- restore either PIN with the recovery code;
- activate a new card while binding every modifying command to the inspected
  reader and card serial; and
- prove and save the printed CAN for the experimental contactless path.

PIN, recovery, and activation values cross the FFI as bounded byte arrays, are
zeroized in the Rust domain types, and never enter the JSON response or event
stream. The CAN is saved only after a live PACE proof. No PIN or recovery code
is placed in Windows Credential Manager.

## Build

Requirements:

- Windows 11;
- the latest stable Rust through `rustup`; the exact release is pinned in
  `rust-toolchain.toml`;
- the latest .NET 10 SDK for the WinUI apps;
- the latest Visual Studio (2026 or later, Community or Build Tools) with the
  *Desktop development with C++* workload, including the MSVC build tools for
  x64 and ARM64 and the latest Windows 11 SDK.

Install all of them, or update them to their latest releases, with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/setup-dev-tools.ps1
```

See [doc/toolchain.md](doc/toolchain.md) for what the script installs, the
architecture-specific tool requirements, and cross-building the Windows target
from macOS or Linux, and
[doc/store-and-driver-distribution.md](doc/store-and-driver-distribution.md)
for how the Store MSIX and the pkg.refineid.fi driver installer split up.

Build the development Card Module for both supported architectures:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/build.ps1 -Architecture x64,arm64
```

The script builds the debug configuration, which reports its errors (see
[Development builds](#development-builds)); `-Configuration Release` builds
the release profile instead.

Outputs:

```text
dist/x64/refineid_minidriver.dll
dist/arm64/refineid_minidriver.dll
dist/SHA256SUMS
```

Run the host checks:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p refineid-lib-core
```

### Managing build cache

During development, Cargo build artifacts and `rustc` incremental compilation caches can grow significantly.

```sh
# Sweep unused build artifacts older than 14 days
cargo sweep -t 14

# Clean incremental compilation cache if disk space is needed
find target -type d -name "incremental" -prune -exec rm -rf {} +
```

Build the unpackaged x64 app:

```powershell
dotnet build apps/RefineID-winui/RefineID.csproj `
  -c Release `
  -p:Platform=x64 `
  -p:WindowsPackageType=None `
  -p:EnableMsixTooling=false
```

## Development builds

A development build makes every error visible. The debug configuration
(Rust `debug_assertions`, C# `DEBUG`) reports each failure of every
RefineID process, the app, the agent, the Card Module inside `lsass.exe`,
browsers and `certutil.exe`, the PKCS#11 module, the document signer and
the RAPP crates, to the Windows Event Log: Application log, source
`RefineID`, event and cause by name only (`refineid-dev-errors`). The app
opens its Errors window when an error arrives; Ctrl+Shift+E or the version
line opens it again. A release build contains no logging at all.

Read the entries from PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'RefineID' } |
  Format-Table TimeCreated, Id, Message -AutoSize
```

Build the development app package, the debug configuration signed with the
development certificate (`CN=RefineID` with the code-signing EKU):

```powershell
dotnet publish apps/RefineID-winui/RefineID.csproj `
  -c Debug `
  -p:Platform=x64 `
  -p:WindowsPackageType=MSIX `
  -p:EnableMsixTooling=true `
  -p:GenerateAppxPackageOnBuild=true `
  -p:AppxPackageDir=dist\msix\ `
  -p:PackageCertificateThumbprint=<thumbprint>
```

## Development install

Production Windows binaries must be Authenticode-signed. Do not distribute an
unsigned or test-signed DLL to end users.

For an isolated development machine with Windows test-signing policy configured,
build the matching architecture and run an elevated PowerShell. The script
also registers the `RefineID` event source that development builds report to,
and `uninstall-dev.ps1` removes it:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/install-dev.ps1 `
  -DllPath dist/x64/refineid_minidriver.dll `
  -AllowUnsigned
```

For an experimental contactless install, first read the complete ATR reported
for the ACR1581 PICC interface with `certutil -scinfo`. Register that exact
value rather than a family-wide mask:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/install-dev.ps1 `
  -DllPath dist/x64/refineid_minidriver.dll `
  -ContactlessAtrHex '<exact ATR from certutil -scinfo>' `
  -AllowUnsigned
```

Then open Settings in RefineID once to prove and save the card's printed CAN. The
CAN argument is deliberately not accepted by the installer or command line.

Validate with a reader and card:

```powershell
certutil -scinfo
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/test-card-sign.ps1
```

Log in to card-authenticating sites in Edge, with the card in a reader. The
script drives Edge with a fresh profile and selects the card's certificate
for each site for the run only; enter PIN 1 in the Windows Security dialog
when Windows asks for it. It needs Python 3 with the `playwright` package:

```powershell
python3 -m pip install playwright
python3 scripts/test-browser-edge.py --url https://card.refineid.fi `
  --expect-title "Card-authenticated guestbook"
```

Remove the development installation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/uninstall-dev.ps1
```

## Remote authorization (RAPP)

`crates/refineid-rapp-core` implements the requester role of the Remote
Authorization Proxy Protocol, RAPP v26.10.22 (specified in refineid-core
`doc/protocols/rapp-v26.10.22.md`), through the `refineid_rapp` engine.
RAPP lets this Windows machine use an identity card held by the holder's
phone: pairing takes the six-character code the phone shows (`CPace`,
then `Noise_XXpsk3`), every session is a mutually authenticated
`Noise_KK` channel that the phone opens with `session.ready` and its card
status, each operation lives inside its session, the phone takes the PIN
for each key it uses (PIN 1 asked once and held in its memory, PIN 2 for
every signature), and no CAN, PIN, or private key ever reaches the
requester. Browsers, the PKCS#11 slot and the card module are offered the
phone's certificate while a session on this computer heard its card
within the last 120 seconds. Forgetting a pairing tells the phone with a
`pairing_revoked` close, on an open session at once or as the first
message of the next one. The crate carries the stream transport
`fi.refineid.stream`; `refineid-rapp-ble` carries `fi.refineid.rapp.ble`.
`refineid-rapp-cli` is the development requester and mock custodian. The
phone-side custodians live in their own platform repositories.

## Accessibility and UI Automation (UIA)

The RefineID application (`apps/RefineID-winui`) implements first-class
Windows Accessibility support through Microsoft UI Automation (UIA) and WinUI 3
`AutomationProperties` (`HeadingLevel`, `AutomationId`, `Name`, `HelpText`). This
provides accessible semantics for screen readers (such as Windows Narrator) and
serves as assistive technology for autonomous AI agents navigating the desktop
deterministically. See [doc/accessibility-and-ui-automation.md](doc/accessibility-and-ui-automation.md)
for architecture details.

## Security boundary

- PIN values and private card material must never be logged.
- A card in a reader of this computer follows the phone's PIN rule (RAPP
  v26.10.22 section 11 item 2): PIN 1 is held in process memory only, never
  in storage and with no time window, until the card is removed or
  replaced, rejects it or shows a retry counter below pristine, or the user
  or the process ends it; a transport failure keeps it. PIN 2 is entered
  for every signature and never held.
- Secret byte containers are zeroized on drop.
- `unsafe_code` is denied workspace-wide and explicitly expected only in the
  Windows ABI adapter.
- Every operation is bounded by the card and Windows API result; unsupported
  Card Module operations fail closed.
- Release optimization keeps integer overflow checks enabled.
- x64 and ARM64 release DLLs enable high-entropy ASLR, NX, and Windows
  Control Flow Guard.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and
[CONTRIBUTING.md](CONTRIBUTING.md) for the public review rules.

## License

Apache License 2.0.
