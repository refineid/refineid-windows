# Microsoft Store lane and pkg.refineid.fi driver distribution

This note captures how the RefineID Windows product is split between the
Microsoft Store and the `pkg.refineid.fi` service, and what future work that
split implies. It records decisions made 2026-10-03.

## Split

### Microsoft Store (`RefineID` MSIX)

The Store MSIX must run inside the AppContainer sandbox. It cannot install
drivers, perform elevated installs, or embed a driver payload. Nothing inside
it may silently download or execute binaries. The app therefore works fine
without any local card driver:

- **Document validation** (PAdES/AdES/CAdES verification of signed
  documents) — local cryptographic work, no card, no network trust needed
  beyond validating certificates against the configured trust anchors.
- **RAPP-based document workflows** — pair with the RefineID Android phone,
  request signatures/PIN proofs from the card via the phone's own NFC path,
  observe progress over the paired Noise `XXpsk3` session. PINs never leave
  the phone (Rule #1).
- **Feature detection at startup.** On launch, check for the reader +
  minidriver stack:
  - If registered, enable the local-card lanes (PC/SC contactless/contact
    flows as they stand today).
  - If missing, show an informational lane and a `Get drivers` action that
    opens `https://pkg.refineid.fi/drivers` in the user's browser.

### pkg.refineid.fi (future)

- Out-of-band, elevated installer for the **minidriver + PKCS#11** DLL.
  These are user-mode artifacts: the installer only needs the Calais
  registry entries; no kernel drivers are installed.
- A normal OV/EV code-signing certificate for the installer. Self-signed
  development builds are allowed for dev, but produce SmartScreen/UAC
  warnings; not acceptable for a public distribution.
- Signed with no WHQL attestation path required for the minidriver itself —
  because it is not a kernel driver.

## Driver/card-mode details

- **The minidriver is user-mode.** It is loaded by WinSCard in user space
  and talks to the reader through the PC/SC service; no kernel driver
  signature (WHQL), no test-signing mode, no Secure Boot change.
- **Readers** use the built-in USB CCID / PC/SC class drivers. If a future
  reader truly needs a custom kernel driver, that driver must go through
  Microsoft attestation/WHQL or WHQL-style signing and ships separately
  from the Store MSIX.
- **PC/SC PKCS#11 module** remains a plain DLL. Only OpenSC/middleware
  stacks load it. This repository publishes it but does not install it,
  same as the minidriver.

## Browser login (suomi.fi etc.)

- Edge/other-browser client-auth requires the private key to be visible in
  the OS certificate store, which the minidriver/PKCS#11 + a registered
  card service creates. Without drivers, no browser-auth key handle for
  the card exists on the PC; vanilla Edge cannot do the handshake.
- A RAPP-backed CNG/TLS bridge could proxy the signing operation from the
  phone, but there is no generic stock picker; would be a separate
  bridge piece and would need to ship outside the Store MSIX.
- Therefore in the Store lane: document validation and RAPP-driven
  document signing are first class; "system-wide card login" remains the
  pkg.refineid.fi lane.

## Why not sign the MSIX with the FINEID card

- MSIX deployment requires the signing certificate to have the **code
  signing EKU**. FINEID card certificates are issued for authentication /
  qualified signing, not code signing.
- Even installing the DVV chain as a trust root would not fix this — the
  EKU is the rejecting check, and manifest `Publisher` must exactly match
  the certificate subject.
- A self-signed cert with the correct `CodeSigning` EKU, installed in
  Trusted People of the target machine, installs and validates — so
  dev uses a self-signed cert, distribution uses an OV/EV code-signing
  cert purchased or issued by CA, registered with the Store.

## Action items for future agents

1. **Feature-detection boot lane**: on WinUI app start, check for
   `System.CardReaders` containing a reader and our minidriver being
   registered (CCAPI/`SCard...` probe); store as a config flag and
   reflect in the UI as the two lane banners.
2. **Store app defaults**: hide the local-card sections while detection is
   negative; keep RAPP document signing and signed-document validation
   always available.
3. **`Get drivers` button**: open the pkg.refineid.fi browser URL.
4. **pkg.refineid.fi initial version**: serve the signed minidriver/PKCS#11
   installer, a `Getting Started` page, and a short "connect the reader"
   walkthrough. Content is unsigned inert download binaries.
5. **Track inventory**: add a small `docs/adrs/005-store-vs-pkg-split.md`
   later when the driver docs landing page is live.

## Trust / validation summary

| Distribution | Signer | Machine trust needed |
| --- | --- | --- |
| Store MSIX | Microsoft code-signing cert (Store signing) | Store account license and standard app check; runtime deps OK |
| Dev MSIX | self-signed `CN=RefineID` with code-signing EKU in Trusted People | one UAC trust import of the .cer |
| Driver installer (pkg.refineid.fi) | OV/EV code-signing cert | UAC elevation only (user-mode minidriver); WHQL/attestation only if a kernel driver appears |
| Card PIN / key usage (RAPP path) | DRES-validated FINEID certificates | No local driver needed; all private operations stay in the Android phone's secure path |

## What changes for users

- Standalone offline document checkers work today.
- Signing-with-phone scenarios work without local drivers.
- Local-card power users accept one admin run of the pkg.refineid.fi
  installer; the experience matches what apple/desktop users expect.
