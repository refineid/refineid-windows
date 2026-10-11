# refineid-minidriver

Windows smart-card minidriver (Card Module) for FINEID -- hooks the card into the Microsoft Base CSP/KSP
so Edge, Chrome, Schannel, .NET, VPN, RDP, and Wi-Fi EAP-TLS reach it through the OS smart-card stack.
Sibling to the PKCS#11 module; card-edge logic is shared with refineid-lib-core.

Windows-only: the crate compiles to an empty library on other targets.

## Verified RSA authentication path

The FINEID RSA-3072 authentication card is hardware-verified through the
Microsoft Smart Card Key Storage Provider for both signing modes Windows uses:

- RSA PKCS#1 v1.5 with SHA-256
- RSA-PSS with SHA-256 and a 32-byte salt

RSA-PSS uses the card-native FINEID algorithm reference (`45h` for SHA-256 x
RSA-PSS): `MSE:Set DST`, external `PSO:HASH`, then an empty `PSO:CDS`. Do not
replace this with host-side EMSA-PSS plus a 384-byte raw-RSA `PSO:CDS`; the card
rejects that operation with `6985`.

`CardSignData` must allocate signature output with the Card Module allocator.
RSA signatures returned by the card are big-endian and must be reversed before
returning them through the Windows Card Module ABI. CNG expects the RSA integer
in little-endian form.

Hardware validation on Windows ARM64:

`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-card-sign.ps1`

Expected output includes:

- `Pkcs1 sign and verify passed (384 bytes).`
- `Pss sign and verify passed (384 bytes).`
- `ECDSA sign and verify passed (...)` on an ECC card.

Edge client authentication to production mutual TLS services is verified working with this
path. Firefox integration is separate: Firefox requires a configured PKCS#11
module (refineid_pkcs11.dll) to reach the card.

## Contactless NFC

Contactless FINEID S4-1 v4.0 is implemented as an experimental path. The card
presents a PC/SC contactless ATR and seals PKCS #15 behind PACE. RefineID
Settings first proves the CAN against the card and saves only that CAN in the
current user's Windows Credential Manager, keyed by the complete ATR. The
minidriver uses the stored CAN to establish secure messaging before certificate
discovery and repeats PACE when Windows replaces its PC/SC handle.

The development installer accepts the exact observed ATR through
`-ContactlessAtrHex` and registers it with an all-bytes mask. It deliberately
does not ship a broad pseudo-ATR mask, which could select this minidriver for an
unrelated contactless card.

The underlying PACE and protected-read sequence has passed on Windows with an
ACS ACR1581 PICC reader. The new Credential Manager-to-Card Module handoff still
requires real-reader acceptance. Contact-mode browser and KSP use remains the
supported alpha path until that test passes.

## Qualified electronic signing

The minidriver exposes both physical certificate/key slots:

- container 0 / `ksc00`: EF.4331 authentication certificate, PIN1, key ref
  `0x01`, default container;
- container 1 / `ksc01`: EF.4332 qualified-signature certificate, PIN2, key
  ref `0x02`, non-default signature-only container.

An old Base CSP `cmapfile` cache may predate container 1. Empty cached slots do
not hide physical on-card containers; the model restores both descriptors and
keeps cached GUIDs only for valid matching slots.

Hardware validation on the FINEID-S4-1-v3.1 RSA card:

- `certutil -scinfo -silent` enumerates the EF.4332 certificate under container
  `{7A6D5E7C-FE1D-4F1A-B8C2-FA1B1B7C3A02}`;
- its `AT_SIGNATURE` public-key matching test succeeds;
- a qualified-signature probe prompts for PIN2, signs through key ref `0x02`,
  returns 384 bytes, and verifies locally against the on-card
  qualified-signature certificate.

The DVV web signing application may additionally require its browser extension
or native signing component. The Windows cryptographic primitive it needs --
the EF.4332 certificate and PIN2-qualified private-key operation -- is
available.

### Firefox handshake diagnosis

`SSL_ERROR_HANDSHAKE_FAILURE_ALERT` is not necessarily a signing failure. Check
the `RefineID-Minidriver` Application events for the same attempt:

- `CardAuthenticateEx` followed by `CardSignData` means Firefox reached signing.
- `CardAuthenticateEx` with no `CardSignData` means Firefox/NSS rejected the
  certificate or handshake parameters before signing.

Export the selected certificate and verify its status with Windows:

`certutil -verify -urlfetch <authentication-certificate.cer>`

The card used during the July 2026 Firefox investigation reported
`CRYPT_E_REVOKED` (`Certificate is REVOKED`, reason 4). Firefox stopped after PIN
authentication and never called `CardSignData`, while both minidriver signature
modes verified locally and Edge completed client authentication. The supported
resolution is a non-revoked authentication certificate/card. Do not work around
this by disabling Firefox revocation checking.

## Contents

- `cardmod.rs` -- cardmod.h-shaped types, the card capability/container model,
  and the logical file system the Base CSP expects.
- `ffi.rs` -- the Windows FFI declarations.
- `transport.rs` -- SCard-handle transport with T=0 chaining.
- `msroots.rs` -- the `msroots` (intermediate/root store) file scaffolding.
- `ksp.rs` -- the CNG key storage provider for a paired phone, exported as
  `GetKeyStorageInterface` from the same DLL.
- `ksp_codec.rs` -- the CNG key blob and signature encodings the provider
  hands out, tested on the host.

## Paired phone for browsers

The DLL is also registered as the `RefineID Key Storage Provider`. The
RefineID app places a paired phone's authentication certificate in
`Cert:\CurrentUser\My` bound to that provider, so Edge, Chrome and Schannel
sign through `SignHash`, which runs `BrowserAuthenticate` over RAPP. No reader
or driver is involved; see
[browser-architecture-and-rapp.md](../../docs/browser-architecture-and-rapp.md)
section 6. The provider answers `NTE_BAD_KEYSET` for a key whose pairing is
gone or has no cached certificate, `NTE_USER_CANCELLED` when the holder
declines on the phone, and `NTE_NOT_SUPPORTED` for everything but opening,
describing and signing.

## Public build and development install

From the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/build.ps1 -Architecture x64,arm64
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/install-dev.ps1 `
  -DllPath dist/x64/refineid_minidriver.dll `
  -AllowUnsigned
```

The development installer registers both supported FINEID ATR families and
restarts the Windows smart-card services. Supplying the exact contactless ATR
through `-ContactlessAtrHex` adds the experimental S4-1 v4.0 NFC registration.
It rejects unsigned DLLs unless the operator explicitly selects
`-AllowUnsigned`.
