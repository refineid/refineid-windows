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

## No card CA

The Card Module serves no `msroots` file. `CardReadFile` and `CardGetFileInfo`
answer `SCARD_E_FILE_NOT_FOUND` for `mscp\msroots`, and `CardEnumFiles` does
not list it. That is what Microsoft's smart card minidriver specification
(v7.07) prescribes for a card without one: `msroots` is the one Base CSP file a
read-only card need not have ("All expected Base CSP/KSP files, with the
exception of the 'msroots' file [...] must exist on the read-only card",
Developer Guidelines, Read-Only Cards), and "If *pszFileName* specifies a
nonexistent file, **CardReadFile** should fail with SCARD\_E\_FILE\_NOT\_FOUND"
(CardReadFile, Remarks).

Why: the Certificate Propagation Service copies whatever `msroots` holds into
the signed-in user's `SmartCardRoot` store, which is the `.SmartCard` physical
store of `CurrentUser\Root` (Win32 "System Store Locations"), and Windows
trusts a certificate there as a root for every purpose, TLS server
authentication included. The file carries certificates and no properties
("properties such as CODE\_SIGNING EKU are not propagated", Developer
Guidelines, Interoperability with msroots), so a card cannot even narrow the
purposes. A card is not a trust authority, so this module lets it choose no
anchor. Chains still build without one: the DVV roots are in the Microsoft
Trusted Root Program, which Windows fetches into `AuthRoot` when a chain needs
them, and Windows fetches the issuing CA from the Authority Information Access
of the authentication certificate, `http://proxy.fineid.fi/ca/dvvcqc4ec.crt`
for the citizen CA `DVV Citizen Certificates - G4E`.

Unix and Firefox differ. The PKCS#11 module presents the card's root
(`EF.4334`) and issuing CA (`EF.4336`) to NSS only while the card is present,
each with an NSS trust record that makes it an anchor for TLS client
authentication and e-mail protection and for nothing else; a web server or a
signed program chaining to it is no more trusted than before
([refineid-pkcs11](../refineid-pkcs11/README.md) and refineid-core
`crates/pkcs11/README.md`, "NSS trust records"). Windows has no such record for
a propagated root.

### DVV test cards in development builds

DVV's test roots are not in the Microsoft Trusted Root Program, so with no
`msroots` Windows holds neither a test card's root nor its issuing CA. A
browser then finds no chain for the card's authentication certificate:
Chromium (Edge, Chrome) selects client certificates with
`CertFindChainInStore`, `CERT_CHAIN_FIND_BY_ISSUER`, matching the server's
CA names against every CA of the chain, with
`CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG` ("search only the cached system
stores (Root, My, Ca, Trust) to find issuer certificates") and
`CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG` ("Only the URL cache is
searched. The Internet is not searched") (Win32 `CertFindChainInStore`;
Chromium `net/ssl/client_cert_store_win.cc`), and sends the intermediates of
that chain without asking whether its root is trusted.

A development build (`debug_assertions`, the switch refineid-core's
`SigningBuild` uses) gives such a card its chain and no trust. After every
pass of the agent's card watch, it reads each card in a reader without a
credential; when the card's root (`EF.4334`) is self-issued, self-signed, a CA and named
with the word `TEST`, it puts the root, and the issuing CA (`EF.4336`) if the
root signed it and it is a CA named so too, into the user's Intermediate
Certification Authorities store, `CurrentUser\CA`
(`refineid-windows-credential-store` `test_card_cas`, Windows STPA W-R-26).
Nothing shipped recognises a test card: no certificate and no fingerprint.

- The CA store is one of the stores the chain engine searches for issuers;
  it makes no certificate a trust anchor. The chain still ends with
  `CERT_TRUST_IS_UNTRUSTED_ROOT`, so no web server, signed program or
  document signed under the test root becomes trusted.
- Each entry also carries `CERT_ENHKEY_USAGE_PROP_ID` set to TLS client
  authentication alone (`CertSetEnhancedKeyUsage`). A certificate with
  both an EKU extension and EKU extended properties "is valid only for the
  uses that are on both lists" (Win32 `CertGetEnhancedKeyUsage`, Remarks),
  and the chain engine narrows a chain to its elements' usages: a synthetic
  root carrying that property in a Root
  store built a valid chain for client authentication and
  `CERT_TRUST_IS_NOT_VALID_FOR_USAGE` for server authentication on a test
  computer.
- Each entry is marked with a property of RefineID's own, and the watch
  removes its marked entries of cards no longer in a reader. An entry the
  store already held is left unmarked and is never removed.
- Release builds compile none of this.

Why not a trust store. The user's own Root store "is protected, and user
interface dialog boxes remind the user to place only trusted certificates into
that store" (Win32 "Managing Certificates with Certificate Stores"), so every
addition and removal would ask the user; its `.SmartCard` physical store, which
`msroots` fills, refuses a user process's write (access denied, observed on
a test computer) and keeps no properties; the machine's Root store needs an
administrator. An exclusive chain engine (`CERT_CHAIN_ENGINE_CONFIG`
`hExclusiveRoot`) serves only the callers that create it, never a browser or
Schannel. A server verifies a client certificate's chain against its own
anchors, so the client needs the chain, not trust in it.

### What earlier builds left

Builds that served `msroots` had Windows propagate the card's root and issuing
CA. The driver package's `RemoveCardRoots` custom action removes them on
install, repair, upgrade and uninstall (`card_roots.rs`,
`refineid-windows-credential-store` `card_roots`). It opens only each user's
`SmartCardRoot` store, never the user's own Root registry store, the machine's
stores or `AuthRoot`, so a root the Microsoft root update or another program
added stays, even with the same bytes. Within `SmartCardRoot` an entry goes only
when every card Windows recorded as having propagated it
(`CERT_SMART_CARD_ROOT_INFO_PROP_ID`: per card, the card module's `cardid` and
the logon session) is a card this module identified, by the `cardid` it derives
from a FINEID authentication certificate in the same user's Personal store.
The agent removes a card's certificates from the Personal store when
the card leaves its reader (`refineid-windows-credential-store`
`card_certificates`), so a root is found this way only while its card's
authentication certificate is still there.

Windows writes each propagated entry under a registry key that only `SYSTEM`
may change, so no process of the user can remove one; the custom action runs as
`LocalSystem`, without impersonation, and reaches the profiles loaded while it
runs. Microsoft documents a confirmation for no change to `SmartCardRoot`, and a
removal as `LocalSystem` completes in a session with no desktop, where a dialog
could not be answered. Unless the machine policy "Configure root certificate
clean-up" says otherwise, Windows also removes propagated roots when the user
signs out.

## Contents

- `cardmod.rs` -- cardmod.h-shaped types, the card capability/container model,
  and the logical file system the Base CSP expects.
- `ffi.rs` -- the Windows FFI declarations.
- `transport.rs` -- SCard-handle transport with T=0 chaining.
- `card_roots.rs` -- the driver package's custom action that removes the
  roots earlier builds had Windows propagate.
- `ksp.rs` -- the CNG key storage provider for a paired phone, exported as
  `GetKeyStorageInterface` from the same DLL.
- `ksp_codec.rs` -- the CNG key blob and signature encodings the provider
  hands out, tested on the host.
- `ksp_register.rs` -- registers the provider with CNG through the BCrypt
  registration API; entry points for the driver MSI and for `rundll32`.
- `card_registrations.rs` -- removes every `Calais\SmartCards` registration
  that names this module, whoever wrote it; the driver MSI calls it on a
  first installation, before it writes its own, and on uninstall
  (`doc/installer-upgrade.md`).

## Paired phone for browsers

The DLL is also registered as the `RefineID Key Storage Provider`. The
RefineID app places a paired phone's authentication certificate in
`Cert:\CurrentUser\My` bound to that provider, so Edge, Chrome and Schannel
sign through `SignHash`, which runs `BrowserAuthenticate` over RAPP. No reader
or driver is involved; see
[browser-architecture-and-rapp.md](../../doc/browser-architecture-and-rapp.md)
section 6. The provider answers `NTE_BAD_KEYSET` for a key whose pairing is
gone, serves nothing (forgotten or revoked), or has no cached certificate, `NTE_USER_CANCELLED` when the holder
declines on the phone, and `NTE_NOT_SUPPORTED` for everything but opening,
describing and signing.

Over the card module's remote arm, an operation that gives no result answers
`SCARD_W_CANCELLED_BY_USER` when the holder declines, `SCARD_E_NO_KEY_CONTAINER`
when the pairing serves nothing, `SCARD_W_REMOVED_CARD` when no dial reached
its phone (an absent phone reads as no card in the reader),
`SCARD_E_COMM_DATA_LOST` when the session ends before the result
or the phone's card does not answer the operation (`card_error`, a failed
operation and not the card's absence), and `SCARD_F_INTERNAL_ERROR` otherwise,
the retry floor included.

A qualified signature over the remote arm reaches the phone as `sign_document`.
A Windows signing call hands the module a hash and no document, so the phone is
told what this computer knows, in the user's Windows interface language: the
program, known by its image's `FileDescription` (else its file stem), the
computer, and that the program did not name the document, for example
"Microsoft Word on work-laptop asks for a signature (the program did not name
the document)" (RAPP section 9.3, Windows STPA W-R-20). The RefineID app signs
documents itself and sends their file names.

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
