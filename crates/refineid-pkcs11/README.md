# refineid-pkcs11

A minimal, read-only, sign-only PKCS#11 v2.40 (cryptoki) module for FINEID cards.
It builds as a C ABI shared library (`librefineid_pkcs11.so` on Linux, `.dylib` on macOS) plus an `rlib` for tests.

Its single job is Firefox / NSS client-certificate TLS authentication:
it exposes the card's authentication certificate and its private key, takes PIN1 through `C_Login`,
and signs the TLS `CertificateVerify` digest on the card.
The same module also drives OpenSSL through the `pkcs11-provider` bridge once registered with p11-kit.

## Scope

Deliberately small.
Implemented:

- Discovery: `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`, `C_GetSlotList`, `C_GetSlotInfo`,
  `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo`, `C_WaitForSlotEvent` (non-blocking: reports card insertion / removal events, so NSS notices a card without a browser restart).
- Sessions: `C_OpenSession` (serial, read-only), `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`.
- Login: `C_Login` (`CKU_USER` only), `C_Logout`.
  On success the module best-effort forwards PIN1 over a local
  pin-channel socket to the RefineID signature-creation-service
  daemon when one is running (a separate component), and reports
  card removal the same way, so that daemon neither prompts a
  second time nor serves a stale cache. Forwards run detached;
  failure is a diagnostic line, never an error to NSS.
  PIN1 is validated as 4..=12 ASCII digits and held in memory only, with no
  time window, until the card is removed or replaced, the card rejects it or
  reports a retry counter below pristine, or the login ends (logout, the last
  session's close, finalize); a transport failure keeps it (RAPP v26.11.2
  section 11 item 2).
  It is verified on the card inside each sign, never logged, and zeroized when it ends.
- Objects: `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal` and `C_GetAttributeValue` over
  the authentication certificate (`CKO_CERTIFICATE`, `CKC_X_509`),
  its public key (`CKO_PUBLIC_KEY`, from the certificate SPKI, for
  consumers such as p11tool / libp11 that enumerate public keys),
  its private key (`CKO_PRIVATE_KEY`, `CKK_RSA` or `CKK_EC`),
  the CA certificates the card carries (`CKO_CERTIFICATE`,
  `CK_CERTIFICATE_CATEGORY_AUTHORITY`), one NSS trust record
  (`CKO_NSS_TRUST`) per CA certificate, and one profile object
  (`CKO_PROFILE`, `CKP_PUBLIC_CERTIFICATES_TOKEN`) declaring the
  certificates readable without a login -- see
  [NSS trust records](#nss-trust-records).
  The three authentication objects share one `CKA_ID` so NSS pairs them.
  The private key answers `CKA_EXTRACTABLE` false and
  `CKA_NEVER_EXTRACTABLE` / `CKA_ALWAYS_SENSITIVE` true -- the FINEID
  key never leaves the card.
- Signing: `C_SignInit` / `C_Sign` (single-part).
  `CKM_RSA_PKCS` takes a DER `DigestInfo` (SHA-256 only) on the RSA-3072 card;
  `CKM_ECDSA` takes a raw digest of any hash on the ECC P-384 card and returns raw `r || s`.
  The card slot is exactly 48 bytes,
  so shorter digests (TLS 1.2 commonly negotiates ECDSA+SHA-256) are left-padded with zeros
  and longer ones truncated to the leftmost 384 bits,
  per the PKCS#11 v2.40 s6.4.1 ECDSA rule -- see `doc/bugs/2026-07-07-ckm-ecdsa-digest-len.md`.
  The two-call length query works without touching the card.
- Verifying: `C_VerifyInit` / `C_Verify` (single-part), pure
  software against the cached certificate public key -- no card
  IO, no PIN. Same input shapes as signing.

Everything else in the v2.40 function list is present but returns `CKR_FUNCTION_NOT_SUPPORTED`,
except where the spec names a more specific code for a permanent refusal:
`C_InitToken` returns `CKR_TOKEN_WRITE_PROTECTED`,
`C_SignRecoverInit` / `C_UnwrapKey` return `CKR_KEY_FUNCTION_NOT_PERMITTED`,
`C_DigestKey` returns `CKR_KEY_INDIGESTIBLE`,
`C_SeedRandom` returns `CKR_RANDOM_SEED_NOT_SUPPORTED`,
and the legacy `C_GetFunctionStatus` / `C_CancelFunction` return `CKR_FUNCTION_NOT_PARALLEL` as v2.40 mandates.
There is no object creation, no key generation, no encryption / decryption / digesting, no write path;
verification is software-only (above);
the token reports `CKF_WRITE_PROTECTED`.

## Diagnostics

Off by default. `REFINEID_PKCS11_LOG=<path>` appends the NSS call
sequence (function names, handles, byte lengths -- never PIN bytes or
attribute values) to an operator-named file; without it,
`REFINEID_DEBUG=1` writes the same lines to stderr. There is
deliberately no default log path: the module runs inside the
browser's address space, and an implicit file in a world-writable
directory would be a symlink-attack surface. The environment is read
once per process.

`examples/nss_debug.rs` in the
[refineid-unix](https://github.com/refineid/refineid-unix) repository
answers "why doesn't Firefox see the card" without launching Firefox:
it dlopens a built module exactly like NSS and replays NSS's discovery
probes, including the vendor-defined builtin-root class and the
`CKO_PROFILE` search, which this module answers with its one
public-certificates profile object and never with
`CKP_AUTHENTICATION_TOKEN` (the eager-PIN1 rule: a PIN prompt appears
only when a TLS handshake needs the key).

## CA certificates from the card

The module ships no certificate. Every FINEID card carries its issuing
CA certificate (EF.4336) and the DVV root (EF.4334), both directly
under the MF and readable without a PIN, and the module reads both
when it builds a token's objects, in the same card session as the
authentication certificate. Each one that parses as an unexpired CA
certificate becomes a `CKO_CERTIFICATE` object of category
`CK_CERTIFICATE_CATEGORY_AUTHORITY` with `CKA_TRUSTED` false (its
trust, per purpose, is the companion trust record's to state), and is
written to a per-user cache so a later session, and the phone-served
token, can present it without a card read: `REFINEID_CA_CACHE_DIR`,
else `LOCALAPPDATA` or `APPDATA` under `refineid\ca-certificates` on
Windows, `~/Library/Caches/fi.refineid/ca-certificates` on macOS, and
`XDG_CACHE_HOME/refineid/ca-certificates` or
`~/.cache/refineid/ca-certificates` elsewhere. The cache only ever
holds certificates read from a card; an expired, oversized, non-CA or
unparseable file in it is deleted on load. The objects, their trust
records and the held PIN are dropped together when the card leaves
the reader.

## NSS trust records

NSS trusts a certificate on a token only when the token also presents
a trust record for it, so the module presents, next to each CA
certificate object, one object of NSS's vendor class `CKO_NSS_TRUST`
(NSS `lib/util/pkcs11n.h`; the standard `CKO_TRUST` class of PKCS#11
v3.2 applies only to modules reporting that version, and this one
reports 2.40). NSS finds the record by `CKA_CLASS`, `CKA_ISSUER` and
`CKA_SERIAL_NUMBER` (NSS `lib/dev/devtoken.c`,
`nssToken_FindTrustForCertificate`), the same issuer and serial the
certificate object answers, and reads from it the label, the
certificate's SHA-1 and MD5 digests (`CKA_NSS_CERT_SHA1_HASH`,
`CKA_NSS_CERT_MD5_HASH`; the MD5 is a lookup key every NSS trust record
carries, never a decision), the subject, and one trust level per
purpose:

| Purpose | Attribute | Level |
| --- | --- | --- |
| TLS client authentication | `CKA_NSS_TRUST_CLIENT_AUTH` | `CKT_NSS_TRUSTED_DELEGATOR` |
| Email protection (S/MIME) | `CKA_NSS_TRUST_EMAIL_PROTECTION` | `CKT_NSS_TRUSTED_DELEGATOR` |
| TLS server authentication | `CKA_NSS_TRUST_SERVER_AUTH` | `CKT_NSS_MUST_VERIFY_TRUST` |
| Code signing | `CKA_NSS_TRUST_CODE_SIGNING` | `CKT_NSS_MUST_VERIFY_TRUST` |

`CKT_NSS_TRUSTED_DELEGATOR` makes the CA a trust anchor for the
purpose: NSS accepts a chain that ends at it. `CKT_NSS_MUST_VERIFY_TRUST`
asserts nothing for the purpose: a chain through the CA must reach some
other anchor, so a web site or a signed program chaining to the DVV root
is no more trusted than before. It is not `CKT_NSS_NOT_TRUSTED`, which
would be an active distrust. `CKA_NSS_TRUST_STEP_UP_APPROVED` is false,
the record is a public, unmodifiable token object, and `certutil -L`
shows the pair as the trust string `T,C,` (trusted client CA for TLS,
trusted CA for email, nothing for object signing).

A trust record exists exactly while its CA certificate object does: it
is built with the token's objects and dropped with them when the card
leaves the reader. Nothing is written to the NSS database and no policy
file or privilege is involved.

NSS searches the certificates and trust records of a token that
requires a login only once the user has logged in to it, unless the
token is friendly, that is, declares its certificates publicly readable
(NSS `lib/dev/devutil.c`, `search_for_objects`; `lib/pk11wrap/pk11slot.c`,
`PK11_IsFriendly`). This token is friendly by its own declaration: it
presents one profile object (class `CKO_PROFILE`, a PKCS#11 v3.0 object
class) whose `CKA_PROFILE_ID` is `CKP_PUBLIC_CERTIFICATES_TOKEN`, as a
public, unmodifiable token object. NSS reads the profile objects of
every token when the token appears, before any login and whatever
cryptoki version the module reports (`PK11_InitToken`,
`pk11_ReadProfileList` in `pk11slot.c`), so the DVV root is trusted
from the moment a FINEID card is in the reader, with no PIN login. The
declaration is true: the card hands out its certificates to anyone, and
no PIN, PUK or CAN is involved in reading them. The profile says nothing
about the key: the private key stays a private object and a PIN prompt
appears only when a TLS handshake needs it. This is the only profile
the token claims; in particular it never presents
`CKP_AUTHENTICATION_TOKEN` (see `token.rs`, `ObjectKind`).

The slot is not declared a hardware slot (`CKF_HW_SLOT`): NSS gives a
hardware slot an object cache and answers trust lookups from it, but
never caches a trust record's serial number while its lookup template
requires one (NSS `lib/pk11wrap/dev3hack.c`, `lib/dev/devutil.c`), so
the trust records would never be found. Without the flag NSS searches
the token directly and the module answers from its own card-read
objects.

## Hardware test rigs (`test/`)

Operator-run, gated on `REFINEID_HARDWARE_TEST=1`; neither runs in
the commit hooks.

- `test/pkcs11-hardware-suite.sh` -- pkcs11-tool + CLI sweep with a
  PIN-retry-counter guard around every card-touching phase (aborts
  the moment a counter drops) and offline openssl verification of
  every signature. PIN-change and PUK-unblock phases are separately
  opt-in.
- `test/headless-cert-auth.sh` -- real TLS client-cert
  authentication through NSS's `tstclnt` against a fresh NSS
  profile, no browser; supports A/B comparison of two module builds
  by diffing their `C_Login`/`C_Sign` log lines. Reproduces in ~5
  seconds the cross-layer regression class that once evaded every
  unit test.

## Card access

The module opens the reader itself through `refineid-lib-pcsc` (`PcscBackend::open_session`),
reads what it needs, and drops the transport immediately.
PIN-bearing opens use `ReaderAccessCap::PinSequence`: the whole
SELECT -> VERIFY -> operation span runs inside one held PC/SC
transaction, so a concurrent card consumer can neither interleave
an APDU mid-sequence nor consume the card's verified state.
It never holds the card open across PKCS#11 calls, and it does not hold the module lock across card IO,
so a shared desktop reader stays usable.

## Versions

- Library version: the workspace CalVer YY.M.D in `Cargo.toml`, stamped to the UTC day at commit.
- Cryptoki version: `2.40`.

## Register with p11-kit

Install the built library somewhere on the system module path (for example `/usr/lib64/pkcs11/librefineid_pkcs11.so`)
and drop a p11-kit module file, e.g. `/usr/share/p11-kit/modules/refineid.module`:

```
module: librefineid_pkcs11.so
critical: no
```

Use an absolute path if the library is not on the default module search path:

```
module: /usr/lib64/pkcs11/librefineid_pkcs11.so
critical: no
```

Firefox / NSS then load the module through p11-kit,
or you can add it directly with `modutil -dbdir sql:$HOME/.pki/nssdb -add "RefineID" -libfile /usr/lib64/pkcs11/librefineid_pkcs11.so`.
OpenSSL reaches the same module through `pkcs11-provider`, which also enumerates p11-kit modules.

This README documents the file content only; it installs nothing.

## Build

```
cargo build -p refineid-pkcs11
```

The `cdylib` builds on both Linux and macOS; PC/SC access is cross-platform through `refineid-lib-pcsc`.
