# refineid-pkcs11

The PKCS#11 v2.40 module for FINEID on Windows, for Firefox and NSS. It is
refineid-core's module (`crates/pkcs11` there, with its documentation) with one
thing of its own: `src/phone.rs` offers the phone paired with this computer as
the module's remote slot.

The module ships no certificate. It reads the card's root from `EF.4334` and
its issuing CA from `EF.4336` and presents them, with NSS trust records, while
the card is present, and keeps them per user so the next process can present
them without a card read: `REFINEID_CA_CACHE_DIR`, else `LOCALAPPDATA` or
`APPDATA` under `refineid\ca-certificates`.
