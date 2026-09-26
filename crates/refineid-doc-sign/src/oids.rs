// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! OID constants the sign stack needs.
//!
//! The Windows port of `refineid-lib-core` does not carry these
//! in `oid::known`. Dotted values copied verbatim from the
//! sibling `refineid-unix` `oid::known` table (Apache-2.0, same
//! copyright holder).
use refineid_lib_core::oid::Oid;

/// X.509 Subject Key Identifier (`2.5.29.14`).
pub const SUBJECT_KEY_IDENTIFIER: Oid<'static> =
    Oid::const_new(::const_oid::ObjectIdentifier::new_unwrap("2.5.29.14").as_bytes());
/// CMS signing-time attribute (`1.2.840.113549.1.9.5`).
pub const SIGNING_TIME: Oid<'static> =
    Oid::const_new(::const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5").as_bytes());
/// RFC 3161 `TSTInfo` content (`1.2.840.113549.1.9.16.1.4`).
pub const TST_INFO: Oid<'static> = Oid::const_new(
    ::const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4").as_bytes(),
);
/// OCSP-response revocation info (`1.3.6.1.5.5.7.16.2`).
pub const OCSP_RESPONSE_REVOCATION_INFO: Oid<'static> =
    Oid::const_new(::const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.16.2").as_bytes());
/// `CAdES` signature-time-stamp-token attribute (`1.2.840.113549.1.9.16.2.14`).
pub const SIGNATURE_TIME_STAMP_TOKEN: Oid<'static> = Oid::const_new(
    ::const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14").as_bytes(),
);
/// `CAdES` signing-certificate-v2 attribute (`1.2.840.113549.1.9.16.2.47`).
pub const SIGNING_CERTIFICATE_V2: Oid<'static> = Oid::const_new(
    ::const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47").as_bytes(),
);
/// `CAdES` signing-certificate attribute (`1.2.840.113549.1.9.16.2.12`).
pub const SIGNING_CERTIFICATE: Oid<'static> = Oid::const_new(
    ::const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12").as_bytes(),
);
/// X.509 Basic Constraints (`2.5.29.19`).
pub const BASIC_CONSTRAINTS: Oid<'static> =
    Oid::const_new(::const_oid::ObjectIdentifier::new_unwrap("2.5.29.19").as_bytes());
/// X.509 Key Usage (`2.5.29.15`).
pub const KEY_USAGE: Oid<'static> =
    Oid::const_new(::const_oid::ObjectIdentifier::new_unwrap("2.5.29.15").as_bytes());
/// X.509 Extended Key Usage (`2.5.29.37`).
pub const EXT_KEY_USAGE: Oid<'static> =
    Oid::const_new(::const_oid::ObjectIdentifier::new_unwrap("2.5.29.37").as_bytes());
/// X.509 Name Constraints (`2.5.29.30`).
pub const NAME_CONSTRAINTS: Oid<'static> =
    Oid::const_new(::const_oid::ObjectIdentifier::new_unwrap("2.5.29.30").as_bytes());
/// OCSP `id-pkix-ocsp-nocheck` (`1.3.6.1.5.5.7.48.1.5`).
pub const OCSP_NO_CHECK: Oid<'static> =
    Oid::const_new(::const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.5").as_bytes());
/// X.509 Certificate Policies (`2.5.29.32`).
pub const CERTIFICATE_POLICIES: Oid<'static> =
    Oid::const_new(::const_oid::ObjectIdentifier::new_unwrap("2.5.29.32").as_bytes());
/// Extended-key-usage purpose `id-kp-OCSPSigning` (`1.3.6.1.5.5.7.3.9`).
pub const KP_OCSP_SIGNING: Oid<'static> =
    Oid::const_new(::const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9").as_bytes());
