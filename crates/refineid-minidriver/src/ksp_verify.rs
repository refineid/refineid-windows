//! The provider's own check of every remote signature (Windows STPA W-R-5).
//!
//! A signature the phone returns is handed to the caller only after it
//! verifies, with Windows' own CNG primitives, against the public key of the
//! certificate the provider opened. A failure is the provider's refusal,
//! distinct from anything the phone said.

use refineid_rapp_core::operations::SignatureAlgorithm;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_KEY_HANDLE, BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS, BCRYPT_PKCS1_PADDING_INFO,
    BCRYPT_PSS_PADDING_INFO, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA384_ALGORITHM,
    BCRYPT_SHA512_ALGORITHM, BCryptDestroyKey, BCryptVerifySignature, CertCreateCertificateContext,
    CertFreeCertificateContext, CryptImportPublicKeyInfoEx2, X509_ASN_ENCODING,
};

/// The salt the card's PSS signatures use: the digest length.
const PSS_SALT_BYTES: u32 = 32;

/// Whether `signature`, in the encoding CNG callers receive (P1363 `r||s`
/// for ECDSA, big-endian for RSA), verifies over `digest` with the public
/// key of `certificate` under `algorithm`.
pub fn verifies(
    certificate: &[u8],
    algorithm: SignatureAlgorithm,
    digest: &[u8],
    signature: &[u8],
) -> bool {
    let (Ok(certificate_len), Ok(digest_len), Ok(signature_len)) = (
        u32::try_from(certificate.len()),
        u32::try_from(digest.len()),
        u32::try_from(signature.len()),
    ) else {
        return false;
    };
    // SAFETY: `certificate` holds `certificate_len` bytes of DER; the
    // context is freed below.
    let context = unsafe {
        CertCreateCertificateContext(X509_ASN_ENCODING, certificate.as_ptr(), certificate_len)
    };
    if context.is_null() {
        return false;
    }
    let mut key: BCRYPT_KEY_HANDLE = core::ptr::null_mut();
    // SAFETY: the context is valid, and its certificate info carries the
    // subject public key; the key handle is destroyed below.
    let imported = unsafe {
        CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            &raw const (*(*context).pCertInfo).SubjectPublicKeyInfo,
            0,
            core::ptr::null(),
            &raw mut key,
        )
    } != 0;
    let verified = imported && {
        let pkcs1 = |hash| BCRYPT_PKCS1_PADDING_INFO { pszAlgId: hash };
        let (padding, flags): (Padding, u32) = match algorithm {
            SignatureAlgorithm::EcdsaSha224
            | SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384
            | SignatureAlgorithm::EcdsaSha512 => (Padding::None, 0),
            SignatureAlgorithm::RsaPkcs1Sha256 => (
                Padding::Pkcs1(pkcs1(BCRYPT_SHA256_ALGORITHM)),
                BCRYPT_PAD_PKCS1,
            ),
            SignatureAlgorithm::RsaPkcs1Sha384 => (
                Padding::Pkcs1(pkcs1(BCRYPT_SHA384_ALGORITHM)),
                BCRYPT_PAD_PKCS1,
            ),
            SignatureAlgorithm::RsaPkcs1Sha512 => (
                Padding::Pkcs1(pkcs1(BCRYPT_SHA512_ALGORITHM)),
                BCRYPT_PAD_PKCS1,
            ),
            SignatureAlgorithm::RsaPssSha256 => (
                Padding::Pss(BCRYPT_PSS_PADDING_INFO {
                    pszAlgId: BCRYPT_SHA256_ALGORITHM,
                    cbSalt: PSS_SALT_BYTES,
                }),
                BCRYPT_PAD_PSS,
            ),
        };
        let info = match &padding {
            Padding::None => core::ptr::null(),
            Padding::Pkcs1(info) => (&raw const *info).cast(),
            Padding::Pss(info) => (&raw const *info).cast(),
        };
        // SAFETY: the key is imported, `info` matches `flags`, and the
        // buffers hold the lengths passed.
        let status = unsafe {
            BCryptVerifySignature(
                key,
                info,
                digest.as_ptr(),
                digest_len,
                signature.as_ptr(),
                signature_len,
                flags,
            )
        };
        status >= 0
    };
    if imported && !key.is_null() {
        // SAFETY: the key was imported here and is destroyed once.
        unsafe { BCryptDestroyKey(key) };
    }
    // SAFETY: the context was created here and is freed once.
    unsafe { CertFreeCertificateContext(context) };
    verified
}

/// The padding information one verification passes to CNG.
enum Padding {
    None,
    Pkcs1(BCRYPT_PKCS1_PADDING_INFO),
    Pss(BCRYPT_PSS_PADDING_INFO),
}
