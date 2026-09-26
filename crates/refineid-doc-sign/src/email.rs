// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Email-address validation for TSA `rfc822Name` entries.
//!
//! Vendored from the sibling `refineid-unix` `identity` module
//! (Apache-2.0, same copyright holder), where the constructor
//! is crate-private.
use core::fmt;
use core::ops::Deref;

/// Email address (RFC 5321 / RFC 822 form).
///
/// Used in `subjectAltName` `rfc822Name` `GeneralName`
/// entries and in FINEID service certificates (S2 §6.3.6.4.4).
/// Validated at construction: contains at least one `@`,
/// non-empty local and domain parts, no whitespace, total
/// length within RFC 5321 §4.5.3.1 limits (320 octets is the
/// practical upper bound; we accept 254 for the address as a
/// whole, the SMTP path-length cap that mail servers
/// commonly enforce).
///
/// The validator is intentionally permissive: it rejects
/// shape-broken inputs (`alice`, `@example.com`, `a@`,
/// `a@b@c`, ` a@b`) without parsing the local-part's quoting
/// rules from RFC 5322. Cert subjects in the wild use the
/// simple form; over-strict parsing would reject valid
/// addresses needlessly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmailAddress(String);

/// Construction errors emitted by `EmailAddress::new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailAddressError {
    /// Input was the empty string.
    Empty,
    /// Input exceeded the byte-length cap.
    TooLong {
        /// Actual byte length.
        got: usize,
        /// Cap (254 octets, the SMTP path-length cap most
        /// mail servers enforce).
        max: usize,
    },
    /// Input contained no `@` separator.
    NoAtSign,
    /// Input contained more than one `@`. Some quoted-local-
    /// part forms allow this per RFC 5322; refineid rejects
    /// the unquoted multi-`@` shape outright since cert
    /// subjects in the wild don't use quoted locals.
    MultipleAtSigns {
        /// Number of `@` characters counted in the input.
        count: usize,
    },
    /// Substring before `@` was empty (e.g. `@example.com`).
    EmptyLocalPart,
    /// Substring after `@` was empty (e.g. `alice@`).
    EmptyDomainPart,
    /// Input contained a whitespace character; ASCII space,
    /// tab, CR, or LF -- none are legal anywhere in the
    /// unquoted form.
    Whitespace {
        /// Byte offset (0-based) where the whitespace lives.
        at: usize,
    },
}

impl fmt::Display for EmailAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("email address cannot be empty"),
            Self::TooLong { got, max } => {
                write!(f, "email too long: {got} > {max} octets")
            }
            Self::NoAtSign => f.write_str("email missing '@' separator"),
            Self::MultipleAtSigns { count } => {
                write!(f, "email has {count} '@' characters, expected exactly 1")
            }
            Self::EmptyLocalPart => f.write_str("email local-part is empty"),
            Self::EmptyDomainPart => f.write_str("email domain part is empty"),
            Self::Whitespace { at } => {
                write!(f, "email contains whitespace at offset {at}")
            }
        }
    }
}

impl core::error::Error for EmailAddressError {}

impl EmailAddress {
    /// # Errors
    /// [`EmailAddressError`] variants for empty input, length
    /// over 254 octets, missing or duplicated `@`, empty
    /// local/domain part, or any whitespace.
    ///
    /// # Panics
    /// Never. The single `.expect()` on `str::split` relies on
    /// the documented invariant that `split` always yields at
    /// least one element (the first call to `.next()` is
    /// guaranteed `Some`); this is a proven invariant of the
    /// Rust stdlib, not an assumption about the input.
    pub fn new(s: &str) -> Result<Self, EmailAddressError> {
        const MAX_LEN: usize = 254;
        if s.is_empty() {
            return Err(EmailAddressError::Empty);
        }
        if s.len() > MAX_LEN {
            return Err(EmailAddressError::TooLong {
                got: s.len(),
                max: MAX_LEN,
            });
        }
        if let Some((i, _)) = s.char_indices().find(|(_, c)| c.is_whitespace()) {
            return Err(EmailAddressError::Whitespace { at: i });
        }
        // Single-pass split-at-@: counts and locates
        // simultaneously. str::split always yields at least
        // one element, so the .expect on the first .next is a
        // proven stdlib invariant (see # Panics above).
        let mut parts = s.split('@');
        #[expect(
            clippy::expect_used,
            reason = "str::split is documented to always yield at least one element on any input (incl. empty); the expect documents that proven stdlib invariant."
        )]
        let local = parts
            .next()
            .expect("str::split always yields at least one element");
        let Some(domain) = parts.next() else {
            return Err(EmailAddressError::NoAtSign);
        };
        // Any further parts means more than one '@'.
        if parts.next().is_some() {
            let count = s.bytes().filter(|&b| b == b'@').count();
            return Err(EmailAddressError::MultipleAtSigns { count });
        }
        if local.is_empty() {
            return Err(EmailAddressError::EmptyLocalPart);
        }
        if domain.is_empty() {
            return Err(EmailAddressError::EmptyDomainPart);
        }
        Ok(Self(s.to_owned()))
    }

    /// Borrow the underlying email-address string (UTF-8, no
    /// whitespace, exactly one `@`, both halves non-empty).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for EmailAddress {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for EmailAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for EmailAddress {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for EmailAddress {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}
