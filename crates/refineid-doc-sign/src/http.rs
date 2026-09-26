// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Synchronous HTTP for the revocation and timestamp fetch paths,
//! over the OS stack (`WinHTTP`).
//!
//! Same call contract as the sibling `refineid-unix` `http`
//! module (`get` / `post` / `post_authority`, [`HttpError`]),
//! but the transport underneath is different on purpose: instead
//! of porting the tokio + custom-TLS + DNSSEC stack, this module
//! uses `WinHTTP` with the OS certificate store, the OS resolver,
//! and the system proxy configuration. Two policy consequences
//! follow from that choice and are documented here so the
//! difference is a decision, not drift:
//!
//! - DNS answers are trusted from the OS resolver; there is no
//!   local DNSSEC validation attempt. The SSRF guard (public
//!   addresses only for certificate-published URLs) is kept by
//!   resolving the host up front and rejecting non-public
//!   answers.
//! - TLS server authentication, including revocation checking,
//!   follows the machine's `WinHTTP` / Schannel configuration
//!   rather than a vendored verifier.
use std::io;
use std::net::ToSocketAddrs;

use refineid_lib_core::text::{Scheme, Uri};
#[cfg(windows)]
use windows::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_DISABLE_REDIRECTS, WINHTTP_FLAG_SECURE,
    WINHTTP_OPEN_REQUEST_FLAGS, WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_QUERY_CONTENT_LENGTH,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_LOCATION, WINHTTP_QUERY_STATUS_CODE,
    WINHTTP_QUERY_STATUS_TEXT, WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryDataAvailable, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetOption, WinHttpSetTimeouts,
};
#[cfg(windows)]
use windows::core::PCWSTR;

/// Honest `User-Agent`: project, crate version, contact URL.
pub const USER_AGENT: &str = concat!(
    "RefineID/",
    env!("CARGO_PKG_VERSION"),
    " (+https://www.refineid.fi/)"
);

/// Errors from `get` / `post` / `post_authority`. Same shape as
/// the sibling unix module so the vendored callers port
/// unchanged.
#[derive(Debug)]
pub enum HttpError {
    /// URL did not parse as a supported HTTP or HTTPS URL.
    BadUrl(&'static str),
    /// The URL used a scheme other than HTTP or HTTPS.
    UnsupportedScheme(String),
    /// TCP / I/O failure.
    Io(io::Error),
    /// HTTP status line wasn't well-formed.
    BadStatusLine(String),
    /// Non-2xx status.
    HttpStatus {
        /// HTTP status code returned by the server.
        code: u16,
        /// Reason-phrase from the status line.
        reason: String,
        /// Where the server said the resource moved to, when it
        /// said so.
        location: Option<String>,
    },
    /// Response had no readable body length.
    UnknownBodyLength,
    /// Chunked encoding chunk-size line wasn't valid hex.
    /// (`WinHTTP` de-chunks internally; kept for contract parity.)
    BadChunkSize(String),
    /// `Content-Length` exceeded the supplied `max_bytes`.
    BodyTooLarge {
        /// `Content-Length` value the server announced.
        content_length: usize,
        /// The caller-supplied `max_bytes` ceiling.
        limit: usize,
    },
    /// A certificate-published endpoint resolved to a
    /// non-public destination.
    UnsafeDestination(String),
    /// A redirect crossed a policy boundary or exceeded its hop
    /// budget.
    UnsafeRedirect(String),
    /// Authentication material was offered without
    /// server-authenticated TLS.
    InsecureCredentials,
    /// HTTPS failed in the TLS path.
    Https {
        /// Redacted transport detail.
        detail: String,
        /// Whether reconnecting may recover without changing
        /// policy or input.
        retryable: bool,
    },
}

impl core::fmt::Display for HttpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadUrl(s) => write!(f, "bad URL: {s}"),
            Self::UnsupportedScheme(s) => write!(f, "unsupported URL scheme: {s}"),
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::BadStatusLine(s) => write!(f, "bad HTTP status line: {s:?}"),
            Self::HttpStatus { code, reason, .. } => write!(f, "HTTP {code} {reason}"),
            Self::UnknownBodyLength => write!(
                f,
                "response had no Content-Length and was not chunked; refusing"
            ),
            Self::BadChunkSize(s) => write!(f, "bad chunk-size: {s:?}"),
            Self::BodyTooLarge {
                content_length,
                limit,
            } => write!(
                f,
                "Content-Length {content_length} exceeds caller limit {limit}"
            ),
            Self::UnsafeDestination(detail) => write!(f, "unsafe destination: {detail}"),
            Self::UnsafeRedirect(detail) => write!(f, "unsafe redirect: {detail}"),
            Self::InsecureCredentials => {
                f.write_str("timestamp credentials require an HTTPS authority")
            }
            Self::Https { detail, .. } => write!(f, "HTTPS: {detail}"),
        }
    }
}

impl core::error::Error for HttpError {}

impl From<io::Error> for HttpError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl HttpError {
    /// Whether a timestamp authority request may be repeated
    /// unchanged.
    pub(crate) fn is_retryable_authority_failure(&self) -> bool {
        match self {
            Self::Io(error) => matches!(
                error.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
            ),
            Self::HttpStatus { code, .. } => {
                matches!(*code, 408 | 425 | 429 | 500 | 502 | 503 | 504)
            }
            Self::Https { retryable, .. } => *retryable,
            Self::BadUrl(_)
            | Self::UnsupportedScheme(_)
            | Self::BadStatusLine(_)
            | Self::UnknownBodyLength
            | Self::BadChunkSize(_)
            | Self::BodyTooLarge { .. }
            | Self::UnsafeDestination(_)
            | Self::UnsafeRedirect(_)
            | Self::InsecureCredentials => false,
        }
    }
}

/// Why one HTTP exchange is being made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    /// A URL learned from a certificate, revocation object, or
    /// signed infrastructure document. It must resolve only to
    /// public addresses.
    CertificateMaterial,
    /// A timestamp authority explicitly configured by the caller.
    /// Local services remain usable, but redirects cannot change
    /// its origin.
    Authority,
}

/// Public certificate material may use a canonical-host and one
/// CDN hop.
const MAX_CERTIFICATE_REDIRECTS: usize = 2;

/// A configured authority may make one tightly constrained hop.
const MAX_AUTHORITY_REDIRECTS: usize = 1;

/// Redirect statuses followed for a `GET` (RFC 9110 sec.15.4).
const GET_REDIRECT_CODES: [u16; 4] = [301, 302, 307, 308];

/// Redirect statuses followed for a `POST`: only the
/// method-preserving ones.
const POST_REDIRECT_CODES: [u16; 2] = [307, 308];

/// GET `url` and return the response body, capped at `max_bytes`.
///
/// # Errors
/// URL parse failure, TCP failure, non-2xx HTTP status, malformed
/// HTTP framing, body exceeding `max_bytes`.
pub(crate) fn get(url: &Uri, max_bytes: usize, user_agent: &str) -> Result<Vec<u8>, HttpError> {
    exchange(
        "GET",
        url,
        None,
        &[],
        max_bytes,
        user_agent,
        None,
        Endpoint::CertificateMaterial,
    )
}

/// POST `body` to `url` with the supplied `content_type` header.
/// Returns the response body capped at `max_bytes`.
///
/// # Errors
/// As for [`get`].
pub(crate) fn post(
    url: &Uri,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
) -> Result<Vec<u8>, HttpError> {
    exchange(
        "POST",
        url,
        Some(content_type),
        body,
        max_bytes,
        user_agent,
        None,
        Endpoint::CertificateMaterial,
    )
}

/// POST to an explicitly configured timestamp authority.
///
/// Unlike certificate-controlled URLs, an authority may
/// intentionally be a service on a private development network.
/// Any redirect is constrained to the same origin or a same-host
/// HTTP-to-HTTPS upgrade.
pub(crate) fn post_authority(
    url: &Uri,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
    authorization: Option<&str>,
) -> Result<Vec<u8>, HttpError> {
    if authorization.is_some() && url.scheme() != Scheme::Https {
        return Err(HttpError::InsecureCredentials);
    }
    exchange(
        "POST",
        url,
        Some(content_type),
        body,
        max_bytes,
        user_agent,
        authorization,
        Endpoint::Authority,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the exchange surface is one call with eight parameters by design: method, url, headers, body, limits, identity, and policy stay visible at the three public entry points instead of hiding in a parameter struct"
)]
fn exchange(
    method: &str,
    url: &Uri,
    content_type: Option<&str>,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
    authorization: Option<&str>,
    endpoint: Endpoint,
) -> Result<Vec<u8>, HttpError> {
    let max_redirects = match endpoint {
        Endpoint::CertificateMaterial => MAX_CERTIFICATE_REDIRECTS,
        Endpoint::Authority => MAX_AUTHORITY_REDIRECTS,
    };
    let redirectable = match method {
        "GET" => &GET_REDIRECT_CODES[..],
        _ => &POST_REDIRECT_CODES[..],
    };
    let mut current = url.clone();
    for _ in 0..=max_redirects {
        guard_destination(&current, endpoint)?;
        let response = roundtrip(
            method,
            &current,
            content_type,
            body,
            max_bytes,
            user_agent,
            authorization,
        )?;
        if (200..300).contains(&response.code) {
            return Ok(response.body);
        }
        if !redirectable.contains(&response.code) {
            return Err(HttpError::HttpStatus {
                code: response.code,
                reason: response.reason,
                location: response.location,
            });
        }
        let Some(location) = response.location else {
            return Err(HttpError::UnsafeRedirect(format!(
                "HTTP {} without Location",
                response.code
            )));
        };
        let next = current
            .join(location)
            .map_err(|_| HttpError::UnsafeRedirect("unparseable Location".to_owned()))?;
        if endpoint == Endpoint::Authority && !authority_redirect_ok(&current, &next) {
            return Err(HttpError::UnsafeRedirect(
                "authority redirect crossed origins".to_owned(),
            ));
        }
        current = next;
    }
    Err(HttpError::UnsafeRedirect("too many redirects".to_owned()))
}

struct ExchangeResponse {
    code: u16,
    reason: String,
    location: Option<String>,
    body: Vec<u8>,
}

/// One request/response round trip without redirect handling.
#[cfg(windows)]
#[allow(
    clippy::too_many_arguments,
    reason = "roundtrip mirrors exchange's parameter list so the call site reads argument-for-argument; see exchange"
)]
#[allow(
    clippy::too_many_lines,
    reason = "one straight-line WinHTTP session-open-request-read recipe; splitting would shuttle RAII handles across boundaries and obscure the cleanup order"
)]
fn roundtrip(
    method: &str,
    url: &Uri,
    content_type: Option<&str>,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
    authorization: Option<&str>,
) -> Result<ExchangeResponse, HttpError> {
    if !matches!(url.scheme(), Scheme::Http | Scheme::Https) {
        return Err(HttpError::UnsupportedScheme("not http(s)".to_owned()));
    }
    let secure = url.scheme() == Scheme::Https;
    let host = url.host().to_string();
    let target = request_target(url);
    let host_wide = wide_nul(&host);
    let target_wide = wide_nul(&target);
    let verb_wide = wide_nul(method);
    let agent_wide = wide_nul(user_agent);

    let session = unsafe {
        WinHttpOpen(
            PCWSTR(agent_wide.as_ptr()),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        )
    };
    if session.is_null() {
        return Err(map_winhttp_null_handle());
    }
    let session = Handle(session);
    unsafe {
        WinHttpSetTimeouts(session.0, 10_000, 10_000, 30_000, 30_000).map_err(map_winhttp_error)?;
        let flag = WINHTTP_DISABLE_REDIRECTS.to_ne_bytes();
        WinHttpSetOption(
            Some(session.0.cast_const()),
            WINHTTP_OPTION_DISABLE_FEATURE,
            Some(&flag),
        )
        .map_err(map_winhttp_error)?;
    }
    let connection =
        unsafe { WinHttpConnect(session.0, PCWSTR(host_wide.as_ptr()), url.port(), 0) };
    if connection.is_null() {
        return Err(map_winhttp_null_handle());
    }
    let connection = Handle(connection);
    let flags = if secure {
        WINHTTP_FLAG_SECURE
    } else {
        WINHTTP_OPEN_REQUEST_FLAGS(0)
    };
    let request = unsafe {
        WinHttpOpenRequest(
            connection.0,
            PCWSTR(verb_wide.as_ptr()),
            PCWSTR(target_wide.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            flags,
        )
    };
    if request.is_null() {
        return Err(map_winhttp_null_handle());
    }
    let request = Handle(request);

    let mut headers = String::new();
    if let Some(content_type) = content_type {
        headers.push_str("Content-Type: ");
        headers.push_str(content_type);
        headers.push_str("\r\n");
    }
    if let Some(authorization) = authorization {
        headers.push_str("Authorization: ");
        headers.push_str(authorization);
        headers.push_str("\r\n");
    }
    let headers_wide: Vec<u16> = headers.encode_utf16().collect();
    let headers_opt = if headers_wide.is_empty() {
        None
    } else {
        Some(headers_wide.as_slice())
    };
    let (body_ptr, body_len) = match body.len() {
        0 => (None, 0),
        len => (
            Some(body.as_ptr().cast::<core::ffi::c_void>()),
            u32::try_from(len).map_err(|_| HttpError::BodyTooLarge {
                content_length: len,
                limit: max_bytes,
            })?,
        ),
    };
    unsafe {
        WinHttpSendRequest(request.0, headers_opt, body_ptr, body_len, body_len, 0)
            .map_err(map_winhttp_error)?;
        WinHttpReceiveResponse(request.0, std::ptr::null_mut()).map_err(map_winhttp_error)?;
    }
    let code = u16::try_from(query_u32(request.0, WINHTTP_QUERY_STATUS_CODE)?)
        .map_err(|_| HttpError::BadStatusLine("status code out of range".to_owned()))?;
    let reason = query_text(request.0, WINHTTP_QUERY_STATUS_TEXT)?;
    if !(200..300).contains(&code) {
        let location = query_text(request.0, WINHTTP_QUERY_LOCATION)
            .ok()
            .filter(|text| !text.is_empty());
        return Ok(ExchangeResponse {
            code,
            reason,
            location,
            body: Vec::new(),
        });
    }
    if let Ok(announced) = query_u32(request.0, WINHTTP_QUERY_CONTENT_LENGTH)
        && announced as usize > max_bytes
    {
        return Err(HttpError::BodyTooLarge {
            content_length: announced as usize,
            limit: max_bytes,
        });
    }
    let mut out = Vec::new();
    loop {
        let mut available = 0u32;
        unsafe {
            WinHttpQueryDataAvailable(request.0, &raw mut available).map_err(map_winhttp_error)?;
        }
        if available == 0 {
            break;
        }
        if out.len() + available as usize > max_bytes {
            return Err(HttpError::BodyTooLarge {
                content_length: out.len() + available as usize,
                limit: max_bytes,
            });
        }
        let start = out.len();
        out.resize(start + available as usize, 0);
        let mut got = 0u32;
        unsafe {
            WinHttpReadData(
                request.0,
                out[start..].as_mut_ptr().cast::<core::ffi::c_void>(),
                available,
                &raw mut got,
            )
            .map_err(map_winhttp_error)?;
        }
        out.truncate(start + got as usize);
        if got == 0 {
            break;
        }
    }
    Ok(ExchangeResponse {
        code,
        reason,
        location: None,
        body: out,
    })
}

/// Non-Windows transports are not implemented: HTTP fetch needs
/// `WinHTTP`. Host builds keep the API so the pure sign stack and
/// its tests still compile and run everywhere.
#[cfg(not(windows))]
#[allow(
    clippy::too_many_arguments,
    reason = "stub keeps the windows roundtrip signature so the exchange call site compiles on every platform"
)]
fn roundtrip(
    _method: &str,
    _url: &Uri,
    _content_type: Option<&str>,
    _body: &[u8],
    _max_bytes: usize,
    _user_agent: &str,
    _authorization: Option<&str>,
) -> Result<ExchangeResponse, HttpError> {
    Err(HttpError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "HTTP fetch requires Windows (WinHTTP)",
    )))
}

/// RAII for a `WinHTTP` `HINTERNET`: closed exactly once, even on
/// early error returns.
#[cfg(windows)]
struct Handle(*mut core::ffi::c_void);

// The handle is used synchronously on one thread only.
#[cfg(windows)]
unsafe impl Send for Handle {}

#[cfg(windows)]
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

/// SSRF guard for certificate-published URLs: the host must
/// resolve, and every answer must be a public address. Authority
/// URLs skip the check (a test TSA may live on a private
/// network).
fn guard_destination(url: &Uri, endpoint: Endpoint) -> Result<(), HttpError> {
    if endpoint == Endpoint::Authority {
        return Ok(());
    }
    let host = url.host().to_string();
    let mut answers = (host.as_str(), url.port())
        .to_socket_addrs()
        .map_err(|error| HttpError::UnsafeDestination(format!("resolve {host}: {error}")))?
        .peekable();
    if answers.peek().is_none() {
        return Err(HttpError::UnsafeDestination(format!(
            "{host} resolved to no addresses"
        )));
    }
    for answer in answers {
        let ip = answer.ip();
        let non_public = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
                    || v6.is_multicast()
                    || v6.is_unspecified()
            }
        };
        if non_public {
            return Err(HttpError::UnsafeDestination(format!(
                "{host} resolves to non-public {ip}"
            )));
        }
    }
    Ok(())
}

/// Authority redirects stay on the same origin, with a same-host
/// HTTP-to-HTTPS upgrade allowed.
fn authority_redirect_ok(from: &Uri, to: &Uri) -> bool {
    if from.host() != to.host() || from.port() != to.port() {
        return false;
    }
    to.scheme() == from.scheme() || (from.scheme() == Scheme::Http && to.scheme() == Scheme::Https)
}

/// Origin-form request target (`/path[?query]`, RFC 9112 §3.1.1).
#[cfg(windows)]
fn request_target(url: &Uri) -> String {
    if url.query().is_empty() {
        url.path().to_string()
    } else {
        format!("{}?{}", url.path(), url.query())
    }
}

#[cfg(windows)]
fn wide_nul(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn query_u32(request: *mut core::ffi::c_void, info: u32) -> Result<u32, HttpError> {
    let mut value = 0u32;
    let mut len = 4u32;
    let mut index = 0u32;
    unsafe {
        WinHttpQueryHeaders(
            request,
            info | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some((&raw mut value).cast::<core::ffi::c_void>()),
            &raw mut len,
            &raw mut index,
        )
    }
    .map_err(map_winhttp_error)?;
    Ok(value)
}

#[cfg(windows)]
fn query_text(request: *mut core::ffi::c_void, info: u32) -> Result<String, HttpError> {
    let mut len = 0u32;
    let mut index = 0u32;
    let _ = unsafe {
        WinHttpQueryHeaders(
            request,
            info,
            PCWSTR::null(),
            None,
            &raw mut len,
            &raw mut index,
        )
    };
    if len < 2 {
        return Ok(String::new());
    }
    let mut buffer = vec![0u16; len as usize / 2 + 1];
    let mut len2 = u32::try_from(buffer.len().saturating_mul(2))
        .map_err(|_| HttpError::BadStatusLine("header length out of range".to_owned()))?;
    unsafe {
        WinHttpQueryHeaders(
            request,
            info,
            PCWSTR::null(),
            Some(buffer.as_mut_ptr().cast::<core::ffi::c_void>()),
            &raw mut len2,
            &raw mut index,
        )
    }
    .map_err(map_winhttp_error)?;
    let units = len2 as usize / 2;
    let text = buffer.get(..units).unwrap_or(&[]);
    let text = text.split(|unit| *unit == 0).next().unwrap_or(&[]);
    Ok(String::from_utf16_lossy(text))
}

/// Map a `WinHTTP` failure onto [`HttpError`], preserving
/// retryability through `io::ErrorKind` for the transient
/// transport failures.
#[cfg(windows)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err passes ownership at eight call sites; borrowing would push a closure onto each"
)]
fn map_winhttp_error(error: windows::core::Error) -> HttpError {
    // `HRESULT_FROM_WIN32` keeps the Win32 code in the low word.
    map_winhttp_code(u32::from_ne_bytes(error.code().0.to_ne_bytes()) & 0xFFFF)
}

/// Map a null-handle `WinHTTP` failure, where there is no
/// `Result` error to carry: read the calling thread's last
/// Win32 error instead.
#[cfg(windows)]
fn map_winhttp_null_handle() -> HttpError {
    let code = unsafe { windows::Win32::Foundation::GetLastError() }.0;
    map_winhttp_code(code)
}

#[cfg(windows)]
fn map_winhttp_code(code: u32) -> HttpError {
    // The `windows` crate builds without its `std` feature, so
    // `windows::core::Error` has no `std::error::Error` impl to
    // carry. The Win32 code alone is the detail; it names no
    // host, path, or credential.
    match code {
        // ERROR_WINHTTP_TIMEOUT
        12002 => HttpError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("WinHTTP timeout ({code})"),
        )),
        // ERROR_WINHTTP_CANNOT_CONNECT
        12029 => HttpError::Io(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("WinHTTP cannot connect ({code})"),
        )),
        // ERROR_WINHTTP_CONNECTION_ERROR
        12030 => HttpError::Io(io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("WinHTTP connection error ({code})"),
        )),
        // ERROR_WINHTTP_NAME_NOT_RESOLVED: fail fast, never retry.
        12007 => HttpError::Io(io::Error::new(
            io::ErrorKind::HostUnreachable,
            format!("WinHTTP name not resolved ({code})"),
        )),
        // TLS failures: date, CN, CA, handshake.
        12037 | 12038 | 12045 | 12157 | 12175 => HttpError::Https {
            detail: format!("TLS failure (WinHTTP {code})"),
            retryable: false,
        },
        _ => HttpError::Io(io::Error::other(format!("WinHTTP failure ({code})"))),
    }
}
