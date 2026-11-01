// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! The Windows HTTP stack (`WinHTTP`) as the transport of
//! `refineid_doc_sign`: timestamp requests, chain and revocation fetches
//! while signing, and the live revocation lookup of a verification.
//!
//! Core vets every certificate-published URL before the transport is
//! called: [`HttpTransport::resolve`] answers with the OS resolver, and
//! core's guard refuses a host that resolves to anything but public
//! unicast addresses. `WinHTTP` then connects by host name, through the
//! OS resolver, the OS certificate store and the system proxy
//! configuration, so TLS server authentication follows the machine's
//! Schannel configuration; the vetted addresses are core's evidence, not
//! the connection's target. Redirects are followed here with `WinHTTP`'s
//! own redirect handling off: a certificate-published hop goes only to a
//! URL `guard_destination` admits, an authority hop only to the same
//! origin or its HTTPS upgrade. Every request names this client with
//! [`USER_AGENT`].

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::ops::Range;
use std::sync::Once;

use refineid_doc_sign::http::{self as core_http, HttpError, HttpTransport};
#[cfg(windows)]
use refineid_doc_sign::uri::Scheme;
use refineid_doc_sign::uri::Uri;
#[cfg(windows)]
use windows::Win32::Networking::WinHttp::{
    ERROR_WINHTTP_CANNOT_CONNECT, ERROR_WINHTTP_CONNECTION_ERROR, ERROR_WINHTTP_NAME_NOT_RESOLVED,
    ERROR_WINHTTP_SECURE_CERT_CN_INVALID, ERROR_WINHTTP_SECURE_CERT_DATE_INVALID,
    ERROR_WINHTTP_SECURE_CHANNEL_ERROR, ERROR_WINHTTP_SECURE_FAILURE,
    ERROR_WINHTTP_SECURE_INVALID_CA, ERROR_WINHTTP_TIMEOUT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_DISABLE_REDIRECTS, WINHTTP_FLAG_SECURE, WINHTTP_OPEN_REQUEST_FLAGS,
    WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_LOCATION, WINHTTP_QUERY_STATUS_CODE, WINHTTP_QUERY_STATUS_TEXT,
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryDataAvailable,
    WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
    WinHttpSetOption, WinHttpSetTimeouts,
};
#[cfg(windows)]
use windows::core::PCWSTR;

/// Honest `User-Agent`: project, crate version, contact URL.
pub const USER_AGENT: &str = concat!(
    "RefineID/",
    env!("CARGO_PKG_VERSION"),
    " (+https://www.refineid.fi/)"
);

/// Register `WinHTTP` with `refineid_doc_sign`, once per process. Every
/// entry point that signs or verifies a document calls it before the
/// first request.
pub fn install() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| core_http::set_http_transport(Box::new(WinHttpTransport)));
}

/// The transport [`install`] registers.
#[derive(Debug, Clone, Copy)]
struct WinHttpTransport;

impl HttpTransport for WinHttpTransport {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, HttpError> {
        Ok((host, port).to_socket_addrs()?.collect())
    }

    fn get(
        &self,
        url: &Uri,
        _vetted: &[SocketAddr],
        max_bytes: usize,
    ) -> Result<Vec<u8>, HttpError> {
        follow(
            Method::Get,
            url,
            Endpoint::CertificateMaterial,
            &mut |hop| roundtrip(Method::Get, hop, None, &[], max_bytes, None),
            &certificate_hop_admitted,
        )
    }

    fn post(
        &self,
        url: &Uri,
        _vetted: &[SocketAddr],
        content_type: &str,
        body: &[u8],
        max_bytes: usize,
    ) -> Result<Vec<u8>, HttpError> {
        follow(
            Method::Post,
            url,
            Endpoint::CertificateMaterial,
            &mut |hop| roundtrip(Method::Post, hop, Some(content_type), body, max_bytes, None),
            &certificate_hop_admitted,
        )
    }

    fn post_authority(
        &self,
        url: &Uri,
        content_type: &str,
        body: &[u8],
        max_bytes: usize,
        auth_header: Option<&str>,
    ) -> Result<Vec<u8>, HttpError> {
        follow(
            Method::Post,
            url,
            Endpoint::Authority,
            &mut |hop| {
                roundtrip(
                    Method::Post,
                    hop,
                    Some(content_type),
                    body,
                    max_bytes,
                    auth_header,
                )
            },
            &certificate_hop_admitted,
        )
    }
}

/// Whether a redirect of certificate material may go to `next`: core's
/// guard admits a host that resolves to public unicast addresses only.
fn certificate_hop_admitted(next: &Uri) -> Result<(), HttpError> {
    core_http::guard_destination(&WinHttpTransport, next).map(|_addresses| ())
}

/// Why one HTTP exchange is being made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    /// A URL learned from a certificate, revocation object, or signed
    /// infrastructure document. Every hop must pass core's guard.
    CertificateMaterial,
    /// A timestamp authority the caller configured. A private service
    /// stays usable, and a redirect cannot change its origin.
    Authority,
}

impl Endpoint {
    /// How many redirects the endpoint may make: public certificate
    /// material a canonical-host and one CDN hop, a configured authority
    /// one tightly constrained hop.
    const fn max_redirects(self) -> usize {
        match self {
            Self::CertificateMaterial => 2,
            Self::Authority => 1,
        }
    }
}

/// The request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

impl Method {
    /// The method as the request line names it.
    #[cfg(windows)]
    const fn verb(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }

    /// The redirect statuses followed (RFC 9110 section 15.4): for a
    /// `POST` only the method-preserving ones.
    const fn redirect_codes(self) -> &'static [u16] {
        match self {
            Self::Get => &GET_REDIRECT_CODES,
            Self::Post => &POST_REDIRECT_CODES,
        }
    }
}

/// Redirect statuses followed for a `GET` (RFC 9110 section 15.4).
const GET_REDIRECT_CODES: [u16; 4] = [301, 302, 307, 308];

/// Redirect statuses followed for a `POST`: only the method-preserving
/// ones.
const POST_REDIRECT_CODES: [u16; 2] = [307, 308];

/// The successful statuses (RFC 9110 section 15.3).
const SUCCESS: Range<u16> = 200..300;

/// One response without redirect handling.
struct Response {
    /// The status code.
    code: u16,
    /// The reason phrase.
    reason: String,
    /// Where the server said the resource moved to, when it said so.
    location: Option<String>,
    /// The body of a successful response; empty otherwise.
    body: Vec<u8>,
}

/// Exchange `url` with `roundtrip`, following its redirects within
/// `endpoint`'s budget: a certificate-material hop only where `admitted`
/// allows, an authority hop only within its origin.
fn follow(
    method: Method,
    url: &Uri,
    endpoint: Endpoint,
    roundtrip: &mut dyn FnMut(&Uri) -> Result<Response, HttpError>,
    admitted: &dyn Fn(&Uri) -> Result<(), HttpError>,
) -> Result<Vec<u8>, HttpError> {
    let mut current = url.clone();
    for _ in 0..=endpoint.max_redirects() {
        let response = roundtrip(&current)?;
        if SUCCESS.contains(&response.code) {
            return Ok(response.body);
        }
        if !method.redirect_codes().contains(&response.code) {
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
        match endpoint {
            Endpoint::CertificateMaterial => admitted(&next)?,
            Endpoint::Authority => {
                if !core_http::authority_redirect_ok(&current, &next) {
                    return Err(HttpError::UnsafeRedirect(
                        "authority redirect crossed origins".to_owned(),
                    ));
                }
            }
        }
        current = next;
    }
    Err(HttpError::UnsafeRedirect("too many redirects".to_owned()))
}

/// How long `WinHTTP` waits for the name to resolve.
#[cfg(windows)]
const RESOLVE_TIMEOUT_MS: i32 = 10_000;
/// How long `WinHTTP` waits for the connection.
#[cfg(windows)]
const CONNECT_TIMEOUT_MS: i32 = 10_000;
/// How long `WinHTTP` waits to send the request.
#[cfg(windows)]
const SEND_TIMEOUT_MS: i32 = 30_000;
/// How long `WinHTTP` waits for the response.
#[cfg(windows)]
const RECEIVE_TIMEOUT_MS: i32 = 30_000;
/// The low word of an `HRESULT` made by `HRESULT_FROM_WIN32`, where the
/// Win32 code sits.
#[cfg(windows)]
const WIN32_CODE_MASK: u32 = 0xFFFF;
/// The UTF-16 units of a header value's terminating NUL.
#[cfg(windows)]
const HEADER_NUL_BYTES: u32 = 2;

/// One request/response round trip without redirect handling.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "one straight-line WinHTTP session-open-request-read recipe; splitting would shuttle RAII handles across boundaries and obscure the cleanup order"
)]
fn roundtrip(
    method: Method,
    url: &Uri,
    content_type: Option<&str>,
    body: &[u8],
    max_bytes: usize,
    authorization: Option<&str>,
) -> Result<Response, HttpError> {
    let secure = match url.scheme() {
        Scheme::Https => true,
        Scheme::Http => false,
    };
    let host_wide = wide_nul(&url.host().to_string());
    let target_wide = wide_nul(&request_target(url));
    let verb_wide = wide_nul(method.verb());
    let agent_wide = wide_nul(USER_AGENT);

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
        WinHttpSetTimeouts(
            session.0,
            RESOLVE_TIMEOUT_MS,
            CONNECT_TIMEOUT_MS,
            SEND_TIMEOUT_MS,
            RECEIVE_TIMEOUT_MS,
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
    unsafe {
        let flag = WINHTTP_DISABLE_REDIRECTS.to_ne_bytes();
        WinHttpSetOption(
            Some(request.0.cast_const()),
            WINHTTP_OPTION_DISABLE_FEATURE,
            Some(&flag),
        )
        .map_err(map_winhttp_error)?;
    }

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
    if !SUCCESS.contains(&code) {
        let location = query_text(request.0, WINHTTP_QUERY_LOCATION)
            .ok()
            .filter(|text| !text.is_empty());
        return Ok(Response {
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
    Ok(Response {
        code,
        reason,
        location: None,
        body: out,
    })
}

/// Another host has no `WinHTTP`: the policy above and its tests build
/// everywhere, and a fetch on such a host is refused.
#[cfg(not(windows))]
fn roundtrip(
    _method: Method,
    _url: &Uri,
    _content_type: Option<&str>,
    _body: &[u8],
    _max_bytes: usize,
    _authorization: Option<&str>,
) -> Result<Response, HttpError> {
    Err(HttpError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "HTTP fetch requires Windows (WinHTTP)",
    )))
}

/// RAII for a `WinHTTP` `HINTERNET`: closed exactly once, even on early
/// error returns.
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

/// Origin-form request target (`/path[?query]`, RFC 9112 section 3.1.1).
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
    let mut len = u32::try_from(size_of::<u32>()).unwrap_or(u32::MAX);
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
    if len < HEADER_NUL_BYTES {
        return Ok(String::new());
    }
    let mut buffer = vec![0u16; len as usize / size_of::<u16>() + 1];
    let mut len2 = u32::try_from(buffer.len().saturating_mul(size_of::<u16>()))
        .map_err(|_| HttpError::BadStatusLine("header length out of range".to_owned()))?;
    index = 0;
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
    let units = len2 as usize / size_of::<u16>();
    let text = buffer.get(..units).unwrap_or(&[]);
    let text = text.split(|unit| *unit == 0).next().unwrap_or(&[]);
    Ok(String::from_utf16_lossy(text))
}

/// Map a `WinHTTP` failure onto [`HttpError`], preserving retryability
/// through `io::ErrorKind` for the transient transport failures.
#[cfg(windows)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err passes ownership at eight call sites; borrowing would push a closure onto each"
)]
fn map_winhttp_error(error: windows::core::Error) -> HttpError {
    map_winhttp_code(u32::from_ne_bytes(error.code().0.to_ne_bytes()) & WIN32_CODE_MASK)
}

/// Map a null-handle `WinHTTP` failure, where there is no `Result` error
/// to carry: read the calling thread's last Win32 error instead.
#[cfg(windows)]
fn map_winhttp_null_handle() -> HttpError {
    let code = unsafe { windows::Win32::Foundation::GetLastError() }.0;
    map_winhttp_code(code)
}

/// The `windows` crate builds without its `std` feature, so
/// `windows::core::Error` has no `std::error::Error` impl to carry. The
/// Win32 code alone is the detail; it names no host, path, or credential.
#[cfg(windows)]
fn map_winhttp_code(code: u32) -> HttpError {
    match code {
        ERROR_WINHTTP_TIMEOUT => HttpError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("WinHTTP timeout ({code})"),
        )),
        ERROR_WINHTTP_CANNOT_CONNECT => HttpError::Io(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("WinHTTP cannot connect ({code})"),
        )),
        ERROR_WINHTTP_CONNECTION_ERROR => HttpError::Io(io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("WinHTTP connection error ({code})"),
        )),
        // A name that does not resolve fails fast and is never retried.
        ERROR_WINHTTP_NAME_NOT_RESOLVED => HttpError::Io(io::Error::new(
            io::ErrorKind::HostUnreachable,
            format!("WinHTTP name not resolved ({code})"),
        )),
        ERROR_WINHTTP_SECURE_CERT_DATE_INVALID
        | ERROR_WINHTTP_SECURE_CERT_CN_INVALID
        | ERROR_WINHTTP_SECURE_INVALID_CA
        | ERROR_WINHTTP_SECURE_CHANNEL_ERROR
        | ERROR_WINHTTP_SECURE_FAILURE => HttpError::Https {
            detail: format!("TLS failure (WinHTTP {code})"),
            retryable: false,
        },
        _ => HttpError::Io(io::Error::other(format!("WinHTTP failure ({code})"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A scripted server: one response per hop, in order.
    fn scripted(
        responses: Vec<Response>,
    ) -> impl FnMut(&Uri) -> Result<Response, HttpError> + 'static {
        let mut queue: VecDeque<Response> = responses.into();
        move |_hop| {
            queue
                .pop_front()
                .ok_or_else(|| HttpError::Io(io::Error::other("the script ran out of responses")))
        }
    }

    /// A successful response carrying `body`.
    fn ok(body: &str) -> Response {
        Response {
            code: 200,
            reason: "OK".to_owned(),
            location: None,
            body: body.as_bytes().to_vec(),
        }
    }

    /// A redirect with status `code` to `location`.
    fn redirect(code: u16, location: Option<&str>) -> Response {
        Response {
            code,
            reason: "Redirect".to_owned(),
            location: location.map(str::to_owned),
            body: Vec::new(),
        }
    }

    /// A guard admitting every hop.
    const EVERY_HOP: &dyn Fn(&Uri) -> Result<(), HttpError> = &|_next| Ok(());

    /// A guard admitting no hop.
    const NO_HOP: &dyn Fn(&Uri) -> Result<(), HttpError> =
        &|next| Err(HttpError::UnsafeDestination(next.to_string()));

    fn uri(text: &str) -> Uri {
        Uri::parse(text.to_owned()).unwrap_or_else(|error| panic!("{text}: {error}"))
    }

    #[test]
    fn a_success_is_its_body() {
        let body = follow(
            Method::Get,
            &uri("http://ocsp.example/"),
            Endpoint::CertificateMaterial,
            &mut scripted(vec![ok("answer")]),
            EVERY_HOP,
        );
        assert_eq!(body.ok(), Some(b"answer".to_vec()));
    }

    #[test]
    fn a_get_follows_an_admitted_redirect() {
        let body = follow(
            Method::Get,
            &uri("http://crl.example/list"),
            Endpoint::CertificateMaterial,
            &mut scripted(vec![
                redirect(302, Some("http://cdn.example/list")),
                ok("list"),
            ]),
            EVERY_HOP,
        );
        assert_eq!(body.ok(), Some(b"list".to_vec()));
    }

    #[test]
    fn a_redirect_the_guard_refuses_is_refused() {
        let outcome = follow(
            Method::Get,
            &uri("http://crl.example/list"),
            Endpoint::CertificateMaterial,
            &mut scripted(vec![redirect(301, Some("http://internal.example/"))]),
            NO_HOP,
        );
        assert!(matches!(outcome, Err(HttpError::UnsafeDestination(_))));
    }

    #[test]
    fn a_post_does_not_follow_a_method_changing_redirect() {
        let outcome = follow(
            Method::Post,
            &uri("http://ocsp.example/"),
            Endpoint::CertificateMaterial,
            &mut scripted(vec![redirect(302, Some("http://ocsp.example/other"))]),
            EVERY_HOP,
        );
        assert!(matches!(
            outcome,
            Err(HttpError::HttpStatus { code: 302, .. })
        ));
    }

    #[test]
    fn an_authority_stays_on_its_origin() {
        let crossed = follow(
            Method::Post,
            &uri("http://tsa.example/"),
            Endpoint::Authority,
            &mut scripted(vec![redirect(307, Some("http://other.example/"))]),
            EVERY_HOP,
        );
        assert!(matches!(crossed, Err(HttpError::UnsafeRedirect(_))));
        let upgraded = follow(
            Method::Post,
            &uri("http://tsa.example:8443/"),
            Endpoint::Authority,
            &mut scripted(vec![
                redirect(307, Some("https://tsa.example:8443/")),
                ok("token"),
            ]),
            EVERY_HOP,
        );
        assert_eq!(upgraded.ok(), Some(b"token".to_vec()));
    }

    #[test]
    fn redirects_beyond_the_budget_are_refused() {
        let hops = (0..=Endpoint::CertificateMaterial.max_redirects())
            .map(|_| redirect(308, Some("http://crl.example/again")))
            .collect();
        let outcome = follow(
            Method::Get,
            &uri("http://crl.example/list"),
            Endpoint::CertificateMaterial,
            &mut scripted(hops),
            EVERY_HOP,
        );
        assert!(matches!(outcome, Err(HttpError::UnsafeRedirect(_))));
    }

    #[test]
    fn a_redirect_without_a_location_is_refused() {
        let outcome = follow(
            Method::Get,
            &uri("http://crl.example/list"),
            Endpoint::CertificateMaterial,
            &mut scripted(vec![redirect(301, None)]),
            EVERY_HOP,
        );
        assert!(matches!(outcome, Err(HttpError::UnsafeRedirect(_))));
    }

    #[test]
    fn the_user_agent_names_the_project_and_its_contact() {
        assert!(USER_AGENT.starts_with("RefineID/"));
        assert!(USER_AGENT.ends_with("(+https://www.refineid.fi/)"));
    }
}
