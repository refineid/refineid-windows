// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Offline verification of `ASiC-E` containers carrying detached `CAdES`.
//!
//! The flow mirrors the writer ([`crate::asic`]): the ZIP yields the
//! manifest plus the files; every manifest digest is recomputed; each
//! detached `CAdES` is parsed and verified against its embedded signer
//! certificate with the manifest supplied as the external content.
//! Nothing here touches the network, the clock beyond file reads, or a
//! card: a container either checks against its own bytes or it does not.
//!
//! `XAdES` containers and PDFs are reported as unsupported rather than
//! mis-verified. A wrong verdict is worse than no verdict.
use std::path::{Path, PathBuf};

use refineid_lib_core::oid::known;

use crate::base64;
use crate::ber::{BerTag, BerTlv, BerTlvIter, Boolean, OctetString, Oid as BerOid, Sequence};
use crate::cades::DigestAlgorithm;
use crate::cms::{SignedData, SignerIdentifier};
use crate::oids;
use refineid_lib_core::oid::Oid;

/// Outcome of verifying one container.
#[derive(Debug)]
pub struct DocumentVerifyReport {
    /// Container display name (file name, not the full path).
    pub container: String,
    /// One entry per manifest-covered file, plus any data file the
    /// manifest does not cover.
    pub files: Vec<VerifiedFile>,
    /// One entry per `CAdES` signature in the container.
    pub signatures: Vec<VerifiedSignature>,
    /// Overall verdict: every digest matched, every signature
    /// verified, and no data file sits outside the manifest.
    pub ok: bool,
}

/// One manifest-covered (or uncovered) file and its digest verdict.
#[derive(Debug)]
pub struct VerifiedFile {
    /// Entry name inside the container.
    pub name: String,
    /// Digest algorithm the manifest names, as a short label.
    pub algorithm: String,
    /// `true` when the recomputed digest matches the manifest.
    pub digest_ok: bool,
    /// Why not, when it does not. Empty on success.
    pub detail: String,
}

/// One `CAdES` signature and its cryptographic verdict.
#[derive(Debug)]
pub struct VerifiedSignature {
    /// Subject common name of the signer certificate, when the
    /// certificate carries one.
    pub signer_cn: Option<String>,
    /// `true` when the signature verifies against the embedded
    /// signer certificate over the manifest bytes.
    pub valid: bool,
    /// Why not, when it does not. Empty on success.
    pub detail: String,
}

impl DocumentVerifyReport {
    /// Multi-line verdict for the GUI result box (`\r\n` separated).
    /// Names files and signers; carries no key material.
    #[must_use]
    pub fn render(&self) -> String {
        let mut lines = vec![
            format!("Container: {}", self.container),
            format!("Files ({}):", self.files.len()),
        ];
        for file in &self.files {
            if file.digest_ok {
                lines.push(format!("  {} — {} ok", file.name, file.algorithm));
            } else {
                lines.push(format!("  {} — FAILED ({})", file.name, file.detail));
            }
        }
        lines.push(format!("Signatures ({}):", self.signatures.len()));
        for signature in &self.signatures {
            let who = signature.signer_cn.as_deref().unwrap_or("unknown signer");
            if signature.valid {
                lines.push(format!("  {who} — valid"));
            } else {
                lines.push(format!("  {who} — INVALID ({})", signature.detail));
            }
        }
        lines.push(if self.ok {
            "Result: VALID".to_owned()
        } else {
            "Result: INVALID".to_owned()
        });
        let mut out = lines.join("\r\n");
        out.push_str("\r\n");
        out
    }
}

/// Why a container could not be verified at all.
///
/// A negative verdict -- digest mismatch, bad signature -- is not an
/// error; it lands on the report with `ok = false`. These are the
/// cases where there is no verdict to report.
#[derive(Debug)]
pub enum DocumentVerifyError {
    /// The container file could not be read.
    Read {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// Not a ZIP container at all.
    NotAContainer,
    /// A signed format this verifier does not implement.
    Unsupported(String),
    /// The ZIP structure is malformed or uses features outside the
    /// `ASiC` profile (encryption, data descriptors, unknown methods).
    Zip(String),
    /// The manifest is missing, malformed, or names a digest this
    /// verifier does not implement.
    Manifest(String),
    /// A signature entry does not parse as CMS, names an unexpected
    /// content type, or does not embed its signer certificate.
    Cms(String),
    /// The container carries no `CAdES` signature entries.
    NoSignatures,
}

impl core::fmt::Display for DocumentVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read { path, .. } => write!(f, "cannot read {}", path.display()),
            Self::NotAContainer => f.write_str("not an ASiC-E container"),
            Self::Unsupported(detail) => write!(f, "unsupported: {detail}"),
            Self::Zip(detail) => write!(f, "container ZIP error: {detail}"),
            Self::Manifest(detail) => write!(f, "manifest error: {detail}"),
            Self::Cms(detail) => write!(f, "signature error: {detail}"),
            Self::NoSignatures => f.write_str("container carries no CAdES signatures"),
        }
    }
}

impl core::error::Error for DocumentVerifyError {}

/// Verify the `ASiC-E` container at `path`.
///
/// # Errors
/// [`DocumentVerifyError`] when the file cannot be read, is not a
/// container, is an unimplemented flavour, or is structurally
/// broken. Cryptographic failures are verdicts, not errors.
pub fn verify_document(path: &Path) -> Result<DocumentVerifyReport, DocumentVerifyError> {
    let bytes = std::fs::read(path).map_err(|source| DocumentVerifyError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let container = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("container")
        .to_owned();
    verify_bytes(&bytes, container)
}

/// Verify container `bytes` under the display name `container`.
fn verify_bytes(
    bytes: &[u8],
    container: String,
) -> Result<DocumentVerifyReport, DocumentVerifyError> {
    if bytes.starts_with(b"%PDF") {
        return Err(DocumentVerifyError::Unsupported(
            "PDF verification is not implemented; verify signed PDFs in their reader application"
                .to_owned(),
        ));
    }
    let entries = read_zip(bytes)?;
    let manifest = entries
        .iter()
        .find(|entry| entry.name == MANIFEST_ENTRY)
        .map(|entry| entry.data.clone());
    let Some(manifest) = manifest else {
        if entries.iter().any(|entry| entry.name == MANIFEST_ENTRY_ODF) {
            return Err(DocumentVerifyError::Unsupported(
                "XAdES verification is not implemented; this container needs its native application"
                    .to_owned(),
            ));
        }
        return Err(DocumentVerifyError::Manifest(
            "no ASiCManifest.xml in META-INF".to_owned(),
        ));
    };
    let refs = parse_manifest(&manifest)?;
    let mut files = check_digests(&entries, &refs);
    flag_uncovered_files(&entries, &refs, &mut files);
    let signatures = verify_signatures(&entries, &manifest)?;
    let ok = files.iter().all(|file| file.digest_ok)
        && signatures.iter().all(|signature| signature.valid);
    Ok(DocumentVerifyReport {
        container,
        files,
        signatures,
        ok,
    })
}

/// Where the manifest lives, in the `CAdES` flavour.
const MANIFEST_ENTRY: &str = "META-INF/ASiCManifest.xml";

/// Where the manifest lives, in the `XAdES` flavour (unsupported).
const MANIFEST_ENTRY_ODF: &str = "META-INF/manifest.xml";

/// One ZIP entry: name plus decompressed bytes.
struct ZipEntry {
    name: String,
    data: Vec<u8>,
}

/// Local file header signature (`PK\x03\x04`).
const ZIP_LOCAL_SIG: u32 = 0x0403_4B50;

/// Central directory file header signature: entries end here.
const ZIP_CENTRAL_SIG: u32 = 0x0201_4B50;

/// End of central directory signature: entries end here too.
const ZIP_EOD_SIG: u32 = 0x0605_4B50;

/// General-purpose bit 0: encryption, outside the `ASiC` profile.
const ZIP_FLAG_ENCRYPTED: u16 = 0x0001;

/// General-purpose bit 3: data descriptor; sizes are unknown up
/// front, so a streaming writer's shape. Outside the profile.
const ZIP_FLAG_DESCRIPTOR: u16 = 0x0008;

/// Compression method 0: stored.
const ZIP_METHOD_STORED: u16 = 0;

/// Compression method 8: deflated.
const ZIP_METHOD_DEFLATED: u16 = 8;

/// Most entries any container may carry.
const MAX_ENTRIES: usize = 4096;

/// Most decompressed bytes in total: decompression-bomb ceiling.
const MAX_TOTAL_BYTES: usize = 512 << 20;

/// Most decompressed bytes in one entry.
const MAX_ENTRY_BYTES: usize = 512 << 20;

/// Read the local-file-header sequence: names plus bytes.
///
/// The central directory is not consulted; the local headers carry
/// everything a verifier needs, and a second source of names would
/// only be a second source of disagreement.
fn read_zip(bytes: &[u8]) -> Result<Vec<ZipEntry>, DocumentVerifyError> {
    let mut cursor = Cursor::new(bytes);
    let mut entries = Vec::new();
    let mut total = 0_usize;
    while let Some(sig) = cursor.u32() {
        if sig == ZIP_CENTRAL_SIG || sig == ZIP_EOD_SIG {
            break;
        }
        if sig != ZIP_LOCAL_SIG {
            // No entries yet means the file never was a ZIP; a bad
            // signature mid-walk means the ZIP is corrupt.
            if entries.is_empty() {
                return Err(DocumentVerifyError::NotAContainer);
            }
            return Err(DocumentVerifyError::Zip(
                "entry does not start with a local file header".to_owned(),
            ));
        }
        let Some(header) = LocalHeader::read(&mut cursor) else {
            return Err(DocumentVerifyError::Zip(
                "truncated local header".to_owned(),
            ));
        };
        if header.flags & ZIP_FLAG_ENCRYPTED != 0 {
            return Err(DocumentVerifyError::Zip(
                "encrypted entries are not supported".to_owned(),
            ));
        }
        if header.flags & ZIP_FLAG_DESCRIPTOR != 0 {
            return Err(DocumentVerifyError::Zip(
                "data descriptors are not supported".to_owned(),
            ));
        }
        let Some(name_bytes) = cursor.take(header.name_len) else {
            return Err(DocumentVerifyError::Zip("truncated entry name".to_owned()));
        };
        let Some(_) = cursor.take(header.extra_len) else {
            return Err(DocumentVerifyError::Zip("truncated extra field".to_owned()));
        };
        let Some(stored) = cursor.take(header.compressed_len) else {
            return Err(DocumentVerifyError::Zip("truncated entry data".to_owned()));
        };
        let data = match header.method {
            ZIP_METHOD_STORED => stored.to_vec(),
            ZIP_METHOD_DEFLATED => {
                miniz_oxide::inflate::decompress_to_vec_with_limit(stored, MAX_ENTRY_BYTES)
                    .map_err(|error| {
                        DocumentVerifyError::Zip(format!("deflate error: {error:?}"))
                    })?
            }
            method => {
                return Err(DocumentVerifyError::Zip(format!(
                    "unsupported compression method {method}"
                )));
            }
        };
        if data.len() != header.uncompressed_len {
            return Err(DocumentVerifyError::Zip(
                "entry size does not match its header".to_owned(),
            ));
        }
        total = total.saturating_add(data.len());
        if total > MAX_TOTAL_BYTES {
            return Err(DocumentVerifyError::Zip(
                "container exceeds the decompressed-size ceiling".to_owned(),
            ));
        }
        entries.push(ZipEntry {
            name: String::from_utf8_lossy(name_bytes).into_owned(),
            data,
        });
        if entries.len() > MAX_ENTRIES {
            return Err(DocumentVerifyError::Zip("too many entries".to_owned()));
        }
    }
    if entries.is_empty() {
        return Err(DocumentVerifyError::NotAContainer);
    }
    Ok(entries)
}

/// Byte cursor that fails closed instead of slicing.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        let pair: [u8; 2] = bytes.try_into().ok()?;
        Some(u16::from_le_bytes(pair))
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        let quad: [u8; 4] = bytes.try_into().ok()?;
        Some(u32::from_le_bytes(quad))
    }
}

/// Local file header fields a verifier needs.
struct LocalHeader {
    flags: u16,
    method: u16,
    compressed_len: usize,
    uncompressed_len: usize,
    name_len: usize,
    extra_len: usize,
}

impl LocalHeader {
    /// Read one header past the already-consumed signature. Times
    /// and CRC are skipped: the manifest digests are the integrity
    /// check, and CRC is error detection, not evidence.
    fn read(cursor: &mut Cursor<'_>) -> Option<Self> {
        let _version = cursor.u16()?;
        let flags = cursor.u16()?;
        let method = cursor.u16()?;
        let _mod_time = cursor.u16()?;
        let _mod_date = cursor.u16()?;
        let _crc = cursor.u32()?;
        let compressed = cursor.u32()?;
        let uncompressed = cursor.u32()?;
        let name_len = cursor.u16()?;
        let extra_len = cursor.u16()?;
        Some(Self {
            flags,
            method,
            compressed_len: usize::try_from(compressed).unwrap_or(usize::MAX),
            uncompressed_len: usize::try_from(uncompressed).unwrap_or(usize::MAX),
            name_len: usize::from(name_len),
            extra_len: usize::from(extra_len),
        })
    }
}

/// One manifest-covered file: where it lives and what it must hash to.
struct ManifestRef {
    /// Entry name after XML-unescape plus percent-decoding.
    uri: String,
    /// Entry name exactly as written, for writers that encode neither.
    raw_uri: String,
    /// Digest algorithm the manifest names.
    algorithm: DigestAlgorithm,
    /// Short label for the report.
    label: String,
    /// Expected digest bytes.
    expected: Vec<u8>,
}

/// Parse the `ASiCManifest.xml` references with a liberal tag scan.
///
/// The scan understands tags, prefixes, and both quote styles, and
/// nothing else: comments and processing instructions between
/// elements are skipped as not-tags, which is all a verifier needs
/// from them.
fn parse_manifest(xml: &[u8]) -> Result<Vec<ManifestRef>, DocumentVerifyError> {
    let text = std::str::from_utf8(xml)
        .map_err(|_| DocumentVerifyError::Manifest("manifest is not UTF-8".to_owned()))?;
    let mut refs = Vec::new();
    let mut pos = 0_usize;
    while let Some((tag, after)) = next_tag(text, pos) {
        pos = after;
        if tag.closing || local_name(tag.name) != "DataObjectReference" {
            continue;
        }
        let raw_uri = attr_value(tag.attrs, "URI")
            .ok_or_else(|| DocumentVerifyError::Manifest("reference without URI".to_owned()))?;
        let mut algorithm = None;
        let mut value = None;
        while let Some((inner, inner_after)) = next_tag(text, pos) {
            pos = inner_after;
            let local = local_name(inner.name);
            if inner.closing && local == "DataObjectReference" {
                break;
            }
            if !inner.closing && local == "DigestMethod" {
                algorithm = attr_value(inner.attrs, "Algorithm");
            }
            if !inner.closing && local == "DigestValue" {
                let content = text
                    .get(pos..)
                    .and_then(|rest| rest.find('<').and_then(|end| rest.get(..end)))
                    .ok_or_else(|| {
                        DocumentVerifyError::Manifest("unterminated DigestValue".to_owned())
                    })?;
                value = Some(content.trim().to_owned());
            }
        }
        let algorithm_uri = algorithm.ok_or_else(|| {
            DocumentVerifyError::Manifest("reference without DigestMethod".to_owned())
        })?;
        let (algorithm, label) = digest_by_uri(&algorithm_uri)?;
        let encoded = value.ok_or_else(|| {
            DocumentVerifyError::Manifest("reference without DigestValue".to_owned())
        })?;
        let expected = base64::decode(&encoded)
            .map_err(|why| DocumentVerifyError::Manifest(format!("bad DigestValue: {why}")))?;
        refs.push(ManifestRef {
            uri: decode_uri(&raw_uri),
            raw_uri,
            algorithm,
            label,
            expected,
        });
    }
    if refs.is_empty() {
        return Err(DocumentVerifyError::Manifest(
            "no DataObjectReference entries".to_owned(),
        ));
    }
    Ok(refs)
}

/// One `<...>` tag: name, attribute text, and whether it closes.
struct Tag<'a> {
    name: &'a str,
    attrs: &'a str,
    closing: bool,
}

/// Next tag at or after `from`: returns the tag plus the offset
/// just past its closing `>`. Comments, processing instructions,
/// and declarations are skipped as not-tags.
fn next_tag(text: &str, from: usize) -> Option<(Tag<'_>, usize)> {
    let mut pos = from;
    loop {
        let rest = text.get(pos..)?;
        let open = rest.find('<')?;
        pos += open;
        let after_open = text.get(pos + 1..)?;
        // Skip comments, PIs, and declarations: none of them is an
        // element a verifier reads.
        if let Some(stripped) = after_open.strip_prefix("!--") {
            let end = stripped.find("-->")?;
            pos += 4 + end + 3;
            continue;
        }
        if after_open.starts_with('?') {
            let end = after_open.find("?>")?;
            pos += 1 + end + 2;
            continue;
        }
        if after_open.starts_with('!') {
            let end = after_open.find('>')?;
            pos += 1 + end + 1;
            continue;
        }
        let end = after_open.find('>')?;
        let body = text.get(pos + 1..pos + 1 + end)?;
        let after = pos + 1 + end + 1;
        let (closing, body) = body
            .strip_prefix('/')
            .map_or((false, body), |rest| (true, rest));
        let body = body.strip_suffix('/').unwrap_or(body);
        let split = body.find(char::is_whitespace).unwrap_or(body.len());
        let (name, attrs) = body.split_at(split);
        if name.is_empty() {
            return None;
        }
        return Some((
            Tag {
                name,
                attrs,
                closing,
            },
            after,
        ));
    }
}

/// Tag name without its namespace prefix.
fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// Value of attribute `wanted` (either quote style), or `None`.
/// Only `name="value"` with no space around the `=` is accepted;
/// the writer never emits anything else, and foreign writers that
/// do are rare enough to fail closed on.
fn attr_value(attrs: &str, wanted: &str) -> Option<String> {
    for form in [format!("{wanted}=\""), format!("{wanted}='")] {
        if let Some(start) = attrs.find(&form) {
            let quote = form.as_bytes().last().copied().unwrap_or(b'"');
            let rest = attrs.get(start + form.len()..)?;
            let end = rest.find(char::from(quote))?;
            return rest.get(..end).map(str::to_owned);
        }
    }
    None
}

/// Map a digest-method URI onto the crate's algorithms.
fn digest_by_uri(uri: &str) -> Result<(DigestAlgorithm, String), DocumentVerifyError> {
    // Canonical xmldsig URIs, plus the xmlenc-namespace SHA-384 some
    // writers emit (same hash, wrong namespace).
    if uri == "http://www.w3.org/2001/04/xmlenc#sha256" {
        Ok((DigestAlgorithm::Sha256, "SHA-256".to_owned()))
    } else if uri == "http://www.w3.org/2001/04/xmldsig-more#sha384"
        || uri == "http://www.w3.org/2001/04/xmlenc#sha384"
    {
        Ok((DigestAlgorithm::Sha384, "SHA-384".to_owned()))
    } else {
        Err(DocumentVerifyError::Manifest(format!(
            "unsupported digest {uri}"
        )))
    }
}

/// XML-unescape plus percent-decode a manifest URI, liberally:
/// malformed escapes stay literal and fail closed at lookup.
fn decode_uri(raw: &str) -> String {
    let unescaped = raw
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    let bytes = unescaped.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0_usize;
    while let Some(byte) = bytes.get(index) {
        if *byte == b'%' {
            let hex = bytes.get(index + 1..index + 3);
            if let Some(hex) = hex
                && let Ok(text) = std::str::from_utf8(hex)
                && let Ok(value) = u8::from_str_radix(text, 16)
            {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(*byte);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Recompute every manifest digest against the container entries.
fn check_digests(entries: &[ZipEntry], refs: &[ManifestRef]) -> Vec<VerifiedFile> {
    refs.iter()
        .map(|reference| {
            entries
                .iter()
                .find(|entry| entry.name == reference.uri)
                .or_else(|| entries.iter().find(|entry| entry.name == reference.raw_uri))
                .map_or_else(
                    || VerifiedFile {
                        name: reference.uri.clone(),
                        algorithm: reference.label.clone(),
                        digest_ok: false,
                        detail: "missing from container".to_owned(),
                    },
                    |entry| {
                        let actual = reference.algorithm.digest(&entry.data);
                        if actual == reference.expected {
                            VerifiedFile {
                                name: reference.uri.clone(),
                                algorithm: reference.label.clone(),
                                digest_ok: true,
                                detail: String::new(),
                            }
                        } else {
                            VerifiedFile {
                                name: reference.uri.clone(),
                                algorithm: reference.label.clone(),
                                digest_ok: false,
                                detail: "digest mismatch".to_owned(),
                            }
                        }
                    },
                )
        })
        .collect()
}

/// Data files the manifest does not cover fail closed: an
/// unreferenced file rides along unattested, which defeats the
/// point of the container. `mimetype` and `META-INF/*` are
/// container furniture, not data.
fn flag_uncovered_files(entries: &[ZipEntry], refs: &[ManifestRef], files: &mut Vec<VerifiedFile>) {
    for entry in entries {
        if entry.name == "mimetype" || entry.name.starts_with("META-INF/") {
            continue;
        }
        let covered = refs
            .iter()
            .any(|reference| reference.uri == entry.name || reference.raw_uri == entry.name);
        if !covered {
            files.push(VerifiedFile {
                name: entry.name.clone(),
                algorithm: "—".to_owned(),
                digest_ok: false,
                detail: "not covered by manifest".to_owned(),
            });
        }
    }
}

/// Verify every `CAdES` signature entry against the manifest bytes.
#[allow(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "ZIP entry names are byte-exact, not filesystem paths: a case-insensitive match would accept entries the manifest does not name"
)]
fn verify_signatures(
    entries: &[ZipEntry],
    manifest: &[u8],
) -> Result<Vec<VerifiedSignature>, DocumentVerifyError> {
    let signatures: Vec<&ZipEntry> = entries
        .iter()
        .filter(|entry| {
            entry.name.starts_with("META-INF/")
                && (entry.name.ends_with(".p7s") || entry.name.ends_with(".p7m"))
        })
        .collect();
    if signatures.is_empty() {
        return Err(DocumentVerifyError::NoSignatures);
    }
    signatures
        .iter()
        .map(|entry| verify_signature(&entry.data, manifest))
        .collect()
}

/// Verify one detached `CAdES` over the manifest bytes.
///
/// The manifest is supplied as the external content: the parsed
/// structure's empty `eContent` is replaced before verification,
/// which is exactly what "detached" means.
fn verify_signature<'a>(
    p7: &'a [u8],
    manifest: &'a [u8],
) -> Result<VerifiedSignature, DocumentVerifyError> {
    let mut signed = SignedData::parse(p7)
        .map_err(|error| DocumentVerifyError::Cms(format!("signature does not parse: {error}")))?;
    if signed.econtent_type_oid != known::DATA {
        return Err(DocumentVerifyError::Cms(
            "signature eContentType is not id-data".to_owned(),
        ));
    }
    signed.econtent_der = manifest;
    let mut matched: Option<(refineid_lib_core::x509::OwnedCert, Option<String>)> = None;
    for candidate in &signed.certificates_der {
        let owned = refineid_lib_core::x509::OwnedCert::from_der(candidate).map_err(|error| {
            DocumentVerifyError::Cms(format!("embedded certificate does not parse: {error:?}"))
        })?;
        let binds = {
            let view = owned.view();
            certificate_matches_sid(&view, signed.signer.signer_identifier)
        };
        if binds {
            let cn = owned
                .view()
                .subject
                .common_name()
                .map(|cn| cn.as_str().to_owned());
            matched = Some((owned, cn));
            break;
        }
    }
    let Some((owned, cn)) = matched else {
        return Err(DocumentVerifyError::Cms(
            "signer certificate is not embedded".to_owned(),
        ));
    };
    let view = owned.view();
    match signed.verify(view.spki.as_der()) {
        Ok(()) => Ok(VerifiedSignature {
            signer_cn: cn,
            valid: true,
            detail: String::new(),
        }),
        Err(error) => Ok(VerifiedSignature {
            signer_cn: cn,
            valid: false,
            detail: error.to_string(),
        }),
    }
}

/// Whether `certificate` is the one `sid` names: issuer plus
/// serial, or subject key identifier.
fn certificate_matches_sid(
    certificate: &refineid_lib_core::x509::Certificate<'_>,
    sid: SignerIdentifier<'_>,
) -> bool {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber {
            issuer_der,
            serial_number,
        } => certificate.issuer.as_der() == issuer_der && certificate.serial_der == serial_number,
        SignerIdentifier::SubjectKeyIdentifier(wanted) => {
            certificate.extensions.and_then(subject_key_id).as_deref() == Some(wanted)
        }
    }
}

/// Subject key identifier extension value, when present and
/// well-formed: `extnValue` is an `OCTET STRING` wrapping the key
/// identifier `OCTET STRING`.
fn subject_key_id(extensions: &[u8]) -> Option<Vec<u8>> {
    for extension in BerTlvIter::new(extensions) {
        let extension = extension.ok()?.expect::<Sequence>().ok()?;
        let mut fields = extension.iter_children();
        let oid = fields.next()?.ok()?.expect::<BerOid>().ok()?;
        let oid = Oid::new(oid.value).ok()?;
        if oid != oids::SUBJECT_KEY_IDENTIFIER {
            continue;
        }
        let next = fields.next()?.ok()?;
        let value = if next.tag == <Boolean as BerTag>::TAG {
            fields.next()?.ok()?.expect::<OctetString>().ok()?
        } else {
            next.expect::<OctetString>().ok()?
        };
        let inner = BerTlv::<OctetString>::parse(value.value).ok()?;
        if inner.size != value.value.len() {
            continue;
        }
        return Some(inner.value.to_vec());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asic::{DataObject, plan, xades_container};
    use std::process::Command;

    fn objects() -> Vec<DataObject> {
        vec![
            DataObject {
                name: "hello.txt".to_owned(),
                mime_type: "text/plain".to_owned(),
                content: b"hello RefineID".to_vec(),
            },
            DataObject {
                name: "data.bin".to_owned(),
                mime_type: "application/octet-stream".to_owned(),
                content: vec![0, 1, 2, 3, 4, 5, 6, 7],
            },
        ]
    }

    #[test]
    fn writer_output_parses_back() {
        let container = plan(objects(), DigestAlgorithm::Sha256)
            .finish(b"dummy-signature")
            .expect("finish");
        let entries = read_zip(&container).expect("parse");
        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "mimetype",
                "hello.txt",
                "data.bin",
                MANIFEST_ENTRY,
                "META-INF/signature.p7s",
            ]
        );
        let hello = entries
            .iter()
            .find(|entry| entry.name == "hello.txt")
            .expect("hello");
        assert_eq!(hello.data, b"hello RefineID");
    }

    #[test]
    fn writer_manifest_parses_to_covering_refs() {
        let manifest = plan(objects(), DigestAlgorithm::Sha256).manifest().to_vec();
        let refs = parse_manifest(&manifest).expect("parse");
        assert_eq!(refs.len(), 2);
        let first = refs.first().expect("first ref");
        assert_eq!(first.uri, "hello.txt");
        assert_eq!(first.label, "SHA-256");
        assert_eq!(
            first.expected,
            DigestAlgorithm::Sha256.digest(b"hello RefineID")
        );
        assert_eq!(refs.get(1).expect("second ref").uri, "data.bin");
    }

    #[test]
    fn writer_round_trip_digests_check() {
        let container = plan(objects(), DigestAlgorithm::Sha384)
            .finish(b"dummy-signature")
            .expect("finish");
        let entries = read_zip(&container).expect("parse");
        let manifest = entries
            .iter()
            .find(|entry| entry.name == MANIFEST_ENTRY)
            .expect("manifest");
        let refs = parse_manifest(&manifest.data).expect("refs");
        let files = check_digests(&entries, &refs);
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|file| file.digest_ok));
        assert_eq!(files.first().expect("first file").algorithm, "SHA-384");
    }

    #[test]
    fn tampered_file_fails_its_digest() {
        let container = plan(objects(), DigestAlgorithm::Sha256)
            .finish(b"dummy-signature")
            .expect("finish");
        let mut entries = read_zip(&container).expect("parse");
        let manifest = entries
            .iter()
            .find(|entry| entry.name == MANIFEST_ENTRY)
            .expect("manifest")
            .data
            .clone();
        let refs = parse_manifest(&manifest).expect("refs");
        let hello = entries
            .iter_mut()
            .find(|entry| entry.name == "hello.txt")
            .expect("hello");
        if let Some(first) = hello.data.first_mut() {
            *first ^= 0xFF;
        }
        let files = check_digests(&entries, &refs);
        let hello = files
            .iter()
            .find(|file| file.name == "hello.txt")
            .expect("hello verdict");
        assert!(!hello.digest_ok);
        assert_eq!(hello.detail, "digest mismatch");
    }

    #[test]
    fn uncovered_file_fails_closed() {
        let container = plan(objects(), DigestAlgorithm::Sha256)
            .finish(b"dummy-signature")
            .expect("finish");
        let mut entries = read_zip(&container).expect("parse");
        entries.push(ZipEntry {
            name: "smuggled.txt".to_owned(),
            data: b"rides along".to_vec(),
        });
        let manifest = entries
            .iter()
            .find(|entry| entry.name == MANIFEST_ENTRY)
            .expect("manifest")
            .data
            .clone();
        let refs = parse_manifest(&manifest).expect("refs");
        let mut files = check_digests(&entries, &refs);
        flag_uncovered_files(&entries, &refs, &mut files);
        let smuggled = files
            .iter()
            .find(|file| file.name == "smuggled.txt")
            .expect("smuggled verdict");
        assert!(!smuggled.digest_ok);
        assert_eq!(smuggled.detail, "not covered by manifest");
    }

    #[test]
    fn non_containers_are_named() {
        assert!(matches!(
            verify_bytes(
                b"not a container at all, far too short?",
                "x.asice".to_owned()
            ),
            Err(DocumentVerifyError::NotAContainer)
        ));
        assert!(matches!(
            verify_bytes(b"%PDF-1.7 fake", "x.pdf".to_owned()),
            Err(DocumentVerifyError::Unsupported(_))
        ));
        let xades = xades_container(&objects(), b"<xml/>").expect("xades");
        assert!(matches!(
            verify_bytes(&xades, "x.bdoc".to_owned()),
            Err(DocumentVerifyError::Unsupported(_))
        ));
    }

    #[test]
    fn empty_manifest_is_an_error() {
        let container = plan(Vec::new(), DigestAlgorithm::Sha256)
            .finish(b"dummy-signature")
            .expect("finish");
        assert!(matches!(
            verify_bytes(&container, "empty.asice".to_owned()),
            Err(DocumentVerifyError::Manifest(_))
        ));
    }

    /// Shell out, the way the `cades` interop tests do: the goal is a
    /// real RSA signature over a real manifest, which needs a real key.
    fn run(program: &str, args: &[&str]) -> Vec<u8> {
        let output = Command::new(program)
            .args(args)
            .output()
            .expect("openssl runs");
        assert!(output.status.success(), "{program} {args:?} failed");
        output.stdout
    }

    /// Throwaway RSA key plus self-signed certificate minted by
    /// the `openssl` binary. Returns the key path, the cert DER,
    /// and the scratch dir the caller removes.
    fn openssl_key_and_cert() -> (PathBuf, Vec<u8>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("refineid-asic-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let key = dir.join("key.pem");
        let cert = dir.join("cert.der");
        run(
            "openssl",
            &["genrsa", "-out", key.to_str().expect("key path"), "2048"],
        );
        run(
            "openssl",
            &[
                "req",
                "-new",
                "-x509",
                "-key",
                key.to_str().expect("key path"),
                "-outform",
                "DER",
                "-out",
                cert.to_str().expect("cert path"),
                "-days",
                "2",
                "-subj",
                "/CN=RefineID ASiC interop",
            ],
        );
        let cert_der = std::fs::read(&cert).expect("cert der");
        (key, cert_der, dir)
    }

    /// End to end: `openssl` signs a manifest the writer built, the
    /// container verifies, and a flipped digest bit flips the verdict.
    /// Ignored by default: needs the `openssl` binary, like the
    /// `cades` interop tests it mirrors.
    #[test]
    #[ignore = "requires the openssl binary"]
    fn openssl_signed_container_verifies() {
        use crate::cades::{
            Encapsulation, SignatureAlgorithm, SignerParameters, SigningTime, signed_attributes,
            signed_data,
        };
        use crate::test_support::parse_certificate_for_test;
        use crate::validation::ValidationMaterial;

        let (key, cert_der, dir) = openssl_key_and_cert();
        let certificate = parse_certificate_for_test(&cert_der);
        let manifest = plan(objects(), DigestAlgorithm::Sha256).manifest().to_vec();
        let parameters = SignerParameters {
            certificate: &certificate,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_time: Some(SigningTime {
                year: 2026,
                month: 1,
                day: 2,
                hour: 3,
                minute: 4,
                second: 5,
            }),
        };
        let content_digest = DigestAlgorithm::Sha256.digest(&manifest);
        let attributes = signed_attributes(&parameters, &content_digest);
        let tbs_path = dir.join("tbs.der");
        std::fs::write(&tbs_path, attributes.as_bytes()).expect("tbs");
        let sig_path = dir.join("sig.bin");
        run(
            "openssl",
            &[
                "dgst",
                "-sha256",
                "-sign",
                key.to_str().expect("key path"),
                "-out",
                sig_path.to_str().expect("sig path"),
                tbs_path.to_str().expect("tbs path"),
            ],
        );
        let signature = std::fs::read(&sig_path).expect("sig");
        let p7 = signed_data(
            &parameters,
            &attributes,
            &signature,
            Encapsulation::Detached,
            &manifest,
            &ValidationMaterial::default(),
            &[],
        );
        let container = plan(objects(), DigestAlgorithm::Sha256)
            .finish(&p7)
            .expect("finish");
        let report =
            verify_bytes(&container, "interop.asice".to_owned()).expect("container verifies");
        assert!(report.ok, "report:\n{}", report.render());
        assert_eq!(report.files.len(), 2);
        assert_eq!(report.signatures.len(), 1);
        assert_eq!(
            report
                .signatures
                .first()
                .expect("one signature")
                .signer_cn
                .as_deref(),
            Some("RefineID ASiC interop")
        );
        assert!(report.render().contains("Result: VALID"));

        // Flip one manifest digest bit: same structure, failed verdict.
        let mut tampered = manifest.clone();
        tamper_first_digest(&mut tampered);
        let mut tampered_container = plan(objects(), DigestAlgorithm::Sha256)
            .finish(&p7)
            .expect("finish");
        let at = tampered_container
            .windows(manifest.len())
            .position(|window| window == manifest.as_slice())
            .expect("manifest inside");
        tampered_container.splice(at..at + manifest.len(), tampered.iter().copied());
        let report = verify_bytes(&tampered_container, "tampered.asice".to_owned())
            .expect("tamper still parses");
        assert!(!report.ok);
        assert!(report.files.iter().any(|file| !file.digest_ok));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Flip the first digest character to a different valid base64
    /// character, so the manifest stays well-formed but names a
    /// digest no file has.
    fn tamper_first_digest(manifest: &mut [u8]) {
        let marker = b"DigestValue>";
        let start = manifest
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("DigestValue present")
            + marker.len();
        let byte = manifest.get_mut(start).expect("digest char");
        *byte = if *byte == b'A' { b'B' } else { b'A' };
    }
}
