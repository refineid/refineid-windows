//! The named pipe between the `RefineID` key storage provider and the
//! per-user agent that holds the phone's Bluetooth session (Windows STPA
//! W-R-1, W-R-3, W-R-4, W-R-15).
//!
//! The provider runs inside whichever program signs, and opens no transport
//! of its own: it sends one [`wire::SignRequest`] per signature on this pipe
//! and reads one [`wire::SignAnswer`]. The agent creates the pipe as the
//! first instance of its name, grants the current user alone, refuses remote
//! clients, and serves a client only when Windows reports it running as the
//! same user in the same Windows session. The provider in turn talks only to a
//! server Windows reports the same way, whose image is the installed agent:
//! a same-user process that creates the pipe first is refused before it
//! receives anything.
//!
//! [`wire`] is the safe message codec and builds on any host. The Windows
//! system calls, and the only `unsafe` code here, are in the
//! Windows-only modules.

#![cfg_attr(
    windows,
    allow(unsafe_code, reason = "the Windows pipe and token boundary")
)]

use std::path::Path;
use std::time::Duration;

use refineid_rapp_core::operations::{CardOperation, KeyProfile, SignatureAlgorithm};

pub mod wire;

#[cfg(windows)]
pub mod client;
#[cfg(windows)]
pub mod identity;
#[cfg(windows)]
pub mod server;

/// The agent's directory under Program Files, as the installer lays it out.
pub const PRODUCT_DIRECTORY_NAME: &str = "RefineID";
/// The agent's file name, as the installer lays it out.
pub const AGENT_IMAGE_NAME: &str = "refineid-agent.exe";

/// Whether `image`, the path Windows reports for a process, is `installed`.
///
/// Paths are compared component by component, ignoring case and accepting
/// `\\` and `/` as separators; a path with a `..` component is neither.
#[must_use]
pub fn is_same_image(image: &Path, installed: &Path) -> bool {
    match (
        path_components(&image.to_string_lossy()),
        path_components(&installed.to_string_lossy()),
    ) {
        (Some(image), Some(installed)) => !installed.is_empty() && image == installed,
        _ => false,
    }
}

/// The pipe name prefix; the user's SID and Windows session complete it,
/// so each user's agent in each session has its own name.
pub const PIPE_NAME_PREFIX: &str = r"\\.\pipe\RefineID.Agent.";

/// The prefix of the mutex only one agent per user and Windows session
/// holds (W-R-15); the user's SID completes it, in the session-local
/// namespace.
pub const AGENT_MUTEX_PREFIX: &str = r"Local\RefineID.Agent.";

/// How long an operation lives on the phone: the holder approves within it
/// (RAPP section 8.2 item 1).
pub const OPERATION_LIFETIME: Duration = Duration::from_secs(300);
/// How long the agent looks for the phone when a signature arrives with no
/// session open.
pub const REACH_WINDOW: Duration = Duration::from_secs(15);
/// What a result takes to cross the Bluetooth link and the pipe after the
/// phone produced it.
pub const TRANSFER_MARGIN: Duration = Duration::from_secs(10);
/// The one remote-signature deadline (W-R-12): the provider waits this long
/// for the agent's answer, which covers finding the phone, the holder's
/// approval and the transfer back.
pub const SIGNATURE_DEADLINE: Duration = Duration::from_secs(
    REACH_WINDOW.as_secs() + OPERATION_LIFETIME.as_secs() + TRANSFER_MARGIN.as_secs(),
);

/// The environment variables that name the Program Files directories,
/// which only administrators can write to on a default Windows install.
pub const PROGRAM_DIRECTORY_VARIABLES: [&str; 3] =
    ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"];

/// The label the operation context carries for a program, or `None` when its
/// image path names no file.
///
/// A product name for the browsers people use when their image lies under
/// a Program Files directory this process's environment names
/// ([`PROGRAM_DIRECTORY_VARIABLES`]), otherwise the image's file name.
/// The context says what asks, not where the request goes, because CNG
/// does not tell a key storage provider the site. Only a process apart from
/// the caller reads this: inside the caller the environment is the caller's,
/// so [`in_process_operation`] trusts no directory.
#[must_use]
pub fn program_label(image: &Path) -> Option<String> {
    let roots: Vec<String> = PROGRAM_DIRECTORY_VARIABLES
        .iter()
        .filter_map(|variable| std::env::var(variable).ok())
        .collect();
    program_label_within(image, &roots)
}

/// The label the operation context carries for a program whose image is
/// `image`, where `trusted_roots` are the directories only administrators can
/// write to, or `None` when `image` names no file.
///
/// A product name for the browsers people use, only when the image lies
/// strictly below one of `trusted_roots`; otherwise the image's file name.
/// Both paths are compared component by component, ignoring case and
/// accepting `\` and `/` as separators; a path with a `..` component is
/// below no root, and an empty root is ignored.
#[must_use]
pub fn program_label_within(image: &Path, trusted_roots: &[String]) -> Option<String> {
    let image = image.to_string_lossy();
    let file = image
        .rsplit(PATH_SEPARATORS)
        .next()
        .map(|name| name.trim().to_owned())
        .unwrap_or_default();
    let known = match file.to_ascii_lowercase().as_str() {
        "msedge.exe" => Some("Microsoft Edge"),
        "chrome.exe" => Some("Google Chrome"),
        "brave.exe" => Some("Brave"),
        "opera.exe" => Some("Opera"),
        "vivaldi.exe" => Some("Vivaldi"),
        _ => None,
    };
    let trusted = trusted_roots.iter().any(|root| lies_below(&image, root));
    match known {
        Some(name) if trusted => Some(name.to_owned()),
        _ if file.is_empty() => None,
        _ => Some(file),
    }
}

/// The separators a Windows path accepts.
const PATH_SEPARATORS: [char; 2] = ['\\', '/'];

/// The case-folded components of `path`, or `None` when one climbs (`..`).
fn path_components(path: &str) -> Option<Vec<String>> {
    path.split(PATH_SEPARATORS)
        .filter(|component| !component.is_empty() && *component != ".")
        .map(|component| (component != "..").then(|| component.to_lowercase()))
        .collect()
}

/// Whether `path` lies strictly below the directory `root`.
fn lies_below(path: &str, root: &str) -> bool {
    let (Some(path), Some(root)) = (path_components(path), path_components(root)) else {
        return false;
    };
    !root.is_empty() && path.len() > root.len() && path.starts_with(&root)
}

/// The asking party as the operation context carries it (W-R-10).
///
/// The program and the computer it runs on. RAPP section 9.2 requires this
/// field and calls it `origin`, but no Requester can know the site, so it never
/// names one, and the phone does not show it (section 11 item 1).
#[must_use]
pub fn requester_context(program: &str, computer: &str) -> String {
    if computer.is_empty() {
        program.to_owned()
    } else {
        format!("{program} on {computer}")
    }
}

/// The key a program inside whose process a provider runs asks to use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteKey {
    /// The authentication key, behind PIN 1.
    Authentication,
    /// The qualified signature key, behind PIN 2.
    QualifiedSignature,
}

/// Why a provider inside the calling program asks the phone for nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteRefusal {
    /// The signature needs a document's name, and a platform signing call
    /// carries only a hash (RAPP section 9.3, section 11 item 1).
    UnnamedDocument,
    /// Windows reported an image path that names no file (W-R-10).
    UnnamedProgram,
}

impl core::fmt::Display for RemoteRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::UnnamedDocument => "the signing call names no document",
            Self::UnnamedProgram => "the calling program has no image name",
        })
    }
}

impl core::error::Error for RemoteRefusal {}

/// The operation a provider running inside the calling program sends for a
/// hash it was handed (W-R-10, W-R-20).
///
/// The context carries the image's file name and the computer. No directory
/// is trusted for a product name, because this process's environment belongs
/// to the program being named.
///
/// # Errors
/// [`RemoteRefusal::UnnamedDocument`] for the qualified key: `document_name`
/// is what the holder consents under and RAPP has no form for a document
/// without one. [`RemoteRefusal::UnnamedProgram`] when `image` names no file.
pub fn in_process_operation(
    key: RemoteKey,
    image: &Path,
    computer: &str,
    key_profile: KeyProfile,
    algorithm: SignatureAlgorithm,
    digest: Vec<u8>,
) -> Result<CardOperation, RemoteRefusal> {
    match key {
        RemoteKey::QualifiedSignature => Err(RemoteRefusal::UnnamedDocument),
        RemoteKey::Authentication => {
            let program = program_label_within(image, &[]).ok_or(RemoteRefusal::UnnamedProgram)?;
            Ok(CardOperation::BrowserAuthenticate {
                origin: requester_context(&program, computer),
                key_profile,
                algorithm,
                digest,
            })
        }
    }
}

/// The pipe name of the user whose SID is `user_sid` in Windows session
/// `session`: one per user and session, as the identity checks require.
#[must_use]
pub fn pipe_name(user_sid: &str, session: u32) -> String {
    format!("{PIPE_NAME_PREFIX}{user_sid}.{session}")
}

/// Why the pipe could not be used. A Windows error carries its code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeError {
    /// Windows could not report a process's identity.
    Identity(u32),
    /// The pipe could not be created, opened or served.
    Pipe(u32),
    /// No agent serves this user.
    NoAgent,
    /// Another agent already serves this user (W-R-15).
    AgentRunning,
    /// The process at the other end runs as another user or in another
    /// session, or, seen from the provider, is not the installed agent.
    Stranger,
    /// The other end did not answer in time.
    TimedOut,
    /// A message was refused at the border.
    Wire(wire::WireError),
}

impl PipeError {
    /// `make` applied to the calling thread's last Windows error.
    #[cfg(windows)]
    pub(crate) fn last(make: fn(u32) -> Self) -> Self {
        // SAFETY: no arguments; reads the thread's last error.
        make(unsafe { windows_sys::Win32::Foundation::GetLastError() })
    }
}

impl core::fmt::Display for PipeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Identity(code) => write!(formatter, "process identity unreadable (error {code})"),
            Self::Pipe(code) => write!(formatter, "agent pipe failed (error {code})"),
            Self::NoAgent => write!(formatter, "the RefineID agent is not running"),
            Self::AgentRunning => write!(formatter, "another RefineID agent serves this user"),
            Self::Stranger => write!(
                formatter,
                "the other end of the pipe runs as another user or session"
            ),
            Self::TimedOut => write!(formatter, "the agent did not answer in time"),
            Self::Wire(error) => write!(formatter, "{error}"),
        }
    }
}

impl core::error::Error for PipeError {}

/// `text` as a NUL-terminated UTF-16 string for a Windows call.
#[cfg(windows)]
pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

impl From<wire::WireError> for PipeError {
    fn from(error: wire::WireError) -> Self {
        Self::Wire(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> Vec<String> {
        vec![
            r"C:\Program Files".to_owned(),
            r"C:\Program Files (x86)".to_owned(),
        ]
    }

    fn label(image: &str) -> String {
        program_label_within(Path::new(image), &roots()).expect("the image names a file")
    }

    const EDGE_IMAGE: &str = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
    const COMPUTER: &str = "EXAMPLE-HOST";
    const DIGEST: &[u8] = b"a digest of thirty-two bytes ...";

    fn in_process(key: RemoteKey, image: &str) -> Result<CardOperation, RemoteRefusal> {
        in_process_operation(
            key,
            Path::new(image),
            COMPUTER,
            KeyProfile::EcdsaP384,
            SignatureAlgorithm::EcdsaSha256,
            DIGEST.to_vec(),
        )
    }

    fn authentication_context(image: &str) -> String {
        match in_process(RemoteKey::Authentication, image) {
            Ok(CardOperation::BrowserAuthenticate { origin, .. }) => origin,
            other => panic!("not an authentication: {other:?}"),
        }
    }

    #[test]
    fn only_the_installed_image_is_the_agent() {
        let installed = Path::new(r"C:\Program Files\RefineID\refineid-agent.exe");
        assert!(is_same_image(installed, installed));
        assert!(is_same_image(
            Path::new(r"c:/program files/REFINEID/Refineid-Agent.EXE"),
            installed
        ));
        for other in [
            r"C:\Users\someone\AppData\Local\Temp\refineid-agent.exe",
            r"C:\Program Files\RefineID\other.exe",
            r"C:\Program Files\RefineID\..\RefineID\refineid-agent.exe",
            r"C:\Program Files\RefineID",
            "refineid-agent.exe",
            "",
        ] {
            assert!(!is_same_image(Path::new(other), installed), "{other}");
        }
        assert!(!is_same_image(Path::new(""), Path::new("")));
    }

    #[test]
    fn an_authentication_names_the_program_and_the_computer_and_no_site() {
        assert_eq!(
            authentication_context(r"C:\Tools\signer.exe"),
            "signer.exe on EXAMPLE-HOST"
        );
    }

    #[test]
    fn inside_the_caller_no_directory_earns_a_product_name() {
        assert_eq!(
            authentication_context(EDGE_IMAGE),
            "msedge.exe on EXAMPLE-HOST"
        );
    }

    #[test]
    fn a_qualified_signature_from_a_signing_call_is_refused() {
        assert_eq!(
            in_process(RemoteKey::QualifiedSignature, EDGE_IMAGE),
            Err(RemoteRefusal::UnnamedDocument)
        );
    }

    #[test]
    fn a_program_with_no_name_is_refused_and_not_described() {
        assert_eq!(
            in_process(RemoteKey::Authentication, ""),
            Err(RemoteRefusal::UnnamedProgram)
        );
    }

    #[test]
    fn the_removed_origin_variables_change_nothing() {
        const VARIABLES: [&str; 2] = ["REFINEID_RP_ORIGIN", "REFINEID_ORIGIN"];
        const THIS_TEST: &str = "tests::the_removed_origin_variables_change_nothing";
        const PLANTED: &str = "https://planted.example";
        if std::env::var_os(VARIABLES[0]).is_some() {
            let context = authentication_context(r"C:\Tools\signer.exe");
            assert_eq!(context, "signer.exe on EXAMPLE-HOST");
            assert_eq!(
                in_process(RemoteKey::QualifiedSignature, EDGE_IMAGE),
                Err(RemoteRefusal::UnnamedDocument)
            );
            return;
        }
        let mut child =
            std::process::Command::new(std::env::current_exe().expect("the test binary's path"));
        child.args(["--exact", THIS_TEST]);
        for variable in VARIABLES {
            child.env(variable, PLANTED);
        }
        assert!(child.status().expect("the test binary runs").success());
    }

    #[test]
    fn a_browser_under_program_files_is_named() {
        assert_eq!(
            label(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
            "Microsoft Edge"
        );
        assert_eq!(
            label(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            "Google Chrome"
        );
    }

    #[test]
    fn a_browser_name_in_a_user_directory_is_its_file_name() {
        assert_eq!(
            label(r"C:\Users\holder\AppData\Local\Temp\msedge.exe"),
            "msedge.exe"
        );
    }

    #[test]
    fn a_look_alike_directory_is_not_program_files() {
        assert_eq!(label(r"C:\Program Files Evil\msedge.exe"), "msedge.exe");
        assert_eq!(label(r"C:\Program Filesx\msedge.exe"), "msedge.exe");
    }

    #[test]
    fn a_climbing_path_is_below_no_root() {
        assert_eq!(
            label(r"C:\Program Files\..\Users\holder\msedge.exe"),
            "msedge.exe"
        );
    }

    #[test]
    fn the_root_itself_is_not_below_it() {
        let roots = vec![r"C:\Program Files\msedge.exe".to_owned()];
        assert_eq!(
            program_label_within(Path::new(r"C:\Program Files\msedge.exe"), &roots).as_deref(),
            Some("msedge.exe")
        );
    }

    #[test]
    fn case_and_separators_do_not_matter() {
        assert_eq!(
            label(r"c:\PROGRAM FILES\Google\Chrome\Application\CHROME.EXE"),
            "Google Chrome"
        );
        assert_eq!(
            label("C:/Program Files/Google/Chrome/Application/chrome.exe"),
            "Google Chrome"
        );
        assert_eq!(
            label(r"C:/Program Files\BraveSoftware/Brave-Browser\Application/brave.exe"),
            "Brave"
        );
        let slashed = vec!["C:/Program Files/".to_owned()];
        assert_eq!(
            program_label_within(
                Path::new(r"C:\Program Files\Vivaldi\Application\vivaldi.exe"),
                &slashed
            )
            .as_deref(),
            Some("Vivaldi")
        );
    }

    #[test]
    fn an_empty_root_trusts_nothing() {
        let roots = vec![String::new()];
        assert_eq!(
            program_label_within(Path::new(r"C:\Opera\opera.exe"), &roots).as_deref(),
            Some("opera.exe")
        );
    }

    #[test]
    fn an_unknown_program_is_its_file_name() {
        assert_eq!(label(r"C:\Program Files\Tool\tool.exe"), "tool.exe");
        assert_eq!(program_label_within(Path::new(""), &roots()), None);
    }
}
