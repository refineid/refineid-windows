//! Who is at the other end of the pipe (Windows STPA W-R-3, W-R-4).
//!
//! The token user, the Windows session and the image of a process are read
//! from Windows, not from anything the process says about itself.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree, S_OK};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX64, FOLDERID_ProgramFilesX86, KF_FLAG_DEFAULT,
    SHGetKnownFolderPath,
};

use crate::{AGENT_IMAGE_NAME, PRODUCT_DIRECTORY_NAME, PipeError};

/// The longest image path read, in UTF-16 units.
const IMAGE_PATH_UNITS: usize = 32_768;
/// The longest `TOKEN_USER` read, in bytes: the structure and a SID of the
/// maximum size.
const TOKEN_USER_BYTES: usize = 128;

/// A user's security identifier as Windows stores it.
///
/// Built only from a process token, so a value names a real account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSid(Vec<u8>);

impl UserSid {
    /// The SID in its string form, `S-1-5-21-...`.
    ///
    /// # Errors
    /// [`PipeError::Identity`] when Windows cannot format it.
    pub fn to_sddl(&self) -> Result<String, PipeError> {
        let mut text: *mut u16 = core::ptr::null_mut();
        // SAFETY: the bytes are a SID copied from a token, and `text`
        // receives a LocalAlloc string this function frees.
        if unsafe { ConvertSidToStringSidW(self.0.as_ptr().cast_mut().cast(), &raw mut text) } == 0
            || text.is_null()
        {
            return Err(PipeError::last(PipeError::Identity));
        }
        // SAFETY: `text` is a NUL-terminated wide string Windows allocated.
        let units = unsafe {
            let mut length = 0;
            while *text.add(length) != 0 {
                length += 1;
            }
            core::slice::from_raw_parts(text, length)
        };
        let formatted = String::from_utf16_lossy(units);
        // SAFETY: `text` came from ConvertSidToStringSidW and is freed once.
        unsafe { LocalFree(text.cast()) };
        Ok(formatted)
    }
}

/// What Windows says about one process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// The user its token runs as.
    pub user: UserSid,
    /// The Windows session it runs in.
    pub session: u32,
    /// The path of its image.
    pub image: PathBuf,
}

impl ProcessIdentity {
    /// The identity of the process `pid`.
    ///
    /// # Errors
    /// [`PipeError::Identity`] when the process cannot be opened or read.
    pub fn of(pid: u32) -> Result<Self, PipeError> {
        // SAFETY: plain query-rights open of a process id; the handle is
        // closed by the guard.
        let process = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
        if process.0.is_null() {
            return Err(PipeError::last(PipeError::Identity));
        }
        let mut token = Handle(core::ptr::null_mut());
        // SAFETY: `process` is open with query rights; the token handle is
        // closed by its guard.
        if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &raw mut token.0) } == 0 {
            return Err(PipeError::last(PipeError::Identity));
        }
        Ok(Self {
            user: token_user(&token)?,
            session: session_of(pid)?,
            image: image_of(&process)?,
        })
    }

    /// The identity of this process.
    ///
    /// # Errors
    /// [`PipeError::Identity`] when Windows cannot report it.
    pub fn current() -> Result<Self, PipeError> {
        // SAFETY: no arguments; always succeeds.
        Self::of(unsafe { GetCurrentProcessId() })
    }

    /// Whether `other` runs as the same user in the same Windows session.
    #[must_use]
    pub fn same_user_and_session(&self, other: &Self) -> bool {
        self.user == other.user && self.session == other.session
    }
}

/// Where the installer put the agent.
///
/// `RefineID\\refineid-agent.exe` under this architecture's Program Files,
/// which only administrators can write to. Windows reports that directory,
/// so nothing in this process's environment can move it. `None` when Windows
/// cannot report it.
#[must_use]
pub fn installed_agent_image() -> Option<PathBuf> {
    Some(
        known_folder(&FOLDERID_ProgramFiles)?
            .join(PRODUCT_DIRECTORY_NAME)
            .join(AGENT_IMAGE_NAME),
    )
}

/// The Program Files directories Windows reports, as text.
#[must_use]
pub fn program_directories() -> Vec<String> {
    [
        FOLDERID_ProgramFiles,
        FOLDERID_ProgramFilesX64,
        FOLDERID_ProgramFilesX86,
    ]
    .iter()
    .filter_map(known_folder)
    .map(|directory| directory.to_string_lossy().into_owned())
    .collect()
}

/// The known folder `id` as Windows reports it, independent of this
/// process's environment. `None` when Windows cannot report it.
fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    let mut path: windows_sys::core::PWSTR = core::ptr::null_mut();
    // SAFETY: `id` is a live GUID; `path` receives a CoTaskMem string this
    // function frees, also on failure as the API documents.
    let status = unsafe {
        SHGetKnownFolderPath(
            id,
            KF_FLAG_DEFAULT.cast_unsigned(),
            core::ptr::null_mut(),
            &raw mut path,
        )
    };
    let directory = (status == S_OK && !path.is_null()).then(|| {
        // SAFETY: on success `path` is a NUL-terminated wide string.
        let units = unsafe {
            let mut length = 0;
            while *path.add(length) != 0 {
                length += 1;
            }
            core::slice::from_raw_parts(path, length)
        };
        PathBuf::from(OsString::from_wide(units))
    });
    // SAFETY: frees the string once; a null pointer is allowed.
    unsafe { CoTaskMemFree(path.cast_const().cast()) };
    directory
}

/// The size of a SID with no subauthority: revision, count and authority.
const MIN_SID_BYTES: usize = 8;

/// The longest computer name read, in UTF-16 units.
const COMPUTER_NAME_UNITS: usize = 256;

/// This computer's DNS host name, or an empty string when Windows cannot
/// report it.
#[must_use]
pub fn computer_name() -> String {
    let mut name = vec![0u16; COMPUTER_NAME_UNITS];
    let Ok(mut length) = u32::try_from(name.len()) else {
        return String::new();
    };
    // SAFETY: `name` holds `length` units; Windows writes at most that.
    if unsafe { GetComputerNameExW(ComputerNameDnsHostname, name.as_mut_ptr(), &raw mut length) }
        == 0
    {
        return String::new();
    }
    name.truncate(length as usize);
    String::from_utf16_lossy(&name)
}

/// A handle closed when it goes out of scope.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle is owned here and closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn token_user(token: &Handle) -> Result<UserSid, PipeError> {
    // `u64` storage keeps the buffer aligned for `TOKEN_USER`.
    let mut buffer = [0u64; TOKEN_USER_BYTES / 8];
    let mut needed = 0u32;
    let size = u32::try_from(size_of_val(&buffer)).map_err(|_| PipeError::Identity(0))?;
    // SAFETY: the buffer is `size` bytes and aligned for TOKEN_USER.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &raw mut needed,
        )
    } == 0
    {
        return Err(PipeError::last(PipeError::Identity));
    }
    // SAFETY: GetTokenInformation filled a TOKEN_USER at the buffer start.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // The SID must lie after the TOKEN_USER and inside the buffer before
    // anything reads it.
    let first = buffer.as_ptr() as usize + size_of::<TOKEN_USER>();
    let end = buffer.as_ptr() as usize + TOKEN_USER_BYTES;
    let address = sid as usize;
    if sid.is_null() || address < first || address + MIN_SID_BYTES > end {
        return Err(PipeError::Identity(0));
    }
    // SAFETY: at least a SID header lies inside the buffer, as checked.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(PipeError::Identity(0));
    }
    // SAFETY: `sid` is a valid SID whose header is inside the buffer.
    let length = unsafe { GetLengthSid(sid) } as usize;
    if address
        .checked_add(length)
        .is_none_or(|sid_end| sid_end > end)
    {
        return Err(PipeError::Identity(0));
    }
    let start = sid.cast::<u8>().cast_const();
    // SAFETY: the SID lies inside the buffer, as just checked.
    Ok(UserSid(
        unsafe { core::slice::from_raw_parts(start, length) }.to_vec(),
    ))
}

fn session_of(pid: u32) -> Result<u32, PipeError> {
    let mut session = 0u32;
    // SAFETY: `session` receives the session id.
    if unsafe { ProcessIdToSessionId(pid, &raw mut session) } == 0 {
        return Err(PipeError::last(PipeError::Identity));
    }
    Ok(session)
}

fn image_of(process: &Handle) -> Result<PathBuf, PipeError> {
    let mut path = vec![0u16; IMAGE_PATH_UNITS];
    let mut length = u32::try_from(path.len()).map_err(|_| PipeError::Identity(0))?;
    // SAFETY: `path` holds `length` units; Windows writes at most that.
    if unsafe {
        QueryFullProcessImageNameW(
            process.0,
            PROCESS_NAME_WIN32,
            path.as_mut_ptr(),
            &raw mut length,
        )
    } == 0
    {
        return Err(PipeError::last(PipeError::Identity));
    }
    path.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&path)))
}
