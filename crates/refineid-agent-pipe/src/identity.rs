//! Who is at the other end of the pipe (Windows STPA W-R-3, W-R-4).
//!
//! The token user, the logon session and the image of a process are read
//! from Windows, not from anything the process says about itself.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::PipeError;

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
    /// The logon session it runs in.
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

    /// Whether `other` runs as the same user in the same logon session.
    #[must_use]
    pub fn same_user_and_session(&self, other: &Self) -> bool {
        self.user == other.user && self.session == other.session
    }
}

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
    if sid.is_null() {
        return Err(PipeError::Identity(0));
    }
    // SAFETY: `sid` points at a valid SID inside the buffer.
    let length = unsafe { GetLengthSid(sid) } as usize;
    let start = sid.cast::<u8>().cast_const();
    let buffer_start = buffer.as_ptr().cast::<u8>();
    let offset = (start as usize).wrapping_sub(buffer_start as usize);
    if offset
        .checked_add(length)
        .is_none_or(|end| end > TOKEN_USER_BYTES)
    {
        return Err(PipeError::Identity(0));
    }
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
