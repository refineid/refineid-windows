//! The name this computer introduces itself by in `pairing.hello`
//! (`display_name`): the host name, as the phone lists computers by name.

/// The display name when Windows reports no host name.
pub const UNNAMED_HOST: &str = "RefineID";

/// The display name this computer sends in `pairing.hello`: its DNS host
/// name, or [`UNNAMED_HOST`] when Windows reports none.
#[must_use]
pub fn local_host_name() -> String {
    dns_host_name().unwrap_or_else(|| UNNAMED_HOST.to_owned())
}

/// This computer's DNS host name as Windows reports it
/// (`ComputerNameDnsHostname`), or `None` when Windows reports none.
#[must_use]
pub fn dns_host_name() -> Option<String> {
    platform::dns_host_name().filter(|name| !name.is_empty())
}

#[cfg(windows)]
mod platform {
    use windows::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
    use windows::core::PWSTR;

    /// The longest host name read, in UTF-16 units.
    const HOST_NAME_UNITS: usize = 256;

    #[allow(
        unsafe_code,
        reason = "GetComputerNameExW writes into a buffer whose length it is given"
    )]
    pub(super) fn dns_host_name() -> Option<String> {
        let mut name = vec![0u16; HOST_NAME_UNITS];
        let mut length = u32::try_from(name.len()).ok()?;
        // SAFETY: `name` holds `length` units; Windows writes at most that
        // and stores the units written, without the terminator, in `length`.
        unsafe {
            GetComputerNameExW(
                ComputerNameDnsHostname,
                Some(PWSTR(name.as_mut_ptr())),
                &raw mut length,
            )
        }
        .ok()?;
        name.truncate(usize::try_from(length).ok()?);
        Some(String::from_utf16_lossy(&name))
    }
}

#[cfg(not(windows))]
mod platform {
    /// Off Windows no `ComputerNameDnsHostname` exists to report.
    pub(super) const fn dns_host_name() -> Option<String> {
        None
    }
}
