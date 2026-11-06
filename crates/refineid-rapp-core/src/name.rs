//! The name this computer gives itself to its phone (RAPP v26.11.2 section
//! 4.3 item 3).
//!
//! A computer names itself by its host name with the operating system's
//! own name in front, joined by a space, a hyphen and a space:
//! `Windows - EXAMPLE-HOST`. The name goes in `pairing.hello` and again in
//! `session.hello` at the start of every session, so a renamed computer's
//! new name reaches the phone with its next session. It is a label for
//! people; nothing is found or matched by it.

use refineid_rapp::{DISPLAY_NAME_MAX_BYTES, DisplayName};

/// The operating system's own name, as `pairing.hello` carries it in
/// `platform` and in front of the host name (section 4.3 item 3).
pub const PLATFORM: &str = "Windows";

/// What joins the operating system's name and the host name.
const PREFIX_SEPARATOR: &str = " - ";

/// The environment variable Windows sets to the computer's name in every
/// process.
const COMPUTER_NAME_VARIABLE: &str = "COMPUTERNAME";

/// This computer's display name: `Windows - ` and its host name, or the
/// operating system's name alone when Windows reports no host name.
#[must_use]
pub fn this_computer() -> DisplayName {
    computer_named(std::env::var(COMPUTER_NAME_VARIABLE).ok().as_deref())
}

/// The display name of a Windows computer whose host name is `host`,
/// shortened at a character boundary to [`DISPLAY_NAME_MAX_BYTES`].
#[must_use]
pub fn computer_named(host: Option<&str>) -> DisplayName {
    let host = host.map(str::trim).filter(|host| !host.is_empty());
    let mut name = host.map_or_else(
        || PLATFORM.to_owned(),
        |host| format!("{PLATFORM}{PREFIX_SEPARATOR}{host}"),
    );
    shorten(&mut name, DISPLAY_NAME_MAX_BYTES);
    DisplayName::parse(name).unwrap_or_else(|_| platform_name())
}

/// The operating system's name as a display name.
fn platform_name() -> DisplayName {
    DisplayName::parse(PLATFORM.to_owned())
        .unwrap_or_else(|_| unreachable!("the platform name is a display name"))
}

/// Shortens `text` to at most `limit` bytes, at a character boundary.
fn shorten(text: &mut String, limit: usize) {
    if text.len() <= limit {
        return;
    }
    let boundary = (0..=limit)
        .rev()
        .find(|index| text.is_char_boundary(*index))
        .unwrap_or(0);
    text.truncate(boundary);
}

#[cfg(test)]
mod tests {
    use super::{DISPLAY_NAME_MAX_BYTES, PLATFORM, PREFIX_SEPARATOR, computer_named};

    /// A synthetic host name.
    const HOST: &str = "EXAMPLE-HOST";

    #[test]
    fn a_computer_names_itself_by_its_host_with_the_platform_in_front() {
        assert_eq!(
            computer_named(Some(HOST)).as_str(),
            format!("{PLATFORM}{PREFIX_SEPARATOR}{HOST}")
        );
    }

    #[test]
    fn no_host_name_leaves_the_platform_name() {
        assert_eq!(computer_named(None).as_str(), PLATFORM);
        assert_eq!(computer_named(Some("  ")).as_str(), PLATFORM);
    }

    #[test]
    fn a_long_host_name_is_shortened_at_a_character_boundary() {
        let two_byte_character = "\u{e4}";
        let host = two_byte_character.repeat(DISPLAY_NAME_MAX_BYTES);
        let name = computer_named(Some(&host));
        assert!(name.as_str().len() <= DISPLAY_NAME_MAX_BYTES);
        assert!(name.as_str().len() >= DISPLAY_NAME_MAX_BYTES - two_byte_character.len());
        assert!(name.as_str().starts_with(PLATFORM));
    }
}
