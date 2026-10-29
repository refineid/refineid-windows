//! The clocks the requester reads.
//!
//! Protocol deadlines run on the continuous clock (RAPP v26.10.29 section
//! 8.1 item 2): milliseconds that keep advancing while the machine sleeps,
//! so a request that waited through a sleep is as old as it is. Record
//! timestamps use the wall clock, which both endpoints can relate to.

/// Milliseconds in one second.
const MILLISECONDS_PER_SECOND: u64 = 1_000;

/// Milliseconds since an arbitrary origin on a clock that advances through
/// sleep and hibernation.
///
/// On Windows this is `GetTickCount64`: the milliseconds elapsed since the
/// system was started, sleep and hibernation included. Microsoft's
/// `GetTickCount64` reference points callers who want only the time spent
/// in the working state to `QueryUnbiasedInterruptTime`, whose reference
/// states that the unbiased count excludes sleep and hibernation; the tick
/// count is the biased one. Elsewhere it is the time since the process
/// started; those builds exist for host-side tests, not for deadlines that
/// span a sleep.
#[must_use]
pub fn continuous_ms() -> u64 {
    platform::continuous_ms()
}

/// Milliseconds since the Unix epoch on the wall clock, for record
/// timestamps such as a pairing's creation or the time it was forgotten.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    reason = "milliseconds since the Unix epoch fit in a u64 for the life of this software"
)]
pub fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Seconds since the Unix epoch on the wall clock, for discovery hint
/// epochs and withdrawal hint counters.
#[must_use]
pub fn unix_time_seconds() -> u64 {
    unix_time_ms() / MILLISECONDS_PER_SECOND
}

#[cfg(windows)]
mod platform {
    /// `GetTickCount64` takes no arguments, reads no memory the caller
    /// owns, and cannot fail; the call is the one unsafe line of the
    /// requester core.
    #[allow(
        unsafe_code,
        reason = "GetTickCount64 has no pointer arguments and no failure mode"
    )]
    pub(super) fn continuous_ms() -> u64 {
        // SAFETY: the function takes no arguments and touches no caller
        // memory; it returns the tick count by value.
        unsafe { windows::Win32::System::SystemInformation::GetTickCount64() }
    }
}

#[cfg(not(windows))]
mod platform {
    use std::sync::LazyLock;
    use std::time::Instant;

    static START: LazyLock<Instant> = LazyLock::new(Instant::now);

    #[allow(
        clippy::cast_possible_truncation,
        reason = "a process does not run for 2^64 milliseconds"
    )]
    pub(super) fn continuous_ms() -> u64 {
        START.elapsed().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_continuous_clock_does_not_run_backwards() {
        let first = super::continuous_ms();
        let second = super::continuous_ms();
        assert!(second >= first);
    }

    #[test]
    fn the_wall_clock_is_after_the_epoch() {
        assert!(super::unix_time_seconds() > 0);
        assert!(
            super::unix_time_ms() >= super::unix_time_seconds() * super::MILLISECONDS_PER_SECOND
        );
    }
}
