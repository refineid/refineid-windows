// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! FINEID PIN retry-risk states and the retry floor.
//!
//! FINEID PINs allow five attempts before locking. The risk states below
//! map the live retry counter to a severity, and [`check_retry_floor`] is
//! the one floor every surface applies before it sends anything that can
//! spend a PIN 1 or PIN 2 attempt: the attempt is served only while the
//! card reports five, four or three tries left. At two, one or none, at a
//! blocked PIN, and at a counter the card did not report, nothing is
//! sent, so this software never spends the next-to-last or last attempt
//! and a lockout is never its doing. Setting a new PIN with the PUK is
//! not a PIN attempt and is not subject to this floor. Arming a reusable
//! authentication cache is separate and stricter: it requires a pristine
//! five-attempt state.

use core::fmt;

use crate::apdu::status_word::PinRetries;
use crate::auth::{PinSlot, PinStatus};

/// Retry count of a pristine FINEID PIN.
const RETRIES_PRISTINE: u8 = 5;
/// Retry count after one wrong attempt.
const RETRIES_ONE_SPENT: u8 = 4;
/// Lowest retry count at which a PIN attempt is served.
const RETRIES_FLOOR: u8 = 3;
/// Highest retry count below the floor.
const RETRIES_BELOW_FLOOR: u8 = 2;
/// Retry count at which credential lockout is one wrong try away.
const RETRIES_LOCKDOWN_IMMINENT: u8 = 1;
/// Retry count after the credential is exhausted.
const RETRIES_EXHAUSTED: u8 = 0;

/// Severity derived from the FINEID five-attempt PIN counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRetryRisk {
    /// Five attempts remain: normal operating conditions.
    NormalOperatingConditions,
    /// Four attempts remain: a disturbance was detected.
    DisturbanceDetected,
    /// Three attempts remain: a security incident is declared; the last
    /// attempt this software serves.
    SecurityIncidentDeclared,
    /// Two attempts remain: below the floor, no PIN is spent here.
    CriticalThreatLevel,
    /// One attempt remains: a credential lockout is imminent.
    LockdownImminent,
    /// No attempts remain: the credential is locked.
    DefencesFallen,
}

impl PinRetryRisk {
    /// Classify a FINEID retry counter. A value above the five-attempt
    /// limit is rejected rather than assigned a misleading state.
    #[must_use]
    pub const fn from_retries(retries: PinRetries) -> Option<Self> {
        match retries.get() {
            RETRIES_PRISTINE => Some(Self::NormalOperatingConditions),
            RETRIES_ONE_SPENT => Some(Self::DisturbanceDetected),
            RETRIES_FLOOR => Some(Self::SecurityIncidentDeclared),
            RETRIES_BELOW_FLOOR => Some(Self::CriticalThreatLevel),
            RETRIES_LOCKDOWN_IMMINENT => Some(Self::LockdownImminent),
            RETRIES_EXHAUSTED => Some(Self::DefencesFallen),
            _ => None,
        }
    }

    /// Whether a PIN attempt is served at this state: five, four or three
    /// tries left.
    const fn is_above_floor(self) -> bool {
        matches!(
            self,
            Self::NormalOperatingConditions
                | Self::DisturbanceDetected
                | Self::SecurityIncidentDeclared
        )
    }

    /// A reusable authentication cache requires a pristine five-attempt
    /// state -- a separate, stricter gate for arming the cache, not the
    /// retry floor.
    #[must_use]
    pub const fn permits_reusable_cache(self) -> bool {
        matches!(self, Self::NormalOperatingConditions)
    }
}

/// Why this software refuses to send a PIN 1 or PIN 2 attempt.
///
/// Carries the PIN and the state the card reported, never candidate PIN
/// data. Each variant except [`Self::CounterUnreadable`] leaves the PUK
/// path open: the PUK sets a new PIN and restores its tries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryFloorRefusal {
    /// The card reports two, one or no tries left for the PIN.
    TriesBelowFloor {
        /// The PIN whose attempt was refused.
        slot: PinSlot,
        /// The tries the card reports left.
        remaining: PinRetries,
    },
    /// The card reports the PIN blocked.
    Blocked {
        /// The PIN whose attempt was refused.
        slot: PinSlot,
    },
    /// The card did not report how many tries are left.
    CounterUnreadable {
        /// The PIN whose attempt was refused.
        slot: PinSlot,
    },
}

impl RetryFloorRefusal {
    /// The PIN whose attempt was refused.
    #[must_use]
    pub const fn slot(self) -> PinSlot {
        match self {
            Self::TriesBelowFloor { slot, .. }
            | Self::Blocked { slot }
            | Self::CounterUnreadable { slot } => slot,
        }
    }
}

const fn slot_name(slot: PinSlot) -> &'static str {
    match slot {
        PinSlot::Pin1 => "PIN 1",
        PinSlot::Pin2 => "PIN 2",
    }
}

impl fmt::Display for RetryFloorRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pin = slot_name(self.slot());
        match self {
            Self::TriesBelowFloor { remaining, .. } => {
                let count = remaining.get();
                let noun = if count == RETRIES_LOCKDOWN_IMMINENT {
                    "try"
                } else {
                    "tries"
                };
                write!(
                    f,
                    "RefineID does not try {pin}: the card has {count} {noun} left, and \
                     RefineID never spends the last two. The PUK can set a new {pin}."
                )
            }
            Self::Blocked { .. } => write!(
                f,
                "RefineID does not try {pin}: the card reports it blocked. The PUK can \
                 set a new {pin}."
            ),
            Self::CounterUnreadable { .. } => write!(
                f,
                "RefineID does not try {pin}: the card did not report how many tries \
                 remain."
            ),
        }
    }
}

impl core::error::Error for RetryFloorRefusal {}

/// The retry floor: whether a command that can spend a `slot` attempt
/// may be sent, given the counter-safe status the card reported for that
/// PIN.
///
/// Served at five, four or three tries left, and when the card reports
/// the PIN verified in the current security context -- a successful
/// verification resets the counter to its maximum. Refused at two, one
/// or no tries left, at a blocked PIN, and at any status that carries no
/// readable counter.
///
/// # Errors
///
/// [`RetryFloorRefusal`] naming the PIN and the state that refused it.
pub const fn check_retry_floor(slot: PinSlot, status: PinStatus) -> Result<(), RetryFloorRefusal> {
    match status {
        PinStatus::Verified => Ok(()),
        PinStatus::Remaining(remaining) => match PinRetryRisk::from_retries(remaining) {
            Some(risk) if risk.is_above_floor() => Ok(()),
            Some(_) => Err(RetryFloorRefusal::TriesBelowFloor { slot, remaining }),
            None => Err(RetryFloorRefusal::CounterUnreadable { slot }),
        },
        PinStatus::Locked => Err(RetryFloorRefusal::Blocked { slot }),
        PinStatus::NoInfo | PinStatus::Other(_) => {
            Err(RetryFloorRefusal::CounterUnreadable { slot })
        }
    }
}

/// Whether PIN1 may be retained in a reusable authentication cache.
#[must_use]
pub const fn pin1_status_permits_reusable_cache(pin1: PinStatus) -> bool {
    matches!(
        pin1,
        PinStatus::Remaining(retries)
            if matches!(
                PinRetryRisk::from_retries(retries),
                Some(risk) if risk.permits_reusable_cache()
            )
    )
}

#[cfg(test)]
mod tests {
    use super::{
        PinRetryRisk, PinSlot, PinStatus, RETRIES_BELOW_FLOOR, RETRIES_EXHAUSTED, RETRIES_FLOOR,
        RETRIES_LOCKDOWN_IMMINENT, RETRIES_ONE_SPENT, RETRIES_PRISTINE, RetryFloorRefusal,
        check_retry_floor, pin1_status_permits_reusable_cache,
    };
    use crate::apdu::status_word::PinRetries;

    /// One above the five-attempt limit, for the rejection test.
    const ABOVE_LIMIT: u8 = 6;
    /// A status word outside the modeled set.
    const UNMODELED_SW: u16 = 0x6F00;
    /// Both PINs the floor guards.
    const SLOTS: &[PinSlot] = &[PinSlot::Pin1, PinSlot::Pin2];
    /// The counts at which an attempt is served.
    const SERVED: &[u8] = &[RETRIES_PRISTINE, RETRIES_ONE_SPENT, RETRIES_FLOOR];
    /// The counts at which an attempt is refused.
    const REFUSED: &[u8] = &[
        RETRIES_BELOW_FLOOR,
        RETRIES_LOCKDOWN_IMMINENT,
        RETRIES_EXHAUSTED,
    ];

    fn retries(count: u8) -> PinRetries {
        PinRetries::from_nibble(count).expect("fits a nibble")
    }

    fn risk(count: u8) -> Option<PinRetryRisk> {
        PinRetries::from_nibble(count).and_then(PinRetryRisk::from_retries)
    }

    fn remaining(count: u8) -> PinStatus {
        PinStatus::Remaining(retries(count))
    }

    #[test]
    fn the_five_attempt_ladder_is_total() {
        assert_eq!(
            risk(RETRIES_PRISTINE),
            Some(PinRetryRisk::NormalOperatingConditions)
        );
        assert_eq!(
            risk(RETRIES_ONE_SPENT),
            Some(PinRetryRisk::DisturbanceDetected)
        );
        assert_eq!(
            risk(RETRIES_FLOOR),
            Some(PinRetryRisk::SecurityIncidentDeclared)
        );
        assert_eq!(
            risk(RETRIES_BELOW_FLOOR),
            Some(PinRetryRisk::CriticalThreatLevel)
        );
        assert_eq!(
            risk(RETRIES_LOCKDOWN_IMMINENT),
            Some(PinRetryRisk::LockdownImminent)
        );
        assert_eq!(risk(RETRIES_EXHAUSTED), Some(PinRetryRisk::DefencesFallen));
        assert_eq!(risk(ABOVE_LIMIT), None);
    }

    #[test]
    fn five_four_and_three_tries_are_served_for_both_pins() {
        for &slot in SLOTS {
            for &count in SERVED {
                assert_eq!(check_retry_floor(slot, remaining(count)), Ok(()));
            }
        }
    }

    #[test]
    fn two_one_and_zero_tries_are_refused_for_both_pins() {
        for &slot in SLOTS {
            for &count in REFUSED {
                assert_eq!(
                    check_retry_floor(slot, remaining(count)),
                    Err(RetryFloorRefusal::TriesBelowFloor {
                        slot,
                        remaining: retries(count),
                    })
                );
            }
        }
    }

    #[test]
    fn a_verified_pin_is_served_and_states_without_a_counter_are_refused() {
        for &slot in SLOTS {
            assert_eq!(check_retry_floor(slot, PinStatus::Verified), Ok(()));
            assert_eq!(
                check_retry_floor(slot, PinStatus::Locked),
                Err(RetryFloorRefusal::Blocked { slot })
            );
            for status in [
                PinStatus::NoInfo,
                PinStatus::Other(UNMODELED_SW),
                remaining(ABOVE_LIMIT),
            ] {
                assert_eq!(
                    check_retry_floor(slot, status),
                    Err(RetryFloorRefusal::CounterUnreadable { slot })
                );
            }
        }
    }

    #[test]
    fn a_refusal_names_the_pin_the_tries_left_and_the_puk() {
        for &slot in SLOTS {
            for &count in REFUSED {
                let text = check_retry_floor(slot, remaining(count))
                    .expect_err("below the floor")
                    .to_string();
                assert!(text.contains(super::slot_name(slot)), "{text}");
                assert!(text.contains(&count.to_string()), "{text}");
                assert!(text.contains("PUK"), "{text}");
            }
            let blocked = check_retry_floor(slot, PinStatus::Locked)
                .expect_err("blocked")
                .to_string();
            assert!(blocked.contains(super::slot_name(slot)), "{blocked}");
            assert!(blocked.contains("PUK"), "{blocked}");
        }
    }

    #[test]
    fn a_reusable_cache_requires_a_pristine_pin1() {
        assert!(pin1_status_permits_reusable_cache(remaining(
            RETRIES_PRISTINE
        )));
        assert!(!pin1_status_permits_reusable_cache(remaining(
            RETRIES_ONE_SPENT
        )));
        assert!(!pin1_status_permits_reusable_cache(remaining(
            RETRIES_FLOOR
        )));
        assert!(!pin1_status_permits_reusable_cache(PinStatus::Verified));
    }

    #[test]
    fn the_reusable_cache_is_never_looser_than_the_floor() {
        for &count in REFUSED.iter().chain(&[ABOVE_LIMIT]) {
            assert!(!pin1_status_permits_reusable_cache(remaining(count)));
        }
        for status in [PinStatus::Locked, PinStatus::NoInfo] {
            assert!(!pin1_status_permits_reusable_cache(status));
        }
    }
}
