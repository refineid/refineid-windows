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
//! spend a PIN 1, PIN 2 or PUK attempt: the attempt is served only while
//! the card reports five, four or three tries left for that credential.
//! At two, one or none, at a blocked credential, and at a counter the
//! card did not report, nothing is sent, so this software never spends
//! the next-to-last or last attempt and a lockout is never its doing.
//! FINEID S1 v4.2 leaves the PUK's try limit to card personalization;
//! the floor serves the PUK at the same three counts as the PINs. A
//! blocked PUK cannot be recovered. Setting a new PIN with the PUK is
//! not a PIN attempt, so the PUK path is gated by the PUK's own counter,
//! whatever the target PIN's counter reads. Arming a reusable
//! authentication cache is separate and stricter: it requires a pristine
//! five-attempt state.

use core::fmt;

use crate::apdu::status_word::PinRetries;
use crate::auth::{PinSlot, PinStatus, PukStatus};

/// A credential whose retry counter the floor guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlooredCredential {
    /// PIN 1, presented by VERIFY or CHANGE REFERENCE DATA.
    Pin1,
    /// PIN 2, presented by VERIFY or CHANGE REFERENCE DATA.
    Pin2,
    /// The PUK, presented by RESET RETRY COUNTER; on cards that ship with blocked PINs the
    /// activation code is presented under the PUK's counter.
    Puk,
}

impl FlooredCredential {
    /// The name the refusal text uses.
    const fn name(self) -> &'static str {
        match self {
            Self::Pin1 => "PIN 1",
            Self::Pin2 => "PIN 2",
            Self::Puk => "the PUK",
        }
    }
}

impl From<PinSlot> for FlooredCredential {
    fn from(slot: PinSlot) -> Self {
        match slot {
            PinSlot::Pin1 => Self::Pin1,
            PinSlot::Pin2 => Self::Pin2,
        }
    }
}

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

/// Severity derived from a FINEID retry counter, read on the five-attempt
/// PIN scale.
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

    /// Whether an attempt is served at this state: five, four or three
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

/// Why this software refuses to send a PIN 1, PIN 2 or PUK attempt.
///
/// Carries the credential and the state the card reported, never
/// candidate credential data. A PIN refusal other than
/// [`Self::CounterUnreadable`] leaves the PUK path open: the PUK sets a
/// new PIN and restores its tries. A PUK refusal names no other
/// credential, because none recovers a PUK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryFloorRefusal {
    /// The card reports two, one or no tries left for the credential.
    TriesBelowFloor {
        /// The credential whose attempt was refused.
        credential: FlooredCredential,
        /// The tries the card reports left.
        remaining: PinRetries,
    },
    /// The card reports the credential blocked.
    Blocked {
        /// The credential whose attempt was refused.
        credential: FlooredCredential,
    },
    /// The card did not report how many tries are left.
    CounterUnreadable {
        /// The credential whose attempt was refused.
        credential: FlooredCredential,
    },
}

impl RetryFloorRefusal {
    /// The credential whose attempt was refused.
    #[must_use]
    pub const fn credential(self) -> FlooredCredential {
        match self {
            Self::TriesBelowFloor { credential, .. }
            | Self::Blocked { credential }
            | Self::CounterUnreadable { credential } => credential,
        }
    }
}

impl fmt::Display for RetryFloorRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let credential = self.credential();
        let name = credential.name();
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
                    "RefineID does not try {name}: the card has {count} {noun} left, and \
                     RefineID never spends the last two."
                )?;
            }
            Self::Blocked { .. } => {
                write!(
                    f,
                    "RefineID does not try {name}: the card reports it blocked."
                )?;
            }
            Self::CounterUnreadable { .. } => {
                return write!(
                    f,
                    "RefineID does not try {name}: the card did not report how many \
                     tries remain."
                );
            }
        }
        match credential {
            FlooredCredential::Pin1 | FlooredCredential::Pin2 => {
                write!(f, " The PUK can set a new {name}.")
            }
            FlooredCredential::Puk => Ok(()),
        }
    }
}

impl core::error::Error for RetryFloorRefusal {}

/// The retry floor: whether a command that can spend a `credential`
/// attempt may be sent, given the counter-safe status the card reported
/// for that credential.
///
/// Served at five, four or three tries left, and when the card reports
/// the credential verified in the current security context -- a
/// successful verification resets the counter to its maximum. Refused at
/// two, one or no tries left, at a blocked credential, and at any status
/// that carries no readable counter, a count above five included.
///
/// # Errors
///
/// [`RetryFloorRefusal`] naming the credential and the state that
/// refused it.
pub const fn check_retry_floor(
    credential: FlooredCredential,
    status: PinStatus,
) -> Result<(), RetryFloorRefusal> {
    match status {
        PinStatus::Verified => Ok(()),
        PinStatus::Remaining(remaining) => match PinRetryRisk::from_retries(remaining) {
            Some(risk) if risk.is_above_floor() => Ok(()),
            Some(_) => Err(RetryFloorRefusal::TriesBelowFloor {
                credential,
                remaining,
            }),
            None => Err(RetryFloorRefusal::CounterUnreadable { credential }),
        },
        PinStatus::Locked => Err(RetryFloorRefusal::Blocked { credential }),
        PinStatus::NoInfo | PinStatus::Other(_) => {
            Err(RetryFloorRefusal::CounterUnreadable { credential })
        }
    }
}

/// The retry floor applied to the PUK's own counter.
///
/// The counter is read by the counter-safe PUK probe. Anything that
/// presents the PUK -- RESET RETRY COUNTER, or the activation code on a
/// card that ships with blocked PINs -- is sent only at five, four or
/// three PUK tries left. A blocked or invalidated PUK, and a counter the
/// card did not report, are refused.
///
/// # Errors
///
/// [`RetryFloorRefusal`] naming the PUK and the state that refused it.
pub const fn check_puk_retry_floor(status: PukStatus) -> Result<(), RetryFloorRefusal> {
    let status = match status {
        PukStatus::Remaining(retries) => PinStatus::Remaining(retries),
        PukStatus::NoInfo => PinStatus::NoInfo,
        PukStatus::Locked | PukStatus::Invalidated => PinStatus::Locked,
        PukStatus::Other(word) => PinStatus::Other(word),
    };
    check_retry_floor(FlooredCredential::Puk, status)
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
        FlooredCredential, PinRetryRisk, PinSlot, PinStatus, RETRIES_BELOW_FLOOR,
        RETRIES_EXHAUSTED, RETRIES_FLOOR, RETRIES_LOCKDOWN_IMMINENT, RETRIES_ONE_SPENT,
        RETRIES_PRISTINE, RetryFloorRefusal, check_puk_retry_floor, check_retry_floor,
        pin1_status_permits_reusable_cache,
    };
    use crate::apdu::status_word::PinRetries;
    use crate::auth::PukStatus;

    /// One above the five-attempt limit, for the rejection test.
    const ABOVE_LIMIT: u8 = 6;
    /// A status word outside the modeled set.
    const UNMODELED_SW: u16 = 0x6F00;
    /// Every credential the floor guards.
    const CREDENTIALS: &[FlooredCredential] = &[
        FlooredCredential::Pin1,
        FlooredCredential::Pin2,
        FlooredCredential::Puk,
    ];
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
    fn a_pin_slot_is_floored_as_its_own_pin() {
        assert_eq!(
            FlooredCredential::from(PinSlot::Pin1),
            FlooredCredential::Pin1
        );
        assert_eq!(
            FlooredCredential::from(PinSlot::Pin2),
            FlooredCredential::Pin2
        );
    }

    #[test]
    fn five_four_and_three_tries_are_served_for_both_pins_and_the_puk() {
        for &credential in CREDENTIALS {
            for &count in SERVED {
                assert_eq!(check_retry_floor(credential, remaining(count)), Ok(()));
            }
        }
    }

    #[test]
    fn two_one_and_zero_tries_are_refused_for_both_pins_and_the_puk() {
        for &credential in CREDENTIALS {
            for &count in REFUSED {
                assert_eq!(
                    check_retry_floor(credential, remaining(count)),
                    Err(RetryFloorRefusal::TriesBelowFloor {
                        credential,
                        remaining: retries(count),
                    })
                );
            }
        }
    }

    #[test]
    fn a_verified_credential_is_served_and_states_without_a_counter_are_refused() {
        for &credential in CREDENTIALS {
            assert_eq!(check_retry_floor(credential, PinStatus::Verified), Ok(()));
            assert_eq!(
                check_retry_floor(credential, PinStatus::Locked),
                Err(RetryFloorRefusal::Blocked { credential })
            );
            for status in [
                PinStatus::NoInfo,
                PinStatus::Other(UNMODELED_SW),
                remaining(ABOVE_LIMIT),
            ] {
                assert_eq!(
                    check_retry_floor(credential, status),
                    Err(RetryFloorRefusal::CounterUnreadable { credential })
                );
            }
        }
    }

    #[test]
    fn a_pin_refusal_names_the_pin_the_tries_left_and_the_puk() {
        for &count in REFUSED {
            let refusal = check_retry_floor(FlooredCredential::Pin2, remaining(count))
                .expect_err("below the floor");
            let text = refusal.to_string();
            assert!(text.contains("PIN 2"), "{text}");
            assert!(text.contains(&count.to_string()), "{text}");
            assert!(text.contains("PUK"), "{text}");
        }
        let blocked = check_retry_floor(FlooredCredential::Pin1, PinStatus::Locked)
            .expect_err("blocked")
            .to_string();
        assert!(blocked.contains("PIN 1"), "{blocked}");
        assert!(blocked.contains("PUK"), "{blocked}");
    }

    #[test]
    fn a_puk_refusal_names_the_puk_and_the_tries_left_and_no_other_credential() {
        let refusals = REFUSED
            .iter()
            .map(|&count| (Some(count), remaining(count)))
            .chain([(None, PinStatus::Locked), (None, PinStatus::NoInfo)]);
        for (count, status) in refusals {
            let text = check_retry_floor(FlooredCredential::Puk, status)
                .expect_err("refused")
                .to_string();
            assert!(text.contains("the PUK"), "{text}");
            if let Some(count) = count {
                assert!(text.contains(&count.to_string()), "{text}");
            }
            assert!(!text.contains("PIN"), "{text}");
            assert!(!text.contains("can set"), "{text}");
        }
    }

    #[test]
    fn the_puk_probe_reads_through_the_same_floor() {
        for &count in SERVED {
            let probe = PukStatus::Remaining(retries(count));
            assert_eq!(check_puk_retry_floor(probe), Ok(()));
        }
        for &count in REFUSED {
            let probe = PukStatus::Remaining(retries(count));
            assert_eq!(
                check_puk_retry_floor(probe),
                Err(RetryFloorRefusal::TriesBelowFloor {
                    credential: FlooredCredential::Puk,
                    remaining: retries(count),
                })
            );
        }
        for probe in [PukStatus::Locked, PukStatus::Invalidated] {
            assert_eq!(
                check_puk_retry_floor(probe),
                Err(RetryFloorRefusal::Blocked {
                    credential: FlooredCredential::Puk
                })
            );
        }
        for probe in [
            PukStatus::NoInfo,
            PukStatus::Other(UNMODELED_SW),
            PukStatus::Remaining(retries(ABOVE_LIMIT)),
        ] {
            assert_eq!(
                check_puk_retry_floor(probe),
                Err(RetryFloorRefusal::CounterUnreadable {
                    credential: FlooredCredential::Puk
                })
            );
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
