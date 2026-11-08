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
//! the one rule for every credential -- PIN 1, PIN 2, the PUK and the
//! activation code -- before a command that could spend a try: refused
//! at two or one tries left or an unreadable counter; sent otherwise,
//! the card answering for itself at zero or blocked. At five, four or
//! three tries left, and at a PIN the card reports verified, the command
//! goes out. At zero tries left or a blocked credential it goes out too,
//! because the card refuses it and spends nothing, and which code the
//! holder has in hand (a PUK, or an activation code) is inferred, never
//! known, so this software does not close a recovery the card would
//! allow. At two or one tries left, at a count above five, and at a
//! status that carries no counter, nothing is sent: this software never
//! spends the next-to-last or last attempt, and a lockout is never its
//! doing.
//!
//! FINEID S1 v4.2 leaves the PUK's try limit to card personalization;
//! the floor reads the PUK on the same five-try scale. Setting a new PIN
//! with the PUK is not a PIN attempt, so the PUK path is gated by the
//! PUK's own counter, whatever the target PIN's counter reads. A PUK the
//! card reports verified carries no count of the try a wrong PUK would
//! spend, so it is refused as unreadable. The preset activation PIN of a
//! card whose PINs ship preset to the letter's code is presented as the
//! PIN's current value and follows that PIN's counter under the same
//! rule.
//!
//! Arming a reusable authentication cache is separate and stricter: it
//! requires a pristine five-attempt state.

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
    /// The PUK, presented by RESET RETRY COUNTER or the organizational
    /// card's PUK VERIFY; on a card whose activation code is the PUK the
    /// activation PIN is presented under the PUK's counter.
    Puk,
}

impl FlooredCredential {
    /// The name the refusal text uses.
    const fn name(self) -> &'static str {
        match self {
            Self::Pin1 => "Basic PIN 1",
            Self::Pin2 => "Signature PIN 2",
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
/// Lowest retry count at which an attempt is served with tries to
/// spare.
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
    /// attempt this software serves with tries to spare.
    SecurityIncidentDeclared,
    /// Two attempts remain: below the floor, no credential is spent here.
    CriticalThreatLevel,
    /// One attempt remains: a credential lockout is imminent.
    LockdownImminent,
    /// No attempts remain: the credential is locked. The card refuses
    /// every presentation itself and spends nothing.
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

    /// Whether an attempt here would spend one of the last two tries:
    /// two or one left. Exhausted is not this state: at no tries left
    /// the card refuses by itself and spends nothing.
    const fn spends_a_last_try(self) -> bool {
        matches!(self, Self::CriticalThreatLevel | Self::LockdownImminent)
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
    /// The card reports two or one tries left for the credential.
    TriesBelowFloor {
        /// The credential whose attempt was refused.
        credential: FlooredCredential,
        /// The tries the card reports left.
        remaining: PinRetries,
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
            Self::TriesBelowFloor { credential, .. } | Self::CounterUnreadable { credential } => {
                credential
            }
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
/// Refused at two or one tries left, and at any status that carries no
/// readable counter: a count above five, no information, and a PUK
/// reported verified, which carries no count of the try a wrong PUK would
/// spend. Sent otherwise. A PIN the card reports verified is served, as a
/// successful verification resets its counter to the maximum. At zero
/// tries left and at a blocked credential the command goes to the card:
/// it answers for itself and spends nothing, and which code the holder
/// has in hand is inferred, never known, so the software does not close a
/// recovery the card would allow.
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
        PinStatus::Verified => match credential {
            FlooredCredential::Pin1 | FlooredCredential::Pin2 => Ok(()),
            FlooredCredential::Puk => Err(RetryFloorRefusal::CounterUnreadable { credential }),
        },
        PinStatus::Remaining(remaining) => match PinRetryRisk::from_retries(remaining) {
            Some(risk) if risk.spends_a_last_try() => Err(RetryFloorRefusal::TriesBelowFloor {
                credential,
                remaining,
            }),
            Some(_) => Ok(()),
            None => Err(RetryFloorRefusal::CounterUnreadable { credential }),
        },
        PinStatus::Locked => Ok(()),
        PinStatus::NoInfo | PinStatus::Other(_) => {
            Err(RetryFloorRefusal::CounterUnreadable { credential })
        }
    }
}

/// Whether the status reports zero tries left or a blocked PIN.
///
/// This reading sends no credential, so a surface may say "blocked" from
/// it where it has no credential to send: a held PIN 1 is never handed
/// out for such a state.
#[must_use]
pub const fn reports_no_tries_left(status: PinStatus) -> bool {
    match status {
        PinStatus::Locked => true,
        PinStatus::Remaining(remaining) => {
            matches!(
                PinRetryRisk::from_retries(remaining),
                Some(PinRetryRisk::DefencesFallen)
            )
        }
        PinStatus::Verified | PinStatus::NoInfo | PinStatus::Other(_) => false,
    }
}

/// The retry floor applied to the PUK's own counter.
///
/// The counter is read by the counter-safe PUK probe. Anything that
/// presents the PUK -- RESET RETRY COUNTER, the organizational card's PUK
/// VERIFY, or the activation PIN on a card whose activation code is the
/// PUK -- follows [`check_retry_floor`]; an invalidated PUK reads as a
/// blocked one.
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
        pin1_status_permits_reusable_cache, reports_no_tries_left,
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
    /// The two PINs.
    const PINS: &[FlooredCredential] = &[FlooredCredential::Pin1, FlooredCredential::Pin2];
    /// The counts at which an attempt is served for every credential.
    const SERVED: &[u8] = &[RETRIES_PRISTINE, RETRIES_ONE_SPENT, RETRIES_FLOOR];
    /// The counts at which an attempt is refused for every credential.
    const REFUSED: &[u8] = &[RETRIES_BELOW_FLOOR, RETRIES_LOCKDOWN_IMMINENT];

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
    fn five_four_and_three_tries_are_served_for_every_credential() {
        for &credential in CREDENTIALS {
            for &count in SERVED {
                assert_eq!(check_retry_floor(credential, remaining(count)), Ok(()));
            }
        }
    }

    #[test]
    fn two_and_one_tries_are_refused_for_every_credential() {
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
    fn every_credential_goes_to_the_card_at_no_tries_left_or_blocked() {
        for &credential in CREDENTIALS {
            for status in [remaining(RETRIES_EXHAUSTED), PinStatus::Locked] {
                assert_eq!(check_retry_floor(credential, status), Ok(()));
            }
        }
    }

    #[test]
    fn only_no_tries_left_and_blocked_report_nothing_left_to_spend() {
        for status in [remaining(RETRIES_EXHAUSTED), PinStatus::Locked] {
            assert!(reports_no_tries_left(status));
        }
        let others = SERVED
            .iter()
            .chain(REFUSED)
            .chain(&[ABOVE_LIMIT])
            .map(|&count| remaining(count))
            .chain([
                PinStatus::Verified,
                PinStatus::NoInfo,
                PinStatus::Other(UNMODELED_SW),
            ]);
        for status in others {
            assert!(!reports_no_tries_left(status));
        }
    }

    #[test]
    fn a_verified_credential_is_served_and_states_without_a_counter_are_refused() {
        for &credential in PINS {
            assert_eq!(check_retry_floor(credential, PinStatus::Verified), Ok(()));
        }
        assert_eq!(
            check_retry_floor(FlooredCredential::Puk, PinStatus::Verified),
            Err(RetryFloorRefusal::CounterUnreadable {
                credential: FlooredCredential::Puk
            })
        );
        for &credential in CREDENTIALS {
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
            assert!(text.contains("Signature PIN 2"), "{text}");
            assert!(text.contains(&count.to_string()), "{text}");
            assert!(text.contains("PUK"), "{text}");
        }
        // An unreadable counter names no recovery: whether the PUK path
        // is open is as unknown as the count.
        let unreadable = check_retry_floor(FlooredCredential::Pin1, PinStatus::NoInfo)
            .expect_err("unreadable")
            .to_string();
        assert!(unreadable.contains("Basic PIN 1"), "{unreadable}");
        assert!(!unreadable.contains("PUK"), "{unreadable}");
    }

    #[test]
    fn a_puk_refusal_names_the_puk_and_the_tries_left_and_no_other_credential() {
        let refusals = REFUSED
            .iter()
            .map(|&count| (Some(count), remaining(count)))
            .chain([(None, PinStatus::NoInfo), (None, PinStatus::Verified)]);
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
        for &count in SERVED.iter().chain(&[RETRIES_EXHAUSTED]) {
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
            assert_eq!(check_puk_retry_floor(probe), Ok(()));
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
        for &count in REFUSED.iter().chain(&[RETRIES_EXHAUSTED, ABOVE_LIMIT]) {
            assert!(!pin1_status_permits_reusable_cache(remaining(count)));
        }
        for status in [PinStatus::Locked, PinStatus::NoInfo] {
            assert!(!pin1_status_permits_reusable_cache(status));
        }
    }
}
