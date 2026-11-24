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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Held PIN 1 and process-lifetime negative PIN retry protection for the
//! Windows Card Module.
//!
//! A PIN 1 the card accepted is held in this process's memory, bound to the
//! card's full PKCS#15 token serial and resolved [`PinReferenceScheme`], with
//! no idle window or countdown (RAPP v26.11.2 section 11 item 2). Every
//! checkout verifies the live serial, scheme, and retry state via
//! [`pin1_status_permits_reusable_cache`]; PIN 2 is never held positively.
//!
//! Process-lifetime rejection memory delegates directly to
//! [`refineid_auth::PinSafetyCache`], which keeps only per-process
//! random-keyed HMAC-SHA-256 fingerprints and never retains raw PIN bytes.

use core::fmt;

use refineid_auth::credentials::{
    CredentialInputError, CredentialRole, PIN_MAX_LENGTH, PIN_MIN_LENGTH,
};
use refineid_auth::{
    Pin1, Pin2, PinReferenceScheme, PinRetryRisk, PinSlot, PinStatus, UnvalidatedSecret,
    pin1_status_permits_reusable_cache,
};
use refineid_pkcs15::TokenSerial;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Validated ASCII-digit PIN bytes retained only in process memory for the
/// held PIN 1 path and boundary negative-cache checks. Zeroized on drop and
/// redacted in [`fmt::Debug`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PinBytes {
    digits: Zeroizing<Vec<u8>>,
}

impl PinBytes {
    /// Validate ASCII-digit bytes within [`PIN_MIN_LENGTH`] through
    /// [`PIN_MAX_LENGTH`].
    ///
    /// # Errors
    /// Returns [`CredentialInputError`] on empty, out-of-range, or non-digit
    /// input; consumes and zeroizes `bytes` on every exit path.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, CredentialInputError> {
        let role = CredentialRole::Pin1;
        if bytes.is_empty() {
            bytes.zeroize();
            return Err(CredentialInputError::Empty { role });
        }
        if bytes.len() < PIN_MIN_LENGTH || bytes.len() > PIN_MAX_LENGTH {
            bytes.zeroize();
            return Err(CredentialInputError::WrongLength {
                role,
                expected_min: PIN_MIN_LENGTH,
                expected_max: PIN_MAX_LENGTH,
            });
        }
        if bytes.iter().any(|byte| !byte.is_ascii_digit()) {
            bytes.zeroize();
            return Err(CredentialInputError::NonDigit { role });
        }
        Ok(Self {
            digits: Zeroizing::new(bytes),
        })
    }

    /// Reconstruct a typed [`Pin1`] from these validated digits.
    pub fn to_pin1(&self) -> Result<Pin1, CredentialInputError> {
        Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(self.digits.to_vec()))
    }

    /// Reconstruct a typed [`Pin2`] from these validated digits.
    pub fn to_pin2(&self) -> Result<Pin2, CredentialInputError> {
        Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(self.digits.to_vec()))
    }
}

impl fmt::Debug for PinBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinBytes([redacted])")
    }
}

/// Whether `status` reports zero tries left or a blocked PIN on `scheme`'s
/// retry scale.
#[must_use]
pub const fn reports_no_tries_left(status: PinStatus, scheme: PinReferenceScheme) -> bool {
    match status {
        PinStatus::Locked => true,
        PinStatus::Remaining(remaining) => matches!(
            PinRetryRisk::from_retries(remaining, scheme),
            Some(PinRetryRisk::DefencesFallen)
        ),
        PinStatus::Verified | PinStatus::NoInfo | PinStatus::Other(_) => false,
    }
}

/// A previously card-rejected PIN was offered again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreviouslyRejectedPin {
    /// Slot for which the PIN was rejected.
    pub slot: PinSlot,
}

impl fmt::Display for PreviouslyRejectedPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self.slot {
            PinSlot::Pin1 => "Basic PIN 1",
            PinSlot::Pin2 => "Signature PIN 2",
        };
        write!(f, "{label} was previously rejected by the card")
    }
}

impl core::error::Error for PreviouslyRejectedPin {}

struct HeldPin1 {
    serial: TokenSerial,
    scheme: PinReferenceScheme,
    pin: PinBytes,
    generation: u64,
}

/// Destructively checked-out PIN 1 for one live card serial and scheme.
///
/// Dropping this value destroys the PIN. It returns to the held state only
/// through [`Self::restore_after_success`], once the card has accepted it, or
/// [`Self::restore_after_unanswered`], when the attempt's answer was lost.
pub struct CheckedOutPin1 {
    entry: HeldPin1,
}

impl CheckedOutPin1 {
    /// Borrow the held PIN for the single VERIFY associated with this checkout.
    #[must_use]
    pub const fn pin(&self) -> &PinBytes {
        &self.entry.pin
    }

    /// Hold this PIN again after the card accepted it. Returns `true` if
    /// restored, or `false` if concurrent or intervening invalidation won.
    #[must_use]
    pub fn restore_after_success(self, cache: &mut PinSafetyCache) -> bool {
        self.restore(cache)
    }

    /// Hold this PIN again after a transport failure or an unanswered
    /// command: the card may not have seen it, and the retry counter read
    /// before its next use decides (see [`PinSafetyCache::checkout_pin1`]).
    /// Returns `true` if restored, or `false` if concurrent or intervening
    /// invalidation won.
    pub fn restore_after_unanswered(self, cache: &mut PinSafetyCache) -> bool {
        self.restore(cache)
    }

    fn restore(self, cache: &mut PinSafetyCache) -> bool {
        if cache.generation != self.entry.generation || cache.held_pin1.is_some() {
            return false;
        }
        cache.held_pin1 = Some(self.entry);
        true
    }
}

impl fmt::Debug for CheckedOutPin1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckedOutPin1")
            .field("serial", &self.entry.serial)
            .field("scheme", &self.entry.scheme)
            .finish_non_exhaustive()
    }
}

/// The held PIN 1 plus `refineid-auth`'s process-lifetime negative PIN cache.
///
/// Dropping this cache destroys any held [`PinBytes`] (zeroizing its digits on
/// drop) and drops the inner [`refineid_auth::PinSafetyCache`] (zeroizing its
/// process-local HMAC key on drop).
pub struct PinSafetyCache {
    held_pin1: Option<HeldPin1>,
    generation: u64,
    negative: refineid_auth::PinSafetyCache,
}

impl Drop for PinSafetyCache {
    fn drop(&mut self) {
        self.clear_positive();
    }
}

impl PinSafetyCache {
    /// Construct an empty cache with a fresh process-local fingerprint key.
    ///
    /// # Errors
    /// Returns the OS random-source error if fingerprint key generation fails.
    pub fn new() -> Result<Self, getrandom::Error> {
        Ok(Self {
            held_pin1: None,
            generation: 0,
            negative: refineid_auth::PinSafetyCache::new()?,
        })
    }

    /// Current positive-cache invalidation generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Hold a card-confirmed PIN 1 bound to `(serial, scheme)` until an
    /// invalidation event.
    ///
    /// # Errors
    /// Refuses a value this process has already seen the card reject.
    pub fn store_pin1(
        &mut self,
        serial: TokenSerial,
        scheme: PinReferenceScheme,
        pin: PinBytes,
    ) -> Result<(), PreviouslyRejectedPin> {
        if self.is_rejected(&serial, PinSlot::Pin1, &pin) {
            return Err(PreviouslyRejectedPin {
                slot: PinSlot::Pin1,
            });
        }
        self.clear_positive();
        self.held_pin1 = Some(HeldPin1 {
            serial,
            scheme,
            pin,
            generation: self.generation,
        });
        Ok(())
    }

    /// Hold a card-confirmed PIN 1 only if no invalidation occurred since
    /// `expected_generation` was captured. Returns `Ok(true)` when stored,
    /// `Ok(false)` when a concurrent invalidation advanced the generation.
    ///
    /// # Errors
    /// Refuses a value this process has already seen the card reject.
    pub fn store_pin1_if_generation(
        &mut self,
        serial: TokenSerial,
        scheme: PinReferenceScheme,
        pin: PinBytes,
        expected_generation: u64,
    ) -> Result<bool, PreviouslyRejectedPin> {
        if self.generation != expected_generation {
            return Ok(false);
        }
        self.store_pin1(serial, scheme, pin)?;
        Ok(true)
    }

    /// Destructively check out the held PIN 1 for the freshly read live
    /// serial, scheme, and PIN 1 status. Another card's serial, another
    /// scheme, or a counter that is neither verified nor pristine for
    /// `scheme` destroys the held value.
    pub fn checkout_pin1(
        &mut self,
        live_serial: &TokenSerial,
        live_scheme: PinReferenceScheme,
        live_status: PinStatus,
    ) -> Option<CheckedOutPin1> {
        let entry = self.held_pin1.take()?;
        let usable = entry.serial == *live_serial
            && entry.scheme == live_scheme
            && pin1_status_permits_reusable_cache(live_status, live_scheme);
        if usable {
            return Some(CheckedOutPin1 { entry });
        }
        drop(entry);
        self.clear_positive();
        None
    }

    /// Whether a PIN 1 is currently held in memory.
    #[must_use]
    pub const fn has_positive_pin1(&self) -> bool {
        self.held_pin1.is_some()
    }

    /// Destroy the held PIN 1 without weakening process-lifetime rejection
    /// memory.
    pub fn clear_positive(&mut self) {
        self.held_pin1 = None;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Whether `pin` has already been rejected by the card for `slot`.
    #[must_use]
    pub fn is_rejected(&self, serial: &TokenSerial, slot: PinSlot, pin: &PinBytes) -> bool {
        match slot {
            PinSlot::Pin1 => pin
                .to_pin1()
                .is_ok_and(|pin1| self.negative.is_rejected_pin1(serial, &pin1)),
            PinSlot::Pin2 => pin
                .to_pin2()
                .is_ok_and(|pin2| self.negative.is_rejected_pin2(serial, &pin2)),
        }
    }

    /// Whether `pin` stays unsent at `status`: the card rejected it before
    /// and a presentation could spend a try. At zero tries left or a blocked
    /// PIN it spends nothing, so the command goes out and the card's answer
    /// reaches the holder.
    #[must_use]
    pub fn bars_presenting(
        &self,
        serial: &TokenSerial,
        slot: PinSlot,
        pin: &PinBytes,
        status: PinStatus,
        scheme: PinReferenceScheme,
    ) -> bool {
        !reports_no_tries_left(status, scheme) && self.is_rejected(serial, slot, pin)
    }

    /// Record a card-side wrong-PIN response for the rest of this process
    /// and destroy any held PIN 1.
    pub fn record_rejected(&mut self, serial: &TokenSerial, slot: PinSlot, pin: &PinBytes) {
        self.clear_positive();
        match slot {
            PinSlot::Pin1 => {
                if let Ok(pin1) = pin.to_pin1() {
                    self.negative.record_rejected_pin1(serial, &pin1);
                }
            }
            PinSlot::Pin2 => {
                if let Ok(pin2) = pin.to_pin2() {
                    self.negative.record_rejected_pin2(serial, &pin2);
                }
            }
        }
    }
}

impl fmt::Debug for PinSafetyCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinSafetyCache")
            .field("has_positive_pin1", &self.held_pin1.is_some())
            .field("negative", &self.negative)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use refineid_apdu::PinRetries;
    use refineid_auth::credentials::PIN_MAX_LENGTH;
    use refineid_auth::{PinReferenceScheme, PinSlot, PinStatus};
    use refineid_pkcs15::TokenSerial;

    use super::{PinBytes, PinSafetyCache, PreviouslyRejectedPin, reports_no_tries_left};

    const CARD_A_SERIAL: &str = "CARD-A-FULL-SERIAL";
    const CARD_B_SERIAL: &str = "CARD-B-FULL-SERIAL";
    const FINEID_PRISTINE: u8 = 5;
    const FINEID_SPENT: u8 = 4;
    const ESTONIAN_PRISTINE: u8 = 3;
    const ZERO_RETRIES: u8 = 0;
    const DECIMAL_RADIX: u8 = 10;

    fn serial(text: &str) -> TokenSerial {
        TokenSerial::new(text.to_owned())
    }

    fn random_pin() -> PinBytes {
        let mut digits = vec![0_u8; PIN_MAX_LENGTH];
        getrandom::fill(&mut digits).expect("OS RNG available");
        for digit in &mut digits {
            *digit = b'0' + (*digit % DECIMAL_RADIX);
        }
        PinBytes::new(digits).expect("valid random PIN")
    }

    fn remaining(count: u8) -> PinStatus {
        PinStatus::Remaining(PinRetries::from_nibble(count).expect("valid retry count"))
    }

    #[test]
    fn held_pin1_binds_serial_scheme_and_pristine_counter() {
        let mut cache = PinSafetyCache::new().expect("cache constructs");
        let pin = random_pin();
        cache
            .store_pin1(
                serial(CARD_A_SERIAL),
                PinReferenceScheme::Organizational,
                pin,
            )
            .expect("fresh PIN 1 stores");
        assert!(cache.has_positive_pin1());

        let checked_out = cache
            .checkout_pin1(
                &serial(CARD_A_SERIAL),
                PinReferenceScheme::Organizational,
                remaining(FINEID_PRISTINE),
            )
            .expect("matching serial, scheme, and pristine counter check out");
        assert!(checked_out.pin().to_pin1().is_ok());
        assert!(!cache.has_positive_pin1());
        assert!(checked_out.restore_after_unanswered(&mut cache));
        assert!(cache.has_positive_pin1());

        let checked_out = cache
            .checkout_pin1(
                &serial(CARD_A_SERIAL),
                PinReferenceScheme::Organizational,
                remaining(FINEID_PRISTINE),
            )
            .expect("restored PIN 1 checks out again");
        assert!(checked_out.restore_after_success(&mut cache));
        assert!(cache.has_positive_pin1());

        assert!(
            cache
                .checkout_pin1(
                    &serial(CARD_A_SERIAL),
                    PinReferenceScheme::Citizen,
                    remaining(FINEID_PRISTINE),
                )
                .is_none(),
            "a different scheme destroys the held PIN 1"
        );
        assert!(!cache.has_positive_pin1());
    }

    #[test]
    fn non_pristine_counter_or_card_swap_destroys_held_pin1() {
        let mut cache = PinSafetyCache::new().expect("cache constructs");
        cache
            .store_pin1(
                serial(CARD_A_SERIAL),
                PinReferenceScheme::Citizen,
                random_pin(),
            )
            .expect("fresh PIN 1 stores");
        assert!(
            cache
                .checkout_pin1(
                    &serial(CARD_A_SERIAL),
                    PinReferenceScheme::Citizen,
                    remaining(FINEID_SPENT),
                )
                .is_none()
        );
        assert!(!cache.has_positive_pin1());

        cache
            .store_pin1(
                serial(CARD_A_SERIAL),
                PinReferenceScheme::Citizen,
                random_pin(),
            )
            .expect("fresh PIN 1 stores");
        assert!(
            cache
                .checkout_pin1(
                    &serial(CARD_B_SERIAL),
                    PinReferenceScheme::Citizen,
                    remaining(FINEID_PRISTINE),
                )
                .is_none()
        );
        assert!(!cache.has_positive_pin1());
    }

    #[test]
    fn negative_cache_bars_retrying_rejected_pin_except_when_blocked() {
        let mut cache = PinSafetyCache::new().expect("cache constructs");
        let pin = random_pin();
        let card = serial(CARD_A_SERIAL);
        cache.record_rejected(&card, PinSlot::Pin2, &pin);

        assert!(cache.bars_presenting(
            &card,
            PinSlot::Pin2,
            &pin,
            remaining(FINEID_PRISTINE),
            PinReferenceScheme::Organizational,
        ));
        assert!(!cache.bars_presenting(
            &card,
            PinSlot::Pin2,
            &pin,
            PinStatus::Locked,
            PinReferenceScheme::Organizational,
        ));
        assert!(!cache.bars_presenting(
            &card,
            PinSlot::Pin2,
            &pin,
            remaining(ZERO_RETRIES),
            PinReferenceScheme::Organizational,
        ));

        let pin1 = random_pin();
        cache.record_rejected(&card, PinSlot::Pin1, &pin1);
        assert_eq!(
            cache.store_pin1(card, PinReferenceScheme::Citizen, pin1),
            Err(PreviouslyRejectedPin {
                slot: PinSlot::Pin1
            })
        );
    }

    #[test]
    fn reports_no_tries_left_and_estonian_pristine_scale() {
        assert!(reports_no_tries_left(
            PinStatus::Locked,
            PinReferenceScheme::Citizen
        ));
        assert!(reports_no_tries_left(
            remaining(ZERO_RETRIES),
            PinReferenceScheme::Estonian
        ));
        assert!(!reports_no_tries_left(
            remaining(ESTONIAN_PRISTINE),
            PinReferenceScheme::Estonian
        ));
        assert!(!reports_no_tries_left(
            PinStatus::Verified,
            PinReferenceScheme::Citizen
        ));

        let mut cache = PinSafetyCache::new().expect("cache constructs");
        cache
            .store_pin1(
                serial(CARD_A_SERIAL),
                PinReferenceScheme::Estonian,
                random_pin(),
            )
            .expect("Estonian PIN 1 stores");
        assert!(
            cache
                .checkout_pin1(
                    &serial(CARD_A_SERIAL),
                    PinReferenceScheme::Estonian,
                    remaining(ESTONIAN_PRISTINE),
                )
                .is_some()
        );
    }

    #[test]
    fn explicit_clear_positive_prevents_outstanding_checkout_restore_and_keeps_negative_memory() {
        let mut cache = PinSafetyCache::new().expect("cache constructs");
        let card = serial(CARD_A_SERIAL);
        let good_pin = random_pin();
        let bad_pin = random_pin();
        cache.record_rejected(&card, PinSlot::Pin1, &bad_pin);
        cache
            .store_pin1(card.clone(), PinReferenceScheme::Citizen, good_pin)
            .expect("fresh PIN 1 stores");

        let checked_out = cache
            .checkout_pin1(
                &card,
                PinReferenceScheme::Citizen,
                remaining(FINEID_PRISTINE),
            )
            .expect("checkout succeeds");
        // Simulates explicit deauthentication arriving while a checkout is live.
        cache.clear_positive();
        assert!(
            !checked_out.restore_after_success(&mut cache),
            "deauthentication generation bump must report failure on restore"
        );
        assert!(
            !cache.has_positive_pin1(),
            "deauthentication generation bump must prevent restoring an invalidated checkout"
        );
        assert!(
            cache.is_rejected(&card, PinSlot::Pin1, &bad_pin),
            "clear_positive must preserve process-lifetime negative retry memory"
        );

        let generation_before = cache.generation();
        cache.clear_positive();
        assert_eq!(
            cache.store_pin1_if_generation(
                card.clone(),
                PinReferenceScheme::Citizen,
                random_pin(),
                generation_before,
            ),
            Ok(false),
            "stale verification generation must not publish PIN 1 after concurrent invalidation"
        );
        assert!(!cache.has_positive_pin1());

        let current_generation = cache.generation();
        assert_eq!(
            cache.store_pin1_if_generation(
                card,
                PinReferenceScheme::Citizen,
                random_pin(),
                current_generation,
            ),
            Ok(true)
        );
        assert!(cache.has_positive_pin1());
    }
}
