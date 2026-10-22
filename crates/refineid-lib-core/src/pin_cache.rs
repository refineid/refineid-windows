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

//! Process-local PIN retry protection and the held PIN 1.
//!
//! A PIN 1 the card accepted is held in this process's memory, never in
//! storage, with no idle window or countdown (RAPP v26.10.22 section 11 item
//! 2). It ends when the card is removed or replaced (a checkout for another
//! card's serial), when the card rejects it or its retry counter reads below
//! pristine or unreadable, when the user clears it, and when the process
//! ends. A transport failure or an unanswered command keeps it: the retry
//! counter read before its next use decides whether the card refused it, and
//! a counter below pristine destroys it instead of sending it again. PIN 2 is
//! never held: it is entered for every signature or batch.
//!
//! A PIN 1 or PIN 2 value rejected by a card is remembered until process exit
//! and refused locally thereafter, so software cannot burn another card retry
//! with the same value. Rejected values are represented only by a fingerprint
//! keyed with fresh process-local random material; raw PIN bytes are never
//! retained by the negative cache.

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::auth::{PinSlot, PinStatus};
use crate::identity::TokenSerial;
use crate::pin::PinBytes;
use crate::pin_retry_risk::pin1_status_permits_reusable_cache;

/// How long a PIN 1 entry is held.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pin1Retention {
    /// Held until an invalidation event.
    Reusable,
    /// Held for one operation only: the counter was below pristine when the
    /// PIN was entered.
    OneShot,
}

/// A previously card-rejected PIN was offered again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreviouslyRejectedPin {
    /// Slot for which the PIN was rejected.
    pub slot: PinSlot,
}

impl core::fmt::Display for PreviouslyRejectedPin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let label = match self.slot {
            PinSlot::Pin1 => "PIN1",
            PinSlot::Pin2 => "PIN2",
        };
        write!(f, "{label} was previously rejected by the card")
    }
}

impl core::error::Error for PreviouslyRejectedPin {}

struct HeldPin1 {
    serial: TokenSerial,
    pin: PinBytes,
    generation: u64,
    retention: Pin1Retention,
}

/// Destructively checked-out PIN 1 for one live card serial.
///
/// Dropping this value destroys the PIN. It returns to the held state only
/// through [`Self::restore_after_success`], once the card has accepted it,
/// or [`Self::restore_after_unanswered`], when the attempt's answer was lost.
pub struct CheckedOutPin1 {
    entry: HeldPin1,
}

impl CheckedOutPin1 {
    /// Borrow the PIN for the single VERIFY associated with this checkout.
    #[must_use]
    pub const fn pin(&self) -> &PinBytes {
        &self.entry.pin
    }

    /// Hold this PIN again after the card accepted it; a one-operation PIN
    /// is destroyed instead. Concurrent or intervening invalidation wins.
    pub fn restore_after_success(self, cache: &mut PinSafetyCache) {
        if self.entry.retention == Pin1Retention::OneShot {
            return;
        }
        self.restore(cache);
    }

    /// Hold this PIN again after a transport failure or an unanswered
    /// command: the card may not have seen it, and the retry counter read
    /// before its next use decides (see [`PinSafetyCache::checkout_pin1`]).
    /// Concurrent or intervening invalidation wins.
    pub fn restore_after_unanswered(self, cache: &mut PinSafetyCache) {
        self.restore(cache);
    }

    fn restore(self, cache: &mut PinSafetyCache) {
        if cache.generation != self.entry.generation || cache.held_pin1.is_some() {
            return;
        }
        cache.held_pin1 = Some(self.entry);
    }
}

impl core::fmt::Debug for CheckedOutPin1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CheckedOutPin1")
            .field("serial", &self.entry.serial)
            .finish_non_exhaustive()
    }
}

/// Opaque keyed mark for one rejected PIN value.
#[derive(Zeroize)]
struct RejectedPinFingerprint([u8; 32]);

/// The held PIN 1 plus process-lifetime negative PIN 1 and PIN 2 memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinSafetyCache {
    #[zeroize(skip)]
    held_pin1: Option<HeldPin1>,
    #[zeroize(skip)]
    generation: u64,
    fingerprint_key: [u8; 32],
    rejected_pin1: Vec<RejectedPinFingerprint>,
    rejected_pin2: Vec<RejectedPinFingerprint>,
}

impl PinSafetyCache {
    /// Construct an empty cache with a fresh process-local fingerprint key.
    ///
    /// # Errors
    /// Returns the OS random-source failure rather than creating a predictable
    /// rejection fingerprint key.
    pub fn new() -> Result<Self, crate::rng::Failure> {
        Ok(Self {
            held_pin1: None,
            generation: 0,
            fingerprint_key: crate::rng::array()?,
            rejected_pin1: Vec::new(),
            rejected_pin2: Vec::new(),
        })
    }

    /// Hold a just-verified PIN 1 until an invalidation event.
    ///
    /// # Errors
    /// Refuses a value that this process has already seen the card reject.
    pub fn store_pin1(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
    ) -> Result<(), PreviouslyRejectedPin> {
        self.hold_pin1(serial, pin, Pin1Retention::Reusable)
    }

    /// Hold a just-verified PIN 1 for exactly one checkout: the counter was
    /// below pristine when it was entered. This bridges PKCS #11 `C_Login`
    /// to the operation that follows without holding the PIN beyond it.
    ///
    /// # Errors
    /// Refuses a value that this process has already seen the card reject.
    pub fn stage_pin1_once(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
    ) -> Result<(), PreviouslyRejectedPin> {
        self.hold_pin1(serial, pin, Pin1Retention::OneShot)
    }

    /// Destructively check out the held PIN 1 for the freshly read live
    /// serial and PIN 1 state. Another card's serial destroys it (the card
    /// was replaced), and so does a state that is neither verified nor a
    /// pristine retry counter: the card refused a PIN since, possibly this
    /// one on an attempt whose answer was lost, or tells nothing. With
    /// nothing held, nothing is invalidated: a checkout in flight elsewhere
    /// still restores.
    pub fn checkout_pin1(
        &mut self,
        live_serial: &TokenSerial,
        live_status: PinStatus,
    ) -> Option<CheckedOutPin1> {
        let entry = self.held_pin1.take()?;
        if entry.serial == *live_serial && permits_held_pin1(live_status) {
            return Some(CheckedOutPin1 { entry });
        }
        drop(entry);
        self.clear_positive();
        None
    }

    /// Whether a PIN 1 is held. This does not expose the secret or authorize
    /// card use; checkout still requires a freshly read matching full serial
    /// and PIN 1 state.
    #[must_use]
    pub const fn has_positive_pin1(&self) -> bool {
        self.held_pin1.is_some()
    }

    /// Destroy the held PIN 1 without weakening process-lifetime rejection
    /// memory: the card was removed, or the user cleared it.
    pub fn clear_positive(&mut self) {
        self.held_pin1 = None;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Whether `pin` has already been rejected by the card for `slot`.
    #[must_use]
    pub fn is_rejected(&self, serial: &TokenSerial, slot: PinSlot, pin: &PinBytes) -> bool {
        let candidate = self.fingerprint(serial, slot, pin);
        self.rejected(slot)
            .iter()
            .any(|known| bool::from(known.0.ct_eq(&candidate.0)))
    }

    /// Record a card-side wrong-PIN response for the rest of this process.
    /// Also destroys the held PIN 1, because the card's authentication state
    /// is now known to have changed.
    pub fn record_rejected(&mut self, serial: &TokenSerial, slot: PinSlot, pin: &PinBytes) {
        self.clear_positive();
        let fingerprint = self.fingerprint(serial, slot, pin);
        let rejected = self.rejected_mut(slot);
        if !rejected
            .iter()
            .any(|known| bool::from(known.0.ct_eq(&fingerprint.0)))
        {
            rejected.push(fingerprint);
        }
    }

    fn hold_pin1(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
        retention: Pin1Retention,
    ) -> Result<(), PreviouslyRejectedPin> {
        if self.is_rejected(&serial, PinSlot::Pin1, &pin) {
            return Err(PreviouslyRejectedPin {
                slot: PinSlot::Pin1,
            });
        }
        self.clear_positive();
        self.held_pin1 = Some(HeldPin1 {
            serial,
            pin,
            generation: self.generation,
            retention,
        });
        Ok(())
    }

    fn fingerprint(
        &self,
        serial: &TokenSerial,
        slot: PinSlot,
        pin: &PinBytes,
    ) -> RejectedPinFingerprint {
        let slot_tag = match slot {
            PinSlot::Pin1 => 1_u8,
            PinSlot::Pin2 => 2_u8,
        };
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.fingerprint_key) else {
            // A fixed 32-byte HMAC-SHA-256 key is valid. Fail closed if
            // that invariant ever changes: all values then share one mark
            // and are refused after the first rejection, never replayed.
            return RejectedPinFingerprint([0_u8; 32]);
        };
        let Ok(digit_count) = u8::try_from(pin.digit_count()) else {
            return RejectedPinFingerprint([0_u8; 32]);
        };
        let Ok(serial_len) = u32::try_from(serial.as_str().len()) else {
            return RejectedPinFingerprint([0_u8; 32]);
        };
        mac.update(&serial_len.to_be_bytes());
        mac.update(serial.as_str().as_bytes());
        mac.update(&[slot_tag]);
        mac.update(&[digit_count]);
        mac.update(pin.as_bytes());
        RejectedPinFingerprint(mac.finalize().into_bytes().into())
    }

    fn rejected(&self, slot: PinSlot) -> &[RejectedPinFingerprint] {
        match slot {
            PinSlot::Pin1 => &self.rejected_pin1,
            PinSlot::Pin2 => &self.rejected_pin2,
        }
    }

    const fn rejected_mut(&mut self, slot: PinSlot) -> &mut Vec<RejectedPinFingerprint> {
        match slot {
            PinSlot::Pin1 => &mut self.rejected_pin1,
            PinSlot::Pin2 => &mut self.rejected_pin2,
        }
    }
}

/// Whether the live PIN 1 state lets a held PIN 1 be presented again: the
/// card holds PIN 1 verified, or its retry counter is pristine.
const fn permits_held_pin1(live: PinStatus) -> bool {
    matches!(live, PinStatus::Verified) || pin1_status_permits_reusable_cache(live)
}

impl core::fmt::Debug for PinSafetyCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinSafetyCache")
            .field("held_pin1", &self.held_pin1.is_some())
            .field("generation", &self.generation)
            .field("rejected_pin1_count", &self.rejected_pin1.len())
            .field("rejected_pin2_count", &self.rejected_pin2.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::status_word::PinRetries;

    /// The retry count of a FINEID PIN no one has mistyped.
    const PRISTINE_RETRIES: u8 = 5;

    fn pin<const N: usize>(digits: &[u8; N]) -> PinBytes {
        PinBytes::try_from(*digits).expect("valid test PIN")
    }

    fn serial(value: &str) -> TokenSerial {
        TokenSerial::new(value.to_owned())
    }

    fn remaining(retries: u8) -> PinStatus {
        PinStatus::Remaining(PinRetries::from_nibble(retries).expect("a retry count"))
    }

    fn pristine() -> PinStatus {
        remaining(PRISTINE_RETRIES)
    }

    fn cache() -> PinSafetyCache {
        PinSafetyCache {
            held_pin1: None,
            generation: 0,
            fingerprint_key: *b"synthetic PIN fingerprint key 32",
            rejected_pin1: Vec::new(),
            rejected_pin2: Vec::new(),
        }
    }

    fn holding(card: &TokenSerial) -> PinSafetyCache {
        let mut cache = cache();
        cache
            .store_pin1(card.clone(), pin(b"1357"))
            .expect("fresh PIN is accepted");
        cache
    }

    #[test]
    fn a_held_pin1_serves_every_use_with_no_window() {
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = holding(&card);
        for status in [pristine(), PinStatus::Verified, pristine()] {
            let checkout = cache
                .checkout_pin1(&card, status)
                .expect("the held PIN serves again");
            checkout.restore_after_success(&mut cache);
        }
        assert!(cache.has_positive_pin1());
    }

    #[test]
    fn an_unanswered_attempt_keeps_the_pin_for_a_pristine_counter() {
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = holding(&card);
        let checkout = cache.checkout_pin1(&card, pristine()).expect("held");
        checkout.restore_after_unanswered(&mut cache);
        assert!(cache.checkout_pin1(&card, pristine()).is_some());
    }

    #[test]
    fn a_counter_below_pristine_destroys_the_pin_instead_of_sending_it() {
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = holding(&card);
        let checkout = cache.checkout_pin1(&card, pristine()).expect("held");
        checkout.restore_after_unanswered(&mut cache);
        assert!(
            cache
                .checkout_pin1(&card, remaining(PRISTINE_RETRIES - 1))
                .is_none()
        );
        assert!(!cache.has_positive_pin1());
    }

    #[test]
    fn an_unreadable_counter_destroys_the_pin() {
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = holding(&card);
        assert!(cache.checkout_pin1(&card, PinStatus::NoInfo).is_none());
        assert!(!cache.has_positive_pin1());
    }

    #[test]
    fn clearing_positive_preserves_negative_memory() {
        let mut cache = cache();
        let card = serial("CARD-A-FULL-SERIAL");
        let rejected = pin(b"1357");
        cache.record_rejected(&card, PinSlot::Pin1, &rejected);
        cache.clear_positive();
        assert!(cache.is_rejected(&card, PinSlot::Pin1, &rejected));
    }

    #[test]
    fn rejection_is_bound_to_slot_and_value() {
        let mut cache = cache();
        let card = serial("CARD-A-FULL-SERIAL");
        let rejected = pin(b"135790");
        cache.record_rejected(&card, PinSlot::Pin2, &rejected);
        assert!(cache.is_rejected(&card, PinSlot::Pin2, &rejected));
        assert!(!cache.is_rejected(&card, PinSlot::Pin1, &rejected));
        assert!(!cache.is_rejected(&card, PinSlot::Pin2, &pin(b"246802")));
    }

    #[test]
    fn rejected_pin1_cannot_be_held() {
        let mut cache = cache();
        let card = serial("CARD-A-FULL-SERIAL");
        let rejected = pin(b"1357");
        cache.record_rejected(&card, PinSlot::Pin1, &rejected);
        assert_eq!(
            cache.store_pin1(card, rejected),
            Err(PreviouslyRejectedPin {
                slot: PinSlot::Pin1
            })
        );
    }

    #[test]
    fn a_replaced_card_destroys_the_held_pin() {
        let card_a = serial("CARD-A-FULL-SERIAL");
        let card_b = serial("CARD-B-FULL-SERIAL");
        let mut cache = holding(&card_a);
        assert!(cache.checkout_pin1(&card_b, pristine()).is_none());
        assert!(cache.checkout_pin1(&card_a, pristine()).is_none());
    }

    #[test]
    fn rejection_is_bound_to_full_serial() {
        let card_a = serial("CARD-A-FULL-SERIAL");
        let card_b = serial("CARD-B-FULL-SERIAL");
        let rejected = pin(b"1357");
        let mut cache = cache();
        cache.record_rejected(&card_a, PinSlot::Pin1, &rejected);
        assert!(cache.is_rejected(&card_a, PinSlot::Pin1, &rejected));
        assert!(!cache.is_rejected(&card_b, PinSlot::Pin1, &rejected));
    }

    #[test]
    fn checkout_drop_does_not_restore_entry() {
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = holding(&card);
        let checkout = cache
            .checkout_pin1(&card, pristine())
            .expect("entry can be checked out once");
        drop(checkout);
        assert!(cache.checkout_pin1(&card, pristine()).is_none());
    }

    #[test]
    fn one_shot_pin1_is_destroyed_after_successful_checkout() {
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = cache();
        cache
            .stage_pin1_once(card.clone(), pin(b"1357"))
            .expect("fresh PIN is accepted");
        let checkout = cache
            .checkout_pin1(&card, PinStatus::Verified)
            .expect("one-shot entry permits one checkout");
        checkout.restore_after_success(&mut cache);
        assert!(cache.checkout_pin1(&card, PinStatus::Verified).is_none());
    }

    #[test]
    fn a_checkout_finding_nothing_held_leaves_one_in_flight_to_restore() {
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = holding(&card);
        let in_flight = cache.checkout_pin1(&card, pristine()).expect("held");
        assert!(cache.checkout_pin1(&card, pristine()).is_none());
        in_flight.restore_after_success(&mut cache);
        assert!(cache.has_positive_pin1());
    }

    #[test]
    fn invalidation_prevents_checked_out_entry_resurrection() {
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = holding(&card);
        let checkout = cache
            .checkout_pin1(&card, pristine())
            .expect("entry can be checked out");
        cache.clear_positive();
        checkout.restore_after_unanswered(&mut cache);
        assert!(cache.checkout_pin1(&card, pristine()).is_none());
    }
}
