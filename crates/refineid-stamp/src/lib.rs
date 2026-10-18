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

//! The build stamp: calendar version `YY.M.D.HHMM`, where `HHMM` is the
//! UTC time of day of the stamp as one number, `hour * 100 + minute`, 0 to
//! 2359.
//!
//! The build environment passes the stamp in `REFINEID_VERSION` so every
//! artifact of one build carries the same instant; without it the stamp is
//! the UTC clock when the build script runs, which Cargo reruns only when an
//! input changes, so a plain incremental build keeps its first stamp. Build
//! scripts call [`Stamp::from_build_environment`].

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// The environment variable the build environment passes the stamp in.
pub const ENV: &str = "REFINEID_VERSION";

/// One build instant as calendar version components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// Years since 2000.
    pub year: u8,
    /// Month of the year, 1 to 12.
    pub month: u8,
    /// Day of the month, 1 to 31.
    pub day: u8,
    /// Hour of the UTC day, 0 to 23.
    pub hour: u8,
    /// Minute of the hour, 0 to 59.
    pub minute: u8,
}

/// Minutes in an hour.
const MINUTES_PER_HOUR: u16 = 60;
/// Minutes in a day.
const MINUTES_PER_DAY: u16 = 24 * MINUTES_PER_HOUR;
/// Minutes in one step of the byte-sized time of day.
const MINUTES_PER_TIME_BYTE_STEP: u16 = 6;
/// The factor that places the hour before the minute in `HHMM`.
const HOUR_PLACE: u16 = 100;

impl Stamp {
    /// The stamp from `REFINEID_VERSION`, or the UTC clock when the
    /// variable is absent. Tells Cargo to rerun the build script when the
    /// variable changes.
    ///
    /// # Panics
    ///
    /// When `REFINEID_VERSION` is set but is not `YY.M.D.HHMM`.
    #[must_use]
    pub fn from_build_environment() -> Self {
        println!("cargo:rerun-if-env-changed={ENV}");
        std::env::var(ENV).map_or_else(
            |_| Self::now(),
            |text| {
                Self::parse(&text)
                    .unwrap_or_else(|| panic!("{ENV} must be YY.M.D.HHMM, found {text:?}"))
            },
        )
    }

    /// Parses `YY.M.D.HHMM`; the time may be written with or without its
    /// leading zero.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.trim().split('.');
        let year = parts.next()?.parse::<u8>().ok()?;
        let month = parts.next()?.parse::<u8>().ok()?;
        let day = parts.next()?.parse::<u8>().ok()?;
        let time = parts.next()?.parse::<u16>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        let hour = u8::try_from(time / HOUR_PLACE).ok()?;
        let minute = u8::try_from(time % HOUR_PLACE).ok()?;
        (u16::from(hour) < MINUTES_PER_DAY / MINUTES_PER_HOUR
            && u16::from(minute) < MINUTES_PER_HOUR)
            .then_some(Self {
                year,
                month,
                day,
                hour,
                minute,
            })
    }

    /// The time of day as one number, `hour * 100 + minute`.
    #[must_use]
    pub fn time_of_day(&self) -> u16 {
        u16::from(self.hour) * HOUR_PLACE + u16::from(self.minute)
    }

    /// The time of day in minutes since midnight, 0 to 1439.
    #[must_use]
    pub fn minute_of_day(&self) -> u16 {
        u16::from(self.hour) * MINUTES_PER_HOUR + u16::from(self.minute)
    }

    /// The time of day truncated to a byte for a field that holds no more:
    /// six-minute steps since midnight, 0 to 239.
    #[must_use]
    pub fn time_byte(&self) -> u8 {
        u8::try_from(self.minute_of_day() / MINUTES_PER_TIME_BYTE_STEP).unwrap_or(u8::MAX)
    }

    /// The stamp of the UTC clock now.
    ///
    /// # Panics
    ///
    /// When the system clock is before 2000 or after 2255.
    #[must_use]
    pub fn now() -> Self {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is after 1970")
            .as_secs();
        Self::from_unix_seconds(seconds)
    }

    fn from_unix_seconds(seconds: u64) -> Self {
        let days = i64::try_from(seconds / 86_400).expect("day count fits");
        let (year, month, day) = civil_from_days(days);
        let second_of_day = seconds % 86_400;
        let minute_of_day = second_of_day / u64::from(MINUTES_PER_HOUR);
        Self {
            year: u8::try_from(year - 2000).expect("year between 2000 and 2255"),
            month: u8::try_from(month).expect("month fits"),
            day: u8::try_from(day).expect("day fits"),
            hour: u8::try_from(minute_of_day / u64::from(MINUTES_PER_HOUR)).expect("hour fits"),
            minute: u8::try_from(minute_of_day % u64::from(MINUTES_PER_HOUR)).expect("minute fits"),
        }
    }
}

impl fmt::Display for Stamp {
    /// `YY.M.D.HHMM`, the time as one number without a leading zero, as
    /// every version field that carries it reads a plain integer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.year,
            self.month,
            self.day,
            self.time_of_day()
        )
    }
}

/// Proleptic Gregorian date of a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::Stamp;

    #[test]
    fn unix_seconds_give_calver_components() {
        assert_eq!(
            Stamp::from_unix_seconds(951_782_400).to_string(),
            "0.2.29.0"
        );
        assert_eq!(
            Stamp::from_unix_seconds(1_791_672_678).to_string(),
            "26.10.10.2251"
        );
        assert_eq!(
            Stamp::from_unix_seconds(4_102_444_799).to_string(),
            "99.12.31.2359"
        );
    }

    #[test]
    fn parse_accepts_four_components_with_a_time_of_day_only() {
        let stamp = Stamp {
            year: 26,
            month: 10,
            day: 10,
            hour: 9,
            minute: 5,
        };
        assert_eq!(Stamp::parse(" 26.10.10.905\n"), Some(stamp));
        assert_eq!(Stamp::parse("26.10.10.0905"), Some(stamp));
        assert_eq!(
            Stamp::parse("26.10.10.2359").map(|s| s.time_of_day()),
            Some(2359)
        );
        assert_eq!(Stamp::parse("26.10.10"), None);
        assert_eq!(Stamp::parse("26.10.10.905.1"), None);
        assert_eq!(Stamp::parse("26.10.10.2400"), None);
        assert_eq!(Stamp::parse("26.10.10.1260"), None);
        assert_eq!(Stamp::parse("1.0.0.0-beta"), None);
    }

    #[test]
    fn the_time_byte_counts_six_minute_steps() {
        let midnight = Stamp::parse("26.10.18.0").expect("parses");
        let late = Stamp::parse("26.10.18.2359").expect("parses");
        let noon = Stamp::parse("26.10.18.1200").expect("parses");
        assert_eq!(midnight.time_byte(), 0);
        assert_eq!(noon.time_byte(), 120);
        assert_eq!(late.time_byte(), 239);
        assert_eq!(late.minute_of_day(), 1439);
    }
}
