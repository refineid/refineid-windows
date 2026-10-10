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

//! The build stamp: calendar version `YY.M.D.B`, where `B` is the
//! ten-minute bucket of the UTC day (hour * 10 + minute / 10, 0 to 235).
//!
//! The build environment passes the stamp in `REFINEID_VERSION` so every
//! artifact of one build carries the same instant; without it the stamp is
//! the UTC clock when the build script runs. Build scripts call
//! [`Stamp::from_build_environment`].

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
    /// Ten-minute bucket of the day, 0 to 235.
    pub bucket: u8,
}

impl Stamp {
    /// The stamp from `REFINEID_VERSION`, or the UTC clock when the
    /// variable is absent. Tells Cargo to rerun the build script when the
    /// variable changes.
    ///
    /// # Panics
    ///
    /// When `REFINEID_VERSION` is set but is not `YY.M.D.B`.
    #[must_use]
    pub fn from_build_environment() -> Self {
        println!("cargo:rerun-if-env-changed={ENV}");
        std::env::var(ENV).map_or_else(
            |_| Self::now(),
            |text| {
                Self::parse(&text)
                    .unwrap_or_else(|| panic!("{ENV} must be YY.M.D.B, found {text:?}"))
            },
        )
    }

    /// Parses `YY.M.D.B`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.trim().split('.').map(|part| part.parse::<u8>().ok());
        let stamp = Self {
            year: parts.next()??,
            month: parts.next()??,
            day: parts.next()??,
            bucket: parts.next()??,
        };
        parts.next().is_none().then_some(stamp)
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
        let bucket = (second_of_day / 3_600) * 10 + (second_of_day % 3_600) / 600;
        Self {
            year: u8::try_from(year - 2000).expect("year between 2000 and 2255"),
            month: u8::try_from(month).expect("month fits"),
            day: u8::try_from(day).expect("day fits"),
            bucket: u8::try_from(bucket).expect("bucket below 236"),
        }
    }
}

impl fmt::Display for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.year, self.month, self.day, self.bucket
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
            "26.10.10.225"
        );
        assert_eq!(
            Stamp::from_unix_seconds(4_102_444_799).to_string(),
            "99.12.31.235"
        );
    }

    #[test]
    fn parse_accepts_four_components_only() {
        assert_eq!(
            Stamp::parse(" 26.10.10.205\n"),
            Some(Stamp {
                year: 26,
                month: 10,
                day: 10,
                bucket: 205
            })
        );
        assert_eq!(Stamp::parse("26.10.10"), None);
        assert_eq!(Stamp::parse("26.10.10.205.1"), None);
        assert_eq!(Stamp::parse("26.10.10.300"), None);
        assert_eq!(Stamp::parse("1.0.0.0-beta"), None);
    }
}
