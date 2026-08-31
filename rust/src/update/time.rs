//! Canonical whole-second UTC timestamps used by update policy.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// Canonical RFC 3339 UTC timestamp in `YYYY-MM-DDTHH:MM:SSZ` form.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UtcTimestamp {
    seconds: u64,
    text: String,
}

impl UtcTimestamp {
    /// Parses one canonical whole-second UTC timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical representation, invalid civil date/time, leap second, or pre-epoch timestamp.
    pub fn parse(value: &str) -> Result<Self> {
        ensure!(
            value.len() == 20
                && value.as_bytes()[4] == b'-'
                && value.as_bytes()[7] == b'-'
                && value.as_bytes()[10] == b'T'
                && value.as_bytes()[13] == b':'
                && value.as_bytes()[16] == b':'
                && value.as_bytes()[19] == b'Z',
            "UTC timestamp must use canonical YYYY-MM-DDTHH:MM:SSZ form"
        );
        let year = decimal(value, 0, 4, "year")?;
        let month = decimal(value, 5, 7, "month")?;
        let day = decimal(value, 8, 10, "day")?;
        let hour = decimal(value, 11, 13, "hour")?;
        let minute = decimal(value, 14, 16, "minute")?;
        let second = decimal(value, 17, 19, "second")?;
        ensure!(
            (1970..=9999).contains(&year),
            "UTC year is outside 1970..=9999"
        );
        ensure!((1..=12).contains(&month), "UTC month is outside 1..=12");
        ensure!(
            (1..=days_in_month(year, month)).contains(&day),
            "UTC day is invalid for its month"
        );
        ensure!(hour <= 23, "UTC hour is outside 0..=23");
        ensure!(minute <= 59, "UTC minute is outside 0..=59");
        ensure!(second <= 59, "UTC second is outside 0..=59");
        let days = days_from_civil(year, month, day);
        ensure!(days >= 0, "UTC timestamp predates the Unix epoch");
        let days = u64::try_from(days).context("UTC day count exceeds supported range")?;
        let seconds = days
            .checked_mul(SECONDS_PER_DAY)
            .and_then(|value| value.checked_add(u64::from(hour) * 60 * 60))
            .and_then(|value| value.checked_add(u64::from(minute) * 60))
            .and_then(|value| value.checked_add(u64::from(second)))
            .context("UTC timestamp exceeds supported range")?;
        Ok(Self {
            seconds,
            text: value.to_owned(),
        })
    }

    /// Returns the current UTC system time, truncated to whole seconds.
    ///
    /// # Errors
    ///
    /// Returns an error if the system clock predates the Unix epoch or exceeds year 9999.
    pub fn now() -> Result<Self> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock predates the Unix epoch")?
            .as_secs();
        Self::from_unix_seconds(seconds)
    }

    /// Returns the canonical timestamp text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns whole seconds since the Unix epoch.
    #[must_use]
    pub fn unix_seconds(&self) -> u64 {
        self.seconds
    }

    /// Returns elapsed whole seconds from `earlier` to this timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when `earlier` is in the future.
    pub fn duration_since(&self, earlier: &Self) -> Result<u64> {
        self.seconds
            .checked_sub(earlier.seconds)
            .context("timestamp is in the future")
    }

    /// Adds an exact number of UTC days.
    ///
    /// # Errors
    ///
    /// Returns an error on arithmetic overflow or a result beyond year 9999.
    pub fn checked_add_days(&self, days: u64) -> Result<Self> {
        let seconds = days
            .checked_mul(SECONDS_PER_DAY)
            .and_then(|value| self.seconds.checked_add(value))
            .context("UTC day addition overflowed")?;
        Self::from_unix_seconds(seconds)
    }

    /// Converts Unix seconds to a UTC timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when the timestamp exceeds the supported year-9999 range.
    pub fn from_unix_seconds(seconds: u64) -> Result<Self> {
        let days = seconds / SECONDS_PER_DAY;
        let day_seconds = seconds % SECONDS_PER_DAY;
        let days = i64::try_from(days).context("UTC timestamp exceeds supported range")?;
        let (year, month, day) = civil_from_days(days);
        ensure!(year <= 9999, "UTC timestamp exceeds year 9999");
        let hour = day_seconds / (60 * 60);
        let minute = day_seconds % (60 * 60) / 60;
        let second = day_seconds % 60;
        let text = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z");
        Self::parse(&text)
    }
}

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

impl Serialize for UtcTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.text)
    }
}

impl<'de> Deserialize<'de> for UtcTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

fn decimal(value: &str, start: usize, end: usize, field: &str) -> Result<u32> {
    let bytes = &value.as_bytes()[start..end];
    ensure!(
        bytes.iter().all(u8::is_ascii_digit),
        "UTC {field} must contain only decimal digits"
    );
    value[start..end]
        .parse()
        .with_context(|| format!("parse UTC {field}"))
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    let mut year = i64::from(year);
    let month = i64::from(month);
    let day = i64::from(day);
    year -= i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (u32, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (
        u32::try_from(year).expect("supported UTC year is nonnegative"),
        u32::try_from(month).expect("civil month fits u32"),
        u32::try_from(day).expect("civil day fits u32"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_timestamp_round_trips_epoch_and_leap_dates() {
        for value in [
            "1970-01-01T00:00:00Z",
            "2000-02-29T23:59:59Z",
            "2026-08-23T19:57:36Z",
            "9999-12-31T23:59:59Z",
        ] {
            let timestamp = UtcTimestamp::parse(value).unwrap();
            assert_eq!(
                UtcTimestamp::from_unix_seconds(timestamp.seconds).unwrap(),
                timestamp
            );
            assert_eq!(
                serde_json::to_string(&timestamp).unwrap(),
                format!("\"{value}\"")
            );
        }
    }

    #[test]
    fn malformed_non_utc_and_noncanonical_timestamps_are_rejected() {
        for value in [
            "1969-12-31T23:59:59Z",
            "2023-02-29T00:00:00Z",
            "2024-02-30T00:00:00Z",
            "2024-01-01T24:00:00Z",
            "2024-01-01T00:00:60Z",
            "2024-01-01t00:00:00z",
            "2024-01-01T00:00:00+00:00",
            "2024-01-01T00:00:00.000Z",
        ] {
            assert!(UtcTimestamp::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn exact_day_boundaries_use_utc_seconds() {
        let published = UtcTimestamp::parse("2024-01-31T12:30:00Z").unwrap();
        let eligible = published.checked_add_days(30).unwrap();
        assert_eq!(eligible.as_str(), "2024-03-01T12:30:00Z");
        assert_eq!(
            eligible.duration_since(&published).unwrap(),
            30 * SECONDS_PER_DAY
        );
        let before = UtcTimestamp::from_unix_seconds(eligible.seconds - 1).unwrap();
        assert_eq!(
            before.duration_since(&published).unwrap(),
            30 * SECONDS_PER_DAY - 1
        );
        assert!(published.duration_since(&eligible).is_err());
    }
}
