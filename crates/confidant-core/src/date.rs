//! Civil-date helpers.
//!
//! Vault dates are strict `YYYY-MM-DD` civil dates: no time, no zone
//! (spec section 4). `jiff::civil::Date` is exactly that type. This module
//! is the single place the codebase reaches for a date library, so parsing,
//! "today", and day arithmetic have one definition each instead of every
//! call site re-deriving them.

pub use jiff::civil::Date;
use jiff::tz::TimeZone;

/// Today's civil date in UTC.
///
/// UTC, not the machine's local zone, is deliberate: `as_of` defaults and
/// `record --date` defaults were already UTC before this module existed, and
/// switching to local would move the answer across midnight depending on
/// where the operator is, changing check output for the same vault. A vault
/// date is a calendar date, not an instant.
pub fn today() -> Date {
    jiff::Timestamp::now()
        .to_zoned_datetime(TimeZone::UTC)
        .date()
}

/// Days from `from` to `to`: positive when `to` is later, negative when
/// earlier, zero when equal.
///
/// Infallible: `Date - Date` is a `Span` in days, and a span can represent
/// the difference between any two possible civil dates.
pub fn days_between(from: Date, to: Date) -> i64 {
    i64::from((to - from).get_days())
}

/// `date` shifted by `days`, which may be negative.
///
/// Panics only if the result leaves the civil calendar's range, which cannot
/// happen for a validated four-digit vault date and a cadence bounded by the
/// spec (at most 3650 days).
pub fn add_days(date: Date, days: i64) -> Date {
    let span = jiff::Span::new().days(days);
    date.checked_add(span)
        .expect("date arithmetic stays inside the civil calendar")
}

#[cfg(test)]
mod tests {
    use super::{add_days, days_between, today, Date};

    fn d(y: i16, m: i8, day: i8) -> Date {
        Date::new(y, m, day).expect("valid date")
    }

    #[test]
    fn days_between_is_signed() {
        assert_eq!(days_between(d(2026, 10, 1), d(2026, 10, 8)), 7);
        assert_eq!(days_between(d(2026, 10, 8), d(2026, 10, 1)), -7);
        assert_eq!(days_between(d(2026, 10, 8), d(2026, 10, 8)), 0);
    }

    #[test]
    fn days_between_crosses_month_and_leap_day() {
        assert_eq!(days_between(d(2026, 1, 31), d(2026, 2, 1)), 1);
        assert_eq!(days_between(d(2024, 2, 28), d(2024, 3, 1)), 2);
        assert_eq!(days_between(d(2026, 2, 28), d(2026, 3, 1)), 1);
    }

    #[test]
    fn add_days_handles_negative_and_month_end() {
        assert_eq!(add_days(d(2026, 10, 8), -7), d(2026, 10, 1));
        assert_eq!(add_days(d(2026, 1, 31), 1), d(2026, 2, 1));
        assert_eq!(add_days(d(2026, 10, 8), 0), d(2026, 10, 8));
    }

    #[test]
    fn today_is_a_real_civil_date() {
        // Pin nothing: this only proves the call path works and returns a
        // four-digit year, so the assertion cannot expire with the calendar.
        assert!((2020..=2100).contains(&today().year()));
    }
}
