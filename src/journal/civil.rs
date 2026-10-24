//! Converts Unix time into local calendar dates and times in the Mac's own time zone, so
//! daylight saving and offsets that are not whole hours come out right.
//!
//! What breaks if you change it: journal file names, the nightly cleanup and the weekly
//! archive all take their dates from here. They must all use the same `LocalZone`, or a
//! query can land in one day's file and be cleaned up as if it belonged to another.

use jiff::civil::Date;
use jiff::tz::TimeZone;
use jiff::{Timestamp, ToSpan, Zoned};

/// The time zone every journal date and timestamp is expressed in.
#[derive(Clone, Debug)]
pub struct LocalZone(TimeZone);

impl LocalZone {
    /// The zone macOS is set to (System Settings → General → Date & Time), with its daylight
    /// saving rules. Errors when the system zone cannot be read.
    pub fn system() -> Result<Self, jiff::Error> {
        TimeZone::try_system().map(Self)
    }

    /// UTC: the fallback when the system zone cannot be read.
    pub fn utc() -> Self {
        Self(TimeZone::UTC)
    }

    /// The zone's IANA name, such as `Europe/London`.
    pub fn name(&self) -> &str {
        self.0.iana_name().unwrap_or("an unnamed zone")
    }

    /// The local calendar date at `unix_seconds`.
    pub fn date_of(&self, unix_seconds: i64) -> Date {
        self.zoned(unix_seconds).date()
    }

    /// The local calendar date `days` days before the one at `unix_seconds`. Counts calendar
    /// days, so a day shortened or lengthened by a daylight saving change still counts once.
    pub fn days_before(&self, unix_seconds: i64, days: i64) -> Date {
        self.date_of(unix_seconds).saturating_sub(days.days())
    }

    fn zoned(&self, unix_seconds: i64) -> Zoned {
        // The clamp keeps the value inside jiff's range (years -9999 to 9999), so the
        // conversion cannot fail; the system clock never leaves that range.
        let seconds = unix_seconds.clamp(Timestamp::MIN.as_second(), Timestamp::MAX.as_second());
        Timestamp::from_second(seconds)
            .unwrap_or(Timestamp::UNIX_EPOCH)
            .to_zoned(self.0.clone())
    }

    #[cfg(test)]
    pub fn fixed_hours(hours: i8) -> Self {
        Self(TimeZone::fixed(jiff::tz::offset(hours)))
    }

    #[cfg(test)]
    pub fn named(name: &str) -> Self {
        Self(TimeZone::get(name).expect("the zoneinfo database has this zone"))
    }
}

/// A local calendar date and time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

impl Civil {
    /// `unix_seconds` is seconds since the epoch in UTC, shown in `zone`.
    pub fn from_unix(unix_seconds: i64, zone: &LocalZone) -> Self {
        let local = zone.zoned(unix_seconds);
        Self {
            year: i64::from(local.year()),
            month: u32::from(local.month().unsigned_abs()),
            day: u32::from(local.day().unsigned_abs()),
            hour: u32::from(local.hour().unsigned_abs()),
            minute: u32::from(local.minute().unsigned_abs()),
            second: u32::from(local.second().unsigned_abs()),
        }
    }

    /// `YYYY-MM-DD`, used as the name of each day's journal file.
    pub fn date_string(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// `YYYY-MM-DD HH:MM:SS`, the timestamp column in the journal.
    pub fn timestamp_string(&self) -> String {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_itself() {
        let c = Civil::from_unix(0, &LocalZone::utc());
        assert_eq!(c.date_string(), "1970-01-01");
        assert_eq!(c.timestamp_string(), "1970-01-01 00:00:00");
    }

    #[test]
    fn a_positive_offset_moves_the_clock_forward() {
        let c = Civil::from_unix(0, &LocalZone::fixed_hours(8));
        assert_eq!(c.timestamp_string(), "1970-01-01 08:00:00");
    }

    #[test]
    fn crossing_midnight_rolls_over_to_the_next_day() {
        // `20:00` UTC on the epoch, plus eight hours, is `04:00` the next day.
        let c = Civil::from_unix(20 * 3600, &LocalZone::fixed_hours(8));
        assert_eq!(c.date_string(), "1970-01-02");
        assert_eq!(c.hour, 4);
    }

    #[test]
    fn the_29th_of_february_in_a_leap_year() {
        let c = Civil::from_unix(1_709_208_000, &LocalZone::utc());
        assert_eq!(c.date_string(), "2024-02-29");
        assert_eq!(c.hour, 12);
    }

    #[test]
    fn the_four_hundred_year_leap_rule() {
        // `1900` was not a leap year and `2000` was; this checks the conversion does not
        // conflate the two.
        let c = Civil::from_unix(951_868_800, &LocalZone::utc());
        assert_eq!(c.date_string(), "2000-03-01");
    }

    #[test]
    fn dates_before_the_epoch_also_work() {
        let c = Civil::from_unix(-3600, &LocalZone::utc());
        assert_eq!(c.date_string(), "1969-12-31");
        assert_eq!(c.hour, 23);
    }

    #[test]
    fn an_ordinary_date_with_an_offset() {
        let c = Civil::from_unix(1_789_388_676, &LocalZone::fixed_hours(8));
        assert_eq!(c.date_string(), "2026-09-14");
        assert_eq!(c.timestamp_string(), "2026-09-14 20:24:36");
    }

    #[test]
    fn the_clock_jumps_forward_when_daylight_saving_starts() {
        // New York switches from EST to EDT at `2026-03-08 02:00` local, which is
        // `07:00` UTC (`1_772_953_200`): one second before, the clock reads `01:59:59`.
        let new_york = LocalZone::named("America/New_York");
        assert_eq!(
            Civil::from_unix(1_772_953_199, &new_york).timestamp_string(),
            "2026-03-08 01:59:59"
        );
        assert_eq!(
            Civil::from_unix(1_772_953_200, &new_york).timestamp_string(),
            "2026-03-08 03:00:00"
        );
    }

    #[test]
    fn an_offset_that_is_not_a_whole_hour() {
        let c = Civil::from_unix(0, &LocalZone::named("Asia/Kolkata"));
        assert_eq!(c.timestamp_string(), "1970-01-01 05:30:00");
    }

    #[test]
    fn days_before_counts_calendar_days_across_a_daylight_saving_change() {
        // `2026-03-09 00:30` EDT is `1_773_030_600`. The day before is only 23 hours long, so
        // going back 86 400 seconds lands on `2026-03-07 23:30` EST and skips a day; one
        // calendar day back must be `2026-03-08`.
        let new_york = LocalZone::named("America/New_York");
        assert_eq!(new_york.date_of(1_773_030_600).to_string(), "2026-03-09");
        assert_eq!(
            new_york.days_before(1_773_030_600, 1).to_string(),
            "2026-03-08"
        );
    }
}
