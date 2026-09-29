//! Converts Unix time into a calendar date and time. Done here rather than pulling in a date
//! library for this one job.
//!
//! The algorithm is Howard Hinnant's `civil_from_days` (public domain; the same one date
//! libraries use internally).
//! What breaks if you change it: there is no daylight saving handling here — the offset is a
//! fixed value from the configuration. Running somewhere with daylight saving needs a
//! rethink.

/// A local calendar date and time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

impl Civil {
    /// `unix_seconds` is seconds since the epoch in UTC; `offset_hours` is the local offset
    /// from UTC.
    pub fn from_unix(unix_seconds: i64, offset_hours: i32) -> Self {
        let local = unix_seconds + i64::from(offset_hours) * 3600;
        let days = local.div_euclid(86_400);
        let seconds_of_day = local.rem_euclid(86_400);

        let (year, month, day) = civil_from_days(days);
        Self {
            year,
            month,
            day,
            hour: (seconds_of_day / 3600) as u32,
            minute: ((seconds_of_day % 3600) / 60) as u32,
            second: (seconds_of_day % 60) as u32,
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

/// Converts days since the Unix epoch back into a calendar date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift the epoch to March 1st so the leap year rules become a regular 400-year cycle.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_itself() {
        let c = Civil::from_unix(0, 0);
        assert_eq!(c.date_string(), "1970-01-01");
        assert_eq!(c.timestamp_string(), "1970-01-01 00:00:00");
    }

    #[test]
    fn a_positive_offset_moves_the_clock_forward() {
        let c = Civil::from_unix(0, 8);
        assert_eq!(c.timestamp_string(), "1970-01-01 08:00:00");
    }

    #[test]
    fn crossing_midnight_rolls_over_to_the_next_day() {
        // 20:00 UTC on the epoch, plus eight hours, is 04:00 the next day.
        let c = Civil::from_unix(20 * 3600, 8);
        assert_eq!(c.date_string(), "1970-01-02");
        assert_eq!(c.hour, 4);
    }

    #[test]
    fn the_29th_of_february_in_a_leap_year() {
        let c = Civil::from_unix(1_709_208_000, 0);
        assert_eq!(c.date_string(), "2024-02-29");
        assert_eq!(c.hour, 12);
    }

    #[test]
    fn the_four_hundred_year_leap_rule() {
        // 1900 was not a leap year and 2000 was; this checks the conversion does not conflate
        // the two.
        let c = Civil::from_unix(951_868_800, 0);
        assert_eq!(c.date_string(), "2000-03-01");
    }

    #[test]
    fn dates_before_the_epoch_also_work() {
        let c = Civil::from_unix(-3600, 0);
        assert_eq!(c.date_string(), "1969-12-31");
        assert_eq!(c.hour, 23);
    }

    #[test]
    fn an_ordinary_date_with_an_offset() {
        let c = Civil::from_unix(1_789_388_676, 8);
        assert_eq!(c.date_string(), "2026-09-14");
        assert_eq!(c.timestamp_string(), "2026-09-14 20:24:36");
    }
}
