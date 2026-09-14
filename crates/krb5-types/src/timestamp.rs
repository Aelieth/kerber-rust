//! `krb5_string_to_timestamp` (`lib/krb5/krb/str_conv.c:146-196`).
//!
//! MIT tries a fixed `strptime` format table against the string, in order,
//! over a `struct tm` seeded from `localtime(now)` (so a time-only form is
//! *today* at that time and a form without `%S` keeps now's seconds), skips a parse that leaves anything but whitespace
//! behind or a year at or before 1900 (`tm_year <= 0`), and converts the
//! first hit with `mktime` — local time. The locale-dependent `%x:%X` entry
//! is skipped here (MIT's comment: "not really supported unless native
//! strptime present"). Digit fields are the fixed widths the formats spell
//! out; `%b` is the C-locale three-letter month, case-insensitive.

use chrono::{Datelike, Local, NaiveDate, NaiveDateTime, TimeZone, Timelike};

/// `atime_format_table` (`str_conv.c:152-165`) minus `%x:%X`.
const FORMATS: &[&str] = &[
    "%Y%m%d%H%M%S",
    "%Y.%m.%d.%H.%M.%S",
    "%y%m%d%H%M%S",
    "%y.%m.%d.%H.%M.%S",
    "%y%m%d%H%M",
    "%H%M%S",
    "%H%M",
    "%T",
    "%R",
    "%d-%b-%Y:%T",
    "%d-%b-%Y:%R",
];

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Parse a MIT absolute-time string to Unix seconds in the local zone.
///
/// `None` is MIT's `EINVAL`.
#[must_use]
pub fn string_to_timestamp(s: &str) -> Option<u32> {
    string_to_timestamp_at(s, Local::now().naive_local())
}

/// [`string_to_timestamp`] with an explicit "now" for the time-only forms.
#[must_use]
pub fn string_to_timestamp_at(s: &str, now: NaiveDateTime) -> Option<u32> {
    let s = s.trim_end_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    if s.is_empty() {
        return None;
    }
    for fmt in FORMATS {
        let Some(ndt) = parse_with(s, fmt, now) else {
            continue;
        };
        if ndt.year() <= 1900 {
            continue;
        }
        let local = Local
            .from_local_datetime(&ndt)
            .earliest()
            .or_else(|| Local.from_local_datetime(&ndt).latest());
        if let Some(t) = local {
            return Some(wrap_ts(t.timestamp()));
        }
    }
    None
}

/// MIT stores `mktime`'s `time_t` in a `krb5_timestamp` (int32) that the
/// 1.22 code reads back as unsigned (`ts2tt`): the low 32 bits.
fn wrap_ts(t: i64) -> u32 {
    u32::try_from(t.rem_euclid(1 << 32)).unwrap_or(0)
}

/// One `strptime` pass over `fmt`; `None` unless the whole string is consumed.
fn parse_with(s: &str, fmt: &str, now: NaiveDateTime) -> Option<NaiveDateTime> {
    let b = s.as_bytes();
    let mut i = 0;
    let (mut year, mut month, mut day) = (now.year(), now.month(), now.day());
    let (mut hour, mut min, mut sec) = (now.hour(), now.minute(), now.second());
    let mut f = fmt.bytes();
    while let Some(c) = f.next() {
        if c != b'%' {
            if b.get(i) != Some(&c) {
                return None;
            }
            i += 1;
            continue;
        }
        match f.next()? {
            b'Y' => year = i32::try_from(digits(b, &mut i, 4)?).ok()?,
            b'y' => {
                let yy = digits(b, &mut i, 2)?;
                // POSIX: 69–99 → 1969–1999, 00–68 → 2000–2068.
                year = i32::try_from(if yy >= 69 { 1900 + yy } else { 2000 + yy }).ok()?;
            }
            b'm' => month = digits(b, &mut i, 2)?,
            b'd' => day = digits(b, &mut i, 2)?,
            b'H' => hour = digits(b, &mut i, 2)?,
            b'M' => min = digits(b, &mut i, 2)?,
            b'S' => sec = digits(b, &mut i, 2)?,
            b'T' => {
                hour = digits(b, &mut i, 2)?;
                lit(b, &mut i, b':')?;
                min = digits(b, &mut i, 2)?;
                lit(b, &mut i, b':')?;
                sec = digits(b, &mut i, 2)?;
            }
            b'R' => {
                hour = digits(b, &mut i, 2)?;
                lit(b, &mut i, b':')?;
                min = digits(b, &mut i, 2)?;
            }
            b'b' => {
                let name = b.get(i..i + 3)?;
                let lower = name.to_ascii_lowercase();
                let idx = MONTHS.iter().position(|m| m.as_bytes() == lower)?;
                month = u32::try_from(idx).ok()? + 1;
                i += 3;
            }
            _ => return None,
        }
    }
    if i != b.len() {
        return None;
    }
    NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, min, sec)
}

fn digits(b: &[u8], i: &mut usize, width: usize) -> Option<u32> {
    let chunk = b.get(*i..*i + width)?;
    if !chunk.iter().all(u8::is_ascii_digit) {
        return None;
    }
    *i += width;
    chunk.iter().try_fold(0u32, |acc, d| {
        acc.checked_mul(10)?.checked_add(u32::from(d - b'0'))
    })
}

fn lit(b: &[u8], i: &mut usize, c: u8) -> Option<()> {
    if b.get(*i) == Some(&c) {
        *i += 1;
        Some(())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 9, 13)
            .unwrap()
            .and_hms_opt(19, 42, 7)
            .unwrap()
    }

    fn local(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> u32 {
        let ndt = NaiveDate::from_ymd_opt(y, mo, d)
            .unwrap()
            .and_hms_opt(h, mi, s)
            .unwrap();
        wrap_ts(
            Local
                .from_local_datetime(&ndt)
                .earliest()
                .unwrap()
                .timestamp(),
        )
    }

    #[test]
    fn full_date_time_forms_parse_in_table_order() {
        let want = local(2030, 1, 2, 3, 4, 5);
        assert_eq!(string_to_timestamp_at("20300102030405", now()), Some(want));
        assert_eq!(
            string_to_timestamp_at("2030.01.02.03.04.05", now()),
            Some(want)
        );
        assert_eq!(string_to_timestamp_at("300102030405", now()), Some(want));
        assert_eq!(
            string_to_timestamp_at("30.01.02.03.04.05", now()),
            Some(want)
        );
        // No `%S`: MIT keeps `localtime(now)`'s tm_sec (7 here).
        assert_eq!(
            string_to_timestamp_at("3001020304", now()),
            Some(local(2030, 1, 2, 3, 4, 7))
        );
        assert_eq!(
            string_to_timestamp_at("02-Jan-2030:03:04:05", now()),
            Some(want)
        );
        assert_eq!(
            string_to_timestamp_at("02-jan-2030:03:04", now()),
            Some(local(2030, 1, 2, 3, 4, 7))
        );
    }

    #[test]
    fn time_only_forms_are_today_at_that_time() {
        assert_eq!(
            string_to_timestamp_at("235959", now()),
            Some(local(2026, 9, 13, 23, 59, 59))
        );
        assert_eq!(
            string_to_timestamp_at("2359", now()),
            Some(local(2026, 9, 13, 23, 59, 7))
        );
        assert_eq!(
            string_to_timestamp_at("23:59:59", now()),
            Some(local(2026, 9, 13, 23, 59, 59))
        );
        assert_eq!(
            string_to_timestamp_at("23:59", now()),
            Some(local(2026, 9, 13, 23, 59, 7))
        );
    }

    #[test]
    fn posix_two_digit_years_split_at_69() {
        assert_eq!(
            string_to_timestamp_at("690102030405", now()),
            Some(local(1969, 1, 2, 3, 4, 5))
        );
        assert_eq!(
            string_to_timestamp_at("680102030405", now()),
            Some(local(2068, 1, 2, 3, 4, 5))
        );
    }

    #[test]
    fn trailing_whitespace_ok_everything_else_is_einval() {
        assert!(string_to_timestamp_at("20300102030405 \t", now()).is_some());
        assert_eq!(string_to_timestamp_at("", now()), None);
        assert_eq!(string_to_timestamp_at("20300102", now()), None);
        assert_eq!(string_to_timestamp_at("2030-01-02", now()), None);
        assert_eq!(string_to_timestamp_at("20300102030405x", now()), None);
        assert_eq!(string_to_timestamp_at(" 20300102030405", now()), None);
        assert_eq!(string_to_timestamp_at("20301302030405", now()), None);
        assert_eq!(string_to_timestamp_at("02-Foo-2030:03:04:05", now()), None);
    }

    #[test]
    fn a_year_at_or_before_1900_is_confused() {
        assert_eq!(string_to_timestamp_at("19000102030405", now()), None);
        assert_eq!(string_to_timestamp_at("00000102030405", now()), None);
    }
}
