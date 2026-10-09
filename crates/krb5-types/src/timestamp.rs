//! MIT's absolute-time conversions: `krb5_string_to_timestamp`, and the dates MIT's tools print
//! through `krb5_timestamp_to_string`, `krb5_timestamp_to_sfstring` and `strftime` in the locale
//! their `setlocale(LC_ALL, "")` selects ([`setlocale`]).
//!
//! Formatting is glibc's `strftime` over glibc's LC_TIME data for the locale (see the `locale`
//! and `strftime` submodules), in the local time zone (`TZ`, else `/etc/localtime`). `%Z` is
//! `UTC` at offset zero and the numeric offset (`+02:00`) elsewhere, not the zone's abbreviation.
//!
//! MIT `krb5_string_to_timestamp` (`lib/krb5/krb/str_conv.c:146-196`): tries a fixed
//! `strptime` format table against the string, in order, over a `struct tm` seeded from
//! `localtime(now)` (so a time-only form is *today* at that time and a form without `%S`
//! keeps now's seconds), skips a parse that consumes nothing or leaves anything but whitespace
//! behind, or a year at or before 1900 (`tm_year <= 0`), and converts the first hit with
//! `mktime`, local time. `strptime` is glibc's in the C locale: a numeric field skips leading
//! whitespace and reads up to its width while the value can still grow within its range, which
//! it must end in; `%b` is a month's full or three-letter name in any case; `%x` is `%m/%d/%y`
//! and `%X` `%H:%M:%S`. `mktime` normalises a day or second past its month's or minute's end
//! (`%d` takes 1–31 whatever the month, `%S` 0–61). The local time is the zone's own for the date;
//! MIT's `mktime` takes the daylight-saving flag of `localtime(now)` as a hint, which can move a
//! date in the other half of the year by the zone's daylight-saving shift.

use std::sync::OnceLock;

use chrono::{Datelike, Local, NaiveDate, NaiveDateTime, TimeDelta, TimeZone, Timelike};

mod locale;
mod strftime;

pub use locale::LcTime;
pub use strftime::{Tm, strftime_tm};

/// The LC_TIME [`setlocale`] chose; `C` until it runs, as in a C program.
static LC_TIME: OnceLock<LcTime> = OnceLock::new();

/// MIT's tools' `setlocale(LC_ALL, "")` (`clients/klist/klist.c` and the others call it first in
/// `main`): the process's LC_TIME from `LC_ALL`, `LC_TIME` and `LANG`, `C` when any category's
/// locale is not installed. Later calls keep the first one's choice.
pub fn setlocale() {
    let _ = LC_TIME.set(locale::resolve(
        &|k| std::env::var_os(k).map(|v| v.to_string_lossy().into_owned()),
        &locale::System::load(),
    ));
}

/// The process's LC_TIME: what [`setlocale`] chose, else `C`.
#[must_use]
pub fn lc_time() -> LcTime {
    LC_TIME.get().copied().unwrap_or(LcTime::C)
}

/// glibc `localtime`: `t` (read as MIT's `ts2tt` reads a `krb5_timestamp`, unsigned) broken down
/// in the local time zone.
#[must_use]
pub fn localtime(t: u32) -> Option<Tm> {
    let utc = chrono::DateTime::from_timestamp(i64::from(t), 0)?;
    let local = utc.with_timezone(&Local);
    let gmtoff = local.offset().local_minus_utc();
    let int = |v: u32| i32::try_from(v).unwrap_or_default();
    Some(Tm {
        sec: int(local.second()),
        min: int(local.minute()),
        hour: int(local.hour()),
        mday: int(local.day()),
        mon: int(local.month0()),
        year: local.year() - 1900,
        wday: int(local.weekday().num_days_from_sunday()),
        yday: int(local.ordinal0()),
        gmtoff: i64::from(gmtoff),
        zone: if gmtoff == 0 {
            "UTC".to_owned()
        } else {
            local.offset().to_string()
        },
        epoch: i64::from(t),
    })
}

/// glibc `strftime` of `t`'s local time in the process's locale: `None` where glibc returns 0
/// (the result and its NUL do not fit in `maxsize` bytes, or it is empty).
#[must_use]
pub fn strftime(fmt: &str, t: u32, maxsize: usize) -> Option<String> {
    strftime_tm(&lc_time(), fmt, &localtime(t)?, maxsize)
}

/// MIT `krb5_timestamp_to_string` (`lib/krb5/krb/str_conv.c:199-213`): `%c` of the local time in a buffer of `buflen` bytes.
/// `None` is MIT's `ENOMEM`: it does not fit.
#[must_use]
pub fn timestamp_to_string(t: u32, buflen: usize) -> Option<String> {
    strftime("%c", t, buflen)
}

/// MIT `krb5_timestamp_to_sfstring` (`lib/krb5/krb/str_conv.c:216-252`): the first format of MIT's table that fits in `buflen`.
/// That is, in `buflen - 1` bytes: the locale's `%c`, `dd mon yyyy hh:mm:ss`, the locale's date
/// with its time, `hh:mm:ss` or `hh:mm`, then ISO 8601 forms. With `pad` (MIT's `fill`, an ASCII
/// byte), the rest up to `buflen - 1` bytes is filled with it. `None` is MIT's `ENOMEM`: none fits.
#[must_use]
pub fn timestamp_to_sfstring(t: u32, buflen: usize, pad: Option<u8>) -> Option<String> {
    sfstring_tm(&lc_time(), &localtime(t)?, buflen, pad)
}

/// [`timestamp_to_sfstring`] of a broken-down time in locale `lc`.
fn sfstring_tm(lc: &LcTime, tm: &Tm, buflen: usize, pad: Option<u8>) -> Option<String> {
    /// MIT `krb5_timestamp_to_sfstring` (`lib/krb5/krb/str_conv.c:224-234`): `sftime_format_table`, tried in this order.
    const SFTIME_FORMATS: [&str; 9] = [
        "%c",
        "%d %b %Y %T",
        "%x %X",
        "%x %T",
        "%x %R",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y%m%d%H%M%S",
        "%Y%m%d%H%M",
    ];
    let mut s = SFTIME_FORMATS
        .iter()
        .find_map(|f| strftime_tm(lc, f, tm, buflen))?;
    if let Some(p) = pad.filter(u8::is_ascii) {
        while s.len() + 1 < buflen {
            s.push(char::from(p));
        }
    }
    Some(s)
}

/// MIT `krb5_string_to_timestamp` (`krb/str_conv.c:152-165`): the `atime_format_table` formats, tried in this order.
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
    "%x:%X",
    "%d-%b-%Y:%T",
    "%d-%b-%Y:%R",
];

/// The C locale's month names, full and abbreviated.
const MONTHS: [(&str, &str); 12] = [
    ("january", "jan"),
    ("february", "feb"),
    ("march", "mar"),
    ("april", "apr"),
    ("may", "may"),
    ("june", "jun"),
    ("july", "jul"),
    ("august", "aug"),
    ("september", "sep"),
    ("october", "oct"),
    ("november", "nov"),
    ("december", "dec"),
];

/// Fields a format sets: years since 1900, the month from 0, the day, hour, minute and second.
#[derive(Clone, Copy)]
struct AtTm {
    year: i64,
    mon: i64,
    mday: i64,
    hour: i64,
    min: i64,
    sec: i64,
}

impl AtTm {
    fn at(now: NaiveDateTime) -> Self {
        Self {
            year: i64::from(now.year()) - 1900,
            mon: i64::from(now.month0()),
            mday: i64::from(now.day()),
            hour: i64::from(now.hour()),
            min: i64::from(now.minute()),
            sec: i64::from(now.second()),
        }
    }

    /// The local date and time `mktime` makes of the fields, an overflowing day or second carried
    /// into the next month or minute.
    fn normalized(self) -> Option<NaiveDateTime> {
        let year = i32::try_from(self.year + 1900).ok()?;
        let mon = u32::try_from(self.mon).ok()?;
        let first = NaiveDate::from_ymd_opt(year, mon + 1, 1)?.and_hms_opt(0, 0, 0)?;
        let offset = TimeDelta::try_days(self.mday - 1)?
            .checked_add(&TimeDelta::try_hours(self.hour)?)?
            .checked_add(&TimeDelta::try_minutes(self.min)?)?
            .checked_add(&TimeDelta::try_seconds(self.sec)?)?;
        first.checked_add_signed(offset)
    }
}

/// Parse a MIT absolute-time string to Unix seconds in the local zone.
///
/// `None` is MIT's `EINVAL`.
#[must_use]
pub fn string_to_timestamp(s: &str) -> Option<u32> {
    string_to_timestamp_at(s, Local::now().naive_local())
}

/// [`string_to_timestamp`] with an explicit "now" for the fields a format does not set.
#[must_use]
pub fn string_to_timestamp_at(s: &str, now: NaiveDateTime) -> Option<u32> {
    let b = s.as_bytes();
    for fmt in FORMATS {
        let mut tm = AtTm::at(now);
        let mut i = 0;
        if strptime(b, &mut i, fmt.as_bytes(), &mut tm).is_none() || i == 0 {
            continue;
        }
        while b.get(i).is_some_and(|&c| is_space(c)) {
            i += 1;
        }
        if i != b.len() || tm.year <= 0 {
            continue;
        }
        let Some(ndt) = tm.normalized() else {
            continue;
        };
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

/// C's `isspace` in the C locale.
const fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

/// One glibc `strptime` pass of `fmt` over `b` from `*i`, into `tm`. `None` where glibc returns
/// `NULL`.
fn strptime(b: &[u8], i: &mut usize, fmt: &[u8], tm: &mut AtTm) -> Option<()> {
    let mut f = 0;
    while let Some(&c) = fmt.get(f) {
        f += 1;
        if is_space(c) {
            while b.get(*i).is_some_and(|&c| is_space(c)) {
                *i += 1;
            }
            continue;
        }
        if c != b'%' {
            if b.get(*i) != Some(&c) {
                return None;
            }
            *i += 1;
            continue;
        }
        let conv = *fmt.get(f)?;
        f += 1;
        match conv {
            b'Y' => tm.year = get_number(b, i, 0, 9999, 4)? - 1900,
            // POSIX: 69–99 are 1969–1999, 00–68 are 2000–2068.
            b'y' => {
                let yy = get_number(b, i, 0, 99, 2)?;
                tm.year = if yy >= 69 { yy } else { yy + 100 };
            }
            b'm' => tm.mon = get_number(b, i, 1, 12, 2)? - 1,
            b'd' => tm.mday = get_number(b, i, 1, 31, 2)?,
            b'H' => tm.hour = get_number(b, i, 0, 23, 2)?,
            b'M' => tm.min = get_number(b, i, 0, 59, 2)?,
            b'S' => tm.sec = get_number(b, i, 0, 61, 2)?,
            b'T' | b'X' => strptime(b, i, b"%H:%M:%S", tm)?,
            b'R' => strptime(b, i, b"%H:%M", tm)?,
            b'x' => strptime(b, i, b"%m/%d/%y", tm)?,
            b'b' => tm.mon = month_name(b, i)?,
            _ => return None,
        }
    }
    Some(())
}

/// glibc's `get_number`: blanks skipped, then at least one digit and at most `width`, a digit
/// read only while ten times the value so far is within `to`. The value must lie in `from..=to`.
fn get_number(b: &[u8], i: &mut usize, from: i64, to: i64, width: usize) -> Option<i64> {
    while b.get(*i).is_some_and(|&c| is_space(c)) {
        *i += 1;
    }
    let mut val = 0i64;
    let mut n = width;
    let mut d = *b.get(*i).filter(|c| c.is_ascii_digit())?;
    loop {
        val = val * 10 + i64::from(d - b'0');
        *i += 1;
        n -= 1;
        match b.get(*i) {
            Some(&next) if n > 0 && val * 10 <= to && next.is_ascii_digit() => d = next,
            _ => break,
        }
    }
    (from..=to).contains(&val).then_some(val)
}

/// glibc's `%b` in the C locale: a month's full name, else its three-letter one, in any case.
/// The month is from 0.
fn month_name(b: &[u8], i: &mut usize) -> Option<i64> {
    let rest = b.get(*i..)?;
    for (m, (full, abbr)) in (0i64..).zip(MONTHS) {
        for name in [full, abbr] {
            if rest.len() >= name.len() && rest[..name.len()].eq_ignore_ascii_case(name.as_bytes())
            {
                *i += name.len();
                return Some(m);
            }
        }
    }
    None
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
        assert_eq!(
            string_to_timestamp_at("02-January-2030:03:04:05", now()),
            Some(want)
        );
        // `%x:%X` in the C locale.
        assert_eq!(
            string_to_timestamp_at("01/02/30:03:04:05", now()),
            Some(want)
        );
    }

    #[test]
    fn time_only_forms_are_today_at_that_time() {
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

    /// glibc's `strptime`: a numeric field skips leading blanks and is as wide as its value
    /// allows; `mktime` carries a day past its month's end. So `235959` is not today's 23:59:59
    /// but `%y%m%d%H%M`'s 2023-05-09 05:09, the first form that takes it whole.
    #[test]
    fn fields_are_glibc_s_and_days_carry_as_mktime_s() {
        assert_eq!(
            string_to_timestamp_at("235959", now()),
            Some(local(2023, 5, 9, 5, 9, 7))
        );
        assert_eq!(
            string_to_timestamp_at(" 20300102030405", now()),
            Some(local(2030, 1, 2, 3, 4, 5))
        );
        assert_eq!(
            string_to_timestamp_at("2030.1.2.3.4.5", now()),
            Some(local(2030, 1, 2, 3, 4, 5))
        );
        assert_eq!(
            string_to_timestamp_at("930", now()),
            Some(local(2026, 9, 13, 9, 30, 7))
        );
        assert_eq!(
            string_to_timestamp_at("20300230120000", now()),
            Some(local(2030, 3, 2, 12, 0, 0))
        );
    }

    #[test]
    fn trailing_whitespace_ok_everything_else_is_einval() {
        assert!(string_to_timestamp_at("20300102030405 \t", now()).is_some());
        assert_eq!(string_to_timestamp_at("", now()), None);
        assert_eq!(string_to_timestamp_at("   ", now()), None);
        assert_eq!(string_to_timestamp_at("20300102", now()), None);
        assert_eq!(string_to_timestamp_at("2030-01-02", now()), None);
        assert_eq!(string_to_timestamp_at("20300102030405x", now()), None);
        assert_eq!(string_to_timestamp_at("20301302030405", now()), None);
        assert_eq!(string_to_timestamp_at("02-Foo-2030:03:04:05", now()), None);
        assert_eq!(string_to_timestamp_at("0", now()), None);
    }

    /// MIT's table walked over glibc 2.42's `strftime` for 2026-03-05 08:40:00, recorded live:
    /// klist's 20-byte width probe and ktutil's 18-byte buffer, padded with spaces.
    #[test]
    fn sfstring_takes_the_first_format_that_fits() {
        let t1 = Tm {
            sec: 0,
            min: 40,
            hour: 8,
            mday: 5,
            mon: 2,
            year: 126,
            wday: 4,
            yday: 63,
            gmtoff: 0,
            zone: "UTC".to_owned(),
            epoch: 1_772_700_000,
        };
        let sp = Some(b' ');
        let c = LcTime::C;
        assert_eq!(
            sfstring_tm(&c, &t1, 20, sp).as_deref(),
            Some("03/05/26 08:40:00  ")
        );
        assert_eq!(
            sfstring_tm(&c, &t1, 20, None).as_deref(),
            Some("03/05/26 08:40:00")
        );
        assert_eq!(
            sfstring_tm(&c, &t1, 18, sp).as_deref(),
            Some("03/05/26 08:40:00")
        );
        assert_eq!(
            sfstring_tm(&c, &t1, 13, sp).as_deref(),
            Some("202603050840")
        );
        assert_eq!(sfstring_tm(&c, &t1, 12, sp), None);
        let en = LcTime::named("en_US.UTF-8").unwrap();
        assert_eq!(
            sfstring_tm(&en, &t1, 20, sp).as_deref(),
            Some("03/05/2026 08:40:00")
        );
        assert_eq!(
            sfstring_tm(&en, &t1, 18, sp).as_deref(),
            Some("03/05/2026 08:40 ")
        );
        let de = LcTime::named("de_DE.UTF-8").unwrap();
        assert_eq!(
            sfstring_tm(&de, &t1, 20, sp).as_deref(),
            Some("05.03.2026 08:40:00")
        );
        assert_eq!(
            sfstring_tm(&de, &t1, 18, sp).as_deref(),
            Some("05.03.2026 08:40 ")
        );
    }

    #[test]
    fn the_process_locale_is_c_until_setlocale() {
        assert_eq!(lc_time(), LcTime::C);
        let tm = localtime(1_772_700_000).unwrap();
        assert_eq!(tm.epoch, 1_772_700_000);
        assert_eq!(
            timestamp_to_sfstring(1_772_700_000, 20, None)
                .unwrap()
                .len(),
            17
        );
        assert!(
            timestamp_to_string(1_772_700_000, 256)
                .unwrap()
                .ends_with(" 2026")
        );
        assert_eq!(timestamp_to_string(1_772_700_000, 10), None);
    }

    #[test]
    fn a_year_at_or_before_1900_is_confused() {
        assert_eq!(string_to_timestamp_at("19000102030405", now()), None);
        assert_eq!(string_to_timestamp_at("00000102030405", now()), None);
    }
}
