// MIT: `krb5_string_to_timestamp` (lib/krb5/krb/str_conv.c:145-196)

use std::sync::OnceLock;

use chrono::{Datelike, Local, NaiveDate, NaiveDateTime, TimeDelta, TimeZone, Timelike};

mod locale;
mod strftime;

pub use locale::LcTime;
pub use strftime::{Tm, strftime_tm};

static LC_TIME: OnceLock<LcTime> = OnceLock::new();

#[allow(
    clippy::disallowed_methods,
    reason = "a tool's locale, read once, first in main"
)]
pub fn setlocale() {
    let _ = LC_TIME.set(locale::resolve(
        &|k| std::env::var_os(k).map(|v| v.to_string_lossy().into_owned()),
        &locale::System::load(),
    ));
}

#[must_use]
pub fn lc_time() -> LcTime {
    LC_TIME.get().copied().unwrap_or(LcTime::C)
}

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

#[must_use]
pub fn strftime(fmt: &str, t: u32, maxsize: usize) -> Option<String> {
    strftime_tm(&lc_time(), fmt, &localtime(t)?, maxsize)
}

// MIT: `krb5_timestamp_to_string` (lib/krb5/krb/str_conv.c:199-213)
// `%c` of the local time in a buffer of `buflen` bytes.
#[must_use]
pub fn timestamp_to_string(t: u32, buflen: usize) -> Option<String> {
    strftime("%c", t, buflen)
}

// MIT: `krb5_timestamp_to_sfstring` (lib/krb5/krb/str_conv.c:216-252)
// the first format of MIT's table that fits in `buflen`.
#[must_use]
pub fn timestamp_to_sfstring(t: u32, buflen: usize, pad: Option<u8>) -> Option<String> {
    sfstring_tm(&lc_time(), &localtime(t)?, buflen, pad)
}

fn sfstring_tm(lc: &LcTime, tm: &Tm, buflen: usize, pad: Option<u8>) -> Option<String> {
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

#[must_use]
pub fn string_to_timestamp(s: &str) -> Option<u32> {
    string_to_timestamp_at(s, Local::now().naive_local())
}

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

fn wrap_ts(t: i64) -> u32 {
    u32::try_from(t.rem_euclid(1 << 32)).unwrap_or(0)
}

const fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

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
