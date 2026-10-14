//! glibc's `strftime`, the formatter behind MIT's `krb5_timestamp_to_sfstring` and the tools'
//! dates, over one locale's LC_TIME.
//!
//! Every conversion glibc 2.42 has, with its flags (`_` pads with spaces, `-` drops the padding,
//! `0` pads with zeros, `^` and `#` change case), a field width, and the `E` (era) and `O`
//! (alternative digits) modifiers where glibc takes them; a conversion it rejects is copied as
//! written. Case changes are ASCII, as glibc's byte-wise `toupper` is in a UTF-8 locale (the
//! Turkic locales' leaves `i` and `I` alone).

use super::locale::LcTime;

/// A broken-down time, as glibc `localtime` fills a `struct tm`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tm {
    /// Seconds, 0 to 60.
    pub sec: i32,
    /// Minutes, 0 to 59.
    pub min: i32,
    /// Hours, 0 to 23.
    pub hour: i32,
    /// Day of the month, 1 to 31.
    pub mday: i32,
    /// Month, 0 to 11.
    pub mon: i32,
    /// Years since 1900.
    pub year: i32,
    /// Day of the week, 0 to 6 from Sunday.
    pub wday: i32,
    /// Day of the year, 0 to 365.
    pub yday: i32,
    /// Seconds east of UTC (`%z`).
    pub gmtoff: i64,
    /// The zone's name (`%Z`).
    pub zone: String,
    /// Seconds since the epoch (`%s`).
    pub epoch: i64,
}

/// glibc `strftime(buf, maxsize, fmt, tm)` in locale `lc`: `None` where it returns 0, that is when
/// the result and its terminating NUL do not fit in `maxsize` bytes, or the result is empty.
#[must_use]
pub fn strftime_tm(lc: &LcTime, fmt: &str, tm: &Tm, maxsize: usize) -> Option<String> {
    let mut out = Vec::new();
    Engine {
        lc,
        tm,
        limit: maxsize,
    }
    .format(fmt.as_bytes(), 0, &mut out)?;
    if out.is_empty() {
        return None;
    }
    String::from_utf8(out).ok()
}

/// One conversion's flags, width and modifier.
#[derive(Clone, Copy)]
struct Spec {
    /// `_`, `-`, `0`, or 0 for none.
    pad: u8,
    /// The field width, -1 for none.
    width: i32,
    /// `E`, `O`, or 0.
    modifier: u8,
    upper: bool,
    lower: bool,
    change_case: bool,
}

/// One era of the locale's `era` item, as glibc `_nl_init_era_entries` reads it.
struct Era<'a> {
    start: [i32; 3],
    stop: [i32; 3],
    offset: i32,
    absolute_direction: i32,
    name: &'a str,
    format: &'a str,
}

struct Engine<'a> {
    lc: &'a LcTime,
    tm: &'a Tm,
    /// The bytes the output and its NUL may take.
    limit: usize,
}

impl Engine<'_> {
    /// glibc `__strftime_internal`: `f` appended to `out`; `None` once the output no longer fits.
    /// `yr_spec` is the era-year padding: an `%EY` with a flag sets it for the rest of the call,
    /// and an `%Ey` without one uses it.
    fn format(&self, f: &[u8], mut yr_spec: u8, out: &mut Vec<u8>) -> Option<()> {
        let mut i = 0;
        while i < f.len() {
            if f[i] != b'%' {
                self.add(out, -1, 0, &f[i..=i])?;
                i += 1;
                continue;
            }
            let start = i;
            let mut s = Spec {
                pad: 0,
                width: -1,
                modifier: 0,
                upper: false,
                lower: false,
                change_case: false,
            };
            loop {
                i += 1;
                match f.get(i) {
                    Some(&c @ (b'_' | b'-' | b'0')) => s.pad = c,
                    Some(b'^') => s.upper = true,
                    Some(b'#') => s.change_case = true,
                    _ => break,
                }
            }
            if f.get(i).is_some_and(u8::is_ascii_digit) {
                s.width = 0;
                while let Some(&d) = f.get(i).filter(|d| d.is_ascii_digit()) {
                    s.width = s
                        .width
                        .checked_mul(10)
                        .and_then(|w| w.checked_add(i32::from(d - b'0')))
                        .unwrap_or(i32::MAX);
                    i += 1;
                }
            }
            if let Some(&m @ (b'E' | b'O')) = f.get(i) {
                s.modifier = m;
                i += 1;
            }
            let Some(&conv) = f.get(i) else {
                // A `%` at the end of the format: copied as written.
                return self.cpy(out, s, &f[start..]);
            };
            if !self.conversion(conv, s, &mut yr_spec, out)? {
                self.cpy(out, s, &f[start..=i])?;
            }
            i += 1;
        }
        Some(())
    }

    /// One conversion. `Some(false)` for one glibc rejects (`bad_format`).
    fn conversion(
        &self,
        conv: u8,
        mut s: Spec,
        yr_spec: &mut u8,
        out: &mut Vec<u8>,
    ) -> Option<bool> {
        let tm = self.tm;
        let lc = self.lc;
        let (e, o) = (s.modifier == b'E', s.modifier == b'O');
        let hour12 = match tm.hour {
            0 => 12,
            h if h > 12 => h - 12,
            h => h,
        };
        match conv {
            b'%' => self.add(out, s.width, s.pad, b"%")?,
            b'n' => self.add(out, s.width, s.pad, b"\n")?,
            b't' => self.add(out, s.width, s.pad, b"\t")?,
            b'a' | b'A' => {
                if s.modifier != 0 {
                    return Some(false);
                }
                if s.change_case {
                    (s.upper, s.lower) = (true, false);
                }
                let names = if conv == b'a' { lc.abday } else { lc.day };
                self.cpy(out, s, name(names, tm.wday).as_bytes())?;
            }
            b'b' | b'h' | b'B' => {
                if e {
                    return Some(false);
                }
                if s.change_case {
                    (s.upper, s.lower) = (true, false);
                }
                let names = match (conv == b'B', o) {
                    (false, false) => lc.abmon,
                    (false, true) => lc.ab_alt_mon,
                    (true, false) => lc.mon,
                    (true, true) => lc.alt_mon,
                };
                self.cpy(out, s, name(names, tm.mon).as_bytes())?;
            }
            b'c' | b'x' | b'X' => {
                if o {
                    return Some(false);
                }
                let (era_fmt, fmt) = match conv {
                    b'c' => (lc.era_d_t_fmt, lc.d_t_fmt),
                    b'x' => (lc.era_d_fmt, lc.d_fmt),
                    _ => (lc.era_t_fmt, lc.t_fmt),
                };
                let sub = if e && !era_fmt.is_empty() {
                    era_fmt
                } else {
                    fmt
                };
                self.subformat(out, s, sub, *yr_spec)?;
            }
            b'D' | b'F' => {
                if s.modifier != 0 {
                    return Some(false);
                }
                let sub = if conv == b'D' { "%m/%d/%y" } else { "%Y-%m-%d" };
                self.subformat(out, s, sub, *yr_spec)?;
            }
            b'R' => self.subformat(out, s, "%H:%M", *yr_spec)?,
            b'T' => self.subformat(out, s, "%H:%M:%S", *yr_spec)?,
            b'r' => {
                let sub = if lc.t_fmt_ampm.is_empty() {
                    "%I:%M:%S %p"
                } else {
                    lc.t_fmt_ampm
                };
                self.subformat(out, s, sub, *yr_spec)?;
            }
            b'C' => {
                if e && let Some(era) = self.era() {
                    self.cpy(out, s, era.name.as_bytes())?;
                } else {
                    self.number(out, s, 2, i64::from(tm.year / 100 + 19), false)?;
                }
            }
            b'd' | b'e' | b'H' | b'I' | b'k' | b'l' | b'j' | b'M' | b'm' | b'S' | b'U' | b'W'
            | b'w' => {
                if e {
                    return Some(false);
                }
                let (digits, value, spacepad) = match conv {
                    b'd' => (2, tm.mday, false),
                    b'e' => (2, tm.mday, true),
                    b'H' => (2, tm.hour, false),
                    b'I' => (2, hour12, false),
                    b'k' => (2, tm.hour, true),
                    b'l' => (2, hour12, true),
                    b'j' => (3, tm.yday + 1, false),
                    b'M' => (2, tm.min, false),
                    b'm' => (2, tm.mon + 1, false),
                    b'S' => (2, tm.sec, false),
                    b'U' => (2, (tm.yday - tm.wday + 7) / 7, false),
                    b'W' => (2, (tm.yday - (tm.wday - 1 + 7) % 7 + 7) / 7, false),
                    _ => (1, tm.wday, false),
                };
                self.number(out, s, digits, i64::from(value), spacepad)?;
            }
            b'u' => self.number(out, s, 1, i64::from((tm.wday - 1 + 7) % 7 + 1), false)?,
            b'V' | b'g' | b'G' => {
                if e {
                    return Some(false);
                }
                let (year_adjust, days) = iso_week(tm);
                let value = match conv {
                    b'g' => {
                        let yy = (tm.year % 100 + year_adjust) % 100;
                        if yy >= 0 {
                            yy
                        } else if tm.year < -1900 - year_adjust {
                            -yy
                        } else {
                            yy + 100
                        }
                    }
                    b'G' => tm.year + 1900 + year_adjust,
                    _ => days / 7 + 1,
                };
                let digits = match conv {
                    b'G' => 1,
                    _ => 2,
                };
                self.number(out, s, digits, i64::from(value), false)?;
            }
            b'Y' => {
                if e && let Some(era) = self.era() {
                    if s.pad != 0 {
                        *yr_spec = s.pad;
                    }
                    self.subformat(out, s, era.format, *yr_spec)?;
                } else if o {
                    return Some(false);
                } else {
                    self.number(out, s, 1, i64::from(tm.year) + 1900, false)?;
                }
            }
            b'y' => {
                if e && let Some(era) = self.era() {
                    if s.pad == 0 {
                        s.pad = *yr_spec;
                    }
                    let delta = i64::from(tm.year) - i64::from(era.start[0]);
                    let value = i64::from(era.offset) + delta * i64::from(era.absolute_direction);
                    self.number(out, s, 2, value, false)?;
                } else {
                    let mut yy = tm.year % 100;
                    if yy < 0 {
                        yy = if tm.year < -1900 { -yy } else { yy + 100 };
                    }
                    self.number(out, s, 2, i64::from(yy), false)?;
                }
            }
            b'P' | b'p' => {
                if conv == b'P' {
                    s.lower = true;
                } else if s.change_case {
                    (s.upper, s.lower) = (false, true);
                }
                let ampm = lc.am_pm.get(usize::from(tm.hour > 11)).copied();
                self.cpy(out, s, ampm.unwrap_or_default().as_bytes())?;
            }
            b's' => {
                let digits = tm.epoch.unsigned_abs().to_string();
                self.sign_and_padding(out, s, 1, tm.epoch < 0, &digits)?;
            }
            b'Z' => {
                if s.change_case {
                    (s.upper, s.lower) = (false, true);
                }
                self.cpy(out, s, tm.zone.as_bytes())?;
            }
            b'z' => {
                let sign: &[u8] = if tm.gmtoff < 0 { b"-" } else { b"+" };
                self.add(out, s.width, s.pad, sign)?;
                let minutes = tm.gmtoff.abs() / 60;
                self.number(out, s, 4, minutes / 60 * 100 + minutes % 60, false)?;
            }
            _ => return Some(false),
        }
        Some(true)
    }

    /// glibc's `add`: `bytes` after `width - len` bytes of padding, zeros for the `0` flag and
    /// spaces otherwise; `None` when that leaves no room for the NUL.
    fn add(&self, out: &mut Vec<u8>, width: i32, pad: u8, bytes: &[u8]) -> Option<()> {
        let delta = usize::try_from(width)
            .unwrap_or(0)
            .saturating_sub(bytes.len());
        if bytes.len() + delta >= self.limit.saturating_sub(out.len()) {
            return None;
        }
        out.resize(out.len() + delta, if pad == b'0' { b'0' } else { b' ' });
        out.extend_from_slice(bytes);
        Some(())
    }

    /// glibc's `cpy`: [`Self::add`] with the case the flags ask for.
    fn cpy(&self, out: &mut Vec<u8>, s: Spec, bytes: &[u8]) -> Option<()> {
        if !s.lower && !s.upper {
            return self.add(out, s.width, s.pad, bytes);
        }
        let mut text = bytes.to_vec();
        if s.lower {
            self.lc.lower(&mut text);
        } else {
            self.lc.upper(&mut text);
        }
        self.add(out, s.width, s.pad, &text)
    }

    /// glibc's `subformat`: `sub` formatted on its own, then placed as one field (upper-cased
    /// for `^`); `yr_spec` goes to the inner conversions.
    fn subformat(&self, out: &mut Vec<u8>, s: Spec, sub: &str, yr_spec: u8) -> Option<()> {
        let mut inner = Vec::new();
        Engine {
            lc: self.lc,
            tm: self.tm,
            limit: self.limit.saturating_sub(out.len()),
        }
        .format(sub.as_bytes(), yr_spec, &mut inner)?;
        if s.upper {
            self.lc.upper(&mut inner);
        }
        self.add(out, s.width, s.pad, &inner)
    }

    /// glibc's `DO_NUMBER` and `DO_NUMBER_SPACEPAD`: `value` in at least `digits` digits, or the
    /// field width when wider; with `O`, the locale's alternative digits when it has them.
    fn number(
        &self,
        out: &mut Vec<u8>,
        mut s: Spec,
        digits: i32,
        value: i64,
        spacepad: bool,
    ) -> Option<()> {
        let digits = digits.max(s.width);
        if spacepad && s.pad != b'0' && s.pad != b'-' {
            s.pad = b'_';
        }
        if s.modifier == b'O'
            && value >= 0
            && let Some(alt) = self.lc.alt_digit(value.unsigned_abs())
        {
            return self.cpy(out, s, alt.as_bytes());
        }
        let magnitude = value.unsigned_abs().to_string();
        self.sign_and_padding(out, s, digits, value < 0, &magnitude)
    }

    /// glibc's `do_number_sign_and_padding`: the sign, then zeros (or spaces for `_`) up to
    /// `digits`, unless `-`; what is left of the width pads the digits as [`Self::add`] does.
    fn sign_and_padding(
        &self,
        out: &mut Vec<u8>,
        mut s: Spec,
        digits: i32,
        negative: bool,
        magnitude: &str,
    ) -> Option<()> {
        let mut text = Vec::with_capacity(magnitude.len() + 1);
        if negative {
            text.push(b'-');
        }
        text.extend_from_slice(magnitude.as_bytes());
        let mut body = text.as_slice();
        if s.pad != b'-' {
            let len = i32::try_from(text.len()).unwrap_or(i32::MAX);
            let padding = digits.saturating_sub(len);
            if let Ok(n) = usize::try_from(padding)
                && n > 0
            {
                let room = self.limit.saturating_sub(out.len());
                if s.pad == b'_' {
                    if n >= room {
                        return None;
                    }
                    out.resize(out.len() + n, b' ');
                } else {
                    if usize::try_from(digits).unwrap_or(usize::MAX) >= room {
                        return None;
                    }
                    if negative {
                        body = &text[1..];
                        out.push(b'-');
                    }
                    out.resize(out.len() + n, b'0');
                }
                s.width = if s.width > padding {
                    s.width - padding
                } else {
                    0
                };
            }
        }
        s.upper = false;
        s.lower = false;
        self.cpy(out, s, body)
    }

    /// glibc `_nl_get_era_entry`: the first era whose span holds the date.
    fn era(&self) -> Option<Era<'static>> {
        let date = [self.tm.year, self.tm.mon, self.tm.mday];
        self.lc.era.iter().filter_map(|e| parse_era(e)).find(|e| {
            (date_le(e.start, date) && date_le(date, e.stop))
                || (date_le(e.stop, date) && date_le(date, e.start))
        })
    }
}

/// A day or month name, `?` out of range as in glibc.
fn name(names: &[&'static str], i: i32) -> &'static str {
    usize::try_from(i)
        .ok()
        .and_then(|i| names.get(i).copied())
        .unwrap_or("?")
}

/// glibc's `ERA_DATE_CMP`: `a` is on or before `b`.
fn date_le(a: [i32; 3], b: [i32; 3]) -> bool {
    a <= b
}

/// One `era` string, `direction:offset:start:stop:name:format`, as glibc localedef stores it: a
/// start or stop `year/month/day` is years since 1900 (year -1 is 1 BC) and a 0-based month; a
/// stop of `+*` or `-*` is open-ended. The direction counts years up or down from the start.
fn parse_era(era: &'static str) -> Option<Era<'static>> {
    let mut f = era.splitn(6, ':');
    let direction = f.next()?;
    let offset = f.next()?.parse().ok()?;
    let start = era_date(f.next()?)?;
    let stop = match f.next()? {
        "+*" => [i32::MAX; 3],
        "-*" => [i32::MIN; 3],
        d => era_date(d)?,
    };
    let (name, format) = (f.next()?, f.next()?);
    let forward = direction == "+";
    let absolute_direction = if date_le(start, stop) == forward {
        1
    } else {
        -1
    };
    Some(Era {
        start,
        stop,
        offset,
        absolute_direction,
        name,
        format,
    })
}

fn era_date(d: &str) -> Option<[i32; 3]> {
    let mut p = d.split('/');
    let year: i32 = p.next()?.parse().ok()?;
    let month: i32 = p.next()?.parse().ok()?;
    let day: i32 = p.next()?.parse().ok()?;
    let mut y = year.checked_sub(1900)?;
    if y < -1900 {
        y += 1;
    }
    Some([y, month - 1, day])
}

/// glibc's ISO 8601 week: the year adjustment (-1, 0, 1) and the days since the week-based
/// year's first Monday.
fn iso_week(tm: &Tm) -> (i32, i32) {
    fn iso_week_days(yday: i32, wday: i32) -> i32 {
        // glibc: Thursday decides the week; weeks start on Monday.
        let big_enough_multiple_of_7 = (366 / 7 + 2) * 7;
        yday - (yday - wday + 4 + big_enough_multiple_of_7) % 7 + 4 - 1
    }
    fn days_in(year: i32) -> i32 {
        if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        }
    }
    let year = tm.year + 1900;
    let days = iso_week_days(tm.yday, tm.wday);
    if days < 0 {
        return (-1, iso_week_days(tm.yday + days_in(year - 1), tm.wday));
    }
    let next = iso_week_days(tm.yday - days_in(year), tm.wday);
    if next >= 0 { (1, next) } else { (0, days) }
}

/// Every expectation is glibc 2.42's `strftime` on the same broken-down time, recorded live.
#[cfg(test)]
mod tests {
    use super::*;

    fn tm(
        (year, mon, mday): (i32, i32, i32),
        (hour, min, sec): (i32, i32, i32),
        wday: i32,
        yday: i32,
        gmtoff: i64,
        zone: &str,
        epoch: i64,
    ) -> Tm {
        Tm {
            sec,
            min,
            hour,
            mday,
            mon,
            year: year - 1900,
            wday,
            yday,
            gmtoff,
            zone: zone.to_owned(),
            epoch,
        }
    }

    /// 2026-03-05 08:40:00 UTC, a Thursday.
    fn t1() -> Tm {
        tm((2026, 2, 5), (8, 40, 0), 4, 63, 0, "UTC", 1_772_700_000)
    }

    /// 2026-10-05 15:00:09 CDT, a Monday.
    fn t2() -> Tm {
        tm(
            (2026, 9, 5),
            (15, 0, 9),
            1,
            277,
            -18_000,
            "CDT",
            1_791_230_409,
        )
    }

    fn lc(name: &str) -> LcTime {
        LcTime::named(name).unwrap()
    }

    fn f(lc: &LcTime, fmt: &str, tm: &Tm) -> Option<String> {
        strftime_tm(lc, fmt, tm, 512)
    }

    #[test]
    fn every_conversion_in_c() {
        let c = LcTime::C;
        assert_eq!(
            f(
                &c,
                "%a %A %b %B %C %d %D %e %F %g %G %h %H %I %j %k %l %m %M %p %P %R %S %T %u %U %V %w %W %y %Y %z %Z %%",
                &t1()
            )
            .unwrap(),
            "Thu Thursday Mar March 20 05 03/05/26  5 2026-03-05 26 2026 Mar 08 08 064  8  8 03 40 AM am 08:40 00 08:40:00 4 09 10 4 09 26 2026 +0000 UTC %"
        );
        assert_eq!(
            f(&c, "%c|%x|%X|%r|%n|%t", &t1()).unwrap(),
            "Thu Mar  5 08:40:00 2026|03/05/26|08:40:00|08:40:00 AM|\n|\t"
        );
        assert_eq!(
            f(&c, "%c|%I %p|%l|%z|%Z|%#Z|%^a", &t2()).unwrap(),
            "Mon Oct  5 15:00:09 2026|03 PM| 3|-0500|CDT|cdt|MON"
        );
        let t4 = tm((2021, 0, 3), (23, 59, 59), 0, 2, 0, "UTC", 1_609_718_399);
        assert_eq!(
            f(&c, "%G-W%V-%u %g %U %W %j", &t4).unwrap(),
            "2020-W53-7 20 01 00 003"
        );
    }

    #[test]
    fn flags_widths_and_rejected_conversions() {
        let c = LcTime::C;
        assert_eq!(
            f(
                &c,
                "%5d|%_5d|%-5d|%05d|%-d|%_d|%10Y|%-10Y|%3C|%_3C|%^a|%#a|%^P|%#p|%10a|%010a",
                &t1()
            )
            .unwrap(),
            "00005|    5|    5|00005|5| 5|0000002026|      2026|020| 20|THU|THU|am|am|       Thu|0000000Thu"
        );
        assert_eq!(
            f(
                &c,
                "%30c|%^c|%12x|%09T|%5|%Q|%5Q|%E|%Ed|%Oc|%E%|%5%|%5n|%10Ez|%Ey|%EY|%EC|%Oy|%OB",
                &t1()
            )
            .unwrap(),
            "      Thu Mar  5 08:40:00 2026|THU MAR  5 08:40:00 2026|    03/05/26|008:40:00|  %5|%Q|  %5Q|%E|%Ed|%Oc|%|    %|    \n|         +0000000000|26|2026|20|26|March"
        );
        assert_eq!(f(&c, "%", &t1()).unwrap(), "%");
        assert_eq!(f(&c, "%5", &t1()).unwrap(), "   %5");
    }

    #[test]
    fn the_result_and_its_nul_must_fit() {
        let c = LcTime::C;
        assert_eq!(
            strftime_tm(&c, "%x %X", &t1(), 18).as_deref(),
            Some("03/05/26 08:40:00")
        );
        assert_eq!(strftime_tm(&c, "%x %X", &t1(), 17), None);
        assert_eq!(strftime_tm(&c, "%x %X", &t1(), 0), None);
        assert_eq!(strftime_tm(&c, "", &t1(), 512), None);
        assert_eq!(strftime_tm(&c, "%999999999d", &t1(), 64), None);
        let en = lc("en_US");
        assert_eq!(strftime_tm(&en, "%x %X", &t2(), 20), None);
        assert_eq!(
            strftime_tm(&en, "%x %T", &t2(), 20).as_deref(),
            Some("10/05/2026 15:00:09")
        );
    }

    #[test]
    fn en_us_and_de_de() {
        assert_eq!(
            f(
                &lc("en_US.UTF-8"),
                "%c|%x|%X|%r|%p|%a %b %d %H:%M:%S %Z %Y",
                &t2()
            )
            .unwrap(),
            "Mon 05 Oct 2026 03:00:09 PM CDT|10/05/2026|03:00:09 PM|03:00:09 PM|PM|Mon Oct 05 15:00:09 CDT 2026"
        );
        let de = lc("de_DE.UTF-8");
        assert_eq!(
            f(
                &de,
                "%c|%x|%X|%r|%A %B|%a %b %d %H:%M:%S %Z %Y|%d %b %Y %T",
                &t1()
            )
            .unwrap(),
            "Do 05 Mär 2026 08:40:00 UTC|05.03.2026|08:40:00|08:40:00 |Donnerstag März|Do Mär 05 08:40:00 UTC 2026|05 Mär 2026 08:40:00"
        );
        assert_eq!(f(&de, "%p", &t1()), None);
    }

    #[test]
    fn eras_and_alternative_digits() {
        let ja = lc("ja_JP");
        // An `%EY` with a flag sets the era-year padding for the rest of the call.
        assert_eq!(
            f(&ja, "%EY|%-EY|%_EY|%Ey|%EC|%Ex|%Ec|%Oy|%OH|%c", &t1()).unwrap(),
            "令和08年|令和8年|令和 8年| 8|令和|令和 8年03月05日|令和 8年03月05日 08時40分00秒|二十六|八|2026年03月05日 08時40分00秒"
        );
        let reiwa1 = tm((2019, 4, 1), (0, 0, 0), 3, 120, 0, "UTC", 1_556_668_800);
        assert_eq!(
            f(&ja, "%EY|%Ex", &reiwa1).unwrap(),
            "令和元年|令和元年05月01日"
        );
        assert_eq!(
            f(&lc("th_TH"), "%Ey|%EY|%x|%c|%Ex", &t1()).unwrap(),
            "2569|พ.ศ. 2569|05/03/2569|พฤ.  5 มี.ค. 2569, 08:40:00| 5 มี.ค. 2569"
        );
        assert_eq!(
            f(&lc("fa_IR"), "%Oy|%5Oy|%OH:%OM|%Oe|%r", &t1()).unwrap(),
            "۲۶| ۲۶|۰۸:۴۰|۰۵|08:40:00 "
        );
    }

    #[test]
    fn turkic_case_changes_leave_i_alone() {
        assert_eq!(f(&lc("tr_TR"), "%^B|%#Z", &t1()).unwrap(), "MART|utc");
        let april = tm((2026, 3, 6), (8, 0, 0), 1, 95, 0, "IST", 1_775_462_400);
        assert_eq!(f(&lc("tr_TR"), "%^b|%#Z", &april).unwrap(), "NiS|Ist");
        assert_eq!(f(&LcTime::C, "%^b|%#Z", &april).unwrap(), "APR|ist");
    }
}
