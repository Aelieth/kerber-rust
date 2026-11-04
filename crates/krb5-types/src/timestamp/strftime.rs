use super::locale::LcTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tm {
    pub sec: i32,
    pub min: i32,
    pub hour: i32,
    pub mday: i32,
    pub mon: i32,
    pub year: i32,
    pub wday: i32,
    pub yday: i32,
    pub gmtoff: i64,
    pub zone: String,
    pub epoch: i64,
}

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

#[derive(Clone, Copy)]
struct Spec {
    pad: u8,
    width: i32,
    modifier: u8,
    upper: bool,
    lower: bool,
    change_case: bool,
}

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
    limit: usize,
}

impl Engine<'_> {
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
                return self.cpy(out, s, &f[start..]);
            };
            if !self.conversion(conv, s, &mut yr_spec, out)? {
                self.cpy(out, s, &f[start..=i])?;
            }
            i += 1;
        }
        Some(())
    }

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

    fn era(&self) -> Option<Era<'static>> {
        let date = [self.tm.year, self.tm.mon, self.tm.mday];
        self.lc.era.iter().filter_map(|e| parse_era(e)).find(|e| {
            (date_le(e.start, date) && date_le(date, e.stop))
                || (date_le(e.stop, date) && date_le(date, e.start))
        })
    }
}

fn name(names: &[&'static str], i: i32) -> &'static str {
    usize::try_from(i)
        .ok()
        .and_then(|i| names.get(i).copied())
        .unwrap_or("?")
}

fn date_le(a: [i32; 3], b: [i32; 3]) -> bool {
    a <= b
}

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

fn iso_week(tm: &Tm) -> (i32, i32) {
    fn iso_week_days(yday: i32, wday: i32) -> i32 {
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
