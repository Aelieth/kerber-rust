//! The date and interval phrases `kadmin` reads: MIT `get_date_rel` (`kadmin/cli/getdate.y`),
//! a port of its grammar, word tables and conversion, and the `parse_date` / `parse_interval`
//! wrappers of `kadmin.c`.
//!
//! Local time comes from the process's time zone (`TZ`, else `/etc/localtime`), as `localtime`
//! gives it to MIT.

use chrono::{Datelike as _, Offset as _, TimeZone as _, Timelike as _};

const EPOCH: i64 = 1970;
const EPOCH_END: i64 = 2106;
const SECSPERDAY: i64 = 24 * 60 * 60;

/// Why a phrase did not convert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DateError {
    /// MIT `parse_date` (`kadmin.c:158-166`): `get_date_rel` failed.
    Invalid(String),
    /// MIT `parse_interval` (`kadmin.c:190-194`): an absolute date before now is refused.
    InPast(String),
}

impl std::fmt::Display for DateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(s) => write!(f, "Invalid date specification \"{s}\"."),
            Self::InPast(s) => write!(f, "Interval specification \"{s}\" is in the past."),
        }
    }
}

/// The current time as `time(&now)` gives it to `kadmin`'s parsers.
#[must_use]
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// `t` as a 32-bit `krb5_timestamp` / `krb5_deltat` keeps it: its low 32 bits.
#[must_use]
pub fn low32(t: i64) -> u32 {
    u32::try_from(t.rem_euclid(1 << 32)).unwrap_or(0)
}

/// `kadmin`'s absolute date: `get_date_rel(s, now)`, 0 for `never`.
/// MIT `parse_date` (`kadmin.c:158-166`): `get_date_rel`, and `Invalid date specification "%s".`
/// when it fails.
///
/// # Errors
///
/// [`DateError::Invalid`] when `s` is not a date `get_date_rel` reads.
pub fn parse_date(s: &str, now: i64) -> Result<i64, DateError> {
    get_date_rel(s, now).ok_or_else(|| DateError::Invalid(s.to_owned()))
}

/// `kadmin`'s interval: a `krb5_string_to_deltat` duration, else a date less now.
/// MIT `parse_interval` (`kadmin.c:174-197`): the deltat first; else `get_date_rel`, an absolute
/// 0 (`never`) being an interval of 0 and a date in the past an error.
///
/// # Errors
///
/// [`DateError::Invalid`] when `s` is neither; [`DateError::InPast`] when it names a moment
/// before `now`.
pub fn parse_interval(s: &str, now: i64) -> Result<i64, DateError> {
    if let Ok(delta) = krb5_types::deltat::parse(s) {
        return Ok(i64::from(delta));
    }
    let date = parse_date(s, now)?;
    if date == 0 {
        return Ok(0);
    }
    if date < now {
        return Err(DateError::InPast(s.to_owned()));
    }
    Ok(date - now)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Meridian {
    Am,
    Pm,
    H24,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DstMode {
    On,
    Off,
    Maybe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    Ago,
    Id,
    Dst,
    Never,
    Day(i64),
    DayZone(i64),
    MinuteUnit(i64),
    Month(i64),
    MonthUnit(i64),
    SecUnit(i64),
    SNumber(i64),
    UNumber(i64),
    Zone(i64),
    Meridian(Meridian),
    Char(u8),
    End,
}

/// The parser's globals (`yyYear`, `yyHaveDate`, …).
struct State {
    dst: DstMode,
    day_ordinal: i64,
    day_number: i64,
    have_date: u32,
    have_day: u32,
    have_rel: u32,
    have_time: u32,
    have_zone: u32,
    timezone: i64,
    day: i64,
    hour: i64,
    minutes: i64,
    month: i64,
    seconds: i64,
    year: i64,
    meridian: Meridian,
    rel_month: i64,
    rel_seconds: i64,
}

const fn hour(h: i64) -> i64 {
    h * 60
}

/// The month and weekday names: MIT's `MonthDayTable` in `getdate.y`.
const MONTH_DAY: &[(&str, Tok)] = &[
    ("january", Tok::Month(1)),
    ("february", Tok::Month(2)),
    ("march", Tok::Month(3)),
    ("april", Tok::Month(4)),
    ("may", Tok::Month(5)),
    ("june", Tok::Month(6)),
    ("july", Tok::Month(7)),
    ("august", Tok::Month(8)),
    ("september", Tok::Month(9)),
    ("sept", Tok::Month(9)),
    ("october", Tok::Month(10)),
    ("november", Tok::Month(11)),
    ("december", Tok::Month(12)),
    ("sunday", Tok::Day(0)),
    ("monday", Tok::Day(1)),
    ("tuesday", Tok::Day(2)),
    ("tues", Tok::Day(2)),
    ("wednesday", Tok::Day(3)),
    ("wednes", Tok::Day(3)),
    ("thursday", Tok::Day(4)),
    ("thur", Tok::Day(4)),
    ("thurs", Tok::Day(4)),
    ("friday", Tok::Day(5)),
    ("saturday", Tok::Day(6)),
];

/// The time units: MIT's `UnitsTable` in `getdate.y`.
const UNITS: &[(&str, Tok)] = &[
    ("year", Tok::MonthUnit(12)),
    ("month", Tok::MonthUnit(1)),
    ("fortnight", Tok::MinuteUnit(14 * 24 * 60)),
    ("week", Tok::MinuteUnit(7 * 24 * 60)),
    ("day", Tok::MinuteUnit(24 * 60)),
    ("hour", Tok::MinuteUnit(60)),
    ("minute", Tok::MinuteUnit(1)),
    ("min", Tok::MinuteUnit(1)),
    ("second", Tok::SecUnit(1)),
    ("sec", Tok::SecUnit(1)),
];

/// The relative words and ordinals: MIT's `OtherTable` in `getdate.y`.
const OTHER: &[(&str, Tok)] = &[
    ("tomorrow", Tok::MinuteUnit(24 * 60)),
    ("yesterday", Tok::MinuteUnit(-24 * 60)),
    ("today", Tok::MinuteUnit(0)),
    ("now", Tok::MinuteUnit(0)),
    ("last", Tok::UNumber(-1)),
    ("this", Tok::MinuteUnit(0)),
    ("next", Tok::UNumber(2)),
    ("first", Tok::UNumber(1)),
    ("third", Tok::UNumber(3)),
    ("fourth", Tok::UNumber(4)),
    ("fifth", Tok::UNumber(5)),
    ("sixth", Tok::UNumber(6)),
    ("seventh", Tok::UNumber(7)),
    ("eighth", Tok::UNumber(8)),
    ("ninth", Tok::UNumber(9)),
    ("tenth", Tok::UNumber(10)),
    ("eleventh", Tok::UNumber(11)),
    ("twelfth", Tok::UNumber(12)),
    ("ago", Tok::Ago),
    ("never", Tok::Never),
];

/// The zone names compiled into MIT's `TimezoneTable` in `getdate.y`, minutes west of UTC.
const ZONES: &[(&str, Tok)] = &[
    ("gmt", Tok::Zone(hour(0))),
    ("ut", Tok::Zone(hour(0))),
    ("utc", Tok::Zone(hour(0))),
    ("wet", Tok::Zone(hour(0))),
    ("bst", Tok::DayZone(hour(0))),
    ("wat", Tok::Zone(hour(1))),
    ("at", Tok::Zone(hour(2))),
    ("ast", Tok::Zone(hour(4))),
    ("adt", Tok::DayZone(hour(4))),
    ("est", Tok::Zone(hour(5))),
    ("edt", Tok::DayZone(hour(5))),
    ("cst", Tok::Zone(hour(6))),
    ("cdt", Tok::DayZone(hour(6))),
    ("mst", Tok::Zone(hour(7))),
    ("mdt", Tok::DayZone(hour(7))),
    ("pst", Tok::Zone(hour(8))),
    ("pdt", Tok::DayZone(hour(8))),
    ("yst", Tok::Zone(hour(9))),
    ("ydt", Tok::DayZone(hour(9))),
    ("hst", Tok::Zone(hour(10))),
    ("hdt", Tok::DayZone(hour(10))),
    ("cat", Tok::Zone(hour(10))),
    ("ahst", Tok::Zone(hour(10))),
    ("nt", Tok::Zone(hour(11))),
    ("idlw", Tok::Zone(hour(12))),
    ("cet", Tok::Zone(-hour(1))),
    ("met", Tok::Zone(-hour(1))),
    ("mewt", Tok::Zone(-hour(1))),
    ("mest", Tok::DayZone(-hour(1))),
    ("swt", Tok::Zone(-hour(1))),
    ("sst", Tok::DayZone(-hour(1))),
    ("fwt", Tok::Zone(-hour(1))),
    ("fst", Tok::DayZone(-hour(1))),
    ("eet", Tok::Zone(-hour(2))),
    ("bt", Tok::Zone(-hour(3))),
    ("zp4", Tok::Zone(-hour(4))),
    ("zp5", Tok::Zone(-hour(5))),
    ("zp6", Tok::Zone(-hour(6))),
    ("wast", Tok::Zone(-hour(7))),
    ("wadt", Tok::DayZone(-hour(7))),
    ("cct", Tok::Zone(-hour(8))),
    ("jst", Tok::Zone(-hour(9))),
    ("kst", Tok::Zone(-hour(9))),
    ("east", Tok::Zone(-hour(10))),
    ("eadt", Tok::DayZone(-hour(10))),
    ("gst", Tok::Zone(-hour(10))),
    ("kdt", Tok::Zone(-hour(10))),
    ("nzt", Tok::Zone(-hour(12))),
    ("nzst", Tok::Zone(-hour(12))),
    ("nzdt", Tok::DayZone(-hour(12))),
    ("idle", Tok::Zone(-hour(12))),
];

fn find(table: &[(&str, Tok)], word: &str) -> Option<Tok> {
    table
        .iter()
        .find(|(name, _)| *name == word)
        .map(|(_, t)| *t)
}

/// MIT `LookupWord` (`getdate.y:681-774`): a word (letters and dots, lowercased) to its token.
fn lookup_word(word: &str) -> Tok {
    let mut buff = word.to_ascii_lowercase();
    if buff == "am" || buff == "a.m." {
        return Tok::Meridian(Meridian::Am);
    }
    if buff == "pm" || buff == "p.m." {
        return Tok::Meridian(Meridian::Pm);
    }
    let abbrev = if buff.len() == 3 {
        true
    } else if buff.len() == 4 && buff.as_bytes()[3] == b'.' {
        buff.truncate(3);
        true
    } else {
        false
    };
    for (name, tok) in MONTH_DAY {
        let hit = if abbrev {
            name.as_bytes().get(..3) == Some(buff.as_bytes())
        } else {
            *name == buff
        };
        if hit {
            return *tok;
        }
    }
    if let Some(t) = find(ZONES, &buff) {
        return t;
    }
    if buff == "dst" {
        return Tok::Dst;
    }
    if let Some(t) = find(UNITS, &buff) {
        return t;
    }
    if let Some(singular) = buff.strip_suffix('s')
        && let Some(t) = find(UNITS, singular)
    {
        return t;
    }
    if let Some(t) = find(OTHER, &buff) {
        return t;
    }
    if buff.contains('.') {
        let undotted: String = buff.chars().filter(|&c| c != '.').collect();
        if let Some(t) = find(ZONES, &undotted) {
            return t;
        }
    }
    Tok::Id
}

/// MIT `yylex` (`getdate.y:778-828`): the tokens of the whole phrase.
fn lex(s: &str) -> Vec<Tok> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    loop {
        while b
            .get(i)
            .is_some_and(|&c| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
        {
            i += 1;
        }
        let Some(&c) = b.get(i) else {
            out.push(Tok::End);
            return out;
        };
        if c.is_ascii_digit() || c == b'-' || c == b'+' {
            let sign = match c {
                b'-' => -1,
                b'+' => 1,
                _ => 0,
            };
            if sign != 0 {
                i += 1;
                if !b.get(i).is_some_and(u8::is_ascii_digit) {
                    continue;
                }
            }
            let mut n: i64 = 0;
            while let Some(&d) = b.get(i).filter(|d| d.is_ascii_digit()) {
                n = n.wrapping_mul(10).wrapping_add(i64::from(d - b'0'));
                i += 1;
            }
            out.push(match sign {
                0 => Tok::UNumber(n),
                s => Tok::SNumber(if s < 0 { n.wrapping_neg() } else { n }),
            });
            continue;
        }
        if c.is_ascii_alphabetic() {
            let start = i;
            while b
                .get(i)
                .is_some_and(|&d| d.is_ascii_alphabetic() || d == b'.')
            {
                i += 1;
            }
            let word = &s[start..i.min(start + 19)];
            out.push(lookup_word(word));
            continue;
        }
        i += 1;
        if c != b'(' {
            out.push(Tok::Char(c));
            continue;
        }
        let mut depth = 1u32;
        while depth > 0 {
            let Some(&d) = b.get(i) else {
                out.push(Tok::End);
                return out;
            };
            i += 1;
            match d {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
        }
    }
}

impl State {
    fn time(&mut self, h: i64, m: i64, s: i64, mer: Meridian) {
        self.hour = h;
        self.minutes = m;
        self.seconds = s;
        self.meridian = mer;
        self.have_time += 1;
    }

    fn time_offset(&mut self, h: i64, m: i64, s: i64, offset: i64) {
        self.time(h, m, s, Meridian::H24);
        self.dst = DstMode::Off;
        self.timezone = (offset % 100)
            .wrapping_add((offset / 100).wrapping_mul(60))
            .wrapping_neg();
    }

    fn date(&mut self, month: i64, day: i64, year: Option<i64>) {
        self.month = month;
        self.day = day;
        if let Some(y) = year {
            self.year = y;
        }
        self.have_date += 1;
    }

    /// The `rel` rule of `getdate.y`: `relunit [ago]`, `ago` negating every relative part.
    fn rel(&mut self, toks: &[Tok], i: usize) -> usize {
        self.have_rel += 1;
        if toks.get(i) == Some(&Tok::Ago) {
            self.rel_seconds = self.rel_seconds.wrapping_neg();
            self.rel_month = self.rel_month.wrapping_neg();
            return i + 1;
        }
        i
    }

    fn add_minutes(&mut self, n: i64) {
        self.rel_seconds = self.rel_seconds.wrapping_add(n.wrapping_mul(60));
    }

    /// The `spec` grammar of `getdate.y` as its yacc parser runs it (a conflict shifts), false
    /// on a syntax error.
    fn parse(&mut self, toks: &[Tok]) -> bool {
        let at = |i: usize| toks.get(i).copied().unwrap_or(Tok::End);
        let mut i = 0;
        if at(0) == Tok::Never {
            self.year = 1970;
            self.month = 1;
            self.day = 1;
            self.hour = 0;
            self.minutes = 0;
            self.seconds = 0;
            self.dst = DstMode::Off;
            self.timezone = 0;
            self.have_date += 1;
            i = 1;
        }
        loop {
            i = match (at(i), at(i + 1)) {
                (Tok::End, _) => return true,
                (Tok::UNumber(h), Tok::Meridian(m)) => {
                    self.time(h, 0, 0, m);
                    i + 2
                }
                (Tok::UNumber(h), Tok::Char(b':')) => {
                    let Tok::UNumber(m) = at(i + 2) else {
                        return false;
                    };
                    match (at(i + 3), at(i + 4)) {
                        (Tok::Char(b':'), Tok::UNumber(s)) => match at(i + 5) {
                            Tok::Meridian(mer) => {
                                self.time(h, m, s, mer);
                                i + 6
                            }
                            Tok::SNumber(z) => {
                                self.time_offset(h, m, s, z);
                                i + 6
                            }
                            _ => {
                                self.time(h, m, s, Meridian::H24);
                                i + 5
                            }
                        },
                        (Tok::Char(b':'), _) => return false,
                        (Tok::Meridian(mer), _) => {
                            self.time(h, m, 0, mer);
                            i + 4
                        }
                        (Tok::SNumber(z), _) => {
                            self.time_offset(h, m, 0, z);
                            i + 4
                        }
                        _ => {
                            self.time(h, m, 0, Meridian::H24);
                            i + 3
                        }
                    }
                }
                (Tok::UNumber(n), Tok::Day(d)) => {
                    self.day_ordinal = n;
                    self.day_number = d;
                    self.have_day += 1;
                    i + 2
                }
                (Tok::UNumber(m), Tok::Char(b'/')) => {
                    let Tok::UNumber(d) = at(i + 2) else {
                        return false;
                    };
                    match (at(i + 3), at(i + 4)) {
                        (Tok::Char(b'/'), Tok::UNumber(y)) => {
                            self.date(m, d, Some(y));
                            i + 5
                        }
                        (Tok::Char(b'/'), _) => return false,
                        _ => {
                            self.date(m, d, None);
                            i + 3
                        }
                    }
                }
                (Tok::UNumber(y), Tok::SNumber(m)) => {
                    let Tok::SNumber(d) = at(i + 2) else {
                        return false;
                    };
                    self.date(m.wrapping_neg(), d.wrapping_neg(), Some(y));
                    i + 3
                }
                (Tok::UNumber(d), Tok::Month(m)) => match at(i + 2) {
                    Tok::SNumber(y) => {
                        self.date(m, d, Some(y.wrapping_neg()));
                        i + 3
                    }
                    Tok::UNumber(y) => {
                        self.date(m, d, Some(y));
                        i + 3
                    }
                    _ => {
                        self.date(m, d, None);
                        i + 2
                    }
                },
                (Tok::UNumber(n) | Tok::SNumber(n), Tok::MinuteUnit(u)) => {
                    self.add_minutes(n.wrapping_mul(u));
                    self.rel(toks, i + 2)
                }
                (Tok::UNumber(n) | Tok::SNumber(n), Tok::SecUnit(_)) => {
                    self.rel_seconds = self.rel_seconds.wrapping_add(n);
                    self.rel(toks, i + 2)
                }
                (Tok::UNumber(n) | Tok::SNumber(n), Tok::MonthUnit(u)) => {
                    self.rel_month = self.rel_month.wrapping_add(n.wrapping_mul(u));
                    self.rel(toks, i + 2)
                }
                (Tok::MinuteUnit(u), _) => {
                    self.add_minutes(u);
                    self.rel(toks, i + 1)
                }
                (Tok::SecUnit(_), _) => {
                    self.rel_seconds = self.rel_seconds.wrapping_add(1);
                    self.rel(toks, i + 1)
                }
                (Tok::MonthUnit(u), _) => {
                    self.rel_month = self.rel_month.wrapping_add(u);
                    self.rel(toks, i + 1)
                }
                (Tok::Zone(z), next) => {
                    self.timezone = z;
                    self.have_zone += 1;
                    if next == Tok::Dst {
                        self.dst = DstMode::On;
                        i + 2
                    } else {
                        self.dst = DstMode::Off;
                        i + 1
                    }
                }
                (Tok::DayZone(z), _) => {
                    self.timezone = z;
                    self.dst = DstMode::On;
                    self.have_zone += 1;
                    i + 1
                }
                (Tok::Day(d), next) => {
                    self.day_ordinal = 1;
                    self.day_number = d;
                    self.have_day += 1;
                    if next == Tok::Char(b',') {
                        i + 2
                    } else {
                        i + 1
                    }
                }
                (Tok::Month(m), Tok::UNumber(d)) => match (at(i + 2), at(i + 3)) {
                    (Tok::Char(b','), Tok::UNumber(y)) => {
                        self.date(m, d, Some(y));
                        i + 4
                    }
                    (Tok::Char(b','), _) => return false,
                    _ => {
                        self.date(m, d, None);
                        i + 2
                    }
                },
                _ => return false,
            };
        }
    }
}

/// The broken-down local time `localtime` gives MIT, `None` outside the calendar.
struct Tm {
    year: i64,
    mon: i64,
    mday: i64,
    hour: i64,
    min: i64,
    sec: i64,
    wday: i64,
    isdst: bool,
}

fn localtime(t: i64) -> Option<Tm> {
    let utc = chrono::DateTime::from_timestamp(t, 0)?;
    let local = utc.with_timezone(&chrono::Local);
    let offset = local.offset().fix().local_minus_utc();
    // tm_isdst: the offset is above the year's standard one (the smaller of January's and
    // July's), which holds in every zone that observes summer time.
    let standard = [1, 7]
        .iter()
        .filter_map(|&m| {
            chrono::Utc
                .with_ymd_and_hms(utc.year(), m, 1, 0, 0, 0)
                .single()
                .map(|d| {
                    d.with_timezone(&chrono::Local)
                        .offset()
                        .fix()
                        .local_minus_utc()
                })
        })
        .min()
        .unwrap_or(offset);
    Some(Tm {
        year: i64::from(local.year()) - 1900,
        mon: i64::from(local.month0()),
        mday: i64::from(local.day()),
        hour: i64::from(local.hour()),
        min: i64::from(local.minute()),
        sec: i64::from(local.second()),
        wday: i64::from(local.weekday().num_days_from_sunday()),
        isdst: offset > standard,
    })
}

/// MIT `ToSeconds` (`getdate.y:534-555`): the time of day in seconds, `None` out of range.
fn to_seconds(h: i64, m: i64, s: i64, mer: Meridian) -> Option<i64> {
    if !(0..=59).contains(&m) || !(0..=59).contains(&s) {
        return None;
    }
    let h = match mer {
        Meridian::H24 if (0..=23).contains(&h) => h,
        Meridian::Am if (1..=12).contains(&h) => h,
        Meridian::Pm if (1..=12).contains(&h) => h + 12,
        _ => return None,
    };
    Some((h * 60 + m) * 60 + s)
}

/// A calendar moment for MIT `Convert`: `yyMonth`, `yyDay`, `yyYear` and the time of day.
struct Moment {
    month: i64,
    day: i64,
    year: i64,
    hour: i64,
    minutes: i64,
    seconds: i64,
}

/// MIT `Convert` (`getdate.y:562-606`): its leap-year rule included; `timezone` is the global
/// `yyTimezone` (minutes west).
fn convert(at: &Moment, mer: Meridian, dst: DstMode, timezone: i64) -> Option<i64> {
    let mut year = at.year.wrapping_abs();
    if year < 1900 {
        year += 1900;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(EPOCH..=EPOCH_END).contains(&year) || !(1..=12).contains(&at.month) {
        return None;
    }
    let mon = usize::try_from(at.month - 1).ok()?;
    if at.day < 1 || at.day > days_in[mon] {
        return None;
    }
    let mut julian = at.day - 1 + days_in[..mon].iter().sum::<i64>();
    for i in EPOCH..year {
        julian += 365 + i64::from(i % 4 == 0 && (year % 100 != 0 || year % 400 == 0));
    }
    julian *= SECSPERDAY;
    julian = julian.wrapping_add(timezone.wrapping_mul(60));
    julian = julian.wrapping_add(to_seconds(at.hour, at.minutes, at.seconds, mer)?);
    match dst {
        DstMode::On => julian -= 60 * 60,
        DstMode::Off => {}
        DstMode::Maybe => {
            if localtime(julian)?.isdst {
                julian -= 60 * 60;
            }
        }
    }
    Some(julian)
}

/// MIT `DSTcorrect` (`getdate.y:610-630`): the distance corrected for a summer-time change.
fn dst_correct(start: i64, future: i64) -> Option<i64> {
    let start_day = (localtime(start)?.hour + 1) % 24;
    let future_day = (localtime(future)?.hour + 1) % 24;
    Some((future - start) + (start_day - future_day) * 60 * 60)
}

/// MIT `RelativeDate` (`getdate.y:634-648`): the distance to the named weekday.
fn relative_date(start: i64, ordinal: i64, number: i64) -> Option<i64> {
    let tm = localtime(start)?;
    let mut now = start;
    now = now.wrapping_add(SECSPERDAY.wrapping_mul((number - tm.wday + 7) % 7));
    let weeks = if ordinal <= 0 { ordinal } else { ordinal - 1 };
    now = now.wrapping_add(7_i64.wrapping_mul(SECSPERDAY).wrapping_mul(weeks));
    dst_correct(start, now)
}

/// MIT `RelativeMonth` (`getdate.y:652-677`): `timezone` is the global `yyTimezone`.
fn relative_month(start: i64, rel_month: i64, timezone: i64) -> Option<i64> {
    if rel_month == 0 {
        return Some(0);
    }
    let tm = localtime(start)?;
    let month = (12 * tm.year + tm.mon).wrapping_add(rel_month);
    let at = Moment {
        month: month % 12 + 1,
        day: tm.mday,
        year: month / 12,
        hour: tm.hour,
        minutes: tm.min,
        seconds: tm.sec,
    };
    let ret = convert(&at, Meridian::H24, DstMode::Maybe, timezone)?;
    dst_correct(start, ret)
}

/// MIT `get_date_rel` (`getdate.y:864-880`): `ftz.timezone`, minutes west of UTC at `t`.
fn local_minutes_west(t: i64) -> Option<i64> {
    let utc = chrono::DateTime::from_timestamp(t, 0)?;
    let offset = utc
        .with_timezone(&chrono::Local)
        .offset()
        .fix()
        .local_minus_utc();
    Some(-i64::from(offset / 60))
}

impl State {
    fn at(tm: &Tm) -> Self {
        Self {
            dst: DstMode::Maybe,
            day_ordinal: 0,
            day_number: 0,
            have_date: 0,
            have_day: 0,
            have_rel: 0,
            have_time: 0,
            have_zone: 0,
            timezone: 0,
            day: tm.mday,
            hour: 0,
            minutes: 0,
            month: tm.mon + 1,
            seconds: 0,
            year: tm.year,
            meridian: Meridian::H24,
            rel_month: 0,
            rel_seconds: 0,
        }
    }
}

/// MIT `get_date_rel` (`getdate.y:864-1012`): the moment `p` names, relative to `now`; `None`
/// where MIT returns -1.
#[must_use]
pub fn get_date_rel(p: &str, now: i64) -> Option<i64> {
    let tm = localtime(now)?;
    let mut st = State::at(&tm);
    st.timezone = local_minutes_west(now)?;
    if !st.parse(&lex(p))
        || st.have_time > 1
        || st.have_zone > 1
        || st.have_date > 1
        || st.have_day > 1
    {
        return None;
    }
    let mut start = if st.have_date > 0 || st.have_time > 0 || st.have_day > 0 {
        let at = Moment {
            month: st.month,
            day: st.day,
            year: st.year,
            hour: st.hour,
            minutes: st.minutes,
            seconds: st.seconds,
        };
        let t = convert(&at, st.meridian, st.dst, st.timezone)?;
        if t < 0 {
            return None;
        }
        t
    } else {
        let mut t = now;
        if st.have_rel == 0 {
            t -= (tm.hour * 60 + tm.min) * 60 + tm.sec;
        }
        t
    };
    start = start.wrapping_add(st.rel_seconds);
    let delta = relative_month(start, st.rel_month, st.timezone)?;
    if delta == -1 {
        return None;
    }
    start = start.wrapping_add(delta);
    if st.have_day > 0 && st.have_date == 0 {
        start = start.wrapping_add(relative_date(start, st.day_ordinal, st.day_number)?);
    }
    Some(if start == -1 { 0 } else { start })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-01 21:53:53 UTC, the settle run's clock; the tests assume `TZ` is UTC or unset
    /// in a UTC container, as the gates and CI run.
    const NOW: i64 = 1_790_891_633;

    fn utc() -> bool {
        local_minutes_west(NOW) == Some(0) && !localtime(NOW).is_some_and(|t| t.isdst)
    }

    #[test]
    fn absolute_dates_in_the_forms_kadmin_scripts_use() {
        let d = |s: &str| get_date_rel(s, NOW);
        assert_eq!(d("2030-01-01 00:00:00 UTC"), Some(1_893_456_000));
        assert_eq!(d("Jan 1, 2020 00:00:00 UTC"), Some(1_577_836_800));
        assert_eq!(d("2031-06-01 12:00:00 UTC"), Some(1_938_081_600));
        assert_eq!(d("1970-01-01 00:00:01 UTC"), Some(1));
        assert_eq!(d("never"), Some(0));
        assert_eq!(d("now"), Some(NOW));
        assert_eq!(d("tomorrow"), Some(NOW + 86_400));
        assert_eq!(d("+90 days"), Some(NOW + 90 * 86_400));
        if !utc() {
            return;
        }
        assert_eq!(d("2030-01-01"), Some(1_893_456_000));
        assert_eq!(d("1/1/1990"), Some(631_152_000));
        assert_eq!(d("1/1/90"), Some(631_152_000));
        assert_eq!(d("17-JUN-1992"), Some(708_739_200));
        assert_eq!(d("10:00pm"), Some(1_790_892_000));
        assert_eq!(d("22:00 +0100"), Some(1_790_892_000 - 3_600));
        assert_eq!(
            d(""),
            Some(NOW - NOW % 86_400),
            "an empty phrase is today's midnight"
        );
    }

    #[test]
    fn what_getdate_refuses() {
        for s in [
            "1",
            "bogus-date",
            "bogus",
            "42 ",
            "2030-01",
            "13/1/2020",
            "Feb 30, 2021",
        ] {
            assert_eq!(get_date_rel(s, NOW), None, "{s}");
        }
        assert_eq!(get_date_rel("1/1/1960", NOW), None, "before the epoch");
        assert_eq!(get_date_rel("10:00 11:00", NOW), None, "two times");
    }

    #[test]
    fn intervals_take_a_deltat_first_then_a_relative_date() {
        assert_eq!(parse_interval("7days", NOW), Ok(7 * 86_400));
        assert_eq!(parse_interval("7d", NOW), Ok(7 * 86_400));
        assert_eq!(parse_interval("10h", NOW), Ok(36_000));
        assert_eq!(parse_interval("2 hours", NOW), Ok(7_200));
        assert_eq!(parse_interval("1 week", NOW), Ok(7 * 86_400));
        assert_eq!(parse_interval("30 days", NOW), Ok(30 * 86_400));
        assert_eq!(parse_interval("never", NOW), Ok(0));
        assert_eq!(
            parse_interval("42 ", NOW).unwrap_err().to_string(),
            "Invalid date specification \"42 \"."
        );
        assert_eq!(
            parse_interval("Jan 1, 1990", NOW).unwrap_err().to_string(),
            "Interval specification \"Jan 1, 1990\" is in the past."
        );
        assert_eq!(
            parse_interval("2 days ago", NOW).unwrap_err(),
            DateError::InPast("2 days ago".into())
        );
        assert_eq!(
            parse_interval("1/1/1990", NOW),
            Ok(1),
            "deltat stops at the '/'"
        );
    }

    #[test]
    fn words_follow_lookup_word() {
        assert_eq!(lookup_word("Sep"), Tok::Month(9));
        assert_eq!(lookup_word("sept"), Tok::Month(9));
        assert_eq!(lookup_word("Thu."), Tok::Day(4));
        assert_eq!(lookup_word("days"), Tok::MinuteUnit(1_440));
        assert_eq!(lookup_word("this"), Tok::MinuteUnit(0));
        assert_eq!(lookup_word("u.t.c."), Tok::Zone(0));
        assert_eq!(lookup_word("p.m."), Tok::Meridian(Meridian::Pm));
        assert_eq!(lookup_word("fortnights"), Tok::MinuteUnit(20_160));
        assert_eq!(lookup_word("bogus"), Tok::Id);
        assert_eq!(
            lex("+ 5 (a (b) c) -3"),
            [Tok::UNumber(5), Tok::SNumber(-3), Tok::End]
        );
    }
}
