// MIT: `krb5_string_to_timestamp` (lib/krb5/krb/str_conv.c:145-196)

use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use jiff::Timestamp;
use jiff::civil::DateTime;
use jiff::tz::{Offset, TimeZone};

mod locale;
mod strftime;

pub use locale::LcTime;
pub use strftime::{Tm, strftime_tm};

static LC_TIME: OnceLock<LcTime> = OnceLock::new();
static FIRST: OnceLock<Arc<Zone>> = OnceLock::new();
static KEPT: Mutex<Kept> = Mutex::new(None);
static LOCALTIME_OFFSET: AtomicI64 = AtomicI64::new(0);
static GMTIME_OFFSET: AtomicI64 = AtomicI64::new(0);

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

// glibc 2.36's stable branch: tzset, tzfile and mktime.
const TZDEFAULT: &str = "/etc/localtime";

#[derive(Clone, Copy, Default)]
enum Day {
    #[default]
    J0,
    J1,
    M,
}

#[derive(Clone, Default)]
struct Rule {
    name: String,
    offset: i64,
    day: Day,
    m: u16,
    n: u16,
    d: u16,
    secs: i64,
}

enum Kind {
    File(TimeZone),
    Rules([Rule; 2]),
    Default {
        trans: Vec<(i64, bool)>,
        rules: [Rule; 2],
        spec: Option<[Rule; 2]>,
    },
}

struct Zone {
    kind: Kind,
    leaps: Vec<(i64, i64)>,
}

struct Local {
    dt: DateTime,
    hit: i8,
    isdst: bool,
    off: i64,
    zone: String,
}

type Ydhms = [i64; 5];

impl Zone {
    const fn rules(r: [Rule; 2]) -> Self {
        Self {
            kind: Kind::Rules(r),
            leaps: Vec::new(),
        }
    }

    fn convert(&self, t: i64) -> Option<Local> {
        let ts = Timestamp::from_second(t).ok()?;
        let (isdst, off, zone) = match &self.kind {
            Kind::File(tz) => {
                let i = tz.to_offset_info(ts);
                let off = i64::from(i.offset().seconds());
                (i.dst().is_dst(), off, i.abbreviation().to_owned())
            }
            Kind::Rules(r) => rules_at(r, ts),
            Kind::Default { trans, rules, spec } => match (trans.last(), spec) {
                (Some(&(last, _)), Some(r)) if t >= last => rules_at(r, ts),
                _ => {
                    let i = trans.partition_point(|&(at, _)| at <= t);
                    let dst = i
                        .checked_sub(1)
                        .and_then(|i| trans.get(i))
                        .is_some_and(|x| x.1);
                    let r = &rules[usize::from(dst)];
                    (dst, r.offset, r.name.clone())
                }
            },
        };
        let (corr, hit) = leap(&self.leaps, t);
        let dt = Offset::UTC.to_datetime(Timestamp::from_second(t - corr + off).ok()?);
        Some(Local {
            dt,
            hit,
            isdst,
            off,
            zone,
        })
    }

    fn ydhms(&self, t: i64) -> Option<(Ydhms, bool)> {
        self.convert(t).map(|l| (ydhms(l.dt, l.hit), l.isdst))
    }
}

fn ydhms(dt: DateTime, hit: i8) -> Ydhms {
    [
        i64::from(dt.year()) - 1900,
        i64::from(dt.day_of_year()) - 1,
        i64::from(dt.hour()),
        i64::from(dt.minute()),
        i64::from(dt.second() + hit),
    ]
}

fn leap(leaps: &[(i64, i64)], t: i64) -> (i64, i8) {
    let Some(mut i) = leaps.iter().rposition(|&(at, _)| at <= t) else {
        return (0, 0);
    };
    let corr = leaps[i].1;
    let mut hit = 0;
    if t == leaps[i].0 && corr > i.checked_sub(1).map_or(0, |p| leaps[p].1) {
        hit = 1;
        while i > 0 && leaps[i].0 == leaps[i - 1].0 + 1 && leaps[i].1 == leaps[i - 1].1 + 1 {
            hit += 1;
            i -= 1;
        }
    }
    (corr, hit)
}

fn rules_at(r: &[Rule; 2], ts: Timestamp) -> (bool, i64, String) {
    let year = i64::from(Offset::UTC.to_datetime(ts).year());
    let (t, c0, c1) = (ts.as_second(), change(&r[0], year), change(&r[1], year));
    let dst = if c0 > c1 {
        t < c1 || t >= c0
    } else {
        t >= c0 && t < c1
    };
    let r = &r[usize::from(dst)];
    (dst, r.offset, r.name.clone())
}

fn change(r: &Rule, year: i64) -> i64 {
    const DAY: i64 = 86_400;
    const MON_YDAY: [i64; 26] = [
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365, 0, 31, 60, 91, 121, 152, 182,
        213, 244, 274, 305, 335, 366,
    ];
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mut t = if year > 1970 {
        let y = year - 1;
        ((year - 1970) * 365 + y / 4 - 1970 / 4 - (y / 100 - 1970 / 100) + (y / 400 - 1970 / 400))
            * DAY
    } else {
        0
    };
    let d = i64::from(r.d);
    match r.day {
        Day::J1 => t += (d - 1 + i64::from(d >= 60 && leap)) * DAY,
        Day::J0 => t += d * DAY,
        Day::M => {
            let m = i64::from(r.m);
            let yday = |i: i64| {
                usize::try_from(i64::from(leap) * 13 + i)
                    .ok()
                    .and_then(|i| MON_YDAY.get(i))
                    .copied()
                    .unwrap_or(0)
            };
            let (first, next) = (yday(m - 1), yday(m));
            let yy0 = if m <= 2 { year - 1 } else { year };
            let (yy1, yy2) = (yy0 / 100, yy0 % 100);
            let dow =
                ((26 * ((m + 9) % 12 + 1) - 2) / 10 + 1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
            let mut day = d - if dow < 0 { dow + 7 } else { dow };
            if day < 0 {
                day += 7;
            }
            for _ in 1..r.n {
                if day + 7 >= next - first {
                    break;
                }
                day += 7;
            }
            t += (first + day) * DAY;
        }
    }
    t - r.offset + r.secs
}

type Stat = (u64, u64, i64);
type Kept = Option<(Option<String>, Option<Stat>, Arc<Zone>)>;

fn first_zone() -> &'static Arc<Zone> {
    FIRST.get_or_init(|| {
        let env = tz_env();
        let (z, st) = load(env.as_deref(), false);
        let z = Arc::new(z);
        keep(
            &mut KEPT.lock().unwrap_or_else(PoisonError::into_inner),
            env,
            st,
            &z,
        );
        z
    })
}

// glibc `tzset_internal`; `steady`: not the process's first evaluation.
fn local_zone(steady: bool) -> Arc<Zone> {
    if !steady {
        return first_zone().clone();
    }
    first_zone();
    let env = tz_env();
    let mut kept = KEPT.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((tz, st, z)) = kept.as_ref()
        && *tz == env
        && (env.is_some() || file_stat(Path::new(TZDEFAULT)) == *st)
    {
        return z.clone();
    }
    let (z, st) = load(env.as_deref(), true);
    let z = Arc::new(z);
    keep(&mut kept, env, st, &z);
    z
}

// Not kept: `posixrules` (glibc drops `old_tz`), or no `/etc/localtime` read.
fn keep(kept: &mut Kept, env: Option<String>, st: Option<Stat>, z: &Arc<Zone>) {
    let ok = !matches!(z.kind, Kind::Default { .. }) && (env.is_some() || st.is_some());
    *kept = ok.then(|| (env, st, z.clone()));
}

fn tz_env() -> Option<String> {
    std::env::var_os("TZ").map(|v| v.to_string_lossy().into_owned())
}

fn file_stat(p: &Path) -> Option<Stat> {
    std::fs::metadata(p)
        .ok()
        .map(|m| (m.dev(), m.ino(), m.mtime()))
}

fn load(env: Option<&str>, steady: bool) -> (Zone, Option<Stat>) {
    let tz = match env {
        None => TZDEFAULT,
        Some("") => "Universal",
        Some(v) => v.strip_prefix(':').unwrap_or(v),
    };
    if let Some((b, f, st)) = tzfile_read(tz)
        && let Ok(z) = TimeZone::tzif(tz, &b)
    {
        let z = Zone {
            kind: Kind::File(z),
            leaps: f.leaps,
        };
        return (z, Some(st));
    }
    if tz.is_empty() || tz == TZDEFAULT {
        let utc = Rule {
            name: "UTC".to_owned(),
            ..Rule::default()
        };
        return (Zone::rules([utc.clone(), utc]), None);
    }
    (parse_tz(tz, Some(steady)), None)
}

struct Tzif {
    trans: Vec<(i64, usize)>,
    types: Vec<(i64, bool, bool, bool)>,
    leaps: Vec<(i64, i64)>,
    spec: String,
}

// glibc `__tzfile_read`; jiff hides isstd/isut and leaps.
fn tzfile_read(file: &str) -> Option<(Vec<u8>, Tzif, Stat)> {
    if file.is_empty() {
        return None;
    }
    let path = if file.starts_with('/') {
        PathBuf::from(file)
    } else {
        let dir = std::env::var_os("TZDIR").filter(|d| !d.is_empty());
        Path::new(dir.as_deref().unwrap_or(OsStr::new("/usr/share/zoneinfo"))).join(file)
    };
    let mut file = std::fs::File::open(path).ok()?;
    let m = file.metadata().ok()?;
    let mut b = Vec::new();
    file.read_to_end(&mut b).ok()?;
    let f = tzif(&b)?;
    Some((b, f, (m.dev(), m.ino(), m.mtime())))
}

fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Option<&'a [u8]> {
    let s = b.get(*p..p.checked_add(n)?)?;
    *p += n;
    Some(s)
}

fn be(s: &[u8]) -> Option<i64> {
    Some(match s.len() {
        8 => i64::from_be_bytes(s.try_into().ok()?),
        _ => i64::from(i32::from_be_bytes(s.try_into().ok()?)),
    })
}

fn tzif(b: &[u8]) -> Option<Tzif> {
    let n = |o: usize, i: usize| -> Option<usize> {
        let c = b.get(o + 20 + 4 * i..o + 24 + 4 * i)?;
        usize::try_from(u32::from_be_bytes(c.try_into().ok()?)).ok()
    };
    if !b.starts_with(b"TZif") {
        return None;
    }
    let (o, w) = if *b.get(4)? >= b'2' {
        let v1 = n(0, 3)? * 5 + n(0, 4)? * 6 + n(0, 5)? + n(0, 2)? * 8 + n(0, 1)? + n(0, 0)?;
        (44 + v1, 8)
    } else {
        (0, 4)
    };
    let (nt, ny) = (n(o, 3)?, n(o, 4)?);
    let mut p = o + 44;
    let times = take(b, &mut p, nt * w)?;
    let idx = take(b, &mut p, nt)?;
    let types = take(b, &mut p, ny * 6)?;
    take(b, &mut p, n(o, 5)?)?;
    let leaps = take(b, &mut p, n(o, 2)? * (w + 4))?;
    let isstd = take(b, &mut p, n(o, 1)?)?;
    let isut = take(b, &mut p, n(o, 0)?)?;
    let flag = |s: &[u8], i: usize| s.get(i).is_some_and(|&c| c != 0);
    let spec = if w == 8 {
        b.get(p..)
            .and_then(|r| r.strip_prefix(b"\n"))
            .and_then(<[u8]>::split_last)
            .map(|(_, s)| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    Some(Tzif {
        trans: times
            .chunks(w)
            .zip(idx)
            .map(|(t, &i)| Some((be(t)?, usize::from(i))).filter(|x| x.1 < ny))
            .collect::<Option<_>>()?,
        types: (0..ny)
            .map(|i| {
                let t = types.get(6 * i..6 * i + 6)?;
                Some((be(&t[..4])?, t[4] != 0, flag(isstd, i), flag(isut, i)))
            })
            .collect::<Option<_>>()?,
        leaps: leaps
            .chunks(w + 4)
            .map(|l| Some((be(&l[..w])?, be(&l[w..])?)))
            .collect::<Option<_>>()?,
        spec,
    })
}

// glibc `__tzfile_default`: `rule_dstoff` stays 0 until a first run sets it.
fn tzfile_default(r: &[Rule; 2], steady: bool) -> Option<Zone> {
    let (_, f, _) = tzfile_read("posixrules")?;
    let first = f.types.first().filter(|_| f.types.len() >= 2)?.0;
    let (std0, dst0) = if f.trans.is_empty() {
        (first, first)
    } else {
        let std = f
            .trans
            .iter()
            .rev()
            .map(|&(_, i)| f.types[i])
            .find(|t| !t.1);
        (std.map_or(0, |t| t.0), if steady { r[1].offset } else { 0 })
    };
    let mut was_dst = false;
    let trans = f
        .trans
        .iter()
        .map(|&(at, i)| {
            let (_, dst, isstd, isut) = f.types[i];
            let at = match (isut, was_dst && !isstd) {
                (true, _) => at,
                (_, true) => at + r[1].offset - dst0,
                _ => at + r[0].offset - std0,
            };
            was_dst = dst;
            (at, dst)
        })
        .collect();
    let spec = match parse_tz(&f.spec, None).kind {
        Kind::Rules(s) if !f.spec.is_empty() => Some(s),
        _ => None,
    };
    Some(Zone {
        kind: Kind::Default {
            trans,
            rules: r.clone(),
            spec,
        },
        leaps: f.leaps,
    })
}

fn parse_tz(tz: &str, default: Option<bool>) -> Zone {
    let mut r: [Rule; 2] = Default::default();
    let mut s = tz.as_bytes();
    if parse_tzname(&mut s, &mut r[0]) && parse_offset(&mut s, &mut r, 0) {
        if s.is_empty() {
            r[1] = Rule {
                name: r[0].name.clone(),
                offset: r[0].offset,
                ..Rule::default()
            };
        } else {
            if parse_tzname(&mut s, &mut r[1]) {
                parse_offset(&mut s, &mut r, 1);
                if let Some(steady) = default
                    && (s.is_empty() || s == b",")
                    && let Some(z) = tzfile_default(&r, steady)
                {
                    return z;
                }
            }
            if parse_rule(&mut s, &mut r[0], true) {
                parse_rule(&mut s, &mut r[1], false);
            }
        }
    }
    Zone::rules(r)
}

fn parse_tzname(s: &mut &[u8], r: &mut Rule) -> bool {
    let n = s.iter().take_while(|c| c.is_ascii_alphabetic()).count();
    let (name, rest) = if n >= 3 {
        s.split_at(n)
    } else {
        let Some(q) = s.strip_prefix(b"<") else {
            return false;
        };
        let n = q
            .iter()
            .take_while(|&&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'-')
            .count();
        if n < 3 || q.get(n) != Some(&b'>') {
            return false;
        }
        (&q[..n], &q[n + 1..])
    };
    r.name = String::from_utf8_lossy(name).into_owned();
    *s = rest;
    true
}

fn scan_hu(s: &[u8]) -> Option<(u16, usize)> {
    let mut i = s.iter().take_while(|&&c| is_space(c)).count();
    let neg = s.get(i) == Some(&b'-');
    i += usize::from(matches!(s.get(i), Some(b'+' | b'-')));
    let n = s
        .get(i..)?
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .count();
    let v = s
        .get(i..i + n)?
        .iter()
        .try_fold(0u64, |a, &c| {
            a.checked_mul(10)?.checked_add(u64::from(c - b'0'))
        })
        .map_or(u64::MAX, |v| if neg { v.wrapping_neg() } else { v });
    (n > 0).then(|| (u16::try_from(v & 0xffff).unwrap_or(0), i + n))
}

fn scan_hms(s: &[u8]) -> ([Option<u16>; 3], usize) {
    let mut f = [None; 3];
    let mut used = 0;
    for (i, slot) in f.iter_mut().enumerate() {
        let at = used + usize::from(i > 0);
        if i > 0 && s.get(used) != Some(&b':') {
            break;
        }
        let Some((v, n)) = s.get(at..).and_then(scan_hu) else {
            break;
        };
        *slot = Some(v);
        used = at + n;
    }
    (f, used)
}

fn parse_offset(s: &mut &[u8], r: &mut [Rule; 2], which: usize) -> bool {
    let signed = matches!(s.first(), Some(b'+' | b'-'));
    if which == 0 && !signed && !s.first().is_some_and(u8::is_ascii_digit) {
        return false;
    }
    let sign = if s.first() == Some(&b'-') { 1 } else { -1 };
    *s = &s[usize::from(signed)..];
    let ([hh, mm, ss], used) = scan_hms(s);
    let Some(hh) = hh else {
        if which == 0 {
            r[0].offset = 0;
            return false;
        }
        r[1].offset = r[0].offset + 3600;
        return true;
    };
    let clamp = |v: Option<u16>, max: u16| i64::from(v.unwrap_or(0).min(max));
    r[which].offset = sign * (clamp(ss, 59) + clamp(mm, 59) * 60 + clamp(Some(hh), 24) * 3600);
    *s = &s[used..];
    true
}

fn parse_rule(s: &mut &[u8], r: &mut Rule, first: bool) -> bool {
    let mut t = s.strip_prefix(b",").unwrap_or(s);
    match t.first() {
        Some(&c) if c == b'J' || c.is_ascii_digit() => {
            let j = c == b'J';
            r.day = if j { Day::J1 } else { Day::J0 };
            t = &t[usize::from(j)..];
            let n = t.iter().take_while(|c| c.is_ascii_digit()).count();
            let d = t[..n].iter().try_fold(0u64, |a, &c| {
                a.checked_mul(10)?.checked_add(u64::from(c - b'0'))
            });
            match d.and_then(|d| u16::try_from(d).ok()) {
                Some(d) if n > 0 && d <= 365 && !(j && d == 0) => r.d = d,
                _ => return false,
            }
            t = &t[n..];
        }
        Some(b'M') => {
            r.day = Day::M;
            let mut at = 1;
            let mut got = 0;
            for (k, field) in [&mut r.m, &mut r.n, &mut r.d].into_iter().enumerate() {
                if k > 0 && t.get(at) != Some(&b'.') {
                    break;
                }
                at += usize::from(k > 0);
                let Some((v, n)) = t.get(at..).and_then(scan_hu) else {
                    break;
                };
                *field = v;
                at += n;
                got += 1;
            }
            if got != 3 || !(1..=12).contains(&r.m) || !(1..=5).contains(&r.n) || r.d > 6 {
                return false;
            }
            t = &t[at..];
        }
        None => {
            (r.day, r.m, r.n, r.d) = if first {
                (Day::M, 3, 2, 0)
            } else {
                (Day::M, 11, 1, 0)
            }
        }
        Some(_) => return false,
    }
    match t.first() {
        None | Some(b',') => r.secs = 7200,
        Some(b'/') => {
            t = &t[1..];
            if t.is_empty() {
                return false;
            }
            let neg = t[0] == b'-';
            t = &t[usize::from(neg)..];
            let ([hh, mm, ss], used) = scan_hms(t);
            t = &t[used..];
            let secs = i64::from(hh.unwrap_or(2)) * 3600 + i64::from(mm.unwrap_or(0)) * 60;
            r.secs = (secs + i64::from(ss.unwrap_or(0))) * if neg { -1 } else { 1 };
        }
        Some(_) => return false,
    }
    *s = t;
    true
}

fn gmt_leaps() -> &'static [(i64, i64)] {
    &first_zone().leaps
}

/// A leap-second (`right/`) zone file.
pub(crate) fn leap_zone() -> bool {
    !gmt_leaps().is_empty()
}

pub(crate) fn gmtime(t: i64) -> Option<(DateTime, i8)> {
    let (corr, hit) = leap(gmt_leaps(), t);
    Some((
        Offset::UTC.to_datetime(Timestamp::from_second(t - corr).ok()?),
        hit,
    ))
}

pub(crate) fn timegm(year: i64, mon: i64, mday: i64, hour: i64, min: i64, sec: i64) -> Option<i64> {
    let at = AtTm {
        year: year - 1900,
        mon,
        mday,
        hour,
        min,
        sec,
        isdst: false,
    };
    mktime(
        |t| gmtime(t).map(|(dt, hit)| (ydhms(dt, hit), false)),
        &at,
        &GMTIME_OFFSET,
    )
}

fn local_tm(t: i64, steady: bool) -> Option<(Tm, bool)> {
    let l = local_zone(steady).convert(t)?;
    let tm = Tm {
        sec: i32::from(l.dt.second() + l.hit),
        min: i32::from(l.dt.minute()),
        hour: i32::from(l.dt.hour()),
        mday: i32::from(l.dt.day()),
        mon: i32::from(l.dt.month()) - 1,
        year: i32::from(l.dt.year()) - 1900,
        wday: i32::from(l.dt.weekday().to_sunday_zero_offset()),
        yday: i32::from(l.dt.day_of_year()) - 1,
        gmtoff: l.off,
        zone: l.zone,
        epoch: t,
    };
    Some((tm, l.isdst))
}

#[must_use]
pub fn localtime(t: u32) -> Option<Tm> {
    local_tm(i64::from(t), false).map(|x| x.0)
}

// MIT's `localtime()` callers (kadmin, getdate, kadmind, the logs), and `tm_isdst`.
#[must_use]
pub fn localtime_steady(t: i64) -> Option<(Tm, bool)> {
    local_tm(t, true)
}

// kadmin's `strdate`.
#[must_use]
pub fn strftime(fmt: &str, t: u32, maxsize: usize) -> Option<String> {
    strftime_tm(&lc_time(), fmt, &localtime_steady(i64::from(t))?.0, maxsize)
}

// MIT: `krb5_timestamp_to_string` (lib/krb5/krb/str_conv.c:199-213)
#[must_use]
pub fn timestamp_to_string(t: u32, buflen: usize) -> Option<String> {
    strftime_tm(&lc_time(), "%c", &localtime(t)?, buflen)
}

// MIT: `krb5_timestamp_to_sfstring` (lib/krb5/krb/str_conv.c:216-252)
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
    isdst: bool,
}

impl AtTm {
    fn at(z: &Zone, t: i64) -> Option<Self> {
        let l = z.convert(t)?;
        Some(Self {
            year: i64::from(l.dt.year()) - 1900,
            mon: i64::from(l.dt.month()) - 1,
            mday: i64::from(l.dt.day()),
            hour: i64::from(l.dt.hour()),
            min: i64::from(l.dt.minute()),
            sec: i64::from(l.dt.second() + l.hit),
            isdst: l.isdst,
        })
    }
}

fn ydhms_diff(a: &Ydhms, b: &Ydhms) -> i64 {
    let leaps = |y: i64| {
        let a4 = (y >> 2) + (1900 >> 2) - i64::from(y % 4 == 0);
        let a100 = (a4 + i64::from(a4 < 0)) / 25 - i64::from(a4 < 0);
        a4 - a100 + (a100 >> 2)
    };
    let days = 365 * (a[0] - b[0]) + a[1] - b[1] + leaps(a[0]) - leaps(b[0]);
    ((days * 24 + a[2] - b[2]) * 60 + a[3] - b[3]) * 60 + a[4] - b[4]
}

// glibc `__mktime_internal`, from the caller's kept guess; None is -1.
fn mktime(
    conv: impl Fn(i64) -> Option<(Ydhms, bool)>,
    r: &AtTm,
    offset: &AtomicI64,
) -> Option<i64> {
    const STRIDE: i64 = 601_200;
    const BOUND: i64 = 457_243_209 / 2 + STRIDE;
    const MON_YDAY: [[i64; 12]; 2] = [
        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334],
        [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335],
    ];
    let year = r.year + r.mon.div_euclid(12);
    let y = year + 1900;
    let leap = usize::from(y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
    let yday = MON_YDAY[leap][usize::try_from(r.mon.rem_euclid(12)).ok()?] - 1 + r.mday;
    let sec = r.sec.clamp(0, 59);
    let want = [year, yday, r.hour, r.min, sec];
    let base = ydhms_diff(&want, &[70, 0, 0, 0, 0]);
    let t0 = base + offset.load(Ordering::Relaxed);
    let (mut t, mut t1, mut t2) = (t0, t0, t0);
    let (mut tm, mut dst) = conv(t)?;
    let mut probes = 6;
    let gap = loop {
        let dt = ydhms_diff(&want, &tm);
        if dt == 0 {
            break false;
        }
        if t == t1 && t != t2 && dst != r.isdst {
            break true;
        }
        probes -= 1;
        if probes == 0 {
            return None;
        }
        (t1, t2, t) = (t2, t, t + dt);
        (tm, dst) = conv(t)?;
    };
    if !gap && dst != r.isdst {
        let found = (STRIDE..BOUND)
            .step_by(601_200)
            .flat_map(|d| [-d, d])
            .find_map(|d| {
                let (otm, odst) = conv(t + d)?;
                let gt = t + d + ydhms_diff(&want, &otm);
                (odst == r.isdst && conv(gt).is_some()).then_some(gt)
            });
        t = found.unwrap_or(t + 3600 * (i64::from(!r.isdst) - i64::from(!dst)));
        (tm, _) = conv(t)?;
    }
    offset.store(t - base, Ordering::Relaxed);
    if r.sec != tm[4] {
        t += i64::from(sec == 0 && tm[4] == 60) - sec + r.sec;
        conv(t)?;
    }
    Some(t)
}

#[must_use]
pub fn string_to_timestamp(s: &str) -> Option<u32> {
    let now = AtTm::at(&local_zone(false), Timestamp::now().as_second())?;
    string_to_timestamp_at(s, &local_zone(true), now)
}

fn string_to_timestamp_at(s: &str, z: &Zone, now: AtTm) -> Option<u32> {
    let b = s.as_bytes();
    for fmt in FORMATS {
        let mut tm = now;
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
        // MIT: `krb5_string_to_timestamp` (lib/krb5/krb/str_conv.c:188-190)
        if let Some(t) = mktime(|t| z.ydhms(t), &tm, &LOCALTIME_OFFSET).filter(|&t| t != -1) {
            return Some(wrap_ts(t));
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
