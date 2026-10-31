use std::fs::File;
use std::os::unix::fs::FileExt as _;

use pure_rust_locales::{Locale, locale_match};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LcTime {
    pub(super) abday: &'static [&'static str],
    pub(super) day: &'static [&'static str],
    pub(super) abmon: &'static [&'static str],
    pub(super) mon: &'static [&'static str],
    pub(super) ab_alt_mon: &'static [&'static str],
    pub(super) alt_mon: &'static [&'static str],
    pub(super) am_pm: &'static [&'static str],
    pub(super) d_t_fmt: &'static str,
    pub(super) d_fmt: &'static str,
    pub(super) t_fmt: &'static str,
    pub(super) t_fmt_ampm: &'static str,
    pub(super) era: &'static [&'static str],
    pub(super) era_d_fmt: &'static str,
    pub(super) era_d_t_fmt: &'static str,
    pub(super) era_t_fmt: &'static str,
    pub(super) alt_digits: &'static [&'static str],
    pub(super) keep_i: bool,
}

impl LcTime {
    pub const C: Self = {
        use pure_rust_locales::POSIX::LC_TIME as T;
        Self {
            abday: T::ABDAY,
            day: T::DAY,
            abmon: T::ABMON,
            mon: T::MON,
            ab_alt_mon: T::ABMON,
            alt_mon: T::MON,
            am_pm: T::AM_PM,
            d_t_fmt: T::D_T_FMT,
            d_fmt: T::D_FMT,
            t_fmt: T::T_FMT,
            t_fmt_ampm: T::T_FMT_AMPM,
            era: &[],
            era_d_fmt: "",
            era_d_t_fmt: "",
            era_t_fmt: "",
            alt_digits: &[],
            keep_i: false,
        }
    };

    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        let (base, modifier) = match name.split_once('@') {
            Some((b, m)) => (b, Some(m)),
            None => (name, None),
        };
        let base = base.split('.').next().unwrap_or(base);
        if base == "C" || base == "POSIX" {
            return modifier.is_none().then_some(Self::C);
        }
        let key = match modifier {
            Some(m) => format!("{base}@{m}"),
            None => base.to_owned(),
        };
        Locale::try_from(key.as_str()).ok().map(Self::of)
    }

    fn of(l: Locale) -> Self {
        let abmon = locale_match!(l => LC_TIME::ABMON);
        let mon = locale_match!(l => LC_TIME::MON);
        Self {
            abday: locale_match!(l => LC_TIME::ABDAY),
            day: locale_match!(l => LC_TIME::DAY),
            abmon,
            mon,
            ab_alt_mon: locale_match!(l => LC_TIME::AB_ALT_MON).unwrap_or(abmon),
            alt_mon: locale_match!(l => LC_TIME::ALT_MON).unwrap_or(mon),
            am_pm: locale_match!(l => LC_TIME::AM_PM),
            d_t_fmt: locale_match!(l => LC_TIME::D_T_FMT),
            d_fmt: locale_match!(l => LC_TIME::D_FMT),
            t_fmt: locale_match!(l => LC_TIME::T_FMT),
            t_fmt_ampm: locale_match!(l => LC_TIME::T_FMT_AMPM),
            era: locale_match!(l => LC_TIME::ERA).unwrap_or_default(),
            era_d_fmt: locale_match!(l => LC_TIME::ERA_D_FMT).unwrap_or_default(),
            era_d_t_fmt: locale_match!(l => LC_TIME::ERA_D_T_FMT).unwrap_or_default(),
            era_t_fmt: locale_match!(l => LC_TIME::ERA_T_FMT).unwrap_or_default(),
            alt_digits: locale_match!(l => LC_TIME::ALT_DIGITS).unwrap_or_default(),
            keep_i: matches!(
                l,
                Locale::az_AZ
                    | Locale::crh_UA
                    | Locale::ku_TR
                    | Locale::tr_CY
                    | Locale::tr_TR
                    | Locale::tt_RU_iqtelif
            ),
        }
    }

    pub(super) fn upper(&self, bytes: &mut [u8]) {
        for b in bytes {
            if !(self.keep_i && *b == b'i') {
                b.make_ascii_uppercase();
            }
        }
    }

    pub(super) fn lower(&self, bytes: &mut [u8]) {
        for b in bytes {
            if !(self.keep_i && *b == b'I') {
                b.make_ascii_lowercase();
            }
        }
    }

    pub(super) fn alt_digit(&self, n: u64) -> Option<&'static str> {
        if n >= 100 {
            return None;
        }
        let i = usize::try_from(n).ok()?;
        self.alt_digits.get(i).copied().filter(|s| !s.is_empty())
    }
}

const CATEGORIES: [&str; 12] = [
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_MESSAGES",
    "LC_PAPER",
    "LC_NAME",
    "LC_ADDRESS",
    "LC_TELEPHONE",
    "LC_MEASUREMENT",
    "LC_IDENTIFICATION",
];

const LOCALE_DIR: &str = "/usr/lib/locale";
const LOCALE_ARCHIVE: &str = "/usr/lib/locale/locale-archive";
const LOCALE_ALIAS: &str = "/usr/share/locale/locale.alias";

pub(super) trait Installed {
    fn in_archive(&self, name: &str) -> bool;
    fn in_dir(&self, dir: &str, name: &str, category: &str) -> bool;
    fn alias(&self, name: &str) -> Option<String>;
}

pub(super) fn resolve(getenv: &dyn Fn(&str) -> Option<String>, store: &dyn Installed) -> LcTime {
    let locpath = getenv("LOCPATH").filter(|p| !p.is_empty());
    let mut time = None;
    for category in CATEGORIES {
        let name = ["LC_ALL", category, "LANG"]
            .into_iter()
            .find_map(|v| getenv(v).filter(|s| !s.is_empty()))
            .unwrap_or_else(|| "C".to_owned());
        let Some(found) = find_locale(&name, category, locpath.as_deref(), store) else {
            return LcTime::C;
        };
        if category == "LC_TIME" {
            time = Some(found);
        }
    }
    time.and_then(|n| LcTime::named(&n)).unwrap_or(LcTime::C)
}

fn find_locale(
    name: &str,
    category: &str,
    locpath: Option<&str>,
    store: &dyn Installed,
) -> Option<String> {
    if name == "C" || name == "POSIX" {
        return Some("C".to_owned());
    }
    if !valid_locale_name(name) {
        return None;
    }
    let alias = store.alias(name);
    if locpath.is_none() {
        if store.in_archive(&normalize_codeset(name)) {
            return Some(name.to_owned());
        }
        if let Some(a) = alias.as_deref()
            && store.in_archive(&normalize_codeset(a))
        {
            return Some(a.to_owned());
        }
    }
    let loc_name = alias.unwrap_or_else(|| name.to_owned());
    let normalized = normalize_codeset(&loc_name);
    let dirs: Vec<&str> = match locpath {
        Some(p) => p.split(':').filter(|d| !d.is_empty()).collect(),
        None => vec![LOCALE_DIR],
    };
    dirs.iter()
        .any(|dir| {
            store.in_dir(dir, &loc_name, category) || store.in_dir(dir, &normalized, category)
        })
        .then_some(loc_name)
}

fn valid_locale_name(name: &str) -> bool {
    name.len() <= 255
        && !name.contains("/../")
        && name != ".."
        && !name.starts_with("../")
        && !name.ends_with("/..")
        && (!name.contains('/') || name.starts_with('/'))
}

fn normalize_codeset(name: &str) -> String {
    let Some((head, rest)) = name.split_once('.') else {
        return name.to_owned();
    };
    if rest.is_empty() || rest.starts_with('@') {
        return name.to_owned();
    }
    let end = rest.find('@').unwrap_or(rest.len());
    let (codeset, tail) = rest.split_at(end);
    let alnum = codeset.bytes().filter(u8::is_ascii_alphanumeric);
    let only_digit = alnum.clone().all(|b| b.is_ascii_digit());
    let mut out = format!("{head}.");
    if only_digit {
        out.push_str("iso");
    }
    out.extend(alnum.map(|b| char::from(b.to_ascii_lowercase())));
    out.push_str(tail);
    out
}

pub(super) struct System {
    archive: Vec<String>,
}

impl System {
    pub(super) fn load() -> Self {
        Self {
            archive: archive_names(LOCALE_ARCHIVE).unwrap_or_default(),
        }
    }
}

impl Installed for System {
    fn in_archive(&self, name: &str) -> bool {
        self.archive.iter().any(|n| n == name)
    }

    fn in_dir(&self, dir: &str, name: &str, category: &str) -> bool {
        std::path::Path::new(&format!("{dir}/{name}/{category}")).exists()
    }

    fn alias(&self, name: &str) -> Option<String> {
        let text = std::fs::read(LOCALE_ALIAS).ok()?;
        alias_lookup(&text, name)
    }
}

fn alias_lookup(text: &[u8], name: &str) -> Option<String> {
    for line in text.split(|&b| b == b'\n') {
        let mut words = line
            .split(u8::is_ascii_whitespace)
            .filter(|w| !w.is_empty());
        let Some(alias) = words.next() else { continue };
        if alias.first() == Some(&b'#') {
            continue;
        }
        let Some(value) = words.next() else { continue };
        if alias.eq_ignore_ascii_case(name.as_bytes()) {
            return String::from_utf8(value.to_vec()).ok();
        }
    }
    None
}

fn archive_names(path: &str) -> Option<Vec<String>> {
    let file = File::open(path).ok()?;
    parse_archive(&|off, buf| file.read_exact_at(buf, off).ok())
}

fn parse_archive(read_at: &dyn Fn(u64, &mut [u8]) -> Option<()>) -> Option<Vec<String>> {
    const MAGIC: u32 = 0xde02_0109;
    const MAX_TABLE: usize = 16 << 20;
    let mut head = [0u8; 56];
    read_at(0, &mut head)?;
    let word = |i: usize| -> Option<usize> {
        let b = head.get(i * 4..i * 4 + 4)?;
        usize::try_from(u32::from_ne_bytes(b.try_into().ok()?)).ok()
    };
    if word(0)? != usize::try_from(MAGIC).ok()? {
        return None;
    }
    let (hash_off, hash_size, str_off, str_used) = (word(2)?, word(4)?, word(5)?, word(6)?);
    let hash_len = hash_size.checked_mul(12).filter(|&n| n <= MAX_TABLE)?;
    if str_used > MAX_TABLE {
        return None;
    }
    let mut table = vec![0u8; hash_len];
    read_at(u64::try_from(hash_off).ok()?, &mut table)?;
    let mut strings = vec![0u8; str_used];
    read_at(u64::try_from(str_off).ok()?, &mut strings)?;
    let mut names = Vec::new();
    for slot in table.as_chunks::<12>().0 {
        let name_off =
            usize::try_from(u32::from_ne_bytes([slot[4], slot[5], slot[6], slot[7]])).ok()?;
        if name_off == 0 {
            continue;
        }
        let Some(at) = name_off.checked_sub(str_off) else {
            continue;
        };
        let Some(bytes) = strings.get(at..) else {
            continue;
        };
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        if let Ok(n) = std::str::from_utf8(&bytes[..end]) {
            names.push(n.to_owned());
        }
    }
    Some(names)
}
