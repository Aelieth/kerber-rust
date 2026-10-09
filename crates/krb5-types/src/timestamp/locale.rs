//! The LC_TIME half of glibc's `setlocale(LC_ALL, "")`, which MIT's tools call before anything
//! else, and the locale data it selects.
//!
//! Each category takes its name from `LC_ALL`, else `LC_<category>`, else `LANG`, else `C`.
//! `C` and `POSIX` are built in; any other name must be installed: in glibc's locale archive
//! (its name with the codeset normalised, `de_DE.UTF-8` → `de_DE.utf8`), or the archive entry of
//! its alias from `locale.alias`, or a directory of that name holding the category under
//! `/usr/lib/locale` (`LOCPATH`'s directories instead, and no archive, when `LOCPATH` is set).
//! When any category's name is not installed the whole call fails and every category stays
//! `C`, so an unknown, unset or uninstalled locale formats dates as `C` does.
//!
//! The data is glibc's own LC_TIME source, from `pure-rust-locales`, chosen by the name's
//! language, territory and modifier. Output is always UTF-8; a locale glibc installs in another
//! codeset prints the same names in UTF-8. glibc's fallback from an uninstalled name to a less
//! specific installed one (`de_AT` to `de`) is not followed, and a locale the crate does not carry
//! formats as `C`.

use std::fs::File;
use std::os::unix::fs::FileExt as _;

use pure_rust_locales::{Locale, locale_match};

/// One locale's LC_TIME: the `nl_langinfo` items `strftime` reads.
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
    /// glibc's LC_CTYPE in the Turkic locales: the byte-wise `toupper` / `tolower` leave `i` and
    /// `I` alone (their case partners are not single bytes).
    pub(super) keep_i: bool,
}

impl LcTime {
    /// The `C` (`POSIX`) locale, a C program's LC_TIME before it calls `setlocale`.
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

    /// The LC_TIME of the glibc locale `name` (`language[_territory][.codeset][@modifier]`),
    /// whether or not it is installed here; `C`, `POSIX` and `C.<codeset>` are `C`. `None` for a
    /// locale glibc does not ship.
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

    /// glibc localedef: an unset `ab_alt_mon` / `alt_mon` is `abmon` / `mon`, and an unset era
    /// or alternative-digit item is empty.
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

    /// glibc's byte-wise `toupper` over `bytes`: ASCII letters only, as in a UTF-8 locale.
    pub(super) fn upper(&self, bytes: &mut [u8]) {
        for b in bytes {
            if !(self.keep_i && *b == b'i') {
                b.make_ascii_uppercase();
            }
        }
    }

    /// glibc's byte-wise `tolower` over `bytes`.
    pub(super) fn lower(&self, bytes: &mut [u8]) {
        for b in bytes {
            if !(self.keep_i && *b == b'I') {
                b.make_ascii_lowercase();
            }
        }
    }

    /// glibc `_nl_get_alt_digit`: the alternative spelling of `n` below 100, if the locale has a
    /// non-empty one.
    pub(super) fn alt_digit(&self, n: u64) -> Option<&'static str> {
        if n >= 100 {
            return None;
        }
        let i = usize::try_from(n).ok()?;
        self.alt_digits.get(i).copied().filter(|s| !s.is_empty())
    }
}

/// The categories `setlocale(LC_ALL, "")` loads, by the names of their variables and files.
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

/// glibc's compiled-in locale directory, and its archive and alias file.
const LOCALE_DIR: &str = "/usr/lib/locale";
const LOCALE_ARCHIVE: &str = "/usr/lib/locale/locale-archive";
const LOCALE_ALIAS: &str = "/usr/share/locale/locale.alias";

/// Where installed locales are found.
pub(super) trait Installed {
    /// The archive holds `name` (spelled as glibc normalises it).
    fn in_archive(&self, name: &str) -> bool;
    /// `dir/name/category` exists (a file, or `LC_MESSAGES`'s directory).
    fn in_dir(&self, dir: &str, name: &str, category: &str) -> bool;
    /// glibc `_nl_expand_alias`: the value `locale.alias` gives `name`, matched ignoring case.
    fn alias(&self, name: &str) -> Option<String>;
}

/// glibc `setlocale(LC_ALL, "")`, kept to the LC_TIME it leaves: every category's name from the
/// environment must be found, else the call fails and LC_TIME stays `C`.
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

/// glibc `_nl_find_locale` for one category: the name it loads `name` under, or `None`.
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

/// glibc `valid_locale_name`: at most 255 bytes, no `..` path component, and a `/` only in a
/// name that starts with one.
fn valid_locale_name(name: &str) -> bool {
    name.len() <= 255
        && !name.contains("/../")
        && name != ".."
        && !name.starts_with("../")
        && !name.ends_with("/..")
        && (!name.contains('/') || name.starts_with('/'))
}

/// glibc `_nl_normalize_codeset` applied to a locale name's codeset: its letters lower-cased, its
/// digits kept, everything else dropped, and `iso` before a codeset of digits only.
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

/// The installed locales on this host.
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

/// glibc `read_alias_file`: per line an alias and its value, separated by blanks; `#` starts a
/// comment line. The first alias equal to `name` ignoring ASCII case.
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

/// The names in glibc's locale archive at `path`; `None` when there is none.
fn archive_names(path: &str) -> Option<Vec<String>> {
    let file = File::open(path).ok()?;
    parse_archive(&|off, buf| file.read_exact_at(buf, off).ok())
}

/// The names in a glibc locale archive read through `read_at`: its name hash table's used
/// slots, each pointing into the string table. `None` when it is not an archive.
fn parse_archive(read_at: &dyn Fn(u64, &mut [u8]) -> Option<()>) -> Option<Vec<String>> {
    /// glibc `AR_MAGIC`.
    const MAGIC: u32 = 0xde02_0109;
    /// Bounds on the tables read, far above any glibc archive's.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// A host with these archive names, `dir/name/category` paths and aliases.
    #[derive(Default)]
    struct Host {
        archive: BTreeSet<&'static str>,
        dirs: BTreeSet<String>,
        aliases: BTreeMap<&'static str, &'static str>,
    }

    impl Installed for Host {
        fn in_archive(&self, name: &str) -> bool {
            self.archive.contains(name)
        }
        fn in_dir(&self, dir: &str, name: &str, category: &str) -> bool {
            self.dirs.contains(&format!("{dir}/{name}/{category}"))
        }
        fn alias(&self, name: &str) -> Option<String> {
            self.aliases
                .iter()
                .find(|(a, _)| a.eq_ignore_ascii_case(name))
                .map(|(_, v)| (*v).to_owned())
        }
    }

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            vars.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    fn fedora() -> Host {
        let mut h = Host::default();
        h.archive
            .extend(["de_DE.utf8", "de_DE", "en_US.utf8", "en_US"]);
        for c in CATEGORIES {
            h.dirs.insert(format!("/usr/lib/locale/C.utf8/{c}"));
        }
        h.aliases.insert("deutsch", "de_DE.ISO-8859-1");
        h
    }

    fn de() -> LcTime {
        LcTime::named("de_DE").unwrap()
    }

    #[test]
    fn unset_empty_and_c_names_are_c() {
        let h = fedora();
        assert_eq!(resolve(&env(&[]), &h), LcTime::C);
        assert_eq!(resolve(&env(&[("LANG", "")]), &h), LcTime::C);
        assert_eq!(resolve(&env(&[("LANG", "POSIX")]), &h), LcTime::C);
        assert_eq!(resolve(&env(&[("LANG", "C.UTF-8")]), &h), LcTime::C);
    }

    #[test]
    fn lc_all_then_lc_time_then_lang() {
        let h = fedora();
        assert_eq!(resolve(&env(&[("LANG", "de_DE.UTF-8")]), &h), de());
        assert_eq!(
            resolve(&env(&[("LANG", "C"), ("LC_TIME", "de_DE.UTF-8")]), &h),
            de()
        );
        assert_eq!(
            resolve(
                &env(&[
                    ("LC_ALL", "C"),
                    ("LC_TIME", "de_DE.UTF-8"),
                    ("LANG", "de_DE")
                ]),
                &h
            ),
            LcTime::C
        );
        assert_eq!(
            resolve(&env(&[("LC_ALL", ""), ("LC_TIME", "de_DE.utf8")]), &h),
            de()
        );
    }

    #[test]
    fn an_uninstalled_name_in_any_category_leaves_everything_c() {
        let h = fedora();
        assert_eq!(resolve(&env(&[("LANG", "fr_FR.UTF-8")]), &h), LcTime::C);
        assert_eq!(
            resolve(
                &env(&[("LANG", "de_DE.UTF-8"), ("LC_MESSAGES", "xx_YY.UTF-8")]),
                &h
            ),
            LcTime::C
        );
        assert_eq!(resolve(&env(&[("LANG", "de_de.utf8")]), &h), LcTime::C);
    }

    #[test]
    fn an_alias_and_a_locale_directory_are_found() {
        let mut h = fedora();
        assert_eq!(resolve(&env(&[("LANG", "Deutsch")]), &h), LcTime::C);
        h.archive.insert("de_DE.iso88591");
        assert_eq!(resolve(&env(&[("LANG", "Deutsch")]), &h), de());
        let mut h = Host::default();
        for c in CATEGORIES {
            h.dirs.insert(format!("/usr/lib/locale/de_DE.utf8/{c}"));
        }
        assert_eq!(resolve(&env(&[("LANG", "de_DE.UTF-8")]), &h), de());
        assert_eq!(
            resolve(&env(&[("LANG", "de_DE.UTF-8"), ("LOCPATH", "/opt/l")]), &h),
            LcTime::C
        );
    }

    #[test]
    fn locpath_replaces_the_archive_and_the_directory() {
        let mut h = fedora();
        for c in CATEGORIES {
            h.dirs.insert(format!("/opt/l/de_DE.utf8/{c}"));
        }
        let vars = [("LANG", "de_DE.UTF-8"), ("LOCPATH", "/nowhere:/opt/l")];
        assert_eq!(resolve(&env(&vars), &h), de());
        let vars = [("LANG", "en_US.UTF-8"), ("LOCPATH", "/opt/l")];
        assert_eq!(resolve(&env(&vars), &h), LcTime::C);
    }

    #[test]
    fn invalid_names_are_not_looked_up() {
        assert!(valid_locale_name("de_DE.UTF-8"));
        assert!(valid_locale_name("/opt/locales/de"));
        assert!(!valid_locale_name("../de_DE"));
        assert!(!valid_locale_name("/opt/../de"));
        assert!(!valid_locale_name("x/de"));
        assert!(!valid_locale_name(".."));
        assert!(!valid_locale_name(&"a".repeat(256)));
    }

    #[test]
    fn codesets_normalise_as_glibc() {
        assert_eq!(normalize_codeset("de_DE.UTF-8"), "de_DE.utf8");
        assert_eq!(
            normalize_codeset("de_DE.ISO-8859-15@euro"),
            "de_DE.iso885915@euro"
        );
        assert_eq!(normalize_codeset("de_DE.8859-1"), "de_DE.iso88591");
        assert_eq!(normalize_codeset("de_DE"), "de_DE");
        assert_eq!(normalize_codeset("de_DE.@euro"), "de_DE.@euro");
    }

    #[test]
    fn names_select_the_crate_data() {
        assert_eq!(LcTime::named("de_DE.UTF-8"), Some(de()));
        assert_eq!(LcTime::named("C.utf8"), Some(LcTime::C));
        assert_eq!(LcTime::named("xx_YY"), None);
        let euro = LcTime::named("de_DE.ISO-8859-15@euro").unwrap();
        assert_eq!(euro.abmon[2], "Mär");
        assert_eq!(de().d_fmt, "%d.%m.%Y");
    }

    #[test]
    fn alias_file_lines_parse_as_glibc() {
        let text =
            b"# comment\n\nbokmal\t\tnb_NO.ISO-8859-1\nDeutsch de_DE.ISO-8859-1 extra\nlonely\n";
        assert_eq!(
            alias_lookup(text, "BOKMAL").as_deref(),
            Some("nb_NO.ISO-8859-1")
        );
        assert_eq!(
            alias_lookup(text, "deutsch").as_deref(),
            Some("de_DE.ISO-8859-1")
        );
        assert_eq!(alias_lookup(text, "lonely"), None);
        assert_eq!(alias_lookup(text, "#"), None);
    }

    fn parse(bytes: &[u8]) -> Option<Vec<String>> {
        parse_archive(&|off, buf| {
            let off = usize::try_from(off).ok()?;
            buf.copy_from_slice(bytes.get(off..off + buf.len())?);
            Some(())
        })
    }

    #[test]
    fn a_missing_or_foreign_archive_lists_nothing() {
        assert_eq!(archive_names("/nonexistent/locale-archive"), None);
        assert_eq!(parse(&[0u8; 64]), None);
        assert_eq!(parse(&[0u8; 8]), None);
    }

    #[test]
    fn an_archive_lists_its_hash_table_names() {
        let words = |ws: &[u32]| ws.iter().flat_map(|w| w.to_ne_bytes()).collect::<Vec<u8>>();
        // The header; two hash slots at 56 (the first empty); the string table at 80.
        let mut a = words(&[0xde02_0109, 0, 56, 1, 2, 80, 11, 11, 0, 0, 0, 0, 0, 0]);
        a.extend(words(&[0, 0, 0, 7, 80, 0]));
        a.extend_from_slice(b"de_DE.utf8\0");
        assert_eq!(parse(&a), Some(vec!["de_DE.utf8".to_owned()]));
        a[56 + 16..56 + 20].copy_from_slice(&79u32.to_ne_bytes());
        assert_eq!(parse(&a), Some(vec![]));
    }
}
