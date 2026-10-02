//! `ktadd` and `ktremove`: MIT `kadmin/cli/keytab.c`.

use std::fmt::Write as _;
use std::path::PathBuf;

use krb5_crypto::EncryptionType;
use krb5_kdc::Error;
use krb5_protocol::{Keytab, KeytabEntry};
use krb5_types::PrincipalName;

use super::{Session, WHOAMI, string_to_keysalts, texts};

/// A resolved keytab: the name MIT prints, and its file (`None` for a `MEMORY:` keytab, which
/// ends with the process).
struct Kt {
    name: String,
    path: Option<PathBuf>,
}

/// `krb5_kt_default_name`: `KRB5_KTNAME`, else `[libdefaults] default_keytab_name`, else
/// `FILE:/etc/krb5.keytab`.
fn default_keytab_name() -> String {
    if let Some(n) = std::env::var("KRB5_KTNAME").ok().filter(|s| !s.is_empty()) {
        return n;
    }
    let files = super::krb5_conf_paths_with_kdc();
    super::profile_values(&files, "libdefaults", "default_keytab_name")
        .into_iter()
        .next()
        .and_then(|n| krb5_config::expand_ccache_params(&n).ok())
        .unwrap_or_else(|| "FILE:/etc/krb5.keytab".to_owned())
}

/// `krb5_kt_resolve` and `krb5_kt_get_name`: `FILE` and `WRFILE` keytabs are files, `MEMORY`
/// is kept in the process; a name with no type is a `FILE`.
fn resolve(name: &str) -> Result<Kt, &'static str> {
    match name.split_once(':') {
        Some((ty @ ("FILE" | "WRFILE"), path)) => Ok(Kt {
            name: format!("{ty}:{path}"),
            path: Some(PathBuf::from(path)),
        }),
        Some(("MEMORY", _)) => Ok(Kt {
            name: name.to_owned(),
            path: None,
        }),
        Some(_) => Err("Unknown Key table type"),
        None => Ok(Kt {
            name: format!("FILE:{name}"),
            path: Some(PathBuf::from(name)),
        }),
    }
}

/// MIT `process_keytab` (`kadmin/cli/keytab.c:67-111`): `-k NAME` (a name without a type is a
/// `WRFILE`), else the default keytab.
fn process_keytab(s: &mut Session<'_>, keytab_str: Option<&str>) -> Option<Kt> {
    let name = keytab_str.map_or_else(default_keytab_name, |n| {
        if n.contains(':') {
            n.to_owned()
        } else {
            format!("WRFILE:{n}")
        }
    });
    match resolve(&name) {
        Ok(kt) => Some(kt),
        Err(msg) => {
            s.io.com_err(WHOAMI, Some(msg), &format!("while resolving keytab {name}"));
            None
        }
    }
}

/// MIT `kadmin_keytab_add` (`kadmin/cli/keytab.c:114-203`): the options, then each principal
/// (a `-glob` pattern adds every match, and is then read as a name itself, as MIT reads it).
pub(crate) fn ktadd(s: &mut Session<'_>, argv: &[String]) {
    let mut rest = argv.get(1..).unwrap_or_default();
    let mut keytab_str: Option<&str> = None;
    let mut quiet = false;
    let mut norandkey = false;
    let mut keysalts = Vec::new();
    while let Some(arg) = rest.first() {
        if arg.starts_with("-k") {
            rest = &rest[1..];
            match rest.first() {
                Some(v) if keytab_str.is_none() => keytab_str = Some(v),
                _ => {
                    s.io.eprint(texts::KTADD_USAGE);
                    return;
                }
            }
        } else if arg == "-q" {
            quiet = true;
        } else if arg == "-norandkey" {
            norandkey = true;
        } else if arg == "-e" {
            rest = &rest[1..];
            let Some(v) = rest.first() else {
                s.io.eprint(texts::KTADD_USAGE);
                return;
            };
            keysalts = string_to_keysalts(v, &[',', ' ', '\t']);
        } else {
            break;
        }
        rest = &rest[1..];
    }
    if rest.is_empty() {
        s.io.eprint(texts::KTADD_USAGE);
        return;
    }
    if norandkey && !keysalts.is_empty() {
        s.io.eprint("cannot specify keysaltlist when not changing key\n");
        return;
    }
    let Some(kt) = process_keytab(s, keytab_str) else {
        return;
    };
    let opts = AddOpts {
        quiet,
        norandkey,
        keysalts,
    };
    let mut i = 0;
    while i < rest.len() {
        if rest[i] != "-glob" {
            add_principal(s, &kt, &opts, &rest[i]);
            i += 1;
            continue;
        }
        i += 1;
        let Some(pattern) = rest.get(i) else {
            s.io.eprint(texts::KTADD_USAGE);
            break;
        };
        match expand(s, pattern) {
            Ok(names) => {
                for name in names {
                    add_principal(s, &kt, &opts, &name);
                }
            }
            Err(msg) => {
                s.io.com_err(
                    WHOAMI,
                    Some(&msg),
                    &format!("while expanding expression \"{pattern}\"."),
                );
                i += 1;
            }
        }
    }
}

/// `kadm5_get_principals` for `-glob`.
fn expand(s: &mut Session<'_>, pattern: &str) -> Result<Vec<String>, String> {
    if !crate::glob_pattern_ok(pattern) {
        return Err("Invalid argument".to_owned());
    }
    s.h.refresh().map_err(|e| texts::princ_text(&e))?;
    let pat = crate::kadm5::glob_expand(pattern, true);
    Ok(s.h
        .store
        .ids()
        .into_iter()
        .filter(|id| crate::kadm5::glob_is_match(pat.as_bytes(), id.as_bytes()))
        .collect())
}

struct AddOpts {
    quiet: bool,
    norandkey: bool,
    keysalts: Vec<EncryptionType>,
}

/// MIT `add_principal` (`kadmin/cli/keytab.c:299-358`): new random keys (`randkey_princ`, then
/// the entry's kvno), or with `-norandkey` the keys the entry has; each is added to the keytab
/// and reported.
fn add_principal(s: &mut Session<'_>, kt: &Kt, opts: &AddOpts, princ_str: &str) {
    let (name, realm) = match s.h.parse_name(princ_str) {
        Ok(n) => n,
        Err(msg) => {
            s.io.com_err(
                WHOAMI,
                Some(msg),
                &format!("while parsing -add principal name {princ_str}"),
            );
            return;
        }
    };
    let keys = if opts.norandkey {
        s.h.refresh().and_then(|()| {
            s.h.store
                .get_in_realm(&name, &realm)
                .map(|p| p.keys.clone())
                .ok_or(Error::NotFound)
        })
    } else {
        s.h.mutate(|st, caller| {
            st.chrand_etypes_keepold_in(&name, &realm, &opts.keysalts, 0, caller)
        })
    };
    let keys = match keys {
        Ok(k) => k,
        Err(Error::NotFound) => {
            s.io.eprint(&format!(
                "{WHOAMI}: Principal {princ_str} does not exist.\n"
            ));
            return;
        }
        Err(e) => {
            s.io.com_err(
                WHOAMI,
                Some(&texts::princ_text(&e)),
                &format!("while changing {princ_str}'s key"),
            );
            return;
        }
    };
    if keys.is_empty() {
        return;
    }
    if let Err(msg) = add_entries(kt, &name, &realm, &keys) {
        s.io.com_err(WHOAMI, Some(&msg), "while adding key to keytab");
        return;
    }
    if !opts.quiet {
        let mut out = String::new();
        for k in &keys {
            let _ = writeln!(
                out,
                "Entry for principal {princ_str} with kvno {}, encryption type {} added to \
                 keytab {}.",
                k.kvno,
                k.etype.to_mit_name(),
                kt.name
            );
        }
        s.io.print(&out);
    }
}

/// `krb5_kt_add_entry` for each key, the keytab file created when missing; an existing file
/// keeps its owner and mode.
fn add_entries(
    kt: &Kt,
    name: &PrincipalName,
    realm: &str,
    keys: &[krb5_kdc::KeyEntry],
) -> Result<(), String> {
    let Some(path) = &kt.path else {
        return Ok(());
    };
    let mut tab = match std::fs::read(path) {
        Ok(bytes) => Keytab::parse(&bytes).map_err(|e| texts::strerror(&e))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Keytab::default(),
        Err(e) => return Err(texts::strerror(&e)),
    };
    if tab.version == 0 {
        tab.version = 0x0502;
    }
    let realm = krb5_types::try_ascii(realm).map_err(|e| e.to_string())?;
    let now = krb5_types::KerberosTime::now().unix_seconds();
    for k in keys {
        tab.entries.push(KeytabEntry {
            realm: realm.clone(),
            name: name.clone(),
            timestamp: now,
            kvno: k.kvno,
            key: k.key.clone(),
        });
    }
    tab.write_file(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            format!("Key table file '{}' not found", path.display())
        }
        _ => texts::strerror(&e),
    })
}

/// MIT `kadmin_keytab_remove` (`kadmin/cli/keytab.c:206-243`): the options, then one principal
/// and an optional kvno, `all` or `old`.
pub(crate) fn ktremove(s: &mut Session<'_>, argv: &[String]) {
    let mut rest = argv.get(1..).unwrap_or_default();
    let mut keytab_str: Option<&str> = None;
    let mut quiet = false;
    while let Some(arg) = rest.first() {
        if arg.starts_with("-k") {
            rest = &rest[1..];
            match rest.first() {
                Some(v) if keytab_str.is_none() => keytab_str = Some(v),
                _ => {
                    s.io.eprint(texts::KTREM_USAGE);
                    return;
                }
            }
        } else if arg == "-q" {
            quiet = true;
        } else {
            break;
        }
        rest = &rest[1..];
    }
    if !(rest.len() == 1 || rest.len() == 2) {
        s.io.eprint(texts::KTREM_USAGE);
        return;
    }
    let Some(kt) = process_keytab(s, keytab_str) else {
        return;
    };
    remove_principal(s, &kt, quiet, &rest[0], rest.get(1).map(String::as_str));
}

/// Which entries `ktremove` takes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Spec(u32),
    High,
    All,
    Old,
}

/// MIT `remove_principal` (`kadmin/cli/keytab.c:361-491`): the highest kvno's entries, those
/// of one kvno, all, or all but the highest.
fn remove_principal(
    s: &mut Session<'_>,
    kt: &Kt,
    quiet: bool,
    princ_str: &str,
    kvno_str: Option<&str>,
) {
    let (name, realm) = match s.h.parse_name(princ_str) {
        Ok(n) => n,
        Err(msg) => {
            s.io.com_err(
                WHOAMI,
                Some(msg),
                &format!("while parsing principal name {princ_str}"),
            );
            return;
        }
    };
    let mode = match kvno_str {
        None => Mode::High,
        Some("all") => Mode::All,
        Some("old") => Mode::Old,
        Some(n) => Mode::Spec(getdate_low32(super::atoi(n))),
    };
    let Some(path) = &kt.path else {
        s.io.eprint(&format!(
            "{WHOAMI}: No entry for principal {princ_str} exists in keytab {}\n",
            kt.name
        ));
        return;
    };
    let mut tab = match std::fs::read(path) {
        Ok(bytes) => match Keytab::parse(&bytes) {
            Ok(t) => t,
            Err(e) => {
                s.io.com_err(
                    WHOAMI,
                    Some(&texts::strerror(&e)),
                    "while retrieving highest kvno from keytab",
                );
                return;
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            s.io.eprint(&format!("{WHOAMI}: Keytab {} does not exist.\n", kt.name));
            return;
        }
        Err(e) => {
            s.io.com_err(
                WHOAMI,
                Some(&texts::strerror(&e)),
                "while retrieving highest kvno from keytab",
            );
            return;
        }
    };
    let matches = |e: &KeytabEntry| {
        krb5_types::principal_compare(
            &e.name,
            &String::from_utf8_lossy(e.realm.as_bytes()),
            &name,
            &realm,
        )
    };
    let highest = tab
        .entries
        .iter()
        .filter(|e| matches(e))
        .map(|e| e.kvno)
        .max();
    let Some(highest) = highest else {
        let text = match mode {
            Mode::Spec(k) => format!(
                "{WHOAMI}: No entry for principal {princ_str} with kvno {k} exists in keytab {}\n",
                kt.name
            ),
            _ => format!(
                "{WHOAMI}: No entry for principal {princ_str} exists in keytab {}\n",
                kt.name
            ),
        };
        s.io.eprint(&text);
        return;
    };
    let kvno = match mode {
        Mode::Spec(k) => {
            if !tab.entries.iter().any(|e| matches(e) && e.kvno == k) {
                s.io.com_err(
                    WHOAMI,
                    Some("Key version number for principal in key table is incorrect"),
                    "while retrieving highest kvno from keytab",
                );
                return;
            }
            k
        }
        _ => highest,
    };
    let take = |e: &KeytabEntry| {
        matches(e)
            && match mode {
                Mode::All => true,
                Mode::Spec(_) | Mode::High => e.kvno == kvno,
                Mode::Old => e.kvno != kvno,
            }
    };
    let removed: Vec<u32> = tab
        .entries
        .iter()
        .filter(|e| take(e))
        .map(|e| e.kvno)
        .collect();
    if removed.is_empty() {
        if mode == Mode::Old {
            s.io.eprint(&format!(
                "{WHOAMI}: There is only one entry for principal {princ_str} in keytab {}\n",
                kt.name
            ));
        }
        return;
    }
    let gone: Vec<usize> = (0..tab.entries.len())
        .filter(|&i| take(&tab.entries[i]))
        .collect();
    for slot in &mut tab.unparsed {
        slot.0 -= gone.iter().filter(|&&g| g < slot.0).count();
    }
    tab.entries.retain(|e| !take(e));
    if let Err(e) = tab.write_file(path) {
        s.io.com_err(
            WHOAMI,
            Some(&texts::strerror(&e)),
            "while deleting entry from keytab",
        );
        return;
    }
    if !quiet {
        let mut out = String::new();
        for k in removed {
            let _ = writeln!(
                out,
                "Entry for principal {princ_str} with kvno {k} removed from keytab {}.",
                kt.name
            );
        }
        s.io.print(&out);
    }
}

fn getdate_low32(n: i64) -> u32 {
    crate::getdate::low32(n)
}
