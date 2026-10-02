//! MIT `kdestroy`: destroy a credential cache, a principal's cache, or the whole collection.
//!
//! Usage: `kdestroy [-A] [-q] [-c cache_name] [-p princ_name]`

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use krb5_client::ccol::{cache_match, collection, resolve};
use krb5_client::cli::{UsageError, UsageLine, getopt_each, own, progname};
use krb5_client::creds::parse_name;
use krb5_client::errmsg::{Code, Krb5Error};
use krb5_config::{CcSpec, parse_ccspec, resolve_ccspec};

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let argv0 = argv.first().map_or("kdestroy", String::as_str);
    let prog = progname(argv0);
    let args = match parse(argv.get(1..).unwrap_or_default()) {
        Ok(a) => a,
        Err(Parsed::Krb4) => {
            eprintln!("Kerberos 4 is no longer supported");
            std::process::exit(3);
        }
        Err(Parsed::Usage(e)) => {
            for line in e.lines(argv0) {
                eprintln!("{line}");
            }
            eprint!("{}", usage(prog));
            std::process::exit(2);
        }
    };
    std::process::exit(run(prog, &args));
}

/// Parsed `kdestroy` argv.
#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    /// `-A`.
    all: bool,
    /// `-q`.
    quiet: bool,
    /// `-c cache_name`.
    cache: Option<String>,
    /// `-p princ_name`.
    princ: Option<String>,
}

/// Why an argv is not run.
#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    /// `-4`.
    Krb4,
    /// A usage error.
    Usage(UsageError),
}

/// MIT `usage` (`kdestroy.c:49-59`): the usage text, `prog` naming the program.
fn usage(prog: &str) -> String {
    format!(
        "Usage: {prog} [-A] [-q] [-c cache_name] [-p princ_name]\n\
         \t-A destroy all credential caches in collection\n\
         \t-q quiet mode\n\
         \t-c specify name of credentials cache\n\
         \t-p specify principal name within collection\n"
    )
}

/// MIT `main` (`kdestroy.c:100-146`): the options `54Aqc:p:`, `-c` and `-p` once each, `-A`
/// without `-p`, and no other argument.
fn parse(args: &[String]) -> Result<Args, Parsed> {
    let (each, rest) = getopt_each(args, "54Aqc:p:", &[]);
    let mut out = Args::default();
    let mut lines = Vec::new();
    let mut errflg = false;
    for o in each {
        let o = match o {
            Ok(o) => o,
            Err(e) => {
                lines.push(UsageLine::Getopt(e));
                errflg = true;
                continue;
            }
        };
        match o.flag {
            'A' => out.all = true,
            'q' => out.quiet = true,
            'c' if out.cache.is_some() => {
                lines.push(own("Only one -c option allowed"));
                errflg = true;
            }
            'c' => out.cache = o.arg,
            'p' if out.princ.is_some() => {
                lines.push(own("Only one -p option allowed"));
                errflg = true;
            }
            'p' => out.princ = o.arg,
            '4' => return Err(Parsed::Krb4),
            _ => {}
        }
    }
    if out.all && out.princ.is_some() {
        lines.push(own("-A option is exclusive with -p option"));
        errflg = true;
    }
    if !rest.is_empty() {
        errflg = true;
    }
    if errflg {
        return Err(Parsed::Usage(UsageError::Each(lines)));
    }
    Ok(out)
}

/// MIT `main` (`kdestroy.c:148-229`): `-A` destroys every cache of the collection and exits 0; else
/// the default cache, or `-p`'s, is destroyed. A cache that does not exist is reported but is not a
/// failure; any other failure is "Ticket cache NOT destroyed!" and exit 1. A remaining cache in the
/// collection is warned of.
fn run(prog: &str, args: &Args) -> i32 {
    if let Err(e) = krb5_client::init_context() {
        krb5_client::com_err!(prog, e, "while initializing krb5");
        return 1;
    }
    let default = match &args.cache {
        Some(name) => parse_ccspec(name),
        None => resolve_ccspec(None),
    }
    .map_err(|e| Krb5Error::from_ccname(&e));
    if args.all {
        let Ok(default) = default else {
            return 0;
        };
        let caches = match collection(&default) {
            Ok(c) => c,
            Err(e) => {
                krb5_client::com_err!(prog, e, "while listing credential caches");
                return 1;
            }
        };
        for cache in caches {
            if let Err(e) = cache.destroy()
                && e.code != Code::FccNofile
            {
                krb5_client::com_err!(prog, e, "while destroying cache {}", cache.full_name());
            }
        }
        return 0;
    }
    let cache = match &args.princ {
        Some(name) => {
            let princ = match parse_name(name, false) {
                Ok(p) => p,
                Err(e) => {
                    krb5_client::com_err!(prog, e, "while parsing principal name {name}");
                    return 1;
                }
            };
            match default
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|d| cache_match(d, &princ))
            {
                Ok(c) => c,
                Err(e) => {
                    krb5_client::com_err!(prog, e, "while finding cache for {name}");
                    return 1;
                }
            }
        }
        None => match default.as_ref().map_err(Clone::clone).and_then(resolve) {
            Ok(c) => c,
            Err(e) => {
                krb5_client::com_err!(prog, e, "while resolving ccache");
                return 1;
            }
        },
    };
    let mut errflg = 0;
    if let Err(e) = cache.destroy() {
        krb5_client::com_err!(prog, e, "while destroying cache");
        if e.code != Code::FccNofile {
            if args.quiet {
                eprintln!("Ticket cache NOT destroyed!");
            } else {
                eprintln!("Ticket cache \x07NOT\x07 destroyed!");
            }
            errflg = 1;
        }
    }
    if !args.quiet
        && errflg == 0
        && args.princ.is_none()
        && let Ok(default) = default
    {
        return remaining_cc_warning(prog, &default);
    }
    errflg
}

/// MIT `print_remaining_cc_warning` (`kdestroy.c:62-83`): a cache left in the collection is
/// warned of.
fn remaining_cc_warning(prog: &str, default: &CcSpec) -> i32 {
    match collection(default) {
        Ok(caches) => {
            if !caches.is_empty() {
                eprintln!("Other credential caches present, use -A to destroy all");
            }
            0
        }
        Err(e) => {
            krb5_client::com_err!(prog, e, "while listing credential caches");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    /// Live MIT 1.22.2 `kdestroy`: its options and refusals.
    #[test]
    fn kdestroy_parses_as_mit() {
        assert_eq!(
            parse(&s(&["-A", "-q", "-c", "KCM:"])).unwrap(),
            Args {
                all: true,
                quiet: true,
                cache: Some("KCM:".into()),
                princ: None,
            }
        );
        let lines = |v: &[&str]| match parse(&s(v)) {
            Err(Parsed::Usage(u)) => u.lines("kdestroy"),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            lines(&["-A", "-p", "alice"]),
            ["-A option is exclusive with -p option"]
        );
        assert_eq!(
            lines(&["-c", "a", "-c", "b"]),
            ["Only one -c option allowed"]
        );
        assert_eq!(parse(&s(&["-4"])), Err(Parsed::Krb4));
        assert_eq!(lines(&["extra"]), Vec::<String>::new());
        // glibc's getopt goes on past a bad option, as MIT's `kdestroy` loop does.
        assert_eq!(
            lines(&["-Z", "-c"]),
            [
                "kdestroy: invalid option -- 'Z'",
                "kdestroy: option requires an argument -- 'c'"
            ]
        );
        assert!(usage("kdestroy").starts_with("Usage: kdestroy [-A] [-q] [-c cache_name]"));
    }

    /// Live MIT 1.22.2: `kdestroy` with no cache reports it and exits 0.
    #[test]
    fn kdestroy_of_a_missing_file_cache_exits_zero() {
        let path = krb5_testkit::scratch_dir("kdestroy-none").join("cc");
        let _ = std::fs::remove_file(&path);
        let args = Args {
            cache: Some(format!("FILE:{}", path.display())),
            ..Args::default()
        };
        assert_eq!(run("kdestroy", &args), 0);
    }
}
