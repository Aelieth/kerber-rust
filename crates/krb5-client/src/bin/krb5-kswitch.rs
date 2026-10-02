//! MIT `kswitch`: make a cache the primary of its collection.
//!
//! Usage: `kswitch {-c cache_name | -p principal}`

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use krb5_client::ccol::{Cache, cache_match, resolve};
use krb5_client::cli::{UsageError, UsageLine, getopt_each, own, progname};
use krb5_client::creds::parse_name;
use krb5_client::errmsg::Krb5Error;
use krb5_config::{parse_ccspec, resolve_ccspec};

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let argv0 = argv.first().map_or("kswitch", String::as_str);
    let prog = progname(argv0);
    let which = match parse(argv.get(1..).unwrap_or_default()) {
        Ok(w) => w,
        Err(e) => {
            for line in e.lines(argv0) {
                eprintln!("{line}");
            }
            eprint!("{}", usage(prog));
            std::process::exit(2);
        }
    };
    if let Err((e, doing)) = run(&which) {
        krb5_client::com_err!(prog, e, "{doing}");
        std::process::exit(1);
    }
}

/// `-c cache_name` or `-p principal`.
#[derive(Debug, PartialEq, Eq)]
enum Which {
    Cache(String),
    Principal(String),
}

/// MIT `usage` (`kswitch.c:38-45`): the usage text, `prog` naming the program.
fn usage(prog: &str) -> String {
    format!(
        "Usage: {prog} {{-c cache_name | -p principal}}\n\
         \t-c specify name of credentials cache\n\
         \t-p specify name of principal\n"
    )
}

/// MIT `main` (`kswitch.c:61-90`): one of `-c` or `-p`, once, and nothing else.
fn parse(args: &[String]) -> Result<Which, UsageError> {
    let (each, rest) = getopt_each(args, "c:p:", &[]);
    let mut lines = Vec::new();
    let mut which = None;
    let mut errflag = false;
    for o in each {
        let o = match o {
            Ok(o) => o,
            Err(e) => {
                lines.push(UsageLine::Getopt(e));
                errflag = true;
                continue;
            }
        };
        let arg = o.arg.unwrap_or_default();
        if which.is_some() {
            lines.push(own("Only one -c or -p option allowed"));
            errflag = true;
        } else if o.flag == 'c' {
            which = Some(Which::Cache(arg));
        } else {
            which = Some(Which::Principal(arg));
        }
    }
    if !rest.is_empty() {
        errflag = true;
    }
    if which.is_none() {
        lines.push(own("One of -c or -p must be specified"));
        errflag = true;
    }
    match which {
        Some(w) if !errflag => Ok(w),
        _ => Err(UsageError::Each(lines)),
    }
}

/// MIT `main` (`kswitch.c:92-127`): the library's profile, then the named cache resolved, or the
/// principal's found in the default collection, and switched to.
fn run(which: &Which) -> Result<(), (Krb5Error, String)> {
    krb5_client::init_context().map_err(|e| (e, "while initializing krb5".to_owned()))?;
    let cache: Cache = match which {
        Which::Cache(name) => parse_ccspec(name)
            .map_err(|e| Krb5Error::from_ccname(&e))
            .and_then(|spec| resolve(&spec))
            .map_err(|e| (e, format!("while resolving {name}")))?,
        Which::Principal(name) => {
            let princ = parse_name(name, false)
                .map_err(|e| (e, format!("while parsing principal name {name}")))?;
            resolve_ccspec(None)
                .map_err(|e| Krb5Error::from_ccname(&e))
                .and_then(|default| cache_match(&default, &princ))
                .map_err(|e| (e, format!("while searching for ccache for {name}")))?
        }
    };
    cache
        .switch_to()
        .map_err(|e| (e, "while switching to credential cache".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    /// Live MIT 1.22.2 `kswitch`: its refusals, then the
    /// usage text; a bad option does not end the parse.
    #[test]
    fn kswitch_refuses_as_mit() {
        assert_eq!(
            parse(&s(&["-Z"])).unwrap_err().lines("kswitch"),
            [
                "kswitch: invalid option -- 'Z'",
                "One of -c or -p must be specified"
            ]
        );
        assert_eq!(
            parse(&s(&[])).unwrap_err().lines("kswitch"),
            ["One of -c or -p must be specified"]
        );
        assert_eq!(
            parse(&s(&["-c", "a", "-p", "b"]))
                .unwrap_err()
                .lines("kswitch"),
            ["Only one -c or -p option allowed"]
        );
        assert_eq!(
            parse(&s(&["-x", "-p", "alice"]))
                .unwrap_err()
                .lines("kswitch"),
            ["kswitch: invalid option -- 'x'"]
        );
        assert_eq!(
            parse(&s(&["-p", "alice"])).unwrap(),
            Which::Principal("alice".into())
        );
        assert!(usage("kswitch").starts_with("Usage: kswitch {-c cache_name | -p principal}\n"));
    }
}
