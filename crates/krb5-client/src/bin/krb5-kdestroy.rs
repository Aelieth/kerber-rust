#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use krb5_client::ccol::{cache_match, collection, resolve};
use krb5_client::cli::{UsageError, UsageLine, getopt_each, own, progname};
use krb5_client::creds::parse_name;
use krb5_client::errmsg::{Code, Krb5Error};
use krb5_config::{CcSpec, ClientContext, parse_ccspec, resolve_ccspec};

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let argv0 = argv.first().map_or("kdestroy", String::as_str);
    let prog = progname(argv0);
    let args = match parse(argv.get(1..).unwrap_or_default()) {
        Ok(a) => a,
        Err(Parsed::Krb4(e)) => {
            for line in e.lines(argv0) {
                eprintln!("{line}");
            }
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

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    all: bool,
    quiet: bool,
    cache: Option<String>,
    princ: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    // MIT main; see docs/parity/b1-client-preauth.md
    Krb4(UsageError),
    Usage(UsageError),
}

// MIT `usage` (`kdestroy.c:49-59`): the usage text, `prog` naming the program.
fn usage(prog: &str) -> String {
    format!(
        "Usage: {prog} [-A] [-q] [-c cache_name] [-p princ_name]\n\
         \t-A destroy all credential caches in collection\n\
         \t-q quiet mode\n\
         \t-c specify name of credentials cache\n\
         \t-p specify principal name within collection\n"
    )
}

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
            '4' => return Err(Parsed::Krb4(UsageError::Each(lines))),
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

fn run(prog: &str, args: &Args) -> i32 {
    let ctx = match krb5_client::init_context() {
        Ok(ctx) => ctx,
        Err(e) => {
            krb5_client::com_err!(prog, e, "while initializing krb5");
            return 1;
        }
    };
    let ctx = &ctx;
    let default = match &args.cache {
        Some(name) => parse_ccspec(name),
        None => resolve_ccspec(ctx, None),
    }
    .map_err(|e| Krb5Error::from_ccname(&e));
    if args.all {
        let Ok(default) = default else {
            return 0;
        };
        let caches = match collection(ctx, &default) {
            Ok(c) => c,
            Err(e) => {
                krb5_client::com_err!(prog, e, "while listing credential caches");
                return 1;
            }
        };
        for cache in caches {
            if let Err(e) = cache.destroy(ctx)
                && e.code != Code::FccNofile
            {
                krb5_client::com_err!(prog, e, "while destroying cache {}", cache.full_name());
            }
        }
        return 0;
    }
    let cache = match &args.princ {
        Some(name) => {
            let princ = match parse_name(ctx, name, false) {
                Ok(p) => p,
                Err(e) => {
                    krb5_client::com_err!(prog, e, "while parsing principal name {name}");
                    return 1;
                }
            };
            match default
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|d| cache_match(ctx, d, &princ))
            {
                Ok(c) => c,
                Err(e) => {
                    krb5_client::com_err!(prog, e, "while finding cache for {name}");
                    return 1;
                }
            }
        }
        None => match default
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|d| resolve(ctx, d))
        {
            Ok(c) => c,
            Err(e) => {
                krb5_client::com_err!(prog, e, "while resolving ccache");
                return 1;
            }
        },
    };
    let mut errflg = 0;
    if let Err(e) = cache.destroy(ctx) {
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
        return remaining_cc_warning(ctx, prog, &default);
    }
    errflg
}

// MIT `print_remaining_cc_warning` (`kdestroy.c:62-83`): a cache left in the collection is
fn remaining_cc_warning(ctx: &ClientContext, prog: &str, default: &CcSpec) -> i32 {
    match collection(ctx, default) {
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
