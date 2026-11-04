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

#[derive(Debug, PartialEq, Eq)]
enum Which {
    Cache(String),
    Principal(String),
}

fn usage(prog: &str) -> String {
    format!(
        "Usage: {prog} {{-c cache_name | -p principal}}\n\
         \t-c specify name of credentials cache\n\
         \t-p specify name of principal\n"
    )
}

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

fn run(which: &Which) -> Result<(), (Krb5Error, String)> {
    let ctx = krb5_client::init_context().map_err(|e| (e, "while initializing krb5".to_owned()))?;
    let ctx = &ctx;
    let cache: Cache = match which {
        Which::Cache(name) => parse_ccspec(name)
            .map_err(|e| Krb5Error::from_ccname(&e))
            .and_then(|spec| resolve(ctx, &spec))
            .map_err(|e| (e, format!("while resolving {name}")))?,
        Which::Principal(name) => {
            let princ = parse_name(ctx, name, false)
                .map_err(|e| (e, format!("while parsing principal name {name}")))?;
            resolve_ccspec(ctx, None)
                .map_err(|e| Krb5Error::from_ccname(&e))
                .and_then(|default| cache_match(ctx, &default, &princ))
                .map_err(|e| (e, format!("while searching for ccache for {name}")))?
        }
    };
    cache
        .switch_to(ctx)
        .map_err(|e| (e, "while switching to credential cache".to_owned()))
}
