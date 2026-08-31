//! Switch the DIR collection primary (MIT `kswitch`).
//!
//! Usage: krb5-kswitch [-c ccache | -p principal]

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use krb5_config::{CcSpec, resolve_ccspec};
use krb5_protocol::{FileCcache, dir_subsidiaries, dir_switch};

fn main() {
    let mut ccname = None::<String>;
    let mut princ = None::<String>;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => {
                let Some(s) = args.next() else {
                    eprintln!("kswitch: missing -c argument");
                    std::process::exit(2);
                };
                ccname = Some(s);
            }
            "-p" => {
                let Some(s) = args.next() else {
                    eprintln!("kswitch: missing -p argument");
                    std::process::exit(2);
                };
                princ = Some(s);
            }
            _ => {
                eprintln!("usage: krb5-kswitch [-c ccache | -p principal]");
                std::process::exit(2);
            }
        }
    }
    if ccname.is_some() && princ.is_some() {
        eprintln!("kswitch: -c and -p are exclusive");
        std::process::exit(2);
    }
    if let Err(e) = run(ccname.as_deref(), princ.as_deref()) {
        eprintln!("kswitch: {e}");
        std::process::exit(1);
    }
}

fn run(ccname: Option<&str>, princ: Option<&str>) -> Result<(), String> {
    if let Some(p) = princ {
        return switch_principal(p);
    }
    let spec = resolve_ccspec(ccname)?;
    match spec {
        CcSpec::Dir(r) if r.starts_with(':') => dir_switch(&r).map_err(|e| e.to_string()),
        CcSpec::Dir(_) => Err("kswitch -c needs DIR::subsidiary".into()),
        _ => Err("kswitch requires a DIR collection".into()),
    }
}

fn switch_principal(princ: &str) -> Result<(), String> {
    let spec = resolve_ccspec(None)?;
    let CcSpec::Dir(r) = spec else {
        return Err("kswitch -p requires DIR default ccache".into());
    };
    let dirname = r.strip_prefix(':').map_or(r.as_str(), |p| {
        std::path::Path::new(p)
            .parent()
            .and_then(|d| d.to_str())
            .unwrap_or(p)
    });
    let dir = if r.starts_with(':') {
        std::path::Path::new(dirname)
    } else {
        std::path::Path::new(r.as_str())
    };
    for path in dir_subsidiaries(dir).map_err(|e| e.to_string())? {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(cc) = FileCcache::parse(&bytes) else {
            continue;
        };
        let name = FileCcache::format_principal(&cc.primary.0, &cc.primary.1);
        if name == princ {
            let residual = format!(":{}", path.display());
            return dir_switch(&residual).map_err(|e| e.to_string());
        }
    }
    Err(format!("no cache for {princ}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_switch_residual_must_be_subsidiary() {
        let e = run(Some("DIR:/tmp/not-a-sub"), None).unwrap_err();
        assert!(e.contains("DIR::"), "{e}");
    }
}
