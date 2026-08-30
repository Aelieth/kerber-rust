//! Obtain a TGT from a KDC and write an MIT FILE ccache.
//!
//! Usage: krb5-kinit [--spake] [--fast --armor-ccache PATH] [--pkinit FILE:user.pem --pkinit-anchors FILE:ca.pem] [-E|--enterprise] <kdc-host> <user@REALM> <ccache-path> [service]
//!
//! Password is read from `KRB5_PASSWORD` or stdin. Never from argv.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use krb5_client::kinit_ex;
use krb5_config::env_password;
use krb5_protocol::KdcAddr;

fn strip_file_spec(s: String) -> String {
    match s.strip_prefix("FILE:") {
        Some(rest) => rest.to_owned(),
        None => s,
    }
}

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter("krb5_crypto=info,krb5_asn1=info,krb5_protocol=info,krb5_client=info")
        .try_init();

    let mut want_spake = false;
    let mut armor_ccache = None::<String>;
    let mut pkinit_identity = None::<String>;
    let mut pkinit_anchors = None::<String>;
    let mut enterprise = false;
    let mut positional = Vec::new();
    let mut args_iter = std::env::args().skip(1);
    while let Some(a) = args_iter.next() {
        match a.as_str() {
            "--spake" => want_spake = true,
            "--fast" => {}
            "--armor-ccache" => armor_ccache = args_iter.next(),
            "--pkinit" => pkinit_identity = args_iter.next().map(strip_file_spec),
            "--pkinit-anchors" => pkinit_anchors = args_iter.next().map(strip_file_spec),
            "-E" | "--enterprise" => enterprise = true,
            _ => positional.push(a),
        }
    }
    if want_spake && (armor_ccache.is_some() || pkinit_identity.is_some()) {
        eprintln!("--spake cannot be combined with --armor-ccache or --pkinit");
        std::process::exit(2);
    }
    let mut args = positional.into_iter();
    let host = args.next().unwrap_or_else(|| {
        eprintln!(
            "usage: krb5-kinit [--spake] [--fast --armor-ccache PATH] [--pkinit FILE:user.pem --pkinit-anchors FILE:ca.pem] [-E|--enterprise] <kdc-host> <user@REALM> <ccache-path> [service]"
        );
        std::process::exit(2);
    });
    let principal = args.next().unwrap_or_else(|| {
        eprintln!("missing user@REALM");
        std::process::exit(2);
    });
    let ccache = args.next().unwrap_or_else(|| {
        eprintln!("missing ccache-path");
        std::process::exit(2);
    });
    let service = args.next();
    let mut password = env_password().unwrap_or_else(|| {
        if pkinit_identity.is_some() {
            return Vec::new();
        }
        let mut s = String::new();
        if std::io::stdin().read_line(&mut s).is_err() {
            eprintln!("failed to read password from stdin");
            std::process::exit(2);
        }
        s.trim_end_matches(['\n', '\r']).as_bytes().to_vec()
    });
    let addr = if let Some((h, p)) = host.rsplit_once(':') {
        if let Ok(port) = p.parse() {
            KdcAddr {
                host: h.to_owned(),
                port,
            }
        } else {
            KdcAddr::new(host)
        }
    } else {
        KdcAddr::new(host)
    };
    match kinit_ex(
        &addr,
        &principal,
        &mut password,
        &ccache,
        service.as_deref(),
        want_spake,
        armor_ccache.as_deref().map(std::path::Path::new),
        pkinit_identity.as_deref().map(std::path::Path::new),
        pkinit_anchors.as_deref().map(std::path::Path::new),
        enterprise,
    ) {
        Ok(r) => {
            println!(
                "ok tgt={} tgs={}",
                r.as_out.enc_part.sname.name_string.len(),
                r.tgs_out.is_some()
            );
        }
        Err(e) => {
            eprintln!("kinit failed: {e}");
            std::process::exit(1);
        }
    }
}
