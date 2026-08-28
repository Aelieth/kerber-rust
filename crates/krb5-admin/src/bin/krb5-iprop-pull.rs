//! IPROP_GET_UPDATES client (ONC RPC program 100423, RPCSEC_GSS).
//!
//! Usage: `krb5-iprop-pull [--last-sno N] [--last-time SEC USEC] [--load-dump PATH] [host:port]`
//!
//! `--load-dump` writes `KRB5_KDC_DB` / `KRB5_KDC_STASH` from a MIT dump
//! (version 7 or `ipropx`). A host argument then pulls serial-delta.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpStream;
use std::path::PathBuf;

use krb5_admin::iprop_pull;
use krb5_kdc::{load_dump_path, load_store, save_store};
use krb5_protocol::{Keytab, as_exchange_key, tgs_exchange};
use krb5_types::PrincipalName;

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "krb5_admin=info,krb5_kdc=info".into()),
        )
        .try_init();

    let mut last_sno: Option<u32> = None;
    let mut last_sec: u32 = 0;
    let mut last_usec: u32 = 0;
    let mut dump: Option<PathBuf> = None;
    let mut target: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--last-sno" => {
                let p = args.next().unwrap_or_else(|| need_arg("--last-sno"));
                last_sno = Some(p.parse().unwrap_or_else(|_| {
                    eprintln!("krb5-iprop-pull: bad last-sno {p}");
                    std::process::exit(2);
                }));
            }
            "--last-time" => {
                let s = args.next().unwrap_or_else(|| need_arg("--last-time"));
                let u = args.next().unwrap_or_else(|| need_arg("--last-time"));
                last_sec = s.parse().unwrap_or_else(|_| {
                    eprintln!("krb5-iprop-pull: bad last-time sec {s}");
                    std::process::exit(2);
                });
                last_usec = u.parse().unwrap_or_else(|_| {
                    eprintln!("krb5-iprop-pull: bad last-time usec {u}");
                    std::process::exit(2);
                });
            }
            "--load-dump" => {
                dump = Some(PathBuf::from(
                    args.next().unwrap_or_else(|| need_arg("--load-dump")),
                ));
            }
            flag if flag.starts_with('-') => {
                eprintln!("krb5-iprop-pull: unknown flag {flag}");
                usage();
            }
            other => target = Some(other.to_owned()),
        }
    }

    let master = std::env::var("KRB5_MASTER_PASSWORD").unwrap_or_else(|_| {
        eprintln!("krb5-iprop-pull: set KRB5_MASTER_PASSWORD");
        std::process::exit(2);
    });
    let db = PathBuf::from(std::env::var("KRB5_KDC_DB").unwrap_or_else(|_| {
        eprintln!("krb5-iprop-pull: set KRB5_KDC_DB");
        std::process::exit(2);
    }));
    let stash = PathBuf::from(std::env::var("KRB5_KDC_STASH").unwrap_or_else(|_| {
        eprintln!("krb5-iprop-pull: set KRB5_KDC_STASH");
        std::process::exit(2);
    }));

    if let Some(path) = dump {
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("krb5-iprop-pull: read dump: {e}");
            std::process::exit(1);
        });
        let header_last = parse_iprop_last(text.lines().next().unwrap_or(""));
        let store = load_dump_path(&path, master.as_bytes()).unwrap_or_else(|e| {
            eprintln!("krb5-iprop-pull: load dump: {e}");
            std::process::exit(1);
        });
        save_store(&store, &db, &stash).unwrap_or_else(|e| {
            eprintln!("krb5-iprop-pull: save: {e}");
            std::process::exit(1);
        });
        if let Some((s, sec, usec)) = header_last {
            println!("iprop dump last_sno={s} last_time={sec} {usec}");
            if last_sno.is_none() {
                last_sno = Some(s);
                last_sec = sec;
                last_usec = usec;
            }
        } else {
            println!("iprop dump loaded");
        }
        if target.is_none() {
            return;
        }
    }

    let Some(target) = target else {
        usage();
    };

    let mut store = load_store(&db, &stash).unwrap_or_else(|e| {
        eprintln!("krb5-iprop-pull: load store: {e}");
        std::process::exit(1);
    });
    store.persist_paths = Some((db.clone(), stash.clone()));
    let sno = last_sno.unwrap_or_else(|| store.serial());
    let realm = store.realm().to_owned();
    let kt_path = std::env::var("KRB5_KPROP_KEYTAB").unwrap_or_else(|_| {
        eprintln!("krb5-iprop-pull: set KRB5_KPROP_KEYTAB");
        std::process::exit(2);
    });
    let kt = std::fs::read(&kt_path)
        .map_err(|e| e.to_string())
        .and_then(|b| Keytab::parse(&b).map_err(|e| e.to_string()))
        .unwrap_or_else(|e| {
            eprintln!("krb5-iprop-pull: keytab: {e}");
            std::process::exit(1);
        });
    let Some(ent) = kt.entries.first() else {
        eprintln!("krb5-iprop-pull: empty keytab");
        std::process::exit(1);
    };
    let mut keys: Vec<_> = kt
        .entries
        .iter()
        .filter(|e| e.name == ent.name)
        .map(|e| e.key.clone())
        .collect();
    let sha1: Vec<_> = keys
        .iter()
        .filter(|k| k.etype() == krb5_crypto::EncryptionType::Aes256CtsHmacSha196)
        .cloned()
        .collect();
    if !sha1.is_empty() {
        keys = sha1;
    }
    eprintln!(
        "krb5-iprop-pull: client {} keys {}",
        ent.name.components_joined(),
        keys.len()
    );
    let kdc_host = std::env::var("KRB5_KDC").unwrap_or_else(|_| "127.0.0.1".into());
    let kdc = krb5_protocol::KdcAddr::new(kdc_host);
    let as_out = as_exchange_key(ent.name.clone(), &realm, &keys, &kdc).unwrap_or_else(|e| {
        eprintln!("krb5-iprop-pull: AS: {e}");
        std::process::exit(1);
    });
    let host = std::env::var("KRB5_IPROP_HOST").unwrap_or_else(|_| "testhost.kerber.test".into());
    let sname = PrincipalName::new(PrincipalName::NT_SRV_HST, ["kiprop", host.as_str()]);
    let tgs = tgs_exchange(&kdc, &as_out, sname, &realm).unwrap_or_else(|e| {
        eprintln!("krb5-iprop-pull: TGS: {e}");
        std::process::exit(1);
    });
    let mut stream = TcpStream::connect(&target).unwrap_or_else(|e| {
        eprintln!("krb5-iprop-pull: connect {target}: {e}");
        std::process::exit(1);
    });
    let pulled = iprop_pull(
        &mut stream,
        tgs.ticket,
        &tgs.session_key,
        &krb5_types::ascii(&realm),
        &ent.name,
        sno,
        last_sec,
        last_usec,
        &mut store,
    )
    .unwrap_or_else(|e| {
        eprintln!("krb5-iprop-pull: pull: {e}");
        std::process::exit(1);
    });
    if pulled.status == krb5_kdc::IPROP_FULL_RESYNC {
        println!("iprop full-resync last_sno={}", pulled.last_sno);
        std::process::exit(1);
    }
    if pulled.status != krb5_kdc::IPROP_OK && pulled.status != krb5_kdc::IPROP_NIL {
        eprintln!("krb5-iprop-pull: status {}", pulled.status);
        std::process::exit(1);
    }
    println!(
        "iprop pull ok last_sno={} applied={}",
        pulled.last_sno, pulled.applied
    );
}

fn parse_iprop_last(header: &str) -> Option<(u32, u32, u32)> {
    let mut it = header.split_whitespace();
    let kind = it.next()?;
    let sno = if kind == "ipropx" {
        let _ver = it.next()?;
        it.next()?.parse().ok()?
    } else if kind == "iprop" {
        it.next()?.parse().ok()?
    } else {
        return None;
    };
    let sec = it.next()?.parse().ok()?;
    let usec = it.next()?.parse().ok()?;
    Some((sno, sec, usec))
}

fn need_arg(flag: &str) -> String {
    eprintln!("krb5-iprop-pull: {flag} needs a value");
    usage();
}

fn usage() -> ! {
    eprintln!(
        "usage: krb5-iprop-pull [--last-sno N] [--last-time SEC USEC] [--load-dump PATH] [host:port]"
    );
    std::process::exit(2);
}
