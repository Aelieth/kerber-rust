//! IPROP_GET_UPDATES client (ONC RPC program 100423, RPCSEC_GSS): the iprop gate's test tool.
//!
//! Usage: `krb5-iprop-pull [--full-resync] [--last-sno N] [--last-time SEC USEC] [--load-dump PATH] [host:port]`
//!
//! It is built only with the `test-hooks` feature (`required-features`), so a release build has
//! no such program and none of its environment; `make install` never installed it.
//!
//! `--load-dump` writes the database ([`krb5_config::KdcPaths`]; a new 0600 file, as a full load
//! leaves it) from a MIT dump the replica's stash opens, as kpropd loads one: with `iprop_enable`
//! set for the realm it must be an iprop dump (`ipropx` / `iprop`), the replica keeps its own
//! lockout attributes and its update log takes the dump's serial and time (MIT's `load -i`);
//! without it, a version 7 dump. `KRB5_MASTER_PASSWORD` opens it instead when set, and a missing
//! stash is then written. A host argument then pulls serial-delta.
//!
//! The pull is kpropd's iprop half and needs `iprop_enable`: the replica's update log (mapped as a
//! replica's) gives the serial and time asked from, unless `--last-sno` gives them, and keeps each
//! update applied, as MIT's `ulog_replay` keeps it.
//!
//! The gate's environment:
//! - `KRB5_KPROP_KEYTAB`: the keytab whose first principal authenticates the pull (required).
//! - `KRB5_KDC`: the KDC asked for its tickets (default `127.0.0.1`).
//! - `KRB5_IPROP_HOST`: the host of the `kiprop/<host>` service pulled from, MIT's admin server
//!   (default the documented test realm's host).

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpStream;
use std::path::PathBuf;

use krb5_admin::{iprop_dump_last, iprop_fullresync, iprop_pull, is_iprop_dump, load_replica};
use krb5_kdc::{IpropRole, load_dump_with_stash, load_store};
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
    let mut full_resync = false;
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
            "--full-resync" => full_resync = true,
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

    let paths = krb5_config::KdcPaths::resolve(None).unwrap_or_else(|e| {
        eprintln!("krb5-iprop-pull: {e}");
        std::process::exit(1);
    });
    let realm = paths.realm.clone().unwrap_or_default();
    let (db, stash) = (paths.database_name, paths.key_stash_file);
    let iprop = krb5_config::IpropParams::load(&realm, &db);

    if let Some(path) = dump {
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("krb5-iprop-pull: read dump: {e}");
            std::process::exit(1);
        });
        // MIT `load_database` (`kprop/kpropd.c:1574-1575`): an iprop replica loads with `-i`, any other plainly; each refuses the other's header.
        let header_last = iprop_dump_last(text.as_bytes());
        let iprop_load = match (iprop.enabled, header_last) {
            (true, Some(last)) => Some((&iprop, last)),
            (false, None) if !is_iprop_dump(text.as_bytes()) => None,
            _ => {
                eprintln!("krb5-iprop-pull: dump header bad in {}", path.display());
                std::process::exit(1);
            }
        };
        let store = load_dump(&text, &stash).unwrap_or_else(|e| {
            eprintln!("krb5-iprop-pull: load dump: {e}");
            std::process::exit(1);
        });
        load_replica(&store, &db, &stash, iprop_load).unwrap_or_else(|e| {
            eprintln!("krb5-iprop-pull: save: {e}");
            std::process::exit(1);
        });
        if let Some(last) = header_last {
            println!(
                "iprop dump last_sno={} last_time={} {}",
                last.sno, last.time.seconds, last.time.useconds
            );
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
    // MIT `parse_args` (`kprop/kpropd.c:1170-1177`): an iprop replica maps its update log as a replica's.
    // MIT `do_iprop` (`kprop/kpropd.c:764-768`): the serial and time asked from are the log's last.
    let mut mylast = krb5_kdc::UlogLast::default();
    if !full_resync {
        if !iprop.enabled {
            eprintln!("krb5-iprop-pull: iprop_enable is not set for {realm}");
            std::process::exit(1);
        }
        if let Err(e) = store.map_ulog(&iprop.logfile, iprop.ulogsize, IpropRole::Replica) {
            eprintln!("krb5-iprop-pull: {e} Unable to map log!");
            std::process::exit(1);
        }
        mylast = store.ulog_last().unwrap_or_default();
    }
    if let Some(sno) = last_sno {
        mylast = krb5_kdc::UlogLast {
            sno,
            time: krb5_kdc::UlogTime {
                seconds: last_sec,
                useconds: last_usec,
            },
        };
    }
    let realm = store.realm().to_owned();
    let kt_path = std::env::var("KRB5_KPROP_KEYTAB").unwrap_or_else(|_| {
        eprintln!("krb5-iprop-pull: set KRB5_KPROP_KEYTAB");
        std::process::exit(2);
    });
    let kt = krb5_protocol::read_secret_file(std::path::Path::new(&kt_path))
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
    let host = std::env::var("KRB5_IPROP_HOST")
        .unwrap_or_else(|_| krb5_kdc::testrealm::TEST_HOST.to_owned());
    let sname = PrincipalName::new(PrincipalName::NT_SRV_HST, ["kiprop", host.as_str()]);
    let tgs = tgs_exchange(&kdc, &as_out, sname, &realm).unwrap_or_else(|e| {
        eprintln!("krb5-iprop-pull: TGS: {e}");
        std::process::exit(1);
    });
    let mut stream = TcpStream::connect(&target).unwrap_or_else(|e| {
        eprintln!("krb5-iprop-pull: connect {target}: {e}");
        std::process::exit(1);
    });
    if full_resync {
        let status = iprop_fullresync(
            &mut stream,
            tgs.ticket,
            &tgs.session_key,
            &krb5_types::ascii(&realm),
            &ent.name,
        )
        .unwrap_or_else(|e| {
            eprintln!("krb5-iprop-pull: full-resync: {e}");
            std::process::exit(1);
        });
        println!("fullresync_status={status}");
        std::process::exit(i32::from(status != krb5_kdc::IPROP_OK));
    }
    let pulled = iprop_pull(
        &mut stream,
        tgs.ticket,
        &tgs.session_key,
        &krb5_types::ascii(&realm),
        &ent.name,
        krb5_admin::IpropLast {
            last_sno: mylast.sno,
            last_sec: mylast.time.seconds,
            last_usec: mylast.time.useconds,
        },
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
        "iprop pull ok last_sno={} last_time={} {} applied={}",
        pulled.last_sno, pulled.last_sec, pulled.last_usec, pulled.applied
    );
}

/// The dump opened with `KRB5_MASTER_PASSWORD` when that is set, else with the replica's stash.
fn load_dump(text: &str, stash: &std::path::Path) -> Result<krb5_kdc::PrincipalStore, String> {
    let hooked = std::env::var("KRB5_MASTER_PASSWORD")
        .ok()
        .map(zeroize::Zeroizing::new);
    if let Some(pw) = hooked {
        return krb5_kdc::load_dump(text, pw.as_bytes()).map_err(|e| e.to_string());
    }
    let bytes = krb5_protocol::read_secret_file(stash)
        .map_err(|e| format!("stash {}: {e}", stash.display()))?;
    load_dump_with_stash(text, &bytes).map_err(|e| e.to_string())
}

fn need_arg(flag: &str) -> String {
    eprintln!("krb5-iprop-pull: {flag} needs a value");
    usage();
}

fn usage() -> ! {
    eprintln!(
        "usage: krb5-iprop-pull [--full-resync] [--last-sno N] [--last-time SEC USEC] [--load-dump PATH] [host:port]"
    );
    std::process::exit(2);
}
