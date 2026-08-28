//! MIT-wire kprop sender (TCP 754) wrapping dump version 7.
//!
//! Usage: `krb5-kprop [-P port] [-s keytab] [-n host-instance] replica`
//!
//! Loads `KRB5_KDC_DB` / `KRB5_KDC_STASH`, issues a `host/<instance>`
//! ticket from that store, and calls [`krb5_admin::kprop_send_store`].
//! Dump keys are wrapped with `KRB5_MASTER_PASSWORD`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpStream;
use std::path::PathBuf;

use krb5_admin::{KPROP_PORT, kprop_send_store, kprop_send_store_iprop};
use krb5_kdc::{as_req, issue_as, issue_tgs, load_store, pa_enc_timestamp, tgs_req};
use krb5_protocol::Keytab;
use krb5_types::PrincipalName;

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "krb5_admin=info,krb5_kdc=info".into()),
        )
        .try_init();

    let mut port = KPROP_PORT;
    let mut keytab: Option<PathBuf> = std::env::var("KRB5_KPROP_KEYTAB").ok().map(PathBuf::from);
    let mut instance: Option<String> = None;
    let mut replica: Option<String> = None;
    let mut iprop = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-i" => iprop = true,
            "-P" => {
                let p = args.next().unwrap_or_else(|| need_arg("-P"));
                port = p.parse().unwrap_or_else(|_| {
                    eprintln!("krb5-kprop: bad port {p}");
                    std::process::exit(2);
                });
            }
            "-s" => {
                keytab = Some(PathBuf::from(args.next().unwrap_or_else(|| need_arg("-s"))));
            }
            "-n" => {
                instance = Some(args.next().unwrap_or_else(|| need_arg("-n")));
            }
            flag if flag.starts_with('-') => {
                eprintln!("krb5-kprop: unknown flag {flag}");
                usage();
            }
            other => replica = Some(other.to_owned()),
        }
    }
    let Some(replica) = replica else {
        usage();
    };
    let master = std::env::var("KRB5_MASTER_PASSWORD").unwrap_or_else(|_| {
        eprintln!("krb5-kprop: set KRB5_MASTER_PASSWORD");
        std::process::exit(2);
    });
    let db = PathBuf::from(std::env::var("KRB5_KDC_DB").unwrap_or_else(|_| {
        eprintln!("krb5-kprop: set KRB5_KDC_DB");
        std::process::exit(2);
    }));
    let stash = PathBuf::from(std::env::var("KRB5_KDC_STASH").unwrap_or_else(|_| {
        eprintln!("krb5-kprop: set KRB5_KDC_STASH");
        std::process::exit(2);
    }));
    let store = load_store(&db, &stash).unwrap_or_else(|e| {
        eprintln!("krb5-kprop: load store: {e}");
        std::process::exit(1);
    });
    let realm = store.realm().to_owned();
    let host_inst = instance.unwrap_or_else(|| replica.clone());
    let server = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", host_inst.as_str()]);
    let client = client_name(keytab.as_deref(), &server);
    let Some(princ) = store.get_name(&client) else {
        eprintln!("krb5-kprop: missing client {}", client.components_joined());
        std::process::exit(1);
    };
    let client_key = princ
        .best_key()
        .unwrap_or_else(|| {
            eprintln!("krb5-kprop: client has no key");
            std::process::exit(1);
        })
        .key
        .clone();
    let pa = pa_enc_timestamp(&client_key).unwrap_or_else(|e| {
        eprintln!("krb5-kprop: PA-ENC-TS: {e}");
        std::process::exit(1);
    });
    let as_req = as_req(client.clone(), &realm, 1, Some(vec![pa])).unwrap_or_else(|e| {
        eprintln!("krb5-kprop: AS-REQ: {e}");
        std::process::exit(1);
    });
    let as_out = issue_as(&store, &as_req).unwrap_or_else(|e| {
        eprintln!("krb5-kprop: issue AS: {e}");
        std::process::exit(1);
    });
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &realm,
        &client,
        server,
        &realm,
        2,
    )
    .unwrap_or_else(|e| {
        eprintln!("krb5-kprop: TGS-REQ: {e}");
        std::process::exit(1);
    });
    let tgs_out = issue_tgs(&store, &tgs).unwrap_or_else(|e| {
        eprintln!("krb5-kprop: issue TGS: {e}");
        std::process::exit(1);
    });
    let addr = format!("{replica}:{port}");
    let mut stream = TcpStream::connect(&addr).unwrap_or_else(|e| {
        eprintln!("krb5-kprop: connect {addr}: {e}");
        std::process::exit(1);
    });
    let send = if iprop {
        kprop_send_store_iprop
    } else {
        kprop_send_store
    };
    send(
        &mut stream,
        &store,
        master.as_bytes(),
        tgs_out.rep.0.ticket,
        &tgs_out.session_key,
        &krb5_types::ascii(&realm),
        &client,
    )
    .unwrap_or_else(|e| {
        eprintln!("krb5-kprop: send: {e}");
        std::process::exit(1);
    });
    println!("kprop ok {addr}");
}

fn client_name(keytab: Option<&std::path::Path>, server: &PrincipalName) -> PrincipalName {
    if let Some(path) = keytab {
        match std::fs::read(path)
            .and_then(|b| Keytab::parse(&b).map_err(|e| std::io::Error::other(e.to_string())))
        {
            Ok(kt) => {
                if let Some(e) = kt.entries.first() {
                    return e.name.clone();
                }
            }
            Err(e) => eprintln!("krb5-kprop: keytab {}: {e}", path.display()),
        }
    }
    server.clone()
}

fn need_arg(flag: &str) -> String {
    eprintln!("krb5-kprop: {flag} needs a value");
    usage();
}

fn usage() -> ! {
    eprintln!("usage: krb5-kprop [-i] [-P port] [-s keytab] [-n host-instance] replica");
    std::process::exit(2);
}
