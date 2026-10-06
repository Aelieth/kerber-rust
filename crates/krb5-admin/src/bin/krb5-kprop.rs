//! MIT-wire kprop sender (TCP 754) wrapping dump version 7.
//!
//! Usage: `krb5-kprop [-P port] [-s keytab] [-n host-instance] replica`
//!
//! Loads the database and stash [`krb5_config::KdcPaths`] resolves, issues a `host/<instance>`
//! ticket from that store, and calls [`krb5_admin::kprop_send_store`]. The dump's keys are
//! wrapped under the stash's master key, as MIT's kprop sends a dump of the database that stash
//! opens; with the `test-hooks` feature, `KRB5_MASTER_PASSWORD` names it instead when set.
//!
//! The keytab is `-s`'s, else the default keytab (`KRB5_KTNAME`, else krb5.conf's
//! `default_keytab_name`, else `/etc/krb5.keytab`), as MIT's kprop finds it; one that cannot be
//! read stops kprop with MIT's error "while getting initial credentials". Its first principal is
//! the client, where MIT's is `host/<this host>` with that keytab's key. kprop reads no
//! environment of its own: MIT's reads none.
//!
//! `-i` sends an iprop dump (`ipropx 1`), what MIT's kadmind sends a replica that asked for a
//! full resync after `kdb5_util dump -i`: it needs `iprop_enable` for the realm, and the dump's
//! header carries the update log's last serial and time, read before the database is, as MIT's
//! dump reads them.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpStream;
use std::path::Path;

use krb5_admin::{KPROP_PORT, iprop_snapshot, kprop_send_store, kprop_send_store_iprop};
use krb5_crypto::ProtocolKey;
use krb5_kdc::{PrincipalStore, issue_as, issue_tgs, load_store};
use krb5_log::klog::JsonLog;
use krb5_protocol::Keytab;
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};
use krb5_types::PrincipalName;

fn main() {
    // MIT `main` (`kprop/kprop.c:101-105`): the library context first, its profile krb5.conf; a
    // profile it refuses ends kprop.
    if let Err(e) = krb5_config::init_profile() {
        let argv0 = std::env::args()
            .next()
            .unwrap_or_else(|| "kprop".to_owned());
        eprintln!("{argv0}: {} while initializing krb5", e.init_text());
        std::process::exit(1);
    }
    // The JSON log only where the KDC profile's `[logging] json` names a destination (MIT has
    // none).
    if let Some(json) = krb5_config::LogSpecs::load_json().and_then(|s| JsonLog::open("kprop", &s))
    {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_writer(json.make_writer())
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "krb5_admin=info,krb5_kdc=info".into()),
            )
            .try_init();
    }

    let mut port = KPROP_PORT;
    let argv0 = std::env::args()
        .next()
        .unwrap_or_else(|| "kprop".to_owned());
    // MIT `parse_args` (`kprop/kprop.c:143-145`): `-s` names the keytab.
    let mut keytab: Option<String> = None;
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
                keytab = Some(args.next().unwrap_or_else(|| need_arg("-s")));
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
    let paths = krb5_config::KdcPaths::resolve(None).unwrap_or_else(|e| {
        // MIT `parse_args` (`kprop/kprop.c:154-159`): no realm prints only this context (MIT
        // passes errno, 0, to com_err), exit 1.
        if matches!(e, krb5_config::Error::NoDefaultRealm) {
            eprintln!("krb5-kprop: while getting default realm");
        } else {
            eprintln!("krb5-kprop: {e}");
        }
        std::process::exit(1);
    });
    // The database is judged first, then the stash, which opens it and wraps the dump: one that
    // cannot be read is named before anything is sent.
    // MIT `open_db_and_mkey` (`kadmin/dbutil/kdb5_util.c:378-401`): the dump kprop sends opens the database, and reads its master entry, before the master key is fetched.
    if let Err(e) = krb5_kdc::check_database(&paths.database_name) {
        eprintln!("krb5-kprop: load store: {e}");
        std::process::exit(1);
    }
    if let Err(e) = std::fs::File::open(&paths.key_stash_file) {
        eprintln!("krb5-kprop: stash {}: {e}", paths.key_stash_file.display());
        std::process::exit(1);
    }
    // MIT `dump_db` (`kadmin/dbutil/dump.c:1173-1192`): an iprop dump needs iprop enabled; its header is the update log's last serial and time.
    // MIT `dump_db` (`kadmin/dbutil/dump.c:1318-1333`): that serial and time are read before the database, so the dump holds at least what they say.
    let (store, iprop_last) = if iprop {
        let realm = paths.realm.clone().unwrap_or_default();
        let params = krb5_config::IpropParams::load(&realm, &paths.database_name);
        if !params.enabled {
            eprintln!("Iprop not enabled");
            std::process::exit(1);
        }
        let (store, last) = iprop_snapshot(&paths.database_name, &paths.key_stash_file, &params)
            .unwrap_or_else(|e| {
                eprintln!("krb5-kprop: {e}");
                std::process::exit(1);
            });
        (store, Some(last))
    } else {
        let store = load_store(&paths.database_name, &paths.key_stash_file).unwrap_or_else(|e| {
            eprintln!("krb5-kprop: load store: {e}");
            std::process::exit(1);
        });
        (store, None)
    };
    let master =
        master_key(&store, &paths.database_name, &paths.key_stash_file).unwrap_or_else(|e| {
            eprintln!("krb5-kprop: {e}");
            std::process::exit(1);
        });
    let realm = store.realm().to_owned();
    let host_inst = instance.unwrap_or_else(|| replica.clone());
    let server = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", host_inst.as_str()]);
    let client = client_name(&argv0, keytab.as_deref(), &realm);
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
    let crealm = krb5_types::ascii(&realm);
    let (ticket, session) = (tgs_out.rep.0.ticket, &tgs_out.session_key);
    match iprop_last {
        Some(last) => kprop_send_store_iprop(
            &mut stream,
            &store,
            &master,
            last,
            ticket,
            session,
            &crealm,
            &client,
        ),
        None => kprop_send_store(
            &mut stream,
            &store,
            &master,
            ticket,
            session,
            &crealm,
            &client,
        ),
    }
    .unwrap_or_else(|e| {
        eprintln!("krb5-kprop: send: {e}");
        std::process::exit(1);
    });
    println!("kprop ok {addr}");
}

/// The key the dump's keys are wrapped under: the stash's (it opened `store`), or with the
/// `test-hooks` feature one derived from `KRB5_MASTER_PASSWORD` with the type of the store's
/// `K/M` key.
fn master_key(store: &PrincipalStore, db: &Path, stash: &Path) -> Result<ProtocolKey, String> {
    #[cfg(feature = "test-hooks")]
    let hooked = std::env::var("KRB5_MASTER_PASSWORD")
        .ok()
        .map(zeroize::Zeroizing::new);
    #[cfg(not(feature = "test-hooks"))]
    let hooked: Option<zeroize::Zeroizing<String>> = None;
    match hooked {
        Some(pw) => {
            let etype = store
                .get(&format!("K/M@{}", store.realm()))
                .and_then(|km| km.keys.first())
                .map_or_else(krb5_kdc::default_master_etype, |k| k.etype);
            krb5_kdc::master_key_from_password(store.realm(), pw.as_bytes(), etype)
                .map_err(|e| e.to_string())
        }
        None => {
            krb5_kdc::read_stash(stash, db).map_err(|e| format!("stash {}: {e}", stash.display()))
        }
    }
}

/// The client: the first principal of kprop's keytab (`-s`, else the default keytab). A keytab
/// that cannot be read stops kprop with MIT's error.
/// MIT `get_tickets` (`kprop/kprop.c:195-208`): a name that does not resolve fails "while resolving keytab", and a keytab `krb5_get_init_creds_keytab` cannot use fails "while getting initial credentials", each ending kprop.
fn client_name(argv0: &str, keytab: Option<&str>, realm: &str) -> PrincipalName {
    let fail = |text: &str, during: &str| -> ! {
        eprintln!("{argv0}: {text} {during}");
        std::process::exit(1);
    };
    let file =
        krb5_admin::kprop_keytab_file(keytab).unwrap_or_else(|e| fail(e, "while resolving keytab"));
    let creds = "while getting initial credentials\n";
    let bytes = match file.as_deref().map(krb5_protocol::read_secret_file) {
        Some(Ok(bytes)) => Some(bytes),
        Some(Err(e)) => fail(&krb5_log::klog::os_error_text(&e), creds),
        None => None,
    };
    if let Some(bytes) = &bytes
        && (bytes.len() < 2 || bytes[0] != 0x05 || !matches!(bytes[1], 0x01 | 0x02))
    {
        fail("Unsupported key table format version number", creds);
    }
    let first = bytes
        .and_then(|b| Keytab::parse(&b).ok())
        .and_then(|kt| kt.entries.into_iter().next());
    if let Some(entry) = first {
        return entry.name;
    }
    // MIT `get_tickets` (`kprop/kprop.c:173-174`): kprop's own name is `host` and this host, made by its krb5.conf context.
    let conf = krb5_config::load_krb5_conf().unwrap_or_default();
    let host = krb5_config::local_host_name(&conf);
    fail(
        &format!("Keytab contains no suitable keys for host/{host}@{realm}"),
        creds,
    )
}

fn need_arg(flag: &str) -> String {
    eprintln!("krb5-kprop: {flag} needs a value");
    usage();
}

fn usage() -> ! {
    eprintln!("usage: krb5-kprop [-i] [-P port] [-s keytab] [-n host-instance] replica");
    std::process::exit(2);
}
