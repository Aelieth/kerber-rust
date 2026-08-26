//! MIT `kdb5_util` dump/load CLI.
//!
//! Usage:
//!   `krb5-kdb load <dump>` — MIT dump → `KRB5_KDC_DB` / `KRB5_KDC_STASH`
//!   `krb5-kdb dump <dump>` — store → MIT dump (version 7)
//!   `krb5-kdb dump <dump> --from-dump <other>` — transcode a MIT dump
//!   `krb5-kdb create <realm>` — bootstrap + dump-v7 persist
//!
//! Master password: `KRB5_MASTER_PASSWORD`. Optional `KRB5_MASTER_ETYPE`
//! (MIT name or IANA number; default `aes256-cts-hmac-sha384-192`).
//! Create passwords: `KRB5_TEST_USER_PASSWORD` / `KRB5_TEST_ADMIN_PASSWORD`.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use krb5_crypto::EncryptionType;
use krb5_kdc::{
    bootstrap_realm, load_dump_etype, load_store, parse_dump, save_store, write_dump_path_etype,
    KDB_DUMP_VERSION, TEST_ADMIN, TEST_USER,
};

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut from_dump: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--from-dump" {
            from_dump = args.get(i + 1).cloned();
            args.remove(i);
            if i < args.len() {
                args.remove(i);
            }
            continue;
        }
        i += 1;
    }
    if args.len() != 2 {
        eprintln!(
            "usage: krb5-kdb load <dump>\n       krb5-kdb dump <dump> [--from-dump <mit-dump>]\n       krb5-kdb create <realm>"
        );
        std::process::exit(2);
    }
    let cmd = args[0].as_str();
    let path = PathBuf::from(&args[1]);
    let password = std::env::var("KRB5_MASTER_PASSWORD").unwrap_or_else(|_| {
        eprintln!("krb5-kdb: set KRB5_MASTER_PASSWORD");
        std::process::exit(2);
    });
    let etype = master_etype();

    match cmd {
        "load" => cmd_load(&path, password.as_bytes(), etype),
        "dump" => cmd_dump(&path, from_dump.as_deref(), password.as_bytes(), etype),
        "create" => cmd_create(&args[1]),
        other => {
            eprintln!("krb5-kdb: unknown command {other}");
            std::process::exit(2);
        }
    }
}

fn cmd_load(path: &std::path::Path, password: &[u8], etype: EncryptionType) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: read {}: {e}", path.display());
        std::process::exit(1);
    });
    let dump = parse_dump(&text).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: parse: {e}");
        std::process::exit(1);
    });
    let version = dump.version;
    let nprinc = dump.princs.len();
    let realm = dump
        .realm()
        .unwrap_or_else(|e| {
            eprintln!("krb5-kdb: {e}");
            std::process::exit(1);
        })
        .to_owned();
    let store = load_dump_etype(&text, password, etype).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: load: {e}");
        std::process::exit(1);
    });
    let (db, stash) = db_and_stash();
    save_store(&store, &db, &stash).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: save store: {e}");
        std::process::exit(1);
    });
    println!("ok load version={version} principals={nprinc} realm={realm}");
}

fn cmd_dump(
    path: &std::path::Path,
    from_dump: Option<&str>,
    password: &[u8],
    etype: EncryptionType,
) {
    let store = if let Some(src) = from_dump {
        let text = std::fs::read_to_string(src).unwrap_or_else(|e| {
            eprintln!("krb5-kdb: read {src}: {e}");
            std::process::exit(1);
        });
        load_dump_etype(&text, password, etype).unwrap_or_else(|e| {
            eprintln!("krb5-kdb: load {src}: {e}");
            std::process::exit(1);
        })
    } else {
        let (db, stash) = db_and_stash();
        load_store(&db, &stash).unwrap_or_else(|e| {
            eprintln!("krb5-kdb: load store: {e}");
            std::process::exit(1);
        })
    };
    write_dump_path_etype(&store, path, password, etype).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: dump: {e}");
        std::process::exit(1);
    });
    let written = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: re-read dump: {e}");
        std::process::exit(1);
    });
    let nprinc = written.lines().filter(|l| l.starts_with("princ\t")).count();
    let header_ok =
        written.starts_with(&format!("kdb5_util load_dump version {KDB_DUMP_VERSION}\n"));
    if !header_ok {
        eprintln!("krb5-kdb: dump header was not version {KDB_DUMP_VERSION}");
        std::process::exit(1);
    }
    println!("ok dump version={KDB_DUMP_VERSION} principals={nprinc}");
}

fn cmd_create(realm: &str) {
    if realm.is_empty() {
        eprintln!("krb5-kdb: empty realm");
        std::process::exit(2);
    }
    let user_pw = std::env::var("KRB5_TEST_USER_PASSWORD").unwrap_or_else(|_| {
        eprintln!("krb5-kdb: create requires KRB5_TEST_USER_PASSWORD");
        std::process::exit(2);
    });
    let admin_pw = std::env::var("KRB5_TEST_ADMIN_PASSWORD").unwrap_or_else(|_| {
        eprintln!("krb5-kdb: create requires KRB5_TEST_ADMIN_PASSWORD");
        std::process::exit(2);
    });
    let (store, _) = bootstrap_realm(
        realm,
        TEST_USER,
        user_pw.as_bytes(),
        TEST_ADMIN,
        admin_pw.as_bytes(),
    )
    .unwrap_or_else(|e| {
        eprintln!("krb5-kdb: bootstrap: {e}");
        std::process::exit(1);
    });
    let (db, stash) = db_and_stash();
    save_store(&store, &db, &stash).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: save store: {e}");
        std::process::exit(1);
    });
    let written = std::fs::read_to_string(&db).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: re-read db: {e}");
        std::process::exit(1);
    });
    if !written.starts_with(&format!("kdb5_util load_dump version {KDB_DUMP_VERSION}\n")) {
        eprintln!("krb5-kdb: create header was not version {KDB_DUMP_VERSION}");
        std::process::exit(1);
    }
    let krbtgt = format!("krbtgt/{realm}@{realm}");
    if !written.contains(&krbtgt) {
        eprintln!("krb5-kdb: create missing {krbtgt}");
        std::process::exit(1);
    }
    let nprinc = written.lines().filter(|l| l.starts_with("princ\t")).count();
    println!("ok create version={KDB_DUMP_VERSION} realm={realm} principals={nprinc}");
}

fn db_and_stash() -> (PathBuf, PathBuf) {
    let db = std::env::var("KRB5_KDC_DB").unwrap_or_else(|_| {
        eprintln!("krb5-kdb: set KRB5_KDC_DB");
        std::process::exit(2);
    });
    let stash = std::env::var("KRB5_KDC_STASH").unwrap_or_else(|_| {
        eprintln!("krb5-kdb: set KRB5_KDC_STASH");
        std::process::exit(2);
    });
    (PathBuf::from(db), PathBuf::from(stash))
}

fn master_etype() -> EncryptionType {
    let raw = std::env::var("KRB5_MASTER_ETYPE").ok().or_else(|| {
        krb5_config::env_kdc_config()
            .and_then(|p| krb5_config::KdcConf::load_file(p).ok())
            .and_then(|c| c.master_key_type)
    });
    match raw {
        None => EncryptionType::Aes256CtsHmacSha384192,
        Some(s) => EncryptionType::from_mit_name(&s).unwrap_or_else(|e| {
            eprintln!("krb5-kdb: master etype {s}: {e}");
            std::process::exit(2);
        }),
    }
}
