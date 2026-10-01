//! MIT `kdb5_util` dump/load CLI.
//!
//! Usage:
//!   `krb5-kdb load <dump>` — MIT dump → the database and stash
//!   `krb5-kdb dump <dump>` — store → MIT dump (version 7)
//!   `krb5-kdb dump <dump> --from-dump <other>` — transcode a MIT dump
//!   `krb5-kdb create <realm>` — bootstrap + dump-v7 persist
//!   `krb5-kdb addpol <name>` — named policy + bind `user` if present
//!   `krb5-kdb setstr <princ> <key> <value>` — string attr (`KRB5_TL_STRING_ATTRS`)
//!
//! The database, stash and master key type are kdc.conf's for the realm
//! ([`krb5_config::KdcPaths`]): `KRB5_KDC_DB` / `KRB5_KDC_STASH` /
//! `KRB5_MASTER_ETYPE` override `database_name` / `key_stash_file` /
//! `master_key_type`, and MIT's defaults under `KDC_DIR` apply when neither is set
//! (master key type default `aes256-cts-hmac-sha384-192`).
//! Master password: `KRB5_MASTER_PASSWORD`.
//! Create passwords: `KRB5_TEST_USER_PASSWORD` / `KRB5_TEST_ADMIN_PASSWORD`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use krb5_config::KdcPaths;
use krb5_crypto::EncryptionType;
use krb5_kdc::testrealm::{TEST_ADMIN, TEST_USER};
use krb5_kdc::{
    KDB_DUMP_VERSION, NamedPolicy, bootstrap_realm_with_kdc_conf, load_dump_etype, load_store,
    parse_dump, save_store, write_dump_path_etype,
};

use krb5_types::PrincipalName;

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
    let cmd = args.first().map_or("", String::as_str);
    if cmd == "setstr" {
        if args.len() != 4 {
            usage();
        }
        cmd_setstr(&args[1], &args[2], &args[3]);
        return;
    }
    if cmd == "alias" {
        if args.len() != 3 {
            usage();
        }
        cmd_alias(&args[1], &args[2]);
        return;
    }
    if cmd == "stash" {
        cmd_stash();
        return;
    }
    if cmd == "setlastpwd" {
        if args.len() != 3 {
            usage();
        }
        cmd_setlastpwd(&args[1], &args[2]);
        return;
    }
    if args.len() != 2 {
        usage();
    }
    let path = PathBuf::from(&args[1]);
    let password = std::env::var("KRB5_MASTER_PASSWORD").unwrap_or_else(|_| {
        eprintln!("krb5-kdb: set KRB5_MASTER_PASSWORD");
        std::process::exit(2);
    });
    let paths = kdc_paths((cmd == "create").then_some(args[1].as_str()));
    let etype = master_etype(&paths);

    match cmd {
        "load" => cmd_load(&paths, &path, password.as_bytes(), etype),
        "dump" => cmd_dump(
            &paths,
            &path,
            from_dump.as_deref(),
            password.as_bytes(),
            etype,
        ),
        "create" => cmd_create(&paths, &args[1]),
        "addpol" => cmd_addpol(&paths, &args[1]),
        other => {
            eprintln!("krb5-kdb: unknown command {other}");
            std::process::exit(2);
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: krb5-kdb load <dump>\n       krb5-kdb dump <dump> [--from-dump <mit-dump>]\n       krb5-kdb create <realm>\n       krb5-kdb addpol <name>\n       krb5-kdb setstr <princ> <key> <value>\n       krb5-kdb alias <alias> <target>\n       krb5-kdb stash\n       krb5-kdb setlastpwd <princ> <unix-seconds>"
    );
    std::process::exit(2);
}

fn cmd_load(paths: &KdcPaths, path: &std::path::Path, password: &[u8], etype: EncryptionType) {
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
    save_store(&store, &paths.database_name, &paths.key_stash_file).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: save store: {e}");
        std::process::exit(1);
    });
    println!("ok load version={version} principals={nprinc} realm={realm}");
}

fn cmd_dump(
    paths: &KdcPaths,
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
        load_store(&paths.database_name, &paths.key_stash_file).unwrap_or_else(|e| {
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

fn cmd_create(paths: &KdcPaths, realm: &str) {
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
    let (store, _) = bootstrap_realm_with_kdc_conf(
        realm,
        TEST_USER,
        user_pw.as_bytes(),
        TEST_ADMIN,
        admin_pw.as_bytes(),
        paths.conf.as_ref(),
    )
    .unwrap_or_else(|e| {
        eprintln!("krb5-kdb: bootstrap: {e}");
        std::process::exit(1);
    });
    let db = &paths.database_name;
    save_store(&store, db, &paths.key_stash_file).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: save store: {e}");
        std::process::exit(1);
    });
    let written = std::fs::read_to_string(db).unwrap_or_else(|e| {
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

fn cmd_addpol(paths: &KdcPaths, name: &str) {
    if name.is_empty() {
        eprintln!("krb5-kdb: empty policy name");
        std::process::exit(2);
    }
    let (db, stash) = (&paths.database_name, &paths.key_stash_file);
    let mut store = load_store(db, stash).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: load store: {e}");
        std::process::exit(1);
    });
    store.put_policy(NamedPolicy {
        name: name.to_owned(),
        min_length: 8,
        min_classes: 2,
        history: 1,
        max_fail: 1,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
        pw_min_life: 0,
        pw_max_life: 0,
        allowed_keysalts: None,
    });
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    if store.get_name(&user).is_some() {
        store
            .set_principal_policy(&user, Some(name.to_owned()))
            .unwrap_or_else(|e| {
                eprintln!("krb5-kdb: bind policy: {e}");
                std::process::exit(1);
            });
    }
    save_store(&store, db, stash).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: save store: {e}");
        std::process::exit(1);
    });
    println!("ok addpol name={name}");
}

fn cmd_setstr(princ: &str, key: &str, value: &str) {
    if key.is_empty() {
        eprintln!("krb5-kdb: empty setstr key");
        std::process::exit(2);
    }
    let paths = kdc_paths(None);
    let (db, stash) = (&paths.database_name, &paths.key_stash_file);
    let mut store = load_store(db, stash).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: load store: {e}");
        std::process::exit(1);
    });
    let name = match krb5_types::principal_from_unparsed(princ, "") {
        Ok((n, _)) => n,
        Err(e) => {
            eprintln!("krb5-kdb: {e}");
            std::process::exit(2);
        }
    };
    store
        .set_string(&name, key, Some(value))
        .unwrap_or_else(|e| {
            eprintln!("krb5-kdb: setstr: {e}");
            std::process::exit(1);
        });
    save_store(&store, db, stash).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: save store: {e}");
        std::process::exit(1);
    });
    println!("ok setstr {princ} {key}");
}

fn cmd_stash() {
    // krb5_util stash: read the master key (existing stash or KRB5_MASTER_PASSWORD)
    // and (re)write the stash in keytab format via save_store.
    let paths = kdc_paths(None);
    let (db, stash) = (&paths.database_name, &paths.key_stash_file);
    let store = load_store(db, stash).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: load store: {e}");
        std::process::exit(1);
    });
    save_store(&store, db, stash).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: stash: {e}");
        std::process::exit(1);
    });
    println!("ok stash realm={}", store.realm());
}

fn cmd_alias(alias: &str, target: &str) {
    let paths = kdc_paths(None);
    let (db, stash) = (&paths.database_name, &paths.key_stash_file);
    let mut store = load_store(db, stash).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: load store: {e}");
        std::process::exit(1);
    });
    let realm = store.realm().to_owned();
    let parse = |s: &str| {
        krb5_types::principal_from_unparsed(s, &realm).unwrap_or_else(|e| {
            eprintln!("krb5-kdb: {e}");
            std::process::exit(2);
        })
    };
    let (a, a_realm) = parse(alias);
    let (t, t_realm) = parse(target);
    store
        .create_alias_in(&a, &a_realm, &t, &t_realm, &format!("kadmin/admin@{realm}"))
        .unwrap_or_else(|e| {
            eprintln!("krb5-kdb: alias: {e}");
            std::process::exit(1);
        });
    save_store(&store, db, stash).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: save store: {e}");
        std::process::exit(1);
    });
    println!("ok alias {alias} {target}");
}

fn cmd_setlastpwd(princ: &str, secs: &str) {
    let ts: u32 = secs.parse().unwrap_or_else(|_| {
        eprintln!("krb5-kdb: setlastpwd wants unix seconds");
        std::process::exit(2);
    });
    let paths = kdc_paths(None);
    let (db, stash) = (&paths.database_name, &paths.key_stash_file);
    let mut store = load_store(db, stash).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: load store: {e}");
        std::process::exit(1);
    });
    let name = match krb5_types::principal_from_unparsed(princ, "") {
        Ok((n, _)) => n,
        Err(e) => {
            eprintln!("krb5-kdb: {e}");
            std::process::exit(2);
        }
    };
    store.set_last_pwd_unix(&name, ts);
    save_store(&store, db, stash).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: save store: {e}");
        std::process::exit(1);
    });
    println!("ok setlastpwd {princ} {ts}");
}

/// The database, stash and master key type, as every KDC-side tool resolves them.
/// MIT `main` (`kdb5_util.c:304-312`): no realm is "… while getting default realm", exit 1.
fn kdc_paths(realm: Option<&str>) -> KdcPaths {
    KdcPaths::resolve(realm).unwrap_or_else(|e| {
        let context = match e {
            krb5_config::Error::NoDefaultRealm => " while getting default realm",
            _ => "",
        };
        eprintln!("krb5-kdb: {e}{context}");
        std::process::exit(1);
    })
}

fn master_etype(paths: &KdcPaths) -> EncryptionType {
    krb5_kdc::master_etype(paths.master_key_type.as_deref()).unwrap_or_else(|e| {
        eprintln!("krb5-kdb: master etype {e}");
        std::process::exit(2);
    })
}
