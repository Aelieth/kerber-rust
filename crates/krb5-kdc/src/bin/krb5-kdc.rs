//! Launch the KDC.
//!
//! Usage: `krb5-kdc [--test-realm] [host:port]`
//!
//! With no `host:port` (and no `KRB5_KDC_BIND`) the KDC listens on kdc.conf's
//! `kdc_listen` / `kdc_ports` and `kdc_tcp_listen` / `kdc_tcp_ports` like MIT's
//! (default port 88 on all local addresses); `--test-realm` alone keeps the
//! loopback candidates.
//!
//! `--test-realm` bootstraps the documented KERBER.TEST principals. Without
//! it the daemon loads `KRB5_KDC_DB`/`KRB5_KDC_STASH` or `database_name` /
//! `key_stash_file` from `kdc.conf`. Ticket policy comes from
//! `KRB5_KDC_PROFILE` / `KRB5_KDC_CONF` / `/etc/krb5kdc/kdc.conf`.
//! Passwords come from `KRB5_TEST_USER_PASSWORD` / `KRB5_TEST_ADMIN_PASSWORD`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;

use krb5_kdc::principals::{kadmin_admin, kadmin_changepw};
use krb5_kdc::testrealm::{TEST_ADMIN, TEST_REALM, TEST_USER, documented_kiprop};
use krb5_kdc::{
    Acl, BIND_CANDIDATES, KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_SVR,
    KDB_OK_TO_AUTH_AS_DELEGATE, PrincipalStore, apply_kadm5_create_service_attrs, bind_preferred,
    bind_tcp_listeners, bind_udp_listeners, drop_privileges, open_store, serve_all, shared_store,
};

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "krb5_kdc=info,krb5_crypto=info,krb5_asn1=info".into()),
        )
        .try_init();

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let test_realm = args.iter().any(|a| a == "--test-realm");
    args.retain(|a| a != "--test-realm");
    let mut export_pkinit: Option<String> = None;
    let mut export_keytab: Option<String> = None;
    let mut export_krbtgt: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--export-pkinit" {
            export_pkinit = args.get(i + 1).cloned();
            args.remove(i);
            if i < args.len() {
                args.remove(i);
            }
            continue;
        }
        if args[i] == "--export-keytab" {
            export_keytab = args.get(i + 1).cloned();
            args.remove(i);
            if i < args.len() {
                args.remove(i);
            }
            continue;
        }
        if args[i] == "--export-krbtgt-keytab" {
            export_krbtgt = args.get(i + 1).cloned();
            args.remove(i);
            if i < args.len() {
                args.remove(i);
            }
            continue;
        }
        i += 1;
    }
    if export_keytab.is_none() {
        export_keytab = std::env::var("KRB5_EXPORT_KEYTAB").ok();
    }
    if export_krbtgt.is_none() {
        export_krbtgt = std::env::var("KRB5_EXPORT_KRBTGT_KEYTAB").ok();
    }

    let kdc_conf = load_kdc_conf();
    let mut store = if test_realm {
        bootstrap_test_realm(kdc_conf.as_ref())
    } else {
        let (db, stash) = db_and_stash(kdc_conf.as_ref());
        if let (Some(db), Some(stash)) = (db, stash) {
            let lib = kdc_conf.as_ref().and_then(|c| c.db_library.as_deref());
            open_store(lib, &db, &stash).unwrap_or_else(|e| {
                eprintln!("krb5-kdc: load store: {e}");
                std::process::exit(1);
            })
        } else {
            eprintln!(
                "krb5-kdc: pass --test-realm or set KRB5_KDC_DB and KRB5_KDC_STASH (or database_name / key_stash_file in kdc.conf)"
            );
            std::process::exit(2);
        }
    };
    if test_realm
        && let (Ok(db), Ok(stash)) = (
            std::env::var("KRB5_KDC_DB"),
            std::env::var("KRB5_KDC_STASH"),
        )
    {
        let db = std::path::PathBuf::from(db);
        let stash = std::path::PathBuf::from(stash);
        if let Err(e) = krb5_kdc::save_store(&store, &db, &stash) {
            eprintln!("krb5-kdc: save store: {e}");
            std::process::exit(1);
        }
        store = krb5_kdc::load_store(&db, &stash).unwrap_or_else(|e| {
            eprintln!("krb5-kdc: reload store: {e}");
            std::process::exit(1);
        });
    }
    // MIT builds the KDC profile with kdc.conf before krb5.conf, so kdc.conf
    // wins (`init_os_ctx.c add_kdc_config_file`). Apply krb5.conf [libdefaults]
    // first as the base, then let kdc.conf override.
    if let Some(c) = krb5_config::load_krb5_conf() {
        store.set_capaths(c.capaths.clone());
        store.apply_libdefaults(&c);
    }
    if let Some(conf) = &kdc_conf
        && let Err(e) = store.apply_kdc_conf(conf)
    {
        eprintln!("krb5-kdc: kdc.conf: {e}");
        std::process::exit(2);
    }
    if std::env::var("KRB5_KDCPOLICY").ok().as_deref() == Some("test") {
        krb5_kdc::set_policy(std::sync::Arc::new(krb5_kdc::testrealm::TestPolicy));
    }
    if std::env::var("KRB5_KDC_AUDIT").ok().as_deref() == Some("test") {
        let path = std::env::var("KRB5_KDC_AUDIT_LOG").unwrap_or_else(|_| "au.log".into());
        match krb5_kdc::testrealm::TestAudit::open(&path) {
            Ok(a) => krb5_kdc::set_audit(std::sync::Arc::new(a)),
            Err(e) => {
                eprintln!("krb5-kdc: KRB5_KDC_AUDIT_LOG {path}: {e}");
                std::process::exit(1);
            }
        }
    }
    krb5_kdc::current_audit().kdc_start(true);
    let enable_pkinit =
        export_pkinit.is_some() || std::env::var("KRB5_ENABLE_PKINIT").ok().as_deref() == Some("1");
    if enable_pkinit && let Err(e) = store.enable_pkinit_ca() {
        eprintln!("krb5-kdc: PKINIT CA: {e}");
        std::process::exit(1);
    }
    if let Some(path) = export_keytab.as_ref() {
        let host_inst = std::env::var("KRB5_TEST_HOST").unwrap_or_else(|_| {
            if store.realm() == TEST_REALM {
                krb5_kdc::testrealm::TEST_HOST.to_owned()
            } else {
                "svc.other.test".into()
            }
        });
        let host = krb5_types::PrincipalName::new(
            krb5_types::PrincipalName::NT_SRV_HST,
            ["host", host_inst.as_str()],
        );
        match store.export_keytab_local(&host) {
            Ok(kt) => {
                if let Err(e) = kt.write_file(path) {
                    eprintln!("krb5-kdc: export-keytab {path}: {e}");
                    std::process::exit(1);
                }
                println!("keytab {path}");
            }
            Err(e) => {
                eprintln!("krb5-kdc: export-keytab: {e}");
                std::process::exit(1);
            }
        }
    }
    if let (Ok(path), Ok(extra_inst)) = (
        std::env::var("KRB5_EXPORT_KEYTAB_EXTRA"),
        std::env::var("KRB5_TEST_EXTRA_HOST"),
    ) {
        let extra = krb5_types::PrincipalName::new(
            krb5_types::PrincipalName::NT_SRV_HST,
            ["host", extra_inst.as_str()],
        );
        match store.export_keytab_local(&extra) {
            Ok(kt) => {
                if let Err(e) = kt.write_file(&path) {
                    eprintln!("krb5-kdc: export-keytab-extra {path}: {e}");
                    std::process::exit(1);
                }
                println!("keytab-extra {path}");
            }
            Err(e) => {
                eprintln!("krb5-kdc: export-keytab-extra: {e}");
                std::process::exit(1);
            }
        }
    }
    if let Some(path) = export_krbtgt.as_ref() {
        let tgt = krb5_types::PrincipalName::krbtgt(store.realm());
        match store.export_keytab_local(&tgt) {
            Ok(kt) => {
                if let Err(e) = kt.write_file(path) {
                    eprintln!("krb5-kdc: export-krbtgt-keytab {path}: {e}");
                    std::process::exit(1);
                }
                println!("krbtgt-keytab {path}");
            }
            Err(e) => {
                eprintln!("krb5-kdc: export-krbtgt-keytab: {e}");
                std::process::exit(1);
            }
        }
    }
    if let Some(dir) = export_pkinit.as_ref() {
        let _ = std::fs::create_dir_all(dir);
        if let Some(pem) = store.pkinit_anchor_pem() {
            let _ = std::fs::write(format!("{dir}/ca.pem"), pem);
            println!("pkinit-ca {dir}/ca.pem");
        }
        if let Some(pem) = store.pkinit_user_pem("user@KERBER.TEST") {
            let _ = std::fs::write(format!("{dir}/user.pem"), pem);
            println!("pkinit-user {dir}/user.pem");
        }
        if let Some(pem) = store.pkinit_user_pem("other@KERBER.TEST") {
            let _ = std::fs::write(format!("{dir}/other.pem"), pem);
            println!("pkinit-other {dir}/other.pem");
        }
        if let Some(pem) = store.pkinit_kdc_pem() {
            let _ = std::fs::write(format!("{dir}/kdc.pem"), pem);
            println!("pkinit-kdc {dir}/kdc.pem");
        }
        if let Some(pem) = store
            .pkinit_ca()
            .and_then(|c| c.kdc_identity_pem_for("OTHER.TEST"))
        {
            let _ = std::fs::write(format!("{dir}/kdc-wrong-realm.pem"), pem);
            println!("pkinit-kdc-wrong-realm {dir}/kdc-wrong-realm.pem");
        }
    }
    let persist = store.persist_paths.clone();
    match &persist {
        Some((db, stash)) => println!("persist {} {}", db.display(), stash.display()),
        None => println!("persist none"),
    }
    let env_lib = std::env::var("KRB5_KDC_DB_LIBRARY").ok();
    let lib = env_lib
        .as_deref()
        .or_else(|| kdc_conf.as_ref().and_then(|c| c.db_library.as_deref()));
    let store = if lib == Some("memory") {
        println!("backend memory");
        shared_store(krb5_kdc::MemoryStore::from_dump(&store))
    } else {
        println!("backend dump");
        shared_store(store)
    };

    let pinned: Option<String> = args
        .into_iter()
        .next()
        .or_else(|| std::env::var("KRB5_KDC_BIND").ok());
    let (udp, tcp) = bind_sockets(test_realm, pinned, kdc_conf.as_ref());
    // Kadmind writes the db as the kadmind uid (root in the gate). Dropping
    // to nobody would make 0600 persist files unreadable on reload.
    if persist.is_none() {
        match drop_privileges() {
            Ok(true) => eprintln!("krb5-kdc: dropped privileges"),
            Ok(false) => {}
            Err(e) => {
                eprintln!("krb5-kdc: privilege drop: {e}");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("krb5-kdc: privilege drop skipped (shared persist db)");
    }
    if std::env::var("KERBER_KDC_GREET").ok().as_deref() == Some("1") {
        krb5_kdc::register_authdata(std::sync::Arc::new(krb5_kdc::testrealm::GreetAuth));
    }
    // One `listening` line per UDP address (the gates' readiness probe), plus a
    // `listening tcp` line for a TCP address that is not also a UDP one.
    let udp_addrs: Vec<_> = udp.iter().filter_map(|u| u.local_addr().ok()).collect();
    for a in &udp_addrs {
        println!("listening {a}");
    }
    for a in tcp.iter().filter_map(|t| t.local_addr().ok()) {
        if !udp_addrs.contains(&a) {
            println!("listening tcp {a}");
        }
    }
    if let Err(e) = serve_all(store, udp, tcp) {
        krb5_kdc::current_audit().kdc_stop(false);
        eprintln!("krb5-kdc: serve: {e}");
        std::process::exit(1);
    }
    krb5_kdc::current_audit().kdc_stop(true);
}

fn load_kdc_conf() -> Option<krb5_config::KdcConf> {
    let path = krb5_config::kdc_conf_path()?;
    match krb5_config::KdcConf::load_file(&path) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("krb5-kdc: kdc.conf: {e}");
            std::process::exit(1);
        }
    }
}

fn db_and_stash(conf: Option<&krb5_config::KdcConf>) -> (Option<PathBuf>, Option<PathBuf>) {
    let db = std::env::var("KRB5_KDC_DB")
        .ok()
        .map(PathBuf::from)
        .or_else(|| conf.and_then(|c| c.database_name.clone()));
    let stash = std::env::var("KRB5_KDC_STASH")
        .ok()
        .map(PathBuf::from)
        .or_else(|| conf.and_then(|c| c.key_stash_file.clone()));
    (db, stash)
}

/// The listening sockets. An address on the command line or in `KRB5_KDC_BIND`, or
/// `--test-realm`, binds one UDP + TCP pair on the first of the pinned address /
/// [`BIND_CANDIDATES`] that binds (the gates' path). Otherwise the KDC listens where MIT's
/// would: every `kdc_listen` / `kdc_ports` entry for UDP and every `kdc_tcp_listen` /
/// `kdc_tcp_ports` entry (else the UDP list) for TCP, a bare port on all local addresses,
/// port 88 when kdc.conf names none.
/// MIT `main` (`kdc/main.c:960-973`): UDP and TCP listeners for each realm's lists.
fn bind_sockets(
    test_realm: bool,
    pinned: Option<String>,
    conf: Option<&krb5_config::KdcConf>,
) -> (Vec<UdpSocket>, Vec<TcpListener>) {
    if pinned.is_some() || test_realm {
        let owned: Vec<String> = pinned.map_or_else(
            || BIND_CANDIDATES.iter().map(|s| (*s).to_owned()).collect(),
            |b| vec![b],
        );
        let candidates: Vec<&str> = owned.iter().map(String::as_str).collect();
        let (_, udp, tcp) = bind_preferred(&candidates).unwrap_or_else(|e| {
            eprintln!("krb5-kdc: bind failed: {e}");
            std::process::exit(1);
        });
        return (vec![udp], vec![tcp]);
    }
    let default_conf = krb5_config::KdcConf::default();
    let conf = conf.unwrap_or(&default_conf);
    let lists = conf
        .kdc_udp_listeners()
        .and_then(|u| conf.kdc_tcp_listeners().map(|t| (u, t)));
    let (udp_addrs, tcp_addrs) = lists.unwrap_or_else(|e| {
        eprintln!("krb5-kdc: kdc.conf: {e}");
        std::process::exit(1);
    });
    let udp = bind_udp_listeners(&udp_addrs).unwrap_or_else(|e| {
        eprintln!("krb5-kdc: bind failed: {e}");
        std::process::exit(1);
    });
    let tcp = bind_tcp_listeners(&tcp_addrs).unwrap_or_else(|e| {
        eprintln!("krb5-kdc: bind failed: {e}");
        std::process::exit(1);
    });
    (udp, tcp)
}

fn bootstrap_test_realm(kdc: Option<&krb5_config::KdcConf>) -> PrincipalStore {
    let user_pw = std::env::var("KRB5_TEST_USER_PASSWORD").unwrap_or_else(|_| {
        eprintln!(
            "krb5-kdc: --test-realm requires KRB5_TEST_USER_PASSWORD (do not compile passwords in)"
        );
        std::process::exit(2);
    });
    let admin_pw = std::env::var("KRB5_TEST_ADMIN_PASSWORD").unwrap_or_else(|_| {
        eprintln!("krb5-kdc: --test-realm requires KRB5_TEST_ADMIN_PASSWORD");
        std::process::exit(2);
    });
    let realm = std::env::var("KRB5_TEST_REALM").unwrap_or_else(|_| TEST_REALM.to_owned());
    let mut store = PrincipalStore::bootstrap_with_kdc_conf(
        &realm,
        TEST_USER,
        user_pw.as_bytes(),
        TEST_ADMIN,
        admin_pw.as_bytes(),
        kdc,
    )
    .unwrap_or_else(|e| {
        eprintln!("krb5-kdc: bootstrap: {e}");
        std::process::exit(1);
    });
    let actor = format!("{TEST_ADMIN}@{realm}");
    let acl = Acl::allow_admin(&actor).unwrap_or_else(|e| {
        eprintln!("krb5-kdc: acl: {e}");
        std::process::exit(1);
    });
    let host_inst = std::env::var("KRB5_TEST_HOST").unwrap_or_else(|_| {
        if realm == TEST_REALM {
            krb5_kdc::testrealm::TEST_HOST.to_owned()
        } else {
            "svc.other.test".into()
        }
    });
    let host = krb5_types::PrincipalName::new(
        krb5_types::PrincipalName::NT_SRV_HST,
        ["host", host_inst.as_str()],
    );
    if let Err(e) = store.create_host(&acl, &actor, &host) {
        eprintln!("krb5-kdc: host principal: {e}");
        std::process::exit(1);
    }
    if std::env::var("KRB5_TEST_OK_TO_AUTH_AS_DELEGATE").as_deref() == Ok("1") {
        let a = if let Some(p) = store.get_name(&host) {
            p.attributes | KDB_OK_TO_AUTH_AS_DELEGATE
        } else {
            eprintln!("krb5-kdc: host missing after create");
            std::process::exit(1);
        };
        if let Err(e) = store.apply_admin_fields(
            &host,
            krb5_kdc::AdminFields {
                attributes: Some(a),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        ) {
            eprintln!("krb5-kdc: ok_to_auth_as_delegate: {e}");
            std::process::exit(1);
        }
    }
    if let Ok(targets) = std::env::var("KRB5_TEST_S4U_TO") {
        for to in targets.split(',') {
            let to = to.trim();
            if !to.is_empty() {
                store.allow_s4u_to(&host, to);
            }
        }
    }
    if let Ok(froms) = std::env::var("KRB5_TEST_S4U_FROM") {
        for from in froms.split(',') {
            let from = from.trim();
            if !from.is_empty() {
                store.allow_s4u_from(&host, from);
            }
        }
    }
    if let Ok(extra_inst) = std::env::var("KRB5_TEST_EXTRA_HOST") {
        let extra = krb5_types::PrincipalName::new(
            krb5_types::PrincipalName::NT_SRV_HST,
            ["host", extra_inst.as_str()],
        );
        if let Err(e) = store.create_host(&acl, &actor, &extra) {
            eprintln!("krb5-kdc: extra host principal: {e}");
            std::process::exit(1);
        }
        if let Ok(froms) = std::env::var("KRB5_TEST_S4U_FROM") {
            for from in froms.split(',') {
                let from = from.trim();
                if !from.is_empty() {
                    store.allow_s4u_from(&extra, from);
                }
            }
        }
    }
    if std::env::var("KRB5_TEST_DISALLOW_DUP_SKEY").as_deref() == Ok("1") {
        let a = if let Some(p) = store.get_name(&host) {
            p.attributes | KDB_DISALLOW_DUP_SKEY
        } else {
            eprintln!("krb5-kdc: host missing after create");
            std::process::exit(1);
        };
        if let Err(e) = store.apply_admin_fields(
            &host,
            krb5_kdc::AdminFields {
                attributes: Some(a),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        ) {
            eprintln!("krb5-kdc: disallow_dup_skey: {e}");
            std::process::exit(1);
        }
    }
    if let Err(e) = store.create_host(&acl, &actor, &kadmin_admin()) {
        eprintln!("krb5-kdc: kadmin/admin: {e}");
        std::process::exit(1);
    }
    if let Err(e) = store.create_host(&acl, &actor, &kadmin_changepw()) {
        eprintln!("krb5-kdc: kadmin/changepw: {e}");
        std::process::exit(1);
    }
    if let Err(e) = store.create_host(&acl, &actor, &documented_kiprop()) {
        eprintln!("krb5-kdc: kiprop: {e}");
        std::process::exit(1);
    }
    if let Err(e) = apply_kadm5_create_service_attrs(&mut store) {
        eprintln!("krb5-kdc: kadmin service attrs: {e}");
        std::process::exit(1);
    }
    if let (Ok(foreigns), Ok(hexkey)) = (
        std::env::var("KRB5_TEST_FOREIGN_REALM"),
        std::env::var("KRB5_TEST_INTERREALM_KEY"),
    ) {
        match parse_hex_key(&hexkey) {
            Ok(key) => {
                for foreign in foreigns.split(',') {
                    let foreign = foreign.trim();
                    if foreign.is_empty() {
                        continue;
                    }
                    if let Err(e) = store.create_interrealm_key(&acl, &actor, foreign, key.clone())
                    {
                        eprintln!("krb5-kdc: inter-realm {foreign}: {e}");
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("krb5-kdc: KRB5_TEST_INTERREALM_KEY: {e}");
                std::process::exit(2);
            }
        }
        // Peer-issued tickets (AD outbound) may use a second AES key
        // (Windows TDO inbound/outbound salts differ).
        if let Ok(hex2) = std::env::var("KRB5_TEST_INTERREALM_KEY_ACCEPT") {
            let mut first = true;
            for part in hex2.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                match parse_hex_key(part) {
                    Ok(key) => {
                        for foreign in foreigns.split(',') {
                            let foreign = foreign.trim();
                            if foreign.is_empty() {
                                continue;
                            }
                            let put = if first {
                                store.set_interrealm_decrypt_key(&acl, &actor, foreign, key.clone())
                            } else {
                                store.add_interrealm_decrypt_key(&acl, &actor, foreign, key.clone())
                            };
                            if let Err(e) = put {
                                eprintln!("krb5-kdc: inter-realm accept key {foreign}: {e}");
                                std::process::exit(1);
                            }
                        }
                        first = false;
                    }
                    Err(e) => {
                        eprintln!("krb5-kdc: KRB5_TEST_INTERREALM_KEY_ACCEPT: {e}");
                        std::process::exit(2);
                    }
                }
            }
        }
    }
    apply_test_disallow(&mut store, "KRB5_TEST_DISALLOW_TIX", KDB_DISALLOW_ALL_TIX);
    apply_test_disallow(&mut store, "KRB5_TEST_DISALLOW_SVR", KDB_DISALLOW_SVR);
    if let Ok(pw) = std::env::var("KRB5_TEST_LOCKED_USER")
        && !pw.is_empty()
    {
        let locked =
            krb5_types::PrincipalName::new(krb5_types::PrincipalName::NT_PRINCIPAL, ["locked"]);
        if let Err(e) = store.create_password(&acl, &actor, &locked, pw.as_bytes()) {
            eprintln!("krb5-kdc: locked user: {e}");
            std::process::exit(1);
        }
        if let Err(e) = store.set_status(&locked, true, 0) {
            eprintln!("krb5-kdc: lock user: {e}");
            std::process::exit(1);
        }
    }
    if let Ok(pw) = std::env::var("KRB5_TEST_PW_EXPIRED_USER")
        && !pw.is_empty()
    {
        let expired =
            krb5_types::PrincipalName::new(krb5_types::PrincipalName::NT_PRINCIPAL, ["expired"]);
        if let Err(e) = store.create_password(&acl, &actor, &expired, pw.as_bytes()) {
            eprintln!("krb5-kdc: expired user: {e}");
            std::process::exit(1);
        }
        if let Err(e) = store.apply_admin_fields(
            &expired,
            krb5_kdc::AdminFields {
                attributes: None,
                max_life: None,
                expiration: None,
                pw_expire: Some(1),
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        ) {
            eprintln!("krb5-kdc: expire user: {e}");
            std::process::exit(1);
        }
    }
    store
}

fn apply_test_disallow(store: &mut PrincipalStore, env: &str, flag: u32) {
    let Ok(spec) = std::env::var(env) else {
        return;
    };
    let spec = spec.trim();
    if spec.is_empty() {
        return;
    }
    let (name_spec, princ_realm) = match spec.rsplit_once('@') {
        Some((n, r)) if !r.is_empty() => (n.trim(), r.to_owned()),
        _ => (spec, store.realm().to_owned()),
    };
    let Some(name) = test_princ(name_spec) else {
        eprintln!("krb5-kdc: {env}: empty principal");
        std::process::exit(2);
    };
    let a = if let Some(p) = store.get_in_realm(&name, &princ_realm) {
        p.attributes | flag
    } else {
        eprintln!("krb5-kdc: {env}: {spec} missing");
        std::process::exit(1);
    };
    if let Err(e) = store.apply_admin_fields_in(
        &name,
        &princ_realm,
        krb5_kdc::AdminFields {
            attributes: Some(a),
            max_life: None,
            expiration: None,
            pw_expire: None,
            policy: None,
            clear_policy: false,
            max_renewable_life: None,
        },
        &format!("kadmin/admin@{princ_realm}"),
    ) {
        eprintln!("krb5-kdc: {env}: {e}");
        std::process::exit(1);
    }
}

fn test_princ(spec: &str) -> Option<krb5_types::PrincipalName> {
    let spec = spec.split('@').next().unwrap_or(spec).trim();
    if spec.is_empty() {
        return None;
    }
    if let Some((a, b)) = spec.split_once('/') {
        Some(krb5_types::PrincipalName::new(
            krb5_types::PrincipalName::NT_SRV_INST,
            [a, b],
        ))
    } else {
        Some(krb5_types::PrincipalName::new(
            krb5_types::PrincipalName::NT_PRINCIPAL,
            [spec],
        ))
    }
}

fn parse_hex_key(hex: &str) -> Result<krb5_crypto::ProtocolKey, String> {
    let h = hex.trim();
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("need 32-byte hex (64 chars)".into());
    }
    let mut bytes = vec![0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    krb5_crypto::ProtocolKey::from_bytes(krb5_crypto::EncryptionType::Aes256CtsHmacSha196, &bytes)
        .map_err(|e| e.to_string())
}
