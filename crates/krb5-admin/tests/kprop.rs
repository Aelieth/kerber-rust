//! Admin whole-flow tests moved from `src/lib.rs`.

#[path = "common/mod.rs"]
mod common;

use krb5_admin::*;
use krb5_kdc::testrealm::bootstrap_documented;

use krb5_protocol::ReplayCache;
use krb5_types::PrincipalName;

#[test]
fn kprop_replica_issues_with_same_krbtgt() {
    let dir = krb5_testkit::scratch_dir("kprop");
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = bootstrap_documented().unwrap();
    let before = store
        .krbtgt()
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .as_bytes()
        .to_vec();
    propagate(&store, &db, &stash).unwrap();
    let replica = receive_propagate(&db, &stash).unwrap();
    let after = replica
        .krbtgt()
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .as_bytes()
        .to_vec();
    assert_eq!(before, after);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let salt = cname.default_salt("KERBER.TEST");
    let key = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"userpassword",
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = krb5_protocol::as_req(
        cname,
        "KERBER.TEST",
        9,
        Some(vec![krb5_protocol::pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&replica, &req).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn kprop_tcp_replica_issues_as_with_shared_stash() {
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use krb5_kdc::testrealm::TEST_REALM;

    use krb5_kdc::testrealm::TEST_USER;

    const MASTER: &[u8] = b"masterpassword";

    let (store, _) = bootstrap_documented().unwrap();
    let before = store
        .krbtgt()
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .as_bytes()
        .to_vec();

    let listener = TcpListener::bind("127.0.0.1:754")
        .or_else(|_| TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let join = thread::spawn(move || {
        krb5_config::isolate_test_krb5();
        let (mut stream, _) = listener.accept().unwrap();
        kprop_recv(&mut stream, MASTER).expect("kprop_recv")
    });
    thread::sleep(Duration::from_millis(20));
    let mut client = TcpStream::connect(addr).unwrap();
    kprop_send(&store, MASTER, &mut client).expect("kprop_send");
    let replica = join.join().expect("thread");
    let after = replica
        .krbtgt()
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .as_bytes()
        .to_vec();
    assert_eq!(
        before, after,
        "replica krbtgt must match the primary (shared stash)"
    );
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(TEST_REALM);
    let key = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"userpassword",
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = krb5_protocol::as_req(
        cname,
        TEST_REALM,
        91,
        Some(vec![krb5_protocol::pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&replica, &req).expect("replica issue_as");
}

#[test]
fn kprop_dump_payload_is_version_7_not_kdb3() {
    const MASTER: &[u8] = b"masterpassword";
    let (store, _) = bootstrap_documented().unwrap();
    let bytes = kprop_dump_bytes(&store, MASTER).unwrap();
    assert!(
        bytes.starts_with(b"kdb5_util load_dump version 7\n"),
        "kprop body must be dump version 7, got {}",
        String::from_utf8_lossy(&bytes[..bytes.len().min(40)])
    );
    assert!(!bytes.starts_with(b"KDB3"));
    let replica = kprop_load_bytes(&bytes, MASTER).unwrap();
    let cname = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    let salt = cname.default_salt(krb5_kdc::testrealm::TEST_REALM);
    let key = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"userpassword",
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = krb5_protocol::as_req(
        cname,
        krb5_kdc::testrealm::TEST_REALM,
        92,
        Some(vec![krb5_protocol::pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&replica, &req).expect("dump-codec replica issue_as");
}

#[test]
fn kprop_truncated_or_kdb3_body_fails() {
    const MASTER: &[u8] = b"masterpassword";
    assert!(kprop_load_bytes(b"KDB3notadump", MASTER).is_err());
    assert!(kprop_load_bytes(b"kdb5_util load_dump version 7\nprinc\t", MASTER).is_err());
    assert!(kprop_load_bytes(b"not a dump", MASTER).is_err());
}

#[test]
fn kprop_mit_wire_sendauth_replica_issues_as() {
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, documented_host};

    use krb5_protocol::{pa_enc_timestamp, tgs_req};

    const MASTER: &[u8] = b"masterpassword";
    let (store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let host_keys: Vec<_> = store
        .get_name(&host)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.key.clone())
        .collect();

    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    let admin_key = store
        .get_name(&admin)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_req = krb5_protocol::as_req(
        admin.clone(),
        TEST_REALM,
        71,
        Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &admin,
        host.clone(),
        TEST_REALM,
        72,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let host_keys2 = host_keys.clone();
    let host_for_server = host.clone();
    let allowed = vec![format!("admin@{TEST_REALM}")];
    let join = thread::spawn(move || {
        krb5_config::isolate_test_krb5();
        let (mut stream, _) = listener.accept().unwrap();
        let dir = krb5_testkit::scratch_dir("kprop-mit");
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("replica");
        let stash = dir.join("stash");
        let store = kpropd_handle_conn(
            &mut stream,
            &KpropdConfig {
                host_keys: &host_keys2,
                keytab: None,
                expected_server: Some(&host_for_server),
                expected_realm: Some(TEST_REALM),
                master_password: Some(MASTER),
                db: &db,
                stash: &stash,
                allowed_clients: Some(allowed.as_slice()),
                iprop: None,
            },
            &ReplayCache::new(),
        )
        .expect("kpropd_handle_conn");
        let _ = std::fs::remove_dir_all(&dir);
        store
    });
    thread::sleep(Duration::from_millis(20));
    let mut client = TcpStream::connect(addr).unwrap();
    kprop_send_store(
        &mut client,
        &store,
        &master_key(TEST_REALM, MASTER),
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &admin,
    )
    .expect("kprop_send_store");
    let replica = join.join().expect("thread");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(TEST_REALM);
    let key = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"userpassword",
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = krb5_protocol::as_req(
        cname,
        TEST_REALM,
        93,
        Some(vec![krb5_protocol::pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&replica, &req).expect("MIT-wire replica issue_as");
}

#[test]
fn kpropd_rejects_client_not_on_allowlist() {
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use krb5_kdc::testrealm::{TEST_REALM, documented_host};

    use krb5_protocol::{pa_enc_timestamp, tgs_req};

    const MASTER: &[u8] = b"masterpassword";
    let (store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let host_keys: Vec<_> = store
        .get_name(&host)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.key.clone())
        .collect();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    let admin_key = store
        .get_name(&admin)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_req = krb5_protocol::as_req(
        admin.clone(),
        TEST_REALM,
        81,
        Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &admin,
        host.clone(),
        TEST_REALM,
        82,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let host_keys2 = host_keys.clone();
    let host_for_server = host.clone();
    let allowed = vec![format!("host/testhost.kerber.test@{TEST_REALM}")];
    let join = thread::spawn(move || {
        krb5_config::isolate_test_krb5();
        let (mut stream, _) = listener.accept().unwrap();
        let dir = krb5_testkit::scratch_dir("kprop-deny");
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("replica");
        let stash = dir.join("stash");
        let err = kpropd_handle_conn(
            &mut stream,
            &KpropdConfig {
                host_keys: &host_keys2,
                keytab: None,
                expected_server: Some(&host_for_server),
                expected_realm: Some(TEST_REALM),
                master_password: Some(MASTER),
                db: &db,
                stash: &stash,
                allowed_clients: Some(allowed.as_slice()),
                iprop: None,
            },
            &ReplayCache::new(),
        )
        .unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        err
    });
    thread::sleep(Duration::from_millis(20));
    let mut client = TcpStream::connect(addr).unwrap();
    let _ = kprop_send_store(
        &mut client,
        &store,
        &master_key(TEST_REALM, MASTER),
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &admin,
    );
    let err = join.join().expect("thread");
    assert_eq!(
        err,
        Error::KpropUnauthorized(format!("admin@{TEST_REALM}")),
        "kpropd.c:540-543 text with the unparsed client"
    );
}

#[test]
fn kpropd_rejects_when_acl_unset() {
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use krb5_kdc::testrealm::{TEST_REALM, documented_host};

    use krb5_protocol::{pa_enc_timestamp, tgs_req};

    const MASTER: &[u8] = b"masterpassword";
    let (store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let host_keys: Vec<_> = store
        .get_name(&host)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.key.clone())
        .collect();
    let host_key = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_req = krb5_protocol::as_req(
        host.clone(),
        TEST_REALM,
        83,
        Some(vec![pa_enc_timestamp(&host_key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        84,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let host_keys2 = host_keys.clone();
    let host_for_server = host.clone();
    let join = thread::spawn(move || {
        krb5_config::isolate_test_krb5();
        let (mut stream, _) = listener.accept().unwrap();
        let dir = krb5_testkit::scratch_dir("kprop-unset");
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("replica");
        let stash = dir.join("stash");
        let err = kpropd_handle_conn(
            &mut stream,
            &KpropdConfig {
                host_keys: &host_keys2,
                keytab: None,
                expected_server: Some(&host_for_server),
                expected_realm: Some(TEST_REALM),
                master_password: Some(MASTER),
                db: &db,
                stash: &stash,
                allowed_clients: None,
                iprop: None,
            },
            &ReplayCache::new(),
        )
        .unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        err
    });
    thread::sleep(Duration::from_millis(20));
    let mut client = TcpStream::connect(addr).unwrap();
    let _ = kprop_send_store(
        &mut client,
        &store,
        &master_key(TEST_REALM, MASTER),
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &host,
    );
    let err = join.join().expect("thread");
    assert_eq!(
        err,
        Error::KpropUnauthorized(format!("host/testhost.kerber.test@{TEST_REALM}")),
        "no ACL file: nobody is authorized"
    );
}

/// The master key a primary's stash would hold for `password`: the default master key type.
fn master_key(realm: &str, password: &[u8]) -> krb5_crypto::ProtocolKey {
    krb5_kdc::master_key_from_password(realm, password, krb5_kdc::default_master_etype()).unwrap()
}

/// MIT's kpropd loads a received dump with `kdb5_util load` beside the replica's stash; a
/// release kpropd opens it with that stash's key, and one that does not open it is refused.
#[test]
fn kpropd_without_a_password_opens_the_dump_with_the_replicas_stash() {
    let dir = krb5_testkit::scratch_dir("kprop-stash");
    let _ = std::fs::create_dir_all(&dir);
    let (store, _) = bootstrap_documented().unwrap();
    let realm = store.realm().to_owned();
    let mkey = master_key(&realm, b"replica-master");
    let dump = krb5_kdc::dump_store_with_key(&store, &mkey).unwrap();
    let stash = dir.join("stash");
    krb5_kdc::write_stash(&stash, &realm, &mkey, 1).unwrap();
    let replica = kprop_load_with_stash(dump.as_bytes(), &stash).unwrap();
    // The dump carries the K/M entry it is wrapped under, beside the store's principals.
    let mut ids = store.ids();
    ids.push(format!("K/M@{realm}"));
    ids.sort();
    let mut got = replica.ids();
    got.sort();
    assert_eq!(got, ids);
    let other = dir.join("other.stash");
    krb5_kdc::write_stash(&other, &realm, &master_key(&realm, b"other-master"), 1).unwrap();
    assert!(kprop_load_with_stash(dump.as_bytes(), &other).is_err());
    let missing = dir.join("missing");
    let err = kprop_load_with_stash(dump.as_bytes(), &missing).unwrap_err();
    assert!(
        err.to_string()
            .contains(&format!("stash {}:", missing.display())),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// One MIT-wire kprop of `store` as `admin` to a kpropd whose ACL names exactly
/// `admin@KERBER.TEST`, loading into `db` beside `stash`; kpropd's error, else kprop's.
fn kprop_exact_acl(
    store: &krb5_kdc::PrincipalStore,
    db: &std::path::Path,
    stash: &std::path::Path,
) -> Result<krb5_kdc::PrincipalStore, String> {
    use krb5_kdc::testrealm::{TEST_REALM, documented_host};
    use krb5_protocol::{pa_enc_timestamp, tgs_req};

    const MASTER: &[u8] = b"masterpassword";
    let host = documented_host();
    let host_keys: Vec<_> = store
        .get_name(&host)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.key.clone())
        .collect();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    let admin_key = store
        .get_name(&admin)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_req = krb5_protocol::as_req(
        admin.clone(),
        TEST_REALM,
        71,
        Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(store, &as_req).unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &admin,
        host.clone(),
        TEST_REALM,
        72,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(store, &tgs).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let allowed = vec![format!("admin@{TEST_REALM}")];
    let (db, stash) = (db.to_path_buf(), stash.to_path_buf());
    let kpropd = std::thread::spawn(move || {
        krb5_config::isolate_test_krb5();
        let (mut stream, _) = listener.accept().unwrap();
        kpropd_handle_conn(
            &mut stream,
            &KpropdConfig {
                host_keys: &host_keys,
                keytab: None,
                expected_server: Some(&host),
                expected_realm: Some(TEST_REALM),
                master_password: Some(MASTER),
                db: &db,
                stash: &stash,
                allowed_clients: Some(allowed.as_slice()),
                iprop: None,
            },
            &ReplayCache::new(),
        )
        .map_err(|e| format!("kpropd: {e}"))
    });
    let mut client = std::net::TcpStream::connect(addr).unwrap();
    let sent = kprop_send_store(
        &mut client,
        store,
        &master_key(TEST_REALM, MASTER),
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &admin,
    );
    let loaded = kpropd.join().unwrap()?;
    sent.map_err(|e| format!("kprop: {e}"))?;
    Ok(loaded)
}

/// MIT's kpropd runs `kdb5_util load`, whose create of the replica's `principal.ok` is
/// `O_CREAT | O_TRUNC` and empties a symlink's target; this full load refuses a link planted
/// there by a non-root owner of the replica's directory, and loads nothing.
#[test]
fn kpropd_refuses_a_symlink_planted_as_the_replicas_lock_file() {
    let dir = krb5_testkit::scratch_dir("kprop-link");
    let _ = std::fs::create_dir_all(&dir);
    let (db, stash) = (dir.join("replica"), dir.join("replica.stash"));
    let (store, _) = bootstrap_documented().unwrap();
    let ok = krb5_kdc::suffixed(&db, krb5_kdc::SUFFIX_LOCK);
    let victim = dir.join("victim");
    std::fs::write(&victim, b"not the realm's\n").unwrap();
    let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    std::fs::File::options()
        .write(true)
        .open(&victim)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(old)
                .set_accessed(old),
        )
        .unwrap();
    std::os::unix::fs::symlink(&victim, &ok).unwrap();
    let err = kprop_exact_acl(&store, &db, &stash).unwrap_err();
    assert!(
        err.contains("replica.ok: Too many levels of symbolic links"),
        "{err}"
    );
    assert!(
        std::fs::symlink_metadata(&ok)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&victim).unwrap(), b"not the realm's\n");
    assert_eq!(std::fs::metadata(&victim).unwrap().modified().unwrap(), old);
    assert!(!db.exists(), "nothing loaded");
}

/// prop-acl-gate's C2 `acl-exact`: a kpropd whose ACL names the sender exactly loads a full dump
/// into an empty replica directory, and again once the replica's database file alone is removed
/// (its lock files stay), as MIT's load opens and locks the lock files it finds.
#[test]
fn kpropd_with_an_exact_acl_loads_into_an_empty_replica_and_beside_its_lock_files() {
    let dir = krb5_testkit::scratch_dir("kprop-exact-acl");
    let _ = std::fs::create_dir_all(&dir);
    let (db, stash) = (dir.join("replica"), dir.join("replica.stash"));
    let (store, _) = bootstrap_documented().unwrap();
    kprop_exact_acl(&store, &db, &stash).unwrap();
    for lock in [krb5_kdc::SUFFIX_LOCK, krb5_kdc::SUFFIX_POLICY_LOCK] {
        assert!(krb5_kdc::suffixed(&db, lock).exists(), "{lock}");
    }
    std::fs::remove_file(&db).unwrap();
    kprop_exact_acl(&store, &db, &stash).unwrap();
    let replica = krb5_kdc::load_store(&db, &stash).unwrap();
    assert!(
        replica
            .get_name(&krb5_kdc::testrealm::documented_host())
            .is_some()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
