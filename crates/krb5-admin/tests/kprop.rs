//! Admin whole-flow tests moved from `src/lib.rs`.

#[path = "common/mod.rs"]
mod common;

use krb5_admin::*;
use krb5_kdc::testrealm::bootstrap_documented;

use krb5_protocol::{AcceptorConfig, ReplayCache};
use krb5_types::PrincipalName;

/// The master key a primary's stash would hold for `password`: the default master key type.
fn master_key(realm: &str, password: &[u8]) -> krb5_crypto::ProtocolKey {
    krb5_kdc::master_key_from_password(realm, password, krb5_kdc::default_master_etype()).unwrap()
}

/// One MIT-wire kprop of `store` as `admin` to a kpropd whose ACL names exactly `admin@KERBER.TEST`, loading into `db` beside `stash`; kpropd's error, else kprop's.
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
                resync_timeout: std::time::Duration::from_secs(300),
                conf: &AcceptorConfig::default(),
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

/// `O_CREAT | O_TRUNC` and empties a symlink's target; this full load refuses a link planted there by a non-root owner of the replica's directory, and loads nothing.
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
