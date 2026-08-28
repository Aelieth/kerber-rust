//! Persist round-trip and UDP listener adversarial tests.

use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, string_to_key};
use krb5_kdc::{
    S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    documented_admin_id, documented_host, handle_request, load_store, pa_enc_timestamp, save_store,
    serve, shared_store, tgs_req,
};
use krb5_types::{AsRep, EncAsRepPart, PrincipalName, err, ku};

#[test]
fn persist_survives_restart_without_key_regen() {
    let dir = std::env::temp_dir().join(format!("krb5-persist-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = bootstrap_documented().unwrap();
    let krbtgt_before = store
        .krbtgt()
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .as_bytes()
        .to_vec();
    save_store(&store, &db, &stash).unwrap();
    let header = std::fs::read(&db).unwrap();
    assert!(
        header.starts_with(b"kdb5_util load_dump version 7"),
        "live db must be dump version 7, got {}",
        String::from_utf8_lossy(&header[..header.len().min(40)])
    );
    assert!(!header.starts_with(b"KDB3"));
    let loaded = load_store(&db, &stash).unwrap();
    let krbtgt_after = loaded
        .krbtgt()
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .as_bytes()
        .to_vec();
    assert_eq!(krbtgt_before, krbtgt_after);
    assert_ne!(
        loaded.domain_sid().to_sddl(),
        krb5_types::pac::RpcSid::dummy_domain().to_sddl()
    );
    assert_eq!(loaded.domain_sid().to_sddl(), store.domain_sid().to_sddl());
    let user = krb5_types::PrincipalName::new(krb5_types::PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    assert_eq!(
        loaded.get_name(&user).unwrap().rid,
        store.get_name(&user).unwrap().rid
    );
    assert_eq!(loaded.krbtgt().unwrap().rid, krb5_kdc::RID_KRBTGT);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn persist_writes_db_and_stash_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!(
        "krb5-persist-0600-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let db_mode = std::fs::metadata(&db).unwrap().permissions().mode() & 0o777;
    let stash_mode = std::fs::metadata(&stash).unwrap().permissions().mode() & 0o777;
    assert_eq!(db_mode, 0o600, "db must be 0600");
    assert_eq!(stash_mode, 0o600, "stash must be 0600");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reload_if_stale_sees_kadmin_create() {
    let dir = std::env::temp_dir().join(format!(
        "krb5-reload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut writer, acl) = bootstrap_documented().unwrap();
    save_store(&writer, &db, &stash).unwrap();
    let mut reader = load_store(&db, &stash).unwrap();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["extra"]);
    writer.persist_paths = Some((db.clone(), stash.clone()));
    writer
        .create_password(&acl, &documented_admin_id(), &extra, b"extra-secret")
        .unwrap();
    reader.reload_if_stale().unwrap();
    assert!(
        reader.get_name(&extra).is_some(),
        "KDC must pick up kadmind create from the shared db"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reload_if_stale_keeps_lockout_and_pa_replay() {
    use krb5_kdc::{NamedPolicy, TEST_USER};
    use krb5_protocol::ReplayKey;

    let dir = std::env::temp_dir().join(format!(
        "krb5-reload-overlay-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut writer, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    writer.put_policy(NamedPolicy {
        name: "lock".into(),
        min_length: 0,
        min_classes: 0,
        history: 0,
        max_fail: 3,
    });
    writer
        .set_principal_policy(&user, Some("lock".into()))
        .unwrap();
    save_store(&writer, &db, &stash).unwrap();
    let mut reader = load_store(&db, &stash).unwrap();
    let before = reader.get_name(&user).unwrap();
    assert_eq!(reader.max_fail_for(before), 3);
    reader.record_as_outcome(&user, false);
    reader.record_as_outcome(&user, false);
    let after_fail = reader.get_name(&user).unwrap();
    assert_eq!(reader.fail_auth_of(after_fail), 2);
    let rk = ReplayKey {
        client: format!("{TEST_USER}@{TEST_REALM}"),
        server: format!("krbtgt/{TEST_REALM}@{TEST_REALM}"),
        ctime: 1,
        cusec: 2,
        auth_hash: [7u8; 20],
    };
    assert!(
        !reader.pa_replay().check_and_store(rk.clone()),
        "first PA must insert"
    );
    writer.persist_paths = Some((db.clone(), stash.clone()));
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["unrelated"]);
    writer
        .create_password(&acl, &documented_admin_id(), &extra, b"unrelated-secret")
        .unwrap();
    reader.reload_if_stale().unwrap();
    assert!(reader.get_name(&extra).is_some(), "reload must see extra");
    let after = reader.get_name(&user).unwrap();
    assert_eq!(
        reader.fail_auth_of(after),
        2,
        "lockout overlay must survive reload_if_stale"
    );
    assert!(
        reader.pa_replay().check_and_store(rk),
        "PA replay cache must survive reload_if_stale"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persist_paths_saves_password_lock_and_expiry() {
    let dir = std::env::temp_dir().join(format!(
        "krb5-persist-status-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let mut store = load_store(&db, &stash).unwrap();
    assert!(
        store.persist_paths.is_some(),
        "load_store must wire persist_paths so mutations save"
    );
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kvno_before = store
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    store
        .change_password(&acl, &documented_admin_id(), &user, b"rotated-secret")
        .unwrap();
    store.set_status(&user, true, 1_700_000_123).unwrap();
    let loaded = load_store(&db, &stash).unwrap();
    let p = loaded.get_name(&user).unwrap();
    let kvno_after = p.keys.iter().map(|k| k.kvno).max().unwrap();
    assert!(
        kvno_after > kvno_before,
        "change_password must persist a kvno bump via save_if_configured"
    );
    assert!(p.locked, "locked must round-trip through dump v7");
    assert_eq!(p.pw_expire, 1_700_000_123);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persist_dump_v7_issues_as_with_string_to_key() {
    let dir = std::env::temp_dir().join(format!(
        "krb5-persist-as-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let raw = std::fs::read(&db).unwrap();
    assert!(raw.starts_with(b"kdb5_util load_dump version 7"));
    assert!(!raw.starts_with(b"KDB3"));
    let loaded = load_store(&db, &stash).unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(TEST_REALM);
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = as_req(
        cname,
        TEST_REALM,
        77,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let rep = handle_request(&loaded, &encode(&req).unwrap()).unwrap();
    assert_eq!(rep.first().copied(), Some(0x6b));
    let as_rep: AsRep = decode(&rep).unwrap();
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&key, usage, as_rep.0.enc_part.cipher.as_ref()).unwrap();
    let EncAsRepPart(_) = decode(&plain).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persist_legacy_kdb3_still_loads_sid() {
    use krb5_kdc::save_store_legacy_kdb3;

    let dir = std::env::temp_dir().join(format!(
        "krb5-persist-kdb3-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = bootstrap_documented().unwrap();
    let sid = store.domain_sid().to_sddl();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let rid = store.get_name(&user).unwrap().rid;
    save_store_legacy_kdb3(&store, &db, &stash).unwrap();
    let raw = std::fs::read(&db).unwrap();
    assert!(raw.starts_with(b"KDB3"));
    let loaded = load_store(&db, &stash).unwrap();
    assert_eq!(loaded.domain_sid().to_sddl(), sid);
    assert_eq!(loaded.get_name(&user).unwrap().rid, rid);
    assert_ne!(sid, krb5_types::pac::RpcSid::dummy_domain().to_sddl());
    let cname = user;
    let salt = cname.default_salt(TEST_REALM);
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = as_req(
        cname,
        TEST_REALM,
        78,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let rep = handle_request(&loaded, &encode(&req).unwrap()).unwrap();
    assert_eq!(rep.first().copied(), Some(0x6b));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn listener_empty_and_truncated_get_krb_error() {
    let (store, _) = bootstrap_documented().unwrap();
    for payload in [&[][..], &[0x6a], &[0xff; 8]] {
        let reply = handle_request(&store, payload).unwrap();
        assert!(!reply.is_empty());
        let e: krb5_types::KrbError = decode(&reply).unwrap();
        assert!(e.error_code != 0);
    }
}

#[test]
fn udp_listener_answers_wrong_password() {
    let (store, _) = bootstrap_documented().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve(store, udp, tcp);
    });
    thread::sleep(Duration::from_millis(50));
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 1, None).unwrap();
    let bytes = encode(&req).unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    sock.send_to(&bytes, addr).unwrap();
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).unwrap();
    let e: krb5_types::KrbError = decode(&buf[..n]).unwrap();
    assert_eq!(e.error_code, err::PREAUTH_REQUIRED);
}

#[test]
fn tcp_worker_cap_drops_excess_connections() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::AtomicBool;

    use krb5_kdc::{ListenLimits, serve_until};

    let (store, _) = bootstrap_documented().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let store = shared_store(store);
    let f2 = Arc::clone(&flag);
    thread::spawn(move || {
        let _ = serve_until(
            store,
            udp,
            tcp,
            f2,
            ListenLimits {
                max_tcp_workers: 1,
                max_tcp_request: 4096,
                io_timeout: Duration::from_secs(2),
            },
        );
    });
    thread::sleep(Duration::from_millis(40));
    let hold = TcpStream::connect(addr).unwrap();
    hold.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    thread::sleep(Duration::from_millis(40));
    let mut extra = TcpStream::connect(addr).unwrap();
    extra
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    extra.write_all(&4u32.to_be_bytes()).unwrap();
    extra.write_all(&[0x6a, 0x02, 0x01, 0x00]).unwrap();
    let mut hdr = [0u8; 4];
    assert!(
        extra.read_exact(&mut hdr).is_err(),
        "worker cap must drop the extra TCP body"
    );
    drop(hold);
    flag.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[test]
fn listener_chaos_udp_garbage_then_valid() {
    use std::sync::atomic::AtomicBool;

    use krb5_kdc::{ListenLimits, serve_until};

    let (store, _) = bootstrap_documented().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let store = shared_store(store);
    let f2 = Arc::clone(&flag);
    thread::spawn(move || {
        let _ = serve_until(
            store,
            udp,
            tcp,
            f2,
            ListenLimits {
                max_tcp_workers: 4,
                max_tcp_request: 4096,
                io_timeout: Duration::from_millis(200),
            },
        );
    });
    thread::sleep(Duration::from_millis(40));
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for junk in [&[][..], &[0xff; 8], &[0x00; 256], &[0x6a, 0x01]] {
        let _ = sock.send_to(junk, addr);
        let mut buf = [0u8; 4096];
        let _ = sock.recv(&mut buf);
    }
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 1, None).unwrap();
    let bytes = encode(&req).unwrap();
    sock.send_to(&bytes, addr).unwrap();
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).unwrap();
    let e: krb5_types::KrbError = decode(&buf[..n]).unwrap();
    assert_eq!(e.error_code, err::PREAUTH_REQUIRED);
    flag.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[test]
fn bounded_stress_handle_request() {
    let (store, _) = bootstrap_documented().unwrap();
    let store = Arc::new(store);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(TEST_REALM);
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let mut joins = Vec::new();
    for t in 0..8u32 {
        let s = Arc::clone(&store);
        let key = key.clone();
        let cname = cname.clone();
        joins.push(thread::spawn(move || {
            let mut ok_as = 0u32;
            let mut ok_tgs = 0u32;
            for i in 0..8u32 {
                let _ = handle_request(&s, &[0xff; 16]);
                let _ = handle_request(&s, &[]);
                let nonce = 10_000 + t * 100 + i;
                let req = as_req(
                    cname.clone(),
                    TEST_REALM,
                    nonce,
                    Some(vec![pa_enc_timestamp(&key).unwrap()]),
                )
                .unwrap();
                let rep = handle_request(&s, &encode(&req).unwrap()).unwrap();
                assert_eq!(
                    rep.first().copied(),
                    Some(0x6b),
                    "valid AS-REQ must yield AS-REP"
                );
                ok_as += 1;
                let as_rep: AsRep = decode(&rep).unwrap();
                let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
                let plain = decrypt(&key, usage, as_rep.0.enc_part.cipher.as_ref()).unwrap();
                let EncAsRepPart(part) = decode(&plain).unwrap();
                let session = ProtocolKey::from_bytes(
                    EncryptionType::from_iana(part.key.keytype).unwrap(),
                    part.key.keyvalue.as_ref(),
                )
                .unwrap();
                let tgs = tgs_req(
                    as_rep.0.ticket,
                    &session,
                    TEST_REALM,
                    &cname,
                    documented_host(),
                    TEST_REALM,
                    nonce + 50,
                )
                .unwrap();
                let tgs_rep = handle_request(&s, &encode(&tgs).unwrap()).unwrap();
                assert_eq!(
                    tgs_rep.first().copied(),
                    Some(0x6d),
                    "valid TGS-REQ must yield TGS-REP"
                );
                ok_tgs += 1;
            }
            (ok_as, ok_tgs)
        }));
    }
    let mut total_as = 0u32;
    let mut total_tgs = 0u32;
    for j in joins {
        let (a, g) = j.join().unwrap();
        total_as += a;
        total_tgs += g;
    }
    assert_eq!(total_as, 64, "every concurrent AS must succeed");
    assert_eq!(total_tgs, 64, "every concurrent TGS must succeed");
}
