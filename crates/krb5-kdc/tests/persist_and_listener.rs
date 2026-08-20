//! Persist round-trip and UDP listener adversarial tests.

use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use krb5_asn1::{decode, encode};
use krb5_kdc::{
    as_req, bootstrap_documented, documented_admin_id, handle_request, load_store, save_store,
    serve, TEST_REALM, TEST_USER,
};
use krb5_types::{err, PrincipalName};

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
    assert!(p.locked, "locked must round-trip through KDB2");
    assert_eq!(p.pw_expire, 1_700_000_123);
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
    let store = Arc::new(store);
    thread::spawn(move || {
        let _ = serve(store, udp, tcp);
    });
    thread::sleep(Duration::from_millis(50));
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 1, None);
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

    use krb5_kdc::{serve_until, ListenLimits};

    let (store, _) = bootstrap_documented().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let store = Arc::new(store);
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

    use krb5_kdc::{serve_until, ListenLimits};

    let (store, _) = bootstrap_documented().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let store = Arc::new(store);
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
    let req = as_req(cname, TEST_REALM, 1, None);
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
    let mut joins = Vec::new();
    for _ in 0..8 {
        let s = Arc::clone(&store);
        joins.push(thread::spawn(move || {
            for _ in 0..32 {
                let _ = handle_request(&s, &[0xff; 16]);
                let _ = handle_request(&s, &[]);
            }
        }));
    }
    for j in joins {
        j.join().unwrap();
    }
}
