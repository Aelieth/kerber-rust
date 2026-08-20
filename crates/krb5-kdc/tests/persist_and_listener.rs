//! Persist round-trip and UDP listener adversarial tests.

use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use krb5_asn1::{decode, encode};
use krb5_kdc::{
    as_req, bootstrap_documented, handle_request, load_store, save_store, serve, TEST_REALM,
    TEST_USER,
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
