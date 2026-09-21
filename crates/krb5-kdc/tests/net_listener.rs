//! MIT `net-server.c:1101-1105,1314-1317` dispatch suffix strings.
//! MIT `net-server.c` TCP `bufsiz` 1 MiB, `FIELD_TOOLONG` at `msglen > bufsiz-4`.
//! Persist round-trip and UDP listener adversarial tests.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, string_to_key};
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_host,
};
use krb5_kdc::{
    MAX_TCP_REQUEST, S2K_ITERS, WHILE_DISPATCHING_TCP, WHILE_DISPATCHING_UDP, as_req,
    handle_request, pa_enc_timestamp, serve, shared_store, tgs_req,
};

use krb5_types::{AsRep, PrincipalName, err, ku};
use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn dispatch_suffixes_are_mit_net_server() {
    assert_eq!(WHILE_DISPATCHING_UDP, "while dispatching (udp)");
    assert_eq!(WHILE_DISPATCHING_TCP, "while dispatching (tcp)");
}

#[test]
fn tcp_max_request_is_one_mib_minus_four() {
    assert_eq!(MAX_TCP_REQUEST, 1024 * 1024 - 4);
}

#[test]
fn listener_empty_and_truncated_are_dropped() {
    let (store, _) = bootstrap_documented().unwrap();
    for payload in [&[][..], &[0x6a], &[0xff; 8]] {
        let reply = handle_request(&store, payload).unwrap();
        assert!(reply.is_empty(), "MIT dispatch drops garbage");
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
fn listener_retransmit_resends_the_cached_reply_like_replay_c() {
    // MIT kdc/replay.c lookaside (dispatch.c:114-140): an identical request
    // resent to the listener is answered from the cache, so the second reply is
    // byte-for-byte the first, not a freshly minted AS-REP (new session key) or a
    // PA-ENC-TIMESTAMP replay error.
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let (store, _) = bootstrap_documented().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve(store, udp, tcp);
    });

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
        88,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let bytes = encode(&req).unwrap();

    let send = |b: &[u8]| -> Vec<u8> {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let len = u32::try_from(b.len()).unwrap();
        s.write_all(&len.to_be_bytes()).unwrap();
        s.write_all(b).unwrap();
        s.flush().unwrap();
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).unwrap();
        let n = u32::from_be_bytes(hdr) as usize;
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).unwrap();
        buf
    };

    let first = send(&bytes);
    assert_eq!(
        first.first().copied(),
        Some(0x6b),
        "first request issues an AS-REP"
    );
    let second = send(&bytes);
    assert_eq!(
        second, first,
        "the retransmit is answered from the lookaside cache byte-for-byte"
    );
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
                max_dgram_reply_size: krb5_kdc::MAX_DGRAM_REPLY,
                io_timeout: Duration::from_secs(2),
                shutdown_poll: Duration::from_millis(50),
            },
        );
    });
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
                max_dgram_reply_size: krb5_kdc::MAX_DGRAM_REPLY,
                io_timeout: Duration::from_millis(200),
                shutdown_poll: Duration::from_millis(50),
            },
        );
    });
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    // MIT dispatch drops garbage with no reply; do not wait out io_timeout.
    for junk in [&[][..], &[0xff; 8], &[0x00; 256], &[0x6a, 0x01]] {
        let _ = sock.send_to(junk, addr);
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
                let part = krb5_asn1::decode_enc_kdc_rep_part(&plain).unwrap();
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

#[test]
fn serve_until_honours_shutdown_within_the_poll_interval() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    use krb5_kdc::{ListenLimits, serve_until};

    let (store, _) = bootstrap_documented().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let store = shared_store(store);
    let f2 = Arc::clone(&flag);
    let handle = thread::spawn(move || {
        let _ = serve_until(
            store,
            udp,
            tcp,
            f2,
            ListenLimits {
                max_tcp_workers: 4,
                max_tcp_request: 4096,
                max_dgram_reply_size: krb5_kdc::MAX_DGRAM_REPLY,
                io_timeout: Duration::from_secs(5),
                shutdown_poll: Duration::from_millis(100),
            },
        );
    });
    // Prove the UDP loop is in recv: a half-round-trip with no read can
    // return before the first recv (the flag is checked only around the
    // blocking read). Send a real AS-REQ and read the KRB-ERROR before
    // storing the flag; a short pause then lets the loop re-enter recv so
    // shutdown_poll (not io_timeout) is the honour path.
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 1, None).unwrap();
    let bytes = encode(&req).unwrap();
    let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
    probe
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    probe.send_to(&bytes, addr).unwrap();
    let mut buf = [0u8; 4096];
    let n = probe.recv(&mut buf).unwrap();
    let e: krb5_types::KrbError = decode(&buf[..n]).unwrap();
    assert_eq!(e.error_code, err::PREAUTH_REQUIRED);
    thread::sleep(Duration::from_millis(20));
    let t0 = Instant::now();
    flag.store(true, Ordering::SeqCst);
    handle.join().unwrap();
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "shutdown must be honoured within ~shutdown_poll, not io_timeout: {:?}",
        t0.elapsed()
    );
}
