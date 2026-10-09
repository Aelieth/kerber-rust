//! MIT `net-server.c` dispatch suffix strings.
//! MIT `process_packet_response` (`net-server.c:1101-1105`): a UDP dispatch failure is logged
//! `while dispatching (udp)` and gets no reply.
//! MIT `process_stream_response` (`net-server.c:1314-1317`): a TCP dispatch failure is logged
//! `while dispatching (tcp)` and the connection is dropped.
//! MIT `net-server.c` TCP `bufsiz` 1 MiB, `FIELD_TOOLONG` at `msglen > bufsiz-4`.
//! Persist round-trip and UDP listener adversarial tests.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, string_to_key};
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_host,
};
use krb5_kdc::{
    MAX_TCP_REQUEST, S2K_ITERS, WHILE_DISPATCHING_TCP, WHILE_DISPATCHING_UDP, handle_request,
    serve, shared_store,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_config::listen::ListenAddr;
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

/// The embedder's `bind_tcp_listeners` (no backlog argument) listens with the KDC default 128.
#[test]
fn bind_tcp_listeners_defaults_the_kdc_backlog_to_128() {
    use krb5_kdc::bind_tcp_listeners;
    let listener = bind_tcp_listeners(&[ListenAddr {
        host: Some("127.0.0.1".into()),
        port: 0,
    }])
    .unwrap();
    assert_eq!(listener.len(), 1);
    let addr = listener[0].local_addr().unwrap();
    assert_eq!(tcp_send_queue(addr), 128, "embedder TCP backlog at {addr}");
}

/// `ss -ltn` Send-Q for a listening socket: the backlog the kernel kept.
fn tcp_send_queue(addr: std::net::SocketAddr) -> i32 {
    let out = std::process::Command::new("ss")
        .args(["-ltn"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ss -ltn: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let port = addr.port().to_string();
    let ip = addr.ip().to_string();
    for line in text.lines() {
        let cols: Vec<_> = line.split_whitespace().collect();
        if cols.len() < 5 {
            continue;
        }
        let Some((host, p)) = cols[3].rsplit_once(':') else {
            continue;
        };
        if p == port && host.trim_matches(['[', ']']) == ip {
            return cols[2].parse().unwrap();
        }
    }
    panic!("no ss row for {addr}\n{text}");
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
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let addr = udp.local_addr().unwrap();
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
    // MIT `dispatch` (`dispatch.c:114-140`): with the kdc/replay.c lookaside, an identical
    // request resent to the listener is answered from the cache, so the second reply is
    // byte-for-byte the first, not a freshly minted AS-REP (new session key).
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let (store, _) = bootstrap_documented().unwrap();
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let addr = udp.local_addr().unwrap();
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

/// Past the stream cap a new connection evicts the one that started first and is served itself,
/// as MIT's `kill_lru_stream_connection` keeps the newcomer.
#[test]
fn a_connection_past_the_cap_evicts_and_is_served() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::AtomicBool;

    use krb5_kdc::{ListenLimits, serve_until};

    let (store, _) = bootstrap_documented().unwrap();
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let addr = udp.local_addr().unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let store = shared_store(store);
    let f2 = Arc::clone(&flag);
    let h = thread::spawn(move || {
        serve_until(
            store,
            udp,
            tcp,
            f2,
            ListenLimits {
                max_tcp_workers: 1,
                shutdown_poll: Duration::from_millis(50),
                ..ListenLimits::default()
            },
        )
        .unwrap();
    });
    // The accept queue keeps the order: `hold` is accepted before the newcomer.
    let mut hold = TcpStream::connect(addr).unwrap();
    assert!(tcp_as_answers(addr), "the newcomer is served");
    hold.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut b = [0u8; 1];
    assert_eq!(
        hold.read(&mut b).unwrap(),
        0,
        "the first connection was evicted"
    );
    let _ = hold.write(&[0]);
    flag.store(true, std::sync::atomic::Ordering::SeqCst);
    h.join().unwrap();
}

/// A stream left part-way through its length for longer than the old five-second timeout is
/// still answered when it completes: as MIT's (settled live: 615 s), a stream has no timeout.
#[test]
fn an_idle_stream_is_not_timed_out() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::AtomicBool;

    use krb5_kdc::{ListenLimits, serve_until};

    let (store, _) = bootstrap_documented().unwrap();
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let addr = udp.local_addr().unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let store = shared_store(store);
    let f2 = Arc::clone(&flag);
    let h = thread::spawn(move || {
        serve_until(
            store,
            udp,
            tcp,
            f2,
            ListenLimits {
                shutdown_poll: Duration::from_millis(50),
                ..ListenLimits::default()
            },
        )
        .unwrap();
    });
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let bytes = encode(&as_req(cname, TEST_REALM, 9, None).unwrap()).unwrap();
    let mut framed = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(&bytes);
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(&framed[..2]).unwrap();
    thread::sleep(Duration::from_secs(6));
    s.write_all(&framed[2..]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).expect("answered after 6 s");
    let mut buf = vec![0u8; u32::from_be_bytes(hdr) as usize];
    s.read_exact(&mut buf).unwrap();
    let e: krb5_types::KrbError = decode(&buf).unwrap();
    assert_eq!(e.error_code, err::PREAUTH_REQUIRED);
    flag.store(true, std::sync::atomic::Ordering::SeqCst);
    h.join().unwrap();
}

/// One AS-REQ for the documented user served by `serve_until` on this thread, a client thread
/// sending it over UDP; the reply's bytes.
fn served_on_this_thread(nonce: u32) -> Vec<u8> {
    use std::sync::atomic::{AtomicBool, Ordering};

    use krb5_kdc::{ListenLimits, serve_until};

    let (store, _) = bootstrap_documented().unwrap();
    let bytes = encode(&documented_as_req(nonce)).unwrap();
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let addr = udp.local_addr().unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let f2 = Arc::clone(&flag);
    let client = thread::spawn(move || {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        sock.send_to(&bytes, addr).unwrap();
        let mut buf = [0u8; 4096];
        let n = sock.recv(&mut buf).unwrap_or(0);
        f2.store(true, Ordering::SeqCst);
        buf[..n].to_vec()
    });
    let limits = ListenLimits {
        shutdown_poll: Duration::from_millis(50),
        ..ListenLimits::default()
    };
    serve_until(shared_store(store), udp, tcp, flag, limits).unwrap();
    client.join().unwrap()
}

/// The documented user's AS-REQ with PA-ENC-TIMESTAMP.
fn documented_as_req(nonce: u32) -> krb5_types::AsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap()
}

/// A kdcpolicy module whose AS check is `verdict`: refusal, or a panic.
struct ThreadPolicy {
    panics: bool,
}

impl krb5_kdc::KdcPolicy for ThreadPolicy {
    fn check_as(
        &self,
        _store: &dyn krb5_kdc::PrincipalRead,
        _client: &krb5_kdc::Principal,
        _indicators: &[String],
    ) -> Result<krb5_kdc::PolicyAdjustment, krb5_kdc::Error> {
        assert!(!self.panics, "the thread's own policy module ran");
        Err(krb5_kdc::Error::Protocol {
            code: err::POLICY,
            text: Some("DENIED".into()),
            e_data: None,
            detail: None,
        })
    }
    fn check_tgs(
        &self,
        _store: &dyn krb5_kdc::PrincipalRead,
        _sname: &PrincipalName,
        _indicators: &[String],
    ) -> Result<krb5_kdc::PolicyAdjustment, krb5_kdc::Error> {
        Ok(krb5_kdc::PolicyAdjustment::default())
    }
}

/// A kdcpolicy module set for the calling thread alone, one that refuses or one that panics,
/// does not reach a request the loop serves on that thread, and is the thread's own again when
/// the loop returns.
#[test]
fn the_loop_does_not_take_a_slot_set_on_its_thread() {
    use krb5_kdc::{clear_thread_policy, set_thread_policy};

    for panics in [false, true] {
        set_thread_policy(Arc::new(ThreadPolicy { panics }));
        let own = |nonce| {
            let (store, _) = bootstrap_documented().unwrap();
            std::panic::catch_unwind(|| krb5_kdc::issue_as(&store, &documented_as_req(nonce)))
                .map_or(true, |r| r.is_err())
        };
        assert!(own(1), "the slot applies to this thread's own calls");
        let reply = served_on_this_thread(2);
        assert_eq!(
            reply.first().copied(),
            Some(0x6b),
            "the loop's request got its AS-REP (panics: {panics})"
        );
        assert!(own(3), "the slot is the thread's again");
        clear_thread_policy();
    }
}

#[test]
fn listener_chaos_udp_garbage_then_valid() {
    use std::sync::atomic::AtomicBool;

    use krb5_kdc::{ListenLimits, serve_until};

    let (store, _) = bootstrap_documented().unwrap();
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let addr = udp.local_addr().unwrap();
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
                shutdown_poll: Duration::from_millis(50),
            },
        );
    });
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    // MIT dispatch answers garbage with no reply.
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
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let addr = udp.local_addr().unwrap();
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
                shutdown_poll: Duration::from_millis(100),
            },
        );
    });
    // Prove the loop is serving: send a real AS-REQ and read the KRB-ERROR before storing the
    // flag; a short pause then lets the loop wait in its poll again, so the flag is honoured
    // within shutdown_poll.
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
        "shutdown must be honoured within ~shutdown_poll: {:?}",
        t0.elapsed()
    );
}

/// One AS-REQ without preauth over UDP to `addr`; the KDC's answer is PREAUTH_REQUIRED.
fn udp_as_answers(addr: std::net::SocketAddr) -> bool {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let bytes = encode(&as_req(cname, TEST_REALM, 1, None).unwrap()).unwrap();
    let local = if addr.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    let sock = UdpSocket::bind(local).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    sock.send_to(&bytes, addr).unwrap();
    let mut buf = [0u8; 4096];
    let Ok(n) = sock.recv(&mut buf) else {
        return false;
    };
    decode::<krb5_types::KrbError>(&buf[..n]).is_ok_and(|e| e.error_code == err::PREAUTH_REQUIRED)
}

/// The same over TCP.
fn tcp_as_answers(addr: std::net::SocketAddr) -> bool {
    use std::io::{Read, Write};
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let bytes = encode(&as_req(cname, TEST_REALM, 2, None).unwrap()).unwrap();
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return false;
    };
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .unwrap();
    s.write_all(&bytes).unwrap();
    let mut hdr = [0u8; 4];
    if s.read_exact(&mut hdr).is_err() {
        return false;
    }
    let mut buf = vec![0u8; u32::from_be_bytes(hdr) as usize];
    s.read_exact(&mut buf).unwrap();
    decode::<krb5_types::KrbError>(&buf).is_ok_and(|e| e.error_code == err::PREAUTH_REQUIRED)
}

#[test]
fn kdc_listen_list_is_served_on_every_address_like_mit() {
    // MIT `loop_add_addresses` (`lib/apputils/net-server.c:381-433`): every entry of a list
    // is added, and `kdc_tcp_listen` is its own list; the first-binds-wins candidate walk
    // answered on one address only.
    use krb5_kdc::{bind_tcp_listeners, bind_udp_listeners, serve_all};
    let conf = krb5_config::KdcConf::parse(
        "[kdcdefaults]\n    kdc_listen = 127.0.0.1:0, 127.0.0.2:0\n    kdc_tcp_listen = 127.0.0.1:0;127.0.0.2:0\n",
    )
    .unwrap();
    let udp = bind_udp_listeners(&conf.kdc_udp_listeners().unwrap()).unwrap();
    let tcp = bind_tcp_listeners(&conf.kdc_tcp_listeners().unwrap()).unwrap();
    assert_eq!((udp.len(), tcp.len()), (2, 2));
    // MIT `setup_socket` (`lib/apputils/net-server.c:861-875`): only a wildcard socket asks for pktinfo.
    assert!(!udp.iter().any(asks_pktinfo));
    let udp_addrs: Vec<_> = udp.iter().map(|s| s.local_addr().unwrap()).collect();
    let tcp_addrs: Vec<_> = tcp.iter().map(|s| s.local_addr().unwrap()).collect();
    let (store, _) = bootstrap_documented().unwrap();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve_all(store, udp, tcp);
    });
    for a in udp_addrs {
        assert!(udp_as_answers(a), "no UDP answer on {a}");
    }
    for a in tcp_addrs {
        assert!(tcp_as_answers(a), "no TCP answer on {a}");
    }
}

/// The wildcard on a port no socket of either family holds: `bind` on `{ host: None, port }`,
/// with another port tried when one is taken between the pick and the bind.
fn bind_wildcard<T>(bind: impl Fn(&[ListenAddr]) -> std::io::Result<Vec<T>>) -> (u16, Vec<T>) {
    for _ in 0..20 {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        match bind(&[ListenAddr { host: None, port }]) {
            Ok(socks) => return (port, socks),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(e) => panic!("wildcard on {port}: {e}"),
        }
    }
    panic!("no port free on both families");
}

/// The host has IPv6 (a `[::1]` socket binds).
fn ipv6_host() -> bool {
    UdpSocket::bind("[::1]:0").is_ok()
}

/// One socket's options as MIT's net-server sets them: `SO_REUSEADDR` on every server socket and
/// `IPV6_V6ONLY` on every IPv6 one.
fn assert_mit_socket(sock: &impl std::os::fd::AsFd, local: std::net::SocketAddr) {
    use nix::sys::socket::{getsockopt, sockopt};
    assert!(
        getsockopt(sock, sockopt::ReuseAddr).unwrap(),
        "{local}: SO_REUSEADDR"
    );
    if local.is_ipv6() {
        assert!(
            getsockopt(sock, sockopt::Ipv6V6Only).unwrap(),
            "{local}: IPV6_V6ONLY"
        );
    }
}

/// A UDP socket asks for each datagram's destination (`IP_PKTINFO` / `IPV6_RECVPKTINFO`).
fn asks_pktinfo(sock: &UdpSocket) -> bool {
    use nix::sys::socket::{getsockopt, sockopt};
    if sock.local_addr().unwrap().is_ipv4() {
        getsockopt(sock, sockopt::Ipv4PacketInfo).unwrap()
    } else {
        getsockopt(sock, sockopt::Ipv6RecvPacketInfo).unwrap()
    }
}

#[test]
fn the_wildcard_is_an_ipv4_and_an_ipv6_only_socket_on_one_port_like_mit() {
    // MIT `setup_addresses` (`lib/apputils/net-server.c:1011-1036`): both addresses of the wildcard are set up.
    // MIT `create_server_socket` (`lib/apputils/net-server.c:647-658`): the IPv6 one is `IPV6_V6ONLY`.
    // So `0.0.0.0` and `[::]` bind on one port whatever `net.ipv6.bindv6only` says.
    use krb5_kdc::{bind_rpc_listeners, bind_tcp_listeners, bind_udp_listeners};
    let want = if ipv6_host() { 2 } else { 1 };
    let (port, udp) = bind_wildcard(bind_udp_listeners);
    let addrs: Vec<_> = udp.iter().map(|s| s.local_addr().unwrap()).collect();
    assert_eq!(addrs.len(), want, "{addrs:?}");
    for (s, a) in udp.iter().zip(&addrs) {
        assert!(a.ip().is_unspecified() && a.port() == port, "{a}");
        assert_mit_socket(s, *a);
        assert!(asks_pktinfo(s), "{a}: pktinfo");
    }
    for bind in [bind_tcp_listeners, bind_rpc_listeners] {
        let (port, tcp) = bind_wildcard(bind);
        let addrs: Vec<_> = tcp.iter().map(|s| s.local_addr().unwrap()).collect();
        assert_eq!(addrs.len(), want, "{addrs:?}");
        assert!(addrs[0].is_ipv4(), "{addrs:?}");
        for (s, a) in tcp.iter().zip(&addrs) {
            assert!(a.ip().is_unspecified() && a.port() == port, "{a}");
            assert_mit_socket(s, *a);
        }
    }
}

#[test]
fn bare_port_listens_on_ipv4_and_ipv6_like_mit() {
    // A bare port is MIT's wildcard (`loop_add_addresses` with no host): IPv4 peers reach the
    // `0.0.0.0` socket and, where the host has IPv6, IPv6 peers the `[::]` one.
    use krb5_kdc::{bind_tcp_listeners, bind_udp_listeners, serve_all};
    let (_, udp) = bind_wildcard(bind_udp_listeners);
    let (_, tcp) = bind_wildcard(bind_tcp_listeners);
    let probes: Vec<(bool, std::net::SocketAddr)> = udp
        .iter()
        .map(|s| (true, s.local_addr().unwrap()))
        .chain(tcp.iter().map(|s| (false, s.local_addr().unwrap())))
        .map(|(is_udp, a)| {
            let ip: std::net::IpAddr = if a.is_ipv4() {
                std::net::Ipv4Addr::LOCALHOST.into()
            } else {
                std::net::Ipv6Addr::LOCALHOST.into()
            };
            (is_udp, std::net::SocketAddr::new(ip, a.port()))
        })
        .collect();
    let (store, _) = bootstrap_documented().unwrap();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve_all(store, udp, tcp);
    });
    for (is_udp, a) in probes {
        let ok = if is_udp {
            udp_as_answers(a)
        } else {
            tcp_as_answers(a)
        };
        assert!(
            ok,
            "no {} answer on {a}",
            if is_udp { "udp" } else { "tcp" }
        );
    }
}

#[test]
fn listener_setup_logs_mits_lines() {
    // MIT `setup_socket` (`lib/apputils/net-server.c:813-815`): each setup is logged at debug.
    // MIT `create_server_socket` (`lib/apputils/net-server.c:647-658`): each IPv6 socket's `IPV6_V6ONLY` is logged with its descriptor.
    // MIT `create_server_socket` (`lib/apputils/net-server.c:660-666`): a bind that fails is logged with the address, then as a failed setup and a failed network.
    use krb5_kdc::{bind_rpc_listeners, bind_tcp_listeners, bind_udp_listeners};
    use krb5_log::klog;
    use std::os::fd::AsRawFd;
    let dir = krb5_testkit::scratch_dir("krb5-kdc-listen-lines");
    let log = dir.join("kdc.log");
    klog::init("krb5kdc", &[format!("FILE:{}", log.display())], true);
    let (udp_port, udp) = bind_wildcard(bind_udp_listeners);
    let (tcp_port, tcp) = bind_wildcard(bind_tcp_listeners);
    let (rpc_port, rpc) = bind_wildcard(bind_rpc_listeners);
    let held = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let busy = held.local_addr().unwrap().port();
    let refused = bind_tcp_listeners(&[ListenAddr {
        host: None,
        port: busy,
    }]);
    klog::close();
    let text = std::fs::read_to_string(&log).unwrap();
    for (kind, port) in [("UDP", udp_port), ("TCP", tcp_port), ("RPC", rpc_port)] {
        let line = format!("(debug): Setting up {kind} socket for address 0.0.0.0:{port}\n");
        assert!(text.contains(&line), "{line}in\n{text}");
    }
    for a in udp.iter().map(|s| s.local_addr().unwrap()) {
        let line = format!("(debug): Setting pktinfo on socket {a}\n");
        assert!(text.contains(&line), "{line}in\n{text}");
    }
    for port in [tcp_port, rpc_port] {
        assert!(!text.contains(&format!("pktinfo on socket 0.0.0.0:{port}\n")));
    }
    let v6_fds: Vec<i32> = udp
        .iter()
        .map(|s| (s.local_addr().unwrap(), s.as_raw_fd()))
        .chain(tcp.iter().map(|s| (s.local_addr().unwrap(), s.as_raw_fd())))
        .chain(rpc.iter().map(|s| (s.local_addr().unwrap(), s.as_raw_fd())))
        .filter(|(a, _)| a.is_ipv6())
        .map(|(_, fd)| fd)
        .collect();
    assert_eq!(v6_fds.len(), if ipv6_host() { 3 } else { 0 });
    for fd in v6_fds {
        let line = format!("(info): setsockopt({fd},IPV6_V6ONLY,1) worked\n");
        assert!(text.contains(&line), "{line}in\n{text}");
    }
    assert_eq!(refused.unwrap_err().kind(), std::io::ErrorKind::AddrInUse);
    for line in [
        format!("(Error): Address already in use - Cannot bind server socket on 0.0.0.0:{busy}\n"),
        "(Error): Failed setting up a TCP socket (for 0.0.0.0)\n".to_owned(),
        "(Error): Address already in use - Error setting up network\n".to_owned(),
    ] {
        assert!(text.contains(&line), "{line}in\n{text}");
    }
    drop(held);
    let _ = std::fs::remove_dir_all(&dir);
}

/// One AS-REQ without preauth over `sock`, sent to `to` or (`None`) to the address `sock` is
/// connected to; the reply and the address it came from.
fn udp_exchange(
    sock: &UdpSocket,
    to: Option<std::net::SocketAddr>,
    nonce: u32,
) -> Option<(krb5_types::KrbError, std::net::SocketAddr)> {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let bytes = encode(&as_req(cname, TEST_REALM, nonce, None).unwrap()).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    match to {
        Some(a) => sock.send_to(&bytes, a).unwrap(),
        None => sock.send(&bytes).unwrap(),
    };
    let mut buf = [0u8; 4096];
    let (n, src) = sock.recv_from(&mut buf).ok()?;
    Some((decode(&buf[..n]).unwrap(), src))
}

#[test]
fn a_udp_reply_leaves_from_the_address_the_request_was_sent_to_like_mit() {
    // MIT `send_to_from` (`lib/apputils/udppktinfo.c:443-474`): a wildcard socket's reply leaves from the request's destination.
    // A client whose UDP socket is connected to that address, as MIT's is, takes no reply from any other.
    use krb5_kdc::{bind_udp_listeners, serve_all};
    let mut entries = vec![ListenAddr {
        host: Some("0.0.0.0".into()),
        port: 0,
    }];
    if ipv6_host() {
        entries.push(ListenAddr {
            host: Some("::".into()),
            port: 0,
        });
    }
    let udp = bind_udp_listeners(&entries).unwrap();
    let addrs: Vec<_> = udp.iter().map(|s| s.local_addr().unwrap()).collect();
    let (store, _) = bootstrap_documented().unwrap();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve_all(store, udp, Vec::new());
    });
    let v4 = std::net::SocketAddr::from(([127, 0, 0, 2], addrs[0].port()));
    let plain = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (e, src) = udp_exchange(&plain, Some(v4), 11).expect("a reply");
    assert_eq!(e.error_code, err::PREAUTH_REQUIRED);
    assert_eq!(src, v4, "the reply's source");
    let connected = UdpSocket::bind("127.0.0.1:0").unwrap();
    connected.connect(v4).unwrap();
    let (e, _) = udp_exchange(&connected, None, 12).expect("the connected client's reply");
    assert_eq!(e.error_code, err::PREAUTH_REQUIRED);
    if let Some(a) = addrs.get(1) {
        let v6 = std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, a.port()));
        let connected = UdpSocket::bind("[::1]:0").unwrap();
        connected.connect(v6).unwrap();
        let (e, src) = udp_exchange(&connected, None, 13).expect("the IPv6 client's reply");
        assert_eq!((e.error_code, src), (err::PREAUTH_REQUIRED, v6));
    }
}
