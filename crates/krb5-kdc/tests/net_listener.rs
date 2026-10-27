//! MIT `net-server.c` dispatch suffix strings.
// MIT: `process_packet_response` (net-server.c:1101-1105)
//! a UDP dispatch failure is logged
//! `while dispatching (udp)` and gets no reply.
// MIT: `process_stream_response` (net-server.c:1314-1317)
//! a TCP dispatch failure is logged
//! `while dispatching (tcp)` and the connection is dropped.
//! MIT `net-server.c` TCP `bufsiz` 1 MiB, `FIELD_TOOLONG` at `msglen > bufsiz-4`.
//! Persist round-trip and UDP listener adversarial tests.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, string_to_key};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};
use krb5_kdc::{S2K_ITERS, serve_until, shared_store};
use krb5_protocol::{as_req, pa_enc_timestamp};

use krb5_config::listen::ListenAddr;
use krb5_types::{PrincipalName, err};
use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn listener_retransmit_resends_the_cached_reply_like_replay_c() {
    // MIT: `dispatch` (dispatch.c:114-140)
    // with the kdc/replay.c lookaside, an identical
    // request resent to the listener is answered from the cache, so the second reply is
    // byte-for-byte the first, not a freshly minted AS-REP (new session key).
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let (store, _) = bootstrap_documented().unwrap();
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let addr = udp.local_addr().unwrap();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve_until(
            store,
            udp,
            tcp,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            krb5_kdc::ListenLimits::default(),
            &krb5_kdc::KdcLog::process(),
        );
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
            &krb5_kdc::KdcLog::process(),
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
    // MIT: `loop_add_addresses` (lib/apputils/net-server.c:381-433)
    // every entry of a list
    // is added, and `kdc_tcp_listen` is its own list; the first-binds-wins candidate walk
    // answered on one address only.
    use krb5_kdc::{bind_tcp_listeners, bind_udp_listeners, serve_all_until};
    let conf = krb5_config::KdcConf::parse(
        "[kdcdefaults]\n    kdc_listen = 127.0.0.1:0, 127.0.0.2:0\n    kdc_tcp_listen = 127.0.0.1:0;127.0.0.2:0\n",
    )
    .unwrap();
    let udp = bind_udp_listeners(&conf.kdc_udp_listeners().unwrap()).unwrap();
    let tcp = bind_tcp_listeners(&conf.kdc_tcp_listeners().unwrap()).unwrap();
    assert_eq!((udp.len(), tcp.len()), (2, 2));
    // MIT: `setup_socket` (lib/apputils/net-server.c:861-875)
    // only a wildcard socket asks for pktinfo.
    assert!(!udp.iter().any(asks_pktinfo));
    let udp_addrs: Vec<_> = udp.iter().map(|s| s.local_addr().unwrap()).collect();
    let tcp_addrs: Vec<_> = tcp.iter().map(|s| s.local_addr().unwrap()).collect();
    let (store, _) = bootstrap_documented().unwrap();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve_all_until(
            store,
            udp,
            tcp,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            krb5_kdc::ListenLimits::default(),
            &krb5_kdc::KdcLog::process(),
        );
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
    // MIT: `setup_addresses` (lib/apputils/net-server.c:1011-1036)
    // both addresses of the wildcard are set up.
    // MIT: `create_server_socket` (lib/apputils/net-server.c:647-658)
    // the IPv6 one is `IPV6_V6ONLY`.
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
    use krb5_kdc::{bind_tcp_listeners, bind_udp_listeners, serve_all_until};
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
        let _ = serve_all_until(
            store,
            udp,
            tcp,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            krb5_kdc::ListenLimits::default(),
            &krb5_kdc::KdcLog::process(),
        );
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
