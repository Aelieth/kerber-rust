//! `kpasswd`'s request for `kadmin/changepw` follows `noaddresses`, as any initial-credentials request does.
//! MIT `main` (`clients/kpasswd/kpasswd.c:63-72`): `kpasswd` sets no address list on its options.
//! MIT `krb5_init_creds_init` (`lib/krb5/krb/get_in_tkt.c:998-1005`): so `noaddresses` absent or true sends none, and false sends `krb5_os_localaddr`'s list.
//! Drives the shipped `krb5-kpasswd` against an in-process KDC that keeps every request; the wrong password ends the run
//! before any password change is sent.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use krb5_kdc::PrincipalStore;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_testkit::scratch_dir;
use krb5_types::{AsReq, HostAddress};

type Seen = Arc<Mutex<Vec<Vec<u8>>>>;

/// Serve `store` on UDP and TCP at one ephemeral port, keeping the bytes of every request.
fn serve(store: PrincipalStore) -> (String, Seen) {
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    udp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let addr = udp.local_addr().unwrap();
    let store = Arc::new(store);
    let seen: Seen = Arc::default();
    let (s_udp, seen_udp) = (store.clone(), seen.clone());
    thread::spawn(move || {
        let mut buf = [0u8; 16384];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            seen_udp.lock().unwrap().push(buf[..n].to_vec());
            if let Ok(reply) = krb5_kdc::handle_request(&*s_udp, &buf[..n]) {
                let _ = udp.send_to(&reply, src);
            }
        }
    });
    let seen_tcp = seen.clone();
    thread::spawn(move || {
        for conn in tcp.incoming() {
            let Ok(mut conn) = conn else { break };
            let (store, seen) = (store.clone(), seen_tcp.clone());
            thread::spawn(move || {
                let mut len = [0u8; 4];
                if conn.read_exact(&mut len).is_err() {
                    return;
                }
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                if conn.read_exact(&mut req).is_err() {
                    return;
                }
                seen.lock().unwrap().push(req.clone());
                if let Ok(reply) = krb5_kdc::handle_request(&*store, &req) {
                    let n = u32::try_from(reply.len()).unwrap();
                    let _ = conn.write_all(&n.to_be_bytes());
                    let _ = conn.write_all(&reply);
                }
            });
        }
    });
    (format!("127.0.0.1:{}", addr.port()), seen)
}

/// Run `krb5-kpasswd user@KERBER.TEST` with a wrong password and `libdefaults` lines added to the profile.
fn kpasswd(kdc: &str, libdefaults: &str) {
    let dir = scratch_dir("ki-kpasswd-addresses");
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        format!(
            "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    \
             dns_lookup_realm = false\n{libdefaults}[realms]\n    KERBER.TEST = {{\n        kdc = {kdc}\n    }}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-kpasswd"))
        .arg(format!("{TEST_USER}@{TEST_REALM}"))
        .env("KRB5_CONFIG", &conf)
        .env_remove("KRB5_PASSWORD")
        .env_remove("KRB5_NEW_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"not-the-password\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    eprintln!(
        "krb5-kpasswd rc={:?}\n{}{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The AS-REQs the KDC kept: each one's service and address field.
fn as_requests(seen: &Seen) -> Vec<(String, Option<Vec<HostAddress>>)> {
    seen.lock()
        .unwrap()
        .iter()
        .filter_map(|raw| krb5_asn1::decode::<AsReq>(raw).ok())
        .map(|req| {
            let sname = req.0.req_body.sname.as_ref().unwrap().components_joined();
            (sname, req.0.req_body.addresses.clone())
        })
        .collect()
}

#[test]
fn the_changepw_request_sends_the_hosts_list_when_noaddresses_is_false_and_none_otherwise() {
    let list = krb5_protocol::os_localaddr().unwrap();
    for (libdefaults, want) in [
        ("", None),
        ("    noaddresses = true\n", None),
        ("    noaddresses = false\n", Some(list)),
    ] {
        let (kdc, seen) = serve(bootstrap_documented().unwrap().0);
        kpasswd(&kdc, libdefaults);
        let reqs = as_requests(&seen);
        reqs.first().expect("the KDC saw an AS-REQ");
        for (sname, addresses) in reqs {
            assert_eq!(sname, "kadmin/changepw");
            assert_eq!(addresses, want, "noaddresses {libdefaults:?}");
        }
    }
}
