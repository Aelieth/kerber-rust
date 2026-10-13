//! `kinit -a`, a false `noaddresses` and the changepw request carry `krb5_os_localaddr`'s list.
//! MIT `k5_kinit` (`clients/kinit/kinit.c:674-683`): `-a` sets that list as the request's and `-A` none.
//! MIT `krb5_init_creds_init` (`lib/krb5/krb/get_in_tkt.c:998-1005`): with neither, `noaddresses` absent or true sends none, and false sends that list.
//! MIT `make_chpw_options` (`lib/krb5/krb/gic_pwd.c:163-163`): the changepw request drops the list the caller set.
//! Drives the shipped `krb5-kinit` against an in-process KDC that keeps every request, and compares the
//! address field of each AS-REQ with this host's own list, so the host's one route towards the KDC picks nothing.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use krb5_kdc::principals::kadmin_changepw;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_kdc::{KDB_REQUIRES_PWCHANGE, PrincipalStore};
use krb5_testkit::scratch_dir;
use krb5_types::{AsReq, HostAddress, PrincipalName};

type Seen = Arc<Mutex<Vec<Vec<u8>>>>;

/// Serve `store` on UDP and TCP at one ephemeral port, keeping the bytes of every request;
/// returns `host:port` and the requests.
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

/// `user` set `+needchange`, and no `kadmin/changepw`: the TGT request is KEY_EXP, and the changepw
/// request that follows is answered at once, so the change itself is never sent.
fn expired_user_without_changepw() -> PrincipalStore {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let attrs = store.get_name(&user).unwrap().attributes | KDB_REQUIRES_PWCHANGE;
    store
        .apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(attrs),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    store.remove_in(&kadmin_changepw(), TEST_REALM).unwrap();
    store
}

/// Run `krb5-kinit -c cc <args> user@KERBER.TEST` with `libdefaults` lines added to the profile.
fn kinit(kdc: &str, libdefaults: &str, args: &[&str]) {
    let dir = scratch_dir("ki-kinit-addresses");
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        format!(
            "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    \
             dns_lookup_realm = false\n{libdefaults}[realms]\n    KERBER.TEST = {{\n        kdc = {kdc}\n    }}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-kinit"))
        .arg("-c")
        .arg(dir.join("cc"))
        .args(args)
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
        .write_all(b"userpassword\nnew-pw\nnew-pw\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    eprintln!(
        "krb5-kinit {args:?} rc={:?}\n{}{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The requests the KDC kept: each AS-REQ's service and address field.
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

/// This host's own list: what `krb5_os_localaddr` gives.
fn host_list() -> Vec<HostAddress> {
    krb5_protocol::os_localaddr().unwrap()
}

#[test]
fn dash_a_sends_every_up_interface_address() {
    let (kdc, seen) = serve(bootstrap_documented().unwrap().0);
    kinit(&kdc, "", &["-a"]);
    let reqs = as_requests(&seen);
    reqs.first().expect("the KDC saw an AS-REQ");
    for (sname, addresses) in reqs {
        assert_eq!(addresses, Some(host_list()), "the AS-REQ for {sname}");
    }
}

#[test]
fn a_false_noaddresses_sends_the_same_list_and_a_default_sends_none() {
    let (kdc, seen) = serve(bootstrap_documented().unwrap().0);
    kinit(&kdc, "    noaddresses = false\n", &[]);
    let reqs = as_requests(&seen);
    reqs.first().expect("the KDC saw an AS-REQ");
    for (sname, addresses) in reqs {
        assert_eq!(addresses, Some(host_list()), "the AS-REQ for {sname}");
    }
    let (kdc, seen) = serve(bootstrap_documented().unwrap().0);
    kinit(&kdc, "", &[]);
    assert!(
        as_requests(&seen).iter().all(|(_, a)| a.is_none()),
        "no -a and no noaddresses sends no address field"
    );
    let (kdc, seen) = serve(bootstrap_documented().unwrap().0);
    kinit(&kdc, "    noaddresses = true\n", &[]);
    assert!(as_requests(&seen).iter().all(|(_, a)| a.is_none()));
}

#[test]
fn dash_capital_a_sends_none_whatever_noaddresses_says() {
    let (kdc, seen) = serve(bootstrap_documented().unwrap().0);
    kinit(&kdc, "    noaddresses = false\n", &["-A"]);
    let reqs = as_requests(&seen);
    reqs.first().expect("the KDC saw an AS-REQ");
    assert!(reqs.iter().all(|(_, a)| a.is_none()), "{reqs:?}");
}

/// The changepw request drops `-a`'s list and follows `noaddresses` alone.
#[test]
fn the_changepw_request_follows_noaddresses_not_dash_a() {
    let by_service = |reqs: &[(String, Option<Vec<HostAddress>>)], want: &str| {
        reqs.iter()
            .filter(|(s, _)| s.starts_with(want))
            .map(|(_, a)| a.clone())
            .collect::<Vec<_>>()
    };
    // `-a` and no `noaddresses`: the TGT request has the list, the changepw request none.
    let (kdc, seen) = serve(expired_user_without_changepw());
    kinit(&kdc, "", &["-a"]);
    let reqs = as_requests(&seen);
    assert_eq!(by_service(&reqs, "krbtgt"), [Some(host_list())], "{reqs:?}");
    assert_eq!(by_service(&reqs, "kadmin"), [None], "{reqs:?}");
    // A false `noaddresses` and no `-a`: both requests have it.
    let (kdc, seen) = serve(expired_user_without_changepw());
    kinit(&kdc, "    noaddresses = false\n", &[]);
    let reqs = as_requests(&seen);
    assert_eq!(by_service(&reqs, "krbtgt"), [Some(host_list())], "{reqs:?}");
    assert_eq!(by_service(&reqs, "kadmin"), [Some(host_list())], "{reqs:?}");
}
