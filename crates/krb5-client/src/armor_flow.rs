//! P6g r5: armor is armed on the first AS-REQ only when the cache has `fast_avail`.
//! Otherwise the first request is unarmored, a KDC error carrying PA-FX-FAST restarts
//! with armor, and a cache that cannot be read then fails with MIT's prefixed text.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use krb5_asn1::{decode, encode};
use krb5_config::CcSpec;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};
use krb5_kdc::{serve, shared_store};
use krb5_protocol::KdcAddr;
use krb5_types::{AsReq, KrbError, MethodData, pa};

use crate::{KinitParams, kinit_prompted, kinit_with, load_ccache, mit_error_code, store_ccache};

const FX_FAST: i32 = pa::FX_FAST;

struct Captured {
    addr: KdcAddr,
    reqs: Arc<Mutex<Vec<Vec<i32>>>>,
}

fn pin_conf(extra_realms: &str) {
    krb5_config::isolate_test_krb5();
    let dir = krb5_testkit::scratch_dir("p6g-r5-conf");
    let path = dir.join("krb5.conf");
    std::fs::write(
        &path,
        format!(
            "[libdefaults]\n    default_realm = {TEST_REALM}\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n    udp_preference_limit = 60000\n    spake_preauth_groups = nosuch\n{extra_realms}"
        ),
    )
    .unwrap();
    krb5_config::set_test_krb5_paths(Some(vec![path]));
}

fn boot(strip_fx_fast: bool) -> Captured {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (kdc_udp, kdc_tcp) = krb5_testkit::loopback_udp_tcp();
    let kdc_udp_addr = kdc_udp.local_addr().expect("kdc udp");
    let kdc_tcp_addr = kdc_tcp.local_addr().expect("kdc tcp");
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve(store, kdc_udp, kdc_tcp);
    });
    let (proxy_udp, proxy_tcp) = krb5_testkit::loopback_udp_tcp();
    let port = proxy_udp.local_addr().expect("proxy udp").port();
    let reqs = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&reqs);
    thread::spawn(move || udp_proxy(proxy_udp, kdc_udp_addr, seen, strip_fx_fast));
    let seen = Arc::clone(&reqs);
    thread::spawn(move || tcp_proxy(proxy_tcp, kdc_tcp_addr, seen, strip_fx_fast));
    Captured {
        addr: KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        reqs,
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the proxy thread owns the socket and the request log"
)]
fn udp_proxy(sock: UdpSocket, kdc: SocketAddr, seen: Arc<Mutex<Vec<Vec<i32>>>>, strip: bool) {
    let _ = sock.set_read_timeout(Some(Duration::from_secs(20)));
    let mut buf = vec![0u8; 65535];
    while let Ok((n, src)) = sock.recv_from(&mut buf) {
        note(&seen, &buf[..n]);
        if sock.send_to(&buf[..n], kdc).is_err() {
            break;
        }
        let Ok((m, _)) = sock.recv_from(&mut buf) else {
            break;
        };
        let reply = if strip {
            strip_fx_fast(&buf[..m])
        } else {
            buf[..m].to_vec()
        };
        let _ = sock.send_to(&reply, src);
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the proxy thread owns the listener and the request log"
)]
fn tcp_proxy(listener: TcpListener, kdc: SocketAddr, seen: Arc<Mutex<Vec<Vec<i32>>>>, strip: bool) {
    let _ = listener.set_nonblocking(false);
    for conn in listener.incoming() {
        let Ok(mut client) = conn else {
            break;
        };
        let _ = client.set_read_timeout(Some(Duration::from_secs(20)));
        let Ok(mut upstream) = TcpStream::connect(kdc) else {
            break;
        };
        let _ = upstream.set_read_timeout(Some(Duration::from_secs(20)));
        while let Ok(req) = read_frame(&mut client) {
            note(&seen, &req);
            if write_frame(&mut upstream, &req).is_err() {
                break;
            }
            let Ok(rep) = read_frame(&mut upstream) else {
                break;
            };
            let rep = if strip { strip_fx_fast(&rep) } else { rep };
            if write_frame(&mut client, &rep).is_err() {
                break;
            }
        }
    }
}

fn note(seen: &Mutex<Vec<Vec<i32>>>, req: &[u8]) {
    if req.first() != Some(&0x6a) {
        return;
    }
    let Ok(mut guard) = seen.lock() else {
        return;
    };
    guard.push(padata_types(req));
}

fn padata_types(req: &[u8]) -> Vec<i32> {
    decode::<AsReq>(req)
        .ok()
        .and_then(|r| r.0.padata)
        .map(|p| p.iter().map(|pa| pa.padata_type).collect())
        .unwrap_or_default()
}

fn strip_fx_fast(bytes: &[u8]) -> Vec<u8> {
    if bytes.first() != Some(&0x7e) {
        return bytes.to_vec();
    }
    let Ok(mut err) = decode::<KrbError>(bytes) else {
        return bytes.to_vec();
    };
    let Some(ed) = err.e_data.as_ref() else {
        return bytes.to_vec();
    };
    let Ok(mut method) = decode::<MethodData>(ed.as_ref()) else {
        return bytes.to_vec();
    };
    let before = method.len();
    method.retain(|p| p.padata_type != FX_FAST);
    if method.len() == before {
        return bytes.to_vec();
    }
    let Ok(body) = encode(&method) else {
        return bytes.to_vec();
    };
    err.e_data = Some(body.into());
    encode(&err).unwrap_or_else(|_| bytes.to_vec())
}

fn read_frame(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut lenb = [0u8; 4];
    s.read_exact(&mut lenb)?;
    let n = usize::try_from(u32::from_be_bytes(lenb)).unwrap_or(0);
    let mut body = vec![0u8; n];
    s.read_exact(&mut body)?;
    Ok(body)
}

fn write_frame(s: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    let Ok(n) = u32::try_from(body.len()) else {
        return Err(std::io::Error::other("frame too long"));
    };
    s.write_all(&n.to_be_bytes())?;
    s.write_all(body)
}

fn reqs_of(cap: &Captured) -> Vec<Vec<i32>> {
    cap.reqs.lock().expect("reqs").clone()
}

fn clear_reqs(cap: &Captured) {
    cap.reqs.lock().expect("reqs").clear();
}

fn out_spec(name: &str) -> CcSpec {
    let dir = krb5_testkit::scratch_dir(name);
    CcSpec::File(dir.join("out.cc"))
}

fn kinit_pw(cap: &Captured, armor: Option<&CcSpec>, out: &CcSpec) -> Result<(), String> {
    let mut pw = TEST_USER_PASSWORD.to_vec();
    let params = KinitParams {
        armor_ccache: armor,
        ..KinitParams::default()
    };
    kinit_with(
        &cap.addr,
        &format!("{TEST_USER}@{TEST_REALM}"),
        &mut pw,
        out,
        params,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn assert_prefixed(err: &str, expected: &str, reqs: &[Vec<i32>]) {
    assert_eq!(
        reqs.len(),
        1,
        "one AS-REQ then the armor error, got {reqs:?} ({err})"
    );
    assert!(
        !reqs[0].contains(&FX_FAST),
        "the first AS-REQ is unarmored, got {:?}",
        reqs[0]
    );
    assert_eq!(err, expected);
}

#[test]
fn empty_memory_armor_sends_one_unarmored_request_then_mits_prefix() {
    pin_conf("");
    let cap = boot(false);
    let armor = CcSpec::Memory("p6g-r5-no-such-memory".into());
    let err = kinit_pw(&cap, Some(&armor), &out_spec("p6g-r5-mem-out")).unwrap_err();
    assert_prefixed(
        &err,
        "Error constructing AP-REQ armor: No credentials cache found",
        &reqs_of(&cap),
    );
}

#[test]
fn missing_file_armor_sends_one_unarmored_request_then_the_filename() {
    pin_conf("");
    let cap = boot(false);
    let path: PathBuf = krb5_testkit::scratch_dir("p6g-r5-missing-file").join("no-such-armor.cc");
    let armor = CcSpec::File(path.clone());
    let err = kinit_pw(&cap, Some(&armor), &out_spec("p6g-r5-file-out")).unwrap_err();
    assert_prefixed(
        &err,
        &format!(
            "Error constructing AP-REQ armor: No credentials cache found (filename: {})",
            path.display()
        ),
        &reqs_of(&cap),
    );
}

#[test]
fn a_kdc_that_sends_no_fx_fast_issues_an_unarmored_ticket() {
    pin_conf("");
    let cap = boot(true);
    let armor = CcSpec::Memory("p6g-r5-nofast-memory".into());
    let got = kinit_pw(&cap, Some(&armor), &out_spec("p6g-r5-nofast-out"));
    let reqs = reqs_of(&cap);
    let Err(err) = got else {
        assert!(
            reqs.iter().all(|p| !p.contains(&FX_FAST)),
            "an unarmored ticket's requests carry no PA-FX-FAST, got {reqs:?}"
        );
        assert!(!reqs.is_empty(), "the KDC was asked");
        return;
    };
    panic!(
        "missing armor must still get a ticket when the KDC sends no PA-FX-FAST: {err} reqs={reqs:?}"
    );
}

#[test]
fn armor_without_fast_avail_upgrades_on_fx_fast() {
    pin_conf("");
    let cap = boot(false);
    let held = out_spec("p6g-r5-armor-src");
    kinit_pw(&cap, None, &held).expect("armor TGT");
    let mut cc = load_ccache(&held).expect("read armor");
    cc.creds.retain(|c| {
        !(c.is_config()
            && c.server
                .1
                .name_string
                .get(1)
                .is_some_and(|s| s.as_bytes() == b"fast_avail"))
    });
    let bare = CcSpec::File(krb5_testkit::scratch_dir("p6g-r5-armor-bare").join("bare.cc"));
    store_ccache(&bare, cc).expect("store armor without fast_avail");
    clear_reqs(&cap);
    kinit_pw(&cap, Some(&bare), &out_spec("p6g-r5-upgraded")).expect("upgraded AS");
    let reqs = reqs_of(&cap);
    assert!(
        reqs.len() >= 2,
        "unarmored try then an armored retry, got {reqs:?}"
    );
    assert!(
        !reqs[0].contains(&FX_FAST),
        "first request unarmored: {:?}",
        reqs[0]
    );
    assert!(
        reqs[1].contains(&FX_FAST),
        "second request armored: {:?}",
        reqs[1]
    );
}

#[test]
fn fast_avail_arms_the_first_request() {
    pin_conf("");
    let cap = boot(false);
    let held = out_spec("p6g-r5-avail-src");
    kinit_pw(&cap, None, &held).expect("armor TGT with fast_avail");
    clear_reqs(&cap);
    kinit_pw(&cap, Some(&held), &out_spec("p6g-r5-avail-out")).expect("armed first");
    let reqs = reqs_of(&cap);
    assert!(!reqs.is_empty(), "a request was sent");
    assert!(
        reqs[0].contains(&FX_FAST),
        "fast_avail arms the first AS-REQ, got {reqs:?}"
    );
}

#[test]
fn disable_encrypted_timestamp_does_not_prompt_and_fails() {
    pin_conf(&format!(
        "[realms]\n    {TEST_REALM} = {{\n        disable_encrypted_timestamp = true\n    }}\n"
    ));
    let cap = boot(false);
    let mut prompts = 0u32;
    let mut prompt = || {
        prompts += 1;
        Ok(TEST_USER_PASSWORD.to_vec())
    };
    let result = kinit_prompted(
        &cap.addr,
        &format!("{TEST_USER}@{TEST_REALM}"),
        &mut prompt,
        &out_spec("p6g-r5-encts"),
        KinitParams::default(),
    );
    let Err(err) = result else {
        panic!("disable_encrypted_timestamp must fail, prompts={prompts}");
    };
    assert_eq!(
        prompts, 0,
        "encrypted timestamp asks for no key when disabled"
    );
    assert_eq!(err.to_string(), "Encrypted timestamp is disabled");
    let proto = err
        .downcast_ref::<krb5_protocol::Error>()
        .expect("encts failure is the protocol error");
    assert_eq!(
        super::Krb5Error::from_protocol(proto, TEST_REALM).to_string(),
        "Pre-authentication failed: Encrypted timestamp is disabled"
    );
    assert_eq!(
        mit_error_code(err.as_ref()),
        Some(krb5_types::err::PREAUTH_FAILED)
    );
    let reqs = reqs_of(&cap);
    assert_eq!(
        reqs.len(),
        1,
        "one unarmored AS-REQ, then the client fails: {reqs:?}"
    );
    assert!(!reqs[0].contains(&FX_FAST));
}
