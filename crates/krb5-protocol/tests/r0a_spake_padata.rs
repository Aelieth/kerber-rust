//! Round-up R0a: the final SPAKE AS-REQ keeps the advertised PA-AS-FRESHNESS
//! and PA-REQ-ENC-PA-REP behind the cookie and the PA-SPAKE response, in
//! MIT's order (`k5_preauth` copies the cookie, the module adds PA-SPAKE,
//! `init_creds_step_request` appends 150 then 149). Without 149 the KDC echoes
//! no enc-pa-rep checksum and the client fails `KDCREP_MODIFIED` — the CI red
//! `rust-kinit-spake-gate` showed against MIT 1.22.2 at `e5d9e28`…`a8563e1`.

use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use krb5_asn1::decode;
use krb5_kdc::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};
use krb5_protocol::{AsRequest, AsTicketOpts, KdcAddr, as_exchange};
use krb5_types::{AsReq, PrincipalName, pa};

fn isolate_host_krb5() {
    krb5_config::isolate_test_krb5();
}

#[test]
fn spake_response_request_keeps_the_advertised_padata_in_mit_order() {
    isolate_host_krb5();
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let seen: Arc<Mutex<Vec<Vec<i32>>>> = Arc::new(Mutex::new(Vec::new()));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let record = Arc::clone(&seen);
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            if let Ok(req) = decode::<AsReq>(&buf[..n]) {
                let types = req
                    .0
                    .padata
                    .iter()
                    .flatten()
                    .map(|p| p.padata_type)
                    .collect();
                record.lock().unwrap().push(types);
            }
            if let Ok(reply) = krb5_kdc::handle_request(&store, &buf[..n]) {
                let _ = udp.send_to(&reply, src);
            }
        }
    });
    thread::sleep(Duration::from_millis(20));

    as_exchange(&AsRequest {
        cname,
        realm: TEST_REALM,
        password: TEST_USER_PASSWORD,
        kdc: &KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: true,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts::default(),
    })
    .expect("SPAKE AS exchange with enc-pa-rep negotiation");

    let seen = seen.lock().unwrap();
    let last = seen.last().expect("at least one AS-REQ");
    let tail = &last[last.len().saturating_sub(2)..];
    assert_eq!(
        tail,
        [pa::AS_FRESHNESS, pa::REQ_ENC_PA_REP],
        "final SPAKE AS-REQ must end with 150, 149; sent {seen:?}"
    );
    let cookie = last.iter().position(|&t| t == pa::FX_COOKIE);
    let spake = last.iter().position(|&t| t == pa::SPAKE);
    assert!(
        matches!((cookie, spake), (Some(c), Some(s)) if c < s),
        "cookie precedes PA-SPAKE like k5_preauth copy_cookie; sent {last:?}"
    );
}
