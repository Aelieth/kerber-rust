//! W1-J L3b: the client verifies the enc-pa-rep echo over the AS-REQ and
//! rejects a reply that sets enc-pa-rep without a PA-REQ-ENC-PA-REP checksum
//! (MIT `krb5int_fast_verify_nego`, `KRB5_KDCREP_MODIFIED`).

use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

use krb5_asn1::{decode, encode};
use krb5_kdc::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};
use krb5_protocol::{AsRequest, AsTicketOpts, KdcAddr, as_exchange};
use krb5_types::{AsReq, PrincipalName, pa};

fn isolate_host_krb5() {
    krb5_config::isolate_test_krb5();
}

#[test]
fn as_exchange_rejects_reply_missing_enc_pa_rep_checksum() {
    isolate_host_krb5();
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    // No-preauth so the KDC issues on the first AS-REQ (single round-trip).
    let attrs = store.get_name(&cname).unwrap().attributes & !krb5_kdc::KDB_REQUIRES_PRE_AUTH;
    store
        .apply_admin_fields(&cname, Some(attrs), None, None, None, None, false, None)
        .unwrap();

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        if let Ok((n, src)) = udp.recv_from(&mut buf) {
            // Strip the client's PA-REQ-ENC-PA-REP so issue_as sets enc-pa-rep
            // (L3a) but echoes no checksum.
            if let Ok(mut req) = decode::<AsReq>(&buf[..n]) {
                if let Some(p) = req.0.padata.as_mut() {
                    p.retain(|d| d.padata_type != pa::REQ_ENC_PA_REP);
                }
                if let Ok(stripped) = encode(&req)
                    && let Ok(reply) = krb5_kdc::handle_request(&store, &stripped)
                {
                    let _ = udp.send_to(&reply, src);
                }
            }
        }
    });
    thread::sleep(Duration::from_millis(20));

    let err = as_exchange(&AsRequest {
        cname,
        realm: TEST_REALM,
        password: TEST_USER_PASSWORD,
        kdc: &KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts::default(),
    })
    .expect_err("enc-pa-rep flag without a PA-149 checksum => KDCREP_MODIFIED");
    match err {
        krb5_protocol::Error::ReplyMismatch(m) => {
            assert!(m.contains("modified"), "want KDCREP_MODIFIED text, got {m}");
        }
        other => panic!("want KDCREP_MODIFIED, got {other:?}"),
    }
}
