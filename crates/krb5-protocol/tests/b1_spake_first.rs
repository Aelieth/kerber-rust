//! W1-B B1: SPAKE first-shot is 150/149 only.
//! MIT `get_in_tkt.c:807-813` sets `optimistic_padata` only for an explicit
//! preauth list; default kinit (and `preferred_preauth_types = 151`) first-shots
//! empty module padata and gets PREAUTH_REQUIRED 25.
//! Live oracle: `client-differential-gate.sh` `MIT_spake_first_padata`.

#[path = "common/mod.rs"]
mod common;
use common::isolate_host_krb5;

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use krb5_asn1::decode;
use krb5_protocol::{AsRequest, AsTicketOpts, KdcAddr, as_exchange};
use krb5_types::{AsReq, KerberosTime, KrbError, Microseconds, PrincipalName, ascii, err, pa};

#[test]
fn b1_spake_first_shot_omits_optimistic_151() {
    isolate_host_krb5();
    let (got, wait) = mpsc::channel();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let Ok((n, src)) = udp.recv_from(&mut buf) else {
            return;
        };
        let reply = encode_preauth_required();
        let _ = udp.send_to(&reply, src);
        let _ = got.send(buf[..n].to_vec());
        while udp.recv_from(&mut buf).is_ok() {}
    });
    thread::spawn(move || {
        let _ = as_exchange(&AsRequest {
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            realm: "KERBER.TEST",
            password: b"userpassword",
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
        });
    });
    let raw = wait
        .recv_timeout(Duration::from_secs(2))
        .expect("SPAKE client must send an AS-REQ");
    assert!(!raw.is_empty(), "SPAKE client must send an AS-REQ");
    let req: AsReq = decode(&raw).expect("AS-REQ");
    let types: Vec<i32> = req
        .0
        .padata
        .unwrap_or_default()
        .iter()
        .map(|p| p.padata_type)
        .collect();
    assert_eq!(
        types,
        vec![pa::AS_FRESHNESS, pa::REQ_ENC_PA_REP],
        "get_in_tkt.c:807-813 first-shot is [150, 149], got {types:?}"
    );
}

fn encode_preauth_required() -> Vec<u8> {
    krb5_asn1::encode(&KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: err::PREAUTH_REQUIRED,
        crealm: None,
        cname: None,
        realm: ascii("KERBER.TEST"),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        e_text: None,
        e_data: None,
    })
    .expect("KRB-ERROR")
}
