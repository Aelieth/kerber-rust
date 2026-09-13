//! W1-B B1: after PREAUTH_REQUIRED, pick the first runnable mechanism
//! in MIT `sort_krb5_padata_sequence` order (`get_in_tkt.c:400-471`,
//! `preauth2.c:649-713`). Default preferred is `17, 16, 15, 14`; the
//! remainder keeps hint order, so advertised 151 is tried before 2.
//! Live oracle: `client-differential-gate.sh` `MIT_preauth_cascade`.

use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use krb5_asn1::{decode, encode};
use krb5_protocol::{
    AsRequest, AsTicketOpts, DEFAULT_PREFERRED_PREAUTH_TYPES, KdcAddr, as_exchange,
    sort_krb5_padata_sequence,
};
use krb5_types::{
    AsReq, KerberosTime, KrbError, MethodData, Microseconds, PaData, PrincipalName, ascii, err, pa,
};

fn isolate_host_krb5() {
    krb5_config::isolate_test_krb5();
}

fn mit_hint() -> MethodData {
    [136, 19, 16, 147, 151, 2, 150, 133]
        .into_iter()
        .map(|padata_type| PaData {
            padata_type,
            padata_value: Vec::<u8>::new().into(),
        })
        .collect()
}

#[test]
fn b1_sort_krb5_padata_sequence_default_puts_pkinit_first() {
    let sorted = sort_krb5_padata_sequence(&mit_hint(), DEFAULT_PREFERRED_PREAUTH_TYPES);
    let types: Vec<i32> = sorted.iter().map(|p| p.padata_type).collect();
    assert_eq!(
        types,
        vec![16, 136, 19, 147, 151, 2, 150, 133],
        "get_in_tkt.c:400-471 default preferred 17,16,15,14 bubbles 16 first"
    );
}

#[test]
fn b1_sort_krb5_padata_sequence_preferred_151_first() {
    let sorted = sort_krb5_padata_sequence(&mit_hint(), &[151]);
    let types: Vec<i32> = sorted.iter().map(|p| p.padata_type).collect();
    assert_eq!(types[0], pa::SPAKE);
    assert!(
        types.iter().position(|&t| t == pa::SPAKE).unwrap()
            < types.iter().position(|&t| t == pa::ENC_TIMESTAMP).unwrap()
    );
}

#[test]
fn b1_sort_krb5_padata_sequence_preferred_2_first() {
    let sorted = sort_krb5_padata_sequence(&mit_hint(), &[2]);
    let types: Vec<i32> = sorted.iter().map(|p| p.padata_type).collect();
    assert_eq!(types[0], pa::ENC_TIMESTAMP);
}

#[test]
fn b1_optimistic_hint_picks_spake_before_enc_ts() {
    isolate_host_krb5();
    let shots = Arc::new(Mutex::new(Vec::new()));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let shots2 = shots.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut n_req = 0;
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            if let Ok(req) = decode::<AsReq>(&buf[..n]) {
                let types: Vec<i32> = req
                    .0
                    .padata
                    .unwrap_or_default()
                    .iter()
                    .map(|p| p.padata_type)
                    .collect();
                shots2.lock().unwrap().push(types);
            }
            n_req += 1;
            let reply = if n_req == 1 {
                encode_preauth_required(&mit_hint())
            } else {
                encode_preauth_failed()
            };
            let _ = udp.send_to(&reply, src);
            if n_req >= 2 {
                break;
            }
        }
    });
    thread::sleep(Duration::from_millis(20));
    let _ = as_exchange(&AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"userpassword",
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
    });
    let seen = shots.lock().unwrap().clone();
    assert!(
        seen.len() >= 2,
        "PREAUTH_REQUIRED must produce a second AS-REQ, got {seen:?}"
    );
    assert_eq!(
        seen[0],
        vec![pa::AS_FRESHNESS, pa::REQ_ENC_PA_REP],
        "first-shot stays [150, 149], got {:?}",
        seen[0]
    );
    assert!(
        seen[1].contains(&pa::SPAKE),
        "k5_preauth after sort must send 151 before 2, got {:?}",
        seen[1]
    );
    assert!(
        !seen[1].contains(&pa::ENC_TIMESTAMP),
        "default password path must not jump to enc-ts when 151 is advertised, got {:?}",
        seen[1]
    );
}

fn encode_preauth_required(method: &MethodData) -> Vec<u8> {
    encode(&KrbError {
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
        e_data: Some(encode(method).expect("METHOD-DATA").into()),
    })
    .expect("KRB-ERROR")
}

fn encode_preauth_failed() -> Vec<u8> {
    encode(&KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: err::PREAUTH_FAILED,
        crealm: None,
        cname: None,
        realm: ascii("KERBER.TEST"),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        e_text: None,
        e_data: None,
    })
    .expect("KRB-ERROR")
}
