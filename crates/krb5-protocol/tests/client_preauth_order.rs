//! W1-B B1: after PREAUTH_REQUIRED, pick the first runnable mechanism
//! in MIT `sort_krb5_padata_sequence` order (`get_in_tkt.c:400-471`,
//! `preauth2.c:649-713`). Default preferred is `17, 16, 15, 14`; the
//! remainder keeps hint order, so advertised 151 is tried before 2.
//! Live oracle: `client-differential-gate.sh` `MIT_preauth_cascade`.

#[path = "common/mod.rs"]
mod common;
use common::isolate_host_krb5;
use krb5_asn1::{decode, encode};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};

use krb5_protocol::{
    AsRequest, AsTicketOpts, DEFAULT_PREFERRED_PREAUTH_TYPES, KdcAddr, as_exchange,
    insert_module_padata_before_info_pa, sort_krb5_padata_sequence,
};
use krb5_types::{
    AsReq, KerberosTime, KrbError, MethodData, Microseconds, PaData, PrincipalName, ascii, err, pa,
};
use std::net::UdpSocket;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

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
fn sort_krb5_padata_sequence_default_puts_pkinit_first() {
    let sorted = sort_krb5_padata_sequence(&mit_hint(), DEFAULT_PREFERRED_PREAUTH_TYPES);
    let types: Vec<i32> = sorted.iter().map(|p| p.padata_type).collect();
    assert_eq!(
        types,
        vec![16, 136, 19, 147, 151, 2, 150, 133],
        "get_in_tkt.c:400-471 default preferred 17,16,15,14 bubbles 16 first"
    );
}

#[test]
fn sort_krb5_padata_sequence_preferred_151_first() {
    let sorted = sort_krb5_padata_sequence(&mit_hint(), &[151]);
    let types: Vec<i32> = sorted.iter().map(|p| p.padata_type).collect();
    assert_eq!(types[0], pa::SPAKE);
    assert!(
        types.iter().position(|&t| t == pa::SPAKE).unwrap()
            < types.iter().position(|&t| t == pa::ENC_TIMESTAMP).unwrap()
    );
}

#[test]
fn sort_krb5_padata_sequence_preferred_2_first() {
    let sorted = sort_krb5_padata_sequence(&mit_hint(), &[2]);
    let types: Vec<i32> = sorted.iter().map(|p| p.padata_type).collect();
    assert_eq!(types[0], pa::ENC_TIMESTAMP);
}

#[test]
fn optimistic_hint_picks_spake_before_enc_ts() {
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

#[test]
fn spake_first_shot_omits_optimistic_151() {
    isolate_host_krb5();
    let (got, wait) = mpsc::channel();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let Ok((n, src)) = udp.recv_from(&mut buf) else {
            return;
        };
        let reply = encode_preauth_required_no_edata();
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

fn encode_preauth_required_no_edata() -> Vec<u8> {
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

fn pa_of(ty: i32) -> PaData {
    PaData {
        padata_type: ty,
        padata_value: Vec::new().into(),
    }
}

fn types(list: &[PaData]) -> Vec<i32> {
    list.iter().map(|p| p.padata_type).collect()
}

#[test]
fn pkinit_padata_cookie_then_module_then_info() {
    let mut list = vec![
        pa_of(pa::FX_COOKIE),
        pa_of(pa::AS_FRESHNESS),
        pa_of(pa::REQ_ENC_PA_REP),
    ];
    insert_module_padata_before_info_pa(&mut list, pa_of(pa::PK_AS_REQ));
    assert_eq!(
        types(&list),
        vec![
            pa::FX_COOKIE,
            pa::PK_AS_REQ,
            pa::AS_FRESHNESS,
            pa::REQ_ENC_PA_REP
        ],
        "preauth2.c:992-1019 + get_in_tkt.c:1365-1372 → [133, 16, 150, 149]"
    );
}

#[test]
fn pkinit_padata_module_before_info_without_cookie() {
    let mut list = vec![pa_of(pa::AS_FRESHNESS), pa_of(pa::REQ_ENC_PA_REP)];
    insert_module_padata_before_info_pa(&mut list, pa_of(pa::PK_AS_REQ));
    assert_eq!(
        types(&list),
        vec![pa::PK_AS_REQ, pa::AS_FRESHNESS, pa::REQ_ENC_PA_REP]
    );
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
