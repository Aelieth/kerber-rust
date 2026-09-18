//! W1-B B2: `kvno -U` emits PA-S4U-X509-USER 130 and PA-FOR-USER 129
//! on the FAST TGS outer list (`s4u_creds.c:517-567`, `fast.c:227-250`)
//! and `verify_s4u2self_reply` (`s4u_creds.c:273-397`) fails closed.
//! Live oracle: `client-differential-gate.sh` `MIT_kvno_U_tgs_padata`.
//! `verify_s4u2self_reply` is new at the parent so a re-export inject
//! does not compile; the live MIT `kvno -U` cell is the production oracle.

#[path = "common/mod.rs"]
mod common;
use common::isolate_host_krb5;

use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::thread;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, ProtocolKey, unkeyed_checksum};
use krb5_protocol::{
    AsOutcome, KdcAddr, pa_s4u_x509_user, tgs_s4u, tgs_s4u2proxy, verify_s4u2self_reply,
};
use krb5_types::{
    EncKdcRepPart, EncryptedData, EncryptionKey, KerberosTime, KrbError, Microseconds, OctetString,
    PaData, PrincipalName, TgsReq, Ticket, TicketFlags, ascii, err, pa,
};

fn session() -> ProtocolKey {
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[7u8; 32]).unwrap()
}

fn fake_tgt() -> AsOutcome {
    let t = KerberosTime::now();
    let sname = PrincipalName::krbtgt("KERBER.TEST");
    AsOutcome {
        ticket: Ticket {
            tkt_vno: Ticket::VNO,
            realm: ascii("KERBER.TEST"),
            sname: sname.clone(),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![0u8; 16]),
            },
        },
        enc_part: EncKdcRepPart {
            key: EncryptionKey {
                keytype: 18,
                keyvalue: OctetString::from(vec![7u8; 32]),
            },
            last_req: vec![],
            nonce: 1,
            key_expiration: None,
            flags: TicketFlags::none(),
            authtime: t.clone(),
            starttime: None,
            endtime: t,
            renew_till: None,
            srealm: ascii("KERBER.TEST"),
            sname,
            caddr: None,
            encrypted_pa_data: None,
        },
        client_key: session(),
        session_key: session(),
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["host"]),
        crealm: ascii("KERBER.TEST"),
        fast_avail: false,
        used_fast: false,
        pa_type: None,
    }
}

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"])
}

fn encode_generic() -> Vec<u8> {
    encode(&KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: err::GENERIC,
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
fn b2_s4u_tgs_outer_padata_is_1_136_130_129() {
    isolate_host_krb5();
    let shots = Arc::new(Mutex::new(Vec::new()));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let shots2 = shots.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        if let Ok((n, src)) = udp.recv_from(&mut buf) {
            *shots2.lock().unwrap() = buf[..n].to_vec();
            let _ = udp.send_to(&encode_generic(), src);
        }
    });
    let _ = tgs_s4u(
        &KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        &fake_tgt(),
        PrincipalName::try_new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"])
            .unwrap(),
        "KERBER.TEST",
        &user(),
        "KERBER.TEST",
    );
    let raw = shots.lock().unwrap().clone();
    assert!(!raw.is_empty(), "tgs_s4u must send a TGS-REQ");
    let req: TgsReq = decode(&raw).expect("TGS-REQ");
    let types: Vec<i32> = req
        .0
        .padata
        .unwrap_or_default()
        .iter()
        .map(|p| p.padata_type)
        .collect();
    assert_eq!(
        types,
        vec![pa::TGS_REQ, pa::FX_FAST, pa::FOR_X509_USER, pa::FOR_USER],
        "s4u_creds.c + fast.c outer TGS padata is [1, 136, 130, 129], got {types:?}"
    );
}

#[test]
fn b2_s4u_verify_missing_both_is_ok() {
    let key = session();
    let req = decode_pa130(&pa_s4u_x509_user(&key, user(), "KERBER.TEST", 42).unwrap());
    verify_s4u2self_reply(&key, &req, None, None).expect("no 130 is ok");
}

#[test]
fn b2_s4u_verify_enc_only_is_modified() {
    let key = session();
    let pa = pa_s4u_x509_user(&key, user(), "KERBER.TEST", 42).unwrap();
    let req = decode_pa130(&pa);
    let enc = vec![pa];
    let err = verify_s4u2self_reply(&key, &req, None, Some(&enc)).unwrap_err();
    assert!(
        matches!(err, krb5_protocol::Error::ReplyMismatch(_)),
        "enc-only 130 is KDCREP_MODIFIED, got {err}"
    );
}

#[test]
fn b2_s4u_verify_valid_is_ok() {
    let key = session();
    let pa = pa_s4u_x509_user(&key, user(), "KERBER.TEST", 42).unwrap();
    let req = decode_pa130(&pa);
    // Request uses ku 26; reply with USE_REPLY_KEY_USAGE uses ku 27.
    let reply = reply_130(&key, &req);
    verify_s4u2self_reply(&key, &req, Some(std::slice::from_ref(&reply)), None)
        .expect("matching reply 130");
}

#[test]
fn b2_s4u_verify_bad_nonce_is_modified() {
    let key = session();
    let pa = pa_s4u_x509_user(&key, user(), "KERBER.TEST", 42).unwrap();
    let req = decode_pa130(&pa);
    let mut other = req.clone();
    other.user_id.nonce = 99;
    let reply = reply_from_userid(&key, &other);
    let err =
        verify_s4u2self_reply(&key, &req, Some(std::slice::from_ref(&reply)), None).unwrap_err();
    assert!(matches!(err, krb5_protocol::Error::ReplyMismatch(_)));
}

#[test]
fn b2_s4u_verify_user_mismatch_is_modified() {
    let key = session();
    let pa = pa_s4u_x509_user(&key, user(), "KERBER.TEST", 42).unwrap();
    let req = decode_pa130(&pa);
    let other_user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["other"]);
    let mut other = req.clone();
    other.user_id.user = Some(other_user);
    let reply = reply_from_userid(&key, &other);
    let err =
        verify_s4u2self_reply(&key, &req, Some(std::slice::from_ref(&reply)), None).unwrap_err();
    assert!(matches!(err, krb5_protocol::Error::ReplyMismatch(_)));
}

#[test]
fn b2_s4u_verify_unkeyed_is_inapp() {
    let key = session();
    let pa = pa_s4u_x509_user(&key, user(), "KERBER.TEST", 42).unwrap();
    let req = decode_pa130(&pa);
    let der = encode(&req.user_id).unwrap();
    let mac = unkeyed_checksum(7, &der).unwrap();
    let mut body = req.clone();
    body.cksum.cksumtype = 7;
    body.cksum.checksum = mac.into();
    let reply = PaData {
        padata_type: pa::FOR_X509_USER,
        padata_value: encode(&body).unwrap().into(),
    };
    let err =
        verify_s4u2self_reply(&key, &req, Some(std::slice::from_ref(&reply)), None).unwrap_err();
    match err {
        krb5_protocol::Error::KrbError { code, .. } => assert_eq!(code, err::INAPP_CKSUM),
        other => panic!("want INAPP_CKSUM, got {other}"),
    }
}

fn decode_pa130(pa: &PaData) -> krb5_types::s4u::PaS4uX509User {
    decode(pa.padata_value.as_ref()).expect("PA-S4U-X509-USER")
}

fn reply_130(key: &ProtocolKey, req: &krb5_types::s4u::PaS4uX509User) -> PaData {
    reply_from_userid(key, req)
}

fn reply_from_userid(key: &ProtocolKey, req: &krb5_types::s4u::PaS4uX509User) -> PaData {
    use krb5_crypto::{KeyUsage, checksum};
    use krb5_types::ku;
    let user_id = krb5_types::s4u::S4uUserId {
        nonce: req.user_id.nonce,
        user: req.user_id.user.clone(),
        realm: req.user_id.realm.clone(),
        subject_cert: None,
        options: Some(krb5_types::s4u::s4u_reply_key_usage_flags()),
    };
    let der = encode(&user_id).unwrap();
    let usage = KeyUsage::new(ku::PA_S4U_X509_USER_REPLY).unwrap();
    let mic = checksum(key, usage, &der).unwrap();
    let body = krb5_types::s4u::PaS4uX509User {
        user_id,
        cksum: krb5_types::Checksum {
            cksumtype: key.etype().checksum_type(),
            checksum: mic.into(),
        },
    };
    PaData {
        padata_type: pa::FOR_X509_USER,
        padata_value: encode(&body).unwrap().into(),
    }
}

#[test]
fn b2_s4u2proxy_outer_padata_is_1_136_167() {
    isolate_host_krb5();
    let shots = Arc::new(Mutex::new(Vec::new()));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let shots2 = shots.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        if let Ok((n, src)) = udp.recv_from(&mut buf) {
            *shots2.lock().unwrap() = buf[..n].to_vec();
            let _ = udp.send_to(&encode_generic(), src);
        }
    });
    let tgt = fake_tgt();
    let evidence = tgt.ticket.clone();
    let _ = tgs_s4u2proxy(
        &KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        &tgt,
        PrincipalName::try_new(PrincipalName::NT_SRV_HST, ["host", "other.kerber.test"]).unwrap(),
        "KERBER.TEST",
        evidence,
    );
    let raw = shots.lock().unwrap().clone();
    assert!(!raw.is_empty(), "tgs_s4u2proxy must send a TGS-REQ");
    let req: TgsReq = decode(&raw).expect("TGS-REQ");
    let types: Vec<i32> = req
        .0
        .padata
        .unwrap_or_default()
        .iter()
        .map(|p| p.padata_type)
        .collect();
    assert_eq!(
        types,
        vec![pa::TGS_REQ, pa::FX_FAST, pa::PAC_OPTIONS],
        "S4U2Proxy FAST outer TGS padata is [1, 136, 167], got {types:?}"
    );
}
