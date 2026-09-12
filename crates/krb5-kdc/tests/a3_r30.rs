//! A′-3 R30 inject: verify_support 24, PKINIT [16, 147], TGS FAST armor.

use std::net::UdpSocket;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::{Error, TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_protocol::{AsOutcome, KdcAddr, as_req, tgs_exchange};
use krb5_types::{
    EncKdcRepPart, EncryptedData, EncryptionKey, KerberosTime, MethodData, OctetString, PaData,
    PrincipalName, TgsReq, Ticket, TicketFlags, ascii, err, pa,
    spake::{GROUP_EDWARDS25519, PaSpake, SpakeSupport},
};

fn proto(err: &Error) -> (i32, Option<&str>) {
    match err {
        Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn support_groups(groups: &[i32]) -> PaData {
    let msg = PaSpake::Support(SpakeSupport {
        groups: groups.to_vec(),
    });
    PaData {
        padata_type: pa::SPAKE,
        padata_value: encode(&msg).unwrap().into(),
    }
}

#[test]
fn r30_verify_support_unpermitted_offer_is_24() {
    let (store, _) = bootstrap_documented().unwrap();
    let req = as_req(
        user(),
        TEST_REALM,
        30001,
        Some(vec![support_groups(&[GROUP_EDWARDS25519])]),
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    assert_eq!(proto(&err), (err::PREAUTH_FAILED, Some("PREAUTH_FAILED")));
}

#[test]
fn r30_pkinit_hint_is_16_147() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.enable_pkinit_ca().unwrap();
    let req = as_req(user(), TEST_REALM, 30004, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PreauthRequired, got {err:?}");
    };
    let method: MethodData = decode(&e_data).unwrap();
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert!(
        types.contains(&pa::PK_AS_REQ) && types.contains(&pa::PKINIT_KX),
        "PKINIT hint must be [16, 147], got {types:?}"
    );
    assert!(
        !types.contains(&pa::TD_DH_PARAMETERS),
        "PKINIT hint must not list 109, got {types:?}"
    );
}

fn session() -> ProtocolKey {
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[7u8; 32]).unwrap()
}

fn password_as_tgt() -> AsOutcome {
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
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        crealm: ascii("KERBER.TEST"),
        fast_avail: false,
        used_fast: false,
        pa_type: None,
    }
}

#[test]
fn r30_tgs_after_password_as_is_fast_armored() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let addr = sock.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        if let Ok((n, src)) = sock.recv_from(&mut buf) {
            let _ = tx.send(buf[..n].to_vec());
            let _ = sock.send_to(&[0x7e], src);
        }
    });
    let tgt = password_as_tgt();
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]);
    let _ = tgs_exchange(
        &KdcAddr {
            host: "127.0.0.1".into(),
            port: addr.port(),
        },
        &tgt,
        host,
        "KERBER.TEST",
    );
    let wire = rx.recv_timeout(Duration::from_secs(2)).expect("TGS-REQ");
    let tgs: TgsReq = decode(&wire).expect("TgsReq");
    let types: Vec<i32> = tgs
        .0
        .padata
        .as_ref()
        .into_iter()
        .flatten()
        .map(|p| p.padata_type)
        .collect();
    assert!(
        types.contains(&pa::FX_FAST),
        "password-AS TGS must carry 136: {types:?}"
    );
    assert!(
        types.contains(&pa::TGS_REQ),
        "password-AS TGS must carry PA-TGS-REQ: {types:?}"
    );
}
