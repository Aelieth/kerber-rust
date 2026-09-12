//! A′-3 R33: TGS FAST_REQUIRED swallow + empty-groups stray PA-SPAKE skip.

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_kdc::{Error, TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_protocol::{AsOutcome, KdcAddr, as_req, tgs_exchange};
use krb5_types::{
    ApReq, Authenticator, EncKdcRepPart, EncTgsRepPart, EncryptedData, EncryptionKey, KerberosTime,
    OctetString, PaData, PrincipalName, TgsRep, TgsReq, Ticket, TicketFlags, ascii, ku, pa,
};

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
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

fn unwrapped_tgs_rep(tgt: &AsOutcome, wire: &[u8]) -> Vec<u8> {
    let tgs: TgsReq = decode(wire).expect("TgsReq");
    let pa_tgs = tgs
        .0
        .padata
        .as_ref()
        .into_iter()
        .flatten()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ");
    let ap: ApReq = decode(pa_tgs.padata_value.as_ref()).expect("AP-REQ");
    let usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).unwrap();
    let plain = decrypt(&tgt.session_key, usage, ap.authenticator.cipher.as_ref()).unwrap();
    let auth: Authenticator = decode(&plain).expect("Authenticator");
    let subk = auth.subkey.expect("TGS subkey");
    let sub = ProtocolKey::from_bytes(
        EncryptionType::known(subk.keytype).unwrap(),
        subk.keyvalue.as_ref(),
    )
    .unwrap();
    let sname = tgs.0.req_body.sname.clone().expect("sname");
    let t = KerberosTime::now();
    let enc = EncKdcRepPart {
        key: EncryptionKey {
            keytype: 18,
            keyvalue: OctetString::from(vec![9u8; 32]),
        },
        last_req: vec![],
        nonce: tgs.0.req_body.nonce,
        key_expiration: None,
        flags: TicketFlags::none(),
        authtime: t.clone(),
        starttime: None,
        endtime: t.clone(),
        renew_till: None,
        srealm: ascii("KERBER.TEST"),
        sname: sname.clone(),
        caddr: None,
        encrypted_pa_data: None,
    };
    let enc_der = encode(&EncTgsRepPart(enc)).unwrap();
    let enc_usage = KeyUsage::new(ku::TGS_REP_ENC_PART_SUBKEY).unwrap();
    let cipher = encrypt(&sub, enc_usage, &enc_der).unwrap();
    let rep = TgsRep(krb5_types::KdcRep {
        pvno: krb5_types::KdcRep::PVNO,
        msg_type: krb5_types::KdcRep::MSG_TGS_REP,
        padata: None,
        crealm: tgt.crealm.clone(),
        cname: tgt.cname.clone(),
        ticket: Ticket {
            tkt_vno: Ticket::VNO,
            realm: ascii("KERBER.TEST"),
            sname,
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![0u8; 16]),
            },
        },
        enc_part: EncryptedData {
            etype: sub.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    });
    encode(&rep).unwrap()
}

#[test]
fn r33_tgs_unwrapped_fast_is_accepted() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).unwrap();
    tcp.set_nonblocking(true).unwrap();
    let tgt = password_as_tgt();
    let tgt_srv = tgt.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            let mut buf = vec![0u8; 65535];
            if let Ok((n, src)) = udp.recv_from(&mut buf) {
                let rep = unwrapped_tgs_rep(&tgt_srv, &buf[..n]);
                let _ = udp.send_to(&rep, src);
                let _ = tx.send(());
                return;
            }
            if let Ok((mut stream, _)) = tcp.accept() {
                let _ = stream.set_nonblocking(false);
                let mut hdr = [0u8; 4];
                if stream.read_exact(&mut hdr).is_ok() {
                    let n = u32::from_be_bytes(hdr) as usize;
                    if (1..=1024 * 1024).contains(&n) {
                        let mut body = vec![0u8; n];
                        if stream.read_exact(&mut body).is_ok() {
                            let rep = unwrapped_tgs_rep(&tgt_srv, &body);
                            let n = u32::try_from(rep.len()).expect("TGS-REP fits u32");
                            let _ = stream.write_all(&n.to_be_bytes());
                            let _ = stream.write_all(&rep);
                            let _ = tx.send(());
                            return;
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
    });
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]);
    let out = tgs_exchange(
        &KdcAddr {
            host: "127.0.0.1".into(),
            port: addr.port(),
        },
        &tgt,
        host.clone(),
        "KERBER.TEST",
    )
    .expect("MIT decode_kdc.c FAST_REQUIRED swallow");
    rx.recv_timeout(Duration::from_secs(2))
        .expect("TGS-REQ seen");
    assert_eq!(out.ticket.sname, host);
}

#[test]
fn r33_empty_groups_stray_pa_spake_is_skipped() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.policy.spake_preauth_groups.clear();
    let princ = user();
    let req = as_req(
        princ.clone(),
        TEST_REALM,
        33001,
        Some(vec![PaData {
            padata_type: pa::SPAKE,
            padata_value: vec![].into(),
        }]),
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    match &err {
        Error::PreauthRequired { .. } => {}
        Error::Protocol { code, .. } => {
            panic!("empty-groups stray PA-SPAKE must skip, not {code}");
        }
        other => panic!("expected PreauthRequired, got {other:?}"),
    }
    assert_eq!(
        store.fail_auth_of(store.get_name(&princ).unwrap()),
        0,
        "skipped PA-SPAKE must not increment fail_auth_count"
    );
}
