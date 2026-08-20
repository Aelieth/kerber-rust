//! Protocol message tests: AP-REP, SAFE/PRIV/CRED, DER tags.

use krb5_asn1::{decode, encode};
use krb5_crypto::{string_to_key, EncryptionType, KeyUsage};
use krb5_kdc::{
    as_req, bootstrap_documented, documented_host, pa_enc_timestamp, tgs_req, S2K_ITERS,
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
};
use krb5_protocol::{
    build_ap_rep, build_ap_req, build_krb_cred, build_krb_priv, build_krb_safe, unwrap_krb_priv,
    unwrap_krb_safe, verify_ap_rep, verify_ap_req, ReplayCache,
};
use krb5_types::{ascii, ku, EncAsRepPart, PrincipalName};

fn client_key() -> krb5_crypto::ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap()
}

#[test]
fn as_rep_enc_part_is_application_25() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname,
        TEST_REALM,
        1,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    );
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = krb5_crypto::decrypt(&key, usage, issued.rep.0.enc_part.cipher.as_ref()).unwrap();
    assert_eq!(plain[0], 0x79, "APPLICATION 25");
    let _: EncAsRepPart = decode(&plain).expect("EncASRepPart");
}

#[test]
fn ap_rep_mutual_and_safe_priv() {
    let (store, acl) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        2,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    );
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        3,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let ap = build_ap_req(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
    )
    .unwrap();
    let raw = encode(&ap).unwrap();
    let kt = store
        .export_keytab(&acl, &krb5_kdc::documented_admin_id(), &documented_host())
        .unwrap();
    let ok = verify_ap_req(&raw, &kt.entries[0].key, &ReplayCache::new()).unwrap();
    let ap_rep = build_ap_rep(&tgs_out.session_key, &ok.authenticator, None, Some(1)).unwrap();
    let ap_rep_raw = encode(&ap_rep).unwrap();
    verify_ap_rep(&ap_rep_raw, &tgs_out.session_key, &ok.authenticator).unwrap();

    let safe = build_krb_safe(&tgs_out.session_key, b"safe-payload").unwrap();
    let got = unwrap_krb_safe(&tgs_out.session_key, &encode(&safe).unwrap()).unwrap();
    assert_eq!(got, b"safe-payload");
    let privm = build_krb_priv(&tgs_out.session_key, b"priv-payload").unwrap();
    let got = unwrap_krb_priv(&tgs_out.session_key, &encode(&privm).unwrap()).unwrap();
    assert_eq!(got, b"priv-payload");

    let cred = build_krb_cred(
        &tgs_out.session_key,
        vec![tgs_out.rep.0.ticket.clone()],
        vec![],
    )
    .unwrap();
    assert_eq!(encode(&cred).unwrap()[0], 0x76); // APPLICATION 22
}

#[test]
fn exchange_tcp_and_udp_round_trip_local_kdc() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::thread;
    use std::time::Duration;

    use krb5_protocol::{exchange, KdcAddr};
    use krb5_types::{ascii, err, KerberosTime, KrbError, Microseconds, PrincipalName};

    let reply = encode(&KrbError {
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
    .unwrap();

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    let tcp = TcpListener::bind(("127.0.0.1", udp_port)).unwrap();
    let reply_u = reply.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let (n, src) = udp.recv_from(&mut buf).unwrap();
        assert!(n > 0);
        udp.send_to(&reply_u, src).unwrap();
    });
    let reply_t = reply.clone();
    thread::spawn(move || {
        let (mut s, _) = tcp.accept().unwrap();
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).unwrap();
        let n = u32::from_be_bytes(hdr) as usize;
        let mut body = vec![0u8; n];
        s.read_exact(&mut body).unwrap();
        s.write_all(&(u32::try_from(reply_t.len()).unwrap().to_be_bytes()))
            .unwrap();
        s.write_all(&reply_t).unwrap();
    });
    thread::sleep(Duration::from_millis(20));
    let got = exchange(
        &KdcAddr {
            host: "127.0.0.1".into(),
            port: udp_port,
        },
        b"\x6a\x03\x02\x01",
    )
    .expect("local exchange");
    assert_eq!(got[0], 0x7e);
    let e: KrbError = decode(&got).unwrap();
    assert_eq!(e.error_code, err::PREAUTH_REQUIRED);
}

#[test]
fn golden_application_tags() {
    use krb5_types::*;
    let t = Ticket {
        tkt_vno: 5,
        realm: ascii("KERBER.TEST"),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        enc_part: EncryptedData {
            etype: 18,
            kvno: Some(1),
            cipher: vec![0].into(),
        },
    };
    assert_eq!(encode(&t).unwrap()[0], 0x61);
    let e = KrbError {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: 6,
        crealm: None,
        cname: None,
        realm: ascii("R"),
        sname: PrincipalName::krbtgt("R"),
        e_text: None,
        e_data: None,
    };
    assert_eq!(encode(&e).unwrap()[0], 0x7e);
}
