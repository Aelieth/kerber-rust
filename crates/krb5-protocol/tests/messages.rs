//! Protocol message tests: AP-REP, SAFE/PRIV/CRED, DER tags.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, string_to_key};
use krb5_kdc::{
    S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    documented_host, pa_enc_timestamp, tgs_req,
};
use krb5_protocol::{
    ReplayCache, build_ap_rep, build_ap_req, build_krb_cred, build_krb_priv, build_krb_safe,
    unwrap_krb_priv, unwrap_krb_safe, verify_ap_rep, verify_ap_req,
};
use krb5_types::{EncAsRepPart, PrincipalName, ascii, ku};

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
    )
    .unwrap();
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
    )
    .unwrap();
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
    let replay = ReplayCache::new();
    let got = unwrap_krb_safe(&tgs_out.session_key, &encode(&safe).unwrap(), &replay).unwrap();
    assert_eq!(got, b"safe-payload");
    let privm = build_krb_priv(&tgs_out.session_key, b"priv-payload").unwrap();
    let got = unwrap_krb_priv(&tgs_out.session_key, &encode(&privm).unwrap(), &replay).unwrap();
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

    use krb5_protocol::{KdcAddr, exchange};
    use krb5_types::{KerberosTime, KrbError, Microseconds, PrincipalName, ascii, err};

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
fn as_req_rejects_non_ascii_realm() {
    let err = as_req(
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        "KERBER.\u{2603}",
        1,
        None,
    );
    assert!(err.is_err(), "non-ASCII realm must not panic");
}

#[test]
fn referral_hop_realm_uses_foreign_sname() {
    let sname = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "OTHER.TEST"]);
    assert_eq!(
        krb5_protocol::referral_hop_realm(&sname).as_deref(),
        Some("OTHER.TEST")
    );
    let ad = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "AD.KERBER.TEST"]);
    assert_eq!(
        krb5_protocol::referral_hop_realm(&ad).as_deref(),
        Some("AD.KERBER.TEST")
    );
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc"]);
    assert!(krb5_protocol::referral_hop_realm(&host).is_none());
}

#[test]
fn non_ascii_realm_as_exchange_is_err() {
    let err = krb5_protocol::as_exchange(&krb5_protocol::AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KÉRBER.TEST",
        password: b"x",
        kdc: &krb5_protocol::KdcAddr {
            host: "127.0.0.1".into(),
            port: 1,
        },
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        ticket: krb5_protocol::AsTicketOpts::default(),
    });
    assert!(err.is_err(), "non-ASCII realm must not panic");
}

#[test]
fn first_bare_as_req_skew_is_retried() {
    use std::net::UdpSocket;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use krb5_types::{KerberosTime, KrbError, Microseconds, PrincipalName, ascii, err};

    let hits = Arc::new(AtomicUsize::new(0));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let hits2 = hits.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        for _ in 0..4 {
            let Ok((n, src)) = udp.recv_from(&mut buf) else {
                break;
            };
            if n == 0 {
                break;
            }
            hits2.fetch_add(1, Ordering::SeqCst);
            let reply = encode(&KrbError {
                pvno: KrbError::PVNO,
                msg_type: KrbError::MSG_TYPE,
                ctime: None,
                cusec: None,
                stime: KerberosTime::now(),
                susec: Microseconds::ZERO,
                error_code: err::SKEW,
                crealm: None,
                cname: None,
                realm: ascii("KERBER.TEST"),
                sname: PrincipalName::krbtgt("KERBER.TEST"),
                e_text: None,
                e_data: None,
            })
            .unwrap();
            let _ = udp.send_to(&reply, src);
        }
    });
    thread::sleep(Duration::from_millis(20));
    let _ = krb5_protocol::as_exchange(&krb5_protocol::AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"userpassword",
        kdc: &krb5_protocol::KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        ticket: krb5_protocol::AsTicketOpts::default(),
    });
    assert!(
        hits.load(Ordering::SeqCst) >= 2,
        "first bare SKEW must resync/retry, not fail on the first PDU"
    );
}

#[test]
fn spake_as_req_carries_pa_spake() {
    use std::net::UdpSocket;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use krb5_types::{AsReq, KerberosTime, KrbError, Microseconds, PrincipalName, ascii, err, pa};

    let first = Arc::new(Mutex::new(Vec::new()));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let first2 = first.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let Ok((n, src)) = udp.recv_from(&mut buf) else {
            return;
        };
        *first2.lock().unwrap() = buf[..n].to_vec();
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
        let _ = udp.send_to(&reply, src);
    });
    thread::sleep(Duration::from_millis(20));
    let _ = krb5_protocol::as_exchange(&krb5_protocol::AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"userpassword",
        kdc: &krb5_protocol::KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: true,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        ticket: krb5_protocol::AsTicketOpts::default(),
    });
    let raw = first.lock().unwrap().clone();
    assert!(!raw.is_empty(), "SPAKE client must send an AS-REQ");
    let req: AsReq = decode(&raw).expect("AS-REQ");
    let padata = req.0.padata.unwrap_or_default();
    assert!(
        padata.iter().any(|p| p.padata_type == pa::SPAKE),
        "want_spake AS-REQ must advertise PA-SPAKE (151), got {padata:?}"
    );
}

#[test]
fn want_spake_rejects_non_preauth_as_rep() {
    use std::net::UdpSocket;
    use std::thread;
    use std::time::Duration;

    use krb5_types::{AsRep, EncryptedData, KdcRep, PrincipalName, Ticket, ascii};

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let Ok((n, src)) = udp.recv_from(&mut buf) else {
            return;
        };
        let _ = n;
        let reply = encode(&AsRep(KdcRep {
            pvno: KdcRep::PVNO,
            msg_type: KdcRep::MSG_AS_REP,
            padata: None,
            crealm: ascii("KERBER.TEST"),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            ticket: Ticket {
                tkt_vno: 5,
                realm: ascii("KERBER.TEST"),
                sname: PrincipalName::krbtgt("KERBER.TEST"),
                enc_part: EncryptedData {
                    etype: 18,
                    kvno: Some(1),
                    cipher: vec![0].into(),
                },
            },
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: vec![0].into(),
            },
        }))
        .unwrap();
        let _ = udp.send_to(&reply, src);
    });
    thread::sleep(Duration::from_millis(20));
    let err = krb5_protocol::as_exchange(&krb5_protocol::AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"userpassword",
        kdc: &krb5_protocol::KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: true,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        ticket: krb5_protocol::AsTicketOpts::default(),
    })
    .expect_err("SPAKE skip");
    assert!(
        err.to_string().contains("SPAKE"),
        "want_spake must refuse a non-preauth AS-REP, got {err}"
    );
}

#[test]
fn want_spake_rejects_fast_and_pkinit() {
    use krb5_crypto::{EncryptionType, ProtocolKey};
    use krb5_protocol::{FastArmor, PkinitClient};
    use krb5_types::{EncryptedData, PrincipalName, Ticket, ascii};

    let kdc = krb5_protocol::KdcAddr {
        host: "127.0.0.1".into(),
        port: 1,
    };
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let pk = PkinitClient {
        cert: vec![1],
        key: [2u8; 32],
        ca_cert: vec![3],
    };
    let err = krb5_protocol::as_exchange(&krb5_protocol::AsRequest {
        cname: cname.clone(),
        realm: "KERBER.TEST",
        password: b"x",
        kdc: &kdc,
        want_spake: true,
        fast_armor: None,
        pkinit: Some(&pk),
        canonicalize: false,
        sname: None,
        ticket: krb5_protocol::AsTicketOpts::default(),
    })
    .expect_err("spake+pkinit");
    assert!(err.to_string().contains("SPAKE exclusive"), "got {err}");

    let session =
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42u8; 32]).unwrap();
    let armor = FastArmor {
        ticket: Ticket {
            tkt_vno: 5,
            realm: ascii("KERBER.TEST"),
            sname: PrincipalName::krbtgt("KERBER.TEST"),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: vec![0u8; 32].into(),
            },
        },
        session,
        crealm: ascii("KERBER.TEST"),
        cname: cname.clone(),
    };
    let err = krb5_protocol::as_exchange(&krb5_protocol::AsRequest {
        cname,
        realm: "KERBER.TEST",
        password: b"x",
        kdc: &kdc,
        want_spake: true,
        fast_armor: Some(&armor),
        pkinit: None,
        canonicalize: false,
        sname: None,
        ticket: krb5_protocol::AsTicketOpts::default(),
    })
    .expect_err("spake+fast");
    assert!(err.to_string().contains("SPAKE exclusive"), "got {err}");
}

#[test]
fn fast_preauth_retry_carries_fx_fast() {
    use std::net::UdpSocket;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use krb5_crypto::{EncryptionType, ProtocolKey};
    use krb5_protocol::FastArmor;
    use krb5_types::{
        AsReq, EncryptedData, KerberosTime, KrbError, Microseconds, PrincipalName, Ticket, ascii,
        err, pa,
    };

    let first = Arc::new(Mutex::new(Vec::new()));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let first2 = first.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        for nsent in 0..2 {
            let Ok((n, src)) = udp.recv_from(&mut buf) else {
                return;
            };
            if nsent == 0 {
                *first2.lock().unwrap() = buf[..n].to_vec();
            }
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
            let _ = udp.send_to(&reply, src);
        }
    });
    thread::sleep(Duration::from_millis(20));
    let session =
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42u8; 32]).unwrap();
    let ticket = Ticket {
        tkt_vno: 5,
        realm: ascii("KERBER.TEST"),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        enc_part: EncryptedData {
            etype: 18,
            kvno: Some(1),
            cipher: vec![0u8; 32].into(),
        },
    };
    let armor = FastArmor {
        ticket,
        session,
        crealm: ascii("KERBER.TEST"),
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
    };
    let _ = krb5_protocol::as_exchange(&krb5_protocol::AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"userpassword",
        kdc: &krb5_protocol::KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: false,
        fast_armor: Some(&armor),
        pkinit: None,
        canonicalize: false,
        sname: None,
        ticket: krb5_protocol::AsTicketOpts::default(),
    });
    let raw = first.lock().unwrap().clone();
    assert!(!raw.is_empty(), "FAST client must send an AS-REQ");
    let req: AsReq = decode(&raw).expect("AS-REQ");
    let padata = req.0.padata.unwrap_or_default();
    assert!(
        padata.iter().any(|p| p.padata_type == pa::FX_FAST),
        "FAST AS-REQ must carry PA-FX-FAST (136), got {padata:?}"
    );
}

#[test]
fn pkinit_as_req_carries_pa_pk_as_req() {
    use std::net::UdpSocket;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use krb5_protocol::PkinitClient;
    use krb5_types::{
        AsReq, KerberosTime, KrbError, Microseconds, PrincipalName, ascii, err, pa, pkinit,
    };

    let ca = pkinit::PkinitCa::generate().expect("CA");
    let pem = ca
        .user_identity_pem("user@KERBER.TEST")
        .expect("user identity");
    let (cert, key) = pkinit::parse_identity_pem(&pem).expect("parse identity");
    let pk = PkinitClient {
        cert,
        key,
        ca_cert: ca.ca_cert.clone(),
    };

    let first = Arc::new(Mutex::new(Vec::new()));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let first2 = first.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        let Ok((n, src)) = udp.recv_from(&mut buf) else {
            return;
        };
        *first2.lock().unwrap() = buf[..n].to_vec();
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
        let _ = udp.send_to(&reply, src);
    });
    thread::sleep(Duration::from_millis(20));
    let _ = krb5_protocol::as_exchange(&krb5_protocol::AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"",
        kdc: &krb5_protocol::KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: false,
        fast_armor: None,
        pkinit: Some(&pk),
        canonicalize: false,
        sname: None,
        ticket: krb5_protocol::AsTicketOpts::default(),
    });
    let raw = first.lock().unwrap().clone();
    assert!(!raw.is_empty(), "PKINIT client must send an AS-REQ");
    let req: AsReq = decode(&raw).expect("AS-REQ");
    let padata = req.0.padata.unwrap_or_default();
    assert!(
        padata.iter().any(|p| p.padata_type == pa::PK_AS_REQ),
        "PKINIT AS-REQ must carry PA-PK-AS-REQ (16), got {padata:?}"
    );
}

#[test]
fn enterprise_as_req_sets_name_type_and_canonicalize() {
    use std::net::UdpSocket;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use krb5_types::{
        AsReq, KerberosTime, KrbError, Microseconds, PrincipalName, ascii, err, flag_bit,
    };

    let first = Arc::new(Mutex::new(Vec::new()));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let first2 = first.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let Ok((n, src)) = udp.recv_from(&mut buf) else {
            return;
        };
        *first2.lock().unwrap() = buf[..n].to_vec();
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
        let _ = udp.send_to(&reply, src);
    });
    thread::sleep(Duration::from_millis(20));
    let cname = PrincipalName::new(PrincipalName::NT_ENTERPRISE, ["user@KERBER.TEST"]);
    let _ = krb5_protocol::as_exchange(&krb5_protocol::AsRequest {
        cname,
        realm: "KERBER.TEST",
        password: b"userpassword",
        kdc: &krb5_protocol::KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: true,
        sname: None,
        ticket: krb5_protocol::AsTicketOpts::default(),
    });
    let raw = first.lock().unwrap().clone();
    assert!(!raw.is_empty(), "enterprise client must send an AS-REQ");
    let req: AsReq = decode(&raw).expect("AS-REQ");
    let got = req.0.req_body.cname.expect("cname");
    assert_eq!(got.name_type, PrincipalName::NT_ENTERPRISE);
    assert_eq!(got.components_joined(), "user@KERBER.TEST");
    assert!(
        req.0.req_body.kdc_options.bit(flag_bit::CANONICALIZE),
        "enterprise AS-REQ must set canonicalize"
    );
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
