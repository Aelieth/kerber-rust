//! A′-3 item 15: SPAKE 91 e_data is module, ETYPE-INFO2, cookie.
//! A′-3 R30 inject: verify_support 24, PKINIT [16, 147], TGS FAST armor.
//! A′-3 R33: TGS FAST_REQUIRED swallow + empty-groups stray PA-SPAKE skip.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.
//! SPAKE 91 carries ETYPE-INFO2 when the client has not yet seen a cookie
//! (`kdc_preauth.c:1141-1170 maybe_add_etype_info2`).

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt, prf_plus};
use krb5_kdc::testrealm::{TEST_ADMIN, TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_kdc::{Error, PrincipalStore, load_dump_path};
use krb5_protocol::as_req;

use krb5_protocol::{AsOutcome, KdcAddr, pa_spake_response, pa_spake_support, tgs_exchange};
use krb5_testkit::{status, user};
use krb5_types::{
    EncKdcRepPart, EncryptedData, EncryptionKey, KerberosTime, KrbError, MethodData, OctetString,
    PaData, PrincipalName, TgsReq, Ticket, TicketFlags, ascii, err, ku, pa,
    spake::{GROUP_EDWARDS25519, PaSpake, SpakeSupport},
};
use std::net::UdpSocket;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[test]
fn as_spake_91_e_data_is_151_19_133() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 15007, Some(vec![pa_spake_support()])).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).unwrap();
    let e: KrbError = decode(&bytes).unwrap();
    assert_eq!(e.error_code, err::MORE_PREAUTH_DATA_REQUIRED);
    let method: MethodData = decode(e.e_data.as_ref().unwrap().as_ref()).unwrap();
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert_eq!(types, vec![pa::SPAKE, pa::ETYPE_INFO2, pa::FX_COOKIE]);
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
fn verify_support_unpermitted_offer_is_preauth_failed() {
    let (store, _) = bootstrap_documented().unwrap();
    let req = as_req(
        user(),
        TEST_REALM,
        30001,
        Some(vec![support_groups(&[GROUP_EDWARDS25519])]),
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    assert_eq!(status(&err), (err::PREAUTH_FAILED, Some("PREAUTH_FAILED")));
}

#[test]
fn pkinit_hint_is_16_147() {
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

#[test]
fn tgs_after_password_as_is_fast_armored() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // Capture UDP or TCP: host `udp_preference_limit` (or a FAST body
    // over MIT's 1465 default) must not hide the 136 assert.
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).unwrap();
    tcp.set_nonblocking(true).unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            let mut buf = vec![0u8; 65535];
            if let Ok((n, src)) = udp.recv_from(&mut buf) {
                let _ = udp.send_to(&[0x7e], src);
                let _ = tx.send(buf[..n].to_vec());
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
                            let _ = stream.write_all(&1u32.to_be_bytes());
                            let _ = stream.write_all(&[0x7e]);
                            let _ = tx.send(body);
                            return;
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(5));
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

#[test]
fn empty_groups_stray_pa_spake_is_skipped() {
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

fn decode_enc_part(plain: &[u8]) -> EncKdcRepPart {
    krb5_asn1::decode_enc_kdc_rep_part(plain).expect("enc-part")
}

fn golden_dump_store() -> PrincipalStore {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/traces/kdb/mit-dump-v7.txt");
    let mut store = load_dump_path(&p, b"masterpassword").expect("golden dump");
    store.policy.spake_preauth_groups = vec![krb5_types::spake::GROUP_P256];
    store
}

fn spake_round1(
    store: &PrincipalStore,
    nonce: u32,
) -> (
    ProtocolKey,
    PaData,
    Vec<u8>,
    krb5_types::spake::SpakeChallenge,
) {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .expect("user")
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .expect("aes256-sha1 key")
        .key
        .clone();
    let support = pa_spake_support();
    let req1 = as_req(cname, TEST_REALM, nonce, Some(vec![support.clone()])).unwrap();
    let err = krb5_kdc::issue_as(store, &req1).unwrap_err();
    let e_data = match err {
        Error::Protocol {
            code,
            e_data: Some(e_data),
            ..
        } if code == err::MORE_PREAUTH_DATA_REQUIRED => e_data,
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    let spa = method
        .iter()
        .find(|p| p.padata_type == pa::SPAKE)
        .expect("PA-SPAKE")
        .clone();
    let cookie = method
        .iter()
        .find(|p| p.padata_type == pa::FX_COOKIE)
        .expect("cookie")
        .padata_value
        .as_ref()
        .to_vec();
    let msg: krb5_types::spake::PaSpake = decode(spa.padata_value.as_ref()).expect("PaSpake");
    let chal = match msg {
        krb5_types::spake::PaSpake::Challenge(c) => c,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    (key, spa, cookie, chal)
}

#[test]
fn spake_challenge_then_as_rep() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .expect("user")
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .expect("aes256-sha1 key")
        .key
        .clone();
    let support = pa_spake_support();
    let req1 = as_req(cname.clone(), TEST_REALM, 301, Some(vec![support.clone()])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req1).unwrap_err();
    let e_data = match err {
        Error::Protocol {
            code,
            text,
            e_data: Some(e_data),
            ..
        } if code == err::MORE_PREAUTH_DATA_REQUIRED => {
            assert_eq!(text.as_deref(), Some("PREAUTH_FAILED"));
            e_data
        }
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    let spa = method
        .iter()
        .find(|p| p.padata_type == pa::SPAKE)
        .expect("PA-SPAKE");
    let cookie = method
        .iter()
        .find(|p| p.padata_type == pa::FX_COOKIE)
        .expect("cookie");
    let msg: krb5_types::spake::PaSpake = decode(spa.padata_value.as_ref()).expect("PaSpake");
    let chal = match msg {
        krb5_types::spake::PaSpake::Challenge(c) => c,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let mut req2 = as_req(cname, TEST_REALM, 302, None).unwrap();
    let body_der = encode(&req2.0.req_body).expect("body");
    let (resp, spake_key) = pa_spake_response(
        &key,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )
    .expect("resp");
    req2.0.padata = Some(vec![
        resp,
        krb5_types::PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: cookie.padata_value.clone(),
        },
    ]);
    let issued = krb5_kdc::issue_as(&store, &req2).expect("SPAKE AS");
    assert_eq!(issued.as_rep_key.as_bytes(), spake_key.as_bytes());
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&spake_key, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 302);
    let cookie_bytes = cookie.padata_value.as_ref();
    assert!(
        cookie_bytes.starts_with(b"MIT1"),
        "SPAKE cookie is MIT1 not a raw blob"
    );
}

#[test]
fn spake_cookie_round_trips_on_golden_dump() {
    let store = golden_dump_store();
    let krbtgt = store.krbtgt().expect("krbtgt");
    let first = krbtgt.first_current_key().expect("first current");
    let best = krbtgt.best_key().expect("best");
    assert_ne!(
        first.etype, best.etype,
        "golden dump stores 20,19,18,17 so first_current ≠ best_key"
    );
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let support = pa_spake_support();
    let (key, spa, cookie, chal) = spake_round1(&store, 321);
    assert!(cookie.starts_with(b"MIT1"), "SPAKE cookie is MIT1");
    let mut req2 = as_req(cname, TEST_REALM, 322, None).unwrap();
    let body_der = encode(&req2.0.req_body).expect("body");
    let (resp, spake_key) = pa_spake_response(
        &key,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )
    .expect("resp");
    req2.0.padata = Some(vec![
        resp,
        krb5_types::PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: cookie.into(),
        },
    ]);
    let issued = krb5_kdc::issue_as(&store, &req2).expect("SPAKE AS on golden dump");
    assert_eq!(issued.as_rep_key.as_bytes(), spake_key.as_bytes());
}

#[test]
fn spake_unknown_cookie_kvno_is_preauth_failed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let support = pa_spake_support();
    let (key, spa, mut cookie, chal) = spake_round1(&store, 323);
    assert!(cookie.starts_with(b"MIT1") && cookie.len() > 8);
    cookie[4..8].copy_from_slice(&0xffff_ffff_u32.to_be_bytes());
    let mut req2 = as_req(cname, TEST_REALM, 324, None).unwrap();
    let body_der = encode(&req2.0.req_body).expect("body");
    let (resp, _) = pa_spake_response(
        &key,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )
    .expect("resp");
    req2.0.padata = Some(vec![
        resp,
        krb5_types::PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: cookie.into(),
        },
    ]);
    let err = krb5_kdc::issue_as(&store, &req2).expect_err("unknown kvno cookie");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected 24, got {other:?}"),
    }
}

#[test]
fn spake_garbage_cookie_is_preauth_failed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .expect("user")
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .expect("aes256-sha1 key")
        .key
        .clone();
    let support = pa_spake_support();
    let req1 = as_req(cname.clone(), TEST_REALM, 303, Some(vec![support.clone()])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req1).unwrap_err();
    let e_data = match err {
        Error::Protocol {
            code,
            e_data: Some(e_data),
            ..
        } if code == err::MORE_PREAUTH_DATA_REQUIRED => e_data,
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    let spa = method
        .iter()
        .find(|p| p.padata_type == pa::SPAKE)
        .expect("PA-SPAKE");
    let mut cookie = method
        .iter()
        .find(|p| p.padata_type == pa::FX_COOKIE)
        .expect("cookie")
        .padata_value
        .as_ref()
        .to_vec();
    assert!(
        cookie.starts_with(b"MIT1"),
        "SPAKE cookie is MIT1 not a raw blob"
    );
    cookie[0] ^= 0xff;
    let msg: krb5_types::spake::PaSpake = decode(spa.padata_value.as_ref()).expect("PaSpake");
    let chal = match msg {
        krb5_types::spake::PaSpake::Challenge(c) => c,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let mut req2 = as_req(cname, TEST_REALM, 304, None).unwrap();
    let body_der = encode(&req2.0.req_body).expect("body");
    let (resp, _) = pa_spake_response(
        &key,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )
    .expect("resp");
    req2.0.padata = Some(vec![
        resp,
        krb5_types::PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: cookie.into(),
        },
    ]);
    let err = krb5_kdc::issue_as(&store, &req2).expect_err("garbage cookie");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected 24, got {other:?}"),
    }
}

#[test]
fn spake_cookie_for_user_ignored_for_admin() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let user_key = store
        .get_name(&user)
        .expect("user")
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .expect("aes256-sha1 key")
        .key
        .clone();
    let support = pa_spake_support();
    let req1 = as_req(user.clone(), TEST_REALM, 305, Some(vec![support.clone()])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req1).unwrap_err();
    let e_data = match err {
        Error::Protocol {
            code,
            e_data: Some(e_data),
            ..
        } if code == err::MORE_PREAUTH_DATA_REQUIRED => e_data,
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    let spa = method
        .iter()
        .find(|p| p.padata_type == pa::SPAKE)
        .expect("PA-SPAKE");
    let cookie = method
        .iter()
        .find(|p| p.padata_type == pa::FX_COOKIE)
        .expect("cookie");
    let msg: krb5_types::spake::PaSpake = decode(spa.padata_value.as_ref()).expect("PaSpake");
    let chal = match msg {
        krb5_types::spake::PaSpake::Challenge(c) => c,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let mut req2 = as_req(admin, TEST_REALM, 306, None).unwrap();
    let body_der = encode(&req2.0.req_body).expect("body");
    let (resp, _) = pa_spake_response(
        &user_key,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )
    .expect("resp");
    req2.0.padata = Some(vec![
        resp,
        krb5_types::PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: cookie.padata_value.clone(),
        },
    ]);
    let err = krb5_kdc::issue_as(&store, &req2).expect_err("wrong-client cookie");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected 24, got {other:?}"),
    }
}

#[test]
fn spake_expired_cookie_is_preauth_failed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .expect("user")
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .expect("aes256-sha1 key")
        .key
        .clone();
    let support = pa_spake_support();
    let req1 = as_req(cname.clone(), TEST_REALM, 307, Some(vec![support.clone()])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req1).unwrap_err();
    let e_data = match err {
        Error::Protocol {
            code,
            e_data: Some(e_data),
            ..
        } if code == err::MORE_PREAUTH_DATA_REQUIRED => e_data,
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    let spa = method
        .iter()
        .find(|p| p.padata_type == pa::SPAKE)
        .expect("PA-SPAKE");
    let cookie = method
        .iter()
        .find(|p| p.padata_type == pa::FX_COOKIE)
        .expect("cookie");
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let princ = cname.unparse_with_realm(TEST_REALM);
    let mut seed = b"COOKIE".to_vec();
    seed.extend_from_slice(princ.as_bytes());
    let rnd = prf_plus(&krbtgt.key, &seed, krbtgt.key.etype().key_len()).expect("prf+");
    let ckey = ProtocolKey::from_bytes(krbtgt.key.etype(), &rnd).expect("cookie key");
    let usage = KeyUsage::new(ku::PA_FX_COOKIE).unwrap();
    let blob = cookie.padata_value.as_ref();
    let plain = decrypt(&ckey, usage, &blob[8..]).expect("open");
    let mut sc: krb5_types::fast::SecureCookie = decode(&plain).expect("SecureCookie");
    sc.time = i32::try_from(KerberosTime::now().unix_seconds()).unwrap() - 700;
    let der = encode(&sc).expect("cookie der");
    let cipher = encrypt(&ckey, usage, &der).expect("enc");
    let mut expired = blob[..8].to_vec();
    expired.extend_from_slice(&cipher);
    let msg: krb5_types::spake::PaSpake = decode(spa.padata_value.as_ref()).expect("PaSpake");
    let chal = match msg {
        krb5_types::spake::PaSpake::Challenge(c) => c,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let mut req2 = as_req(cname, TEST_REALM, 308, None).unwrap();
    let body_der = encode(&req2.0.req_body).expect("body");
    let (resp, _) = pa_spake_response(
        &key,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )
    .expect("resp");
    req2.0.padata = Some(vec![
        resp,
        krb5_types::PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: expired.into(),
        },
    ]);
    let err = krb5_kdc::issue_as(&store, &req2).expect_err("expired cookie");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected 24, got {other:?}"),
    }
}

#[test]
// oracle: differential-gate.sh as-spake-round1
fn handle_request_spake_91_e_text_is_preauth_failed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 391, Some(vec![pa_spake_support()])).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    let e: KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::MORE_PREAUTH_DATA_REQUIRED);
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(text, Some("PREAUTH_FAILED"));
    assert_ne!(text, Some("SPAKE challenge"));
    let method: MethodData = decode(e.e_data.as_ref().expect("e_data").as_ref()).expect("METHOD");
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert!(
        types.contains(&pa::SPAKE)
            && types.contains(&pa::FX_COOKIE)
            && types.contains(&pa::ETYPE_INFO2),
        "91 without cookie: SPAKE+COOKIE+ETYPE-INFO2, got {types:?}"
    );
}

#[test]
fn spake_91_without_cookie_carries_etype_info2() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 711, Some(vec![pa_spake_support()])).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    let e: KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::MORE_PREAUTH_DATA_REQUIRED);
    let method: MethodData = decode(e.e_data.as_ref().expect("e_data").as_ref()).expect("METHOD");
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert!(
        types.contains(&pa::SPAKE)
            && types.contains(&pa::FX_COOKIE)
            && types.contains(&pa::ETYPE_INFO2),
        "91 without cookie: SPAKE+COOKIE+ETYPE-INFO2, got {types:?}"
    );
}
