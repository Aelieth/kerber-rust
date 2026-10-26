//! Protocol message tests: AP-REP, SAFE/PRIV/CRED, DER tags.

#[path = "common/mod.rs"]
mod common;
use common::{client_key, isolate_host_krb5};

use krb5_asn1::{decode, encode};
use krb5_crypto::KeyUsage;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented, documented_host};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_protocol::{
    ReplayCache, build_ap_rep, build_ap_req, build_krb_cred, build_krb_priv_with_seq,
    build_krb_safe_ex, unwrap_krb_priv, unwrap_krb_safe, verify_ap_rep, verify_ap_req,
};
use krb5_types::{PrincipalName, ascii, ku};

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
        .export_keytab(
            &acl,
            &krb5_kdc::testrealm::documented_admin_id(),
            &documented_host(),
        )
        .unwrap();
    let ok = verify_ap_req(&raw, &kt.entries[0].key, &ReplayCache::new()).unwrap();
    let ap_rep = build_ap_rep(&tgs_out.session_key, &ok.authenticator, None, Some(1)).unwrap();
    let ap_rep_raw = encode(&ap_rep).unwrap();
    verify_ap_rep(&ap_rep_raw, &tgs_out.session_key, &ok.authenticator).unwrap();

    let safe = build_krb_safe_ex(&tgs_out.session_key, b"safe-payload", Some(1), true).unwrap();
    let replay = ReplayCache::new();
    let got = unwrap_krb_safe(&tgs_out.session_key, &encode(&safe).unwrap(), &replay).unwrap();
    assert_eq!(got, b"safe-payload");
    let privm = build_krb_priv_with_seq(&tgs_out.session_key, b"priv-payload", Some(1)).unwrap();
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

/// A KDC that answers the first AS-REQ with PREAUTH_REQUIRED at `kdc_time` (hint: ETYPE-INFO2
/// aes256-cts with the user's salt, and PA-ENC-TIMESTAMP), and the second with PREAUTH_FAILED;
/// returns both requests.
fn preauth_at(
    profile: &krb5_config::Krb5Conf,
    kdc_time: u32,
) -> (krb5_types::AsReq, krb5_types::AsReq) {
    use krb5_types::{
        AsReq, EtypeInfo2Entry, KerberosTime, KrbError, Microseconds, PaData, err, pa,
    };
    use std::net::UdpSocket;
    use std::sync::mpsc;
    use std::thread;

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        for round in 0..2 {
            let Ok((n, src)) = udp.recv_from(&mut buf) else {
                return;
            };
            let _ = tx.send(buf[..n].to_vec());
            let info = vec![EtypeInfo2Entry {
                etype: 18,
                salt: Some(ascii("KERBER.TESTuser")),
                s2kparams: None,
            }];
            let method = vec![
                PaData {
                    padata_type: pa::ETYPE_INFO2,
                    padata_value: encode(&info).unwrap().into(),
                },
                PaData {
                    padata_type: pa::ENC_TIMESTAMP,
                    padata_value: Vec::new().into(),
                },
            ];
            let reply = encode(&KrbError {
                pvno: KrbError::PVNO,
                msg_type: KrbError::MSG_TYPE,
                ctime: None,
                cusec: None,
                stime: KerberosTime::from_unix_seconds(kdc_time),
                susec: Microseconds::new(123_456).unwrap(),
                error_code: if round == 0 {
                    err::PREAUTH_REQUIRED
                } else {
                    err::PREAUTH_FAILED
                },
                crealm: None,
                cname: None,
                realm: ascii("KERBER.TEST"),
                sname: PrincipalName::krbtgt("KERBER.TEST"),
                e_text: None,
                e_data: Some(encode(&method).unwrap().into()),
            })
            .unwrap();
            let _ = udp.send_to(&reply, src);
        }
    });
    let out = krb5_protocol::as_exchange(&krb5_protocol::AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"userpassword",
        kdc: &krb5_protocol::KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        profile,
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: Some(&[18]),
        ticket: krb5_protocol::AsTicketOpts::default(),
    });
    assert!(out.is_err(), "the stub ends with PREAUTH_FAILED");
    let first: AsReq = decode(&rx.recv().unwrap()).unwrap();
    let second: AsReq = decode(&rx.recv().unwrap()).unwrap();
    (first, second)
}

/// The request's encrypted timestamp, opened with the user's aes256-cts key.
fn timestamp_of(req: &krb5_types::AsReq) -> krb5_types::PaEncTsEnc {
    use krb5_crypto::{EncryptionType, string_to_key};
    use krb5_types::{EncryptedData, pa};
    let p = req
        .0
        .padata
        .as_ref()
        .unwrap()
        .iter()
        .find(|p| p.padata_type == pa::ENC_TIMESTAMP)
        .expect("PA-ENC-TIMESTAMP");
    let enc: EncryptedData = decode(p.padata_value.as_ref()).unwrap();
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        b"userpassword",
        b"KERBER.TESTuser",
        None,
    )
    .unwrap();
    let usage = KeyUsage::new(ku::PA_ENC_TIMESTAMP).unwrap();
    decode(&krb5_crypto::decrypt(&key, usage, enc.cipher.as_ref()).unwrap()).unwrap()
}

// MIT: `note_req_timestamp` (lib/krb5/krb/get_in_tkt.c:1433-1438)
/// a retried PREAUTH_REQUIRED sets the offset of the KDC's time.
// MIT: `k5_init_creds_current_time` (lib/krb5/krb/get_in_tkt.c:683-697)
/// the next request's times and its encrypted timestamp are then the KDC's.
#[test]
fn after_preauth_required_the_timestamp_and_times_are_the_kdcs() {
    isolate_host_krb5();
    let now = i64::from(krb5_types::KerberosTime::now().unix_seconds());
    let kdc = u32::try_from(now + 3600).unwrap();
    let (first, second) = preauth_at(&krb5_config::isolated_profile(), kdc);
    let near = |a: i64, b: i64| (a - b).abs() <= 5;
    assert!(
        near(
            i64::from(first.0.req_body.till.unix_seconds()),
            now + 86_400
        ),
        "the first request is made at the local time"
    );
    assert!(
        near(
            i64::from(second.0.req_body.till.unix_seconds()),
            now + 3600 + 86_400
        ),
        "the second request's till is the KDC's time plus the lifetime"
    );
    let ts = timestamp_of(&second);
    assert!(
        near(i64::from(ts.patimestamp.unix_seconds()), now + 3600),
        "the timestamp is the KDC's time"
    );
}
