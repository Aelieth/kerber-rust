//! SPAKE preauthentication: the 91 e_data (module, ETYPE-INFO2, cookie), `verify_support`'s
//! 24, the PKINIT hint `[16, 147]`, TGS FAST armor after a password AS, the TGS
//! FAST_REQUIRED swallow, and a stray PA-SPAKE skipped when no groups are configured.
//! The tests drive the shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry points of a
//! bootstrapped realm.
//! SPAKE 91 carries ETYPE-INFO2 when the client has not yet seen a cookie.
// MIT: `maybe_add_etype_info2` (kdc_preauth.c:1141-1170)
//! a 91 reply gets PA-ETYPE-INFO2
//! only while the request carries no cookie.

#[path = "common/mod.rs"]
mod common;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt, prf_plus};
use krb5_kdc::testrealm::{TEST_ADMIN, TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_kdc::{Error, PrincipalStore, load_dump_path};
use krb5_protocol::as_req;

use krb5_protocol::{pa_spake_response, pa_spake_support};
use krb5_testkit::{status, user};
use krb5_types::{
    EncKdcRepPart, KerberosTime, KrbError, MethodData, PaData, PrincipalName, err, ku, pa,
    spake::{GROUP_EDWARDS25519, PaSpake, SpakeSupport},
};

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

fn decode_enc_part(plain: &[u8]) -> EncKdcRepPart {
    krb5_asn1::decode_enc_kdc_rep_part(plain).expect("enc-part")
}

fn golden_dump_store() -> PrincipalStore {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/traces/kdb/mit-dump-v7.txt");
    let mut store = load_dump_path(&p, b"masterpassword").expect("golden dump");
    store.policy.spake_preauth_groups = vec![krb5_crypto::SpakeGroup::P256];
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
    let support = pa_spake_support(&[krb5_crypto::SpakeGroup::P256]);
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
    let support = pa_spake_support(&[krb5_crypto::SpakeGroup::P256]);
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
        krb5_crypto::SpakeGroup::P256,
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
    let support = pa_spake_support(&[krb5_crypto::SpakeGroup::P256]);
    let (key, spa, cookie, chal) = spake_round1(&store, 321);
    assert!(cookie.starts_with(b"MIT1"), "SPAKE cookie is MIT1");
    let mut req2 = as_req(cname, TEST_REALM, 322, None).unwrap();
    let body_der = encode(&req2.0.req_body).expect("body");
    let (resp, spake_key) = pa_spake_response(
        &key,
        krb5_crypto::SpakeGroup::P256,
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
    let support = pa_spake_support(&[krb5_crypto::SpakeGroup::P256]);
    let (key, spa, mut cookie, chal) = spake_round1(&store, 323);
    assert!(cookie.starts_with(b"MIT1") && cookie.len() > 8);
    cookie[4..8].copy_from_slice(&0xffff_ffff_u32.to_be_bytes());
    let mut req2 = as_req(cname, TEST_REALM, 324, None).unwrap();
    let body_der = encode(&req2.0.req_body).expect("body");
    let (resp, _) = pa_spake_response(
        &key,
        krb5_crypto::SpakeGroup::P256,
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
    let support = pa_spake_support(&[krb5_crypto::SpakeGroup::P256]);
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
        krb5_crypto::SpakeGroup::P256,
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
    let support = pa_spake_support(&[krb5_crypto::SpakeGroup::P256]);
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
        krb5_crypto::SpakeGroup::P256,
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
    let support = pa_spake_support(&[krb5_crypto::SpakeGroup::P256]);
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
        krb5_crypto::SpakeGroup::P256,
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
// oracle: differential-gate.sh as-spake-unknown-choice
fn as_spake_unknown_choice_is_preauth_failed() {
    // MIT: `decode_cntype` (lib/krb5/asn.1/asn1_encode.c:1277-1293)
    // a PA-SPAKE no alternative takes ([4]) is an unknown choice.
    // MIT: `spake_verify` (plugins/preauth/spake/spake_kdc.c:532-535)
    // an unknown choice is PREAUTH_FAILED.
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let spake = PaData {
        padata_type: pa::SPAKE,
        padata_value: vec![0xa4, 0x02, 0x30, 0x00].into(),
    };
    let req = as_req(cname, TEST_REALM, 392, Some(vec![spake])).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    let e: KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::PREAUTH_FAILED);
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(text, Some("PREAUTH_FAILED"));
}

fn spake_traced(store: &PrincipalStore, req: &krb5_types::AsReq) -> (i32, Vec<String>) {
    let raw = encode(req).unwrap();
    let (reply, log) = common::kdc_log(|| krb5_kdc::handle_request(store, &raw));
    let e: KrbError = decode(&reply.expect("a KRB-ERROR reply")).expect("KRB-ERROR");
    (e.error_code, log)
}

fn spake_padata_req(nonce: u32, padata: Vec<PaData>) -> krb5_types::AsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    as_req(cname, TEST_REALM, nonce, Some(padata)).unwrap()
}

#[test]
fn spake_support_message_is_logged_as_a_verify_failure() {
    // MIT: `send_challenge` (plugins/preauth/spake/spake_kdc.c:290-292)
    // the module answers a support message with `KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED`, which `finish_verify_padata` logs like any failure of a module.
    let (store, _) = bootstrap_documented().unwrap();
    let req = spake_padata_req(
        0x4b11,
        vec![pa_spake_support(&[krb5_crypto::SpakeGroup::P256])],
    );
    let (code, log) = spake_traced(&store, &req);
    assert_eq!(code, err::MORE_PREAUTH_DATA_REQUIRED);
    assert_eq!(
        common::failure_trace(&log),
        [
            "preauth (spake) verify failure: More preauthentication data is required",
            "AS_REQ PREAUTH_FAILED, More preauthentication data is required",
        ]
    );
}

#[test]
fn spake_messages_that_do_not_decode_log_the_decoders_text() {
    // MIT: `spake_verify` (plugins/preauth/spake/spake_kdc.c:519-521)
    // a PA-SPAKE the decoder refuses fails the module with the decoder's code.
    // MIT: `spake_verify` (plugins/preauth/spake/spake_kdc.c:532-535)
    // a choice no alternative takes fails with this message.
    let (store, _) = bootstrap_documented().unwrap();
    for (n, (der, message)) in [
        (vec![0xff, 0xff], "ASN.1 encoding ended unexpectedly"),
        (vec![0xa0, 0x00], "ASN.1 encoding ended unexpectedly"),
        (
            vec![0xa0, 0x02, 0x30, 0x00],
            "ASN.1 structure is missing a required field",
        ),
        (
            vec![0xa2, 0x02, 0x30, 0x00],
            "ASN.1 structure is missing a required field",
        ),
        (
            vec![0xa0, 0x02, 0x04, 0x00],
            "ASN.1 identifier doesn't match expected value",
        ),
        (
            vec![0xa1, 0x02, 0x30, 0x00],
            "ASN.1 structure is missing a required field",
        ),
        (vec![0xa4, 0x02, 0x30, 0x00], "Unknown SPAKE request type"),
        (vec![0x30, 0x00], "Unknown SPAKE request type"),
        // A well-formed challenge: the KDC reads one from a client as an unknown request type.
        (
            vec![
                0xa1, 0x11, 0x30, 0x0f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x04, 0x04, 0x02, 0xaa,
                0xbb, 0xa2, 0x02, 0x30, 0x00,
            ],
            "Unknown SPAKE request type",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let padata = PaData {
            padata_type: pa::SPAKE,
            padata_value: der.clone().into(),
        };
        let req = spake_padata_req(0x4b20 + u32::try_from(n).unwrap(), vec![padata]);
        let (code, log) = spake_traced(&store, &req);
        assert_eq!(code, err::PREAUTH_FAILED, "{der:02x?}");
        assert_eq!(
            common::verify_failures(&log),
            [format!("preauth (spake) verify failure: {message}")],
            "{der:02x?}"
        );
    }
}

#[test]
fn spake_response_failures_are_logged_as_the_plain_24_text() {
    let (store, _) = bootstrap_documented().unwrap();
    let support = pa_spake_support(&[krb5_crypto::SpakeGroup::P256]);
    let wrong = krb5_testkit::password_key(TEST_USER, b"not-the-password");
    let plain = [
        "preauth (spake) verify failure: Preauthentication failed",
        "AS_REQ PREAUTH_FAILED, Preauthentication failed",
    ];
    // MIT: `verify_response` (plugins/preauth/spake/spake_kdc.c:429-434)
    // a factor that does not decrypt is the wrong password.
    let (_, spa, cookie, chal) = spake_round1(&store, 0x4b31);
    let mut req = spake_padata_req(0x4b32, vec![]);
    let body_der = encode(&req.0.req_body).unwrap();
    let (resp, _) = pa_spake_response(
        &wrong,
        krb5_crypto::SpakeGroup::P256,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )
    .unwrap();
    req.0.padata = Some(vec![
        resp,
        PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: cookie.into(),
        },
    ]);
    let (code, log) = spake_traced(&store, &req);
    assert_eq!(code, err::PREAUTH_FAILED);
    assert_eq!(common::failure_trace(&log), plain, "wrong password");
    // MIT: `verify_response` (plugins/preauth/spake/spake_kdc.c:388-391)
    // a response with no cookie to answer is refused the same way.
    let (key, spa, _cookie, chal) = spake_round1(&store, 0x4b33);
    let mut req = spake_padata_req(0x4b34, vec![]);
    let body_der = encode(&req.0.req_body).unwrap();
    let (resp, _) = pa_spake_response(
        &key,
        krb5_crypto::SpakeGroup::P256,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )
    .unwrap();
    req.0.padata = Some(vec![resp]);
    let (code, log) = spake_traced(&store, &req);
    assert_eq!(code, err::PREAUTH_FAILED);
    assert_eq!(common::failure_trace(&log), plain, "no cookie");
}
