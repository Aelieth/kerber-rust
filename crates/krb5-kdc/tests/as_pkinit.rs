//! PKINIT: freshness tokens (`pkinit_require_freshness`, the minted token), advertising, the
//! ECDH / MODP reply keys, and the refusals.
//! The tests drive the shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry points of a
//! bootstrapped realm.

#[path = "common/mod.rs"]
mod common;

use krb5_asn1::{decode, encode};
use krb5_crypto::p256_generate;
use krb5_kdc::Error;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id};
use krb5_protocol::as_req;

use krb5_protocol::{pa_pk_as_req, pa_pk_as_req_cn, pa_pk_as_req_unsigned};
use krb5_testkit::user;
use krb5_types::{
    MethodData, PaData, PrincipalName, err, pa,
    pkinit::kdc_req_body_checksum,
    pkinit::{ECONTENT_AUTHDATA, PaPkAsReq, cms_sign_leaf, cms_verify, parse_pa_pk_as_req_cms},
};

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if let Ok(b) = u8::try_from(body.len()) {
        if b < 128 {
            out.push(b);
        } else {
            out.push(0x81);
            out.push(b);
        }
    } else {
        out.push(0x82);
        out.extend_from_slice(&(u16::try_from(body.len()).unwrap_or(u16::MAX)).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

fn take_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (hlen, ln) = if first < 128 {
        (1, usize::from(first))
    } else if first == 0x81 && input.len() >= 3 {
        (2, usize::from(input[2]))
    } else if first == 0x82 && input.len() >= 4 {
        (3, usize::from(u16::from_be_bytes([input[2], input[3]])))
    } else {
        return None;
    };
    let start = 1 + hlen;
    let body = input.get(start..start + ln)?;
    let rest = input.get(start + ln..)?;
    Some((tag, body, rest))
}

fn inject_pkauth_freshness(authpack: &[u8], token: &[u8]) -> Vec<u8> {
    let (t, body, _) = take_tlv(authpack).expect("AuthPack");
    assert_eq!(t, 0x30);
    let mut out = Vec::new();
    let mut cur = body;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_tlv(cur).expect("field");
        if tag == 0xa0 {
            let seq = if inner.first() == Some(&0x30) {
                take_tlv(inner).expect("pkauth").1
            } else {
                inner
            };
            let tok = tlv(0xa4, &tlv(0x04, token));
            out.extend(tlv(0xa0, &tlv(0x30, &[seq, tok.as_slice()].concat())));
        } else {
            out.extend(tlv(tag, inner));
        }
        cur = rest;
    }
    tlv(0x30, &out)
}

fn p256(k: [u8; 32]) -> krb5_types::pkinit::IdentityKey {
    krb5_types::pkinit::IdentityKey::P256(zeroize::Zeroizing::new(k))
}

#[test]
fn empty_150_hint_carries_populated_token() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let _ca = krb5_testkit::enable_pkinit(&mut store);
    let mut req = as_req(user(), TEST_REALM, 1701, None).unwrap();
    req.0.padata = Some(vec![PaData {
        padata_type: pa::AS_FRESHNESS,
        padata_value: Vec::<u8>::new().into(),
    }]);
    let Error::PreauthRequired { e_data } = krb5_kdc::issue_as(&store, &req).unwrap_err() else {
        panic!("want PreauthRequired");
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    let tok = method
        .iter()
        .find(|p| p.padata_type == pa::AS_FRESHNESS)
        .expect("PA-AS-FRESHNESS");
    assert!(
        tok.padata_value.as_ref().len() > 8,
        "hint 150 must be populated, types={types:?}"
    );
    let i150 = types.iter().position(|t| *t == pa::AS_FRESHNESS).unwrap();
    let i133 = types.iter().position(|t| *t == pa::FX_COOKIE).unwrap();
    assert!(i150 < i133, "150 before cookie, types={types:?}");
}

/// A signed PKINIT request carrying a freshness token ten minutes past its time.
fn stale_freshness_req(ca: &krb5_types::pkinit::PkinitCa) -> krb5_types::AsReq {
    let (cert, key) = ca
        .client_identity_for("user@KERBER.TEST")
        .expect("client id");
    let kp = p256_generate().expect("ecdh");
    let mut req = as_req(user(), TEST_REALM, 1702, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let ck = krb5_types::pkinit::kdc_req_body_checksum(&body);
    let honest = pa_pk_as_req(&kp.public, ca, Some(&ck)).expect("PA-PK-AS-REQ");
    let cms0 = parse_pa_pk_as_req_cms(honest.padata_value.as_ref()).expect("cms");
    let inner = cms_verify(&cms0, &ca.ca_cert).expect("AuthPack");
    let mut stale = 0u32.wrapping_sub(601).to_be_bytes().to_vec();
    stale.extend_from_slice(&1u32.to_be_bytes());
    stale.extend_from_slice(&[0u8; 12]);
    let inner = inject_pkauth_freshness(&inner, &stale);
    let cms = cms_sign_leaf(&inner, &cert, &p256(key), ECONTENT_AUTHDATA).expect("CMS");
    let pa = PaPkAsReq {
        signed_auth_pack: cms.into(),
        trusted_certifiers: None,
        kdc_pk_id: None,
    };
    req.0.padata = Some(vec![
        PaData {
            padata_type: pa::PK_AS_REQ,
            padata_value: encode(&pa).expect("PA-PK-AS-REQ").into(),
        },
        PaData {
            padata_type: pa::AS_FRESHNESS,
            padata_value: Vec::<u8>::new().into(),
        },
    ]);
    req
}

#[test]
fn stale_freshness_token_is_preauth_failed() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let ca = krb5_testkit::enable_pkinit(&mut store);
    let req = stale_freshness_req(&ca);
    let (code, _) = match krb5_kdc::issue_as(&store, &req).unwrap_err() {
        Error::Protocol { code, text, .. } => (code, text),
        other => panic!("want Protocol 24, got {other:?}"),
    };
    assert_eq!(code, err::PREAUTH_FAILED);
}

#[test]
fn stale_freshness_token_logs_preauth_expired_and_the_as_req_line_says_24() {
    // MIT: `check_freshness_token` (kdc/kdc_preauth.c:564-564)
    // a token the checks refuse, its age among them, is `KRB5KDC_ERR_PREAUTH_EXPIRED`.
    // MIT: `finish_verify_padata` (kdc/kdc_preauth.c:1224-1228)
    // the module's message is the verify line's.
    // MIT: `filter_preauth_error` (kdc/kdc_preauth.c:1092-1133)
    // 90 is off the pass-through list, so the `AS_REQ` line reads like a 24.
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let ca = krb5_testkit::enable_pkinit(&mut store);
    let raw = encode(&stale_freshness_req(&ca)).expect("AS-REQ");
    let (reply, log) = common::kdc_log(|| krb5_kdc::handle_request(&store, &raw));
    let e = decode::<krb5_types::KrbError>(&reply.expect("a KRB-ERROR reply")).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::PREAUTH_FAILED);
    assert_eq!(
        common::failure_trace(&log),
        [
            "preauth (pkinit) verify failure: Preauthentication expired",
            "AS_REQ PREAUTH_FAILED, Preauthentication failed",
        ]
    );
}

fn pkinit_as_req(
    cname: PrincipalName,
    nonce: u32,
    make_pa: impl FnOnce(&[u8]) -> krb5_types::PaData,
) -> krb5_types::AsReq {
    let mut req = as_req(cname, TEST_REALM, nonce, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let cksum = krb5_types::pkinit::kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![make_pa(&cksum)]);
    req
}

#[test]
fn pkinit_advertised_in_method_data_when_ca_enabled() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let _ca = krb5_testkit::enable_pkinit(&mut store);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 400, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let e_data = match err {
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected PreauthRequired, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    assert!(
        method.iter().any(|p| p.padata_type == pa::PK_AS_REQ),
        "PA-PK-AS-REQ must be advertised when the CA is provisioned: {method:?}"
    );
    assert!(method.iter().any(|p| p.padata_type == pa::ENC_TIMESTAMP));
    assert!(method.iter().any(|p| p.padata_type == pa::ETYPE_INFO2));
    assert!(
        method.iter().any(|p| p.padata_type == pa::FX_FAST),
        "PA-FX-FAST must be advertised so MIT kinit -T armors AS: {method:?}"
    );
}

#[test]
fn ca_enabled_preauth_required_method_data_types() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let _ca = krb5_testkit::enable_pkinit(&mut store);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 401, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let e_data = match err {
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected PreauthRequired, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert_eq!(
        types,
        vec![
            pa::FX_FAST,
            pa::ETYPE_INFO2,
            pa::PK_AS_REQ,
            pa::PKINIT_KX,
            pa::SPAKE,
            pa::ENC_TIMESTAMP,
            pa::FX_COOKIE,
        ],
        "CA-enabled METHOD-DATA types must pin [136, 19, 16, 147, 151, 2, 133]"
    );
    let again = encode(&method).expect("re-encode");
    let round: MethodData = decode(&again).expect("decode encode");
    assert_eq!(round, method);
    assert_eq!(again, e_data, "METHOD-DATA encode(decode) must be identity");
}

#[test]
fn pkinit_not_advertised_without_ca() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    assert!(store.pkinit().is_none());
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 399, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let e_data = match err {
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected PreauthRequired, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    assert!(
        method.iter().all(|p| p.padata_type != pa::PK_AS_REQ),
        "PA-PK-AS-REQ must not be advertised without a CA"
    );
}

#[test]
fn pkinit_san_mismatch_is_refused() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let ca = krb5_testkit::enable_pkinit(&mut store);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(cname.clone(), 422, |ck| {
        pa_pk_as_req_cn(&kp.public, &ca, "other@KERBER.TEST", Some(ck)).expect("other")
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("SAN mismatch");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::CLIENT_NAME_MISMATCH),
        other => panic!("expected CLIENT_NAME_MISMATCH, got {other}"),
    }
    let req_ok = pkinit_as_req(cname, 423, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("user")
    });
    krb5_kdc::issue_as(&store, &req_ok).expect("matching SAN");
}

#[test]
fn pkinit_signed_content_type_mismatch_is_refused() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let ca = krb5_testkit::enable_pkinit(&mut store);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req_ok = pkinit_as_req(cname.clone(), 427, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("ok")
    });
    let pa = req_ok
        .0
        .padata
        .as_ref()
        .and_then(|v| v.first())
        .expect("pa");
    let cms = krb5_types::pkinit::parse_pa_pk_as_req_cms(pa.padata_value.as_ref()).expect("cms");
    let inner = krb5_types::pkinit::cms_verify(&cms, &ca.ca_cert).expect("inner");
    let (cert, key) = ca
        .client_identity_for("user@KERBER.TEST")
        .expect("client id");
    let bad = krb5_types::pkinit::cms_sign_leaf_oids(
        &inner,
        &cert,
        &p256(key),
        krb5_types::pkinit::ECONTENT_AUTHDATA,
        krb5_types::pkinit::ECONTENT_DHKEY,
    )
    .expect("split oids");
    let wrapped = krb5_types::pkinit::PaPkAsReq {
        signed_auth_pack: bad.into(),
        trusted_certifiers: None,
        kdc_pk_id: None,
    };
    let mut req = req_ok;
    req.0.padata = Some(vec![krb5_types::PaData {
        padata_type: pa::PK_AS_REQ,
        padata_value: encode(&wrapped).expect("pa").into(),
    }]);
    let err = krb5_kdc::issue_as(&store, &req).expect_err("content-type");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
}

// MIT: `pkinit_server_verify_padata` (plugins/preauth/pkinit/pkinit_srv.c:528-532)
/// no replay cache, so a replayed AuthPack inside the skew verifies again and issues a new ticket.
#[test]
fn pkinit_replayed_authpack_is_issued_again() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let ca = krb5_testkit::enable_pkinit(&mut store);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(cname, 440, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("PA-PK-AS-REQ")
    });
    let first = krb5_kdc::issue_as(&store, &req).expect("first PKINIT");
    let again = krb5_kdc::issue_as(&store, &req).expect("the replay issues again");
    assert_ne!(
        first.session_key.as_bytes(),
        again.session_key.as_bytes(),
        "the replay is processed again, not answered from a cache"
    );
}

#[test]
fn pkinit_enterprise_san_binds_issued_cname() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let ca = krb5_testkit::enable_pkinit(&mut store);
    let stored = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user@OTHER.TEST"]);
    store
        .create_password(&acl, &documented_admin_id(), &stored, b"foreign-pass")
        .expect("create");
    let ent = PrincipalName::new(PrincipalName::NT_ENTERPRISE, ["user@OTHER.TEST"]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(ent.clone(), 428, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("san user")
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("SAN vs issued cname");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::CLIENT_NAME_MISMATCH),
        other => panic!("expected CLIENT_NAME_MISMATCH, got {other}"),
    }
    let req_ok = pkinit_as_req(ent, 429, |ck| {
        pa_pk_as_req_cn(&kp.public, &ca, "user@OTHER.TEST@KERBER.TEST", Some(ck))
            .expect("issued san")
    });
    krb5_kdc::issue_as(&store, &req_ok).expect("SAN matches issued cname");
}

#[test]
fn pkinit_padata_that_does_not_decode_logs_the_decoders_text() {
    // MIT: `pkinit_server_verify_padata` (plugins/preauth/pkinit/pkinit_srv.c:479-483)
    // a PA-PK-AS-REQ the decoder refuses fails the module with the decoder's code.
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let _ca = krb5_testkit::enable_pkinit(&mut store);
    for (n, (der, message)) in [
        (vec![0xff, 0xff], "ASN.1 encoding ended unexpectedly"),
        (
            vec![0x30, 0x00],
            "ASN.1 structure is missing a required field",
        ),
        (
            vec![0x04, 0x00],
            "ASN.1 identifier doesn't match expected value",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut req = as_req(user(), TEST_REALM, 0x4b40 + u32::try_from(n).unwrap(), None).unwrap();
        req.0.padata = Some(vec![PaData {
            padata_type: pa::PK_AS_REQ,
            padata_value: der.clone().into(),
        }]);
        let raw = encode(&req).expect("AS-REQ");
        let (reply, log) = common::kdc_log(|| krb5_kdc::handle_request(&store, &raw));
        let e =
            decode::<krb5_types::KrbError>(&reply.expect("a KRB-ERROR reply")).expect("KRB-ERROR");
        assert_eq!(e.error_code, err::PREAUTH_FAILED, "{der:02x?}");
        assert_eq!(
            common::failure_trace(&log),
            [
                format!("preauth (pkinit) verify failure: {message}"),
                "AS_REQ PREAUTH_FAILED, Preauthentication failed".to_owned(),
            ],
            "{der:02x?}"
        );
    }
}

#[test]
fn unsigned_pkinit_for_a_client_that_is_not_anonymous_logs_its_message() {
    // MIT: `pkinit_server_verify_padata` (plugins/preauth/pkinit/pkinit_srv.c:508-516)
    // an unsigned request from a client that is not anonymous is refused with this message.
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let _ca = krb5_testkit::enable_pkinit(&mut store);
    let kp = p256_generate().expect("ecdh");
    let mut req = as_req(user(), TEST_REALM, 0x4b50, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let ck = kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![
        pa_pk_as_req_unsigned(&kp.public, 0x4b50, &ck, None).expect("unsigned"),
    ]);
    let raw = encode(&req).expect("AS-REQ");
    let (reply, log) = common::kdc_log(|| krb5_kdc::handle_request(&store, &raw));
    let e = decode::<krb5_types::KrbError>(&reply.expect("a KRB-ERROR reply")).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::PREAUTH_FAILED);
    assert_eq!(
        common::failure_trace(&log),
        [
            "preauth (pkinit) verify failure: Pkinit request not signed, but client not anonymous.",
            "AS_REQ PREAUTH_FAILED, Pkinit request not signed, but client not anonymous.",
        ]
    );
}
