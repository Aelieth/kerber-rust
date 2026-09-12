//! A′-4 item 17 units that need `pkinit_require_freshness` / token mint.

use krb5_asn1::{decode, encode};
use krb5_crypto::p256_generate;
use krb5_kdc::{Error, TEST_REALM, TEST_USER, as_req, bootstrap_documented};
use krb5_protocol::{pa_pk_as_req_signed, pa_pk_as_req_unsigned};
use krb5_types::{
    MethodData, PaData, PrincipalName, err, flag_bit, pa,
    pkinit::{kdc_req_body_checksum, parse_authpack_freshness_token},
};

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn wellknown_anonymous() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_WELLKNOWN, ["WELLKNOWN", "ANONYMOUS"])
}

fn hint_token(store: &krb5_kdc::PrincipalStore) -> Vec<u8> {
    let mut req = as_req(user(), TEST_REALM, 1710, None).unwrap();
    req.0.padata = Some(vec![PaData {
        padata_type: pa::AS_FRESHNESS,
        padata_value: Vec::<u8>::new().into(),
    }]);
    let Error::PreauthRequired { e_data } = krb5_kdc::issue_as(store, &req).unwrap_err() else {
        panic!("want PreauthRequired for token mint");
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    method
        .iter()
        .find(|p| p.padata_type == pa::AS_FRESHNESS)
        .map(|p| p.padata_value.as_ref().to_vec())
        .filter(|v| v.len() > 8)
        .expect("populated 150")
}

#[test]
fn a4_17_no_150_in_request_omits_token_from_hint() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let req = as_req(user(), TEST_REALM, 1711, None).unwrap();
    let Error::PreauthRequired { e_data } = krb5_kdc::issue_as(&store, &req).unwrap_err() else {
        panic!("want PreauthRequired");
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    assert!(
        !method.iter().any(|p| p.padata_type == pa::AS_FRESHNESS),
        "must not mint 150 unless the request advertised it"
    );
}

#[test]
fn a4_17_require_freshness_signed_without_token_is_24() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    store.policy.pkinit_require_freshness = true;
    let ca = store.pkinit_ca().expect("CA").clone();
    let (cert, key) = ca
        .client_identity_for("user@KERBER.TEST")
        .expect("client id");
    let kp = p256_generate().expect("ecdh");
    let mut req = as_req(user(), TEST_REALM, 1712, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let ck = kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![
        pa_pk_as_req_signed(&kp.public, &cert, &key, 1712, &ck, None).expect("signed"),
        PaData {
            padata_type: pa::AS_FRESHNESS,
            padata_value: Vec::<u8>::new().into(),
        },
    ]);
    let (code, _) = match krb5_kdc::issue_as(&store, &req).unwrap_err() {
        Error::Protocol { code, text, .. } => (code, text),
        other => panic!("want 24, got {other:?}"),
    };
    assert_eq!(code, err::PREAUTH_FAILED);
}

#[test]
fn a4_17_require_freshness_signed_with_token_issues() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    store.policy.pkinit_require_freshness = true;
    let ca = store.pkinit_ca().expect("CA").clone();
    let (cert, key) = ca
        .client_identity_for("user@KERBER.TEST")
        .expect("client id");
    let token = hint_token(&store);
    let kp = p256_generate().expect("ecdh");
    let mut req = as_req(user(), TEST_REALM, 1713, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let ck = kdc_req_body_checksum(&body);
    let pa = pa_pk_as_req_signed(&kp.public, &cert, &key, 1713, &ck, Some(&token)).expect("signed");
    let cms = krb5_types::pkinit::parse_pa_pk_as_req_cms(pa.padata_value.as_ref()).expect("cms");
    let inner = krb5_types::pkinit::cms_verify(&cms, &ca.ca_cert).expect("inner");
    assert_eq!(
        parse_authpack_freshness_token(&inner).as_deref(),
        Some(token.as_slice())
    );
    req.0.padata = Some(vec![
        pa,
        PaData {
            padata_type: pa::AS_FRESHNESS,
            padata_value: Vec::<u8>::new().into(),
        },
    ]);
    krb5_kdc::issue_as(&store, &req).expect("signed PKINIT with freshness");
}

#[test]
fn a4_17_require_freshness_unsigned_without_token_issues() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    store.policy.pkinit_require_freshness = true;
    store
        .insert_new_password(
            &wellknown_anonymous(),
            TEST_REALM,
            b"anon",
            &[krb5_crypto::EncryptionType::Aes256CtsHmacSha196],
        )
        .expect("WELLKNOWN/ANONYMOUS");
    let kp = p256_generate().expect("ecdh");
    let mut req = as_req(wellknown_anonymous(), TEST_REALM, 1714, None).unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::ANONYMOUS, true);
    let body = encode(&req.0.req_body).expect("body");
    let ck = kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![
        pa_pk_as_req_unsigned(&kp.public, 1714, &ck, None).expect("unsigned"),
    ]);
    krb5_kdc::issue_as(&store, &req).expect("anonymous PKINIT without token");
}
