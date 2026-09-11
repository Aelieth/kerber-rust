//! A′-3 R29: unkeyed CAMMAC KDC verifier is skipped.

use krb5_asn1::{decode, encode};
use krb5_crypto::{KeyUsage, ProtocolKey, checksum, decrypt, encrypt, unkeyed_checksum};
use krb5_kdc::{
    Error, PrincipalStore, TEST_REALM, TEST_USER, bootstrap_documented, documented_host, issue_tgs,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};
use krb5_types::cammac::{Cammac, VerifierMac};
use krb5_types::{
    AuthorizationData, AuthorizationDataValue, Checksum, EncTicketPart, PrincipalName, Ticket, err,
    ku, pa,
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

fn krbtgt() -> PrincipalName {
    PrincipalName::krbtgt(TEST_REALM)
}

fn user_as(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let key = store
        .get_name(&user())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        user(),
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn tgt_key(store: &PrincipalStore) -> (ProtocolKey, u32) {
    let e = store
        .get_name(&krbtgt())
        .unwrap()
        .first_current_key()
        .unwrap();
    (e.key.clone(), e.kvno)
}

fn decrypt_tgt(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> EncTicketPart {
    let (key, _) = tgt_key(store);
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    decode(&decrypt(&key, usage, issued.rep.0.ticket.enc_part.cipher.as_ref()).unwrap()).unwrap()
}

fn wrap_if_relevant(inner: &[AuthorizationDataValue]) -> AuthorizationData {
    vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: encode(&inner.to_vec()).unwrap().into(),
    }]
}

fn indicator_elements() -> AuthorizationData {
    vec![AuthorizationDataValue {
        ad_type: pa::AD_AUTH_INDICATOR,
        ad_data: encode(&vec!["pkinit".to_string()]).unwrap().into(),
    }]
}

fn kdcver_der(part: &EncTicketPart, elements: &[AuthorizationDataValue]) -> Vec<u8> {
    let mut ck = part.clone();
    ck.authorization_data = Some(elements.to_vec());
    encode(&ck).unwrap()
}

fn attach_cammac(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs, cksumtype: i32) -> Ticket {
    let (key, kvno) = tgt_key(store);
    let mut part = decrypt_tgt(store, issued);
    let elements = indicator_elements();
    let der = kdcver_der(&part, &elements);
    let usage = KeyUsage::new(ku::CAMMAC).unwrap();
    let mac = if cksumtype == 0 {
        checksum(&key, usage, &der).unwrap()
    } else {
        unkeyed_checksum(cksumtype, &der).unwrap()
    };
    let cammac = Cammac {
        elements,
        kdc_verifier: Some(VerifierMac {
            identifier: None,
            kvno: Some(kvno),
            enctype: None,
            mac: Checksum {
                cksumtype,
                checksum: mac.into(),
            },
        }),
        svc_verifier: None,
        other_verifiers: None,
    };
    let wrapped = wrap_if_relevant(&[AuthorizationDataValue {
        ad_type: pa::AD_CAMMAC,
        ad_data: encode(&cammac).unwrap().into(),
    }]);
    let mut ad = part.authorization_data.take().unwrap_or_default();
    ad.extend(wrapped);
    part.authorization_data = Some(ad);
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let cipher = encrypt(&key, usage, &encode(&part).unwrap()).unwrap();
    let mut ticket = issued.rep.0.ticket.clone();
    ticket.enc_part.cipher = cipher.into();
    ticket
}

fn tgs_require_auth(
    store: &mut PrincipalStore,
    ticket: Ticket,
    session: &ProtocolKey,
    nonce: u32,
    req: &str,
) -> Result<krb5_kdc::IssuedTgs, Error> {
    store
        .set_string(&documented_host(), "require_auth", Some(req))
        .unwrap();
    let tgs = tgs_req(
        ticket,
        session,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        nonce,
    )
    .unwrap();
    issue_tgs(store, &tgs)
}

fn expect_higher(
    store: &mut PrincipalStore,
    issued: &krb5_kdc::IssuedAs,
    cksumtype: i32,
    nonce: u32,
) {
    let ticket = attach_cammac(store, issued, cksumtype);
    let err = tgs_require_auth(store, ticket, &issued.session_key, nonce, "pkinit").unwrap_err();
    assert_eq!(
        proto(&err),
        (err::POLICY, Some("HIGHER_AUTHENTICATION_REQUIRED"))
    );
}

#[test]
fn r29_cammac_rsa_md5_kdcver_is_skipped() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 29001);
    expect_higher(&mut store, &issued, 7, 29002);
}

#[test]
fn r29_cammac_sha1_kdcver_is_skipped() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 29003);
    expect_higher(&mut store, &issued, 14, 29004);
}

#[test]
fn r29_cammac_md4_kdcver_is_skipped() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 29005);
    expect_higher(&mut store, &issued, 2, 29006);
}

#[test]
fn r29_cammac_nist_sha_kdcver_is_skipped() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 29007);
    expect_higher(&mut store, &issued, 9, 29008);
}

#[test]
fn r29_cammac_cksumtype_zero_kdcver_is_skipped() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 29009);
    expect_higher(&mut store, &issued, 0, 29010);
}

#[test]
fn r29_cammac_unkeyed_does_not_satisfy_any_match() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 29011);
    let ticket = attach_cammac(&store, &issued, 7);
    let err = tgs_require_auth(
        &mut store,
        ticket,
        &issued.session_key,
        29012,
        "pkinit spake",
    )
    .unwrap_err();
    assert_eq!(
        proto(&err),
        (err::POLICY, Some("HIGHER_AUTHENTICATION_REQUIRED"))
    );
}
