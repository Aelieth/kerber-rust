//! A′-3 item 14: require_auth, CAMMAC extract, GET_AUTH_INDICATORS.

use krb5_asn1::{decode, encode};
use krb5_crypto::{KeyUsage, decrypt, encrypt};
use krb5_kdc::{
    Error, PrincipalStore, TEST_REALM, TEST_USER, bootstrap_documented, documented_host,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};
use krb5_types::{AuthorizationDataValue, EncTicketPart, PrincipalName, Ticket, err, ku, pa};

fn proto(err: &Error) -> (i32, Option<&str>) {
    match err {
        Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

fn user_as(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn krbtgt_name() -> PrincipalName {
    PrincipalName::krbtgt(TEST_REALM)
}

#[test]
fn as_require_auth_is_higher_authentication() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .set_string(&krbtgt_name(), "require_auth", Some("pkinit"))
        .unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        cname,
        TEST_REALM,
        14001,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    assert_eq!(
        proto(&err),
        (err::POLICY, Some("HIGHER_AUTHENTICATION_REQUIRED"))
    );
}

#[test]
fn tgs_require_auth_is_higher_authentication() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 14002);
    store
        .set_string(&documented_host(), "require_auth", Some("pkinit"))
        .unwrap();
    let tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]),
        documented_host(),
        TEST_REALM,
        14003,
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(
        proto(&err),
        (err::POLICY, Some("HIGHER_AUTHENTICATION_REQUIRED"))
    );
}

#[test]
fn tgs_truncated_cammac_is_get_auth_indicators() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 14004);
    let tgt_key = store
        .get_name(&krbtgt_name())
        .unwrap()
        .first_current_key()
        .unwrap()
        .key
        .clone();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &tgt_key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    let mut part: EncTicketPart = decode(&plain).unwrap();
    let mut ad = part.authorization_data.take().unwrap_or_default();
    let inner = vec![AuthorizationDataValue {
        ad_type: pa::AD_CAMMAC,
        ad_data: b"truncated".to_vec().into(),
    }];
    ad.push(AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: encode(&inner).unwrap().into(),
    });
    part.authorization_data = Some(ad);
    let cipher = encrypt(&tgt_key, usage, &encode(&part).unwrap()).unwrap();
    let mut ticket: Ticket = issued.rep.0.ticket.clone();
    ticket.enc_part.cipher = cipher.into();
    let tgs = tgs_req(
        ticket,
        &issued.session_key,
        TEST_REALM,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]),
        documented_host(),
        TEST_REALM,
        14005,
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::GENERIC, Some("GET_AUTH_INDICATORS")));
}
