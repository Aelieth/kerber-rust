//! Anonymous AS requests: `restrict_anon`, anonymous PKINIT, and the unsigned AuthPack.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, p256_generate};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented, documented_host};
use krb5_kdc::{AdminFields, Error, KDB_REQUIRES_PRE_AUTH, PrincipalStore, decrypt_ticket_part};
use krb5_protocol::as_req;

use krb5_protocol::{pa_pk_as_req_unsigned, pkinit_reply_key_agile};
use krb5_types::{KerberosTime, PrincipalName, err, flag_bit, pa};

#[test]
fn named_anon_without_preauth_is_validate_anonymous() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = as_req(cname, TEST_REALM, 57, None).unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::ANONYMOUS, true);
    let (code, text) = match krb5_kdc::issue_as(&store, &req).unwrap_err() {
        Error::Protocol { code, text, .. } => (code, text),
        other => panic!("want Protocol 13 before preauth, got {other:?}"),
    };
    assert_eq!(code, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("VALIDATE_ANONYMOUS_PRINCIPAL"));
}

fn wellknown_anonymous() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_WELLKNOWN, ["WELLKNOWN", "ANONYMOUS"])
}

fn insert_anonymous(store: &mut PrincipalStore) {
    store
        .insert_new_password(
            &wellknown_anonymous(),
            TEST_REALM,
            b"anon",
            &[EncryptionType::Aes256CtsHmacSha196],
            "kadmin/admin@KERBER.TEST",
        )
        .expect("WELLKNOWN/ANONYMOUS");
}

fn unsigned_anon_as(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let anon = wellknown_anonymous();
    let kp = p256_generate().expect("client ECDH");
    let mut req = as_req(anon, TEST_REALM, nonce, None).unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::ANONYMOUS, true);
    let body = encode(&req.0.req_body).expect("body");
    let ck = krb5_types::pkinit::kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![
        pa_pk_as_req_unsigned(&kp.public, nonce, &ck, None).expect("unsigned AuthPack"),
    ]);
    krb5_kdc::issue_as(store, &req).expect("anonymous PKINIT")
}

#[test]
fn restrict_anon_as_to_host() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.policy.restrict_anon = true;
    insert_anonymous(&mut store);
    let mut req = krb5_protocol::as_req_sname(
        wellknown_anonymous(),
        TEST_REALM,
        58,
        None,
        documented_host(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::ANONYMOUS, true);
    let (code, text) = match krb5_kdc::issue_as(&store, &req).unwrap_err() {
        Error::Protocol { code, text, .. } => (code, text),
        other => panic!("want POLICY, got {other:?}"),
    };
    assert_eq!(code, err::POLICY);
    assert_eq!(text.as_deref(), Some("ANONYMOUS NOT ALLOWED"));
}

#[test]
fn restrict_anon_as_to_local_tgt() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.policy.restrict_anon = true;
    insert_anonymous(&mut store);
    let mut req = as_req(wellknown_anonymous(), TEST_REALM, 59, None).unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::ANONYMOUS, true);
    match krb5_kdc::issue_as(&store, &req).unwrap_err() {
        Error::PreauthRequired { .. } => {}
        Error::Protocol {
            code,
            text: Some(t),
            ..
        } if code == err::POLICY && t == "ANONYMOUS NOT ALLOWED" => {
            panic!("local TGT must pass check_anon")
        }
        other => panic!("want PreauthRequired, got {other:?}"),
    }
}

#[test]
fn anonymous_pkinit_issues_kx() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let ca = krb5_testkit::enable_pkinit(&mut store);
    store.policy.pkinit_indicators = vec!["pkinit".into()];
    insert_anonymous(&mut store);
    let kp = p256_generate().expect("client ECDH");
    let anon = wellknown_anonymous();
    let mut req = as_req(anon.clone(), TEST_REALM, 460, None).unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::ANONYMOUS, true);
    let body = encode(&req.0.req_body).expect("body");
    let ck = krb5_types::pkinit::kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![
        pa_pk_as_req_unsigned(&kp.public, 460, &ck, None).expect("unsigned AuthPack"),
    ]);
    let issued = krb5_kdc::issue_as(&store, &req).expect("anonymous PKINIT");
    assert_eq!(
        issued.rep.0.cname.components_joined(),
        "WELLKNOWN/ANONYMOUS"
    );
    assert_eq!(
        String::from_utf8_lossy(issued.rep.0.crealm.as_bytes()),
        "WELLKNOWN:ANONYMOUS"
    );
    let types: Vec<i32> = issued
        .rep
        .0
        .padata
        .as_ref()
        .into_iter()
        .flatten()
        .map(|p| p.padata_type)
        .collect();
    assert!(types.contains(&pa::PKINIT_KX), "PA-PKINIT-KX: {types:?}");
    assert!(types.contains(&pa::PK_AS_REP), "PA-PK-AS-REP: {types:?}");
    let reply = pkinit_reply_key_agile(
        &p256_kx(&kp.secret),
        &issued.rep.0.padata,
        EncryptionType::Aes256CtsHmacSha196,
        krb5_protocol::KdcTrust::anchor(&ca.ca_cert),
        &encode(&req).expect("as-req"),
        &anon,
        TEST_REALM,
    )
    .expect("agile key");
    assert_eq!(reply.as_bytes(), issued.as_rep_key.as_bytes());
    let part = decrypt_ticket_part(
        &store.krbtgt().unwrap().best_key().unwrap().key,
        &issued.rep.0.ticket,
    )
    .expect("ticket");
    assert_eq!(
        String::from_utf8_lossy(part.crealm.as_bytes()),
        "WELLKNOWN:ANONYMOUS"
    );
    assert!(part.flags.bit(flag_bit::ANONYMOUS), "TKT_FLG_ANONYMOUS");
    assert!(
        part.authorization_data
            .as_ref()
            .is_none_or(|ad| { !ad.iter().any(|v| v.ad_type == pa::AD_WIN2K_PAC) }),
        "no PAC on anonymous tickets"
    );
}

/// MIT 1.22.2, settled live: an anonymous PKINIT reply stamps the anonymous principal's last
/// success, the KDC giving the entry `REQUIRES_PRE_AUTH` for its audit; the stored entry keeps its
/// own flags, where MIT's db2 saves the flag with the stamp.
#[test]
fn an_anonymous_reply_stamps_the_anonymous_principals_last_success() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let _ca = krb5_testkit::enable_pkinit(&mut store);
    insert_anonymous(&mut store);
    let attributes = store
        .get_name(&wellknown_anonymous())
        .expect("anonymous")
        .attributes;
    store
        .apply_admin_fields(
            &wellknown_anonymous(),
            AdminFields {
                attributes: Some(attributes & !KDB_REQUIRES_PRE_AUTH),
                ..AdminFields::default()
            },
        )
        .expect("as MIT's addprinc makes it, without +requires_preauth");
    let before = KerberosTime::now().unix_seconds();
    unsigned_anon_as(&store, 467);
    let anon = store.get_name(&wellknown_anonymous()).expect("anonymous");
    assert_eq!(
        anon.attributes & KDB_REQUIRES_PRE_AUTH,
        0,
        "the flag is not stored"
    );
    let stamped = store.last_success_of(anon);
    assert!(stamped >= before, "last success {stamped}, before {before}");
}

fn p256_kx(secret: &[u8; 32]) -> krb5_types::pkinit::KxKey {
    krb5_types::pkinit::KxKey::from_secret(krb5_types::pkinit::KxGroup::P256, secret)
        .expect("P-256 key")
}
