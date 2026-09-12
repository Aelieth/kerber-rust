//! A′-4 item 16 units that need the new `restrict_anon` / unsigned-AuthPack surface.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, ProtocolKey, p256_generate};
use krb5_kdc::{
    Error, PrincipalStore, TEST_REALM, TEST_USER, as_req, bootstrap_documented,
    decrypt_ticket_part, documented_host, tgs_req,
};
use krb5_protocol::{
    armor_key, attach_fast, build_fast_armor, pa_pk_as_req_unsigned, pkinit_reply_key_agile,
};
use krb5_types::{KrbError, PrincipalName, ascii, err, flag_bit, pa};

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
fn a4_16_restrict_anon_as_to_host() {
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
fn a4_16_restrict_anon_as_to_local_tgt() {
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
fn a4_16_anonymous_pkinit_issues_kx() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
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
        &kp.secret,
        &issued.rep.0.padata,
        EncryptionType::Aes256CtsHmacSha196,
        &ca.ca_cert,
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

#[test]
fn a4_16_restrict_anon_tgs_to_host() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    insert_anonymous(&mut store);
    let issued = unsigned_anon_as(&store, 462);
    store.policy.restrict_anon = true;
    let tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        "WELLKNOWN:ANONYMOUS",
        &wellknown_anonymous(),
        documented_host(),
        TEST_REALM,
        463,
    )
    .unwrap();
    let (code, text) = match krb5_kdc::issue_tgs(&store, &tgs).unwrap_err() {
        Error::Protocol { code, text, .. } => (code, text),
        other => panic!("want POLICY, got {other:?}"),
    };
    assert_eq!(code, err::POLICY);
    assert_eq!(text.as_deref(), Some("ANONYMOUS NOT ALLOWED"));
}

#[test]
fn a4_16_anonymous_tgt_fast_armor() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    insert_anonymous(&mut store);
    let issued = unsigned_anon_as(&store, 464);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x39u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        &ascii("WELLKNOWN:ANONYMOUS"),
        &wellknown_anonymous(),
        Some(&sub),
    )
    .expect("anonymous armor");
    let akey = armor_key(&issued.session_key, Some(&sub)).expect("armor key");
    let mut as_req = as_req(user, TEST_REALM, 465, None).unwrap();
    attach_fast(&mut as_req, &armor_ap, &akey, Vec::new()).expect("FAST wrap");
    let bytes = krb5_kdc::handle_request(&store, &encode(&as_req).unwrap()).expect("reply");
    let kerr: KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(kerr.error_code, err::PREAUTH_REQUIRED);
}

#[test]
fn a4_16_unsigned_anon_name_without_anon_bit_is_24() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    insert_anonymous(&mut store);
    let kp = p256_generate().expect("client ECDH");
    let mut req = as_req(wellknown_anonymous(), TEST_REALM, 466, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let ck = krb5_types::pkinit::kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![
        pa_pk_as_req_unsigned(&kp.public, 466, &ck, None).expect("unsigned"),
    ]);
    let (code, detail) = match krb5_kdc::issue_as(&store, &req).unwrap_err() {
        Error::Protocol { code, detail, .. } => (code, detail),
        other => panic!("want 24, got {other:?}"),
    };
    assert_eq!(code, err::PREAUTH_FAILED);
    assert!(
        detail
            .as_deref()
            .is_some_and(|d| d.contains("not signed") && d.contains("not anonymous")),
        "{detail:?}"
    );
}

#[test]
fn a4_16_unsigned_pkinit_named_is_24() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let mut req = as_req(cname, TEST_REALM, 461, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let ck = krb5_types::pkinit::kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![
        pa_pk_as_req_unsigned(&kp.public, 461, &ck, None).expect("unsigned"),
    ]);
    let (code, detail) = match krb5_kdc::issue_as(&store, &req).unwrap_err() {
        Error::Protocol { code, detail, .. } => (code, detail),
        other => panic!("want 24, got {other:?}"),
    };
    assert_eq!(code, err::PREAUTH_FAILED);
    assert!(
        detail
            .as_deref()
            .is_some_and(|d| d.contains("not signed") && d.contains("not anonymous")),
        "{detail:?}"
    );
}
