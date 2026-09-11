//! A′-3 item 15: hint-list order, EC outside FAST, enc_padata PAC-OPTIONS.

use krb5_asn1::{decode, decode_enc_kdc_rep_part};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
use krb5_kdc::{
    Error, PrincipalStore, TEST_REALM, TEST_USER, bootstrap_documented, documented_host,
};
use krb5_protocol::{
    armor_key, as_req, attach_fast, build_fast_armor, pa_enc_timestamp, pa_pac_options, tgs_req_ex,
    unwrap_fast_rep,
};
use krb5_types::{KdcOptions, MethodData, PaData, PrincipalName, ascii, err, ku, pa};

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

#[test]
fn as_hint_list_is_136_info2_modules_cookie() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 15001, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PreauthRequired, got {err:?}");
    };
    let method: MethodData = decode(&e_data).unwrap();
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert_eq!(
        types,
        vec![
            pa::FX_FAST,
            pa::ETYPE_INFO2,
            pa::SPAKE,
            pa::ENC_TIMESTAMP,
            pa::FX_COOKIE,
        ]
    );
}

#[test]
fn as_ec_outside_fast_is_preauth_failed() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(
        cname,
        TEST_REALM,
        15002,
        Some(vec![PaData {
            padata_type: pa::ENCRYPTED_CHALLENGE,
            padata_value: b"outside-fast".to_vec().into(),
        }]),
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    assert_eq!(proto(&err), (err::PREAUTH_FAILED, Some("PREAUTH_FAILED")));
}

#[test]
fn tgs_pac_options_rbcd_is_echoed_in_enc_padata() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 15003);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        15004,
        KdcOptions::none(),
        None,
        vec![pa_pac_options(true).unwrap()],
        vec![18],
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART).unwrap();
    let plain = decrypt(
        &issued.session_key,
        usage,
        out.rep.0.enc_part.cipher.as_ref(),
    )
    .unwrap();
    let enc = decode_enc_kdc_rep_part(&plain).unwrap();
    let types: Vec<i32> = enc
        .encrypted_pa_data
        .as_ref()
        .into_iter()
        .flatten()
        .map(|p| p.padata_type)
        .collect();
    assert!(
        types.contains(&pa::PAC_OPTIONS),
        "enc_padata types {types:?} must echo PAC-OPTIONS"
    );
}

#[test]
fn as_fast_hint_keeps_136_151_lists_138_omits_2() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let armor = user_as(&store, 15005);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x61u8; 32]).unwrap();
    let armor_ap = build_fast_armor(
        armor.rep.0.ticket.clone(),
        &armor.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .unwrap();
    let akey = armor_key(&armor.session_key, Some(&sub)).unwrap();
    let mut req = as_req(cname, TEST_REALM, 15006, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, vec![]).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PreauthRequired, got {err:?}");
    };
    let method: MethodData = decode(&e_data).unwrap();
    let fast = unwrap_fast_rep(&akey, &Some(method)).unwrap();
    let types: Vec<i32> = fast.padata.iter().map(|p| p.padata_type).collect();
    assert!(
        types.contains(&pa::FX_FAST),
        "FAST-inner METHOD-DATA keeps 136: {types:?}"
    );
    assert!(
        types.contains(&pa::SPAKE),
        "FAST-inner METHOD-DATA keeps 151: {types:?}"
    );
    assert!(
        types.contains(&pa::ENCRYPTED_CHALLENGE),
        "FAST-inner METHOD-DATA lists 138: {types:?}"
    );
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP),
        "FAST-inner METHOD-DATA omits 2: {types:?}"
    );
}
