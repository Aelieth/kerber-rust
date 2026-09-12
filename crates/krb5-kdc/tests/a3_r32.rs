//! A′-3 R32: PKINIT does not set `HW_AUTHENT`; RENEW uses signed header life.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, decrypt, encrypt, p256_generate};
use krb5_kdc::{
    Error, KDB_REQUIRES_HW_AUTH, PrincipalStore, TEST_REALM, TEST_USER, bootstrap_documented,
    documented_host,
};
use krb5_protocol::{as_req, pa_enc_timestamp, pa_pk_as_req, tgs_req_ex};
use krb5_types::{
    EncTicketPart, EncryptedData, KdcOptions, MethodData, PrincipalName, Ticket, err, flag_bit, ku,
    pa,
};

fn proto(err: &Error) -> (i32, Option<&str>) {
    match err {
        Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

fn etypes() -> Vec<i32> {
    vec![EncryptionType::Aes256CtsHmacSha196.to_iana()]
}

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn krbtgt() -> PrincipalName {
    PrincipalName::krbtgt(TEST_REALM)
}

fn or_attr(store: &mut PrincipalStore, name: &PrincipalName, bit: u32) {
    let a = store.get_name(name).unwrap().attributes | bit;
    store
        .apply_admin_fields(name, Some(a), None, None, None, None, false, None)
        .unwrap();
}

fn tgt_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> EncTicketPart {
    let key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    decode(
        &decrypt(
            &key.key,
            usage,
            issued.rep.0.ticket.enc_part.cipher.as_ref(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn tgs_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
    let key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    decode(
        &decrypt(
            &key.key,
            usage,
            issued.rep.0.ticket.enc_part.cipher.as_ref(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn pkinit_as(store: &PrincipalStore, nonce: u32) -> Result<krb5_kdc::IssuedAs, Error> {
    let ca = store.pkinit_ca().expect("CA").clone();
    let kp = p256_generate().unwrap();
    let mut req = as_req(user(), TEST_REALM, nonce, None).unwrap();
    let body = encode(&req.0.req_body).unwrap();
    let cksum = krb5_types::pkinit::kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![
        pa_pk_as_req(&kp.public, &ca, Some(cksum.as_slice())).unwrap(),
    ]);
    krb5_kdc::issue_as(store, &req)
}

#[test]
fn r32_pkinit_tgt_has_no_hw_authent() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.enable_pkinit_ca().unwrap();
    let part = tgt_part(&store, &pkinit_as(&store, 32001).unwrap());
    assert!(part.flags.bit(flag_bit::PRE_AUTHENT));
    assert!(!part.flags.bit(flag_bit::HW_AUTHENT));
}

#[test]
fn r32_pkinit_client_requires_hwauth_is_needed_hw_preauth() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.enable_pkinit_ca().unwrap();
    or_attr(&mut store, &user(), KDB_REQUIRES_HW_AUTH);
    match pkinit_as(&store, 32002).unwrap_err() {
        Error::Protocol {
            code,
            text,
            e_data: Some(ed),
            ..
        } if code == err::PREAUTH_REQUIRED && text.as_deref() == Some("NEEDED_HW_PREAUTH") => {
            let types: Vec<i32> = decode::<MethodData>(&ed)
                .unwrap()
                .iter()
                .map(|p| p.padata_type)
                .collect();
            assert!(
                types.contains(&pa::PK_AS_REQ),
                "hw_only still advertises PA-PK-AS-REQ, got {types:?}"
            );
            assert!(
                !types.contains(&pa::PKINIT_KX),
                "pkinit_srv.c:928-929 PKINIT_KX is PA_INFO, skipped under hw_only, got {types:?}"
            );
        }
        other => panic!("expected Protocol NEEDED_HW_PREAUTH with e_data, got {other:?}"),
    }
}

#[test]
fn r32_pkinit_tgs_requires_hwauth_is_no_hw_preauth() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.enable_pkinit_ca().unwrap();
    let host = documented_host();
    or_attr(&mut store, &host, KDB_REQUIRES_HW_AUTH);
    let issued = pkinit_as(&store, 32003).unwrap();
    let tgs = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        host,
        TEST_REALM,
        32004,
        KdcOptions::forwardable(),
        None,
        Vec::new(),
        etypes(),
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::GENERIC, Some("NO HW PREAUTH")));
}

#[test]
fn r32_renew_header_end_before_start_is_expired() {
    let (store, _) = bootstrap_documented().unwrap();
    let key = store
        .get_name(&user())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let mut req = as_req(
        user(),
        TEST_REALM,
        32011,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    let krbtgt_key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut part = tgt_part(&store, &issued);
    let start = part
        .starttime
        .clone()
        .unwrap_or_else(|| part.authtime.clone());
    part.endtime = start.add_seconds(-60).unwrap();
    part.flags = part.flags.with_bit(flag_bit::RENEWABLE, true);
    if part.renew_till.is_none() {
        part.renew_till = Some(start.add_hours(24).unwrap());
    }
    let tgt = Ticket {
        tkt_vno: issued.rep.0.ticket.tkt_vno,
        realm: issued.rep.0.ticket.realm.clone(),
        sname: issued.rep.0.ticket.sname.clone(),
        enc_part: EncryptedData {
            etype: issued.rep.0.ticket.enc_part.etype,
            kvno: issued.rep.0.ticket.enc_part.kvno,
            cipher: encrypt(&krbtgt_key.key, usage, &encode(&part).unwrap())
                .unwrap()
                .into(),
        },
    };
    let tgs = tgs_req_ex(
        tgt,
        &issued.session_key,
        TEST_REALM,
        &user(),
        krbtgt(),
        TEST_REALM,
        32012,
        KdcOptions::none()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
        None,
        Vec::new(),
        etypes(),
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let got = tgs_part(&store, &out);
    let start = got
        .starttime
        .as_ref()
        .unwrap_or(&got.authtime)
        .unix_seconds();
    let life = i64::from(got.endtime.unix_seconds()) - i64::from(start);
    assert_eq!(life, -60);
}
