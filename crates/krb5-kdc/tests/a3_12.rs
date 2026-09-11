//! A′-3 item 12: `check_tgs_svc_reqd_flags` PRE_AUTH + `compute_ticket_times`.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, decrypt, encrypt};
use krb5_kdc::{
    Error, KDB_REQUIRES_PRE_AUTH, PrincipalStore, TEST_REALM, TEST_USER, bootstrap_documented,
    documented_host,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req_ex};
use krb5_types::{
    EncTicketPart, EncryptedData, KdcOptions, PrincipalName, Ticket, err, flag_bit, ku,
};

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

fn or_attr(store: &mut PrincipalStore, name: &PrincipalName, bit: u32) {
    let a = store.get_name(name).unwrap().attributes | bit;
    store
        .apply_admin_fields(name, Some(a), None, None, None, None, false, None)
        .unwrap();
}

fn cname() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn tgt_without_preauth(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> Ticket {
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &krbtgt.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    let mut part: EncTicketPart = decode(&plain).unwrap();
    part.flags = part.flags.with_bit(flag_bit::PRE_AUTHENT, false);
    let der = encode(&part).unwrap();
    let cipher = encrypt(&krbtgt.key, usage, &der).unwrap();
    Ticket {
        tkt_vno: issued.rep.0.ticket.tkt_vno,
        realm: issued.rep.0.ticket.realm.clone(),
        sname: issued.rep.0.ticket.sname.clone(),
        enc_part: EncryptedData {
            etype: issued.rep.0.ticket.enc_part.etype,
            kvno: issued.rep.0.ticket.enc_part.kvno,
            cipher: cipher.into(),
        },
    }
}

fn host_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
    let host = documented_host();
    let key = store.get_name(&host).unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode(&plain).unwrap()
}

fn tgt_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> EncTicketPart {
    let key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode(&plain).unwrap()
}

#[test]
fn tgs_requires_preauth_without_pa_flag_is_no_preauth() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let issued = user_as(&store, 12001);
    or_attr(&mut store, &host, KDB_REQUIRES_PRE_AUTH);
    let tgs = tgs_req_ex(
        tgt_without_preauth(&store, &issued),
        &issued.session_key,
        TEST_REALM,
        &cname(),
        host,
        TEST_REALM,
        12002,
        KdcOptions::forwardable(),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::GENERIC, Some("NO PREAUTH")));
}

#[test]
fn as_omits_starttime_when_it_matches_authtime() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 12011);
    let part = tgt_part(&store, &issued);
    assert!(part.starttime.is_none(), "starttime={:?}", part.starttime);
}

#[test]
fn tgs_caps_endtime_at_client_max_life() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 12021);
    store
        .apply_admin_fields(&cname(), None, Some(60), None, None, None, false, None)
        .unwrap();
    let tgs = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname(),
        documented_host(),
        TEST_REALM,
        12022,
        KdcOptions::forwardable(),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let part = host_part(&store, &out);
    let start = part
        .starttime
        .as_ref()
        .unwrap_or(&part.authtime)
        .unix_seconds();
    assert!(
        part.endtime.unix_seconds().saturating_sub(start) <= 60,
        "life={}",
        part.endtime.unix_seconds().saturating_sub(start)
    );
}
