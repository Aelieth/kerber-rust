//! A′-3 R26: `max_renewable_life` 0, AS `PRE_AUTHENT`, `check_tgs_opts` order.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, decrypt, encrypt};
use krb5_kdc::{
    Error, KDB_REQUIRES_PRE_AUTH, PrincipalStore, Restrictions, TEST_REALM, TEST_USER,
    bootstrap_documented,
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

fn cname() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn user_as(store: &PrincipalStore, nonce: u32, bits: &[(usize, bool)]) -> krb5_kdc::IssuedAs {
    let key = store
        .get_name(&cname())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let mut req = as_req(
        cname(),
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    for (bit, on) in bits {
        req.0.req_body.kdc_options = req.0.req_body.kdc_options.with_bit(*bit, *on);
    }
    krb5_kdc::issue_as(store, &req).unwrap()
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

fn forge_tgt(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs, part: &EncTicketPart) -> Ticket {
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let cipher = encrypt(&krbtgt.key, usage, &encode(part).unwrap()).unwrap();
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

#[test]
fn as_renewable_with_zero_rlife_caps_renew_till_at_start() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let rs = Restrictions {
        max_renewable_life: Some(0),
        ..Restrictions::default()
    };
    store.impose_acl_restrictions(&cname(), &rs).unwrap();
    let issued = user_as(&store, 26001, &[(flag_bit::RENEWABLE, true)]);
    let part = tgt_part(&store, &issued);
    let start = part
        .starttime
        .as_ref()
        .unwrap_or(&part.authtime)
        .unix_seconds();
    let till = part
        .renew_till
        .as_ref()
        .expect("RENEWABLE sets renew_till")
        .unix_seconds();
    assert_eq!(till, start);
}

#[test]
fn as_without_preauth_has_no_pre_authent() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let rs = Restrictions {
        forbid_attrs: !KDB_REQUIRES_PRE_AUTH,
        ..Restrictions::default()
    };
    store.impose_acl_restrictions(&cname(), &rs).unwrap();
    let req = as_req(cname(), TEST_REALM, 26011, None).unwrap();
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    assert!(!tgt_part(&store, &issued).flags.pre_authent());
}

#[test]
fn tgs_renew_invalid_non_renewable_is_ticket_not_renewable() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 26021, &[]);
    let mut part = tgt_part(&store, &issued);
    part.flags = part
        .flags
        .with_bit(flag_bit::INVALID, true)
        .with_bit(flag_bit::RENEWABLE, false);
    let tgs = tgs_req_ex(
        forge_tgt(&store, &issued, &part),
        &issued.session_key,
        TEST_REALM,
        &cname(),
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        26022,
        KdcOptions::none().with_bit(flag_bit::RENEW, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::BADOPTION, Some("TICKET NOT RENEWABLE")));
}
