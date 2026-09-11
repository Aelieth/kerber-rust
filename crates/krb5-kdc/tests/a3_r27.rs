//! A′-3 R27: S4U `t->client`, signed `ts_delta`, `check_tgs_svc_time` slot.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, decrypt, encrypt};
use krb5_kdc::{
    Error, KDB_DISALLOW_RENEWABLE, PrincipalStore, TEST_ADMIN, TEST_REALM, TEST_USER,
    bootstrap_documented, documented_host,
};
use krb5_protocol::{as_req, pa_enc_timestamp, pa_for_user, tgs_req_ex, tgs_req_ex_from};
use krb5_types::{
    EncTicketPart, EncryptedData, KdcOptions, KerberosTime, PrincipalName, Ticket, err, flag_bit,
    ku,
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

fn admin() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN])
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

fn host_as(store: &PrincipalStore, nonce: u32, renewable: bool) -> krb5_kdc::IssuedAs {
    let host = documented_host();
    let key = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let mut req = as_req(
        host,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    if renewable {
        req.0.req_body.kdc_options = req
            .0
            .req_body
            .kdc_options
            .with_bit(flag_bit::RENEWABLE, true);
    }
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn host_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
    let key = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
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

fn s4u_tgs(tgt: &krb5_kdc::IssuedAs, nonce: u32, opts: KdcOptions) -> krb5_types::TgsReq {
    let host = documented_host();
    let pa = pa_for_user(&tgt.session_key, admin(), TEST_REALM).unwrap();
    tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        nonce,
        opts,
        None,
        vec![pa],
        etypes(),
    )
    .unwrap()
}

#[test]
fn r27_s4u2self_caps_endtime_at_impersonated_max_life() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .apply_admin_fields(&admin(), None, Some(60), None, None, None, false, None)
        .unwrap();
    let tgt = host_as(&store, 27001, false);
    let out =
        krb5_kdc::issue_tgs(&store, &s4u_tgs(&tgt, 27002, KdcOptions::forwardable())).unwrap();
    let part = host_part(&store, &out);
    let start = part
        .starttime
        .as_ref()
        .unwrap_or(&part.authtime)
        .unix_seconds();
    let life = part.endtime.unix_seconds().saturating_sub(start);
    assert!(life <= 60, "life={life}");
}

#[test]
fn r27_s4u2self_disallow_renewable_user_has_no_r() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let a = store.get_name(&admin()).unwrap().attributes | KDB_DISALLOW_RENEWABLE;
    store
        .apply_admin_fields(&admin(), Some(a), None, None, None, None, false, None)
        .unwrap();
    let tgt = host_as(&store, 27011, true);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true);
    let out = krb5_kdc::issue_tgs(&store, &s4u_tgs(&tgt, 27012, opts)).unwrap();
    assert!(!host_part(&store, &out).flags.renewable());
}

#[test]
fn r27_as_till_in_past_endtime_is_till() {
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
        27021,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let till = KerberosTime::now().add_seconds(-60).unwrap();
    req.0.req_body.till = till.clone();
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    assert_eq!(
        tgt_part(&store, &issued).endtime.unix_seconds(),
        till.unix_seconds()
    );
}

#[test]
fn r27_tgs_expired_server_beats_require_auth() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let issued = user_as(&store, 27031);
    store
        .set_string(&host, "require_auth", Some("pkinit"))
        .unwrap();
    store
        .apply_admin_fields(&host, None, None, Some(1), None, None, false, None)
        .unwrap();
    let tgs = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        host,
        TEST_REALM,
        27032,
        KdcOptions::forwardable(),
        None,
        Vec::new(),
        etypes(),
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::SERVICE_EXP, Some("SERVICE EXPIRED")));
}

#[test]
fn r27_tgs_postdated_omitted_from_is_epoch() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 27041);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut part = tgt_part(&store, &issued);
    part.flags = part.flags.with_bit(flag_bit::MAY_POSTDATE, true);
    let tgt = Ticket {
        tkt_vno: issued.rep.0.ticket.tkt_vno,
        realm: issued.rep.0.ticket.realm.clone(),
        sname: issued.rep.0.ticket.sname.clone(),
        enc_part: EncryptedData {
            etype: issued.rep.0.ticket.enc_part.etype,
            kvno: issued.rep.0.ticket.enc_part.kvno,
            cipher: encrypt(&krbtgt.key, usage, &encode(&part).unwrap())
                .unwrap()
                .into(),
        },
    };
    let tgs = tgs_req_ex_from(
        tgt,
        &issued.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        27042,
        KdcOptions::none()
            .with_bit(flag_bit::MAY_POSTDATE, true)
            .with_bit(flag_bit::POSTDATED, true),
        None,
        Vec::new(),
        etypes(),
        None,
        None,
        None,
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let got = host_part(&store, &out);
    assert!(
        got.starttime.is_none(),
        "MIT from=0 is omitted on the wire (krb5_timestamp 0)"
    );
}

#[test]
fn r27_as_from_after_till_issues_expired_end() {
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
        27051,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let till = KerberosTime::now().add_seconds(30).unwrap();
    let from = KerberosTime::now().add_seconds(90).unwrap();
    req.0.req_body.from = Some(from.clone());
    req.0.req_body.till = till.clone();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::MAY_POSTDATE, true)
        .with_bit(flag_bit::POSTDATED, true);
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    let part = tgt_part(&store, &issued);
    assert_eq!(
        part.starttime.as_ref().map(KerberosTime::unix_seconds),
        Some(from.unix_seconds())
    );
    assert_eq!(part.endtime.unix_seconds(), till.unix_seconds());
}
