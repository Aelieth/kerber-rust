//! A′-3 R27: S4U `t->client`, signed `ts_delta`, `check_tgs_svc_time` slot.
//! A′-4 item 19 units that compile at `7403ec6` and fail there.
//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.
//! Z6.6: unset `kdc.conf` `max_life` is `params.max_life` = 24 h
//! (`alt_prof.c:574-575` `GET_DELTAT_PARAM(…, 24 * 60 * 60)`). Compiles
//! at the parent: create already takes `Policy::max_life` / `KdcConf::max_life`;
//! the parent defaults both to 10 h.
//! Z7.1: lifetime defaults whole. Compiles at `818d4d6` (parent-red):
//! omitted `max_renewable_life` still fed the create field (0) into the
//! KDC issue cap, `synthesize_km` hard-coded 10 h / 7 d, and `as_ex`
//! `till` fell back to 10 h. Do not name `realm_max_renewable_life` here.
//! Z8 leftover: `add_admin_princ` sets `KADM5_MAX_LIFE`
//! (`kadm5_create.c:54-55,207-213`). Compiles at the parent:
//! `bootstrap_documented` and the kadmin names exist; the parent
//! leaves `params.max_life` (24 h).

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_asn1::{decode, decode_enc_kdc_rep_part, encode};
use krb5_crypto::{EncryptionType, KeyUsage, decrypt};
use krb5_kdc::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_POSTDATED, KDB_DISALLOW_RENEWABLE, PrincipalStore,
    TEST_REALM, TEST_USER, as_req, bootstrap_documented, decrypt_ticket_part, documented_changepw,
    documented_host, documented_kadmin, dump_store, pa_enc_timestamp, parse_dump, tgs_req,
};
use krb5_testkit::{TgsReqBuilder, status, user, user_as};
use krb5_types::{
    EncKdcRepPart, EncTicketPart, KdcOptions, KerberosTime, KrbError, PrincipalName, err, flag_bit,
    ku,
};

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

fn enc_as(issued: &krb5_kdc::IssuedAs) -> krb5_types::EncKdcRepPart {
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(
        &issued.as_rep_key,
        usage,
        issued.rep.0.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode_enc_kdc_rep_part(&plain).unwrap()
}

fn ticket_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> krb5_types::EncTicketPart {
    let key = store
        .get_name(&PrincipalName::krbtgt(TEST_REALM))
        .unwrap()
        .best_key()
        .unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    krb5_asn1::decode(&plain).unwrap()
}

#[test]
fn a4_19_last_req_is_lrq_none_epoch() {
    let (store, _) = bootstrap_documented().unwrap();
    let enc = enc_as(&user_as(&store, 1901));
    assert_eq!(enc.last_req.len(), 1);
    assert_eq!(enc.last_req[0].lr_type, 0);
    assert_eq!(enc.last_req[0].lr_value.unix_seconds(), 0);
}

#[test]
fn a4_19_as_key_exp_is_min_of_expiration_and_pw_expire() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let now = KerberosTime::now().unix_seconds();
    store
        .apply_admin_fields(
            &user(),
            None,
            None,
            Some(now + 4 * 86400),
            Some(now + 2 * 86400),
            None,
            false,
            None,
        )
        .unwrap();
    let enc = enc_as(&user_as(&store, 1902));
    assert_eq!(
        enc.key_expiration.as_ref().map(KerberosTime::unix_seconds),
        Some(now + 2 * 86400)
    );
}

#[test]
fn a4_19_renew_postdated_starts_at_from() {
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
        1905,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true)
        .with_bit(flag_bit::MAY_POSTDATE, true);
    let tgt = krb5_kdc::issue_as(&store, &req).unwrap();
    let from = KerberosTime::now().add_seconds(3600).unwrap();
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user(),
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        1906,
    )
    .options(
        KdcOptions::none()
            .with_bit(flag_bit::RENEW, true)
            .with_bit(flag_bit::POSTDATED, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .addresses(None)
    .from(Some(from.clone()))
    .enc_authorization_data(None)
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let part = ticket_part(&store, &out);
    assert_eq!(
        part.starttime
            .as_ref()
            .unwrap_or(&part.authtime)
            .unix_seconds(),
        from.unix_seconds()
    );
}

fn decode_enc_part(plain: &[u8]) -> EncKdcRepPart {
    krb5_asn1::decode_enc_kdc_rep_part(plain).expect("enc-part")
}

fn user_as_req(nonce: u32) -> krb5_types::AsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa-ts")]),
    )
    .unwrap()
}

fn or_attr(store: &mut PrincipalStore, name: &PrincipalName, bit: u32) {
    let a = store.get_name(name).unwrap().attributes | bit;
    store
        .apply_admin_fields(name, Some(a), None, None, None, None, false, None)
        .unwrap();
}

fn tgt_part_issue_acl_ap(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> EncTicketPart {
    let tgt_key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &tgt_key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode(&plain).unwrap()
}

fn host_tgs(
    _store: &PrincipalStore,
    issued: &krb5_kdc::IssuedAs,
    nonce: u32,
) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        nonce,
    )
    .unwrap()
}

fn wait_unix_past(target: u32) {
    let cap = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while KerberosTime::now().unix_seconds() <= target {
        assert!(
            std::time::Instant::now() < cap,
            "unix seconds did not pass {target} within 2s"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn tgs_tgt_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
    let tgt_key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &tgt_key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode(&plain).unwrap()
}

fn postdated_as_req(nonce: u32, from: KerberosTime) -> krb5_types::AsReq {
    let mut req = user_as_req(nonce);
    req.0.req_body.from = Some(from);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::MAY_POSTDATE, true)
        .with_bit(flag_bit::POSTDATED, true);
    req
}

fn validate_tgs(issued: &krb5_kdc::IssuedAs, nonce: u32) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        nonce,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::VALIDATE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("VALIDATE TGS-REQ")
}

#[test]
fn as_rep_flags_are_initial_and_preauth_not_renewable() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname,
        TEST_REALM,
        42,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let issued = krb5_kdc::issue_as(&store, &req).expect("AS");
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&key, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("dec");
    assert_eq!(
        plain.first().copied(),
        Some(0x7a),
        "APPLICATION 26 EncKDCRepPart"
    );
    let enc = decode_enc_part(&plain);
    assert!(enc.flags.initial());
    assert!(enc.flags.pre_authent());
    assert!(!enc.flags.renewable());
    assert!(enc.renew_till.is_none());
}

#[test]
fn as_rejects_expired_principal_before_expired_password() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .apply_admin_fields(&cname, None, None, Some(1), Some(1), None, false, None)
        .unwrap();
    let err = krb5_kdc::issue_as(&store, &user_as_req(41)).unwrap_err();
    assert_eq!(status(&err).0, err::NAME_EXP);

    let raw = encode(&user_as_req(42)).unwrap();
    let reply = krb5_kdc::handle_request(&store, &raw).unwrap();
    let krb: KrbError = decode(&reply).expect("KRB-ERROR");
    assert_eq!(krb.error_code, err::NAME_EXP);
}

#[test]
fn as_zero_expiration_still_issues() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .apply_admin_fields(&cname, None, None, Some(0), Some(0), None, false, None)
        .unwrap();
    krb5_kdc::issue_as(&store, &user_as_req(45)).expect("0 = never");
    store
        .apply_admin_fields(
            &cname,
            None,
            None,
            Some(u32::MAX),
            Some(u32::MAX),
            None,
            false,
            None,
        )
        .unwrap();
    krb5_kdc::issue_as(&store, &user_as_req(46)).expect("future still issues");
}

#[test]
fn as_strips_renewable_when_disallow_renewable() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = user_as_req(62);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    or_attr(&mut store, &cname, KDB_DISALLOW_RENEWABLE);
    let issued = krb5_kdc::issue_as(&store, &req).expect("AS");
    assert!(!tgt_part_issue_acl_ap(&store, &issued).flags.renewable());
}

#[test]
fn as_disallow_all_tix_still_client_revoked() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    or_attr(&mut store, &cname, KDB_DISALLOW_ALL_TIX);
    let err = krb5_kdc::issue_as(&store, &user_as_req(64)).unwrap_err();
    assert_eq!(status(&err).0, err::CLIENT_REVOKED);
}

#[test]
fn as_postdated_is_invalid_until_validate() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.policy.skew = 0;
    let from = KerberosTime::now().add_seconds(1).unwrap();
    let issued =
        krb5_kdc::issue_as(&store, &postdated_as_req(110, from.clone())).expect("postdated AS");
    let part = tgt_part_issue_acl_ap(&store, &issued);
    assert!(part.flags.invalid());
    assert!(part.flags.bit(flag_bit::POSTDATED));
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 111)).unwrap_err();
    assert_eq!(status(&err).0, err::TKT_NYV);
    let too_soon = krb5_kdc::issue_tgs(&store, &validate_tgs(&issued, 112)).unwrap_err();
    assert_eq!(status(&too_soon).0, err::TKT_NYV);
    // starttime is now+1 s; wait until that integer second has passed.
    wait_unix_past(from.unix_seconds());
    let out = krb5_kdc::issue_tgs(&store, &validate_tgs(&issued, 113)).expect("VALIDATE");
    let after = tgs_tgt_part(&store, &out);
    assert!(!after.flags.invalid());
    krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 114))
        .expect_err("unvalidated TGT still NYV");
}

#[test]
fn as_may_postdate_alone_does_not_postdate() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let from = KerberosTime::now().add_seconds(60).unwrap();
    let mut req = user_as_req(123);
    req.0.req_body.from = Some(from);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::MAY_POSTDATE, true);
    let issued = krb5_kdc::issue_as(&store, &req).expect("AS");
    let part = tgt_part_issue_acl_ap(&store, &issued);
    assert!(!part.flags.invalid());
    assert!(!part.flags.bit(flag_bit::POSTDATED));
    assert!(part.flags.bit(flag_bit::MAY_POSTDATE));
}

#[test]
fn as_cannot_postdate_when_disallow() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    or_attr(&mut store, &cname, KDB_DISALLOW_POSTDATED);
    let from = KerberosTime::now().add_seconds(30).unwrap();
    let err = krb5_kdc::issue_as(&store, &postdated_as_req(115, from)).unwrap_err();
    assert_eq!(status(&err).0, err::CANNOT_POSTDATE);
}

#[test]
fn as_postdated_end_is_absolute_till() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let from = KerberosTime::now().add_seconds(60).unwrap();
    let till = from.add_seconds(300).unwrap();
    let mut req = postdated_as_req(121, from.clone());
    req.0.req_body.till = till.clone();
    let issued = krb5_kdc::issue_as(&store, &req).expect("postdated AS");
    let part = tgt_part_issue_acl_ap(&store, &issued);
    assert_eq!(
        part.starttime.as_ref().map(KerberosTime::unix_seconds),
        Some(from.unix_seconds())
    );
    assert_eq!(part.endtime.unix_seconds(), till.unix_seconds());
}

#[test]
fn as_from_after_till_endtime_is_till() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let till = KerberosTime::now().add_seconds(30).unwrap();
    let from = KerberosTime::now().add_seconds(90).unwrap();
    let mut req = postdated_as_req(122, from.clone());
    req.0.req_body.till = till.clone();
    let issued = krb5_kdc::issue_as(&store, &req).expect("from after till");
    let part = tgt_part_issue_acl_ap(&store, &issued);
    assert_eq!(
        part.starttime.as_ref().map(KerberosTime::unix_seconds),
        Some(from.unix_seconds())
    );
    assert_eq!(part.endtime.unix_seconds(), till.unix_seconds());
}

const ACTOR: &str = "kadmin/admin@KERBER.TEST";

fn name(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

#[test]
fn z6_params_max_life_default_is_one_day() {
    let (mut store, _) = bootstrap_documented().unwrap();
    assert_eq!(
        store.policy().max_life,
        24 * 3600,
        "Policy default is alt_prof.c 24 h, not 10 h"
    );
    store
        .insert_new_password(&name("z66"), TEST_REALM, b"x", &[], ACTOR)
        .unwrap();
    assert_eq!(store.get_name(&name("z66")).unwrap().max_life, 24 * 3600);

    let conf =
        krb5_config::KdcConf::parse(&format!("[realms]\n    {TEST_REALM} = {{\n    }}\n")).unwrap();
    assert_eq!(
        conf.max_life,
        24 * 3600,
        "omitted kdc.conf max_life is 24 h"
    );
    store.apply_kdc_conf(&conf).unwrap();
    store
        .insert_new_password(&name("z66b"), TEST_REALM, b"x", &[], ACTOR)
        .unwrap();
    assert_eq!(store.get_name(&name("z66b")).unwrap().max_life, 24 * 3600);
}

#[test]
fn z7_realm_cap_omitted_rlife_allows_five_day_renew() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let conf = krb5_config::KdcConf::parse(&format!(
        "[realms]\n    {TEST_REALM} = {{\n        max_life = 1h\n    }}\n"
    ))
    .unwrap();
    assert_eq!(conf.max_renewable_life, 0, "alt_prof.c create default");
    store.apply_kdc_conf(&conf).unwrap();
    store
        .insert_new_password(&name("z71c"), TEST_REALM, b"x", &[], ACTOR)
        .unwrap();
    assert_eq!(
        store.get_name(&name("z71c")).unwrap().max_renewable_life,
        0,
        "omitted kdc.conf max_renewable_life is params.max_rlife = 0"
    );

    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = PrincipalName::krbtgt(TEST_REALM);
    store
        .apply_admin_fields(
            &user,
            None,
            None,
            None,
            None,
            None,
            false,
            Some(7 * 24 * 3600),
        )
        .unwrap();
    store
        .apply_admin_fields(
            &tgt,
            None,
            None,
            None,
            None,
            None,
            false,
            Some(7 * 24 * 3600),
        )
        .unwrap();

    let key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let mut req = as_req(
        user,
        TEST_REALM,
        7101,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    req.0.req_body.rtime = Some(
        req.0
            .req_body
            .till
            .add_seconds(i64::from(5 * 24 * 3600) - 10 * 3600)
            .expect("rtime 5d from now"),
    );
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    let tgt_key = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let part = decrypt_ticket_part(&tgt_key, &issued.rep.0.ticket).unwrap();
    let start = part
        .starttime
        .as_ref()
        .unwrap_or(&part.authtime)
        .unix_seconds();
    let renew = part
        .renew_till
        .as_ref()
        .expect("RENEWABLE ticket")
        .unix_seconds();
    let delta = i64::from(renew) - i64::from(start);
    assert!(
        (i64::from(5 * 24 * 3600) - 5..=i64::from(5 * 24 * 3600) + 5).contains(&delta),
        "kdc/main.c realm_maxrlife 7 d allows a 5 d renew; got {delta}"
    );
}

#[test]
fn z7_synthesize_km_uses_params_lifetimes() {
    let store = PrincipalStore::new(TEST_REALM);
    let text = dump_store(&store, b"masterpassword").expect("dump");
    let dump = parse_dump(&text).expect("parse");
    let km = dump.princ("K/M@KERBER.TEST").expect("K/M");
    assert_eq!(km.max_life, 24 * 3600, "params.max_life default 24 h");
    assert_eq!(km.max_renewable_life, 0, "params.max_rlife default 0");
}

#[test]
fn z7_client_till_default_is_one_day() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../krb5-protocol/src/as_ex.rs"
    ));
    assert!(
        src.contains("unwrap_or(24 * 3600)") || src.contains("unwrap_or(24 * 60 * 60)"),
        "get_in_tkt.c:947 omitted lifetime is 24 h"
    );
    assert!(
        !src.contains("unwrap_or(10 * 3600)"),
        "as_ex till fallback must not be 10 h"
    );
}

#[test]
fn z8_kadmin_admin_max_life_is_three_hours() {
    let (store, _) = bootstrap_documented().unwrap();
    let p = store.get_name(&documented_kadmin()).expect("kadmin/admin");
    assert_eq!(
        p.max_life,
        60 * 60 * 3,
        "kadm5_create.c:54 ADMIN_LIFETIME (got {})",
        p.max_life
    );
}

#[test]
fn z8_kadmin_changepw_max_life_is_five_minutes() {
    let (store, _) = bootstrap_documented().unwrap();
    let p = store
        .get_name(&documented_changepw())
        .expect("kadmin/changepw");
    assert_eq!(
        p.max_life,
        60 * 5,
        "kadm5_create.c:55 CHANGEPW_LIFETIME (got {})",
        p.max_life
    );
}
