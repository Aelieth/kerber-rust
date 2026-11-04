//! TGS ticket times: `check_tgs_svc_reqd_flags` PRE_AUTH, `compute_ticket_times`, the S4U
//! client lifetime, renewal, and the header-ticket time check.
//! The KDC's header-ticket time check is `krb5int_validate_times` too
//! (`kdc_util.c` `kdc_rd_ap_req` → `krb5_rd_req_decoded_anyflag`).
// MIT: `rd_req_decoded_opt` (rd_req_dec.c:627-627)
//! the decoded AP-REQ's ticket times go
//! through `krb5int_validate_times`.
// MIT: `krb5int_validate_times` (valid_times.c:44-51)
//! a TGT with no `starttime` is
//! judged by its `authtime`, so a resealed TGT with a future `authtime` and no `starttime`
//! is not yet valid.

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_asn1::decode;
use krb5_crypto::{EncryptionType, KeyUsage, decrypt};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented, documented_host};
use krb5_kdc::{Error, KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_RENEWABLE, PrincipalStore};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_testkit::{TgsReqBuilder, admin, s4u_admin, status, user, user_as};
use krb5_types::{EncTicketPart, KdcOptions, KerberosTime, PrincipalName, err, flag_bit, ku};

fn or_attr(store: &mut PrincipalStore, name: &PrincipalName, bit: u32) {
    let a = store.get_name(name).unwrap().attributes | bit;
    store
        .apply_admin_fields(
            name,
            krb5_kdc::AdminFields {
                attributes: Some(a),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
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
        .apply_admin_fields(
            &user(),
            krb5_kdc::AdminFields {
                attributes: None,
                max_life: Some(60),
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        12022,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
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

fn host_part_a3_r27(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
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

fn wait_unix_past(target: u32) {
    let cap = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while KerberosTime::now().unix_seconds() <= target {
        assert!(
            std::time::Instant::now() < cap,
            "unix seconds did not pass {target} within 10s"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn s4u2self_caps_endtime_at_impersonated_max_life() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .apply_admin_fields(
            &admin(),
            krb5_kdc::AdminFields {
                attributes: None,
                max_life: Some(60),
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    let tgt = host_as(&store, 27001, false);
    let out =
        krb5_kdc::issue_tgs(&store, &s4u_admin(&tgt, 27002, KdcOptions::forwardable())).unwrap();
    let part = host_part_a3_r27(&store, &out);
    let start = part
        .starttime
        .as_ref()
        .unwrap_or(&part.authtime)
        .unix_seconds();
    let life = part.endtime.unix_seconds().saturating_sub(start);
    assert!(life <= 60, "life={life}");
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

fn renewable_as(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let mut req = user_as_req(nonce);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    krb5_kdc::issue_as(store, &req).expect("AS renewable")
}

fn renew_tgs(issued: &krb5_kdc::IssuedAs, nonce: u32) -> krb5_types::TgsReq {
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
    .options(
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("RENEW TGS-REQ")
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

fn renew_and_validate_tgs(issued: &krb5_kdc::IssuedAs, nonce: u32) -> krb5_types::TgsReq {
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
    .options(
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEW, true)
            .with_bit(flag_bit::VALIDATE, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("RENEW+VALIDATE TGS-REQ")
}

fn renew_tgs_sname(
    issued: &krb5_kdc::IssuedAs,
    sname: PrincipalName,
    nonce: u32,
) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        sname,
        TEST_REALM,
        nonce,
    )
    .options(
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("RENEW TGS-REQ")
}

#[test]
fn tgs_renew_strips_when_disallow_renewable() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = renewable_as(&store, 93);
    or_attr(&mut store, &cname, KDB_DISALLOW_RENEWABLE);
    let out = krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 94)).expect("RENEW strips");
    let after = tgs_tgt_part(&store, &out);
    assert!(!after.flags.renewable());
    assert!(after.renew_till.is_none());
}

fn assert_process_tgs_expired(err: Error) {
    // MIT reports an expired header ticket at the rd_req stage: code 32 with
    // e_text PROCESS_TGS, not TKT_EXPIRED.
    // MIT: `gather_tgs_req_info` (do_tgs_req.c:623-623)
    // a `kdc_process_tgs_req` failure
    // has the status PROCESS_TGS.
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::TKT_EXPIRED);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
}

/// Issue `build` until the refusal is the expired header ticket.
/// A stamp taken on one second and checked on the next is `SKEW` when skew is 0;
/// that sample is not the expiry result, so it is tried again inside the second
/// that is already past the ticket end.
fn tgs_once_past_end(store: &PrincipalStore, build: impl Fn() -> krb5_types::TgsReq) -> Error {
    let mut last = None;
    for _ in 0..8 {
        let err = krb5_kdc::issue_tgs(store, &build()).unwrap_err();
        let skew = matches!(&err, Error::Protocol { code, .. } if *code == err::SKEW);
        if !skew {
            return err;
        }
        last = Some(err);
    }
    last.expect("a TGS attempt")
}

#[test]
// oracle: differential-gate.sh tgt-expired
fn tgs_renew_after_endtime_is_process_tgs() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .apply_admin_fields(
            &cname,
            krb5_kdc::AdminFields {
                attributes: None,
                max_life: Some(1),
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    // MIT: `enc_ts_verify` (kdc/kdc_preauth_encts.c:97-99)
    // the encrypted timestamp
    // is `krb5_check_clockskew`. Skew 0 before this AS rejects a stamp from the
    // adjacent second. The expired-ticket check is what needs skew 0.
    let issued = renewable_as(&store, 95);
    store.policy.skew = 0;
    // max_life is 1 s; wait until the integer endtime second has passed.
    wait_unix_past(
        tgt_part_issue_acl_ap(&store, &issued)
            .endtime
            .unix_seconds(),
    );
    assert_process_tgs_expired(tgs_once_past_end(&store, || host_tgs(&store, &issued, 96)));
    assert_process_tgs_expired(tgs_once_past_end(&store, || renew_tgs(&issued, 97)));
}

#[test]
fn tgs_renew_keeps_forwardable_when_disallow() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = renewable_as(&store, 126);
    assert!(tgt_part_issue_acl_ap(&store, &issued).flags.forwardable());
    or_attr(&mut store, &cname, KDB_DISALLOW_FORWARDABLE);
    let out = krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 127)).expect("RENEW");
    assert!(tgs_tgt_part(&store, &out).flags.forwardable());
}

#[test]
fn tgs_renew_and_validate_together_is_badoption() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let from = KerberosTime::now().add_seconds(1).unwrap();
    let issued =
        krb5_kdc::issue_as(&store, &postdated_as_req(116, from.clone())).expect("postdated AS");
    assert!(!tgt_part_issue_acl_ap(&store, &issued).flags.renewable());
    // starttime is now+1 s; wait until that integer second has passed.
    wait_unix_past(from.unix_seconds());
    let err = krb5_kdc::issue_tgs(&store, &renew_and_validate_tgs(&issued, 117)).unwrap_err();
    assert_eq!(status(&err).0, err::BADOPTION);
}

#[test]
fn tgs_renew_wrong_sname_is_badoption() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = renewable_as(&store, 118);
    let err =
        krb5_kdc::issue_tgs(&store, &renew_tgs_sname(&issued, documented_host(), 119)).unwrap_err();
    assert_eq!(status(&err).0, err::SERVER_NOMATCH);
    krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 120)).expect("RENEW krbtgt");
}
