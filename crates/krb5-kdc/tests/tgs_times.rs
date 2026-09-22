//! A′-3 item 12: `check_tgs_svc_reqd_flags` PRE_AUTH + `compute_ticket_times`.
//! A′-3 R26: `max_renewable_life` 0, AS `PRE_AUTHENT`, `check_tgs_opts` order.
//! A′-3 R27: S4U `t->client`, signed `ts_delta`, `check_tgs_svc_time` slot.
//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.
//! Z1.3 follow-up: the KDC's header-ticket time check is `krb5int_validate_times`
//! too (`kdc_util.c` `kdc_rd_ap_req` → `krb5_rd_req_decoded_anyflag` →
//! `rd_req_dec.c:627` → `valid_times.c:44-51`): a TGT with no `starttime` is
//! judged by its `authtime`. Compiles at the parent `284ec70` and fails there —
//! `check_header_times_rd_req` only tested NYV when `starttime` was present, so
//! a resealed TGT with a future `authtime` and no `starttime` was accepted.

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, decrypt, encrypt};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented, documented_host};
use krb5_kdc::{
    Error, KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_RENEWABLE, KDB_REQUIRES_PRE_AUTH, PrincipalStore,
    decrypt_ticket_part,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_testkit::{TgsReqBuilder, admin, s4u_admin, status, user, user_as, user_as_bits};
use krb5_types::{
    EncTicketPart, EncryptedData, KdcOptions, KerberosTime, OctetString, PaData, PaPacRequest,
    PrincipalName, Ticket, err, flag_bit, ku, pa,
};

fn or_attr(store: &mut PrincipalStore, name: &PrincipalName, bit: u32) {
    let a = store.get_name(name).unwrap().attributes | bit;
    store
        .apply_admin_fields(name, Some(a), None, None, None, None, false, None)
        .unwrap();
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
// oracle: differential-gate.sh tgs-no-preauth-flag
fn tgs_requires_preauth_without_pa_flag_is_no_preauth() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let issued = user_as(&store, 12001);
    or_attr(&mut store, &host, KDB_REQUIRES_PRE_AUTH);
    let tgs = TgsReqBuilder::new(
        tgt_without_preauth(&store, &issued),
        &issued.session_key,
        TEST_REALM,
        &user(),
        host,
        TEST_REALM,
        12002,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::GENERIC, Some("NO PREAUTH")));
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
        .apply_admin_fields(&user(), None, Some(60), None, None, None, false, None)
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
// oracle: differential-gate.sh tgs-validate-invalid-non-renewable
fn tgs_renew_invalid_non_renewable_is_ticket_not_renewable() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as_bits(&store, 26021, &[]);
    let mut part = tgt_part(&store, &issued);
    part.flags = part
        .flags
        .with_bit(flag_bit::INVALID, true)
        .with_bit(flag_bit::RENEWABLE, false);
    let tgs = TgsReqBuilder::new(
        forge_tgt(&store, &issued, &part),
        &issued.session_key,
        TEST_REALM,
        &user(),
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        26022,
    )
    .options(KdcOptions::none().with_bit(flag_bit::RENEW, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::BADOPTION, Some("TICKET NOT RENEWABLE")));
}

fn etypes() -> Vec<i32> {
    vec![EncryptionType::Aes256CtsHmacSha196.to_iana()]
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
    let cap = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while KerberosTime::now().unix_seconds() <= target {
        assert!(
            std::time::Instant::now() < cap,
            "unix seconds did not pass {target} within 2s"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn tgt_part_a3_r27(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> EncTicketPart {
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
fn s4u2self_caps_endtime_at_impersonated_max_life() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .apply_admin_fields(&admin(), None, Some(60), None, None, None, false, None)
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

#[test]
fn s4u2self_disallow_renewable_user_has_no_r() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let a = store.get_name(&admin()).unwrap().attributes | KDB_DISALLOW_RENEWABLE;
    store
        .apply_admin_fields(&admin(), Some(a), None, None, None, None, false, None)
        .unwrap();
    let tgt = host_as(&store, 27011, true);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true);
    let out = krb5_kdc::issue_tgs(&store, &s4u_admin(&tgt, 27012, opts)).unwrap();
    assert!(!host_part_a3_r27(&store, &out).flags.renewable());
}

#[test]
// oracle: differential-gate.sh tgs-service-expired-require-auth
fn tgs_expired_server_beats_require_auth() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let issued = user_as(&store, 27031);
    store
        .set_string(&host, "require_auth", Some("pkinit"))
        .unwrap();
    store
        .apply_admin_fields(&host, None, None, Some(1), None, None, false, None)
        .unwrap();
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        host,
        TEST_REALM,
        27032,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(etypes())
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::SERVICE_EXP, Some("SERVICE EXPIRED")));
}

#[test]
fn tgs_postdated_omitted_from_is_epoch() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 27041);
    // Authtime must be in the past so omitted from (epoch) is not NYV.
    wait_unix_past(tgt_part_a3_r27(&store, &issued).authtime.unix_seconds());
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut part = tgt_part_a3_r27(&store, &issued);
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
    let tgs = TgsReqBuilder::new(
        tgt,
        &issued.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        27042,
    )
    .options(
        KdcOptions::none()
            .with_bit(flag_bit::MAY_POSTDATE, true)
            .with_bit(flag_bit::POSTDATED, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(etypes())
    .addresses(None)
    .from(None)
    .enc_authorization_data(None)
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let got = host_part_a3_r27(&store, &out);
    assert!(
        got.starttime.is_none(),
        "MIT from=0 is omitted on the wire (krb5_timestamp 0)"
    );
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
fn tgs_issues_after_client_expires() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = krb5_kdc::issue_as(&store, &user_as_req(47)).expect("AS while unexpired");
    store
        .apply_admin_fields(&cname, None, None, Some(1), None, None, false, None)
        .unwrap();
    krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 48)).expect("TGS after NAME_EXP");

    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(49)).expect("AS while unexpired");
    store
        .apply_admin_fields(&cname, None, None, None, Some(1), None, false, None)
        .unwrap();
    krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 50)).expect("TGS after KEY_EXPIRED");
}

#[test]
fn tgs_rejects_expired_server() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let issued = krb5_kdc::issue_as(&store, &user_as_req(51)).expect("AS");
    store
        .apply_admin_fields(&host, None, None, Some(1), None, None, false, None)
        .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 52)).unwrap_err();
    assert_eq!(status(&err).0, err::SERVICE_EXP);
}

#[test]
fn tgs_renewable_when_server_disallow_is_non_renewable() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let mut areq = user_as_req(77);
    areq.0.req_body.kdc_options = areq
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    let issued = krb5_kdc::issue_as(&store, &areq).expect("AS renewable");
    assert!(tgt_part_issue_acl_ap(&store, &issued).flags.renewable());
    or_attr(&mut store, &host, KDB_DISALLOW_RENEWABLE);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        78,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("TGS-REQ");
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("NON-RENEWABLE TICKET"));
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
}

#[test]
fn tgs_renew_preserves_renew_till() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = renewable_as(&store, 91);
    let before = tgt_part_issue_acl_ap(&store, &issued);
    assert!(before.flags.renewable());
    let old_till = before.renew_till.clone().expect("renew_till");
    // Needs wall-clock so renew_till is compared after time has moved.
    wait_unix_past(KerberosTime::now().unix_seconds());
    let out = krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 92)).expect("RENEW");
    let after = tgs_tgt_part(&store, &out);
    assert!(after.flags.renewable());
    assert_eq!(after.renew_till, Some(old_till));
    assert!(after.endtime.unix_seconds() >= before.endtime.unix_seconds());
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

#[test]
// oracle: differential-gate.sh tgt-expired
fn tgs_renew_after_endtime_is_process_tgs() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.policy.skew = 0;
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .apply_admin_fields(&cname, None, Some(1), None, None, None, false, None)
        .unwrap();
    let issued = renewable_as(&store, 95);
    // max_life is 1 s; wait until the integer endtime second has passed.
    wait_unix_past(
        tgt_part_issue_acl_ap(&store, &issued)
            .endtime
            .unix_seconds(),
    );
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 96)).unwrap_err();
    // MIT reports an expired header ticket at the rd_req stage: code 32 with
    // e_text PROCESS_TGS (do_tgs_req.c:623), not TKT_EXPIRED.
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::TKT_EXPIRED);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
    let renew_err = krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 97)).unwrap_err();
    match renew_err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::TKT_EXPIRED);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
}

#[test]
fn tgs_renew_rejects_renew_till_not_after_now() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let skew = store.policy.skew;
    assert!(skew >= 2, "default skew must include [now-skew, now]");
    let issued = renewable_as(&store, 100);
    let tgt_key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut part = tgt_part_issue_acl_ap(&store, &issued);
    let now = KerberosTime::now();
    part.renew_till = Some(now.add_seconds(-(skew / 2)).unwrap());
    // Stale PAC ticket-checksum would fail before the renew_till bound.
    part.authorization_data = None;
    let der = encode(&part).unwrap();
    let cipher = encrypt(&tgt_key.key, usage, &der).unwrap();
    let mut issued = issued;
    issued.rep.0.ticket.enc_part.cipher = OctetString::from(cipher);
    let err = krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 101)).unwrap_err();
    assert_eq!(status(&err).0, err::TKT_EXPIRED);
}

#[test]
fn tgs_renew_non_renewable_is_badoption() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(98)).expect("AS");
    assert!(!tgt_part_issue_acl_ap(&store, &issued).flags.renewable());
    let err = krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 99)).unwrap_err();
    assert_eq!(status(&err).0, err::BADOPTION);
}

#[test]
// oracle: differential-gate.sh tgs-nyv-inside-skew
fn tgs_validate_future_starttime_is_not_yet_valid() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let from = KerberosTime::now().add_seconds(2).unwrap();
    let issued = krb5_kdc::issue_as(&store, &postdated_as_req(124, from)).expect("postdated AS");
    let err = krb5_kdc::issue_tgs(&store, &validate_tgs(&issued, 125)).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::TKT_NYV);
            assert_eq!(text.as_deref(), Some("NOT_YET_VALID"));
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
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

fn user_key(store: &PrincipalStore) -> krb5_crypto::ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone()
}

fn reseal_tgt(
    store: &PrincipalStore,
    ticket: &krb5_types::Ticket,
    mutate: impl FnOnce(&mut EncTicketPart),
) -> krb5_types::Ticket {
    let key = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&key.key, ticket).unwrap();
    mutate(&mut part);
    let der = encode(&part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut out = ticket.clone();
    out.enc_part.cipher = encrypt(&key.key, usage, &der).unwrap().into();
    out
}

#[test]
// oracle: differential-gate.sh tgt-nyv
// oracle: differential-gate.sh tgt-nyv-no-starttime
fn tgs_header_tgt_without_starttime_and_future_authtime_is_nyv() {
    krb5_config::isolate_test_krb5();
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    // PA-PAC-REQUEST false: a PAC-bearing TGT would fail HEADER_PAC on the
    // rewritten authtime before any time check could be reached, masking the
    // laxness this unit pins (MIT validates times in rd_req, before the PAC).
    let padata = vec![
        pa_enc_timestamp(&user_key(&store)).unwrap(),
        PaData {
            padata_type: pa::PAC_REQUEST,
            padata_value: encode(&PaPacRequest { include_pac: false }).unwrap().into(),
        },
    ];
    let req = as_req(cname.clone(), TEST_REALM, 0x2600_0001, Some(padata)).unwrap();
    let tgt = krb5_kdc::issue_as(&store, &req).unwrap();

    // Control: the untouched TGT gets a host ticket.
    let ok_req = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        0x2600_0002,
    )
    .unwrap();
    krb5_kdc::issue_tgs(&store, &ok_req).expect("control TGS issues");

    // valid_times.c:44-46 starttime == 0 → authtime; :47-51 far-future → NYV.
    let far = KerberosTime::now()
        .add_seconds(store.policy().skew + 3600)
        .unwrap();
    let forged = reseal_tgt(&store, &tgt.rep.0.ticket, |part| {
        part.starttime = None;
        part.authtime = far.clone();
    });
    let req = tgs_req(
        forged,
        &tgt.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        0x2600_0003,
    )
    .unwrap();
    match krb5_kdc::issue_tgs(&store, &req) {
        Err(krb5_kdc::Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::TKT_NYV, "KRB5KRB_AP_ERR_TKT_NYV, got {text:?}");
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        Err(other) => panic!("expected 33 PROCESS_TGS, got {other:?}"),
        Ok(_) => panic!("a TGT with no starttime and a future authtime must be NYV"),
    }
}
