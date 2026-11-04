//! User-to-user and second-ticket statuses.
//! The tests drive the shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry points of a
//! bootstrapped realm.
//! The `u2u_session` statuses follow MIT.
// MIT: `decrypt_2ndtkt` (do_tgs_req.c:250-307)
//! the second-ticket statuses are
//! `2ND_TKT_SERVER`, `2ND_TKT_DECRYPT` and `2ND_TKT_PAC`, by the step that failed.
// MIT: `find_server_key` (kdc_util.c:420-450)
//! the key is looked up by enctype and kvno
//! (`krb5_dbe_find_enctype`), and a key whose enctype is not similar is
//! `KRB5_KDB_NO_PERMITTED_KEY`.
//! A U2U second ticket whose server is missing is 7 `2ND_TKT_SERVER`.
// MIT: `decrypt_2ndtkt` (do_tgs_req.c:280-289)
//! a second-ticket server that
//! `kdc_get_server_key(stkt)` cannot find is `2ND_TKT_SERVER`.

use krb5_crypto::EncryptionType;
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    bootstrap_documented, documented_host,
};
use krb5_kdc::{PrincipalStore, decrypt_ticket_part};
use krb5_protocol::tgs_req;

use krb5_testkit::{
    TgsReqBuilder, expect_status, host_tgt, issue_tgt, issue_tgt_password, pref_etypes, status,
};
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit};

fn u2u_opts() -> KdcOptions {
    KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true)
}

fn u2u_req(
    store: &PrincipalStore,
    dest: PrincipalName,
    extra: Option<Vec<krb5_types::Ticket>>,
    nonce: u32,
) -> krb5_types::TgsReq {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(store, TEST_USER, nonce);
    TgsReqBuilder::new(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        dest,
        TEST_REALM,
        nonce + 1,
    )
    .options(u2u_opts())
    .additional_tickets(extra)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap()
}

#[test]
// oracle: differential-gate.sh u2u-2nd-ticket-not-tgs
fn u2u_service_ticket_is_not_tgs() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, 9110);
    let svc = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        9111,
    )
    .unwrap();
    let extra = krb5_kdc::issue_tgs(&store, &svc).unwrap().rep.0.ticket;
    let req = u2u_req(&store, documented_host(), Some(vec![extra]), 9112);
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("2ND_TKT_NOT_TGS"));
}

#[test]
fn u2u_host_tgt_issues_kvno_zero() {
    let (store, _) = bootstrap_documented().unwrap();
    let extra = host_tgt(&store, 9160);
    let req = u2u_req(
        &store,
        documented_host(),
        Some(vec![extra.rep.0.ticket]),
        9161,
    );
    let out = krb5_kdc::issue_tgs(&store, &req).unwrap();
    assert!(out.rep.0.ticket.enc_part.kvno.is_none());
    let part = decrypt_ticket_part(&extra.session_key, &out.rep.0.ticket).unwrap();
    assert_eq!(part.cname.components_joined(), TEST_USER);
}

fn u2u(store: &PrincipalStore, second: krb5_types::Ticket) -> krb5_kdc::Error {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_tgt = issue_tgt_password(store, TEST_USER, TEST_USER_PASSWORD, 813);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    let tgs = TgsReqBuilder::new(
        user_tgt.rep.0.ticket,
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        user.clone(),
        TEST_REALM,
        814,
    )
    .options(opts)
    .additional_tickets(Some(vec![second]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    krb5_kdc::issue_tgs(store, &tgs).unwrap_err()
}

#[test]
// oracle: differential-gate.sh u2u-2nd-ticket-kvno-miss
fn u2u_no_key_of_ticket_etype_is_2nd_tkt_server() {
    let (store, _) = bootstrap_documented().unwrap();
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 811);
    let mut second = admin_tgt.rep.0.ticket;
    second.enc_part.etype = EncryptionType::Camellia128CtsCmac.to_iana();
    let err = u2u(&store, second);
    let (code, text) = status(&err);
    assert_eq!(code, err::GENERIC);
    assert_eq!(text, Some("2ND_TKT_SERVER"));
}

#[test]
// oracle: differential-gate.sh u2u-2nd-ticket-bad-etype
fn u2u_unknown_etype_99_is_2nd_tkt_server() {
    let (store, _) = bootstrap_documented().unwrap();
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 812);
    let mut second = admin_tgt.rep.0.ticket;
    second.enc_part.etype = 99;
    let err = u2u(&store, second);
    let (code, text) = status(&err);
    assert_eq!(code, err::GENERIC);
    assert_eq!(text, Some("2ND_TKT_SERVER"));
}

#[test]
// oracle: differential-gate.sh u2u-2nd-ticket-corrupt
fn u2u_corrupt_cipher_is_2nd_tkt_decrypt() {
    let (store, _) = bootstrap_documented().unwrap();
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 815);
    let mut second = admin_tgt.rep.0.ticket;
    let mut cipher = second.enc_part.cipher.as_ref().to_vec();
    if let Some(b) = cipher.last_mut() {
        *b ^= 1;
    }
    second.enc_part.cipher = cipher.into();
    let err = u2u(&store, second);
    let (code, text) = status(&err);
    assert_eq!(code, err::BAD_INTEGRITY);
    assert_eq!(text, Some("2ND_TKT_DECRYPT"));
}

#[test]
// oracle: differential-gate.sh u2u-2nd-ticket-disallow-svr
// oracle: differential-gate.sh u2u-2nd-ticket-unknown-server
fn u2u_missing_second_ticket_server_is_2nd_tkt_server() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 741);
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 742);
    let mut second = admin_tgt.rep.0.ticket.clone();
    // Outer sname does not exist; MIT `kdc_get_server_key` → 7 `2ND_TKT_SERVER`.
    second.sname = PrincipalName::new(PrincipalName::NT_SRV_INST, ["no-such-2ndtkt", TEST_REALM]);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    let tgs = TgsReqBuilder::new(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        743,
    )
    .options(opts)
    .additional_tickets(Some(vec![second]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    let (code, text) = status(&err);
    assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text, Some("2ND_TKT_SERVER"));
}
