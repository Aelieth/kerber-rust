//! A′-2 item 9 U2U / second-ticket statuses.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.
//! R13: `u2u_session` statuses (`do_tgs_req.c:250-307`, `kdc_util.c:420-450`).
//! R9: U2U missing second-ticket server is 7 `2ND_TKT_SERVER`
//! (`do_tgs_req.c:280-289` via `kdc_get_server_key(stkt)`).

use krb5_crypto::EncryptionType;
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    bootstrap_documented, documented_host,
};
use krb5_kdc::{
    KDB_DISALLOW_DUP_SKEY, PrincipalStore, as_req, decrypt_ticket_part, pa_enc_timestamp,
    pac_from_ticket_part, tgs_req, wrap_win2k_pac,
};

use krb5_testkit::{
    TgsReqBuilder, expect_status, host_tgt, issue_tgt, issue_tgt_password, pref_etypes,
    reseal_store, status,
};
use krb5_types::pac::{PAC_SERVER_CHECKSUM, Pac};
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
// oracle: differential-gate.sh u2u-no-2nd-tkt
fn u2u_no_2nd_tkt_is_badoption() {
    let (store, _) = bootstrap_documented().unwrap();
    let req = u2u_req(&store, documented_host(), None, 9100);
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("NO_2ND_TKT"));
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
// oracle: differential-gate.sh u2u-2nd-ticket-mismatch
fn u2u_admin_tgt_for_host_is_mismatch() {
    let (store, _) = bootstrap_documented().unwrap();
    let admin = issue_tgt(&store, TEST_ADMIN, 9120);
    let req = u2u_req(
        &store,
        documented_host(),
        Some(vec![admin.rep.0.ticket]),
        9121,
    );
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::SERVER_NOMATCH);
    assert_eq!(text.as_deref(), Some("2ND_TKT_MISMATCH"));
}

#[test]
// oracle: differential-gate.sh u2u-bad-etype
fn u2u_bad_session_etype_is_etype_nosupp() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = host_tgt(&store, 9130);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &host.rep.0.ticket).unwrap();
    part.key.keytype = 99;
    let mut extra = host.rep.0.ticket.clone();
    reseal_store(&store, &mut extra, &part);
    let req = u2u_req(&store, documented_host(), Some(vec![extra]), 9131);
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::ETYPE_NOSUPP);
    assert_eq!(text.as_deref(), Some("BAD_ETYPE_IN_2ND_TKT"));
}

#[test]
// oracle: differential-gate.sh u2u-2nd-ticket-bad-pac
fn u2u_bad_pac_is_modified() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = host_tgt(&store, 9140);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &host.rep.0.ticket).unwrap();
    let raw = pac_from_ticket_part(&part).unwrap();
    let mut parsed = Pac::parse(&raw).unwrap();
    if let Some(buf) = parsed
        .buffers
        .iter_mut()
        .find(|b| b.kind == PAC_SERVER_CHECKSUM)
        && buf.data.len() > 4
    {
        buf.data[4] ^= 0xff;
    }
    part.authorization_data = Some(wrap_win2k_pac(&parsed.to_bytes()).unwrap());
    let mut extra = host.rep.0.ticket.clone();
    reseal_store(&store, &mut extra, &part);
    let req = u2u_req(&store, documented_host(), Some(vec![extra]), 9141);
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::MODIFIED);
    assert_eq!(text.as_deref(), Some("2ND_TKT_PAC"));
}

#[test]
// oracle: differential-gate.sh u2u-dup-skey-tgt-based
fn u2u_dup_skey_disallowed_is_policy() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let attrs = store.get_name(&host).unwrap().attributes | KDB_DISALLOW_DUP_SKEY;
    store
        .apply_admin_fields(&host, Some(attrs), None, None, None, None, false, None)
        .unwrap();
    let extra = host_tgt(&store, 9150).rep.0.ticket;
    let req = u2u_req(&store, host, Some(vec![extra]), 9151);
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("DUP_SKEY DISALLOWED"));
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

#[test]
fn u2u_encrypts_ticket_in_additional_tgt_session() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let host = documented_host();
    let user_tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 801);
    let host_key = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let host_as = as_req(
        host.clone(),
        TEST_REALM,
        802,
        Some(vec![pa_enc_timestamp(&host_key).expect("pa")]),
    )
    .unwrap();
    let host_tgt = krb5_kdc::issue_as(&store, &host_as).expect("host TGT");
    let opts = KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    let tgs = TgsReqBuilder::new(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        host,
        TEST_REALM,
        803,
    )
    .options(opts)
    .additional_tickets(Some(vec![host_tgt.rep.0.ticket.clone()]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("U2U TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("U2U");
    assert!(out.rep.0.ticket.enc_part.kvno.is_none());
    let longterm = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    assert!(
        decrypt_ticket_part(&longterm.key, &out.rep.0.ticket).is_err(),
        "U2U ticket must not use the service long-term key"
    );
    let part = decrypt_ticket_part(&host_tgt.session_key, &out.rep.0.ticket).expect("U2U enc");
    assert_eq!(part.cname.components_joined(), TEST_USER);
    assert_eq!(part.key.keyvalue.as_ref(), out.session_key.as_bytes());
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
