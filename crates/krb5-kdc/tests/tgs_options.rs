//! `get_ticket_flags` + `check_tgs_opts` + deny_opts.
//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, decrypt};
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_host,
};
use krb5_kdc::{
    Error, KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_POSTDATED, KDB_DISALLOW_RENEWABLE, KDB_DISALLOW_SVR,
    KDB_DISALLOW_TGT_BASED, KDB_NO_AUTH_DATA_REQUIRED, KDB_OK_AS_DELEGATE, KDB_REQUIRES_HW_AUTH,
    PrincipalStore,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_testkit::{TgsReqBuilder, issue_tgt_password, status, user, user_as_bits};
use krb5_types::{ApReq, EncTicketPart, KdcOptions, PrincipalName, err, flag_bit, ku, pa};

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

fn tgt_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
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
// oracle: differential-gate.sh tgs-postdate-on-non-postdatable
fn tgs_postdate_without_may_postdate_is_tgt_not_postdatable() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as_bits(&store, 11001, &[]);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        11002,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::MAY_POSTDATE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::BADOPTION, Some("TGT NOT POSTDATABLE")));
}

#[test]
fn tgs_renewable_against_disallow_is_non_renewable() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let issued = user_as_bits(&store, 11011, &[(flag_bit::RENEWABLE, true)]);
    or_attr(&mut store, &host, KDB_DISALLOW_RENEWABLE);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        host,
        TEST_REALM,
        11012,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::POLICY, Some("NON-RENEWABLE TICKET")));
}

#[test]
fn tgs_forwarded_sets_forwarded() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as_bits(&store, 11021, &[]);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        11022,
    )
    .options(KdcOptions::none().with_bit(flag_bit::FORWARDED, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    assert!(tgt_part(&store, &out).flags.bit(flag_bit::FORWARDED));
}

#[test]
fn tgs_proxy_sets_proxy() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as_bits(&store, 11031, &[(flag_bit::PROXIABLE, true)]);
    let host_req = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        11032,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::PROXIABLE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let host_out = krb5_kdc::issue_tgs(&store, &host_req).unwrap();
    assert!(host_part(&store, &host_out).flags.proxiable());
    let proxy = TgsReqBuilder::new(
        host_out.rep.0.ticket.clone(),
        &host_out.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        11033,
    )
    .options(KdcOptions::none().with_bit(flag_bit::PROXY, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &proxy).unwrap();
    assert!(host_part(&store, &out).flags.bit(flag_bit::PROXY));
}

#[test]
fn tgs_postdated_is_invalid() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as_bits(&store, 11041, &[(flag_bit::MAY_POSTDATE, true)]);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        11042,
    )
    .options(
        KdcOptions::none()
            .with_bit(flag_bit::MAY_POSTDATE, true)
            .with_bit(flag_bit::POSTDATED, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let part = host_part(&store, &out);
    assert!(part.flags.bit(flag_bit::POSTDATED));
    assert!(part.flags.invalid());
}

#[test]
fn tgs_postdated_bit_alone_does_not_deny_postdate() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    or_attr(&mut store, &host, KDB_DISALLOW_POSTDATED);
    let issued = user_as_bits(&store, 11051, &[(flag_bit::MAY_POSTDATE, true)]);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        host,
        TEST_REALM,
        11052,
    )
    .options(KdcOptions::none().with_bit(flag_bit::POSTDATED, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("deny_opts keys only on ALLOW_POSTDATE");
    assert!(host_part(&store, &out).flags.invalid());
}

#[test]
fn tgs_renew_skips_ok_as_delegate() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let krbtgt = PrincipalName::krbtgt(TEST_REALM);
    or_attr(&mut store, &krbtgt, KDB_OK_AS_DELEGATE);
    let issued = user_as_bits(&store, 11061, &[(flag_bit::RENEWABLE, true)]);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        krbtgt,
        TEST_REALM,
        11062,
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
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    assert!(!tgt_part(&store, &out).flags.bit(flag_bit::OK_AS_DELEGATE));
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

#[test]
fn tgs_session_enctypes_attr_is_membership() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store
        .set_string(&documented_host(), "session_enctypes", Some("aes128-cts"))
        .expect("setstr");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        64,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS");
    let tgs = TgsReqBuilder::new(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        65,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![18, 17])
    .build()
    .expect("tgs");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    assert_eq!(
        tgs_out.session_key.etype(),
        EncryptionType::Aes128CtsHmacSha196
    );
}

#[test]
fn tgs_honors_svr_tgt_based_lockout_and_ok_as_delegate() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let issued = krb5_kdc::issue_as(&store, &user_as_req(65)).expect("AS");

    or_attr(&mut store, &host, KDB_DISALLOW_SVR);
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 66)).unwrap_err();
    assert_eq!(status(&err).0, err::MUST_USE_USER2USER);

    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(67)).expect("AS");
    or_attr(&mut store, &host, KDB_DISALLOW_TGT_BASED);
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 68)).unwrap_err();
    assert_eq!(status(&err).0, err::POLICY);

    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(69)).expect("AS");
    or_attr(&mut store, &host, KDB_DISALLOW_ALL_TIX);
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 70)).unwrap_err();
    assert_eq!(status(&err).0, err::S_PRINCIPAL_UNKNOWN);

    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(71)).expect("AS");
    or_attr(&mut store, &host, KDB_OK_AS_DELEGATE);
    let tgs = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 72)).expect("TGS");
    let host_key = store.get_name(&host).unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &host_key.key,
        usage,
        tgs.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    let part: EncTicketPart = decode(&plain).unwrap();
    assert!(part.flags.bit(flag_bit::OK_AS_DELEGATE));
}

#[test]
fn tgs_skips_pac_when_no_auth_data_required() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let issued = krb5_kdc::issue_as(&store, &user_as_req(73)).expect("AS");
    or_attr(&mut store, &host, KDB_NO_AUTH_DATA_REQUIRED);
    let tgs = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 74)).expect("TGS");
    let host_key = store.get_name(&host).unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &host_key.key,
        usage,
        tgs.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    let part: EncTicketPart = decode(&plain).unwrap();
    assert!(part.authorization_data.is_none());
}

#[test]
fn tgs_requires_hw_auth_without_hw_flag() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let issued = krb5_kdc::issue_as(&store, &user_as_req(75)).expect("AS");
    or_attr(&mut store, &host, KDB_REQUIRES_HW_AUTH);
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 76)).unwrap_err();
    assert_eq!(status(&err).0, err::GENERIC);
}

#[test]
// oracle: differential-gate.sh tgs-ap-options
fn tgs_ap_options_use_session_key_is_policy() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 414);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        415,
    )
    .unwrap();
    let pa = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ");
    let mut ap: ApReq = decode(pa.padata_value.as_ref()).expect("ap");
    ap.ap_options = krb5_types::ApOptions::mutual_required();
    pa.padata_value = encode(&ap).expect("ap").into();
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("MUTUAL_REQUIRED");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("expected 12 PROCESS_TGS, got {other:?}"),
    }
}
