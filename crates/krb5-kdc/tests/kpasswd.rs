//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::principals::{kadmin_admin, kadmin_changepw};
use krb5_kdc::{
    Acl, AdminOp, Error, KDB_REQUIRES_PWCHANGE, PrincipalStore, TEST_ADMIN, TEST_REALM, TEST_USER,
    TEST_USER_PASSWORD, as_req, bootstrap_documented, documented_admin_id, pa_enc_timestamp,
    tgs_req,
};

use krb5_protocol::as_req_sname;
use krb5_testkit::{password_key, status};
use krb5_types::{PrincipalName, err};

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

fn service_tgs(
    issued: &krb5_kdc::IssuedAs,
    sname: PrincipalName,
    nonce: u32,
) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        sname,
        TEST_REALM,
        nonce,
    )
    .unwrap()
}

fn assert_tgt_based_not_allowed(err: Error) {
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("TGT BASED NOT ALLOWED"));
        }
        other => panic!("expected POLICY TGT BASED NOT ALLOWED, got {other:?}"),
    }
}

#[test]
fn kpasswd_acl_c_honours_target_pattern() {
    let (mut store, admin_acl) = bootstrap_documented().expect("bootstrap");
    let admin = documented_admin_id();
    let user2 = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user2"]);
    let svc = PrincipalName::new(PrincipalName::NT_SRV_INST, ["svc", "x"]);
    store
        .create_password(&admin_acl, &admin, &user2, b"user2-secret")
        .unwrap();
    store.create_host(&admin_acl, &admin, &svc).unwrap();
    let acl = Acl::parse("pwadmin@KERBER.TEST c *@KERBER.TEST\n").expect("acl");
    let actor = "pwadmin@KERBER.TEST";
    store
        .change_password(&acl, actor, &user2, b"user2-rotated")
        .expect("cpw in scope");
    assert_eq!(
        store
            .change_password(&acl, actor, &svc, b"svc-rotated")
            .unwrap_err(),
        Error::AclDenied
    );
}

#[test]
fn as_rejects_expired_password_unless_pwchange_service() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .apply_admin_fields(&cname, None, None, Some(0), Some(1), None, false, None)
        .unwrap();
    let err = krb5_kdc::issue_as(&store, &user_as_req(43)).unwrap_err();
    assert_eq!(status(&err).0, err::KEY_EXPIRED);

    let key = client_key();
    let changepw = as_req_sname(
        cname.clone(),
        TEST_REALM,
        44,
        Some(vec![pa_enc_timestamp(&key).expect("pa-ts")]),
        kadmin_changepw(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    krb5_kdc::issue_as(&store, &changepw).expect("PWCHANGE_SERVICE allows expired key");
}

#[test]
// oracle: differential-gate.sh as-needchange
fn as_needchange_is_key_expired_unless_changepw() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    or_attr(&mut store, &cname, KDB_REQUIRES_PWCHANGE);
    let err = krb5_kdc::issue_as(&store, &user_as_req(48)).unwrap_err();
    // MIT validate_as_request (kdc_util.c:762-766): REQUIRES_PWCHANGE is its own
    // "REQUIRED PWCHANGE" status (code KEY_EXP 23), not "CLIENT KEY EXPIRED".
    let (code, text) = match err {
        Error::Protocol { code, text, .. } => (code, text),
        other => panic!("want Protocol, got {other:?}"),
    };
    assert_eq!(code, err::KEY_EXPIRED);
    assert_eq!(
        text.as_deref(),
        Some("REQUIRED PWCHANGE"),
        "needchange status is REQUIRED PWCHANGE, not CLIENT KEY EXPIRED"
    );
    let key = client_key();
    let changepw = as_req_sname(
        cname,
        TEST_REALM,
        49,
        Some(vec![pa_enc_timestamp(&key).expect("pa-ts")]),
        kadmin_changepw(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    krb5_kdc::issue_as(&store, &changepw).expect("PWCHANGE_SERVICE allows +needchange");
}

#[test]
fn tgs_for_changepw_with_tgt_is_tgt_based_not_allowed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(801)).expect("AS");
    let err =
        krb5_kdc::issue_tgs(&store, &service_tgs(&issued, kadmin_changepw(), 802)).unwrap_err();
    assert_tgt_based_not_allowed(err);
}

#[test]
fn tgs_for_admin_with_tgt_is_tgt_based_not_allowed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(803)).expect("AS");
    let err = krb5_kdc::issue_tgs(&store, &service_tgs(&issued, kadmin_admin(), 804)).unwrap_err();
    assert_tgt_based_not_allowed(err);
}

fn user_key() -> ProtocolKey {
    password_key(TEST_USER, TEST_USER_PASSWORD)
}

#[test]
fn kpasswd_bumps_kvno_single_active_and_switches_password() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let before = store.get_name(&cname).expect("user");
    let old_kvno = before.keys.iter().map(|k| k.kvno).max().expect("kvno");
    store
        .change_password(
            &acl,
            &format!("{TEST_ADMIN}@{TEST_REALM}"),
            &cname,
            b"brand-new-pass",
        )
        .expect("cpw");
    let after = store.get_name(&cname).expect("user");
    let new_kvno = after.keys.iter().map(|k| k.kvno).max().expect("kvno");
    assert_eq!(new_kvno, old_kvno + 1);
    assert!(
        after.keys.iter().all(|k| k.kvno == new_kvno),
        "keepold=false: one active kvno"
    );

    let new_key = password_key(TEST_USER, b"brand-new-pass");
    let ok = as_req(
        cname.clone(),
        TEST_REALM,
        101,
        Some(vec![pa_enc_timestamp(&new_key).expect("pa")]),
    )
    .unwrap();
    krb5_kdc::issue_as(&store, &ok).expect("AS with new password");

    let old = as_req(
        cname,
        TEST_REALM,
        102,
        Some(vec![pa_enc_timestamp(&user_key()).expect("pa")]),
    )
    .unwrap();
    match krb5_kdc::issue_as(&store, &old) {
        Err(
            Error::Crypto(_)
            | Error::Protocol {
                code: err::PREAUTH_FAILED,
                ..
            },
        ) => {}
        other => panic!("old password must fail AS, got {other:?}"),
    }
}

#[test]
fn kpasswd_denied_without_changepw_acl() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let acl = Acl::parse("admin@KERBER.TEST a\n").expect("acl");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let err = store
        .change_password(&acl, "admin@KERBER.TEST", &cname, b"x")
        .unwrap_err();
    assert_eq!(err, Error::AclDenied);
    assert!(
        acl.check("admin@KERBER.TEST", AdminOp::ChangePassword, None)
            .is_err()
    );
    let acl_c = Acl::parse("admin@KERBER.TEST c\n").expect("acl");
    store
        .change_password(&acl_c, "admin@KERBER.TEST", &cname, b"ok-pass")
        .expect("c bit allows cpw");
}

#[test]
fn ktadd_exports_all_kvnos_after_kpasswd() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .change_password(&acl, &documented_admin_id(), &cname, b"second-pass")
        .expect("cpw");
    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &cname)
        .expect("ktadd");
    let kvnos: Vec<u32> = kt.entries.iter().map(|e| e.kvno).collect();
    assert!(
        !kvnos.is_empty() && kvnos.iter().all(|v| *v > 1),
        "keepold=false ktadd exports the new kvno only: {kvnos:?}"
    );
}
