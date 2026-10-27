//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_crypto::EncryptionType;
use krb5_kdc::principals::kadmin_changepw;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_kdc::{Error, KDB_REQUIRES_PWCHANGE, PrincipalStore};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_protocol::as_req_sname;
use krb5_testkit::status;
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
fn as_rejects_expired_password_unless_pwchange_service() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .apply_admin_fields(
            &cname,
            krb5_kdc::AdminFields {
                attributes: None,
                max_life: None,
                expiration: Some(0),
                pw_expire: Some(1),
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
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
    // MIT: `validate_as_request` (kdc_util.c:762-766)
    // REQUIRES_PWCHANGE is its own
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
