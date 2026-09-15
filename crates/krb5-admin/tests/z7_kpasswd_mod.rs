//! Z7.2 (a): kpasswd stamps `kadmind@REALM` (`ovsec_kadmd.c:446`,
//! `schpw.c:406`). Compiles at the parent: `handle_kpasswd_rfc3244` and
//! `tl_mod_princ_name` already exist; the parent stamps the ticket client.

use krb5_admin::{encode_kpasswd_req, handle_kpasswd_rfc3244};
use krb5_asn1::encode;
use krb5_kdc::{
    TEST_REALM, TEST_USER, bootstrap_documented, documented_changepw, shared_dump,
    tl_mod_princ_name,
};
use krb5_protocol::{ReplayCache, as_req_sname, build_ap_req, build_krb_priv, pa_enc_timestamp};
use krb5_types::{ChangePasswdData, PrincipalName};

#[test]
fn z7_kpasswd_stamps_kadmind_not_the_client() {
    krb5_config::isolate_test_krb5();
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .expect("user")
        .best_key()
        .expect("key")
        .key
        .clone();
    let changepw = documented_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .expect("changepw")
        .best_key()
        .expect("key")
        .key
        .clone();
    let as_out = krb5_kdc::issue_as(
        &store,
        &as_req_sname(
            user.clone(),
            TEST_REALM,
            0x2400_0001,
            Some(vec![pa_enc_timestamp(&user_key).expect("pa")]),
            documented_changepw(),
            krb5_crypto::EncryptionType::preferred()
                .iter()
                .map(|e| e.to_iana())
                .collect(),
        )
        .expect("as-req"),
    )
    .expect("AS for kadmin/changepw");
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .expect("AP-REQ");
    let cpw = ChangePasswdData {
        newpasswd: b"z72-kpw-newpass-1".to_vec().into(),
        targname: None,
        targrealm: None,
    };
    let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw).expect("cpw")).expect("priv");
    let mut req = encode_kpasswd_req(&encode(&ap).expect("ap"), &encode(&priv_msg).expect("priv"));
    req[2..4].copy_from_slice(&0xff80u16.to_be_bytes());
    let shared = shared_dump(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("handler returns a datagram");
    assert!(
        rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
        "INITIAL self-change includes AP-REP"
    );
    let g = shared
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let p = g.get_name(&user).expect("user after kpasswd");
    let got = tl_mod_princ_name(&p.tl_data);
    assert_eq!(
        got.as_deref(),
        Some("kadmind@KERBER.TEST"),
        "kpasswd must stamp the global handle, not the client (got {got:?})"
    );
}
