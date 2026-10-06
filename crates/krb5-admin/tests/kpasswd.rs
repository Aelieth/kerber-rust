//! Admin whole-flow tests.
//! The kpasswd acceptor pins the changepw service (`schpw.c` / MIT `krb5_rd_req` on the
//! kadmin/changepw cred): a ticket whose sname is anything else (here `host/x`) is refused
//! even when it decrypts under the changepw key, before the KRB-PRIV is read.
//! kpasswd stamps `kadmind@REALM` as the modifier.
//! MIT `main` (`ovsec_kadmd.c:446-446`): the global handle is `kadm5_init(…, "kadmind", …)`.
//! MIT `dispatch` (`schpw.c:407-407`): the changepw dispatcher uses that global handle.
//! The modifier is that global handle's caller, not the ticket client.
//! kpasswd reloads the store before it changes it (the `write_store` rule), so a change
//! made by another process is kept.

#[path = "common/mod.rs"]
mod common;
use common::*;

use krb5_admin::{encode_kpasswd_req, handle_kpasswd_rfc3244, *};
use krb5_asn1::encode;
use krb5_kdc::principals::kadmin_changepw;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id};
use krb5_kdc::{load_store, save_store, shared_dump, tl_mod_princ_name};

use krb5_protocol::{
    ReplayCache, as_req_sname, build_ap_req, build_krb_priv_with_seq, pa_enc_timestamp,
};
use krb5_testkit::scratch_dir;
use krb5_types::{ChangePasswdData, PrincipalName};

#[test]
fn kpasswd_host_ticket_under_changepw_key_is_refused() {
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
    let changepw = kadmin_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .expect("changepw")
        .best_key()
        .expect("key")
        .key
        .clone();

    // A real INITIAL ticket for kadmin/changepw (encrypted under the changepw key).
    let as_out = krb5_kdc::issue_as(
        &store,
        &as_req_sname(
            user.clone(),
            TEST_REALM,
            0x2400_0001,
            Some(vec![pa_enc_timestamp(&user_key).expect("pa")]),
            kadmin_changepw(),
            krb5_crypto::EncryptionType::preferred()
                .iter()
                .map(|e| e.to_iana())
                .collect(),
        )
        .expect("as-req"),
    )
    .expect("AS for kadmin/changepw");

    let mut ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .expect("AP-REQ");
    // Forge only the cleartext sname: the ticket still decrypts under the
    // changepw key, but it now claims to be host/x, not kadmin/changepw.
    ap.ticket.sname = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.kerber.test"]);
    let ap_der = encode(&ap).expect("encode ap");

    let priv_msg =
        build_krb_priv_with_seq(&as_out.session_key, b"z1-forge-newpass-123", None).expect("priv");
    let req = encode_kpasswd_req(&ap_der, &encode(&priv_msg).expect("encode priv"));

    let shared = shared_dump(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("handler returns a datagram");
    // A refusal before processing is a framed KRB-ERROR: AP-REP length 0, not a
    // real AP-REP for the host/x ticket.
    let ap_len = u16::from_be_bytes([rep[4], rep[5]]);
    assert_eq!(
        ap_len, 0,
        "host/x ticket under the changepw key must be refused"
    );
}

#[test]
fn kpasswd_self_change_without_initial_is_initial_flag_needed() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_REALM, TEST_USER};

    use krb5_protocol::{build_ap_req, build_krb_priv_with_seq, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();

    let (mut store, acl) = bootstrap_documented().unwrap();
    allow_tgs_changepw(&mut store);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let kvno_before = store
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let tgs_out = changepw_tgs_ticket(&store, &user, &user_key, 901);
    let changepw = kadmin_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"tgs-new-pass".to_vec().into(),
        targname: None,
        targrealm: None,
    };
    let priv_msg =
        build_krb_priv_with_seq(&tgs_out.session_key, &encode(&cpw).unwrap(), None).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
    let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
    let user_data = unwrap_krb_priv_ex(
        &tgs_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 7,
        "INITIAL_FLAG_NEEDED user-data [0,7]…, got {user_data:?}"
    );
    assert!(
        user_data[2..].starts_with(b"Ticket must be derived from a password"),
        "MIT text, got {:?}",
        String::from_utf8_lossy(&user_data[2..])
    );
    let after = shared.read().unwrap();
    let kvno_after = after
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert_eq!(
        kvno_after, kvno_before,
        "self-change without INITIAL must not set password"
    );
}

#[test]
fn kpasswd_self_change_with_other_name_type_still_requires_initial() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_REALM, TEST_USER};

    use krb5_protocol::{build_ap_req, build_krb_priv_with_seq, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();

    let (mut store, acl) = bootstrap_documented().unwrap();
    allow_tgs_changepw(&mut store);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let kvno_before = store
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let tgs_out = changepw_tgs_ticket(&store, &user, &user_key, 931);
    let changepw = kadmin_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"nt-unknown-pass".to_vec().into(),
        targname: Some(PrincipalName::new(PrincipalName::NT_UNKNOWN, [TEST_USER])),
        targrealm: Some(krb5_types::ascii(TEST_REALM)),
    };
    let priv_msg =
        build_krb_priv_with_seq(&tgs_out.session_key, &encode(&cpw).unwrap(), None).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
    let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
    let user_data = unwrap_krb_priv_ex(
        &tgs_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 7,
        "name-type-insensitive self-change is INITIAL_FLAG_NEEDED [0,7], got {user_data:?}"
    );
    assert!(
        user_data[2..].starts_with(b"Ticket must be derived from a password"),
        "MIT text, got {:?}",
        String::from_utf8_lossy(&user_data[2..])
    );
    let after = shared.read().unwrap();
    let kvno_after = after
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert_eq!(
        kvno_after, kvno_before,
        "NT-UNKNOWN targname must not bypass INITIAL"
    );
}

#[test]
fn kpasswd_target_realm_mismatch_is_harderror() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_ADMIN, TEST_REALM, TEST_USER};

    use krb5_protocol::{build_ap_req, build_krb_priv_with_seq, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_key = store
        .get_name(&admin)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kvno_before = store
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let as_out = changepw_as_ticket(&store, &admin, &admin_key, 941);
    let changepw = kadmin_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &admin,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"foreign-realm-pass".to_vec().into(),
        targname: Some(user.clone()),
        targrealm: Some(krb5_types::ascii("OTHER.TEST")),
    };
    let priv_msg =
        build_krb_priv_with_seq(&as_out.session_key, &encode(&cpw).unwrap(), None).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
    let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
    let user_data = unwrap_krb_priv_ex(
        &as_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 2,
        "privileged foreign targrealm is HARDERROR [0,2], got {user_data:?}"
    );
    assert_eq!(
        &user_data[2..],
        b"Password not changed.\nPrincipal does not exist while trying to change password.\n",
        "chpass_util.c:136-140, got {:?}",
        String::from_utf8_lossy(&user_data[2..])
    );
    let after = shared.read().unwrap();
    let kvno_after = after
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert_eq!(
        kvno_after, kvno_before,
        "foreign targrealm must not set password"
    );
}

#[test]
fn kpasswd_foreign_self_change_needs_initial() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::TEST_USER;

    use krb5_protocol::{build_ap_req, build_krb_priv_with_seq, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();

    let (mut store, acl) = bootstrap_documented().unwrap();
    allow_tgs_changepw(&mut store);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let kvno_before = store
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let tgs_out = changepw_tgs_ticket(&store, &user, &user_key, 951);
    let changepw = kadmin_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let mut ticket = tgs_out.rep.0.ticket.clone();
    reseal_ticket_crealm(&cpw_key, &mut ticket, "OTHER.TEST");
    let ap = build_ap_req(
        ticket,
        &tgs_out.session_key,
        &krb5_types::ascii("OTHER.TEST"),
        &user,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"foreign-self-pass".to_vec().into(),
        targname: Some(user.clone()),
        targrealm: Some(krb5_types::ascii("OTHER.TEST")),
    };
    let priv_msg =
        build_krb_priv_with_seq(&tgs_out.session_key, &encode(&cpw).unwrap(), None).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
    let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
    let user_data = unwrap_krb_priv_ex(
        &tgs_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 7,
        "foreign-realm self without INITIAL is [0,7], got {user_data:?}"
    );
    assert!(
        user_data[2..].starts_with(b"Ticket must be derived from a password"),
        "MIT text, got {:?}",
        String::from_utf8_lossy(&user_data[2..])
    );
    let after = shared.read().unwrap();
    let kvno_after = after
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert_eq!(
        kvno_after, kvno_before,
        "foreign-realm self without INITIAL must not set password"
    );
}

#[test]
fn kpasswd_unprivileged_other_principal_is_accessdenied() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_ADMIN, TEST_REALM, TEST_USER};

    use krb5_protocol::{build_ap_req, build_krb_priv_with_seq, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();

    let (mut store, acl) = bootstrap_documented().unwrap();
    allow_tgs_changepw(&mut store);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let kvno_before = store
        .get_name(&admin)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let tgs_out = changepw_tgs_ticket(&store, &user, &user_key, 961);
    let changepw = kadmin_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"other-should-fail".to_vec().into(),
        targname: Some(admin.clone()),
        targrealm: Some(krb5_types::ascii(TEST_REALM)),
    };
    let priv_msg =
        build_krb_priv_with_seq(&tgs_out.session_key, &encode(&cpw).unwrap(), None).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
    let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
    let user_data = unwrap_krb_priv_ex(
        &tgs_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 5,
        "unprivileged other principal is ACCESSDENIED [0,5], got {user_data:?}"
    );
    assert_eq!(
        &user_data[2..],
        b"Unauthorized request",
        "schpw.c:250-251, got {:?}",
        String::from_utf8_lossy(&user_data[2..])
    );
    let after = shared.read().unwrap();
    let kvno_after = after
        .get_name(&admin)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert_eq!(
        kvno_after, kvno_before,
        "unprivileged other principal must not set password"
    );
}

#[test]
fn kpasswd_self_change_with_initial_succeeds() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_REALM, TEST_USER};

    use krb5_protocol::{build_ap_req, build_krb_priv_with_seq, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let kvno_before = store
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 911);
    let changepw = kadmin_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"as-new-pass".to_vec().into(),
        targname: None,
        targrealm: None,
    };
    let priv_msg =
        build_krb_priv_with_seq(&as_out.session_key, &encode(&cpw).unwrap(), None).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
    assert!(
        rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
        "INITIAL self-change includes AP-REP"
    );
    let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
    let user_data = unwrap_krb_priv_ex(
        &as_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 0,
        "INITIAL self-change [0,0], got {user_data:?}"
    );
    let after = shared.read().unwrap();
    let kvno_after = after
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert!(
        kvno_after > kvno_before,
        "INITIAL self-change must bump kvno ({kvno_before} -> {kvno_after})"
    );
}

#[test]
fn kpasswd_admin_change_ignores_initial() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_ADMIN, TEST_REALM, TEST_USER};

    use krb5_protocol::{build_ap_req, build_krb_priv_with_seq};
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();

    let (mut store, acl) = bootstrap_documented().unwrap();
    allow_tgs_changepw(&mut store);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_key = store
        .get_name(&admin)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let tgs_out = changepw_tgs_ticket(&store, &admin, &admin_key, 921);
    let changepw = kadmin_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let ap = build_ap_req(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &admin,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"admin-set-user".to_vec().into(),
        targname: Some(user.clone()),
        targrealm: Some(krb5_types::ascii(TEST_REALM)),
    };
    let priv_msg =
        build_krb_priv_with_seq(&tgs_out.session_key, &encode(&cpw).unwrap(), None).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
    let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
    let user_data = krb5_protocol::unwrap_krb_priv_ex(
        &tgs_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 0,
        "admin-style change ignores INITIAL, got {user_data:?}"
    );
}

#[test]
fn kpasswd_self_service_and_admin_acl() {
    krb5_config::isolate_test_krb5();
    let (mut store, acl) = bootstrap_documented().unwrap();
    let user_name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let admin_name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    {
        let mut user = AdminSession::local(&mut store, &acl, "user@KERBER.TEST");
        user.change_password(&user_name, b"new-user-pass").unwrap();
        assert_eq!(
            user.change_password(&admin_name, b"nope").unwrap_err(),
            Error::AclDenied
        );
    }
    let after = store.get_name(&user_name).unwrap();
    let old_max = after.keys.iter().map(|k| k.kvno).max().unwrap();
    assert!(old_max > 1, "self-service kpasswd must bump kvno");
    {
        let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
        admin
            .change_password(&user_name, b"admin-set-pass")
            .unwrap();
    }
    let after = store.get_name(&user_name).unwrap();
    let new_max = after.keys.iter().map(|k| k.kvno).max().unwrap();
    assert!(new_max > old_max);
}

#[test]
fn kpasswd_policy_rejection_is_softerror() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::testrealm::{TEST_REALM, TEST_USER};
    use krb5_kdc::{NamedPolicy, shared_dump as shared_store};

    use krb5_protocol::{ReplayCache, build_ap_req, build_krb_priv_with_seq, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();

    let (mut store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store.put_policy(NamedPolicy {
        name: "short8".into(),
        min_length: 8,
        min_classes: 0,
        history: 0,
        max_fail: 0,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
        pw_min_life: 0,
        pw_max_life: 0,
        allowed_keysalts: None,
    });
    store
        .set_principal_policy(&user, Some("short8".into()))
        .unwrap();
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let changepw = kadmin_changepw();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 47);
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"abc".to_vec().into(),
        targname: Some(user),
        targrealm: Some(krb5_types::ascii(TEST_REALM)),
    };
    let priv_msg =
        build_krb_priv_with_seq(&as_out.session_key, &encode(&cpw).unwrap(), None).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let replay = ReplayCache::new();
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &replay, &req)
        .expect("policy rejection must reply");
    let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).expect("parse kpasswd rep");
    assert!(!ap_rep.is_empty(), "SOFTERROR reply includes AP-REP");
    let user_data = unwrap_krb_priv_ex(
        &as_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .expect("unwrap KRB-PRIV");
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 4,
        "SOFTERROR user-data [0,4]…, got {user_data:?}"
    );
}

#[test]
fn kpasswd_refuses_a_dictionary_word_after_the_database_is_read_again() {
    use krb5_protocol::unwrap_krb_priv_ex;
    krb5_config::isolate_test_krb5();
    let dir = scratch_dir("krb5-kpw-dict");
    let (db, stash, words) = (dir.join("principal"), dir.join("stash"), dir.join("words"));
    std::fs::write(&words, "zebra\ncorrecthorse\n").expect("words");
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store.put_policy(krb5_kdc::NamedPolicy::new("pq"));
    store
        .set_principal_policy(&user, Some("pq".into()))
        .expect("bind pq");
    save_store(&store, &db, &stash).expect("save");
    // kadmind's store: the database, and the dictionary read once.
    let mut store = load_store(&db, &stash).expect("load");
    let conf = krb5_config::KdcConf {
        dict_file: Some(words),
        ..Default::default()
    };
    store.init_pwqual(Some(&conf)).expect("dictionary");
    let key_of = |store: &krb5_kdc::PrincipalStore, name: &PrincipalName| {
        let p = store.get_name(name).expect("principal");
        p.best_key().expect("key").key.clone()
    };
    let user_key = key_of(&store, &user);
    let cpw_key = key_of(&store, &kadmin_changepw());
    let as_out = krb5_kdc::issue_as(
        &store,
        &as_req_sname(
            user.clone(),
            TEST_REALM,
            0x2400_0002,
            Some(vec![pa_enc_timestamp(&user_key).expect("pa")]),
            kadmin_changepw(),
            krb5_crypto::EncryptionType::preferred()
                .iter()
                .map(|e| e.to_iana())
                .collect(),
        )
        .expect("as-req"),
    )
    .expect("AS for kadmin/changepw");
    let shared = shared_dump(store);
    // Another process changes the database, so the change reads it again first.
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kpwdictx"]);
    load_store(&db, &stash)
        .expect("load writer")
        .change(|s| s.create_password(&acl, &documented_admin_id(), &extra, b"x-secret"))
        .expect("lock")
        .expect("out-of-process addprinc");
    let chpw = |newpw: &[u8]| {
        let ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .expect("AP-REQ");
        let cpw = ChangePasswdData {
            newpasswd: newpw.to_vec().into(),
            targname: None,
            targrealm: None,
        };
        let priv_msg =
            build_krb_priv_with_seq(&as_out.session_key, &encode(&cpw).expect("cpw"), None)
                .expect("priv");
        let req = encode_setpw(&encode(&ap).expect("ap"), &encode(&priv_msg).expect("priv"));
        let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
            .expect("reply");
        let (_, priv_rep) = parse_kpasswd_rep(&rep).expect("parse");
        let data = unwrap_krb_priv_ex(
            &as_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .expect("unwrap");
        let text = String::from_utf8_lossy(&data[2..]).into_owned();
        (u16::from_be_bytes([data[0], data[1]]), text)
    };
    let (code, text) = chpw(b"CorrectHorse");
    assert_eq!(code, 4, "SOFTERROR for a dictionary word: {text}");
    assert!(text.contains("dictionary"), "{text}");
    assert_eq!(chpw(b"correcthorse-9").0, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn kpasswd_unknown_version_is_bad_version() {
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let cpw_key = store
        .get_name(&kadmin_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = [0u8, 6, 0, 2, 0, 0];
    let shared = shared_store(store);
    let err = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect_err("MIT dispatch sends no reply");
    assert!(
        err.to_string()
            .contains("Requested protocol version not supported"),
        "{err}"
    );
}

#[test]
fn kpasswd_inconsistent_length_is_malformed() {
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let cpw_key = store
        .get_name(&kadmin_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = [0u8, 99, 0, 1, 0, 0];
    let shared = shared_store(store);
    let err = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect_err("MIT dispatch sends no reply");
    assert!(err.to_string().contains("Message stream modified"), "{err}");
}

#[test]
fn kpasswd_bad_ap_req_is_chpwfail_autherror() {
    use krb5_asn1::decode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;

    use krb5_types::KrbError;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let cpw_key = store
        .get_name(&kadmin_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = encode_kpasswd_req(&[0, 1, 2, 3], b"x");
    let shared = shared_store(store);
    let r1 = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("chpwfail");
    let r2 = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("retransmit");
    for rep in [&r1, &r2] {
        assert!(rep.len() > 6);
        assert_eq!(&rep[4..6], &[0, 0], "AP-REP length 0");
        let e: KrbError = decode(&rep[6..]).expect("framed KRB-ERROR");
        assert_eq!(e.error_code, krb5_types::err::GENERIC);
        assert!(e.e_text.is_none());
        assert_eq!(e.sname.name_type, PrincipalName::NT_PRINCIPAL);
        let data = e.e_data.as_ref().expect("e_data");
        assert!(data.len() >= 2 && data.as_ref()[0] == 0 && data.as_ref()[1] == 3);
        assert!(data.as_ref()[2..].starts_with(b"Failed reading application request"));
    }
}

#[test]
fn kpasswd_ap_req_fills_datagram_is_bailout() {
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let cpw_key = store
        .get_name(&kadmin_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = encode_kpasswd_req(&[0, 1, 2, 3], &[]);
    let shared = shared_store(store);
    let err = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect_err("schpw.c:89 >= is bailout");
    assert!(err.to_string().contains("Message stream modified"), "{err}");
}

#[test]
fn kpasswd_bad_priv_after_ap_req_is_harderror() {
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_REALM, TEST_USER};

    use krb5_protocol::{build_ap_req, unwrap_krb_priv_ex};

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 77);
    let cpw_key = store
        .get_name(&kadmin_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let req = encode_kpasswd_req(&krb5_asn1::encode(&ap).unwrap(), b"not-priv");
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("PRIV fail after AP-REQ");
    let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).expect("AP-REP + KRB-PRIV");
    assert_ne!(ap_rep, [] as [u8; 0]);
    let user_data = unwrap_krb_priv_ex(
        &as_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 2,
        "HARDERROR [0,2], got {user_data:?}"
    );
    assert_eq!(&user_data[2..], b"Failed decrypting request");
}

#[test]
fn kpasswd_setpw_decode_failure_is_malformed() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_REALM, TEST_USER};

    use krb5_protocol::{build_ap_req, build_krb_priv_with_seq, unwrap_krb_priv_ex};

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let kvno_before = store
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 62);
    let cpw_key = store
        .get_name(&kadmin_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let priv_msg = build_krb_priv_with_seq(&as_out.session_key, b"not-der-setpw", None).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("decode failure replies");
    let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).expect("KRB-PRIV");
    assert!(!ap_rep.is_empty(), "decode failure after AP-REQ has AP-REP");
    let user_data = unwrap_krb_priv_ex(
        &as_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 1,
        "Failed decoding ChangePasswdData is MALFORMED [0,1], got {user_data:?}"
    );
    assert_eq!(&user_data[2..], b"Failed decoding ChangePasswdData");
    let after = shared.read().unwrap();
    let kvno_after = after
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert_eq!(
        kvno_after, kvno_before,
        "decode failure must not set password"
    );
}

#[test]
fn kpasswd_rfc3244_bumps_kvno() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_REALM, TEST_USER};

    use krb5_protocol::{build_ap_req, build_krb_priv_with_seq, pa_enc_timestamp};
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let kvno_before = store
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let changepw = kadmin_changepw();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 43);
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let ap_der = encode(&ap).unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"rfc3244-new".to_vec().into(),
        targname: Some(user.clone()),
        targrealm: Some(krb5_types::ascii(TEST_REALM)),
    };
    let cpw_der = encode(&cpw).unwrap();
    let priv_msg = build_krb_priv_with_seq(&as_out.session_key, &cpw_der, None).unwrap();
    let priv_der = encode(&priv_msg).unwrap();
    let req = encode_setpw(&ap_der, &priv_der);
    let shared = shared_store(store);
    let replay = ReplayCache::new();
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &replay, &req).expect("kpasswd");
    assert!(
        rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
        "success reply must include AP-REP"
    );
    let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).expect("parse kpasswd rep");
    assert!(!ap_rep.is_empty() && !priv_rep.is_empty());
    assert!(parse_kpasswd_rep(&[0, 6, 0, 1, 0, 0]).is_err());
    let after = shared.read().unwrap();
    let kvno_after = after
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert!(kvno_after > kvno_before, "RFC 3244 must bump kvno");

    let salt = user.default_salt(TEST_REALM);
    let new_key = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"rfc3244-new",
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let as_new = krb5_protocol::as_req(
        user.clone(),
        TEST_REALM,
        45,
        Some(vec![pa_enc_timestamp(&new_key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&*after, &as_new).expect("AS with RFC 3244 new password");

    let as_old = krb5_protocol::as_req(
        user,
        TEST_REALM,
        46,
        Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
    )
    .unwrap();
    assert!(
        krb5_kdc::issue_as(&*after, &as_old).is_err(),
        "old password must fail after kpasswd"
    );
}

#[test]
fn kpasswd_accepts_first_current_ticket_when_best_key_differs() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::testrealm::{
        TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    };
    use krb5_kdc::{bootstrap_realm_with_kdc_conf, shared_dump as shared_store};

    use krb5_protocol::{build_ap_req, build_krb_priv_with_seq};
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();

    let kdc = krb5_config::KdcConf::parse(
            r"
[realms]
    KERBER.TEST = {
        supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
",
        )
        .unwrap();
    let (store, acl) = bootstrap_realm_with_kdc_conf(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
        Some(&kdc),
    )
    .unwrap();
    let changepw = kadmin_changepw();
    let cpw = store.get_name(&changepw).unwrap();
    let first = cpw.first_current_key().unwrap();
    let best = cpw.best_key().unwrap();
    assert_eq!(first.etype.to_iana(), 20);
    assert_eq!(best.etype.to_iana(), 18);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 1919);
    assert_eq!(as_out.rep.0.ticket.enc_part.etype, 20);
    let cpw_key = best.key.clone();
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let cpw_data = ChangePasswdData {
        newpasswd: b"sha384-first-pass".to_vec().into(),
        targname: Some(user.clone()),
        targrealm: Some(krb5_types::ascii(TEST_REALM)),
    };
    let priv_msg =
        build_krb_priv_with_seq(&as_out.session_key, &encode(&cpw_data).unwrap(), None).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("rd_req must try every changepw key");
    assert!(
        rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
        "success reply must include AP-REP"
    );
}

#[test]
fn kpasswd_udp_listener_then_issue_as() {
    use std::net::UdpSocket;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_REALM, TEST_USER};

    use krb5_protocol::{build_ap_req, build_krb_priv_with_seq, pa_enc_timestamp};
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let changepw = kadmin_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 47);
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"udp-new-pass".to_vec().into(),
        targname: Some(user.clone()),
        targrealm: Some(krb5_types::ascii(TEST_REALM)),
    };
    let priv_msg =
        build_krb_priv_with_seq(&as_out.session_key, &encode(&cpw).unwrap(), None).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());

    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let shared = shared_store(store);
    let shared2 = shared.clone();
    let stop2 = Arc::clone(&stop);
    thread::spawn(move || {
        krb5_config::isolate_test_krb5();
        let _ = serve_kpasswd_udp(shared2, acl, cpw_key, sock, stop2);
    });
    thread::sleep(Duration::from_millis(30));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    // Debug s2k in change_password can exceed 2s before the reply.
    client
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    client.send_to(&req, addr).unwrap();
    let mut buf = [0u8; 4096];
    let n = client.recv(&mut buf).expect("kpasswd reply");
    assert!(n > 6, "RFC 3244 reply");
    stop.store(true, Ordering::Relaxed);
    let after = shared.read().unwrap();
    let salt = user.default_salt(TEST_REALM);
    let new_key = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"udp-new-pass",
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let as_new = krb5_protocol::as_req(
        user,
        TEST_REALM,
        49,
        Some(vec![pa_enc_timestamp(&new_key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&*after, &as_new).expect("AS after UDP kpasswd");
}

#[test]
fn kpasswd_mit_style_subkey_seq0_then_issue_as() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_REALM, TEST_USER};

    use krb5_protocol::{build_ap_req_with_cksum, build_krb_priv_with_seq, pa_enc_timestamp};
    use krb5_types::ApOptions;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let changepw = kadmin_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 50);
    let sub = krb5_crypto::ProtocolKey::from_bytes(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        &[0x5au8; 32],
    )
    .unwrap();
    let sub_ek = krb5_types::EncryptionKey {
        keytype: sub.etype().to_iana(),
        keyvalue: sub.as_bytes().to_vec().into(),
    };
    let ap = build_ap_req_with_cksum(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
        ApOptions::none(),
        None,
        Some(sub_ek),
    )
    .unwrap();
    // MIT kpasswd: version 1, raw password, subkey, seq 0.
    let priv_msg = build_krb_priv_with_seq(&sub, b"kpasswd-one", Some(0)).unwrap();
    let req = encode_kpasswd_req(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let replay = ReplayCache::new();
    let rep =
        handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &replay, &req).expect("MIT-style kpasswd");
    assert!(
        rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
        "MIT kpasswd requires AP-REP on success"
    );
    let after = shared.read().unwrap();
    let salt = user.default_salt(TEST_REALM);
    let new_key = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"kpasswd-one",
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let as_new = krb5_protocol::as_req(
        user,
        TEST_REALM,
        52,
        Some(vec![pa_enc_timestamp(&new_key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&*after, &as_new).expect("AS after MIT-style kpasswd");
}

#[test]
fn kpasswd_vno1_der_stays_password() {
    use krb5_asn1::encode;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_ADMIN, TEST_REALM, TEST_USER};

    use krb5_protocol::{build_ap_req, build_krb_priv_with_seq};
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let user_kvno = store
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let admin_kvno = store
        .get_name(&admin)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 61);
    let cpw_key = store
        .get_name(&kadmin_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"der-as-pass".to_vec().into(),
        targname: Some(admin.clone()),
        targrealm: Some(krb5_types::ascii(TEST_REALM)),
    };
    let priv_msg =
        build_krb_priv_with_seq(&as_out.session_key, &encode(&cpw).unwrap(), None).unwrap();
    let req = encode_kpasswd_req(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
    let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
    let user_data = krb5_protocol::unwrap_krb_priv_ex(
        &as_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 0,
        "vno-1 DER is a self-change password, got {user_data:?}"
    );
    let after = shared.read().unwrap();
    let user_kvno_after = after
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let admin_kvno_after = after
        .get_name(&admin)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert!(user_kvno_after > user_kvno, "vno-1 DER must set self");
    assert_eq!(admin_kvno_after, admin_kvno, "vno-1 DER must not retarget");
}

#[test]
fn kpasswd_udp_exchange_ignores_off_path() {
    use std::net::UdpSocket;
    use std::thread;
    use std::time::Duration;

    krb5_config::isolate_test_krb5();

    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dest = server.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 64];
        let (n, src) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"req");
        let spoof = UdpSocket::bind("127.0.0.1:0").unwrap();
        let _ = spoof.send_to(b"spoof", src);
        thread::sleep(Duration::from_millis(30));
        let _ = server.send_to(b"kdc-ok", src);
    });
    let got = kpasswd_udp_exchange_to(dest, b"req").expect("kdc reply");
    assert_eq!(got, b"kdc-ok");
}

#[test]
fn kpasswd_stamps_kadmind_not_the_client() {
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
    let changepw = kadmin_changepw();
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
            kadmin_changepw(),
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
    let priv_msg = build_krb_priv_with_seq(&as_out.session_key, &encode(&cpw).expect("cpw"), None)
        .expect("priv");
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

#[test]
fn kpasswd_keeps_an_out_of_process_principal() {
    krb5_config::isolate_test_krb5();
    let dir = scratch_dir("krb5-z8-kpw");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    save_store(&store, &db, &stash).expect("save");
    let store = load_store(&db, &stash).expect("load listener");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .expect("user")
        .best_key()
        .expect("key")
        .key
        .clone();
    let changepw = kadmin_changepw();
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
            kadmin_changepw(),
            krb5_crypto::EncryptionType::preferred()
                .iter()
                .map(|e| e.to_iana())
                .collect(),
        )
        .expect("as-req"),
    )
    .expect("AS for kadmin/changepw");
    let shared = shared_dump(store);

    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["z8x"]);
    let mut other = load_store(&db, &stash).expect("load writer");
    other
        .change(|s| s.create_password(&acl, &documented_admin_id(), &extra, b"z8x-secret"))
        .expect("lock")
        .expect("out-of-process addprinc");
    assert!(
        other.get_name(&extra).is_some(),
        "writer must persist z8x before kpasswd"
    );

    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .expect("AP-REQ");
    let cpw = ChangePasswdData {
        newpasswd: b"z8-kpw-newpass-1".to_vec().into(),
        targname: None,
        targrealm: None,
    };
    let priv_msg = build_krb_priv_with_seq(&as_out.session_key, &encode(&cpw).expect("cpw"), None)
        .expect("priv");
    let mut req = encode_kpasswd_req(&encode(&ap).expect("ap"), &encode(&priv_msg).expect("priv"));
    req[2..4].copy_from_slice(&0xff80u16.to_be_bytes());
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("handler returns a datagram");
    assert!(
        rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
        "INITIAL self-change includes AP-REP"
    );

    let after = load_store(&db, &stash).expect("reload after kpasswd");
    assert!(
        after.get_name(&extra).is_some(),
        "kpasswd must reload before save so the out-of-process principal survives"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An MIT `kpasswd` request: the authenticator carries a subkey and no seq-number, and the
/// KRB-PRIV under that subkey carries neither a seq-number nor a timestamp (`changepw.c`).
fn mit_shaped_kpasswd_req(
    as_out: &krb5_kdc::IssuedAs,
    user: &PrincipalName,
    subkey: &krb5_crypto::ProtocolKey,
    password: &[u8],
) -> Vec<u8> {
    kpasswd_req_with_seqs(as_out, user, subkey, password, None, None)
}

/// A kpasswd request as `mit_shaped_kpasswd_req` builds it, with the authenticator's and the
/// KRB-PRIV's seq-numbers chosen (no field when `None`).
fn kpasswd_req_with_seqs(
    as_out: &krb5_kdc::IssuedAs,
    user: &PrincipalName,
    subkey: &krb5_crypto::ProtocolKey,
    password: &[u8],
    auth_seq: Option<u32>,
    priv_seq: Option<u32>,
) -> Vec<u8> {
    use krb5_types::{ApOptions, Authenticator, EncryptionKey, KerberosTime, Microseconds};

    let now = KerberosTime::now();
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: krb5_types::ascii(TEST_REALM),
        cname: user.clone(),
        cksum: None,
        cusec: Microseconds::from_subsec_micros(614_741),
        ctime: now,
        subkey: Some(EncryptionKey {
            keytype: subkey.etype().to_iana(),
            keyvalue: subkey.as_bytes().to_vec().into(),
        }),
        seq_number: auth_seq,
        authorization_data: None,
    };
    let ap = krb5_protocol::build_ap_req_from_authenticator(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        ApOptions::none(),
        &authenticator,
    )
    .unwrap();
    let mut state = krb5_crypto::CipherState::initial();
    let priv_msg =
        krb5_protocol::build_krb_priv_chained(subkey, password, priv_seq, false, &mut state)
            .unwrap();
    encode_kpasswd_req(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap())
}

/// MIT `process_chpw_request` (`schpw.c:153-166`): `krb5_rd_priv` with `DO_SEQUENCE` takes the request's KRB-PRIV only with the authenticator's seq-number (none when it has none), else the answer is HARDERROR "Failed decrypting request" and the password stays.
/// The five cases settled live beside MIT 1.22.2's kadmind.
#[test]
fn kpasswd_refuses_a_request_krb_priv_out_of_sequence() {
    use krb5_crypto::{KeyUsage, ProtocolKey, decrypt};
    use krb5_types::{EncKrbPrivPart, KrbPriv, ku};

    krb5_config::isolate_test_krb5();
    let s = 864_518_167;
    for (n, (auth_seq, priv_seq, changed)) in [
        (None, None, true),
        (None, Some(1), false),
        (Some(s), Some(s), true),
        (Some(s), Some(s + 1), false),
        (Some(s), None, false),
    ]
    .into_iter()
    .enumerate()
    {
        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let cpw_key = store
            .get_name(&kadmin_changepw())
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let kvno_before = store
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let as_out = changepw_as_ticket(&store, &user, &user_key, 930 + u32::try_from(n).unwrap());
        let subkey = ProtocolKey::random(as_out.session_key.etype()).unwrap();
        let req = kpasswd_req_with_seqs(
            &as_out,
            &user,
            &subkey,
            b"p15c-new-pass-3",
            auth_seq,
            priv_seq,
        );
        let shared = shared_dump(store);
        let rep =
            handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
        let (_, priv_der) = parse_kpasswd_rep(&rep).unwrap();
        let msg: KrbPriv = krb5_asn1::decode(&priv_der).unwrap();
        let usage = KeyUsage::new(ku::KRB_PRIV_ENC_PART).unwrap();
        let plain = decrypt(&subkey, usage, msg.enc_part.cipher.as_ref()).unwrap();
        let enc: EncKrbPrivPart = krb5_asn1::decode(&plain).unwrap();
        let kvno_after = shared
            .read()
            .unwrap()
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        if changed {
            assert_eq!(enc.user_data.as_ref(), &[0, 0], "case {n}: success");
            assert!(kvno_after > kvno_before, "case {n}: the password changed");
        } else {
            assert_eq!(
                enc.user_data.as_ref(),
                b"\x00\x02Failed decrypting request",
                "case {n}: HARDERROR"
            );
            assert_eq!(kvno_after, kvno_before, "case {n}: the password stayed");
        }
    }
}

#[test]
fn kpasswd_success_reply_is_mit_shaped() {
    use krb5_crypto::{KeyUsage, ProtocolKey, decrypt};
    use krb5_types::{ApRep, EncApRepPart, EncKrbPrivPart, KrbPriv, ku};

    krb5_config::isolate_test_krb5();
    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let cpw_key = store
        .get_name(&kadmin_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 917);
    let subkey = ProtocolKey::random(as_out.session_key.etype()).unwrap();
    let req = mit_shaped_kpasswd_req(&as_out, &user, &subkey, b"p15a-new-pass-2");
    let shared = shared_dump(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
    let (ap_der, priv_der) = parse_kpasswd_rep(&rep).unwrap();

    // MIT `process_chpw_request` / `k5_mk_rep`: the AP-REP echoes the client's own subkey and
    // takes a fresh 30-bit seq-number.
    let ap: ApRep = krb5_asn1::decode(&ap_der).unwrap();
    let usage = KeyUsage::new(ku::AP_REP_ENC_PART).unwrap();
    let plain = decrypt(&as_out.session_key, usage, ap.enc_part.cipher.as_ref()).unwrap();
    let part: EncApRepPart = krb5_asn1::decode(&plain).unwrap();
    assert_eq!(
        part.cusec.get(),
        614_741,
        "ctime/cusec echo the authenticator"
    );
    let echoed = part.subkey.expect("the AP-REP carries a subkey");
    assert_eq!(
        echoed.keyvalue.as_ref(),
        subkey.as_bytes(),
        "the client's own subkey"
    );
    let seq = part.seq_number.expect("the AP-REP carries a seq-number");
    assert!(seq != 0 && seq < 1 << 30, "a fresh 30-bit seq, got {seq}");

    // MIT `krb5_mk_priv` under DO_SEQUENCE: no timestamp, the AP-REP's seq, the address the
    // request came in on, no r-address.
    let msg: KrbPriv = krb5_asn1::decode(&priv_der).unwrap();
    let usage = KeyUsage::new(ku::KRB_PRIV_ENC_PART).unwrap();
    let plain = decrypt(&subkey, usage, msg.enc_part.cipher.as_ref()).unwrap();
    let enc: EncKrbPrivPart = krb5_asn1::decode(&plain).unwrap();
    assert_eq!(enc.user_data.as_ref(), &[0, 0], "success");
    assert_eq!(enc.timestamp, None);
    assert_eq!(enc.usec, None);
    assert_eq!(enc.seq_number, Some(seq));
    assert_eq!(enc.s_address.addr_type, 2);
    assert_eq!(enc.s_address.address.as_ref(), &[127, 0, 0, 1]);
    assert_eq!(enc.r_address, None);
}

#[test]
fn kpasswd_session_enctype_outside_permitted_is_autherror() {
    krb5_config::isolate_test_krb5();
    let dir = scratch_dir("p15a-kpasswd-permitted");
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        "[libdefaults]\n    default_realm = KERBER.TEST\n    permitted_enctypes = aes128-cts-hmac-sha1-96\n",
    )
    .unwrap();
    krb5_config::set_test_krb5_paths(Some(vec![conf]));
    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let cpw_key = store
        .get_name(&kadmin_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 919);
    assert_eq!(
        as_out.session_key.etype(),
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196
    );
    let subkey = krb5_crypto::ProtocolKey::random(as_out.session_key.etype()).unwrap();
    let req = mit_shaped_kpasswd_req(&as_out, &user, &subkey, b"p15a-new-pass-3");
    let shared = shared_dump(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
    krb5_config::set_test_krb5_paths(None);
    let _ = std::fs::remove_dir_all(&dir);
    // MIT `negotiate_etype` fails `krb5_rd_req`, so `process_chpw_request` answers with the
    // framed KRB-ERROR whose e-data is AUTHERROR "Failed reading application request".
    assert_eq!(u16::from_be_bytes([rep[4], rep[5]]), 0, "no AP-REP");
    let err: krb5_types::KrbError = krb5_asn1::decode(&rep[6..]).unwrap();
    let e_data = err.e_data.unwrap();
    assert_eq!(&e_data.as_ref()[..2], &[0, 3]);
    assert_eq!(&e_data.as_ref()[2..], b"Failed reading application request");
}
