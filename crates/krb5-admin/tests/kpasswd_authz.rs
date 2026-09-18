//! Admin whole-flow tests moved from `src/lib.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
use common::*;

use krb5_admin::*;
use krb5_kdc::{bootstrap_documented, documented_admin_id};
use krb5_protocol::ReplayCache;
use krb5_types::PrincipalName;

#[test]
fn kpasswd_self_change_without_initial_is_initial_flag_needed() {
    use krb5_asn1::encode;
    use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
    use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

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
    let changepw = documented_changepw();
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
    let priv_msg = build_krb_priv(&tgs_out.session_key, &encode(&cpw).unwrap()).unwrap();
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
    use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
    use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

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
    let changepw = documented_changepw();
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
    let priv_msg = build_krb_priv(&tgs_out.session_key, &encode(&cpw).unwrap()).unwrap();
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
    use krb5_kdc::{
        TEST_ADMIN, TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store,
    };
    use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

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
    let changepw = documented_changepw();
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
    let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw).unwrap()).unwrap();
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
    use krb5_kdc::{TEST_USER, documented_changepw, shared_dump as shared_store};
    use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

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
    let changepw = documented_changepw();
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
    let priv_msg = build_krb_priv(&tgs_out.session_key, &encode(&cpw).unwrap()).unwrap();
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
    use krb5_kdc::{
        TEST_ADMIN, TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store,
    };
    use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

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
    let changepw = documented_changepw();
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
    let priv_msg = build_krb_priv(&tgs_out.session_key, &encode(&cpw).unwrap()).unwrap();
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
    use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
    use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

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
    let changepw = documented_changepw();
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
    let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw).unwrap()).unwrap();
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
    use krb5_kdc::{
        TEST_ADMIN, TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store,
    };
    use krb5_protocol::{build_ap_req, build_krb_priv};
    use krb5_types::ChangePasswdData;

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
    let changepw = documented_changepw();
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
    let priv_msg = build_krb_priv(&tgs_out.session_key, &encode(&cpw).unwrap()).unwrap();
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
    use krb5_kdc::{
        NamedPolicy, TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store,
    };
    use krb5_protocol::{ReplayCache, build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
    use krb5_types::ChangePasswdData;

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
    let changepw = documented_changepw();
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
    let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw).unwrap()).unwrap();
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
