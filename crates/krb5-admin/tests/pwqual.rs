//! W1-C C1: MIT built-in password-quality modules (`dict`, `empty`, `princ`)
//! on kadm5 create and on chpass. Compiles at `370461b` (parent-red).

#[path = "common/mod.rs"]
mod common;
use common::*;

use krb5_admin::{AdminSession, Error};
use krb5_kdc::principals::kadmin_admin;
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id,
};
use krb5_kdc::{Acl, NamedPolicy, shared_dump};

use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

const CREATE_PRINCIPAL: u32 = 1;

const KADM5_PRINCIPAL: u32 = 0x0000_0001;

const KADM5_POLICY: u32 = 0x0000_0800;

const KADM5_PASS_Q_TOOSHORT: u32 = 43_787_542;

const KADM5_PASS_Q_DICT: u32 = 43_787_544;

const EMPTY: &str = "Empty passwords are not allowed";

const PRINC: &str = "Password may not match principal name";

const DICT: &str = "Password is in the password dictionary";

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn n(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn rejected(r: Result<(), Error>) -> String {
    match r {
        Err(Error::PasswordPolicy(s)) => s,
        other => panic!("expected PasswordPolicy, got {other:?}"),
    }
}

fn create_args(name: &str, password: &str, policy: Option<&str>) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, name);
    // expire, last_pwd, pw_expire, max_life, mod_name NULL, mod_date,
    // attributes, kvno, mkvno
    for v in [0, 0, 0, 3600, 1, 0, 0, 1, 1] {
        push_u32(&mut w, v);
    }
    match policy {
        Some(p) => push_nullstring(&mut w, p),
        None => push_u32(&mut w, 0),
    }
    // aux, max_rlife, last_success, last_failed, fail_auth_count, n_key,
    // n_tl, tl_data NULL, empty key_data array
    for v in [0, 0, 0, 0, 0, 0, 0, 1, 0] {
        push_u32(&mut w, v);
    }
    push_u32(
        &mut w,
        KADM5_PRINCIPAL | if policy.is_some() { KADM5_POLICY } else { 0 },
    );
    push_nullstring(&mut w, password);
    w
}

#[test]
fn kadm5_create_empty_password_is_pass_q_tooshort_and_creates_nothing() {
    let (store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let args = create_args(&format!("c1empty@{TEST_REALM}"), "", None);
    let (stat, body) = data_call(&mut c, &store, &acl, CREATE_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_PASS_Q_TOOSHORT);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        g.get_name(&n("c1empty")).is_none(),
        "rejected create left an entry"
    );
}

#[test]
fn kadm5_create_principal_name_password_is_pass_q_dict_only_with_policy() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.put_policy(NamedPolicy::new("pq"));
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let args = create_args(&format!("pqu@{TEST_REALM}"), "PQU", Some("pq"));
    let (stat, body) = data_call(&mut c, &store, &acl, CREATE_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_PASS_Q_DICT);
    // Realm match: the plain KADM5_PASS_Q_DICT branch.
    let args = create_args(&format!("pqu@{TEST_REALM}"), "kerber.test", Some("pq"));
    let (_, body) = data_call(&mut c, &store, &acl, CREATE_PRINCIPAL, &args);
    assert_eq!(ret_code(&body), KADM5_PASS_Q_DICT);
    // No policy: the same password is accepted.
    let args = create_args(&format!("pqfree@{TEST_REALM}"), "PQFREE", None);
    let (_, body) = data_call(&mut c, &store, &acl, CREATE_PRINCIPAL, &args);
    assert_eq!(ret_code(&body), 0);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(g.get_name(&n("pqu")).is_none());
    assert!(g.get_name(&n("pqfree")).is_some());
}

#[test]
fn kadm5_create_null_password_is_a_random_key_not_the_empty_password() {
    let (store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let mut args = Vec::new();
    push_u32(&mut args, API_V2);
    push_nullstring(&mut args, &format!("host/rk.kerber.test@{TEST_REALM}"));
    for v in [0, 0, 0, 3600, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0] {
        push_u32(&mut args, v);
    }
    push_u32(&mut args, KADM5_PRINCIPAL);
    push_u32(&mut args, 0); // NULL passwd
    let (stat, body) = data_call(&mut c, &store, &acl, CREATE_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), 0, "randkey create is not passwd_checked");
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let p = g
        .get_name(&PrincipalName::new(
            PrincipalName::NT_SRV_HST,
            ["host", "rk.kerber.test"],
        ))
        .expect("created");
    assert!(!p.keys.is_empty());
    for k in &p.keys {
        let params = krb5_kdc::s2k_params(k.etype);
        let empty = krb5_crypto::string_to_key(k.etype, b"", &p.salt, Some(&params)).unwrap();
        assert_ne!(
            empty.as_bytes(),
            k.key.as_bytes(),
            "etype {:?} key is the empty-password key",
            k.etype
        );
    }
}

#[test]
fn chpass_runs_empty_and_princ_modules() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let mut sess = AdminSession::local(&mut store, &acl, documented_admin_id());
    assert_eq!(rejected(sess.change_password(&user(), b"")), EMPTY);
    // Without a policy dict/princ skip: the user's own name is accepted.
    sess.change_password(&user(), TEST_USER.as_bytes()).unwrap();
    sess.add_policy("pq");
    sess.set_policy(&user(), "pq").unwrap();
    assert_eq!(
        rejected(sess.change_password(&user(), TEST_USER.to_ascii_uppercase().as_bytes())),
        PRINC
    );
    assert_eq!(
        rejected(sess.change_password(&user(), TEST_REALM.to_ascii_lowercase().as_bytes())),
        DICT
    );
    // Under a policy the floors run first (server_misc.c:114-117): addpol
    // defaults pw_min_length to 1 (svr_policy.c:114), so "" is the policy's
    // KADM5_PASS_Q_TOOSHORT, not the empty module's text.
    assert_eq!(rejected(sess.change_password(&user(), b"")), "min_length 1");
    sess.change_password(&user(), b"userpassword").unwrap();
}

#[test]
fn dict_file_from_the_realm_stanza_rejects_words_case_insensitively() {
    let dir = scratch_dir("c1-dict-admin");
    let dict = dir.join("dict.txt");
    std::fs::write(&dict, "zebra\ncorrecthorse\napple\n").unwrap();
    let conf = krb5_config::KdcConf::parse(&format!(
        "[realms]\n    {TEST_REALM} = {{\n        dict_file = {}\n    }}\n",
        dict.display()
    ))
    .unwrap();
    let (mut store, acl) = bootstrap_documented().unwrap();
    store.apply_kdc_conf(&conf).unwrap();
    let mut sess = AdminSession::local(&mut store, &acl, documented_admin_id());
    // No policy: the dictionary does not apply.
    sess.change_password(&user(), b"correcthorse").unwrap();
    sess.add_policy("pq");
    sess.set_policy(&user(), "pq").unwrap();
    assert_eq!(
        rejected(sess.change_password(&user(), b"CorrectHorse")),
        DICT
    );
    assert_eq!(rejected(sess.change_password(&user(), b"APPLE")), DICT);
    sess.change_password(&user(), b"correcthorse1").unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
