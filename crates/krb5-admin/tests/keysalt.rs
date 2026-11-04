//! `kadm5_create_principal_3` honours the v3 `ks_tuple` array (`apply_keysalt_policy`).
// MIT: `kadm5_chpass_principal_3` (svr_principal.c:1259-1259)
//! the requested `ks_tuple` goes through `apply_keysalt_policy` with the entry's policy.
// MIT: `kadm5_randkey_principal_3` (svr_principal.c:1425-1425)
//! the requested `ks_tuple` goes through `apply_keysalt_policy` with the entry's policy.

#[path = "common/mod.rs"]
mod common;
use common::*;

use krb5_kdc::principals::kadmin_admin;
use krb5_kdc::testrealm::{TEST_ADMIN, TEST_REALM, bootstrap_documented};
use krb5_kdc::{Acl, NamedPolicy, shared_dump};

use krb5_types::PrincipalName;

const CREATE_PRINCIPAL3: u32 = 18;

const KADM5_PRINCIPAL: u32 = 0x0000_0001;

const KADM5_POLICY: u32 = 0x0000_0800;

const KADM5_BAD_KEYSALTS: u32 = 43_787_578;

const ETYPE_AES128_SHA1: u32 = 17;

const SALTTYPE_NORMAL: u32 = 0;

fn n(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn create3_randkey(name: &str, policy: Option<&str>, mask: u32, etype: u32) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, name);
    push_u32(&mut w, 0); // expire
    push_u32(&mut w, 0); // last_pwd
    push_u32(&mut w, 0); // pw_expire
    push_u32(&mut w, 0); // max_life
    push_u32(&mut w, 1); // mod_name NULL
    push_u32(&mut w, 0); // mod_date
    push_u32(&mut w, 0); // attributes
    push_u32(&mut w, 0); // kvno
    push_u32(&mut w, 0); // mkvno
    match policy {
        Some(p) => push_nullstring(&mut w, p),
        None => push_u32(&mut w, 0),
    }
    push_u32(&mut w, 0); // aux
    push_u32(&mut w, 0); // max_rlife
    push_u32(&mut w, 0); // last_success
    push_u32(&mut w, 0); // last_failed
    push_u32(&mut w, 0); // fail_auth_count
    push_u32(&mut w, 0); // n_key_data
    push_u32(&mut w, 0); // n_tl_data
    push_u32(&mut w, 1); // tl_data NULL
    push_u32(&mut w, 0); // key_data
    push_u32(&mut w, mask);
    push_u32(&mut w, 1); // n_ks_tuple
    push_u32(&mut w, etype);
    push_u32(&mut w, SALTTYPE_NORMAL);
    push_u32(&mut w, 0); // NULL passwd
    w
}

#[test]
fn create3_ks_tuple_outside_allowed_keysalts_is_bad_keysalts() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let mut pol = NamedPolicy::new("ksonly");
    pol.allowed_keysalts = Some("aes256-cts-hmac-sha1-96:normal".into());
    store.put_policy(pol).unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut client = init_client(&store, &acl, &n(TEST_ADMIN), &kadmin_admin(), GSS_INTEGRITY);
    let args = create3_randkey(
        &format!("z65bad@{TEST_REALM}"),
        Some("ksonly"),
        KADM5_PRINCIPAL | KADM5_POLICY,
        ETYPE_AES128_SHA1,
    );
    let (stat, body) = data_call(&mut client, &store, &acl, CREATE_PRINCIPAL3, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_BAD_KEYSALTS);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        g.get_name(&n("z65bad")).is_none(),
        "rejected keysalt create left an entry"
    );
}

const CHPASS_PRINCIPAL3: u32 = 19;

const ETYPE_UNKNOWN: u32 = 99;

fn chpass3(name: &str, etype: u32, pass: &str) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, name);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, etype);
    push_u32(&mut w, SALTTYPE_NORMAL);
    push_nullstring(&mut w, pass);
    w
}

#[test]
fn chpass3_unknown_etype_is_bad_keysalts() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    store
        .create_password(&acl, "admin@KERBER.TEST", &n("z72bad"), b"z72-bad-secret")
        .unwrap();
    let store = shared_dump(store);
    let mut client = init_client(&store, &acl, &n(TEST_ADMIN), &kadmin_admin(), GSS_INTEGRITY);
    let args = chpass3(
        &format!("z72bad@{TEST_REALM}"),
        ETYPE_UNKNOWN,
        "z72-bad-new",
    );
    let (stat, body) = data_call(&mut client, &store, &acl, CHPASS_PRINCIPAL3, &args);
    assert_eq!(stat, SUCCESS, "unknown ks_tuple must not be RPC SYSTEM_ERR");
    assert_eq!(ret_code(&body), KADM5_BAD_KEYSALTS);
}
