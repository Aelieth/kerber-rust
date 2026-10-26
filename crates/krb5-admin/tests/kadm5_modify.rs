//! `kadm5_modify_principal` validates TL type and fail_auth_count before the store write.
// MIT: `xdr_krb5_tl_data` (kadm_rpc_xdr.c:349-349)
//! a TL type that does not decode as an int16 fails the decode.
// MIT: `krb5_dbe_lookup_mod_princ_data` (kdb5.c:1637-1663)
//! the mod principal is parsed from `KRB5_TL_MOD_PRINC` after its 4-byte time.
//! The mod name `GET_PRINCIPAL` returns is the RPC caller's GSS name, never a fixed `kadmin/admin@REALM`.

#[path = "common/mod.rs"]
mod common;
use common::*;

use krb5_kdc::principals::kadmin_admin;
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id,
};
use krb5_kdc::{Acl, load_store, save_store, shared_dump};

use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

const MODIFY_PRINCIPAL: u32 = 3;

const KADM5_MAX_LIFE: u32 = 0x0000_0020;

const KADM5_TL_DATA: u32 = 0x0004_0000;

const CREATE_PRINCIPAL: u32 = 1;

const KADM5_POLICY: u32 = 0x0000_0800;

const KADM5_POLICY_CLR: u32 = 0x0000_1000;

const KADM5_PRINCIPAL: u32 = 0x0000_0001;

const KADM5_BAD_MASK: u32 = 43_787_534;

const KADM5_KEY_DATA: u32 = 0x0002_0000;

const KADM5_AUTH_MODIFY: u32 = 43_787_523;

const KADM5_UNK_PRINC: u32 = 43_787_532;

const EINVAL: u32 = 22;

fn modify_args_r12_kadm5_order(
    princ: &str,
    max_life: u32,
    tls: &[(u32, &[u8])],
    mask: u32,
) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, princ);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, max_life);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    for _ in 0..4 {
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, u32::from(!tls.is_empty()));
    if tls.is_empty() {
        push_u32(&mut w, 1);
    } else {
        push_u32(&mut w, 0);
        for (ty, contents) in tls {
            push_u32(&mut w, 1);
            push_u32(&mut w, *ty);
            push_opaque(&mut w, contents);
        }
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, 0);
    push_u32(&mut w, mask);
    w
}

fn admin_client(store: &krb5_kdc::SharedDump, acl: &Acl) -> common::Client {
    init_client(
        store,
        acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    )
}

#[test]
fn modify_one_db_args_is_einval_and_unchanged() {
    let dir = scratch_dir("krb5-r12-kadm5");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let store = load_store(&db, &stash).unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let orig = store.get_name(&user).unwrap().clone();
    let file_before = std::fs::read(&db).unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = admin_client(&store, &acl);
    let args = modify_args_r12_kadm5_order(
        &format!("{TEST_USER}@{TEST_REALM}"),
        60,
        &[(0x7fff, b"foo=bar\0")],
        KADM5_MAX_LIFE | KADM5_TL_DATA,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), EINVAL);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let p = g.get_name(&user).unwrap();
    assert_eq!(p.attributes, orig.attributes);
    assert_eq!(p.max_life, orig.max_life);
    assert_eq!(p.tl_data, orig.tl_data);
    assert_eq!(std::fs::read(&db).unwrap(), file_before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ro_policy_and_policy_clr_is_auth_modify() {
    let (mut store, admin_acl) = bootstrap_documented().unwrap();
    let ro = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["ro"]);
    store
        .create_password(&admin_acl, &documented_admin_id(), &ro, b"ro-secret")
        .unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\nro@KERBER.TEST i\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(&store, &acl, &ro, &kadmin_admin(), GSS_INTEGRITY);
    let args = modify_args_r12_kadm5_order(
        &format!("{TEST_USER}@{TEST_REALM}"),
        60,
        &[],
        KADM5_POLICY | KADM5_POLICY_CLR,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_AUTH_MODIFY);
    assert_ne!(ret_code(&body), KADM5_BAD_MASK);
    let mut admin = admin_client(&store, &acl);
    let unk = modify_args_r12_kadm5_order(&format!("nosuch@{TEST_REALM}"), 60, &[], KADM5_MAX_LIFE);
    let (stat, body) = data_call(&mut admin, &store, &acl, MODIFY_PRINCIPAL, &unk);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_UNK_PRINC);
}

#[test]
fn create_key_data_mask_with_one_key_is_bad_mask() {
    let (store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = admin_client(&store, &acl);
    let name = format!("r12key@{TEST_REALM}");
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, &name);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 3600);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, 1);
    push_u32(&mut w, 1);
    push_u32(&mut w, 1);
    push_u32(&mut w, 18);
    push_u32(&mut w, KADM5_PRINCIPAL | KADM5_KEY_DATA);
    push_nullstring(&mut w, "password");
    let (stat, body) = data_call(&mut c, &store, &acl, CREATE_PRINCIPAL, &w);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_BAD_MASK);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["r12key"]))
            .is_none()
    );
}

const KADM5_MAX_RLIFE: u32 = 0x0000_2000;

fn modify_rlife_args(princ: &str, max_rlife: u32, mask: u32) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, princ);
    for _ in 0..4 {
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, 1);
    for _ in 0..5 {
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, 0);
    push_u32(&mut w, max_rlife);
    for _ in 0..5 {
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, mask);
    w
}

#[test]
fn kadm5_modify_sets_max_rlife() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let args = modify_rlife_args(
        &format!("{TEST_USER}@{TEST_REALM}"),
        86_400,
        KADM5_MAX_RLIFE,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), 0);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(g.get_name(&user).unwrap().max_renewable_life, 86_400);
}

const GET_PRINCIPAL: u32 = 5;

fn n(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn push_create(name: &str, password: &str) -> Vec<u8> {
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
    push_u32(&mut w, 0); // policy NULL
    push_u32(&mut w, 0); // aux
    push_u32(&mut w, 0); // max_rlife
    push_u32(&mut w, 0); // last_success
    push_u32(&mut w, 0); // last_failed
    push_u32(&mut w, 0); // fail_auth_count
    push_u32(&mut w, 0); // n_key_data
    push_u32(&mut w, 0); // n_tl_data
    push_u32(&mut w, 1); // tl_data NULL
    push_u32(&mut w, 0); // key_data
    push_u32(&mut w, KADM5_PRINCIPAL);
    push_nullstring(&mut w, password);
    w
}

fn get_args(name: &str) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, name);
    push_u32(&mut w, u32::MAX);
    w
}

fn take_nullstring(b: &[u8], i: &mut usize) -> Option<String> {
    let raw = take_opaque(b, i);
    if raw.is_empty() {
        return None;
    }
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    Some(String::from_utf8_lossy(&raw[..end]).into_owned())
}

fn gprinc_mod_name(body: &[u8]) -> String {
    let mut i = 0;
    assert_eq!(take_u32(body, &mut i), API_V2);
    assert_eq!(take_u32(body, &mut i), 0);
    let _princ = take_nullstring(body, &mut i);
    let _ = take_u32(body, &mut i);
    let _ = take_u32(body, &mut i);
    let _ = take_u32(body, &mut i);
    let _ = take_u32(body, &mut i);
    assert_eq!(take_u32(body, &mut i), 0, "mod_name present");
    take_nullstring(body, &mut i).expect("mod_name")
}

#[test]
fn getprinc_mod_name_is_the_rpc_caller() {
    let (store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut client = init_client(&store, &acl, &n(TEST_ADMIN), &kadmin_admin(), GSS_INTEGRITY);
    let (stat, body) = data_call(
        &mut client,
        &store,
        &acl,
        CREATE_PRINCIPAL,
        &push_create("z64g@KERBER.TEST", "z64-secret"),
    );
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), 0);
    let (stat, body) = data_call(
        &mut client,
        &store,
        &acl,
        GET_PRINCIPAL,
        &get_args("z64g@KERBER.TEST"),
    );
    assert_eq!(stat, SUCCESS);
    let want = format!("{TEST_ADMIN}@{TEST_REALM}");
    let got = gprinc_mod_name(&body);
    assert_eq!(
        got, want,
        "getprinc mod_name is the GSS client, not the kadmind acceptor"
    );
}
