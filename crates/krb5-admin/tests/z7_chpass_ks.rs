//! Z7.2 (d): `kadm5_chpass_principal_3` / `kadm5_randkey_principal_3`
//! honour the v3 `ks_tuple` (`svr_principal.c:1259,1425`). Compiles at
//! the parent: CHPASS3/CHRAND3 already exist and skip the array, so `-e`
//! is ignored and an unknown etype is not `KADM5_BAD_KEYSALTS`.

mod common;

use common::{API_V2, GSS_INTEGRITY, SUCCESS, data_call, init_client, push_nullstring, push_u32};
use krb5_crypto::EncryptionType;
use krb5_kdc::{
    Acl, NamedPolicy, TEST_ADMIN, TEST_REALM, bootstrap_documented, documented_kadmin, shared_dump,
};
use krb5_types::PrincipalName;

const CHPASS_PRINCIPAL3: u32 = 19;
const CHRAND_PRINCIPAL3: u32 = 20;
const KADM5_BAD_KEYSALTS: u32 = 43_787_578;
const ETYPE_AES128_SHA1: u32 = 17;
const SALTTYPE_NORMAL: u32 = 0;
const ETYPE_UNKNOWN: u32 = 99;

fn n(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn ret_code(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[4..8].try_into().unwrap())
}

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

fn chrand3(name: &str, etype: u32) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, name);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, etype);
    push_u32(&mut w, SALTTYPE_NORMAL);
    w
}

fn stored(store: &krb5_kdc::SharedDump, name: &str) -> krb5_kdc::Principal {
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    g.get_name(&n(name))
        .unwrap_or_else(|| panic!("{name} missing"))
        .clone()
}

#[test]
fn z7_chpass3_ks_tuple_is_the_only_key() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    store
        .create_password(&acl, "admin@KERBER.TEST", &n("z72c"), b"z72-old-secret")
        .unwrap();
    let store = shared_dump(store);
    let mut client = init_client(
        &store,
        &acl,
        &n(TEST_ADMIN),
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let args = chpass3(
        &format!("z72c@{TEST_REALM}"),
        ETYPE_AES128_SHA1,
        "z72-new-secret",
    );
    let (stat, body) = data_call(&mut client, &store, &acl, CHPASS_PRINCIPAL3, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), 0);
    let etypes: Vec<_> = stored(&store, "z72c")
        .keys
        .iter()
        .map(|k| k.etype)
        .collect();
    assert_eq!(
        etypes,
        vec![EncryptionType::Aes128CtsHmacSha196],
        "CHPASS3 ks_tuple is the key list, not supported_enctypes"
    );
}

#[test]
fn z7_chrand3_ks_tuple_is_the_only_key() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    store
        .create_password(&acl, "admin@KERBER.TEST", &n("z72r"), b"z72-rand-secret")
        .unwrap();
    let store = shared_dump(store);
    let mut client = init_client(
        &store,
        &acl,
        &n(TEST_ADMIN),
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let args = chrand3(&format!("z72r@{TEST_REALM}"), ETYPE_AES128_SHA1);
    let (stat, body) = data_call(&mut client, &store, &acl, CHRAND_PRINCIPAL3, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), 0);
    let etypes: Vec<_> = stored(&store, "z72r")
        .keys
        .iter()
        .map(|k| k.etype)
        .collect();
    assert_eq!(
        etypes,
        vec![EncryptionType::Aes128CtsHmacSha196],
        "CHRAND3 ks_tuple is the key list, not supported_enctypes"
    );
}

#[test]
fn z7_chpass3_unknown_etype_is_bad_keysalts() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    store
        .create_password(&acl, "admin@KERBER.TEST", &n("z72bad"), b"z72-bad-secret")
        .unwrap();
    let store = shared_dump(store);
    let mut client = init_client(
        &store,
        &acl,
        &n(TEST_ADMIN),
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let args = chpass3(
        &format!("z72bad@{TEST_REALM}"),
        ETYPE_UNKNOWN,
        "z72-bad-new",
    );
    let (stat, body) = data_call(&mut client, &store, &acl, CHPASS_PRINCIPAL3, &args);
    assert_eq!(stat, SUCCESS, "unknown ks_tuple must not be RPC SYSTEM_ERR");
    assert_eq!(ret_code(&body), KADM5_BAD_KEYSALTS);
}

#[test]
fn z7_chrand3_unknown_etype_is_bad_keysalts() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    store
        .create_password(&acl, "admin@KERBER.TEST", &n("z72rbad"), b"z72-rbad-secret")
        .unwrap();
    let store = shared_dump(store);
    let mut client = init_client(
        &store,
        &acl,
        &n(TEST_ADMIN),
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let args = chrand3(&format!("z72rbad@{TEST_REALM}"), ETYPE_UNKNOWN);
    let (stat, body) = data_call(&mut client, &store, &acl, CHRAND_PRINCIPAL3, &args);
    assert_eq!(stat, SUCCESS, "unknown ks_tuple must not be RPC SYSTEM_ERR");
    assert_eq!(ret_code(&body), KADM5_BAD_KEYSALTS);
}

#[test]
fn z7_chpass3_outside_allowed_keysalts_is_bad_keysalts() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let mut pol = NamedPolicy::new("ksonly");
    pol.allowed_keysalts = Some("aes256-cts-hmac-sha1-96:normal".into());
    store.put_policy(pol);
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    store
        .create_password(&acl, "admin@KERBER.TEST", &n("z72pol"), b"z72-pol-secret")
        .unwrap();
    store
        .apply_admin_fields(
            &n("z72pol"),
            None,
            None,
            None,
            None,
            Some("ksonly".into()),
            false,
            None,
        )
        .unwrap();
    let store = shared_dump(store);
    let mut client = init_client(
        &store,
        &acl,
        &n(TEST_ADMIN),
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let args = chpass3(
        &format!("z72pol@{TEST_REALM}"),
        ETYPE_AES128_SHA1,
        "z72-pol-new",
    );
    let (stat, body) = data_call(&mut client, &store, &acl, CHPASS_PRINCIPAL3, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_BAD_KEYSALTS);
}
