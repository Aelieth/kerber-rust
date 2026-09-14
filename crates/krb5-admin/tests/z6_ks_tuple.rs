//! Z6.5: `kadm5_create_principal_3` honours the v3 `ks_tuple` array
//! (`svr_principal.c:444-447` `apply_keysalt_policy`). Compiles at the
//! parent: CREATE_PRINCIPAL3 already parses the array (and skips it) and
//! `create_principal_3_in` already accepts an etype slice — the parent
//! passes `&[]`, so `-e` is ignored and a tuple outside
//! `allowed_keysalts` is accepted.

mod common;

use common::{API_V2, GSS_INTEGRITY, SUCCESS, data_call, init_client, push_nullstring, push_u32};
use krb5_crypto::EncryptionType;
use krb5_kdc::{
    Acl, NamedPolicy, TEST_ADMIN, TEST_REALM, bootstrap_documented, documented_kadmin, shared_dump,
};
use krb5_types::PrincipalName;

const CREATE_PRINCIPAL3: u32 = 18;
const KADM5_PRINCIPAL: u32 = 0x0000_0001;
const KADM5_POLICY: u32 = 0x0000_0800;
/// MIT `ovk` 58 (`KADM5_BAD_KEYSALTS`).
const KADM5_BAD_KEYSALTS: u32 = 43_787_578;
/// `aes128-cts-hmac-sha1-96`.
const ETYPE_AES128_SHA1: u32 = 17;
/// `KRB5_KDB_SALTTYPE_NORMAL`.
const SALTTYPE_NORMAL: u32 = 0;

fn n(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn ret_code(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[4..8].try_into().unwrap())
}

/// `xdr_cprinc3_arg`: record + mask + `ks_tuple[]` + NULL passwd (`-randkey`).
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

fn stored(store: &krb5_kdc::SharedDump, name: &str) -> krb5_kdc::Principal {
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    g.get_name(&n(name))
        .unwrap_or_else(|| panic!("{name} not created"))
        .clone()
}

/// Live: MIT `kadmin addprinc -randkey -e aes128-cts-hmac-sha1-96:normal z65`
/// → `Key: vno 1, aes128-cts-hmac-sha1-96` only.
#[test]
fn z6_create3_ks_tuple_is_the_only_key() {
    let (store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut client = init_client(
        &store,
        &acl,
        &n(TEST_ADMIN),
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let args = create3_randkey(
        &format!("z65@{TEST_REALM}"),
        None,
        KADM5_PRINCIPAL,
        ETYPE_AES128_SHA1,
    );
    let (stat, body) = data_call(&mut client, &store, &acl, CREATE_PRINCIPAL3, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), 0);
    let p = stored(&store, "z65");
    let etypes: Vec<_> = p.keys.iter().map(|k| k.etype).collect();
    assert_eq!(
        etypes,
        vec![EncryptionType::Aes128CtsHmacSha196],
        "CREATE3 ks_tuple is the key list, not supported_enctypes"
    );
}

/// `apply_keysalt_policy`: a requested tuple outside the bound policy's
/// `allowed_keysalts` is `KADM5_BAD_KEYSALTS` and creates nothing.
#[test]
fn z6_create3_ks_tuple_outside_allowed_keysalts_is_bad_keysalts() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let mut pol = NamedPolicy::new("ksonly");
    pol.allowed_keysalts = Some("aes256-cts-hmac-sha1-96:normal".into());
    store.put_policy(pol);
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut client = init_client(
        &store,
        &acl,
        &n(TEST_ADMIN),
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
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
