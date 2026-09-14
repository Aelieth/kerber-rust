//! Z6.4: `get_principal` unparses `mod_name` from `KRB5_TL_MOD_PRINC`
//! (`kadmin.c:1476`, `kdb5.c:1637-1663`). Compiles at the parent: CREATE
//! and GET already exist; the parent hard-codes `kadmin/admin@REALM` on
//! the wire regardless of the GSS client.

mod common;

use common::{API_V2, GSS_INTEGRITY, SUCCESS, data_call, init_client, push_nullstring, push_u32};
use krb5_kdc::{Acl, TEST_ADMIN, TEST_REALM, bootstrap_documented, documented_kadmin, shared_dump};
use krb5_types::PrincipalName;

const CREATE_PRINCIPAL: u32 = 1;
const GET_PRINCIPAL: u32 = 5;
const KADM5_PRINCIPAL: u32 = 0x0000_0001;

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

fn ret_code(b: &[u8]) -> u32 {
    let mut i = 0;
    let _api = u32::from_be_bytes(b[i..i + 4].try_into().unwrap());
    i += 4;
    u32::from_be_bytes(b[i..i + 4].try_into().unwrap())
}

fn take_u32(b: &[u8], i: &mut usize) -> u32 {
    let v = u32::from_be_bytes(b[*i..*i + 4].try_into().unwrap());
    *i += 4;
    v
}

fn take_opaque<'a>(b: &'a [u8], i: &mut usize) -> &'a [u8] {
    let n = take_u32(b, i) as usize;
    let s = &b[*i..*i + n];
    *i += n + (4 - n % 4) % 4;
    s
}

fn take_nullstring(b: &[u8], i: &mut usize) -> Option<String> {
    let raw = take_opaque(b, i);
    if raw.is_empty() {
        return None;
    }
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    Some(String::from_utf8_lossy(&raw[..end]).into_owned())
}

/// `xdr_kadm5_principal_ent_rec`: principal, expire, last_pwd, pw_expire,
/// max_life, xdr_nulltype+mod_name, mod_date.
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
fn z6_getprinc_mod_name_is_the_rpc_caller() {
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
