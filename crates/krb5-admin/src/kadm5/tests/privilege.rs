//! kadm5 privilege/ACL tests (private-bound; regrouped in place).

use super::*;

/// W1-Z Z1b.3: a store-level `AclDenied` takes the stub's own
/// `KADM5_AUTH_*` (`server_stubs.c`), not `KADM5_AUTH_GET` for every op.
#[test]
fn store_acl_denied_is_the_stubs_auth_code() {
    use super::*;
    let d = Error::AclDenied;
    assert_eq!(kadm5_code(CREATE_PRINCIPAL, &d), KADM5_AUTH_ADD);
    assert_eq!(kadm5_code(CREATE_PRINCIPAL3, &d), KADM5_AUTH_ADD);
    assert_eq!(kadm5_code(CREATE_POLICY, &d), KADM5_AUTH_ADD);
    assert_eq!(kadm5_code(DELETE_PRINCIPAL, &d), KADM5_AUTH_DELETE);
    assert_eq!(kadm5_code(DELETE_POLICY, &d), KADM5_AUTH_DELETE);
    assert_eq!(kadm5_code(MODIFY_PRINCIPAL, &d), KADM5_AUTH_MODIFY);
    assert_eq!(kadm5_code(MODIFY_POLICY, &d), KADM5_AUTH_MODIFY);
    assert_eq!(kadm5_code(PURGEKEYS, &d), KADM5_AUTH_MODIFY);
    assert_eq!(kadm5_code(SET_STRING, &d), KADM5_AUTH_MODIFY);
    assert_eq!(kadm5_code(RENAME_PRINCIPAL, &d), KADM5_AUTH_INSUFFICIENT);
    assert_eq!(kadm5_code(CREATE_ALIAS, &d), KADM5_AUTH_INSUFFICIENT);
    assert_eq!(kadm5_code(GET_PRINCIPAL, &d), KADM5_AUTH_GET);
    assert_eq!(kadm5_code(GET_POLICY, &d), KADM5_AUTH_GET);
    assert_eq!(kadm5_code(GET_STRINGS, &d), KADM5_AUTH_GET);
    assert_eq!(kadm5_code(GET_PRINCS, &d), KADM5_AUTH_LIST);
    assert_eq!(kadm5_code(GET_POLS, &d), KADM5_AUTH_LIST);
    assert_eq!(kadm5_code(CHPASS_PRINCIPAL, &d), KADM5_AUTH_CHANGEPW);
    assert_eq!(kadm5_code(CHRAND_PRINCIPAL3, &d), KADM5_AUTH_CHANGEPW);
    assert_eq!(kadm5_code(SETKEY_PRINCIPAL4, &d), KADM5_AUTH_SETKEY);
    assert_eq!(kadm5_code(EXTRACT_KEYS, &d), KADM5_AUTH_EXTRACT);
    // Other store errors are op-independent.
    assert_eq!(
        kadm5_code(DELETE_PRINCIPAL, &Error::NotFound),
        KADM5_UNK_PRINC
    );
}

#[test]
fn get_privs_is_all_ones() {
    let (store, _acl, actor) = setup();
    let limited = Acl::parse("limited@KERBER.TEST i\n").expect("acl");
    for who in [actor.as_str(), "limited@KERBER.TEST", "nobody@KERBER.TEST"] {
        let out = dispatch_kadm5(&store, &limited, who, GET_PRIVS, &[]).unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.u32().unwrap(), !0, "MIT server_misc.c:155 *privs = ~0");
    }
}

#[test]
fn listprincs_inquire_is_auth_list() {
    let (store, _acl, _actor) = setup();
    let ro = Acl::parse("ro@KERBER.TEST i\n").expect("acl");
    let out = dispatch_kadm5(&store, &ro, "ro@KERBER.TEST", GET_PRINCS, &list_args()).unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_LIST);
}

#[test]
fn listprincs_list_is_ok() {
    let (store, _acl, _actor) = setup();
    let ro = Acl::parse("ro@KERBER.TEST l\n").expect("acl");
    let out = dispatch_kadm5(&store, &ro, "ro@KERBER.TEST", GET_PRINCS, &list_args()).unwrap();
    assert_eq!(ret_code(&out), 0);
}

#[test]
fn addpol_denied_is_auth_add() {
    let (store, _acl, _actor) = setup();
    let ro = Acl::parse("ro@KERBER.TEST i\n").expect("acl");
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("p"));
    let out = dispatch_kadm5(&store, &ro, "ro@KERBER.TEST", CREATE_POLICY, &w.b).unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_ADD);
}

#[test]
fn delpol_denied_is_auth_delete() {
    let (store, _acl, _actor) = setup();
    let ro = Acl::parse("ro@KERBER.TEST i\n").expect("acl");
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("p"));
    let out = dispatch_kadm5(&store, &ro, "ro@KERBER.TEST", DELETE_POLICY, &w.b).unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_DELETE);
}

#[test]
fn getprinc_self_without_acl_is_ok() {
    let (store, _acl, _actor) = setup();
    let none = Acl::parse("nobody@KERBER.TEST a\n").expect("acl");
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@KERBER.TEST"));
    w.u32(u32::MAX);
    let out = dispatch_kadm5(&store, &none, "user@KERBER.TEST", GET_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&out), 0);
}

#[test]
fn cpw_self_without_initial_is_auth_initial() {
    let (store, _acl, _actor) = setup();
    let none = Acl::parse("nobody@KERBER.TEST a\n").expect("acl");
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@KERBER.TEST"));
    w.nullstring(Some("new-secret"));
    let out = dispatch_kadm5_ticket(
        &store,
        &none,
        "user@KERBER.TEST",
        CHPASS_PRINCIPAL,
        &w.b,
        false,
        false,
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_INITIAL);
}

#[test]
fn extract_keys_acl_is_auth_extract() {
    let (store, _acl, _actor) = setup();
    let limited = Acl::parse("admin@KERBER.TEST *\nlimited@KERBER.TEST i\n").expect("acl");
    let out = dispatch_kadm5(
        &store,
        &limited,
        "limited@KERBER.TEST",
        EXTRACT_KEYS,
        &extract_args("user@KERBER.TEST", 0),
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_EXTRACT);
    let star = Acl::parse("admin@KERBER.TEST *\n").expect("acl");
    let denied = dispatch_kadm5(
        &store,
        &star,
        "admin@KERBER.TEST",
        EXTRACT_KEYS,
        &extract_args("user@KERBER.TEST", 0),
    )
    .unwrap();
    assert_eq!(ret_code(&denied), KADM5_AUTH_EXTRACT);
}

#[test]
fn purgekeys_acl_is_auth_modify() {
    let (store, _acl, _actor) = setup();
    let limited = Acl::parse("limited@KERBER.TEST i\n").expect("acl");
    let out = dispatch_kadm5(
        &store,
        &limited,
        "limited@KERBER.TEST",
        PURGEKEYS,
        &purgekeys_args("user@KERBER.TEST", -1),
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_MODIFY);
}

#[test]
fn setkey_acl_is_auth_setkey() {
    let (store, _acl, _actor) = setup();
    let limited = Acl::parse("limited@KERBER.TEST i\n").expect("acl");
    let out = dispatch_kadm5(
        &store,
        &limited,
        "limited@KERBER.TEST",
        SETKEY_PRINCIPAL,
        &setkey16_args("user@KERBER.TEST", 18, &[0xABu8; 32]),
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_SETKEY);
}

#[test]
fn unauthorized_is_auth_even_if_missing_or_lockdown() {
    let (store, _acl, _actor) = setup();
    lockdown_user(&store);
    let limited = Acl::parse("limited@KERBER.TEST i\n").expect("acl");
    let actor = "limited@KERBER.TEST";
    let cases: [(u32, Vec<u8>, u32); 10] = [
        (
            EXTRACT_KEYS,
            extract_args("user@KERBER.TEST", 0),
            KADM5_AUTH_EXTRACT,
        ),
        (
            EXTRACT_KEYS,
            extract_args("no-such@KERBER.TEST", 0),
            KADM5_UNK_PRINC,
        ),
        (
            PURGEKEYS,
            purgekeys_args("user@KERBER.TEST", -1),
            KADM5_AUTH_MODIFY,
        ),
        (
            PURGEKEYS,
            purgekeys_args("no-such@KERBER.TEST", -1),
            KADM5_UNK_PRINC,
        ),
        (
            SETKEY_PRINCIPAL,
            setkey16_args("user@KERBER.TEST", 18, &[0xABu8; 32]),
            KADM5_AUTH_SETKEY,
        ),
        (
            SETKEY_PRINCIPAL,
            setkey16_args("no-such@KERBER.TEST", 18, &[0xABu8; 32]),
            KADM5_UNK_PRINC,
        ),
        (
            CHPASS_PRINCIPAL,
            chpass_args("user@KERBER.TEST", "nope"),
            KADM5_AUTH_CHANGEPW,
        ),
        (
            CHPASS_PRINCIPAL,
            chpass_args("no-such@KERBER.TEST", "nope"),
            KADM5_UNK_PRINC,
        ),
        (
            CHRAND_PRINCIPAL,
            encode_named("user@KERBER.TEST"),
            KADM5_AUTH_CHANGEPW,
        ),
        (
            CHRAND_PRINCIPAL,
            encode_named("no-such@KERBER.TEST"),
            KADM5_UNK_PRINC,
        ),
    ];
    for (proc, args, want) in cases {
        let out = dispatch_kadm5(&store, &limited, actor, proc, &args).unwrap();
        assert_eq!(ret_code(&out), want, "proc {proc}");
    }
}

#[test]
fn chrand_acl_is_auth_changepw() {
    let (store, _acl, _actor) = setup();
    let limited = Acl::parse("limited@KERBER.TEST i\n").expect("acl");
    let out = dispatch_kadm5(
        &store,
        &limited,
        "limited@KERBER.TEST",
        CHRAND_PRINCIPAL,
        &encode_named("user@KERBER.TEST"),
    )
    .unwrap();
    let code = ret_code(&out);
    assert_eq!(code, KADM5_AUTH_CHANGEPW);
    assert_ne!(code, KADM5_AUTH_GET);
    let missing = dispatch_kadm5(
        &store,
        &limited,
        "limited@KERBER.TEST",
        CHRAND_PRINCIPAL,
        &encode_named("no-such@KERBER.TEST"),
    )
    .unwrap();
    assert_eq!(ret_code(&missing), KADM5_UNK_PRINC);
}
