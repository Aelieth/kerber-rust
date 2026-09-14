//! W1-Z Z1.1, store side: the realm defaults `kadm5_create_principal_3`
//! takes for fields absent from the mask (`svr_principal.c:381-401`
//! `handle->params.*`, `alt_prof.c:573-632`) and the local-verb shape of
//! `impose_restrictions` (`auth.c:205-272`). Compiles at `b50d6bf`
//! (parent-red).

use krb5_kdc::{Acl, KDB_DISALLOW_SVR, KDB_REQUIRES_PRE_AUTH, TEST_REALM, bootstrap_documented};
use krb5_types::PrincipalName;

fn name(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn kdc_conf(realm_lines: &str) -> krb5_config::KdcConf {
    krb5_config::KdcConf::parse(&format!(
        "[realms]\n    {TEST_REALM} = {{\n        max_life = 10h\n        max_renewable_life = 7d\n{realm_lines}    }}\n"
    ))
    .unwrap()
}

/// `alt_prof.c:596-632`: `default_principal_flags` is `params.flags`, the
/// attributes of a create without `KADM5_ATTRIBUTES`; tokens are
/// `krb5_flagspec_to_mask` over a running value that starts at
/// `KRB5_KDB_DEF_FLAGS` (0), so a written stanza overrides the Rust
/// `requires_preauth` knob (the harness sets `requires_preauth = yes`) and an
/// unknown token stops the parse keeping what came before.
#[test]
fn z1_default_principal_flags_is_params_flags_for_a_create() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .apply_kdc_conf(&kdc_conf(
            "        requires_preauth = yes\n        default_principal_flags = +disallow_svr, -requires_preauth\n",
        ))
        .unwrap();
    store
        .insert_new_password(&name("z1flags"), TEST_REALM, b"z1flags-secret", &[])
        .unwrap();
    assert_eq!(
        store.get_name(&name("z1flags")).unwrap().attributes,
        KDB_DISALLOW_SVR
    );
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .apply_kdc_conf(&kdc_conf(
            "        requires_preauth = yes\n        default_principal_flags = +disallow_svr nosuchflag +requires_preauth\n",
        ))
        .unwrap();
    store
        .insert_new_password(&name("z1stop"), TEST_REALM, b"z1stop-secret", &[])
        .unwrap();
    assert_eq!(
        store.get_name(&name("z1stop")).unwrap().attributes,
        KDB_DISALLOW_SVR,
        "parse starts at 0 and stops at the unknown token"
    );
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .apply_kdc_conf(&kdc_conf("        requires_preauth = yes\n"))
        .unwrap();
    store
        .insert_new_password(&name("z1knob"), TEST_REALM, b"z1knob-secret", &[])
        .unwrap();
    assert_eq!(
        store.get_name(&name("z1knob")).unwrap().attributes,
        KDB_REQUIRES_PRE_AUTH,
        "no stanza: the knob's bit alone (docs/security.md)"
    );
}

/// `alt_prof.c:580-594` + `svr_principal.c:396-399`: `expiration` without
/// `KADM5_PRINC_EXPIRE_TIME` is `params.expiration` =
/// `default_principal_expiration` (a `krb5_string_to_timestamp` form, local
/// time), 0 when the stanza is absent or unparsable.
#[test]
fn z1_create_without_expire_takes_default_principal_expiration() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .apply_kdc_conf(&kdc_conf(
            "        default_principal_expiration = 20300102030405\n",
        ))
        .unwrap();
    store
        .insert_new_password(&name("z1exp"), TEST_REALM, b"z1exp-secret", &[])
        .unwrap();
    // 2030-01-02T03:04:05Z is 1893553445; the stanza is local time (MIT
    // `mktime`), so the stored value is that ± the zone offset. The exact
    // local conversion is pinned by `krb5_types::timestamp` unit tests.
    let got = i64::from(store.get_name(&name("z1exp")).unwrap().expiration);
    assert_ne!(got, 0, "the stanza was ignored");
    assert!(
        (got - 1_893_553_445).abs() <= 14 * 3600,
        "{got} is not 2030-01-02 03:04:05 in any zone"
    );
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .apply_kdc_conf(&kdc_conf(
            "        default_principal_expiration = 2030-01-02\n",
        ))
        .unwrap();
    store
        .insert_new_password(&name("z1noexp"), TEST_REALM, b"z1noexp-secret", &[])
        .unwrap();
    assert_eq!(
        store.get_name(&name("z1noexp")).unwrap().expiration,
        0,
        "an unparsable value leaves MIT's zeroed params.expiration"
    );
}

/// `svr_principal.c:386-389`: `max_life` without the mask bit is
/// `params.max_life` (kdc.conf `max_life`), not 0 — MIT `getprinc` of a
/// plain `addprinc` shows the realm value.
#[test]
fn z1_create_without_max_life_takes_params_max_life() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .apply_kdc_conf(&kdc_conf("        max_life = 1h 30m\n"))
        .unwrap();
    store
        .insert_new_password(&name("z1life"), TEST_REALM, b"z1life-secret", &[])
        .unwrap();
    assert_eq!(store.get_name(&name("z1life")).unwrap().max_life, 5400);
    store
        .insert_new_randkey(&name("host/z1life"), TEST_REALM, &[])
        .unwrap();
    assert_eq!(
        store.get_name(&name("host/z1life")).unwrap().max_life,
        5400,
        "the NULL-password (random key) create takes the same default"
    );
}

/// `auth.c:259-263` for a request that carries no `max_life` (the local
/// `modprinc +flag` verb): the cap is imposed even below the stored value.
#[test]
fn z1_impose_acl_restrictions_on_an_empty_request_takes_every_cap() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let acl =
        Acl::parse("admin@KERBER.TEST * *@KERBER.TEST -maxlife 1h -maxrenewlife 2h\n").unwrap();
    store
        .insert_new_password(&name("z1cap"), TEST_REALM, b"z1cap-secret", &[])
        .unwrap();
    store
        .apply_admin_fields(
            &name("z1cap"),
            None,
            Some(600),
            None,
            None,
            None,
            false,
            Some(0),
        )
        .unwrap();
    let rs = acl
        .restrictions("admin@KERBER.TEST", Some("z1cap@KERBER.TEST"))
        .expect("restriction line");
    store.impose_acl_restrictions(&name("z1cap"), rs).unwrap();
    let p = store.get_name(&name("z1cap")).unwrap();
    assert_eq!(p.max_life, 3600, "absent from the request: cap");
    assert_eq!(p.max_renewable_life, 7200, "a stored 0 is absent too: cap");
}
