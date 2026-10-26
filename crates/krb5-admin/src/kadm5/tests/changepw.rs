//! kadm5 changepw tests (private-bound; regrouped in place).

use super::*;

// AZ-1 cell 6 (A2-20): a caller's own policy is read in the caller's realm, so a same-name store
// principal does not grant it. Not lab-gradable (MIT's KDC refuses the cross-realm kadmin ticket).
#[test]
fn changepw_cross_realm_same_name_getpol_is_denied() {
    let (store, acl, _actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    {
        let mut g = store.write().unwrap();
        g.put_policy(krb5_kdc::NamedPolicy::new("userpol")).unwrap();
        g.set_principal_policy(&user, Some("userpol".into()))
            .unwrap();
    }
    // user@KERBER.TEST holds userpol, but the caller is user@OTHER.REALM: its own-policy lookup
    // finds no record, so the read pre-AZ's name-only lookup allowed is now denied.
    let denied = cpw_dispatch(
        &store,
        &acl,
        "user@OTHER.REALM",
        GET_POLICY,
        &encode_named("userpol"),
    );
    assert_eq!(ret_code(&denied), KADM5_AUTH_GET);
}

#[test]
fn changepw_acceptor_requires_store_realm() {
    let cpw = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]);
    let realm = "KERBER.TEST";
    assert!(acceptor_realm_ok(
        Some(&cpw),
        Some(realm),
        realm,
        kadm5_changepw_ok
    ));
    assert!(!acceptor_realm_ok(
        Some(&cpw),
        Some("OTHER.REALM"),
        realm,
        kadm5_changepw_ok
    ));
    assert!(!acceptor_realm_ok(
        Some(&cpw),
        None,
        realm,
        kadm5_changepw_ok
    ));
}
