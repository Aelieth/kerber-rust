//! kadm5 lockdown tests (private-bound; regrouped in place).

use super::*;

#[test]
fn extract_keys_lockdown_is_protect_keys() {
    let (store, acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    {
        let mut g = store.write().unwrap();
        g.apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        EXTRACT_KEYS,
        &extract_args("user@KERBER.TEST", 0),
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_EXTRACT);
}
