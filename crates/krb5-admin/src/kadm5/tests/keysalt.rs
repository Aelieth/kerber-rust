//! kadm5 keysalt tests (private-bound; regrouped in place).

use super::*;

#[test]
fn setkey4_keepold_retains_history() {
    let (store, acl, actor) = setup();
    let n_old = {
        let g = store.read().unwrap();
        g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .unwrap()
            .keys
            .len()
    };
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        SETKEY_PRINCIPAL4,
        &setkey4_args("user@KERBER.TEST", true, 0, 18, &[0xCDu8; 32], 0, &[]),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0);
    let g = store.read().unwrap();
    let p = g
        .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
        .unwrap();
    assert_eq!(p.keys.len(), 1 + n_old);
    assert!(p.keys.iter().any(|k| k.key.as_bytes() == [0xCDu8; 32]));
    assert!(p.key_history.is_empty());
}
