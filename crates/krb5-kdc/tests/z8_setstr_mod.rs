//! Z8 leftover: `kadm5_set_string` → `kdb_put_entry` stamps
//! `current_caller` (`svr_principal.c:2022-2043`). Compiles at the
//! parent: `set_string` and `tl_mod_princ_name` exist; the parent
//! writes the attr and does not stamp.

use krb5_kdc::{bootstrap_documented, documented_admin_id, tl_mod_princ_name};
use krb5_types::PrincipalName;

#[test]
fn z8_setstr_stamps_the_mod_actor() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["z8str"]);
    store
        .create_password(&acl, &documented_admin_id(), &extra, b"z8str-secret")
        .unwrap();
    let before = store.get_name(&extra).expect("created");
    assert_eq!(
        tl_mod_princ_name(&before.tl_data).as_deref(),
        Some("admin@KERBER.TEST"),
        "create stamps the session actor"
    );
    store.set_string(&extra, "note", Some("leftover")).unwrap();
    let after = store.get_name(&extra).expect("still there");
    assert_eq!(
        tl_mod_princ_name(&after.tl_data).as_deref(),
        Some("db_creation@KERBER.TEST"),
        "kdb_put_entry stamps current_caller (default_mod_actor without a handle)"
    );
}
