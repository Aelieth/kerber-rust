//! Z8 leftover: `kadm5_purgekeys` → `kdb_put_entry` stamps
//! `current_caller` (`server_kdb.c:376-377`). Compiles at the parent:
//! `purgekeys` and `tl_mod_princ_name` exist; the parent does not stamp.

use krb5_kdc::{bootstrap_documented, documented_admin_id, tl_mod_princ_name};
use krb5_types::PrincipalName;

#[test]
fn z8_purgekeys_stamps_the_mod_actor() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["z8pk"]);
    store
        .create_password(&acl, &documented_admin_id(), &extra, b"z8pk-secret")
        .unwrap();
    let before = store.get_name(&extra).expect("created");
    assert_eq!(
        tl_mod_princ_name(&before.tl_data).as_deref(),
        Some("admin@KERBER.TEST"),
        "create stamps the session actor"
    );
    store.purgekeys(&extra, -1).unwrap();
    let after = store.get_name(&extra).expect("still there");
    assert_eq!(
        tl_mod_princ_name(&after.tl_data).as_deref(),
        Some("db_creation@KERBER.TEST"),
        "kdb_put_entry stamps current_caller (default_mod_actor without a handle)"
    );
}
