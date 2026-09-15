//! Z8.3: `kadm5_create` stamps `kadmin/admin` and `kadmin/changepw`
//! `kdb5_util@REALM` (`kadm5_create.c:100`). Compiles at the parent:
//! bootstrap and `tl_mod_princ_name` exist; the parent restamps them
//! `db_creation@` via `apply_admin_fields`.

use krb5_kdc::{
    TEST_REALM, bootstrap_documented, documented_changepw, documented_kadmin, tl_mod_princ_name,
};
use krb5_types::PrincipalName;

#[test]
fn z8_bootstrap_kadmin_services_are_stamped_kdb5_util() {
    let (store, _) = bootstrap_documented().unwrap();
    for (label, name) in [
        ("kadmin/admin", documented_kadmin()),
        ("kadmin/changepw", documented_changepw()),
    ] {
        let p = store.get_name(&name).unwrap_or_else(|| panic!("{label}"));
        let got = tl_mod_princ_name(&p.tl_data);
        assert_eq!(
            got.as_deref(),
            Some("kdb5_util@KERBER.TEST"),
            "{label} kadm5_create.c:100 stamps kdb5_util@REALM (got {got:?})"
        );
    }
    let tgt = PrincipalName::krbtgt(TEST_REALM);
    let p = store.get_name(&tgt).expect("krbtgt");
    assert_eq!(
        tl_mod_princ_name(&p.tl_data).as_deref(),
        Some("db_creation@KERBER.TEST"),
        "kdb5_create.c:114-133 still stamps krbtgt db_creation@"
    );
}
