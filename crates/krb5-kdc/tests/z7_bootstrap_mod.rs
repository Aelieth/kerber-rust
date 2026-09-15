//! Z7.2 (c): `kdb5_util create` stamps `db_creation@REALM`
//! (`kdb5_create.c:114-133`). Compiles at the parent: bootstrap and
//! `tl_mod_princ_name` exist; the parent hard-codes `kadmin/admin@REALM`.

use krb5_kdc::{TEST_REALM, bootstrap_documented, tl_mod_princ_name};
use krb5_types::PrincipalName;

#[test]
fn z7_bootstrap_krbtgt_is_stamped_db_creation() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = PrincipalName::krbtgt(TEST_REALM);
    let p = store.get_name(&tgt).expect("krbtgt");
    let got = tl_mod_princ_name(&p.tl_data);
    assert_eq!(
        got.as_deref(),
        Some("db_creation@KERBER.TEST"),
        "kdb5_util create stamps db_creation@REALM (got {got:?})"
    );
}
