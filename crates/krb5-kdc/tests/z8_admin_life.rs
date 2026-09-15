//! Z8 leftover: `add_admin_princ` sets `KADM5_MAX_LIFE`
//! (`kadm5_create.c:54-55,207-213`). Compiles at the parent:
//! `bootstrap_documented` and the kadmin names exist; the parent
//! leaves `params.max_life` (24 h).

use krb5_kdc::{bootstrap_documented, documented_changepw, documented_kadmin};

#[test]
fn z8_kadmin_admin_max_life_is_three_hours() {
    let (store, _) = bootstrap_documented().unwrap();
    let p = store.get_name(&documented_kadmin()).expect("kadmin/admin");
    assert_eq!(
        p.max_life,
        60 * 60 * 3,
        "kadm5_create.c:54 ADMIN_LIFETIME (got {})",
        p.max_life
    );
}

#[test]
fn z8_kadmin_changepw_max_life_is_five_minutes() {
    let (store, _) = bootstrap_documented().unwrap();
    let p = store
        .get_name(&documented_changepw())
        .expect("kadmin/changepw");
    assert_eq!(
        p.max_life,
        60 * 5,
        "kadm5_create.c:55 CHANGEPW_LIFETIME (got {})",
        p.max_life
    );
}
