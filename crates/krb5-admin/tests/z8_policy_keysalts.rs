//! Z8.4: `validate_allowed_keysalts` at addpol/modpol
//! (`svr_policy.c:20-36`). Compiles at the parent: `parse_policy_args`
//! and `add_policy_ent` exist; the parent CLI rejects `bogus:normal`
//! and a tab in the parser with a different text.

use krb5_admin::{AdminSession, parse_policy_args};
use krb5_kdc::{bootstrap_documented, documented_admin_id};

#[test]
fn z8_addpol_unknown_keysalt_is_stored_like_mit() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let mut sess = AdminSession::local(&mut store, &acl, documented_admin_id());
    let a = parse_policy_args(&["-allowedkeysalts", "bogus:normal", "z8pol"])
        .expect("CLI stores the string; MIT string_to_keysalts skips unknown tokens");
    sess.add_policy_ent(&a)
        .expect("svr_policy.c:20-36 does not EINVAL on bogus:normal");
    let text = sess.get_policy("z8pol").expect("created");
    assert!(
        text.contains("Allowed key/salt types: bogus:normal"),
        "{text}"
    );
}

#[test]
fn z8_addpol_tab_keysalt_is_invalid_key_salt_tuples() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let mut sess = AdminSession::local(&mut store, &acl, documented_admin_id());
    let a = parse_policy_args(&["-allowedkeysalts", "aes256-cts:normal\tfoo", "z8tab"])
        .expect("CLI stores the string; a tab is KADM5_BAD_KEYSALTS");
    let err = sess.add_policy_ent(&a).expect_err("svr_policy.c:28-29 tab");
    assert!(
        err.to_string().contains("Invalid key/salt tuples"),
        "got {err}"
    );
}

#[test]
fn z8_modpol_unknown_keysalt_is_stored_like_mit() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let mut sess = AdminSession::local(&mut store, &acl, documented_admin_id());
    sess.add_policy_ent(&parse_policy_args(&["z8mod"]).unwrap())
        .unwrap();
    let a = parse_policy_args(&["-allowedkeysalts", "bogus:normal", "z8mod"])
        .expect("CLI stores the string");
    sess.modify_policy_ent(&a)
        .expect("svr_policy.c:271-275 skips unknown tokens like MIT");
    let text = sess.get_policy("z8mod").expect("modified");
    assert!(
        text.contains("Allowed key/salt types: bogus:normal"),
        "{text}"
    );
}
