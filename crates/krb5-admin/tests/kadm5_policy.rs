//! `svr_policy.c` create DUP before floors; modify validates the merged record.

use krb5_admin::{AdminSession, PolicyArgs, parse_policy_args};
use krb5_kdc::testrealm::{bootstrap_documented, documented_admin_id};

#[test]
fn create_policy_dup_before_floors() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let mut sess = AdminSession::local(&mut store, &acl, actor);
    sess.add_policy_ent(&PolicyArgs {
        name: "dup".into(),
        ..PolicyArgs::default()
    })
    .unwrap();
    let err = sess
        .add_policy_ent(&PolicyArgs {
            name: "dup".into(),
            history: Some(0),
            ..PolicyArgs::default()
        })
        .unwrap_err();
    let s = err.to_string();
    assert!(
        s.contains("already exists"),
        "DUP before floors, not BAD_HISTORY: {s}"
    );
}

#[test]
fn kadmin_local_alias_creates_a_stub_for_the_target() {
    use krb5_kdc::testrealm::TEST_REALM;

    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let mut sess = AdminSession::local(&mut store, &acl, actor);
    let alias = krb5_types::PrincipalName::new(krb5_types::PrincipalName::NT_PRINCIPAL, ["av1"]);
    let target = krb5_types::PrincipalName::new(krb5_types::PrincipalName::NT_PRINCIPAL, ["user"]);
    sess.create_alias(&alias, TEST_REALM, &target, TEST_REALM)
        .expect("alias");
    assert_eq!(
        sess.get_principal_id(&alias).unwrap(),
        format!("user@{TEST_REALM}")
    );
    let realm = sess
        .create_alias(&alias, TEST_REALM, &target, "OTHER.REALM")
        .unwrap_err();
    assert_eq!(
        realm.to_string(),
        "Alias target must be within the same realm"
    );
}

#[test]
fn addpol_unknown_keysalt_is_stored_like_mit() {
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
fn addpol_tab_keysalt_is_invalid_key_salt_tuples() {
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
fn modpol_unknown_keysalt_is_stored_like_mit() {
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
