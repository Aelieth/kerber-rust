//! `svr_policy.c` create DUP before floors; modify validates the merged record.

use krb5_admin::{AdminSession, PolicyArgs};
use krb5_kdc::{bootstrap_documented, documented_admin_id};

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
fn modify_policy_below_floor_is_bad_length() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let mut sess = AdminSession::local(&mut store, &acl, actor);
    sess.add_policy_ent(&PolicyArgs {
        name: "floors1".into(),
        ..PolicyArgs::default()
    })
    .unwrap();
    let err = sess
        .modify_policy_ent(&PolicyArgs {
            name: "floors1".into(),
            min_length: Some(0),
            ..PolicyArgs::default()
        })
        .unwrap_err();
    assert!(err.to_string().contains("Invalid password length"), "{err}");
}

#[test]
fn getpol_prints_allowed_keysalts_only_when_set() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let mut sess = AdminSession::local(&mut store, &acl, actor);
    sess.add_policy_ent(&PolicyArgs {
        name: "plain".into(),
        ..PolicyArgs::default()
    })
    .unwrap();
    sess.add_policy_ent(&PolicyArgs {
        name: "ksalt".into(),
        allowed_keysalts: Some("aes256-cts:normal".into()),
        ..PolicyArgs::default()
    })
    .unwrap();
    assert!(
        !sess
            .get_policy("plain")
            .unwrap()
            .contains("Allowed key/salt types:")
    );
    assert!(
        sess.get_policy("ksalt")
            .unwrap()
            .contains("Allowed key/salt types: aes256-cts:normal")
    );
}

#[test]
fn create_policy_checks_min_over_max_before_length_like_mit() {
    // MIT kadm5_create_policy order: DUP -> name -> min>max -> length -> classes -> history.
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let mut sess = AdminSession::local(&mut store, &acl, actor);
    let err = sess
        .add_policy_ent(&PolicyArgs {
            name: "ordr".into(),
            min_length: Some(0),
            pw_min_life: Some(7200),
            pw_max_life: Some(3600),
            ..PolicyArgs::default()
        })
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "Password minimum life is greater than password maximum life"
    );
}

#[test]
fn create_policy_class_and_history_texts_match_mit() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let mut sess = AdminSession::local(&mut store, &acl, actor);
    let cls = sess
        .add_policy_ent(&PolicyArgs {
            name: "cls".into(),
            min_classes: Some(6),
            ..PolicyArgs::default()
        })
        .unwrap_err();
    assert_eq!(cls.to_string(), "Invalid number of character classes");
    let hist = sess
        .add_policy_ent(&PolicyArgs {
            name: "h0".into(),
            history: Some(0),
            ..PolicyArgs::default()
        })
        .unwrap_err();
    assert_eq!(hist.to_string(), "Invalid password history count");
}

#[test]
fn create_policy_zero_max_life_disables_min_over_max() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let mut sess = AdminSession::local(&mut store, &acl, actor);
    sess.add_policy_ent(&PolicyArgs {
        name: "zeromax".into(),
        pw_min_life: Some(7200),
        pw_max_life: Some(0),
        ..PolicyArgs::default()
    })
    .expect("max life 0 disables the min>max check");
}

#[test]
fn modify_missing_policy_is_policy_does_not_exist() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let mut sess = AdminSession::local(&mut store, &acl, actor);
    let err = sess
        .modify_policy_ent(&PolicyArgs {
            name: "nope".into(),
            min_length: Some(8),
            ..PolicyArgs::default()
        })
        .unwrap_err();
    assert_eq!(err.to_string(), "Policy does not exist");
}

#[test]
fn kadmin_local_alias_creates_a_stub_for_the_target() {
    use krb5_kdc::TEST_REALM;
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
