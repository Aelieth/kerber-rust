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
