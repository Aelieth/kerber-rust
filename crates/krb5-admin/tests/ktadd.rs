//! Admin whole-flow tests.
//! the entry's modifier is stamped as the handle's `current_caller`.

#[path = "common/mod.rs"]
mod common;

use krb5_admin::AdminSession;
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented};
use krb5_kdc::{Acl, tl_mod_princ_name};

use krb5_types::PrincipalName;

fn n(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

#[test]
fn ktadd_local_stamps_the_session_actor() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let actor = "root/admin@KERBER.TEST";
    let acl = Acl::allow_admin(actor).unwrap();
    let name = n("z72kt");
    {
        let mut sess = AdminSession::local(&mut store, &acl, actor);
        sess.create_randkey(&name).unwrap();
        sess.ktadd_local(&name, true, |_| Ok(())).unwrap();
    }
    let p = store.get_name(&name).expect("ktadd target");
    let got = tl_mod_princ_name(&p.tl_data);
    assert_eq!(
        got.as_deref(),
        Some(actor),
        "ktadd rotate must stamp the session actor, not default_mod_actor (got {got:?})"
    );
}

#[test]
fn admin_unlock_stamps_the_session_actor() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let creator = "joe/admin@KERBER.TEST";
    let actor = "root/admin@KERBER.TEST";
    let acl = Acl::parse(&format!("{creator} *\n{actor} *\n")).unwrap();
    let name = n("z72ul");
    {
        let mut sess = AdminSession::local(&mut store, &acl, creator);
        sess.create_password(&name, b"z72-unlock-secret").unwrap();
    }
    {
        let mut sess = AdminSession::local(&mut store, &acl, actor);
        sess.admin_unlock(&name).unwrap();
    }
    let p = store.get_name(&name).expect("unlocked");
    let got = tl_mod_princ_name(&p.tl_data);
    assert_eq!(
        got.as_deref(),
        Some(actor),
        "unlock must stamp the session actor (got {got:?}; realm {TEST_REALM})"
    );
}
