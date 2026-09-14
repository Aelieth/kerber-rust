//! Z6.4: `kdb_put_entry` stamps `KRB5_TL_MOD_PRINC` with
//! `handle->current_caller` (`server_kdb.c:376-377`), not a hard-coded
//! `kadmin/admin@REALM`. Compiles at the parent: `create_password` already
//! takes `actor`, but `stamp_admin_tl` ignored it.

use krb5_kdc::{Acl, TL_MOD_PRINC, bootstrap_documented, documented_admin_id};
use krb5_types::PrincipalName;

fn tl_mod_name(p: &krb5_kdc::Principal) -> Option<String> {
    let t = p.tl_data.iter().find(|t| t.ty == TL_MOD_PRINC)?;
    let bytes = t.contents.get(4..)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec()).ok()
}

#[test]
fn z6_create_stamps_the_authenticated_caller() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let actor = "joe/admin@KERBER.TEST";
    let acl = Acl::allow_admin(actor).unwrap();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["z64u"]);
    store
        .create_password(&acl, actor, &name, b"z64-secret")
        .unwrap();
    let p = store.get_name(&name).expect("created");
    assert_eq!(
        tl_mod_name(p).as_deref(),
        Some(actor),
        "TL_MOD_PRINC must be current_caller, not kadmin/admin (got {:?}); documented admin is {}",
        tl_mod_name(p),
        documented_admin_id()
    );
    assert_ne!(
        tl_mod_name(p).as_deref(),
        Some("kadmin/admin@KERBER.TEST"),
        "must not hard-code the kadmind acceptor"
    );
}
