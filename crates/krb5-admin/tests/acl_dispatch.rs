//! Admin whole-flow tests moved from `src/lib.rs`.

#[path = "common/mod.rs"]
mod common;

use krb5_admin::*;
use krb5_kdc::AdminOp;
use krb5_kdc::testrealm::{bootstrap_documented, documented_admin_id, documented_host};

use krb5_protocol::ReplayCache;
use krb5_types::PrincipalName;

#[test]
fn kadmind_enforces_acl() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
    let extra = PrincipalName::new(
        PrincipalName::NT_SRV_HST,
        ["host", "admin-extra.kerber.test"],
    );
    admin.create_password(&extra, b"secret-pass").unwrap();
    let kt = admin.ktadd(&extra).unwrap();
    assert_eq!(&kt.to_bytes()[..2], &[0x05, 0x02]);
}

#[test]
fn kadmind_denies_user() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let mut user = AdminSession::local(&mut store, &acl, "user@KERBER.TEST");
    let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "nope.kerber.test"]);
    assert_eq!(
        user.create_password(&extra, b"x").unwrap_err(),
        Error::AclDenied
    );
    assert_eq!(
        user.ktadd(&documented_host()).unwrap_err(),
        Error::AclDenied
    );
}

#[test]
fn kadmind_wire_create_is_visible_after_reload() {
    use krb5_asn1::encode;
    use krb5_kdc::testrealm::{TEST_REALM, documented_host};
    use krb5_kdc::{load_store, save_store, shared_dump as shared_store};

    use krb5_protocol::{build_ap_req, pa_enc_timestamp, tgs_req};

    let dir = std::env::temp_dir().join(format!(
        "kadmind-wire-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let store = load_store(&db, &stash).unwrap();
    assert!(store.persist_paths.is_some());

    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    let admin_key = store
        .get_name(&admin)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_req = krb5_protocol::as_req(
        admin.clone(),
        TEST_REALM,
        41,
        Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &admin,
        documented_host(),
        TEST_REALM,
        42,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let host_key = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &admin,
    )
    .unwrap();
    let ap_der = encode(&ap).unwrap();

    let shared = shared_store(store);
    let replay = ReplayCache::new();
    let payload = b"wireuser@KERBER.TEST\0wire-secret";
    let body = encode_kadmind_req(Op::Create, &ap_der, payload);
    let reply = dispatch_kadmind(&shared, &acl, &host_key, &replay, &body).expect("create");
    assert_eq!(&reply[..4], &[0, 0, 0, 0]);

    let loaded = load_store(&db, &stash).unwrap();
    let created = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["wireuser"]);
    assert!(
        loaded.get_name(&created).is_some(),
        "kadmind create must persist to stash/db"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_acl_file_missing_is_error() {
    let path = std::env::temp_dir().join(format!("krb5-acl-missing-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    assert!(load_acl_file("admin@KERBER.TEST", Some(&path)).is_err());
    let acl = load_acl_file("admin@KERBER.TEST", None).unwrap();
    assert!(
        acl.check("admin@KERBER.TEST", AdminOp::Create, None)
            .is_ok()
    );
}

#[test]
fn load_acl_file_parses_readable() {
    let path = std::env::temp_dir().join(format!("krb5-acl-ok-{}", std::process::id()));
    std::fs::write(&path, "admin@KERBER.TEST *\n").unwrap();
    let acl = load_acl_file("other@KERBER.TEST", Some(&path)).unwrap();
    assert!(
        acl.check("admin@KERBER.TEST", AdminOp::Create, None)
            .is_ok()
    );
    let _ = std::fs::remove_file(&path);
}
