//! Realm-qualified kadm5 acceptor checks (`server_stubs.c:28-32`).

use krb5_admin::{
    changepw_acceptor, check_auth_gssapi_names, check_iprop_rpcsec_auth, check_rpcsec_auth,
};
use krb5_gss::GssContext;
use krb5_kdc::TEST_REALM;
use krb5_types::PrincipalName;

#[test]
fn changepw_acceptor_requires_store_realm() {
    let cpw = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]);
    let ok = GssContext::for_kadm5_acceptor(cpw.clone(), TEST_REALM).unwrap();
    assert!(changepw_acceptor(&ok, TEST_REALM));
    let foreign = GssContext::for_kadm5_acceptor(cpw, "OTHER.REALM").unwrap();
    assert!(!changepw_acceptor(&foreign, TEST_REALM));
}

#[test]
fn kadm5_auth_gssapi_ok_requires_store_realm() {
    let admin = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "admin"]);
    let ok = GssContext::for_kadm5_acceptor(admin.clone(), TEST_REALM).unwrap();
    assert!(check_auth_gssapi_names(&ok, TEST_REALM));
    let foreign = GssContext::for_kadm5_acceptor(admin, "OTHER.REALM").unwrap();
    assert!(!check_auth_gssapi_names(&foreign, TEST_REALM));
}

#[test]
fn kiprop_acceptor_requires_store_realm() {
    let kip = PrincipalName::new(
        PrincipalName::NT_SRV_HST,
        ["kiprop", "testhost.kerber.test"],
    );
    let ok = GssContext::for_kadm5_acceptor(kip.clone(), TEST_REALM).unwrap();
    assert!(check_iprop_rpcsec_auth(&ok, TEST_REALM));
    assert!(!check_rpcsec_auth(&ok, TEST_REALM));
    let foreign = GssContext::for_kadm5_acceptor(kip, "OTHER.REALM").unwrap();
    assert!(!check_iprop_rpcsec_auth(&foreign, TEST_REALM));
}
