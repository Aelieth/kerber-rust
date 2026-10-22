//! Realm-qualified kadm5 acceptor checks.
// MIT: `CHANGEPW_SERVICE` (server_stubs.c:28-32)
//! the acceptor name is compared with the changepw service name, and with the old changepw name when one is set.

use krb5_admin::{
    changepw_acceptor, check_auth_gssapi_names, check_iprop_rpcsec_auth, check_rpcsec_auth,
};
use krb5_gss::GssContext;
use krb5_kdc::testrealm::TEST_REALM;

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

fn acceptor(parts: &[&str]) -> GssContext {
    let name = PrincipalName::new(PrincipalName::NT_SRV_HST, parts);
    GssContext::for_kadm5_acceptor(name, TEST_REALM).unwrap()
}

/// deviation on purpose (`docs/mit-deviations.md`).
// MIT: `check_iprop_rpcsec_auth` (ipropd_svc.c:513-514)
/// `strncmp("kiprop", c1->data, c1->length)` takes any prefix of `kiprop`.
#[test]
fn the_iprop_program_takes_kiprop_alone_not_its_prefixes() {
    let host = "testhost.kerber.test";
    assert!(check_iprop_rpcsec_auth(
        &acceptor(&["kiprop", host]),
        TEST_REALM
    ));
    for first in [
        "", "k", "ki", "kip", "kipr", "kipro", "kiprop2", "kipropx", "K", "Kiprop", "kadmin",
        "host",
    ] {
        assert!(
            !check_iprop_rpcsec_auth(&acceptor(&[first, host]), TEST_REALM),
            "{first:?}"
        );
    }
    assert!(!check_iprop_rpcsec_auth(&acceptor(&["kiprop"]), TEST_REALM));
    assert!(!check_iprop_rpcsec_auth(
        &acceptor(&["kiprop", host, "x"]),
        TEST_REALM
    ));
}

#[test]
fn the_kadm5_program_takes_kadmin_and_not_history_by_the_whole_name() {
    for parts in [
        &["kadmin", "admin"][..],
        &["kadmin", "changepw"],
        &["kadmin", "testhost.kerber.test"],
        &["kadmin", "histor"],
        &["kadmin", "history2"],
        &["kadmin", ""],
    ] {
        assert!(check_rpcsec_auth(&acceptor(parts), TEST_REALM), "{parts:?}");
    }
    for parts in [
        &["kadmin", "history"][..],
        &["kadmins", "admin"],
        &["kadmi", "admin"],
        &["Kadmin", "admin"],
        &["kiprop", "testhost.kerber.test"],
        &["host", "testhost.kerber.test"],
        &["kadmin"],
        &["kadmin", "admin", "x"],
    ] {
        assert!(
            !check_rpcsec_auth(&acceptor(parts), TEST_REALM),
            "{parts:?}"
        );
    }
}
