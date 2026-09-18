//! W1-B B2: acceptor `krb5_sname_match`. MIT `sname_match.c:30-57`.
//! Live oracle: GSS / `vfy_increds` cells (`MIT_sname_match`).
//! Unit-only: `sname_match` is new at the parent.

use krb5_protocol::sname_match;
use krb5_types::PrincipalName;

fn host(svc: &str, name: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_HST, [svc, name])
}

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"])
}

#[test]
fn b2_sname_match_none_accepts_any() {
    assert!(sname_match(
        None,
        None,
        &host("host", "svc.kerber.test"),
        b"KERBER.TEST",
        false,
    ));
}

#[test]
fn b2_sname_match_srv_hst_requires_service_and_host() {
    let want = host("host", "svc.kerber.test");
    let got = host("host", "svc.kerber.test");
    assert!(sname_match(
        Some(&want),
        Some("KERBER.TEST"),
        &got,
        b"KERBER.TEST",
        false,
    ));
    let other = host("host", "other.kerber.test");
    assert!(!sname_match(
        Some(&want),
        Some("KERBER.TEST"),
        &other,
        b"KERBER.TEST",
        false,
    ));
}

#[test]
fn b2_sname_match_ignore_acceptor_hostname_skips_host() {
    let want = host("host", "svc.kerber.test");
    let other = host("host", "other.kerber.test");
    assert!(sname_match(
        Some(&want),
        Some("KERBER.TEST"),
        &other,
        b"KERBER.TEST",
        true,
    ));
    let http = host("HTTP", "other.kerber.test");
    assert!(!sname_match(
        Some(&want),
        Some("KERBER.TEST"),
        &http,
        b"KERBER.TEST",
        true,
    ));
}

#[test]
fn b2_sname_match_empty_hostname_is_wildcard() {
    let want = host("host", "");
    let got = host("host", "svc.kerber.test");
    assert!(sname_match(
        Some(&want),
        Some("KERBER.TEST"),
        &got,
        b"KERBER.TEST",
        false,
    ));
}

#[test]
fn b2_sname_match_empty_realm_is_unspecified() {
    let want = host("host", "svc.kerber.test");
    let got = host("host", "svc.kerber.test");
    assert!(sname_match(
        Some(&want),
        Some(""),
        &got,
        b"OTHER.TEST",
        false
    ));
    assert!(sname_match(Some(&want), None, &got, b"OTHER.TEST", false));
}

#[test]
fn b2_sname_match_realm_mismatch_is_false() {
    let want = host("host", "svc.kerber.test");
    let got = host("host", "svc.kerber.test");
    assert!(!sname_match(
        Some(&want),
        Some("KERBER.TEST"),
        &got,
        b"OTHER.TEST",
        false,
    ));
}

#[test]
fn b2_sname_match_non_hst_is_principal_compare() {
    let want = user();
    assert!(sname_match(
        Some(&want),
        Some("KERBER.TEST"),
        &user(),
        b"KERBER.TEST",
        false,
    ));
    let other = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["other"]);
    assert!(!sname_match(
        Some(&want),
        Some("KERBER.TEST"),
        &other,
        b"KERBER.TEST",
        false,
    ));
    let nt = PrincipalName::new(PrincipalName::NT_UNKNOWN, ["user"]);
    assert!(sname_match(
        Some(&want),
        Some("KERBER.TEST"),
        &nt,
        b"KERBER.TEST",
        false,
    ));
}

#[test]
fn b2_sname_match_hst_rejects_non_two_component_ticket() {
    let want = host("host", "svc.kerber.test");
    assert!(!sname_match(
        Some(&want),
        Some("KERBER.TEST"),
        &user(),
        b"KERBER.TEST",
        false,
    ));
}
