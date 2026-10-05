//! The names a PAC carries, as MIT writes and reads them: S4U2Proxy's proxy target with no realm
//! and unquoted, one DELEGATION_INFO only, and a cross-realm S4U2Proxy's PAC client parsed as
//! MIT's `get_pac_princ_with_realm` parses it.

use super::*;
use krb5_types::pac::{S4uDelegationInfo, delegation_info_buffer, parse_delegation_info};

/// A component holding `@` and `\`: MIT's `KRB5_PRINCIPAL_UNPARSE_DISPLAY |
/// KRB5_PRINCIPAL_UNPARSE_NO_REALM` form keeps both as they are, where `krb5_unparse_name` quotes
/// them.
fn odd_target() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["svc", r"a@b\c"])
}

fn pac_of(buffers: Vec<PacBuffer>) -> Vec<u8> {
    Pac::built(0, buffers).to_bytes()
}

fn client_info(authtime: u32, name: &str) -> PacBuffer {
    PacBuffer::new(PAC_CLIENT_INFO, client_info_buffer(authtime, name))
}

fn delegation(target: &str, transited: &[&str]) -> PacBuffer {
    PacBuffer::new(
        PAC_DELEGATION_INFO,
        delegation_info_buffer(&S4uDelegationInfo {
            proxy_target: target.to_owned(),
            transited_services: transited.iter().map(|s| (*s).to_owned()).collect(),
        }),
    )
}

fn expect_handle_authdata(res: Result<Vec<u8>, Error>) {
    match res {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::GENERIC);
            assert_eq!(text.as_deref(), Some(status::HANDLE_AUTHDATA));
        }
        other => panic!("expected HANDLE_AUTHDATA 60, got {other:?}"),
    }
}

#[test]
fn update_delegation_info_writes_the_proxy_target_unquoted() {
    let subject = pac_of(vec![client_info(1, "user")]);
    let out = update_delegation_info(&subject, &odd_target(), "svc/impersonator@R").unwrap();
    let pac = Pac::parse(&out).unwrap();
    let di = parse_delegation_info(pac.buffer(PAC_DELEGATION_INFO).unwrap()).unwrap();
    assert_eq!(di.proxy_target, r"svc/a@b\c");
    assert_eq!(di.transited_services, ["svc/impersonator@R"]);
}

#[test]
fn update_delegation_info_refuses_a_doubled_delegation_info() {
    let subject = pac_of(vec![
        client_info(1, "user"),
        delegation("x", &["y@R"]),
        delegation("x", &["y@R"]),
    ]);
    expect_handle_authdata(update_delegation_info(&subject, &odd_target(), "svc/i@R"));
}

#[test]
fn mit_pac_refuses_a_subject_with_a_doubled_delegation_info() {
    let subject = pac_of(vec![
        client_info(1, "user"),
        delegation("x", &["y@R"]),
        delegation("x", &["y@R"]),
    ]);
    let key = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[7; 32]).unwrap();
    let ticket = PacTicket {
        server: &key,
        kdc: &key,
        enc_tkt_der: &[],
        is_service_tkt: false,
    };
    let req = HandlePac {
        subject: Some(&subject),
        ..HandlePac::default()
    };
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    expect_handle_authdata(mit_ticket_pac(&req, &user, 1, &ticket));
}

#[test]
fn verify_deleg_pac_compares_the_proxy_target_unquoted() {
    let impersonator = PrincipalName::new(PrincipalName::NT_SRV_HST, ["svc", "impersonator"]);
    let authtime = krb5_types::KerberosTime::from_unix_seconds(1_700_000_000);
    let part = EncTicketPart {
        flags: krb5_types::TicketFlags::initial_preauth(),
        key: EncryptionKey {
            keytype: 18,
            keyvalue: vec![0u8; 32].into(),
        },
        crealm: krb5_types::try_ascii("R").unwrap(),
        cname: impersonator.clone(),
        transited: krb5_types::TransitedEncoding::empty(),
        authtime: authtime.clone(),
        starttime: None,
        endtime: authtime.clone(),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let with_target = |target: &str| {
        Pac::parse(&pac_of(vec![
            client_info(authtime.unix_seconds(), "user@R"),
            delegation(target, &["svc/impersonator@R"]),
        ]))
        .unwrap()
    };
    assert!(verify_deleg_pac(
        &with_target(r"svc/a@b\c"),
        &part,
        Some(&odd_target())
    ));
    assert!(!verify_deleg_pac(
        &with_target(r"svc/a\@b\\c"),
        &part,
        Some(&odd_target())
    ));
}

fn rbcd_client(name: &str) -> Result<(PrincipalName, String), Error> {
    rbcd_pac_client(&pac_of(vec![client_info(1, name)]))
}

#[test]
fn rbcd_pac_client_splits_components_as_mit_parses_them() {
    let (princ, realm) = rbcd_client("a/b@R").unwrap();
    assert_eq!(princ.name_type, PrincipalName::NT_MS_PRINCIPAL);
    assert_eq!(princ.components_joined(), "a/b");
    assert_eq!(princ.name_string.len(), 2);
    assert_eq!(realm, "R");
    let (unescaped, _) = rbcd_client(r"a\/b@R").unwrap();
    assert_eq!(unescaped.name_string.len(), 1);
    assert_eq!(unescaped.components_joined(), "a/b");
}

#[test]
fn rbcd_pac_client_parses_an_enterprise_name() {
    let (princ, realm) = rbcd_client("a@b@R").unwrap();
    assert_eq!(princ.name_type, PrincipalName::NT_MS_PRINCIPAL);
    assert_eq!(princ.name_string.len(), 1);
    assert_eq!(princ.components_joined(), "a@b");
    assert_eq!(realm, "R");
}

#[test]
fn rbcd_pac_client_refuses_a_name_that_is_not_ascii() {
    match rbcd_client("caf\u{e9}@R") {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::BADOPTION);
            assert_eq!(text.as_deref(), Some(status::RBCD_PAC_PRINC));
        }
        other => panic!("expected RBCD_PAC_PRINC, got {other:?}"),
    }
}
