//! A′-2 item 6: TGS gather order, `is_crossrealm`, constraints skeleton, header PAC.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt, string_to_key};
use krb5_kdc::{
    Error, KDB_DISALLOW_SVR, PacTicket, PrincipalStore, S2K_ITERS, TEST_REALM, TEST_USER,
    TEST_USER_PASSWORD, as_req, bootstrap_documented, decrypt_ticket_part, documented_host,
    pa_enc_timestamp, pac_from_ticket_part, sign_pac, tgs_req, ticket_checksum_der, wrap_win2k_pac,
};
use krb5_protocol::tgs_req_ex;
use krb5_types::pac::{PAC_SERVER_CHECKSUM, Pac};
use krb5_types::{EncTicketPart, KdcOptions, PrincipalName, err, flag_bit, ku};

fn password_key(name: &str, password: &[u8]) -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        password,
        &cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap()
}

fn issue_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = password_key(TEST_USER, TEST_USER_PASSWORD);
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn renewable_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = password_key(TEST_USER, TEST_USER_PASSWORD);
    let mut req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn proto(err: &Error) -> (i32, Option<&str>) {
    match err {
        Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

fn rewrap(
    ticket: &krb5_types::Ticket,
    part: &EncTicketPart,
    key: &ProtocolKey,
) -> krb5_types::Ticket {
    let der = encode(part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut out = ticket.clone();
    out.enc_part.cipher = encrypt(key, usage, &der).unwrap().into();
    out
}

fn host_tgs(issued: &krb5_kdc::IssuedAs, nonce: u32) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        nonce,
    )
    .unwrap()
}

#[test]
fn tgs_renew_service_ticket_issues() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = renewable_tgt(&store, 6010);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let first = tgs_req_ex(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        6011,
        KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let svc = krb5_kdc::issue_tgs(&store, &first).unwrap();
    let renew = tgs_req_ex(
        svc.rep.0.ticket.clone(),
        &svc.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        6012,
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    krb5_kdc::issue_tgs(&store, &renew).expect("RENEW of a service ticket");
}

#[test]
fn tgs_proxy_krbtgt_is_cant_proxy_tgt() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = password_key(TEST_USER, TEST_USER_PASSWORD);
    let mut req = as_req(
        cname.clone(),
        TEST_REALM,
        6020,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::PROXIABLE, true);
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let tgs = tgs_req_ex(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        6021,
        KdcOptions::forwardable().with_bit(flag_bit::PROXY, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::BADOPTION, Some("CAN'T PROXY TGT")));
}

#[test]
fn tgs_corrupt_pac_before_unknown_sname_is_header_pac() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, 6030);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    let pac = pac_from_ticket_part(&part).unwrap();
    let mut parsed = Pac::parse(&pac).unwrap();
    let buf = parsed
        .buffers
        .iter_mut()
        .find(|b| b.kind == PAC_SERVER_CHECKSUM)
        .unwrap();
    buf.data[4] ^= 0xff;
    part.authorization_data = Some(wrap_win2k_pac(&parsed.to_bytes()).unwrap());
    let tkt = rewrap(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["nosuch", "x"]),
        TEST_REALM,
        6031,
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::MODIFIED, Some("HEADER_PAC")));
}

#[test]
fn tgs_pac_client_mismatch_is_header_pac() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, 6040);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    let ident = store.pac_identity(&part.cname, TEST_REALM);
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(&part).unwrap();
    let wrong = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["other"]);
    let pac = sign_pac(
        &wrong,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: &krbtgt.key,
            kdc: &krbtgt.key,
            enc_tkt_der: &der,
            is_service_tkt: false,
        },
        &ident,
        None,
    )
    .unwrap();
    part.authorization_data = Some(wrap_win2k_pac(&pac).unwrap());
    let tkt = rewrap(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        6041,
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::BADOPTION, Some("HEADER_PAC")));
}

#[test]
fn tgs_missing_pa_tgs_req_is_padata_type_nosupp() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, 6060);
    let mut tgs = host_tgs(&as_out, 6061);
    tgs.0.padata = None;
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::PADATA_TYPE_NOSUPP, Some("PROCESS_TGS")));
}

#[test]
fn tgs_disallow_svr_service_header_is_process_tgs() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let as_out = renewable_tgt(&store, 6070);
    let svc = krb5_kdc::issue_tgs(&store, &host_tgs(&as_out, 6071)).unwrap();
    let host = documented_host();
    let attrs = store.get_name(&host).unwrap().attributes | KDB_DISALLOW_SVR;
    store
        .apply_admin_fields(&host, Some(attrs), None, None, None, None, false)
        .unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let renew = tgs_req_ex(
        svc.rep.0.ticket.clone(),
        &svc.session_key,
        TEST_REALM,
        &cname,
        host,
        TEST_REALM,
        6072,
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &renew).unwrap_err();
    assert_eq!(proto(&err), (err::S_PRINCIPAL_UNKNOWN, Some("PROCESS_TGS")));
}

#[test]
fn tgs_forwarded_without_forwardable_is_tgt_not_forwardable() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, 6110);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    part.flags = part.flags.with_bit(flag_bit::FORWARDABLE, false);
    let tkt = rewrap(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req_ex(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        6111,
        KdcOptions::forwardable().with_bit(flag_bit::FORWARDED, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::BADOPTION, Some("TGT NOT FORWARDABLE")));
}

#[test]
fn tgs_proxy_without_proxiable_is_tgt_not_proxiable() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, 6120);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    part.flags = part.flags.with_bit(flag_bit::PROXIABLE, false);
    let tkt = rewrap(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req_ex(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        6121,
        KdcOptions::forwardable().with_bit(flag_bit::PROXY, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::BADOPTION, Some("TGT NOT PROXIABLE")));
}
