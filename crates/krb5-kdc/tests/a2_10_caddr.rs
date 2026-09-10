//! A′-2 item 10 ticket addresses and TGS sender bind.

use krb5_asn1::{decode, encode};
use krb5_crypto::{KeyUsage, decrypt, encrypt};
use krb5_kdc::{
    PrincipalStore, TEST_REALM, TEST_USER, as_req, bootstrap_documented, decrypt_ticket_part,
    documented_host, handle_request_from, pa_enc_timestamp,
};
use krb5_protocol::{tgs_req, tgs_req_ex, tgs_req_ex_addr};
use krb5_types::{
    HostAddress, KdcOptions, KrbError, PaData, PaPacRequest, PrincipalName, err, flag_bit, ku, pa,
};

fn inet(a: u8, b: u8, c: u8, d: u8) -> HostAddress {
    HostAddress {
        addr_type: HostAddress::ADDRTYPE_INET,
        address: vec![a, b, c, d].into(),
    }
}

fn pref_etypes() -> Vec<i32> {
    krb5_crypto::EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn user_key(store: &PrincipalStore) -> krb5_crypto::ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone()
}

fn as_with_addrs(
    store: &PrincipalStore,
    addrs: Option<Vec<HostAddress>>,
    nonce: u32,
    pac: bool,
    renewable: bool,
) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut padata = vec![pa_enc_timestamp(&user_key(store)).unwrap()];
    if !pac {
        padata.push(PaData {
            padata_type: pa::PAC_REQUEST,
            padata_value: encode(&PaPacRequest { include_pac: false }).unwrap().into(),
        });
    }
    let mut req = as_req(cname, TEST_REALM, nonce, Some(padata)).unwrap();
    req.0.req_body.addresses = addrs;
    if renewable {
        req.0.req_body.kdc_options = req
            .0
            .req_body
            .kdc_options
            .with_bit(flag_bit::RENEWABLE, true);
    }
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn rewrap_caddr(
    store: &PrincipalStore,
    ticket: &krb5_types::Ticket,
    caddr: Option<Vec<HostAddress>>,
) -> krb5_types::Ticket {
    let key = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&key.key, ticket).unwrap();
    part.caddr = caddr;
    let der = encode(&part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut out = ticket.clone();
    out.enc_part.cipher = encrypt(&key.key, usage, &der).unwrap().into();
    out
}

fn tkt_part(store: &PrincipalStore, ticket: &krb5_types::Ticket) -> krb5_types::EncTicketPart {
    let key = store.krbtgt().unwrap().best_key().unwrap();
    decrypt_ticket_part(&key.key, ticket).unwrap()
}

fn host_part(store: &PrincipalStore, ticket: &krb5_types::Ticket) -> krb5_types::EncTicketPart {
    let key = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    decrypt_ticket_part(&key.key, ticket).unwrap()
}

fn enc_as(issued: &krb5_kdc::IssuedAs) -> krb5_types::EncKdcRepPart {
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(
        &issued.as_rep_key,
        usage,
        issued.rep.0.enc_part.cipher.as_ref(),
    )
    .unwrap();
    krb5_asn1::decode_enc_kdc_rep_part(&plain).unwrap()
}

fn enc_tgs(
    issued: &krb5_kdc::IssuedTgs,
    reply_key: &krb5_crypto::ProtocolKey,
) -> krb5_types::EncKdcRepPart {
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART).unwrap();
    let plain = decrypt(reply_key, usage, issued.rep.0.enc_part.cipher.as_ref()).unwrap();
    krb5_asn1::decode_enc_kdc_rep_part(&plain).unwrap()
}

fn err_of(bytes: &[u8]) -> (i32, String, Option<String>) {
    let e: KrbError = decode(bytes).unwrap();
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok())
        .unwrap_or("")
        .to_owned();
    let cname = e.cname.as_ref().map(PrincipalName::components_joined);
    (e.error_code, text, cname)
}

#[test]
fn as_copies_request_addresses() {
    let (store, _) = bootstrap_documented().unwrap();
    let addrs = vec![inet(192, 0, 2, 10)];
    let issued = as_with_addrs(&store, Some(addrs.clone()), 10100, true, false);
    let part = tkt_part(&store, &issued.rep.0.ticket);
    assert_eq!(part.caddr.as_ref(), Some(&addrs));
    assert_eq!(enc_as(&issued).caddr.as_ref(), Some(&addrs));
}

#[test]
fn tgs_copies_header_caddr() {
    let (store, _) = bootstrap_documented().unwrap();
    let addrs = vec![inet(192, 0, 2, 11)];
    let tgt = as_with_addrs(&store, Some(addrs.clone()), 10110, true, false);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        10111,
    )
    .unwrap();
    let issued = krb5_kdc::issue_tgs(&store, &req).unwrap();
    assert_eq!(
        host_part(&store, &issued.rep.0.ticket).caddr.as_ref(),
        Some(&addrs)
    );
    assert_eq!(enc_tgs(&issued, &tgt.session_key).caddr, None);
}

#[test]
fn tgs_forwarded_copies_request_addresses() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = as_with_addrs(&store, None, 10120, false, false);
    let want = vec![inet(192, 0, 2, 12)];
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req_ex_addr(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        10121,
        KdcOptions::none().with_bit(flag_bit::FORWARDED, true),
        None,
        Vec::new(),
        pref_etypes(),
        Some(want.clone()),
    )
    .unwrap();
    let issued = krb5_kdc::issue_tgs(&store, &req).unwrap();
    assert_eq!(
        tkt_part(&store, &issued.rep.0.ticket).caddr.as_ref(),
        Some(&want)
    );
    assert_eq!(
        enc_tgs(&issued, &tgt.session_key).caddr.as_ref(),
        Some(&want)
    );
}

#[test]
fn tgs_renew_keeps_header_caddr() {
    let (store, _) = bootstrap_documented().unwrap();
    let addrs = vec![inet(192, 0, 2, 13)];
    let tgt = as_with_addrs(&store, Some(addrs.clone()), 10130, true, true);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        10131,
        KdcOptions::none().with_bit(flag_bit::RENEW, true),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let issued = krb5_kdc::issue_tgs(&store, &req).unwrap();
    assert_eq!(
        tkt_part(&store, &issued.rep.0.ticket).caddr.as_ref(),
        Some(&addrs)
    );
    assert_eq!(enc_tgs(&issued, &tgt.session_key).caddr, None);
}

#[test]
fn tgs_sender_mismatch_is_badaddr() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = as_with_addrs(&store, None, 10140, false, false);
    let ticket = rewrap_caddr(&store, &tgt.rep.0.ticket, Some(vec![inet(10, 0, 0, 1)]));
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        10141,
    )
    .unwrap();
    let bytes =
        handle_request_from(&store, &encode(&req).unwrap(), Some(&inet(192, 0, 2, 1))).unwrap();
    let (code, text, cname) = err_of(&bytes);
    assert_eq!(code, err::BADADDR);
    assert_eq!(text, "PROCESS_TGS");
    assert_eq!(cname.as_deref(), Some(TEST_USER));
}

#[test]
fn tgs_netbios_only_caddr_matches() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = as_with_addrs(&store, None, 10150, false, false);
    let nb = HostAddress {
        addr_type: HostAddress::ADDRTYPE_NETBIOS,
        address: b"HOST            ".to_vec().into(),
    };
    let ticket = rewrap_caddr(&store, &tgt.rep.0.ticket, Some(vec![nb]));
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        10151,
    )
    .unwrap();
    let bytes =
        handle_request_from(&store, &encode(&req).unwrap(), Some(&inet(192, 0, 2, 1))).unwrap();
    assert_eq!(bytes.first().copied(), Some(0x6d));
}

#[test]
fn tgs_null_caddr_matches() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = as_with_addrs(&store, None, 10160, true, false);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        10161,
    )
    .unwrap();
    let bytes =
        handle_request_from(&store, &encode(&req).unwrap(), Some(&inet(192, 0, 2, 1))).unwrap();
    assert_eq!(bytes.first().copied(), Some(0x6d));
}

#[test]
fn tgs_sender_match_issues() {
    let (store, _) = bootstrap_documented().unwrap();
    let addrs = vec![inet(192, 0, 2, 14)];
    let tgt = as_with_addrs(&store, Some(addrs.clone()), 10170, true, false);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        10171,
    )
    .unwrap();
    let bytes = handle_request_from(&store, &encode(&req).unwrap(), Some(&addrs[0])).unwrap();
    assert_eq!(bytes.first().copied(), Some(0x6d));
}
