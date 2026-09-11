//! A′-2 R23: PAC UnsupportedChecksum wires 60 on non-retry exits.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, encrypt};
use krb5_kdc::{
    PrincipalStore, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    decrypt_ticket_part, documented_host, pa_enc_timestamp, pac_from_ticket_part, wrap_win2k_pac,
};
use krb5_protocol::{tgs_req, tgs_req_ex};
use krb5_types::pac::{PAC_SERVER_CHECKSUM, Pac};
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit, ku};

fn pref_etypes() -> Vec<i32> {
    EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn issue_tgt(store: &PrincipalStore, name: &str, password: &[u8], nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let key = store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let _ = password;
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn issue_host_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let host = documented_host();
    let key = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        host,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn code(e: krb5_kdc::Error) -> (i32, Option<String>) {
    match e {
        krb5_kdc::Error::Protocol { code, text, .. } => (code, text),
        other => panic!("{other:?}"),
    }
}

fn rewrite_server_cksumtype(part: &mut krb5_types::EncTicketPart, ctype: i32) {
    let raw = pac_from_ticket_part(part).unwrap();
    let mut parsed = Pac::parse(&raw).unwrap();
    let buf = parsed
        .buffers
        .iter_mut()
        .find(|b| b.kind == PAC_SERVER_CHECKSUM)
        .unwrap();
    buf.data[..4].copy_from_slice(&ctype.to_le_bytes());
    part.authorization_data = Some(wrap_win2k_pac(&parsed.to_bytes()).unwrap());
}

fn reseal(store: &PrincipalStore, tkt: &mut krb5_types::Ticket, part: &krb5_types::EncTicketPart) {
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let der = encode(part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    tkt.enc_part.cipher = encrypt(&krbtgt.key, usage, &der).unwrap().into();
}

#[test]
fn a2_r23_header_pac_wrong_cksumtype_is_generic() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 23000);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    rewrite_server_cksumtype(&mut part, 15);
    let tkt = {
        let mut t = as_out.rep.0.ticket.clone();
        reseal(&store, &mut t, &part);
        t
    };
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        23001,
    )
    .unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &tgs).unwrap_err());
    assert_eq!(c, err::GENERIC);
    assert_eq!(text.as_deref(), Some("HEADER_PAC"));
}

#[test]
fn a2_r23_u2u_stkt_pac_wrong_cksumtype_is_generic() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = issue_host_tgt(&store, 23010);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &host.rep.0.ticket).unwrap();
    rewrite_server_cksumtype(&mut part, 15);
    let mut extra = host.rep.0.ticket.clone();
    reseal(&store, &mut extra, &part);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 23020);
    let req = tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        23021,
        KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true),
        Some(vec![extra]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::GENERIC);
    assert_eq!(text.as_deref(), Some("2ND_TKT_PAC"));
}
