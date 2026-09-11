//! A′-2 item 9 U2U / second-ticket statuses.

use krb5_asn1::encode;
use krb5_crypto::{KeyUsage, encrypt};
use krb5_kdc::{
    KDB_DISALLOW_DUP_SKEY, PrincipalStore, TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER,
    TEST_USER_PASSWORD, as_req, bootstrap_documented, decrypt_ticket_part, documented_host,
    pa_enc_timestamp, pac_from_ticket_part, wrap_win2k_pac,
};
use krb5_protocol::{tgs_req, tgs_req_ex};
use krb5_types::pac::{PAC_SERVER_CHECKSUM, Pac};
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit, ku};

fn pref_etypes() -> Vec<i32> {
    krb5_crypto::EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn issue_tgt(
    store: &PrincipalStore,
    name: &str,
    password: &[u8],
    nonce: u32,
) -> krb5_kdc::IssuedAs {
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

fn u2u_opts() -> KdcOptions {
    KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true)
}

fn u2u_req(
    store: &PrincipalStore,
    dest: PrincipalName,
    extra: Option<Vec<krb5_types::Ticket>>,
    nonce: u32,
) -> krb5_types::TgsReq {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(store, TEST_USER, TEST_USER_PASSWORD, nonce);
    tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        dest,
        TEST_REALM,
        nonce + 1,
        u2u_opts(),
        extra,
        Vec::new(),
        pref_etypes(),
    )
    .unwrap()
}

fn code(e: krb5_kdc::Error) -> (i32, Option<String>) {
    match e {
        krb5_kdc::Error::Protocol { code, text, .. } => (code, text),
        other => panic!("{other:?}"),
    }
}

fn reseal(store: &PrincipalStore, tkt: &mut krb5_types::Ticket, part: &krb5_types::EncTicketPart) {
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let der = encode(part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    tkt.enc_part.cipher = encrypt(&krbtgt.key, usage, &der).unwrap().into();
}

#[test]
fn u2u_no_2nd_tkt_is_badoption() {
    let (store, _) = bootstrap_documented().unwrap();
    let req = u2u_req(&store, documented_host(), None, 9100);
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("NO_2ND_TKT"));
}

#[test]
fn u2u_service_ticket_is_not_tgs() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 9110);
    let svc = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        9111,
    )
    .unwrap();
    let extra = krb5_kdc::issue_tgs(&store, &svc).unwrap().rep.0.ticket;
    let req = u2u_req(&store, documented_host(), Some(vec![extra]), 9112);
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("2ND_TKT_NOT_TGS"));
}

#[test]
fn u2u_admin_tgt_for_host_is_mismatch() {
    let (store, _) = bootstrap_documented().unwrap();
    let admin = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 9120);
    let req = u2u_req(
        &store,
        documented_host(),
        Some(vec![admin.rep.0.ticket]),
        9121,
    );
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::SERVER_NOMATCH);
    assert_eq!(text.as_deref(), Some("2ND_TKT_MISMATCH"));
}

#[test]
fn u2u_bad_session_etype_is_etype_nosupp() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = issue_host_tgt(&store, 9130);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &host.rep.0.ticket).unwrap();
    part.key.keytype = 99;
    let mut extra = host.rep.0.ticket.clone();
    reseal(&store, &mut extra, &part);
    let req = u2u_req(&store, documented_host(), Some(vec![extra]), 9131);
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::ETYPE_NOSUPP);
    assert_eq!(text.as_deref(), Some("BAD_ETYPE_IN_2ND_TKT"));
}

#[test]
fn u2u_bad_pac_is_modified() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = issue_host_tgt(&store, 9140);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &host.rep.0.ticket).unwrap();
    let raw = pac_from_ticket_part(&part).unwrap();
    let mut parsed = Pac::parse(&raw).unwrap();
    if let Some(buf) = parsed
        .buffers
        .iter_mut()
        .find(|b| b.kind == PAC_SERVER_CHECKSUM)
        && buf.data.len() > 4
    {
        buf.data[4] ^= 0xff;
    }
    part.authorization_data = Some(wrap_win2k_pac(&parsed.to_bytes()).unwrap());
    let mut extra = host.rep.0.ticket.clone();
    reseal(&store, &mut extra, &part);
    let req = u2u_req(&store, documented_host(), Some(vec![extra]), 9141);
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::MODIFIED);
    assert_eq!(text.as_deref(), Some("2ND_TKT_PAC"));
}

#[test]
fn u2u_dup_skey_disallowed_is_policy() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let attrs = store.get_name(&host).unwrap().attributes | KDB_DISALLOW_DUP_SKEY;
    store
        .apply_admin_fields(&host, Some(attrs), None, None, None, None, false, None)
        .unwrap();
    let extra = issue_host_tgt(&store, 9150).rep.0.ticket;
    let req = u2u_req(&store, host, Some(vec![extra]), 9151);
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("DUP_SKEY DISALLOWED"));
}

#[test]
fn u2u_host_tgt_issues_kvno_zero() {
    let (store, _) = bootstrap_documented().unwrap();
    let extra = issue_host_tgt(&store, 9160);
    let req = u2u_req(
        &store,
        documented_host(),
        Some(vec![extra.rep.0.ticket]),
        9161,
    );
    let out = krb5_kdc::issue_tgs(&store, &req).unwrap();
    assert!(out.rep.0.ticket.enc_part.kvno.is_none());
    let part = decrypt_ticket_part(&extra.session_key, &out.rep.0.ticket).unwrap();
    assert_eq!(part.cname.components_joined(), TEST_USER);
}
