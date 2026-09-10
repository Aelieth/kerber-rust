//! A′-2 item 7 S4U2Self units that fail at parent `2e5995a`.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, checksum, encrypt};
use krb5_kdc::{
    PacTicket, PrincipalStore, TEST_ADMIN, TEST_REALM, TEST_USER, as_req, bootstrap_documented,
    decrypt_ticket_part, documented_host, pa_enc_timestamp, sign_reply_pac, ticket_checksum_der,
    wrap_win2k_pac,
};
use krb5_protocol::{pa_for_user, pa_s4u_x509_user, tgs_req_ex};
use krb5_types::pac::{PAC_CLIENT_INFO, Pac, PacBuffer, PacIdentity, RpcSid, client_info_buffer};
use krb5_types::{EncTicketPart, KdcOptions, PaData, PrincipalName, err, ku, pa};

fn pref_etypes() -> Vec<i32> {
    EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn host_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
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

fn s4u_tgs(tgt: &krb5_kdc::IssuedAs, padata: Vec<PaData>, nonce: u32) -> krb5_types::TgsReq {
    let host = documented_host();
    tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        nonce,
        KdcOptions::forwardable(),
        None,
        padata,
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

fn reseal_tgt(
    store: &PrincipalStore,
    tgt: &krb5_kdc::IssuedAs,
    part: &EncTicketPart,
) -> krb5_types::Ticket {
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let der = encode(part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut t = tgt.rep.0.ticket.clone();
    t.enc_part.cipher = encrypt(&krbtgt.key, usage, &der).unwrap().into();
    t
}

fn attach_client_info_pac(store: &PrincipalStore, part: &mut EncTicketPart, info_name: &str) {
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let stub = Pac::built(
        0,
        vec![PacBuffer::new(
            PAC_CLIENT_INFO,
            client_info_buffer(part.authtime.unix_seconds(), info_name),
        )],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(part).unwrap();
    let ident = PacIdentity {
        sam: part.cname.components_joined(),
        realm: String::new(),
        domain_sid: RpcSid::nt_domain(1, 2, 3),
        rid: 1,
    };
    let pac = sign_reply_pac(
        &part.cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: &krbtgt.key,
            kdc: &krbtgt.key,
            enc_tkt_der: &der,
            is_service_tkt: false,
        },
        &ident,
        None,
        Some(&stub),
    )
    .unwrap();
    part.authorization_data = Some(wrap_win2k_pac(&pac).unwrap());
}

#[test]
fn s4u2self_no_pac_is_tgt_revoked() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7100);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &tgt.rep.0.ticket).unwrap();
    part.authorization_data = None;
    let tkt = reseal_tgt(&store, &tgt, &part);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let host = documented_host();
    let req = tgs_req_ex(
        tkt,
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        7101,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::TGT_REVOKED);
    assert_eq!(text.as_deref(), Some("S4U2SELF_NO_PAC"));
}

#[test]
fn s4u2self_local_pac_mismatch_is_badoption() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7102);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &tgt.rep.0.ticket).unwrap();
    attach_client_info_pac(&store, &mut part, TEST_ADMIN);
    let tkt = reseal_tgt(&store, &tgt, &part);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let host = documented_host();
    let req = tgs_req_ex(
        tkt,
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        7103,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("S4U2SELF_LOCAL_PAC_CLIENT"));
}

#[test]
fn s4u2self_x509_nonce_mismatch_is_modified() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7110);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_s4u_x509_user(&tgt.session_key, admin, TEST_REALM, 0xdead).unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &s4u_tgs(&tgt, vec![pa], 7111)).unwrap_err());
    assert_eq!(c, err::MODIFIED);
    assert_eq!(text.as_deref(), Some("INVALID_S4U2SELF_CHECKSUM"));
}

#[test]
fn s4u2self_x509_bad_checksum_is_modified() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7112);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let mut pa = pa_s4u_x509_user(&tgt.session_key, admin, TEST_REALM, 7113).unwrap();
    let mut body: krb5_types::s4u::PaS4uX509User =
        krb5_asn1::decode(pa.padata_value.as_ref()).unwrap();
    let mut ck = body.cksum.checksum.to_vec();
    ck[0] ^= 0xff;
    body.cksum.checksum = ck.into();
    pa.padata_value = encode(&body).unwrap().into();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &s4u_tgs(&tgt, vec![pa], 7113)).unwrap_err());
    assert_eq!(c, err::MODIFIED);
    assert_eq!(text.as_deref(), Some("INVALID_S4U2SELF_CHECKSUM"));
}

#[test]
fn s4u2self_x509_empty_is_invalid_request() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7120);
    let empty = PrincipalName::new(PrincipalName::NT_UNKNOWN, std::iter::empty::<&str>());
    let pa = pa_s4u_x509_user(&tgt.session_key, empty, TEST_REALM, 7121).unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &s4u_tgs(&tgt, vec![pa], 7121)).unwrap_err());
    assert_eq!(c, err::C_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("INVALID_S4U2SELF_REQUEST"));
}

#[test]
fn s4u2self_x509_cert_only_local_is_looking_up() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7122);
    let user_id = krb5_types::s4u::S4uUserId {
        nonce: 7123,
        user: None,
        realm: krb5_types::try_ascii(TEST_REALM).unwrap(),
        subject_cert: Some(b"cert".to_vec().into()),
        options: Some(krb5_types::s4u::s4u_reply_key_usage_flags()),
    };
    let der = encode(&user_id).unwrap();
    let usage = KeyUsage::new(ku::PA_S4U_X509_USER_REQUEST).unwrap();
    let mic = checksum(&tgt.session_key, usage, &der).unwrap();
    let body = krb5_types::s4u::PaS4uX509User {
        user_id,
        cksum: krb5_types::Checksum {
            cksumtype: tgt.session_key.etype().checksum_type(),
            checksum: mic.into(),
        },
    };
    let pa = PaData {
        padata_type: pa::FOR_X509_USER,
        padata_value: encode(&body).unwrap().into(),
    };
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &s4u_tgs(&tgt, vec![pa], 7123)).unwrap_err());
    assert_eq!(c, err::GENERIC);
    assert_eq!(text.as_deref(), Some("LOOKING_UP_S4U2SELF_PRINCIPAL"));
}

#[test]
fn s4u2self_x509_issues_and_replies_130() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7130);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_s4u_x509_user(&tgt.session_key, admin, TEST_REALM, 7131).unwrap();
    let out = krb5_kdc::issue_tgs(&store, &s4u_tgs(&tgt, vec![pa], 7131)).unwrap();
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
    assert!(
        out.rep
            .0
            .padata
            .as_ref()
            .is_some_and(|v| v.iter().any(|p| p.padata_type == pa::FOR_X509_USER))
    );
}

#[test]
fn s4u2self_x509_wins_over_for_user() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7132);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let pa130 = pa_s4u_x509_user(&tgt.session_key, admin, TEST_REALM, 7133).unwrap();
    let pa129 = pa_for_user(&tgt.session_key, user, TEST_REALM).unwrap();
    let out = krb5_kdc::issue_tgs(&store, &s4u_tgs(&tgt, vec![pa129, pa130], 7133)).unwrap();
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
}

#[test]
fn s4u2self_for_user_only_omits_reply_130() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7134);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let out = krb5_kdc::issue_tgs(&store, &s4u_tgs(&tgt, vec![pa], 7135)).unwrap();
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
    assert!(
        out.rep
            .0
            .padata
            .as_ref()
            .is_none_or(|v| v.iter().all(|p| p.padata_type != pa::FOR_X509_USER))
    );
}

#[test]
fn s4u2self_pw_expired_user_still_issues() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store
        .apply_admin_fields(&admin, None, None, None, Some(1), None, false)
        .unwrap();
    let tgt = host_tgt(&store, 7140);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    krb5_kdc::issue_tgs(&store, &s4u_tgs(&tgt, vec![pa], 7141)).unwrap();
}

#[test]
fn s4u2self_keeps_forwardable_without_delegate_targets() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.clear_s4u_to(&documented_host());
    let tgt = host_tgt(&store, 7150);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let out = krb5_kdc::issue_tgs(&store, &s4u_tgs(&tgt, vec![pa], 7151)).unwrap();
    let host = documented_host();
    let hostk = store.get_name(&host).unwrap().best_key().unwrap();
    let part: EncTicketPart = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).unwrap();
    assert!(part.flags.forwardable());
}

#[test]
fn s4u2self_for_user_undecodable_is_generic() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7160);
    let pa = PaData {
        padata_type: pa::FOR_USER,
        padata_value: b"\x30\x03\x01\x01".to_vec().into(),
    };
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &s4u_tgs(&tgt, vec![pa], 7161)).unwrap_err());
    assert_eq!(c, err::GENERIC);
    assert_eq!(text.as_deref(), Some("DECODE_PA_FOR_USER"));
}
