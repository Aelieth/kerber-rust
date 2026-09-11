//! Item 7 units that compile at parent `543f4da` and fail there.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, encrypt};
use krb5_kdc::{
    PacTicket, PrincipalStore, TEST_ADMIN, TEST_REALM, as_req, bootstrap_documented,
    decrypt_ticket_part, documented_host, pa_enc_timestamp, sign_reply_pac, ticket_checksum_der,
    wrap_win2k_pac,
};
use krb5_protocol::{pa_for_user, tgs_req_ex};
use krb5_types::pac::{PAC_CLIENT_INFO, Pac, PacBuffer, PacIdentity, RpcSid, client_info_buffer};
use krb5_types::{EncTicketPart, KdcOptions, PrincipalName, err, ku};

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

fn s4u_req(tgt: &krb5_kdc::IssuedAs, tkt: krb5_types::Ticket, nonce: u32) -> krb5_types::TgsReq {
    let host = documented_host();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    tgs_req_ex(
        tkt,
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        nonce,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .unwrap()
}

#[test]
fn s4u2self_no_pac_is_tgt_revoked() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7200);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &tgt.rep.0.ticket).unwrap();
    part.authorization_data = None;
    let tkt = reseal_tgt(&store, &tgt, &part);
    let err = krb5_kdc::issue_tgs(&store, &s4u_req(&tgt, tkt, 7201)).unwrap_err();
    match err {
        krb5_kdc::Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::TGT_REVOKED);
            assert_eq!(text.as_deref(), Some("S4U2SELF_NO_PAC"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn s4u2self_local_pac_mismatch_is_badoption() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7210);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &tgt.rep.0.ticket).unwrap();
    attach_client_info_pac(&store, &mut part, TEST_ADMIN);
    let tkt = reseal_tgt(&store, &tgt, &part);
    let err = krb5_kdc::issue_tgs(&store, &s4u_req(&tgt, tkt, 7211)).unwrap_err();
    match err {
        krb5_kdc::Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::BADOPTION);
            assert_eq!(text.as_deref(), Some("S4U2SELF_LOCAL_PAC_CLIENT"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn s4u2self_pw_expired_user_still_issues() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store
        .apply_admin_fields(&admin, None, None, None, Some(1), None, false, None)
        .unwrap();
    let tgt = host_tgt(&store, 7220);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let host = documented_host();
    let req = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        7221,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .unwrap();
    krb5_kdc::issue_tgs(&store, &req).unwrap();
}
