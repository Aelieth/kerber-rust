//! A′-2 item 6 PAC-shape units that need APIs parent `2e5995a` does not export.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, derive_prfplus_enctype, encrypt, string_to_key,
};
use krb5_kdc::{
    PacTicket, PrincipalStore, S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req,
    bootstrap_documented, decrypt_ticket_part, documented_host, pa_enc_timestamp,
    pac_from_ticket_part, sign_reply_pac, tgs_req, ticket_checksum_der, verify_pac_signatures,
    wrap_win2k_pac,
};
use krb5_protocol::tgs_req_ex;
use krb5_types::pac::{
    PAC_CLIENT_INFO, PAC_FULL_CHECKSUM, PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM,
    PAC_TICKET_CHECKSUM, Pac, PacBuffer, client_info_buffer,
};
use krb5_types::{
    EncTicketPart, KdcOptions, KerberosTime, KrbError, PaData, PaPacRequest, PrincipalName, err,
    flag_bit, ku, pa,
};

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
fn as_pac_request_false_and_disable_pac_omit_pac() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = password_key(TEST_USER, TEST_USER_PASSWORD);
    let pac_req = encode(&PaPacRequest { include_pac: false }).unwrap();
    let mut req = as_req(
        cname.clone(),
        TEST_REALM,
        6050,
        Some(vec![
            pa_enc_timestamp(&key).unwrap(),
            PaData {
                padata_type: pa::PAC_REQUEST,
                padata_value: pac_req.into(),
            },
        ]),
    )
    .unwrap();
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).unwrap();
    assert!(pac_from_ticket_part(&part).is_none());

    let (mut store2, _) = bootstrap_documented().unwrap();
    store2.policy.disable_pac = true;
    req.0.req_body.nonce = 6051;
    req.0.padata = Some(vec![pa_enc_timestamp(&key).unwrap()]);
    let issued2 = krb5_kdc::issue_as(&store2, &req).unwrap();
    let krbtgt2 = store2.krbtgt().unwrap().best_key().unwrap();
    let part2 = decrypt_ticket_part(&krbtgt2.key, &issued2.rep.0.ticket).unwrap();
    assert!(pac_from_ticket_part(&part2).is_none());
}

#[test]
fn tgs_privsvr_enctype_signs_with_prfplus() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    store
        .set_string(
            &host,
            "pac_privsvr_enctype",
            Some("aes128-cts-hmac-sha1-96"),
        )
        .unwrap();
    let as_out = issue_tgt(&store, 6130);
    let svc = krb5_kdc::issue_tgs(&store, &host_tgs(&as_out, 6131)).unwrap();
    let host_key = store.get_name(&host).unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&host_key.key, &svc.rep.0.ticket).unwrap();
    let pac = pac_from_ticket_part(&part).expect("PAC");
    let krbtgt = store.krbtgt().unwrap().first_current_key().unwrap();
    let privsvr = derive_prfplus_enctype(
        &krbtgt.key,
        b"pac_privsvr",
        EncryptionType::Aes128CtsHmacSha196,
    )
    .unwrap();
    let der = ticket_checksum_der(&part).unwrap();
    verify_pac_signatures(&pac, &host_key.key, Some(&privsvr), Some(&der), true).unwrap();
    assert!(
        verify_pac_signatures(&pac, &host_key.key, Some(&krbtgt.key), Some(&der), true).is_err()
    );
}

#[test]
fn tgs_from_client_info_only_tgt_does_not_invent_logon() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, 6140);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    let stub = Pac::built(
        0,
        vec![PacBuffer::new(
            PAC_CLIENT_INFO,
            client_info_buffer(
                part.authtime.unix_seconds(),
                &part.cname.components_joined(),
            ),
        )],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(&part).unwrap();
    let ident = store.pac_identity(&part.cname, TEST_REALM);
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
    let tkt = rewrap(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        6141,
    )
    .unwrap();
    let svc = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let svc_part = decrypt_ticket_part(&host.key, &svc.rep.0.ticket).unwrap();
    let issued = Pac::parse(&pac_from_ticket_part(&svc_part).unwrap()).unwrap();
    let mut kinds: Vec<u32> = issued.buffers.iter().map(|b| b.kind).collect();
    kinds.sort_unstable();
    assert_eq!(
        kinds,
        vec![
            PAC_SERVER_CHECKSUM,
            PAC_PRIVSVR_CHECKSUM,
            PAC_CLIENT_INFO,
            PAC_TICKET_CHECKSUM,
            PAC_FULL_CHECKSUM,
        ]
    );
    assert!(issued.buffer(PAC_LOGON_INFO).is_none());
}

#[test]
fn tgs_from_local_tgt_keeps_subject_logon() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, 6150);
    let svc = krb5_kdc::issue_tgs(&store, &host_tgs(&as_out, 6151)).unwrap();
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part = decrypt_ticket_part(&host.key, &svc.rep.0.ticket).unwrap();
    let pac = Pac::parse(&pac_from_ticket_part(&part).unwrap()).unwrap();
    assert!(pac.buffer(PAC_LOGON_INFO).is_some());
}

#[test]
fn tgs_preserves_subject_authtime() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, 6160);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    let old = KerberosTime::from_unix_seconds(1_700_000_000);
    part.authtime = old.clone();
    let stub = Pac::built(
        0,
        vec![PacBuffer::new(
            PAC_CLIENT_INFO,
            client_info_buffer(old.unix_seconds(), &part.cname.components_joined()),
        )],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(&part).unwrap();
    let ident = store.pac_identity(&part.cname, TEST_REALM);
    let pac = sign_reply_pac(
        &part.cname,
        old.unix_seconds(),
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
    let tkt = rewrap(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        6161,
    )
    .unwrap();
    let svc = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let svc_part = decrypt_ticket_part(&host.key, &svc.rep.0.ticket).unwrap();
    assert_eq!(svc_part.authtime, old);
}

#[test]
fn tgs_not_a_tgt_decrypts_and_names_client() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, 6001);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    part.authorization_data = None;
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let mut svc_tkt = as_out.rep.0.ticket.clone();
    svc_tkt.sname = documented_host();
    svc_tkt.enc_part.etype = host.etype.to_iana();
    svc_tkt.enc_part.kvno = Some(host.kvno);
    let svc_tkt = rewrap(&svc_tkt, &part, &host.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        svc_tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        6003,
    )
    .unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).unwrap()).unwrap();
    let ke: KrbError = decode(&bytes).unwrap();
    assert_eq!(ke.error_code, err::NOT_US);
    let et = ke
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(et, Some("BAD TGS SERVER NAME"));
    assert_eq!(
        ke.cname.as_ref().map(PrincipalName::components_joined),
        Some(TEST_USER.to_owned())
    );
}

#[test]
fn tgs_expired_beats_unknown_sname() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, 6080);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    part.endtime = KerberosTime::now().add_seconds(-3600).unwrap();
    let tkt = rewrap(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["nosuch", "x"]),
        TEST_REALM,
        6081,
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    match err {
        krb5_kdc::Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::TKT_EXPIRED);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn tgs_canonicalize_renew_issues_local_tgt() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = renewable_tgt(&store, 6090);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req_ex(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        6091,
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true)
            .with_bit(flag_bit::CANONICALIZE, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    assert!(out.rep.0.ticket.sname.is_krbtgt_for(TEST_REALM));
}
