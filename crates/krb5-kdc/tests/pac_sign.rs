//! PAC shape at issue and verify.
//! RODCIdentifier trailer on the server checksum (MIT `pac.c:557-569`).
//! PAC shape and placement rules MIT 1.22.2 applies at issue and verify time:
//! `k5_pac_should_have_ticket_signature` (`pac.c:583-592`, `pac_sign.c:239-243`),
//! `get_verified_pac` for TGS principals (`kdc_util.c:597-602`),
//! `krb5_pac_parse` (`pac.c:281-317`) and `k5_pac_locate_buffer` (`pac.c:137-147`).
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

use krb5_asn1::encode;
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, derive_prfplus_enctype, encrypt,
};
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_host,
};
use krb5_kdc::{
    PacTicket, decrypt_ticket_part, pac_from_ticket_part, should_have_ticket_signature, sign_pac,
    sign_reply_pac, ticket_checksum_der, verify_pac, verify_pac_signatures, wrap_win2k_pac,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_testkit::{issue_tgt_password, password_key, protocol_code};
use krb5_types::pac::{
    PAC_CLIENT_INFO, PAC_FULL_CHECKSUM, PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM,
    PAC_TICKET_CHECKSUM, Pac, PacBuffer, PacError, client_info_buffer, signature_buffer,
    zero_pac_ad_data,
};
use krb5_types::{EncTicketPart, KerberosTime, PaData, PaPacRequest, PrincipalName, err, ku, pa};

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
    let as_out = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 6130);
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
    let as_out = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 6140);
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
    let as_out = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 6150);
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
    let as_out = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 6160);
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

fn signed_as_pac() -> (Vec<u8>, ProtocolKey, ProtocolKey) {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user = store.get_name(&cname).unwrap().best_key().unwrap();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        802,
        Some(vec![pa_enc_timestamp(&user.key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let part = krb5_kdc::decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    let der = ticket_checksum_der(&part).unwrap();
    let ident = store.pac_identity(&cname, TEST_REALM);
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let signed = sign_pac(
        &cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: &host.key,
            kdc: &krbtgt.key,
            enc_tkt_der: &der,
            is_service_tkt: true,
        },
        &ident,
        None,
    )
    .unwrap();
    (signed, host.key.clone(), krbtgt.key.clone())
}

#[test]
fn accept_rodc_trailer_privsvr_covers_server_buffer_minus_type() {
    let (signed, server, kdc) = signed_as_pac();
    let stretched = {
        let mut parsed = Pac::parse(&signed).unwrap();
        for b in &mut parsed.buffers {
            if b.kind == PAC_SERVER_CHECKSUM {
                b.data.extend_from_slice(&[0x12, 0x34]);
            }
        }
        parsed.to_bytes()
    };
    let stretched_pac = Pac::parse(&stretched).unwrap();
    let copy = stretched_pac.bytes_for_checksum();
    let usage = KeyUsage::new(ku::KERB_NON_KERB_CKSUM_SALT).unwrap();
    let server_mac = checksum(&server, usage, &copy).unwrap();
    let mut out_bufs = stretched_pac.buffers.clone();
    for b in &mut out_bufs {
        if b.kind == PAC_SERVER_CHECKSUM {
            let mut d = signature_buffer(server.etype().checksum_type(), &server_mac);
            d.extend_from_slice(&[0x12, 0x34]);
            b.data = d;
        }
    }
    let privsvr_over = {
        let s = out_bufs
            .iter()
            .find(|b| b.kind == PAC_SERVER_CHECKSUM)
            .unwrap();
        checksum(&kdc, usage, &s.data[4..]).unwrap()
    };
    for b in &mut out_bufs {
        if b.kind == PAC_PRIVSVR_CHECKSUM {
            b.data = signature_buffer(kdc.etype().checksum_type(), &privsvr_over);
        }
    }
    let out = {
        let mut rebuilt = stretched_pac.clone();
        rebuilt.buffers = out_bufs;
        rebuilt.to_bytes()
    };
    verify_pac_signatures(&out, &server, Some(&kdc), None, false)
        .expect("RODC trailer PAC verifies");
}

struct Signed {
    tgt_shaped: Vec<u8>,
    service_shaped: Vec<u8>,
    der: Vec<u8>,
    server: ProtocolKey,
    kdc: ProtocolKey,
}

fn signed() -> Signed {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user = store.get_name(&cname).unwrap().best_key().unwrap();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        803,
        Some(vec![pa_enc_timestamp(&user.key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let krbtgt = store.krbtgt().unwrap().first_current_key().unwrap();
    let part = krb5_kdc::decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    let der = ticket_checksum_der(&part).unwrap();
    let ident = store.pac_identity(&cname, TEST_REALM);
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let shape = |service: bool| {
        sign_pac(
            &cname,
            part.authtime.unix_seconds(),
            &PacTicket {
                server: &host.key,
                kdc: &krbtgt.key,
                enc_tkt_der: &der,
                is_service_tkt: service,
            },
            &ident,
            None,
        )
        .unwrap()
    };
    Signed {
        tgt_shaped: shape(false),
        service_shaped: shape(true),
        der,
        server: host.key.clone(),
        kdc: krbtgt.key.clone(),
    }
}

fn kinds(pac: &[u8]) -> Vec<u32> {
    Pac::parse(pac)
        .unwrap()
        .buffers
        .iter()
        .map(|b| b.kind)
        .collect()
}

#[test]
fn ticket_signature_predicate_matches_mit() {
    let tgt = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", TEST_REALM]);
    let changepw = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]);
    let admin = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "admin"]);
    assert!(!should_have_ticket_signature(&tgt));
    assert!(!should_have_ticket_signature(&changepw));
    assert!(should_have_ticket_signature(&admin));
    assert!(should_have_ticket_signature(&documented_host()));
}

#[test]
fn tgt_pac_carries_no_ticket_or_full_checksum() {
    let s = signed();
    let tgt = kinds(&s.tgt_shaped);
    assert!(
        !tgt.contains(&PAC_TICKET_CHECKSUM) && !tgt.contains(&PAC_FULL_CHECKSUM),
        "{tgt:?}"
    );
    assert!(tgt.contains(&PAC_SERVER_CHECKSUM) && tgt.contains(&PAC_PRIVSVR_CHECKSUM));
    let svc = kinds(&s.service_shaped);
    assert!(
        svc.contains(&PAC_TICKET_CHECKSUM) && svc.contains(&PAC_FULL_CHECKSUM),
        "{svc:?}"
    );
}

#[test]
fn tgt_pac_verifies_without_ticket_or_full_checksum() {
    let s = signed();
    verify_pac_signatures(&s.tgt_shaped, &s.server, Some(&s.kdc), Some(&s.der), false)
        .expect("TGT shape: server + privsvr only");
    assert_eq!(
        protocol_code(&verify_pac_signatures(
            &s.tgt_shaped,
            &s.server,
            Some(&s.kdc),
            Some(&s.der),
            true
        )),
        Some(err::GENERIC),
        "a service ticket must carry the ticket checksum"
    );
    verify_pac_signatures(
        &s.service_shaped,
        &s.server,
        Some(&s.kdc),
        Some(&s.der),
        true,
    )
    .expect("service shape: all four");
}

#[test]
fn duplicate_signature_buffer_is_generic_60() {
    let s = signed();
    let mut pac = Pac::parse(&s.tgt_shaped).unwrap();
    let dup = pac
        .buffers
        .iter()
        .find(|b| b.kind == PAC_SERVER_CHECKSUM)
        .unwrap()
        .clone();
    pac.buffers.push(dup);
    let bytes = pac.to_bytes();
    let parsed = Pac::parse(&bytes).unwrap();
    assert!(matches!(
        parsed.unique_buffer(PAC_SERVER_CHECKSUM),
        Err(PacError::Malformed)
    ));
    assert!(parsed.unique_buffer(PAC_LOGON_INFO).unwrap().is_some());
    assert_eq!(
        protocol_code(&verify_pac_signatures(
            &bytes,
            &s.server,
            Some(&s.kdc),
            None,
            false
        )),
        Some(err::GENERIC)
    );
}

#[test]
fn first_current_key_ignores_the_session_etype() {
    let (store, _) = bootstrap_documented().unwrap();
    let krbtgt = store.krbtgt().unwrap();
    let first = krbtgt.first_current_key().unwrap();
    let highest = krbtgt.keys.iter().map(|k| k.kvno).max().unwrap();
    assert_eq!(first.kvno, highest);
    assert_eq!(
        first.etype,
        krbtgt
            .keys
            .iter()
            .find(|k| k.kvno == highest)
            .unwrap()
            .etype
    );
}

fn rewrap_ticket(
    ticket: &krb5_types::Ticket,
    part: &EncTicketPart,
    key: &ProtocolKey,
) -> krb5_types::Ticket {
    let der = encode(part).expect("enc-tkt DER");
    let usage = KeyUsage::new(ku::TICKET).expect("usage");
    let cipher = encrypt(key, usage, &der).expect("encrypt");
    let mut out = ticket.clone();
    out.enc_part.cipher = cipher.into();
    out
}

#[test]
fn as_and_tgs_tickets_carry_verifiable_pac() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 501);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let tgt_part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    let pac = pac_from_ticket_part(&tgt_part).expect("PAC on TGT");
    verify_pac(&pac, &krbtgt.key, &krbtgt.key, false).expect("TGT PAC");

    let tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        502,
    )
    .expect("TGS-REQ");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let svc = decrypt_ticket_part(&host.key, &tgs_out.rep.0.ticket).expect("svc");
    let pac = pac_from_ticket_part(&svc).expect("PAC on service ticket");
    verify_pac(&pac, &host.key, &krbtgt.key, true).expect("service PAC");
    let ident = store.pac_identity(&cname, TEST_REALM);
    let signed = sign_pac(
        &cname,
        tgt_part.authtime.unix_seconds(),
        &PacTicket {
            server: &host.key,
            kdc: &krbtgt.key,
            enc_tkt_der: &[],
            is_service_tkt: true,
        },
        &ident,
        None,
    )
    .expect("sign");
    verify_pac(&signed, &host.key, &krbtgt.key, true).expect("re-sign");
}

#[test]
fn pac_logon_info_is_ndr() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 54);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    let pac = pac_from_ticket_part(&part).expect("PAC");
    let parsed = krb5_types::pac::Pac::parse(&pac).expect("parse");
    let logon = parsed
        .buffers
        .iter()
        .find(|b| b.kind == krb5_types::pac::PAC_LOGON_INFO)
        .expect("logon");
    let (c, r) = krb5_types::pac::parse_logon_info(&logon.data).expect("NDR");
    assert_eq!(c, TEST_USER);
    assert_eq!(r, TEST_REALM);
}

#[test]
fn tgs_without_pac_still_issues() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 9300);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    assert!(pac_from_ticket_part(&part).is_some());
    part.authorization_data = None;
    let stripped = rewrap_ticket(&issued.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        stripped,
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        9301,
    )
    .expect("TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("MIT TGT without PAC must still issue");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let svc = decrypt_ticket_part(&host.key, &out.rep.0.ticket).expect("svc");
    assert!(
        pac_from_ticket_part(&svc).is_none(),
        "TGS from a PAC-less subject issues no PAC (kdc_authdata.c:491)"
    );
}

#[test]
fn type16_checksum_uses_original_enc_tkt_bytes() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 9400);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).expect("usage");
    let plain = decrypt(
        &krbtgt.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .expect("plain");
    let part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    let pac = pac_from_ticket_part(&part).expect("PAC");
    let from_bytes = zero_pac_ad_data(&plain, &pac).expect("surgical PAC zero");
    let reencoded = ticket_checksum_der(&part).expect("re-encode");
    assert_eq!(
        from_bytes, reencoded,
        "self-issued rasn DER must match original-bytes PAC zero"
    );
    verify_pac_signatures(
        &pac,
        &krbtgt.key,
        Some(&krbtgt.key),
        Some(&from_bytes),
        false,
    )
    .expect("type-16 over original bytes");
}
