//! PAC shape at issue and verify, including the RODCIdentifier trailer on the server
//! checksum.
// MIT: `verify_pac_checksums` (pac.c:557-569)
//! the privsvr checksum covers the server
//! checksum buffer past its 4-byte type, a trailer included.
//! PAC shape and placement rules MIT 1.22.2 applies at issue and verify time:
// MIT: `k5_pac_should_have_ticket_signature` (pac.c:583-592)
//! tickets to TGS and
//! `kadmin/changepw` principals carry no ticket signature.
// MIT: `sign_pac` (pac_sign.c:239-243)
//! only a service ticket (`is_service_tkt`) gets the
//! full checksum.
// MIT: `get_verified_pac` (kdc_util.c:597-602)
//! for a TGS principal only the server
//! signature is checked.
// MIT: `krb5_pac_parse` (pac.c:281-317)
//! it refuses a bad version, buffer count,
//! alignment, or offset.
// MIT: `k5_pac_locate_buffer` (pac.c:137-147)
//! a buffer type present twice is `EINVAL`,
//! and one that is absent is `ENOENT`.
//! The tests drive the shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry points of a
//! bootstrapped realm.

use krb5_asn1::encode;
use krb5_crypto::{KeyUsage, ProtocolKey, checksum};
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_host,
};
use krb5_kdc::{
    PacTicket, decrypt_ticket_part, pac_from_ticket_part, should_have_ticket_signature, sign_pac,
    ticket_checksum_der, verify_pac_signatures,
};
use krb5_protocol::{as_req, pa_enc_timestamp};

use krb5_testkit::{password_key, protocol_code};
use krb5_types::pac::{
    PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, Pac, PacError, signature_buffer,
};
use krb5_types::{PaData, PaPacRequest, PrincipalName, err, ku, pa};

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
