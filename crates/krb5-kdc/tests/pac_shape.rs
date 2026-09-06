//! PAC shape and placement rules MIT 1.22.2 applies at issue and verify time:
//! `k5_pac_should_have_ticket_signature` (`pac.c:583-592`, `pac_sign.c:239-243`),
//! `get_verified_pac` for TGS principals (`kdc_util.c:597-602`),
//! `krb5_pac_parse` (`pac.c:281-317`) and `k5_pac_locate_buffer` (`pac.c:137-147`).

use krb5_crypto::ProtocolKey;
use krb5_kdc::{
    Error, PacTicket, TEST_REALM, TEST_USER, bootstrap_documented, documented_host,
    should_have_ticket_signature, sign_pac, ticket_checksum_der, verify_pac_signatures,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_types::pac::{
    PAC_FULL_CHECKSUM, PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM,
    PAC_TICKET_CHECKSUM, Pac, PacError,
};
use krb5_types::{PrincipalName, err};

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

fn code(r: &Result<(), Error>) -> Option<i32> {
    match r {
        Err(Error::Protocol { code, .. }) => Some(*code),
        _ => None,
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
        code(&verify_pac_signatures(
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
        code(&verify_pac_signatures(
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
