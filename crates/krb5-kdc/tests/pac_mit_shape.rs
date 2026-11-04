//! MIT's PAC for a principal with no AD data: the buffers, in MIT's order,
//! signed as MIT signs them, on the shipped `issue_as` / `issue_tgs` paths of a bootstrapped
//! realm with no AD identity. The AD shape stays for AD data: a realm whose kdc.conf sets
//! `domain_sid`, or a subject PAC carrying LOGON_INFO. `src/ad/mit_pac_golden.rs` pins the bytes
//! against MIT 1.22.2's own tickets.

use krb5_crypto::ProtocolKey;
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    bootstrap_documented, documented_host,
};
use krb5_kdc::{
    PrincipalStore, decrypt_ticket_part, pac_from_ticket_part, ticket_checksum_der,
    verify_pac_signatures,
};
use krb5_protocol::tgs_req;
use krb5_testkit::{TgsReqBuilder, issue_tgt_password, pref_etypes};
use krb5_types::pac::{
    PAC_CLIENT_INFO, PAC_DELEGATION_INFO, PAC_FULL_CHECKSUM, PAC_PRIVSVR_CHECKSUM,
    PAC_SERVER_CHECKSUM, PAC_TICKET_CHECKSUM, Pac, parse_client_info, parse_delegation_info,
};
use krb5_types::{EncTicketPart, KdcOptions, PrincipalName, flag_bit};

fn kinds(pac: &[u8]) -> Vec<u32> {
    Pac::parse(pac)
        .unwrap()
        .buffers
        .iter()
        .map(|b| b.kind)
        .collect()
}

fn client_info(pac: &[u8]) -> (u32, String) {
    parse_client_info(Pac::parse(pac).unwrap().buffer(PAC_CLIENT_INFO).unwrap()).unwrap()
}

fn krbtgt_key(store: &PrincipalStore) -> ProtocolKey {
    store.krbtgt().unwrap().best_key().unwrap().key.clone()
}

fn host_key(store: &PrincipalStore) -> ProtocolKey {
    store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone()
}

/// The PAC of `ticket`, after checking its signatures as the KDC that issued it would.
fn checked_pac(
    ticket: &krb5_types::Ticket,
    server: &ProtocolKey,
    kdc: &ProtocolKey,
    service: bool,
) -> (EncTicketPart, Vec<u8>) {
    let part = decrypt_ticket_part(server, ticket).unwrap();
    let pac = pac_from_ticket_part(&part).expect("PAC");
    let der = ticket_checksum_der(&part).unwrap();
    verify_pac_signatures(&pac, server, Some(kdc), Some(&der), service).expect("signatures");
    (part, pac)
}

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

#[test]
fn s4u2proxy_carries_mits_pac() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store.allow_s4u_to(&user(), &documented_host().components_joined());
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 9851);
    let evidence_req = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user(),
        TEST_REALM,
        9852,
    )
    .unwrap();
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_req).unwrap();
    let user_tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 9853);
    let req = TgsReqBuilder::new(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        9854,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true))
    .additional_tickets(Some(vec![evidence.rep.0.ticket.clone()]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &req).unwrap();
    let (part, pac) = checked_pac(
        &out.rep.0.ticket,
        &host_key(&store),
        &krbtgt_key(&store),
        true,
    );
    assert_eq!(
        kinds(&pac),
        [
            PAC_DELEGATION_INFO,
            PAC_TICKET_CHECKSUM,
            PAC_CLIENT_INFO,
            PAC_SERVER_CHECKSUM,
            PAC_PRIVSVR_CHECKSUM,
            PAC_FULL_CHECKSUM,
        ]
    );
    assert_eq!(
        client_info(&pac),
        (part.authtime.unix_seconds(), TEST_ADMIN.to_owned())
    );
    let parsed = Pac::parse(&pac).unwrap();
    let di = parse_delegation_info(parsed.buffer(PAC_DELEGATION_INFO).unwrap()).unwrap();
    assert_eq!(di.proxy_target, documented_host().components_joined());
    assert_eq!(
        di.transited_services,
        [user().unparse_with_realm(TEST_REALM)]
    );
}
