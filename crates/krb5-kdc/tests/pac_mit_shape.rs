//! MIT's PAC for a principal with no AD data: the buffers, in MIT's order,
//! signed as MIT signs them, on the shipped `issue_as` / `issue_tgs` paths of a bootstrapped
//! realm with no AD identity. The AD shape stays for AD data: a realm whose kdc.conf sets
//! `domain_sid`, or a subject PAC carrying LOGON_INFO. `src/ad/mit_pac_golden.rs` pins the bytes
//! against MIT 1.22.2's own tickets.

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    bootstrap_documented, documented_admin_id, documented_host,
};
use krb5_kdc::{
    Acl, IssuedAs, PrincipalStore, decrypt_ticket_part, pac_from_ticket_part, ticket_checksum_der,
    verify_pac_signatures,
};
use krb5_protocol::{pa_for_user, tgs_req};
use krb5_testkit::{
    AsReqBuilder, TgsReqBuilder, host_tgt, issue_tgt_password, issue_tgt_renewable, pref_etypes,
};
use krb5_types::pac::{
    PAC_ATTRIBUTES_INFO, PAC_CLIENT_INFO, PAC_DELEGATION_INFO, PAC_FULL_CHECKSUM, PAC_LOGON_INFO,
    PAC_PRIVSVR_CHECKSUM, PAC_REQUESTER_SID, PAC_SERVER_CHECKSUM, PAC_TICKET_CHECKSUM,
    PAC_UPN_DNS_INFO, Pac, parse_client_info, parse_delegation_info,
};
use krb5_types::{EncTicketPart, KdcOptions, PrincipalName, flag_bit};

/// MIT's TGT: CLIENT_INFO and the server and KDC checksums.
const TGT: [u32; 3] = [PAC_CLIENT_INFO, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM];
/// MIT's TGS-REQ service ticket: the subject's CLIENT_INFO, then the ticket checksum.
const TGS_SERVICE: [u32; 5] = [
    PAC_CLIENT_INFO,
    PAC_TICKET_CHECKSUM,
    PAC_SERVER_CHECKSUM,
    PAC_PRIVSVR_CHECKSUM,
    PAC_FULL_CHECKSUM,
];
/// MIT's service ticket with a new CLIENT_INFO (AS-REQ, S4U2Self): the ticket checksum first.
const NEW_SERVICE: [u32; 5] = [
    PAC_TICKET_CHECKSUM,
    PAC_CLIENT_INFO,
    PAC_SERVER_CHECKSUM,
    PAC_PRIVSVR_CHECKSUM,
    PAC_FULL_CHECKSUM,
];
/// The documented AD shape of a TGT.
const AD_TGT: [u32; 7] = [
    PAC_LOGON_INFO,
    PAC_CLIENT_INFO,
    PAC_UPN_DNS_INFO,
    PAC_ATTRIBUTES_INFO,
    PAC_REQUESTER_SID,
    PAC_SERVER_CHECKSUM,
    PAC_PRIVSVR_CHECKSUM,
];

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

fn host_tgs_req(tgt: &IssuedAs, nonce: u32) -> krb5_types::TgsReq {
    tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        nonce,
    )
    .unwrap()
}

#[test]
fn as_tgt_carries_mits_pac() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 9801);
    let k = krbtgt_key(&store);
    let (part, pac) = checked_pac(&tgt.rep.0.ticket, &k, &k, false);
    assert_eq!(kinds(&pac), TGT);
    assert_eq!(
        client_info(&pac),
        (part.authtime.unix_seconds(), TEST_USER.to_owned())
    );
}

#[test]
fn as_service_ticket_carries_mits_pac() {
    let (store, _) = bootstrap_documented().unwrap();
    let key = krb5_testkit::password_key(TEST_USER, TEST_USER_PASSWORD);
    let req = AsReqBuilder::new(user(), 9811)
        .sname(documented_host())
        .padata(vec![krb5_protocol::pa_enc_timestamp(&key).unwrap()])
        .build()
        .unwrap();
    let out = krb5_kdc::issue_as(&store, &req).unwrap();
    let (part, pac) = checked_pac(
        &out.rep.0.ticket,
        &host_key(&store),
        &krbtgt_key(&store),
        true,
    );
    assert_eq!(kinds(&pac), NEW_SERVICE);
    assert_eq!(
        client_info(&pac),
        (part.authtime.unix_seconds(), TEST_USER.to_owned())
    );
}

#[test]
fn tgs_service_ticket_carries_mits_pac() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 9821);
    let k = krbtgt_key(&store);
    let (_, tgt_pac) = checked_pac(&tgt.rep.0.ticket, &k, &k, false);
    let svc = krb5_kdc::issue_tgs(&store, &host_tgs_req(&tgt, 9822)).unwrap();
    let (_, pac) = checked_pac(&svc.rep.0.ticket, &host_key(&store), &k, true);
    assert_eq!(kinds(&pac), TGS_SERVICE);
    let tgt_info = Pac::parse(&tgt_pac).unwrap();
    let svc_info = Pac::parse(&pac).unwrap();
    assert_eq!(
        svc_info.buffer(PAC_CLIENT_INFO),
        tgt_info.buffer(PAC_CLIENT_INFO),
        "a TGS-REQ copies the subject's CLIENT_INFO"
    );
}

#[test]
fn tgt_renewal_gives_the_tgt_pac_back() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = issue_tgt_renewable(&store, TEST_USER, 9831, true);
    let k = krbtgt_key(&store);
    let (_, tgt_pac) = checked_pac(&tgt.rep.0.ticket, &k, &k, false);
    let renew = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user(),
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        9832,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::RENEW, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &renew).unwrap();
    let (_, pac) = checked_pac(&out.rep.0.ticket, &k, &k, false);
    assert_eq!(pac, tgt_pac, "MIT renews a TGT into the same PAC bytes");
}

#[test]
fn s4u2self_carries_mits_pac() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = host_tgt(&store, 9841);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let req = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        9842,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
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
    assert_eq!(kinds(&pac), NEW_SERVICE);
    assert_eq!(
        client_info(&pac),
        (part.authtime.unix_seconds(), TEST_ADMIN.to_owned())
    );
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

#[test]
fn cross_realm_referral_and_foreign_ticket_carry_mits_pac() {
    let (local, acl_a) = bootstrap_documented().unwrap();
    let mut local = local;
    let mut foreign = PrincipalStore::bootstrap(
        "OTHER.TEST",
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
    )
    .unwrap();
    let actor_b = format!("{TEST_ADMIN}@OTHER.TEST");
    let acl_b = Acl::allow_admin(&actor_b).unwrap();
    let host_b = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.other.test"]);
    foreign.create_host(&acl_b, &actor_b, &host_b).unwrap();
    let ir = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32]).unwrap();
    local
        .create_interrealm_key(&acl_a, &documented_admin_id(), "OTHER.TEST", ir.clone())
        .unwrap();
    foreign
        .create_interrealm_key(&acl_b, &actor_b, TEST_REALM, ir.clone())
        .unwrap();
    let tgt = issue_tgt_password(&local, TEST_USER, TEST_USER_PASSWORD, 9861);
    let referral = krb5_kdc::issue_tgs(
        &local,
        &tgs_req(
            tgt.rep.0.ticket.clone(),
            &tgt.session_key,
            TEST_REALM,
            &user(),
            PrincipalName::krbtgt("OTHER.TEST"),
            TEST_REALM,
            9862,
        )
        .unwrap(),
    )
    .unwrap();
    // MIT: the inter-realm key signs the server checksum, the local krbtgt key the KDC checksum.
    let (_, ref_pac) = checked_pac(&referral.rep.0.ticket, &ir, &krbtgt_key(&local), false);
    assert_eq!(kinds(&ref_pac), TGT);
    let svc = krb5_kdc::issue_tgs(
        &foreign,
        &tgs_req(
            referral.rep.0.ticket.clone(),
            &referral.session_key,
            TEST_REALM,
            &user(),
            host_b.clone(),
            "OTHER.TEST",
            9863,
        )
        .unwrap(),
    )
    .unwrap();
    let host_key_b = foreign
        .get_name(&host_b)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let (_, pac) = checked_pac(&svc.rep.0.ticket, &host_key_b, &krbtgt_key(&foreign), true);
    assert_eq!(kinds(&pac), TGS_SERVICE);
}

#[test]
fn a_realm_with_an_ad_identity_keeps_the_ad_shape() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.policy.ad_identity = true;
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 9871);
    let k = krbtgt_key(&store);
    let (_, tgt_pac) = checked_pac(&tgt.rep.0.ticket, &k, &k, false);
    assert_eq!(kinds(&tgt_pac), AD_TGT);
    let svc = krb5_kdc::issue_tgs(&store, &host_tgs_req(&tgt, 9872)).unwrap();
    let (_, pac) = checked_pac(&svc.rep.0.ticket, &host_key(&store), &k, true);
    assert_eq!(
        kinds(&pac),
        [
            PAC_LOGON_INFO,
            PAC_CLIENT_INFO,
            PAC_UPN_DNS_INFO,
            PAC_ATTRIBUTES_INFO,
            PAC_REQUESTER_SID,
            PAC_TICKET_CHECKSUM,
            PAC_FULL_CHECKSUM,
            PAC_SERVER_CHECKSUM,
            PAC_PRIVSVR_CHECKSUM,
        ]
    );
}

#[test]
fn a_subject_pac_with_logon_info_keeps_the_ad_shape() {
    // A TGT issued while the realm had an AD identity is AD data on its own.
    let (mut store, _) = bootstrap_documented().unwrap();
    store.policy.ad_identity = true;
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 9881);
    store.policy.ad_identity = false;
    let svc = krb5_kdc::issue_tgs(&store, &host_tgs_req(&tgt, 9882)).unwrap();
    let (_, pac) = checked_pac(
        &svc.rep.0.ticket,
        &host_key(&store),
        &krbtgt_key(&store),
        true,
    );
    assert_eq!(kinds(&pac)[0], PAC_LOGON_INFO);
    assert_eq!(kinds(&pac).len(), 9);
}

#[test]
fn kdc_conf_domain_sid_is_the_ad_identity() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let with = krb5_config::KdcConf::parse(
        "[realms]\n    KERBER.TEST = {\n        domain_sid = S-1-5-21-891046300-1937985867-1481223175\n    }\n",
    )
    .unwrap();
    store.apply_kdc_conf(&with).unwrap();
    assert!(store.policy().ad_identity);
    let without = krb5_config::KdcConf::parse("[realms]\n    KERBER.TEST = {\n    }\n").unwrap();
    store.apply_kdc_conf(&without).unwrap();
    assert!(!store.policy().ad_identity);
}
