//! A′-2 R16: incoming-trust principals and realm-aware TGS lookup.

use krb5_asn1::encode;
use krb5_crypto::{KeyUsage, encrypt};
use krb5_kdc::{
    RID_KRBTGT, TEST_REALM, TEST_USER, as_req, bootstrap_documented, decrypt_ticket_part,
    documented_admin_id, documented_host, dump_store, dump_store_iprop, load_dump,
    pa_enc_timestamp,
};
use krb5_protocol::tgs_req;
use krb5_testkit::{TgsReqBuilder, aes_key, expect_status, issue_tgt_renewable, pref_etypes};
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit, ku};

const FOREIGN: &str = "AD.KERBER.TEST";

fn incoming_name() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", TEST_REALM])
}

#[test]
fn a2_r16_incoming_trust_is_own_principal() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let issue = aes_key(0x11);
    let accept = aes_key(0x22);
    store
        .create_interrealm_key(&acl, &actor, FOREIGN, issue)
        .unwrap();
    store
        .add_interrealm_decrypt_key(&acl, &actor, FOREIGN, accept)
        .unwrap();
    let outgoing = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", FOREIGN]);
    let out = store.get_name(&outgoing).expect("outgoing");
    assert_eq!(out.realm, TEST_REALM);
    assert_eq!(out.keys.len(), 1);
    assert_eq!(out.keys[0].key.as_bytes(), &[0x11u8; 32]);
    let incoming = store
        .get_in_realm(&incoming_name(), FOREIGN)
        .expect("incoming");
    assert_eq!(incoming.realm, FOREIGN);
    assert_ne!(incoming.rid, RID_KRBTGT);
    assert_eq!(store.krbtgt().unwrap().rid, RID_KRBTGT);
    assert!(
        incoming
            .keys
            .iter()
            .any(|k| k.key.as_bytes() == [0x22u8; 32])
    );
}

#[test]
fn a2_r16_cross_tgt_renew_realm_mismatch_is_26() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let ir = aes_key(0x33);
    store
        .create_interrealm_key(&acl, &actor, FOREIGN, ir.clone())
        .unwrap();
    let issued = issue_tgt_renewable(&store, TEST_USER, 16100, true);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &issued.rep.0.ticket).unwrap();
    part.flags = part.flags.with_bit(flag_bit::RENEWABLE, true);
    part.renew_till = Some(part.endtime.add_hours(24).unwrap());
    part.authorization_data = None;
    let der = encode(&part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let header = krb5_types::Ticket {
        tkt_vno: issued.rep.0.ticket.tkt_vno,
        realm: krb5_types::try_ascii(FOREIGN).unwrap(),
        sname: incoming_name(),
        enc_part: krb5_types::EncryptedData {
            etype: ir.etype().to_iana(),
            kvno: Some(1),
            cipher: encrypt(&ir, usage, &der).unwrap().into(),
        },
    };
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = TgsReqBuilder::new(
        header,
        &issued.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        16101,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::RENEW, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::SERVER_NOMATCH);
    assert_eq!(
        text.as_deref(),
        Some("SERVER DIDN'T MATCH TICKET FOR RENEW/FORWARD/ETC")
    );
}

#[test]
fn a2_r16_u2u_second_ticket_foreign_realm_is_7() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let hkey = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let href = as_req(
        host.clone(),
        TEST_REALM,
        16110,
        Some(vec![pa_enc_timestamp(&hkey).unwrap()]),
    )
    .unwrap();
    let extra = krb5_kdc::issue_as(&store, &href).unwrap().rep.0.ticket;
    let mut foreign = extra;
    foreign.realm = krb5_types::try_ascii("OTHER.TEST").unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_renewable(&store, TEST_USER, 16111, false);
    let req = TgsReqBuilder::new(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        host,
        TEST_REALM,
        16112,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true))
    .additional_tickets(Some(vec![foreign]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("2ND_TKT_SERVER"));
}

#[test]
fn a2_r16_incoming_trust_dump_load_round_trip() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let ir = aes_key(0x44);
    store
        .create_interrealm_key(&acl, &actor, FOREIGN, ir)
        .unwrap();
    let text = dump_store(&store, b"masterpassword").unwrap();
    assert!(
        text.contains("krbtgt/KERBER.TEST@AD.KERBER.TEST"),
        "dump must name the incoming id: {text}"
    );
    let loaded = load_dump(&text, b"masterpassword").unwrap();
    let incoming = loaded
        .get_in_realm(&incoming_name(), FOREIGN)
        .expect("load incoming");
    assert_eq!(incoming.realm, FOREIGN);
    assert_eq!(incoming.keys[0].key.as_bytes(), &[0x44u8; 32]);
}

#[test]
fn a2_r16_incoming_trust_iprop_names_foreign_id() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, aes_key(0x55))
        .unwrap();
    let text = dump_store_iprop(&store, b"masterpassword").unwrap();
    assert!(text.starts_with("ipropx "));
    assert!(
        text.contains("krbtgt/KERBER.TEST@AD.KERBER.TEST"),
        "iprop dump must name the incoming id"
    );
}

#[test]
fn a2_r16_foreign_header_decrypts_via_incoming_kvno() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let issue = aes_key(0x66);
    let accept = aes_key(0x77);
    store
        .create_interrealm_key(&acl, &actor, FOREIGN, issue)
        .unwrap();
    store
        .set_interrealm_decrypt_key(&acl, &actor, FOREIGN, accept.clone())
        .unwrap();
    let incoming = store.get_in_realm(&incoming_name(), FOREIGN).unwrap();
    assert_eq!(incoming.keys.len(), 1);
    assert_eq!(incoming.keys[0].kvno, 1);
    assert_eq!(incoming.keys[0].key.as_bytes(), &[0x77u8; 32]);
    let issued = issue_tgt_renewable(&store, TEST_USER, 16120, false);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &issued.rep.0.ticket).unwrap();
    part.authorization_data = None;
    let der = encode(&part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let header = krb5_types::Ticket {
        tkt_vno: issued.rep.0.ticket.tkt_vno,
        realm: krb5_types::try_ascii(FOREIGN).unwrap(),
        sname: incoming_name(),
        enc_part: krb5_types::EncryptedData {
            etype: accept.etype().to_iana(),
            kvno: Some(1),
            cipher: encrypt(&accept, usage, &der).unwrap().into(),
        },
    };
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        header,
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        16121,
    )
    .unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("INVALID LINEAGE"));
}
