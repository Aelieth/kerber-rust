//! A′-2 R16: incoming-trust principals and realm-aware TGS lookup.
//! Capaths transited check on the shipped `issue_tgs` path.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_kdc::{
    Acl, Error, KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_SVR, PrincipalStore, RID_KRBTGT, TEST_ADMIN,
    TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    decrypt_ticket_part, documented_admin_id, documented_host, dump_store, dump_store_iprop,
    load_dump, pa_enc_timestamp, pac_from_ticket_part, tgs_req, ticket_checksum_der,
    verify_pac_signatures, wrap_win2k_pac,
};
use krb5_testkit::{
    TgsReqBuilder, aes_key, expect_status, issue_tgt_password, issue_tgt_renewable, password_key,
    pref_etypes, reseal_mut,
};
use krb5_types::pac::{
    PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, Pac, RpcSid,
    parse_kerb_validation_info,
};
use krb5_types::{
    EncTicketPart, KdcOptions, OctetString, PrincipalName, Ticket, err, flag_bit, ku,
};

const FOREIGN: &str = "AD.KERBER.TEST";

fn incoming_name() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", TEST_REALM])
}

#[test]
fn incoming_trust_is_own_principal() {
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
fn cross_tgt_renew_realm_mismatch_is_badoption() {
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
fn u2u_second_ticket_foreign_realm_is_2nd_tkt_server() {
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
fn incoming_trust_dump_load_round_trip() {
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
fn incoming_trust_iprop_names_foreign_id() {
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
fn foreign_header_decrypts_via_incoming_kvno() {
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

fn realm_store(realm: &str, host: &str) -> (PrincipalStore, Acl, String, PrincipalName) {
    let mut store = PrincipalStore::bootstrap(
        realm,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
    )
    .expect("bootstrap");
    let actor = format!("{TEST_ADMIN}@{realm}");
    let acl = Acl::allow_admin(&actor).expect("acl");
    let hostn = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", host]);
    store.create_host(&acl, &actor, &hostn).expect("host");
    (store, acl, actor, hostn)
}

fn as_tgt(store: &PrincipalStore, realm: &str, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(realm);
    let key = krb5_crypto::string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k");
    let req = as_req(
        cname,
        realm,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).expect("AS")
}

fn as_tgt_may_postdate(store: &PrincipalStore, realm: &str, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(realm);
    let key = krb5_crypto::string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k");
    let mut req = as_req(
        cname,
        realm,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::MAY_POSTDATE, true);
    krb5_kdc::issue_as(store, &req).expect("AS may-postdate")
}

fn as_tgt_renewable(store: &PrincipalStore, realm: &str, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(realm);
    let key = krb5_crypto::string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k");
    let mut req = as_req(
        cname,
        realm,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    req.0.req_body.rtime = Some(req.0.req_body.till.add_hours(48).expect("rtime"));
    krb5_kdc::issue_as(store, &req).expect("AS renewable")
}

fn chase_tgs(
    store: &PrincipalStore,
    ticket: krb5_types::Ticket,
    session: &ProtocolKey,
    crealm: &str,
    sname: PrincipalName,
    realm: &str,
    nonce: u32,
) -> Result<krb5_kdc::IssuedTgs, Error> {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(ticket, session, crealm, &cname, sname, realm, nonce).expect("tgs-req");
    krb5_kdc::issue_tgs(store, &req)
}

fn three_realm() -> (
    PrincipalStore,
    PrincipalStore,
    PrincipalStore,
    ProtocolKey,
    PrincipalName,
    krb5_kdc::IssuedTgs,
) {
    let ir = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32]).expect("ir");
    let (mut a, acl_a, actor_a, _) = realm_store("A.TEST", "svc.a.test");
    let (mut b, acl_b, actor_b, _) = realm_store("B.TEST", "svc.b.test");
    let (mut c, acl_c, actor_c, host_c) = realm_store("C.TEST", "svc.c.test");
    a.create_interrealm_key(&acl_a, &actor_a, "B.TEST", ir.clone())
        .expect("A→B");
    b.create_interrealm_key(&acl_b, &actor_b, "A.TEST", ir.clone())
        .expect("B→A");
    b.create_interrealm_key(&acl_b, &actor_b, "C.TEST", ir.clone())
        .expect("B→C");
    c.create_interrealm_key(&acl_c, &actor_c, "B.TEST", ir.clone())
        .expect("C→B");
    let mut cap = std::collections::BTreeMap::new();
    cap.entry("A.TEST".into())
        .or_insert_with(std::collections::BTreeMap::new)
        .insert("C.TEST".into(), vec!["B.TEST".into()]);
    c.set_capaths(cap);
    let tgt = as_tgt(&a, "A.TEST", 500);
    let ab = chase_tgs(
        &a,
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        "A.TEST",
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "B.TEST"]),
        "A.TEST",
        501,
    )
    .expect("A→B");
    let bc = chase_tgs(
        &b,
        ab.rep.0.ticket.clone(),
        &ab.session_key,
        "A.TEST",
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]),
        "B.TEST",
        502,
    )
    .expect("B→C");
    (a, b, c, ir, host_c, bc)
}

fn three_realm_distinct() -> (
    PrincipalStore,
    PrincipalStore,
    PrincipalStore,
    ProtocolKey,
    ProtocolKey,
    PrincipalName,
    krb5_kdc::IssuedTgs,
) {
    let ab = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0xa1; 32]).expect("ab");
    let bc = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0xc3; 32]).expect("bc");
    let (mut a, acl_a, actor_a, _) = realm_store("A.TEST", "svc.a.test");
    let (mut b, acl_b, actor_b, _) = realm_store("B.TEST", "svc.b.test");
    let (mut c, acl_c, actor_c, host_c) = realm_store("C.TEST", "svc.c.test");
    a.create_interrealm_key(&acl_a, &actor_a, "B.TEST", ab.clone())
        .expect("A B");
    b.create_interrealm_key(&acl_b, &actor_b, "A.TEST", ab.clone())
        .expect("B A");
    b.create_interrealm_key(&acl_b, &actor_b, "C.TEST", bc.clone())
        .expect("B C");
    c.create_interrealm_key(&acl_c, &actor_c, "B.TEST", bc.clone())
        .expect("C B");
    let mut cap = std::collections::BTreeMap::new();
    cap.entry("A.TEST".into())
        .or_insert_with(std::collections::BTreeMap::new)
        .insert("C.TEST".into(), vec!["B.TEST".into()]);
    c.set_capaths(cap);
    let tgt = as_tgt(&a, "A.TEST", 900);
    let abtgt = chase_tgs(
        &a,
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        "A.TEST",
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "B.TEST"]),
        "A.TEST",
        901,
    )
    .expect("A B");
    let bctgt = chase_tgs(
        &b,
        abtgt.rep.0.ticket.clone(),
        &abtgt.session_key,
        "A.TEST",
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]),
        "B.TEST",
        902,
    )
    .expect("B C");
    (a, b, c, ab, bc, host_c, bctgt)
}

fn reseal_empty_transited(key: &ProtocolKey, ticket: &Ticket, claimed: &str) -> Ticket {
    let mut t = ticket.clone();
    let mut part = decrypt_ticket_part(key, &t).expect("enc");
    part.transited = krb5_types::TransitedEncoding::empty();
    part.authorization_data = None;
    reseal_mut(&mut t, &part, key);
    t.realm = krb5_types::try_ascii(claimed).expect("realm");
    t
}

fn tgs_code_text(res: Result<krb5_kdc::IssuedTgs, Error>) -> (i32, Option<String>) {
    match res {
        Err(Error::Protocol { code, text, .. }) => (code, text),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

#[test]
fn three_hop_capaths_accept_and_reject() {
    let ir = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32]).expect("ir");
    let (mut a, acl_a, actor_a, _) = realm_store("A.TEST", "svc.a.test");
    let (mut b, acl_b, actor_b, _) = realm_store("B.TEST", "svc.b.test");
    let (mut c, acl_c, actor_c, host_c) = realm_store("C.TEST", "svc.c.test");
    a.create_interrealm_key(&acl_a, &actor_a, "B.TEST", ir.clone())
        .expect("A→B");
    b.create_interrealm_key(&acl_b, &actor_b, "A.TEST", ir.clone())
        .expect("B→A");
    b.create_interrealm_key(&acl_b, &actor_b, "C.TEST", ir.clone())
        .expect("B→C");
    c.create_interrealm_key(&acl_c, &actor_c, "B.TEST", ir)
        .expect("C→B");

    let mut cap = std::collections::BTreeMap::new();
    cap.entry("A.TEST".into())
        .or_insert_with(std::collections::BTreeMap::new)
        .insert("C.TEST".into(), vec!["B.TEST".into()]);
    c.set_capaths(cap.clone());

    let tgt = as_tgt(&a, "A.TEST", 400);
    let ab = chase_tgs(
        &a,
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        "A.TEST",
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "B.TEST"]),
        "A.TEST",
        401,
    )
    .expect("A→B referral");
    let bc = chase_tgs(
        &b,
        ab.rep.0.ticket.clone(),
        &ab.session_key,
        "A.TEST",
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]),
        "B.TEST",
        402,
    )
    .expect("B→C referral");
    let host = chase_tgs(
        &c,
        bc.rep.0.ticket.clone(),
        &bc.session_key,
        "A.TEST",
        host_c.clone(),
        "C.TEST",
        403,
    )
    .expect("C host with capaths");
    let host_key = c.get_name(&host_c).unwrap().best_key().unwrap().key.clone();
    let part = decrypt_ticket_part(&host_key, &host.rep.0.ticket).expect("enc");
    assert!(
        part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "T set only when capaths check passed"
    );
    let hops = part
        .transited
        .realms_for("A.TEST", "C.TEST")
        .expect("expand");
    assert_eq!(hops, vec!["B.TEST".to_string()]);
    let contents = String::from_utf8(part.transited.contents.as_ref().to_vec()).unwrap();
    assert_eq!(contents, "B.TEST");
    assert_eq!(part.transited.tr_type, 1);

    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let skip_req = TgsReqBuilder::new(
        bc.rep.0.ticket.clone(),
        &bc.session_key,
        "A.TEST",
        &cname,
        host_c.clone(),
        "C.TEST",
        406,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::DISABLE_TRANSITED_CHECK, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("skip tgs");
    match krb5_kdc::issue_tgs(&c, &skip_req) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("BAD_TRANSIT"));
        }
        other => panic!("capaths-permitted + skip + default must be POLICY, got {other:?}"),
    }

    c.set_capaths(std::collections::BTreeMap::new());
    let denied = chase_tgs(
        &c,
        bc.rep.0.ticket.clone(),
        &bc.session_key,
        "A.TEST",
        host_c.clone(),
        "C.TEST",
        404,
    );
    match denied {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::POLICY),
        other => panic!("expected POLICY, got {other:?}"),
    }

    c.policy.reject_bad_transit = false;
    let lax = chase_tgs(
        &c,
        bc.rep.0.ticket.clone(),
        &bc.session_key,
        "A.TEST",
        host_c.clone(),
        "C.TEST",
        405,
    )
    .expect("reject_bad_transit=false accepts");
    let lax_part = decrypt_ticket_part(&host_key, &lax.rep.0.ticket).expect("enc lax");
    assert!(
        !lax_part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "failed check must not set T when reject_bad_transit is false"
    );
}

#[test]
fn transited_add_path_type_and_ill_formed() {
    let (_a, _b, mut c, ir, host_c, bc) = three_realm();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);

    let mut t2 = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t2).expect("bc");
    part.transited.tr_type = 2;
    part.authorization_data = None;
    reseal_mut(&mut t2, &part, &ir);
    let req = tgs_req(
        t2,
        &bc.session_key,
        "A.TEST",
        &cname,
        host_c.clone(),
        "C.TEST",
        510,
    )
    .expect("tgs");
    match krb5_kdc::issue_tgs(&c, &req) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::TRTYPE_NOSUPP);
            assert_eq!(text.as_deref(), Some("VALIDATE_TRANSIT_TYPE"));
        }
        other => panic!("add-path tr_type=2 must be 17, got {other:?}"),
    }

    c.policy.reject_bad_transit = false;
    let mut tlong = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &tlong).expect("bc");
    part.transited.tr_type = 1;
    part.transited.contents = OctetString::from(vec![b'A'; 500]);
    part.authorization_data = None;
    reseal_mut(&mut tlong, &part, &ir);
    let req = tgs_req(
        tlong,
        &bc.session_key,
        "A.TEST",
        &cname,
        host_c.clone(),
        "C.TEST",
        511,
    )
    .expect("tgs");
    match krb5_kdc::issue_tgs(&c, &req) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::ILL_CR_TKT);
            assert_eq!(text.as_deref(), Some("ADD_TO_TRANSITED_LIST"));
        }
        other => {
            panic!("add-path raw 500 must be 43 even with reject_bad_transit=false, got {other:?}")
        }
    }
}

#[test]
fn transited_add_path_bad_intermediates_is_policy() {
    let (_a, _b, c, ir, host_c, bc) = three_realm();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut t = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t).expect("bc");
    part.transited.tr_type = 1;
    part.transited.contents = OctetString::from(b",,".to_vec());
    part.authorization_data = None;
    reseal_mut(&mut t, &part, &ir);
    let req = tgs_req(t, &bc.session_key, "A.TEST", &cname, host_c, "C.TEST", 530).expect("tgs");
    match krb5_kdc::issue_tgs(&c, &req) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("BAD_TRANSIT"));
        }
        other => panic!("add-path BadIntermediates inbound must be 12, got {other:?}"),
    }
}

#[test]
fn transited_cross_realm_renew_at_dest_is_server_nomatch() {
    let (_a, _b, c, ir, _host_c, bc) = three_realm();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut t = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t).expect("bc");
    part.transited.tr_type = 2;
    part.flags = part.flags.with_bit(flag_bit::RENEWABLE, true);
    part.renew_till = Some(part.endtime.add_hours(24).expect("renew_till"));
    part.authorization_data = None;
    reseal_mut(&mut t, &part, &ir);
    let req = TgsReqBuilder::new(
        t,
        &bc.session_key,
        "A.TEST",
        &cname,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]),
        "C.TEST",
        531,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::RENEW, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("renew tgs");
    match krb5_kdc::issue_tgs(&c, &req) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::SERVER_NOMATCH);
            assert_eq!(
                text.as_deref(),
                Some("SERVER DIDN'T MATCH TICKET FOR RENEW/FORWARD/ETC")
            );
        }
        other => panic!("cross-realm RENEW of krbtgt/C@B as krbtgt/C@C must be 26, got {other:?}"),
    }
}

#[test]
fn transited_non_add_overlong_forwarded() {
    let (mut store, _, _, hostn) = realm_store("A.TEST", "svc.a.test");
    store.policy.reject_bad_transit = false;
    let tgt = as_tgt(&store, "A.TEST", 520);
    let tgt_key = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut ticket = tgt.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&tgt_key, &ticket).expect("tgt");
    part.transited.tr_type = 1;
    part.transited.contents = OctetString::from(vec![b'A'; 512]);
    part.authorization_data = None;
    reseal_mut(&mut ticket, &part, &tgt_key);
    let out = chase_tgs(
        &store,
        ticket,
        &tgt.session_key,
        "A.TEST",
        hostn.clone(),
        "A.TEST",
        521,
    )
    .expect("non-add over-long + reject_bad_transit=false");
    let host_key = store
        .get_name(&hostn)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let issued = decrypt_ticket_part(&host_key, &out.rep.0.ticket).expect("enc");
    assert!(
        !issued.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "non-add expansion error must leave T off"
    );
    assert_eq!(
        issued.transited.contents.as_ref(),
        vec![b'A'; 512].as_slice(),
        "non-add must forward inbound bytes unchanged"
    );
}

#[test]
fn presented_tgt_decrypt_is_bound_to_ticket_realm() {
    let (_a, _b, mut c, _ab, bckey, host_c, bctgt) = three_realm_distinct();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let host_key = c.get_name(&host_c).unwrap().best_key().unwrap().key.clone();

    let honest = chase_tgs(
        &c,
        bctgt.rep.0.ticket.clone(),
        &bctgt.session_key,
        "A.TEST",
        host_c.clone(),
        "C.TEST",
        910,
    )
    .expect("honest B hop with capaths");
    let part = decrypt_ticket_part(&host_key, &honest.rep.0.ticket).expect("enc");
    assert!(
        part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "honest capaths must set T"
    );

    c.set_capaths(std::collections::BTreeMap::new());
    let (code, text) = tgs_code_text(chase_tgs(
        &c,
        bctgt.rep.0.ticket.clone(),
        &bctgt.session_key,
        "A.TEST",
        host_c.clone(),
        "C.TEST",
        911,
    ));
    assert_eq!(code, err::POLICY);
    assert_eq!(text.as_deref(), Some("BAD_TRANSIT"));

    for (nonce, claimed, want_code) in [
        (912, "A.TEST", err::S_PRINCIPAL_UNKNOWN),
        (913, "C.TEST", err::BAD_INTEGRITY),
        (914, "D.TEST", err::S_PRINCIPAL_UNKNOWN),
    ] {
        let t = reseal_empty_transited(&bckey, &bctgt.rep.0.ticket, claimed);
        let req = tgs_req(
            t,
            &bctgt.session_key,
            "A.TEST",
            &cname,
            host_c.clone(),
            "C.TEST",
            nonce,
        )
        .expect("tgs");
        let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
        assert_eq!(code, want_code, "forged ticket.realm={claimed}");
        assert_eq!(
            text.as_deref(),
            Some("PROCESS_TGS"),
            "forged ticket.realm={claimed}"
        );
    }
}

#[test]
fn tgs_local_sname_unknown_body_realm_is_get_local_tgt() {
    let (_a, _b, c, _ir, host_c, bc) = three_realm();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        bc.rep.0.ticket.clone(),
        &bc.session_key,
        "A.TEST",
        &cname,
        host_c.clone(),
        "GARBAGE.EXAMPLE",
        920,
    )
    .expect("tgs");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    assert_eq!(code, err::GENERIC);
    assert_eq!(text.as_deref(), Some("GET_LOCAL_TGT"));

    let tgt = as_tgt(&c, "C.TEST", 921);
    let req = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        "C.TEST",
        &cname,
        host_c,
        "GARBAGE.EXAMPLE",
        922,
    )
    .expect("tgs");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    assert_eq!(code, err::GENERIC);
    assert_eq!(text.as_deref(), Some("GET_LOCAL_TGT"));
}

#[test]
fn tgs_huge_body_realm_is_get_local_tgt_quickly() {
    let (_a, _b, c, _ir, host_c, bc) = three_realm();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let big = format!("{}A.TEST", "A.".repeat(30_000));
    let req = tgs_req(
        bc.rep.0.ticket.clone(),
        &bc.session_key,
        "A.TEST",
        &cname,
        host_c,
        &big,
        923,
    )
    .expect("tgs");
    let t0 = std::time::Instant::now();
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    let elapsed = t0.elapsed();
    assert_eq!(code, err::GENERIC);
    assert_eq!(text.as_deref(), Some("GET_LOCAL_TGT"));
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "60 KiB body.realm took {elapsed:?}"
    );
}

#[test]
fn tgs_renew_at_dest_issuer_realm_is_get_local_tgt() {
    let (a, b, mut c, _ab, _bc, host_c, _bctgt) = three_realm_distinct();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = as_tgt_renewable(&a, "A.TEST", 970);
    let ren = KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true);
    let ab = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        "A.TEST",
        &cname,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "B.TEST"]),
        "A.TEST",
        971,
    )
    .options(ren.clone())
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("ab");
    let ab = krb5_kdc::issue_tgs(&a, &ab).expect("A->B");
    let bc = TgsReqBuilder::new(
        ab.rep.0.ticket.clone(),
        &ab.session_key,
        "A.TEST",
        &cname,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]),
        "B.TEST",
        972,
    )
    .options(ren)
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("bc");
    let bc = krb5_kdc::issue_tgs(&b, &bc).expect("B->C");
    c.set_capaths(std::collections::BTreeMap::new());
    let honest = tgs_req(
        bc.rep.0.ticket.clone(),
        &bc.session_key,
        "A.TEST",
        &cname,
        host_c.clone(),
        "C.TEST",
        973,
    )
    .expect("tgs");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &honest));
    assert_eq!(code, err::POLICY);
    assert_eq!(text.as_deref(), Some("BAD_TRANSIT"));
    let renew = TgsReqBuilder::new(
        bc.rep.0.ticket.clone(),
        &bc.session_key,
        "A.TEST",
        &cname,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]),
        "B.TEST",
        974,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::RENEW, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("renew");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &renew));
    assert_eq!(code, err::GENERIC);
    assert_eq!(text.as_deref(), Some("GET_LOCAL_TGT"));
}

#[test]
fn tgs_non_ascii_ticket_realm_is_process_tgs() {
    let (_a, _b, c, _ir, host_c, bc) = three_realm();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let der = [0x1bu8, 0x02, 0xC3, 0xA9];
    let realm: krb5_types::Realm = decode(&der).expect("rasn GeneralString C3A9");
    let mut t = bc.rep.0.ticket.clone();
    t.realm = realm;
    let req = tgs_req(t, &bc.session_key, "A.TEST", &cname, host_c, "C.TEST", 940).expect("tgs");
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        krb5_kdc::issue_tgs(&c, &req)
    }))
    .expect("non-ASCII ticket.realm must not panic");
    let (code, text) = tgs_code_text(res);
    assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
}

#[test]
fn tgs_lineage_local_user_on_foreign_tgt_is_policy() {
    let (_a, _b, mut c, _ab, bckey, host_c, bctgt) = three_realm_distinct();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut t = bctgt.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&bckey, &t).expect("bc");
    part.crealm = krb5_types::try_ascii("C.TEST").expect("realm");
    part.authorization_data = None;
    reseal_mut(&mut t, &part, &bckey);
    for lax in [false, true] {
        c.policy.reject_bad_transit = !lax;
        let req = tgs_req(
            t.clone(),
            &bctgt.session_key,
            "C.TEST",
            &cname,
            host_c.clone(),
            "C.TEST",
            if lax { 951 } else { 950 },
        )
        .expect("tgs");
        let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
        assert_eq!(code, err::POLICY, "reject_bad_transit={}", !lax);
        assert_eq!(
            text.as_deref(),
            Some("INVALID LINEAGE"),
            "reject_bad_transit={}",
            !lax
        );
    }
}

#[test]
fn tgs_krbtgt_disallow_all_tix_is_process_tgs() {
    let (_a, _b, mut c, _ab, _bc, host_c, bctgt) = three_realm_distinct();
    let irn = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]);
    let a = c.get_in_realm(&irn, "B.TEST").unwrap().attributes | KDB_DISALLOW_ALL_TIX;
    c.apply_admin_fields_in(
        &irn,
        "B.TEST",
        Some(a),
        None,
        None,
        None,
        None,
        false,
        None,
        "kadmin/admin@B.TEST",
    )
    .unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        bctgt.rep.0.ticket.clone(),
        &bctgt.session_key,
        "A.TEST",
        &cname,
        host_c,
        "C.TEST",
        980,
    )
    .expect("tgs");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
}

#[test]
fn tgs_local_krbtgt_disallow_all_tix_is_process_tgs() {
    let (mut store, _, _, host) = realm_store("C.TEST", "svc.c.test");
    let tgt = as_tgt(&store, "C.TEST", 981);
    let krbtgt = PrincipalName::krbtgt("C.TEST");
    let a = store.get_name(&krbtgt).unwrap().attributes | KDB_DISALLOW_ALL_TIX;
    store
        .apply_admin_fields(&krbtgt, Some(a), None, None, None, None, false, None)
        .unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        "C.TEST",
        &cname,
        host,
        "C.TEST",
        982,
    )
    .expect("tgs");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&store, &req));
    assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
}

#[test]
fn tgs_local_krbtgt_disallow_svr_is_process_tgs() {
    let (mut store, _, _, host) = realm_store("C.TEST", "svc.c.test");
    let tgt = as_tgt(&store, "C.TEST", 983);
    let krbtgt = PrincipalName::krbtgt("C.TEST");
    let a = store.get_name(&krbtgt).unwrap().attributes | KDB_DISALLOW_SVR;
    store
        .apply_admin_fields(&krbtgt, Some(a), None, None, None, None, false, None)
        .unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        "C.TEST",
        &cname,
        host,
        "C.TEST",
        984,
    )
    .expect("tgs");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&store, &req));
    assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
}

#[test]
fn tgs_cross_krbtgt_disallow_svr_is_process_tgs() {
    let (_a, _b, mut c, _ab, _bc, host_c, bctgt) = three_realm_distinct();
    let irn = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]);
    let a = c.get_in_realm(&irn, "B.TEST").unwrap().attributes | KDB_DISALLOW_SVR;
    c.apply_admin_fields_in(
        &irn,
        "B.TEST",
        Some(a),
        None,
        None,
        None,
        None,
        false,
        None,
        "kadmin/admin@B.TEST",
    )
    .unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        bctgt.rep.0.ticket.clone(),
        &bctgt.session_key,
        "A.TEST",
        &cname,
        host_c,
        "C.TEST",
        985,
    )
    .expect("tgs");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
}

#[test]
fn transited_renew_at_dest_mismatched_realm_is_26() {
    let (_a, _b, c, ir, _host_c, bc) = three_realm();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut t = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t).expect("bc");
    part.transited.tr_type = 1;
    part.transited.contents = OctetString::from(
        std::iter::repeat_n("A".repeat(100), 5)
            .collect::<Vec<_>>()
            .join(",")
            .into_bytes(),
    );
    part.flags = part.flags.with_bit(flag_bit::RENEWABLE, true);
    part.renew_till = Some(part.endtime.add_hours(24).expect("renew_till"));
    part.authorization_data = None;
    reseal_mut(&mut t, &part, &ir);
    let req = TgsReqBuilder::new(
        t,
        &bc.session_key,
        "A.TEST",
        &cname,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]),
        "C.TEST",
        930,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::RENEW, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("renew tgs");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    assert_eq!(code, err::SERVER_NOMATCH);
    assert_eq!(
        text.as_deref(),
        Some("SERVER DIDN'T MATCH TICKET FOR RENEW/FORWARD/ETC")
    );
}

#[test]
fn anonymous_crealm_skips_transited_parse() {
    let (_a, _b, c, ir, host_c, bc) = three_realm();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut t = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t).expect("bc");
    part.crealm = krb5_types::try_ascii("WELLKNOWN:ANONYMOUS").expect("anon");
    part.transited.tr_type = 1;
    part.transited.contents = OctetString::from(b",".to_vec());
    part.authorization_data = None;
    reseal_mut(&mut t, &part, &ir);
    let req = tgs_req(
        t,
        &bc.session_key,
        "WELLKNOWN:ANONYMOUS",
        &cname,
        host_c,
        "C.TEST",
        931,
    )
    .expect("tgs");
    krb5_kdc::issue_tgs(&c, &req)
        .expect("anonymous crealm must not POLICY on unexpandable transited");
}

#[test]
fn cross_realm_pac_drops_local_domain_sids_keeps_foreign() {
    use krb5_kdc::{PacTicket, pac_from_ticket_part, sign_pac, wrap_win2k_pac};
    use krb5_types::pac::{
        ExtraSid, KerbValidationInfo, PAC_LOGON_INFO, Pac, PacIdentity, RpcSid,
        parse_kerb_validation_info,
    };

    let (_a, _b, mut c, ir, host_c, bc) = three_realm();
    c.policy.reject_bad_transit = false;
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let local = c.domain_sid().clone();
    let foreign = RpcSid::nt_domain(4242, 4243, 4244);
    let admins = local.with_rid(512); // local "Domain Admins" the foreign realm forged
    let wellknown = RpcSid::from_sddl("S-1-18-1").expect("wk"); // asserted-identity, kept
    let foreign_grp = foreign.with_rid(1106); // the trusted realm's own group, kept

    let mut kvi = KerbValidationInfo::for_client(TEST_USER, "B.TEST", &foreign, 1105);
    kvi.extra_sids = vec![
        ExtraSid {
            sid: admins.clone(),
            attributes: 7,
        },
        ExtraSid {
            sid: wellknown.clone(),
            attributes: 7,
        },
        ExtraSid {
            sid: foreign_grp.clone(),
            attributes: 7,
        },
    ];
    let logon = kvi.to_ndr();
    let ident = PacIdentity {
        sam: TEST_USER.to_owned(),
        realm: "B.TEST".to_owned(),
        domain_sid: foreign.clone(),
        rid: 1105,
    };
    let mut t = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t).expect("bc");
    part.cname = cname.clone();
    part.crealm = krb5_types::try_ascii("B.TEST").expect("realm");
    let pac = sign_pac(
        &cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: &ir,
            kdc: &ir,
            enc_tkt_der: &[0],
            is_service_tkt: false,
        },
        &ident,
        Some(&logon),
    )
    .expect("sign");
    part.authorization_data = Some(wrap_win2k_pac(&pac).expect("wrap"));
    reseal_mut(&mut t, &part, &ir);

    let req = tgs_req(
        t,
        &bc.session_key,
        "B.TEST",
        &cname,
        host_c.clone(),
        "C.TEST",
        991,
    )
    .expect("tgs");
    let out = krb5_kdc::issue_tgs(&c, &req).expect("cross-realm reissue");

    let host_key = c.get_name(&host_c).unwrap().best_key().unwrap().key.clone();
    let re_part = decrypt_ticket_part(&host_key, &out.rep.0.ticket).expect("svc enc");
    let re_pac = pac_from_ticket_part(&re_part).expect("reissued PAC");
    let re_logon =
        parse_kerb_validation_info(Pac::parse(&re_pac).unwrap().buffer(PAC_LOGON_INFO).unwrap())
            .expect("reissued NDR");

    assert_eq!(re_logon.logon_domain_id, foreign, "foreign base kept");
    assert!(
        !re_logon.extra_sids.iter().any(|e| e.sid == admins),
        "forged local Domain Admins must be filtered: {:?}",
        re_logon.extra_sids
    );
    assert!(
        re_logon.extra_sids.iter().any(|e| e.sid == wellknown),
        "well-known S-1-18-1 kept"
    );
    assert!(
        re_logon.extra_sids.iter().any(|e| e.sid == foreign_grp),
        "foreign realm's own SID kept"
    );
}

#[test]
fn cross_realm_pac_claiming_local_domain_base_is_policy() {
    use krb5_kdc::{PacTicket, sign_pac, wrap_win2k_pac};
    use krb5_types::pac::{KerbValidationInfo, PacIdentity};

    let (_a, _b, mut c, ir, host_c, bc) = three_realm();
    c.policy.reject_bad_transit = false;
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let local = c.domain_sid().clone();
    let kvi = KerbValidationInfo::for_client(TEST_USER, "B.TEST", &local, 500);
    let logon = kvi.to_ndr();
    let ident = PacIdentity {
        sam: TEST_USER.to_owned(),
        realm: "B.TEST".to_owned(),
        domain_sid: local.clone(),
        rid: 500,
    };
    let mut t = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t).expect("bc");
    part.cname = cname.clone();
    part.crealm = krb5_types::try_ascii("B.TEST").expect("realm");
    let pac = sign_pac(
        &cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: &ir,
            kdc: &ir,
            enc_tkt_der: &[0],
            is_service_tkt: false,
        },
        &ident,
        Some(&logon),
    )
    .expect("sign");
    part.authorization_data = Some(wrap_win2k_pac(&pac).expect("wrap"));
    reseal_mut(&mut t, &part, &ir);
    let req = tgs_req(t, &bc.session_key, "B.TEST", &cname, host_c, "C.TEST", 992).expect("tgs");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    assert_eq!(code, err::POLICY);
    assert_eq!(text.as_deref(), Some("INVALID LINEAGE"));
}

#[test]
fn tgs_service_deny_opts_precedes_deny_all() {
    use krb5_kdc::KDB_DISALLOW_POSTDATED;
    let (mut store, _, _, host) = realm_store("C.TEST", "svc.c.test");
    let a =
        store.get_name(&host).unwrap().attributes | KDB_DISALLOW_ALL_TIX | KDB_DISALLOW_POSTDATED;
    store
        .apply_admin_fields(&host, Some(a), None, None, None, None, false, None)
        .unwrap();
    let tgt = as_tgt_may_postdate(&store, "C.TEST", 973);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        "C.TEST",
        &cname,
        host.clone(),
        "C.TEST",
        974,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::MAY_POSTDATE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("tgs");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&store, &req));
    assert_eq!(code, err::CANNOT_POSTDATE, "deny_opts (postdate) wins");
    assert_eq!(text.as_deref(), Some("NON-POSTDATABLE TICKET"));
}

fn user_key() -> ProtocolKey {
    password_key(TEST_USER, TEST_USER_PASSWORD)
}

fn two_realm_pac_stores() -> (PrincipalStore, PrincipalStore, ProtocolKey, PrincipalName) {
    let (mut local, acl_a) = bootstrap_documented().expect("local");
    local.set_domain_sid(RpcSid::nt_domain(9, 8, 7));
    let mut foreign = PrincipalStore::bootstrap(
        "OTHER.TEST",
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
    )
    .expect("foreign");
    foreign.set_domain_sid(RpcSid::nt_domain(11, 12, 13));
    let actor_b = format!("{TEST_ADMIN}@OTHER.TEST");
    let acl_b = Acl::allow_admin(&actor_b).expect("acl");
    let host_b = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.other.test"]);
    foreign
        .create_host(&acl_b, &actor_b, &host_b)
        .expect("host");
    let ir =
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32]).expect("ir key");
    local
        .create_interrealm_key(&acl_a, &documented_admin_id(), "OTHER.TEST", ir.clone())
        .expect("A→B");
    foreign
        .create_interrealm_key(&acl_b, &actor_b, TEST_REALM, ir.clone())
        .expect("B→A");
    (local, foreign, ir, host_b)
}

fn referral_from_local(local: &PrincipalStore, nonce: u32) -> (krb5_kdc::IssuedTgs, PrincipalName) {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_password(local, TEST_USER, TEST_USER_PASSWORD, nonce);
    let other = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "OTHER.TEST"]);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        other.clone(),
        TEST_REALM,
        nonce + 1,
    )
    .expect("referral TGS-REQ");
    (
        krb5_kdc::issue_tgs(local, &tgs).expect("referral TGS"),
        cname,
    )
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

fn flip_pac_sig(part: &mut EncTicketPart, kind: u32) {
    let pac = pac_from_ticket_part(part).expect("PAC");
    let mut parsed = Pac::parse(&pac).expect("parse");
    let buf = parsed
        .buffers
        .iter_mut()
        .find(|b| b.kind == kind)
        .expect("sig buffer");
    assert!(buf.data.len() > 4, "MAC bytes");
    buf.data[4] ^= 0xff;
    part.authorization_data = Some(wrap_win2k_pac(&parsed.to_bytes()).expect("wrap"));
}

#[test]
fn interrealm_issue_key_is_not_the_peer_accept_key() {
    // Windows TDO inbound/outbound AES keys differ by salt. Issue toward
    // AD with the inbound key; still decrypt AD-issued referrals with the
    // outbound key.
    let issue_bytes = [0x11u8; 32];
    let accept_bytes = [0x22u8; 32];
    let issue_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &issue_bytes)
            .expect("issue key");
    let accept_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &accept_bytes)
            .expect("accept key");
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm_key(&acl, &documented_admin_id(), "AD.KERBER.TEST", issue_key)
        .expect("issue");
    store
        .set_interrealm_decrypt_key(&acl, &documented_admin_id(), "AD.KERBER.TEST", accept_key)
        .expect("accept");
    let ir_name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "AD.KERBER.TEST"]);
    let ir = store.get_name(&ir_name).expect("ir");
    assert_eq!(ir.keys.len(), 1);
    assert_eq!(
        ir.best_key().unwrap().key.as_bytes(),
        issue_bytes.as_slice(),
        "TGS issue must use the inbound AD key"
    );
    let incoming_id = krb5_kdc::lookup_principal_id(
        &PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", TEST_REALM]),
        "AD.KERBER.TEST",
    );
    let incoming = store.get(&incoming_id).expect("incoming trust");
    assert_eq!(incoming.realm, "AD.KERBER.TEST");
    assert!(
        incoming
            .keys
            .iter()
            .any(|k| k.key.as_bytes() == accept_bytes)
    );
    assert!(
        !incoming
            .keys
            .iter()
            .any(|k| k.key.as_bytes() == issue_bytes)
    );
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 81);
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        ir_name,
        TEST_REALM,
        82,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("AD referral TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("AD referral TGS");
    let issue_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &issue_bytes)
            .unwrap();
    let accept_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &accept_bytes)
            .unwrap();
    decrypt_ticket_part(&issue_key, &out.rep.0.ticket).expect("issue key must open the referral");
    assert!(
        decrypt_ticket_part(&accept_key, &out.rep.0.ticket).is_err(),
        "peer accept key must not open tickets we issue toward AD"
    );
    let part = decrypt_ticket_part(&issue_key, &out.rep.0.ticket).unwrap();
    let pac = pac_from_ticket_part(&part).expect("referral TGT must carry a PAC");
    let parsed = krb5_types::pac::Pac::parse(&pac).expect("PAC");
    let logon =
        parse_kerb_validation_info(parsed.buffer(PAC_LOGON_INFO).expect("logon")).expect("NDR");
    assert_ne!(
        logon.logon_domain_id.to_sddl(),
        krb5_types::pac::RpcSid::dummy_domain().to_sddl()
    );
    let der = ticket_checksum_der(&part).expect("der");
    verify_pac_signatures(&pac, &issue_key, Some(&issue_key), Some(&der), false)
        .expect("referral PAC signed with inter-realm key");
}

#[test]
fn same_realm_ticket_sets_transited_policy_checked() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 70);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let tgt_part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("tgt");
    assert!(
        !tgt_part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "AS-REP TGT must not set TRANSITED-POLICY-CHECKED"
    );
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        71,
    )
    .expect("tgs");
    let out = krb5_kdc::issue_tgs(&store, &tgt).expect("issue");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part = decrypt_ticket_part(&host.key, &out.rep.0.ticket).expect("enc");
    assert!(
        part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "same-realm TGS must set TRANSITED-POLICY-CHECKED when the check ran"
    );

    let skip_opts = KdcOptions::forwardable().with_bit(flag_bit::DISABLE_TRANSITED_CHECK, true);
    let skip = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        72,
    )
    .options(skip_opts.clone())
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("tgs skip");
    match krb5_kdc::issue_tgs(&store, &skip) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("BAD_TRANSIT"));
        }
        other => panic!("skip + default must be POLICY (12), got {other:?}"),
    }

    let mut as_renew = as_req(
        cname.clone(),
        TEST_REALM,
        73,
        Some(vec![pa_enc_timestamp(&user_key()).expect("pa")]),
    )
    .unwrap();
    as_renew.0.req_body.kdc_options = as_renew
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    let issued_r = krb5_kdc::issue_as(&store, &as_renew).expect("AS renewable");
    let as_part = decrypt_ticket_part(
        &store.krbtgt().unwrap().best_key().unwrap().key,
        &issued_r.rep.0.ticket,
    )
    .expect("as tgt");
    assert!(
        !as_part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "AS TGT is the non-T negative control"
    );
    assert!(as_part.flags.renewable());
    let renew_non_t = TgsReqBuilder::new(
        issued_r.rep.0.ticket.clone(),
        &issued_r.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        78,
    )
    .options(
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEW, true)
            .with_bit(flag_bit::DISABLE_TRANSITED_CHECK, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("renew non-T skip");
    match krb5_kdc::issue_tgs(&store, &renew_non_t) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("BAD_TRANSIT"));
        }
        other => panic!("RENEW of a non-T ticket + skip must be POLICY, got {other:?}"),
    }
    let tgs_tgt = TgsReqBuilder::new(
        issued_r.rep.0.ticket.clone(),
        &issued_r.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        74,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("tgs tgt");
    let tgs_tgt_out = krb5_kdc::issue_tgs(&store, &tgs_tgt).expect("TGS TGT");
    let tgt_key = store.krbtgt().unwrap().best_key().unwrap();
    let tgs_tgt_part = decrypt_ticket_part(&tgt_key.key, &tgs_tgt_out.rep.0.ticket).expect("enc");
    assert!(
        tgs_tgt_part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "same-realm TGS TGT must carry T before RENEW+skip"
    );
    assert!(tgs_tgt_part.flags.renewable());
    let renew_skip = TgsReqBuilder::new(
        tgs_tgt_out.rep.0.ticket.clone(),
        &tgs_tgt_out.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        75,
    )
    .options(
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEW, true)
            .with_bit(flag_bit::DISABLE_TRANSITED_CHECK, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("renew skip");
    let renewed = krb5_kdc::issue_tgs(&store, &renew_skip).expect("RENEW skip inherits T");
    let renewed_part = decrypt_ticket_part(&tgt_key.key, &renewed.rep.0.ticket).expect("enc renew");
    assert!(
        renewed_part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "RENEW of a T ticket + skip must keep T"
    );

    let (mut lax_store, _) = bootstrap_documented().expect("lax");
    lax_store.policy.reject_bad_transit = false;
    let issued_lax = issue_tgt_password(&lax_store, TEST_USER, TEST_USER_PASSWORD, 76);
    let skip_lax = TgsReqBuilder::new(
        issued_lax.rep.0.ticket.clone(),
        &issued_lax.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        77,
    )
    .options(skip_opts)
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("tgs skip lax");
    let skipped =
        krb5_kdc::issue_tgs(&lax_store, &skip_lax).expect("skip + reject_bad_transit=false");
    let lax_host = lax_store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let skip_part = decrypt_ticket_part(&lax_host.key, &skipped.rep.0.ticket).expect("enc skip");
    assert!(
        !skip_part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "skip + reject_bad_transit=false must leave T off"
    );
}

#[test]
fn tgs_copies_foreign_referral_pac_identity() {
    let (local, foreign, ir, host_b) = two_realm_pac_stores();
    assert_ne!(local.domain_sid().to_sddl(), foreign.domain_sid().to_sddl());
    let (referral, cname) = referral_from_local(&local, 9100);
    let ref_part = decrypt_ticket_part(&ir, &referral.rep.0.ticket).expect("referral enc");
    let ref_pac = pac_from_ticket_part(&ref_part).expect("referral PAC");
    let ref_logon = parse_kerb_validation_info(
        Pac::parse(&ref_pac)
            .expect("PAC")
            .buffer(PAC_LOGON_INFO)
            .expect("logon"),
    )
    .expect("NDR");
    assert_eq!(
        ref_logon.logon_domain_id.to_sddl(),
        local.domain_sid().to_sddl()
    );

    let tgs = tgs_req(
        referral.rep.0.ticket.clone(),
        &referral.session_key,
        TEST_REALM,
        &cname,
        host_b.clone(),
        "OTHER.TEST",
        9102,
    )
    .expect("foreign TGS-REQ");
    let out = krb5_kdc::issue_tgs(&foreign, &tgs).expect("foreign TGS");
    let host_key = foreign.get_name(&host_b).unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&host_key.key, &out.rep.0.ticket).expect("svc");
    let pac = pac_from_ticket_part(&part).expect("svc PAC");
    let logon = parse_kerb_validation_info(
        Pac::parse(&pac)
            .expect("PAC")
            .buffer(PAC_LOGON_INFO)
            .expect("logon"),
    )
    .expect("NDR");
    assert_eq!(logon.user_id, ref_logon.user_id);
    assert_eq!(
        logon.logon_domain_id.to_sddl(),
        local.domain_sid().to_sddl(),
        "issued PAC must keep the foreign LOGON_INFO SID, not the local store SID"
    );
    assert_ne!(
        logon.logon_domain_id.to_sddl(),
        foreign.domain_sid().to_sddl()
    );
    assert_ne!(
        logon.logon_domain_id.to_sddl(),
        RpcSid::dummy_domain().to_sddl()
    );
}

#[test]
fn tgs_rejects_corrupt_foreign_referral_pac() {
    let (local, foreign, ir, host_b) = two_realm_pac_stores();
    let (referral, cname) = referral_from_local(&local, 9200);
    let mut part = decrypt_ticket_part(&ir, &referral.rep.0.ticket).expect("referral enc");
    flip_pac_sig(&mut part, PAC_SERVER_CHECKSUM);
    let bad_server = rewrap_ticket(&referral.rep.0.ticket, &part, &ir);
    let tgs = tgs_req(
        bad_server,
        &referral.session_key,
        TEST_REALM,
        &cname,
        host_b.clone(),
        "OTHER.TEST",
        9202,
    )
    .expect("TGS-REQ");
    match krb5_kdc::issue_tgs(&foreign, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::MODIFIED),
        other => panic!("corrupt server checksum must fail, got {other:?}"),
    }

    let mut part7 = decrypt_ticket_part(&ir, &referral.rep.0.ticket).expect("referral enc");
    flip_pac_sig(&mut part7, PAC_PRIVSVR_CHECKSUM);
    let bad_7 = rewrap_ticket(&referral.rep.0.ticket, &part7, &ir);
    let tgs7 = tgs_req(
        bad_7,
        &referral.session_key,
        TEST_REALM,
        &cname,
        host_b,
        "OTHER.TEST",
        9203,
    )
    .expect("TGS-REQ");
    krb5_kdc::issue_tgs(&foreign, &tgs7).expect(
        "only the server signature of a TGS-principal ticket is checked (kdc_util.c:597-602)",
    );
}
