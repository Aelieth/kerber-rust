//! Capaths transited check on the shipped `issue_tgs` path.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_kdc::{
    Acl, Error, PrincipalStore, TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_USER, TEST_USER_PASSWORD,
    as_req, decrypt_ticket_part, pa_enc_timestamp, tgs_req,
};
use krb5_protocol::{pa_for_user, tgs_req_ex};
use krb5_types::{
    EncTicketPart, KdcOptions, OctetString, PrincipalName, Ticket, err, flag_bit, ku,
};

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
    let acl = Acl::allow_admin(&actor);
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
    let skip_req = tgs_req_ex(
        bc.rep.0.ticket.clone(),
        &bc.session_key,
        "A.TEST",
        &cname,
        host_c.clone(),
        "C.TEST",
        406,
        KdcOptions::forwardable().with_bit(flag_bit::DISABLE_TRANSITED_CHECK, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
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

fn reseal(key: &ProtocolKey, ticket: &mut Ticket, part: &EncTicketPart) {
    let der = encode(part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let cipher = encrypt(key, usage, &der).unwrap();
    ticket.enc_part.cipher = OctetString::from(cipher);
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

#[test]
fn transited_add_path_type_and_ill_formed() {
    let (_a, _b, mut c, ir, host_c, bc) = three_realm();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);

    let mut t2 = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t2).expect("bc");
    part.transited.tr_type = 2;
    part.authorization_data = None;
    reseal(&ir, &mut t2, &part);
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
    reseal(&ir, &mut tlong, &part);
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
    reseal(&ir, &mut t, &part);
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
fn transited_cross_realm_renew_at_dest_checks_tr_type() {
    let (_a, _b, c, ir, _host_c, bc) = three_realm();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut t = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t).expect("bc");
    part.transited.tr_type = 2;
    part.flags = part.flags.with_bit(flag_bit::RENEWABLE, true);
    part.renew_till = Some(part.endtime.add_hours(24).expect("renew_till"));
    part.authorization_data = None;
    reseal(&ir, &mut t, &part);
    let req = tgs_req_ex(
        t,
        &bc.session_key,
        "A.TEST",
        &cname,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]),
        "B.TEST",
        531,
        KdcOptions::forwardable().with_bit(flag_bit::RENEW, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .expect("renew tgs");
    match krb5_kdc::issue_tgs(&c, &req) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::TRTYPE_NOSUPP);
            assert_eq!(text.as_deref(), Some("VALIDATE_TRANSIT_TYPE"));
        }
        other => panic!("cross-realm RENEW at dest with tr_type≠1 must be 17, got {other:?}"),
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
    reseal(&tgt_key, &mut ticket, &part);
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
    reseal(key, &mut t, &part);
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
fn tgs_local_sname_unknown_body_realm_is_looking_up_server() {
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
    assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("LOOKING_UP_SERVER"));

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
    assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("LOOKING_UP_SERVER"));
}

#[test]
fn tgs_huge_body_realm_is_looking_up_server_quickly() {
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
    assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("LOOKING_UP_SERVER"));
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "60 KiB body.realm took {elapsed:?}"
    );
}

#[test]
fn transited_renew_at_dest_five_hundred_byte_add_path_is_43() {
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
    reseal(&ir, &mut t, &part);
    let req = tgs_req_ex(
        t,
        &bc.session_key,
        "A.TEST",
        &cname,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]),
        "B.TEST",
        930,
        KdcOptions::forwardable().with_bit(flag_bit::RENEW, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .expect("renew tgs");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    assert_eq!(code, err::ILL_CR_TKT);
    assert_eq!(text.as_deref(), Some("ADD_TO_TRANSITED_LIST"));
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
    reseal(&ir, &mut t, &part);
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
fn s4u2self_referral_names_header_client() {
    let (a, b, _c, ir, _host_c, _bc) = three_realm();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = as_tgt(&a, "A.TEST", 980);
    let ab = chase_tgs(
        &a,
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        "A.TEST",
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "B.TEST"]),
        "A.TEST",
        981,
    )
    .expect("A B");
    let pa = pa_for_user(&ab.session_key, admin, "A.TEST").expect("PA-FOR-USER");
    let req = tgs_req_ex(
        ab.rep.0.ticket.clone(),
        &ab.session_key,
        "A.TEST",
        &user,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]),
        "B.TEST",
        982,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .expect("s4u referral");
    let out = krb5_kdc::issue_tgs(&b, &req).expect("cross S4U referral");
    let part = decrypt_ticket_part(&ir, &out.rep.0.ticket).expect("enc");
    assert_eq!(part.cname.components_joined(), TEST_USER);
    assert_eq!(
        std::str::from_utf8(part.crealm.as_bytes()).unwrap(),
        "A.TEST"
    );
}

#[test]
fn s4u2self_cross_tgt_local_user_local_server_is_not_cross_realm() {
    let (_a, _b, c, ir, host_c, bc) = three_realm();
    let mut t = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t).expect("bc");
    part.cname = host_c.clone();
    part.crealm = krb5_types::try_ascii("C.TEST").expect("realm");
    part.authorization_data = None;
    reseal(&ir, &mut t, &part);
    let local = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let pa = pa_for_user(&bc.session_key, local, "C.TEST").expect("PA-FOR-USER");
    let req = tgs_req_ex(
        t,
        &bc.session_key,
        "C.TEST",
        &host_c,
        host_c.clone(),
        "C.TEST",
        983,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .expect("s4u");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    assert_eq!(code, err::C_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("NOT_CROSS_REALM_REQUEST"));
}
