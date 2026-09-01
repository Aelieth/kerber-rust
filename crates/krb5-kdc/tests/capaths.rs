//! Capaths transited check on the shipped `issue_tgs` path.

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::{
    Acl, Error, PrincipalStore, TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_USER, TEST_USER_PASSWORD,
    as_req, decrypt_ticket_part, pa_enc_timestamp, tgs_req,
};
use krb5_types::{PrincipalName, err, flag_bit};

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
    let skey = c.get_name(&host_c).unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&skey.key, &host.rep.0.ticket).expect("enc");
    assert!(
        part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "T set only when capaths check passed"
    );
    let hops = part.transited.realms();
    assert_eq!(hops, vec!["B.TEST".to_string()]);
    let contents = String::from_utf8(part.transited.contents.as_ref().to_vec()).unwrap();
    assert_eq!(contents, "B.TEST");
    assert_eq!(part.transited.tr_type, 1);

    c.set_capaths(std::collections::BTreeMap::new());
    let denied = chase_tgs(
        &c,
        bc.rep.0.ticket.clone(),
        &bc.session_key,
        "A.TEST",
        host_c,
        "C.TEST",
        404,
    );
    match denied {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::PATH_NOT_ACCEPTED),
        other => panic!("expected PATH_NOT_ACCEPTED, got {other:?}"),
    }
}
