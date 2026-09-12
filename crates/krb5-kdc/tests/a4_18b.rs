//! A′-4 item 18 units that need `domain_realm` / host-based knobs.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt, string_to_key};
use krb5_kdc::{
    Acl, Error, PacTicket, PrincipalStore, S2K_ITERS, TEST_ADMIN, TEST_REALM, TEST_USER,
    TEST_USER_PASSWORD, as_req, bootstrap_documented, decrypt_ticket_part, documented_admin_id,
    documented_host, pa_enc_timestamp, pac_from_ticket_part, sign_reply_pac, ticket_checksum_der,
    wrap_win2k_pac,
};
use krb5_protocol::{pa_for_user, pa_pac_options, tgs_req, tgs_req_ex};
use krb5_types::pac::{
    PAC_CLIENT_INFO, Pac, PacBuffer, PacIdentity, RpcSid, client_info_buffer, parse_client_info,
};
use krb5_types::{
    EncTicketPart, EncryptedData, KdcOptions, PrincipalName, Ticket, err, flag_bit, ku,
};

fn password_key(name: &str, password: &[u8]) -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        password,
        &cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k")
}

fn pref_etypes() -> Vec<i32> {
    EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn issue_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = password_key(TEST_USER, TEST_USER_PASSWORD);
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).expect("AS")
}

fn other_store(store: &mut PrincipalStore, acl: &Acl) {
    store
        .create_interrealm(
            acl,
            &documented_admin_id(),
            "OTHER.TEST",
            b"interrealm-secret",
        )
        .expect("interrealm");
    store
        .policy
        .domain_realm
        .insert(".other.test".into(), "OTHER.TEST".into());
}

fn canon() -> KdcOptions {
    KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true)
}

fn tgs_for(
    store: &PrincipalStore,
    sname: PrincipalName,
    opts: KdcOptions,
    nonce: u32,
) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(store, nonce);
    tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &cname,
        sname,
        TEST_REALM,
        nonce + 1,
        opts,
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("TGS-REQ")
}

#[test]
fn a4_18_host_fqdn_canonicalize_issues_referral() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    other_store(&mut store, &acl);
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.other.test"]);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, 1810);
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &cname,
        host,
        TEST_REALM,
        1811,
        canon(),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("host referral");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/OTHER.TEST"
    );
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART).unwrap();
    let plain = decrypt(&tgt.session_key, usage, out.rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = krb5_asn1::decode_enc_kdc_rep_part(&plain).expect("EncTgsRepPart");
    assert_eq!(enc.sname.components_joined(), "krbtgt/OTHER.TEST");
}

#[test]
fn a4_18_referral_no_dot_is_looking_up_server() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    other_store(&mut store, &acl);
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "nodot"]);
    let tgs = tgs_for(&store, host, canon(), 1820);
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
            assert_eq!(text.as_deref(), Some("LOOKING_UP_SERVER"));
        }
        other => panic!("expected LOOKING_UP_SERVER, got {other:?}"),
    }
}

#[test]
fn a4_18_nt_unknown_needs_host_based_services() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    other_store(&mut store, &acl);
    let host = PrincipalName::new(PrincipalName::NT_UNKNOWN, ["host", "x.other.test"]);
    let tgs = tgs_for(&store, host.clone(), canon(), 1830);
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::S_PRINCIPAL_UNKNOWN),
        other => panic!("expected 7, got {other:?}"),
    }
    store.policy.host_based_services = "host".into();
    let tgs = tgs_for(&store, host, canon(), 1832);
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("NT-UNKNOWN referral");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/OTHER.TEST"
    );
}

#[test]
fn a4_18_no_host_referral_star_blocks() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    other_store(&mut store, &acl);
    store.policy.no_host_referral = "*".into();
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.other.test"]);
    let tgs = tgs_for(&store, host, canon(), 1840);
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
            assert_eq!(text.as_deref(), Some("LOOKING_UP_SERVER"));
        }
        other => panic!("expected LOOKING_UP_SERVER, got {other:?}"),
    }
}

#[test]
fn a4_18_renew_skips_alternate_tgs() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    other_store(&mut store, &acl);
    let mut hops = std::collections::BTreeMap::new();
    hops.insert("FAR.TEST".into(), vec!["OTHER.TEST".into()]);
    let mut capaths = std::collections::BTreeMap::new();
    capaths.insert(TEST_REALM.into(), hops);
    store.set_capaths(capaths);
    let far = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "FAR.TEST"]);
    let opts = KdcOptions::forwardable()
        .with_bit(flag_bit::CANONICALIZE, true)
        .with_bit(flag_bit::RENEW, true);
    let tgs = tgs_for(&store, far, opts, 1850);
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
            assert_eq!(text.as_deref(), Some("LOOKING_UP_SERVER"));
        }
        other => panic!("RENEW must not alternate, got {other:?}"),
    }
}

fn aes_key(b: u8) -> ProtocolKey {
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[b; 32]).expect("key")
}

fn attach_pac(key: &ProtocolKey, part: &mut EncTicketPart, info_name: &str) {
    let stub = Pac::built(
        0,
        vec![PacBuffer::new(
            PAC_CLIENT_INFO,
            client_info_buffer(part.authtime.unix_seconds(), info_name),
        )],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(part).unwrap();
    let ident = PacIdentity {
        sam: part.cname.components_joined(),
        realm: String::new(),
        domain_sid: RpcSid::nt_domain(1, 2, 3),
        rid: 1,
    };
    let pac = sign_reply_pac(
        &part.cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: key,
            kdc: key,
            enc_tkt_der: &der,
            is_service_tkt: false,
        },
        &ident,
        None,
        Some(&stub),
    )
    .unwrap();
    part.authorization_data = Some(wrap_win2k_pac(&pac).unwrap());
}

fn reseal_incoming(key: &ProtocolKey, tgt: &krb5_kdc::IssuedAs, part: &EncTicketPart) -> Ticket {
    let der = encode(part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    Ticket {
        tkt_vno: tgt.rep.0.ticket.tkt_vno,
        realm: krb5_types::try_ascii("OTHER.TEST").unwrap(),
        sname: PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", TEST_REALM]),
        enc_part: EncryptedData {
            etype: key.etype().to_iana(),
            kvno: Some(1),
            cipher: encrypt(key, usage, &der).unwrap().into(),
        },
    }
}

fn host_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let host = documented_host();
    let key = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        host,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn evidence_for_user(store: &PrincipalStore, nonce: u32) -> Ticket {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = {
        let key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = as_req(
            admin.clone(),
            TEST_REALM,
            nonce,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(store, &req).unwrap()
    };
    let req = tgs_req(
        admin_tgt.rep.0.ticket,
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user,
        TEST_REALM,
        nonce + 1,
    )
    .unwrap();
    krb5_kdc::issue_tgs(store, &req).unwrap().rep.0.ticket
}

#[test]
fn a4_18_s4u2self_case2_cross_local_user_referral_issues() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let ir = aes_key(0x44);
    store
        .create_interrealm_key(&acl, &documented_admin_id(), "OTHER.TEST", ir.clone())
        .unwrap();
    store
        .policy
        .domain_realm
        .insert(".other.test".into(), "OTHER.TEST".into());
    let mut hops = std::collections::BTreeMap::new();
    hops.insert("OTHER.TEST".into(), vec![".".into()]);
    let mut capaths = std::collections::BTreeMap::new();
    capaths.insert(TEST_REALM.into(), hops);
    let mut back = std::collections::BTreeMap::new();
    back.insert(TEST_REALM.into(), vec![".".into()]);
    capaths.insert("OTHER.TEST".into(), back);
    store.set_capaths(capaths);
    let tgt = host_tgt(&store, 1860);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &tgt.rep.0.ticket).unwrap();
    let foreign_host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.other.test"]);
    part.cname = foreign_host.clone();
    part.crealm = krb5_types::try_ascii("OTHER.TEST").unwrap();
    attach_pac(&ir, &mut part, &foreign_host.components_joined());
    let header = reseal_incoming(&ir, &tgt, &part);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let pa = pa_for_user(&tgt.session_key, user, TEST_REALM).unwrap();
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.other.test"]);
    let req = tgs_req_ex(
        header,
        &tgt.session_key,
        "OTHER.TEST",
        &foreign_host,
        host,
        TEST_REALM,
        1861,
        canon(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &req).expect("S4U2Self case 2");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/OTHER.TEST"
    );
}

#[test]
fn a4_18_s4u2self_case3_cross_foreign_user_referral_issues() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let ir = aes_key(0x55);
    store
        .create_interrealm_key(&acl, &documented_admin_id(), "OTHER.TEST", ir.clone())
        .unwrap();
    store
        .policy
        .domain_realm
        .insert(".other.test".into(), "OTHER.TEST".into());
    let mut hops = std::collections::BTreeMap::new();
    hops.insert("OTHER.TEST".into(), vec![".".into()]);
    let mut capaths = std::collections::BTreeMap::new();
    capaths.insert(TEST_REALM.into(), hops);
    let mut back = std::collections::BTreeMap::new();
    back.insert(TEST_REALM.into(), vec![".".into()]);
    capaths.insert("OTHER.TEST".into(), back);
    store.set_capaths(capaths);
    let tgt = host_tgt(&store, 1864);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &tgt.rep.0.ticket).unwrap();
    let alice = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["alice"]);
    part.cname = alice.clone();
    part.crealm = krb5_types::try_ascii("OTHER.TEST").unwrap();
    attach_pac(&ir, &mut part, "alice@OTHER.TEST");
    let header = reseal_incoming(&ir, &tgt, &part);
    let pa = pa_for_user(&tgt.session_key, alice.clone(), "OTHER.TEST").unwrap();
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.other.test"]);
    let req = tgs_req_ex(
        header,
        &tgt.session_key,
        "OTHER.TEST",
        &alice,
        host,
        TEST_REALM,
        1865,
        canon(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &req).expect("S4U2Self case 3");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/OTHER.TEST"
    );
}

#[test]
fn a4_18_s4u2self_local_tgt_referral_is_looking_up_server() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    other_store(&mut store, &acl);
    let tgt = host_tgt(&store, 1870);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let pa = pa_for_user(&tgt.session_key, user, TEST_REALM).unwrap();
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.other.test"]);
    let req = tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &documented_host(),
        host,
        TEST_REALM,
        1871,
        canon(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .unwrap();
    match krb5_kdc::issue_tgs(&store, &req) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
            assert_eq!(text.as_deref(), Some("LOOKING_UP_SERVER"));
        }
        other => panic!("expected LOOKING_UP_SERVER, got {other:?}"),
    }
}

#[test]
fn a4_18_s4u2proxy_referral_without_rbcd_is_unsupported() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    other_store(&mut store, &acl);
    let evidence = evidence_for_user(&store, 1880);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let user_tgt = {
        let req = as_req(
            user.clone(),
            TEST_REALM,
            1882,
            Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&store, &req).unwrap()
    };
    let dest = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.other.test"]);
    let opts = KdcOptions::forwardable()
        .with_bit(flag_bit::CNAME_IN_ADDL_TKT, true)
        .with_bit(flag_bit::CANONICALIZE, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket,
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        dest,
        TEST_REALM,
        1883,
        opts,
        Some(vec![evidence]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::BADOPTION);
            assert_eq!(text.as_deref(), Some("UNSUPPORTED_S4U2PROXY_REQUEST"));
        }
        other => panic!("expected UNSUPPORTED_S4U2PROXY_REQUEST, got {other:?}"),
    }
}

#[test]
fn a4_18_s4u2proxy_referral_with_rbcd_issues() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    other_store(&mut store, &acl);
    let host = documented_host();
    let tgt = host_tgt(&store, 1890);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let pa = pa_for_user(&tgt.session_key, user, TEST_REALM).unwrap();
    let self_req = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        1891,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .unwrap();
    let evidence = krb5_kdc::issue_tgs(&store, &self_req)
        .expect("S4U2Self evidence")
        .rep
        .0
        .ticket;
    let dest = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.other.test"]);
    let opts = KdcOptions::forwardable()
        .with_bit(flag_bit::CNAME_IN_ADDL_TKT, true)
        .with_bit(flag_bit::CANONICALIZE, true);
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &host,
        dest,
        TEST_REALM,
        1893,
        opts,
        Some(vec![evidence]),
        vec![pa_pac_options(true).unwrap()],
        pref_etypes(),
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("S4U2Proxy referral");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/OTHER.TEST"
    );
    // MIT `do_tgs_req.c:756-759` + `gc_via_tkt.c:261-269`: referral TGT
    // client is the header impersonator, not the evidence user.
    assert_eq!(
        out.rep.0.cname.components_joined(),
        host.components_joined()
    );
    // MIT `kdc_authdata.c:534-539`: S4U referral PAC client info is the
    // subject with realm (B's `RBCD_PAC_PRINC` read).
    let ir = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_SRV_INST,
            ["krbtgt", "OTHER.TEST"],
        ))
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let part = decrypt_ticket_part(&ir, &out.rep.0.ticket).unwrap();
    let pac = Pac::parse(&pac_from_ticket_part(&part).unwrap()).unwrap();
    let info = pac.unique_buffer(PAC_CLIENT_INFO).unwrap().unwrap();
    let (_, name) = parse_client_info(info).unwrap();
    assert_eq!(name, format!("{TEST_USER}@{TEST_REALM}"));
}
