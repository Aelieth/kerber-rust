//! A′-4 item 18 units that compile at `6be3b65` and fail there.
//! A′-4 item 18 units that need `domain_realm` / host-based knobs.
//! F4 hierarchical `find_alternate_tgs` / numeric host referral.
//!
//! These compile at `b749e73` and fail there: the walk reused transit
//! intermediates, so `.skip(1)` dropped the hop MIT issues, `common == 0`
//! walked nothing, a numeric host still took `[domain_realm]`, and
//! `is_referral` compared name-type.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

use krb5_crypto::{KeyUsage, decrypt};
use krb5_kdc::{
    Acl, Error, PrincipalStore, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req,
    bootstrap_documented, decrypt_ticket_part, documented_admin_id, documented_host,
    pa_enc_timestamp, pac_from_ticket_part, tgs_req,
};
use krb5_protocol::{pa_for_user, pa_pac_options};
use krb5_testkit::{
    TgsReqBuilder, aes_key, attach_pac, evidence_for_user, foreign, host_tgt, issue_tgt_password,
    pref_etypes, reseal_incoming,
};
use krb5_types::pac::{PAC_CLIENT_INFO, Pac, parse_client_info};
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit, ku};
use std::collections::BTreeMap;

#[test]
fn alternate_tgs_issues_near_hop() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "OTHER.TEST",
            b"interrealm-secret",
        )
        .expect("interrealm");
    let mut hops = BTreeMap::new();
    hops.insert("FAR.TEST".into(), vec!["OTHER.TEST".into()]);
    let mut capaths = BTreeMap::new();
    capaths.insert(TEST_REALM.into(), hops);
    store.set_capaths(capaths);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 1801);
    let far = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "FAR.TEST"]);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        far,
        TEST_REALM,
        1802,
    )
    .expect("TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("alternate TGS");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/OTHER.TEST"
    );
}

#[test]
fn alternate_tgs_without_hop_is_unknown_server() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 1803);
    let far = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "FAR.TEST"]);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        far,
        TEST_REALM,
        1804,
    )
    .expect("TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
            assert_eq!(text.as_deref(), Some("UNKNOWN_SERVER"));
        }
        other => panic!("expected UNKNOWN_SERVER, got {other:?}"),
    }
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
    let tgt = issue_tgt_password(store, TEST_USER, TEST_USER_PASSWORD, nonce);
    TgsReqBuilder::new(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &cname,
        sname,
        TEST_REALM,
        nonce + 1,
    )
    .options(opts)
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("TGS-REQ")
}

#[test]
fn host_fqdn_canonicalize_issues_referral() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    other_store(&mut store, &acl);
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.other.test"]);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 1810);
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &cname,
        host,
        TEST_REALM,
        1811,
    )
    .options(canon())
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
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
fn referral_no_dot_is_looking_up_server() {
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
fn nt_unknown_needs_host_based_services() {
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
fn no_host_referral_star_blocks() {
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
fn renew_skips_alternate_tgs() {
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

#[test]
fn s4u2self_case2_cross_local_user_referral_issues() {
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
    let req = TgsReqBuilder::new(
        header,
        &tgt.session_key,
        "OTHER.TEST",
        &foreign_host,
        host,
        TEST_REALM,
        1861,
    )
    .options(canon())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &req).expect("S4U2Self case 2");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/OTHER.TEST"
    );
}

#[test]
fn s4u2self_case3_cross_foreign_user_referral_issues() {
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
    let req = TgsReqBuilder::new(
        header,
        &tgt.session_key,
        "OTHER.TEST",
        &alice,
        host,
        TEST_REALM,
        1865,
    )
    .options(canon())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &req).expect("S4U2Self case 3");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/OTHER.TEST"
    );
}

#[test]
fn s4u2self_local_tgt_referral_is_looking_up_server() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    other_store(&mut store, &acl);
    let tgt = host_tgt(&store, 1870);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let pa = pa_for_user(&tgt.session_key, user, TEST_REALM).unwrap();
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.other.test"]);
    let req = TgsReqBuilder::new(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &documented_host(),
        host,
        TEST_REALM,
        1871,
    )
    .options(canon())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
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
fn s4u2proxy_referral_without_rbcd_is_unsupported() {
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
    let tgs = TgsReqBuilder::new(
        user_tgt.rep.0.ticket,
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        dest,
        TEST_REALM,
        1883,
    )
    .options(opts)
    .additional_tickets(Some(vec![evidence]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
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
fn s4u2proxy_referral_with_rbcd_issues() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    other_store(&mut store, &acl);
    let host = documented_host();
    let tgt = host_tgt(&store, 1890);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let pa = pa_for_user(&tgt.session_key, user, TEST_REALM).unwrap();
    let self_req = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        1891,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
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
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &host,
        dest,
        TEST_REALM,
        1893,
    )
    .options(opts)
    .additional_tickets(Some(vec![evidence]))
    .padata(vec![pa_pac_options(true).unwrap()])
    .etypes(pref_etypes())
    .build()
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
        .get_name(&foreign())
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

#[test]
fn hier_alternate_issues_sub_realm() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "SUB.KERBER.TEST",
            b"interrealm-secret",
        )
        .expect("interrealm");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 4001);
    let far = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "X.SUB.KERBER.TEST"]);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        far,
        TEST_REALM,
        4002,
    )
    .expect("TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("hierarchical alternate TGS");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/SUB.KERBER.TEST"
    );
}

#[test]
fn hier_common_zero_issues_org_hop() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(&acl, &documented_admin_id(), "ORG", b"interrealm-secret")
        .expect("interrealm");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 4003);
    let far = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "BAR.ORG"]);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        far,
        TEST_REALM,
        4004,
    )
    .expect("TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("common-zero alternate TGS");
    assert_eq!(out.rep.0.ticket.sname.components_joined(), "krbtgt/ORG");
}

#[test]
fn referral_numeric_ipv4_is_looking_up_server() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "OTHER.TEST",
            b"interrealm-secret",
        )
        .expect("interrealm");
    store
        .policy
        .domain_realm
        .insert("1.2.3.4".into(), "OTHER.TEST".into());
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 4005);
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "1.2.3.4"]);
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &cname,
        host,
        TEST_REALM,
        4006,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
            assert_eq!(text.as_deref(), Some("LOOKING_UP_SERVER"));
        }
        other => panic!("expected LOOKING_UP_SERVER, got {other:?}"),
    }
}

#[test]
fn explicit_cross_tgs_keeps_request_name_type() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "OTHER.TEST",
            b"interrealm-secret",
        )
        .expect("interrealm");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 4007);
    let far = PrincipalName::new(PrincipalName::NT_UNKNOWN, ["krbtgt", "OTHER.TEST"]);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        far,
        TEST_REALM,
        4008,
    )
    .expect("TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("explicit cross TGS");
    assert_eq!(out.rep.0.ticket.sname.name_type, PrincipalName::NT_UNKNOWN);
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/OTHER.TEST"
    );
}

#[test]
fn tgs_referral_uses_interrealm_key_and_transited() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "OTHER.TEST",
            b"interrealm-secret",
        )
        .expect("interrealm");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 51);
    let other = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "OTHER.TEST"]);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        other.clone(),
        TEST_REALM,
        52,
    )
    .expect("referral TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("referral");
    assert_eq!(out.rep.0.ticket.sname, other);
    let ir = store.get_name(&other).unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&ir.key, &out.rep.0.ticket).expect("inter-realm enc");
    assert!(
        part.transited
            .realms_for(TEST_REALM, "OTHER.TEST")
            .expect("expand")
            .is_empty(),
        "first-hop referral transited excludes client realm: {:?}",
        part.transited.realms_for(TEST_REALM, "OTHER.TEST")
    );
}

#[test]
fn tgs_canonicalize_issues_cross_realm_krbtgt() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "OTHER.TEST",
            b"interrealm-secret",
        )
        .expect("interrealm");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 61);
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.other.test"]);
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        host,
        "OTHER.TEST",
        62,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("cross-realm TGS-REQ");
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("foreign body.realm");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::GENERIC);
            assert_eq!(text.as_deref(), Some("GET_LOCAL_TGT"));
        }
        other => panic!("expected 60 GET_LOCAL_TGT, got {other:?}"),
    }
}

#[test]
fn tgs_referral_ad_kerber_test_issues_krbtgt() {
    // In-tree hop for the A5 realm names. Live AD.KERBER.TEST↔KERBER.TEST
    // trust is not configured on the DC; this is not that proof.
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "AD.KERBER.TEST",
            b"ad-interrealm-secret",
        )
        .expect("interrealm");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 71);
    let ir_sname = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "AD.KERBER.TEST"]);
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        ir_sname,
        TEST_REALM,
        72,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("AD referral TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("AD referral TGS");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/AD.KERBER.TEST"
    );
    let ir_name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "AD.KERBER.TEST"]);
    let ir = store.get_name(&ir_name).unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&ir.key, &out.rep.0.ticket).expect("inter-realm enc");
    assert!(
        part.transited
            .realms_for(TEST_REALM, "AD.KERBER.TEST")
            .expect("expand")
            .is_empty(),
        "first-hop referral transited excludes client realm: {:?}",
        part.transited.realms_for(TEST_REALM, "AD.KERBER.TEST")
    );
}
