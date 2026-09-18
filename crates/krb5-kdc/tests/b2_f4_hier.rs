//! F4 hierarchical `find_alternate_tgs` / numeric host referral.
//!
//! These compile at `b749e73` and fail there: the walk reused transit
//! intermediates, so `.skip(1)` dropped the hop MIT issues, `common == 0`
//! walked nothing, a numeric host still took `[domain_realm]`, and
//! `is_referral` compared name-type.

use krb5_kdc::{
    Error, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_admin_id,
    tgs_req,
};
use krb5_testkit::{TgsReqBuilder, issue_tgt_password, pref_etypes};
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit};

#[test]
fn f4_hier_alternate_issues_sub_realm() {
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
fn f4_hier_common_zero_issues_org_hop() {
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
fn f4_referral_numeric_ipv4_is_looking_up_server() {
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
fn f4_explicit_cross_tgs_keeps_request_name_type() {
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
