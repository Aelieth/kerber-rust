//! A′-4 item 18 units that compile at `6be3b65` and fail there.

use std::collections::BTreeMap;

use krb5_kdc::{
    Error, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_admin_id,
    tgs_req,
};
use krb5_testkit::issue_tgt_password;
use krb5_types::{PrincipalName, err};

#[test]
fn a4_18_alternate_tgs_issues_near_hop() {
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
fn a4_18_alternate_tgs_without_hop_is_unknown_server() {
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
