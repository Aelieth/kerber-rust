//! A′-4 item 18 units that compile at `6be3b65` and fail there.

use std::collections::BTreeMap;

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_kdc::{
    Error, PrincipalStore, S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req,
    bootstrap_documented, documented_admin_id, pa_enc_timestamp, tgs_req,
};
use krb5_types::{PrincipalName, err};

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
    let tgt = issue_tgt(&store, 1801);
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
    let tgt = issue_tgt(&store, 1803);
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
