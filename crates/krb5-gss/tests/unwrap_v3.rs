//! RFC 4121 RRC is reduced modulo the payload length.

#[path = "common/mod.rs"]
mod common;
use common::issue_tgt;

use krb5_crypto::ProtocolKey;
use krb5_gss::GssContext;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented, documented_host};
use krb5_protocol::{AcceptorConfig, ReplayCache};
use krb5_types::{PrincipalName, ascii};

fn linked() -> (GssContext, GssContext) {
    krb5_config::isolate_test_krb5();
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, 40);
    let tgs = krb5_protocol::tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        41,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let (init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        krb5_gss::GSS_C_REPLAY | krb5_gss::GSS_C_SEQUENCE,
        None,
        None,
    )
    .unwrap();
    let host = store.get_name(&documented_host()).unwrap();
    let skey: &ProtocolKey = &host.best_key().unwrap().key;
    let (acc, _) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
        &AcceptorConfig::default(),
    )
    .unwrap();
    (init, acc)
}

#[test]
fn rrc_reduces_modulo_the_payload_length() {
    // A token MIT accepts (rc %= len): rrc = payload.len() + real_rrc.
    let (mut init, mut acc) = linked();
    let tok = init.wrap_with_rrc(b"rrc-wrap", 0).unwrap();
    let payload_len = u16::try_from(tok.len() - 16).unwrap();
    let (mut init2, mut acc2) = linked();
    let tok2 = init2.wrap_with_rrc(b"rrc-wrap", payload_len + 5).unwrap();
    let _ = (&mut acc, &mut init);
    assert_eq!(
        acc2.unwrap(&tok2).unwrap(),
        b"rrc-wrap",
        "rrc = len + k must rotate by k, not be ignored"
    );
}
