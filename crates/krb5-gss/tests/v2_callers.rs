//! W1-J Round 2 V2: the callers of `unwrap_v3` and `process_checksum`.
//! `conf_state` (`unwrap.c:363-364`), `GSS_C_DELEG_FLAG` after a stored
//! delegation (`accept_sec_context.c:573-577`), `GSS_C_PROT_READY_FLAG`
//! (`:1089`), RRC reduced modulo the length (`unwrap.c:259-262`).

use krb5_crypto::ProtocolKey;
use krb5_gss::{DelegCred, GSS_C_DELEG, GSS_C_PROT_READY, GssContext};
use krb5_kdc::{
    TEST_REALM, TEST_USER, as_req, bootstrap_documented, documented_host, pa_enc_timestamp,
};
use krb5_protocol::ReplayCache;
use krb5_types::{PrincipalName, ascii};

fn issue_tgt(store: &krb5_kdc::PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let ukey = store.get_name(&cname).unwrap().best_key().unwrap();
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&ukey.key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn linked() -> (GssContext, GssContext) {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, 40);
    let tgs = krb5_kdc::tgs_req(
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
        false,
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
    )
    .unwrap();
    (init, acc)
}

#[test]
fn unwrap_conf_reports_confidentiality() {
    let (mut init, mut acc) = linked();
    let sealed = init.wrap(b"sealed-body").unwrap();
    let (data, conf) = acc.unwrap_conf(&sealed).unwrap();
    assert_eq!(data, b"sealed-body");
    assert!(conf, "a wrap token is sealed");

    let (mut init2, mut acc2) = linked();
    let integ = init2.wrap_integ(b"integ-body").unwrap();
    let (data, conf) = acc2.unwrap_conf(&integ).unwrap();
    assert_eq!(data, b"integ-body");
    assert!(
        !conf,
        "wrap_integ is integrity-only; a privacy service must reject it"
    );
}

#[test]
fn acceptor_sets_prot_ready_flag() {
    let (_, acc) = linked();
    assert_ne!(
        acc.inquire_context().flags & GSS_C_PROT_READY,
        0,
        "established context sets GSS_C_PROT_READY_FLAG"
    );
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

#[test]
fn delegation_sets_the_deleg_flag() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, 42);
    let tgs = krb5_kdc::tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        43,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let deleg = DelegCred {
        ticket: tgt.rep.0.ticket.clone(),
        session: tgt.session_key.clone(),
        crealm: ascii(TEST_REALM),
        cname: cname.clone(),
    };
    let (_, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        false,
        None,
        Some(&deleg),
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
    )
    .unwrap();
    assert!(acc.delegated().is_some(), "delegated credential stored");
    assert_ne!(
        acc.inquire_context().flags & GSS_C_DELEG,
        0,
        "storing a delegated credential sets GSS_C_DELEG_FLAG"
    );
}
