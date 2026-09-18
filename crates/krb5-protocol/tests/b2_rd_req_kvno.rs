//! B2 `rd_req_dec.c`: acceptor key selection uses ticket kvno + etype
//! (`try_one_princ` → `krb5_kt_get_entry(..., tkt_kvno, tkt_etype)`).
//! These compile at `7e55747` and fail there: `want_kvno` was discarded
//! and every key was tried.

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::{
    TEST_REALM, TEST_USER, as_req, bootstrap_documented, documented_admin_id, documented_host,
    pa_enc_timestamp, tgs_req,
};
use krb5_protocol::{ApVerifyParams, DEFAULT_SKEW, ReplayCache, build_ap_req, verify_ap_req_ex};
use krb5_types::{ApReq, KerberosTime, PrincipalName, err};

fn host_ap_req() -> (Vec<u8>, ProtocolKey, u32) {
    krb5_config::isolate_test_krb5();
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        0x2000_0001,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS");
    let tgs = tgs_req(
        as_out.rep.0.ticket,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        0x2000_0002,
    )
    .expect("TGS-REQ");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let ap = build_ap_req(
        tgs_out.rep.0.ticket,
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &cname,
    )
    .expect("AP-REQ");
    let raw = encode(&ap).expect("encode");
    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &documented_host())
        .expect("keytab");
    let ent = kt.entries.into_iter().next().expect("host key");
    (raw, ent.key, ent.kvno)
}

#[test]
fn b2_rd_req_kvno_mismatch_is_nokey() {
    let (raw, key, kvno) = host_ap_req();
    assert_eq!(kvno, 1);
    let other = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[9u8; 32]).unwrap();
    let keys = [other, key];
    let kvnos = [2u32, 2];
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: Some(&kvnos),
        kvno: None,
        expected_server: None,
        expected_realm: None,
        skew: DEFAULT_SKEW,
        addresses: None,
        now: None,
    };
    match verify_ap_req_ex(&raw, &params, &ReplayCache::new(), None) {
        Err(krb5_protocol::Error::KrbError { code, .. }) => assert_eq!(code, err::NOKEY),
        other => panic!("expected NOKEY, got {other:?}"),
    }
}

#[test]
fn b2_rd_req_relabeled_ticket_kvno_is_nokey() {
    let (raw, key, kvno) = host_ap_req();
    assert_eq!(kvno, 1);
    let mut ap: ApReq = decode(&raw).expect("AP-REQ");
    ap.ticket.enc_part.kvno = Some(2);
    let raw2 = encode(&ap).expect("encode");
    let keys = [key];
    let kvnos = [1u32];
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: Some(&kvnos),
        kvno: None,
        expected_server: None,
        expected_realm: None,
        skew: DEFAULT_SKEW,
        addresses: None,
        now: None,
    };
    match verify_ap_req_ex(&raw2, &params, &ReplayCache::new(), None) {
        Err(krb5_protocol::Error::KrbError { code, .. }) => assert_eq!(code, err::NOKEY),
        other => panic!("expected NOKEY, got {other:?}"),
    }
}

#[test]
fn b2_rd_req_wrong_key_at_claimed_kvno_is_integrity() {
    let (raw, key, kvno) = host_ap_req();
    assert_eq!(kvno, 1);
    let mut ap: ApReq = decode(&raw).expect("AP-REQ");
    ap.ticket.enc_part.kvno = Some(2);
    let raw2 = encode(&ap).expect("encode");
    let dummy = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[3u8; 32]).unwrap();
    let keys = [key, dummy];
    let kvnos = [1u32, 2];
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: Some(&kvnos),
        kvno: None,
        expected_server: None,
        expected_realm: None,
        skew: DEFAULT_SKEW,
        addresses: None,
        now: None,
    };
    match verify_ap_req_ex(&raw2, &params, &ReplayCache::new(), None) {
        Err(krb5_protocol::Error::Crypto(s)) => assert!(s.contains("integrity"), "{s}"),
        other => panic!("expected integrity failure, got {other:?}"),
    }
}

#[test]
fn b2_rd_req_matching_kvno_verifies() {
    let (raw, key, kvno) = host_ap_req();
    let keys = [key];
    let kvnos = [kvno];
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: Some(&kvnos),
        kvno: None,
        expected_server: None,
        expected_realm: None,
        skew: DEFAULT_SKEW,
        addresses: None,
        now: None,
    };
    verify_ap_req_ex(&raw, &params, &ReplayCache::new(), None).expect("matching kvno");
}

#[test]
fn b2_rd_req_authenticator_skew_is_37() {
    let (raw, key, _) = host_ap_req();
    let now = KerberosTime::now();
    let far = KerberosTime::from_unix_seconds(now.unix_seconds().saturating_add(10_000));
    let keys = [key];
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: None,
        kvno: None,
        expected_server: None,
        expected_realm: None,
        skew: DEFAULT_SKEW,
        addresses: None,
        now: Some(far),
    };
    match verify_ap_req_ex(&raw, &params, &ReplayCache::new(), None) {
        Err(krb5_protocol::Error::KrbError { code, .. }) => assert_eq!(code, err::SKEW),
        other => panic!("expected SKEW, got {other:?}"),
    }
}
