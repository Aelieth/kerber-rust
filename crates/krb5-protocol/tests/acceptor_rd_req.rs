//! B2 `rd_req_dec.c`: acceptor key selection uses ticket kvno + etype
//! (`try_one_princ` → `krb5_kt_get_entry(..., tkt_kvno, tkt_etype)`).
//! These compile at `7e55747` and fail there: `want_kvno` was discarded
//! and every key was tried.

#[path = "common/mod.rs"]
mod common;
use common::client_key;
use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id, documented_host,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_protocol::{ApVerifyParams, DEFAULT_SKEW, ReplayCache, build_ap_req, verify_ap_req_ex};
use krb5_types::{
    ApReq, EncTicketPart, KerberosTime, PrincipalName, TransitedEncoding, err, flag_bit, ku,
};

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
fn rd_req_kvno_mismatch_is_nokey() {
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
fn rd_req_relabeled_ticket_kvno_is_nokey() {
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
fn rd_req_wrong_key_at_claimed_kvno_is_integrity() {
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
fn rd_req_matching_kvno_verifies() {
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
fn rd_req_authenticator_skew_is_skew() {
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

fn rewrite_ticket(raw: &[u8], key: &ProtocolKey, f: impl FnOnce(&mut EncTicketPart)) -> Vec<u8> {
    let mut ap: ApReq = decode(raw).expect("AP-REQ");
    let usage = KeyUsage::new(ku::TICKET).expect("ku");
    let plain = decrypt(key, usage, ap.ticket.enc_part.cipher.as_ref()).expect("dec");
    let mut part: EncTicketPart = decode(&plain).expect("EncTicketPart");
    f(&mut part);
    let new_plain = encode(&part).expect("enc part");
    ap.ticket.enc_part.cipher = encrypt(key, usage, &new_plain).expect("enc").into();
    encode(&ap).expect("AP-REQ")
}

fn verify(
    raw: &[u8],
    key: &ProtocolKey,
) -> Result<krb5_protocol::ApVerifyOk, krb5_protocol::Error> {
    let keys = [key.clone()];
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: None,
        kvno: None,
        expected_server: None,
        expected_realm: None,
        skew: DEFAULT_SKEW,
        addresses: None,
        now: None,
    };
    verify_ap_req_ex(raw, &params, &ReplayCache::new(), None)
}

#[test]
fn rd_req_transited_issued_ticket_with_t_flag_verifies() {
    let (raw, key, _) = host_ap_req();
    verify(&raw, &key).expect("KDC-issued ticket has TRANSITED_POLICY_CHECKED");
}

#[test]
fn rd_req_transited_unchecked_evil_hop_is_ill_cr_tkt() {
    let (raw, key, _) = host_ap_req();
    let raw2 = rewrite_ticket(&raw, &key, |part| {
        part.flags = part
            .flags
            .clone()
            .with_bit(flag_bit::TRANSITED_POLICY_CHECKED, false);
        part.transited = TransitedEncoding::from_realms(&["EVIL.COM"]);
    });
    match verify(&raw2, &key) {
        Err(krb5_protocol::Error::KrbError { code, .. }) => assert_eq!(code, err::ILL_CR_TKT),
        other => panic!("expected ILL_CR_TKT, got {other:?}"),
    }
}

#[test]
fn rd_req_transited_t_flag_skips_evil_hop() {
    let (raw, key, _) = host_ap_req();
    let raw2 = rewrite_ticket(&raw, &key, |part| {
        assert!(
            part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
            "KDC-issued ticket should carry T"
        );
        part.transited = TransitedEncoding::from_realms(&["EVIL.COM"]);
    });
    verify(&raw2, &key).expect("TRANSITED_POLICY_CHECKED skips krb5_check_transited_list");
}

#[test]
fn rd_req_transited_unchecked_empty_verifies() {
    let (raw, key, _) = host_ap_req();
    let raw2 = rewrite_ticket(&raw, &key, |part| {
        part.flags = part
            .flags
            .clone()
            .with_bit(flag_bit::TRANSITED_POLICY_CHECKED, false);
        part.transited = TransitedEncoding::empty();
    });
    verify(&raw2, &key).expect("empty transited is at most one hop");
}

fn host_ap_req_forged(mutate: impl FnOnce(&mut EncTicketPart)) -> (Vec<u8>, ProtocolKey) {
    krb5_config::isolate_test_krb5();
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        0x2300_0001,
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
        0x2300_0002,
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
    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &documented_host())
        .expect("keytab");
    let host_key = kt.entries.into_iter().next().expect("host key").key;

    let mut ap: ApReq = ap;
    let usage = KeyUsage::new(ku::TICKET).expect("usage");
    let plain = decrypt(&host_key, usage, ap.ticket.enc_part.cipher.as_ref()).expect("decrypt tkt");
    let mut part: EncTicketPart = decode(&plain).expect("EncTicketPart");
    mutate(&mut part);
    let der = encode(&part).expect("encode part");
    let cipher = encrypt(&host_key, usage, &der).expect("reseal");
    ap.ticket.enc_part.cipher = cipher.into();
    let raw = encode(&ap).expect("encode ap");
    (raw, host_key)
}

fn accept(raw: &[u8], key: &ProtocolKey) -> Result<(), krb5_protocol::Error> {
    let keys = [key.clone()];
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: None,
        kvno: None,
        expected_server: None,
        expected_realm: None,
        skew: DEFAULT_SKEW,
        addresses: None,
        now: None,
    };
    verify_ap_req_ex(raw, &params, &ReplayCache::new(), None).map(|_| ())
}

#[test]
fn no_starttime_future_authtime_is_nyv() {
    // MIT `krb5int_validate_times` (`valid_times.c:44-51`): starttime==0 falls back to authtime; a ticket
    // whose authtime is well beyond the skew is not yet valid.
    let far = KerberosTime::now()
        .add_seconds(DEFAULT_SKEW + 3600)
        .unwrap();
    let (raw, key) = host_ap_req_forged(|part| {
        part.starttime = None;
        part.authtime = far.clone();
    });
    match accept(&raw, &key) {
        Err(krb5_protocol::Error::KrbError { code, .. }) => {
            assert_eq!(code, krb5_types::err::TKT_NYV);
        }
        other => panic!("expected NYV, got {other:?}"),
    }
}

#[test]
fn invalid_flag_is_tkt_invalid() {
    // MIT `rd_req_decoded_opt` (`rd_req_dec.c:634-638`): the INVALID flag yields KRB5KRB_AP_ERR_TKT_INVALID
    // (offset 145), distinct from TKT_NYV.
    let (raw, key) = host_ap_req_forged(|part| {
        part.flags = part.flags.clone().with_bit(flag_bit::INVALID, true);
    });
    match accept(&raw, &key) {
        Err(krb5_protocol::Error::KrbError { code, .. }) => {
            // 145 = MIT KRB5KRB_AP_ERR_TKT_INVALID (krb5_err.et offset). Literal
            // so this inject file still compiles at the parent, where the
            // `err::TKT_INVALID` constant does not exist. Parent returns 33.
            assert_eq!(code, 145, "KRB5KRB_AP_ERR_TKT_INVALID");
        }
        other => panic!("expected TKT_INVALID, got {other:?}"),
    }
}

#[test]
fn pinned_name_wrong_kvno_is_badkeyver() {
    // MIT `decrypt_try_server` (`rd_req_dec.c:374-376`): MIT try_one_princ → krb5_kt_get_entry(princ, kvno
    // MIT `krb5_ktfile_get_entry` (`kt_file.c:380-384`): etype); an entry for the principal+enctype at another
    // MIT `keytab_fetch_error` (`rd_req_dec.c:139-148`): kvno is KRB5_KT_KVNONOTFOUND; keytab_fetch_error
    // maps it to KRB5KRB_AP_ERR_BADKEYVER (44) "Cannot find key for %s kvno %d
    // in keytab" when the pinned name is the ticket's server. Parent: 45 NOKEY.
    let (raw, key) = host_ap_req_forged(|_| {});
    let ap: ApReq = decode(&raw).expect("AP-REQ");
    let tkt_kvno = ap.ticket.enc_part.kvno.expect("ticket kvno");
    let keys = [key];
    let kvnos = [tkt_kvno + 1];
    let server = documented_host();
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: Some(&kvnos),
        kvno: None,
        expected_server: Some(&server),
        expected_realm: Some(TEST_REALM),
        skew: DEFAULT_SKEW,
        addresses: None,
        now: None,
    };
    match verify_ap_req_ex(&raw, &params, &ReplayCache::new(), None) {
        Err(krb5_protocol::Error::KrbError { code, text }) => {
            assert_eq!(code, krb5_types::err::BADKEYVER, "KRB5KRB_AP_ERR_BADKEYVER");
            let text = text.unwrap_or_default();
            assert!(
                text.starts_with("Cannot find key for host/")
                    && text.ends_with(&format!("kvno {tkt_kvno} in keytab")),
                "MIT keytab_fetch_error text, got {text:?}"
            );
        }
        other => panic!("expected BADKEYVER, got {other:?}"),
    }
}
