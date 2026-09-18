//! Z1.3 acceptor `krb5int_validate_times` + INVALID flag (`valid_times.c:36-58`,
//! `rd_req_dec.c:627-638`). These compile at the parent `d6ae0c1` and fail there:
//! `verify_inner` only checked NYV when `starttime` was present (a no-starttime
//! ticket rode on nothing), the INVALID flag returned `TKT_NYV` (33) instead
//! of MIT's library-local `KRB5KRB_AP_ERR_TKT_INVALID` (145), and a pinned name
//! with no key at the ticket's kvno was `NOKEY` (45) where MIT's
//! `keytab_fetch_error` says `BADKEYVER` (44).

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_asn1::{decode, encode};
use krb5_crypto::{KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_kdc::{
    TEST_REALM, TEST_USER, as_req, bootstrap_documented, documented_admin_id, documented_host,
    pa_enc_timestamp, tgs_req,
};
use krb5_protocol::{ApVerifyParams, DEFAULT_SKEW, ReplayCache, build_ap_req, verify_ap_req_ex};
use krb5_types::{ApReq, EncTicketPart, KerberosTime, PrincipalName, flag_bit, ku};

/// Build a real `host/…` AP-REQ, then reseal its ticket after `mutate` has
/// rewritten the (decrypted) `EncTicketPart`. The session key is untouched, so
/// the original authenticator still verifies.
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
fn z1_no_starttime_future_authtime_is_nyv() {
    // MIT valid_times.c:44-51: starttime==0 falls back to authtime; a ticket
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
fn z1_invalid_flag_is_tkt_invalid() {
    // MIT rd_req_dec.c:634-638: the INVALID flag yields KRB5KRB_AP_ERR_TKT_INVALID
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
fn z1_pinned_name_wrong_kvno_is_badkeyver() {
    // MIT rd_req_dec.c:374-376 try_one_princ → krb5_kt_get_entry(princ, kvno,
    // etype); kt_file.c:380-384 an entry for the principal+enctype at another
    // kvno is KRB5_KT_KVNONOTFOUND; rd_req_dec.c:139-148 keytab_fetch_error
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
