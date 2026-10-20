//! Non-0x8003 authenticator checksum over empty data.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, checksum, string_to_key};
use krb5_gss::{GSS_C_MUTUAL, GSS_C_REPLAY, GSS_C_SEQUENCE, GssContext};
use krb5_kdc::S2K_ITERS;
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_host,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_protocol::{AcceptorConfig, ReplayCache, build_ap_req_with_cksum};
use krb5_types::{ApOptions, Checksum, EncryptionKey, PrincipalName, ascii, ku};

fn host_ticket() -> (
    krb5_types::Ticket,
    krb5_crypto::ProtocolKey,
    krb5_crypto::ProtocolKey,
    PrincipalName,
) {
    krb5_config::isolate_test_krb5();
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        1,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        2,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let host = store.get_name(&documented_host()).unwrap();
    let skey = host.best_key().unwrap().key.clone();
    (
        tgs_out.rep.0.ticket.clone(),
        tgs_out.session_key.clone(),
        skey,
        cname,
    )
}

fn wrap_ap(ap: &krb5_types::ApReq) -> Vec<u8> {
    let inner = encode(ap).unwrap();
    let mut body = der_tlv(0x06, krb5_gss::KRB5_OID);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&inner);
    der_tlv(0x60, &body)
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(u8::try_from(body.len()).unwrap());
    } else if body.len() < 256 {
        out.push(0x81);
        out.push(u8::try_from(body.len()).unwrap());
    } else {
        out.push(0x82);
        out.extend_from_slice(&(u16::try_from(body.len()).unwrap()).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

#[test]
fn accept_non_8003_empty_with_subkey_uses_session_key() {
    let (ticket, session, skey, cname) = host_ticket();
    let usage = KeyUsage::new(ku::AP_REQ_AUTH_CKSUM).unwrap();
    let mac = checksum(&session, usage, b"").unwrap();
    let cksum = Checksum {
        cksumtype: session.etype().checksum_type(),
        checksum: mac.into(),
    };
    let mut sub_bytes = session.as_bytes().to_vec();
    sub_bytes[0] ^= 0xff;
    let enc_sub = EncryptionKey {
        keytype: session.etype().to_iana(),
        keyvalue: sub_bytes.into(),
    };
    let ap = build_ap_req_with_cksum(
        ticket,
        &session,
        &ascii(TEST_REALM),
        &cname,
        ApOptions::mutual_required(),
        Some(cksum),
        Some(enc_sub),
    )
    .unwrap();
    let token = wrap_ap(&ap);
    let (acc, rep) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
        &AcceptorConfig::default(),
    )
    .unwrap();
    assert!(rep.is_some());
    let flags = acc.inquire_context().flags;
    assert_ne!(flags & GSS_C_MUTUAL, 0);
    assert_ne!(flags & GSS_C_REPLAY, 0);
    assert_ne!(flags & GSS_C_SEQUENCE, 0);
}
