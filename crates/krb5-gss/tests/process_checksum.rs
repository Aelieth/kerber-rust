//! MIT `accept_sec_context.c` `process_checksum`.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, checksum, string_to_key};
use krb5_gss::{
    ChannelBindings, Error, GSS_C_CHANNEL_BOUND, GSS_C_DELEG, GSS_C_INTEG, GSS_C_MUTUAL,
    GSS_C_PROT_READY, GSS_C_REPLAY, GSS_C_SEQUENCE, GSS_C_TRANS, GSS_CHECKSUM_TYPE, GssContext,
};
use krb5_kdc::{
    S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    documented_host, pa_enc_timestamp, tgs_req,
};
use krb5_protocol::{ReplayCache, build_ap_req_with_cksum};
use krb5_types::{ApOptions, Checksum, EncryptionKey, PrincipalName, ascii, ku};

fn host_ticket() -> (
    krb5_types::Ticket,
    krb5_crypto::ProtocolKey,
    krb5_crypto::ProtocolKey,
    PrincipalName,
) {
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
fn accept_no_checksum_is_flags_zero_and_no_ap_rep() {
    let (ticket, session, skey, cname) = host_ticket();
    let ap = build_ap_req_with_cksum(
        ticket,
        &session,
        &ascii(TEST_REALM),
        &cname,
        ApOptions::mutual_required(),
        None,
        None,
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
    )
    .unwrap();
    assert!(rep.is_none());
    assert_eq!(
        acc.inquire_context().flags & !(GSS_C_TRANS | GSS_C_PROT_READY),
        0
    );
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
    )
    .unwrap();
    assert!(rep.is_some());
    let flags = acc.inquire_context().flags;
    assert_ne!(flags & GSS_C_MUTUAL, 0);
    assert_ne!(flags & GSS_C_REPLAY, 0);
    assert_ne!(flags & GSS_C_SEQUENCE, 0);
}

#[test]
fn accept_cb_mismatch_is_bad_bindings() {
    let (ticket, session, skey, cname) = host_ticket();
    let init_cb = ChannelBindings {
        application_data: b"tls-a".to_vec(),
        ..ChannelBindings::default()
    };
    let (_init, token) = GssContext::init_sec_context(
        ticket,
        &session,
        &ascii(TEST_REALM),
        &cname,
        false,
        Some(&init_cb),
        None,
    )
    .unwrap();
    let other = ChannelBindings {
        application_data: b"tls-b".to_vec(),
        ..ChannelBindings::default()
    };
    match GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        Some(&other),
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    ) {
        Err(Error::ChannelBindings) => {}
        Err(e) => panic!("expected channel bindings, got {e}"),
        Ok(_) => panic!("expected channel bindings"),
    }
}

#[test]
fn accept_cb_match_sets_channel_bound() {
    let (ticket, session, skey, cname) = host_ticket();
    let cb = ChannelBindings {
        application_data: b"tls-unique".to_vec(),
        ..ChannelBindings::default()
    };
    let (_init, token) = GssContext::init_sec_context(
        ticket,
        &session,
        &ascii(TEST_REALM),
        &cname,
        false,
        Some(&cb),
        None,
    )
    .unwrap();
    let (acc, _) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        Some(&cb),
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .unwrap();
    assert_ne!(acc.inquire_context().flags & GSS_C_CHANNEL_BOUND, 0);
}

#[test]
fn accept_cb_len_not_16_is_failure() {
    let (ticket, session, skey, cname) = host_ticket();
    let mut raw = vec![0u8; 24];
    raw[0..4].copy_from_slice(&8u32.to_le_bytes());
    let cksum = Checksum {
        cksumtype: GSS_CHECKSUM_TYPE,
        checksum: raw.into(),
    };
    let ap = build_ap_req_with_cksum(
        ticket,
        &session,
        &ascii(TEST_REALM),
        &cname,
        ApOptions::none(),
        Some(cksum),
        None,
    )
    .unwrap();
    let token = wrap_ap(&ap);
    match GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    ) {
        Err(Error::Inner(s)) if s.contains("gss failure") => {}
        Err(e) => panic!("expected gss failure, got {e}"),
        Ok(_) => panic!("expected gss failure"),
    }
}

#[test]
fn accept_initiator_flags_are_masked() {
    let (ticket, session, skey, cname) = host_ticket();
    let mut raw = vec![0u8; 24];
    raw[0..4].copy_from_slice(&16u32.to_le_bytes());
    raw[20..24].copy_from_slice(&(GSS_C_INTEG | GSS_C_DELEG | 0x0800_0000).to_le_bytes());
    let cksum = Checksum {
        cksumtype: GSS_CHECKSUM_TYPE,
        checksum: raw.into(),
    };
    let ap = build_ap_req_with_cksum(
        ticket,
        &session,
        &ascii(TEST_REALM),
        &cname,
        ApOptions::none(),
        Some(cksum),
        None,
    )
    .unwrap();
    let token = wrap_ap(&ap);
    let (acc, _) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .unwrap();
    let flags = acc.inquire_context().flags;
    assert_eq!(flags & GSS_C_INTEG, GSS_C_INTEG);
    assert_eq!(flags & GSS_C_DELEG, 0);
    assert_eq!(flags & 0x0800_0000, 0);
}

#[test]
fn accept_bad_deleg_option_id_is_failure() {
    let (ticket, session, skey, cname) = host_ticket();
    let mut raw = vec![0u8; 32];
    raw[0..4].copy_from_slice(&16u32.to_le_bytes());
    raw[20..24].copy_from_slice(&GSS_C_DELEG.to_le_bytes());
    raw[24..26].copy_from_slice(&99u16.to_le_bytes());
    raw[26..28].copy_from_slice(&4u16.to_le_bytes());
    let cksum = Checksum {
        cksumtype: GSS_CHECKSUM_TYPE,
        checksum: raw.into(),
    };
    let ap = build_ap_req_with_cksum(
        ticket,
        &session,
        &ascii(TEST_REALM),
        &cname,
        ApOptions::none(),
        Some(cksum),
        None,
    )
    .unwrap();
    let token = wrap_ap(&ap);
    match GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    ) {
        Err(Error::Inner(s)) if s.contains("gss failure") => {}
        Err(e) => panic!("expected gss failure, got {e}"),
        Ok(_) => panic!("expected gss failure"),
    }
}

#[test]
fn accept_trailing_extensions_are_skipped() {
    let (ticket, session, skey, cname) = host_ticket();
    let mut raw = vec![0u8; 24 + 12];
    raw[0..4].copy_from_slice(&16u32.to_le_bytes());
    raw[20..24].copy_from_slice(&GSS_C_MUTUAL.to_le_bytes());
    raw[24..28].copy_from_slice(&0x0000_0001u32.to_be_bytes());
    raw[28..32].copy_from_slice(&4u32.to_be_bytes());
    let cksum = Checksum {
        cksumtype: GSS_CHECKSUM_TYPE,
        checksum: raw.into(),
    };
    let ap = build_ap_req_with_cksum(
        ticket,
        &session,
        &ascii(TEST_REALM),
        &cname,
        ApOptions::none(),
        Some(cksum),
        None,
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
    )
    .unwrap();
    assert!(rep.is_some());
    assert_ne!(acc.inquire_context().flags & GSS_C_MUTUAL, 0);
}
