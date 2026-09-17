//! B2 `rd_req_dec.c:590-610`: acceptor re-checks transited when
//! `TRANSITED_POLICY_CHECKED` is unset (`krb5_check_transited_list`).
//! These compile at `cedd3dc` and fail there: `verify_inner` ignored the
//! transited field.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_kdc::{
    S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    documented_admin_id, documented_host, pa_enc_timestamp, tgs_req,
};
use krb5_protocol::{ApVerifyParams, DEFAULT_SKEW, ReplayCache, build_ap_req, verify_ap_req_ex};
use krb5_types::{ApReq, EncTicketPart, PrincipalName, TransitedEncoding, err, flag_bit, ku};

fn client_key() -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    krb5_crypto::string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k")
}

fn host_ap_req() -> (Vec<u8>, ProtocolKey) {
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
    (raw, ent.key)
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
fn b2_rd_req_transited_issued_ticket_with_t_flag_verifies() {
    let (raw, key) = host_ap_req();
    verify(&raw, &key).expect("KDC-issued ticket has TRANSITED_POLICY_CHECKED");
}

#[test]
fn b2_rd_req_transited_unchecked_evil_hop_is_ill_cr_tkt() {
    let (raw, key) = host_ap_req();
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
fn b2_rd_req_transited_t_flag_skips_evil_hop() {
    let (raw, key) = host_ap_req();
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
fn b2_rd_req_transited_unchecked_empty_verifies() {
    let (raw, key) = host_ap_req();
    let raw2 = rewrite_ticket(&raw, &key, |part| {
        part.flags = part
            .flags
            .clone()
            .with_bit(flag_bit::TRANSITED_POLICY_CHECKED, false);
        part.transited = TransitedEncoding::empty();
    });
    verify(&raw2, &key).expect("empty transited is at most one hop");
}
