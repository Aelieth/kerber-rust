//! RFC 4121 wrap unwrap (`unwrap.c` `unwrap_v3` / `verify_enc_header`)
//! and the callers of `unwrap_v3` / `process_checksum`.

#[path = "common/mod.rs"]
mod common;
use common::issue_tgt;

use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt, string_to_key};
use krb5_gss::{DelegCred, Error, GSS_C_DELEG, GSS_C_PROT_READY, GssContext};
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_host,
};
use krb5_kdc::{S2K_ITERS, as_req, pa_enc_timestamp, tgs_req};

use krb5_protocol::ReplayCache;
use krb5_types::{PrincipalName, TicketFlags, ascii, ku};

fn contexts() -> (GssContext, GssContext) {
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
    let skey = &host.best_key().unwrap().key;
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

fn conf_token(
    key: &krb5_crypto::ProtocolKey,
    initiator: bool,
    seq: u64,
    plaintext: &[u8],
    ec: u16,
    rrc: u16,
) -> Vec<u8> {
    let usage = KeyUsage::from_rfc(if initiator {
        ku::GSS_INITIATOR_SEAL
    } else {
        ku::GSS_ACCEPTOR_SEAL
    });
    let mut header = [0u8; 16];
    header[0] = 0x05;
    header[1] = 0x04;
    header[2] = 0x02;
    if !initiator {
        header[2] |= 0x01;
    }
    header[3] = 0xFF;
    header[4..6].copy_from_slice(&ec.to_be_bytes());
    header[8..16].copy_from_slice(&seq.to_be_bytes());
    let mut to_enc = plaintext.to_vec();
    to_enc.extend(vec![0xFF; usize::from(ec)]);
    to_enc.extend_from_slice(&header);
    let cipher = encrypt(key, usage, &to_enc).unwrap();
    let mut tok = header.to_vec();
    tok.extend_from_slice(&cipher);
    if rrc != 0 && tok.len() > 16 {
        tok[6..8].copy_from_slice(&rrc.to_be_bytes());
        let n = usize::from(rrc);
        let cipher = tok[16..].to_vec();
        if n > 0 && n < cipher.len() {
            let mut rotated = Vec::with_capacity(cipher.len());
            rotated.extend_from_slice(&cipher[n..]);
            rotated.extend_from_slice(&cipher[..n]);
            tok[16..].copy_from_slice(&rotated);
        }
    }
    tok
}

#[test]
fn unwrap_direction_flipped_is_bad_sig() {
    let (mut init, mut acc) = contexts();
    let mut tok = init.wrap(b"dir").unwrap();
    tok[2] ^= 0x01;
    assert!(matches!(acc.unwrap(&tok), Err(Error::Integrity)));
}

#[test]
fn unwrap_bad_filler_is_defective() {
    let (mut init, mut acc) = contexts();
    let mut tok = init.wrap(b"fill").unwrap();
    tok[3] = 0x00;
    assert!(matches!(acc.unwrap(&tok), Err(Error::Truncated)));
}

#[test]
fn unwrap_conf_ec_padding_is_stripped() {
    let (init, mut acc) = contexts();
    let tok = conf_token(init.session_key(), true, 0, b"ec-plain", 16, 0);
    let plain = acc.unwrap(&tok).unwrap();
    assert_eq!(plain, b"ec-plain");
}

#[test]
fn unwrap_rrc_round_trip_both_directions() {
    let (mut init, mut acc) = contexts();
    let tok = init.wrap_with_rrc(b"rrc-init", 16).unwrap();
    assert_ne!(&tok[6..8], &[0, 0]);
    assert_eq!(acc.unwrap(&tok).unwrap(), b"rrc-init");
    let tok = acc.wrap_with_rrc(b"rrc-acc", 16).unwrap();
    assert_ne!(&tok[6..8], &[0, 0]);
    assert_eq!(init.unwrap(&tok).unwrap(), b"rrc-acc");
    let tok = conf_token(init.session_key(), true, 2, b"rrc-ec", 16, 16);
    assert_eq!(acc.unwrap(&tok).unwrap(), b"rrc-ec");
}

#[test]
fn unwrap_non_conf_ec_not_cksumsize_is_defective() {
    let (mut init, mut acc) = contexts();
    let mut tok = init.wrap_integ(b"ec").unwrap();
    tok[5] = tok[5].wrapping_add(1);
    assert!(matches!(acc.unwrap(&tok), Err(Error::Truncated)));
}

fn linked() -> (GssContext, GssContext) {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, 40);
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
    let tgt = issue_tgt(&store, TEST_USER, 42);
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
        flags: TicketFlags::none(),
        authtime: None,
        starttime: None,
        endtime: None,
        renew_till: None,
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
