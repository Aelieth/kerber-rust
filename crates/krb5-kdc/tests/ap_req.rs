//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_asn1::{decode, encode};
use krb5_crypto::{KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_kdc::{
    Error, PrincipalStore, TEST_ADMIN, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req,
    bootstrap_documented, documented_admin_id, documented_host, pa_enc_timestamp, tgs_req,
};
use krb5_protocol::{ReplayCache, build_ap_req, verify_ap_req};
use krb5_testkit::issue_tgt_password;
use krb5_types::{ApReq, KrbError, PrincipalName, ascii, err, ku, pa};

#[test]
fn ap_req_valid_truncated_wrong_key_replay() {
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        21,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS");
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        22,
    )
    .expect("TGS-REQ");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");

    let ap = build_ap_req(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
    )
    .expect("build AP-REQ");
    let raw = encode(&ap).expect("AP-REQ der");

    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &documented_host())
        .expect("ktadd");
    let service_key = &kt.entries[0].key;

    let replay = ReplayCache::new();
    verify_ap_req(&raw, service_key, &replay).expect("valid AP-REQ");

    let truncated = &raw[..raw.len() / 2];
    assert!(verify_ap_req(truncated, service_key, &ReplayCache::new()).is_err());

    let wrong = ProtocolKey::from_bytes(
        service_key.etype(),
        &vec![0x11u8; service_key.as_bytes().len()],
    )
    .expect("wrong key");
    assert!(verify_ap_req(&raw, &wrong, &ReplayCache::new()).is_err());

    let replay2 = ReplayCache::new();
    verify_ap_req(&raw, service_key, &replay2).expect("first");
    let replay_err = verify_ap_req(&raw, service_key, &replay2).unwrap_err();
    match replay_err {
        krb5_protocol::Error::KrbError { code, .. } => assert_eq!(code, err::REPEAT),
        other => panic!("expected REPEAT, got {other}"),
    }
}

#[test]
fn tgs_authenticator_replay_is_repeat() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        31,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS");
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        32,
    )
    .expect("TGS-REQ");
    krb5_kdc::issue_tgs(&store, &tgs).expect("first TGS");
    let replay_err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    match replay_err {
        Error::Protocol { code, .. } => {
            assert_eq!(
                code,
                err::REPEAT,
                "TGS authenticator replay must set REPEAT"
            );
        }
        other => panic!("expected REPEAT, got {other}"),
    }
}

#[test]
fn pa_enc_timestamp_replay_is_repeat() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let padata = vec![pa_enc_timestamp(&key).expect("pa-ts")];
    let req = as_req(cname, TEST_REALM, 33, Some(padata)).unwrap();
    krb5_kdc::issue_as(&store, &req).expect("first AS");
    let replay_err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    match replay_err {
        Error::Protocol { code, .. } => {
            assert_eq!(code, err::REPEAT, "same PA-ENC-TIMESTAMP must set REPEAT");
        }
        other => panic!("expected REPEAT, got {other}"),
    }
}

fn map_tgs_authenticator_cksum(
    tgs: &mut krb5_types::TgsReq,
    session: &ProtocolKey,
    f: impl FnOnce(&mut krb5_types::Checksum),
) {
    let pa = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ");
    let mut ap: ApReq = decode(pa.padata_value.as_ref()).expect("ap");
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).unwrap();
    let auth_plain = decrypt(session, auth_usage, ap.authenticator.cipher.as_ref()).expect("auth");
    let mut authenticator: krb5_types::Authenticator = decode(&auth_plain).expect("authenticator");
    f(authenticator.cksum.as_mut().expect("cksum"));
    let auth_der = encode(&authenticator).expect("auth der");
    ap.authenticator.cipher = encrypt(session, auth_usage, &auth_der).expect("enc").into();
    pa.padata_value = encode(&ap).expect("ap").into();
}

fn assert_process_tgs(err: Error, code: i32) {
    match err {
        Error::Protocol {
            code: got, text, ..
        } => {
            assert_eq!(got, code);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("expected {code} PROCESS_TGS, got {other:?}"),
    }
}

fn assert_krb_error(bytes: &[u8], code: i32, e_text: &str) {
    assert_eq!(bytes.first(), Some(&0x7e), "expected KRB-ERROR");
    let e: KrbError = decode(bytes).expect("KrbError");
    assert_eq!(e.error_code, code);
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(text, Some(e_text));
}

fn tgs_wire_reply(store: &PrincipalStore, tgs: &krb5_types::TgsReq) -> Vec<u8> {
    krb5_kdc::handle_request(store, &encode(tgs).expect("der")).expect("reply")
}

#[test]
fn tgs_authenticator_unknown_cksumtype_is_sumtype_nosupp() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 930);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        931,
    )
    .unwrap();
    map_tgs_authenticator_cksum(&mut tgs, &issued.session_key, |ck| ck.cksumtype = 99);
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("unknown cksumtype");
    assert_process_tgs(err, err::SUMTYPE_NOSUPP);
}

#[test]
fn tgs_authenticator_bad_bytes_is_bad_integrity() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 932);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        933,
    )
    .unwrap();
    map_tgs_authenticator_cksum(&mut tgs, &issued.session_key, |ck| {
        let mut b = ck.checksum.to_vec();
        b[0] ^= 0xff;
        ck.checksum = b.into();
    });
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("bad TGS checksum");
    assert_process_tgs(err, err::BAD_INTEGRITY);
}

#[test]
fn tgs_authenticator_cksum_provider_mismatch_is_generic() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 940);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        941,
    )
    .unwrap();
    map_tgs_authenticator_cksum(&mut tgs, &issued.session_key, |ck| {
        ck.cksumtype = 15;
        ck.checksum = vec![0u8; 12].into();
    });
    let bytes = tgs_wire_reply(&store, &tgs);
    assert_krb_error(&bytes, err::GENERIC, "PROCESS_TGS");
}

#[test]
fn tgs_authenticator_cksum_wrong_length_is_generic() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 942);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        943,
    )
    .unwrap();
    map_tgs_authenticator_cksum(&mut tgs, &issued.session_key, |ck| {
        let mut b = ck.checksum.to_vec();
        b.pop();
        ck.checksum = b.into();
    });
    let bytes = tgs_wire_reply(&store, &tgs);
    assert_krb_error(&bytes, err::GENERIC, "PROCESS_TGS");
}

#[test]
fn tgs_authenticator_missing_checksum_is_process_tgs() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 944);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        945,
    )
    .unwrap();
    let pa = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ");
    let mut ap: ApReq = decode(pa.padata_value.as_ref()).expect("ap");
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).unwrap();
    let auth_plain = decrypt(
        &issued.session_key,
        auth_usage,
        ap.authenticator.cipher.as_ref(),
    )
    .expect("auth");
    let mut authenticator: krb5_types::Authenticator = decode(&auth_plain).expect("authenticator");
    authenticator.cksum = None;
    let auth_der = encode(&authenticator).expect("auth der");
    ap.authenticator.cipher = encrypt(&issued.session_key, auth_usage, &auth_der)
        .expect("enc")
        .into();
    pa.padata_value = encode(&ap).expect("ap").into();
    let bytes = tgs_wire_reply(&store, &tgs);
    assert_krb_error(&bytes, err::INAPP_CKSUM, "PROCESS_TGS");
}

#[test]
fn tgs_authenticator_cname_mismatch_is_badmatch() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 904);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        905,
    )
    .unwrap();
    let pa = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ");
    let mut ap: ApReq = decode(pa.padata_value.as_ref()).expect("ap");
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).unwrap();
    let auth_plain = decrypt(
        &issued.session_key,
        auth_usage,
        ap.authenticator.cipher.as_ref(),
    )
    .expect("auth");
    let mut authenticator: krb5_types::Authenticator = decode(&auth_plain).expect("authenticator");
    authenticator.cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let auth_der = encode(&authenticator).expect("auth der");
    ap.authenticator.cipher = encrypt(&issued.session_key, auth_usage, &auth_der)
        .expect("enc")
        .into();
    pa.padata_value = encode(&ap).expect("ap").into();
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("cname mismatch");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::BADMATCH);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("expected 36 BADMATCH PROCESS_TGS, got {other:?}"),
    }
}

#[test]
fn tgs_authenticator_crealm_mismatch_is_badmatch() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 906);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        907,
    )
    .unwrap();
    let pa = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ");
    let mut ap: ApReq = decode(pa.padata_value.as_ref()).expect("ap");
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).unwrap();
    let auth_plain = decrypt(
        &issued.session_key,
        auth_usage,
        ap.authenticator.cipher.as_ref(),
    )
    .expect("auth");
    let mut authenticator: krb5_types::Authenticator = decode(&auth_plain).expect("authenticator");
    authenticator.crealm = ascii("OTHER.TEST");
    let auth_der = encode(&authenticator).expect("auth der");
    ap.authenticator.cipher = encrypt(&issued.session_key, auth_usage, &auth_der)
        .expect("enc")
        .into();
    pa.padata_value = encode(&ap).expect("ap").into();
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("crealm mismatch");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::BADMATCH);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("expected 36 BADMATCH PROCESS_TGS, got {other:?}"),
    }
}

#[test]
fn tgs_header_unknown_kvno_is_generic() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 417);
    let mut tkt = issued.rep.0.ticket.clone();
    tkt.enc_part.kvno = Some(99);
    let tgs = tgs_req(
        tkt,
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        418,
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("unknown kvno");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::GENERIC);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("expected 60 PROCESS_TGS, got {other:?}"),
    }
}

#[test]
fn tgs_header_kvno_zero_issues() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 419);
    let mut tkt = issued.rep.0.ticket.clone();
    tkt.enc_part.kvno = Some(0);
    let tgs = tgs_req(
        tkt,
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        420,
    )
    .unwrap();
    krb5_kdc::issue_tgs(&store, &tgs).expect("kvno 0 retries");
}
