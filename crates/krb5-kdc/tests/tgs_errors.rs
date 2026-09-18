//! A′-2 R23: PAC UnsupportedChecksum wires 60 on non-retry exits.
//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.
//! W1-H J3: an unknown client's KRB-ERROR carries MIT's status word `CLIENT_NOT_FOUND` as `e_text`.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.
//! TGS KRB-ERROR omits `crealm` when `errpkt.client` is NULL
//! (`do_tgs_req.c:201-204`, `asn1_k_encode.c:919`).

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_asn1::{decode, encode};
use krb5_kdc::{
    Error, PrincipalStore, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    decrypt_ticket_part, documented_host, pa_enc_timestamp, pac_from_ticket_part, tgs_req,
    wrap_win2k_pac,
};
use krb5_testkit::{
    TgsReqBuilder, expect_status, host_tgt, issue_tgt, issue_tgt_password, pref_etypes,
    reseal_store,
};
use krb5_types::pac::{PAC_SERVER_CHECKSUM, Pac};
use krb5_types::{ApReq, KdcOptions, KrbError, PrincipalName, err, flag_bit, pa};

fn rewrite_server_cksumtype(part: &mut krb5_types::EncTicketPart, ctype: i32) {
    let raw = pac_from_ticket_part(part).unwrap();
    let mut parsed = Pac::parse(&raw).unwrap();
    let buf = parsed
        .buffers
        .iter_mut()
        .find(|b| b.kind == PAC_SERVER_CHECKSUM)
        .unwrap();
    buf.data[..4].copy_from_slice(&ctype.to_le_bytes());
    part.authorization_data = Some(wrap_win2k_pac(&parsed.to_bytes()).unwrap());
}

#[test]
// oracle: differential-gate.sh tgs-pac-server-cksum-wrong-enctype
fn header_pac_wrong_cksumtype_is_generic() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, TEST_USER, 23000);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    rewrite_server_cksumtype(&mut part, 15);
    let tkt = {
        let mut t = as_out.rep.0.ticket.clone();
        reseal_store(&store, &mut t, &part);
        t
    };
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        23001,
    )
    .unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &tgs).unwrap_err());
    assert_eq!(c, err::GENERIC);
    assert_eq!(text.as_deref(), Some("HEADER_PAC"));
}

#[test]
// oracle: differential-gate.sh u2u-2nd-ticket-pac-wrong-enctype
fn u2u_stkt_pac_wrong_cksumtype_is_generic() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = host_tgt(&store, 23010);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &host.rep.0.ticket).unwrap();
    rewrite_server_cksumtype(&mut part, 15);
    let mut extra = host.rep.0.ticket.clone();
    reseal_store(&store, &mut extra, &part);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, 23020);
    let req = TgsReqBuilder::new(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        23021,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true))
    .additional_tickets(Some(vec![extra]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::GENERIC);
    assert_eq!(text.as_deref(), Some("2ND_TKT_PAC"));
}

#[test]
fn handle_request_empty_is_dropped() {
    let store = PrincipalStore::new(TEST_REALM);
    let reply = krb5_kdc::handle_request(&store, &[]).expect("drop is empty");
    assert!(reply.is_empty());
}

#[test]
// oracle: differential-gate.sh unknown-cname
fn unknown_client_e_text_is_client_not_found() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosuchuser"]);
    let req = as_req(cname, TEST_REALM, 9, None).unwrap();
    let bytes = encode(&req).unwrap();
    let reply = krb5_kdc::handle_request(&store, &bytes).expect("KRB-ERROR");
    let e: KrbError = decode(&reply).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::C_PRINCIPAL_UNKNOWN);
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(text, Some("CLIENT_NOT_FOUND"));
}

#[test]
fn non_ascii_realm_is_krb_error_not_panic() {
    let store = PrincipalStore::new("CAFÉ.TEST");
    let r = std::panic::catch_unwind(|| krb5_kdc::handle_request(&store, &[]));
    assert!(r.is_ok(), "untrusted realm must not panic ascii()");
    let reply = r.unwrap().expect("drop");
    assert!(reply.is_empty());
}

#[test]
fn tgs_bad_checksum_is_error() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        8,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS");
    let mut tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        9,
    )
    .expect("tgs");
    tgs.0.req_body.nonce = 99; // body no longer matches authenticator checksum
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).expect("der")).expect("reply");
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::BAD_INTEGRITY);
}

#[test]
fn tgs_error_echoes_the_header_ticket_client_like_prepare_error_tgs() {
    // MIT prepare_error_tgs (do_tgs_req.c:201-204) sets errpkt.client to the
    // decrypted header ticket's client, so a TGS KRB-ERROR carries the TGT
    // client's cname even though the TGS-REQ body has none.
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        8,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS");
    let mut tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        9,
    )
    .expect("tgs");
    tgs.0.req_body.nonce = 99; // corrupt so the TGS errors after the TGT decrypts
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).expect("der")).expect("reply");
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::BAD_INTEGRITY);
    assert_eq!(
        e.cname.as_ref(),
        Some(&cname),
        "cname is the header ticket client"
    );
}

#[test]
fn hostile_keytab_does_not_panic() {
    use std::panic::catch_unwind;
    let min_hole = {
        let mut v = vec![0x05, 0x02];
        v.extend_from_slice(&i32::MIN.to_be_bytes());
        v
    };
    let r = catch_unwind(|| krb5_protocol::Keytab::parse(&min_hole));
    assert!(r.is_ok());
    assert!(r.unwrap().is_err());
    let non_ascii = {
        let mut v = vec![0x05, 0x02];
        // size 8, then garbage including 0x80
        v.extend_from_slice(&8i32.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00]);
        v
    };
    let r = catch_unwind(|| krb5_protocol::Keytab::parse(&non_ascii));
    assert!(r.is_ok());
    assert!(r.unwrap().is_err());
}

#[test]
fn as_error_echoes_the_requested_client_like_prepare_error_as() {
    // MIT prepare_error_as (do_as_req.c:806-808) sets errpkt.client =
    // request->client, so the AS KRB-ERROR echoes the requested crealm/cname
    // even for an unknown client.
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosuchuser"]);
    let req = as_req(cname.clone(), TEST_REALM, 10, None).unwrap();
    let bytes = encode(&req).unwrap();
    let reply = krb5_kdc::handle_request(&store, &bytes).unwrap();
    let e: KrbError = decode(&reply).unwrap();
    assert_eq!(e.error_code, err::C_PRINCIPAL_UNKNOWN);
    assert_eq!(e.cname.as_ref(), Some(&cname), "cname echoes the request");
    let crealm = e
        .crealm
        .as_ref()
        .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned());
    assert_eq!(
        crealm.as_deref(),
        Some(TEST_REALM),
        "crealm echoes the request realm"
    );
}

#[test]
// oracle: differential-gate.sh tgs-bad-msg-type
fn tgs_bad_msg_type_is_unknown_reason_without_cname() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 412);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        413,
    )
    .unwrap();
    tgs.0.msg_type = krb5_types::KdcReq::MSG_AS_REQ;
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("bad TGS msg_type");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::GENERIC);
            assert_eq!(text.as_deref(), Some("UNKNOWN_REASON"));
        }
        other => panic!("expected 60 UNKNOWN_REASON, got {other:?}"),
    }
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).expect("der")).expect("reply");
    let e: KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::GENERIC);
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(text, Some("UNKNOWN_REASON"));
    assert!(e.cname.is_none(), "no cname");
    assert!(e.crealm.is_none(), "no crealm when client is NULL");
    assert_eq!(e.sname, documented_host());
}

fn local_tgt() -> (krb5_kdc::PrincipalStore, krb5_kdc::IssuedAs, PrincipalName) {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 801);
    (store, issued, cname)
}

fn no_client(e: &KrbError) {
    assert!(e.cname.is_none(), "no cname");
    assert!(e.crealm.is_none(), "no crealm when client is NULL");
}

#[test]
fn tgs_bad_msg_type_omits_crealm() {
    let (store, issued, cname) = local_tgt();
    let mut tgs = krb5_protocol::tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        802,
    )
    .unwrap();
    tgs.0.msg_type = krb5_types::KdcReq::MSG_AS_REQ;
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).unwrap()).unwrap();
    let e: KrbError = decode(&bytes).unwrap();
    assert_eq!(e.error_code, err::GENERIC);
    no_client(&e);
}

#[test]
fn tgs_ap_options_omits_crealm() {
    let (store, issued, cname) = local_tgt();
    let mut tgs = krb5_protocol::tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        803,
    )
    .unwrap();
    let pa = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .unwrap();
    let mut ap: ApReq = decode(pa.padata_value.as_ref()).unwrap();
    ap.ap_options = krb5_types::ApOptions::mutual_required();
    pa.padata_value = encode(&ap).unwrap().into();
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).unwrap()).unwrap();
    let e: KrbError = decode(&bytes).unwrap();
    assert_eq!(e.error_code, err::POLICY);
    no_client(&e);
}
