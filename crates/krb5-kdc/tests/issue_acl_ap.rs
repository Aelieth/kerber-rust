//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.

use krb5_asn1::{decode, encode};
use krb5_client::Keytab;
use krb5_crypto::{decrypt, string_to_key, EncryptionType, KeyUsage, ProtocolKey};
use krb5_kdc::{
    as_req, bootstrap_documented, documented_admin_id, documented_host, pa_enc_timestamp, tgs_req,
    Acl, AdminOp, Error, PrincipalStore, S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
};
use krb5_protocol::{build_ap_req, verify_ap_req, ReplayCache};
use krb5_types::{ascii, err, ku, EncKdcRepPart, EncTgsRepPart, EncTicketPart, PrincipalName};

fn client_key() -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(TEST_REALM);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k")
}

fn decode_enc_part(plain: &[u8]) -> EncKdcRepPart {
    if let Ok(EncTgsRepPart(p)) = decode::<EncTgsRepPart>(plain) {
        return p;
    }
    decode::<EncKdcRepPart>(plain).expect("enc-part")
}

#[test]
fn acl_allow_admin_create_and_ktadd() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "extra.kerber.test"]);
    store
        .create_host(&acl, &documented_admin_id(), extra.clone())
        .expect("admin create");
    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &extra)
        .expect("admin ktadd");
    let bytes = kt.to_bytes();
    assert_eq!(&bytes[..2], &[0x05, 0x02]);
    let parsed = Keytab::parse(&bytes).expect("keytab v2");
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(
        parsed.entries[0].name.components_joined(),
        "host/extra.kerber.test"
    );
}

#[test]
fn acl_deny_non_admin_create_delete_ktadd() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let user = format!("{TEST_USER}@{TEST_REALM}");
    let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "denied.kerber.test"]);
    let err = store.create_host(&acl, &user, extra.clone()).unwrap_err();
    assert_eq!(err, Error::AclDenied);
    let err = store
        .export_keytab(&acl, &user, &documented_host())
        .unwrap_err();
    assert_eq!(err, Error::AclDenied);
    let err = store.delete(&acl, &user, &documented_host()).unwrap_err();
    assert_eq!(err, Error::AclDenied);
    assert!(acl.check(&user, AdminOp::Create).is_err());
}

#[test]
fn acl_parse_kadm5_style() {
    let acl = Acl::parse("admin@KERBER.TEST *\nuser@KERBER.TEST i\n# comment\n");
    assert!(acl.check("admin@KERBER.TEST", AdminOp::Create).is_ok());
    assert!(acl.check("user@KERBER.TEST", AdminOp::Ktadd).is_ok());
    assert_eq!(
        acl.check("user@KERBER.TEST", AdminOp::Create).unwrap_err(),
        Error::AclDenied
    );
}

#[test]
fn as_without_preauth_is_preauth_required() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 7, None);
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    match err {
        Error::PreauthRequired { e_data } => assert!(!e_data.is_empty()),
        other => panic!("expected PreauthRequired, got {other:?}"),
    }
}

#[test]
fn as_and_tgs_issue_decryptable_tickets() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let padata = vec![pa_enc_timestamp(&key).expect("pa-ts")];
    let req = as_req(cname.clone(), TEST_REALM, 11, Some(padata));
    let issued = krb5_kdc::issue_as(&store, &req).expect("AS");

    let usage_as = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&key, usage_as, issued.rep.0.enc_part.cipher.as_ref()).expect("AS enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 11);
    assert_eq!(issued.session_key.as_bytes(), enc.key.keyvalue.as_ref());

    let tgt_key = store.krbtgt().expect("krbtgt").best_key().expect("key");
    let usage_tkt = KeyUsage::new(ku::TICKET).unwrap();
    assert_ne!(usage_tkt.get(), 0);
    let tkt_plain = decrypt(
        &tgt_key.key,
        usage_tkt,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .expect("TGT enc-part");
    let part: EncTicketPart = decode(&tkt_plain).expect("EncTicketPart");
    assert_eq!(part.cname.components_joined(), TEST_USER);
    assert_eq!(part.key.keyvalue.as_ref(), issued.session_key.as_bytes());

    let tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        13,
    )
    .expect("TGS-REQ");
    let tgs_issued = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let usage_tgs = KeyUsage::new(ku::TGS_REP_ENC_PART).unwrap();
    let tgs_plain = decrypt(
        &issued.session_key,
        usage_tgs,
        tgs_issued.rep.0.enc_part.cipher.as_ref(),
    )
    .expect("TGS enc");
    let tgs_enc = decode_enc_part(&tgs_plain);
    assert_eq!(tgs_enc.nonce, 13);

    let host = store.get_name(&documented_host()).expect("host");
    let host_key = host.best_key().expect("host key");
    let svc_plain = decrypt(
        &host_key.key,
        usage_tkt,
        tgs_issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .expect("service ticket");
    let svc: EncTicketPart = decode(&svc_plain).expect("host EncTicketPart");
    assert_eq!(svc.cname.components_joined(), TEST_USER);
    assert_eq!(svc.key.keyvalue.as_ref(), tgs_issued.session_key.as_bytes());
}

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
    );
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

    let mut replay = ReplayCache::new();
    verify_ap_req(&raw, service_key, &mut replay).expect("valid AP-REQ");

    let truncated = &raw[..raw.len() / 2];
    assert!(verify_ap_req(truncated, service_key, &mut ReplayCache::new()).is_err());

    let wrong = ProtocolKey::from_bytes(
        service_key.etype(),
        &vec![0x11u8; service_key.as_bytes().len()],
    )
    .expect("wrong key");
    assert!(verify_ap_req(&raw, &wrong, &mut ReplayCache::new()).is_err());

    let mut replay2 = ReplayCache::new();
    verify_ap_req(&raw, service_key, &mut replay2).expect("first");
    let replay_err = verify_ap_req(&raw, service_key, &mut replay2).unwrap_err();
    match replay_err {
        krb5_protocol::Error::KrbError { code, .. } => assert_eq!(code, err::REPEAT),
        other => panic!("expected REPEAT, got {other}"),
    }
}

#[test]
fn handle_request_empty_is_error() {
    let store = PrincipalStore::new(TEST_REALM);
    assert!(krb5_kdc::handle_request(&store, &[]).is_err());
}

#[test]
fn documented_kadm5_acl_file_shape() {
    let text = include_str!("../../../harness/kadm5.acl");
    let acl = Acl::parse(text);
    // Harness ACL lists */admin@KERBER.TEST with *.
    assert!(acl.check("foo/admin@KERBER.TEST", AdminOp::Create).is_ok());
    assert_eq!(
        acl.check("user@KERBER.TEST", AdminOp::Create).unwrap_err(),
        Error::AclDenied
    );
}
