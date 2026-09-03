//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt, string_to_key};
use krb5_kdc::{
    Acl, AdminOp, Error, KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_POSTDATED,
    KDB_DISALLOW_RENEWABLE, KDB_DISALLOW_SVR, KDB_DISALLOW_TGT_BASED, KDB_LOCKDOWN_KEYS,
    KDB_NO_AUTH_DATA_REQUIRED, KDB_OK_AS_DELEGATE, KDB_PWCHANGE_SERVICE, KDB_REQUIRES_HW_AUTH,
    KDB_REQUIRES_PWCHANGE, PrincipalStore, S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    acl_for_store, as_req, bootstrap_documented, documented_admin_id, documented_changepw,
    documented_host, documented_kadmin, pa_enc_timestamp, tgs_req,
};
use krb5_protocol::Keytab;
use krb5_protocol::{ReplayCache, as_req_sname, build_ap_req, tgs_req_ex, verify_ap_req};
use krb5_types::{
    EncAsRepPart, EncKdcRepPart, EncTgsRepPart, EncTicketPart, KdcOptions, KerberosTime, KrbError,
    OctetString, PrincipalName, ascii, err, flag_bit, ku,
};

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
    if let Ok(EncAsRepPart(p)) = decode::<EncAsRepPart>(plain) {
        return p;
    }
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
        .create_host(&acl, &documented_admin_id(), &extra)
        .expect("admin create");
    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &extra)
        .expect("admin ktadd");
    let bytes = kt.to_bytes();
    assert_eq!(&bytes[..2], &[0x05, 0x02]);
    let parsed = Keytab::parse(&bytes).expect("keytab v2");
    assert_eq!(
        parsed.entries.len(),
        4,
        "host randkeys include etypes 17–20"
    );
    assert!(
        parsed
            .entries
            .iter()
            .any(|e| e.key.etype() == EncryptionType::Aes256CtsHmacSha384192)
    );
    assert_eq!(
        parsed.entries[0].name.components_joined(),
        "host/extra.kerber.test"
    );
}

#[test]
fn export_keytab_lockdown_is_denied() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .apply_admin_fields(
            &documented_host(),
            Some(KDB_LOCKDOWN_KEYS),
            None,
            None,
            None,
            None,
            false,
        )
        .expect("lockdown");
    let err = store
        .export_keytab(&acl, &documented_admin_id(), &documented_host())
        .unwrap_err();
    assert_eq!(err, Error::AclDenied);
}

#[test]
fn export_keytab_local_bypasses_lockdown() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let tgt = PrincipalName::krbtgt(TEST_REALM);
    store
        .apply_admin_fields(&tgt, Some(KDB_LOCKDOWN_KEYS), None, None, None, None, false)
        .expect("lockdown krbtgt");
    let err = store
        .export_keytab(&acl, &documented_admin_id(), &tgt)
        .unwrap_err();
    assert_eq!(err, Error::AclDenied);
    let kt = store
        .export_keytab_local(&tgt)
        .expect("local --export-krbtgt-keytab");
    assert!(!kt.entries.is_empty());
    assert_eq!(kt.entries[0].name.components_joined(), "krbtgt/KERBER.TEST");
}

#[test]
fn acl_deny_non_admin_create_delete_ktadd() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let user = format!("{TEST_USER}@{TEST_REALM}");
    let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "denied.kerber.test"]);
    let err = store.create_host(&acl, &user, &extra).unwrap_err();
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
    assert!(acl.check("admin@KERBER.TEST", AdminOp::Modify).is_ok());
    assert!(acl.check("admin@KERBER.TEST", AdminOp::SetKey).is_ok());
    assert!(acl.check("admin@KERBER.TEST", AdminOp::Inquire).is_ok());
    assert_eq!(
        acl.check("admin@KERBER.TEST", AdminOp::Extract)
            .unwrap_err(),
        Error::AclDenied,
        "MIT * / x does not grant extract"
    );
    assert_eq!(
        acl.check("user@KERBER.TEST", AdminOp::Ktadd).unwrap_err(),
        Error::AclDenied
    );
    assert!(acl.check("user@KERBER.TEST", AdminOp::Inquire).is_ok());
    assert_eq!(
        acl.check("user@KERBER.TEST", AdminOp::Create).unwrap_err(),
        Error::AclDenied
    );
    assert_eq!(
        acl.check("user@KERBER.TEST", AdminOp::Modify).unwrap_err(),
        Error::AclDenied
    );
    assert_eq!(acl.privs("admin@KERBER.TEST"), 0x3F);
    assert_eq!(acl.privs("user@KERBER.TEST"), 0x01);
    assert_eq!(acl.privs("nobody@KERBER.TEST"), 0);
    let with_e = Acl::parse("admin@KERBER.TEST *e\n");
    assert!(with_e.check("admin@KERBER.TEST", AdminOp::Extract).is_ok());
    assert_eq!(with_e.privs("admin@KERBER.TEST"), 0x7F);
}

#[test]
fn as_without_preauth_is_preauth_required() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 7, None).unwrap();
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
    let req = as_req(cname.clone(), TEST_REALM, 11, Some(padata)).unwrap();
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

#[test]
fn handle_request_empty_is_error() {
    let store = PrincipalStore::new(TEST_REALM);
    let reply = krb5_kdc::handle_request(&store, &[]).expect("always a byte reply");
    assert!(!reply.is_empty());
    let e: krb5_types::KrbError = decode(&reply).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::GENERIC);
}

#[test]
fn non_ascii_realm_is_krb_error_not_panic() {
    let store = PrincipalStore::new("CAFÉ.TEST");
    let r = std::panic::catch_unwind(|| krb5_kdc::handle_request(&store, &[]));
    assert!(r.is_ok(), "untrusted realm must not panic ascii()");
    let reply = r.unwrap().expect("always a byte reply");
    let e: krb5_types::KrbError = decode(&reply).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::GENERIC);
}

#[test]
fn as_rep_flags_are_initial_and_preauth_not_renewable() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname,
        TEST_REALM,
        42,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let issued = krb5_kdc::issue_as(&store, &req).expect("AS");
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&key, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("dec");
    assert_eq!(
        plain.first().copied(),
        Some(0x79),
        "APPLICATION 25 EncASRepPart"
    );
    let enc = decode_enc_part(&plain);
    assert!(enc.flags.initial());
    assert!(enc.flags.pre_authent());
    assert!(!enc.flags.renewable());
    assert!(enc.renew_till.is_none());
}

#[test]
fn wrong_password_yields_preauth_failed_bytes() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let wrong = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"not-the-password",
        &cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k");
    let req = as_req(
        cname,
        TEST_REALM,
        5,
        Some(vec![pa_enc_timestamp(&wrong).expect("pa")]),
    )
    .unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    assert!(!bytes.is_empty());
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::PREAUTH_FAILED);
}

#[test]
fn no_common_etype_is_etype_nosupp() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let mut req = as_req(
        cname,
        TEST_REALM,
        6,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    req.0.req_body.etype = vec![23]; // rc4, not in store unless allow_weak
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::ETYPE_NOSUPP);
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
    assert_eq!(e.error_code, err::INAPP_CKSUM);
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
fn kadmind_acl_follows_store_realm_or_acl_file() {
    let none = acl_for_store("PROD.KERBER.TEST", None).expect("default acl");
    assert!(
        none.check("admin@PROD.KERBER.TEST", AdminOp::Create)
            .is_ok()
    );
    assert!(
        none.check(
            "kiprop/testhost.prod.kerber.test@PROD.KERBER.TEST",
            AdminOp::Propagate
        )
        .is_ok()
    );
    assert_eq!(
        none.check("admin@KERBER.TEST", AdminOp::Create)
            .unwrap_err(),
        Error::AclDenied
    );

    let dir = std::env::temp_dir().join(format!(
        "kadmind-acl-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("kadm5.acl");
    std::fs::write(
        &path,
        "admin@PROD.KERBER.TEST *\noperator@PROD.KERBER.TEST i\n",
    )
    .unwrap();
    let file = acl_for_store("PROD.KERBER.TEST", Some(&path)).expect("file acl");
    assert!(
        file.check("admin@PROD.KERBER.TEST", AdminOp::Create)
            .is_ok()
    );
    assert!(
        file.check("operator@PROD.KERBER.TEST", AdminOp::Inquire)
            .is_ok()
    );
    assert_eq!(
        file.check("admin@KERBER.TEST", AdminOp::Create)
            .unwrap_err(),
        Error::AclDenied
    );
    assert_eq!(
        file.check("operator@PROD.KERBER.TEST", AdminOp::Create)
            .unwrap_err(),
        Error::AclDenied
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn acl_file_without_realm_admin_add_is_discarded_not_merged() {
    let dir = std::env::temp_dir().join(format!(
        "kadmind-acl-discard-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("kadm5.acl");
    std::fs::write(&path, "operator@PROD.KERBER.TEST *\n").unwrap();
    let acl = acl_for_store("PROD.KERBER.TEST", Some(&path)).expect("discard to default");
    assert!(
        acl.check("admin@PROD.KERBER.TEST", AdminOp::Create).is_ok(),
        "realm admin must keep * after discard"
    );
    assert_eq!(
        acl.check("operator@PROD.KERBER.TEST", AdminOp::Create)
            .unwrap_err(),
        Error::AclDenied,
        "operator grant must not merge in when the file is discarded"
    );
    let _ = std::fs::remove_dir_all(&dir);
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

fn user_as_req(nonce: u32) -> krb5_types::AsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa-ts")]),
    )
    .unwrap()
}

fn proto_code(e: Error) -> i32 {
    match e {
        Error::Protocol { code, .. } => code,
        other => panic!("expected protocol error, got {other:?}"),
    }
}

#[test]
fn as_rejects_expired_principal_before_expired_password() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .apply_admin_fields(&cname, None, None, Some(1), Some(1), None, false)
        .unwrap();
    let err = krb5_kdc::issue_as(&store, &user_as_req(41)).unwrap_err();
    assert_eq!(proto_code(err), err::NAME_EXP);

    let raw = encode(&user_as_req(42)).unwrap();
    let reply = krb5_kdc::handle_request(&store, &raw).unwrap();
    let krb: KrbError = decode(&reply).expect("KRB-ERROR");
    assert_eq!(krb.error_code, err::NAME_EXP);
}

#[test]
fn as_rejects_expired_password_unless_pwchange_service() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .apply_admin_fields(&cname, None, None, Some(0), Some(1), None, false)
        .unwrap();
    let err = krb5_kdc::issue_as(&store, &user_as_req(43)).unwrap_err();
    assert_eq!(proto_code(err), err::KEY_EXPIRED);

    let key = client_key();
    let changepw = as_req_sname(
        cname.clone(),
        TEST_REALM,
        44,
        Some(vec![pa_enc_timestamp(&key).expect("pa-ts")]),
        documented_changepw(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    krb5_kdc::issue_as(&store, &changepw).expect("PWCHANGE_SERVICE allows expired key");
}

#[test]
fn as_needchange_is_key_expired_unless_changepw() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    or_attr(&mut store, &cname, KDB_REQUIRES_PWCHANGE);
    let err = krb5_kdc::issue_as(&store, &user_as_req(48)).unwrap_err();
    assert_eq!(proto_code(err), err::KEY_EXPIRED);
    let key = client_key();
    let changepw = as_req_sname(
        cname,
        TEST_REALM,
        49,
        Some(vec![pa_enc_timestamp(&key).expect("pa-ts")]),
        documented_changepw(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    krb5_kdc::issue_as(&store, &changepw).expect("PWCHANGE_SERVICE allows +needchange");
}

#[test]
fn as_zero_expiration_still_issues() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .apply_admin_fields(&cname, None, None, Some(0), Some(0), None, false)
        .unwrap();
    krb5_kdc::issue_as(&store, &user_as_req(45)).expect("0 = never");
    store
        .apply_admin_fields(
            &cname,
            None,
            None,
            Some(u32::MAX),
            Some(u32::MAX),
            None,
            false,
        )
        .unwrap();
    krb5_kdc::issue_as(&store, &user_as_req(46)).expect("future still issues");
}

#[test]
fn tgs_issues_after_client_expires() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = krb5_kdc::issue_as(&store, &user_as_req(47)).expect("AS while unexpired");
    store
        .apply_admin_fields(&cname, None, None, Some(1), None, None, false)
        .unwrap();
    krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 48)).expect("TGS after NAME_EXP");

    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(49)).expect("AS while unexpired");
    store
        .apply_admin_fields(&cname, None, None, None, Some(1), None, false)
        .unwrap();
    krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 50)).expect("TGS after KEY_EXPIRED");
}

#[test]
fn tgs_rejects_expired_server() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let issued = krb5_kdc::issue_as(&store, &user_as_req(51)).expect("AS");
    store
        .apply_admin_fields(&host, None, None, Some(1), None, None, false)
        .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 52)).unwrap_err();
    assert_eq!(proto_code(err), err::SERVICE_EXP);
}

fn or_attr(store: &mut PrincipalStore, name: &PrincipalName, bit: u32) {
    let a = store.get_name(name).unwrap().attributes | bit;
    store
        .apply_admin_fields(name, Some(a), None, None, None, None, false)
        .unwrap();
}

fn tgt_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> EncTicketPart {
    let tgt_key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &tgt_key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode(&plain).unwrap()
}

fn host_tgs(
    _store: &PrincipalStore,
    issued: &krb5_kdc::IssuedAs,
    nonce: u32,
) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        nonce,
    )
    .unwrap()
}

#[test]
fn as_strips_forwardable_when_disallow_forwardable() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let before = krb5_kdc::issue_as(&store, &user_as_req(60)).expect("AS");
    assert!(tgt_part(&store, &before).flags.forwardable());
    or_attr(&mut store, &cname, KDB_DISALLOW_FORWARDABLE);
    let after = krb5_kdc::issue_as(&store, &user_as_req(61)).expect("AS");
    assert!(!tgt_part(&store, &after).flags.forwardable());
}

#[test]
fn as_strips_renewable_when_disallow_renewable() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = user_as_req(62);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    or_attr(&mut store, &cname, KDB_DISALLOW_RENEWABLE);
    let issued = krb5_kdc::issue_as(&store, &req).expect("AS");
    assert!(!tgt_part(&store, &issued).flags.renewable());
}

#[test]
fn as_hw_auth_required_rejects_enc_ts() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    or_attr(&mut store, &cname, KDB_REQUIRES_HW_AUTH);
    let err = krb5_kdc::issue_as(&store, &user_as_req(63)).unwrap_err();
    assert_eq!(proto_code(err), err::PREAUTH_FAILED);
}

#[test]
fn as_disallow_all_tix_still_client_revoked() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    or_attr(&mut store, &cname, KDB_DISALLOW_ALL_TIX);
    let err = krb5_kdc::issue_as(&store, &user_as_req(64)).unwrap_err();
    assert_eq!(proto_code(err), err::CLIENT_REVOKED);
}

#[test]
fn tgs_strips_renewable_when_server_disallow_renewable() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let mut areq = user_as_req(77);
    areq.0.req_body.kdc_options = areq
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    let issued = krb5_kdc::issue_as(&store, &areq).expect("AS renewable");
    assert!(tgt_part(&store, &issued).flags.renewable());
    or_attr(&mut store, &host, KDB_DISALLOW_RENEWABLE);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        78,
        KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .expect("TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("strip not POLICY");
    let host_key = store.get_name(&host).unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &host_key.key,
        usage,
        out.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    let part: EncTicketPart = decode(&plain).unwrap();
    assert!(!part.flags.renewable());
}

fn renewable_as(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let mut req = user_as_req(nonce);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    krb5_kdc::issue_as(store, &req).expect("AS renewable")
}

fn renew_tgs(issued: &krb5_kdc::IssuedAs, nonce: u32) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        nonce,
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .expect("RENEW TGS-REQ")
}

fn tgs_tgt_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
    let tgt_key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &tgt_key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode(&plain).unwrap()
}

#[test]
fn as_sets_proxiable_when_requested() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let mut req = user_as_req(90);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::PROXIABLE, true);
    let issued = krb5_kdc::issue_as(&store, &req).expect("AS");
    assert!(tgt_part(&store, &issued).flags.proxiable());
}

#[test]
fn tgs_renew_preserves_renew_till() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = renewable_as(&store, 91);
    let before = tgt_part(&store, &issued);
    assert!(before.flags.renewable());
    let old_till = before.renew_till.clone().expect("renew_till");
    std::thread::sleep(std::time::Duration::from_secs(1));
    let out = krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 92)).expect("RENEW");
    let after = tgs_tgt_part(&store, &out);
    assert!(after.flags.renewable());
    assert_eq!(after.renew_till, Some(old_till));
    assert!(after.endtime.unix_seconds() >= before.endtime.unix_seconds());
}

#[test]
fn tgs_renew_strips_when_disallow_renewable() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = renewable_as(&store, 93);
    or_attr(&mut store, &cname, KDB_DISALLOW_RENEWABLE);
    let out = krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 94)).expect("RENEW strips");
    let after = tgs_tgt_part(&store, &out);
    assert!(!after.flags.renewable());
    assert!(after.renew_till.is_none());
}

#[test]
fn tgs_renew_after_endtime_still_issues() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.policy.skew = 0;
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .apply_admin_fields(&cname, None, Some(1), None, None, None, false)
        .unwrap();
    let issued = renewable_as(&store, 95);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 96)).unwrap_err();
    assert_eq!(proto_code(err), err::TKT_EXPIRED);
    krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 97)).expect("RENEW after endtime");
}

#[test]
fn tgs_renew_rejects_renew_till_not_after_now() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let skew = store.policy.skew;
    assert!(skew >= 2, "default skew must include [now-skew, now]");
    let issued = renewable_as(&store, 100);
    let tgt_key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut part = tgt_part(&store, &issued);
    let now = KerberosTime::now();
    part.renew_till = Some(now.add_seconds(-(skew / 2)).unwrap());
    // Stale PAC ticket-checksum would fail before the renew_till bound.
    part.authorization_data = None;
    let der = encode(&part).unwrap();
    let cipher = encrypt(&tgt_key.key, usage, &der).unwrap();
    let mut issued = issued;
    issued.rep.0.ticket.enc_part.cipher = OctetString::from(cipher);
    let err = krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 101)).unwrap_err();
    assert_eq!(proto_code(err), err::TKT_EXPIRED);
}

#[test]
fn tgs_renew_non_renewable_is_badoption() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(98)).expect("AS");
    assert!(!tgt_part(&store, &issued).flags.renewable());
    let err = krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 99)).unwrap_err();
    assert_eq!(proto_code(err), err::BADOPTION);
}

fn postdated_as_req(nonce: u32, from: KerberosTime) -> krb5_types::AsReq {
    let mut req = user_as_req(nonce);
    req.0.req_body.from = Some(from);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::MAY_POSTDATE, true)
        .with_bit(flag_bit::POSTDATED, true);
    req
}

fn validate_tgs(issued: &krb5_kdc::IssuedAs, nonce: u32) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        nonce,
        KdcOptions::forwardable().with_bit(flag_bit::VALIDATE, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .expect("VALIDATE TGS-REQ")
}

#[test]
fn as_postdated_is_invalid_until_validate() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.policy.skew = 0;
    let from = KerberosTime::now().add_seconds(2).unwrap();
    let issued = krb5_kdc::issue_as(&store, &postdated_as_req(110, from)).expect("postdated AS");
    let part = tgt_part(&store, &issued);
    assert!(part.flags.invalid());
    assert!(part.flags.bit(flag_bit::POSTDATED));
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 111)).unwrap_err();
    assert_eq!(proto_code(err), err::TKT_NYV);
    let too_soon = krb5_kdc::issue_tgs(&store, &validate_tgs(&issued, 112)).unwrap_err();
    assert_eq!(proto_code(too_soon), err::TKT_NYV);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let out = krb5_kdc::issue_tgs(&store, &validate_tgs(&issued, 113)).expect("VALIDATE");
    let after = tgs_tgt_part(&store, &out);
    assert!(!after.flags.invalid());
    krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 114))
        .expect_err("unvalidated TGT still NYV");
}

#[test]
fn as_may_postdate_alone_does_not_postdate() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let from = KerberosTime::now().add_seconds(60).unwrap();
    let mut req = user_as_req(123);
    req.0.req_body.from = Some(from);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::MAY_POSTDATE, true);
    let issued = krb5_kdc::issue_as(&store, &req).expect("AS");
    let part = tgt_part(&store, &issued);
    assert!(!part.flags.invalid());
    assert!(!part.flags.bit(flag_bit::POSTDATED));
    assert!(part.flags.bit(flag_bit::MAY_POSTDATE));
}

#[test]
fn tgs_validate_allows_starttime_within_skew() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let from = KerberosTime::now().add_seconds(2).unwrap();
    let issued = krb5_kdc::issue_as(&store, &postdated_as_req(124, from)).expect("postdated AS");
    krb5_kdc::issue_tgs(&store, &validate_tgs(&issued, 125)).expect("VALIDATE within skew");
}

#[test]
fn tgs_renew_strips_forwardable_when_disallow() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = renewable_as(&store, 126);
    assert!(tgt_part(&store, &issued).flags.forwardable());
    or_attr(&mut store, &cname, KDB_DISALLOW_FORWARDABLE);
    let out = krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 127)).expect("RENEW");
    assert!(!tgs_tgt_part(&store, &out).flags.forwardable());
}

#[test]
fn as_cannot_postdate_when_disallow() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    or_attr(&mut store, &cname, KDB_DISALLOW_POSTDATED);
    let from = KerberosTime::now().add_seconds(30).unwrap();
    let err = krb5_kdc::issue_as(&store, &postdated_as_req(115, from)).unwrap_err();
    assert_eq!(proto_code(err), err::CANNOT_POSTDATE);
}

#[test]
fn as_postdated_end_is_absolute_till() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let from = KerberosTime::now().add_seconds(60).unwrap();
    let till = from.add_seconds(300).unwrap();
    let mut req = postdated_as_req(121, from.clone());
    req.0.req_body.till = till.clone();
    let issued = krb5_kdc::issue_as(&store, &req).expect("postdated AS");
    let part = tgt_part(&store, &issued);
    assert_eq!(
        part.starttime.as_ref().map(KerberosTime::unix_seconds),
        Some(from.unix_seconds())
    );
    assert_eq!(part.endtime.unix_seconds(), till.unix_seconds());
}

#[test]
fn as_from_after_till_is_never_valid() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let till = KerberosTime::now().add_seconds(30).unwrap();
    let from = KerberosTime::now().add_seconds(90).unwrap();
    let mut req = postdated_as_req(122, from);
    req.0.req_body.till = till;
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    assert_eq!(proto_code(err), err::NEVER_VALID);
}

fn renew_and_validate_tgs(issued: &krb5_kdc::IssuedAs, nonce: u32) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        nonce,
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEW, true)
            .with_bit(flag_bit::VALIDATE, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .expect("RENEW+VALIDATE TGS-REQ")
}

#[test]
fn tgs_renew_and_validate_together_is_badoption() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let from = KerberosTime::now().add_seconds(1).unwrap();
    let issued = krb5_kdc::issue_as(&store, &postdated_as_req(116, from)).expect("postdated AS");
    assert!(!tgt_part(&store, &issued).flags.renewable());
    std::thread::sleep(std::time::Duration::from_secs(2));
    let err = krb5_kdc::issue_tgs(&store, &renew_and_validate_tgs(&issued, 117)).unwrap_err();
    assert_eq!(proto_code(err), err::BADOPTION);
}

fn renew_tgs_sname(
    issued: &krb5_kdc::IssuedAs,
    sname: PrincipalName,
    nonce: u32,
) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        sname,
        TEST_REALM,
        nonce,
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .expect("RENEW TGS-REQ")
}

#[test]
fn tgs_renew_wrong_sname_is_badoption() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = renewable_as(&store, 118);
    let err =
        krb5_kdc::issue_tgs(&store, &renew_tgs_sname(&issued, documented_host(), 119)).unwrap_err();
    assert_eq!(proto_code(err), err::BADOPTION);
    krb5_kdc::issue_tgs(&store, &renew_tgs(&issued, 120)).expect("RENEW krbtgt");
}

#[test]
fn bootstrap_changepw_and_admin_carry_kadm5_create_attributes() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let admin = store.get_name(&documented_kadmin()).expect("kadmin/admin");
    assert_eq!(admin.attributes, KDB_DISALLOW_TGT_BASED | KDB_LOCKDOWN_KEYS);
    let changepw = store
        .get_name(&documented_changepw())
        .expect("kadmin/changepw");
    assert_eq!(
        changepw.attributes,
        KDB_DISALLOW_TGT_BASED | KDB_PWCHANGE_SERVICE | KDB_LOCKDOWN_KEYS
    );
}

fn service_tgs(
    issued: &krb5_kdc::IssuedAs,
    sname: PrincipalName,
    nonce: u32,
) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        sname,
        TEST_REALM,
        nonce,
    )
    .unwrap()
}

fn assert_tgt_based_not_allowed(err: Error) {
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("TGT BASED NOT ALLOWED"));
        }
        other => panic!("expected POLICY TGT BASED NOT ALLOWED, got {other:?}"),
    }
}

#[test]
fn tgs_for_changepw_with_tgt_is_tgt_based_not_allowed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(801)).expect("AS");
    let err =
        krb5_kdc::issue_tgs(&store, &service_tgs(&issued, documented_changepw(), 802)).unwrap_err();
    assert_tgt_based_not_allowed(err);
}

#[test]
fn tgs_for_admin_with_tgt_is_tgt_based_not_allowed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(803)).expect("AS");
    let err =
        krb5_kdc::issue_tgs(&store, &service_tgs(&issued, documented_kadmin(), 804)).unwrap_err();
    assert_tgt_based_not_allowed(err);
}

#[test]
fn tgs_honors_svr_tgt_based_lockout_and_ok_as_delegate() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let issued = krb5_kdc::issue_as(&store, &user_as_req(65)).expect("AS");

    or_attr(&mut store, &host, KDB_DISALLOW_SVR);
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 66)).unwrap_err();
    assert_eq!(proto_code(err), err::MUST_USE_USER2USER);

    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(67)).expect("AS");
    or_attr(&mut store, &host, KDB_DISALLOW_TGT_BASED);
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 68)).unwrap_err();
    assert_eq!(proto_code(err), err::POLICY);

    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(69)).expect("AS");
    or_attr(&mut store, &host, KDB_DISALLOW_ALL_TIX);
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 70)).unwrap_err();
    assert_eq!(proto_code(err), err::S_PRINCIPAL_UNKNOWN);

    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let issued = krb5_kdc::issue_as(&store, &user_as_req(71)).expect("AS");
    or_attr(&mut store, &host, KDB_OK_AS_DELEGATE);
    let tgs = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 72)).expect("TGS");
    let host_key = store.get_name(&host).unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &host_key.key,
        usage,
        tgs.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    let part: EncTicketPart = decode(&plain).unwrap();
    assert!(part.flags.bit(flag_bit::OK_AS_DELEGATE));
}

#[test]
fn tgs_skips_pac_when_no_auth_data_required() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let issued = krb5_kdc::issue_as(&store, &user_as_req(73)).expect("AS");
    or_attr(&mut store, &host, KDB_NO_AUTH_DATA_REQUIRED);
    let tgs = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 74)).expect("TGS");
    let host_key = store.get_name(&host).unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &host_key.key,
        usage,
        tgs.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    let part: EncTicketPart = decode(&plain).unwrap();
    assert!(part.authorization_data.is_none());
}

#[test]
fn tgs_requires_hw_auth_without_hw_flag() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let issued = krb5_kdc::issue_as(&store, &user_as_req(75)).expect("AS");
    or_attr(&mut store, &host, KDB_REQUIRES_HW_AUTH);
    let err = krb5_kdc::issue_tgs(&store, &host_tgs(&store, &issued, 76)).unwrap_err();
    assert_eq!(proto_code(err), err::GENERIC);
}
