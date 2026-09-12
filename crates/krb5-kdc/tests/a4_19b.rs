//! A′-4 item 19 HEAD-only: TestPolicy, profile `supported_enctypes`, TGS key_exp.

use krb5_asn1::decode_enc_kdc_rep_part;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
use krb5_kdc::{
    Error, KdcPolicy, TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    TestPolicy, bootstrap_documented, clear_thread_policy, documented_admin_id, documented_host,
    set_thread_policy,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_types::{PrincipalName, err, ku};

fn proto(err: &Error) -> (i32, Option<&str>) {
    match err {
        Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

#[test]
fn a4_19_test_policy_fail_client_is_local_policy() {
    set_thread_policy(std::sync::Arc::new(TestPolicy));
    let (mut store, acl) = bootstrap_documented().unwrap();
    let fail = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["fail"]);
    store
        .create_password(&acl, &documented_admin_id(), &fail, b"fail-secret")
        .unwrap();
    let key = store
        .get_name(&fail)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        fail,
        TEST_REALM,
        1910,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let (code, text) = proto(&err);
    assert_eq!(code, err::POLICY);
    assert_eq!(text, Some("LOCAL_POLICY"));
    clear_thread_policy();
}

#[test]
fn a4_19_test_policy_foreign_indicator_is_local_policy() {
    set_thread_policy(std::sync::Arc::new(TestPolicy));
    let store = krb5_kdc::PrincipalStore::bootstrap(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
    )
    .unwrap();
    // Inject a non-ONE_HOUR/SEVEN_HOURS indicator via the store client path:
    // TestPolicy sees indicators from AS only after preauth. Use the
    // thread policy against a password AS with a dummy indicator by
    // setting require-style indicators on the issue path through SPAKE
    // is heavier; the name-deny cell above is the live gate's twin.
    // Here we call check_as directly.
    let user = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .unwrap()
        .clone();
    let err = TestPolicy
        .check_as(&store, &user, &["OTHER".into()])
        .unwrap_err();
    let (code, text) = proto(&err);
    assert_eq!(code, err::POLICY);
    assert_eq!(text, Some("LOCAL_POLICY"));
    clear_thread_policy();
}

#[test]
fn a4_19_test_policy_one_hour_rewrites_endtime() {
    set_thread_policy(std::sync::Arc::new(TestPolicy));
    let store = krb5_kdc::PrincipalStore::bootstrap(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
    )
    .unwrap();
    let user = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .unwrap()
        .clone();
    let adj = TestPolicy
        .check_as(&store, &user, &["ONE_HOUR".into()])
        .unwrap();
    assert_eq!(adj.lifetime, 3600);
    assert_eq!(adj.renew_lifetime, 7200);
    let tgs = TestPolicy
        .check_tgs(
            &store,
            &PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x"]),
            &["ONE_HOUR".into()],
        )
        .unwrap();
    assert_eq!(tgs.lifetime, 1800);
    assert_eq!(tgs.renew_lifetime, 3600);
    let seven = TestPolicy
        .check_as(&store, &user, &["SEVEN_HOURS".into()])
        .unwrap();
    assert_eq!(seven.lifetime, 7 * 3600);
    assert_eq!(seven.renew_lifetime, 14 * 3600);
    clear_thread_policy();
}

#[test]
fn a4_19_bootstrap_honours_supported_enctypes_order() {
    let kdc = krb5_config::KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
",
    )
    .unwrap();
    let store = krb5_kdc::PrincipalStore::bootstrap_with_kdc_conf(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
        Some(&kdc),
    )
    .unwrap();
    let keys: Vec<i32> = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .unwrap()
        .keys
        .iter()
        .map(|k| k.etype.to_iana())
        .collect();
    assert_eq!(keys, vec![20, 19, 18, 17]);
}

#[test]
fn a4_19_tgt_hex_must_use_ticket_etype_not_preferred() {
    let kdc = krb5_config::KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
",
    )
    .unwrap();
    let store = krb5_kdc::PrincipalStore::bootstrap_with_kdc_conf(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
        Some(&kdc),
    )
    .unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        user,
        TEST_REALM,
        1920,
        Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
    )
    .unwrap();
    let tgt = krb5_kdc::issue_as(&store, &req).unwrap();
    assert_eq!(tgt.rep.0.ticket.enc_part.etype, 20);
    let first = store.krbtgt().unwrap().first_current_key().unwrap();
    assert_eq!(first.etype.to_iana(), 20);
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let as18 =
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, first.key.as_bytes()).unwrap();
    assert!(
        decrypt(&as18, usage, tgt.rep.0.ticket.enc_part.cipher.as_ref()).is_err(),
        "etype-20 TGT is not decryptable as preferred etype 18"
    );
    decrypt(&first.key, usage, tgt.rep.0.ticket.enc_part.cipher.as_ref()).unwrap();

    let as_usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let enc_plain = decrypt(
        &tgt.as_rep_key,
        as_usage,
        tgt.rep.0.enc_part.cipher.as_ref(),
    )
    .unwrap();
    let enc = decode_enc_kdc_rep_part(&enc_plain).unwrap();
    let cred = krb5_protocol::tgt_cred(
        &tgt.rep.0.crealm,
        &tgt.rep.0.cname,
        &tgt.rep.0.ticket,
        &tgt.session_key,
        &enc,
    )
    .unwrap();
    let cc = krb5_protocol::FileCcache::new(
        (tgt.rep.0.crealm.clone(), tgt.rep.0.cname.clone()),
        vec![cred],
    );
    let scratch = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("CARGO_TARGET_DIR")
                .map(|p| std::path::PathBuf::from(p).join("test-krb5"))
        })
        .or_else(|| std::env::var_os("KERBER_SCRATCH").map(std::path::PathBuf::from))
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/test-krb5")
        });
    let dir = scratch.join(format!("a4-19-forge-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let in_cc = dir.join("in.cc");
    let out_cc = dir.join("out.cc");
    cc.write_file(&in_cc).unwrap();
    let hex: String = first
        .key
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_krb5-forge-tgt"))
        .args([
            "--ccache",
            in_cc.to_str().unwrap(),
            "--out",
            out_cc.to_str().unwrap(),
            "--tgt",
            "krbtgt/KERBER.TEST",
            "--claim-realm",
            "B.TEST",
            "--key-hex",
            &hex,
        ])
        .status()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        status.success(),
        "forge-tgt must decrypt a profile-first (etype 20) TGT"
    );
}

#[test]
fn a4_19_tgs_key_exp_is_omitted() {
    let (store, _) = bootstrap_documented().unwrap();
    let key = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]),
        TEST_REALM,
        1903,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let tgt = krb5_kdc::issue_as(&store, &req).unwrap();
    let tgs = krb5_protocol::tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]),
        documented_host(),
        TEST_REALM,
        1904,
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART).unwrap();
    let plain = decrypt(&tgt.session_key, usage, out.rep.0.enc_part.cipher.as_ref()).unwrap();
    let enc = decode_enc_kdc_rep_part(&plain).unwrap();
    assert!(enc.key_expiration.is_none());
}
