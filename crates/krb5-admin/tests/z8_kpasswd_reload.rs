//! Z8.1: kpasswd reloads before mutate (`write_store` house rule).
//! Compiles at the parent: `handle_kpasswd_rfc3244`, `save_store` /
//! `load_store`, and `persist_paths` already exist; the parent writes
//! without `reload_if_stale()`.

use krb5_admin::{encode_kpasswd_req, handle_kpasswd_rfc3244};
use krb5_asn1::encode;
use krb5_kdc::{
    TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id, documented_changepw,
    load_store, save_store, shared_dump,
};
use krb5_protocol::{ReplayCache, as_req_sname, build_ap_req, build_krb_priv, pa_enc_timestamp};
use krb5_types::{ChangePasswdData, PrincipalName};

#[test]
fn z8_kpasswd_keeps_an_out_of_process_principal() {
    krb5_config::isolate_test_krb5();
    let dir = std::env::temp_dir().join(format!(
        "krb5-z8-kpw-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    save_store(&store, &db, &stash).expect("save");
    let store = load_store(&db, &stash).expect("load listener");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .expect("user")
        .best_key()
        .expect("key")
        .key
        .clone();
    let changepw = documented_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .expect("changepw")
        .best_key()
        .expect("key")
        .key
        .clone();
    let as_out = krb5_kdc::issue_as(
        &store,
        &as_req_sname(
            user.clone(),
            TEST_REALM,
            0x2400_0001,
            Some(vec![pa_enc_timestamp(&user_key).expect("pa")]),
            documented_changepw(),
            krb5_crypto::EncryptionType::preferred()
                .iter()
                .map(|e| e.to_iana())
                .collect(),
        )
        .expect("as-req"),
    )
    .expect("AS for kadmin/changepw");
    let shared = shared_dump(store);

    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["z8x"]);
    let mut other = load_store(&db, &stash).expect("load writer");
    other
        .create_password(&acl, &documented_admin_id(), &extra, b"z8x-secret")
        .expect("out-of-process addprinc");
    assert!(
        other.get_name(&extra).is_some(),
        "writer must persist z8x before kpasswd"
    );

    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .expect("AP-REQ");
    let cpw = ChangePasswdData {
        newpasswd: b"z8-kpw-newpass-1".to_vec().into(),
        targname: None,
        targrealm: None,
    };
    let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw).expect("cpw")).expect("priv");
    let mut req = encode_kpasswd_req(&encode(&ap).expect("ap"), &encode(&priv_msg).expect("priv"));
    req[2..4].copy_from_slice(&0xff80u16.to_be_bytes());
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("handler returns a datagram");
    assert!(
        rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
        "INITIAL self-change includes AP-REP"
    );

    let after = load_store(&db, &stash).expect("reload after kpasswd");
    assert!(
        after.get_name(&extra).is_some(),
        "kpasswd must reload before save so the out-of-process principal survives"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
