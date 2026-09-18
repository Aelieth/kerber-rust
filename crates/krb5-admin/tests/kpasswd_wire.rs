//! Admin whole-flow tests moved from `src/lib.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
use common::*;

use krb5_admin::*;
use krb5_kdc::bootstrap_documented;
use krb5_protocol::ReplayCache;
use krb5_types::PrincipalName;

#[test]
fn kpasswd_rfc3244_bumps_kvno() {
    use krb5_asn1::encode;
    use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
    use krb5_protocol::{build_ap_req, build_krb_priv, pa_enc_timestamp};
    use krb5_types::ChangePasswdData;

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let kvno_before = store
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let changepw = documented_changepw();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 43);
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let ap_der = encode(&ap).unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"rfc3244-new".to_vec().into(),
        targname: Some(user.clone()),
        targrealm: Some(krb5_types::ascii(TEST_REALM)),
    };
    let cpw_der = encode(&cpw).unwrap();
    let priv_msg = build_krb_priv(&as_out.session_key, &cpw_der).unwrap();
    let priv_der = encode(&priv_msg).unwrap();
    let req = encode_setpw(&ap_der, &priv_der);
    let shared = shared_store(store);
    let replay = ReplayCache::new();
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &replay, &req).expect("kpasswd");
    assert!(
        rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
        "success reply must include AP-REP"
    );
    let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).expect("parse kpasswd rep");
    assert!(!ap_rep.is_empty() && !priv_rep.is_empty());
    assert!(parse_kpasswd_rep(&[0, 6, 0, 1, 0, 0]).is_err());
    let after = shared.read().unwrap();
    let kvno_after = after
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert!(kvno_after > kvno_before, "RFC 3244 must bump kvno");

    let salt = user.default_salt(TEST_REALM);
    let new_key = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"rfc3244-new",
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let as_new = krb5_kdc::as_req(
        user.clone(),
        TEST_REALM,
        45,
        Some(vec![pa_enc_timestamp(&new_key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&*after, &as_new).expect("AS with RFC 3244 new password");

    let as_old = krb5_kdc::as_req(
        user,
        TEST_REALM,
        46,
        Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
    )
    .unwrap();
    assert!(
        krb5_kdc::issue_as(&*after, &as_old).is_err(),
        "old password must fail after kpasswd"
    );
}

#[test]
fn kpasswd_accepts_first_current_ticket_when_best_key_differs() {
    use krb5_asn1::encode;
    use krb5_kdc::{
        TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
        bootstrap_realm_with_kdc_conf, documented_changepw, shared_dump as shared_store,
    };
    use krb5_protocol::{build_ap_req, build_krb_priv};
    use krb5_types::ChangePasswdData;

    let kdc = krb5_config::KdcConf::parse(
            r"
[realms]
    KERBER.TEST = {
        supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
",
        )
        .unwrap();
    let (store, acl) = bootstrap_realm_with_kdc_conf(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
        Some(&kdc),
    )
    .unwrap();
    let changepw = documented_changepw();
    let cpw = store.get_name(&changepw).unwrap();
    let first = cpw.first_current_key().unwrap();
    let best = cpw.best_key().unwrap();
    assert_eq!(first.etype.to_iana(), 20);
    assert_eq!(best.etype.to_iana(), 18);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 1919);
    assert_eq!(as_out.rep.0.ticket.enc_part.etype, 20);
    let cpw_key = best.key.clone();
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let cpw_data = ChangePasswdData {
        newpasswd: b"sha384-first-pass".to_vec().into(),
        targname: Some(user.clone()),
        targrealm: Some(krb5_types::ascii(TEST_REALM)),
    };
    let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw_data).unwrap()).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("rd_req must try every changepw key");
    assert!(
        rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
        "success reply must include AP-REP"
    );
}

#[test]
fn kpasswd_udp_listener_then_issue_as() {
    use std::net::UdpSocket;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    use krb5_asn1::encode;
    use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
    use krb5_protocol::{build_ap_req, build_krb_priv, pa_enc_timestamp};
    use krb5_types::ChangePasswdData;

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let changepw = documented_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 47);
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"udp-new-pass".to_vec().into(),
        targname: Some(user.clone()),
        targrealm: Some(krb5_types::ascii(TEST_REALM)),
    };
    let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw).unwrap()).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());

    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let shared = shared_store(store);
    let shared2 = shared.clone();
    let stop2 = Arc::clone(&stop);
    thread::spawn(move || {
        let _ = serve_kpasswd_udp(shared2, acl, cpw_key, sock, stop2);
    });
    thread::sleep(Duration::from_millis(30));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    // Debug s2k in change_password can exceed 2s before the reply.
    client
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    client.send_to(&req, addr).unwrap();
    let mut buf = [0u8; 4096];
    let n = client.recv(&mut buf).expect("kpasswd reply");
    assert!(n > 6, "RFC 3244 reply");
    stop.store(true, Ordering::Relaxed);
    let after = shared.read().unwrap();
    let salt = user.default_salt(TEST_REALM);
    let new_key = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"udp-new-pass",
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let as_new = krb5_kdc::as_req(
        user,
        TEST_REALM,
        49,
        Some(vec![pa_enc_timestamp(&new_key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&*after, &as_new).expect("AS after UDP kpasswd");
}

#[test]
fn kpasswd_mit_style_subkey_seq0_then_issue_as() {
    use krb5_asn1::encode;
    use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
    use krb5_protocol::{build_ap_req_with_cksum, build_krb_priv_with_seq, pa_enc_timestamp};
    use krb5_types::ApOptions;

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let changepw = documented_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 50);
    let sub = krb5_crypto::ProtocolKey::from_bytes(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        &[0x5au8; 32],
    )
    .unwrap();
    let sub_ek = krb5_types::EncryptionKey {
        keytype: sub.etype().to_iana(),
        keyvalue: sub.as_bytes().to_vec().into(),
    };
    let ap = build_ap_req_with_cksum(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
        ApOptions::none(),
        None,
        Some(sub_ek),
    )
    .unwrap();
    // MIT kpasswd: version 1, raw password, subkey, seq 0.
    let priv_msg = build_krb_priv_with_seq(&sub, b"kpasswd-one", Some(0)).unwrap();
    let req = encode_kpasswd_req(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let replay = ReplayCache::new();
    let rep =
        handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &replay, &req).expect("MIT-style kpasswd");
    assert!(
        rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
        "MIT kpasswd requires AP-REP on success"
    );
    let after = shared.read().unwrap();
    let salt = user.default_salt(TEST_REALM);
    let new_key = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"kpasswd-one",
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let as_new = krb5_kdc::as_req(
        user,
        TEST_REALM,
        52,
        Some(vec![pa_enc_timestamp(&new_key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&*after, &as_new).expect("AS after MIT-style kpasswd");
}

#[test]
fn kpasswd_vno1_der_stays_password() {
    use krb5_asn1::encode;
    use krb5_kdc::{
        TEST_ADMIN, TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store,
    };
    use krb5_protocol::{build_ap_req, build_krb_priv};
    use krb5_types::ChangePasswdData;

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let user_kvno = store
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let admin_kvno = store
        .get_name(&admin)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 61);
    let cpw_key = store
        .get_name(&documented_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"der-as-pass".to_vec().into(),
        targname: Some(admin.clone()),
        targrealm: Some(krb5_types::ascii(TEST_REALM)),
    };
    let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw).unwrap()).unwrap();
    let req = encode_kpasswd_req(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
    let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
    let user_data = krb5_protocol::unwrap_krb_priv_ex(
        &as_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 0,
        "vno-1 DER is a self-change password, got {user_data:?}"
    );
    let after = shared.read().unwrap();
    let user_kvno_after = after
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let admin_kvno_after = after
        .get_name(&admin)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert!(user_kvno_after > user_kvno, "vno-1 DER must set self");
    assert_eq!(admin_kvno_after, admin_kvno, "vno-1 DER must not retarget");
}

#[test]
fn kpasswd_udp_exchange_ignores_off_path() {
    use std::net::UdpSocket;
    use std::thread;
    use std::time::Duration;

    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dest = server.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 64];
        let (n, src) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"req");
        let spoof = UdpSocket::bind("127.0.0.1:0").unwrap();
        let _ = spoof.send_to(b"spoof", src);
        thread::sleep(Duration::from_millis(30));
        let _ = server.send_to(b"kdc-ok", src);
    });
    let got = kpasswd_udp_exchange_to(dest, b"req").expect("kdc reply");
    assert_eq!(got, b"kdc-ok");
}
