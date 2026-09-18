//! Admin whole-flow tests moved from `src/lib.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
use common::*;

use krb5_admin::*;
use krb5_kdc::bootstrap_documented;
use krb5_protocol::ReplayCache;
use krb5_types::PrincipalName;

#[test]
fn kpasswd_unknown_version_is_bad_version() {
    use krb5_kdc::{documented_changepw, shared_dump as shared_store};

    let (store, acl) = bootstrap_documented().unwrap();
    let cpw_key = store
        .get_name(&documented_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = [0u8, 6, 0, 2, 0, 0];
    let shared = shared_store(store);
    let err = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect_err("MIT dispatch sends no reply");
    assert!(
        err.to_string()
            .contains("Requested protocol version not supported"),
        "{err}"
    );
}

#[test]
fn kpasswd_inconsistent_length_is_malformed() {
    use krb5_kdc::{documented_changepw, shared_dump as shared_store};

    let (store, acl) = bootstrap_documented().unwrap();
    let cpw_key = store
        .get_name(&documented_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = [0u8, 99, 0, 1, 0, 0];
    let shared = shared_store(store);
    let err = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect_err("MIT dispatch sends no reply");
    assert!(err.to_string().contains("Message stream modified"), "{err}");
}

#[test]
fn kpasswd_bad_ap_req_is_chpwfail_autherror() {
    use krb5_asn1::decode;
    use krb5_kdc::{documented_changepw, shared_dump as shared_store};
    use krb5_types::KrbError;

    let (store, acl) = bootstrap_documented().unwrap();
    let cpw_key = store
        .get_name(&documented_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = encode_kpasswd_req(&[0, 1, 2, 3], b"x");
    let shared = shared_store(store);
    let r1 = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("chpwfail");
    let r2 = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("retransmit");
    for rep in [&r1, &r2] {
        assert!(rep.len() > 6);
        assert_eq!(&rep[4..6], &[0, 0], "AP-REP length 0");
        let e: KrbError = decode(&rep[6..]).expect("framed KRB-ERROR");
        assert_eq!(e.error_code, krb5_types::err::GENERIC);
        assert!(e.e_text.is_none());
        assert_eq!(e.sname.name_type, PrincipalName::NT_PRINCIPAL);
        let data = e.e_data.as_ref().expect("e_data");
        assert!(data.len() >= 2 && data.as_ref()[0] == 0 && data.as_ref()[1] == 3);
        assert!(data.as_ref()[2..].starts_with(b"Failed reading application request"));
    }
}

#[test]
fn kpasswd_ap_req_fills_datagram_is_bailout() {
    use krb5_kdc::{documented_changepw, shared_dump as shared_store};

    let (store, acl) = bootstrap_documented().unwrap();
    let cpw_key = store
        .get_name(&documented_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = encode_kpasswd_req(&[0, 1, 2, 3], &[]);
    let shared = shared_store(store);
    let err = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect_err("schpw.c:89 >= is bailout");
    assert!(err.to_string().contains("Message stream modified"), "{err}");
}

#[test]
fn kpasswd_bad_priv_after_ap_req_is_harderror() {
    use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
    use krb5_protocol::{build_ap_req, unwrap_krb_priv_ex};

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 77);
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
    let req = encode_kpasswd_req(&krb5_asn1::encode(&ap).unwrap(), b"not-priv");
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("PRIV fail after AP-REQ");
    let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).expect("AP-REP + KRB-PRIV");
    assert!(!ap_rep.is_empty());
    let user_data = unwrap_krb_priv_ex(
        &as_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 2,
        "HARDERROR [0,2], got {user_data:?}"
    );
    assert_eq!(&user_data[2..], b"Failed decrypting request");
}

#[test]
fn kpasswd_setpw_decode_failure_is_malformed() {
    use krb5_asn1::encode;
    use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
    use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};

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
    let as_out = changepw_as_ticket(&store, &user, &user_key, 62);
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
    let priv_msg = build_krb_priv(&as_out.session_key, b"not-der-setpw").unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_store(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("decode failure replies");
    let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).expect("KRB-PRIV");
    assert!(!ap_rep.is_empty(), "decode failure after AP-REQ has AP-REP");
    let user_data = unwrap_krb_priv_ex(
        &as_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .unwrap();
    assert!(
        user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 1,
        "Failed decoding ChangePasswdData is MALFORMED [0,1], got {user_data:?}"
    );
    assert_eq!(&user_data[2..], b"Failed decoding ChangePasswdData");
    let after = shared.read().unwrap();
    let kvno_after = after
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert_eq!(
        kvno_after, kvno_before,
        "decode failure must not set password"
    );
}
