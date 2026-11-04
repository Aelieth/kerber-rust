#![cfg(feature = "test-hooks")]
//! Admin whole-flow tests.
//! The modifier is that global handle's caller, not the ticket client.

#[path = "common/mod.rs"]
mod common;
use common::*;

use krb5_admin::{encode_kpasswd_req, *};
use krb5_asn1::encode;
use krb5_kdc::principals::kadmin_changepw;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_kdc::{shared_dump, tl_mod_princ_name};

use krb5_protocol::{
    AcceptorConfig, ReplayCache, as_req_sname, build_ap_req, build_krb_priv_with_seq,
    pa_enc_timestamp,
};
use krb5_testkit::scratch_dir;
use krb5_types::{ChangePasswdData, PrincipalName};

fn kpasswd_answer(
    store: &krb5_kdc::SharedDump,
    acl: &krb5_kdc::Acl,
    conf: &AcceptorConfig,
    replay: &ReplayCache,
    raw: &[u8],
) -> Result<Vec<u8>, krb5_admin::Error> {
    let authcfg = krb5_admin::Kadm5AuthConfig::from_acl(acl.clone());
    krb5_admin::handle_kpasswd_from(
        store,
        &authcfg,
        conf,
        replay,
        raw,
        "127.0.0.1",
        Some(std::net::IpAddr::from([127, 0, 0, 1])),
    )
}

/// the keytab principal becomes the ticket's server, so garbled cleartext (here `host/x`) is never compared.
#[test]
fn kpasswd_ticket_with_a_forged_cleartext_server_is_served_under_the_changepw_key() {
    use krb5_protocol::unwrap_krb_priv_ex;

    krb5_config::isolate_test_krb5();
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .expect("user")
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
            kadmin_changepw(),
            krb5_crypto::EncryptionType::preferred()
                .iter()
                .map(|e| e.to_iana())
                .collect(),
        )
        .expect("as-req"),
    )
    .expect("AS for kadmin/changepw");

    let mut ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .expect("AP-REQ");
    ap.ticket.sname = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.kerber.test"]);
    ap.ticket.realm = krb5_types::ascii("ELSEWHERE.TEST");
    let ap_der = encode(&ap).expect("encode ap");

    let priv_msg =
        build_krb_priv_with_seq(&as_out.session_key, b"z1-forge-newpass-123", None).expect("priv");
    let req = encode_kpasswd_req(&ap_der, &encode(&priv_msg).expect("encode priv"));

    let shared = shared_dump(store);
    let rep = kpasswd_answer(
        &shared,
        &acl,
        &AcceptorConfig::default(),
        &ReplayCache::new(),
        &req,
    )
    .expect("handler returns a datagram");
    let ap_len = u16::from_be_bytes([rep[4], rep[5]]);
    assert!(
        ap_len > 0,
        "the ticket is the changepw service's: an AP-REP"
    );
    let (_, priv_rep) = parse_kpasswd_rep(&rep).expect("reply");
    let user_data = unwrap_krb_priv_ex(
        &as_out.session_key,
        &priv_rep,
        &ReplayCache::new(),
        false,
        false,
    )
    .expect("KRB-PRIV");
    assert_eq!(&user_data[..2], &[0, 0], "the change is made");
}

/// A set-password line prints the CLIENT's name, cut to the length of the target's, in its `for` slot.
#[test]
fn kpasswd_setpw_log_prints_the_client_cut_to_the_targets_length() {
    use krb5_asn1::encode;
    use krb5_kdc::testrealm::TEST_REALM;
    use krb5_types::ChangePasswdData;

    krb5_config::isolate_test_krb5();
    let dir = scratch_dir("ra4-kpasswd-setpw-log");
    let log = dir.join("kadmind.log");
    krb5_log::klog::init("kadmind", &[format!("FILE:{}", log.display())], false);

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 1212);
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .unwrap();
    let cpw = ChangePasswdData {
        newpasswd: b"log-slot-pass".to_vec().into(),
        targname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["x"]),
        targrealm: krb5_types::ascii(TEST_REALM),
    };
    let priv_msg =
        build_krb_priv_with_seq(&as_out.session_key, &encode(&cpw).unwrap(), None).unwrap();
    let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
    let shared = shared_dump(store);
    kpasswd_answer(
        &shared,
        &acl,
        &AcceptorConfig::default(),
        &ReplayCache::new(),
        &req,
    )
    .unwrap();
    krb5_log::klog::close();
    let text = std::fs::read_to_string(&log).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        text.contains(
            "setpw request from 127.0.0.1 by user@KERBER.TEST for user@KERBER.T: Operation requires ``change-password'' privilege"
        ),
        "{text}"
    );
}

/// A refused change's Notice is the code's table text, not the sentence the rejecting module set: the empty module's refusal logs `Password is too short` with a policy bound or not, while its Error line keeps `Empty passwords are not allowed`. A principal-name match keeps its sentence in both.
#[test]
fn kpasswd_logs_the_code_text_for_an_empty_password_and_the_module_sentence_for_a_name_match() {
    use krb5_protocol::unwrap_krb_priv_ex;

    krb5_config::isolate_test_krb5();
    let dir = scratch_dir("kn-kpasswd-empty-log");
    let log = dir.join("kadmind.log");
    krb5_log::klog::init("kadmind", &[format!("FILE:{}", log.display())], false);

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let as_out = changepw_as_ticket(&store, &user, &user_key, 7101);
    let shared = shared_dump(store);
    // MIT `kpasswd` sends version 1: the KRB-PRIV carries the new password itself.
    let chpw = |newpw: &[u8]| {
        let ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let priv_msg = build_krb_priv_with_seq(&as_out.session_key, newpw, None).unwrap();
        let req = encode_kpasswd_req(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let rep = kpasswd_answer(
            &shared,
            &acl,
            &AcceptorConfig::default(),
            &ReplayCache::new(),
            &req,
        )
        .expect("a refused change is a reply");
        let (_, priv_rep) = parse_kpasswd_rep(&rep).expect("parse");
        let data = unwrap_krb_priv_ex(
            &as_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .expect("unwrap");
        (
            u16::from_be_bytes([data[0], data[1]]),
            String::from_utf8_lossy(&data[2..]).into_owned(),
        )
    };

    // No policy: the reply is the code text and `Password not changed.`
    assert_eq!(
        chpw(b""),
        (
            4,
            "Password is too short\n\nPassword not changed.".to_owned()
        )
    );
    // A policy whose floor is 0 lets the empty module refuse: the reply names the floor.
    {
        let mut g = shared.write().unwrap();
        g.put_policy(krb5_kdc::NamedPolicy::new("floor0")).unwrap();
        g.set_principal_policy(&user, Some("floor0".into()))
            .unwrap();
    }
    assert_eq!(
        chpw(b""),
        (
            4,
            "New password is too short.\nPlease choose a password which is at least 0 characters long."
                .to_owned()
        )
    );
    // The `princ` module checks only with a policy: its refusal is the dictionary paragraph.
    let (code, _) = chpw(TEST_USER.as_bytes());
    assert_eq!(code, 4);

    krb5_log::klog::close();
    let text = std::fs::read_to_string(&log).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let after = |tag: &str| -> Vec<&str> {
        text.lines()
            .filter_map(|l| l.split_once(tag).map(|(_, rest)| rest))
            .collect()
    };
    assert_eq!(
        after("(Error): "),
        [
            "password quality module empty rejected password for user@KERBER.TEST: Empty passwords are not allowed",
            "password quality module empty rejected password for user@KERBER.TEST: Empty passwords are not allowed",
            "password quality module princ rejected password for user@KERBER.TEST: Password may not match principal name",
        ],
        "{text}"
    );
    assert_eq!(
        after("(Notice): "),
        [
            "chpw request from 127.0.0.1 for user@KERBER.TEST: Password is too short",
            "chpw request from 127.0.0.1 for user@KERBER.TEST: Password is too short",
            "chpw request from 127.0.0.1 for user@KERBER.TEST: Password may not match principal name",
        ],
        "{text}"
    );
}

#[test]
fn kpasswd_bad_ap_req_is_chpwfail_autherror() {
    use krb5_asn1::decode;
    use krb5_kdc::shared_dump as shared_store;

    use krb5_types::KrbError;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let req = encode_kpasswd_req(&[0, 1, 2, 3], b"x");
    let shared = shared_store(store);
    let r1 = kpasswd_answer(
        &shared,
        &acl,
        &AcceptorConfig::default(),
        &ReplayCache::new(),
        &req,
    )
    .expect("chpwfail");
    let r2 = kpasswd_answer(
        &shared,
        &acl,
        &AcceptorConfig::default(),
        &ReplayCache::new(),
        &req,
    )
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
    use krb5_kdc::shared_dump as shared_store;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let req = encode_kpasswd_req(&[0, 1, 2, 3], &[]);
    let shared = shared_store(store);
    let err = kpasswd_answer(
        &shared,
        &acl,
        &AcceptorConfig::default(),
        &ReplayCache::new(),
        &req,
    )
    .expect_err("schpw.c:89 >= is bailout");
    assert!(err.to_string().contains("Message stream modified"), "{err}");
}

#[test]
fn kpasswd_stamps_kadmind_not_the_client() {
    krb5_config::isolate_test_krb5();
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .expect("user")
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
            kadmin_changepw(),
            krb5_crypto::EncryptionType::preferred()
                .iter()
                .map(|e| e.to_iana())
                .collect(),
        )
        .expect("as-req"),
    )
    .expect("AS for kadmin/changepw");
    let ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .expect("AP-REQ");
    let cpw = ChangePasswdData {
        newpasswd: b"z72-kpw-newpass-1".to_vec().into(),
        targname: user.clone(),
        targrealm: krb5_types::ascii(TEST_REALM),
    };
    let priv_msg = build_krb_priv_with_seq(&as_out.session_key, &encode(&cpw).expect("cpw"), None)
        .expect("priv");
    let mut req = encode_kpasswd_req(&encode(&ap).expect("ap"), &encode(&priv_msg).expect("priv"));
    req[2..4].copy_from_slice(&0xff80u16.to_be_bytes());
    let shared = shared_dump(store);
    let rep = kpasswd_answer(
        &shared,
        &acl,
        &AcceptorConfig::default(),
        &ReplayCache::new(),
        &req,
    )
    .expect("handler returns a datagram");
    assert!(
        rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
        "INITIAL self-change includes AP-REP"
    );
    let g = shared
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let p = g.get_name(&user).expect("user after kpasswd");
    let got = tl_mod_princ_name(&p.tl_data);
    assert_eq!(
        got.as_deref(),
        Some("kadmind@KERBER.TEST"),
        "kpasswd must stamp the global handle, not the client (got {got:?})"
    );
}

fn kpasswd_req_naming_receiver(
    as_out: &krb5_kdc::IssuedAs,
    user: &PrincipalName,
    subkey: &krb5_crypto::ProtocolKey,
    password: &[u8],
    receiver: Option<krb5_types::HostAddress>,
) -> Vec<u8> {
    use krb5_crypto::{KeyUsage, encrypt};
    use krb5_types::{
        ApOptions, Authenticator, EncKrbPrivPart, EncryptedData, EncryptionKey, HostAddress,
        KerberosTime, KrbPriv, Microseconds, ku,
    };

    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: krb5_types::ascii(TEST_REALM),
        cname: user.clone(),
        cksum: None,
        cusec: Microseconds::from_subsec_micros(614_741),
        ctime: KerberosTime::now(),
        subkey: Some(EncryptionKey {
            keytype: subkey.etype().to_iana(),
            keyvalue: subkey.as_bytes().to_vec().into(),
        }),
        seq_number: None,
        authorization_data: None,
    };
    let ap = krb5_protocol::build_ap_req_from_authenticator(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        ApOptions::none(),
        &authenticator,
    )
    .unwrap();
    let part = EncKrbPrivPart {
        user_data: password.to_vec().into(),
        timestamp: None,
        usec: None,
        seq_number: None,
        s_address: HostAddress {
            addr_type: HostAddress::ADDRTYPE_INET,
            address: vec![192, 0, 2, 9].into(),
        },
        r_address: receiver,
    };
    let cipher = encrypt(
        subkey,
        KeyUsage::new(ku::KRB_PRIV_ENC_PART).unwrap(),
        &encode(&part).unwrap(),
    )
    .unwrap();
    let priv_msg = KrbPriv {
        pvno: KrbPriv::PVNO,
        msg_type: KrbPriv::MSG_TYPE,
        enc_part: EncryptedData {
            etype: subkey.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    encode_kpasswd_req(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap())
}

/// A request whose KRB-PRIV names a receiver address that is none of the server's is refused, and the password stays; one that names none, or whose address is the host's, is read.
/// `krb5_rd_priv` is called with no address set, and a refusal is HARDERROR "Failed decrypting request".
// MIT: `k5_privsafe_check_addrs` (lib/krb5/krb/privsafe.c:355-378)
/// the receiver address is looked up among the host's (`krb5_os_localaddr`, which leaves out 127.0.0.1).
#[test]
fn kpasswd_request_naming_a_receiver_the_server_does_not_have_is_refused() {
    use krb5_crypto::{ProtocolKey, decrypt};
    use krb5_types::HostAddress;

    krb5_config::isolate_test_krb5();
    let inet = |o: [u8; 4]| HostAddress {
        addr_type: HostAddress::ADDRTYPE_INET,
        address: o.to_vec().into(),
    };
    for (receiver, read) in [
        (None, true),
        (Some(inet([203, 0, 113, 77])), false),
        (Some(inet([127, 0, 0, 1])), false),
    ] {
        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let kvno_before = max_kvno(&store, &user);
        let as_out = changepw_as_ticket(&store, &user, &user_key, 1414);
        let subkey = ProtocolKey::random(as_out.session_key.etype()).unwrap();
        let req = kpasswd_req_naming_receiver(
            &as_out,
            &user,
            &subkey,
            b"receiver-pass",
            receiver.clone(),
        );
        let shared = shared_dump(store);
        let rep = kpasswd_answer(
            &shared,
            &acl,
            &AcceptorConfig::default(),
            &ReplayCache::new(),
            &req,
        )
        .unwrap();
        let (_, priv_der) = parse_kpasswd_rep(&rep).unwrap();
        let msg: krb5_types::KrbPriv = krb5_asn1::decode(&priv_der).unwrap();
        let usage = krb5_crypto::KeyUsage::new(krb5_types::ku::KRB_PRIV_ENC_PART).unwrap();
        let plain = decrypt(&subkey, usage, msg.enc_part.cipher.as_ref()).unwrap();
        let part: krb5_types::EncKrbPrivPart = krb5_asn1::decode(&plain).unwrap();
        let data = part.user_data.as_ref();
        let changed = max_kvno(&shared.read().unwrap(), &user) > kvno_before;
        if read {
            assert_eq!(&data[..2], &[0, 0], "{receiver:?} is read: {data:?}");
            assert!(changed, "{receiver:?}: the password is changed");
        } else {
            assert_eq!(
                data,
                [&[0u8, 2][..], b"Failed decrypting request"].concat(),
                "{receiver:?}"
            );
            assert!(!changed, "{receiver:?}: the password stays");
        }
    }
}

/// A ticket sealed in any key of `kadmin/changepw` but its first is refused.
/// the refusal is AUTHERROR "Failed reading application request".
#[test]
fn kpasswd_ticket_sealed_in_a_later_changepw_key_is_refused() {
    use krb5_crypto::{KeyUsage, encrypt};
    use krb5_kdc::testrealm::{TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_USER_PASSWORD};
    use krb5_kdc::{bootstrap_realm_with_kdc_conf, decrypt_ticket_part};
    use krb5_types::{OctetString, ku};

    krb5_config::isolate_test_krb5();
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
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let cpw = store.get_name(&kadmin_changepw()).unwrap().clone();
    let first = cpw.first_current_key().unwrap().clone();
    assert_eq!(first.etype.to_iana(), 20);
    let as_out = changepw_as_ticket(&store, &user, &user_key, 1313);
    let shared = shared_dump(store);
    let mut tried = 0;
    for later in cpw.keys.iter().filter(|k| k.etype != first.etype) {
        let mut ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let part = decrypt_ticket_part(&first.key, &ap.ticket).unwrap();
        let usage = KeyUsage::new(ku::TICKET).unwrap();
        ap.ticket.enc_part.etype = later.etype.to_iana();
        ap.ticket.enc_part.cipher =
            OctetString::from(encrypt(&later.key, usage, &encode(&part).unwrap()).unwrap());
        let priv_msg =
            build_krb_priv_with_seq(&as_out.session_key, b"later-key-pass", None).unwrap();
        let req = encode_kpasswd_req(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let rep = kpasswd_answer(
            &shared,
            &acl,
            &AcceptorConfig::default(),
            &ReplayCache::new(),
            &req,
        )
        .unwrap();
        assert_eq!(
            u16::from_be_bytes([rep[4], rep[5]]),
            0,
            "a ticket sealed in the {} key is refused",
            later.etype.to_iana()
        );
        let err: krb5_types::KrbError = krb5_asn1::decode(&rep[6..]).unwrap();
        let e_data = err.e_data.unwrap();
        assert_eq!(&e_data.as_ref()[..2], &[0, 3]);
        assert_eq!(&e_data.as_ref()[2..], b"Failed reading application request");
        tried += 1;
    }
    assert_eq!(tried, 3);
}

/// changes no password, the caller's own included.
#[test]
fn setpw_without_a_target_is_malformed() {
    use krb5_kdc::shared_dump as shared_store;
    use krb5_protocol::unwrap_krb_priv_ex;

    krb5_config::isolate_test_krb5();

    let (store, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let kvno = |s: &krb5_kdc::PrincipalStore| {
        s.get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap()
    };
    let kvno_before = kvno(&store);
    let as_out = changepw_as_ticket(&store, &user, &user_key, 921);
    let shared = shared_store(store);
    let tlv = |tag: u8, content: &[u8]| {
        let mut out = vec![tag, u8::try_from(content.len()).unwrap()];
        out.extend_from_slice(content);
        out
    };
    let newpasswd = tlv(0xa0, &tlv(0x04, b"no-target-pass"));
    let targrealm = tlv(0xa2, &tlv(0x1b, TEST_REALM.as_bytes()));
    let requests = [
        tlv(0x30, &newpasswd),
        tlv(
            0x30,
            &[newpasswd.clone(), tlv(0xa1, &tlv(0x31, &[])), targrealm].concat(),
        ),
    ];
    for (i, cpw) in requests.iter().enumerate() {
        let ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let priv_msg = build_krb_priv_with_seq(&as_out.session_key, cpw, None).unwrap();
        let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let rep = kpasswd_answer(
            &shared,
            &acl,
            &AcceptorConfig::default(),
            &ReplayCache::new(),
            &req,
        )
        .unwrap();
        let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
        let user_data = unwrap_krb_priv_ex(
            &as_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .unwrap();
        assert_eq!(&user_data[..2], &[0, 1], "request {i}: MALFORMED");
        assert_eq!(
            &user_data[2..],
            b"Failed decoding ChangePasswdData",
            "request {i}"
        );
    }
    assert_eq!(
        kvno(&shared.read().unwrap()),
        kvno_before,
        "no password changed"
    );
}
