//! The des3-cbc-sha1 keys the KDC makes for a reply: the session key of a TGT and of a service ticket.
//!
// MIT: `krb5_c_make_random_key` (lib/crypto/krb/make_random_key.c:31-76)
//! `keybytes` random octets through the enctype's random-to-key, so a des3 key is 24 octets of odd parity; the AS and TGS exchanges draw their session keys with it.
//! A MIT client that is given a des3 session key of even parity says "DES key has bad parity" and cannot use the ticket.
// MIT: `select_session_keytype` (kdc/kdc_util.c:1085-1110)
//! a des3 session key is issued only under `allow_des3` and for a server whose `session_enctypes` or keys hold des3.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented, documented_admin_id, documented_host};
use krb5_kdc::{
    AdminFields, Error, KDB_REQUIRES_PRE_AUTH, KeyEntry, PrincipalStore, dump_store, load_dump,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_testkit::{TgsReqBuilder, err_of, status};
use krb5_types::{KdcOptions, PaData, PrincipalName, err, pa};

const DES3: EncryptionType = EncryptionType::Des3CbcSha1;

/// A DES key octet has an odd number of one bits: its low bit is the parity.
fn odd_parity(key: &ProtocolKey) -> bool {
    key.as_bytes().len() == 24 && key.as_bytes().iter().all(|b| b.count_ones() % 2 == 1)
}

/// A realm whose krbtgt and whose service allow a des3 session key, and a client that holds only a des3 key.
fn realm_with_des3_user() -> (krb5_kdc::PrincipalStore, PrincipalName, ProtocolKey) {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store.policy.allow_des3 = true;
    for name in [PrincipalName::krbtgt(TEST_REALM), documented_host()] {
        store
            .set_string(&name, "session_enctypes", Some("des3-cbc-sha1"))
            .expect("setstr");
    }
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["des3user"]);
    store
        .create_password_etypes(
            &acl,
            &documented_admin_id(),
            &user,
            b"des3-secret",
            &[DES3.into()],
        )
        .expect("addprinc -e des3");
    let key =
        string_to_key(DES3, b"des3-secret", user.default_salt(TEST_REALM), None).expect("s2k");
    (store, user, key)
}

/// The session key of a TGT issued to a client of des3 is des3, and of odd parity on every octet.
/// Before, it was 24 raw random octets from `random_key`.
#[test]
fn as_issues_a_des3_session_key_of_odd_parity() {
    let (store, user, key) = realm_with_des3_user();
    for nonce in 700..716 {
        let mut req = as_req(
            user.clone(),
            TEST_REALM,
            nonce,
            Some(vec![pa_enc_timestamp(&key).expect("pa")]),
        )
        .unwrap();
        req.0.req_body.etype = vec![DES3.to_iana()];
        let issued = krb5_kdc::issue_as(&store, &req).expect("AS");
        assert_eq!(issued.session_key.etype(), DES3);
        assert!(
            odd_parity(&issued.session_key),
            "{:02x?}",
            issued.session_key.as_bytes()
        );
    }
}

/// The session key of a service ticket is des3, and of odd parity, under a TGT whose session key is des3 as well
/// (its checksum and its authenticator are made with the des3 key, which needs the hmac-sha1-des3-kd checksum).
#[test]
fn tgs_issues_a_des3_session_key_of_odd_parity() {
    let (store, user, key) = realm_with_des3_user();
    let mut req = as_req(
        user.clone(),
        TEST_REALM,
        720,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    req.0.req_body.etype = vec![DES3.to_iana()];
    let tgt = krb5_kdc::issue_as(&store, &req).expect("AS");
    assert_eq!(tgt.session_key.etype(), DES3);
    for nonce in 721..737 {
        let tgs = TgsReqBuilder::new(
            tgt.rep.0.ticket.clone(),
            &tgt.session_key,
            TEST_REALM,
            &user,
            documented_host(),
            TEST_REALM,
            nonce,
        )
        .options(KdcOptions::forwardable())
        .etypes(vec![DES3.to_iana()])
        .build()
        .expect("TGS-REQ");
        let issued = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
        assert_eq!(issued.session_key.etype(), DES3);
        assert!(
            odd_parity(&issued.session_key),
            "{:02x?}",
            issued.session_key.as_bytes()
        );
    }
}

// A des3 key whose parity is wrong, as a dump of an earlier build's database, a keytab or a ticket carries it. MIT loads such a key as it is
// and refuses it at its first use, and where the KDC meets it first decides the status word and the code the client is given.
// MIT: `validate_and_schedule` (lib/crypto/builtin/enc_provider/des3.c:33-53)
// the first use of the key fails with `KRB5DES_BAD_KEYPAR`.
// MIT: `errcode_to_protocol` (kdc/kdc_util.c:691-697)
// `KRB5DES_BAD_KEYPAR` is past the table's protocol codes, so it is sent as `KRB_ERR_GENERIC` (60).

/// `key` with the parity bit of one octet flipped.
fn with_bad_parity(key: &ProtocolKey) -> ProtocolKey {
    let mut bytes = key.as_bytes().to_vec();
    bytes[3] ^= 1;
    let bad =
        ProtocolKey::from_bytes(DES3, &bytes).expect("a 24-octet key loads, whatever its parity");
    assert!(!odd_parity(&bad));
    bad
}

fn set_key(store: &mut PrincipalStore, name: &PrincipalName, key: ProtocolKey, kvno: u32) {
    store
        .set_keys(name, vec![KeyEntry::new(DES3, key, kvno)], 0)
        .expect("setkey");
}

/// The documented realm's users require preauthentication; a request without it needs the attribute off.
fn set_preauth(store: &mut PrincipalStore, user: &PrincipalName, required: bool) {
    let was = store.get_name(user).unwrap().attributes;
    let attrs = if required {
        was | KDB_REQUIRES_PRE_AUTH
    } else {
        was & !KDB_REQUIRES_PRE_AUTH
    };
    store
        .apply_admin_fields(
            user,
            AdminFields {
                attributes: Some(attrs),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
}

/// The realm of the des3 user, whose stored key has bad parity; `preauth` is whether the user must preauthenticate.
fn realm_with_a_bad_des3_user(preauth: bool) -> (PrincipalStore, PrincipalName, ProtocolKey) {
    let (mut store, user, key) = realm_with_des3_user();
    set_key(&mut store, &user, with_bad_parity(&key), 0);
    set_preauth(&mut store, &user, preauth);
    (store, user, key)
}

fn detail(e: &Error) -> Option<&str> {
    match e {
        Error::Protocol { detail, .. } => detail.as_deref(),
        other => panic!("{other:?}"),
    }
}

fn enc_pa_rep() -> PaData {
    PaData {
        padata_type: pa::REQ_ENC_PA_REP,
        padata_value: Vec::new().into(),
    }
}

fn as_req_for(user: &PrincipalName, nonce: u32, padata: Vec<PaData>) -> krb5_types::AsReq {
    let mut req = as_req(user.clone(), TEST_REALM, nonce, Some(padata)).unwrap();
    req.0.req_body.etype = vec![DES3.to_iana()];
    req
}

/// A client that asks for PA-REQ-ENC-PA-REP, as MIT's does, has its reply's checksum made under the stored key first, and that is
/// where the key is refused: status KDC_RETURN_ENC_PADATA, code 60, the message in the log line.
// MIT: `finish_process_as_req` (kdc/do_as_req.c:316-322)
/// `return_enc_padata` fails, status `KDC_RETURN_ENC_PADATA`.
#[test]
fn as_under_a_stored_key_of_bad_parity_fails_in_return_enc_padata() {
    let (store, user, _) = realm_with_a_bad_des3_user(false);
    let req = as_req_for(&user, 740, vec![enc_pa_rep()]);
    // The checksum covers the request as it came, so the request goes by its bytes.
    let wire = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).unwrap();
    assert_eq!(err_of(&wire), (60, "KDC_RETURN_ENC_PADATA".to_owned()));
}

/// A client that must preauthenticate sends a timestamp under its own (good) key; the KDC cannot decrypt it with the stored key and
/// that is PREAUTH_FAILED, as for a wrong password.
// MIT: `enc_ts_verify` (kdc/kdc_preauth_encts.c:74-92)
/// a key that does not decrypt, for any reason, sends the walk on to the next key, and the end of the keys is `KRB5KDC_ERR_PREAUTH_FAILED`.
#[test]
fn as_with_preauth_under_a_stored_key_of_bad_parity_is_preauth_failed() {
    let (store, user, key) = realm_with_a_bad_des3_user(true);
    let req = as_req_for(&user, 742, vec![pa_enc_timestamp(&key).unwrap()]);
    let e = krb5_kdc::issue_as(&store, &req).unwrap_err();
    assert_eq!(status(&e), (err::PREAUTH_FAILED, Some("PREAUTH_FAILED")));
    let wire = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).unwrap();
    assert_eq!(err_of(&wire), (24, "PREAUTH_FAILED".to_owned()));
}

fn tgs_for_host(
    store: &PrincipalStore,
    user: &PrincipalName,
    key: &ProtocolKey,
    nonce: u32,
) -> Result<(), Error> {
    let tgt = krb5_kdc::issue_as(
        store,
        &as_req_for(user, nonce, vec![pa_enc_timestamp(key).unwrap()]),
    )
    .expect("AS");
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        user,
        documented_host(),
        TEST_REALM,
        nonce + 1,
    )
    .etypes(vec![DES3.to_iana()])
    .build()
    .expect("TGS-REQ");
    krb5_kdc::issue_tgs(store, &tgs).map(|_| ())
}

/// A service whose key has bad parity cannot have its ticket signed or sealed. The PAC's server signature is made first, in
/// `handle_authdata`, and that is where MIT fails: the log line `TGS_REQ : handle_authdata (-1765328198)`, then status HANDLE_AUTHDATA.
// MIT: `tgs_issue_ticket` (kdc/do_tgs_req.c:1038-1048)
/// `handle_authdata` fails, `krb5_klog_syslog(LOG_INFO, "TGS_REQ : handle_authdata (%d)")`, status `HANDLE_AUTHDATA`.
#[test]
fn tgs_for_a_service_whose_key_has_bad_parity_fails_in_handle_authdata() {
    let (mut store, user, key) = realm_with_des3_user();
    let good = ProtocolKey::random(DES3).unwrap();
    set_key(&mut store, &documented_host(), good.clone(), 0);
    tgs_for_host(&store, &user, &key, 750).expect("the service key as it was");
    set_key(&mut store, &documented_host(), with_bad_parity(&good), 0);
    let e = tgs_for_host(&store, &user, &key, 760).unwrap_err();
    assert_eq!(status(&e), (err::GENERIC, Some("HANDLE_AUTHDATA")));
    assert_eq!(detail(&e), Some("DES key has bad parity"));
}

/// A TGT that the krbtgt key of bad parity cannot open is a failure of the TGS-REQ's processing, with code 60.
// MIT: `kdc_rd_ap_req` (kdc/kdc_util.c:293-345)
/// `krb5_decrypt_tkt_part` fails with the key's code, `errcode_to_protocol` (`:691-697`) sends it as 60, status `PROCESS_TGS`.
#[test]
fn a_tgt_under_a_krbtgt_key_of_bad_parity_is_a_process_tgs_failure() {
    let (mut store, user, key) = realm_with_des3_user();
    let krbtgt = PrincipalName::krbtgt(TEST_REALM);
    let kvno = store
        .get_name(&krbtgt)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    // The krbtgt holds a des3 key of good parity, so that the TGT is sealed under it.
    let good = ProtocolKey::random(DES3).unwrap();
    set_key(&mut store, &krbtgt, good.clone(), kvno);
    let tgt = krb5_kdc::issue_as(
        &store,
        &as_req_for(&user, 770, vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .expect("AS");
    assert_eq!(tgt.rep.0.ticket.enc_part.etype, DES3.to_iana());
    // Then the key is spoiled, at the same version: a dump of an earlier build's database.
    set_key(&mut store, &krbtgt, with_bad_parity(&good), kvno);
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        771,
    )
    .etypes(vec![DES3.to_iana()])
    .build()
    .expect("TGS-REQ");
    let e = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&e), (err::GENERIC, Some("PROCESS_TGS")));
    assert_eq!(detail(&e), Some("DES key has bad parity"));
}

/// The dump of such a database loads, as MIT's `kdb5_util load` loads it, and the key is refused at its first use after the load.
#[test]
fn a_dump_of_a_key_of_bad_parity_loads_and_the_key_is_refused_at_its_use() {
    let (store, user, _) = realm_with_a_bad_des3_user(false);
    let text = dump_store(&store, b"masterpassword").expect("dump");
    let mut loaded = load_dump(&text, b"masterpassword").expect("a dump with such a key loads");
    loaded.policy.allow_des3 = true;
    let stored = loaded.get_name(&user).unwrap();
    assert!(
        !odd_parity(&stored.keys[0].key),
        "the key is as it was dumped"
    );
    let req = as_req_for(&user, 780, vec![enc_pa_rep()]);
    let wire = krb5_kdc::handle_request(&loaded, &encode(&req).unwrap()).unwrap();
    assert_eq!(err_of(&wire), (60, "KDC_RETURN_ENC_PADATA".to_owned()));
}
