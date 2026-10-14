//! The des3-cbc-sha1 keys the KDC makes for a reply: the session key of a TGT and of a service ticket.
//!
//! MIT `krb5_c_make_random_key` (`lib/crypto/krb/make_random_key.c:31-76`): `keybytes` random octets through the enctype's random-to-key, so a des3 key is 24 octets of odd parity; the AS and TGS exchanges draw their session keys with it.
//! A MIT client that is given a des3 session key of even parity says "DES key has bad parity" and cannot use the ticket.
//! MIT `select_session_keytype` (`kdc/kdc_util.c:1085-1110`): a des3 session key is issued only under `allow_des3` and for a server whose `session_enctypes` or keys hold des3.

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented, documented_admin_id, documented_host};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_testkit::TgsReqBuilder;
use krb5_types::{KdcOptions, PrincipalName};

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
        .create_password_etypes(&acl, &documented_admin_id(), &user, b"des3-secret", &[DES3])
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
