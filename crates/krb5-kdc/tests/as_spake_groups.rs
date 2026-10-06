//! The KDC's SPAKE module as MIT's `spake_kdc.c` and `groups.c`: edwards25519 end to end, the
//! group the client's order picks, the optimistic challenge `spake_preauth_kdc_challenge` sends
//! with PREAUTH_REQUIRED, the module that does not load (no group, or a challenge group not
//! permitted), and the messages that are PREAUTH_FAILED.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, SpakeGroup, decrypt};
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented};
use krb5_kdc::{Error, PrincipalStore};
use krb5_protocol::{as_req, pa_spake_response};
use krb5_testkit::{status, user};
use krb5_types::spake::{PaSpake, SF_NONE, SpakeChallenge, SpakeSecondFactor, SpakeSupport};
use krb5_types::{EncryptedData, MethodData, PaData, err, ku, pa};

fn store_with(groups: &[SpakeGroup], challenge: Option<&str>) -> PrincipalStore {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.policy.spake_preauth_groups = groups.to_vec();
    store.policy.spake_preauth_kdc_challenge = challenge.map(ToOwned::to_owned);
    store
}

fn user_key(store: &PrincipalStore) -> ProtocolKey {
    store
        .get_name(&user())
        .expect("user")
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .expect("aes256-sha1 key")
        .key
        .clone()
}

fn support(groups: &[i32]) -> PaData {
    PaData {
        padata_type: pa::SPAKE,
        padata_value: encode(&PaSpake::Support(SpakeSupport {
            groups: groups.to_vec(),
        }))
        .unwrap()
        .into(),
    }
}

fn method_of(err: Error) -> (i32, MethodData) {
    let (code, e_data) = match err {
        Error::Protocol {
            code,
            e_data: Some(e_data),
            ..
        } => (code, e_data),
        Error::PreauthRequired { e_data } => (err::PREAUTH_REQUIRED, e_data),
        other => panic!("expected an error with METHOD-DATA, got {other:?}"),
    };
    (code, decode(&e_data).expect("METHOD-DATA"))
}

fn types(method: &MethodData) -> Vec<i32> {
    method.iter().map(|p| p.padata_type).collect()
}

fn find(method: &MethodData, ty: i32) -> PaData {
    method
        .iter()
        .find(|p| p.padata_type == ty)
        .unwrap_or_else(|| panic!("no padata {ty} in {:?}", types(method)))
        .clone()
}

fn challenge_of(spake: &PaData) -> SpakeChallenge {
    match decode::<PaSpake>(spake.padata_value.as_ref()).expect("PA-SPAKE") {
        PaSpake::Challenge(c) => c,
        other => panic!("expected a challenge, got {other:?}"),
    }
}

/// Answer the challenge in `spake` (whose transcript began with `support_der`) and return the
/// issued reply key and the client's `K'[0]`.
fn respond(
    store: &PrincipalStore,
    support_der: &[u8],
    spake: &PaData,
    cookie: &PaData,
    nonce: u32,
) -> Result<(ProtocolKey, ProtocolKey), Error> {
    let chal = challenge_of(spake);
    let group = SpakeGroup::from_number(chal.group).expect("group");
    let mut req = as_req(user(), TEST_REALM, nonce, None).unwrap();
    let body = encode(&req.0.req_body).unwrap();
    let (resp, k0) = pa_spake_response(
        &user_key(store),
        group,
        support_der,
        spake.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body,
    )
    .expect("response");
    req.0.padata = Some(vec![cookie.clone(), resp]);
    let issued = krb5_kdc::issue_as(store, &req)?;
    Ok((issued.as_rep_key.clone(), k0))
}

#[test]
fn edwards25519_support_challenge_response_issues_in_k0() {
    let store = store_with(&[SpakeGroup::Edwards25519], None);
    let sup = support(&[1]);
    let req = as_req(user(), TEST_REALM, 7101, Some(vec![sup.clone()])).unwrap();
    let (code, method) = method_of(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert_eq!(code, err::MORE_PREAUTH_DATA_REQUIRED);
    assert_eq!(types(&method), [pa::SPAKE, pa::ETYPE_INFO2, pa::FX_COOKIE]);
    let spake = find(&method, pa::SPAKE);
    let chal = challenge_of(&spake);
    assert_eq!(chal.group, 1);
    assert_eq!(chal.pubkey.as_ref().len(), 32);
    assert_eq!(
        chal.factors,
        [SpakeSecondFactor {
            factor_type: SF_NONE,
            data: None
        }]
    );
    let (reply_key, k0) = respond(
        &store,
        sup.padata_value.as_ref(),
        &spake,
        &find(&method, pa::FX_COOKIE),
        7102,
    )
    .expect("SPAKE AS");
    assert_eq!(reply_key.as_bytes(), k0.as_bytes());
}

#[test]
fn the_clients_order_picks_the_group() {
    let store = store_with(&[SpakeGroup::P256, SpakeGroup::Edwards25519], None);
    for (offer, want) in [
        (&[1, 2][..], 1),
        (&[2, 1], 2),
        (&[3, 4, 2], 2),
        (&[4, 1], 1),
    ] {
        let req = as_req(user(), TEST_REALM, 7110, Some(vec![support(offer)])).unwrap();
        let (code, method) = method_of(krb5_kdc::issue_as(&store, &req).unwrap_err());
        assert_eq!(code, err::MORE_PREAUTH_DATA_REQUIRED, "{offer:?}");
        assert_eq!(
            challenge_of(&find(&method, pa::SPAKE)).group,
            want,
            "{offer:?}"
        );
    }
    // No permitted group in the offer is PREAUTH_FAILED.
    let req = as_req(user(), TEST_REALM, 7111, Some(vec![support(&[3, 4])])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    assert_eq!(status(&err), (err::PREAUTH_FAILED, Some("PREAUTH_FAILED")));
}

#[test]
fn an_optimistic_challenge_rides_preauth_required_and_completes() {
    let store = store_with(&[SpakeGroup::Edwards25519], Some("edwards25519"));
    let req = as_req(user(), TEST_REALM, 7120, None).unwrap();
    let (code, method) = method_of(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert_eq!(code, err::PREAUTH_REQUIRED);
    // MIT 1.22.2 with Fedora's kdc.conf: {136, 19, 151 (a challenge), 2, 133}.
    assert_eq!(
        types(&method),
        [
            pa::FX_FAST,
            pa::ETYPE_INFO2,
            pa::SPAKE,
            pa::ENC_TIMESTAMP,
            pa::FX_COOKIE
        ]
    );
    let spake = find(&method, pa::SPAKE);
    assert_eq!(challenge_of(&spake).group, 1);
    let cookie = find(&method, pa::FX_COOKIE);
    assert!(cookie.padata_value.as_ref().starts_with(b"MIT1"));
    // No support message: the transcript starts at the challenge.
    let (reply_key, k0) = respond(&store, &[], &spake, &cookie, 7121).expect("SPAKE AS");
    assert_eq!(reply_key.as_bytes(), k0.as_bytes());
}

#[test]
fn the_as_rep_after_spake_keeps_etype_info2_like_mit() {
    // MIT 1.22.2 live: the AS-REP after SPAKE has padata {19}; K'[0] is a strengthened key.
    let store = store_with(&[SpakeGroup::Edwards25519], Some("edwards25519"));
    let req = as_req(user(), TEST_REALM, 7125, None).unwrap();
    let (_, method) = method_of(krb5_kdc::issue_as(&store, &req).unwrap_err());
    let spake = find(&method, pa::SPAKE);
    let chal = challenge_of(&spake);
    let mut req = as_req(user(), TEST_REALM, 7126, None).unwrap();
    let body = encode(&req.0.req_body).unwrap();
    let (resp, _) = pa_spake_response(
        &user_key(&store),
        SpakeGroup::Edwards25519,
        &[],
        spake.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body,
    )
    .unwrap();
    req.0.padata = Some(vec![find(&method, pa::FX_COOKIE), resp]);
    let issued = krb5_kdc::issue_as(&store, &req).expect("SPAKE AS");
    let types: Vec<i32> = issued
        .rep
        .0
        .padata
        .iter()
        .flatten()
        .map(|p| p.padata_type)
        .collect();
    assert_eq!(types, [pa::ETYPE_INFO2]);
}

#[test]
fn a_challenge_group_the_client_lacks_is_answered_by_support() {
    // KDC: optimistic P-256, both groups permitted; an edwards25519-only client sends support and
    // gets an edwards25519 challenge whose transcript includes that support message.
    let store = store_with(&[SpakeGroup::P256, SpakeGroup::Edwards25519], Some("P-256"));
    let req = as_req(user(), TEST_REALM, 7130, None).unwrap();
    let (_, method) = method_of(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert_eq!(challenge_of(&find(&method, pa::SPAKE)).group, 2);
    let sup = support(&[1]);
    let req = as_req(
        user(),
        TEST_REALM,
        7131,
        Some(vec![find(&method, pa::FX_COOKIE), sup.clone()]),
    )
    .unwrap();
    let (code, method) = method_of(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert_eq!(code, err::MORE_PREAUTH_DATA_REQUIRED);
    let spake = find(&method, pa::SPAKE);
    assert_eq!(challenge_of(&spake).group, 1);
    let (reply_key, k0) = respond(
        &store,
        sup.padata_value.as_ref(),
        &spake,
        &find(&method, pa::FX_COOKIE),
        7132,
    )
    .expect("SPAKE AS");
    assert_eq!(reply_key.as_bytes(), k0.as_bytes());
}

#[test]
fn the_module_loads_as_mit_decides() {
    let policy = |groups: &[SpakeGroup], challenge: Option<&str>| {
        let store = store_with(groups, challenge);
        store.policy.spake_kdc().map(|k| k.challenge)
    };
    assert_eq!(
        policy(&[], None),
        Err("No SPAKE preauth groups configured".to_owned())
    );
    assert_eq!(
        policy(&[], Some("edwards25519")),
        Err("No SPAKE preauth groups configured".to_owned())
    );
    assert_eq!(
        policy(&[SpakeGroup::P256], Some("edwards25519")),
        Err("SPAKE challenge group not a permitted group: edwards25519".to_owned())
    );
    assert_eq!(
        policy(&[SpakeGroup::P256], Some("P-521")),
        Err("SPAKE challenge group not a permitted group: P-521".to_owned())
    );
    assert_eq!(
        policy(&[SpakeGroup::Edwards25519], Some("EDWARDS25519")),
        Ok(Some(SpakeGroup::Edwards25519))
    );
    assert_eq!(policy(&[SpakeGroup::P256], None), Ok(None));
}

#[test]
fn a_module_that_did_not_load_offers_nothing_and_skips_pa_spake() {
    // MIT: a challenge group that is not permitted fails the module's init, so the KDC neither
    // offers SPAKE nor answers a PA-SPAKE.
    let store = store_with(&[SpakeGroup::P256], Some("edwards25519"));
    let req = as_req(user(), TEST_REALM, 7140, None).unwrap();
    let (code, method) = method_of(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert_eq!(code, err::PREAUTH_REQUIRED);
    assert!(!types(&method).contains(&pa::SPAKE), "{:?}", types(&method));
    let req = as_req(user(), TEST_REALM, 7141, Some(vec![support(&[2])])).unwrap();
    let (code, _) = method_of(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert_eq!(code, err::PREAUTH_REQUIRED);
}

#[test]
fn a_challenge_or_encdata_from_the_client_is_preauth_failed() {
    let store = store_with(&[SpakeGroup::Edwards25519], None);
    let challenge = PaSpake::Challenge(SpakeChallenge {
        group: 1,
        pubkey: vec![0u8; 32].into(),
        factors: vec![],
    });
    let encdata = PaSpake::EncData(EncryptedData {
        etype: 18,
        kvno: None,
        cipher: vec![0u8; 40].into(),
    });
    for msg in [challenge, encdata] {
        let pa = PaData {
            padata_type: pa::SPAKE,
            padata_value: encode(&msg).unwrap().into(),
        };
        let req = as_req(user(), TEST_REALM, 7150, Some(vec![pa])).unwrap();
        let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
        assert_eq!(status(&err).0, err::PREAUTH_FAILED, "{msg:?}");
    }
}

#[test]
fn a_factor_in_another_enctype_or_a_wrong_key_is_preauth_failed() {
    let store = store_with(&[SpakeGroup::Edwards25519], Some("edwards25519"));
    let req = as_req(user(), TEST_REALM, 7160, None).unwrap();
    let (_, method) = method_of(krb5_kdc::issue_as(&store, &req).unwrap_err());
    let spake = find(&method, pa::SPAKE);
    let cookie = find(&method, pa::FX_COOKIE);
    let chal = challenge_of(&spake);
    for wrong_key in [false, true] {
        let mut req = as_req(user(), TEST_REALM, 7161, None).unwrap();
        let body = encode(&req.0.req_body).unwrap();
        let key = if wrong_key {
            ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[3u8; 32]).unwrap()
        } else {
            user_key(&store)
        };
        let (resp, _) = pa_spake_response(
            &key,
            SpakeGroup::Edwards25519,
            &[],
            spake.padata_value.as_ref(),
            chal.pubkey.as_ref(),
            &body,
        )
        .unwrap();
        let resp = if wrong_key {
            resp
        } else {
            let PaSpake::Response(mut r) = decode::<PaSpake>(resp.padata_value.as_ref()).unwrap()
            else {
                panic!("response")
            };
            r.factor.etype = 17;
            PaData {
                padata_type: pa::SPAKE,
                padata_value: encode(&PaSpake::Response(r)).unwrap().into(),
            }
        };
        req.0.padata = Some(vec![cookie.clone(), resp]);
        let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
        assert_eq!(status(&err).0, err::PREAUTH_FAILED, "wrong key {wrong_key}");
    }
}

#[test]
fn the_reply_key_is_k0_not_the_long_term_key() {
    let store = store_with(&[SpakeGroup::Edwards25519], Some("edwards25519"));
    let req = as_req(user(), TEST_REALM, 7170, None).unwrap();
    let (_, method) = method_of(krb5_kdc::issue_as(&store, &req).unwrap_err());
    let spake = find(&method, pa::SPAKE);
    let chal = challenge_of(&spake);
    let mut req = as_req(user(), TEST_REALM, 7171, None).unwrap();
    let body = encode(&req.0.req_body).unwrap();
    let (resp, k0) = pa_spake_response(
        &user_key(&store),
        SpakeGroup::Edwards25519,
        &[],
        spake.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body,
    )
    .unwrap();
    req.0.padata = Some(vec![find(&method, pa::FX_COOKIE), resp]);
    let issued = krb5_kdc::issue_as(&store, &req).expect("SPAKE AS");
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let cipher = issued.rep.0.enc_part.cipher.as_ref();
    assert!(decrypt(&k0, usage, cipher).is_ok());
    assert!(decrypt(&user_key(&store), usage, cipher).is_err());
}
