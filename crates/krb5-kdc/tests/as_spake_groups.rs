//! The KDC's SPAKE module as MIT's `spake_kdc.c` and `groups.c`: edwards25519 end to end, the
//! group the client's order picks, the optimistic challenge `spake_preauth_kdc_challenge` sends
//! with PREAUTH_REQUIRED, the module that does not load (no group, or a challenge group not
//! permitted), and the messages that are PREAUTH_FAILED.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, ProtocolKey, SpakeGroup};
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented};
use krb5_kdc::{Error, PrincipalStore};
use krb5_protocol::{as_req, pa_spake_response};
use krb5_testkit::{status, user};
use krb5_types::spake::{PaSpake, SpakeChallenge, SpakeSupport};
use krb5_types::{MethodData, PaData, err, pa};

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
fn a_module_that_did_not_load_offers_nothing_and_skips_pa_spake() {
    // A challenge group that is not permitted fails the module's init, so the KDC neither
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
