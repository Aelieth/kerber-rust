//! Z6.2: ENC-TS (2) / ENC-CHALLENGE (138) are advertised only when
//! `have_client_keys` (`kdc_preauth.c:434-447`) is true — a permitted key of
//! a requested etype at the top kvno. SPAKE (151) uses the same condition
//! via `client_keyblock` (`spake_kdc.c:309-314`). Compiles at the parent
//! and fails there: EncTsMod advertised 2 whenever armor was absent,
//! EncChallengeMod advertised 138 whenever the client had any key, SpakeMod
//! advertised 151 whenever groups were configured, and a preauth-required
//! client with no selected key was 14 `CANT_FIND_CLIENT_KEY` instead of 25.

use krb5_asn1::decode;
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::{
    Error, KeyEntry, PrincipalStore, TEST_REALM, TEST_USER, as_req, bootstrap_documented,
    pa_enc_timestamp, random_key,
};
use krb5_protocol::{armor_key, as_req_sname, attach_fast, build_fast_armor, unwrap_fast_rep};
use krb5_types::{MethodData, PrincipalName, ascii, pa};

const AES128: EncryptionType = EncryptionType::Aes128CtsHmacSha196;
const AES256: EncryptionType = EncryptionType::Aes256CtsHmacSha196;

fn user_name() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn store_permitting_aes256() -> PrincipalStore {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let kdc = krb5_config::KdcConf::parse(
        "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    store
}

fn set_user_aes128_only(store: &mut PrincipalStore) {
    store
        .set_keys(
            &user_name(),
            vec![KeyEntry::new(AES128, random_key(AES128).unwrap(), 0)],
            0,
        )
        .unwrap();
}

fn hint_types(err: Error) -> Vec<i32> {
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PREAUTH_REQUIRED, got {err:?}");
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    method.iter().map(|p| p.padata_type).collect()
}

/// Client keyed only aes128 under `permitted_enctypes = aes256`: no
/// `have_client_keys`, so the 25 hint omits PA-ENC-TIMESTAMP (2).
#[test]
fn z6_hint_omits_enc_ts_when_the_only_key_is_not_permitted() {
    let mut store = store_permitting_aes256();
    set_user_aes128_only(&mut store);
    assert!(store.get_name(&user_name()).unwrap().requires_preauth);
    let req = as_req(user_name(), TEST_REALM, 0x2600_0062, None).unwrap();
    let types = hint_types(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert!(
        types.contains(&pa::FX_FAST),
        "25 still advertises FAST: {types:?}"
    );
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP),
        "ENC-TS must be omitted when have_client_keys is false: {types:?}"
    );
    assert!(
        !types.contains(&pa::ETYPE_INFO2),
        "no selected client key → no ETYPE-INFO2: {types:?}"
    );
    assert!(
        !types.contains(&pa::SPAKE),
        "SPAKE must be omitted when client_keyblock is NULL: {types:?}"
    );
}

/// Client keyed only aes128, request lists only aes256: same omit, without
/// changing `permitted_enctypes` (the live diffsend shape).
#[test]
fn z6_hint_omits_enc_ts_when_the_only_key_is_not_requested() {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    set_user_aes128_only(&mut store);
    let req = as_req_sname(
        user_name(),
        TEST_REALM,
        0x2600_0063,
        None,
        PrincipalName::krbtgt(TEST_REALM),
        vec![AES256.to_iana()],
    )
    .unwrap();
    let types = hint_types(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP),
        "ENC-TS must be omitted when no requested etype has a key: {types:?}"
    );
    assert!(
        !types.contains(&pa::SPAKE),
        "SPAKE must be omitted when client_keyblock is NULL: {types:?}"
    );
}

/// FAST: client keyed only aes128 under `permitted_enctypes = aes256` omits
/// PA-ENCRYPTED-CHALLENGE (138). Parent advertised 138 because `keys` was
/// non-empty.
#[test]
fn z6_fast_hint_omits_enc_challenge_when_have_client_keys_is_false() {
    let mut store = store_permitting_aes256();
    let key = store
        .get_name(&user_name())
        .unwrap()
        .keys
        .iter()
        .find(|k| k.etype == AES256)
        .expect("user aes256")
        .key
        .clone();
    let req = as_req(
        user_name(),
        TEST_REALM,
        0x2600_0064,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let armor = krb5_kdc::issue_as(&store, &req).expect("armor TGT");
    set_user_aes128_only(&mut store);
    let sub = ProtocolKey::from_bytes(AES256, &[0x61u8; 32]).unwrap();
    let armor_ap = build_fast_armor(
        armor.rep.0.ticket.clone(),
        &armor.session_key,
        &ascii(TEST_REALM),
        &user_name(),
        Some(&sub),
    )
    .unwrap();
    let akey = armor_key(&armor.session_key, Some(&sub)).unwrap();
    let mut req = as_req(user_name(), TEST_REALM, 0x2600_0065, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, vec![]).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PREAUTH_REQUIRED, got {err:?}");
    };
    let outer: MethodData = decode(&e_data).expect("outer METHOD-DATA");
    let fast = unwrap_fast_rep(&akey, &Some(outer)).expect("FAST unwrap");
    let types: Vec<i32> = fast.padata.iter().map(|p| p.padata_type).collect();
    assert!(
        !types.contains(&pa::ENCRYPTED_CHALLENGE),
        "ENC-CHALLENGE must be omitted when have_client_keys is false: {types:?}"
    );
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP),
        "ENC-TS stays omitted under armor: {types:?}"
    );
}
