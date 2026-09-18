//! W1-Z Z1b.3 follow-up: MIT `filter_preauth_error` (`kdc_preauth.c:1092-1133`)
//! at the kdcpreauth module boundary (`finish_check_padata` `:1206`). A module
//! failure whose code is not on the pass-through list reaches the client as
//! 24 `PREAUTH_FAILED`, under the `PREAUTH_FAILED` status `finish_preauth`
//! sets for every module failure (`do_as_req.c:442`). Compiles at `7a44ef8`
//! (parent-red): the parent put each module's own code on the wire — 60 for
//! both cells here — and CI 550-552 were red on `differential-gate.sh`
//! `as-optimistic-encts-wrong-etype` because of the first one.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_kdc::{PrincipalStore, TEST_REALM, bootstrap_documented};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_testkit::user;
use krb5_types::{
    EncryptedData, KerberosTime, KrbError, Microseconds, PaData, PaEncTsEnc, err, ku, pa,
};

fn user_key(store: &PrincipalStore, etype: EncryptionType) -> ProtocolKey {
    store
        .get_name(&user())
        .unwrap()
        .keys
        .iter()
        .filter(|k| k.etype == etype)
        .max_by_key(|k| k.kvno)
        .expect("user key of that etype")
        .key
        .clone()
}

fn wire(store: &PrincipalStore, nonce: u32, padata: Vec<PaData>) -> (i32, Option<String>) {
    let req = as_req(user(), TEST_REALM, nonce, Some(padata)).unwrap();
    let raw = encode(&req).unwrap();
    let reply = krb5_kdc::handle_request(store, &raw).expect("a KRB-ERROR reply");
    let e = decode::<KrbError>(&reply).expect("KRB-ERROR");
    (
        e.error_code,
        e.e_text
            .as_ref()
            .map(|t| String::from_utf8_lossy(t.as_bytes()).into_owned()),
    )
}

/// A PA-ENC-TIMESTAMP declaring an enctype the KDC knows but does not permit
/// is `KRB5_KDB_NO_PERMITTED_KEY` out of `krb5_dbe_search_enctype`
/// (`kdb_default.c:60-61`); `enc_ts_verify` remaps only `NO_MATCHING_KEY`
/// (`kdc_preauth_encts.c:113-114`), and the filter turns everything else into
/// 24 — the same wire answer as a plain wrong password. (`differential-gate.sh`
/// `as-optimistic-encts-wrong-etype`: des3 against the harness profile's
/// aes-only `permitted_enctypes`, 24 on the MIT leg.)
#[test]
fn z1b_encts_under_a_non_permitted_etype_is_24_like_filter_preauth_error() {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let kdc = krb5_config::KdcConf::parse(
        "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    assert!(
        !store
            .policy()
            .etype_permitted(EncryptionType::Aes128CtsHmacSha196)
    );
    // The user's real aes128 key: a *correct* timestamp under a non-permitted
    // enctype, so nothing but the permitted-enctype walk can refuse it.
    let aes128 = user_key(&store, EncryptionType::Aes128CtsHmacSha196);
    let padata = vec![pa_enc_timestamp(&aes128).unwrap()];
    assert_eq!(
        wire(&store, 0x1b06, padata),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into()))
    );
}

/// A timestamp whose `pausec` is outside 0..=999999: the module refuses it
/// with a code that is not on the pass-through list (MIT's decoder would
/// take it and `krb5_check_clockskew` looks at `patimestamp` only, so MIT
/// never errs here; when the Rust module does, the filter still applies and
/// the client sees 24, not 60).
#[test]
fn z1b_encts_with_an_out_of_range_pausec_is_24_not_60() {
    krb5_config::isolate_test_krb5();
    let (store, _) = bootstrap_documented().unwrap();
    let key = user_key(&store, EncryptionType::Aes256CtsHmacSha196);
    let ts = PaEncTsEnc {
        patimestamp: KerberosTime::now(),
        pausec: Some(Microseconds(1_000_000)),
    };
    let der = encode(&ts).unwrap();
    let cipher = encrypt(&key, KeyUsage::new(ku::PA_ENC_TIMESTAMP).unwrap(), &der).unwrap();
    let enc = EncryptedData {
        etype: key.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    };
    let padata = vec![PaData {
        padata_type: pa::ENC_TIMESTAMP,
        padata_value: encode(&enc).unwrap().into(),
    }];
    assert_eq!(
        wire(&store, 0x1b07, padata),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into()))
    );
}
