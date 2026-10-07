//! The encrypted challenge module against MIT 1.22.2's own keys: the client and KDC challenge keys
//! below are what MIT's `krb5_c_fx_cf2_simple` gives for these armor and AS keys with
//! `preauth_ec.c`'s peppers, read live from MIT's library.

use super::{
    ASN1_BAD_ID, KRB5_BAD_ENCTYPE, KRB5_BAD_MSIZE, client_challenge, pa_enc_ts, reply_code,
    verify_kdc_challenge,
};
use crate::trace::kdc_code;
use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_types::{EncryptedData, KerberosTime, Microseconds, PaData, PaEncTsEnc, err, ku, pa};

/// MIT 1.22.2, live: armor aes256-sha2 00..1F, AS key aes256-sha2 20..3F, client challenge key.
const MIT_CLIENT_SHA2: &str = "4897C9E5DDF5B289B11ED315E1F08C816E2D2FCFFA4065DB886AFEEA47D10BDD";
/// The same keys' KDC challenge key.
const MIT_KDC_SHA2: &str = "EE90E6C8202684D975BC2408F0A3F930278F5F5D87D2162DC814317844612BE2";
/// MIT 1.22.2, live: armor aes256-cts 00..1F, AS key aes128-cts 40..4F, client challenge key
/// (the armor key's enctype).
const MIT_CLIENT_AES: &str = "81D3AA6A417BB4EB2B4CE1DAD806DA65F350A7A1C104DF4ED7301579C6E33AEA";
/// The same keys' KDC challenge key.
const MIT_KDC_AES: &str = "E672A3FC2439F61C4FCB08F6B4E32CEA366BF05F1A56C2A1A244EE9AF497EE1D";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn counting_key(etype: EncryptionType, start: u8) -> ProtocolKey {
    let len = u8::try_from(etype.key_len()).unwrap();
    let bytes: Vec<u8> = (0..len).map(|i| start + i).collect();
    ProtocolKey::from_bytes(etype, &bytes).unwrap()
}

fn sha2_pair() -> (ProtocolKey, ProtocolKey) {
    (
        counting_key(EncryptionType::Aes256CtsHmacSha384192, 0x00),
        counting_key(EncryptionType::Aes256CtsHmacSha384192, 0x20),
    )
}

fn aes_pair() -> (ProtocolKey, ProtocolKey) {
    (
        counting_key(EncryptionType::Aes256CtsHmacSha196, 0x00),
        counting_key(EncryptionType::Aes128CtsHmacSha196, 0x40),
    )
}

fn when() -> (KerberosTime, Microseconds) {
    (
        KerberosTime::from_unix_seconds(1_791_265_478),
        Microseconds::new(244_167).unwrap(),
    )
}

/// The client's PA-ENCRYPTED-CHALLENGE, decrypted with MIT's client challenge key under usage 54.
fn open_client(pa: &PaData, mit_key: &str, etype: EncryptionType) -> PaEncTsEnc {
    assert_eq!(pa.padata_type, pa::ENCRYPTED_CHALLENGE);
    let enc: EncryptedData = decode(pa.padata_value.as_ref()).unwrap();
    assert_eq!(
        enc.etype,
        etype.to_iana(),
        "labelled with the armor key's enctype"
    );
    assert_eq!(enc.kvno, None);
    let key = ProtocolKey::from_bytes(etype, &unhex(mit_key)).unwrap();
    let usage = KeyUsage::new(ku::ENC_CHALLENGE_CLIENT).unwrap();
    decode(&decrypt(&key, usage, enc.cipher.as_ref()).unwrap()).unwrap()
}

/// A KDC challenge as MIT's `ec_return` makes it, under `key_hex` and `usage`.
fn kdc_challenge(key_hex: &str, etype: EncryptionType, usage: u32) -> Vec<u8> {
    let key = ProtocolKey::from_bytes(etype, &unhex(key_hex)).unwrap();
    let (t, usec) = when();
    let ts = encode(&pa_enc_ts(&t, usec)).unwrap();
    let cipher = encrypt(&key, KeyUsage::new(usage).unwrap(), &ts).unwrap();
    encode(&EncryptedData {
        etype: etype.to_iana(),
        kvno: None,
        cipher: cipher.into(),
    })
    .unwrap()
}

#[test]
fn the_client_challenge_is_under_mits_client_challenge_key() {
    let (t, usec) = when();
    for (pair, mit, etype) in [
        (
            sha2_pair(),
            MIT_CLIENT_SHA2,
            EncryptionType::Aes256CtsHmacSha384192,
        ),
        (
            aes_pair(),
            MIT_CLIENT_AES,
            EncryptionType::Aes256CtsHmacSha196,
        ),
    ] {
        let (armor, as_key) = pair;
        let pa = client_challenge(&armor, &as_key, (&t, usec)).unwrap();
        let ts = open_client(&pa, mit, etype);
        assert_eq!(ts.patimestamp, t);
        assert_eq!(ts.pausec, Some(usec));
    }
}

#[test]
fn the_kdc_challenge_opens_under_mits_kdc_challenge_key_only() {
    for (pair, kdc, client, etype) in [
        (
            sha2_pair(),
            MIT_KDC_SHA2,
            MIT_CLIENT_SHA2,
            EncryptionType::Aes256CtsHmacSha384192,
        ),
        (
            aes_pair(),
            MIT_KDC_AES,
            MIT_CLIENT_AES,
            EncryptionType::Aes256CtsHmacSha196,
        ),
    ] {
        let (armor, as_key) = pair;
        let good = kdc_challenge(kdc, etype, ku::ENC_CHALLENGE_KDC);
        assert_eq!(verify_kdc_challenge(&armor, &as_key, &good), 0);
        // The client's own key, or the KDC's key under the client's usage, does not open it.
        let swapped = kdc_challenge(client, etype, ku::ENC_CHALLENGE_KDC);
        let usage54 = kdc_challenge(kdc, etype, ku::ENC_CHALLENGE_CLIENT);
        for bad in [swapped, usage54] {
            assert_eq!(
                verify_kdc_challenge(&armor, &as_key, &bad),
                kdc_code(err::BAD_INTEGRITY)
            );
        }
    }
}

#[test]
fn a_malformed_kdc_challenge_is_traced_with_mits_codes() {
    let (armor, as_key) = sha2_pair();
    assert_eq!(
        verify_kdc_challenge(&armor, &as_key, &[0x04, 0x01, 0x00]),
        ASN1_BAD_ID
    );
    let mut enc: EncryptedData = decode(&kdc_challenge(
        MIT_KDC_SHA2,
        EncryptionType::Aes256CtsHmacSha384192,
        ku::ENC_CHALLENGE_KDC,
    ))
    .unwrap();
    enc.etype = EncryptionType::Aes256CtsHmacSha196.to_iana();
    let relabelled = encode(&enc).unwrap();
    assert_eq!(
        verify_kdc_challenge(&armor, &as_key, &relabelled),
        KRB5_BAD_ENCTYPE
    );
    enc.etype = EncryptionType::Aes256CtsHmacSha384192.to_iana();
    enc.cipher = vec![0u8; 8].into();
    let short = encode(&enc).unwrap();
    assert_eq!(
        verify_kdc_challenge(&armor, &as_key, &short),
        KRB5_BAD_MSIZE
    );
}

#[test]
fn only_a_reply_that_carries_a_kdc_challenge_is_processed() {
    let (armor, as_key) = sha2_pair();
    let good = PaData {
        padata_type: pa::ENCRYPTED_CHALLENGE,
        padata_value: kdc_challenge(
            MIT_KDC_SHA2,
            EncryptionType::Aes256CtsHmacSha384192,
            ku::ENC_CHALLENGE_KDC,
        )
        .into(),
    };
    let info = PaData {
        padata_type: pa::ETYPE_INFO2,
        padata_value: Vec::new().into(),
    };
    assert_eq!(reply_code(&[good, info.clone()], &armor, &as_key), Some(0));
    assert_eq!(reply_code(&[info], &armor, &as_key), None);
}

#[test]
fn pausec_is_encoded_only_when_it_is_not_zero() {
    let (t, usec) = when();
    let with = encode(&pa_enc_ts(&t, usec)).unwrap();
    let zero = encode(&pa_enc_ts(&t, Microseconds::ZERO)).unwrap();
    assert_eq!(
        decode::<PaEncTsEnc>(&with).unwrap().pausec,
        Some(usec),
        "MIT encodes a set pausec"
    );
    assert_eq!(
        decode::<PaEncTsEnc>(&zero).unwrap().pausec,
        None,
        "MIT's opt_int32 omits a zero pausec"
    );
    assert_eq!(
        with.len() - zero.len(),
        7,
        "[1] INTEGER 244167 is seven octets"
    );
}

#[test]
fn under_armor_encrypted_timestamp_runs_only_when_the_kdc_offers_it_first() {
    let list = |types: &[i32]| -> Vec<PaData> {
        types
            .iter()
            .map(|&padata_type| PaData {
                padata_type,
                padata_value: Vec::new().into(),
            })
            .collect()
    };
    // MIT's KDC under FAST (live, kinit -T): 136, 19, 138, 133, 137.
    assert_eq!(
        super::super::fast::fast_mechanism(&list(&[136, 19, 138, 133, 137])).unwrap(),
        pa::ENCRYPTED_CHALLENGE
    );
    assert_eq!(
        super::super::fast::fast_mechanism(&list(&[136, 19, 151, 138, 133, 137])).unwrap(),
        pa::ENCRYPTED_CHALLENGE
    );
    assert_eq!(
        super::super::fast::fast_mechanism(&list(&[2, 138])).unwrap(),
        pa::ENC_TIMESTAMP
    );
    assert!(super::super::fast::fast_mechanism(&list(&[136, 19, 133, 137])).is_err());
}
