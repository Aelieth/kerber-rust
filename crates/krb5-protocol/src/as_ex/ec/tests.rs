//! The encrypted challenge module against MIT 1.22.2's own keys: the client and KDC challenge keys below are what MIT's `krb5_c_fx_cf2_simple` gives for these armor and AS keys with `preauth_ec.c`'s peppers, read live from MIT's library.

use super::{client_challenge, pa_enc_ts, verify_kdc_challenge};
use crate::trace::kdc_code;
use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_types::{EncryptedData, KerberosTime, Microseconds, PaData, PaEncTsEnc, err, ku, pa};

const MIT_CLIENT_SHA2: &str = "4897C9E5DDF5B289B11ED315E1F08C816E2D2FCFFA4065DB886AFEEA47D10BDD";
const MIT_KDC_SHA2: &str = "EE90E6C8202684D975BC2408F0A3F930278F5F5D87D2162DC814317844612BE2";
const MIT_CLIENT_AES: &str = "81D3AA6A417BB4EB2B4CE1DAD806DA65F350A7A1C104DF4ED7301579C6E33AEA";
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
