//! W1-B B1: FAST reply nonce. MIT `fast.c:397-402` `decrypt_fast_reply`.
//! Unit-only: no MIT tool emits a flipped FAST nonce.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_protocol::{unwrap_fast_rep, unwrap_fast_rep_checked};
use krb5_types::{EncryptedData, PaData, fast::KrbFastArmoredRep, fast::KrbFastResponse, ku, pa};

fn armor() -> ProtocolKey {
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32]).expect("armor")
}

fn sealed(key: &ProtocolKey, nonce: u32) -> PaData {
    let resp = KrbFastResponse {
        padata: Vec::new(),
        strengthen_key: None,
        finished: None,
        nonce,
    };
    let der = encode(&resp).expect("enc");
    let usage = KeyUsage::new(ku::FAST_REP).expect("usage");
    let cipher = encrypt(key, usage, &der).expect("seal");
    let armored = KrbFastArmoredRep {
        enc_fast_rep: EncryptedData {
            etype: key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFastRep::ArmoredData(armored))
            .expect("pa")
            .into(),
    }
}

#[test]
fn b1_fast_reply_nonce_mismatch_is_kdcrep_modified() {
    let key = armor();
    let pa = sealed(&key, 100);
    let err = unwrap_fast_rep_checked(&key, &Some(vec![pa]), 101).expect_err("flipped nonce");
    let msg = err.to_string();
    assert!(
        msg.contains("nonce modified in FAST response"),
        "MIT fast.c:398-402 text, got {msg}"
    );
}

#[test]
fn b1_fast_reply_nonce_match_unwraps() {
    let key = armor();
    let pa = sealed(&key, 100);
    let fast = unwrap_fast_rep_checked(&key, &Some(vec![pa.clone()]), 100).expect("match");
    assert_eq!(fast.nonce, 100);
    let raw = unwrap_fast_rep(&key, &Some(vec![pa])).expect("decrypt-only still works");
    assert_eq!(raw.nonce, 100);
}
