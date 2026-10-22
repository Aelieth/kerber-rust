//! The encrypted challenge clpreauth module (`lib/krb5/krb/preauth_ec.c`).

use krb5_asn1::{decode, encode};
use krb5_crypto::{KeyUsage, ProtocolKey, decrypt_enc_data, encrypt, krb_fx_cf2};
use krb5_types::{EncryptedData, KerberosTime, Microseconds, PaData, PaEncTsEnc, ku, pa};

use crate::error::Error;
use crate::trace::kdc_code;

/// MIT's name of the encrypted challenge module (`preauth_ec.c`).
pub(super) const EC_MODULE: &str = "encrypted_challenge";

const ASN1_BAD_ID: i64 = 1_859_794_438;

/// The PA-ENC-TS-ENC of `sec`.`usec`; MIT encodes `pausec` only when it is not zero.
/// MIT `pa_enc_ts_1` (`lib/krb5/asn.1/asn1_k_encode.c:935-935`): `pausec` is an `opt_int32`, which is omitted when 0.
pub(super) fn pa_enc_ts(sec: &KerberosTime, usec: Microseconds) -> PaEncTsEnc {
    PaEncTsEnc {
        patimestamp: sec.clone(),
        pausec: (usec.get() != 0).then_some(usec),
    }
}

/// The client's PA-ENCRYPTED-CHALLENGE: the timestamp encrypted in the client challenge key.
/// MIT `ec_process` (`lib/krb5/krb/preauth_ec.c:96-145`): with no padata from the KDC, the timestamp MIT's `get_preauth_time` gives is encoded, encrypted under KRB-FX-CF2(armor key, AS key, "clientchallengearmor", "challengelongterm") with key usage 54, and sent as PA-ENCRYPTED-CHALLENGE; no fallback follows it.
pub(super) fn client_challenge(
    armor_key: &ProtocolKey,
    as_key: &ProtocolKey,
    now: (&KerberosTime, Microseconds),
) -> Result<PaData, Error> {
    let ts = encode(&pa_enc_ts(now.0, now.1))?;
    let challenge_key = krb_fx_cf2(
        armor_key,
        as_key,
        b"clientchallengearmor",
        b"challengelongterm",
    )?;
    let cipher = encrypt(
        &challenge_key,
        KeyUsage::new(ku::ENC_CHALLENGE_CLIENT)?,
        &ts,
    )?;
    let enc = EncryptedData {
        etype: challenge_key.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    };
    Ok(PaData {
        padata_type: pa::ENCRYPTED_CHALLENGE,
        padata_value: encode(&enc)?.into(),
    })
}

/// The KDC's PA-ENCRYPTED-CHALLENGE in the reply, decrypted under the KDC challenge key; the code the module returns, 0 when it decrypts.
/// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:679-712`): on the reply a module's failure is traced and noted, and the reply is processed on, so it fails nothing.
pub(super) fn verify_kdc_challenge(
    armor_key: &ProtocolKey,
    as_key: &ProtocolKey,
    padata: &[u8],
) -> i64 {
    let Ok(enc) = decode::<EncryptedData>(padata) else {
        return ASN1_BAD_ID;
    };
    let Ok(key) = krb_fx_cf2(
        armor_key,
        as_key,
        b"kdcchallengearmor",
        b"challengelongterm",
    ) else {
        return KRB5_BAD_ENCTYPE;
    };
    // MIT `krb5_k_decrypt` (`lib/crypto/krb/decrypt.c:45-52`): ciphertext of another enctype is `KRB5_BAD_ENCTYPE`, a short one `KRB5_BAD_MSIZE`.
    let decrypted = KeyUsage::new(ku::ENC_CHALLENGE_KDC)
        .and_then(|usage| decrypt_enc_data(&key, usage, enc.etype, enc.cipher.as_ref()));
    match decrypted {
        Ok(_) => 0,
        Err(krb5_crypto::Error::BadEnctype(_)) => KRB5_BAD_ENCTYPE,
        Err(krb5_crypto::Error::CiphertextTooShort) => KRB5_BAD_MSIZE,
        Err(_) => kdc_code(krb5_types::err::BAD_INTEGRITY),
    }
}

const KRB5_BAD_ENCTYPE: i64 = crate::trace::ERROR_TABLE_BASE_KRB5 + 188;

const KRB5_BAD_MSIZE: i64 = crate::trace::ERROR_TABLE_BASE_KRB5 + 190;

/// What the module returns for the reply's PA-ENCRYPTED-CHALLENGE, `None` when the reply has none.
pub(super) fn reply_code(
    padata: &[PaData],
    armor_key: &ProtocolKey,
    as_key: &ProtocolKey,
) -> Option<i64> {
    padata
        .iter()
        .find(|p| p.padata_type == pa::ENCRYPTED_CHALLENGE && !p.padata_value.is_empty())
        .map(|p| verify_kdc_challenge(armor_key, as_key, p.padata_value.as_ref()))
}

#[cfg(test)]
mod tests;
