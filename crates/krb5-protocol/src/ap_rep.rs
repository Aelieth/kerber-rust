//! AP-REP / EncAPRepPart (RFC 4120 §5.5.2) mutual authentication.

use krb5_asn1::{decode, encode};
use krb5_crypto::{KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_types::{
    ApRep, Authenticator, EncApRepPart, EncryptedData, EncryptionKey, Microseconds, ku,
};

use crate::error::Error;

/// Build an AP-REP echoing `ctime`/`cusec` from the AP-REQ authenticator.
///
/// # Errors
///
/// Returns crypto or DER failures.
pub fn build_ap_rep(
    session: &ProtocolKey,
    authenticator: &Authenticator,
    subkey: Option<EncryptionKey>,
    seq_number: Option<u32>,
) -> Result<ApRep, Error> {
    let part = EncApRepPart {
        ctime: authenticator.ctime.clone(),
        cusec: authenticator.cusec,
        subkey,
        seq_number,
    };
    let der = encode(&part)?;
    let usage = KeyUsage::new(ku::AP_REP_ENC_PART)?;
    let cipher = encrypt(session, usage, &der)?;
    Ok(ApRep {
        pvno: ApRep::PVNO,
        msg_type: ApRep::MSG_TYPE,
        enc_part: EncryptedData {
            etype: session.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    })
}

/// Decrypt and check an AP-REP against the AP-REQ authenticator.
///
/// # Errors
///
/// Returns crypto, DER, or `ctime`/`cusec` mismatch.
pub fn verify_ap_rep(
    raw: &[u8],
    session: &ProtocolKey,
    authenticator: &Authenticator,
) -> Result<EncApRepPart, Error> {
    let ap: ApRep = decode(raw)?;
    let usage = KeyUsage::new(ku::AP_REP_ENC_PART)?;
    let plain = decrypt(session, usage, ap.enc_part.cipher.as_ref())?;
    let part: EncApRepPart = decode(&plain)?;
    if part.ctime != authenticator.ctime || part.cusec.get() != authenticator.cusec.get() {
        return Err(Error::ReplyMismatch("AP-REP ctime/cusec mismatch".into()));
    }
    let _ = Microseconds::validate(part.cusec);
    Ok(part)
}
