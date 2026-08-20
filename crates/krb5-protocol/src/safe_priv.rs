//! KRB-SAFE, KRB-PRIV, and KRB-CRED (RFC 4120 §5.6–5.8).

use krb5_asn1::{decode, encode};
use krb5_crypto::{checksum, decrypt, encrypt, verify_checksum, KeyUsage, ProtocolKey};
use krb5_types::{
    ku, EncKrbCredPart, EncKrbPrivPart, EncryptedData, HostAddress, KerberosTime, KrbCred,
    KrbCredInfo, KrbPriv, KrbSafe, KrbSafeBody, Microseconds, OctetString, Ticket,
};

use crate::error::Error;

fn local_addr() -> HostAddress {
    HostAddress {
        addr_type: 2,
        address: OctetString::from(vec![127, 0, 0, 1]),
    }
}

/// Build a KRB-SAFE (integrity-only).
///
/// # Errors
///
/// Crypto or DER failures.
pub fn build_krb_safe(session: &ProtocolKey, user_data: &[u8]) -> Result<KrbSafe, Error> {
    let now = KerberosTime::now();
    let body = KrbSafeBody {
        user_data: user_data.to_vec().into(),
        timestamp: Some(now.clone()),
        usec: Some(Microseconds::from_subsec_micros(
            now.0.timestamp_subsec_micros(),
        )),
        seq_number: Some(1),
        s_address: local_addr(),
        r_address: None,
    };
    let body_der = encode(&body)?;
    let usage = KeyUsage::new(ku::KRB_SAFE_CKSUM)?;
    let mic = checksum(session, usage, &body_der)?;
    Ok(KrbSafe {
        pvno: KrbSafe::PVNO,
        msg_type: KrbSafe::MSG_TYPE,
        safe_body: body,
        cksum: krb5_types::Checksum {
            cksumtype: session.etype().checksum_type(),
            checksum: mic.into(),
        },
    })
}

/// Verify a KRB-SAFE and return the user data.
///
/// # Errors
///
/// Integrity or DER failures.
pub fn unwrap_krb_safe(session: &ProtocolKey, raw: &[u8]) -> Result<Vec<u8>, Error> {
    let msg: KrbSafe = decode(raw)?;
    let body_der = encode(&msg.safe_body)?;
    let usage = KeyUsage::new(ku::KRB_SAFE_CKSUM)?;
    verify_checksum(session, usage, &body_der, msg.cksum.checksum.as_ref())?;
    check_safe_priv_window(msg.safe_body.timestamp.as_ref(), msg.safe_body.seq_number)?;
    Ok(msg.safe_body.user_data.to_vec())
}

fn check_safe_priv_window(ts: Option<&KerberosTime>, seq: Option<u32>) -> Result<(), Error> {
    let Some(t) = ts else {
        return Err(Error::ReplyMismatch("SAFE/PRIV missing timestamp".into()));
    };
    let now = i64::from(KerberosTime::now().unix_seconds());
    let then = i64::from(t.unix_seconds());
    if (now - then).abs() > 300 {
        return Err(Error::ReplyMismatch("SAFE/PRIV timestamp window".into()));
    }
    if seq == Some(0) {
        return Err(Error::ReplyMismatch("SAFE/PRIV seq 0".into()));
    }
    Ok(())
}

/// Build a KRB-PRIV (encrypted).
///
/// # Errors
///
/// Crypto or DER failures.
pub fn build_krb_priv(session: &ProtocolKey, user_data: &[u8]) -> Result<KrbPriv, Error> {
    let now = KerberosTime::now();
    let part = EncKrbPrivPart {
        user_data: user_data.to_vec().into(),
        timestamp: Some(now.clone()),
        usec: Some(Microseconds::from_subsec_micros(
            now.0.timestamp_subsec_micros(),
        )),
        seq_number: Some(1),
        s_address: local_addr(),
        r_address: None,
    };
    let der = encode(&part)?;
    let usage = KeyUsage::new(ku::KRB_PRIV_ENC_PART)?;
    let cipher = encrypt(session, usage, &der)?;
    Ok(KrbPriv {
        pvno: KrbPriv::PVNO,
        msg_type: KrbPriv::MSG_TYPE,
        enc_part: EncryptedData {
            etype: session.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    })
}

/// Decrypt a KRB-PRIV and return the user data.
///
/// # Errors
///
/// Crypto or DER failures.
pub fn unwrap_krb_priv(session: &ProtocolKey, raw: &[u8]) -> Result<Vec<u8>, Error> {
    let msg: KrbPriv = decode(raw)?;
    let usage = KeyUsage::new(ku::KRB_PRIV_ENC_PART)?;
    let plain = decrypt(session, usage, msg.enc_part.cipher.as_ref())?;
    let part: EncKrbPrivPart = decode(&plain)?;
    check_safe_priv_window(part.timestamp.as_ref(), part.seq_number)?;
    Ok(part.user_data.to_vec())
}

/// Build a KRB-CRED forwarding `tickets` + `info`.
///
/// # Errors
///
/// Crypto or DER failures.
pub fn build_krb_cred(
    session: &ProtocolKey,
    tickets: Vec<Ticket>,
    ticket_info: Vec<KrbCredInfo>,
) -> Result<KrbCred, Error> {
    let now = KerberosTime::now();
    let part = EncKrbCredPart {
        ticket_info,
        nonce: None,
        timestamp: Some(now.clone()),
        usec: Some(Microseconds::from_subsec_micros(
            now.0.timestamp_subsec_micros(),
        )),
        s_address: Some(local_addr()),
        r_address: None,
    };
    let der = encode(&part)?;
    let usage = KeyUsage::new(ku::KRB_CRED_ENC_PART)?;
    let cipher = encrypt(session, usage, &der)?;
    Ok(KrbCred {
        pvno: KrbCred::PVNO,
        msg_type: KrbCred::MSG_TYPE,
        tickets,
        enc_part: EncryptedData {
            etype: session.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    })
}

/// Decrypt a KRB-CRED.
///
/// # Errors
///
/// Crypto or DER failures.
pub fn unwrap_krb_cred(
    session: &ProtocolKey,
    raw: &[u8],
) -> Result<(KrbCred, EncKrbCredPart), Error> {
    let msg: KrbCred = decode(raw)?;
    let usage = KeyUsage::new(ku::KRB_CRED_ENC_PART)?;
    let plain = decrypt(session, usage, msg.enc_part.cipher.as_ref())?;
    let part: EncKrbCredPart = decode(&plain)?;
    Ok((msg, part))
}
