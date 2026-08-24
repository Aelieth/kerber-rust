//! KRB-SAFE, KRB-PRIV, and KRB-CRED (RFC 4120 §5.6–5.8).

use std::sync::atomic::{AtomicU32, Ordering};

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    checksum, decrypt, decrypt_with_state, encrypt, encrypt_with_state, verify_checksum,
    CipherState, KeyUsage, ProtocolKey,
};
use krb5_types::{
    ku, EncKrbCredPart, EncKrbPrivPart, EncryptedData, HostAddress, KerberosTime, KrbCred,
    KrbCredInfo, KrbPriv, KrbSafe, KrbSafeBody, Microseconds, OctetString, Ticket,
};

use crate::error::Error;
use crate::replay::{ReplayCache, ReplayKey};

static NEXT_SAFE_SEQ: AtomicU32 = AtomicU32::new(1);
static NEXT_PRIV_SEQ: AtomicU32 = AtomicU32::new(1);

fn take_seq(counter: &AtomicU32) -> u32 {
    loop {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        if n != 0 {
            return n;
        }
    }
}

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
    build_krb_safe_ex(session, user_data, Some(take_seq(&NEXT_SAFE_SEQ)), true)
}

/// Build a KRB-SAFE with explicit sequence and optional timestamp.
///
/// MIT `kprop` sets `KRB5_AUTH_CONTEXT_DO_SEQUENCE` only (no `DO_TIME`).
///
/// # Errors
///
/// Crypto or DER failures.
pub fn build_krb_safe_ex(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
    include_time: bool,
) -> Result<KrbSafe, Error> {
    let (timestamp, usec) = if include_time {
        let now = KerberosTime::now();
        (
            Some(now.clone()),
            Some(Microseconds::from_subsec_micros(
                now.0.timestamp_subsec_micros(),
            )),
        )
    } else {
        (None, None)
    };
    let body = KrbSafeBody {
        user_data: user_data.to_vec().into(),
        timestamp,
        usec,
        seq_number,
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
/// Integrity, window, replay, or DER failures.
pub fn unwrap_krb_safe(
    session: &ProtocolKey,
    raw: &[u8],
    replay: &ReplayCache,
) -> Result<Vec<u8>, Error> {
    unwrap_krb_safe_ex(session, raw, replay, true, true)
}

/// Verify a KRB-SAFE.
///
/// # Errors
///
/// Integrity, window, replay, or DER failures.
pub fn unwrap_krb_safe_ex(
    session: &ProtocolKey,
    raw: &[u8],
    replay: &ReplayCache,
    require_seq: bool,
    require_time: bool,
) -> Result<Vec<u8>, Error> {
    let msg: KrbSafe = decode(raw)?;
    let body_der = encode(&msg.safe_body)?;
    let usage = KeyUsage::new(ku::KRB_SAFE_CKSUM)?;
    verify_checksum(session, usage, &body_der, msg.cksum.checksum.as_ref())?;
    accept_fresh(
        replay,
        "SAFE",
        msg.safe_body.timestamp.as_ref(),
        msg.safe_body.usec.as_ref(),
        msg.safe_body.seq_number,
        fresh_policy(require_seq, require_time),
        raw,
    )?;
    Ok(msg.safe_body.user_data.to_vec())
}

#[derive(Clone, Copy)]
enum FreshPolicy {
    /// SAFE / application PRIV: timestamp + non-zero seq.
    SeqAndTime,
    /// CRED: timestamp required, seq optional.
    TimeOnly,
    /// MIT kpasswd: seq 0 and missing timestamp are legal.
    HashOnly,
    /// MIT `kprop` (`DO_SEQUENCE` only): seq required, timestamp optional.
    SeqOnly,
}

fn fresh_policy(require_seq: bool, require_time: bool) -> FreshPolicy {
    match (require_seq, require_time) {
        (true, true) => FreshPolicy::SeqAndTime,
        (true, false) => FreshPolicy::SeqOnly,
        (false, true) => FreshPolicy::TimeOnly,
        (false, false) => FreshPolicy::HashOnly,
    }
}

fn accept_fresh(
    replay: &ReplayCache,
    kind: &str,
    ts: Option<&KerberosTime>,
    usec: Option<&Microseconds>,
    seq: Option<u32>,
    policy: FreshPolicy,
    raw: &[u8],
) -> Result<(), Error> {
    let require_time = matches!(policy, FreshPolicy::SeqAndTime | FreshPolicy::TimeOnly);
    let require_seq = matches!(policy, FreshPolicy::SeqAndTime | FreshPolicy::SeqOnly);
    if require_time && ts.is_none() {
        return Err(Error::ReplyMismatch(format!("{kind} missing timestamp")));
    }
    if let Some(t) = ts {
        let now = i64::from(KerberosTime::now().unix_seconds());
        let then = i64::from(t.unix_seconds());
        if (now - then).abs() > 300 {
            return Err(Error::ReplyMismatch(format!("{kind} timestamp window")));
        }
    }
    if require_seq {
        match seq {
            None => {
                return Err(Error::ReplyMismatch(format!("{kind} seq")));
            }
            Some(0) if matches!(policy, FreshPolicy::SeqAndTime) => {
                return Err(Error::ReplyMismatch(format!("{kind} seq")));
            }
            Some(_) => {}
        }
    }
    let key = ReplayKey {
        client: kind.to_owned(),
        server: seq.map_or_else(String::new, |s| s.to_string()),
        ctime: ts.map_or(0, KerberosTime::unix_seconds),
        cusec: usec.map_or(0, |u| u.0),
        auth_hash: ReplayCache::hash_authenticator(raw),
    };
    if replay.check_and_store(key) {
        return Err(Error::ReplyMismatch(format!("{kind} replay")));
    }
    Ok(())
}

/// Build a KRB-PRIV (encrypted). Sequence numbers start at 1.
///
/// # Errors
///
/// Crypto or DER failures.
pub fn build_krb_priv(session: &ProtocolKey, user_data: &[u8]) -> Result<KrbPriv, Error> {
    build_krb_priv_with_seq(session, user_data, Some(take_seq(&NEXT_PRIV_SEQ)))
}

/// Build a KRB-PRIV with an explicit sequence number.
///
/// MIT kpasswd (`DO_SEQUENCE`) puts the authenticator's initial seq (often 0)
/// on the request KRB-PRIV. The reply must echo the same seq in AP-REP and
/// KRB-PRIV so `krb5_rd_priv` accepts it.
///
/// # Errors
///
/// Crypto or DER failures.
pub fn build_krb_priv_with_seq(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
) -> Result<KrbPriv, Error> {
    let mut state = CipherState::initial();
    build_krb_priv_chained(session, user_data, seq_number, true, &mut state)
}

/// Build a KRB-PRIV with cipher-state chaining (MIT `auth_con_initivector`).
///
/// # Errors
///
/// Crypto or DER failures.
pub fn build_krb_priv_chained(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
    include_time: bool,
    state: &mut CipherState,
) -> Result<KrbPriv, Error> {
    let (timestamp, usec) = if include_time {
        let now = KerberosTime::now();
        (
            Some(now.clone()),
            Some(Microseconds::from_subsec_micros(
                now.0.timestamp_subsec_micros(),
            )),
        )
    } else {
        (None, None)
    };
    let part = EncKrbPrivPart {
        user_data: user_data.to_vec().into(),
        timestamp,
        usec,
        seq_number,
        s_address: local_addr(),
        r_address: None,
    };
    let der = encode(&part)?;
    let usage = KeyUsage::new(ku::KRB_PRIV_ENC_PART)?;
    let cipher = encrypt_with_state(session, usage, state, &der)?;
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
/// Requires a non-zero sequence number (RFC 4120 application traffic).
///
/// # Errors
///
/// Crypto, window, replay, or DER failures.
pub fn unwrap_krb_priv(
    session: &ProtocolKey,
    raw: &[u8],
    replay: &ReplayCache,
) -> Result<Vec<u8>, Error> {
    unwrap_krb_priv_ex(session, raw, replay, true, true)
}

/// Decrypt a KRB-PRIV.
///
/// MIT `kpasswd` (`krb5int_mk_chpw_req`) sets `DO_SEQUENCE` only, clearing
/// `DO_TIME`, so the request KRB-PRIV often has seq 0 and no timestamp.
/// Pass `require_seq`/`require_time` false on that path.
///
/// # Errors
///
/// Crypto, window, replay, or DER failures.
pub fn unwrap_krb_priv_ex(
    session: &ProtocolKey,
    raw: &[u8],
    replay: &ReplayCache,
    require_seq: bool,
    require_time: bool,
) -> Result<Vec<u8>, Error> {
    let mut state = CipherState::initial();
    unwrap_krb_priv_chained(session, raw, replay, require_seq, require_time, &mut state)
}

/// Decrypt a KRB-PRIV using cipher-state chaining (MIT kprop `initivector`).
///
/// # Errors
///
/// Crypto, window, replay, or DER failures.
pub fn unwrap_krb_priv_chained(
    session: &ProtocolKey,
    raw: &[u8],
    replay: &ReplayCache,
    require_seq: bool,
    require_time: bool,
    state: &mut CipherState,
) -> Result<Vec<u8>, Error> {
    let msg: KrbPriv = decode(raw)?;
    let usage = KeyUsage::new(ku::KRB_PRIV_ENC_PART)?;
    let plain = decrypt_with_state(session, usage, state, msg.enc_part.cipher.as_ref())?;
    let part: EncKrbPrivPart = decode(&plain)?;
    accept_fresh(
        replay,
        "PRIV",
        part.timestamp.as_ref(),
        part.usec.as_ref(),
        part.seq_number,
        fresh_policy(require_seq, require_time),
        raw,
    )?;
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
/// Crypto, window, replay, or DER failures.
pub fn unwrap_krb_cred(
    session: &ProtocolKey,
    raw: &[u8],
    replay: &ReplayCache,
) -> Result<(KrbCred, EncKrbCredPart), Error> {
    let msg: KrbCred = decode(raw)?;
    let usage = KeyUsage::new(ku::KRB_CRED_ENC_PART)?;
    let plain = decrypt(session, usage, msg.enc_part.cipher.as_ref())?;
    let part: EncKrbCredPart = decode(&plain)?;
    accept_fresh(
        replay,
        "CRED",
        part.timestamp.as_ref(),
        part.usec.as_ref(),
        None,
        FreshPolicy::TimeOnly,
        raw,
    )?;
    Ok((msg, part))
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_crypto::{EncryptionType, ProtocolKey};

    fn session() -> ProtocolKey {
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42u8; 32]).unwrap()
    }

    #[test]
    fn safe_seq_increments_and_second_unwrap_fails() {
        let key = session();
        let a = build_krb_safe(&key, b"one").unwrap();
        let b = build_krb_safe(&key, b"two").unwrap();
        assert!(a.safe_body.seq_number.unwrap() < b.safe_body.seq_number.unwrap());
        let raw = encode(&a).unwrap();
        let cache = ReplayCache::new();
        assert_eq!(unwrap_krb_safe(&key, &raw, &cache).unwrap(), b"one");
        assert!(unwrap_krb_safe(&key, &raw, &cache).is_err());
    }

    #[test]
    fn priv_second_unwrap_fails() {
        let key = session();
        let msg = build_krb_priv(&key, b"secret").unwrap();
        let raw = encode(&msg).unwrap();
        let cache = ReplayCache::new();
        assert_eq!(unwrap_krb_priv(&key, &raw, &cache).unwrap(), b"secret");
        assert!(unwrap_krb_priv(&key, &raw, &cache).is_err());
    }

    #[test]
    fn cred_window_and_second_unwrap_fails() {
        let key = session();
        let msg = build_krb_cred(&key, Vec::new(), Vec::new()).unwrap();
        let raw = encode(&msg).unwrap();
        let cache = ReplayCache::new();
        let (_, part) = unwrap_krb_cred(&key, &raw, &cache).unwrap();
        assert!(part.timestamp.is_some());
        assert!(unwrap_krb_cred(&key, &raw, &cache).is_err());
    }
}
