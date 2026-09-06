//! KRB-SAFE, KRB-PRIV, and KRB-CRED (RFC 4120 §5.6–5.8).

use std::sync::atomic::{AtomicU32, Ordering};

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    CipherState, KeyUsage, ProtocolKey, checksum, cksumtype_is_coll_proof, cksumtype_is_keyed,
    cksumtype_is_known, decrypt, decrypt_with_state, encrypt, encrypt_with_state,
    verify_checksum_type,
};
use krb5_types::{
    Checksum, EncKrbCredPart, EncKrbPrivPart, EncryptedData, HostAddress, KerberosTime, KrbCred,
    KrbCredInfo, KrbPriv, KrbSafe, KrbSafeBody, Microseconds, OctetString, Ticket, err, ku,
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
    let msg = verify_krb_safe_checksum(session, raw, None, None)?;
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

/// MIT `rd_safe.c:43-125`: APPLICATION 20, saved body DER, addrs, dummy, body fallback.
///
/// # Errors
///
/// [`Error::KrbError`] 40 / 38 / 15 / 50 / 41.
pub fn verify_krb_safe_checksum(
    session: &ProtocolKey,
    raw: &[u8],
    remote: Option<&HostAddress>,
    local: Option<&HostAddress>,
) -> Result<KrbSafe, Error> {
    if !is_krb_safe(raw) {
        return Err(Error::KrbError {
            code: err::MSG_TYPE,
            text: Some("Invalid message type".into()),
        });
    }
    let (msg, body_der) = decode_safe_with_body(raw)?;
    if msg.msg_type != KrbSafe::MSG_TYPE {
        return Err(Error::KrbError {
            code: err::MSG_TYPE,
            text: Some("Invalid message type".into()),
        });
    }
    let ctype = msg.cksum.cksumtype;
    if !cksumtype_is_known(ctype) {
        return Err(Error::KrbError {
            code: err::SUMTYPE_NOSUPP,
            text: Some("checksum type".into()),
        });
    }
    if !cksumtype_is_coll_proof(ctype) || !cksumtype_is_keyed(ctype) {
        return Err(Error::KrbError {
            code: err::INAPP_CKSUM,
            text: Some("inapp checksum".into()),
        });
    }
    check_privsafe_addrs(
        &msg.safe_body.s_address,
        msg.safe_body.r_address.as_ref(),
        remote,
        local,
    )?;
    let usage = KeyUsage::new(ku::KRB_SAFE_CKSUM)?;
    let mac = msg.cksum.checksum.as_ref();
    let dummy = encode_safe_with_body(msg.pvno, msg.msg_type, &body_der, &zero_safe_cksum())?;
    if verify_checksum_type(session, usage, &dummy, ctype, mac).is_ok() {
        return Ok(msg);
    }
    if verify_checksum_type(session, usage, &body_der, ctype, mac).is_ok() {
        return Ok(msg);
    }
    Err(Error::KrbError {
        code: err::MODIFIED,
        text: Some("safe checksum".into()),
    })
}

/// MIT `k5_privsafe_check_addrs` (`privsafe.c:312-382`).
///
/// # Errors
///
/// [`Error::KrbError`] 38 when a supplied comparison address does not match.
pub fn check_privsafe_addrs(
    msg_s: &HostAddress,
    msg_r: Option<&HostAddress>,
    remote: Option<&HostAddress>,
    local: Option<&HostAddress>,
) -> Result<(), Error> {
    if let Some(want) = remote
        && want != msg_s
    {
        return Err(Error::KrbError {
            code: err::BADADDR,
            text: Some("Incorrect net address".into()),
        });
    }
    let Some(got_r) = msg_r else {
        return Ok(());
    };
    if let Some(want) = local
        && want != got_r
    {
        return Err(Error::KrbError {
            code: err::BADADDR,
            text: Some("Incorrect net address".into()),
        });
    }
    Ok(())
}

fn is_krb_safe(raw: &[u8]) -> bool {
    raw.first().is_some_and(|b| b & !0x20 == 0x54)
}

fn zero_safe_cksum() -> Checksum {
    Checksum {
        cksumtype: 0,
        checksum: Vec::new().into(),
    }
}

fn decode_safe_with_body(raw: &[u8]) -> Result<(KrbSafe, Vec<u8>), Error> {
    let msg: KrbSafe = decode(raw)?;
    let body = safe_body_der(raw).ok_or_else(|| Error::Asn1("KRB-SAFE-BODY".into()))?;
    Ok((msg, body))
}

fn safe_body_der(raw: &[u8]) -> Option<Vec<u8>> {
    let (_, app) = der_take(raw)?;
    let (_, seq) = der_take(app)?;
    let mut rest = seq;
    while !rest.is_empty() {
        let (tag, inner, next) = der_take_rest(rest)?;
        if tag & 0x1f == 2 {
            return Some(inner.to_vec());
        }
        rest = next;
    }
    None
}

fn encode_safe_with_body(
    pvno: i32,
    msg_type: i32,
    body: &[u8],
    cksum: &Checksum,
) -> Result<Vec<u8>, Error> {
    let cksum_der = encode(cksum)?;
    let mut seq = Vec::new();
    seq.extend(ctx_explicit(0, &der_i32(pvno)));
    seq.extend(ctx_explicit(1, &der_i32(msg_type)));
    seq.extend(ctx_explicit(2, body));
    seq.extend(ctx_explicit(3, &cksum_der));
    Ok(tlv(0x74, &tlv(0x30, &seq)))
}

fn ctx_explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, inner)
}

fn der_i32(v: i32) -> Vec<u8> {
    let mut b = v.to_be_bytes().to_vec();
    while b.len() > 1 && ((b[0] == 0 && b[1] < 0x80) || (b[0] == 0xff && b[1] >= 0x80)) {
        b.remove(0);
    }
    tlv(0x02, &b)
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(tag);
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_len(n: usize) -> Vec<u8> {
    if let Ok(b) = u8::try_from(n)
        && b < 0x80
    {
        return vec![b];
    }
    let b = n.to_be_bytes();
    let start = b.iter().position(|x| *x != 0).unwrap_or(b.len() - 1);
    let raw = &b[start..];
    let nlen = u8::try_from(raw.len()).unwrap_or(8);
    let mut out = vec![0x80 | nlen];
    out.extend_from_slice(raw);
    out
}

fn der_take(input: &[u8]) -> Option<(u8, &[u8])> {
    let (tag, inner, _) = der_take_rest(input)?;
    Some((tag, inner))
}

fn der_take_rest(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let (ln, hdr) = der_len_at(input, 1)?;
    let start = 1 + hdr;
    let end = start.checked_add(ln)?;
    Some((tag, input.get(start..end)?, input.get(end..)?))
}

fn der_len_at(data: &[u8], off: usize) -> Option<(usize, usize)> {
    let b = *data.get(off)?;
    if b < 0x80 {
        return Some((b as usize, 1));
    }
    let nbytes = (b & 0x7f) as usize;
    if nbytes == 0 || nbytes > 4 || off + 1 + nbytes > data.len() {
        return None;
    }
    let mut n = 0usize;
    for i in 0..nbytes {
        n = (n << 8) | usize::from(*data.get(off + 1 + i)?);
    }
    Some((n, 1 + nbytes))
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

    #[test]
    fn safe_unkeyed_cksumtype_is_inapp() {
        let key = session();
        let mut msg = build_krb_safe(&key, b"body").unwrap();
        msg.cksum.cksumtype = 7;
        match verify_krb_safe_checksum(&key, &encode(&msg).unwrap(), None, None) {
            Err(Error::KrbError { code, .. }) => assert_eq!(code, err::INAPP_CKSUM),
            other => panic!("unkeyed SAFE must be 50, got {other:?}"),
        }
    }

    #[test]
    fn safe_unknown_cksumtype_is_sumtype_nosupp() {
        let key = session();
        let mut msg = build_krb_safe(&key, b"body").unwrap();
        msg.cksum.cksumtype = 1;
        match verify_krb_safe_checksum(&key, &encode(&msg).unwrap(), None, None) {
            Err(Error::KrbError { code, .. }) => assert_eq!(code, err::SUMTYPE_NOSUPP),
            other => panic!("unknown SAFE type must be 15, got {other:?}"),
        }
    }

    #[test]
    fn safe_bad_mac_is_modified() {
        let key = session();
        let mut msg = build_krb_safe(&key, b"body").unwrap();
        let mut mac = msg.cksum.checksum.to_vec();
        mac[0] ^= 0xff;
        msg.cksum.checksum = mac.into();
        match verify_krb_safe_checksum(&key, &encode(&msg).unwrap(), None, None) {
            Err(Error::KrbError { code, .. }) => assert_eq!(code, err::MODIFIED),
            other => panic!("bad SAFE MAC must be 41, got {other:?}"),
        }
    }

    #[test]
    fn safe_dummy_with_saved_body_matches_rasn_zero_cksum() {
        let key = session();
        let msg = build_krb_safe(&key, b"dummy-eq").unwrap();
        let raw = encode(&msg).unwrap();
        let (decoded, body) = decode_safe_with_body(&raw).unwrap();
        let mut rasn_dummy = decoded.clone();
        rasn_dummy.cksum = zero_safe_cksum();
        let rasn_der = encode(&rasn_dummy).unwrap();
        let swb = encode_safe_with_body(decoded.pvno, decoded.msg_type, &body, &zero_safe_cksum())
            .unwrap();
        assert_eq!(rasn_der, swb);
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> HostAddress {
        HostAddress {
            addr_type: 2,
            address: OctetString::from(vec![a, b, c, d]),
        }
    }

    fn code_of(e: Error) -> i32 {
        match e {
            Error::KrbError { code, .. } => code,
            other => panic!("expected KrbError, got {other:?}"),
        }
    }

    #[test]
    fn reject_non_safe_application_tag_is_msg_type_40() {
        let key = session();
        let raw = encode(&build_krb_safe(&key, b"tag").unwrap()).unwrap();
        for tag in [0x6e_u8, 0x75] {
            let mut bad = raw.clone();
            bad[0] = tag;
            assert_eq!(
                code_of(verify_krb_safe_checksum(&key, &bad, None, None).unwrap_err()),
                err::MSG_TYPE
            );
        }
    }

    #[test]
    fn check_privsafe_addrs_sender_mismatch_is_badaddr() {
        let local = v4(127, 0, 0, 1);
        let other = v4(10, 0, 0, 1);
        check_privsafe_addrs(&local, None, Some(&local), None).unwrap();
        assert_eq!(
            code_of(check_privsafe_addrs(&local, None, Some(&other), None).unwrap_err()),
            err::BADADDR
        );
    }

    #[test]
    fn check_privsafe_addrs_receiver_mismatch_is_badaddr() {
        let local = v4(127, 0, 0, 1);
        let other = v4(10, 0, 0, 1);
        check_privsafe_addrs(&local, Some(&local), None, Some(&local)).unwrap();
        assert_eq!(
            code_of(check_privsafe_addrs(&local, Some(&local), None, Some(&other)).unwrap_err()),
            err::BADADDR
        );
    }

    #[test]
    fn accept_seq_number_at_least_2_31() {
        let key = session();
        let msg = build_krb_safe_ex(&key, b"high-seq", Some(1 << 31), true).unwrap();
        let raw = encode(&msg).unwrap();
        let cache = ReplayCache::new();
        assert_eq!(unwrap_krb_safe(&key, &raw, &cache).unwrap(), b"high-seq");
    }
}
