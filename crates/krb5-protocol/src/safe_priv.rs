//! Accepted only after checksum or decryption, 300 s window, new replay tag.
//! Unlike MIT: sequence not checked against the remote one.

use zeroize::{Zeroize, Zeroizing};

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    CipherState, EncryptionType, KeyUsage, ProtocolKey, checksum, cksumtype_is_coll_proof,
    cksumtype_is_keyed, cksumtype_is_known, decrypt_enc_data, decrypt_enc_data_with_state, encrypt,
    encrypt_with_state, verify_checksum_type,
};
use krb5_types::{
    Checksum, EncKrbCredPart, EncKrbPrivPart, EncryptedData, HostAddress, KerberosTime, KrbCred,
    KrbCredInfo, KrbPriv, KrbSafe, KrbSafeBody, OctetString, Ticket, err, ku,
};

use crate::ap_req::address_in_list;
use crate::error::Error;
use crate::replay::{ReplayCache, ReplayKey};

fn local_addr() -> HostAddress {
    HostAddress {
        addr_type: 2,
        address: OctetString::from(vec![127, 0, 0, 1]),
    }
}

pub fn build_krb_safe_ex(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
    include_time: bool,
) -> Result<KrbSafe, Error> {
    build_krb_safe_from(session, user_data, seq_number, include_time, &local_addr())
}

// MIT: `create_krbsafe` (lib/krb5/krb/mk_safe.c:62-63)
pub fn build_krb_safe_from(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
    include_time: bool,
    s_address: &HostAddress,
) -> Result<KrbSafe, Error> {
    // MIT: `k5_privsafe_gen_rdata` (lib/krb5/krb/privsafe.c:53-55)
    let (timestamp, usec) = if include_time {
        let (now, usec) = crate::us_timeofday();
        (Some(now), Some(usec))
    } else {
        (None, None)
    };
    let body = KrbSafeBody {
        user_data: user_data.to_vec().into(),
        timestamp,
        usec,
        seq_number,
        s_address: s_address.clone(),
        r_address: None,
    };
    let body_der = encode(&body)?;
    let usage = KeyUsage::new(ku::KRB_SAFE_CKSUM)?;
    // Checksum covers the whole KRB-SAFE, zero checksum spliced in.
    // Body-only checksum: the RFC 1510 fallback.
    let dummy = encode_safe_with_body(
        KrbSafe::PVNO,
        KrbSafe::MSG_TYPE,
        &body_der,
        &zero_safe_cksum(),
    )?;
    let mic = checksum(session, usage, &dummy)?;
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

pub fn unwrap_krb_safe(
    session: &ProtocolKey,
    raw: &[u8],
    replay: &ReplayCache,
) -> Result<Vec<u8>, Error> {
    unwrap_krb_safe_ex(session, raw, replay, true, true)
}

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
        msg.safe_body.seq_number,
        fresh_policy(require_seq, require_time),
        ReplayKey::tag(msg.cksum.checksum.as_ref()),
    )?;
    Ok(msg.safe_body.user_data.to_vec())
}

#[derive(Clone, Copy)]
enum FreshPolicy {
    SeqAndTime,
    TimeOnly,
    /// Kpasswd: sequence 0, no timestamp; cache is the replay check.
    HashOnly,
    SeqOnly,
}

// MIT: `read_krbsafe` (rd_safe.c:43-125)
pub fn verify_krb_safe_checksum(
    session: &ProtocolKey,
    raw: &[u8],
    remote: Option<&HostAddress>,
    local: Option<&HostAddress>,
) -> Result<KrbSafe, Error> {
    verify_krb_safe_checksum_in(session, raw, remote, local, None)
}

pub fn verify_krb_safe_checksum_in(
    session: &ProtocolKey,
    raw: &[u8],
    remote: Option<&HostAddress>,
    local: Option<&HostAddress>,
    hosts: Option<&[HostAddress]>,
) -> Result<KrbSafe, Error> {
    if !is_krb_safe(raw) {
        return Err(Error::KrbError {
            code: err::MSG_TYPE,
            text: Some("Invalid message type".into()),
        });
    }
    // MIT: `safe_msg_type` (lib/krb5/asn.1/asn1_k_encode.c:816-816)
    let (msg, body_der) = decode_safe_with_body(raw)?;
    let ctype = msg.cksum.cksumtype;
    // MIT: `read_krbsafe` (lib/krb5/krb/rd_safe.c:66-69)
    // Unknown checksum type: KRB5_PROG_SUMTYPE_NOSUPP, not the KDC error.
    if !cksumtype_is_known(ctype) {
        return Err(Error::ProgSumtypeNosupp);
    }
    if !cksumtype_is_coll_proof(ctype) || !cksumtype_is_keyed(ctype) {
        return Err(Error::KrbError {
            code: err::INAPP_CKSUM,
            text: Some("inapp checksum".into()),
        });
    }
    check_privsafe_addrs_in(
        &msg.safe_body.s_address,
        msg.safe_body.r_address.as_ref(),
        remote,
        local,
        hosts,
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

// MIT: `k5_privsafe_check_addrs` (privsafe.c:312-382)
/// Sender must match a set remote address.
/// Receiver must match local, or host address if local unset.
pub fn check_privsafe_addrs(
    msg_s: &HostAddress,
    msg_r: Option<&HostAddress>,
    remote: Option<&HostAddress>,
    local: Option<&HostAddress>,
) -> Result<(), Error> {
    check_privsafe_addrs_in(msg_s, msg_r, remote, local, None)
}

pub fn check_privsafe_addrs_in(
    msg_s: &HostAddress,
    msg_r: Option<&HostAddress>,
    remote: Option<&HostAddress>,
    local: Option<&HostAddress>,
    hosts: Option<&[HostAddress]>,
) -> Result<(), Error> {
    let badaddr = || Error::KrbError {
        code: err::BADADDR,
        text: Some("Incorrect net address".into()),
    };
    if let Some(want) = remote
        && want != msg_s
    {
        return Err(badaddr());
    }
    let Some(got_r) = msg_r else {
        return Ok(());
    };
    if let Some(want) = local {
        return if want == got_r {
            Ok(())
        } else {
            Err(badaddr())
        };
    }
    let found = match hosts {
        Some(list) => address_in_list(got_r, list),
        None => address_in_list(got_r, &crate::localaddr::os_localaddr()?),
    };
    if found { Ok(()) } else { Err(badaddr()) }
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
    let mut out = Vec::with_capacity(1 + krb5_types::der::len_len(content.len()) + content.len());
    krb5_types::der::push_tlv(&mut out, tag, content);
    out
}

fn der_take(input: &[u8]) -> Option<(u8, &[u8])> {
    let (tag, inner, _) = der_take_rest(input)?;
    Some((tag, inner))
}

fn der_take_rest(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let (ln, hdr) = krb5_types::der::read_len(input.get(1..)?)?;
    let start = 1 + hdr;
    let end = start.checked_add(ln)?;
    Some((tag, input.get(start..end)?, input.get(end..)?))
}

fn enc_tag(enc: &EncryptedData) -> Result<ReplayKey, Error> {
    EncryptionType::known(enc.etype)
        .ok()
        .and_then(|et| ReplayKey::from_ciphertext(et, enc.cipher.as_ref()))
        .ok_or_else(|| Error::Crypto("ciphertext shorter than its checksum".into()))
}

fn fresh_policy(require_seq: bool, require_time: bool) -> FreshPolicy {
    match (require_seq, require_time) {
        (true, true) => FreshPolicy::SeqAndTime,
        (true, false) => FreshPolicy::SeqOnly,
        (false, true) => FreshPolicy::TimeOnly,
        (false, false) => FreshPolicy::HashOnly,
    }
}

// MIT: `k5_memrcache_store` (memrcache.c:136-139)
/// Stored tag is a replay; SeqAndTime rejects sequence 0.
fn accept_fresh(
    replay: &ReplayCache,
    kind: &str,
    ts: Option<&KerberosTime>,
    seq: Option<u32>,
    policy: FreshPolicy,
    key: ReplayKey,
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
    if replay.check_and_store(key, 300) {
        return Err(Error::ReplyMismatch(format!("{kind} replay")));
    }
    Ok(())
}

pub fn build_krb_priv_with_seq(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
) -> Result<KrbPriv, Error> {
    let mut state = CipherState::initial();
    build_krb_priv_chained(session, user_data, seq_number, true, &mut state)
}

// MIT: `create_krbpriv` (lib/krb5/krb/mk_priv.c:60-61)
/// Receiver unset, as kpasswd leaves it.
pub fn build_krb_priv_from(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
    sender: &HostAddress,
) -> Result<KrbPriv, Error> {
    let mut state = CipherState::initial();
    krb_priv_part(
        session,
        user_data,
        seq_number,
        false,
        &mut state,
        sender.clone(),
    )
}

// MIT: `krb5_auth_con_initivector` (lib/krb5/krb/auth_con.c:315)
pub fn build_krb_priv_chained(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
    include_time: bool,
    state: &mut CipherState,
) -> Result<KrbPriv, Error> {
    krb_priv_part(
        session,
        user_data,
        seq_number,
        include_time,
        state,
        local_addr(),
    )
}

pub fn build_krb_priv_chained_from(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
    include_time: bool,
    s_address: &HostAddress,
    state: &mut CipherState,
) -> Result<KrbPriv, Error> {
    krb_priv_part(
        session,
        user_data,
        seq_number,
        include_time,
        state,
        s_address.clone(),
    )
}

fn krb_priv_part(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
    include_time: bool,
    state: &mut CipherState,
    s_address: HostAddress,
) -> Result<KrbPriv, Error> {
    let (timestamp, usec) = if include_time {
        let (now, usec) = crate::us_timeofday();
        (Some(now), Some(usec))
    } else {
        (None, None)
    };
    let part = EncKrbPrivPart {
        user_data: user_data.to_vec().into(),
        timestamp,
        usec,
        seq_number,
        s_address,
        r_address: None,
    };
    let der = encode(&part);
    wipe_octets(part.user_data);
    let der = Zeroizing::new(der?);
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

/// Wipes only when this string is the sole owner.
pub(crate) fn wipe_octets(octets: OctetString) {
    if let Ok(buf) = bytes::Bytes::from(octets).try_into_mut() {
        wipe_vec(Vec::<u8>::from(buf));
    }
}

pub(crate) fn wipe_vec(mut buf: Vec<u8>) {
    buf.resize(buf.capacity(), 0);
    buf.as_mut_slice().zeroize();
    #[cfg(test)]
    let _ = wiped::WIPED.try_with(|w| w.borrow_mut().push(buf));
}

#[cfg(test)]
pub(crate) mod wiped {
    use std::cell::RefCell;

    thread_local! {
        /// What [`super::wipe_vec`] zeroed on this thread, kept alive.
        pub(super) static WIPED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }
}

pub fn unwrap_krb_priv(
    session: &ProtocolKey,
    raw: &[u8],
    replay: &ReplayCache,
) -> Result<Vec<u8>, Error> {
    unwrap_krb_priv_ex(session, raw, replay, true, true)
}

// MIT: `read_krbpriv` (lib/krb5/krb/rd_priv.c:43-97)
pub fn read_krb_priv(key: &ProtocolKey, raw: &[u8]) -> Result<EncKrbPrivPart, Error> {
    if raw.first().is_none_or(|b| b & !0x20 != 0x55) {
        return Err(Error::KrbError {
            code: err::MSG_TYPE,
            text: Some("Invalid message type".into()),
        });
    }
    let msg: KrbPriv = decode(raw)?;
    let usage = KeyUsage::new(ku::KRB_PRIV_ENC_PART)?;
    let plain = decrypt_enc_data(key, usage, msg.enc_part.etype, msg.enc_part.cipher.as_ref())?;
    let part = decode::<EncKrbPrivPart>(&plain);
    wipe_vec(plain);
    Ok(part?)
}

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

// MIT: `krb5_auth_con_initivector` (lib/krb5/krb/auth_con.c:315)
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
    let plain = decrypt_enc_data_with_state(
        session,
        usage,
        state,
        msg.enc_part.etype,
        msg.enc_part.cipher.as_ref(),
    )?;
    let part: EncKrbPrivPart = decode(&plain)?;
    accept_fresh(
        replay,
        "PRIV",
        part.timestamp.as_ref(),
        part.seq_number,
        fresh_policy(require_seq, require_time),
        enc_tag(&msg.enc_part)?,
    )?;
    Ok(part.user_data.to_vec())
}

pub fn build_krb_cred(
    session: &ProtocolKey,
    tickets: Vec<Ticket>,
    ticket_info: Vec<KrbCredInfo>,
) -> Result<KrbCred, Error> {
    // MIT: `krb5_mk_ncred` (lib/krb5/krb/mk_cred.c:177-178)
    let (now, usec) = crate::us_timeofday();
    let part = EncKrbCredPart {
        ticket_info,
        nonce: None,
        timestamp: Some(now),
        usec: Some(usec),
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

pub fn unwrap_krb_cred(
    session: &ProtocolKey,
    raw: &[u8],
    replay: &ReplayCache,
) -> Result<(KrbCred, EncKrbCredPart), Error> {
    let msg: KrbCred = decode(raw)?;
    let usage = KeyUsage::new(ku::KRB_CRED_ENC_PART)?;
    let plain = decrypt_enc_data(
        session,
        usage,
        msg.enc_part.etype,
        msg.enc_part.cipher.as_ref(),
    )?;
    let part: EncKrbCredPart = decode(&plain)?;
    accept_fresh(
        replay,
        "CRED",
        part.timestamp.as_ref(),
        None,
        FreshPolicy::TimeOnly,
        enc_tag(&msg.enc_part)?,
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
    fn safe_second_unwrap_fails() {
        let key = session();
        let a = build_krb_safe_ex(&key, b"one", Some(1), true).unwrap();
        let raw = encode(&a).unwrap();
        let cache = ReplayCache::new();
        assert_eq!(unwrap_krb_safe(&key, &raw, &cache).unwrap(), b"one");
        assert!(unwrap_krb_safe(&key, &raw, &cache).is_err());
    }

    #[test]
    fn priv_second_unwrap_fails() {
        let key = session();
        let msg = build_krb_priv_with_seq(&key, b"secret", Some(1)).unwrap();
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
        let mut msg = build_krb_safe_ex(&key, b"body", Some(1), true).unwrap();
        msg.cksum.cksumtype = 7;
        match verify_krb_safe_checksum(&key, &encode(&msg).unwrap(), None, None) {
            Err(Error::KrbError { code, .. }) => assert_eq!(code, err::INAPP_CKSUM),
            other => panic!("unkeyed SAFE must be 50, got {other:?}"),
        }
    }

    #[test]
    fn safe_unknown_cksumtype_is_prog_sumtype_nosupp() {
        let key = session();
        for ctype in [1, 3, 4, 5, 6, 8, 10, 13, 127] {
            let mut msg = build_krb_safe_ex(&key, b"body", Some(1), true).unwrap();
            msg.cksum.cksumtype = ctype;
            match verify_krb_safe_checksum(&key, &encode(&msg).unwrap(), None, None) {
                Err(Error::ProgSumtypeNosupp) => {}
                other => panic!("checksum type {ctype}: want PROG_SUMTYPE_NOSUPP, got {other:?}"),
            }
        }
    }

    #[test]
    fn safe_bad_mac_is_modified() {
        let key = session();
        let mut msg = build_krb_safe_ex(&key, b"body", Some(1), true).unwrap();
        let mut mac = msg.cksum.checksum.to_vec();
        mac[0] ^= 0xff;
        msg.cksum.checksum = mac.into();
        match verify_krb_safe_checksum(&key, &encode(&msg).unwrap(), None, None) {
            Err(Error::KrbError { code, .. }) => assert_eq!(code, err::MODIFIED),
            other => panic!("bad SAFE MAC must be 41, got {other:?}"),
        }
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
        let raw = encode(&build_krb_safe_ex(&key, b"tag", Some(1), true).unwrap()).unwrap();
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

    fn host(last: u8) -> HostAddress {
        HostAddress {
            addr_type: 2,
            address: OctetString::from(vec![192, 0, 2, last]),
        }
    }

    fn safe_to(session: &ProtocolKey, r: Option<HostAddress>) -> Vec<u8> {
        let body = KrbSafeBody {
            user_data: b"p".to_vec().into(),
            timestamp: None,
            usec: None,
            seq_number: None,
            s_address: local_addr(),
            r_address: r,
        };
        let body_der = encode(&body).unwrap();
        let dummy = encode_safe_with_body(
            KrbSafe::PVNO,
            KrbSafe::MSG_TYPE,
            &body_der,
            &zero_safe_cksum(),
        )
        .unwrap();
        let usage = KeyUsage::new(ku::KRB_SAFE_CKSUM).unwrap();
        let mic = checksum(session, usage, &dummy).unwrap();
        encode(&KrbSafe {
            pvno: KrbSafe::PVNO,
            msg_type: KrbSafe::MSG_TYPE,
            safe_body: body,
            cksum: krb5_types::Checksum {
                cksumtype: session.etype().checksum_type(),
                checksum: mic.into(),
            },
        })
        .unwrap()
    }

    /// with no local address a receiver address must be one of the host's, and an empty list holds none.
    #[test]
    fn check_privsafe_addrs_no_local_wants_the_receiver_among_the_hosts() {
        let s = host(1);
        let list = [host(7), host(8)];
        check_privsafe_addrs_in(&s, Some(&host(8)), None, None, Some(&list)).unwrap();
        check_privsafe_addrs_in(&s, None, None, None, Some(&list)).unwrap();
        for hosts in [&list[..1], &[][..]] {
            let e =
                check_privsafe_addrs_in(&s, Some(&host(8)), None, None, Some(hosts)).unwrap_err();
            assert!(matches!(e, Error::KrbError { code: 38, .. }), "{e:?}");
        }
        let netbios = [HostAddress {
            addr_type: HostAddress::ADDRTYPE_NETBIOS,
            address: OctetString::from(vec![0; 16]),
        }];
        check_privsafe_addrs_in(&s, Some(&host(8)), None, None, Some(&netbios)).unwrap();
        check_privsafe_addrs_in(&s, Some(&host(8)), None, Some(&host(8)), Some(&[])).unwrap();
        let e = check_privsafe_addrs_in(&s, Some(&host(7)), Some(&host(2)), None, Some(&list))
            .unwrap_err();
        assert!(matches!(e, Error::KrbError { code: 38, .. }), "{e:?}");
    }

    #[test]
    fn verify_krb_safe_checksum_in_looks_the_receiver_up_among_the_hosts() {
        let key = session();
        let hosts = [host(7)];
        let ok = safe_to(&key, Some(host(7)));
        verify_krb_safe_checksum_in(&key, &ok, None, None, Some(&hosts)).unwrap();
        let no = safe_to(&key, Some(host(9)));
        let e = verify_krb_safe_checksum_in(&key, &no, None, None, Some(&hosts)).unwrap_err();
        assert!(matches!(e, Error::KrbError { code: 38, .. }), "{e:?}");
        verify_krb_safe_checksum_in(&key, &no, None, Some(&host(9)), Some(&hosts)).unwrap();
        let none = safe_to(&key, None);
        verify_krb_safe_checksum_in(&key, &none, None, None, Some(&[])).unwrap();
    }
}
