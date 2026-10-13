//! KRB-SAFE, KRB-PRIV, and KRB-CRED (RFC 4120 §5.6–5.8).
//!
//! Outgoing SAFE and PRIV sequence numbers come from two process-global
//! counters that start at 1, wrap, and skip 0. The `unwrap_*` functions
//! accept a received message only after its checksum or decryption
//! succeeds, a timestamp it carries is within 300 seconds, and the replay
//! cache has not seen it. A received sequence number must be present when
//! the caller requires one. It is not compared with an expected remote
//! sequence, which MIT `k5_privsafe_check_seqnum` does.

use std::sync::atomic::{AtomicU32, Ordering};

use zeroize::{Zeroize, Zeroizing};

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    CipherState, KeyUsage, ProtocolKey, checksum, cksumtype_is_coll_proof, cksumtype_is_keyed,
    cksumtype_is_known, decrypt_enc_data, decrypt_enc_data_with_state, encrypt, encrypt_with_state,
    verify_checksum_type,
};
use krb5_types::{
    Checksum, EncKrbCredPart, EncKrbPrivPart, EncryptedData, HostAddress, KerberosTime, KrbCred,
    KrbCredInfo, KrbPriv, KrbSafe, KrbSafeBody, Microseconds, OctetString, Ticket, err, ku,
};

use crate::ap_req::address_in_list;
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
/// [`Error::Asn1`] when the KRB-SAFE body does not encode, and [`Error::Crypto`] when the
/// checksum under `session` cannot be computed.
pub fn build_krb_safe(session: &ProtocolKey, user_data: &[u8]) -> Result<KrbSafe, Error> {
    build_krb_safe_ex(session, user_data, Some(take_seq(&NEXT_SAFE_SEQ)), true)
}

/// Build a KRB-SAFE with explicit sequence and optional timestamp.
///
/// MIT `kprop` sets `KRB5_AUTH_CONTEXT_DO_SEQUENCE` only (no `DO_TIME`).
///
/// # Errors
///
/// [`Error::Asn1`] when the KRB-SAFE body does not encode, and [`Error::Crypto`] when the
/// checksum under `session` cannot be computed.
pub fn build_krb_safe_ex(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
    include_time: bool,
) -> Result<KrbSafe, Error> {
    // MIT `k5_privsafe_gen_rdata` (`lib/krb5/krb/privsafe.c:53-55`): the timestamp and its microseconds come from one `krb5_us_timeofday` reading.
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
        s_address: local_addr(),
        r_address: None,
    };
    let body_der = encode(&body)?;
    let usage = KeyUsage::new(ku::KRB_SAFE_CKSUM)?;
    // MIT `create_krbsafe` (`mk_safe.c:68-80`): checksums the full KRB-SAFE with a zero checksum
    // spliced in — the verifier's primary branch (`rd_safe.c`); body-only was accepted only via
    // the RFC 1510 fallback.
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

/// Verify a KRB-SAFE and return the user data.
///
/// # Errors
///
/// [`Error::KrbError`] `MSG_TYPE` when `raw` is not a KRB-SAFE, `INAPP_CKSUM` for an unsuitable
/// checksum type, and `MODIFIED` when the checksum does not verify; [`Error::ProgSumtypeNosupp`]
/// for an unknown checksum type;
/// [`Error::Asn1`] when `raw` does not decode; [`Error::ReplyMismatch`] when the timestamp or a
/// non-zero sequence number is missing, the timestamp is more than 300 seconds from now, or
/// `replay` has seen the message.
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
/// [`Error::KrbError`] `MSG_TYPE` when `raw` is not a KRB-SAFE, `INAPP_CKSUM` for an unsuitable
/// checksum type, and `MODIFIED` when the checksum does not verify; [`Error::ProgSumtypeNosupp`]
/// for an unknown checksum type;
/// [`Error::Asn1`] when `raw` does not decode; [`Error::ReplyMismatch`] when a required timestamp
/// or sequence number is missing (zero counts as missing when both are required), the timestamp
/// is more than 300 seconds from now, or `replay` has seen the message.
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

/// MIT `read_krbsafe` (`rd_safe.c:43-125`): APPLICATION 20, saved body DER, addrs, dummy, body
/// fallback.
///
/// # Errors
///
/// [`Error::KrbError`] `MSG_TYPE` (40) when `raw` is not a KRB-SAFE, `INAPP_CKSUM` (50) for a
/// checksum type that is not keyed and collision-proof, `BADADDR` (38) when `remote` or `local`
/// does not match, and `MODIFIED` (41) when the checksum verifies over neither the message nor
/// the body; [`Error::ProgSumtypeNosupp`] for a checksum type the library does not implement;
/// [`Error::Asn1`] when `raw` does not decode.
pub fn verify_krb_safe_checksum(
    session: &ProtocolKey,
    raw: &[u8],
    remote: Option<&HostAddress>,
    local: Option<&HostAddress>,
) -> Result<KrbSafe, Error> {
    verify_krb_safe_checksum_in(session, raw, remote, local, None)
}

/// [`verify_krb_safe_checksum`] with the host addresses a receiver address is looked up in when
/// `local` is `None`: `hosts`, else the machine's own ([`crate::os_localaddr`]).
///
/// # Errors
///
/// As [`verify_krb_safe_checksum`], and the error of [`crate::os_localaddr`].
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
    // MIT `safe_msg_type` (`lib/krb5/asn.1/asn1_k_encode.c:816-816`): the msg-type decodes as the message's own.
    let (msg, body_der) = decode_safe_with_body(raw)?;
    let ctype = msg.cksum.cksumtype;
    // MIT `read_krbsafe` (`lib/krb5/krb/rd_safe.c:66-69`): a checksum type `krb5_c_valid_cksumtype` does not know is KRB5_PROG_SUMTYPE_NOSUPP, a library code, not KDC_ERR_SUMTYPE_NOSUPP.
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

/// MIT `k5_privsafe_check_addrs` (`privsafe.c:312-382`): the sender address must match the
/// remote address when one is set; a receiver address, when present, must match the local
/// address, or one of the host's addresses when no local address is set.
///
/// # Errors
///
/// [`Error::KrbError`] 38 when a supplied comparison address does not match; the error of
/// [`crate::os_localaddr`] when the host's addresses are wanted and cannot be read.
pub fn check_privsafe_addrs(
    msg_s: &HostAddress,
    msg_r: Option<&HostAddress>,
    remote: Option<&HostAddress>,
    local: Option<&HostAddress>,
) -> Result<(), Error> {
    check_privsafe_addrs_in(msg_s, msg_r, remote, local, None)
}

/// [`check_privsafe_addrs`] with the host addresses to search when `local` is `None`: `hosts`,
/// else the machine's own, read only when a receiver address is there to look up.
/// MIT `k5_privsafe_check_addrs` (`privsafe.c:348-378`): the sender against the remote address; a receiver address is optional and, with no local address, must be one of `krb5_os_localaddr`'s (`krb5_address_search`, so an empty list holds none and a list of one NetBIOS address holds any).
///
/// # Errors
///
/// As [`check_privsafe_addrs`].
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

/// MIT `k5_memrcache_store` (`memrcache.c:136-139`): a tag already stored is a replay and is not
/// accepted again. A timestamp more than 300 seconds from now is not fresh, and a required
/// sequence of zero is not a sequence.
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
/// [`Error::Asn1`] when the EncKrbPrivPart does not encode, and [`Error::Crypto`] when encrypting
/// it under `session` fails.
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
/// [`Error::Asn1`] when the EncKrbPrivPart does not encode, and [`Error::Crypto`] when encrypting
/// it under `session` fails.
pub fn build_krb_priv_with_seq(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
) -> Result<KrbPriv, Error> {
    let mut state = CipherState::initial();
    build_krb_priv_chained(session, user_data, seq_number, true, &mut state)
}

/// Build a KRB-PRIV that names `sender` as its sender address and carries no timestamp.
///
/// MIT `create_krbpriv` (`lib/krb5/krb/mk_priv.c:60-61`): the message's sender is the auth context's local address, and its receiver the remote address, which kpasswd does not set.
/// MIT `k5_privsafe_gen_rdata` (`lib/krb5/krb/privsafe.c:52-60`): a timestamp only under `DO_TIME`, which `krb5int_mk_chpw_req` does not set.
///
/// # Errors
///
/// [`Error::Asn1`] when the EncKrbPrivPart does not encode, and [`Error::Crypto`] when encrypting
/// it under `session` fails.
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

/// Build a KRB-PRIV with cipher-state chaining (MIT `auth_con_initivector`).
///
/// # Errors
///
/// [`Error::Asn1`] when the EncKrbPrivPart does not encode, and [`Error::Crypto`] when encrypting
/// it under `session` and `state` fails.
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

fn krb_priv_part(
    session: &ProtocolKey,
    user_data: &[u8],
    seq_number: Option<u32>,
    include_time: bool,
    state: &mut CipherState,
    s_address: HostAddress,
) -> Result<KrbPriv, Error> {
    // MIT `k5_privsafe_gen_rdata` (`lib/krb5/krb/privsafe.c:53-55`): the timestamp and its microseconds come from one `krb5_us_timeofday` reading.
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

/// Wipes an octet string's bytes when it holds the only reference to them, as a copy of a secret
/// made only to be encoded does.
pub(crate) fn wipe_octets(octets: OctetString) {
    if let Ok(buf) = bytes::Bytes::from(octets).try_into_mut() {
        wipe_vec(Vec::<u8>::from(buf));
    }
}

/// Zeroizes every byte of `buf`'s allocation, then frees it: a plaintext that was encoded only
/// to be encrypted. A test build keeps each wiped allocation ([`wiped::take`]) instead of freeing
/// it, so a test can see the buffer zeroed, whole.
pub(crate) fn wipe_vec(mut buf: Vec<u8>) {
    buf.resize(buf.capacity(), 0);
    buf.as_mut_slice().zeroize();
    #[cfg(test)]
    let _ = wiped::WIPED.try_with(|w| w.borrow_mut().push(buf));
}

/// The allocations this crate's wipes zeroed on the current thread, kept for the tests.
#[cfg(test)]
pub(crate) mod wiped {
    use std::cell::RefCell;

    thread_local! {
        /// What [`super::wipe_vec`] zeroed on this thread, kept alive.
        pub(super) static WIPED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    /// The allocations wiped on this thread since the last call.
    pub(crate) fn take() -> Vec<Vec<u8>> {
        WIPED.with(|w| std::mem::take(&mut *w.borrow_mut()))
    }
}

/// Decrypt a KRB-PRIV and return the user data.
///
/// Requires a non-zero sequence number (RFC 4120 application traffic).
///
/// # Errors
///
/// [`Error::Asn1`] when `raw` or its decrypted part does not decode, [`Error::Crypto`] when the
/// enc-part does not decrypt under `session`, and [`Error::ReplyMismatch`] when the timestamp or
/// a non-zero sequence number is missing, the timestamp is more than 300 seconds from now, or
/// `replay` has seen the message.
pub fn unwrap_krb_priv(
    session: &ProtocolKey,
    raw: &[u8],
    replay: &ReplayCache,
) -> Result<Vec<u8>, Error> {
    unwrap_krb_priv_ex(session, raw, replay, true, true)
}

/// The decrypted part of a KRB-PRIV under `key`, for a caller that checks its sequence number.
/// MIT `read_krbpriv` (`lib/krb5/krb/rd_priv.c:43-97`): a message that is not a KRB-PRIV is `KRB5KRB_AP_ERR_MSG_TYPE`; the decrypted part is zeroed before it is freed.
///
/// # Errors
///
/// [`Error::KrbError`] `MSG_TYPE` (40) for another message type; [`Error::Asn1`] when the message
/// or its part does not decode; [`Error::Crypto`] when it does not decrypt under `key`.
pub fn read_krb_priv(key: &ProtocolKey, raw: &[u8]) -> Result<EncKrbPrivPart, Error> {
    // MIT `krb5_is_krb_priv`: [APPLICATION 21], constructed or not.
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

/// Decrypt a KRB-PRIV.
///
/// MIT `kpasswd` (`krb5int_mk_chpw_req`) sets `DO_SEQUENCE` only, clearing
/// `DO_TIME`, so the request KRB-PRIV often has seq 0 and no timestamp.
/// Pass `require_seq`/`require_time` false on that path.
///
/// # Errors
///
/// [`Error::Asn1`] when `raw` or its decrypted part does not decode, [`Error::Crypto`] when the
/// enc-part does not decrypt under `session`, and [`Error::ReplyMismatch`] when a required
/// timestamp or sequence number is missing (zero counts as missing when both are required), the
/// timestamp is more than 300 seconds from now, or `replay` has seen the message.
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
/// [`Error::Asn1`] when `raw` or its decrypted part does not decode, [`Error::Crypto`] when the
/// enc-part does not decrypt under `session` and `state`, and [`Error::ReplyMismatch`] when a
/// required timestamp or sequence number is missing (zero counts as missing when both are
/// required), the timestamp is more than 300 seconds from now, or `replay` has seen the message.
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
/// [`Error::Asn1`] when the EncKrbCredPart does not encode, and [`Error::Crypto`] when encrypting
/// it under `session` fails.
pub fn build_krb_cred(
    session: &ProtocolKey,
    tickets: Vec<Ticket>,
    ticket_info: Vec<KrbCredInfo>,
) -> Result<KrbCred, Error> {
    // MIT `krb5_mk_ncred` (`lib/krb5/krb/mk_cred.c:177-178`): a missing timestamp is filled from one `krb5_us_timeofday` reading.
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

/// Decrypt a KRB-CRED.
///
/// # Errors
///
/// [`Error::Asn1`] when `raw` or its decrypted part does not decode, [`Error::Crypto`] when the
/// enc-part does not decrypt under `session`, and [`Error::ReplyMismatch`] when the timestamp is
/// missing or more than 300 seconds from now, or `replay` has seen the message.
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
    fn safe_unknown_cksumtype_is_prog_sumtype_nosupp() {
        // MIT `read_krbsafe` (`lib/krb5/krb/rd_safe.c:66-69`): KRB5_PROG_SUMTYPE_NOSUPP, settled live for types 1 3 4 5 6 8 10 13 127.
        let key = session();
        for ctype in [1, 3, 4, 5, 6, 8, 10, 13, 127] {
            let mut msg = build_krb_safe(&key, b"body").unwrap();
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

    fn host(last: u8) -> HostAddress {
        HostAddress {
            addr_type: 2,
            address: OctetString::from(vec![192, 0, 2, last]),
        }
    }

    /// A KRB-SAFE of `p` from 127.0.0.1 to `r`, checksummed as MIT's `create_krbsafe` does.
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

    /// MIT `k5_privsafe_check_addrs` (`privsafe.c:355-378`): with no local address a receiver
    /// address must be one of the host's, and an empty list holds none.
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
        // A list of one NetBIOS address holds any address (`krb5_address_search`).
        let netbios = [HostAddress {
            addr_type: HostAddress::ADDRTYPE_NETBIOS,
            address: OctetString::from(vec![0; 16]),
        }];
        check_privsafe_addrs_in(&s, Some(&host(8)), None, None, Some(&netbios)).unwrap();
        // A local address, when set, is the only one compared; the hosts are not read.
        check_privsafe_addrs_in(&s, Some(&host(8)), None, Some(&host(8)), Some(&[])).unwrap();
        // The sender is compared with the remote address first.
        let e = check_privsafe_addrs_in(&s, Some(&host(7)), Some(&host(2)), None, Some(&list))
            .unwrap_err();
        assert!(matches!(e, Error::KrbError { code: 38, .. }), "{e:?}");
    }

    /// MIT `read_krbsafe` (`lib/krb5/krb/rd_safe.c:75-78`): a KRB-SAFE goes through the same address check.
    #[test]
    fn verify_krb_safe_checksum_in_looks_the_receiver_up_among_the_hosts() {
        let key = session();
        let hosts = [host(7)];
        let ok = safe_to(&key, Some(host(7)));
        verify_krb_safe_checksum_in(&key, &ok, None, None, Some(&hosts)).unwrap();
        let no = safe_to(&key, Some(host(9)));
        let e = verify_krb_safe_checksum_in(&key, &no, None, None, Some(&hosts)).unwrap_err();
        assert!(matches!(e, Error::KrbError { code: 38, .. }), "{e:?}");
        // The local address, when there is one, replaces the host list.
        verify_krb_safe_checksum_in(&key, &no, None, Some(&host(9)), Some(&hosts)).unwrap();
        // No receiver address: nothing to look up.
        let none = safe_to(&key, None);
        verify_krb_safe_checksum_in(&key, &none, None, None, Some(&[])).unwrap();
    }
}
