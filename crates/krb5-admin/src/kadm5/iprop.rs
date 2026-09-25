//! Incremental propagation (`kadmin/server/ipropd_svc.c`,
//! `lib/kdb/iprop_xdr.c`): the `IPROP_GET_UPDATES` / `IPROP_FULL_RESYNC`
//! server side, the `kdbe_t` codecs, and the `krb5-iprop-pull` client
//! (kpropd's RPCSEC_GSS calls). Keys leave the store only wrapped under
//! the iprop master key.

use std::net::TcpStream;

use krb5_crypto::{EncryptionType, ProtocolKey, kdb_decrypt_key};
use krb5_gss::GssContext;
use krb5_kdc::{
    Acl, KDB_DISALLOW_ALL_TIX, KDB_REQUIRES_PRE_AUTH, KDB_V1_BASE_LENGTH, KadmData, KeyEntry,
    OsaKeyData, OsaPrincEnt, Principal, SharedDump as SharedStore, TL_LAST_PWD_CHANGE,
    TL_MOD_PRINC, TL_STRING_ATTRS, TlData,
};
use krb5_types::{PrincipalName, Ticket};

use super::codes::{
    AT_ATTRFLAGS, AT_EXP, AT_FAIL_AUTH_COUNT, AT_KEYDATA, AT_LAST_FAILED, AT_LAST_SUCCESS, AT_LEN,
    AT_MAX_LIFE, AT_MAX_RENEW_LIFE, AT_MOD_PRINC, AT_MOD_TIME, AT_PRINC, AT_PW_EXP, AT_PW_HIST,
    AT_PW_HIST_KVNO, AT_PW_LAST_CHANGE, AT_PW_POLICY, AT_PW_POLICY_SWITCH, AT_TL_DATA, FLAVOR_GSS,
    FLAVOR_NONE, GSS_PRIVACY, IPROP_FULL_RESYNC, IPROP_FULL_RESYNC_EXT, IPROP_GET_UPDATES,
    IPROP_NULL, IPROP_PROG, IPROP_VERS, MSG_ACCEPTED, MSG_CALL, MSG_REPLY, RPC_VERSION,
    RPCSEC_GSS_VERS, RPG_DATA, RPG_INIT, SUCCESS,
};
use super::rpc::{read_record, rpc_call_bytes, write_record};
use super::xdr::{XdrR, XdrW};
use crate::Error;

/// MIT `iprop_get_updates_1_svc` (`ipropd_svc.c:191-200`): a caller who fails the iprop ACL gets permission denied and no entries.
/// The null procedure skips that check, and an incremental update that carries keys is refused when no master key exists rather than sending those keys in the clear.
pub(super) fn dispatch_iprop(
    store: &SharedStore,
    acl: &Acl,
    actor: &str,
    proc: u32,
    args: &[u8],
) -> Vec<u8> {
    if proc != IPROP_NULL
        && acl
            .check(actor, krb5_kdc::AdminOp::Propagate, None)
            .is_err()
    {
        return if proc == IPROP_FULL_RESYNC || proc == IPROP_FULL_RESYNC_EXT {
            encode_fullresync_status(0, krb5_kdc::IPROP_PERM_DENIED)
        } else {
            encode_incr_result(krb5_kdc::IPROP_PERM_DENIED, 0, &[], None)
        };
    }
    match proc {
        IPROP_NULL => Vec::new(),
        IPROP_GET_UPDATES => {
            let mut r = XdrR::new(args);
            let last_sno = r.u32().unwrap_or(0);
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (status, last, entries) = g.iprop_get(last_sno);
            let mkey = g.iprop_master_key();
            // MIT ships each key as the master-key ciphertext already stored in
            // the KDB (`kdb_convert.c` copies `key_data_contents`). The Rust
            // store holds plaintext keys, so it wraps them under the master key
            // at ship time; with no master key available it must refuse the
            // update rather than send keys in the clear. (`iprop_master_key`
            // falls back to the stash, `KRB5_MASTER_PASSWORD`, then the `K/M`
            // principal, so this is reached only when none of those exist.)
            if mkey.is_none()
                && entries
                    .iter()
                    .any(|e| e.princ.as_ref().is_some_and(|p| !p.keys.is_empty()))
            {
                return encode_incr_result(krb5_kdc::IPROP_ERROR, 0, &[], None);
            }
            encode_incr_result(status, last, &entries, mkey.as_ref())
        }
        IPROP_FULL_RESYNC | IPROP_FULL_RESYNC_EXT => {
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            encode_fullresync(g.serial())
        }
        _ => encode_incr_result(krb5_kdc::IPROP_FULL_RESYNC, 0, &[], None),
    }
}

fn encode_kdb_last(w: &mut XdrW, sno: u32) {
    w.u32(sno);
    w.u32(
        u32::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
        .unwrap_or(0),
    );
    w.u32(0);
}

fn encode_utf8str(w: &mut XdrW, s: &str) {
    w.opaque(s.as_bytes());
}

fn encode_keydata(
    w: &mut XdrW,
    keys: &[KeyEntry],
    mkey: Option<&krb5_crypto::ProtocolKey>,
    fallback_salt: &[u8],
) {
    w.u32(u32::try_from(keys.len()).unwrap_or(0));
    for k in keys {
        let salt = k.kdb_salt.clone().unwrap_or_else(|| fallback_salt.to_vec());
        let salt_ty = k.salt_type.unwrap_or(0);
        w.u32(2);
        w.u32(k.kvno);
        w.u32(2);
        w.u32(u32::try_from(k.etype.to_iana()).unwrap_or(0));
        w.u32(u32::try_from(salt_ty).unwrap_or(0));
        w.u32(2);
        let enc = mkey
            .and_then(|m| krb5_crypto::kdb_encrypt_key(m, k.key.as_bytes()).ok())
            .unwrap_or_else(|| k.key.as_bytes().to_vec());
        w.opaque(&enc);
        w.opaque(&salt);
    }
}

/// `kdbe_key_t` of stored key data (history entries stay under the history
/// key, as MIT ships them).
fn encode_keydata_raw(w: &mut XdrW, keys: &[OsaKeyData]) {
    w.u32(u32::try_from(keys.len()).unwrap_or(0));
    for k in keys {
        let slots = usize::from(k.ver.clamp(1, 2));
        w.u32(u32::from(k.ver));
        w.u32(u32::from(k.kvno));
        w.u32(u32::try_from(slots).unwrap_or(0));
        for t in &k.types[..slots] {
            w.u32(i32::from(*t).cast_unsigned());
        }
        w.u32(u32::try_from(slots).unwrap_or(0));
        for c in &k.contents[..slots] {
            w.opaque(c);
        }
    }
}

fn decode_keydata_raw(r: &mut XdrR<'_>) -> Result<Vec<OsaKeyData>, Error> {
    let n = r.u32()? as usize;
    let mut keys = Vec::with_capacity(n.min(16));
    for _ in 0..n {
        let ver = u16::try_from(r.u32()?).unwrap_or(u16::MAX);
        let kvno = u16::try_from(r.u32()?).unwrap_or(u16::MAX);
        let n_enc = r.u32()? as usize;
        let mut all_types = Vec::with_capacity(n_enc.min(4));
        for _ in 0..n_enc {
            all_types.push(i16::try_from(r.u32()?.cast_signed()).unwrap_or(0));
        }
        let n_cont = r.u32()? as usize;
        let mut all_contents = Vec::with_capacity(n_cont.min(4));
        for _ in 0..n_cont {
            all_contents.push(r.opaque()?);
        }
        let mut types = [0i16; 2];
        for (slot, t) in types.iter_mut().zip(&all_types) {
            *slot = *t;
        }
        let mut contents: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        for (slot, c) in contents.iter_mut().zip(all_contents) {
            *slot = c;
        }
        keys.push(OsaKeyData {
            ver,
            kvno,
            types,
            contents,
        });
    }
    Ok(keys)
}

fn kdbe_tl(p: &krb5_kdc::Principal) -> Vec<TlData> {
    let mut tl = p.tl_data.clone();
    tl.retain(|t| t.ty != TL_STRING_ATTRS && !(0x4B00..=0x4BFF).contains(&t.ty));
    if !p.string_attrs.is_empty() {
        let mut contents = Vec::new();
        for (k, v) in &p.string_attrs {
            contents.extend_from_slice(k.as_bytes());
            contents.push(0);
            contents.extend_from_slice(v.as_bytes());
            contents.push(0);
        }
        tl.push(TlData {
            ty: TL_STRING_ATTRS,
            contents,
        });
    }
    tl
}

fn string_attrs_from_tl(tl: &[TlData]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for t in tl {
        if t.ty != TL_STRING_ATTRS {
            continue;
        }
        let mut parts = t.contents.split(|b| *b == 0);
        while let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            if k.is_empty() {
                continue;
            }
            out.push((
                String::from_utf8_lossy(k).into_owned(),
                String::from_utf8_lossy(v).into_owned(),
            ));
        }
    }
    out
}

pub(super) fn tl_u32(tl: &[TlData], ty: i32) -> Option<u32> {
    let t = tl.iter().find(|t| t.ty == ty)?;
    let b: [u8; 4] = t.contents.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

fn encode_incr_update(
    w: &mut XdrW,
    e: &krb5_kdc::UlogEntry,
    mkey: Option<&krb5_crypto::ProtocolKey>,
) {
    encode_utf8str(w, &e.name);
    w.u32(e.sno);
    w.u32(e.time);
    w.u32(0);
    if e.deleted {
        w.u32(0);
    } else if let Some(p) = e.princ.as_ref() {
        encode_kdbe(w, p, mkey);
    } else {
        w.u32(0);
    }
    w.u32(u32::from(e.deleted));
    w.u32(1);
    w.u32(0);
    w.u32(0);
}

/// MIT `ulog_conv_2logentry` (`kdb_convert.c:472-486`): a stored mod-principal is shipped as its own attribute.
/// This encoder writes that attribute on every entry, using kadmin/admin when the record has none, because omitting it corrupts the replica.
pub(super) fn encode_kdbe(
    w: &mut XdrW,
    p: &krb5_kdc::Principal,
    mkey: Option<&krb5_crypto::ProtocolKey>,
) {
    let mut body = XdrW::default();
    let mut n = 0u32;
    body.u32(AT_ATTRFLAGS);
    body.u32(p.attributes);
    n += 1;
    body.u32(AT_MAX_LIFE);
    body.u32(u32::try_from(p.max_life).unwrap_or(0));
    n += 1;
    body.u32(AT_MAX_RENEW_LIFE);
    body.u32(u32::try_from(p.max_renewable_life).unwrap_or(0));
    n += 1;
    body.u32(AT_EXP);
    body.u32(p.expiration);
    n += 1;
    body.u32(AT_PW_EXP);
    body.u32(p.pw_expire);
    n += 1;
    body.u32(AT_LAST_SUCCESS);
    body.u32(p.last_success);
    n += 1;
    body.u32(AT_LAST_FAILED);
    body.u32(p.last_failed);
    n += 1;
    body.u32(AT_FAIL_AUTH_COUNT);
    body.u32(p.fail_auth_count);
    n += 1;
    body.u32(AT_PRINC);
    encode_utf8str(&mut body, &p.realm);
    let comps: Vec<String> = p
        .name
        .name_string
        .iter()
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
        .collect();
    body.u32(u32::try_from(comps.len()).unwrap_or(0));
    for c in &comps {
        // MIT `KV5M_DATA` (`krb5_data.magic`).
        body.u32((-1_760_647_422i32).cast_unsigned());
        encode_utf8str(&mut body, c);
    }
    body.u32(u32::try_from(p.name.name_type).unwrap_or(0));
    n += 1;
    body.u32(AT_KEYDATA);
    encode_keydata(&mut body, &p.keys, mkey, &p.salt);
    n += 1;
    let tl = kdbe_tl(p);
    if !tl.is_empty() {
        body.u32(AT_TL_DATA);
        body.u32(u32::try_from(tl.len()).unwrap_or(0));
        for t in &tl {
            body.u32(u32::try_from(t.ty).unwrap_or(0));
            body.opaque(&t.contents);
        }
        n += 1;
    }
    body.u32(AT_LEN);
    body.u32(p.db_entry_len);
    n += 1;
    if let Some(pol) = p.pw_policy.as_deref().filter(|s| !s.is_empty()) {
        body.u32(AT_PW_POLICY);
        encode_utf8str(&mut body, pol);
        n += 1;
    }
    if !p.kadm.old_keys.is_empty() {
        body.u32(AT_PW_HIST_KVNO);
        body.u32(p.kadm.admin_history_kvno);
        n += 1;
        body.u32(AT_PW_HIST);
        body.u32(u32::try_from(p.kadm.old_keys.len()).unwrap_or(0));
        for entry in &p.kadm.old_keys {
            encode_keydata_raw(&mut body, entry);
        }
        n += 1;
    }
    let now = u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0);
    let pw_last = tl_u32(&p.tl_data, TL_LAST_PWD_CHANGE).unwrap_or(now);
    let mod_time = tl_u32(&p.tl_data, TL_MOD_PRINC).unwrap_or(now);
    body.u32(AT_PW_LAST_CHANGE);
    body.u32(pw_last);
    n += 1;
    // MIT kadmin unparses mod_name; omitting AT_MOD_PRINC corrupts the replica.
    body.u32(AT_MOD_PRINC);
    encode_utf8str(&mut body, &p.realm);
    body.u32(2);
    body.u32((-1_760_647_422i32).cast_unsigned());
    encode_utf8str(&mut body, "kadmin");
    body.u32((-1_760_647_422i32).cast_unsigned());
    encode_utf8str(&mut body, "admin");
    body.u32(u32::try_from(krb5_types::PrincipalName::NT_SRV_INST).unwrap_or(2));
    n += 1;
    body.u32(AT_MOD_TIME);
    body.u32(mod_time);
    n += 1;
    w.u32(n);
    w.b.extend_from_slice(&body.b);
}

pub(super) fn encode_incr_result(
    status: u32,
    last: u32,
    entries: &[krb5_kdc::UlogEntry],
    mkey: Option<&krb5_crypto::ProtocolKey>,
) -> Vec<u8> {
    let mut w = XdrW::default();
    encode_kdb_last(&mut w, last);
    let n = u32::try_from(entries.len()).unwrap_or(0);
    w.u32(n);
    for e in entries {
        encode_incr_update(&mut w, e, mkey);
    }
    w.u32(status);
    w.b
}

pub(super) fn encode_fullresync_status(last: u32, status: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    encode_kdb_last(&mut w, last);
    w.u32(status);
    w.b
}

pub(super) fn encode_fullresync(last: u32) -> Vec<u8> {
    encode_fullresync_status(last, krb5_kdc::IPROP_OK)
}

/// Outcome of [`iprop_pull`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpropPull {
    /// MIT `update_status_t`.
    pub status: u32,
    /// `kdb_last_t.last_sno` from the reply.
    pub last_sno: u32,
    /// `kdb_last_t.last_time.seconds`.
    pub last_sec: u32,
    /// `kdb_last_t.last_time.useconds`.
    pub last_usec: u32,
    /// Entries applied into the replica store.
    pub applied: usize,
}

/// Replica cursor passed to `IPROP_GET_UPDATES`.
///
/// MIT `kdb_last_t` (`include/iprop.h:176-180`): the serial number and
/// the timestamp's seconds and microseconds.
#[derive(Clone, Copy)]
pub struct IpropLast {
    /// `kdb_last_t.last_sno`.
    pub last_sno: u32,
    /// `kdb_last_t.last_time.seconds`.
    pub last_sec: u32,
    /// `kdb_last_t.last_time.useconds`.
    pub last_usec: u32,
}

/// RPCSEC_GSS IPROP_GET_UPDATES against MIT `kadmind` (program 100423).
///
/// # Errors
///
/// Context, RPC, decode, or a key failure.
pub fn iprop_pull(
    stream: &mut TcpStream,
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &krb5_types::Realm,
    cname: &PrincipalName,
    last: IpropLast,
    store: &mut krb5_kdc::PrincipalStore,
) -> Result<IpropPull, Error> {
    let IpropLast {
        last_sno,
        last_sec,
        last_usec,
    } = last;
    let (mut ctx, token) =
        GssContext::init_sec_context(ticket, session, crealm, cname, true, None, None)
            .map_err(|e| Error::Inner(e.to_string()))?;
    let mut xid = 1u32;
    let handle = rpcsec_init(stream, &mut ctx, session, &token, &mut xid)?;
    let mut args = XdrW::default();
    args.u32(last_sno);
    args.u32(last_sec);
    args.u32(last_usec);
    let body = rpcsec_data(
        stream,
        &mut ctx,
        &handle,
        &mut xid,
        1,
        IPROP_PROG,
        IPROP_VERS,
        IPROP_GET_UPDATES,
        &args.b,
    )?;
    let (status, last, last_sec, last_usec, entries) =
        decode_incr_result(&body, store.iprop_master_key().as_ref())?;
    let n = entries.len();
    if status == krb5_kdc::IPROP_OK && n > 0 {
        store.apply_updates(&entries);
    }
    Ok(IpropPull {
        status,
        last_sno: last,
        last_sec,
        last_usec,
        applied: if status == krb5_kdc::IPROP_OK { n } else { 0 },
    })
}

/// RPCSEC_GSS `IPROP_FULL_RESYNC` against program 100423.
///
/// # Errors
///
/// Context, RPC, decode, or a key failure.
pub fn iprop_fullresync(
    stream: &mut TcpStream,
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &krb5_types::Realm,
    cname: &PrincipalName,
) -> Result<u32, Error> {
    let (mut ctx, token) =
        GssContext::init_sec_context(ticket, session, crealm, cname, true, None, None)
            .map_err(|e| Error::Inner(e.to_string()))?;
    let mut xid = 1u32;
    let handle = rpcsec_init(stream, &mut ctx, session, &token, &mut xid)?;
    let body = rpcsec_data(
        stream,
        &mut ctx,
        &handle,
        &mut xid,
        1,
        IPROP_PROG,
        IPROP_VERS,
        IPROP_FULL_RESYNC,
        &[],
    )?;
    let mut r = XdrR::new(&body);
    let _last = r.u32()?;
    let _sec = r.u32()?;
    let _usec = r.u32()?;
    r.u32()
}

/// MIT `authgss_validate` (`auth_gss.c:369-389`): the init verifier is a MIC of the sequence window, and a bad MIC is not success.
/// A non-zero GSS major status is not a context, and the AP-REP is processed only after that status is zero.
fn rpcsec_init(
    stream: &mut TcpStream,
    ctx: &mut GssContext,
    ticket_session: &ProtocolKey,
    token: &[u8],
    xid: &mut u32,
) -> Result<Vec<u8>, Error> {
    let mut cred = XdrW::default();
    cred.u32(RPCSEC_GSS_VERS);
    cred.u32(RPG_INIT);
    cred.u32(0);
    cred.u32(GSS_PRIVACY);
    cred.opaque(&[]);
    let mut arg = XdrW::default();
    arg.opaque(token);
    let rec = rpc_call_bytes(
        super::rpc::RpcCallId {
            xid: *xid,
            prog: IPROP_PROG,
            vers: IPROP_VERS,
            proc: IPROP_NULL,
        },
        FLAVOR_GSS,
        &cred.b,
        FLAVOR_NONE,
        &[],
        &arg.b,
    );
    *xid = xid.wrapping_add(1);
    write_record(stream, &rec).map_err(|e| Error::Inner(e.to_string()))?;
    let reply = read_record(stream).map_err(|e| Error::Inner(e.to_string()))?;
    let mut r = XdrR::new(&reply);
    let _ = r.u32()?;
    if r.u32()? != MSG_REPLY {
        return Err(Error::Inner("rpcsec init not reply".into()));
    }
    if r.u32()? != MSG_ACCEPTED {
        return Err(Error::Inner("rpcsec init denied".into()));
    }
    let verf_flavor = r.u32()?;
    let verf = r.opaque()?;
    if r.u32()? != SUCCESS {
        return Err(Error::Inner("rpcsec init accept".into()));
    }
    let handle = r.opaque()?;
    let major = r.u32()?;
    let _minor = r.u32()?;
    let window = r.u32()?;
    let out = r.opaque()?;
    if major != 0 {
        return Err(Error::Inner(format!("rpcsec gss major {major}")));
    }
    if !out.is_empty() {
        ctx.process_ap_rep(&out, ticket_session)
            .map_err(|e| Error::Inner(format!("rpcsec ap-rep: {e}")))?;
    }
    ctx.allow_rpcsec_init_window();
    // RFC 2203: INIT verifier is a MIC of the sequence window.
    if verf_flavor == FLAVOR_GSS && !verf.is_empty() {
        ctx.verify_mic(&window.to_be_bytes(), &verf)
            .map_err(|e| Error::Inner(format!("rpcsec init mic: {e}")))?;
    }
    Ok(handle)
}

/// MIT `xdr_rpc_gss_unwrap_data` (`authgss_prot.c:239-256`): a privacy reply that is not sealed, or whose sequence does not match, is not the arguments.
/// The wrapped body is the sequence number followed by the arguments, so a reply that omits that prefix is rejected.
#[expect(clippy::too_many_arguments, reason = "xid is advanced inside the body")]
fn rpcsec_data(
    stream: &mut TcpStream,
    ctx: &mut GssContext,
    handle: &[u8],
    xid: &mut u32,
    seq: u32,
    prog: u32,
    vers: u32,
    proc: u32,
    args: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut cred = XdrW::default();
    cred.u32(RPCSEC_GSS_VERS);
    cred.u32(RPG_DATA);
    cred.u32(seq);
    cred.u32(GSS_PRIVACY);
    cred.opaque(handle);
    let mut header = XdrW::default();
    header.u32(*xid);
    header.u32(MSG_CALL);
    header.u32(RPC_VERSION);
    header.u32(prog);
    header.u32(vers);
    header.u32(proc);
    header.u32(FLAVOR_GSS);
    header.opaque(&cred.b);
    let mic = ctx
        .get_mic(&header.b)
        .map_err(|e| Error::Inner(format!("rpcsec mic: {e}")))?;
    // MIT `xdr_rpc_gss_wrap_data`: gss_wrap(xdr_u_int32(seq) || args).
    // libgssrpc unwraps RRC=0 (same as the acceptor path above).
    let mut inner = Vec::with_capacity(4 + args.len());
    inner.extend_from_slice(&seq.to_be_bytes());
    inner.extend_from_slice(args);
    let wrap = ctx
        .wrap_with_rrc(&inner, 0)
        .map_err(|e| Error::Inner(format!("rpcsec wrap: {e}")))?;
    let mut arg = XdrW::default();
    arg.opaque(&wrap);
    let rec = rpc_call_bytes(
        super::rpc::RpcCallId {
            xid: *xid,
            prog,
            vers,
            proc,
        },
        FLAVOR_GSS,
        &cred.b,
        FLAVOR_GSS,
        &mic,
        &arg.b,
    );
    *xid = xid.wrapping_add(1);
    write_record(stream, &rec).map_err(|e| Error::Inner(e.to_string()))?;
    let reply = read_record(stream).map_err(|e| Error::Inner(e.to_string()))?;
    let mut r = XdrR::new(&reply);
    let _ = r.u32()?;
    if r.u32()? != MSG_REPLY {
        return Err(Error::Inner("rpcsec data not reply".into()));
    }
    if r.u32()? != MSG_ACCEPTED {
        return Err(Error::Inner("rpcsec data denied".into()));
    }
    let verf_flavor = r.u32()?;
    let verf = r.opaque()?;
    let accept_stat = r.u32()?;
    if accept_stat != SUCCESS {
        return Err(Error::Inner(format!("rpcsec data accept {accept_stat}")));
    }
    if verf_flavor == FLAVOR_GSS {
        ctx.verify_mic(&seq.to_be_bytes(), &verf)
            .map_err(|e| Error::Inner(format!("rpcsec reply mic: {e}")))?;
    }
    let wrapped = r.opaque()?;
    let (plain, conf) = ctx
        .unwrap_conf(&wrapped)
        .map_err(|e| Error::Inner(format!("rpcsec unwrap: {e}")))?;
    if !conf {
        return Err(Error::Inner("rpcsec privacy reply not sealed".into()));
    }
    if plain.len() < 4 {
        return Err(Error::Inner("rpcsec wrap seq".into()));
    }
    let got = u32::from_be_bytes(
        plain[..4]
            .try_into()
            .map_err(|_| Error::Inner("rpcsec wrap seq".into()))?,
    );
    if got != seq {
        return Err(Error::Inner(format!("rpcsec wrap seq {got} want {seq}")));
    }
    Ok(plain[4..].to_vec())
}

pub(super) fn decode_incr_result(
    b: &[u8],
    mkey: Option<&ProtocolKey>,
) -> Result<(u32, u32, u32, u32, Vec<krb5_kdc::UlogEntry>), Error> {
    let mut r = XdrR::new(b);
    let last = r.u32()?;
    let sec = r.u32()?;
    let usec = r.u32()?;
    let n = r.u32()? as usize;
    let mut entries = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        entries.push(decode_incr_update(&mut r, mkey)?);
    }
    let status = r.u32()?;
    Ok((status, last, sec, usec, entries))
}

fn decode_incr_update(
    r: &mut XdrR<'_>,
    mkey: Option<&ProtocolKey>,
) -> Result<krb5_kdc::UlogEntry, Error> {
    let name_raw = r.opaque()?;
    let name = String::from_utf8_lossy(&name_raw).into_owned();
    let sno = r.u32()?;
    let time = r.u32()?;
    let _usec = r.u32()?;
    let princ = decode_kdbe(r, mkey, &name)?;
    let deleted = r.bool()?;
    let _commit = r.bool()?;
    let seen = r.u32()?;
    for _ in 0..seen {
        let _ = r.opaque()?;
    }
    let _futures = r.opaque()?;
    Ok(krb5_kdc::UlogEntry {
        sno,
        time,
        name,
        deleted,
        princ: if deleted { None } else { princ },
    })
}

/// MIT `ulog_conv_2dbentry` (`kdb_convert.c:725-731`): the mod-principal attribute is a principal, not an opaque blob.
/// An unrecognized attribute is consumed as one opaque value so later attributes stay aligned, and a zero-length update is not a principal.
pub(super) fn decode_kdbe(
    r: &mut XdrR<'_>,
    mkey: Option<&ProtocolKey>,
    fallback: &str,
) -> Result<Option<Principal>, Error> {
    let n = r.u32()? as usize;
    if n == 0 {
        return Ok(None);
    }
    let mut attributes = 0u32;
    let mut max_life = 0u64;
    let mut max_renewable_life = 0u64;
    let mut expiration = 0u32;
    let mut pw_expire = 0u32;
    let mut last_success = 0u32;
    let mut last_failed = 0u32;
    let mut fail_auth_count = 0u32;
    let mut db_entry_len = KDB_V1_BASE_LENGTH;
    let mut pw_policy = None;
    let mut parsed_name: Option<(PrincipalName, String)> = None;
    let mut keys = Vec::new();
    let mut tl_data = Vec::new();
    let mut old_keys: Vec<Vec<OsaKeyData>> = Vec::new();
    let mut hist_kvno = None;
    let mut pw_last_change = None;
    for _ in 0..n {
        let tag = r.u32()?;
        match tag {
            AT_ATTRFLAGS => attributes = r.u32()?,
            AT_MAX_LIFE => max_life = u64::from(r.u32()?),
            AT_MAX_RENEW_LIFE => max_renewable_life = u64::from(r.u32()?),
            AT_EXP => expiration = r.u32()?,
            AT_PW_EXP => pw_expire = r.u32()?,
            AT_LAST_SUCCESS => last_success = r.u32()?,
            AT_LAST_FAILED => last_failed = r.u32()?,
            AT_FAIL_AUTH_COUNT => fail_auth_count = r.u32()?,
            AT_PRINC => parsed_name = Some(decode_princ(r)?),
            AT_KEYDATA => keys = decode_keydata(r, mkey)?,
            AT_TL_DATA => {
                let nt = r.u32()? as usize;
                for _ in 0..nt {
                    let ty = r.u32()?.cast_signed();
                    let contents = r.opaque()?;
                    tl_data.push(TlData { ty, contents });
                }
            }
            AT_LEN => db_entry_len = r.u32()?,
            AT_PW_LAST_CHANGE => pw_last_change = Some(r.u32()?),
            AT_MOD_TIME => {
                let _ = r.u32()?;
            }
            AT_PW_HIST_KVNO => hist_kvno = Some(r.u32()?),
            AT_PW_POLICY => {
                let s = r.opaque()?;
                pw_policy = Some(String::from_utf8_lossy(&s).into_owned());
            }
            AT_PW_POLICY_SWITCH => {
                let _ = r.bool()?;
            }
            AT_MOD_PRINC => {
                let _ = decode_princ(r)?;
            }
            AT_PW_HIST => {
                let nh = r.u32()? as usize;
                for _ in 0..nh {
                    old_keys.push(decode_keydata_raw(r)?);
                }
            }
            _ => {
                let _ = r.opaque()?;
            }
        }
    }
    let (name, realm) = if let Some(v) = parsed_name {
        v
    } else {
        parse_unparsed(fallback)?
    };
    let string_attrs = string_attrs_from_tl(&tl_data);
    if let Some(ts) = pw_last_change
        && !tl_data.iter().any(|t| t.ty == TL_LAST_PWD_CHANGE)
    {
        tl_data.push(TlData {
            ty: TL_LAST_PWD_CHANGE,
            contents: ts.to_le_bytes().to_vec(),
        });
    }
    let requires_preauth = attributes & KDB_REQUIRES_PRE_AUTH != 0;
    let locked = attributes & KDB_DISALLOW_ALL_TIX != 0;
    let salt = name.default_salt(&realm);
    // MIT carries the admin record inside AT_TL_DATA (`KRB5_TL_KADM_DATA`) and,
    // for a changed entry, the history as AT_PW_HIST / AT_PW_HIST_KVNO.
    let osa = OsaPrincEnt::from_tl(&tl_data).map_err(|e| Error::Inner(e.to_string()))?;
    let mut kadm = osa.as_ref().map(KadmData::from_osa).unwrap_or_default();
    if !old_keys.is_empty() {
        kadm.old_keys = old_keys;
        kadm.old_key_next = 0;
    }
    if let Some(k) = hist_kvno {
        kadm.admin_history_kvno = k;
    }
    let pw_policy = pw_policy.or_else(|| osa.and_then(|o| o.bound_policy().map(str::to_owned)));
    Ok(Some(Principal {
        name,
        realm,
        keys,
        key_history: Vec::new(),
        salt,
        requires_preauth,
        max_life,
        locked,
        pw_expire,
        attributes,
        max_renewable_life,
        expiration,
        last_success,
        last_failed,
        fail_auth_count,
        mkvno: 1,
        db_entry_len,
        tl_data,
        e_data: Vec::new(),
        rid: 0,
        s4u_allowed_from: Vec::new(),
        s4u_allowed_to: Vec::new(),
        pw_policy,
        kadm,
        string_attrs,
    }))
}

fn decode_princ(r: &mut XdrR<'_>) -> Result<(PrincipalName, String), Error> {
    let realm_b = r.opaque()?;
    let realm = String::from_utf8_lossy(&realm_b).into_owned();
    let n = r.u32()? as usize;
    let mut comps = Vec::with_capacity(n.min(16));
    for _ in 0..n {
        let _magic = r.u32()?;
        let c = r.opaque()?;
        comps.push(String::from_utf8_lossy(&c).into_owned());
    }
    let ntype = r.u32()?.cast_signed();
    let refs: Vec<&str> = comps.iter().map(String::as_str).collect();
    let name = PrincipalName::try_new(ntype, refs).map_err(|e| Error::Inner(e.to_string()))?;
    Ok((name, realm))
}

fn parse_unparsed(s: &str) -> Result<(PrincipalName, String), Error> {
    krb5_types::principal_from_unparsed(s, "").map_err(|e| Error::Inner(e.to_string()))
}

/// MIT `krb5_dbe_def_decrypt_key_data` (`decrypt_key.c:91-93`): a master-key decrypt failure is not a usable key.
/// An etype this build does not know, or a plaintext of the wrong length, is omitted and the other keys in the entry are kept.
fn decode_keydata(r: &mut XdrR<'_>, mkey: Option<&ProtocolKey>) -> Result<Vec<KeyEntry>, Error> {
    let n = r.u32()? as usize;
    let mut keys = Vec::with_capacity(n.min(16));
    for _ in 0..n {
        let ver = r.u32()?;
        let kvno = r.u32()?;
        let n_enc = r.u32()? as usize;
        let mut enctypes = Vec::with_capacity(n_enc.min(16));
        for _ in 0..n_enc {
            enctypes.push(r.u32()?.cast_signed());
        }
        let n_cont = r.u32()? as usize;
        let mut contents = Vec::with_capacity(n_cont.min(16));
        for _ in 0..n_cont {
            contents.push(r.opaque()?);
        }
        let Some(et) = enctypes.first().copied() else {
            continue;
        };
        let Ok(etype) = EncryptionType::from_iana(et).or_else(|_| EncryptionType::known(et)) else {
            continue;
        };
        let Some(raw_enc) = contents.first() else {
            continue;
        };
        let raw = if let Some(m) = mkey {
            kdb_decrypt_key(m, raw_enc).map_err(|e| Error::Inner(e.to_string()))?
        } else {
            raw_enc.clone()
        };
        let Ok(key) = ProtocolKey::from_bytes(etype, &raw) else {
            continue;
        };
        let (salt_type, kdb_salt) = if ver >= 2 {
            (enctypes.get(1).copied(), contents.get(1).cloned())
        } else {
            (None, None)
        };
        keys.push(KeyEntry {
            etype,
            key,
            kvno,
            salt_type,
            kdb_salt,
        });
    }
    Ok(keys)
}
