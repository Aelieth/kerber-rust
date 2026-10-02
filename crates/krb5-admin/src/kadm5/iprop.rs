//! Incremental propagation (`kadmin/server/ipropd_svc.c`,
//! `lib/kdb/iprop_xdr.c`): the `IPROP_GET_UPDATES` / `IPROP_FULL_RESYNC`
//! server side, the `kdbe_t` codecs, and the `krb5-iprop-pull` client
//! (kpropd's RPCSEC_GSS calls). Keys leave the store only wrapped under
//! the iprop master key.

use std::net::TcpStream;

use krb5_crypto::{EncryptionType, ProtocolKey, kdb_decrypt_key};
use krb5_gss::GssContext;
use krb5_kdc::{
    Acl, IpropUpdate, KdbeVal, KeyEntry, OsaKeyData, SharedDump as SharedStore, TlData,
};
use krb5_types::{PrincipalName, Ticket};

use super::codes::{
    AT_ATTRFLAGS, AT_EXP, AT_FAIL_AUTH_COUNT, AT_KEYDATA, AT_LAST_FAILED, AT_LAST_SUCCESS, AT_LEN,
    AT_MAX_LIFE, AT_MAX_RENEW_LIFE, AT_MOD_PRINC, AT_MOD_TIME, AT_MOD_WHERE, AT_PRINC, AT_PW_EXP,
    AT_PW_HIST, AT_PW_HIST_KVNO, AT_PW_LAST_CHANGE, AT_PW_POLICY, AT_PW_POLICY_SWITCH, AT_TL_DATA,
    FLAVOR_GSS, FLAVOR_NONE, GSS_PRIVACY, IPROP_FULL_RESYNC, IPROP_FULL_RESYNC_EXT,
    IPROP_GET_UPDATES, IPROP_NULL, IPROP_PROG, IPROP_VERS, MSG_ACCEPTED, MSG_CALL, MSG_REPLY,
    RPC_VERSION, RPCSEC_GSS_VERS, RPG_DATA, RPG_INIT, SUCCESS,
};
use super::rpc::{read_record, rpc_call_bytes, write_record};
use super::xdr::{XdrR, XdrW};
use crate::Error;

/// MIT `iprop_get_updates_1_svc` (`ipropd_svc.c:191-200`): a caller who fails the iprop ACL gets
/// permission denied and no entries.
/// The null procedure skips that check, and an incremental update whose keys do not wrap under
/// the master key is refused rather than sending those keys in the clear.
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
            encode_incr_status(krb5_kdc::IPROP_PERM_DENIED, 0)
        };
    }
    match proc {
        IPROP_NULL => Vec::new(),
        IPROP_GET_UPDATES => {
            let mut r = XdrR::new(args);
            let last_sno = r.u32().unwrap_or(0);
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // The update log another process (kadmin.local) appended to is read before answering.
            if g.reload_if_stale().is_err() {
                return encode_incr_status(krb5_kdc::IPROP_ERROR, 0);
            }
            let (status, last, entries) = g.iprop_get(last_sno);
            let mkey = g.iprop_master_key();
            incr_reply(status, last, &entries, &master_key_wrap(mkey.as_ref()))
        }
        IPROP_FULL_RESYNC | IPROP_FULL_RESYNC_EXT => {
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if g.reload_if_stale().is_err() {
                return encode_fullresync_status(0, krb5_kdc::IPROP_ERROR);
            }
            encode_fullresync(g.serial())
        }
        _ => encode_incr_status(krb5_kdc::IPROP_FULL_RESYNC, 0),
    }
}

/// How a key leaves the store in an update: wrapped, or not at all.
pub(super) type KeyWrap<'a> = dyn Fn(&[u8]) -> Result<Vec<u8>, Error> + 'a;

/// MIT ships each key as the master-key ciphertext its database stores (`kdb_convert.c` copies
/// `key_data_contents`). The store holds plaintext keys, so they are wrapped under the master key
/// as they leave; with no master key (`iprop_master_key`: the stash, the `K/M` principal, and
/// `KRB5_MASTER_PASSWORD` only in a `test-hooks` build), or a wrap that fails, no key leaves.
pub(super) fn master_key_wrap(
    mkey: Option<&ProtocolKey>,
) -> impl Fn(&[u8]) -> Result<Vec<u8>, Error> + '_ {
    move |raw| match mkey {
        Some(m) => krb5_crypto::kdb_encrypt_key(m, raw)
            .map_err(|e| Error::Inner(format!("iprop key: {e}"))),
        None => Err(Error::Inner("iprop key: no master key".into())),
    }
}

/// The GET_UPDATES reply: `UPDATE_ERROR` and no entries when a key of one does not wrap, never a
/// key in the clear.
pub(super) fn incr_reply(
    status: u32,
    last: u32,
    entries: &[krb5_kdc::UlogEntry],
    wrap: &KeyWrap<'_>,
) -> Vec<u8> {
    encode_incr_result(status, last, entries, wrap)
        .unwrap_or_else(|_| encode_incr_status(krb5_kdc::IPROP_ERROR, 0))
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

/// MIT `xdr_kdbe_key_t` (`lib/kdb/iprop_xdr.c:75-90`): each key's version, kvno, then as many types and contents as its version.
/// MIT `ulog_conv_2logentry` (`lib/kdb/kdb_convert.c:415-462`): each key goes as stored, its version deciding how many types and contents follow.
/// A key is stored at version 2 when it has a salt type and salt, as the dump writes it.
fn encode_keydata(w: &mut XdrW, keys: &[KeyEntry], wrap: &KeyWrap<'_>) -> Result<(), Error> {
    w.u32(u32::try_from(keys.len()).unwrap_or(0));
    for k in keys {
        let enc = wrap(k.key.as_bytes())?;
        let etype = u32::try_from(k.etype.to_iana()).unwrap_or(0);
        if let (Some(salt_type), Some(salt)) = (k.salt_type, k.kdb_salt.as_ref()) {
            w.u32(2);
            w.u32(k.kvno);
            w.u32(2);
            w.u32(etype);
            w.u32(salt_type.cast_unsigned());
            w.u32(2);
            w.opaque(&enc);
            w.opaque(salt);
        } else {
            w.u32(1);
            w.u32(k.kvno);
            w.u32(1);
            w.u32(etype);
            w.u32(1);
            w.opaque(&enc);
        }
    }
    Ok(())
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

pub(super) fn tl_u32(tl: &[TlData], ty: i32) -> Option<u32> {
    let t = tl.iter().find(|t| t.ty == ty)?;
    let b: [u8; 4] = t.contents.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

/// MIT `xdr_kdb_incr_update_t` (`lib/kdb/iprop_xdr.c:263-285`): the name, serial, time, the update, the deleted and committed flags, no KDCs seen, no futures.
fn encode_incr_update(
    w: &mut XdrW,
    e: &krb5_kdc::UlogEntry,
    wrap: &KeyWrap<'_>,
) -> Result<(), Error> {
    encode_utf8str(w, &e.name);
    w.u32(e.sno);
    w.u32(e.time);
    w.u32(0);
    encode_kdbe(w, &e.kdbe_vals(), wrap)?;
    w.u32(u32::from(e.deleted));
    w.u32(1);
    w.u32(0);
    w.u32(0);
    Ok(())
}

/// `kdbe_princ_t`: the realm, each component with MIT's `KV5M_DATA` magic, the name type.
fn encode_princ(w: &mut XdrW, name: &PrincipalName, realm: &str) {
    encode_utf8str(w, realm);
    w.u32(u32::try_from(name.name_string.len()).unwrap_or(0));
    for c in &name.name_string {
        // MIT `KV5M_DATA` (`krb5_data.magic`).
        w.u32((-1_760_647_422i32).cast_unsigned());
        w.opaque(c.as_bytes());
    }
    w.u32(name.name_type.cast_unsigned());
}

/// MIT `xdr_kdbe_val_t` (`lib/kdb/iprop_xdr.c:153-249`): each attribute's type, then its value in that type's shape.
/// The attributes are the ones the update carries, in its order; keys are wrapped by `wrap`.
///
/// # Errors
///
/// A key `wrap` refuses.
pub(super) fn encode_kdbe(w: &mut XdrW, vals: &[KdbeVal], wrap: &KeyWrap<'_>) -> Result<(), Error> {
    w.u32(u32::try_from(vals.len()).unwrap_or(0));
    for v in vals {
        w.u32(v.attr());
        match v {
            KdbeVal::AttrFlags(n)
            | KdbeVal::MaxLife(n)
            | KdbeVal::MaxRenewLife(n)
            | KdbeVal::Exp(n)
            | KdbeVal::PwExp(n)
            | KdbeVal::LastSuccess(n)
            | KdbeVal::LastFailed(n)
            | KdbeVal::FailAuthCount(n)
            | KdbeVal::Len(n)
            | KdbeVal::ModTime(n)
            | KdbeVal::PwLastChange(n)
            | KdbeVal::PwHistKvno(n) => w.u32(*n),
            KdbeVal::Princ(name, realm) | KdbeVal::ModPrinc(name, realm) => {
                encode_princ(w, name, realm);
            }
            KdbeVal::KeyData(keys) => encode_keydata(w, keys, wrap)?,
            KdbeVal::TlData(tl) => {
                w.u32(u32::try_from(tl.len()).unwrap_or(0));
                for t in tl {
                    w.u32(t.ty.cast_unsigned());
                    w.opaque(&t.contents);
                }
            }
            KdbeVal::ModWhere(b) | KdbeVal::PwPolicy(b) | KdbeVal::Extension(_, b) => w.opaque(b),
            KdbeVal::PwPolicySwitch(on) => w.u32(u32::from(*on)),
            KdbeVal::PwHist(hist) => {
                w.u32(u32::try_from(hist.len()).unwrap_or(0));
                for entry in hist {
                    encode_keydata_raw(w, entry);
                }
            }
        }
    }
    Ok(())
}

/// A `kdb_incr_result_t` with no updates.
pub(super) fn encode_incr_status(status: u32, last: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    encode_kdb_last(&mut w, last);
    w.u32(0);
    w.u32(status);
    w.b
}

/// A `kdb_incr_result_t` with `entries`, their keys wrapped by `wrap`.
///
/// # Errors
///
/// A key `wrap` refuses.
pub(super) fn encode_incr_result(
    status: u32,
    last: u32,
    entries: &[krb5_kdc::UlogEntry],
    wrap: &KeyWrap<'_>,
) -> Result<Vec<u8>, Error> {
    let mut w = XdrW::default();
    encode_kdb_last(&mut w, last);
    let n = u32::try_from(entries.len()).unwrap_or(0);
    w.u32(n);
    for e in entries {
        encode_incr_update(&mut w, e, wrap)?;
    }
    w.u32(status);
    Ok(w.b)
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
/// [`Error::GarbageArgs`] when a reply is truncated; [`Error::Inner`] when the GSS context
/// cannot be built, a read or write on `stream` fails, a reply is not an accepted `SUCCESS`
/// or carries a non-zero GSS major status, a reply's AP-REP, MIC, or seal does not verify or
/// has the wrong sequence, or an update's name or KADM data does not decode or its keys do not
/// decrypt under the replica's iprop master key.
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
        // MIT `ulog_replay` (`lib/kdb/kdb_log.c:430-467`): each update is put into the database, which locks it.
        store
            .change(|s| s.apply_updates(&entries).map_err(Error::from))
            .map_err(Error::from)??;
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
/// [`Error::GarbageArgs`] when a reply is truncated; [`Error::Inner`] when the GSS context
/// cannot be built, a read or write on `stream` fails, a reply is not an accepted `SUCCESS`
/// or carries a non-zero GSS major status, or a reply's AP-REP, MIC, or seal does not verify
/// or has the wrong sequence.
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

/// MIT `authgss_validate` (`auth_gss.c:369-389`): the init verifier is a MIC of the sequence
/// window, and a bad MIC is not success.
/// A non-zero GSS major status is not a context, and the AP-REP is processed only after that status
/// is zero.
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

/// MIT `xdr_rpc_gss_unwrap_data` (`authgss_prot.c:239-256`): a privacy reply that is not sealed, or
/// whose sequence does not match, is not the arguments.
/// The wrapped body is the sequence number followed by the arguments, so a reply that omits that
/// prefix is rejected.
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
) -> Result<(u32, u32, u32, u32, Vec<IpropUpdate>), Error> {
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

fn decode_incr_update(r: &mut XdrR<'_>, mkey: Option<&ProtocolKey>) -> Result<IpropUpdate, Error> {
    let name_raw = r.opaque()?;
    let name = String::from_utf8_lossy(&name_raw).into_owned();
    let sno = r.u32()?;
    let time = r.u32()?;
    let _usec = r.u32()?;
    let vals = decode_kdbe(r, mkey)?;
    let deleted = r.bool()?;
    let _commit = r.bool()?;
    let seen = r.u32()?;
    for _ in 0..seen {
        let _ = r.opaque()?;
    }
    let _futures = r.opaque()?;
    Ok(IpropUpdate {
        sno,
        time,
        name,
        deleted,
        vals,
    })
}

/// MIT `xdr_kdbe_val_t` (`lib/kdb/iprop_xdr.c:153-249`): each attribute's value is read in its type's shape, and a type MIT does not name is one opaque value.
/// The update keeps which attributes it carried; none stands in for one it did not.
pub(super) fn decode_kdbe(
    r: &mut XdrR<'_>,
    mkey: Option<&ProtocolKey>,
) -> Result<Vec<KdbeVal>, Error> {
    let n = r.u32()? as usize;
    let mut vals = Vec::with_capacity(n.min(32));
    for _ in 0..n {
        let tag = r.u32()?;
        vals.push(match tag {
            AT_ATTRFLAGS => KdbeVal::AttrFlags(r.u32()?),
            AT_MAX_LIFE => KdbeVal::MaxLife(r.u32()?),
            AT_MAX_RENEW_LIFE => KdbeVal::MaxRenewLife(r.u32()?),
            AT_EXP => KdbeVal::Exp(r.u32()?),
            AT_PW_EXP => KdbeVal::PwExp(r.u32()?),
            AT_LAST_SUCCESS => KdbeVal::LastSuccess(r.u32()?),
            AT_LAST_FAILED => KdbeVal::LastFailed(r.u32()?),
            AT_FAIL_AUTH_COUNT => KdbeVal::FailAuthCount(r.u32()?),
            AT_PRINC => {
                let (name, realm) = decode_princ(r)?;
                KdbeVal::Princ(name, realm)
            }
            AT_KEYDATA => KdbeVal::KeyData(decode_keydata(r, mkey)?),
            AT_TL_DATA => {
                let nt = r.u32()? as usize;
                let mut tl = Vec::with_capacity(nt.min(64));
                for _ in 0..nt {
                    let ty = r.u32()?.cast_signed();
                    let contents = r.opaque()?;
                    tl.push(TlData { ty, contents });
                }
                KdbeVal::TlData(tl)
            }
            AT_LEN => KdbeVal::Len(r.u32()?),
            AT_MOD_PRINC => {
                let (name, realm) = decode_princ(r)?;
                KdbeVal::ModPrinc(name, realm)
            }
            AT_MOD_TIME => KdbeVal::ModTime(r.u32()?),
            AT_MOD_WHERE => KdbeVal::ModWhere(r.opaque()?),
            AT_PW_LAST_CHANGE => KdbeVal::PwLastChange(r.u32()?),
            AT_PW_POLICY => KdbeVal::PwPolicy(r.opaque()?),
            AT_PW_POLICY_SWITCH => KdbeVal::PwPolicySwitch(r.bool()?),
            AT_PW_HIST_KVNO => KdbeVal::PwHistKvno(r.u32()?),
            AT_PW_HIST => {
                let nh = r.u32()? as usize;
                let mut hist = Vec::with_capacity(nh.min(16));
                for _ in 0..nh {
                    hist.push(decode_keydata_raw(r)?);
                }
                KdbeVal::PwHist(hist)
            }
            other => KdbeVal::Extension(other, r.opaque()?),
        });
    }
    Ok(vals)
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

/// MIT `krb5_dbe_def_decrypt_key_data` (`decrypt_key.c:91-93`): a master-key decrypt failure is not
/// a usable key.
/// MIT `ulog_conv_2dbentry` (`lib/kdb/kdb_convert.c:678-683`): a key of a version past 2 is not a key, and the update does not apply.
/// An etype this build does not know, or a plaintext of the wrong length, is omitted and the other
/// keys in the entry are kept.
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
        if ver > 2 {
            return Err(Error::Inner(format!("iprop key data version {ver}")));
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
