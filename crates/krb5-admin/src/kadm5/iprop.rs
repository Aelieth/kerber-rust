//! Incremental propagation (`kadmin/server/ipropd_svc.c`): the `IPROP_GET_UPDATES` /
//! `IPROP_FULL_RESYNC` server side, answered from the update log ([`krb5_kdc::Ulog`]), and the
//! `krb5-iprop-pull` client (kpropd's RPCSEC_GSS calls). The `kdb_incr_update_t` codec is
//! `krb5_kdc`'s (`lib/kdb/iprop_xdr.c`): updates leave as the log stores them, keys wrapped under
//! the master key.

use std::net::TcpStream;

use krb5_crypto::ProtocolKey;
use krb5_gss::GssContext;
use krb5_kdc::{
    Acl, IpropUpdate, SharedDump as SharedStore, TlData, UlogLast, UlogTime, UlogUpdates,
};
use krb5_types::{PrincipalName, Ticket};

use super::codes::{
    FLAVOR_GSS, FLAVOR_NONE, GSS_PRIVACY, IPROP_FULL_RESYNC, IPROP_FULL_RESYNC_EXT,
    IPROP_GET_UPDATES, IPROP_NULL, IPROP_PROG, IPROP_VERS, MSG_ACCEPTED, MSG_CALL, MSG_REPLY,
    RPC_VERSION, RPCSEC_GSS_VERS, RPG_DATA, RPG_INIT, SUCCESS,
};
use super::rpc::{read_record, rpc_call_bytes, write_record};
use super::xdr::{XdrR, XdrW};
use crate::Error;

/// MIT `iprop_get_updates_1_svc` (`kadmin/server/ipropd_svc.c:191-200`): a caller who fails the iprop ACL gets permission denied and no entries.
/// The null procedure skips that check. Updates leave as the log holds them: their keys were
/// wrapped under the master key when they were logged, so none leaves in the clear.
/// MIT `iprop_get_updates_1_svc` (`kadmin/server/ipropd_svc.c:203-205`): the answer is the update log's.
/// MIT `ipropx_resync` (`kadmin/server/ipropd_svc.c:400-424`): a granted full resync answers `UPDATE_OK` with a zero last entry; the dump comes by kprop.
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
            encode_fullresync_status(UlogLast::default(), krb5_kdc::IPROP_PERM_DENIED)
        } else {
            encode_incr_status(krb5_kdc::IPROP_PERM_DENIED)
        };
    }
    match proc {
        IPROP_NULL => Vec::new(),
        IPROP_GET_UPDATES => {
            let mut r = XdrR::new(args);
            let last = UlogLast {
                sno: r.u32().unwrap_or(0),
                time: UlogTime {
                    seconds: r.u32().unwrap_or(0),
                    useconds: r.u32().unwrap_or(0),
                },
            };
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            encode_incr_result(&g.ulog_get_entries(last))
        }
        IPROP_FULL_RESYNC | IPROP_FULL_RESYNC_EXT => {
            encode_fullresync_status(UlogLast::default(), krb5_kdc::IPROP_OK)
        }
        _ => encode_incr_status(krb5_kdc::IPROP_FULL_RESYNC),
    }
}

/// MIT `xdr_kdb_last_t` (`lib/kdb/iprop_xdr.c:309-318`): the serial, then the time's seconds and microseconds.
fn encode_kdb_last(w: &mut XdrW, last: UlogLast) {
    w.u32(last.sno);
    w.u32(last.time.seconds);
    w.u32(last.time.useconds);
}

pub(super) fn tl_u32(tl: &[TlData], ty: i32) -> Option<u32> {
    let t = tl.iter().find(|t| t.ty == ty)?;
    let b: [u8; 4] = t.contents.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

/// A `kdb_incr_result_t` with no updates and a zero last entry: what MIT's reply holds before
/// any update was sent.
pub(super) fn encode_incr_status(status: u32) -> Vec<u8> {
    encode_incr_result(&UlogUpdates {
        status,
        ..UlogUpdates::default()
    })
}

/// A `kdb_incr_result_t`: the last entry, the updates as the log holds them, the status.
/// MIT `xdr_kdb_incr_result_t` (`lib/kdb/iprop_xdr.c:321-332`): the last entry, the updates, then the status.
pub(super) fn encode_incr_result(got: &UlogUpdates) -> Vec<u8> {
    let mut w = XdrW::default();
    encode_kdb_last(&mut w, got.last);
    w.u32(u32::try_from(got.updates.len()).unwrap_or(0));
    for u in &got.updates {
        w.b.extend_from_slice(u);
    }
    w.u32(got.status);
    w.b
}

/// A `kdb_fullresync_result_t`: the last entry and the status.
pub(super) fn encode_fullresync_status(last: UlogLast, status: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    encode_kdb_last(&mut w, last);
    w.u32(status);
    w.b
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
        let (update, len) = krb5_kdc::decode_incr_update(r.rest(), mkey).map_err(|e| match e {
            krb5_kdc::XdrError::Short => Error::GarbageArgs,
            krb5_kdc::XdrError::Invalid(s) => Error::Inner(s),
        })?;
        r.i += len;
        entries.push(update);
    }
    let status = r.u32()?;
    Ok((status, last, sec, usec, entries))
}
