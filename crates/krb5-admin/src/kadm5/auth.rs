//! A context is bound to the ticket's realm.
//! Refused flavors are answered at once.

use krb5_gss::{ChannelBindings, GSS_C_AF_INET, GssContext};
use krb5_log::klog::Severity;
use krb5_protocol::ReplayCache;
use krb5_types::{KerberosTime, PrincipalName};

use super::acceptor::{accept_auth_gssapi, accept_from_kdb};
use super::codes::{
    AGSS_INDEF_EXPIRE, AGSS_INITIATION_TIMEOUT, AUTH_BADCRED, AUTH_BADVERF, AUTH_FAILED,
    AUTH_GSSAPI_CONTINUE_INIT, AUTH_GSSAPI_CREDS_VERS, AUTH_GSSAPI_DESTROY, AUTH_GSSAPI_INIT,
    AUTH_GSSAPI_MSG, AUTH_REJECTEDCRED, AUTH_REJECTEDVERF, CREATE_ALIAS, FLAVOR_AUTH_GSSAPI,
    FLAVOR_GSS, GARBAGE_ARGS, GSS_INTEGRITY, GSS_NONE, GSS_PRIVACY, GSS_S_BAD_BINDINGS,
    GSS_S_DEFECTIVE_TOKEN, GSS_S_FAILURE, IPROP_FULL_RESYNC_EXT, IPROP_VERS, KADM_VERS, MAXSEQ,
    PROC_UNAVAIL, PROG_UNAVAIL, RPCSEC_GSS_CREDPROBLEM, RPCSEC_GSS_CTXPROBLEM, RPCSEC_GSS_VERS,
    RPCSEC_SEQ_WINDOW, RPG_CONTINUE, RPG_DATA, RPG_DESTROY, RPG_INIT, SETV4KEY_PRINCIPAL,
    SYSTEM_ERR,
};
use super::dispatch::kadm5_or_iprop;
use super::log::{
    Caller, kadm5_log_op, kadm5_service_name, rpc_log_bad_proc, rpc_log_bad_service,
    rpc_log_badauth, rpc_log_badverf, rpc_log_flavor_refused, rpc_log_miscerr,
};
use super::rpc::{
    RpcCtx, RpcPeer, parse_gcred, rpc_reply_accepted_verf, rpc_reply_agss, rpc_reply_agss_status,
    rpc_reply_auth_error, rpc_reply_clear, rpc_reply_gss, rpc_reply_gss_verf,
    rpc_reply_mismatch_verf, rpc_reply_weakauth,
};
use super::xdr::{XdrR, XdrW, opaque_len};
use crate::Error;
use zeroize::Zeroizing;

pub(super) struct Agss {
    pub(super) ctx: Option<GssContext>,
    pub(super) handle: Vec<u8>,
    pub(super) seq: u32,
    pub(super) expires: u32,
}

// MIT: `create_client` (svc_auth_gssapi.c:694-738)
const AGSS_HANDLE: [u8; 4] = 1u32.to_le_bytes();

pub(super) struct RpcsecGss {
    pub(super) ctx: GssContext,
    seqlast: u32,
    seqmask: u32,
    pub(super) svc: u32,
}

// MIT: `gssrpc__svcauth_gss` (svc_auth_gss.c:460-471)
/// Replayed or out-of-window: not dispatched.
#[expect(clippy::too_many_arguments, reason = "over seven inputs after RpcCtx")]
#[allow(clippy::unnecessary_wraps)]
pub(super) fn handle_rpcsec_gss(
    ctx: RpcCtx<'_>,
    handle: &[u8],
    gss: &mut Option<RpcsecGss>,
    xid: u32,
    proc: u32,
    kadm: bool,
    iprop: bool,
    vers: u32,
    cred: &[u8],
    verf_flavor: u32,
    verf: &[u8],
    rec: &[u8],
    header_end: usize,
    args: &[u8],
    rcache: &ReplayCache,
    addr: &str,
) -> Result<Vec<u8>, Error> {
    let RpcCtx {
        store,
        expected_realm,
        conf,
        ..
    } = ctx;
    let _ = verf_flavor;
    let mut r = XdrR::new(args);
    let Ok(gcred) = parse_gcred(cred) else {
        return Ok(rpc_reply_auth_error(xid, AUTH_BADCRED));
    };
    if gcred.version != RPCSEC_GSS_VERS {
        return Ok(rpc_reply_auth_error(xid, AUTH_BADCRED));
    }
    if gcred.service != GSS_NONE && gcred.service != GSS_INTEGRITY && gcred.service != GSS_PRIVACY {
        return Ok(rpc_reply_auth_error(xid, AUTH_BADCRED));
    }

    if let Some(gd) = gss.as_mut()
        && (gcred.seq_num > MAXSEQ || !seq_window_ok(gd, gcred.seq_num))
    {
        return Ok(rpc_reply_auth_error(xid, RPCSEC_GSS_CTXPROBLEM));
    }

    match gcred.proc {
        RPG_INIT | RPG_CONTINUE => {
            if proc != 0 {
                return Ok(rpc_reply_auth_error(xid, AUTH_FAILED));
            }
            let Ok(token) = r.opaque() else {
                return Ok(rpc_reply_auth_error(xid, AUTH_REJECTEDCRED));
            };
            // MIT: `svcauth_gss_accept_sec_context` (svc_auth_gss.c:216-221)
            // MIT: `svcauth_gss_acquire_cred` (svc_auth_gss.c:149-157)
            let (mut ctx, out_tok) =
                match accept_from_kdb(store, expected_realm, None, &token, None, rcache, conf) {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        rpc_log_badauth(addr, accept_major(&e), &e.to_string());
                        return Ok(rpc_reply_auth_error(xid, AUTH_REJECTEDCRED));
                    }
                };
            let mut body = XdrW::default();
            body.opaque(handle);
            body.u32(0);
            body.u32(0);
            body.u32(RPCSEC_SEQ_WINDOW);
            body.opaque(out_tok.as_deref().unwrap_or(&[]));
            if ctx.get_mic(&RPCSEC_SEQ_WINDOW.to_be_bytes()).is_err() {
                return Ok(rpc_reply_auth_error(xid, AUTH_REJECTEDCRED));
            }
            let Ok(mic) = ctx.get_mic(&RPCSEC_SEQ_WINDOW.to_be_bytes()) else {
                return Ok(rpc_reply_auth_error(xid, AUTH_FAILED));
            };
            *gss = Some(RpcsecGss {
                ctx,
                seqlast: 0,
                seqmask: 0,
                svc: gcred.service,
            });
            Ok(rpc_reply_gss_verf(xid, &mic, &body.b))
        }
        RPG_DATA => {
            // MIT does not compare gc_handle.
            if !rpcsec_validate(gss, proc, &rec[..header_end], verf, addr) {
                return Ok(rpc_reply_auth_error(xid, RPCSEC_GSS_CREDPROBLEM));
            }
            let Some(gd) = gss.as_mut() else {
                return Ok(rpc_reply_auth_error(xid, RPCSEC_GSS_CREDPROBLEM));
            };
            let Ok(mic) = gd.ctx.get_mic(&gcred.seq_num.to_be_bytes()) else {
                return Ok(rpc_reply_auth_error(xid, AUTH_FAILED));
            };
            if kadm && vers != KADM_VERS {
                return Ok(rpc_reply_mismatch_verf(
                    xid,
                    Some(&mic),
                    KADM_VERS,
                    KADM_VERS,
                ));
            }
            if iprop && vers != IPROP_VERS {
                return Ok(rpc_reply_mismatch_verf(
                    xid,
                    Some(&mic),
                    IPROP_VERS,
                    IPROP_VERS,
                ));
            }
            if !kadm && !iprop {
                return Ok(rpc_reply_accepted_verf(xid, Some(&mic), PROG_UNAVAIL));
            }
            // Clear bodies carry passwords and keys.
            let databody = match gd.svc {
                GSS_NONE => None,
                GSS_INTEGRITY => {
                    let (Ok(databody), Ok(checksum)) = (r.opaque(), r.opaque()) else {
                        return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                    };
                    let databody = Zeroizing::new(databody);
                    if gd.ctx.verify_mic(&databody, &checksum).is_err() {
                        return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                    }
                    Some(databody)
                }
                _ => {
                    let Ok(wrapped) = r.opaque() else {
                        return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                    };
                    // Privacy: the body must be sealed.
                    // MIT: `xdr_rpc_gss_unwrap_data` (authgss_prot.c:238-240)
                    let Ok((plain, conf)) = gd.ctx.unwrap_conf(&wrapped) else {
                        return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                    };
                    let plain = Zeroizing::new(plain);
                    if !conf {
                        return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                    }
                    Some(plain)
                }
            };
            // Body must open with the credential's sequence.
            let kadm_args = match &databody {
                None => r.rest(),
                Some(body) => {
                    if body.get(..4) != Some(gcred.seq_num.to_be_bytes().as_slice()) {
                        return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                    }
                    &body[4..]
                }
            };
            Ok(rpcsec_dispatch(
                ctx,
                gd,
                xid,
                proc,
                kadm_args,
                iprop,
                &mic,
                gcred.seq_num,
                addr,
            ))
        }
        RPG_DESTROY => {
            if proc != 0 {
                return Ok(rpc_reply_auth_error(xid, AUTH_FAILED));
            }
            if !rpcsec_validate(gss, proc, &rec[..header_end], verf, addr) {
                return Ok(rpc_reply_auth_error(xid, RPCSEC_GSS_CREDPROBLEM));
            }
            let Some(gd) = gss.as_mut() else {
                return Ok(rpc_reply_auth_error(xid, RPCSEC_GSS_CREDPROBLEM));
            };
            let Ok(mic) = gd.ctx.get_mic(&gcred.seq_num.to_be_bytes()) else {
                return Ok(rpc_reply_auth_error(xid, AUTH_FAILED));
            };
            *gss = None;
            Ok(rpc_reply_gss_verf(xid, &mic, &[]))
        }
        _ => Ok(rpc_reply_auth_error(xid, AUTH_REJECTEDCRED)),
    }
}

// MIT: `svcauth_gss_validate` (svc_auth_gss.c:295-351)
fn rpcsec_validate(
    gss: &mut Option<RpcsecGss>,
    proc: u32,
    header: &[u8],
    verf: &[u8],
    addr: &str,
) -> bool {
    if gss
        .as_mut()
        .is_some_and(|gd| gd.ctx.verify_mic(header, verf).is_ok())
    {
        return true;
    }
    let client = gss.as_ref().and_then(|gd| gd.ctx.client.as_deref());
    rpc_log_badverf(proc, client, None, addr);
    false
}

fn seq_window_ok(gd: &mut RpcsecGss, seq: u32) -> bool {
    let offset = i64::from(gd.seqlast) - i64::from(seq);
    if offset < 0 {
        let shift = u32::try_from(-offset).unwrap_or(u32::MAX);
        gd.seqlast = seq;
        if shift >= 32 {
            gd.seqmask = 0;
        } else {
            gd.seqmask <<= shift;
        }
        gd.seqmask |= 1;
        true
    } else {
        let off = u32::try_from(offset).unwrap_or(u32::MAX);
        if off >= RPCSEC_SEQ_WINDOW || (gd.seqmask & (1 << off)) != 0 {
            return false;
        }
        gd.seqmask |= 1 << off;
        true
    }
}

// MIT: `check_rpcsec_auth` (kadm_rpc_svc.c:324-331)
/// Acceptor: two components, `kadmin`, in the server realm.
// MIT: `kadm_1` (kadm_rpc_svc.c:251-255)
/// Procedures past 27: PROC_UNAVAIL.
#[expect(clippy::too_many_arguments, reason = "over seven inputs after RpcCtx")]
fn rpcsec_dispatch(
    ctx: RpcCtx<'_>,
    gd: &mut RpcsecGss,
    xid: u32,
    proc: u32,
    kadm_args: &[u8],
    iprop: bool,
    mic: &[u8],
    seq: u32,
    addr: &str,
) -> Vec<u8> {
    let RpcCtx { expected_realm, .. } = ctx;
    let Some(actor) = gd.ctx.client.clone() else {
        return rpc_reply_weakauth(xid);
    };
    let served = if iprop {
        check_iprop_rpcsec_auth(&gd.ctx, expected_realm)
    } else {
        check_rpcsec_auth(&gd.ctx, expected_realm)
    };
    if !served {
        rpc_log_bad_service(&kadm5_service_name(&gd.ctx));
        rpc_log_flavor_refused(iprop, addr, FLAVOR_GSS);
        return rpc_reply_weakauth(xid);
    }
    let unserved = if iprop {
        proc > IPROP_FULL_RESYNC_EXT
    } else {
        proc > CREATE_ALIAS || proc == SETV4KEY_PRINCIPAL
    };
    if unserved {
        rpc_log_bad_proc(iprop, addr, proc);
        return rpc_reply_accepted_verf(xid, Some(mic), PROC_UNAVAIL);
    }
    let service = kadm5_service_name(&gd.ctx);
    let who = Caller {
        client: &actor,
        service: &service,
        addr,
        flavor: FLAVOR_GSS,
    };
    let result = Zeroizing::new(
        match kadm5_or_iprop(
            ctx,
            &who,
            proc,
            kadm_args,
            gd.ctx.ticket_is_initial(),
            changepw_acceptor(&gd.ctx, expected_realm),
            iprop,
        ) {
            Ok(b) => b,
            Err(Error::GarbageArgs) => {
                return rpc_reply_accepted_verf(xid, Some(mic), GARBAGE_ARGS);
            }
            Err(Error::ProcUnavail) => {
                return rpc_reply_accepted_verf(xid, Some(mic), PROC_UNAVAIL);
            }
            Err(_) => return rpc_reply_accepted_verf(xid, Some(mic), SYSTEM_ERR),
        },
    );
    if !iprop {
        kadm5_log_op(proc, kadm_args, &who, &result);
    }
    match gd.svc {
        GSS_NONE => rpc_reply_gss_verf(xid, mic, &result),
        GSS_INTEGRITY => {
            let mut databody = Zeroizing::new(Vec::with_capacity(4 + result.len()));
            databody.extend_from_slice(&seq.to_be_bytes());
            databody.extend_from_slice(&result);
            match gd.ctx.get_mic(&databody) {
                Ok(checksum) => {
                    let size = opaque_len(databody.len()) + opaque_len(checksum.len());
                    let mut body = XdrW::with_capacity(size);
                    body.opaque(&databody);
                    body.opaque(&checksum);
                    let body = Zeroizing::new(body.b);
                    rpc_reply_gss_verf(xid, mic, &body)
                }
                Err(_) => rpc_reply_auth_error(xid, AUTH_FAILED),
            }
        }
        _ => {
            let mut inner = Zeroizing::new(Vec::with_capacity(4 + result.len()));
            inner.extend_from_slice(&seq.to_be_bytes());
            inner.extend_from_slice(&result);
            match gd.ctx.wrap_with_rrc(&inner, 0) {
                Ok(w) => rpc_reply_gss(xid, mic, &w),
                Err(_) => rpc_reply_auth_error(xid, AUTH_FAILED),
            }
        }
    }
}

pub(super) enum AgssAuth {
    Denied(u32),
    Replied(Vec<u8>),
    Dispatch(Vec<u8>),
}

fn agss_denied(addr: &str, why: u32, error: &str) -> AgssAuth {
    rpc_log_miscerr(addr, error);
    AgssAuth::Denied(why)
}

#[expect(clippy::too_many_arguments, reason = "over seven inputs after RpcCtx")]
pub(super) fn svcauth_gssapi(
    ctx: RpcCtx<'_>,
    agss: &mut Option<Agss>,
    xid: u32,
    proc: u32,
    cred: &[u8],
    verf: &[u8],
    args: &[u8],
    rcache: &ReplayCache,
    peer: &RpcPeer,
) -> AgssAuth {
    let addr = peer.addr();
    // MIT: `clean_client` (svc_auth_gssapi.c:894-918)
    let now = KerberosTime::now().unix_seconds();
    if agss.as_ref().is_some_and(|st| st.expires < now) {
        *agss = None;
    }
    if cred.is_empty() {
        return agss_denied(addr, AUTH_BADCRED, "empty client credentials");
    }
    let mut cr = XdrR::new(cred);
    let (Ok(version), Ok(auth_msg), Ok(client_handle)) = (cr.u32(), cr.bool(), cr.opaque()) else {
        return agss_denied(addr, AUTH_BADCRED, "protocol error in client credentials");
    };
    if version != AUTH_GSSAPI_CREDS_VERS {
        return agss_denied(addr, AUTH_BADCRED, "unsupported client credentials version");
    }
    tracing::debug!(
        event = krb5_log::events::ADMIN,
        component = "krb5-admin",
        outcome = "ok",
        detail = "auth_gssapi",
        proc,
        auth_msg,
        handle_len = client_handle.len(),
    );
    if auth_msg && proc == AUTH_GSSAPI_INIT {
        if !client_handle.is_empty() {
            return agss_denied(addr, AUTH_FAILED, "protocol error in client handle");
        }
        *agss = Some(Agss {
            ctx: None,
            handle: AGSS_HANDLE.to_vec(),
            seq: 0,
            expires: now.saturating_add(AGSS_INITIATION_TIMEOUT),
        });
    } else if client_handle.is_empty() {
        return agss_denied(addr, AUTH_FAILED, "protocol error in client credentials");
    } else if agss
        .as_ref()
        .is_none_or(|st| client_handle.get(..4) != Some(st.handle.as_slice()))
    {
        // MIT: `get_client` (svc_auth_gssapi.c:783-801)
        // MIT reads past a short handle; refused here.
        return agss_denied(addr, AUTH_BADCRED, "invalid client handle received");
    }
    let Some(st) = agss.as_mut() else {
        return agss_denied(addr, AUTH_BADCRED, "invalid client handle received");
    };
    if st.ctx.is_none() {
        return agss_init(ctx, st, xid, proc, auth_msg, args, rcache, peer);
    }
    let (auth, destroyed) = agss_established(st, xid, proc, auth_msg, verf, args, addr);
    if destroyed {
        *agss = None;
    }
    auth
}

/// Versions 3 and 4 bind to both IPv4 addresses.
/// Acceptor names: realm's kadmin/admin, kadmin/changepw.
#[expect(clippy::too_many_arguments, reason = "over seven inputs after RpcCtx")]
fn agss_init(
    ctx: RpcCtx<'_>,
    st: &mut Agss,
    xid: u32,
    proc: u32,
    auth_msg: bool,
    args: &[u8],
    rcache: &ReplayCache,
    peer: &RpcPeer,
) -> AgssAuth {
    let addr = peer.addr();
    if !auth_msg {
        return agss_denied(
            addr,
            AUTH_REJECTEDCRED,
            "protocol error on incomplete connection",
        );
    }
    if proc != AUTH_GSSAPI_INIT && proc != AUTH_GSSAPI_CONTINUE_INIT {
        return agss_denied(addr, AUTH_FAILED, "protocol error on incomplete connection");
    }
    let mut ar = XdrR::new(args);
    let (Ok(arg_ver), Ok(token)) = (ar.u32(), ar.opaque()) else {
        return agss_denied(addr, AUTH_BADCRED, "protocol error in procedure arguments");
    };
    let res_ver = match arg_ver {
        1 | 2 => {
            rpc_log_miscerr(addr, "Warning: Accepted old RPC protocol request");
            1
        }
        3 | 4 => arg_ver,
        _ => return agss_denied(addr, AUTH_BADCRED, "unsupported GSSAPI_INIT version"),
    };
    let bindings = if arg_ver >= 3 {
        let Some(local) = peer.local_inet() else {
            return agss_denied(addr, AUTH_FAILED, "cannot get local address");
        };
        Some(ChannelBindings {
            initiator_addrtype: GSS_C_AF_INET,
            initiator_address: peer.remote_inet().to_vec(),
            acceptor_addrtype: GSS_C_AF_INET,
            acceptor_address: local.to_vec(),
            application_data: Vec::new(),
        })
    } else {
        None
    };
    let accepted = accept_auth_gssapi(
        ctx.store,
        ctx.expected_realm,
        &token,
        bindings.as_ref(),
        rcache,
        ctx.conf,
    );
    let (mut gctx, out_tok) = match accepted {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                event = krb5_log::events::ADMIN,
                component = "krb5-admin",
                outcome = "error",
                error = %e,
                detail = "accept_sec_context",
            );
            let major = accept_major(&e);
            rpc_log_badauth(addr, major, &accept_minor_text(&e));
            return AgssAuth::Replied(init_res_reply(xid, res_ver, &st.handle, major, &[], &[]));
        }
    };
    let mut isn = [0u8; 4];
    if getrandom::getrandom(&mut isn).is_err() {
        return agss_denied(addr, AUTH_FAILED, "cannot generate initial sequence number");
    }
    let seq = u32::from_le_bytes(isn);
    let Ok(signed_isn) = gctx.wrap_integ(&seq.to_be_bytes()) else {
        return agss_denied(addr, AUTH_FAILED, "internal error sealing sequence number");
    };
    let token = out_tok.unwrap_or_default();
    let reply = init_res_reply(xid, res_ver, &st.handle, 0, &token, &signed_isn);
    st.expires = gctx.endtime().map_or_else(
        || {
            KerberosTime::now()
                .unix_seconds()
                .saturating_add(AGSS_INDEF_EXPIRE)
        },
        |end| end.saturating_add_signed(ctx.conf.clockskew),
    );
    st.ctx = Some(gctx);
    st.seq = seq;
    AgssAuth::Replied(reply)
}

fn accept_major(e: &krb5_gss::Error) -> u32 {
    match e {
        krb5_gss::Error::ChannelBindings => GSS_S_BAD_BINDINGS,
        krb5_gss::Error::Truncated => GSS_S_DEFECTIVE_TOKEN,
        _ => GSS_S_FAILURE,
    }
}

fn accept_minor_text(e: &krb5_gss::Error) -> String {
    if matches!(e, krb5_gss::Error::ChannelBindings) {
        "Unknown code 0".to_owned()
    } else {
        e.to_string()
    }
}

fn init_res_reply(
    xid: u32,
    version: u32,
    handle: &[u8],
    major: u32,
    token: &[u8],
    signed_isn: &[u8],
) -> Vec<u8> {
    let mut body = XdrW::default();
    encode_init_res(&mut body, version, handle, major, 0, token, signed_isn);
    rpc_reply_clear(xid, &body.b)
}

fn agss_established(
    st: &mut Agss,
    xid: u32,
    proc: u32,
    auth_msg: bool,
    verf: &[u8],
    args: &[u8],
    addr: &str,
) -> (AgssAuth, bool) {
    let Some(gctx) = st.ctx.as_mut() else {
        return (
            agss_denied(
                addr,
                AUTH_REJECTEDCRED,
                "protocol error on incomplete connection",
            ),
            false,
        );
    };
    let seq = gctx
        .unwrap(verf)
        .ok()
        .and_then(|p| <[u8; 4]>::try_from(p.as_slice()).ok())
        .map(u32::from_be_bytes);
    let Some(seq) = seq else {
        return (
            agss_denied(
                addr,
                AUTH_BADVERF,
                "internal error unsealing sequence number",
            ),
            false,
        );
    };
    if seq != st.seq.wrapping_add(1) {
        let server = kadm5_service_name(gctx);
        rpc_log_badverf(proc, gctx.client.as_deref(), Some(&server), addr);
        return (AgssAuth::Denied(AUTH_REJECTEDVERF), false);
    }
    st.seq = seq;
    let Ok(reply_verf) = gctx.wrap_integ(&seq.wrapping_add(1).to_be_bytes()) else {
        return (
            agss_denied(addr, AUTH_FAILED, "internal error sealing sequence number"),
            false,
        );
    };
    st.seq = seq.wrapping_add(1);
    if !auth_msg {
        return (AgssAuth::Dispatch(reply_verf), false);
    }
    match proc {
        AUTH_GSSAPI_MSG => {
            let decoded = agss_unwrap_args(gctx, seq, args).is_some_and(|plain| {
                let mut ar = XdrR::new(plain.get(4..).unwrap_or_default());
                ar.u32().is_ok() && ar.opaque().is_ok()
            });
            if !decoded {
                return (
                    agss_denied(addr, AUTH_BADCRED, "protocol error in call arguments"),
                    false,
                );
            }
            (AgssAuth::Denied(AUTH_FAILED), false)
        }
        AUTH_GSSAPI_DESTROY => {
            let reply = agss_result(gctx, st.seq, xid, &reply_verf, &[])
                .unwrap_or_else(|| rpc_reply_agss_status(xid, &reply_verf, SYSTEM_ERR));
            (AgssAuth::Replied(reply), true)
        }
        _ => (
            agss_denied(addr, AUTH_FAILED, "invalid call procedure number"),
            false,
        ),
    }
}

// MIT: `auth_gssapi_unwrap_data` (auth_gssapi_misc.c:264-339)
/// Sealed opaque; opens with the call's sequence.
fn agss_unwrap_args(
    gctx: &mut GssContext,
    call_seq: u32,
    args: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let wrapped = XdrR::new(args).opaque().ok()?;
    let plain = Zeroizing::new(gctx.unwrap(&wrapped).ok()?);
    (plain.get(..4) == Some(call_seq.to_be_bytes().as_slice())).then_some(plain)
}

// MIT: `auth_gssapi_wrap_data` (auth_gssapi_misc.c:196-262)
/// Sequence, then the result, sealed as one opaque.
fn agss_result(
    gctx: &mut GssContext,
    seq: u32,
    xid: u32,
    reply_verf: &[u8],
    result: &[u8],
) -> Option<Vec<u8>> {
    let mut inner = Zeroizing::new(Vec::with_capacity(4 + result.len()));
    inner.extend_from_slice(&seq.to_be_bytes());
    inner.extend_from_slice(result);
    let wrap = gctx.wrap_with_rrc(&inner, 0).ok()?;
    let mut body = XdrW::with_capacity(opaque_len(wrap.len()));
    body.opaque(&wrap);
    Some(rpc_reply_agss(xid, reply_verf, &body.b))
}

/// Args that do not unseal or decode: GARBAGE_ARGS.
pub(super) fn agss_dispatch(
    ctx: RpcCtx<'_>,
    st: &mut Agss,
    xid: u32,
    proc: u32,
    args: &[u8],
    reply_verf: &[u8],
    addr: &str,
) -> Vec<u8> {
    let RpcCtx { expected_realm, .. } = ctx;
    let seq = st.seq;
    let Some(gctx) = st.ctx.as_mut() else {
        return rpc_reply_agss_status(xid, reply_verf, SYSTEM_ERR);
    };
    if proc == 0 {
        return agss_result(gctx, seq, xid, reply_verf, &[])
            .unwrap_or_else(|| rpc_reply_agss_status(xid, reply_verf, SYSTEM_ERR));
    }
    if proc > CREATE_ALIAS || proc == SETV4KEY_PRINCIPAL {
        crate::kadmind::admin_syslog(
            Severity::Err,
            &format!("Invalid KADM5 procedure number: {addr}, {proc}"),
        );
        return rpc_reply_agss_status(xid, reply_verf, PROC_UNAVAIL);
    }
    let Some(plain) = agss_unwrap_args(gctx, seq.wrapping_sub(1), args) else {
        return rpc_reply_agss_status(xid, reply_verf, GARBAGE_ARGS);
    };
    let kadm_args = plain.get(4..).unwrap_or_default();
    let Some(actor) = gctx.client.clone() else {
        return rpc_reply_weakauth(xid);
    };
    let service = kadm5_service_name(gctx);
    let who = Caller {
        client: &actor,
        service: &service,
        addr,
        flavor: FLAVOR_AUTH_GSSAPI,
    };
    // Result can carry keys.
    let result = Zeroizing::new(
        match kadm5_or_iprop(
            ctx,
            &who,
            proc,
            kadm_args,
            gctx.ticket_is_initial(),
            changepw_acceptor(gctx, expected_realm),
            false,
        ) {
            Ok(b) => b,
            Err(Error::GarbageArgs) => {
                return rpc_reply_agss_status(xid, reply_verf, GARBAGE_ARGS);
            }
            Err(Error::ProcUnavail) => {
                return rpc_reply_agss_status(xid, reply_verf, PROC_UNAVAIL);
            }
            Err(_) => return rpc_reply_agss_status(xid, reply_verf, SYSTEM_ERR),
        },
    );
    kadm5_log_op(proc, kadm_args, &who, &result);
    agss_result(gctx, seq, xid, reply_verf, &result).unwrap_or_else(|| {
        crate::kadmind::admin_syslog(
            Severity::Err,
            "WARNING! Unable to send function results, continuing.",
        );
        rpc_reply_agss_status(xid, reply_verf, SYSTEM_ERR)
    })
}

pub(super) fn encode_init_res(
    w: &mut XdrW,
    version: u32,
    handle: &[u8],
    major: u32,
    minor: u32,
    token: &[u8],
    signed_isn: &[u8],
) {
    w.u32(version);
    w.opaque(handle);
    w.u32(major);
    w.u32(minor);
    w.opaque(token);
    w.opaque(signed_isn);
}

pub(super) fn acceptor_realm_ok(
    acceptor: Option<&PrincipalName>,
    ticket_realm: Option<&str>,
    store_realm: &str,
    pred: impl Fn(&PrincipalName) -> bool,
) -> bool {
    ticket_realm == Some(store_realm) && acceptor.is_some_and(pred)
}

#[must_use]
pub fn changepw_acceptor(ctx: &GssContext, store_realm: &str) -> bool {
    acceptor_realm_ok(
        ctx.acceptor.as_ref(),
        ctx.ticket_realm.as_deref(),
        store_realm,
        kadm5_changepw_ok,
    )
}

fn acceptor_parts(n: &PrincipalName) -> Vec<String> {
    n.name_string
        .iter()
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
        .collect()
}

pub(super) fn kadm5_changepw_ok(n: &PrincipalName) -> bool {
    let p = acceptor_parts(n);
    p.len() == 2 && p[0] == "kadmin" && p[1] == "changepw"
}

pub(super) fn kadm5_auth_gssapi_ok(n: &PrincipalName) -> bool {
    let p = acceptor_parts(n);
    p.len() == 2 && p[0] == "kadmin" && (p[1] == "admin" || p[1] == "changepw")
}

pub(super) fn kadm5_rpcsec_ok(n: &PrincipalName) -> bool {
    let p = acceptor_parts(n);
    p.len() == 2 && p[0] == "kadmin" && p[1] != "history"
}

pub(super) fn iprop_rpcsec_ok(n: &PrincipalName) -> bool {
    let p = acceptor_parts(n);
    p.len() == 2 && p[0] == "kiprop"
}

#[must_use]
pub fn check_auth_gssapi_names(ctx: &GssContext, store_realm: &str) -> bool {
    acceptor_realm_ok(
        ctx.acceptor.as_ref(),
        ctx.ticket_realm.as_deref(),
        store_realm,
        kadm5_auth_gssapi_ok,
    )
}

#[must_use]
pub fn check_rpcsec_auth(ctx: &GssContext, store_realm: &str) -> bool {
    acceptor_realm_ok(
        ctx.acceptor.as_ref(),
        ctx.ticket_realm.as_deref(),
        store_realm,
        kadm5_rpcsec_ok,
    )
}

#[must_use]
pub fn check_iprop_rpcsec_auth(ctx: &GssContext, store_realm: &str) -> bool {
    acceptor_realm_ok(
        ctx.acceptor.as_ref(),
        ctx.ticket_realm.as_deref(),
        store_realm,
        iprop_rpcsec_ok,
    )
}
