//! Authentication flavors on the kadm5 and iprop programs: AUTH_GSSAPI
//! (`lib/rpc/svc_auth_gssapi.c`), RPCSEC_GSS (`svc_auth_gss.c`, RFC 2203
//! sequence window) and the acceptor-name checks of `kadm_rpc_svc.c`
//! (`check_rpcsec_auth`, `KADM5_CHANGEPW_SERVICE`). A context is bound to
//! the realm the ticket named, and the acceptor must be the kadmin or
//! kiprop service of that realm before any procedure runs.

use krb5_crypto::ProtocolKey;
use krb5_gss::GssContext;
use krb5_kdc::{Acl, SharedDump as SharedStore};
use krb5_protocol::ReplayCache;
use krb5_types::PrincipalName;

use super::codes::{
    AUTH_BADCRED, AUTH_FAILED, AUTH_GSSAPI_CONTINUE_INIT, AUTH_GSSAPI_CREDS_VERS,
    AUTH_GSSAPI_DESTROY, AUTH_GSSAPI_INIT, AUTH_REJECTEDCRED, GARBAGE_ARGS, GSS_INTEGRITY,
    GSS_NONE, GSS_PRIVACY, IPROP_VERS, KADM_VERS, MAXSEQ, PROC_UNAVAIL, PROG_UNAVAIL,
    RPCSEC_GSS_CREDPROBLEM, RPCSEC_GSS_CTXPROBLEM, RPCSEC_GSS_VERS, RPCSEC_SEQ_WINDOW,
    RPG_CONTINUE, RPG_DATA, RPG_DESTROY, RPG_INIT, SYSTEM_ERR,
};
use super::dispatch::kadm5_or_iprop;
use super::log::kadm5_log_op;
use super::rpc::{
    parse_gcred, rpc_reply_accepted, rpc_reply_accepted_verf, rpc_reply_agss, rpc_reply_auth_error,
    rpc_reply_clear, rpc_reply_gss, rpc_reply_gss_verf, rpc_reply_mismatch_verf,
    rpc_reply_weakauth,
};
use super::xdr::{XdrR, XdrW};
use crate::Error;

pub(super) struct Agss {
    pub(super) ctx: GssContext,
    established: bool,
    pub(super) handle: Vec<u8>,
    pub(super) seq: u32,
}

pub(super) struct RpcsecGss {
    pub(super) ctx: GssContext,
    seqlast: u32,
    seqmask: u32,
    pub(super) svc: u32,
}

#[allow(clippy::too_many_arguments, clippy::unnecessary_wraps)]
pub(super) fn handle_rpcsec_gss(
    store: &SharedStore,
    acl: &Acl,
    service_keys: &[ProtocolKey],
    expected_realm: &str,
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
            let Ok((mut ctx, out_tok)) = GssContext::accept_sec_context(
                &token,
                service_keys,
                None,
                None,
                Some(expected_realm),
                rcache,
            ) else {
                return Ok(rpc_reply_auth_error(xid, AUTH_REJECTEDCRED));
            };
            let mut body = XdrW::default();
            body.opaque(handle);
            body.u32(0);
            body.u32(0);
            body.u32(RPCSEC_SEQ_WINDOW);
            body.opaque(out_tok.as_deref().unwrap_or(&[]));
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
            let Some(gd) = gss.as_mut() else {
                return Ok(rpc_reply_auth_error(xid, RPCSEC_GSS_CREDPROBLEM));
            };
            // MIT does not compare gc_handle (svc_auth_gss.c); the per-connection
            // context and the header MIC authenticate the request.
            if gd.ctx.verify_mic(&rec[..header_end], verf).is_err() {
                return Ok(rpc_reply_auth_error(xid, RPCSEC_GSS_CREDPROBLEM));
            }
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
            let kadm_args = match gd.svc {
                GSS_NONE => r.rest().to_vec(),
                GSS_INTEGRITY => {
                    let (Ok(databody), Ok(checksum)) = (r.opaque(), r.opaque()) else {
                        return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                    };
                    if gd.ctx.verify_mic(&databody, &checksum).is_err()
                        || databody.get(..4) != Some(gcred.seq_num.to_be_bytes().as_slice())
                    {
                        return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                    }
                    databody[4..].to_vec()
                }
                _ => {
                    let Ok(wrapped) = r.opaque() else {
                        return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                    };
                    // rpc_gss_svc_privacy: the body must be sealed
                    // (authgss_prot.c:238-240 rejects conf_state != TRUE).
                    let Ok((plain, conf)) = gd.ctx.unwrap_conf(&wrapped) else {
                        return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                    };
                    if !conf || plain.len() < 4 {
                        return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                    }
                    plain[4..].to_vec()
                }
            };
            Ok(rpcsec_dispatch(
                store,
                acl,
                gd,
                xid,
                proc,
                &kadm_args,
                iprop,
                expected_realm,
                &mic,
                gcred.seq_num,
                addr,
            ))
        }
        RPG_DESTROY => {
            if proc != 0 {
                return Ok(rpc_reply_auth_error(xid, AUTH_FAILED));
            }
            let Some(gd) = gss.as_mut() else {
                return Ok(rpc_reply_auth_error(xid, RPCSEC_GSS_CREDPROBLEM));
            };
            if gd.ctx.verify_mic(&rec[..header_end], verf).is_err() {
                return Ok(rpc_reply_auth_error(xid, RPCSEC_GSS_CREDPROBLEM));
            }
            let mic = gd
                .ctx
                .get_mic(&gcred.seq_num.to_be_bytes())
                .unwrap_or_default();
            *gss = None;
            Ok(rpc_reply_gss_verf(xid, &mic, &[]))
        }
        _ => Ok(rpc_reply_auth_error(xid, AUTH_REJECTEDCRED)),
    }
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

#[allow(clippy::too_many_arguments)]
fn rpcsec_dispatch(
    store: &SharedStore,
    acl: &Acl,
    gd: &mut RpcsecGss,
    xid: u32,
    proc: u32,
    kadm_args: &[u8],
    iprop: bool,
    expected_realm: &str,
    mic: &[u8],
    seq: u32,
    addr: &str,
) -> Vec<u8> {
    let Some(actor) = gd.ctx.client.clone() else {
        return rpc_reply_weakauth(xid);
    };
    if iprop {
        if !check_iprop_rpcsec_auth(&gd.ctx, expected_realm) {
            return rpc_reply_weakauth(xid);
        }
    } else if !check_rpcsec_auth(&gd.ctx, expected_realm) {
        return rpc_reply_weakauth(xid);
    }
    let result = match kadm5_or_iprop(
        store,
        acl,
        &actor,
        proc,
        kadm_args,
        gd.ctx.ticket_is_initial(),
        changepw_acceptor(&gd.ctx, expected_realm),
        iprop,
    ) {
        Ok(b) => b,
        Err(Error::GarbageArgs) => return rpc_reply_accepted_verf(xid, Some(mic), GARBAGE_ARGS),
        Err(Error::ProcUnavail) => return rpc_reply_accepted_verf(xid, Some(mic), PROC_UNAVAIL),
        Err(_) => return rpc_reply_accepted_verf(xid, Some(mic), SYSTEM_ERR),
    };
    if !iprop {
        kadm5_log_op(proc, kadm_args, &actor, &gd.ctx, addr, &result);
    }
    match gd.svc {
        GSS_NONE => rpc_reply_gss_verf(xid, mic, &result),
        GSS_INTEGRITY => {
            let mut databody = Vec::with_capacity(4 + result.len());
            databody.extend_from_slice(&seq.to_be_bytes());
            databody.extend_from_slice(&result);
            match gd.ctx.get_mic(&databody) {
                Ok(checksum) => {
                    let mut body = XdrW::default();
                    body.opaque(&databody);
                    body.opaque(&checksum);
                    rpc_reply_gss_verf(xid, mic, &body.b)
                }
                Err(_) => rpc_reply_auth_error(xid, AUTH_FAILED),
            }
        }
        _ => {
            let mut inner = Vec::with_capacity(4 + result.len());
            inner.extend_from_slice(&seq.to_be_bytes());
            inner.extend_from_slice(&result);
            match gd.ctx.wrap_with_rrc(&inner, 0) {
                Ok(w) => rpc_reply_gss(xid, mic, &w),
                Err(_) => rpc_reply_auth_error(xid, AUTH_FAILED),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_auth_gssapi(
    store: &SharedStore,
    acl: &Acl,
    service_keys: &[ProtocolKey],
    expected_realm: &str,
    agss: &mut Option<Agss>,
    xid: u32,
    proc: u32,
    iprop: bool,
    cred: &[u8],
    verf: &[u8],
    args: &[u8],
    rcache: &ReplayCache,
) -> Result<Vec<u8>, Error> {
    let mut cr = XdrR::new(cred);
    let version = cr.u32()?;
    let auth_msg = cr.bool()?;
    let client_handle = cr.opaque()?;
    if version != AUTH_GSSAPI_CREDS_VERS {
        return Err(Error::Inner("auth_gssapi creds version".into()));
    }
    tracing::info!(
        event = krb5_log::events::ADMIN,
        component = "krb5-admin",
        outcome = "ok",
        detail = "auth_gssapi",
        proc,
        auth_msg,
        handle_len = client_handle.len(),
    );

    if auth_msg && (proc == AUTH_GSSAPI_INIT || proc == AUTH_GSSAPI_CONTINUE_INIT) {
        // svc_auth_gssapi.c:308-315: an undecodable `authgssapi_init_arg`
        // is AUTH_BADCRED ("protocol error in procedure arguments").
        let mut ar = XdrR::new(args);
        let (Ok(arg_ver), Ok(token)) = (ar.u32(), ar.opaque()) else {
            tracing::warn!(
                event = krb5_log::events::ADMIN,
                component = "krb5-admin",
                outcome = "denied",
                detail = "protocol error in procedure arguments",
            );
            return Ok(rpc_reply_auth_error(xid, AUTH_BADCRED));
        };
        // svc_auth_gssapi.c:326-341: the init-arg version switch. 1 and 2
        // are the OpenVision protocol — answered with `call_res.version`
        // 1 and a compat warning; 3 and 4 are echoed; anything else is
        // AUTH_BADCRED ("unsupported GSSAPI_INIT version"). The version
        // is settled before the token is looked at, so a bad version is
        // refused even when the token would not have verified.
        let res_ver = match arg_ver {
            1 | 2 => {
                tracing::warn!(
                    event = krb5_log::events::ADMIN,
                    component = "krb5-admin",
                    outcome = "ok",
                    detail = "Warning: Accepted old RPC protocol request",
                    arg_ver,
                );
                1
            }
            3 | 4 => arg_ver,
            _ => {
                tracing::warn!(
                    event = krb5_log::events::ADMIN,
                    component = "krb5-admin",
                    outcome = "denied",
                    detail = "unsupported GSSAPI_INIT version",
                    arg_ver,
                );
                return Ok(rpc_reply_auth_error(xid, AUTH_BADCRED));
            }
        };
        let (ctx, out_tok) = match GssContext::accept_sec_context(
            &token,
            service_keys,
            None,
            None,
            Some(expected_realm),
            rcache,
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    event = krb5_log::events::ADMIN,
                    component = "krb5-admin",
                    outcome = "error",
                    error = %e,
                    detail = "accept_sec_context",
                );
                let mut body = XdrW::default();
                encode_init_res(&mut body, res_ver, &[], 1, 0, &[], &[]);
                return Ok(rpc_reply_clear(xid, &body.b));
            }
        };
        if !iprop && !check_auth_gssapi_names(&ctx, expected_realm) {
            return Ok(rpc_reply_weakauth(xid));
        }
        let mut isn = [0u8; 4];
        let _ = getrandom::getrandom(&mut isn);
        let seq = u32::from_le_bytes(isn);
        let handle = 1u32.to_le_bytes().to_vec();
        let mut ctx = ctx;
        let signed = ctx
            .wrap_integ(&seq.to_be_bytes())
            .map_err(|e| Error::Inner(format!("seal isn: {e}")))?;
        let tok = out_tok.unwrap_or_default();
        *agss = Some(Agss {
            ctx,
            established: true,
            handle: handle.clone(),
            seq,
        });
        let mut body = XdrW::default();
        encode_init_res(&mut body, res_ver, &handle, 0, 0, &tok, &signed);
        return Ok(rpc_reply_clear(xid, &body.b));
    }

    let Some(st) = agss.as_mut() else {
        return Ok(rpc_reply_auth_error(xid, AUTH_FAILED));
    };
    if !client_handle.is_empty() && client_handle != st.handle {
        return Err(Error::Inner("auth_gssapi handle".into()));
    }
    if auth_msg && proc == AUTH_GSSAPI_DESTROY {
        *agss = None;
        return Ok(rpc_reply_clear(xid, &[]));
    }
    if iprop {
        return Ok(rpc_reply_weakauth(xid));
    }

    if !st.established {
        return Err(Error::Inner("auth_gssapi incomplete".into()));
    }

    // Verifier is gss_seal(conf=0) of htonl(expected seq).
    let got = st
        .ctx
        .unwrap(verf)
        .map_err(|e| Error::Inner(format!("unseal seq: {e}")))?;
    if got.len() != 4 {
        return Err(Error::Inner("unseal seq len".into()));
    }
    let mut seqb = [0u8; 4];
    seqb.copy_from_slice(&got);
    let got_seq = u32::from_be_bytes(seqb);
    if got_seq != st.seq.wrapping_add(1) {
        return Err(Error::Inner(format!(
            "auth_gssapi seq {} want {}",
            got_seq,
            st.seq.wrapping_add(1)
        )));
    }
    st.seq = st.seq.wrapping_add(1);
    let req_seq = st.seq;
    let reply_seq = st.seq.wrapping_add(1);
    let reply_verf = st
        .ctx
        .wrap_integ(&reply_seq.to_be_bytes())
        .map_err(|e| Error::Inner(format!("seal reply seq: {e}")))?;
    st.seq = st.seq.wrapping_add(1);

    if auth_msg {
        return Ok(rpc_reply_agss(xid, &reply_verf, &[]));
    }

    let mut wr = XdrR::new(args);
    let wrapped = wr.opaque()?;
    let plain = st
        .ctx
        .unwrap(&wrapped)
        .map_err(|e| Error::Inner(format!("unwrap data: {e}")))?;
    if plain.len() < 4 {
        return Err(Error::Inner("wrap_data seq".into()));
    }
    let mut inner_seq = [0u8; 4];
    inner_seq.copy_from_slice(&plain[..4]);
    let inner_seq = u32::from_be_bytes(inner_seq);
    if inner_seq != req_seq {
        return Err(Error::Inner("wrap_data seq mismatch".into()));
    }
    let kadm_args = &plain[4..];
    let actor = st.ctx.client.clone().ok_or(Error::AclDenied)?;
    if !check_auth_gssapi_names(&st.ctx, expected_realm) {
        return Ok(rpc_reply_weakauth(xid));
    }
    let result = match kadm5_or_iprop(
        store,
        acl,
        &actor,
        proc,
        kadm_args,
        st.ctx.ticket_is_initial(),
        changepw_acceptor(&st.ctx, expected_realm),
        iprop,
    ) {
        Ok(b) => b,
        Err(Error::GarbageArgs) => return Ok(rpc_reply_accepted(xid, GARBAGE_ARGS)),
        Err(Error::ProcUnavail) => return Ok(rpc_reply_accepted(xid, PROC_UNAVAIL)),
        Err(e) => return Err(e),
    };
    let mut inner = Vec::with_capacity(4 + result.len());
    inner.extend_from_slice(&st.seq.to_be_bytes());
    inner.extend_from_slice(&result);
    let wrap = st
        .ctx
        .wrap_with_rrc(&inner, 0)
        .map_err(|e| Error::Inner(format!("wrap data: {e}")))?;
    let mut body = XdrW::default();
    body.opaque(&wrap);
    Ok(rpc_reply_agss(xid, &reply_verf, &body.b))
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

/// CHANGEPW_SERVICE: realm-qualified `kadmin/changepw` acceptor.
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

/// AUTH_GSSAPI acceptor names built with `params.realm`.
#[must_use]
pub fn check_auth_gssapi_names(ctx: &GssContext, store_realm: &str) -> bool {
    acceptor_realm_ok(
        ctx.acceptor.as_ref(),
        ctx.ticket_realm.as_deref(),
        store_realm,
        kadm5_auth_gssapi_ok,
    )
}

/// `kadm_rpc_svc.c` `check_rpcsec_auth`: realm-qualified kadm5 acceptor.
#[must_use]
pub fn check_rpcsec_auth(ctx: &GssContext, store_realm: &str) -> bool {
    acceptor_realm_ok(
        ctx.acceptor.as_ref(),
        ctx.ticket_realm.as_deref(),
        store_realm,
        kadm5_rpcsec_ok,
    )
}

/// iprop acceptor: realm-qualified `kiprop`.
#[must_use]
pub fn check_iprop_rpcsec_auth(ctx: &GssContext, store_realm: &str) -> bool {
    acceptor_realm_ok(
        ctx.acceptor.as_ref(),
        ctx.ticket_realm.as_deref(),
        store_realm,
        iprop_rpcsec_ok,
    )
}
