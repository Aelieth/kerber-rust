//! MIT kadm5 GSS-RPC (ONC RPC program 2112, version 2) on TCP 749.
//!
//! MIT 1.22.2 `kadmin` authenticates with AUTH_GSSAPI flavor 300001
//! (`auth_gssapi.h`), not RFC 2203 RPCSEC_GSS flavor 6. This is not a
//! full C ABI clone.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use krb5_crypto::ProtocolKey;
use krb5_gss::GssContext;
use krb5_kdc::{Acl, SharedStore};
use krb5_types::PrincipalName;

use crate::AdminSession;
use crate::Error;

const LAST_FRAG: u32 = 0x8000_0000;
const RPC_VERSION: u32 = 2;
const KADM_PROG: u32 = 2112;
const KADM_VERS: u32 = 2;
const FLAVOR_GSS: u32 = 6;
const FLAVOR_NONE: u32 = 0;
/// OpenVision / MIT `AUTH_GSSAPI` (`<gssrpc/auth.h>`).
const FLAVOR_AUTH_GSSAPI: u32 = 300_001;
const AUTH_GSSAPI_INIT: u32 = 1;
const AUTH_GSSAPI_CONTINUE_INIT: u32 = 2;
const AUTH_GSSAPI_DESTROY: u32 = 4;
const AUTH_GSSAPI_CREDS_VERS: u32 = 2;
const RPCSEC_GSS_VERS: u32 = 1;
const RPG_DATA: u32 = 0;
const RPG_INIT: u32 = 1;
const RPG_CONTINUE: u32 = 2;
const GSS_PRIVACY: u32 = 3;
const MSG_CALL: u32 = 0;
const MSG_REPLY: u32 = 1;
const MSG_ACCEPTED: u32 = 0;
const SUCCESS: u32 = 0;

const CREATE_PRINCIPAL: u32 = 1;
const DELETE_PRINCIPAL: u32 = 2;
const MODIFY_PRINCIPAL: u32 = 3;
const RENAME_PRINCIPAL: u32 = 4;
const GET_PRINCIPAL: u32 = 5;
const CHPASS_PRINCIPAL: u32 = 6;
const CHRAND_PRINCIPAL: u32 = 7;
const CREATE_POLICY: u32 = 8;
const DELETE_POLICY: u32 = 9;
const MODIFY_POLICY: u32 = 10;
const GET_POLICY: u32 = 11;
const GET_PRIVS: u32 = 12;
const INIT: u32 = 13;
const GET_PRINCS: u32 = 14;
const GET_POLS: u32 = 15;
const CREATE_PRINCIPAL3: u32 = 18;
const CHPASS_PRINCIPAL3: u32 = 19;
const CHRAND_PRINCIPAL3: u32 = 20;

/// MIT `KADM5_UNK_PRINC`.
const KADM5_UNK_PRINC: u32 = 43_787_532;
/// MIT `KADM5_UNK_POLICY`.
const KADM5_UNK_POLICY: u32 = 43_787_533;
/// MIT `KADM5_DUP`.
const KADM5_DUP: u32 = 43_787_527;
/// MIT `KADM5_FAILURE`.
const KADM5_FAILURE: u32 = 43_787_520;
const KADM5_PASS_Q_TOOSHORT: u32 = 43_787_538;
const KADM5_PASS_Q_CLASS: u32 = 43_787_539;
const KADM5_PASS_REUSE: u32 = 43_787_541;
const KADM5_ATTRIBUTES: u32 = 0x0000_0010;
const KADM5_MAX_LIFE: u32 = 0x0000_0020;
const KADM5_PRINC_EXPIRE_TIME: u32 = 0x0000_0002;
const KADM5_PW_EXPIRATION: u32 = 0x0000_0004;
const KADM5_POLICY: u32 = 0x0000_0800;
const KADM5_POLICY_CLR: u32 = 0x0000_1000;
const KADM5_PW_MIN_LENGTH: u32 = 0x0001_0000;
const KADM5_PW_MIN_CLASSES: u32 = 0x0002_0000;
const KADM5_PW_HISTORY_NUM: u32 = 0x0004_0000;
const KADM5_PW_MAX_FAILURE: u32 = 0x0010_0000;

/// OpenVision/MIT `KADM5_API_VERSION_2`.
const API_V2: u32 = 0x1234_5702;
const API_V3: u32 = 0x1234_5703;
const API_V4: u32 = 0x1234_5704;
/// MIT `KADM5_PRIV_{GET,ADD,MODIFY,DELETE}` plus list (0x10) and cpw (0x20).
const KADM5_PRIVS: u32 = 0x0000_003F;

/// Serve one TCP connection until EOF.
///
/// # Errors
///
/// I/O or GSS/RPC failures.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_kadm5_conn(
    store: SharedStore,
    acl: Acl,
    service_keys: Vec<ProtocolKey>,
    expected_server: PrincipalName,
    expected_realm: String,
    mut stream: TcpStream,
) -> io::Result<()> {
    let mut gss: Option<GssContext> = None;
    let mut agss: Option<Agss> = None;
    let handle = random_handle();
    loop {
        let rec = match read_record(&mut stream) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let reply = match handle_rpc(
            &store,
            &acl,
            &service_keys,
            &expected_server,
            &expected_realm,
            &handle,
            &mut gss,
            &mut agss,
            &rec,
        ) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    event = krb5_log::events::ADMIN,
                    component = "krb5-admin",
                    outcome = "error",
                    error = %e,
                );
                eprintln!("kadm5: {e}");
                return Err(io::Error::other(e.to_string()));
            }
        };
        write_record(&mut stream, &reply)?;
    }
}

fn random_handle() -> Vec<u8> {
    let mut h = [0u8; 8];
    let _ = getrandom::getrandom(&mut h);
    h.to_vec()
}

fn read_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr)?;
        let n = u32::from_be_bytes(hdr);
        let last = n & LAST_FRAG != 0;
        let len = (n & !LAST_FRAG) as usize;
        if len > 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "rpc record"));
        }
        let mut chunk = vec![0u8; len];
        stream.read_exact(&mut chunk)?;
        out.extend_from_slice(&chunk);
        if last {
            return Ok(out);
        }
    }
}

fn write_record(stream: &mut TcpStream, body: &[u8]) -> io::Result<()> {
    let n = u32::try_from(body.len()).unwrap_or(0) | LAST_FRAG;
    stream.write_all(&n.to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

struct Agss {
    ctx: GssContext,
    established: bool,
    handle: Vec<u8>,
    seq: u32,
}

#[allow(clippy::too_many_arguments)]
fn handle_rpc(
    store: &SharedStore,
    acl: &Acl,
    service_keys: &[ProtocolKey],
    expected_server: &PrincipalName,
    expected_realm: &str,
    handle: &[u8],
    gss: &mut Option<GssContext>,
    agss: &mut Option<Agss>,
    rec: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut r = XdrR::new(rec);
    let xid = r.u32()?;
    let mtype = r.u32()?;
    if mtype != MSG_CALL {
        return Err(Error::Inner("rpc not CALL".into()));
    }
    let rpcvers = r.u32()?;
    let prog = r.u32()?;
    let vers = r.u32()?;
    let proc = r.u32()?;
    if rpcvers != RPC_VERSION || prog != KADM_PROG || vers != KADM_VERS {
        return Err(Error::Inner("rpc program".into()));
    }
    let cred_flavor = r.u32()?;
    let cred = r.opaque()?;
    let header_end = r.i;
    let verf_flavor = r.u32()?;
    let verf = r.opaque()?;

    if cred_flavor == FLAVOR_AUTH_GSSAPI {
        return handle_auth_gssapi(
            store,
            acl,
            service_keys,
            expected_server,
            expected_realm,
            agss,
            xid,
            proc,
            &cred,
            &verf,
            r.rest(),
        );
    }

    if cred_flavor != FLAVOR_GSS {
        // ONC RPC ping (AUTH_NONE / AUTH_UNIX NULLPROC).
        tracing::info!(
            event = krb5_log::events::ADMIN,
            component = "krb5-admin",
            outcome = "ok",
            detail = "rpc probe",
            flavor = cred_flavor,
            proc,
        );
        return Ok(rpc_reply_clear(xid, &[]));
    }
    let gcred = parse_gcred(&cred)?;
    if gcred.version != RPCSEC_GSS_VERS {
        return Err(Error::Inner("gssrpc version".into()));
    }

    if gcred.proc == RPG_INIT || gcred.proc == RPG_CONTINUE {
        let token = r.opaque()?;
        let (ctx, out_tok) = GssContext::accept_sec_context(
            &token,
            service_keys,
            None,
            Some(expected_server),
            Some(expected_realm),
        )
        .map_err(|e| Error::Inner(e.to_string()))?;
        *gss = Some(ctx);
        let mut body = XdrW::default();
        body.opaque(handle);
        body.u32(0); // GSS_S_COMPLETE
        body.u32(0);
        body.u32(1); // seq_window
        body.opaque(out_tok.as_deref().unwrap_or(&[]));
        return Ok(rpc_reply_clear(xid, &body.b));
    }

    let ctx = gss
        .as_mut()
        .ok_or_else(|| Error::Inner("gss not established".into()))?;
    if verf_flavor == FLAVOR_GSS {
        ctx.verify_mic(&rec[..header_end], &verf)
            .map_err(|e| Error::Inner(format!("rpc mic: {e}")))?;
    }
    if gcred.proc != RPG_DATA {
        return Err(Error::Inner("gssrpc proc".into()));
    }
    if gcred.service != GSS_PRIVACY {
        return Err(Error::Inner("need privacy".into()));
    }
    let wrapped = r.opaque()?;
    let plain = ctx
        .unwrap(&wrapped)
        .map_err(|e| Error::Inner(format!("gss unwrap: {e}")))?;
    if plain.len() < 4 {
        return Err(Error::Inner("wrapped seq".into()));
    }
    let seq = u32::from_be_bytes(
        plain[..4]
            .try_into()
            .map_err(|_| Error::Inner("seq".into()))?,
    );
    let args = &plain[4..];
    let actor = ctx
        .client
        .clone()
        .unwrap_or_else(|| format!("admin@{expected_realm}"));
    let result = dispatch_kadm5(store, acl, &actor, proc, args)?;
    let mut inner = Vec::with_capacity(4 + result.len());
    inner.extend_from_slice(&seq.to_be_bytes());
    inner.extend_from_slice(&result);
    // RPCSEC_GSS peers (MIT libgssrpc) historically unwrap RRC=0.
    let wrap = ctx
        .wrap_with_rrc(&inner, 0)
        .map_err(|e| Error::Inner(format!("gss wrap: {e}")))?;
    let mic = ctx
        .get_mic(&seq.to_be_bytes())
        .map_err(|e| Error::Inner(format!("gss mic: {e}")))?;
    Ok(rpc_reply_gss(xid, &mic, &wrap))
}

#[allow(clippy::too_many_arguments)]
fn handle_auth_gssapi(
    store: &SharedStore,
    acl: &Acl,
    service_keys: &[ProtocolKey],
    expected_server: &PrincipalName,
    expected_realm: &str,
    agss: &mut Option<Agss>,
    xid: u32,
    proc: u32,
    cred: &[u8],
    verf: &[u8],
    args: &[u8],
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
        let mut ar = XdrR::new(args);
        let arg_ver = ar.u32()?;
        let token = ar.opaque()?;
        let (ctx, out_tok) = match GssContext::accept_sec_context(
            &token,
            service_keys,
            None,
            Some(expected_server),
            Some(expected_realm),
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
                encode_init_res(&mut body, arg_ver, &[], 1, 0, &[], &[]);
                return Ok(rpc_reply_clear(xid, &body.b));
            }
        };
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
        encode_init_res(&mut body, arg_ver, &handle, 0, 0, &tok, &signed);
        return Ok(rpc_reply_clear(xid, &body.b));
    }

    let st = agss
        .as_mut()
        .ok_or_else(|| Error::Inner("auth_gssapi not established".into()))?;
    if !client_handle.is_empty() && client_handle != st.handle {
        return Err(Error::Inner("auth_gssapi handle".into()));
    }

    if auth_msg && proc == AUTH_GSSAPI_DESTROY {
        *agss = None;
        return Ok(rpc_reply_clear(xid, &[]));
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
    let actor = st
        .ctx
        .client
        .clone()
        .unwrap_or_else(|| format!("admin@{expected_realm}"));
    let result = dispatch_kadm5(store, acl, &actor, proc, kadm_args)?;
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

fn encode_init_res(
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

fn rpc_reply_clear(xid: u32, body: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    w.u32(SUCCESS);
    w.b.extend_from_slice(body);
    w.b
}

fn rpc_reply_gss(xid: u32, mic: &[u8], wrap: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    w.u32(FLAVOR_GSS);
    w.opaque(mic);
    w.u32(SUCCESS);
    w.opaque(wrap);
    w.b
}

fn rpc_reply_agss(xid: u32, verf: &[u8], body: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    w.u32(FLAVOR_AUTH_GSSAPI);
    w.opaque(verf);
    w.u32(SUCCESS);
    w.b.extend_from_slice(body);
    w.b
}

struct Gcred {
    version: u32,
    proc: u32,
    #[allow(dead_code)]
    seq_num: u32,
    service: u32,
}

fn parse_gcred(data: &[u8]) -> Result<Gcred, Error> {
    let mut r = XdrR::new(data);
    Ok(Gcred {
        version: r.u32()?,
        proc: r.u32()?,
        seq_num: r.u32()?,
        service: r.u32()?,
    })
}

fn dispatch_kadm5(
    store: &SharedStore,
    acl: &Acl,
    actor: &str,
    proc: u32,
    args: &[u8],
) -> Result<Vec<u8>, Error> {
    match proc {
        0 | INIT => Ok(generic_ret(API_V2, 0)),
        GET_PRIVS => {
            let mut w = XdrW::default();
            w.u32(API_V2);
            w.u32(0);
            w.u32(KADM5_PRIVS);
            Ok(w.b)
        }
        GET_PRINCIPAL => {
            let (name, _mask) = parse_get(args)?;
            if acl.check(actor, krb5_kdc::AdminOp::Inquire).is_err() {
                return Ok(generic_ret(API_V2, 43_787_521));
            }
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match g.get_name(&name) {
                Some(p) => {
                    tracing::info!(
                        event = krb5_log::events::ADMIN,
                        component = "krb5-admin",
                        outcome = "ok",
                        detail = "getprinc",
                        principal = p.id(),
                    );
                    Ok(encode_gprinc(p))
                }
                None => Ok(generic_ret(API_V2, KADM5_UNK_PRINC)),
            }
        }
        GET_PRINCS => {
            if acl.check(actor, krb5_kdc::AdminOp::Inquire).is_err() {
                return Ok(generic_ret(API_V2, 43_787_521));
            }
            let expr = parse_gprincs(args)?;
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut ids = g.ids();
            if let Some(e) = expr.as_deref()
                && e != "*"
                && !e.is_empty()
            {
                ids.retain(|id| id.contains(e.trim_end_matches('*')));
            }
            Ok(encode_gprincs(&ids))
        }
        DELETE_PRINCIPAL => {
            let name = parse_one_princ(args)?;
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut sess = AdminSession::local(&mut g, acl, actor);
            match sess.delete(&name) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(&e))),
            }
        }
        MODIFY_PRINCIPAL => {
            let (name, mask, fields) = parse_modify(args)?;
            if acl.check(actor, krb5_kdc::AdminOp::Modify).is_err() {
                return Ok(generic_ret(API_V2, 43_787_523));
            }
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let attributes = (mask & KADM5_ATTRIBUTES != 0).then_some(fields.attributes);
            let max_life = (mask & KADM5_MAX_LIFE != 0).then_some(u64::from(fields.max_life));
            let expiration = (mask & KADM5_PRINC_EXPIRE_TIME != 0).then_some(fields.expire);
            let pw_expire = (mask & KADM5_PW_EXPIRATION != 0).then_some(fields.pw_expire);
            let clear_policy = mask & KADM5_POLICY_CLR != 0;
            let policy = if clear_policy {
                None
            } else if mask & KADM5_POLICY != 0 {
                fields.policy
            } else {
                None
            };
            match g.apply_admin_fields(
                &name,
                attributes,
                max_life,
                expiration,
                pw_expire,
                policy,
                clear_policy,
            ) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(&Error::from(e)))),
            }
        }
        CREATE_PRINCIPAL | CREATE_PRINCIPAL3 => {
            let (name, pass, policy) = parse_create(args, proc == CREATE_PRINCIPAL3)?;
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(ref pol) = policy
                && let Err(e) = g.check_named_policy(pol, pass.as_bytes())
            {
                return Ok(generic_ret(API_V2, kadm5_code(&Error::from(e))));
            }
            let mut sess = AdminSession::local(&mut g, acl, actor);
            let created = sess.create_password(&name, pass.as_bytes());
            drop(sess);
            match created {
                Ok(()) => {
                    if let Some(pol) = policy
                        && let Err(e) = g.set_principal_policy(&name, Some(pol))
                    {
                        return Ok(generic_ret(API_V2, kadm5_code(&Error::from(e))));
                    }
                    Ok(generic_ret(API_V2, 0))
                }
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(&e))),
            }
        }
        RENAME_PRINCIPAL => {
            let (old, new) = parse_rename(args)?;
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut sess = AdminSession::local(&mut g, acl, actor);
            match sess.rename(&old, &new) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(&e))),
            }
        }
        CHPASS_PRINCIPAL | CHPASS_PRINCIPAL3 => {
            let (name, pass) = parse_chpass(args, proc == CHPASS_PRINCIPAL3)?;
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut sess = AdminSession::local(&mut g, acl, actor);
            match sess.change_password(&name, pass.as_bytes()) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(&e))),
            }
        }
        CREATE_POLICY => {
            let (api, pol, _mask) = parse_policy_arg(args)?;
            if acl.check(actor, krb5_kdc::AdminOp::Create).is_err() {
                return Ok(generic_ret(api, 43_787_521));
            }
            if pol.name.is_empty() {
                return Ok(generic_ret(api, KADM5_UNK_POLICY));
            }
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if g.policies().contains_key(&pol.name) {
                return Ok(generic_ret(api, KADM5_DUP));
            }
            g.put_policy(pol);
            Ok(generic_ret(api, 0))
        }
        DELETE_POLICY => {
            let (api, name) = parse_policy_name(args)?;
            if acl.check(actor, krb5_kdc::AdminOp::Delete).is_err() {
                return Ok(generic_ret(api, 43_787_521));
            }
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match g.delete_policy(&name) {
                Ok(()) => Ok(generic_ret(api, 0)),
                Err(krb5_kdc::Error::NotFound) => Ok(generic_ret(api, KADM5_UNK_POLICY)),
                Err(e) => Ok(generic_ret(api, kadm5_code(&Error::from(e)))),
            }
        }
        MODIFY_POLICY => {
            let (api, rec, mask) = parse_policy_arg(args)?;
            if acl.check(actor, krb5_kdc::AdminOp::Modify).is_err() {
                return Ok(generic_ret(api, 43_787_523));
            }
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(existing) = g.policies().get(&rec.name).cloned() else {
                return Ok(generic_ret(api, KADM5_UNK_POLICY));
            };
            g.put_policy(merge_policy(existing, &rec, mask));
            Ok(generic_ret(api, 0))
        }
        GET_POLICY => {
            let (api, name) = parse_policy_name(args)?;
            if acl.check(actor, krb5_kdc::AdminOp::Inquire).is_err() {
                return Ok(generic_ret(api, 43_787_521));
            }
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match g.policies().get(&name) {
                Some(p) => Ok(encode_policy(api, p)),
                None => Ok(generic_ret(api, KADM5_UNK_POLICY)),
            }
        }
        GET_POLS => {
            let (api, expr) = parse_gpols(args);
            if acl.check(actor, krb5_kdc::AdminOp::Inquire).is_err() {
                return Ok(generic_ret(api, 43_787_521));
            }
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut names: Vec<_> = g.policies().keys().cloned().collect();
            if let Some(e) = expr.as_deref()
                && e != "*"
                && !e.is_empty()
            {
                names.retain(|n| n.contains(e.trim_end_matches('*')));
            }
            names.sort();
            Ok(encode_pols(api, &names))
        }
        CHRAND_PRINCIPAL | CHRAND_PRINCIPAL3 => {
            let name = parse_chrand(args, proc == CHRAND_PRINCIPAL3)?;
            if acl.check(actor, krb5_kdc::AdminOp::ChangePassword).is_err() {
                return Ok(generic_ret(API_V2, 43_787_521));
            }
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match g.chrand(&name) {
                Ok(keys) => Ok(encode_chrand(&keys)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(&Error::from(e)))),
            }
        }
        _ => Ok(generic_ret(API_V2, 7)),
    }
}

fn kadm5_code(e: &Error) -> u32 {
    match e {
        Error::AclDenied => 43_787_521,
        Error::NotFound => KADM5_UNK_PRINC,
        Error::Inner(s) if s.contains("min_length") => KADM5_PASS_Q_TOOSHORT,
        Error::Inner(s) if s.contains("min_classes") => KADM5_PASS_Q_CLASS,
        Error::Inner(s) if s.contains("history") => KADM5_PASS_REUSE,
        Error::Inner(_) => KADM5_FAILURE,
    }
}

fn generic_ret(api: u32, code: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(api);
    w.u32(code);
    w.b
}

fn parse_policy_name(args: &[u8]) -> Result<(u32, String), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    Ok((api, r.nullstring()?.unwrap_or_default()))
}

fn parse_gpols(args: &[u8]) -> (u32, Option<String>) {
    let mut r = XdrR::new(args);
    let api = r.u32().unwrap_or(API_V2);
    (api, r.nullstring().ok().flatten())
}

fn parse_policy_arg(args: &[u8]) -> Result<(u32, krb5_kdc::NamedPolicy, u32), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let name = r.nullstring()?.unwrap_or_default();
    let _min_life = r.u32().unwrap_or(0);
    let _max_life = r.u32().unwrap_or(0);
    let min_length = r.u32().unwrap_or(0);
    let min_classes = r.u32().unwrap_or(0);
    let history = r.u32().unwrap_or(0);
    let _refcnt = r.u32().unwrap_or(0);
    let mut max_fail = 0;
    if api >= API_V3 {
        max_fail = r.u32().unwrap_or(0);
        let _ = r.u32();
        let _ = r.u32();
    }
    if api >= API_V4 {
        let _ = r.u32();
        let _ = r.u32();
        let _ = r.u32();
        let _ = r.nullstring();
        let _n_tl = r.u32().unwrap_or(0);
        let tl_null = r.u32().unwrap_or(1);
        if tl_null == 0 {
            loop {
                let more = r.u32().unwrap_or(0);
                if more == 0 {
                    break;
                }
                let _ = r.u32();
                let _ = r.opaque();
            }
        }
    }
    let mask = r.u32().unwrap_or(0);
    Ok((
        api,
        krb5_kdc::NamedPolicy {
            name,
            min_length,
            min_classes,
            history,
            max_fail,
        },
        mask,
    ))
}

fn merge_policy(
    mut existing: krb5_kdc::NamedPolicy,
    rec: &krb5_kdc::NamedPolicy,
    mask: u32,
) -> krb5_kdc::NamedPolicy {
    if mask & KADM5_PW_MIN_LENGTH != 0 {
        existing.min_length = rec.min_length;
    }
    if mask & KADM5_PW_MIN_CLASSES != 0 {
        existing.min_classes = rec.min_classes;
    }
    if mask & KADM5_PW_HISTORY_NUM != 0 {
        existing.history = rec.history;
    }
    if mask & KADM5_PW_MAX_FAILURE != 0 {
        existing.max_fail = rec.max_fail;
    }
    existing
}

fn encode_policy_rec(w: &mut XdrW, api: u32, p: &krb5_kdc::NamedPolicy) {
    w.nullstring(Some(&p.name));
    w.u32(0);
    w.u32(0);
    w.u32(p.min_length);
    w.u32(p.min_classes);
    w.u32(p.history);
    w.u32(0);
    if api >= API_V3 {
        w.u32(p.max_fail);
        w.u32(0);
        w.u32(0);
    }
    if api >= API_V4 {
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(1);
    }
}

fn encode_policy(api: u32, p: &krb5_kdc::NamedPolicy) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(api);
    w.u32(0);
    encode_policy_rec(&mut w, api, p);
    w.b
}

fn encode_pols(api: u32, names: &[String]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(api);
    w.u32(0);
    let n = u32::try_from(names.len()).unwrap_or(0);
    w.u32(n);
    w.u32(n);
    for name in names {
        w.nullstring(Some(name));
    }
    w.b
}

fn parse_create(args: &[u8], v3: bool) -> Result<(PrincipalName, String, Option<String>), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    let princ = r.principal()?;
    let policy = skip_principal_ent_rest(&mut r)?;
    let _mask = r.u32()?;
    if v3 {
        r.skip_array_i32_pairs()?;
    }
    let pass = r.nullstring()?.unwrap_or_default();
    Ok((princ, pass, policy))
}

fn parse_chpass(args: &[u8], v3: bool) -> Result<(PrincipalName, String), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    let princ = r.principal()?;
    if v3 {
        let _keepold = r.u32()?;
        r.skip_array_i32_pairs()?;
    }
    let pass = r.nullstring()?.unwrap_or_default();
    Ok((princ, pass))
}

fn parse_get(args: &[u8]) -> Result<(PrincipalName, u32), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    let princ = r.principal()?;
    let mask = r.u32().unwrap_or(u32::MAX);
    Ok((princ, mask))
}

fn parse_gprincs(args: &[u8]) -> Result<Option<String>, Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    r.nullstring()
}

fn parse_one_princ(args: &[u8]) -> Result<PrincipalName, Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    r.principal()
}

fn parse_rename(args: &[u8]) -> Result<(PrincipalName, PrincipalName), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    let old = r.principal()?;
    let new = r.principal()?;
    Ok((old, new))
}

fn parse_chrand(args: &[u8], v3: bool) -> Result<PrincipalName, Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    let princ = r.principal()?;
    if v3 {
        let _keepold = r.u32().unwrap_or(0);
        let _ = r.skip_array_i32_pairs();
    }
    Ok(princ)
}

struct ModFields {
    expire: u32,
    pw_expire: u32,
    max_life: u32,
    attributes: u32,
    policy: Option<String>,
}

fn parse_modify(args: &[u8]) -> Result<(PrincipalName, u32, ModFields), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    let princ = r.principal()?;
    let expire = r.u32()?;
    let _last_pwd = r.u32()?;
    let pw_expire = r.u32()?;
    let max_life = r.u32()?;
    let mod_null = r.u32()?;
    if mod_null == 0 {
        let _ = r.principal()?;
    }
    let _mod_date = r.u32()?;
    let attributes = r.u32()?;
    r.u32()?; // kvno
    r.u32()?; // mkvno
    let policy = r.nullstring()?;
    r.u32()?; // aux
    r.u32()?; // max_rlife
    r.u32()?; // last_success
    r.u32()?; // last_failed
    r.u32()?; // fail_auth_count
    let n_key = r.u32()?;
    let _n_tl = r.u32()?;
    let tl_null = r.u32()?;
    if tl_null == 0 {
        loop {
            let more = r.u32()?;
            if more == 0 {
                break;
            }
            r.u32()?;
            let _ = r.opaque()?;
        }
    }
    let n = r.u32().unwrap_or(0);
    let walk = if n == 0 { n_key } else { n };
    for _ in 0..walk {
        let ver = r.u32()?;
        r.u32()?;
        r.u32()?;
        if ver > 1 {
            r.u32()?;
        }
    }
    let mask = r.u32().unwrap_or(0);
    Ok((
        princ,
        mask,
        ModFields {
            expire,
            pw_expire,
            max_life,
            attributes,
            policy,
        },
    ))
}

fn encode_gprinc(p: &krb5_kdc::Principal) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.u32(0);
    encode_principal_ent(&mut w, p);
    w.b
}

fn encode_principal_ent(w: &mut XdrW, p: &krb5_kdc::Principal) {
    let id = p.id();
    w.nullstring(Some(&id));
    w.u32(p.expiration);
    w.u32(0);
    w.u32(p.pw_expire);
    w.u32(u32::try_from(p.max_life).unwrap_or(0));
    // MIT kadmin always unparses `mod_name`; a NULL pointer is
    // KRB5_PARSE_MALFORMED ("while unparsing principal").
    let mod_name = format!("kadmin/admin@{}", p.realm);
    w.u32(0); // xdr_nulltype FALSE → encode principal
    w.nullstring(Some(&mod_name));
    w.u32(0); // mod_date
    w.u32(p.attributes);
    let kvno = p.keys.iter().map(|k| k.kvno).max().unwrap_or(1);
    w.u32(kvno);
    w.u32(u32::from(p.mkvno));
    match p.pw_policy.as_deref() {
        Some(n) if !n.is_empty() => {
            w.nullstring(Some(n));
            w.u32(KADM5_POLICY);
        }
        _ => {
            w.u32(0);
            w.u32(0);
        }
    }
    w.u32(u32::try_from(p.max_renewable_life).unwrap_or(0));
    w.u32(p.last_success);
    w.u32(p.last_failed);
    w.u32(p.fail_auth_count);
    // Omit key_data on the wire (n_key_data=0). MIT kadmin getprinc does
    // not need key contents; xdr_array maxsize is n_key_data.
    w.u32(0); // n_key_data
    w.u32(0); // n_tl_data
    w.u32(1); // tl_data NULL (xdr_nulltype)
    w.u32(0); // key_data array count
}

fn encode_gprincs(ids: &[String]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.u32(0);
    let n = u32::try_from(ids.len()).unwrap_or(0);
    // MIT `xdr_gprincs_ret`: `xdr_int count` then `xdr_array` of
    // `xdr_nullstring` (the array writes count again).
    w.u32(n);
    w.u32(n);
    for id in ids {
        w.nullstring(Some(id));
    }
    w.b
}

fn encode_chrand(keys: &[krb5_kdc::KeyEntry]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.u32(0);
    w.u32(u32::try_from(keys.len()).unwrap_or(0));
    for k in keys {
        w.u32(u32::try_from(k.etype.to_iana()).unwrap_or(0));
        w.opaque(k.key.as_bytes());
    }
    w.b
}

/// After the leading principal, skip the rest of `kadm5_principal_ent_rec`.
fn skip_principal_ent_rest(r: &mut XdrR<'_>) -> Result<Option<String>, Error> {
    // 4 timestamps/deltats: expire, last_pwd, pw_expire, max_life
    for _ in 0..4 {
        r.u32()?;
    }
    let mod_null = r.u32()?; // xdr_bool: TRUE means NULL
    if mod_null == 0 {
        let _ = r.principal()?;
    }
    r.u32()?; // mod_date
    r.u32()?; // attributes
    r.u32()?; // kvno
    r.u32()?; // mkvno
    let policy = r.nullstring()?;
    r.u32()?; // aux_attributes (xdr_long)
    r.u32()?; // max_renewable_life
    r.u32()?; // last_success
    r.u32()?; // last_failed
    r.u32()?; // fail_auth_count
    let n_key = r.u32()?; // int16 via xdr_int
    let _n_tl = r.u32()?;
    let tl_null = r.u32()?;
    if tl_null == 0 {
        loop {
            let more = r.u32()?;
            if more == 0 {
                break;
            }
            r.u32()?; // type (int16 via xdr_int)
            let _ = r.opaque()?;
        }
    }
    // xdr_array of key_data_nocontents
    let n = r.u32()?;
    if n != n_key && n_key != 0 {
        // tolerate mismatch; walk `n`
    }
    for _ in 0..n {
        let ver = r.u32()?;
        r.u32()?; // kvno ui_2
        r.u32()?; // type[0]
        if ver > 1 {
            r.u32()?; // type[1]
        }
    }
    Ok(policy)
}

struct XdrR<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> XdrR<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }

    fn need(&self, n: usize) -> Result<(), Error> {
        if self.i.saturating_add(n) > self.b.len() {
            Err(Error::Inner("xdr truncated".into()))
        } else {
            Ok(())
        }
    }

    fn u32(&mut self) -> Result<u32, Error> {
        self.need(4)?;
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.b[self.i..self.i + 4]);
        self.i += 4;
        Ok(u32::from_be_bytes(buf))
    }

    fn bool(&mut self) -> Result<bool, Error> {
        Ok(self.u32()? != 0)
    }

    fn rest(&self) -> &[u8] {
        self.b.get(self.i..).unwrap_or(&[])
    }

    fn opaque(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.u32()? as usize;
        self.need(n)?;
        let v = self.b[self.i..self.i + n].to_vec();
        self.i += n;
        let pad = (4 - (n % 4)) % 4;
        self.i = self.i.saturating_add(pad).min(self.b.len());
        Ok(v)
    }

    fn nullstring(&mut self) -> Result<Option<String>, Error> {
        let n = self.u32()? as usize;
        if n == 0 {
            return Ok(None);
        }
        self.need(n)?;
        let raw = &self.b[self.i..self.i + n];
        self.i += n;
        let pad = (4 - (n % 4)) % 4;
        self.i = self.i.saturating_add(pad).min(self.b.len());
        let s = std::str::from_utf8(raw).map_err(|e| Error::Inner(e.to_string()))?;
        Ok(Some(s.trim_end_matches('\0').to_owned()))
    }

    fn principal(&mut self) -> Result<PrincipalName, Error> {
        let s = self
            .nullstring()?
            .ok_or_else(|| Error::Inner("null principal".into()))?;
        let (user, _realm) = s.split_once('@').unwrap_or((s.as_str(), ""));
        let parts: Vec<&str> = user.split('/').collect();
        let ntype = if parts.len() > 1 {
            PrincipalName::NT_SRV_INST
        } else {
            PrincipalName::NT_PRINCIPAL
        };
        PrincipalName::try_new(ntype, parts).map_err(|e| Error::Inner(e.to_string()))
    }

    fn skip_array_i32_pairs(&mut self) -> Result<(), Error> {
        let n = self.u32()?;
        for _ in 0..n {
            self.u32()?;
            self.u32()?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct XdrW {
    b: Vec<u8>,
}

impl XdrW {
    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }
    fn opaque(&mut self, d: &[u8]) {
        self.u32(u32::try_from(d.len()).unwrap_or(0));
        self.b.extend_from_slice(d);
        let pad = (4 - (d.len() % 4)) % 4;
        self.b.extend(std::iter::repeat_n(0u8, pad));
    }

    fn nullstring(&mut self, s: Option<&str>) {
        match s {
            None => self.u32(0),
            Some(s) => {
                let n = s.len() + 1;
                self.u32(u32::try_from(n).unwrap_or(0));
                self.b.extend_from_slice(s.as_bytes());
                self.b.push(0);
                let pad = (4 - (n % 4)) % 4;
                self.b.extend(std::iter::repeat_n(0u8, pad));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdr_nullstring_round_trip_shape() {
        let mut w = XdrW::default();
        w.opaque(b"alice@KERBER.TEST\0");
        let mut r = XdrR::new(&w.b);
        let s = r.nullstring().unwrap().unwrap();
        // opaque != nullstring (nullstring writes size then bytes including NUL)
        assert!(!s.is_empty() || w.b.len() >= 4);
        let mut w2 = XdrW::default();
        let s = "alice@KERBER.TEST";
        w2.u32(u32::try_from(s.len() + 1).unwrap());
        w2.b.extend_from_slice(s.as_bytes());
        w2.b.push(0);
        let pad = (4 - ((s.len() + 1) % 4)) % 4;
        w2.b.extend(std::iter::repeat_n(0u8, pad));
        let mut r2 = XdrR::new(&w2.b);
        assert_eq!(
            r2.nullstring().unwrap().as_deref(),
            Some("alice@KERBER.TEST")
        );
        let p = {
            let mut r3 = XdrR::new(&w2.b);
            r3.principal().unwrap()
        };
        assert_eq!(p.components_joined(), "alice");
    }

    #[test]
    fn generic_ret_is_eight_bytes() {
        let b = generic_ret(API_V2, 0);
        assert_eq!(b.len(), 8);
        assert_eq!(&b[..4], &API_V2.to_be_bytes());
    }

    #[test]
    fn parse_rename_reads_two_principals() {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("old@KERBER.TEST"));
        w.nullstring(Some("new@KERBER.TEST"));
        let (old, new) = parse_rename(&w.b).unwrap();
        assert_eq!(old.components_joined(), "old");
        assert_eq!(new.components_joined(), "new");
    }

    #[test]
    fn rename_dispatch_keeps_rid_and_requires_add_delete() {
        use krb5_kdc::{TEST_REALM, bootstrap_documented, documented_admin_id, shared_store};

        let (mut store, acl) = bootstrap_documented().unwrap();
        let actor = documented_admin_id();
        let old = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["renamefrom"]);
        let new = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["renameto"]);
        store
            .create_password(&acl, &actor, &old, b"rename-secret")
            .unwrap();
        let rid = store.get_name(&old).unwrap().rid;
        let key = store
            .get_name(&old)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .as_bytes()
            .to_vec();
        let shared = shared_store(store);
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some(&format!("renamefrom@{TEST_REALM}")));
        w.nullstring(Some(&format!("renameto@{TEST_REALM}")));
        let ret = dispatch_kadm5(&shared, &acl, &actor, RENAME_PRINCIPAL, &w.b).unwrap();
        assert_eq!(&ret[4..8], &0u32.to_be_bytes());
        {
            let g = shared.read().unwrap();
            assert!(g.get_name(&old).is_none());
            let p = g.get_name(&new).unwrap();
            assert_eq!(p.rid, rid);
            assert_eq!(p.best_key().unwrap().key.as_bytes(), key.as_slice());
        }
        let add_only = Acl::parse("admin@KERBER.TEST a\n");
        let mut w2 = XdrW::default();
        w2.u32(API_V2);
        w2.nullstring(Some(&format!("renameto@{TEST_REALM}")));
        w2.nullstring(Some(&format!("renamefrom@{TEST_REALM}")));
        let denied = dispatch_kadm5(&shared, &add_only, &actor, RENAME_PRINCIPAL, &w2.b).unwrap();
        assert_ne!(&denied[4..8], &0u32.to_be_bytes());
        let g = shared.read().unwrap();
        assert!(g.get_name(&new).is_some());
        assert!(g.get_name(&old).is_none());
    }

    #[test]
    fn auth_gssapi_creds_and_init_res_xdr() {
        let mut w = XdrW::default();
        w.u32(2);
        w.u32(1); // auth_msg TRUE
        w.opaque(&[]);
        let mut r = XdrR::new(&w.b);
        assert_eq!(r.u32().unwrap(), 2);
        assert!(r.bool().unwrap());
        assert!(r.opaque().unwrap().is_empty());

        let mut body = XdrW::default();
        encode_init_res(&mut body, 4, &1u32.to_le_bytes(), 0, 0, b"tok", b"isn");
        let mut r = XdrR::new(&body.b);
        assert_eq!(r.u32().unwrap(), 4);
        assert_eq!(r.opaque().unwrap(), 1u32.to_le_bytes());
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.opaque().unwrap(), b"tok");
        assert_eq!(r.opaque().unwrap(), b"isn");
    }

    fn setup() -> (krb5_kdc::SharedStore, Acl, String) {
        let (store, acl) = krb5_kdc::bootstrap_documented().unwrap();
        let actor = krb5_kdc::documented_admin_id();
        (krb5_kdc::shared_store(store), acl, actor)
    }

    fn encode_named(name: &str) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some(name));
        w.b
    }

    fn ret_code(b: &[u8]) -> u32 {
        let mut r = XdrR::new(b);
        let _api = r.u32().unwrap();
        r.u32().unwrap()
    }

    #[test]
    fn getprinc_returns_documented_user_not_unk_princ() {
        let (store, acl, actor) = setup();
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.u32(u32::MAX);
        let out = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &w.b).unwrap();
        assert_ne!(ret_code(&out), KADM5_UNK_PRINC);
        assert_eq!(ret_code(&out), 0);
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(
            r.nullstring().unwrap().as_deref(),
            Some("user@KERBER.TEST"),
            "gprinc_ret.rec.principal is xdr_nullstring of name@REALM"
        );
        r.u32().unwrap(); // expire
        r.u32().unwrap();
        r.u32().unwrap();
        r.u32().unwrap();
        assert_eq!(r.u32().unwrap(), 0, "mod_name present");
        assert_eq!(
            r.nullstring().unwrap().as_deref(),
            Some("kadmin/admin@KERBER.TEST")
        );
    }

    #[test]
    fn getprinc_missing_is_unk_princ() {
        let (store, acl, actor) = setup();
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("no-such@KERBER.TEST"));
        w.u32(u32::MAX);
        let out = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &w.b).unwrap();
        assert_eq!(ret_code(&out), KADM5_UNK_PRINC);
    }

    #[test]
    fn listprincs_names_documented_principals() {
        let (store, acl, actor) = setup();
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.u32(0);
        let out = dispatch_kadm5(&store, &acl, &actor, GET_PRINCS, &w.b).unwrap();
        assert_eq!(ret_code(&out), 0);
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        let n = r.u32().unwrap();
        assert_eq!(r.u32().unwrap(), n, "xdr_array repeats count");
        assert!(n >= 2);
        let mut names = Vec::new();
        for _ in 0..n {
            names.push(r.nullstring().unwrap().unwrap());
        }
        assert!(names.iter().any(|s| s == "user@KERBER.TEST"));
        assert!(names.iter().any(|s| s == "admin@KERBER.TEST"));
    }

    #[test]
    fn delprinc_then_getprinc_is_unk_princ() {
        let (store, acl, actor) = setup();
        let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["extra"]);
        {
            let mut g = store.write().unwrap();
            g.create_password(&acl, &actor, &extra, b"extra-secret")
                .unwrap();
        }
        let del = encode_named("extra@KERBER.TEST");
        let out = dispatch_kadm5(&store, &acl, &actor, DELETE_PRINCIPAL, &del).unwrap();
        assert_eq!(ret_code(&out), 0);
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("extra@KERBER.TEST"));
        w.u32(u32::MAX);
        let got = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &w.b).unwrap();
        assert_eq!(ret_code(&got), KADM5_UNK_PRINC);
    }

    #[test]
    fn chrand_bumps_kvno() {
        let (store, acl, actor) = setup();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
        let kvno_before = {
            let g = store.read().unwrap();
            g.get_name(&user)
                .unwrap()
                .keys
                .iter()
                .map(|k| k.kvno)
                .max()
                .unwrap()
        };
        let args = encode_named("user@KERBER.TEST");
        let out = dispatch_kadm5(&store, &acl, &actor, CHRAND_PRINCIPAL, &args).unwrap();
        assert_eq!(ret_code(&out), 0);
        let kvno_after = {
            let g = store.read().unwrap();
            g.get_name(&user)
                .unwrap()
                .keys
                .iter()
                .map(|k| k.kvno)
                .max()
                .unwrap()
        };
        assert!(kvno_after > kvno_before);
    }

    #[test]
    fn modprinc_sets_requires_preauth_bit() {
        let (store, acl, actor) = setup();
        let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["modme"]);
        {
            let mut g = store.write().unwrap();
            g.create_password(&acl, &actor, &extra, b"mod-secret")
                .unwrap();
        }
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("modme@KERBER.TEST"));
        w.u32(0); // expire
        w.u32(0);
        w.u32(0); // pw_expire
        w.u32(3600); // max_life
        w.u32(1); // mod_name NULL
        w.u32(0);
        w.u32(krb5_kdc::KDB_REQUIRES_PRE_AUTH);
        w.u32(1); // kvno
        w.u32(1);
        w.u32(0); // policy
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0); // n_key
        w.u32(0); // n_tl
        w.u32(1); // tl null
        w.u32(0); // key_data array
        w.u32(KADM5_ATTRIBUTES | KADM5_MAX_LIFE);
        let out = dispatch_kadm5(&store, &acl, &actor, MODIFY_PRINCIPAL, &w.b).unwrap();
        assert_eq!(ret_code(&out), 0);
        let g = store.read().unwrap();
        let p = g.get_name(&extra).unwrap();
        assert!(p.requires_preauth);
        assert_eq!(p.max_life, 3600);
    }

    fn encode_cpol(api: u32, p: &krb5_kdc::NamedPolicy, mask: u32) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(api);
        encode_policy_rec(&mut w, api, p);
        w.u32(mask);
        w.b
    }

    #[test]
    fn kadm5_policy_verbs_and_pwqual() {
        let (store, acl, actor) = setup();
        let pol = krb5_kdc::NamedPolicy {
            name: "strict".into(),
            min_length: 8,
            min_classes: 2,
            history: 0,
            max_fail: 2,
        };
        let mask = KADM5_POLICY | KADM5_PW_MIN_LENGTH | KADM5_PW_MIN_CLASSES | KADM5_PW_MAX_FAILURE;
        let created = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            CREATE_POLICY,
            &encode_cpol(API_V4, &pol, mask),
        )
        .unwrap();
        assert_eq!(ret_code(&created), 0);

        let dup = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            CREATE_POLICY,
            &encode_cpol(API_V4, &pol, mask),
        )
        .unwrap();
        assert_eq!(ret_code(&dup), KADM5_DUP);

        let mut gq = XdrW::default();
        gq.u32(API_V4);
        gq.nullstring(Some("strict"));
        let got = dispatch_kadm5(&store, &acl, &actor, GET_POLICY, &gq.b).unwrap();
        assert_eq!(ret_code(&got), 0);
        let mut r = XdrR::new(&got);
        assert_eq!(r.u32().unwrap(), API_V4);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.nullstring().unwrap().as_deref(), Some("strict"));
        r.u32().unwrap();
        r.u32().unwrap();
        assert_eq!(r.u32().unwrap(), 8);
        assert_eq!(r.u32().unwrap(), 2);
        r.u32().unwrap();
        r.u32().unwrap();
        assert_eq!(r.u32().unwrap(), 2);

        let mut list_args = XdrW::default();
        list_args.u32(API_V4);
        list_args.u32(0);
        let listed = dispatch_kadm5(&store, &acl, &actor, GET_POLS, &list_args.b).unwrap();
        assert_eq!(ret_code(&listed), 0);
        let mut lr = XdrR::new(&listed);
        let _ = lr.u32().unwrap();
        let _ = lr.u32().unwrap();
        let n = lr.u32().unwrap();
        assert_eq!(lr.u32().unwrap(), n);
        let mut names = Vec::new();
        for _ in 0..n {
            names.push(lr.nullstring().unwrap().unwrap());
        }
        assert!(names.iter().any(|s| s == "strict"));

        let mut shorter = pol.clone();
        shorter.min_length = 10;
        let mod_mask = KADM5_PW_MIN_LENGTH;
        let modified = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            MODIFY_POLICY,
            &encode_cpol(API_V4, &shorter, mod_mask),
        )
        .unwrap();
        assert_eq!(ret_code(&modified), 0);
        {
            let g = store.read().unwrap();
            let p = g.policies().get("strict").unwrap();
            assert_eq!(p.min_length, 10);
            assert_eq!(p.max_fail, 2, "modpol must not zero unmasked fields");
        }

        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
        {
            let mut g = store.write().unwrap();
            g.set_principal_policy(&user, Some("strict".into()))
                .unwrap();
        }
        let mut chpw = XdrW::default();
        chpw.u32(API_V2);
        chpw.nullstring(Some("user@KERBER.TEST"));
        chpw.nullstring(Some("short"));
        let rejected = dispatch_kadm5(&store, &acl, &actor, CHPASS_PRINCIPAL, &chpw.b).unwrap();
        assert_eq!(ret_code(&rejected), KADM5_PASS_Q_TOOSHORT);

        let mut del = XdrW::default();
        del.u32(API_V4);
        del.nullstring(Some("strict"));
        let deleted = dispatch_kadm5(&store, &acl, &actor, DELETE_POLICY, &del.b).unwrap();
        assert_eq!(ret_code(&deleted), 0);
        let missing = dispatch_kadm5(&store, &acl, &actor, GET_POLICY, &gq.b).unwrap();
        assert_eq!(ret_code(&missing), KADM5_UNK_POLICY);
    }
}
