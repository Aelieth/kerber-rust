//! MIT kadm5 GSS-RPC (ONC RPC program 2112, version 2) on TCP 749.
//!
//! MIT 1.22.2 `kadmin` authenticates with AUTH_GSSAPI flavor 300001
//! (`auth_gssapi.h`), not RFC 2203 RPCSEC_GSS flavor 6. This is not a
//! full C ABI clone.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use krb5_crypto::{EncryptionType, ProtocolKey, kdb_decrypt_key};
use krb5_gss::GssContext;
use krb5_kdc::{
    Acl, KDB_DISALLOW_ALL_TIX, KDB_LOCKDOWN_KEYS, KDB_REQUIRES_PRE_AUTH, KDB_V1_BASE_LENGTH,
    KeyEntry, Principal, SharedDump as SharedStore,
};
use krb5_types::{PrincipalName, Ticket};

use crate::AdminSession;
use crate::Error;

const LAST_FRAG: u32 = 0x8000_0000;
const RPC_VERSION: u32 = 2;
const KADM_PROG: u32 = 2112;
const KADM_VERS: u32 = 2;
/// MIT `KRB5_IPROP_PROG`.
const IPROP_PROG: u32 = 100_423;
const IPROP_VERS: u32 = 1;
const IPROP_NULL: u32 = 0;
const IPROP_GET_UPDATES: u32 = 1;
const IPROP_FULL_RESYNC: u32 = 2;
const IPROP_FULL_RESYNC_EXT: u32 = 3;
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
const SETKEY_PRINCIPAL: u32 = 16;
const SETKEY_PRINCIPAL3: u32 = 21;
const SETKEY_PRINCIPAL4: u32 = 25;
const PURGEKEYS: u32 = 22;
const EXTRACT_KEYS: u32 = 26;

/// MIT `KADM5_UNK_PRINC`.
const KADM5_UNK_PRINC: u32 = 43_787_532;
/// MIT `KADM5_UNK_POLICY`.
const KADM5_UNK_POLICY: u32 = 43_787_533;
/// MIT `KADM5_DUP`.
const KADM5_DUP: u32 = 43_787_527;
/// MIT `KADM5_FAILURE`.
const KADM5_FAILURE: u32 = 43_787_520;
/// MIT `ovk` 22 (`kadm_err.et`; base `43787520`).
const KADM5_PASS_Q_TOOSHORT: u32 = 43_787_542;
/// MIT `ovk` 23.
const KADM5_PASS_Q_CLASS: u32 = 43_787_543;
/// MIT `ovk` 25.
const KADM5_PASS_REUSE: u32 = 43_787_545;
/// MIT `ovk` 3 (`KADM5_AUTH_MODIFY`).
const KADM5_AUTH_MODIFY: u32 = 43_787_523;
/// MIT `ovk` 50 (`KADM5_AUTH_SETKEY`).
const KADM5_AUTH_SETKEY: u32 = 43_787_570;
/// MIT `ovk` 59 (`KADM5_SETKEY_BAD_KVNO`).
const KADM5_SETKEY_BAD_KVNO: u32 = 43_787_579;
/// MIT `ovk` 60 (`KADM5_AUTH_EXTRACT`).
const KADM5_AUTH_EXTRACT: u32 = 43_787_580;
/// MIT `ovk` 61 (`KADM5_PROTECT_KEYS`).
const KADM5_PROTECT_KEYS: u32 = 43_787_581;
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
const KADM5_PW_FAILURE_COUNT_INTERVAL: u32 = 0x0020_0000;
const KADM5_PW_LOCKOUT_DURATION: u32 = 0x0040_0000;

/// OpenVision/MIT `KADM5_API_VERSION_2`.
const API_V2: u32 = 0x1234_5702;
const API_V3: u32 = 0x1234_5703;
const API_V4: u32 = 0x1234_5704;
/// MIT `KADM5_PRIV_{GET,ADD,MODIFY,DELETE}` plus list (0x10), cpw (0x20), extract (0x40).
const KADM5_PRIVS: u32 = 0x0000_007F;

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
    let kadm = prog == KADM_PROG && vers == KADM_VERS;
    let iprop = prog == IPROP_PROG && vers == IPROP_VERS;
    if rpcvers != RPC_VERSION || !(kadm || iprop) {
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
            iprop,
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
        // RPCSEC_GSS: MIT kadmin uses kadmin/admin; kpropd uses kiprop/host
        // on program 2112 then 100423. Bind by service key, not sname.
        let (ctx, out_tok) =
            GssContext::accept_sec_context(&token, service_keys, None, None, Some(expected_realm))
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
    let actor = ctx.client.clone().ok_or(Error::AclDenied)?;
    let result = if iprop {
        dispatch_iprop(store, acl, &actor, proc, args)
    } else {
        dispatch_kadm5(store, acl, &actor, proc, args)?
    };
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
    iprop: bool,
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
        let server = if iprop { None } else { Some(expected_server) };
        let (ctx, out_tok) = match GssContext::accept_sec_context(
            &token,
            service_keys,
            None,
            server,
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
    let actor = st.ctx.client.clone().ok_or(Error::AclDenied)?;
    let result = if iprop {
        dispatch_iprop(store, acl, &actor, proc, kadm_args)
    } else {
        dispatch_kadm5(store, acl, &actor, proc, kadm_args)?
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

const AT_ATTRFLAGS: u32 = 0;
const AT_MAX_LIFE: u32 = 1;
const AT_MAX_RENEW_LIFE: u32 = 2;
const AT_EXP: u32 = 3;
const AT_PW_EXP: u32 = 4;
const AT_LAST_SUCCESS: u32 = 5;
const AT_LAST_FAILED: u32 = 6;
const AT_FAIL_AUTH_COUNT: u32 = 7;
const AT_PRINC: u32 = 8;
const AT_KEYDATA: u32 = 9;
const AT_TL_DATA: u32 = 10;
const AT_LEN: u32 = 11;
const AT_MOD_PRINC: u32 = 12;
const AT_MOD_TIME: u32 = 13;
const AT_PW_LAST_CHANGE: u32 = 15;
const AT_PW_POLICY: u32 = 16;
const AT_PW_POLICY_SWITCH: u32 = 17;
const AT_PW_HIST_KVNO: u32 = 18;
const AT_PW_HIST: u32 = 19;

fn dispatch_iprop(store: &SharedStore, acl: &Acl, actor: &str, proc: u32, args: &[u8]) -> Vec<u8> {
    if proc != IPROP_NULL && acl.check(actor, krb5_kdc::AdminOp::Propagate).is_err() {
        return encode_incr_result(krb5_kdc::IPROP_PERM_DENIED, 0, &[], None);
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
            encode_incr_result(status, last, &entries, g.iprop_master_key().as_ref())
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

fn encode_kdbe(w: &mut XdrW, p: &krb5_kdc::Principal, mkey: Option<&krb5_crypto::ProtocolKey>) {
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
    body.u32(u32::try_from(p.keys.len()).unwrap_or(0));
    for k in &p.keys {
        let salt = k.kdb_salt.clone().unwrap_or_else(|| p.salt.clone());
        let salt_ty = k.salt_type.unwrap_or(0);
        body.u32(2);
        body.u32(k.kvno);
        body.u32(2);
        body.u32(u32::try_from(k.etype.to_iana()).unwrap_or(0));
        body.u32(u32::try_from(salt_ty).unwrap_or(0));
        body.u32(2);
        let enc = mkey
            .and_then(|m| krb5_crypto::kdb_encrypt_key(m, k.key.as_bytes()).ok())
            .unwrap_or_else(|| k.key.as_bytes().to_vec());
        body.opaque(&enc);
        body.opaque(&salt);
    }
    n += 1;
    body.u32(AT_LEN);
    body.u32(p.db_entry_len);
    n += 1;
    let now = u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0);
    body.u32(AT_PW_LAST_CHANGE);
    body.u32(now);
    n += 1;
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
    body.u32(now);
    n += 1;
    w.u32(n);
    w.b.extend_from_slice(&body.b);
}

fn encode_incr_result(
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

fn encode_fullresync(last: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    encode_kdb_last(&mut w, last);
    w.u32(krb5_kdc::IPROP_OK);
    w.b
}

/// Outcome of [`iprop_pull`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpropPull {
    /// MIT `update_status_t`.
    pub status: u32,
    /// `kdb_last_t.last_sno` from the reply.
    pub last_sno: u32,
    /// Entries applied into the replica store.
    pub applied: usize,
}

/// RPCSEC_GSS IPROP_GET_UPDATES against MIT `kadmind` (program 100423).
///
/// # Errors
///
/// GSS, RPC, XDR, or crypto failures.
#[allow(clippy::too_many_arguments)]
pub fn iprop_pull(
    stream: &mut TcpStream,
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &krb5_types::Realm,
    cname: &PrincipalName,
    last_sno: u32,
    last_sec: u32,
    last_usec: u32,
    store: &mut krb5_kdc::PrincipalStore,
) -> Result<IpropPull, Error> {
    let (mut ctx, token) = GssContext::init_sec_context(ticket, session, crealm, cname, true, None)
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
    let (status, last, entries) = decode_incr_result(&body, store.iprop_master_key().as_ref())?;
    let n = entries.len();
    if status == krb5_kdc::IPROP_OK && n > 0 {
        store.apply_updates(&entries);
    }
    Ok(IpropPull {
        status,
        last_sno: last,
        applied: if status == krb5_kdc::IPROP_OK { n } else { 0 },
    })
}

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
        *xid,
        IPROP_PROG,
        IPROP_VERS,
        IPROP_NULL,
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

#[allow(clippy::too_many_arguments)]
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
        *xid, prog, vers, proc, FLAVOR_GSS, &cred.b, FLAVOR_GSS, &mic, &arg.b,
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
    let plain = ctx
        .unwrap(&wrapped)
        .map_err(|e| Error::Inner(format!("rpcsec unwrap: {e}")))?;
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

#[allow(clippy::too_many_arguments)]
fn rpc_call_bytes(
    xid: u32,
    prog: u32,
    vers: u32,
    proc: u32,
    cred_flavor: u32,
    cred: &[u8],
    verf_flavor: u32,
    verf: &[u8],
    args: &[u8],
) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(prog);
    w.u32(vers);
    w.u32(proc);
    w.u32(cred_flavor);
    w.opaque(cred);
    w.u32(verf_flavor);
    w.opaque(verf);
    w.b.extend_from_slice(args);
    w.b
}

fn decode_incr_result(
    b: &[u8],
    mkey: Option<&ProtocolKey>,
) -> Result<(u32, u32, Vec<krb5_kdc::UlogEntry>), Error> {
    let mut r = XdrR::new(b);
    let last = r.u32()?;
    let _sec = r.u32()?;
    let _usec = r.u32()?;
    let n = r.u32()? as usize;
    let mut entries = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        entries.push(decode_incr_update(&mut r, mkey)?);
    }
    let status = r.u32()?;
    Ok((status, last, entries))
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

fn decode_kdbe(
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
                    let _ty = r.u32()?;
                    let _ = r.opaque()?;
                }
            }
            AT_LEN => db_entry_len = r.u32()?,
            AT_PW_LAST_CHANGE | AT_MOD_TIME | AT_PW_HIST_KVNO => {
                let _ = r.u32()?;
            }
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
                    let _ = decode_keydata(r, None)?;
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
    let requires_preauth = attributes & KDB_REQUIRES_PRE_AUTH != 0;
    let locked = attributes & KDB_DISALLOW_ALL_TIX != 0;
    let salt = name.default_salt(&realm);
    Ok(Some(Principal {
        name,
        realm,
        keys,
        // Incremental iprop kdbe does not carry TL_KERBER_HIST (full-resync dump does).
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
        tl_data: Vec::new(),
        e_data: Vec::new(),
        rid: 0,
        s4u_allowed_from: Vec::new(),
        s4u_allowed_to: Vec::new(),
        pw_policy,
    }))
}

fn decode_princ(r: &mut XdrR<'_>) -> Result<(PrincipalName, String), Error> {
    let realm_b = r.opaque()?;
    let realm = String::from_utf8_lossy(&realm_b).into_owned();
    let n = r.u32()? as usize;
    let mut comps = Vec::with_capacity(n);
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
    let (left, realm) = s.split_once('@').unwrap_or((s, ""));
    let parts: Vec<&str> = left.split('/').collect();
    let ntype = if parts.len() > 1 {
        PrincipalName::NT_SRV_HST
    } else {
        PrincipalName::NT_PRINCIPAL
    };
    let name = PrincipalName::try_new(ntype, parts).map_err(|e| Error::Inner(e.to_string()))?;
    Ok((name, realm.to_owned()))
}

fn decode_keydata(r: &mut XdrR<'_>, mkey: Option<&ProtocolKey>) -> Result<Vec<KeyEntry>, Error> {
    let n = r.u32()? as usize;
    let mut keys = Vec::with_capacity(n.min(16));
    for _ in 0..n {
        let ver = r.u32()?;
        let kvno = r.u32()?;
        let n_enc = r.u32()? as usize;
        let mut enctypes = Vec::with_capacity(n_enc);
        for _ in 0..n_enc {
            enctypes.push(r.u32()?.cast_signed());
        }
        let n_cont = r.u32()? as usize;
        let mut contents = Vec::with_capacity(n_cont);
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
            w.u32(acl.privs(actor) & KADM5_PRIVS);
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
                return Ok(generic_ret(API_V2, KADM5_AUTH_MODIFY));
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
                return Ok(generic_ret(api, KADM5_AUTH_MODIFY));
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
        EXTRACT_KEYS => {
            let (api, name, kvno) = parse_extract(args)?;
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(p) = g.get_name(&name) else {
                return Ok(generic_ret(api, KADM5_UNK_PRINC));
            };
            if acl.check(actor, krb5_kdc::AdminOp::Extract).is_err() {
                return Ok(generic_ret(api, KADM5_AUTH_EXTRACT));
            }
            if p.attributes & KDB_LOCKDOWN_KEYS != 0 {
                return Ok(generic_ret(api, KADM5_PROTECT_KEYS));
            }
            tracing::info!(
                event = krb5_log::events::ADMIN,
                component = "krb5-admin",
                outcome = "ok",
                detail = "extract",
                principal = p.id(),
            );
            Ok(encode_extract_keys(api, p, kvno))
        }
        PURGEKEYS => {
            let (api, name, keepkvno) = parse_purgekeys(args)?;
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let lockdown = match g.get_name(&name) {
                None => return Ok(generic_ret(api, KADM5_UNK_PRINC)),
                Some(p) => p.attributes & KDB_LOCKDOWN_KEYS != 0,
            };
            if lockdown {
                return Ok(generic_ret(api, KADM5_PROTECT_KEYS));
            }
            if acl.check(actor, krb5_kdc::AdminOp::Modify).is_err() {
                return Ok(generic_ret(api, KADM5_AUTH_MODIFY));
            }
            match g.purgekeys(&name, keepkvno) {
                Ok(()) => {
                    tracing::info!(
                        event = krb5_log::events::ADMIN,
                        component = "krb5-admin",
                        outcome = "ok",
                        detail = "purgekeys",
                    );
                    Ok(generic_ret(api, 0))
                }
                Err(e) => Ok(generic_ret(api, kadm5_code(&Error::from(e)))),
            }
        }
        SETKEY_PRINCIPAL | SETKEY_PRINCIPAL3 | SETKEY_PRINCIPAL4 => {
            let (api, name, keys, keepold) = parse_setkey(args, proc)?;
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let lockdown = match g.get_name(&name) {
                None => return Ok(generic_ret(api, KADM5_UNK_PRINC)),
                Some(p) => p.attributes & KDB_LOCKDOWN_KEYS != 0,
            };
            if lockdown {
                return Ok(generic_ret(api, KADM5_PROTECT_KEYS));
            }
            if acl.check(actor, krb5_kdc::AdminOp::SetKey).is_err() {
                return Ok(generic_ret(api, KADM5_AUTH_SETKEY));
            }
            match g.set_keys(&name, keys, keepold) {
                Ok(()) => Ok(generic_ret(api, 0)),
                Err(e) => Ok(generic_ret(api, kadm5_code(&Error::from(e)))),
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
        Error::Inner(s) if s.contains("setkey kvno") => KADM5_SETKEY_BAD_KVNO,
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
    let mut pw_failcnt_interval = 0;
    let mut pw_lockout_duration = 0;
    if api >= API_V3 {
        max_fail = r.u32().unwrap_or(0);
        pw_failcnt_interval = r.u32().unwrap_or(0);
        pw_lockout_duration = r.u32().unwrap_or(0);
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
            pw_failcnt_interval,
            pw_lockout_duration,
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
    if mask & KADM5_PW_FAILURE_COUNT_INTERVAL != 0 {
        existing.pw_failcnt_interval = rec.pw_failcnt_interval;
    }
    if mask & KADM5_PW_LOCKOUT_DURATION != 0 {
        existing.pw_lockout_duration = rec.pw_lockout_duration;
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
        w.u32(p.pw_failcnt_interval);
        w.u32(p.pw_lockout_duration);
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

fn parse_purgekeys(args: &[u8]) -> Result<(u32, PrincipalName, i32), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let princ = r.principal()?;
    let keep = i32::from_be_bytes(r.u32().unwrap_or(u32::MAX).to_be_bytes());
    Ok((api, princ, keep))
}

fn parse_setkey(
    args: &[u8],
    proc: u32,
) -> Result<(u32, PrincipalName, Vec<krb5_kdc::KeyEntry>, bool), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let princ = r.principal()?;
    let keepold = if proc == SETKEY_PRINCIPAL {
        false
    } else {
        r.u32()? != 0
    };
    if proc == SETKEY_PRINCIPAL3 {
        r.skip_array_i32_pairs()?;
    }
    let n = r.u32()?;
    let mut keys = Vec::new();
    for _ in 0..n {
        let kvno = if proc == SETKEY_PRINCIPAL4 {
            r.u32()?
        } else {
            0
        };
        let et = i32::from_be_bytes(r.u32()?.to_be_bytes());
        let etype = EncryptionType::known(et).map_err(|e| Error::Inner(e.to_string()))?;
        let bytes = r.opaque()?;
        let key =
            ProtocolKey::from_bytes(etype, &bytes).map_err(|e| Error::Inner(e.to_string()))?;
        let mut ke = KeyEntry::new(etype, key, kvno);
        if proc == SETKEY_PRINCIPAL4 {
            let st = i32::from_be_bytes(r.u32()?.to_be_bytes());
            let salt = r.opaque()?;
            if st != 0 {
                ke.salt_type = Some(st);
            }
            if !salt.is_empty() {
                ke.kdb_salt = Some(salt);
            }
        }
        keys.push(ke);
    }
    Ok((api, princ, keys, keepold))
}

fn parse_extract(args: &[u8]) -> Result<(u32, PrincipalName, u32), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let princ = r.principal()?;
    let kvno = r.u32().unwrap_or(0);
    Ok((api, princ, kvno))
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
    let n_key = u32::try_from(p.keys.len().saturating_add(p.key_history.len())).unwrap_or(0);
    let n_tl = u32::try_from(p.tl_data.len()).unwrap_or(0);
    w.u32(n_key);
    w.u32(n_tl);
    if p.tl_data.is_empty() {
        w.u32(1);
    } else {
        w.u32(0);
        for tl in &p.tl_data {
            w.u32(1);
            w.u32(u32::try_from(tl.ty).unwrap_or(0));
            w.opaque(&tl.contents);
        }
        w.u32(0);
    }
    w.u32(n_key);
    for k in p.keys.iter().chain(p.key_history.iter()) {
        let ver = if k.salt_type.is_some() { 2 } else { 1 };
        w.u32(ver);
        w.u32(k.kvno);
        w.u32(u32::try_from(k.etype.to_iana()).unwrap_or(0));
        if ver > 1 {
            w.u32(u32::try_from(k.salt_type.unwrap_or(0)).unwrap_or(0));
        }
    }
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

fn encode_extract_keys(api: u32, p: &krb5_kdc::Principal, kvno: u32) -> Vec<u8> {
    let keys: Vec<&krb5_kdc::KeyEntry> = p
        .keys
        .iter()
        .chain(p.key_history.iter())
        .filter(|k| kvno == 0 || k.kvno == kvno)
        .collect();
    let mut w = XdrW::default();
    w.u32(api);
    w.u32(0);
    w.u32(u32::try_from(keys.len()).unwrap_or(0));
    for k in keys {
        w.u32(k.kvno);
        w.u32(u32::try_from(k.etype.to_iana()).unwrap_or(0));
        w.opaque(k.key.as_bytes());
        w.u32(u32::try_from(k.salt_type.unwrap_or(0)).unwrap_or(0));
        w.opaque(k.kdb_salt.as_deref().unwrap_or(p.salt.as_slice()));
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
    fn get_privs_follows_actor_acl_not_constant() {
        let (store, acl, actor) = setup();
        let admin = dispatch_kadm5(&store, &acl, &actor, GET_PRIVS, &[]).unwrap();
        let mut r = XdrR::new(&admin);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.u32().unwrap(), KADM5_PRIVS);
        let star = Acl::parse("admin@KERBER.TEST *\n");
        let star_out = dispatch_kadm5(&store, &star, &actor, GET_PRIVS, &[]).unwrap();
        let mut r = XdrR::new(&star_out);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(
            r.u32().unwrap(),
            0x3F,
            "MIT * does not include extract (0x40)"
        );
        let limited = Acl::parse("admin@KERBER.TEST *\nlimited@KERBER.TEST i\n");
        let out = dispatch_kadm5(&store, &limited, "limited@KERBER.TEST", GET_PRIVS, &[]).unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.u32().unwrap(), 0x01, "inquire-only is GET, not 0x3F");
        let none = dispatch_kadm5(&store, &limited, "nobody@KERBER.TEST", GET_PRIVS, &[]).unwrap();
        let mut r = XdrR::new(&none);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.u32().unwrap(), 0);
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
        use krb5_kdc::{
            TEST_REALM, bootstrap_documented, documented_admin_id, shared_dump as shared_store,
        };

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

    fn setup() -> (krb5_kdc::SharedDump, Acl, String) {
        let (store, acl) = krb5_kdc::bootstrap_documented().unwrap();
        let actor = krb5_kdc::documented_admin_id();
        (krb5_kdc::shared_dump(store), acl, actor)
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
        r.u32().unwrap(); // mod_date
        r.u32().unwrap(); // attributes
        r.u32().unwrap(); // kvno
        r.u32().unwrap(); // mkvno
        let _ = r.nullstring().unwrap();
        r.u32().unwrap(); // aux
        r.u32().unwrap(); // max_renewable
        r.u32().unwrap(); // last_success
        r.u32().unwrap(); // last_failed
        r.u32().unwrap(); // fail_auth_count
        let n_key = r.u32().unwrap();
        assert!(n_key >= 1, "getprinc n_key_data, got {n_key}");
        let n_tl = r.u32().unwrap();
        let tl_null = r.u32().unwrap();
        if tl_null == 0 {
            loop {
                let more = r.u32().unwrap();
                if more == 0 {
                    break;
                }
                r.u32().unwrap();
                let _ = r.opaque().unwrap();
            }
        } else {
            assert_eq!(n_tl, 0);
        }
        let n = r.u32().unwrap();
        assert_eq!(n, n_key);
        for _ in 0..n {
            let ver = r.u32().unwrap();
            let kvno = r.u32().unwrap();
            let etype = r.u32().unwrap();
            assert!(kvno >= 1);
            assert!(etype > 0);
            if ver > 1 {
                r.u32().unwrap();
            }
        }
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

    fn extract_args(name: &str, kvno: u32) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some(name));
        w.u32(kvno);
        w.b
    }

    #[test]
    fn extract_keys_returns_key_bytes() {
        let (store, acl, actor) = setup();
        let expected = {
            let g = store.read().unwrap();
            let p = g
                .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
                .unwrap();
            (
                p.keys.len(),
                p.keys[0].kvno,
                p.keys[0].etype.to_iana(),
                p.keys[0].key.as_bytes().to_vec(),
                p.salt.clone(),
            )
        };
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            EXTRACT_KEYS,
            &extract_args("user@KERBER.TEST", 0),
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0);
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        let n = r.u32().unwrap();
        assert_eq!(n as usize, expected.0);
        assert_eq!(r.u32().unwrap(), expected.1);
        assert_eq!(r.u32().unwrap(), u32::try_from(expected.2).unwrap());
        assert_eq!(r.opaque().unwrap(), expected.3);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.opaque().unwrap(), expected.4);
    }

    #[test]
    fn extract_keys_acl_is_auth_extract() {
        let (store, _acl, _actor) = setup();
        let limited = Acl::parse("admin@KERBER.TEST *\nlimited@KERBER.TEST i\n");
        let out = dispatch_kadm5(
            &store,
            &limited,
            "limited@KERBER.TEST",
            EXTRACT_KEYS,
            &extract_args("user@KERBER.TEST", 0),
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_EXTRACT);
        let star = Acl::parse("admin@KERBER.TEST *\n");
        let denied = dispatch_kadm5(
            &store,
            &star,
            "admin@KERBER.TEST",
            EXTRACT_KEYS,
            &extract_args("user@KERBER.TEST", 0),
        )
        .unwrap();
        assert_eq!(ret_code(&denied), KADM5_AUTH_EXTRACT);
    }

    #[test]
    fn extract_keys_lockdown_is_protect_keys() {
        let (store, acl, actor) = setup();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        {
            let mut g = store.write().unwrap();
            g.apply_admin_fields(
                &user,
                Some(KDB_LOCKDOWN_KEYS),
                None,
                None,
                None,
                None,
                false,
            )
            .unwrap();
        }
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            EXTRACT_KEYS,
            &extract_args("user@KERBER.TEST", 0),
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_PROTECT_KEYS);
    }

    fn purgekeys_args(name: &str, keepkvno: i32) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some(name));
        w.u32(u32::from_be_bytes(keepkvno.to_be_bytes()));
        w.b
    }

    #[test]
    fn purgekeys_drops_old_kvnos() {
        let (store, acl, actor) = setup();
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["purgee"]);
        {
            let mut g = store.write().unwrap();
            let mut pol = krb5_kdc::NamedPolicy::new("g3bhist");
            pol.history = 2;
            g.put_policy(pol);
            g.create_password(&acl, &actor, &name, b"purge-secret")
                .unwrap();
            g.set_principal_policy(&name, Some("g3bhist".into()))
                .unwrap();
            g.set_password(&name, b"purge-rotated").unwrap();
            let p = g.get_name(&name).unwrap();
            assert!(!p.key_history.is_empty());
        }
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            PURGEKEYS,
            &purgekeys_args("purgee@KERBER.TEST", -1),
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0);
        let g = store.read().unwrap();
        let p = g.get_name(&name).unwrap();
        assert!(p.key_history.is_empty());
        assert!(!p.keys.is_empty());
        let got = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &{
            let mut w = XdrW::default();
            w.u32(API_V2);
            w.nullstring(Some("purgee@KERBER.TEST"));
            w.u32(u32::MAX);
            w.b
        })
        .unwrap();
        assert_eq!(ret_code(&got), 0);
    }

    #[test]
    fn purgekeys_acl_is_auth_modify() {
        let (store, _acl, _actor) = setup();
        let limited = Acl::parse("limited@KERBER.TEST i\n");
        let out = dispatch_kadm5(
            &store,
            &limited,
            "limited@KERBER.TEST",
            PURGEKEYS,
            &purgekeys_args("user@KERBER.TEST", -1),
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_MODIFY);
    }

    #[test]
    fn purgekeys_lockdown_is_protect_keys() {
        let (store, acl, actor) = setup();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        {
            let mut g = store.write().unwrap();
            g.apply_admin_fields(
                &user,
                Some(KDB_LOCKDOWN_KEYS),
                None,
                None,
                None,
                None,
                false,
            )
            .unwrap();
        }
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            PURGEKEYS,
            &purgekeys_args("user@KERBER.TEST", -1),
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_PROTECT_KEYS);
    }

    fn setkey16_args(name: &str, etype: i32, key: &[u8]) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some(name));
        w.u32(1);
        w.u32(u32::try_from(etype).unwrap());
        w.opaque(key);
        w.b
    }

    #[test]
    fn setkey3_empty_ks_tuple() {
        let (store, acl, actor) = setup();
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.u32(0);
        w.u32(0);
        w.u32(1);
        w.u32(18);
        w.opaque(&[0xEFu8; 32]);
        let out = dispatch_kadm5(&store, &acl, &actor, SETKEY_PRINCIPAL3, &w.b).unwrap();
        assert_eq!(ret_code(&out), 0);
        let g = store.read().unwrap();
        let p = g
            .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .unwrap();
        assert_eq!(p.keys[0].key.as_bytes(), &[0xEFu8; 32]);
        assert!(p.key_history.is_empty());
    }

    #[test]
    fn setkey_replaces_keys() {
        let (store, acl, actor) = setup();
        let key = [0xABu8; 32];
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            SETKEY_PRINCIPAL,
            &setkey16_args("user@KERBER.TEST", 18, &key),
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0);
        let g = store.read().unwrap();
        let p = g
            .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .unwrap();
        assert_eq!(p.keys.len(), 1);
        assert_eq!(p.keys[0].etype.to_iana(), 18);
        assert_eq!(p.keys[0].key.as_bytes(), key);
        assert!(p.key_history.is_empty());
    }

    #[test]
    fn setkey4_keepold_retains_history() {
        let (store, acl, actor) = setup();
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.u32(1);
        w.u32(1);
        w.u32(0);
        w.u32(18);
        w.opaque(&[0xCDu8; 32]);
        w.u32(0);
        w.opaque(&[]);
        let n_old = {
            let g = store.read().unwrap();
            g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
                .unwrap()
                .keys
                .len()
        };
        let out = dispatch_kadm5(&store, &acl, &actor, SETKEY_PRINCIPAL4, &w.b).unwrap();
        assert_eq!(ret_code(&out), 0);
        let g = store.read().unwrap();
        let p = g
            .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .unwrap();
        assert_eq!(p.keys.len(), 1);
        assert_eq!(p.key_history.len(), n_old);
        assert_eq!(p.keys[0].key.as_bytes(), &[0xCDu8; 32]);
    }

    #[test]
    fn setkey_acl_is_auth_setkey() {
        let (store, _acl, _actor) = setup();
        let limited = Acl::parse("limited@KERBER.TEST i\n");
        let out = dispatch_kadm5(
            &store,
            &limited,
            "limited@KERBER.TEST",
            SETKEY_PRINCIPAL,
            &setkey16_args("user@KERBER.TEST", 18, &[0xABu8; 32]),
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_SETKEY);
    }

    #[test]
    fn setkey_lockdown_is_protect_keys() {
        let (store, acl, actor) = setup();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        {
            let mut g = store.write().unwrap();
            g.apply_admin_fields(
                &user,
                Some(KDB_LOCKDOWN_KEYS),
                None,
                None,
                None,
                None,
                false,
            )
            .unwrap();
        }
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            SETKEY_PRINCIPAL,
            &setkey16_args("user@KERBER.TEST", 18, &[0xABu8; 32]),
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_PROTECT_KEYS);
    }

    #[test]
    fn extract_keys_missing_is_unk_princ() {
        let (store, acl, actor) = setup();
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            EXTRACT_KEYS,
            &extract_args("no-such@KERBER.TEST", 0),
        )
        .unwrap();
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
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
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
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.u32().unwrap(), 0);

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
        let mut timed = pol.clone();
        timed.pw_failcnt_interval = 30;
        timed.pw_lockout_duration = 60;
        let tmask = KADM5_PW_FAILURE_COUNT_INTERVAL | KADM5_PW_LOCKOUT_DURATION;
        let tmod = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            MODIFY_POLICY,
            &encode_cpol(API_V4, &timed, tmask),
        )
        .unwrap();
        assert_eq!(ret_code(&tmod), 0);
        {
            let g = store.read().unwrap();
            let p = g.policies().get("strict").unwrap();
            assert_eq!(p.pw_failcnt_interval, 30);
            assert_eq!(p.pw_lockout_duration, 60);
            assert_eq!(p.min_length, 10);
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

    #[test]
    fn iprop_get_updates_full_resync_then_delta() {
        let (store, acl, actor) = setup();
        let last = {
            let g = store.read().unwrap();
            g.serial()
        };
        let mut args = XdrW::default();
        args.u32(0);
        args.u32(0);
        args.u32(0);
        let first = dispatch_iprop(&store, &acl, &actor, IPROP_GET_UPDATES, &args.b);
        let mut r = XdrR::new(&first);
        let sno = r.u32().unwrap();
        assert!(sno >= last);
        r.u32().unwrap();
        r.u32().unwrap();
        let n = r.u32().unwrap();
        for _ in 0..n {
            let _ = r.opaque();
            let _ = r.u32();
            let _ = r.u32();
            let _ = r.u32();
            let _ = r.u32();
            let _ = r.u32();
            let _ = r.u32();
            let _ = r.u32();
            let _ = r.u32();
        }
        assert_eq!(r.u32().unwrap(), krb5_kdc::IPROP_FULL_RESYNC);

        let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["iproprpc"]);
        {
            let mut g = store.write().unwrap();
            g.create_password(&acl, &actor, &extra, b"iprop-rpc-secret")
                .unwrap();
        }
        let mut delta = XdrW::default();
        delta.u32(last);
        delta.u32(0);
        delta.u32(0);
        let out = dispatch_iprop(&store, &acl, &actor, IPROP_GET_UPDATES, &delta.b);
        assert!(
            out.windows(b"iproprpc".len()).any(|w| w == b"iproprpc"),
            "GET_UPDATES delta must name the new principal"
        );
        assert!(
            out.windows(4).any(|w| w == AT_KEYDATA.to_be_bytes()),
            "kdb_incr_update_t must carry AT_KEYDATA for MIT ulog_replay"
        );
        let mut d = XdrR::new(&out);
        let _ = d.u32().unwrap();
        let _ = d.u32().unwrap();
        let _ = d.u32().unwrap();
        assert!(d.u32().unwrap() >= 1);

        let (st, last2, entries) = decode_incr_result(&out, None).unwrap();
        assert_eq!(st, krb5_kdc::IPROP_OK);
        assert!(last2 >= last);
        assert!(
            entries
                .iter()
                .any(|e| e.name.contains("iproprpc") && e.princ.is_some()),
            "decode must recover the new principal: {entries:?}"
        );
    }

    #[test]
    fn iprop_get_updates_denies_actor_without_propagate() {
        let (store, _acl, _actor) = setup();
        let limited = Acl::parse("admin@KERBER.TEST *\nuser@KERBER.TEST i\n");
        let mut args = XdrW::default();
        args.u32(0);
        args.u32(0);
        args.u32(0);
        let out = dispatch_iprop(
            &store,
            &limited,
            "user@KERBER.TEST",
            IPROP_GET_UPDATES,
            &args.b,
        );
        let (st, _, entries) = decode_incr_result(&out, None).unwrap();
        assert_eq!(st, krb5_kdc::IPROP_PERM_DENIED);
        assert!(
            entries.is_empty(),
            "unauthorized GET_UPDATES must not leak ulog: {entries:?}"
        );
        let ok = dispatch_iprop(
            &store,
            &limited,
            "admin@KERBER.TEST",
            IPROP_GET_UPDATES,
            &args.b,
        );
        let (st_ok, _, _) = decode_incr_result(&ok, None).unwrap();
        assert_ne!(st_ok, krb5_kdc::IPROP_PERM_DENIED);
    }
}
