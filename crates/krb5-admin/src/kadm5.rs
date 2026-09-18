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
    Acl, AdminEnt, KDB_DISALLOW_ALL_TIX, KDB_LOCKDOWN_KEYS, KDB_REQUIRES_PRE_AUTH,
    KDB_V1_BASE_LENGTH, KadmData, KeyEntry, OsaKeyData, OsaPrincEnt, Principal,
    SharedDump as SharedStore, TL_DB_ARGS, TL_LAST_PWD_CHANGE, TL_MOD_PRINC, TL_STRING_ATTRS,
    TlData,
};
use krb5_protocol::ReplayCache;
use krb5_types::{PrincipalName, Ticket};

#[cfg(test)]
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
const RPG_DESTROY: u32 = 3;
/// RFC 2203 / MIT `auth_gss.h` `rpc_gss_svc_t` (none=1, integrity=2, privacy=3).
const GSS_NONE: u32 = 1;
const GSS_INTEGRITY: u32 = 2;
const GSS_PRIVACY: u32 = 3;
const AUTH_REJECTEDCRED: u32 = 2;
const MAXSEQ: u32 = 0x8000_0000;
const SYSTEM_ERR: u32 = 5;
const MSG_CALL: u32 = 0;
const MSG_REPLY: u32 = 1;
const MSG_ACCEPTED: u32 = 0;
const MSG_DENIED: u32 = 1;
const SUCCESS: u32 = 0;
const PROG_UNAVAIL: u32 = 1;
const PROG_MISMATCH: u32 = 2;
const PROC_UNAVAIL: u32 = 3;
const GARBAGE_ARGS: u32 = 4;
const REJECT_AUTH_ERROR: u32 = 1;
const AUTH_TOOWEAK: u32 = 5;
const AUTH_BADCRED: u32 = 1;
const AUTH_FAILED: u32 = 7;
/// MIT `gssrpc/auth.h` `RPCSEC_GSS_CREDPROBLEM`.
const RPCSEC_GSS_CREDPROBLEM: u32 = 13;
/// MIT `gssrpc/auth.h` `RPCSEC_GSS_CTXPROBLEM`.
const RPCSEC_GSS_CTXPROBLEM: u32 = 14;
/// MIT `svc_auth_gss.c:226` `sizeof(seqmask)*8`.
const RPCSEC_SEQ_WINDOW: u32 = 32;

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
const GET_STRINGS: u32 = 23;
const SET_STRING: u32 = 24;
const EXTRACT_KEYS: u32 = 26;
const CREATE_ALIAS: u32 = 27;

/// MIT `KADM5_UNK_PRINC`.
const KADM5_UNK_PRINC: u32 = 43_787_532;
/// MIT `KADM5_UNK_POLICY`.
const KADM5_UNK_POLICY: u32 = 43_787_533;
const KADM5_BAD_MASK: u32 = 43_787_534;
const KADM5_BAD_CLASS: u32 = 43_787_535;
const KADM5_BAD_LENGTH: u32 = 43_787_536;
const KADM5_BAD_POLICY: u32 = 43_787_537;
const KADM5_BAD_HISTORY: u32 = 43_787_540;
const KADM5_BAD_MIN_PASS_LIFE: u32 = 43_787_541;
/// MIT `KADM5_DUP`.
const KADM5_DUP: u32 = 43_787_527;
/// MIT `KADM5_FAILURE`.
const KADM5_FAILURE: u32 = 43_787_520;
/// MIT `ovk` 22 (`kadm_err.et`; base `43787520`).
const KADM5_PASS_Q_TOOSHORT: u32 = 43_787_542;
/// MIT `ovk` 23.
const KADM5_PASS_Q_CLASS: u32 = 43_787_543;
/// MIT `ovk` 24 (`KADM5_PASS_Q_DICT`): `dict` and `princ` modules.
const KADM5_PASS_Q_DICT: u32 = 43_787_544;
/// MIT `ovk` 25.
const KADM5_PASS_REUSE: u32 = 43_787_545;
/// MIT `ovk` 26 (`KADM5_PASS_TOOSOON`).
const KADM5_PASS_TOOSOON: u32 = 43_787_546;
/// MIT `ovk` 2 (`KADM5_AUTH_ADD`).
const KADM5_AUTH_ADD: u32 = 43_787_522;
/// MIT `ovk` 3 (`KADM5_AUTH_MODIFY`).
const KADM5_AUTH_MODIFY: u32 = 43_787_523;
/// MIT `ovk` 4 (`KADM5_AUTH_DELETE`).
const KADM5_AUTH_DELETE: u32 = 43_787_524;
/// MIT `ovk` 5 (`KADM5_AUTH_INSUFFICIENT`).
const KADM5_AUTH_INSUFFICIENT: u32 = 43_787_525;
/// MIT `ovk` 63 (`KADM5_ALIAS_REALM`).
const KADM5_ALIAS_REALM: u32 = 43_787_583;
/// MIT `KRB5_KDB_ALIAS_UNSUPPORTED` (`kdb5_err.et`, -1780008402) as the
/// `kadm5_ret_t` the client decodes.
const KRB5_KDB_ALIAS_UNSUPPORTED: u32 = 2_514_958_894;
/// MIT `ovk` 1 (`KADM5_AUTH_GET`).
const KADM5_AUTH_GET: u32 = 43_787_521;
/// MIT `ovk` 44 (`KADM5_AUTH_LIST`).
const KADM5_AUTH_LIST: u32 = 43_787_564;
/// MIT `ovk` 62 (`KADM5_AUTH_INITIAL`).
const KADM5_AUTH_INITIAL: u32 = 43_787_582;
/// MIT `ovk` 45 (`KADM5_AUTH_CHANGEPW`).
const KADM5_AUTH_CHANGEPW: u32 = 43_787_565;
/// MIT `ovk` 50 (`KADM5_AUTH_SETKEY`).
const KADM5_AUTH_SETKEY: u32 = 43_787_570;
/// MIT `ovk` 58 (`KADM5_BAD_KEYSALTS`).
const KADM5_BAD_KEYSALTS: u32 = 43_787_578;
/// MIT `ovk` 59 (`KADM5_SETKEY_BAD_KVNO`).
const KADM5_SETKEY_BAD_KVNO: u32 = 43_787_579;
/// MIT `ovk` 60 (`KADM5_AUTH_EXTRACT`).
const KADM5_AUTH_EXTRACT: u32 = 43_787_580;
const KADM5_ATTRIBUTES: u32 = 0x0000_0010;
const KADM5_FAIL_AUTH_COUNT: u32 = 0x0001_0000;
const KADM5_TL_DATA: u32 = 0x0004_0000;
const KADM5_KEY_DATA: u32 = 0x0002_0000;
const KADM5_BAD_SERVER_PARAMS: u32 = 43_787_563;
/// MIT `ovk` 47 (`KADM5_BAD_TL_TYPE`, `kadm_err.et:54`).
const KADM5_BAD_TL_TYPE: u32 = 43_787_567;
const KADM5_MAX_LIFE: u32 = 0x0000_0020;
const KADM5_PRINCIPAL: u32 = 0x0000_0001;
const KADM5_PRINC_EXPIRE_TIME: u32 = 0x0000_0002;
const KADM5_PW_EXPIRATION: u32 = 0x0000_0004;
const KADM5_LAST_PWD_CHANGE: u32 = 0x0000_0008;
const KADM5_MOD_TIME: u32 = 0x0000_0040;
const KADM5_MOD_NAME: u32 = 0x0000_0080;
const KADM5_KVNO: u32 = 0x0000_0100;
const KADM5_MKVNO: u32 = 0x0000_0200;
const KADM5_AUX_ATTRIBUTES: u32 = 0x0000_0400;
const KADM5_MAX_RLIFE: u32 = 0x0000_2000;
const KADM5_LAST_SUCCESS: u32 = 0x0000_4000;
const KADM5_LAST_FAILED: u32 = 0x0000_8000;
/// MIT `KADM5_PW_MAX_LIFE`.
const KADM5_PW_MAX_LIFE: u32 = 0x0000_4000;
/// MIT `KADM5_PW_MIN_LIFE`.
const KADM5_PW_MIN_LIFE: u32 = 0x0000_8000;
const KADM5_POLICY: u32 = 0x0000_0800;
const KADM5_POLICY_CLR: u32 = 0x0000_1000;
const ALL_PRINC_MASK: u32 = KADM5_PRINCIPAL
    | KADM5_PRINC_EXPIRE_TIME
    | KADM5_PW_EXPIRATION
    | KADM5_LAST_PWD_CHANGE
    | KADM5_ATTRIBUTES
    | KADM5_MAX_LIFE
    | KADM5_MOD_TIME
    | KADM5_MOD_NAME
    | KADM5_KVNO
    | KADM5_MKVNO
    | KADM5_AUX_ATTRIBUTES
    | KADM5_POLICY_CLR
    | KADM5_POLICY
    | KADM5_MAX_RLIFE
    | KADM5_TL_DATA
    | KADM5_KEY_DATA
    | KADM5_FAIL_AUTH_COUNT;
const KADM5_PW_MIN_LENGTH: u32 = 0x0001_0000;
const KADM5_PW_MIN_CLASSES: u32 = 0x0002_0000;
const KADM5_PW_HISTORY_NUM: u32 = 0x0004_0000;
const KADM5_PW_MAX_FAILURE: u32 = 0x0010_0000;
const KADM5_PW_FAILURE_COUNT_INTERVAL: u32 = 0x0020_0000;
const KADM5_PW_LOCKOUT_DURATION: u32 = 0x0040_0000;
const KADM5_REF_COUNT: u32 = 0x0008_0000;
const KADM5_POLICY_ATTRIBUTES: u32 = 0x0080_0000;
const KADM5_POLICY_MAX_LIFE: u32 = 0x0100_0000;
const KADM5_POLICY_MAX_RLIFE: u32 = 0x0200_0000;
const KADM5_POLICY_ALLOWED_KEYSALTS: u32 = 0x0400_0000;
const KADM5_POLICY_TL_DATA: u32 = 0x0800_0000;
const ALL_POLICY_MASK: u32 = KADM5_POLICY
    | KADM5_PW_MAX_LIFE
    | KADM5_PW_MIN_LIFE
    | KADM5_PW_MIN_LENGTH
    | KADM5_PW_MIN_CLASSES
    | KADM5_PW_HISTORY_NUM
    | KADM5_REF_COUNT
    | KADM5_PW_MAX_FAILURE
    | KADM5_PW_FAILURE_COUNT_INTERVAL
    | KADM5_PW_LOCKOUT_DURATION
    | KADM5_POLICY_ATTRIBUTES
    | KADM5_POLICY_MAX_LIFE
    | KADM5_POLICY_MAX_RLIFE
    | KADM5_POLICY_ALLOWED_KEYSALTS
    | KADM5_POLICY_TL_DATA;

/// OpenVision/MIT `KADM5_API_VERSION_2`.
const API_V2: u32 = 0x1234_5702;
const API_V3: u32 = 0x1234_5703;
const API_V4: u32 = 0x1234_5704;
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
    expected_realm: String,
    rcache: ReplayCache,
    mut stream: TcpStream,
) -> io::Result<()> {
    let mut gss: Option<RpcsecGss> = None;
    let mut agss: Option<Agss> = None;
    let handle = random_handle();
    let addr = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
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
            &expected_realm,
            &handle,
            &mut gss,
            &mut agss,
            &rcache,
            &rec,
            &addr,
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
        if reply.is_empty() {
            continue;
        }
        write_record(&mut stream, &reply)?;
    }
}

fn random_handle() -> Vec<u8> {
    let mut h = [0u8; 8];
    let _ = getrandom::getrandom(&mut h);
    h.to_vec()
}

/// Total accumulated record cap. MIT drives kadmind over the net-server's fixed
/// 1 MiB per-connection buffer (`net-server.c:1278`) and processes the RPC as it
/// streams; Rust buffers the whole record, so it bounds the accumulated total to
/// the same size rather than letting a pre-auth client chain fragments without
/// limit (R2-S3).
const MAX_KADM5_RECORD: usize = 1024 * 1024;

fn read_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr)?;
        let n = u32::from_be_bytes(hdr);
        let last = n & LAST_FRAG != 0;
        let len = (n & !LAST_FRAG) as usize;
        if len > MAX_KADM5_RECORD || out.len().saturating_add(len) > MAX_KADM5_RECORD {
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

struct RpcsecGss {
    ctx: GssContext,
    seqlast: u32,
    seqmask: u32,
    svc: u32,
}

/// RPCSEC/AUTH_GSSAPI session for [`kadm5_handle_rpc`].
#[derive(Default)]
pub struct Kadm5RpcSession {
    gss: Option<RpcsecGss>,
    agss: Option<Agss>,
}

/// One ONC RPC record through `handle_rpc`.
///
/// # Errors
///
/// Truncated record or I/O.
#[allow(clippy::too_many_arguments)]
pub fn kadm5_handle_rpc(
    store: &SharedStore,
    acl: &Acl,
    service_keys: &[ProtocolKey],
    expected_realm: &str,
    handle: &[u8],
    sess: &mut Kadm5RpcSession,
    rcache: &ReplayCache,
    rec: &[u8],
    addr: &str,
) -> Result<Vec<u8>, Error> {
    handle_rpc(
        store,
        acl,
        service_keys,
        expected_realm,
        handle,
        &mut sess.gss,
        &mut sess.agss,
        rcache,
        rec,
        addr,
    )
}

#[allow(clippy::too_many_arguments)]
fn handle_rpc(
    store: &SharedStore,
    acl: &Acl,
    service_keys: &[ProtocolKey],
    expected_realm: &str,
    handle: &[u8],
    gss: &mut Option<RpcsecGss>,
    agss: &mut Option<Agss>,
    rcache: &ReplayCache,
    rec: &[u8],
    addr: &str,
) -> Result<Vec<u8>, Error> {
    let mut r = XdrR::new(rec);
    let xid = r.u32()?;
    let mtype = r.u32()?;
    if mtype != MSG_CALL {
        return Ok(Vec::new());
    }
    let rpcvers = r.u32()?;
    if rpcvers != RPC_VERSION {
        return Ok(Vec::new());
    }
    let prog = r.u32()?;
    let vers = r.u32()?;
    let proc = r.u32()?;
    let cred_flavor = r.u32()?;
    let cred = r.opaque()?;
    let header_end = r.i;
    let verf_flavor = r.u32()?;
    let verf = r.opaque()?;

    tracing::info!(
        event = krb5_log::events::ADMIN,
        component = "krb5-admin",
        outcome = "ok",
        detail = "rpc.flavor",
        rpc_flavor = if cred_flavor == FLAVOR_GSS {
            "RPCSEC_GSS"
        } else if cred_flavor == FLAVOR_AUTH_GSSAPI {
            "AUTH_GSSAPI"
        } else {
            "OTHER"
        },
        prog,
    );

    let kadm = prog == KADM_PROG;
    let iprop = prog == IPROP_PROG;
    if cred_flavor == FLAVOR_GSS {
        return handle_rpcsec_gss(
            store,
            acl,
            service_keys,
            expected_realm,
            handle,
            gss,
            xid,
            proc,
            kadm,
            iprop,
            vers,
            &cred,
            verf_flavor,
            &verf,
            rec,
            header_end,
            r.rest(),
            rcache,
            addr,
        );
    }

    // svc.c:486-520: AUTH_NONE is AUTH_OK, then program/version.
    if kadm && vers != KADM_VERS {
        return Ok(rpc_reply_mismatch(xid, KADM_VERS, KADM_VERS));
    }
    if iprop && vers != IPROP_VERS {
        return Ok(rpc_reply_mismatch(xid, IPROP_VERS, IPROP_VERS));
    }
    if !kadm && !iprop {
        return Ok(rpc_reply_accepted(xid, PROG_UNAVAIL));
    }

    if cred_flavor == FLAVOR_AUTH_GSSAPI {
        return handle_auth_gssapi(
            store,
            acl,
            service_keys,
            expected_realm,
            agss,
            xid,
            proc,
            iprop,
            &cred,
            &verf,
            r.rest(),
            rcache,
        );
    }

    // kadm_rpc_svc.c:80-87: only AUTH_GSSAPI / RPCSEC_GSS.
    Ok(rpc_reply_weakauth(xid))
}

#[allow(clippy::too_many_arguments, clippy::unnecessary_wraps)]
fn handle_rpcsec_gss(
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

/// MIT `server_stubs.c` op name for the `Request:`/`Unauthorized request:`
/// kadmind log lines; `None` for the procs MIT does not log this way.
fn kadm5_op_name(proc: u32) -> Option<&'static str> {
    Some(match proc {
        CREATE_PRINCIPAL | CREATE_PRINCIPAL3 => "kadm5_create_principal",
        DELETE_PRINCIPAL => "kadm5_delete_principal",
        MODIFY_PRINCIPAL => "kadm5_modify_principal",
        RENAME_PRINCIPAL => "kadm5_rename_principal",
        GET_PRINCIPAL => "kadm5_get_principal",
        CHPASS_PRINCIPAL | CHPASS_PRINCIPAL3 => "kadm5_chpass_principal",
        CHRAND_PRINCIPAL | CHRAND_PRINCIPAL3 => "kadm5_randkey_principal",
        SETKEY_PRINCIPAL | SETKEY_PRINCIPAL3 | SETKEY_PRINCIPAL4 => "kadm5_setkey_principal",
        GET_PRINCS => "kadm5_get_principals",
        CREATE_POLICY => "kadm5_create_policy",
        DELETE_POLICY => "kadm5_delete_policy",
        MODIFY_POLICY => "kadm5_modify_policy",
        GET_POLICY => "kadm5_get_policy",
        GET_POLS => "kadm5_get_policies",
        GET_PRIVS => "kadm5_get_privs",
        PURGEKEYS => "kadm5_purgekeys",
        GET_STRINGS => "kadm5_get_strings",
        SET_STRING => "kadm5_mod_strings",
        EXTRACT_KEYS => "kadm5_get_principal_keys",
        CREATE_ALIAS => "kadm5_create_alias",
        _ => return None,
    })
}

fn kadm5_auth_denied(code: u32) -> bool {
    matches!(
        code,
        KADM5_AUTH_GET
            | KADM5_AUTH_ADD
            | KADM5_AUTH_MODIFY
            | KADM5_AUTH_DELETE
            | KADM5_AUTH_INSUFFICIENT
            | KADM5_AUTH_LIST
            | KADM5_AUTH_CHANGEPW
            | KADM5_AUTH_SETKEY
            | KADM5_AUTH_EXTRACT
            | KADM5_AUTH_INITIAL
    )
}

/// `krb5_timeofday` for `impose_restrictions`' `-expire`/`-pwexpire` caps.
fn unix_now() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(u32::MAX)
}

/// `auth_restrict` for a modify request: the actor's ACL restrictions, if
/// any, imposed on the parsed `(mask, fields)` (`auth.c:205-272`).
fn impose_request_restrictions(
    acl: &krb5_kdc::Acl,
    actor: &str,
    tid: &str,
    mask: u32,
    mut fields: ModFields,
) -> (u32, ModFields) {
    let Some(rs) = acl.restrictions(actor, Some(tid)) else {
        return (mask, fields);
    };
    let mut ent = fields.admin_ent(mask);
    rs.impose(&mut ent, unix_now());
    let mask = fields.take_admin_ent(ent);
    (mask, fields)
}

/// The kadmind acceptor principal for the `service=` field (`kadmin/admin@REALM`).
fn kadm5_service_name(ctx: &GssContext) -> String {
    match (&ctx.acceptor, &ctx.ticket_realm) {
        (Some(a), Some(r)) => a.unparse_with_realm(r),
        _ => String::new(),
    }
}

/// MIT `prime_arg` (`stub_setup`): the unparsed principal for a principal op,
/// the policy/expression for a policy or list op, else the client.
fn kadm5_prime_arg(proc: u32, args: &[u8], client: &str) -> String {
    let mut r = XdrR::new(args);
    if r.u32().is_err() {
        return client.to_owned();
    }
    match proc {
        CREATE_PRINCIPAL | CREATE_PRINCIPAL3 | DELETE_PRINCIPAL | MODIFY_PRINCIPAL
        | GET_PRINCIPAL | CHPASS_PRINCIPAL | CHPASS_PRINCIPAL3 | CHRAND_PRINCIPAL
        | CHRAND_PRINCIPAL3 | SETKEY_PRINCIPAL | SETKEY_PRINCIPAL3 | SETKEY_PRINCIPAL4
        | PURGEKEYS | GET_STRINGS | SET_STRING | EXTRACT_KEYS | RENAME_PRINCIPAL | CREATE_ALIAS => {
            r.principal_realm().map_or_else(
                |_| client.to_owned(),
                |(p, realm)| p.unparse_with_realm(&realm),
            )
        }
        CREATE_POLICY | DELETE_POLICY | MODIFY_POLICY | GET_POLICY => r
            .nullstring()
            .ok()
            .flatten()
            .unwrap_or_else(|| client.to_owned()),
        GET_PRINCS | GET_POLS => match r.nullstring() {
            Ok(Some(s)) if !s.is_empty() => s,
            _ => "*".to_owned(),
        },
        _ => client.to_owned(),
    }
}

/// The kadm5 result text for `log_done`; the full `com_err` table is not ported,
/// so a non-success, non-denial code logs a generic phrase (documented).
fn kadm5_result_text(code: u32) -> &'static str {
    if code == 0 {
        "success"
    } else {
        "operation failed"
    }
}

/// MIT `log_done`/`log_unauth` (`server_stubs.c:403-459`): one `Request:` or
/// `Unauthorized request:` line per kadmind operation with client/service/addr.
fn kadm5_log_op(proc: u32, args: &[u8], client: &str, ctx: &GssContext, addr: &str, reply: &[u8]) {
    let Some(op) = kadm5_op_name(proc) else {
        return;
    };
    let code = reply
        .get(4..8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_be_bytes);
    let target = kadm5_prime_arg(proc, args, client);
    let service = kadm5_service_name(ctx);
    if kadm5_auth_denied(code) {
        tracing::info!(
            event = krb5_log::events::ADMIN,
            component = "krb5-admin",
            outcome = "unauthorized",
            "Unauthorized request: {op}, {target}, client={client}, service={service}, addr={addr}"
        );
    } else {
        let result = kadm5_result_text(code);
        tracing::info!(
            event = krb5_log::events::ADMIN,
            component = "krb5-admin",
            outcome = "done",
            "Request: {op}, {target}, {result}, client={client}, service={service}, addr={addr}"
        );
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
fn handle_auth_gssapi(
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

fn rpc_reply_weakauth(xid: u32) -> Vec<u8> {
    rpc_reply_auth_error(xid, AUTH_TOOWEAK)
}

fn rpc_reply_auth_error(xid: u32, stat: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_DENIED);
    w.u32(REJECT_AUTH_ERROR);
    w.u32(stat);
    w.b
}

fn rpc_reply_accepted(xid: u32, stat: u32) -> Vec<u8> {
    rpc_reply_accepted_verf(xid, None, stat)
}

fn write_rpc_verf(w: &mut XdrW, verf: Option<&[u8]>) {
    if let Some(mic) = verf {
        w.u32(FLAVOR_GSS);
        w.opaque(mic);
    } else {
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
    }
}

fn rpc_reply_accepted_verf(xid: u32, verf: Option<&[u8]>, stat: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    write_rpc_verf(&mut w, verf);
    w.u32(stat);
    w.b
}

fn rpc_reply_mismatch(xid: u32, low: u32, high: u32) -> Vec<u8> {
    rpc_reply_mismatch_verf(xid, None, low, high)
}

fn rpc_reply_mismatch_verf(xid: u32, verf: Option<&[u8]>, low: u32, high: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    write_rpc_verf(&mut w, verf);
    w.u32(PROG_MISMATCH);
    w.u32(low);
    w.u32(high);
    w.b
}

#[allow(clippy::too_many_arguments)]
fn kadm5_or_iprop(
    store: &SharedStore,
    acl: &Acl,
    actor: &str,
    proc: u32,
    args: &[u8],
    initial: bool,
    changepw: bool,
    iprop: bool,
) -> Result<Vec<u8>, Error> {
    if proc == 0 {
        return Ok(Vec::new());
    }
    if iprop {
        if !matches!(
            proc,
            IPROP_GET_UPDATES | IPROP_FULL_RESYNC | IPROP_FULL_RESYNC_EXT
        ) {
            return Err(Error::ProcUnavail);
        }
        return Ok(dispatch_iprop(store, acl, actor, proc, args));
    }
    dispatch_kadm5_ticket(store, acl, actor, proc, args, initial, changepw)
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

fn rpc_reply_gss_verf(xid: u32, mic: &[u8], body: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    w.u32(FLAVOR_GSS);
    w.opaque(mic);
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

fn tl_u32(tl: &[TlData], ty: i32) -> Option<u32> {
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

fn encode_fullresync_status(last: u32, status: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    encode_kdb_last(&mut w, last);
    w.u32(status);
    w.b
}

fn encode_fullresync(last: u32) -> Vec<u8> {
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
/// GSS, RPC, XDR, or crypto failures.
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

fn write_store(
    store: &SharedStore,
    proc: u32,
    api: u32,
) -> Result<std::sync::RwLockWriteGuard<'_, krb5_kdc::PrincipalStore>, Vec<u8>> {
    let mut g = store
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Reload then mutate then save. Two processes can still interleave
    // that window; a dump file lock is deferred with db2/LMDB.
    if let Err(e) = g.reload_if_stale() {
        return Err(generic_ret(api, kadm5_code(proc, &Error::from(e))));
    }
    Ok(g)
}

fn acl_id(name: &PrincipalName, realm: &str) -> String {
    name.unparse_with_realm(realm)
}

fn parse_actor(actor: &str) -> Option<(PrincipalName, String)> {
    krb5_types::principal_from_unparsed(actor, "").ok()
}

const MAX_SELF_KEEPOLD: u32 = 5;

fn clamp_self_keepold(self_change: bool, keepold: bool) -> u32 {
    if !keepold {
        0
    } else if self_change {
        MAX_SELF_KEEPOLD
    } else {
        1
    }
}

fn is_self(actor: &str, name: &PrincipalName, realm: &str) -> bool {
    let Some((actor_name, arealm)) = parse_actor(actor) else {
        return false;
    };
    krb5_types::principal_compare(name, realm, &actor_name, &arealm)
}

fn acceptor_realm_ok(
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

fn changepw_not_self(changepw: bool, actor: &str, name: &PrincipalName, realm: &str) -> bool {
    changepw && !is_self(actor, name, realm)
}

fn acceptor_parts(n: &PrincipalName) -> Vec<String> {
    n.name_string
        .iter()
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
        .collect()
}

fn kadm5_changepw_ok(n: &PrincipalName) -> bool {
    let p = acceptor_parts(n);
    p.len() == 2 && p[0] == "kadmin" && p[1] == "changepw"
}

fn kadm5_auth_gssapi_ok(n: &PrincipalName) -> bool {
    let p = acceptor_parts(n);
    p.len() == 2 && p[0] == "kadmin" && (p[1] == "admin" || p[1] == "changepw")
}

fn kadm5_rpcsec_ok(n: &PrincipalName) -> bool {
    let p = acceptor_parts(n);
    p.len() == 2 && p[0] == "kadmin" && p[1] != "history"
}

fn iprop_rpcsec_ok(n: &PrincipalName) -> bool {
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

fn store_realm(store: &SharedStore) -> String {
    store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .realm()
        .to_owned()
}

fn req_realm(prealm: &str, store_realm: &str) -> String {
    if prealm.is_empty() {
        store_realm.to_owned()
    } else {
        prealm.to_owned()
    }
}

#[cfg(test)]
fn dispatch_kadm5(
    store: &SharedStore,
    acl: &Acl,
    actor: &str,
    proc: u32,
    args: &[u8],
) -> Result<Vec<u8>, Error> {
    dispatch_kadm5_ticket(store, acl, actor, proc, args, true, false)
}

fn dispatch_kadm5_ticket(
    store: &SharedStore,
    acl: &Acl,
    actor: &str,
    proc: u32,
    args: &[u8],
    initial: bool,
    changepw: bool,
) -> Result<Vec<u8>, Error> {
    let realm = store_realm(store);
    match proc {
        INIT => Ok(generic_ret(API_V2, 0)),
        GET_PRIVS => {
            let mut w = XdrW::default();
            w.u32(API_V2);
            w.u32(0);
            w.u32(!0);
            Ok(w.b)
        }
        GET_PRINCIPAL => {
            let (name, prealm, _mask) = parse_get(args)?;
            let req = req_realm(&prealm, &realm);
            let g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            match g.get_in_realm(&name, &req) {
                None => Ok(generic_ret(API_V2, KADM5_UNK_PRINC)),
                Some(p) => {
                    let tid = acl_id(&name, &req);
                    if changepw_not_self(changepw, actor, &name, &req)
                        || (acl
                            .check(actor, krb5_kdc::AdminOp::Inquire, Some(&tid))
                            .is_err()
                            && !is_self(actor, &name, &req))
                    {
                        return Ok(generic_ret(API_V2, KADM5_AUTH_GET));
                    }
                    tracing::info!(
                        event = krb5_log::events::ADMIN,
                        component = "krb5-admin",
                        outcome = "ok",
                        detail = "getprinc",
                        principal = p.id(),
                    );
                    Ok(encode_gprinc(p))
                }
            }
        }
        GET_PRINCS => {
            if changepw || acl.check(actor, krb5_kdc::AdminOp::List, None).is_err() {
                return Ok(generic_ret(API_V2, KADM5_AUTH_LIST));
            }
            let expr = parse_gprincs(args)?;
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let glob = expr.as_deref().unwrap_or("*");
            if !glob_pattern_ok(glob) {
                return Ok(generic_ret(API_V2, EINVAL));
            }
            let mut ids = g.ids();
            if glob != "*" && !glob.is_empty() {
                let pat = glob_expand(glob, true);
                ids.retain(|id| glob_is_match(pat.as_bytes(), id.as_bytes()));
            }
            Ok(encode_gprincs(&ids))
        }
        DELETE_PRINCIPAL => {
            let (name, prealm) = parse_one_princ(args)?;
            let req = req_realm(&prealm, &realm);
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::Delete, Some(&acl_id(&name, &req)))
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_DELETE));
            }
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req)
                .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0)
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_DELETE));
            }
            match g.remove_in(&name, &req) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        MODIFY_PRINCIPAL => {
            let (name, prealm, mask, fields) = parse_modify(args)?;
            let req = req_realm(&prealm, &realm);
            let tid = acl_id(&name, &req);
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            // stub_setup rec_out, then ACL, then check_lockdown, then mask
            // (server_stubs.c:296-301,621-638).
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(API_V2, KADM5_UNK_PRINC));
            }
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::Modify, Some(&tid))
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_MODIFY));
            }
            // stub_auth_restrict → auth_restrict → impose_restrictions on
            // the request (`auth.c:205-272`) before check_lockdown and the
            // library's mask validation (`server_stubs.c:630-638`).
            let (mask, fields) = impose_request_restrictions(acl, actor, &tid, mask, fields);
            if mask & KADM5_ATTRIBUTES != 0
                && fields.attributes & KDB_LOCKDOWN_KEYS == 0
                && g.get_in_realm(&name, &req)
                    .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0)
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_MODIFY));
            }
            if let Some(code) = modify_princ_mask_err(mask, fields.policy.as_deref()) {
                return Ok(generic_ret(API_V2, code));
            }
            if mask & KADM5_TL_DATA != 0 && fields.tl_data.iter().any(|t| t.ty < 256) {
                return Ok(generic_ret(API_V2, KADM5_BAD_TL_TYPE));
            }
            if mask & KADM5_FAIL_AUTH_COUNT != 0 && fields.fail_auth_count != 0 {
                return Ok(generic_ret(API_V2, KADM5_BAD_SERVER_PARAMS));
            }
            if mask & KADM5_TL_DATA != 0 && db_args_code(&fields.tl_data).is_some() {
                return Ok(generic_ret(API_V2, EINVAL));
            }
            let attributes = (mask & KADM5_ATTRIBUTES != 0).then_some(fields.attributes);
            let max_life = (mask & KADM5_MAX_LIFE != 0).then_some(u64::from(fields.max_life));
            let max_renewable_life =
                (mask & KADM5_MAX_RLIFE != 0).then_some(u64::from(fields.max_rlife));
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
            match g.apply_admin_fields_in(
                &name,
                &req,
                attributes,
                max_life,
                expiration,
                pw_expire,
                policy,
                clear_policy,
                max_renewable_life,
                actor,
            ) {
                Ok(()) => {
                    if mask & KADM5_TL_DATA != 0
                        && let Err(e) = g.merge_tl_data_in(&name, &req, &fields.tl_data)
                    {
                        return Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e))));
                    }
                    if mask & KADM5_FAIL_AUTH_COUNT != 0
                        && let Err(e) = g.clear_fail_auth_count_in(&name, &req)
                    {
                        return Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e))));
                    }
                    Ok(generic_ret(API_V2, 0))
                }
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        CREATE_PRINCIPAL | CREATE_PRINCIPAL3 => {
            let mut c = match parse_ks(parse_create(args, proc == CREATE_PRINCIPAL3)) {
                Ok(c) => c,
                Err(rep) => return rep,
            };
            let req = req_realm(&c.prealm, &realm);
            let tid = acl_id(&c.name, &req);
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::Create, Some(&tid))
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_ADD));
            }
            // stub_auth_restrict (`server_stubs.c:478,519`): the ACL line's
            // restrictions rewrite the request (`auth.c:205-272`) before
            // kadm5_create_principal_3 validates the mask, loads the policy
            // and runs passwd_check — so a `-policy P` restriction is
            // enforced by P's floors and the quality modules.
            if let Some(rs) = acl.restrictions(actor, Some(&tid)) {
                rs.impose(&mut c.ent, unix_now());
            }
            if let Some(code) =
                create_princ_mask_err(c.ent.mask, c.ent.policy.as_deref(), c.n_key_data)
            {
                return Ok(generic_ret(API_V2, code));
            }
            if c.ent.mask & KADM5_TL_DATA != 0 && c.tl_data.iter().any(|t| t.ty < 256) {
                return Ok(generic_ret(API_V2, KADM5_BAD_TL_TYPE));
            }
            if c.ent.mask & KADM5_TL_DATA != 0 && db_args_code(&c.tl_data).is_some() {
                return Ok(generic_ret(API_V2, EINVAL));
            }
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            // NULL password: random key (`krb5_dbe_crk`), no quality check.
            // `-nokey` (KADM5_KEY_DATA) also lands here — MIT would create a
            // keyless entry (ledger deviation).
            let created = g.create_principal_3_in(
                &c.name,
                &req,
                c.pass.as_deref().map(str::as_bytes),
                &c.ks,
                &c.ent,
                actor,
            );
            match created {
                Ok(()) => {
                    if c.ent.mask & KADM5_TL_DATA != 0
                        && let Err(e) = g.merge_tl_data_in(&c.name, &req, &c.tl_data)
                    {
                        return Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e))));
                    }
                    Ok(generic_ret(API_V2, 0))
                }
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        RENAME_PRINCIPAL => {
            let (old, old_realm, new, new_realm) = parse_rename(args)?;
            let old_req = req_realm(&old_realm, &realm);
            let new_req = req_realm(&new_realm, &realm);
            // MIT server_stubs.c:700-712: ACL (AUTH_INSUFFICIENT) then lockdown (AUTH_DELETE).
            // auth_acl.c:638-648: delete on src and add on dest without restrictions.
            if changepw
                || acl
                    .check_rename(actor, &acl_id(&old, &old_req), &acl_id(&new, &new_req))
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_INSUFFICIENT));
            }
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&old, &old_req)
                .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0)
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_DELETE));
            }
            match g.rename_unchecked(&old, &old_req, &new, &new_req, actor) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        CHPASS_PRINCIPAL | CHPASS_PRINCIPAL3 => {
            let (name, prealm, pass, keepold, ks) =
                match parse_ks(parse_chpass(args, proc == CHPASS_PRINCIPAL3)) {
                    Ok(v) => v,
                    Err(rep) => return rep,
                };
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            let lockdown = match g.get_in_realm(&name, &req) {
                None => return Ok(generic_ret(API_V2, KADM5_UNK_PRINC)),
                Some(p) => p.attributes & KDB_LOCKDOWN_KEYS != 0,
            };
            if lockdown {
                return Ok(generic_ret(API_V2, KADM5_AUTH_CHANGEPW));
            }
            let self_change = is_self(actor, &name, &req);
            if !self_change
                && (changepw
                    || acl
                        .check(
                            actor,
                            krb5_kdc::AdminOp::ChangePassword,
                            Some(&acl_id(&name, &req)),
                        )
                        .is_err())
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_CHANGEPW));
            }
            if self_change && !initial {
                return Ok(generic_ret(API_V2, KADM5_AUTH_INITIAL));
            }
            if self_change && let Err(e) = g.check_min_life_in(&name, &req) {
                return Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e))));
            }
            let n = clamp_self_keepold(self_change, keepold);
            match g.set_password_etypes_keepold_n_in(&name, &req, pass.as_bytes(), n, actor, &ks) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        CREATE_POLICY => {
            let (api, mut pol, mask) = parse_policy_arg(args)?;
            if changepw || acl.check(actor, krb5_kdc::AdminOp::Create, None).is_err() {
                return Ok(generic_ret(api, KADM5_AUTH_ADD));
            }
            if let Some(code) = policy_mask_err(mask, true) {
                return Ok(generic_ret(api, code));
            }
            if mask & KADM5_POLICY_ALLOWED_KEYSALTS != 0
                && let Some(code) = validate_allowed_keysalts(pol.allowed_keysalts.as_deref())
            {
                return Ok(generic_ret(api, code));
            }
            let mut g = match write_store(store, proc, api) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.policies().contains_key(&pol.name) {
                return Ok(generic_ret(api, KADM5_DUP));
            }
            if let Some(code) = policy_name_err(&pol.name) {
                return Ok(generic_ret(api, code));
            }
            if mask & KADM5_PW_MAX_LIFE == 0 {
                pol.pw_max_life = 0;
            }
            if mask & KADM5_PW_MIN_LIFE == 0 {
                pol.pw_min_life = 0;
            }
            if mask & KADM5_POLICY_ALLOWED_KEYSALTS == 0 {
                pol.allowed_keysalts = None;
            }
            if let Some(code) = policy_floor_err(&pol, mask) {
                return Ok(generic_ret(api, code));
            }
            apply_policy_floors(&mut pol, mask);
            g.put_policy(pol);
            Ok(generic_ret(api, 0))
        }
        DELETE_POLICY => {
            let (api, name) = parse_policy_name(args)?;
            if changepw || acl.check(actor, krb5_kdc::AdminOp::Delete, None).is_err() {
                return Ok(generic_ret(api, KADM5_AUTH_DELETE));
            }
            let mut g = match write_store(store, proc, api) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            match g.delete_policy(&name) {
                Ok(()) => Ok(generic_ret(api, 0)),
                Err(krb5_kdc::Error::NotFound) => Ok(generic_ret(api, KADM5_UNK_POLICY)),
                Err(e) => Ok(generic_ret(api, kadm5_code(proc, &Error::from(e)))),
            }
        }
        MODIFY_POLICY => {
            let (api, rec, mask) = parse_policy_arg(args)?;
            if changepw || acl.check(actor, krb5_kdc::AdminOp::Modify, None).is_err() {
                return Ok(generic_ret(api, KADM5_AUTH_MODIFY));
            }
            if let Some(code) = policy_name_err(&rec.name) {
                return Ok(generic_ret(api, code));
            }
            if let Some(code) = policy_mask_err(mask, false) {
                return Ok(generic_ret(api, code));
            }
            if mask & KADM5_POLICY_ALLOWED_KEYSALTS != 0
                && let Some(code) = validate_allowed_keysalts(rec.allowed_keysalts.as_deref())
            {
                return Ok(generic_ret(api, code));
            }
            let mut g = match write_store(store, proc, api) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            let Some(existing) = g.policies().get(&rec.name).cloned() else {
                return Ok(generic_ret(api, KADM5_UNK_POLICY));
            };
            let merged = merge_policy(existing, &rec, mask);
            if let Some(code) = policy_floor_err(&merged, mask) {
                return Ok(generic_ret(api, code));
            }
            g.put_policy(merged);
            Ok(generic_ret(api, 0))
        }
        GET_POLICY => {
            let (api, name) = parse_policy_name(args)?;
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let own_pol = parse_actor(actor)
                .and_then(|(n, _)| g.get_name(&n).and_then(|p| p.pw_policy.clone()));
            if (changepw || acl.check(actor, krb5_kdc::AdminOp::Inquire, None).is_err())
                && own_pol.as_deref() != Some(name.as_str())
            {
                return Ok(generic_ret(api, KADM5_AUTH_GET));
            }
            match g.policies().get(&name) {
                Some(p) => Ok(encode_policy(api, p)),
                None => Ok(generic_ret(api, KADM5_UNK_POLICY)),
            }
        }
        GET_POLS => {
            let (api, expr) = parse_gpols(args);
            if changepw || acl.check(actor, krb5_kdc::AdminOp::List, None).is_err() {
                return Ok(generic_ret(api, KADM5_AUTH_LIST));
            }
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut names: Vec<_> = g.policies().keys().cloned().collect();
            let glob = expr.as_deref().unwrap_or("*");
            if !glob_pattern_ok(glob) {
                return Ok(generic_ret(api, EINVAL));
            }
            if glob != "*" && !glob.is_empty() {
                let pat = glob_expand(glob, false);
                names.retain(|n| glob_is_match(pat.as_bytes(), n.as_bytes()));
            }
            names.sort();
            Ok(encode_pols(api, &names))
        }
        CHRAND_PRINCIPAL | CHRAND_PRINCIPAL3 => {
            let (name, prealm, keepold, ks) =
                match parse_ks(parse_chrand(args, proc == CHRAND_PRINCIPAL3)) {
                    Ok(v) => v,
                    Err(rep) => return rep,
                };
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(API_V2, KADM5_UNK_PRINC));
            }
            let self_change = is_self(actor, &name, &req);
            if changepw_not_self(changepw, actor, &name, &req)
                || (acl
                    .check(
                        actor,
                        krb5_kdc::AdminOp::ChangePassword,
                        Some(&acl_id(&name, &req)),
                    )
                    .is_err()
                    && !self_change)
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_CHANGEPW));
            }
            if self_change && !initial {
                return Ok(generic_ret(API_V2, KADM5_AUTH_INITIAL));
            }
            if self_change && let Err(e) = g.check_min_life_in(&name, &req) {
                return Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e))));
            }
            let n = clamp_self_keepold(self_change, keepold);
            match g.chrand_etypes_keepold_in(&name, &req, &ks, n, actor) {
                Ok(keys) => {
                    let hide = g
                        .get_in_realm(&name, &req)
                        .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0);
                    Ok(encode_chrand(if hide { &[] } else { &keys }))
                }
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        EXTRACT_KEYS => {
            let (api, name, prealm, kvno) = parse_extract(args)?;
            let req = req_realm(&prealm, &realm);
            let g = match write_store(store, proc, api) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            let Some(p) = g.get_in_realm(&name, &req) else {
                return Ok(generic_ret(api, KADM5_UNK_PRINC));
            };
            if changepw
                || acl
                    .check(
                        actor,
                        krb5_kdc::AdminOp::Extract,
                        Some(&acl_id(&name, &req)),
                    )
                    .is_err()
            {
                return Ok(generic_ret(api, KADM5_AUTH_EXTRACT));
            }
            if p.attributes & KDB_LOCKDOWN_KEYS != 0 {
                return Ok(generic_ret(api, KADM5_AUTH_EXTRACT));
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
            let (api, name, prealm, keepkvno) = parse_purgekeys(args)?;
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(api, KADM5_UNK_PRINC));
            }
            if changepw
                || (acl
                    .check(actor, krb5_kdc::AdminOp::Modify, Some(&acl_id(&name, &req)))
                    .is_err()
                    && !is_self(actor, &name, &req))
            {
                return Ok(generic_ret(api, KADM5_AUTH_MODIFY));
            }
            match g.purgekeys_in(&name, &req, keepkvno, actor) {
                Ok(()) => {
                    tracing::info!(
                        event = krb5_log::events::ADMIN,
                        component = "krb5-admin",
                        outcome = "ok",
                        detail = "purgekeys",
                    );
                    Ok(generic_ret(api, 0))
                }
                Err(e) => Ok(generic_ret(api, kadm5_code(proc, &Error::from(e)))),
            }
        }
        SETKEY_PRINCIPAL | SETKEY_PRINCIPAL3 | SETKEY_PRINCIPAL4 => {
            let (api, name, prealm, keys, keepold) = parse_setkey(args, proc)?;
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(api, KADM5_UNK_PRINC));
            }
            let lockdown = g
                .get_in_realm(&name, &req)
                .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0);
            if lockdown {
                return Ok(generic_ret(api, KADM5_AUTH_SETKEY));
            }
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::SetKey, Some(&acl_id(&name, &req)))
                    .is_err()
            {
                return Ok(generic_ret(api, KADM5_AUTH_SETKEY));
            }
            let n = clamp_self_keepold(is_self(actor, &name, &req), keepold);
            match g.set_keys_in(&name, &req, keys, n, actor) {
                Ok(()) => Ok(generic_ret(api, 0)),
                Err(e) => Ok(generic_ret(api, kadm5_code(proc, &Error::from(e)))),
            }
        }
        GET_STRINGS => {
            let (api, name, prealm) = parse_gstrings(args)?;
            let req = req_realm(&prealm, &realm);
            let g = match write_store(store, proc, api) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(api, KADM5_UNK_PRINC));
            }
            if changepw
                || (acl
                    .check(
                        actor,
                        krb5_kdc::AdminOp::Inquire,
                        Some(&acl_id(&name, &req)),
                    )
                    .is_err()
                    && !is_self(actor, &name, &req))
            {
                return Ok(generic_ret(api, KADM5_AUTH_GET));
            }
            match g.get_strings_in(&name, &req) {
                Ok(attrs) => Ok(encode_gstrings(api, &attrs)),
                Err(e) => Ok(generic_ret(api, kadm5_code(proc, &Error::from(e)))),
            }
        }
        SET_STRING => {
            let (api, name, prealm, key, value) = parse_sstring(args)?;
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(api, KADM5_UNK_PRINC));
            }
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::Modify, Some(&acl_id(&name, &req)))
                    .is_err()
            {
                return Ok(generic_ret(api, KADM5_AUTH_MODIFY));
            }
            if key.is_empty() {
                return Ok(generic_ret(api, KADM5_FAILURE));
            }
            match g.set_string_in(&name, &req, &key, value.as_deref(), actor) {
                Ok(()) => Ok(generic_ret(api, 0)),
                Err(e) => Ok(generic_ret(api, kadm5_code(proc, &Error::from(e)))),
            }
        }
        CREATE_ALIAS => {
            let (alias, alias_realm, target, target_realm) = parse_alias(args)?;
            let alias_req = req_realm(&alias_realm, &realm);
            let target_req = req_realm(&target_realm, &realm);
            // server_stubs.c:1727-1758: CHANGEPW deny, acl_addalias, no lockdown check.
            if changepw
                || acl
                    .check_addalias(
                        actor,
                        &acl_id(&alias, &alias_req),
                        &acl_id(&target, &target_req),
                    )
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_INSUFFICIENT));
            }
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            match g.create_alias_in(&alias, &alias_req, &target, &target_req, actor) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        _ => Err(Error::ProcUnavail),
    }
}

/// The `KADM5_AUTH_*` code a stub denies with (`server_stubs.c`, the
/// `ret->code = KADM5_AUTH_…` of each `*_2_svc`): ADD for the creates
/// (`:480,521,1268`), DELETE for the deletes (`:582,1311`), MODIFY for
/// modify/purgekeys/set_string/modify_policy (`:633,1515,1594,1352`),
/// INSUFFICIENT for rename and create_alias (`:702,1743`), GET for the gets
/// (`:772,1400,1553`), LIST for the lists (`:816,1445`), CHANGEPW for
/// chpass/chrand (`:860,915,1150,1210`), SETKEY for setkey (`:971,1023,1077`),
/// EXTRACT for get_principal_keys (`:1691`).
fn auth_code_for(proc: u32) -> u32 {
    match proc {
        CREATE_PRINCIPAL | CREATE_PRINCIPAL3 | CREATE_POLICY => KADM5_AUTH_ADD,
        DELETE_PRINCIPAL | DELETE_POLICY => KADM5_AUTH_DELETE,
        MODIFY_PRINCIPAL | MODIFY_POLICY | PURGEKEYS | SET_STRING => KADM5_AUTH_MODIFY,
        RENAME_PRINCIPAL | CREATE_ALIAS => KADM5_AUTH_INSUFFICIENT,
        GET_PRINCS | GET_POLS => KADM5_AUTH_LIST,
        CHPASS_PRINCIPAL | CHPASS_PRINCIPAL3 | CHRAND_PRINCIPAL | CHRAND_PRINCIPAL3 => {
            KADM5_AUTH_CHANGEPW
        }
        SETKEY_PRINCIPAL | SETKEY_PRINCIPAL3 | SETKEY_PRINCIPAL4 => KADM5_AUTH_SETKEY,
        EXTRACT_KEYS => KADM5_AUTH_EXTRACT,
        _ => KADM5_AUTH_GET,
    }
}

/// kadm5 return code for a store error surfacing from the `proc` stub. A
/// store-level `AclDenied` takes the stub's own `KADM5_AUTH_*` (no in-tree
/// store path returns it today — the ACL is checked inline in each arm —
/// so this is latent hygiene, `working/w1-sweep/plan-w1z-0913-1915.md` Z1b.3).
fn kadm5_code(proc: u32, e: &Error) -> u32 {
    let s = match e {
        Error::AclDenied | Error::KpropUnauthorized(_) => return auth_code_for(proc),
        Error::NotFound => return KADM5_UNK_PRINC,
        Error::PassTooSoon { .. } => return KADM5_PASS_TOOSOON,
        Error::GarbageArgs | Error::ProcUnavail => return KADM5_FAILURE,
        Error::PasswordPolicy(s) | Error::Inner(s) => s.as_str(),
    };
    if s.starts_with("Unsupported argument") || s == "Invalid argument" {
        return EINVAL;
    }
    if s.contains("min_length") || s == krb5_kdc::PWQUAL_EMPTY {
        KADM5_PASS_Q_TOOSHORT
    } else if s.contains("min_classes") {
        KADM5_PASS_Q_CLASS
    } else if s == krb5_kdc::PWQUAL_DICT || s == krb5_kdc::PWQUAL_PRINC {
        KADM5_PASS_Q_DICT
    } else if s.contains("history") {
        KADM5_PASS_REUSE
    } else if s.contains("setkey kvno") {
        KADM5_SETKEY_BAD_KVNO
    } else if s == "Invalid key/salt tuples" {
        KADM5_BAD_KEYSALTS
    } else if s.contains("principal exists") {
        KADM5_DUP
    } else if s == "Alias target must be within the same realm" {
        KADM5_ALIAS_REALM
    } else if s == "Operation unsupported on alias principal name" {
        KRB5_KDB_ALIAS_UNSUPPORTED
    } else {
        KADM5_FAILURE
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
    let min_life = r.u32().unwrap_or(0);
    let max_life = r.u32().unwrap_or(0);
    let min_length = r.u32().unwrap_or(0);
    let min_classes = r.u32().unwrap_or(0);
    let history = r.u32().unwrap_or(0);
    let _refcnt = r.u32().unwrap_or(0);
    let mut max_fail = 0;
    let mut pw_failcnt_interval = 0;
    let mut pw_lockout_duration = 0;
    let mut allowed_keysalts = None;
    if api >= API_V3 {
        max_fail = r.u32().unwrap_or(0);
        pw_failcnt_interval = r.u32().unwrap_or(0);
        pw_lockout_duration = r.u32().unwrap_or(0);
    }
    if api >= API_V4 {
        let _ = r.u32();
        let _ = r.u32();
        let _ = r.u32();
        allowed_keysalts = r.nullstring().ok().flatten().filter(|s| !s.is_empty());
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
            pw_min_life: min_life,
            pw_max_life: max_life,
            allowed_keysalts,
        },
        mask,
    ))
}

fn merge_policy(
    mut existing: krb5_kdc::NamedPolicy,
    rec: &krb5_kdc::NamedPolicy,
    mask: u32,
) -> krb5_kdc::NamedPolicy {
    if mask & KADM5_PW_MIN_LIFE != 0 {
        existing.pw_min_life = rec.pw_min_life;
    }
    if mask & KADM5_PW_MAX_LIFE != 0 {
        existing.pw_max_life = rec.pw_max_life;
    }
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
    if mask & KADM5_POLICY_ALLOWED_KEYSALTS != 0 {
        existing.allowed_keysalts.clone_from(&rec.allowed_keysalts);
    }
    existing
}

const MIN_PW_LENGTH: u32 = 1;
const MIN_PW_CLASSES: u32 = 1;
const MAX_PW_CLASSES: u32 = 5;
const MIN_PW_HISTORY: u32 = 1;

/// MIT `kadm_err.et` text for a policy validation code (kadmin.local `com_err`).
pub(crate) fn policy_text(code: u32) -> &'static str {
    match code {
        KADM5_DUP => "Principal or policy already exists",
        KADM5_UNK_POLICY => "Policy does not exist",
        KADM5_BAD_POLICY => "Illegal policy name",
        KADM5_BAD_MIN_PASS_LIFE => "Password minimum life is greater than password maximum life",
        KADM5_BAD_LENGTH => "Invalid password length",
        KADM5_BAD_CLASS => "Invalid number of character classes",
        KADM5_BAD_HISTORY => "Invalid password history count",
        KADM5_BAD_KEYSALTS => "Invalid key/salt tuples",
        _ => "Operation failed",
    }
}

/// MIT `validate_allowed_keysalts` (`svr_policy.c:20-36`): a tab is
/// `KADM5_BAD_KEYSALTS`. `krb5_string_to_keysalts` skips unknown tokens
/// and only fails ENOMEM, so `addpol -allowedkeysalts bogus:normal`
/// succeeds on MIT 1.22.2 (live settle).
fn validate_allowed_keysalts(allowed: Option<&str>) -> Option<u32> {
    let s = allowed.filter(|s| !s.is_empty())?;
    if s.contains('\t') {
        return Some(KADM5_BAD_KEYSALTS);
    }
    None
}

/// Build an `osa_policy_ent` and its mask from CLI `PolicyArgs`.
pub(crate) fn build_policy(a: &crate::PolicyArgs) -> (krb5_kdc::NamedPolicy, u32) {
    let mut p = krb5_kdc::NamedPolicy::new(&a.name);
    let mut mask = 0u32;
    if let Some(v) = a.pw_max_life {
        p.pw_max_life = v;
        mask |= KADM5_PW_MAX_LIFE;
    }
    if let Some(v) = a.pw_min_life {
        p.pw_min_life = v;
        mask |= KADM5_PW_MIN_LIFE;
    }
    if let Some(v) = a.min_length {
        p.min_length = v;
        mask |= KADM5_PW_MIN_LENGTH;
    }
    if let Some(v) = a.min_classes {
        p.min_classes = v;
        mask |= KADM5_PW_MIN_CLASSES;
    }
    if let Some(v) = a.history {
        p.history = v;
        mask |= KADM5_PW_HISTORY_NUM;
    }
    if let Some(v) = a.max_fail {
        p.max_fail = v;
        mask |= KADM5_PW_MAX_FAILURE;
    }
    if let Some(v) = a.pw_failcnt_interval {
        p.pw_failcnt_interval = v;
        mask |= KADM5_PW_FAILURE_COUNT_INTERVAL;
    }
    if let Some(v) = a.pw_lockout_duration {
        p.pw_lockout_duration = v;
        mask |= KADM5_PW_LOCKOUT_DURATION;
    }
    if a.allowed_keysalts.is_some() {
        p.allowed_keysalts.clone_from(&a.allowed_keysalts);
        mask |= KADM5_POLICY_ALLOWED_KEYSALTS;
    }
    (p, mask)
}

/// `kadm5_create_policy` for kadmin.local: DUP -> name -> min>max -> length ->
/// classes -> history (`svr_policy.c`). Returns the MIT `com_err` text on failure.
pub(crate) fn create_policy_local(
    exists: bool,
    a: &crate::PolicyArgs,
) -> Result<krb5_kdc::NamedPolicy, &'static str> {
    let (mut pol, mask) = build_policy(a);
    if mask & KADM5_POLICY_ALLOWED_KEYSALTS != 0
        && let Some(code) = validate_allowed_keysalts(pol.allowed_keysalts.as_deref())
    {
        return Err(policy_text(code));
    }
    if exists {
        return Err(policy_text(KADM5_DUP));
    }
    if let Some(code) = policy_name_err(&a.name) {
        return Err(policy_text(code));
    }
    if let Some(code) = policy_floor_err(&pol, mask) {
        return Err(policy_text(code));
    }
    apply_policy_floors(&mut pol, mask);
    Ok(pol)
}

/// `kadm5_modify_policy` for kadmin.local: merge the masked fields onto the
/// existing policy, then the same floor checks (no name check).
pub(crate) fn modify_policy_local(
    existing: &krb5_kdc::NamedPolicy,
    a: &crate::PolicyArgs,
) -> Result<krb5_kdc::NamedPolicy, &'static str> {
    let (rec, mask) = build_policy(a);
    if mask & KADM5_POLICY_ALLOWED_KEYSALTS != 0
        && let Some(code) = validate_allowed_keysalts(rec.allowed_keysalts.as_deref())
    {
        return Err(policy_text(code));
    }
    let merged = merge_policy(existing.clone(), &rec, mask);
    if let Some(code) = policy_floor_err(&merged, mask) {
        return Err(policy_text(code));
    }
    Ok(merged)
}

pub(crate) fn policy_name_err(name: &str) -> Option<u32> {
    if name.is_empty() || name.bytes().any(|b| !(b' '..=b'~').contains(&b)) {
        return Some(KADM5_BAD_POLICY);
    }
    None
}

fn policy_mask_err(mask: u32, create: bool) -> Option<u32> {
    if mask & !ALL_POLICY_MASK != 0 {
        return Some(KADM5_BAD_MASK);
    }
    if create {
        if mask & KADM5_POLICY == 0 {
            return Some(KADM5_BAD_MASK);
        }
    } else if mask & KADM5_POLICY != 0 {
        return Some(KADM5_BAD_MASK);
    }
    None
}

/// MIT `kadm5_create_principal` mask checks (`svr_principal.c:313-326`).
fn create_princ_mask_err(mask: u32, policy: Option<&str>, n_key_data: u32) -> Option<u32> {
    if mask & KADM5_PRINCIPAL == 0
        || mask
            & (KADM5_MOD_NAME
                | KADM5_MOD_TIME
                | KADM5_LAST_PWD_CHANGE
                | KADM5_MKVNO
                | KADM5_AUX_ATTRIBUTES
                | KADM5_LAST_SUCCESS
                | KADM5_LAST_FAILED
                | KADM5_FAIL_AUTH_COUNT)
            != 0
    {
        return Some(KADM5_BAD_MASK);
    }
    if mask & KADM5_KEY_DATA != 0 && n_key_data != 0 {
        return Some(KADM5_BAD_MASK);
    }
    if mask & KADM5_POLICY != 0 && policy.is_none() {
        return Some(KADM5_BAD_MASK);
    }
    if mask & KADM5_POLICY != 0 && mask & KADM5_POLICY_CLR != 0 {
        return Some(KADM5_BAD_MASK);
    }
    if mask & !ALL_PRINC_MASK != 0 {
        return Some(KADM5_BAD_MASK);
    }
    None
}

/// MIT `kadm5_modify_principal` mask checks (`svr_principal.c:569-580`).
fn modify_princ_mask_err(mask: u32, policy: Option<&str>) -> Option<u32> {
    if mask
        & (KADM5_PRINCIPAL
            | KADM5_LAST_PWD_CHANGE
            | KADM5_MOD_TIME
            | KADM5_MOD_NAME
            | KADM5_MKVNO
            | KADM5_AUX_ATTRIBUTES
            | KADM5_KEY_DATA
            | KADM5_LAST_SUCCESS
            | KADM5_LAST_FAILED)
        != 0
    {
        return Some(KADM5_BAD_MASK);
    }
    if mask & !ALL_PRINC_MASK != 0 {
        return Some(KADM5_BAD_MASK);
    }
    if mask & KADM5_POLICY != 0 && policy.is_none() {
        return Some(KADM5_BAD_MASK);
    }
    if mask & KADM5_POLICY != 0 && mask & KADM5_POLICY_CLR != 0 {
        return Some(KADM5_BAD_MASK);
    }
    None
}

fn db_args_code(tls: &[TlData]) -> Option<u32> {
    tls.iter().any(|t| t.ty == TL_DB_ARGS).then_some(EINVAL)
}

/// MIT `xdr_krb5_int16` truncates `tl_data_type` before the `< 256` guard.
#[allow(clippy::cast_possible_truncation)]
fn xdr_tl_type(wire: u32) -> i32 {
    i32::from(wire as i16)
}

pub(crate) fn policy_floor_err(pol: &krb5_kdc::NamedPolicy, mask: u32) -> Option<u32> {
    if mask & KADM5_PW_MIN_LIFE != 0 && pol.pw_min_life > pol.pw_max_life && pol.pw_max_life != 0 {
        return Some(KADM5_BAD_MIN_PASS_LIFE);
    }
    if mask & KADM5_PW_MIN_LENGTH != 0 && pol.min_length < MIN_PW_LENGTH {
        return Some(KADM5_BAD_LENGTH);
    }
    if mask & KADM5_PW_MIN_CLASSES != 0
        && (pol.min_classes < MIN_PW_CLASSES || pol.min_classes > MAX_PW_CLASSES)
    {
        return Some(KADM5_BAD_CLASS);
    }
    if mask & KADM5_PW_HISTORY_NUM != 0 && pol.history < MIN_PW_HISTORY {
        return Some(KADM5_BAD_HISTORY);
    }
    None
}

pub(crate) fn apply_policy_floors(pol: &mut krb5_kdc::NamedPolicy, mask: u32) {
    if mask & KADM5_PW_MIN_LENGTH == 0 {
        pol.min_length = MIN_PW_LENGTH;
    }
    if mask & KADM5_PW_MIN_CLASSES == 0 {
        pol.min_classes = MIN_PW_CLASSES;
    }
    if mask & KADM5_PW_HISTORY_NUM == 0 {
        pol.history = MIN_PW_HISTORY;
    }
}

fn encode_policy_rec(w: &mut XdrW, api: u32, p: &krb5_kdc::NamedPolicy) {
    w.nullstring(Some(&p.name));
    w.u32(p.pw_min_life);
    w.u32(p.pw_max_life);
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
        w.nullstring(p.allowed_keysalts.as_deref());
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

struct CreateFields {
    name: PrincipalName,
    prealm: String,
    /// `None` is the XDR NULL `passwd` of `kadmin addprinc -randkey`
    /// (1.8+): `svr_principal.c:463-470` creates with a random key and
    /// `:369` skips `passwd_check`.
    pass: Option<String>,
    /// The `kadm5_principal_ent_rec` fields `kadm5_create_principal_3`
    /// applies under `mask` (`svr_principal.c:376-420`), as sent.
    ent: AdminEnt,
    tl_data: Vec<TlData>,
    n_key_data: u32,
    /// v3 `ks_tuple` (`xdr_cprinc3_arg`); empty on v2 and when the
    /// client omitted `-e`.
    ks: Vec<EncryptionType>,
}

/// `xdr_cprinc_arg` / `xdr_cprinc3_arg`: api_version, the whole
/// `kadm5_principal_ent_rec`, mask, (v3: ks_tuple array), passwd.
fn parse_create(args: &[u8], v3: bool) -> Result<CreateFields, Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    let (name, prealm) = r.principal_realm()?;
    let (fields, n_key_data) = parse_principal_ent_rest(&mut r)?;
    let mask = r.u32()?;
    let ks = if v3 { r.key_salt_tuples()? } else { Vec::new() };
    let pass = r.nullstring()?;
    let ent = AdminEnt {
        mask,
        attributes: fields.attributes,
        max_life: fields.max_life,
        max_renewable_life: fields.max_rlife,
        princ_expire_time: fields.expire,
        pw_expiration: fields.pw_expire,
        kvno: fields.kvno,
        policy: fields.policy,
    };
    Ok(CreateFields {
        name,
        prealm,
        pass,
        ent,
        tl_data: fields.tl_data,
        n_key_data,
        ks,
    })
}

/// Unknown v3 `ks_tuple` etypes are `KADM5_BAD_KEYSALTS` in the stub
/// reply, not ONC RPC `SYSTEM_ERR` (`svr_principal.c` `apply_keysalt_policy`).
fn parse_ks<T>(r: Result<T, Error>) -> Result<T, Result<Vec<u8>, Error>> {
    match r {
        Ok(v) => Ok(v),
        Err(Error::Inner(s)) if s == "Invalid key/salt tuples" => {
            Err(Ok(generic_ret(API_V2, KADM5_BAD_KEYSALTS)))
        }
        Err(e) => Err(Err(e)),
    }
}

fn parse_chpass(
    args: &[u8],
    v3: bool,
) -> Result<(PrincipalName, String, String, bool, Vec<EncryptionType>), Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let (keepold, ks) = if v3 {
        let k = r.u32()? != 0;
        (k, r.key_salt_tuples()?)
    } else {
        (false, Vec::new())
    };
    let pass = r.nullstring()?.unwrap_or_default();
    Ok((princ, prealm, pass, keepold, ks))
}

fn parse_get(args: &[u8]) -> Result<(PrincipalName, String, u32), Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let mask = r.u32().unwrap_or(u32::MAX);
    Ok((princ, prealm, mask))
}

/// MIT `glob_to_regexp` EINVAL for a trailing backslash (`svr_iters.c:63-64`).
const EINVAL: u32 = 22;

/// MIT compiles the glob to a POSIX BRE with `regcomp` (`svr_iters.c:175`); a
/// pattern that fails to compile (trailing `\\`, an unterminated `[...]`) is
/// `EINVAL` from `kadm5_get_either`. This mirrors that pre-flight.
#[must_use]
pub fn glob_pattern_ok(glob: &str) -> bool {
    // MIT's `ss_parse` unescapes a `\\` pair before `glob_to_regexp`; the Rust
    // tokenizer does not, so a pattern ending in a backslash is `EINVAL` either
    // way (a lone trailing `\` fails `regcomp`; MIT unescapes a `\\` pair to a
    // lone trailing `\` and then fails).
    if glob.ends_with('\\') {
        return false;
    }
    let b = glob.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                if i + 1 >= b.len() {
                    return false;
                }
                i += 2;
            }
            b'[' => {
                let mut j = i + 1;
                if b.get(j) == Some(&b'^') {
                    j += 1;
                }
                if b.get(j) == Some(&b']') {
                    j += 1;
                }
                while j < b.len() && b[j] != b']' {
                    if b[j] == b'[' && b.get(j + 1) == Some(&b':') {
                        j += 2;
                        while j + 1 < b.len() && !(b[j] == b':' && b[j + 1] == b']') {
                            j += 1;
                        }
                        if j + 1 >= b.len() {
                            return false;
                        }
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                if j >= b.len() {
                    return false;
                }
                i = j + 1;
            }
            _ => i += 1,
        }
    }
    true
}

/// POSIX character classes MIT's BRE accepts inside `[...]`.
fn posix_class_match(name: &[u8], c: u8) -> bool {
    match name {
        b"digit" => c.is_ascii_digit(),
        b"alpha" => c.is_ascii_alphabetic(),
        b"alnum" => c.is_ascii_alphanumeric(),
        b"upper" => c.is_ascii_uppercase(),
        b"lower" => c.is_ascii_lowercase(),
        b"space" => c.is_ascii_whitespace(),
        b"blank" => c == b' ' || c == b'\t',
        b"punct" => c.is_ascii_punctuation(),
        b"xdigit" => c.is_ascii_hexdigit(),
        _ => false,
    }
}

/// Append `@*` when a principal glob has no realm (`svr_iters.c` implicit `@*`).
pub(crate) fn glob_expand(glob: &str, append_realm: bool) -> String {
    if append_realm && !glob.contains('@') {
        format!("{glob}@*")
    } else {
        glob.to_owned()
    }
}

/// `glob_to_regexp` + `regexec` (`svr_iters.c:41-115`) as a direct anchored
/// matcher: `?`=one, `*`=run, `[...]`=class, `\\x`=literal.
pub(crate) fn glob_is_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t): (Option<usize>, usize) = (None, 0);
    while t < text.len() {
        let mut matched = false;
        if p < pattern.len() {
            match pattern[p] {
                b'?' => {
                    p += 1;
                    t += 1;
                    matched = true;
                }
                b'*' => {
                    star_p = Some(p);
                    star_t = t;
                    p += 1;
                    matched = true;
                }
                b'[' => {
                    if let Some((ok, np)) = glob_class(&pattern[p..], text[t]) {
                        if ok {
                            p += np;
                            t += 1;
                            matched = true;
                        }
                    } else if pattern[p] == text[t] {
                        p += 1;
                        t += 1;
                        matched = true;
                    }
                }
                b'\\' if p + 1 < pattern.len() => {
                    if pattern[p + 1] == text[t] {
                        p += 2;
                        t += 1;
                        matched = true;
                    }
                }
                c => {
                    if c == text[t] {
                        p += 1;
                        t += 1;
                        matched = true;
                    }
                }
            }
        }
        if matched {
            continue;
        }
        if let Some(sp) = star_p {
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Match one `[...]` class at the start of `pat`; `Some((matched, consumed))`
/// or `None` when the class is malformed (treat `[` as a literal).
fn glob_class(pat: &[u8], c: u8) -> Option<(bool, usize)> {
    let mut i = 1;
    let negate = pat.get(i) == Some(&b'^');
    if negate {
        i += 1;
    }
    let mut matched = false;
    let start = i;
    while i < pat.len() && (pat[i] != b']' || i == start) {
        if pat[i] == b'[' && pat.get(i + 1) == Some(&b':') {
            let mut k = i + 2;
            while k + 1 < pat.len() && !(pat[k] == b':' && pat[k + 1] == b']') {
                k += 1;
            }
            if posix_class_match(&pat[i + 2..k], c) {
                matched = true;
            }
            i = k + 2;
        } else if i + 2 < pat.len() && pat[i + 1] == b'-' && pat[i + 2] != b']' {
            if pat[i] <= c && c <= pat[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if pat[i] == c {
                matched = true;
            }
            i += 1;
        }
    }
    if i >= pat.len() || pat[i] != b']' {
        return None;
    }
    Some((matched != negate, i + 1))
}

fn parse_gprincs(args: &[u8]) -> Result<Option<String>, Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    r.nullstring()
}

fn parse_one_princ(args: &[u8]) -> Result<(PrincipalName, String), Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    r.principal_realm()
}

fn parse_rename(args: &[u8]) -> Result<(PrincipalName, String, PrincipalName, String), Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    let (old, old_realm) = r.principal_realm()?;
    let (new, new_realm) = r.principal_realm()?;
    Ok((old, old_realm, new, new_realm))
}

/// `xdr_calias_arg` (`kadm_rpc_xdr.c:1214-1227`): api version, alias, target.
fn parse_alias(args: &[u8]) -> Result<(PrincipalName, String, PrincipalName, String), Error> {
    parse_rename(args)
}

fn parse_purgekeys(args: &[u8]) -> Result<(u32, PrincipalName, String, i32), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let keep = i32::from_be_bytes(r.u32().unwrap_or(u32::MAX).to_be_bytes());
    Ok((api, princ, prealm, keep))
}

fn parse_setkey(
    args: &[u8],
    proc: u32,
) -> Result<(u32, PrincipalName, String, Vec<krb5_kdc::KeyEntry>, bool), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
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
        // SETKEY4 is MIT xdr_kadm5_key_data (kvno, keyblock, salt), not
        // xdr_krb5_key_data (no leading key_data_ver).
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
    Ok((api, princ, prealm, keys, keepold))
}

fn parse_gstrings(args: &[u8]) -> Result<(u32, PrincipalName, String), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    Ok((api, princ, prealm))
}

fn parse_sstring(
    args: &[u8],
) -> Result<(u32, PrincipalName, String, String, Option<String>), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let key = r.nullstring()?.unwrap_or_default();
    let value = r.nullstring()?;
    Ok((api, princ, prealm, key, value))
}

fn encode_gstrings(api: u32, attrs: &[(String, String)]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(api);
    w.u32(0);
    let n = u32::try_from(attrs.len()).unwrap_or(0);
    w.u32(n);
    w.u32(n);
    for (k, v) in attrs {
        w.nullstring(Some(k));
        w.nullstring(Some(v));
    }
    w.b
}

fn parse_extract(args: &[u8]) -> Result<(u32, PrincipalName, String, u32), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let kvno = r.u32().unwrap_or(0);
    Ok((api, princ, prealm, kvno))
}

fn parse_chrand(
    args: &[u8],
    v3: bool,
) -> Result<(PrincipalName, String, bool, Vec<EncryptionType>), Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let (keepold, ks) = if v3 {
        let k = r.u32()? != 0;
        (k, r.key_salt_tuples()?)
    } else {
        (false, Vec::new())
    };
    Ok((princ, prealm, keepold, ks))
}

struct ModFields {
    expire: u32,
    pw_expire: u32,
    max_life: u32,
    max_rlife: u32,
    attributes: u32,
    kvno: u32,
    policy: Option<String>,
    fail_auth_count: u32,
    tl_data: Vec<TlData>,
}

impl ModFields {
    /// The restriction-bearing subset as an [`AdminEnt`] under `mask`.
    fn admin_ent(&self, mask: u32) -> AdminEnt {
        AdminEnt {
            mask,
            attributes: self.attributes,
            max_life: self.max_life,
            max_renewable_life: self.max_rlife,
            princ_expire_time: self.expire,
            pw_expiration: self.pw_expire,
            kvno: self.kvno,
            policy: self.policy.clone(),
        }
    }

    /// Write an imposed [`AdminEnt`] back (`impose_restrictions` modifies
    /// `*ent` and `*mask` in place).
    fn take_admin_ent(&mut self, ent: AdminEnt) -> u32 {
        self.attributes = ent.attributes;
        self.max_life = ent.max_life;
        self.max_rlife = ent.max_renewable_life;
        self.expire = ent.princ_expire_time;
        self.pw_expire = ent.pw_expiration;
        self.policy = ent.policy;
        ent.mask
    }
}

fn parse_modify(args: &[u8]) -> Result<(PrincipalName, String, u32, ModFields), Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
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
    let kvno = r.u32()?;
    r.u32()?; // mkvno
    let policy = r.nullstring()?;
    r.u32()?; // aux
    let max_rlife = r.u32()?;
    r.u32()?; // last_success
    r.u32()?; // last_failed
    let fail_auth_count = r.u32()?;
    let n_key = r.u32()?;
    let _n_tl = r.u32()?;
    let tl_null = r.u32()?;
    let mut tl_data = Vec::new();
    if tl_null == 0 {
        loop {
            let more = r.u32()?;
            if more == 0 {
                break;
            }
            let ty = xdr_tl_type(r.u32()?);
            let contents = r.opaque()?;
            tl_data.push(TlData { ty, contents });
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
        prealm,
        mask,
        ModFields {
            expire,
            pw_expire,
            max_life,
            max_rlife,
            attributes,
            kvno,
            policy,
            fail_auth_count,
            tl_data,
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
    w.u32(tl_u32(&p.tl_data, TL_LAST_PWD_CHANGE).unwrap_or(0));
    w.u32(p.pw_expire);
    w.u32(u32::try_from(p.max_life).unwrap_or(0));
    // MIT kadmin always unparses `mod_name`; a NULL pointer is
    // KRB5_PARSE_MALFORMED ("while unparsing principal").
    let mod_name = krb5_kdc::tl_mod_princ_name(&p.tl_data)
        .unwrap_or_else(|| format!("kadmin/admin@{}", p.realm));
    w.u32(0); // xdr_nulltype FALSE → encode principal
    w.nullstring(Some(&mod_name));
    w.u32(tl_u32(&p.tl_data, TL_MOD_PRINC).unwrap_or(0));
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
    let n_key = u32::try_from(p.keys.len()).unwrap_or(0);
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
    for k in &p.keys {
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
/// `xdr_kadm5_principal_ent_rec` after the principal: every scalar the
/// server reads (`kadm_rpc_xdr.c:xdr_kadm5_principal_ent_rec_v1`), the TL
/// list and the key_data-nocontents array (walked, not kept). Returns the
/// fields and `n_key_data`.
fn parse_principal_ent_rest(r: &mut XdrR<'_>) -> Result<(ModFields, u32), Error> {
    let expire = r.u32()?;
    let _last_pwd = r.u32()?;
    let pw_expire = r.u32()?;
    let max_life = r.u32()?;
    let mod_null = r.u32()?; // xdr_bool: TRUE means NULL
    if mod_null == 0 {
        let _ = r.principal()?;
    }
    r.u32()?; // mod_date
    let attributes = r.u32()?;
    let kvno = r.u32()?;
    r.u32()?; // mkvno
    let policy = r.nullstring()?;
    r.u32()?; // aux_attributes (xdr_long)
    let max_rlife = r.u32()?;
    r.u32()?; // last_success
    r.u32()?; // last_failed
    let fail_auth_count = r.u32()?;
    let n_key = r.u32()?; // int16 via xdr_int
    let _n_tl = r.u32()?;
    let tl_null = r.u32()?;
    let mut tl_data = Vec::new();
    if tl_null == 0 {
        loop {
            let more = r.u32()?;
            if more == 0 {
                break;
            }
            let ty = xdr_tl_type(r.u32()?);
            let contents = r.opaque()?;
            tl_data.push(TlData { ty, contents });
        }
    }
    // xdr_array of key_data_nocontents
    let n = r.u32()?;
    for _ in 0..n {
        let ver = r.u32()?;
        r.u32()?; // kvno ui_2
        r.u32()?; // type[0]
        if ver > 1 {
            r.u32()?; // type[1]
        }
    }
    Ok((
        ModFields {
            expire,
            pw_expire,
            max_life,
            max_rlife,
            attributes,
            kvno,
            policy,
            fail_auth_count,
            tl_data,
        },
        n_key,
    ))
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
            Err(Error::GarbageArgs)
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
        Ok(self.principal_realm()?.0)
    }

    fn principal_realm(&mut self) -> Result<(PrincipalName, String), Error> {
        let s = self
            .nullstring()?
            .ok_or_else(|| Error::Inner("null principal".into()))?;
        krb5_types::principal_from_unparsed(&s, "").map_err(|e| Error::Inner(e.to_string()))
    }

    fn skip_array_i32_pairs(&mut self) -> Result<(), Error> {
        let n = self.u32()?;
        for _ in 0..n {
            self.u32()?;
            self.u32()?;
        }
        Ok(())
    }

    /// `xdr_array` of `krb5_key_salt_tuple` (`kadm_rpc_xdr.c` `xdr_krb5_key_salt_tuple`).
    fn key_salt_tuples(&mut self) -> Result<Vec<EncryptionType>, Error> {
        let n = self.u32()?;
        let mut out = Vec::new();
        for _ in 0..n {
            let et = i32::try_from(self.u32()?).unwrap_or(i32::MAX);
            let _salttype = self.u32()?;
            let e = EncryptionType::known(et)
                .map_err(|_| Error::Inner("Invalid key/salt tuples".into()))?;
            // MIT `etypes.c`: `allow_weak_crypto` filters `ETYPE_WEAK` only.
            // None of the implemented types set that flag (`is_mit_weak`).
            // Deprecated des3/rc4 and camellia are accepted on the v3
            // `ks_tuple` like MIT kadmind (`from_iana` stays stricter).
            if e.is_mit_weak() {
                return Err(Error::Inner("Invalid key/salt tuples".into()));
            }
            out.push(e);
        }
        Ok(out)
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
mod tests;
