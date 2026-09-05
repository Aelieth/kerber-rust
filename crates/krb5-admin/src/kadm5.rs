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
    KeyEntry, Principal, SharedDump as SharedStore, TL_LAST_PWD_CHANGE, TL_MOD_PRINC,
    TL_STRING_ATTRS, TlData,
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
/// MIT `ovk` 59 (`KADM5_SETKEY_BAD_KVNO`).
const KADM5_SETKEY_BAD_KVNO: u32 = 43_787_579;
/// MIT `ovk` 60 (`KADM5_AUTH_EXTRACT`).
const KADM5_AUTH_EXTRACT: u32 = 43_787_580;
const KADM5_ATTRIBUTES: u32 = 0x0000_0010;
const KADM5_MAX_LIFE: u32 = 0x0000_0020;
const KADM5_PRINC_EXPIRE_TIME: u32 = 0x0000_0002;
const KADM5_PW_EXPIRATION: u32 = 0x0000_0004;
/// MIT `KADM5_PW_MAX_LIFE`.
const KADM5_PW_MAX_LIFE: u32 = 0x0000_4000;
/// MIT `KADM5_PW_MIN_LIFE`.
const KADM5_PW_MIN_LIFE: u32 = 0x0000_8000;
const KADM5_POLICY: u32 = 0x0000_0800;
const KADM5_POLICY_CLR: u32 = 0x0000_1000;
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

struct RpcsecGss {
    ctx: GssContext,
    handle: Vec<u8>,
    seqlast: u32,
    seqmask: u32,
    svc: u32,
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
                handle: handle.to_vec(),
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
            if !gcred.handle.is_empty() && gcred.handle != gd.handle {
                return Ok(rpc_reply_auth_error(xid, RPCSEC_GSS_CREDPROBLEM));
            }
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
            let kadm_args = if gd.svc == GSS_NONE {
                r.rest().to_vec()
            } else {
                let Ok(wrapped) = r.opaque() else {
                    return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                };
                let Ok(plain) = gd.ctx.unwrap(&wrapped) else {
                    return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                };
                if plain.len() < 4 {
                    return Ok(rpc_reply_accepted_verf(xid, Some(&mic), GARBAGE_ARGS));
                }
                plain[4..].to_vec()
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
            ))
        }
        RPG_DESTROY => {
            if proc != 0 {
                return Ok(rpc_reply_auth_error(xid, AUTH_FAILED));
            }
            let Some(gd) = gss.as_mut() else {
                return Ok(rpc_reply_auth_error(xid, RPCSEC_GSS_CREDPROBLEM));
            };
            if !gcred.handle.is_empty() && gcred.handle != gd.handle {
                return Ok(rpc_reply_auth_error(xid, RPCSEC_GSS_CREDPROBLEM));
            }
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
        changepw_acceptor(&gd.ctx),
        iprop,
    ) {
        Ok(b) => b,
        Err(Error::GarbageArgs) => return rpc_reply_accepted_verf(xid, Some(mic), GARBAGE_ARGS),
        Err(Error::ProcUnavail) => return rpc_reply_accepted_verf(xid, Some(mic), PROC_UNAVAIL),
        Err(_) => return rpc_reply_accepted_verf(xid, Some(mic), SYSTEM_ERR),
    };
    if gd.svc == GSS_NONE {
        return rpc_reply_gss_verf(xid, mic, &result);
    }
    let mut inner = Vec::with_capacity(4 + result.len());
    inner.extend_from_slice(&seq.to_be_bytes());
    inner.extend_from_slice(&result);
    let wrap = if gd.svc == GSS_PRIVACY {
        gd.ctx.wrap_with_rrc(&inner, 0)
    } else {
        gd.ctx.wrap_integ(&inner)
    };
    match wrap {
        Ok(w) => rpc_reply_gss(xid, mic, &w),
        Err(_) => rpc_reply_auth_error(xid, AUTH_FAILED),
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
        let mut ar = XdrR::new(args);
        let arg_ver = ar.u32()?;
        let token = ar.opaque()?;
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
                encode_init_res(&mut body, arg_ver, &[], 1, 0, &[], &[]);
                return Ok(rpc_reply_clear(xid, &body.b));
            }
        };
        if !iprop && !check_auth_gssapi_names(&ctx) {
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
        encode_init_res(&mut body, arg_ver, &handle, 0, 0, &tok, &signed);
        return Ok(rpc_reply_clear(xid, &body.b));
    }

    let Some(st) = agss.as_mut() else {
        return Ok(rpc_reply_auth_error(xid, AUTH_FAILED));
    };
    if iprop {
        return Ok(rpc_reply_weakauth(xid));
    }
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
    if !check_auth_gssapi_names(&st.ctx) {
        return Ok(rpc_reply_weakauth(xid));
    }
    let result = match kadm5_or_iprop(
        store,
        acl,
        &actor,
        proc,
        kadm_args,
        st.ctx.ticket_is_initial(),
        changepw_acceptor(&st.ctx),
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
    handle: Vec<u8>,
}

fn parse_gcred(data: &[u8]) -> Result<Gcred, Error> {
    let mut r = XdrR::new(data);
    Ok(Gcred {
        version: r.u32()?,
        proc: r.u32()?,
        seq_num: r.u32()?,
        service: r.u32()?,
        handle: r.opaque().unwrap_or_default(),
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
    if !p.key_history.is_empty() {
        body.u32(AT_PW_HIST);
        body.u32(1);
        encode_keydata(&mut body, &p.key_history, mkey, &p.salt);
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
    let mut key_history = Vec::new();
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
            AT_MOD_TIME | AT_PW_HIST_KVNO => {
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
                    key_history.extend(decode_keydata(r, mkey)?);
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
    Ok(Some(Principal {
        name,
        realm,
        keys,
        key_history,
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
    api: u32,
) -> Result<std::sync::RwLockWriteGuard<'_, krb5_kdc::PrincipalStore>, Vec<u8>> {
    let mut g = store
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Reload then mutate then save. Two processes can still interleave
    // that window; a dump file lock is deferred with db2/LMDB.
    if let Err(e) = g.reload_if_stale() {
        return Err(generic_ret(api, kadm5_code(&Error::from(e))));
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

fn changepw_acceptor(ctx: &GssContext) -> bool {
    ctx.acceptor.as_ref().is_some_and(|n| {
        let p = acceptor_parts(n);
        p.len() == 2 && p[0] == "kadmin" && p[1] == "changepw"
    })
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

fn check_auth_gssapi_names(ctx: &GssContext) -> bool {
    ctx.acceptor.as_ref().is_some_and(kadm5_auth_gssapi_ok)
}

fn check_rpcsec_auth(ctx: &GssContext, store_realm: &str) -> bool {
    ctx.ticket_realm.as_deref() == Some(store_realm)
        && ctx.acceptor.as_ref().is_some_and(kadm5_rpcsec_ok)
}

fn check_iprop_rpcsec_auth(ctx: &GssContext, store_realm: &str) -> bool {
    ctx.ticket_realm.as_deref() == Some(store_realm)
        && ctx.acceptor.as_ref().is_some_and(iprop_rpcsec_ok)
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
            let g = match write_store(store, API_V2) {
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
            let (name, prealm) = parse_one_princ(args)?;
            let req = req_realm(&prealm, &realm);
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::Delete, Some(&acl_id(&name, &req)))
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_DELETE));
            }
            let mut g = match write_store(store, API_V2) {
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
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(&Error::from(e)))),
            }
        }
        MODIFY_PRINCIPAL => {
            let (name, prealm, mask, fields) = parse_modify(args)?;
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(API_V2, KADM5_UNK_PRINC));
            }
            let tid = acl_id(&name, &req);
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::Modify, Some(&tid))
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_MODIFY));
            }
            if mask & KADM5_ATTRIBUTES != 0
                && fields.attributes & KDB_LOCKDOWN_KEYS == 0
                && g.get_in_realm(&name, &req)
                    .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0)
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_MODIFY));
            }
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
            match g.apply_admin_fields_in(
                &name,
                &req,
                attributes,
                max_life,
                expiration,
                pw_expire,
                policy,
                clear_policy,
            ) {
                Ok(()) => {
                    if let Some(rs) = acl.restrictions(actor, Some(&tid))
                        && let Err(e) = g.impose_acl_restrictions_in(&name, &req, rs)
                    {
                        return Ok(generic_ret(API_V2, kadm5_code(&Error::from(e))));
                    }
                    Ok(generic_ret(API_V2, 0))
                }
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(&Error::from(e)))),
            }
        }
        CREATE_PRINCIPAL | CREATE_PRINCIPAL3 => {
            let (name, prealm, pass, policy) = parse_create(args, proc == CREATE_PRINCIPAL3)?;
            let req = req_realm(&prealm, &realm);
            let tid = acl_id(&name, &req);
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::Create, Some(&tid))
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_ADD));
            }
            let mut g = match write_store(store, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            let rs = acl.restrictions(actor, Some(&tid));
            let skip_policy = rs.is_some_and(|r| r.clear_policy || r.policy.is_some());
            if let Some(ref pol) = policy
                && !skip_policy
                && let Err(e) = g.check_named_policy(pol, pass.as_bytes())
            {
                return Ok(generic_ret(API_V2, kadm5_code(&Error::from(e))));
            }
            match g.insert_new_password(&name, &req, pass.as_bytes(), &[]) {
                Ok(()) => {
                    if let Some(rs) = rs
                        && let Err(e) = g.impose_acl_restrictions_in(&name, &req, rs)
                    {
                        return Ok(generic_ret(API_V2, kadm5_code(&Error::from(e))));
                    }
                    if !skip_policy
                        && let Some(pol) = policy
                        && let Err(e) = g.set_principal_policy_in(&name, &req, Some(pol))
                    {
                        return Ok(generic_ret(API_V2, kadm5_code(&Error::from(e))));
                    }
                    Ok(generic_ret(API_V2, 0))
                }
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(&Error::from(e)))),
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
            let mut g = match write_store(store, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&old, &old_req)
                .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0)
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_DELETE));
            }
            match g.rename_unchecked(&old, &old_req, &new, &new_req) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(&Error::from(e)))),
            }
        }
        CHPASS_PRINCIPAL | CHPASS_PRINCIPAL3 => {
            let (name, prealm, pass, keepold) = parse_chpass(args, proc == CHPASS_PRINCIPAL3)?;
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, API_V2) {
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
                return Ok(generic_ret(API_V2, kadm5_code(&Error::from(e))));
            }
            let n = clamp_self_keepold(self_change, keepold);
            match g.set_password_keepold_n_in(&name, &req, pass.as_bytes(), n) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(&Error::from(e)))),
            }
        }
        CREATE_POLICY => {
            let (api, mut pol, mask) = parse_policy_arg(args)?;
            if changepw || acl.check(actor, krb5_kdc::AdminOp::Create, None).is_err() {
                return Ok(generic_ret(api, KADM5_AUTH_ADD));
            }
            if let Some(code) = policy_name_err(&pol.name) {
                return Ok(generic_ret(api, code));
            }
            if let Some(code) = policy_mask_err(mask, true) {
                return Ok(generic_ret(api, code));
            }
            let mut g = match write_store(store, api) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.policies().contains_key(&pol.name) {
                return Ok(generic_ret(api, KADM5_DUP));
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
            let mut g = match write_store(store, api) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            match g.delete_policy(&name) {
                Ok(()) => Ok(generic_ret(api, 0)),
                Err(krb5_kdc::Error::NotFound) => Ok(generic_ret(api, KADM5_UNK_POLICY)),
                Err(e) => Ok(generic_ret(api, kadm5_code(&Error::from(e)))),
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
            let mut g = match write_store(store, api) {
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
            let (name, prealm, keepold) = parse_chrand(args, proc == CHRAND_PRINCIPAL3)?;
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, API_V2) {
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
                return Ok(generic_ret(API_V2, kadm5_code(&Error::from(e))));
            }
            let n = clamp_self_keepold(self_change, keepold);
            match g.chrand_keepold_n_in(&name, &req, n) {
                Ok(keys) => {
                    let hide = g
                        .get_in_realm(&name, &req)
                        .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0);
                    Ok(encode_chrand(if hide { &[] } else { &keys }))
                }
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(&Error::from(e)))),
            }
        }
        EXTRACT_KEYS => {
            let (api, name, prealm, kvno) = parse_extract(args)?;
            let req = req_realm(&prealm, &realm);
            let g = match write_store(store, api) {
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
            let mut g = match write_store(store, API_V2) {
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
            match g.purgekeys_in(&name, &req, keepkvno) {
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
            let (api, name, prealm, keys, keepold) = parse_setkey(args, proc)?;
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, API_V2) {
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
            match g.set_keys_in(&name, &req, keys, n) {
                Ok(()) => Ok(generic_ret(api, 0)),
                Err(e) => Ok(generic_ret(api, kadm5_code(&Error::from(e)))),
            }
        }
        GET_STRINGS => {
            let (api, name, prealm) = parse_gstrings(args)?;
            let req = req_realm(&prealm, &realm);
            let g = match write_store(store, api) {
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
                Err(e) => Ok(generic_ret(api, kadm5_code(&Error::from(e)))),
            }
        }
        SET_STRING => {
            let (api, name, prealm, key, value) = parse_sstring(args)?;
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, API_V2) {
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
            match g.set_string_in(&name, &req, &key, value.as_deref()) {
                Ok(()) => Ok(generic_ret(api, 0)),
                Err(e) => Ok(generic_ret(api, kadm5_code(&Error::from(e)))),
            }
        }
        _ => Err(Error::ProcUnavail),
    }
}

fn kadm5_code(e: &Error) -> u32 {
    let s = match e {
        Error::AclDenied => return KADM5_AUTH_GET,
        Error::NotFound => return KADM5_UNK_PRINC,
        Error::PassTooSoon { .. } => return KADM5_PASS_TOOSOON,
        Error::GarbageArgs | Error::ProcUnavail => return KADM5_FAILURE,
        Error::PasswordPolicy(s) | Error::Inner(s) => s.as_str(),
    };
    if s.contains("min_length") {
        KADM5_PASS_Q_TOOSHORT
    } else if s.contains("min_classes") {
        KADM5_PASS_Q_CLASS
    } else if s.contains("history") {
        KADM5_PASS_REUSE
    } else if s.contains("setkey kvno") {
        KADM5_SETKEY_BAD_KVNO
    } else if s.contains("principal exists") {
        KADM5_DUP
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
            pw_min_life: min_life,
            pw_max_life: max_life,
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
    existing
}

const MIN_PW_LENGTH: u32 = 1;
const MIN_PW_CLASSES: u32 = 1;
const MAX_PW_CLASSES: u32 = 5;
const MIN_PW_HISTORY: u32 = 1;

fn policy_name_err(name: &str) -> Option<u32> {
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

fn policy_floor_err(pol: &krb5_kdc::NamedPolicy, mask: u32) -> Option<u32> {
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

fn apply_policy_floors(pol: &mut krb5_kdc::NamedPolicy, mask: u32) {
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

fn parse_create(
    args: &[u8],
    v3: bool,
) -> Result<(PrincipalName, String, String, Option<String>), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let policy = skip_principal_ent_rest(&mut r)?;
    let _mask = r.u32()?;
    if v3 {
        r.skip_array_i32_pairs()?;
    }
    let pass = r.nullstring()?.unwrap_or_default();
    Ok((princ, prealm, pass, policy))
}

fn parse_chpass(args: &[u8], v3: bool) -> Result<(PrincipalName, String, String, bool), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let keepold = if v3 {
        let k = r.u32()? != 0;
        r.skip_array_i32_pairs()?;
        k
    } else {
        false
    };
    let pass = r.nullstring()?.unwrap_or_default();
    Ok((princ, prealm, pass, keepold))
}

fn parse_get(args: &[u8]) -> Result<(PrincipalName, String, u32), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let mask = r.u32().unwrap_or(u32::MAX);
    Ok((princ, prealm, mask))
}

fn parse_gprincs(args: &[u8]) -> Result<Option<String>, Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    r.nullstring()
}

fn parse_one_princ(args: &[u8]) -> Result<(PrincipalName, String), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    r.principal_realm()
}

fn parse_rename(args: &[u8]) -> Result<(PrincipalName, String, PrincipalName, String), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    let (old, old_realm) = r.principal_realm()?;
    let (new, new_realm) = r.principal_realm()?;
    Ok((old, old_realm, new, new_realm))
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

fn parse_chrand(args: &[u8], v3: bool) -> Result<(PrincipalName, String, bool), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let keepold = if v3 {
        let k = r.u32().unwrap_or(0) != 0;
        let _ = r.skip_array_i32_pairs();
        k
    } else {
        false
    };
    Ok((princ, prealm, keepold))
}

struct ModFields {
    expire: u32,
    pw_expire: u32,
    max_life: u32,
    attributes: u32,
    policy: Option<String>,
}

fn parse_modify(args: &[u8]) -> Result<(PrincipalName, String, u32, ModFields), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
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
        prealm,
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
    w.u32(tl_u32(&p.tl_data, TL_LAST_PWD_CHANGE).unwrap_or(0));
    w.u32(p.pw_expire);
    w.u32(u32::try_from(p.max_life).unwrap_or(0));
    // MIT kadmin always unparses `mod_name`; a NULL pointer is
    // KRB5_PARSE_MALFORMED ("while unparsing principal").
    let mod_name = format!("kadmin/admin@{}", p.realm);
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
    fn xdr_principal_parse_name_escapes() {
        let mut w = XdrW::default();
        w.nullstring(Some(r"foo\/admin@KERBER.TEST"));
        let mut r = XdrR::new(&w.b);
        let p = r.principal().unwrap();
        assert_eq!(p.name_string.len(), 1);
        assert_eq!(p.unparse(), r"foo\/admin");
        assert_eq!(p.components_joined(), "foo/admin");
    }

    #[test]
    fn generic_ret_is_eight_bytes() {
        let b = generic_ret(API_V2, 0);
        assert_eq!(b.len(), 8);
        assert_eq!(&b[..4], &API_V2.to_be_bytes());
    }

    #[test]
    fn unknown_proc_is_proc_unavail() {
        let (store, acl, actor) = setup();
        let err = dispatch_kadm5(&store, &acl, &actor, 99, &[]).unwrap_err();
        assert_eq!(err, Error::ProcUnavail);
    }

    #[test]
    fn truncated_getprinc_is_garbage_args() {
        let (store, acl, actor) = setup();
        let err = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &[]).unwrap_err();
        assert_eq!(err, Error::GarbageArgs);
    }

    fn rpc_call(xid: u32, prog: u32, vers: u32, proc: u32, flavor: u32) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(xid);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(prog);
        w.u32(vers);
        w.u32(proc);
        w.u32(flavor);
        w.opaque(&[]);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        w.b
    }

    #[test]
    fn auth_none_is_auth_too_weak() {
        let (store, acl, _) = setup();
        let rec = rpc_call(7, KADM_PROG, KADM_VERS, 99, FLAVOR_NONE);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 7);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_DENIED);
        assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
        assert_eq!(r.u32().unwrap(), AUTH_TOOWEAK);
    }

    #[test]
    fn bad_program_is_prog_unavail() {
        let (store, acl, _) = setup();
        let rec = rpc_call(8, 99_999, 1, 0, FLAVOR_NONE);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 8);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(r.u32().unwrap(), FLAVOR_NONE);
        assert_eq!(r.opaque().unwrap().len(), 0);
        assert_eq!(r.u32().unwrap(), PROG_UNAVAIL);
    }

    #[test]
    fn kadm_vers_99_is_prog_mismatch_2_2() {
        let (store, acl, _) = setup();
        let rec = rpc_call(9, KADM_PROG, 99, 0, FLAVOR_NONE);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 9);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(r.u32().unwrap(), FLAVOR_NONE);
        assert_eq!(r.opaque().unwrap().len(), 0);
        assert_eq!(r.u32().unwrap(), PROG_MISMATCH);
        assert_eq!(r.u32().unwrap(), KADM_VERS);
        assert_eq!(r.u32().unwrap(), KADM_VERS);
    }

    #[test]
    fn reply_typed_rpc_is_no_reply() {
        let (store, acl, _) = setup();
        let mut w = XdrW::default();
        w.u32(10);
        w.u32(MSG_REPLY);
        w.u32(RPC_VERSION);
        w.u32(KADM_PROG);
        w.u32(KADM_VERS);
        w.u32(12);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &w.b,
        )
        .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn auth_gssapi_on_iprop_data_is_auth_failed() {
        let (store, acl, _) = setup();
        let mut cred = XdrW::default();
        cred.u32(AUTH_GSSAPI_CREDS_VERS);
        cred.u32(0);
        cred.opaque(&[]);
        let mut w = XdrW::default();
        w.u32(11);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(IPROP_PROG);
        w.u32(IPROP_VERS);
        w.u32(IPROP_GET_UPDATES);
        w.u32(FLAVOR_AUTH_GSSAPI);
        w.opaque(&cred.b);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &w.b,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 11);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_DENIED);
        assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
        assert_eq!(r.u32().unwrap(), AUTH_FAILED);
    }

    #[test]
    fn auth_gssapi_on_iprop_init_is_success() {
        let (store, acl, _) = setup();
        let mut cred = XdrW::default();
        cred.u32(AUTH_GSSAPI_CREDS_VERS);
        cred.u32(1);
        cred.opaque(&[]);
        let mut args = XdrW::default();
        args.u32(2);
        args.opaque(&[]);
        let mut w = XdrW::default();
        w.u32(12);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(IPROP_PROG);
        w.u32(IPROP_VERS);
        w.u32(AUTH_GSSAPI_INIT);
        w.u32(FLAVOR_AUTH_GSSAPI);
        w.opaque(&cred.b);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        w.b.extend_from_slice(&args.b);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &w.b,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 12);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(r.u32().unwrap(), FLAVOR_NONE);
        let _verf = r.opaque().unwrap();
        assert_eq!(r.u32().unwrap(), SUCCESS);
    }

    #[test]
    fn rpcsec_bad_version_is_auth_badcred() {
        let (store, acl, _) = setup();
        let mut cred = XdrW::default();
        cred.u32(99);
        cred.u32(RPG_INIT);
        cred.u32(0);
        cred.u32(GSS_PRIVACY);
        cred.opaque(&[]);
        let mut w = XdrW::default();
        w.u32(13);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(KADM_PROG);
        w.u32(KADM_VERS);
        w.u32(0);
        w.u32(FLAVOR_GSS);
        w.opaque(&cred.b);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &w.b,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 13);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_DENIED);
        assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
        assert_eq!(r.u32().unwrap(), AUTH_BADCRED);
    }

    #[test]
    fn rpcsec_unknown_program_bad_version_is_auth_badcred() {
        let (store, acl, _) = setup();
        let mut cred = XdrW::default();
        cred.u32(99);
        cred.u32(RPG_INIT);
        cred.u32(0);
        cred.u32(GSS_PRIVACY);
        cred.opaque(&[]);
        let mut w = XdrW::default();
        w.u32(15);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(99_999);
        w.u32(1);
        w.u32(0);
        w.u32(FLAVOR_GSS);
        w.opaque(&cred.b);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &w.b,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 15);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_DENIED);
        assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
        assert_eq!(r.u32().unwrap(), AUTH_BADCRED);
    }

    #[test]
    fn rpcsec_init_non_nullproc_is_auth_failed() {
        let (store, acl, _) = setup();
        let mut cred = XdrW::default();
        cred.u32(RPCSEC_GSS_VERS);
        cred.u32(RPG_INIT);
        cred.u32(0);
        cred.u32(GSS_PRIVACY);
        cred.opaque(&[]);
        let mut w = XdrW::default();
        w.u32(21);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(KADM_PROG);
        w.u32(KADM_VERS);
        w.u32(12);
        w.u32(FLAVOR_GSS);
        w.opaque(&cred.b);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &w.b,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 21);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_DENIED);
        assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
        assert_eq!(r.u32().unwrap(), AUTH_FAILED);
    }

    #[test]
    fn rpcsec_data_without_context_is_credproblem() {
        let (store, acl, _) = setup();
        let mut cred = XdrW::default();
        cred.u32(RPCSEC_GSS_VERS);
        cred.u32(RPG_DATA);
        cred.u32(1);
        cred.u32(GSS_PRIVACY);
        cred.opaque(&[]);
        let mut w = XdrW::default();
        w.u32(14);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(KADM_PROG);
        w.u32(KADM_VERS);
        w.u32(12);
        w.u32(FLAVOR_GSS);
        w.opaque(&cred.b);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &w.b,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 14);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_DENIED);
        assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
        assert_eq!(r.u32().unwrap(), RPCSEC_GSS_CREDPROBLEM);
    }

    #[test]
    fn rpcsec_unknown_program_data_without_context_is_credproblem() {
        let (store, acl, _) = setup();
        let mut cred = XdrW::default();
        cred.u32(RPCSEC_GSS_VERS);
        cred.u32(RPG_DATA);
        cred.u32(1);
        cred.u32(GSS_PRIVACY);
        cred.opaque(&[]);
        let mut w = XdrW::default();
        w.u32(16);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(99_999);
        w.u32(1);
        w.u32(12);
        w.u32(FLAVOR_GSS);
        w.opaque(&cred.b);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &w.b,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 16);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_DENIED);
        assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
        assert_eq!(r.u32().unwrap(), RPCSEC_GSS_CREDPROBLEM);
    }

    #[test]
    fn rpc_reply_gss_verf_is_rpcsec_gss_mic() {
        let out = rpc_reply_gss_verf(3, b"mic-bytes", b"init-body");
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 3);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
        assert_eq!(r.opaque().unwrap(), b"mic-bytes");
        assert_eq!(r.u32().unwrap(), SUCCESS);
        assert_eq!(r.rest(), b"init-body");
    }

    #[test]
    fn rpcsec_init_reply_mic_is_window() {
        use krb5_crypto::EncryptionType;
        use krb5_kdc::{TEST_REALM, documented_kadmin};
        use krb5_protocol::{as_req_sname, pa_enc_timestamp};
        use krb5_types::ascii;

        let (store, acl, _) = setup();
        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
        let kadm = documented_kadmin();
        let (admin_key, kadm_key) = {
            let g = store.read().unwrap();
            (
                g.get_name(&admin).unwrap().best_key().unwrap().key.clone(),
                g.get_name(&kadm).unwrap().best_key().unwrap().key.clone(),
            )
        };
        let as_req = as_req_sname(
            admin.clone(),
            TEST_REALM,
            7,
            Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
            kadm.clone(),
            EncryptionType::preferred()
                .iter()
                .map(|e| e.to_iana())
                .collect(),
        )
        .unwrap();
        let as_out = {
            let g = store.read().unwrap();
            krb5_kdc::issue_as(&*g, &as_req).unwrap()
        };
        let (mut ctx, token) = GssContext::init_sec_context(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &ascii(TEST_REALM),
            &admin,
            true,
            None,
            None,
        )
        .unwrap();
        let mut cred = XdrW::default();
        cred.u32(RPCSEC_GSS_VERS);
        cred.u32(RPG_INIT);
        cred.u32(0);
        cred.u32(GSS_PRIVACY);
        cred.opaque(&[]);
        let mut arg = XdrW::default();
        arg.opaque(&token);
        let mut w = XdrW::default();
        w.u32(12);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(IPROP_PROG);
        w.u32(IPROP_VERS);
        w.u32(IPROP_NULL);
        w.u32(FLAVOR_GSS);
        w.opaque(&cred.b);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        w.b.extend_from_slice(&arg.b);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[kadm_key],
            TEST_REALM,
            b"hdl",
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &w.b,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 12);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
        let verf = r.opaque().unwrap();
        assert!(!verf.is_empty(), "INIT verifier must be MIC of the window");
        assert_eq!(r.u32().unwrap(), SUCCESS);
        let _handle = r.opaque().unwrap();
        assert_eq!(r.u32().unwrap(), 0);
        let _minor = r.u32().unwrap();
        let window = r.u32().unwrap();
        assert_eq!(window, RPCSEC_SEQ_WINDOW);
        let _out_tok = r.opaque().unwrap();
        ctx.verify_mic(&window.to_be_bytes(), &verf)
            .expect("INIT xp_verf is MIC(htonl(window))");
    }

    fn rpcsec_cred(proc: u32, seq: u32, svc: u32, handle: &[u8]) -> Vec<u8> {
        let mut cred = XdrW::default();
        cred.u32(RPCSEC_GSS_VERS);
        cred.u32(proc);
        cred.u32(seq);
        cred.u32(svc);
        cred.opaque(handle);
        cred.b
    }

    #[allow(clippy::too_many_arguments)]
    fn rpcsec_call(
        xid: u32,
        prog: u32,
        vers: u32,
        proc: u32,
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
        w.u32(FLAVOR_GSS);
        w.opaque(cred);
        w.u32(verf_flavor);
        w.opaque(verf);
        w.b.extend_from_slice(args);
        w.b
    }

    fn decode_denied(out: &[u8]) -> (u32, u32) {
        let mut r = XdrR::new(out);
        let xid = r.u32().unwrap();
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_DENIED);
        assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
        (xid, r.u32().unwrap())
    }

    fn admin_rpcsec_init() -> (
        krb5_kdc::SharedDump,
        Acl,
        GssContext,
        Vec<u8>,
        Option<RpcsecGss>,
    ) {
        use krb5_crypto::EncryptionType;
        use krb5_kdc::{TEST_REALM, documented_kadmin};
        use krb5_protocol::{as_req_sname, pa_enc_timestamp};
        use krb5_types::ascii;

        let (store, acl, _) = setup();
        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
        let kadm = documented_kadmin();
        let (admin_key, kadm_key) = {
            let g = store.read().unwrap();
            (
                g.get_name(&admin).unwrap().best_key().unwrap().key.clone(),
                g.get_name(&kadm).unwrap().best_key().unwrap().key.clone(),
            )
        };
        let as_req = as_req_sname(
            admin.clone(),
            TEST_REALM,
            7,
            Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
            kadm.clone(),
            EncryptionType::preferred()
                .iter()
                .map(|e| e.to_iana())
                .collect(),
        )
        .unwrap();
        let as_out = {
            let g = store.read().unwrap();
            krb5_kdc::issue_as(&*g, &as_req).unwrap()
        };
        let (mut ctx, token) = GssContext::init_sec_context(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &ascii(TEST_REALM),
            &admin,
            true,
            None,
            None,
        )
        .unwrap();
        let cred = rpcsec_cred(RPG_INIT, 0, GSS_PRIVACY, &[]);
        let mut arg = XdrW::default();
        arg.opaque(&token);
        let rec = rpcsec_call(1, KADM_PROG, KADM_VERS, 0, &cred, FLAVOR_NONE, &[], &arg.b);
        let mut gss = None;
        let mut agss = None;
        let keys = [kadm_key];
        let out = handle_rpc(
            &store,
            &acl,
            &keys,
            TEST_REALM,
            b"hdl",
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 1);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
        let verf = r.opaque().unwrap();
        assert_eq!(r.u32().unwrap(), SUCCESS);
        let handle = r.opaque().unwrap();
        let _major = r.u32().unwrap();
        let _minor = r.u32().unwrap();
        let window = r.u32().unwrap();
        let out_tok = r.opaque().unwrap();
        if !out_tok.is_empty() {
            ctx.process_ap_rep(&out_tok, &as_out.session_key).unwrap();
        }
        ctx.allow_rpcsec_init_window();
        ctx.verify_mic(&window.to_be_bytes(), &verf).unwrap();
        assert!(gss.is_some());
        (store, acl, ctx, handle, gss)
    }

    #[allow(clippy::too_many_arguments)]
    fn rpcsec_data_rec(
        ctx: &mut GssContext,
        xid: u32,
        prog: u32,
        vers: u32,
        proc: u32,
        seq: u32,
        handle: &[u8],
        args: &[u8],
        wrap: bool,
    ) -> Vec<u8> {
        let cred = rpcsec_cred(RPG_DATA, seq, GSS_PRIVACY, handle);
        let mut header = XdrW::default();
        header.u32(xid);
        header.u32(MSG_CALL);
        header.u32(RPC_VERSION);
        header.u32(prog);
        header.u32(vers);
        header.u32(proc);
        header.u32(FLAVOR_GSS);
        header.opaque(&cred);
        let mic = ctx.get_mic(&header.b).unwrap();
        let mut arg = XdrW::default();
        if wrap {
            let mut inner = Vec::with_capacity(4 + args.len());
            inner.extend_from_slice(&seq.to_be_bytes());
            inner.extend_from_slice(args);
            let w = ctx.wrap_with_rrc(&inner, 0).unwrap();
            arg.opaque(&w);
        } else {
            arg.b.extend_from_slice(args);
        }
        rpcsec_call(xid, prog, vers, proc, &cred, FLAVOR_GSS, &mic, &arg.b)
    }

    #[test]
    fn rpcsec_unknown_gc_proc_is_rejectedcred() {
        let (store, acl, _) = setup();
        let cred = rpcsec_cred(99, 0, GSS_PRIVACY, &[]);
        let rec = rpcsec_call(22, KADM_PROG, KADM_VERS, 0, &cred, FLAVOR_NONE, &[], &[]);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec,
        )
        .unwrap();
        let (xid, why) = decode_denied(&out);
        assert_eq!(xid, 22);
        assert_eq!(why, AUTH_REJECTEDCRED);
    }

    #[test]
    fn rpcsec_init_garbage_token_is_rejectedcred() {
        let (store, acl, _) = setup();
        let cred = rpcsec_cred(RPG_INIT, 0, GSS_PRIVACY, &[]);
        let mut arg = XdrW::default();
        arg.opaque(&[0xff, 0x00]);
        let rec = rpcsec_call(23, KADM_PROG, KADM_VERS, 0, &cred, FLAVOR_NONE, &[], &arg.b);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec,
        )
        .unwrap();
        let (xid, why) = decode_denied(&out);
        assert_eq!(xid, 23);
        assert_eq!(why, AUTH_REJECTEDCRED);
        assert!(gss.is_none());
    }

    #[test]
    fn rpcsec_destroy_without_context_is_credproblem() {
        let (store, acl, _) = setup();
        let cred = rpcsec_cred(RPG_DESTROY, 1, GSS_PRIVACY, &[]);
        let rec = rpcsec_call(24, KADM_PROG, KADM_VERS, 0, &cred, FLAVOR_NONE, &[], &[]);
        let mut gss = None;
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            "KERBER.TEST",
            &[],
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec,
        )
        .unwrap();
        let (xid, why) = decode_denied(&out);
        assert_eq!(xid, 24);
        assert_eq!(why, RPCSEC_GSS_CREDPROBLEM);
    }

    #[test]
    fn rpcsec_bad_mic_is_credproblem() {
        use krb5_kdc::TEST_REALM;
        let (store, acl, _ctx, handle, mut gss) = admin_rpcsec_init();
        let cred = rpcsec_cred(RPG_DATA, 1, GSS_PRIVACY, &handle);
        let rec = rpcsec_call(
            25,
            KADM_PROG,
            KADM_VERS,
            GET_PRIVS,
            &cred,
            FLAVOR_GSS,
            b"not-a-mic",
            &[],
        );
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            TEST_REALM,
            b"hdl",
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec,
        )
        .unwrap();
        let (xid, why) = decode_denied(&out);
        assert_eq!(xid, 25);
        assert_eq!(why, RPCSEC_GSS_CREDPROBLEM);
    }

    #[test]
    fn rpcsec_seq_over_maxseq_is_ctxproblem() {
        use krb5_kdc::TEST_REALM;
        let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
        let rec = rpcsec_data_rec(
            &mut ctx,
            26,
            KADM_PROG,
            KADM_VERS,
            GET_PRIVS,
            MAXSEQ.saturating_add(1),
            &handle,
            &[],
            true,
        );
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            TEST_REALM,
            b"hdl",
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec,
        )
        .unwrap();
        let (xid, why) = decode_denied(&out);
        assert_eq!(xid, 26);
        assert_eq!(why, RPCSEC_GSS_CTXPROBLEM);
    }

    #[test]
    fn rpcsec_seq_replay_is_ctxproblem() {
        use krb5_kdc::TEST_REALM;
        let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
        let rec1 = rpcsec_data_rec(
            &mut ctx,
            27,
            KADM_PROG,
            KADM_VERS,
            GET_PRIVS,
            1,
            &handle,
            &[],
            true,
        );
        let mut agss = None;
        let out1 = handle_rpc(
            &store,
            &acl,
            &[],
            TEST_REALM,
            b"hdl",
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec1,
        )
        .unwrap();
        let mut r = XdrR::new(&out1);
        assert_eq!(r.u32().unwrap(), 27);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
        let rec2 = rpcsec_data_rec(
            &mut ctx,
            28,
            KADM_PROG,
            KADM_VERS,
            GET_PRIVS,
            1,
            &handle,
            &[],
            true,
        );
        let out2 = handle_rpc(
            &store,
            &acl,
            &[],
            TEST_REALM,
            b"hdl",
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec2,
        )
        .unwrap();
        let (xid, why) = decode_denied(&out2);
        assert_eq!(xid, 28);
        assert_eq!(why, RPCSEC_GSS_CTXPROBLEM);
    }

    #[test]
    fn rpcsec_destroy_then_data_is_credproblem() {
        use krb5_kdc::TEST_REALM;
        let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
        let cred = rpcsec_cred(RPG_DESTROY, 1, GSS_PRIVACY, &handle);
        let mut header = XdrW::default();
        header.u32(29);
        header.u32(MSG_CALL);
        header.u32(RPC_VERSION);
        header.u32(KADM_PROG);
        header.u32(KADM_VERS);
        header.u32(0);
        header.u32(FLAVOR_GSS);
        header.opaque(&cred);
        let mic = ctx.get_mic(&header.b).unwrap();
        let rec = rpcsec_call(29, KADM_PROG, KADM_VERS, 0, &cred, FLAVOR_GSS, &mic, &[]);
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            TEST_REALM,
            b"hdl",
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 29);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
        assert!(gss.is_none(), "DESTROY drops the context");
        let rec2 = rpcsec_data_rec(
            &mut ctx,
            30,
            KADM_PROG,
            KADM_VERS,
            GET_PRIVS,
            2,
            &handle,
            &[],
            true,
        );
        let out2 = handle_rpc(
            &store,
            &acl,
            &[],
            TEST_REALM,
            b"hdl",
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec2,
        )
        .unwrap();
        let (xid, why) = decode_denied(&out2);
        assert_eq!(xid, 30);
        assert_eq!(why, RPCSEC_GSS_CREDPROBLEM);
    }

    #[test]
    fn rpcsec_unknown_program_data_carries_xp_verf() {
        use krb5_kdc::TEST_REALM;
        let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
        let rec = rpcsec_data_rec(&mut ctx, 31, 99_999, 1, 0, 1, &handle, &[], true);
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            TEST_REALM,
            b"hdl",
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 31);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
        let verf = r.opaque().unwrap();
        assert!(!verf.is_empty(), "PROG_UNAVAIL carries xp_verf");
        assert_eq!(r.u32().unwrap(), PROG_UNAVAIL);
        ctx.verify_mic(&1u32.to_be_bytes(), &verf)
            .expect("DATA xp_verf is MIC(htonl(seq))");
    }

    #[test]
    fn rpcsec_unwrap_fail_is_garbage_args_with_verf() {
        use krb5_kdc::TEST_REALM;
        let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
        let cred = rpcsec_cred(RPG_DATA, 1, GSS_PRIVACY, &handle);
        let mut header = XdrW::default();
        header.u32(32);
        header.u32(MSG_CALL);
        header.u32(RPC_VERSION);
        header.u32(KADM_PROG);
        header.u32(KADM_VERS);
        header.u32(GET_PRIVS);
        header.u32(FLAVOR_GSS);
        header.opaque(&cred);
        let mic = ctx.get_mic(&header.b).unwrap();
        let mut arg = XdrW::default();
        arg.opaque(b"\x00\x01");
        let rec = rpcsec_call(
            32, KADM_PROG, KADM_VERS, GET_PRIVS, &cred, FLAVOR_GSS, &mic, &arg.b,
        );
        let mut agss = None;
        let out = handle_rpc(
            &store,
            &acl,
            &[],
            TEST_REALM,
            b"hdl",
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            &rec,
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), 32);
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
        let verf = r.opaque().unwrap();
        assert!(!verf.is_empty());
        assert_eq!(r.u32().unwrap(), GARBAGE_ARGS);
    }

    #[test]
    fn get_privs_is_all_ones() {
        let (store, _acl, actor) = setup();
        let limited = Acl::parse("limited@KERBER.TEST i\n").expect("acl");
        for who in [actor.as_str(), "limited@KERBER.TEST", "nobody@KERBER.TEST"] {
            let out = dispatch_kadm5(&store, &limited, who, GET_PRIVS, &[]).unwrap();
            let mut r = XdrR::new(&out);
            assert_eq!(r.u32().unwrap(), API_V2);
            assert_eq!(r.u32().unwrap(), 0);
            assert_eq!(r.u32().unwrap(), !0, "MIT server_misc.c:155 *privs = ~0");
        }
    }

    fn list_args() -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("*"));
        w.b
    }

    #[test]
    fn listprincs_inquire_is_auth_list() {
        let (store, _acl, _actor) = setup();
        let ro = Acl::parse("ro@KERBER.TEST i\n").expect("acl");
        let out = dispatch_kadm5(&store, &ro, "ro@KERBER.TEST", GET_PRINCS, &list_args()).unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_LIST);
    }

    #[test]
    fn listprincs_list_is_ok() {
        let (store, _acl, _actor) = setup();
        let ro = Acl::parse("ro@KERBER.TEST l\n").expect("acl");
        let out = dispatch_kadm5(&store, &ro, "ro@KERBER.TEST", GET_PRINCS, &list_args()).unwrap();
        assert_eq!(ret_code(&out), 0);
    }

    #[test]
    fn addpol_denied_is_auth_add() {
        let (store, _acl, _actor) = setup();
        let ro = Acl::parse("ro@KERBER.TEST i\n").expect("acl");
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("p"));
        let out = dispatch_kadm5(&store, &ro, "ro@KERBER.TEST", CREATE_POLICY, &w.b).unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_ADD);
    }

    #[test]
    fn delpol_denied_is_auth_delete() {
        let (store, _acl, _actor) = setup();
        let ro = Acl::parse("ro@KERBER.TEST i\n").expect("acl");
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("p"));
        let out = dispatch_kadm5(&store, &ro, "ro@KERBER.TEST", DELETE_POLICY, &w.b).unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_DELETE);
    }

    #[test]
    fn getprinc_self_without_acl_is_ok() {
        let (store, _acl, _actor) = setup();
        let none = Acl::parse("nobody@KERBER.TEST a\n").expect("acl");
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.u32(u32::MAX);
        let out = dispatch_kadm5(&store, &none, "user@KERBER.TEST", GET_PRINCIPAL, &w.b).unwrap();
        assert_eq!(ret_code(&out), 0);
    }

    #[test]
    fn cpw_self_without_initial_is_auth_initial() {
        let (store, _acl, _actor) = setup();
        let none = Acl::parse("nobody@KERBER.TEST a\n").expect("acl");
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.nullstring(Some("new-secret"));
        let out = dispatch_kadm5_ticket(
            &store,
            &none,
            "user@KERBER.TEST",
            CHPASS_PRINCIPAL,
            &w.b,
            false,
            false,
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_INITIAL);
    }

    fn getprinc_args(name: &str) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some(name));
        w.u32(u32::MAX);
        w.b
    }

    fn modify_args(name: &str) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some(name));
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(3600);
        w.u32(1);
        w.u32(0);
        w.u32(0);
        w.u32(1);
        w.u32(1);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(1);
        w.u32(0);
        w.u32(KADM5_ATTRIBUTES);
        w.b
    }

    fn setstr_args(name: &str, key: &str, value: &str) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some(name));
        w.nullstring(Some(key));
        w.nullstring(Some(value));
        w.b
    }

    fn cpw_dispatch(
        store: &krb5_kdc::SharedDump,
        acl: &Acl,
        actor: &str,
        proc: u32,
        args: &[u8],
    ) -> Vec<u8> {
        dispatch_kadm5_ticket(store, acl, actor, proc, args, true, true).unwrap()
    }

    #[test]
    fn changepw_service_listprincs_is_auth_list() {
        let (store, acl, actor) = setup();
        let out = cpw_dispatch(&store, &acl, &actor, GET_PRINCS, &list_args());
        assert_eq!(ret_code(&out), KADM5_AUTH_LIST);
    }

    #[test]
    fn changepw_service_denies_non_self_ops() {
        let (store, acl, _actor) = setup();
        let user = "user@KERBER.TEST";
        let other = "admin@KERBER.TEST";
        let mut rename = XdrW::default();
        rename.u32(API_V2);
        rename.nullstring(Some(user));
        rename.nullstring(Some("renamed@KERBER.TEST"));
        let cases: &[(u32, Vec<u8>, u32)] = &[
            (GET_PRINCS, list_args(), KADM5_AUTH_LIST),
            (GET_POLS, list_args(), KADM5_AUTH_LIST),
            (GET_PRINCIPAL, getprinc_args(user), KADM5_AUTH_GET),
            (DELETE_PRINCIPAL, encode_named(user), KADM5_AUTH_DELETE),
            (MODIFY_PRINCIPAL, modify_args(user), KADM5_AUTH_MODIFY),
            (RENAME_PRINCIPAL, rename.b.clone(), KADM5_AUTH_INSUFFICIENT),
            (
                CHPASS_PRINCIPAL,
                chpass_args(user, "nope"),
                KADM5_AUTH_CHANGEPW,
            ),
            (CHRAND_PRINCIPAL, encode_named(user), KADM5_AUTH_CHANGEPW),
            (CREATE_POLICY, encode_named("cpwpol"), KADM5_AUTH_ADD),
            (DELETE_POLICY, encode_named("cpwpol"), KADM5_AUTH_DELETE),
            (MODIFY_POLICY, encode_named("cpwpol"), KADM5_AUTH_MODIFY),
            (GET_POLICY, encode_named("cpwpol"), KADM5_AUTH_GET),
            (PURGEKEYS, encode_named(user), KADM5_AUTH_MODIFY),
            (GET_STRINGS, encode_named(user), KADM5_AUTH_GET),
            (
                SET_STRING,
                setstr_args(user, "note", "x"),
                KADM5_AUTH_MODIFY,
            ),
            (EXTRACT_KEYS, extract_args(user, 0), KADM5_AUTH_EXTRACT),
        ];
        for (proc, args, want) in cases {
            let out = cpw_dispatch(&store, &acl, other, *proc, args);
            assert_eq!(ret_code(&out), *want, "changepw proc {proc} want {want}");
        }
    }

    #[test]
    fn changepw_service_self_getprinc_is_ok() {
        let (store, acl, _actor) = setup();
        let out = cpw_dispatch(
            &store,
            &acl,
            "user@KERBER.TEST",
            GET_PRINCIPAL,
            &getprinc_args("user@KERBER.TEST"),
        );
        assert_eq!(ret_code(&out), 0);
    }

    #[test]
    fn changepw_service_self_getstrs_is_auth_get() {
        let (store, acl, _actor) = setup();
        let out = cpw_dispatch(
            &store,
            &acl,
            "user@KERBER.TEST",
            GET_STRINGS,
            &encode_named("user@KERBER.TEST"),
        );
        assert_eq!(ret_code(&out), KADM5_AUTH_GET);
    }

    #[test]
    fn changepw_service_self_purgekeys_is_auth_modify() {
        let (store, acl, _actor) = setup();
        let out = cpw_dispatch(
            &store,
            &acl,
            "user@KERBER.TEST",
            PURGEKEYS,
            &encode_named("user@KERBER.TEST"),
        );
        assert_eq!(ret_code(&out), KADM5_AUTH_MODIFY);
    }

    #[test]
    fn changepw_service_own_policy_getpol_is_ok() {
        let (store, acl, actor) = setup();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        {
            let mut g = store.write().unwrap();
            g.put_policy(krb5_kdc::NamedPolicy::new("userpol"));
            g.set_principal_policy(&user, Some("userpol".into()))
                .unwrap();
        }
        let out = cpw_dispatch(
            &store,
            &acl,
            "user@KERBER.TEST",
            GET_POLICY,
            &encode_named("userpol"),
        );
        assert_eq!(ret_code(&out), 0);
        let denied = cpw_dispatch(&store, &acl, &actor, GET_POLICY, &encode_named("userpol"));
        assert_eq!(ret_code(&denied), KADM5_AUTH_GET);
    }

    #[test]
    fn changepw_service_getprivs_is_ok() {
        let (store, acl, actor) = setup();
        let out = cpw_dispatch(&store, &acl, &actor, GET_PRIVS, &[]);
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.u32().unwrap(), !0);
    }

    #[test]
    fn parse_rename_reads_two_principals() {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("old@KERBER.TEST"));
        w.nullstring(Some("new@KERBER.TEST"));
        let (old, old_realm, new, new_realm) = parse_rename(&w.b).unwrap();
        assert_eq!(old.components_joined(), "old");
        assert_eq!(old_realm, "KERBER.TEST");
        assert_eq!(new.components_joined(), "new");
        assert_eq!(new_realm, "KERBER.TEST");
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
        let add_only = Acl::parse("admin@KERBER.TEST a\n").expect("acl");
        let mut w2 = XdrW::default();
        w2.u32(API_V2);
        w2.nullstring(Some(&format!("renameto@{TEST_REALM}")));
        w2.nullstring(Some(&format!("renamefrom@{TEST_REALM}")));
        let denied = dispatch_kadm5(&shared, &add_only, &actor, RENAME_PRINCIPAL, &w2.b).unwrap();
        assert_eq!(ret_code(&denied), KADM5_AUTH_INSUFFICIENT);
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

    fn gprinc_key_kvnos(out: &[u8]) -> (u32, Vec<u32>) {
        let mut r = XdrR::new(out);
        r.u32().unwrap();
        r.u32().unwrap();
        let _ = r.nullstring().unwrap();
        for _ in 0..4 {
            r.u32().unwrap();
        }
        assert_eq!(r.u32().unwrap(), 0);
        let _ = r.nullstring().unwrap();
        for _ in 0..4 {
            r.u32().unwrap();
        }
        let _ = r.nullstring().unwrap();
        for _ in 0..5 {
            r.u32().unwrap();
        }
        let n_key = r.u32().unwrap();
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
        let mut kvnos = Vec::new();
        for _ in 0..n {
            let ver = r.u32().unwrap();
            kvnos.push(r.u32().unwrap());
            r.u32().unwrap();
            if ver > 1 {
                r.u32().unwrap();
            }
        }
        (n_key, kvnos)
    }

    #[test]
    fn getprinc_dates_from_create_cpw_mod() {
        let (store, acl, actor) = setup();
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["dated"]);
        {
            let mut g = store.write().unwrap();
            g.create_password(&acl, &actor, &name, b"date-secret")
                .unwrap();
        }
        let created = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &{
            let mut w = XdrW::default();
            w.u32(API_V2);
            w.nullstring(Some("dated@KERBER.TEST"));
            w.u32(u32::MAX);
            w.b
        })
        .unwrap();
        let (pwd0, mod0) = gprinc_pwd_and_mod(&created);
        assert_ne!(pwd0, 0, "create must stamp last_pwd_change, not [never]");
        assert_ne!(mod0, 0, "create must stamp mod_date, not Unix epoch");
        {
            let mut g = store.write().unwrap();
            g.set_password(&name, b"date-rotated").unwrap();
        }
        let after_cpw = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &{
            let mut w = XdrW::default();
            w.u32(API_V2);
            w.nullstring(Some("dated@KERBER.TEST"));
            w.u32(u32::MAX);
            w.b
        })
        .unwrap();
        let (pwd1, mod1) = gprinc_pwd_and_mod(&after_cpw);
        assert!(pwd1 >= pwd0, "cpw must keep a real last_pwd_change");
        assert_ne!(mod1, 0);
        {
            let mut g = store.write().unwrap();
            g.apply_admin_fields(&name, None, None, Some(u32::MAX), None, None, false)
                .unwrap();
        }
        let after_mod = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &{
            let mut w = XdrW::default();
            w.u32(API_V2);
            w.nullstring(Some("dated@KERBER.TEST"));
            w.u32(u32::MAX);
            w.b
        })
        .unwrap();
        let (pwd2, mod2) = gprinc_pwd_and_mod(&after_mod);
        assert_eq!(pwd2, pwd1, "modprinc must not clear last_pwd_change");
        assert_ne!(mod2, 0);
    }

    fn gprinc_pwd_and_mod(out: &[u8]) -> (u32, u32) {
        let mut r = XdrR::new(out);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        let _ = r.nullstring().unwrap();
        let _ = r.u32().unwrap();
        let last_pwd = r.u32().unwrap();
        let _ = r.u32().unwrap();
        let _ = r.u32().unwrap();
        assert_eq!(r.u32().unwrap(), 0);
        let _ = r.nullstring().unwrap();
        let mod_date = r.u32().unwrap();
        (last_pwd, mod_date)
    }

    #[test]
    fn getprinc_omits_password_history_kvnos() {
        let (store, acl, actor) = setup();
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["histuser"]);
        {
            let mut g = store.write().unwrap();
            let mut pol = krb5_kdc::NamedPolicy::new("e3hist");
            pol.history = 2;
            g.put_policy(pol);
            g.create_password(&acl, &actor, &name, b"hist-secret")
                .unwrap();
            g.set_principal_policy(&name, Some("e3hist".into()))
                .unwrap();
            g.set_password(&name, b"hist-rotated").unwrap();
            let p = g.get_name(&name).unwrap();
            assert!(!p.key_history.is_empty());
        }
        let out = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &{
            let mut w = XdrW::default();
            w.u32(API_V2);
            w.nullstring(Some("histuser@KERBER.TEST"));
            w.u32(u32::MAX);
            w.b
        })
        .unwrap();
        assert_eq!(ret_code(&out), 0);
        let (n_key, kvnos) = gprinc_key_kvnos(&out);
        let g = store.read().unwrap();
        let p = g.get_name(&name).unwrap();
        assert_eq!(n_key as usize, p.keys.len());
        let current = p.keys[0].kvno;
        assert!(
            kvnos.iter().all(|v| *v == current),
            "history kvnos in getprinc: {kvnos:?}"
        );
        assert!(!p.key_history.is_empty());
        assert!(p.key_history.iter().any(|k| k.kvno != current));
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
    fn getprinc_missing_unauthorised_is_unk_princ() {
        let (store, _acl, _actor) = setup();
        let none = Acl::parse("nobody@KERBER.TEST a\n").expect("acl");
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("nosuch@KERBER.TEST"));
        w.u32(u32::MAX);
        let out = dispatch_kadm5(&store, &none, "user@KERBER.TEST", GET_PRINCIPAL, &w.b).unwrap();
        assert_eq!(ret_code(&out), KADM5_UNK_PRINC);
        assert_ne!(ret_code(&out), KADM5_AUTH_GET);
    }

    #[test]
    fn getprinc_foreign_realm_is_unk_princ() {
        let (store, acl, actor) = setup();
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@OTHER.REALM"));
        w.u32(u32::MAX);
        let out = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &w.b).unwrap();
        assert_eq!(ret_code(&out), KADM5_UNK_PRINC);
        let mut loc = XdrW::default();
        loc.u32(API_V2);
        loc.nullstring(Some("user@KERBER.TEST"));
        loc.u32(u32::MAX);
        let ok = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &loc.b).unwrap();
        assert_eq!(ret_code(&ok), 0);
    }

    #[test]
    fn modify_foreign_realm_existing_user_is_unk_princ() {
        let (store, acl, actor) = setup();
        let before = {
            let g = store.read().unwrap();
            g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
                .unwrap()
                .attributes
        };
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            MODIFY_PRINCIPAL,
            &modify_rec("user@OTHER.REALM"),
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_UNK_PRINC);
        let after = {
            let g = store.read().unwrap();
            g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
                .unwrap()
                .attributes
        };
        assert_eq!(after, before);
        let local = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            MODIFY_PRINCIPAL,
            &modify_rec("user@KERBER.TEST"),
        )
        .unwrap();
        assert_eq!(ret_code(&local), 0);
    }

    fn create_rec(name: &str, pass: &str) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some(name));
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(3600);
        w.u32(1);
        w.u32(0);
        w.u32(0);
        w.u32(1);
        w.u32(1);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(1);
        w.u32(0);
        w.u32(0);
        w.nullstring(Some(pass));
        w.b
    }

    #[test]
    fn create_foreign_realm_authorises_first() {
        let (store, _acl, _actor) = setup();
        let none = Acl::parse("nobody@KERBER.TEST a\n").expect("acl");
        let out = dispatch_kadm5(
            &store,
            &none,
            "user@KERBER.TEST",
            CREATE_PRINCIPAL,
            &create_rec("user@OTHER.REALM", "x"),
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_ADD);
        assert_ne!(ret_code(&out), KADM5_UNK_PRINC);
        let del = dispatch_kadm5(
            &store,
            &none,
            "user@KERBER.TEST",
            DELETE_PRINCIPAL,
            &encode_named("user@OTHER.REALM"),
        )
        .unwrap();
        assert_eq!(ret_code(&del), KADM5_AUTH_DELETE);
        assert_ne!(ret_code(&del), KADM5_UNK_PRINC);
        let mut ren_args = XdrW::default();
        ren_args.u32(API_V2);
        ren_args.nullstring(Some("user@OTHER.REALM"));
        ren_args.nullstring(Some("x@OTHER.REALM"));
        let ren = dispatch_kadm5(
            &store,
            &none,
            "user@KERBER.TEST",
            RENAME_PRINCIPAL,
            &ren_args.b,
        )
        .unwrap();
        assert_eq!(ret_code(&ren), KADM5_AUTH_INSUFFICIENT);
        assert_ne!(ret_code(&ren), KADM5_UNK_PRINC);
    }

    #[test]
    fn create_foreign_realm_then_getprinc() {
        let (store, acl, actor) = setup();
        let created = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            CREATE_PRINCIPAL,
            &create_rec("user@OTHER.REALM", "x"),
        )
        .unwrap();
        assert_eq!(ret_code(&created), 0);
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@OTHER.REALM"));
        w.u32(u32::MAX);
        let got = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &w.b).unwrap();
        assert_eq!(ret_code(&got), 0);
        let mut r = XdrR::new(&got);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.nullstring().unwrap().as_deref(), Some("user@OTHER.REALM"));
        let local = {
            let g = store.read().unwrap();
            g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
                .map(krb5_kdc::Principal::id)
        };
        assert_eq!(local.as_deref(), Some("user@KERBER.TEST"));
    }

    fn stub_unk_before_acl(proc: u32, args: &[u8], not_auth: u32) {
        let (store, _acl, _actor) = setup();
        let none = Acl::parse("nobody@KERBER.TEST a\n").expect("acl");
        let out = dispatch_kadm5(&store, &none, "user@KERBER.TEST", proc, args)
            .unwrap_or_else(|e| panic!("proc {proc} dispatch {e:?}"));
        assert_eq!(ret_code(&out), KADM5_UNK_PRINC, "proc {proc}");
        assert_ne!(
            ret_code(&out),
            not_auth,
            "proc {proc} must not be ACL-first"
        );
    }

    fn modify_rec(name: &str) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some(name));
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(3600);
        w.u32(1);
        w.u32(0);
        w.u32(0);
        w.u32(1);
        w.u32(1);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(1);
        w.u32(0);
        w.u32(KADM5_ATTRIBUTES);
        w.b
    }

    #[test]
    fn stub_setup_unk_before_acl_on_modify_setkey_purge_extract_setstr() {
        stub_unk_before_acl(
            EXTRACT_KEYS,
            &extract_args("nosuch@KERBER.TEST", 0),
            KADM5_AUTH_EXTRACT,
        );
        stub_unk_before_acl(
            MODIFY_PRINCIPAL,
            &modify_rec("nosuch@KERBER.TEST"),
            KADM5_AUTH_MODIFY,
        );
        let mut pk = XdrW::default();
        pk.u32(API_V2);
        pk.nullstring(Some("nosuch@KERBER.TEST"));
        pk.u32(0);
        stub_unk_before_acl(PURGEKEYS, &pk.b, KADM5_AUTH_MODIFY);
        let mut sk = XdrW::default();
        sk.u32(API_V2);
        sk.nullstring(Some("nosuch@KERBER.TEST"));
        sk.u32(0);
        sk.u32(0);
        sk.u32(1);
        sk.u32(18);
        sk.opaque(&[0xEFu8; 32]);
        stub_unk_before_acl(SETKEY_PRINCIPAL3, &sk.b, KADM5_AUTH_SETKEY);
        stub_unk_before_acl(
            SETKEY_PRINCIPAL,
            &setkey16_args("nosuch@KERBER.TEST", 18, &[0xEFu8; 32]),
            KADM5_AUTH_SETKEY,
        );
        stub_unk_before_acl(
            SETKEY_PRINCIPAL4,
            &setkey4_args("nosuch@KERBER.TEST", false, 1, 18, &[0xEFu8; 32], 0, &[]),
            KADM5_AUTH_SETKEY,
        );
        let mut ss = XdrW::default();
        ss.u32(API_V2);
        ss.nullstring(Some("nosuch@KERBER.TEST"));
        ss.nullstring(Some("k"));
        ss.nullstring(Some("v"));
        stub_unk_before_acl(SET_STRING, &ss.b, KADM5_AUTH_MODIFY);
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
    fn extract_keys_omits_password_history() {
        let (store, acl, actor) = setup();
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["exhist"]);
        let (n_cur, hist_kvno) = {
            let mut g = store.write().unwrap();
            let mut pol = krb5_kdc::NamedPolicy::new("exhistpol");
            pol.history = 2;
            g.put_policy(pol);
            g.create_password(&acl, &actor, &name, b"ex-secret")
                .unwrap();
            g.set_principal_policy(&name, Some("exhistpol".into()))
                .unwrap();
            g.set_password(&name, b"ex-rotated").unwrap();
            let p = g.get_name(&name).unwrap();
            let hist = p.key_history.iter().map(|k| k.kvno).max().unwrap();
            (u32::try_from(p.keys.len()).unwrap_or(0), hist)
        };
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            EXTRACT_KEYS,
            &extract_args("exhist@KERBER.TEST", 0),
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0);
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        let n = r.u32().unwrap();
        assert_eq!(n, n_cur);
        for _ in 0..n {
            let kvno = r.u32().unwrap();
            assert_ne!(
                kvno, hist_kvno,
                "EXTRACT kvno=0 must not return osa history"
            );
            let _ = r.u32().unwrap();
            let _ = r.opaque().unwrap();
            let _ = r.u32().unwrap();
            let _ = r.opaque().unwrap();
        }
    }

    #[test]
    fn chpass3_keepold_retains_prior_keys() {
        let (store, acl, actor) = setup();
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["keepu"]);
        let old_kvno = {
            let mut g = store.write().unwrap();
            g.create_password(&acl, &actor, &name, b"keep-secret")
                .unwrap();
            g.get_name(&name).unwrap().keys[0].kvno
        };
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("keepu@KERBER.TEST"));
        w.u32(1);
        w.u32(0);
        w.nullstring(Some("keep-rotated"));
        let out = dispatch_kadm5(&store, &acl, &actor, CHPASS_PRINCIPAL3, &w.b).unwrap();
        assert_eq!(ret_code(&out), 0);
        let n_keys = {
            let g = store.read().unwrap();
            let p = g.get_name(&name).unwrap();
            assert!(p.keys.iter().any(|k| k.kvno == old_kvno));
            assert!(p.keys.iter().any(|k| k.kvno != old_kvno));
            p.keys.len()
        };
        let got = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &{
            let mut w = XdrW::default();
            w.u32(API_V2);
            w.nullstring(Some("keepu@KERBER.TEST"));
            w.u32(u32::MAX);
            w.b
        })
        .unwrap();
        let (n_key, kvnos) = gprinc_key_kvnos(&got);
        assert_eq!(n_key as usize, n_keys);
        assert!(kvnos.contains(&old_kvno));
    }

    #[test]
    fn policy_min_max_life_round_trip_and_min_life() {
        let (store, acl, actor) = setup();
        let mut pol = krb5_kdc::NamedPolicy::new("life");
        pol.pw_min_life = 3600;
        pol.pw_max_life = 86400;
        let mask = KADM5_POLICY | KADM5_PW_MIN_LIFE | KADM5_PW_MAX_LIFE;
        let created = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            CREATE_POLICY,
            &encode_cpol(API_V2, &pol, mask),
        )
        .unwrap();
        assert_eq!(ret_code(&created), 0);
        let mut gq = XdrW::default();
        gq.u32(API_V2);
        gq.nullstring(Some("life"));
        let got = dispatch_kadm5(&store, &acl, &actor, GET_POLICY, &gq.b).unwrap();
        assert_eq!(ret_code(&got), 0);
        let mut r = XdrR::new(&got);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(r.nullstring().unwrap().as_deref(), Some("life"));
        assert_eq!(r.u32().unwrap(), 3600);
        assert_eq!(r.u32().unwrap(), 86400);
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
        {
            let mut g = store.write().unwrap();
            g.set_principal_policy(&user, Some("life".into())).unwrap();
            assert!(g.get_name(&user).unwrap().pw_expire > 0);
            g.set_last_pwd_unix(&user, 1);
        }
        let once = dispatch_kadm5(
            &store,
            &acl,
            "user@KERBER.TEST",
            CHPASS_PRINCIPAL,
            &chpass_args("user@KERBER.TEST", "user-rotated"),
        )
        .unwrap();
        assert_eq!(ret_code(&once), 0);
        let twice = dispatch_kadm5(
            &store,
            &acl,
            "user@KERBER.TEST",
            CHPASS_PRINCIPAL,
            &chpass_args("user@KERBER.TEST", "user-rotated2"),
        )
        .unwrap();
        assert_eq!(ret_code(&twice), KADM5_PASS_TOOSOON);
        let admin = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            CHPASS_PRINCIPAL,
            &chpass_args("user@KERBER.TEST", "admin-rotated"),
        )
        .unwrap();
        assert_eq!(ret_code(&admin), 0);
    }

    #[test]
    fn min_life_requires_pwchange_bypasses() {
        let (store, acl, _actor) = setup();
        let mut pol = krb5_kdc::NamedPolicy::new("soon");
        pol.pw_min_life = 3600;
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
        {
            let mut g = store.write().unwrap();
            g.put_policy(pol);
            g.set_principal_policy(&user, Some("soon".into())).unwrap();
            g.set_password(&user, b"need-change").unwrap();
            g.apply_admin_fields(
                &user,
                Some(krb5_kdc::KDB_REQUIRES_PWCHANGE),
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
            "user@KERBER.TEST",
            CHPASS_PRINCIPAL,
            &chpass_args("user@KERBER.TEST", "changed-now"),
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0);
    }

    #[test]
    fn chpass_lockdown_self_is_auth_changepw_before_initial() {
        let (store, acl, actor) = setup();
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["lockedself"]);
        {
            let mut g = store.write().unwrap();
            g.create_password(&acl, &actor, &name, b"lock-secret")
                .unwrap();
            g.apply_admin_fields(
                &name,
                Some(krb5_kdc::KDB_LOCKDOWN_KEYS),
                None,
                None,
                None,
                None,
                false,
            )
            .unwrap();
        }
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("lockedself@KERBER.TEST"));
        w.nullstring(Some("new-secret"));
        let out = dispatch_kadm5_ticket(
            &store,
            &acl,
            "lockedself@KERBER.TEST",
            CHPASS_PRINCIPAL,
            &w.b,
            false,
            false,
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_CHANGEPW);
    }

    #[test]
    fn chrand3_self_keepold_clamps_to_five() {
        let (store, acl, actor) = setup();
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["selfchrand"]);
        {
            let mut g = store.write().unwrap();
            g.create_password(&acl, &actor, &name, b"keep-0").unwrap();
        }
        for i in 1..=6 {
            let mut w = XdrW::default();
            w.u32(API_V2);
            w.nullstring(Some("selfchrand@KERBER.TEST"));
            w.u32(1);
            w.u32(0);
            let out = dispatch_kadm5(
                &store,
                &acl,
                "selfchrand@KERBER.TEST",
                CHRAND_PRINCIPAL3,
                &w.b,
            )
            .unwrap();
            assert_eq!(ret_code(&out), 0, "chrand {i}");
        }
        let g = store.read().unwrap();
        let p = g.get_name(&name).unwrap();
        let mut kvnos: Vec<u32> = p.keys.iter().map(|k| k.kvno).collect();
        kvnos.sort_unstable();
        kvnos.dedup();
        assert_eq!(kvnos.len(), 5, "self chrand keepold cap: {kvnos:?}");
    }

    #[test]
    fn self_keepold_clamps_to_five() {
        let (store, acl, actor) = setup();
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["selfkeep"]);
        {
            let mut g = store.write().unwrap();
            g.create_password(&acl, &actor, &name, b"keep-0").unwrap();
        }
        for i in 1..=6 {
            let mut w = XdrW::default();
            w.u32(API_V2);
            w.nullstring(Some("selfkeep@KERBER.TEST"));
            w.u32(1);
            w.u32(0);
            w.nullstring(Some(&format!("keep-{i}")));
            let out = dispatch_kadm5(
                &store,
                &acl,
                "selfkeep@KERBER.TEST",
                CHPASS_PRINCIPAL3,
                &w.b,
            )
            .unwrap();
            assert_eq!(ret_code(&out), 0, "cpw {i}");
        }
        let g = store.read().unwrap();
        let p = g.get_name(&name).unwrap();
        let mut kvnos: Vec<u32> = p.keys.iter().map(|k| k.kvno).collect();
        kvnos.sort_unstable();
        kvnos.dedup();
        assert_eq!(kvnos.len(), 5, "self keepold cap: {kvnos:?}");
    }

    #[test]
    fn extract_keys_acl_is_auth_extract() {
        let (store, _acl, _actor) = setup();
        let limited = Acl::parse("admin@KERBER.TEST *\nlimited@KERBER.TEST i\n").expect("acl");
        let out = dispatch_kadm5(
            &store,
            &limited,
            "limited@KERBER.TEST",
            EXTRACT_KEYS,
            &extract_args("user@KERBER.TEST", 0),
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_EXTRACT);
        let star = Acl::parse("admin@KERBER.TEST *\n").expect("acl");
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
        assert_eq!(ret_code(&out), KADM5_AUTH_EXTRACT);
    }

    #[test]
    fn chpass_lockdown_is_protect_keys() {
        let (store, acl, actor) = setup();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let before = {
            let g = store.read().unwrap();
            g.get_name(&user)
                .unwrap()
                .keys
                .iter()
                .map(|k| k.key.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
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
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.nullstring(Some("lock-rotated-secret"));
        let out = dispatch_kadm5(&store, &acl, &actor, CHPASS_PRINCIPAL, &w.b).unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_CHANGEPW);
        let after = {
            let g = store.read().unwrap();
            g.get_name(&user)
                .unwrap()
                .keys
                .iter()
                .map(|k| k.key.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        assert_eq!(after, before, "lockdown chpass must not rewrite keys");
    }

    #[test]
    fn chrand_lockdown_returns_empty_keys() {
        let (store, acl, actor) = setup();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let before = {
            let g = store.read().unwrap();
            g.get_name(&user)
                .unwrap()
                .keys
                .iter()
                .map(|k| k.key.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
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
            CHRAND_PRINCIPAL,
            &encode_named("user@KERBER.TEST"),
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0);
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        assert_eq!(
            r.u32().unwrap(),
            0,
            "MIT chrand under lockdown returns no keys"
        );
        let after = {
            let g = store.read().unwrap();
            g.get_name(&user)
                .unwrap()
                .keys
                .iter()
                .map(|k| k.key.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        assert_ne!(after, before, "lockdown chrand still rotates stored keys");
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
        {
            let g = store.read().unwrap();
            let p = g.get_name(&name).unwrap();
            assert!(!p.key_history.is_empty());
            assert!(p.keys.iter().all(|k| k.kvno != 1));
            assert!(!p.keys.is_empty());
        }
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
        let limited = Acl::parse("limited@KERBER.TEST i\n").expect("acl");
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
    fn purgekeys_locked_down_target_is_allowed() {
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
        assert_eq!(ret_code(&out), 0);
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

    fn setkey4_args(
        name: &str,
        keepold: bool,
        kvno: u32,
        etype: i32,
        key: &[u8],
        salt_type: i32,
        salt: &[u8],
    ) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some(name));
        w.u32(u32::from(keepold));
        w.u32(1);
        w.u32(kvno);
        w.u32(u32::try_from(etype).unwrap());
        w.opaque(key);
        w.u32(u32::try_from(salt_type).unwrap());
        w.opaque(salt);
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
        let n_old = {
            let g = store.read().unwrap();
            g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
                .unwrap()
                .keys
                .len()
        };
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            SETKEY_PRINCIPAL4,
            &setkey4_args("user@KERBER.TEST", true, 0, 18, &[0xCDu8; 32], 0, &[]),
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0);
        let g = store.read().unwrap();
        let p = g
            .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .unwrap();
        assert_eq!(p.keys.len(), 1 + n_old);
        assert!(p.keys.iter().any(|k| k.key.as_bytes() == [0xCDu8; 32]));
        assert!(p.key_history.is_empty());
    }

    #[test]
    fn setkey4_kadm5_key_data_kvno_and_salt() {
        let (store, acl, actor) = setup();
        let key = [0x11u8; 32];
        let salt = b"special-salt";
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            SETKEY_PRINCIPAL4,
            &setkey4_args("user@KERBER.TEST", false, 5, 18, &key, 4, salt),
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0);
        let g = store.read().unwrap();
        let p = g
            .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .unwrap();
        assert_eq!(p.keys.len(), 1);
        assert_eq!(p.keys[0].kvno, 5);
        assert_eq!(p.keys[0].etype.to_iana(), 18);
        assert_eq!(p.keys[0].key.as_bytes(), key);
        assert_eq!(p.keys[0].salt_type, Some(4));
        assert_eq!(p.keys[0].kdb_salt.as_deref(), Some(salt.as_slice()));
        assert!(p.key_history.is_empty());
    }

    #[test]
    fn setkey4_krb5_key_data_ver_first_does_not_decode() {
        let (store, acl, actor) = setup();
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.u32(0);
        w.u32(1);
        w.u32(2);
        w.u32(5);
        w.u32(18);
        w.opaque(&[0xABu8; 32]);
        w.u32(4);
        w.opaque(b"s");
        assert!(
            dispatch_kadm5(&store, &acl, &actor, SETKEY_PRINCIPAL4, &w.b).is_err(),
            "xdr_krb5_key_data (key_data_ver first) is not SETKEY4"
        );
    }

    #[test]
    fn setkey_acl_is_auth_setkey() {
        let (store, _acl, _actor) = setup();
        let limited = Acl::parse("limited@KERBER.TEST i\n").expect("acl");
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
        assert_eq!(ret_code(&out), KADM5_AUTH_SETKEY);
    }

    #[test]
    fn delete_lockdown_is_auth_delete() {
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
            DELETE_PRINCIPAL,
            &encode_named("user@KERBER.TEST"),
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_DELETE);
        assert!(store.read().unwrap().get_name(&user).is_some());
    }

    #[test]
    fn modify_clear_lockdown_is_auth_modify() {
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
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(3600);
        w.u32(1);
        w.u32(0);
        w.u32(0);
        w.u32(1);
        w.u32(1);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(1);
        w.u32(0);
        w.u32(KADM5_ATTRIBUTES);
        let out = dispatch_kadm5(&store, &acl, &actor, MODIFY_PRINCIPAL, &w.b).unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_MODIFY);
        let g = store.read().unwrap();
        assert_eq!(
            g.get_name(&user).unwrap().attributes & KDB_LOCKDOWN_KEYS,
            KDB_LOCKDOWN_KEYS
        );
    }

    #[test]
    fn modprinc_keeping_lockdown_bit_is_allowed() {
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
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(3600);
        w.u32(1);
        w.u32(0);
        w.u32(KDB_LOCKDOWN_KEYS);
        w.u32(1);
        w.u32(1);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u32(1);
        w.u32(0);
        w.u32(KADM5_ATTRIBUTES);
        let out = dispatch_kadm5(&store, &acl, &actor, MODIFY_PRINCIPAL, &w.b).unwrap();
        assert_eq!(ret_code(&out), 0);
        let g = store.read().unwrap();
        assert_eq!(
            g.get_name(&user).unwrap().attributes & KDB_LOCKDOWN_KEYS,
            KDB_LOCKDOWN_KEYS
        );
    }

    #[test]
    fn rename_lockdown_source_is_auth_delete() {
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
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.nullstring(Some("renamed@KERBER.TEST"));
        let out = dispatch_kadm5(&store, &acl, &actor, RENAME_PRINCIPAL, &w.b).unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_DELETE);
        assert!(store.read().unwrap().get_name(&user).is_some());
    }

    #[test]
    fn rename_unauthorised_lockdown_is_auth_insufficient() {
        let (store, _acl, actor) = setup();
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
        let add_only = Acl::parse("admin@KERBER.TEST a\n").expect("acl");
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.nullstring(Some("renamed@KERBER.TEST"));
        let out = dispatch_kadm5(&store, &add_only, &actor, RENAME_PRINCIPAL, &w.b).unwrap();
        assert_eq!(ret_code(&out), KADM5_AUTH_INSUFFICIENT);
        assert!(store.read().unwrap().get_name(&user).is_some());
    }

    #[test]
    fn setstr_getstrs_round_trip() {
        let (store, acl, actor) = setup();
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.nullstring(Some("note"));
        w.nullstring(Some("hello-g3d"));
        let out = dispatch_kadm5(&store, &acl, &actor, SET_STRING, &w.b).unwrap();
        assert_eq!(ret_code(&out), 0);
        let mut g = XdrW::default();
        g.u32(API_V2);
        g.nullstring(Some("user@KERBER.TEST"));
        let got = dispatch_kadm5(&store, &acl, &actor, GET_STRINGS, &g.b).unwrap();
        assert_eq!(ret_code(&got), 0);
        let mut r = XdrR::new(&got);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        let n = r.u32().unwrap();
        assert_eq!(r.u32().unwrap(), n);
        assert_eq!(n, 1);
        assert_eq!(r.nullstring().unwrap().as_deref(), Some("note"));
        assert_eq!(r.nullstring().unwrap().as_deref(), Some("hello-g3d"));
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

    fn chpass_args(name: &str, pass: &str) -> Vec<u8> {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some(name));
        w.nullstring(Some(pass));
        w.b
    }

    #[test]
    fn chpass_reload_keeps_concurrent_local_create() {
        use krb5_kdc::{load_store, save_store};
        let dir = std::env::temp_dir().join(format!(
            "n7-chpass-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("principal");
        let stash = dir.join("stash");
        let (store, acl) = krb5_kdc::bootstrap_documented().unwrap();
        save_store(&store, &db, &stash).unwrap();
        let mut local = load_store(&db, &stash).unwrap();
        let kadmind = load_store(&db, &stash).unwrap();
        let n7 = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["n7local"]);
        {
            let mut sess = AdminSession::local(&mut local, &acl, krb5_kdc::documented_admin_id());
            sess.create_password(&n7, b"n7-secret").unwrap();
        }
        let shared = krb5_kdc::shared_dump(kadmind);
        let actor = krb5_kdc::documented_admin_id();
        let out = dispatch_kadm5(
            &shared,
            &acl,
            &actor,
            CHPASS_PRINCIPAL,
            &chpass_args("user@KERBER.TEST", "n7-changed"),
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0, "chpass user");
        let loaded = load_store(&db, &stash).unwrap();
        assert!(
            loaded.get_name(&n7).is_some(),
            "local addprinc must survive remote cpw"
        );
        assert!(
            loaded
                .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
                .is_some()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_reload_sees_local_cpw() {
        use krb5_kdc::{load_store, save_store};
        let dir = std::env::temp_dir().join(format!(
            "o3-extract-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("principal");
        let stash = dir.join("stash");
        let (store, acl) = krb5_kdc::bootstrap_documented().unwrap();
        save_store(&store, &db, &stash).unwrap();
        let mut local = load_store(&db, &stash).unwrap();
        let kadmind = load_store(&db, &stash).unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let before = local
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        {
            let mut sess = AdminSession::local(&mut local, &acl, krb5_kdc::documented_admin_id());
            sess.change_password(&user, b"o3-new-secret").unwrap();
        }
        let after = local
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        assert!(after > before, "cpw must bump kvno");
        let shared = krb5_kdc::shared_dump(kadmind);
        let actor = krb5_kdc::documented_admin_id();
        let out = dispatch_kadm5(
            &shared,
            &acl,
            &actor,
            EXTRACT_KEYS,
            &extract_args("user@KERBER.TEST", 0),
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0, "extract");
        let mut r = XdrR::new(&out);
        assert_eq!(r.u32().unwrap(), API_V2);
        assert_eq!(r.u32().unwrap(), 0);
        let n = r.u32().unwrap();
        assert!(n > 0);
        let kvno = r.u32().unwrap();
        assert_eq!(kvno, after, "EXTRACT_KEYS must reload after local cpw");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn lockdown_user(store: &SharedStore) {
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
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

    #[test]
    fn unauthorized_is_auth_even_if_missing_or_lockdown() {
        let (store, _acl, _actor) = setup();
        lockdown_user(&store);
        let limited = Acl::parse("limited@KERBER.TEST i\n").expect("acl");
        let actor = "limited@KERBER.TEST";
        let cases: [(u32, Vec<u8>, u32); 10] = [
            (
                EXTRACT_KEYS,
                extract_args("user@KERBER.TEST", 0),
                KADM5_AUTH_EXTRACT,
            ),
            (
                EXTRACT_KEYS,
                extract_args("no-such@KERBER.TEST", 0),
                KADM5_UNK_PRINC,
            ),
            (
                PURGEKEYS,
                purgekeys_args("user@KERBER.TEST", -1),
                KADM5_AUTH_MODIFY,
            ),
            (
                PURGEKEYS,
                purgekeys_args("no-such@KERBER.TEST", -1),
                KADM5_UNK_PRINC,
            ),
            (
                SETKEY_PRINCIPAL,
                setkey16_args("user@KERBER.TEST", 18, &[0xABu8; 32]),
                KADM5_AUTH_SETKEY,
            ),
            (
                SETKEY_PRINCIPAL,
                setkey16_args("no-such@KERBER.TEST", 18, &[0xABu8; 32]),
                KADM5_UNK_PRINC,
            ),
            (
                CHPASS_PRINCIPAL,
                chpass_args("user@KERBER.TEST", "nope"),
                KADM5_AUTH_CHANGEPW,
            ),
            (
                CHPASS_PRINCIPAL,
                chpass_args("no-such@KERBER.TEST", "nope"),
                KADM5_UNK_PRINC,
            ),
            (
                CHRAND_PRINCIPAL,
                encode_named("user@KERBER.TEST"),
                KADM5_AUTH_CHANGEPW,
            ),
            (
                CHRAND_PRINCIPAL,
                encode_named("no-such@KERBER.TEST"),
                KADM5_UNK_PRINC,
            ),
        ];
        for (proc, args, want) in cases {
            let out = dispatch_kadm5(&store, &limited, actor, proc, &args).unwrap();
            assert_eq!(ret_code(&out), want, "proc {proc}");
        }
    }

    #[test]
    fn chrand_acl_is_auth_changepw() {
        let (store, _acl, _actor) = setup();
        let limited = Acl::parse("limited@KERBER.TEST i\n").expect("acl");
        let out = dispatch_kadm5(
            &store,
            &limited,
            "limited@KERBER.TEST",
            CHRAND_PRINCIPAL,
            &encode_named("user@KERBER.TEST"),
        )
        .unwrap();
        let code = ret_code(&out);
        assert_eq!(code, KADM5_AUTH_CHANGEPW);
        assert_ne!(code, KADM5_AUTH_GET);
        let missing = dispatch_kadm5(
            &store,
            &limited,
            "limited@KERBER.TEST",
            CHRAND_PRINCIPAL,
            &encode_named("no-such@KERBER.TEST"),
        )
        .unwrap();
        assert_eq!(ret_code(&missing), KADM5_UNK_PRINC);
    }

    #[test]
    fn setkey_keepold_kvno_collision_is_bad_kvno() {
        let (store, acl, actor) = setup();
        let kvno = {
            let g = store.read().unwrap();
            g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
                .unwrap()
                .keys[0]
                .kvno
        };
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            SETKEY_PRINCIPAL4,
            &setkey4_args("user@KERBER.TEST", true, kvno, 18, &[0xABu8; 32], 0, &[]),
        )
        .unwrap();
        assert_eq!(ret_code(&out), KADM5_SETKEY_BAD_KVNO);
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
    fn create_policy_unspecified_floors_and_zero_history_is_bad() {
        let (store, acl, actor) = setup();
        let empty = krb5_kdc::NamedPolicy::new("floors");
        let created = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            CREATE_POLICY,
            &encode_cpol(API_V2, &empty, KADM5_POLICY),
        )
        .unwrap();
        assert_eq!(ret_code(&created), 0);
        let g = store.read().unwrap();
        let p = g.policies().get("floors").unwrap();
        assert_eq!(p.min_length, 1);
        assert_eq!(p.min_classes, 1);
        assert_eq!(p.history, 1);
        drop(g);
        let zhist = krb5_kdc::NamedPolicy {
            name: "zhist".into(),
            min_length: 1,
            min_classes: 1,
            history: 0,
            max_fail: 0,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
            pw_min_life: 0,
            pw_max_life: 0,
        };
        let bad = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            CREATE_POLICY,
            &encode_cpol(API_V2, &zhist, KADM5_POLICY | KADM5_PW_HISTORY_NUM),
        )
        .unwrap();
        assert_eq!(ret_code(&bad), KADM5_BAD_HISTORY);
    }

    #[test]
    fn modify_policy_below_floor_is_bad_length() {
        let (store, acl, actor) = setup();
        let pol = krb5_kdc::NamedPolicy::new("fl");
        assert_eq!(
            ret_code(
                &dispatch_kadm5(
                    &store,
                    &acl,
                    &actor,
                    CREATE_POLICY,
                    &encode_cpol(API_V2, &pol, KADM5_POLICY),
                )
                .unwrap()
            ),
            0
        );
        let mut rec = pol.clone();
        rec.min_length = 0;
        let bad = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            MODIFY_POLICY,
            &encode_cpol(API_V2, &rec, KADM5_PW_MIN_LENGTH),
        )
        .unwrap();
        assert_eq!(ret_code(&bad), KADM5_BAD_LENGTH);
        rec.min_length = 1;
        rec.min_classes = 0;
        let badc = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            MODIFY_POLICY,
            &encode_cpol(API_V2, &rec, KADM5_PW_MIN_CLASSES),
        )
        .unwrap();
        assert_eq!(ret_code(&badc), KADM5_BAD_CLASS);
        rec.min_classes = 1;
        rec.history = 0;
        let badh = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            MODIFY_POLICY,
            &encode_cpol(API_V2, &rec, KADM5_PW_HISTORY_NUM),
        )
        .unwrap();
        assert_eq!(ret_code(&badh), KADM5_BAD_HISTORY);
    }

    #[test]
    fn modify_policy_min_life_over_merged_max_is_bad_min_pass_life() {
        let (store, acl, actor) = setup();
        let mut pol = krb5_kdc::NamedPolicy::new("life");
        pol.pw_max_life = 86_400;
        assert_eq!(
            ret_code(
                &dispatch_kadm5(
                    &store,
                    &acl,
                    &actor,
                    CREATE_POLICY,
                    &encode_cpol(API_V2, &pol, KADM5_POLICY | KADM5_PW_MAX_LIFE),
                )
                .unwrap()
            ),
            0
        );
        pol.pw_min_life = 172_800;
        let bad = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            MODIFY_POLICY,
            &encode_cpol(API_V2, &pol, KADM5_PW_MIN_LIFE),
        )
        .unwrap();
        assert_eq!(ret_code(&bad), KADM5_BAD_MIN_PASS_LIFE);
    }

    #[test]
    fn create_policy_dup_before_floors() {
        let (store, acl, actor) = setup();
        let pol = krb5_kdc::NamedPolicy::new("dup");
        assert_eq!(
            ret_code(
                &dispatch_kadm5(
                    &store,
                    &acl,
                    &actor,
                    CREATE_POLICY,
                    &encode_cpol(API_V2, &pol, KADM5_POLICY),
                )
                .unwrap()
            ),
            0
        );
        let mut z = pol.clone();
        z.history = 0;
        let dup = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            CREATE_POLICY,
            &encode_cpol(API_V2, &z, KADM5_POLICY | KADM5_PW_HISTORY_NUM),
        )
        .unwrap();
        assert_eq!(ret_code(&dup), KADM5_DUP);
    }

    #[test]
    fn non_self_keepold_is_unbounded() {
        let (store, acl, actor) = setup();
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        for i in 1..=6 {
            let mut w = XdrW::default();
            w.u32(API_V2);
            w.nullstring(Some("user@KERBER.TEST"));
            w.u32(1);
            w.u32(0);
            w.nullstring(Some(&format!("admin-keep-{i}")));
            let out = dispatch_kadm5(&store, &acl, &actor, CHPASS_PRINCIPAL3, &w.b).unwrap();
            assert_eq!(ret_code(&out), 0, "admin keepold {i}");
        }
        let g = store.read().unwrap();
        let p = g.get_name(&name).unwrap();
        let mut kvnos: Vec<u32> = p.keys.iter().map(|k| k.kvno).collect();
        kvnos.sort_unstable();
        kvnos.dedup();
        assert!(
            kvnos.len() > 5,
            "non-self keepold=1 is unbounded: {kvnos:?}"
        );
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
            pw_min_life: 0,
            pw_max_life: 0,
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

        let (st, last2, _, _, entries) = decode_incr_result(&out, None).unwrap();
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
        let limited = Acl::parse("admin@KERBER.TEST *\nuser@KERBER.TEST i\n").expect("acl");
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
        let (st, _, _, _, entries) = decode_incr_result(&out, None).unwrap();
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
        let (st_ok, _, _, _, _) = decode_incr_result(&ok, None).unwrap();
        assert_ne!(st_ok, krb5_kdc::IPROP_PERM_DENIED);
    }

    #[test]
    fn check_rpcsec_auth_rejects_kiprop_history_and_one_component() {
        let admin = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "admin"]);
        let cpw = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]);
        let hist = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "history"]);
        let kip = PrincipalName::new(
            PrincipalName::NT_SRV_HST,
            ["kiprop", "testhost.kerber.test"],
        );
        let one = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin"]);
        assert!(kadm5_rpcsec_ok(&admin));
        assert!(kadm5_rpcsec_ok(&cpw));
        assert!(!kadm5_rpcsec_ok(&hist));
        assert!(!kadm5_rpcsec_ok(&kip));
        assert!(!kadm5_rpcsec_ok(&one));
        assert!(kadm5_auth_gssapi_ok(&admin));
        assert!(kadm5_auth_gssapi_ok(&cpw));
        assert!(!kadm5_auth_gssapi_ok(&hist));
        assert!(!kadm5_auth_gssapi_ok(&kip));
        assert!(iprop_rpcsec_ok(&kip));
        assert!(!iprop_rpcsec_ok(&admin));
        assert!(!iprop_rpcsec_ok(&one));
    }

    #[test]
    fn iprop_fullresync_deny_is_fullresync_result() {
        let (store, _acl, _actor) = setup();
        let limited = Acl::parse("admin@KERBER.TEST *\nuser@KERBER.TEST i\n").expect("acl");
        let denied = dispatch_iprop(&store, &limited, "user@KERBER.TEST", IPROP_FULL_RESYNC, &[]);
        let want = encode_fullresync_status(0, krb5_kdc::IPROP_PERM_DENIED);
        assert_eq!(denied, want);
        let incr = encode_incr_result(krb5_kdc::IPROP_PERM_DENIED, 0, &[], None);
        assert_ne!(denied, incr);
        let ok = dispatch_iprop(
            &store,
            &limited,
            "admin@KERBER.TEST",
            IPROP_FULL_RESYNC,
            &[],
        );
        assert_eq!(ok, encode_fullresync(store.read().unwrap().serial()));
    }

    #[test]
    fn iprop_kdbe_round_trips_string_attrs_history_policy_lockout() {
        let (store, acl, actor) = setup();
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["g4user"]);
        {
            let mut g = store.write().unwrap();
            let mut pol = krb5_kdc::NamedPolicy::new("g4apol");
            pol.history = 2;
            g.put_policy(pol);
            g.create_password(&acl, &actor, &name, b"g4-secret")
                .unwrap();
            g.set_principal_policy(&name, Some("g4apol".into()))
                .unwrap();
            g.set_password(&name, b"g4-rotated").unwrap();
            g.set_string(&name, "note", Some("hello-g4a")).unwrap();
        }
        let mut p = {
            let g = store.read().unwrap();
            g.get_name(&name).unwrap().clone()
        };
        assert!(!p.key_history.is_empty());
        assert_eq!(p.string_attrs, vec![("note".into(), "hello-g4a".into())]);
        p.last_success = 111;
        p.last_failed = 222;
        p.fail_auth_count = 3;
        p.tl_data.retain(|t| t.ty != TL_LAST_PWD_CHANGE);
        p.tl_data.push(TlData {
            ty: TL_LAST_PWD_CHANGE,
            contents: 1_234u32.to_le_bytes().to_vec(),
        });
        let mut w = XdrW::default();
        encode_kdbe(&mut w, &p, None);
        let mut r = XdrR::new(&w.b);
        let got = decode_kdbe(&mut r, None, &p.id()).unwrap().unwrap();
        assert_eq!(got.string_attrs, p.string_attrs);
        assert_eq!(got.key_history.len(), p.key_history.len());
        assert_eq!(got.keys[0].key.as_bytes(), p.keys[0].key.as_bytes());
        assert_eq!(got.pw_policy.as_deref(), Some("g4apol"));
        assert_eq!(got.last_success, 111);
        assert_eq!(got.last_failed, 222);
        assert_eq!(got.fail_auth_count, 3);
        assert_eq!(tl_u32(&got.tl_data, TL_LAST_PWD_CHANGE), Some(1_234));
        assert!(
            !got.string_attrs.is_empty(),
            "incremental kdbe must carry string_attrs"
        );
    }

    #[test]
    fn iprop_decode_caps_hostile_wire_counts() {
        let mut princ = XdrW::default();
        princ.u32(1);
        princ.u32(AT_PRINC);
        princ.opaque(b"KERBER.TEST");
        princ.u32(u32::MAX);
        let mut r = XdrR::new(&princ.b);
        assert!(
            decode_kdbe(&mut r, None, "hostile@KERBER.TEST").is_err(),
            "huge principal-component count must not pre-alloc"
        );
        let mut keys = XdrW::default();
        keys.u32(1);
        keys.u32(AT_KEYDATA);
        keys.u32(1);
        keys.u32(2);
        keys.u32(1);
        keys.u32(u32::MAX);
        let mut r = XdrR::new(&keys.b);
        assert!(
            decode_kdbe(&mut r, None, "hostile@KERBER.TEST").is_err(),
            "huge keydata slot count must not pre-alloc"
        );
    }

    #[test]
    fn iprop_kdbe_omits_internal_kerber_tl() {
        let (store, _, _) = setup();
        let mut p = {
            let g = store.read().unwrap();
            g.krbtgt().unwrap().clone()
        };
        p.tl_data.push(TlData {
            ty: krb5_kdc::TL_KERBER_SID,
            contents: vec![1, 2, 3, 4],
        });
        p.tl_data.push(TlData {
            ty: krb5_kdc::TL_KERBER_SERIAL,
            contents: 9u32.to_be_bytes().to_vec(),
        });
        let mut w = XdrW::default();
        encode_kdbe(&mut w, &p, None);
        assert!(
            !w.b.windows(4).any(|w| w == 0x4B01u32.to_be_bytes()),
            "incremental kdbe must not emit TL_KERBER_SID"
        );
        assert!(
            !w.b.windows(4).any(|w| w == 0x4B03u32.to_be_bytes()),
            "incremental kdbe must not emit TL_KERBER_SERIAL"
        );
        let mut r = XdrR::new(&w.b);
        let got = decode_kdbe(&mut r, None, &p.id()).unwrap().unwrap();
        assert!(
            !got.tl_data
                .iter()
                .any(|t| t.ty == krb5_kdc::TL_KERBER_SID || t.ty == krb5_kdc::TL_KERBER_SERIAL)
        );
    }
}
