//! MIT kadm5 GSS-RPC (ONC RPC program 2112, version 2) on TCP 749.
//!
//! Enough of RFC 2203 RPCSEC_GSS + KADM5_API_VERSION_2/3 for MIT 1.22.2
//! `kadmin` to `addprinc` and `cpw`. This is not a full C ABI clone.

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
const CHPASS_PRINCIPAL: u32 = 6;
const GET_PRIVS: u32 = 12;
const INIT: u32 = 13;
const CREATE_PRINCIPAL3: u32 = 18;
const CHPASS_PRINCIPAL3: u32 = 19;

/// OpenVision/MIT `KADM5_API_VERSION_2`.
const API_V2: u32 = 0x1234_5702;
const KADM5_PRIVS: u32 = 0x0000_000F;

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

#[allow(clippy::too_many_arguments)]
fn handle_rpc(
    store: &SharedStore,
    acl: &Acl,
    service_keys: &[ProtocolKey],
    expected_server: &PrincipalName,
    expected_realm: &str,
    handle: &[u8],
    gss: &mut Option<GssContext>,
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
    if cred_flavor != FLAVOR_GSS {
        // ONC RPC ping (AUTH_NONE / AUTH_UNIX NULLPROC) before RPCSEC_GSS.
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
        5 => Ok(generic_ret(API_V2, 437_875_715)), // KADM5_UNK_PRINC
        CREATE_PRINCIPAL | CREATE_PRINCIPAL3 => {
            let (name, pass) = parse_create(args, proc == CREATE_PRINCIPAL3)?;
            let mut g = store
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut sess = AdminSession::local(&mut g, acl, actor);
            match sess.create_password(&name, pass.as_bytes()) {
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
        _ => Ok(generic_ret(API_V2, 7)),
    }
}

fn kadm5_code(e: &Error) -> u32 {
    match e {
        Error::AclDenied => 1,
        Error::NotFound => 2,
        Error::Inner(_) => 7,
    }
}

fn generic_ret(api: u32, code: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(api);
    w.u32(code);
    w.b
}

fn parse_create(args: &[u8], v3: bool) -> Result<(PrincipalName, String), Error> {
    let mut r = XdrR::new(args);
    let _api = r.u32()?;
    let princ = r.principal()?;
    skip_principal_ent_rest(&mut r)?;
    let _mask = r.u32()?;
    if v3 {
        r.skip_array_i32_pairs()?;
    }
    let pass = r.nullstring()?.unwrap_or_default();
    Ok((princ, pass))
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

/// After the leading principal, skip the rest of `kadm5_principal_ent_rec`.
fn skip_principal_ent_rest(r: &mut XdrR<'_>) -> Result<(), Error> {
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
    let _ = r.nullstring()?; // policy
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
    Ok(())
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
}
