//! MIT's `AUTH_GSSAPI` client.

use std::net::TcpStream;
use std::time::Duration;

use krb5_gss::{ChannelBindings, GSS_C_AF_INET, GssContext};

use super::client_conn::AdminTicket;
use super::codes::{
    AUTH_BADCRED, AUTH_FAILED, AUTH_GSSAPI_CREDS_VERS, AUTH_GSSAPI_DESTROY, AUTH_GSSAPI_INIT,
    AUTH_INVALIDRESP, AUTH_REJECTEDVERF, FLAVOR_AUTH_GSSAPI, GSS_S_COMPLETE,
};
use super::iprop::{ReplyStat, RpcFailure, exchange};
use super::rpc::{RpcCallId, rpc_call_bytes, sockaddr_in_addr};
use super::xdr::{XdrR, XdrW};
use crate::Error;

pub(super) struct AgssClient {
    stream: TcpStream,
    prog: (u32, u32),
    ctx: GssContext,
    handle: Vec<u8>,
    xid: u32,
    seq: u32,
}

type Attempt = Result<(GssContext, Vec<u8>, u32), u32>;

fn fail(what: &str) -> Error {
    Error::Inner(format!("auth_gssapi: {what}"))
}

// MIT: `xdr_authgssapi_creds` (lib/rpc/auth_gssapi_misc.c:57-66)
// MIT: `marshall_new_creds` (lib/rpc/auth_gssapi.c:492-532)
fn creds(auth_msg: bool, handle: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(AUTH_GSSAPI_CREDS_VERS);
    w.u32(u32::from(auth_msg));
    w.opaque(handle);
    w.b
}

fn bindings_of(stream: &TcpStream) -> Result<ChannelBindings, Error> {
    let (local, remote) = stream
        .local_addr()
        .ok()
        .zip(stream.peer_addr().ok())
        .ok_or_else(|| fail("no socket addresses"))?;
    Ok(ChannelBindings {
        initiator_addrtype: GSS_C_AF_INET,
        initiator_address: sockaddr_in_addr(&local).to_vec(),
        acceptor_addrtype: GSS_C_AF_INET,
        acceptor_address: sockaddr_in_addr(&remote).to_vec(),
        application_data: Vec::new(),
    })
}

impl AgssClient {
    // MIT: `auth_gssapi_create` (lib/rpc/auth_gssapi.c:127-463)
    pub(super) fn establish(
        mut stream: TcpStream,
        prog: (u32, u32),
        t: &AdminTicket,
    ) -> Result<Self, Error> {
        stream
            .set_read_timeout(Some(Duration::from_hours(1)))
            .map_err(|e| Error::Inner(e.to_string()))?;
        let mut version = 4;
        loop {
            let bindings = if version >= 3 {
                Some(bindings_of(&stream)?)
            } else {
                None
            };
            match Self::attempt(&mut stream, prog, t, version, bindings.as_ref())? {
                Err(v) => version = v,
                Ok((ctx, handle, seq)) => {
                    return Ok(Self {
                        stream,
                        prog,
                        ctx,
                        handle,
                        xid: 2,
                        seq,
                    });
                }
            }
        }
    }

    fn attempt(
        stream: &mut TcpStream,
        prog: (u32, u32),
        t: &AdminTicket,
        version: u32,
        bindings: Option<&ChannelBindings>,
    ) -> Result<Attempt, Error> {
        let (mut ctx, token) = GssContext::init_sec_context(
            t.ticket.clone(),
            &t.session,
            &t.crealm,
            &t.cname,
            krb5_gss::GSS_C_MUTUAL | krb5_gss::GSS_C_REPLAY,
            bindings,
            None,
            None,
            0,
            &t.times,
        )
        .map_err(|e| Error::Inner(e.to_string()))?;
        let mut arg = XdrW::default();
        arg.u32(version);
        arg.opaque(&token);
        let id = RpcCallId {
            xid: 1,
            prog: prog.0,
            vers: prog.1,
            proc: AUTH_GSSAPI_INIT,
        };
        let rec = rpc_call_bytes(
            id,
            FLAVOR_AUTH_GSSAPI,
            &creds(true, &[]),
            FLAVOR_AUTH_GSSAPI,
            &[],
            &arg.b,
        );
        let sent = exchange(stream, 1, &rec).map_err(|f| fail(&f.sperror("call")))?;
        let (reply, results) = match sent {
            (reply, ReplyStat::Success { results, .. }) => (reply, results),
            (_, ReplyStat::Failed(RpcFailure::AuthError(AUTH_BADCRED | AUTH_FAILED)))
                if version >= 1 =>
            {
                return Ok(Err(version - 1));
            }
            (_, ReplyStat::Failed(f)) => return Err(fail(&f.sperror("call"))),
        };
        let mut r = XdrR::new(reply.get(results..).unwrap_or_default());
        let res_version = r.u32()?;
        let handle = r.opaque()?;
        let major = r.u32()?;
        let _minor = r.u32()?;
        let server_token = r.opaque()?;
        let signed_isn = r.opaque()?;
        if res_version != version && !(version == 2 && res_version == 1) {
            if version > 2 && res_version == 1 {
                return Ok(Err(1));
            }
            return Err(fail("invalid call_res version"));
        }
        if major != GSS_S_COMPLETE {
            return Err(fail("error in response from server"));
        }
        if handle.is_empty() || server_token.is_empty() || signed_isn.is_empty() {
            return Err(fail("incomplete response from server"));
        }
        ctx.process_ap_rep(&server_token, &t.session)
            .map_err(|e| fail(&e.to_string()))?;
        let isn = ctx.unwrap(&signed_isn).map_err(|e| fail(&e.to_string()))?;
        let isn = <[u8; 4]>::try_from(isn.as_slice()).map_err(|_| fail("bad isn"))?;
        Ok(Ok((ctx, handle, u32::from_be_bytes(isn))))
    }

    // MIT: `auth_gssapi_marshall` (lib/rpc/auth_gssapi.c:569-611)
    // MIT: `auth_gssapi_validate` (lib/rpc/auth_gssapi.c:620-656)
    // MIT: `auth_gssapi_refresh` (lib/rpc/auth_gssapi.c:677-690)
    pub(super) fn call(&mut self, proc: u32, args: &[u8]) -> Result<Vec<u8>, RpcFailure> {
        let mut refreshes = 2;
        loop {
            let xid = self.xid;
            self.xid = self.xid.wrapping_add(1);
            let rec = self
                .record((xid, proc), false, args)
                .ok_or(RpcFailure::CantEncodeArgs)?;
            match exchange(&mut self.stream, xid, &rec)? {
                (reply, ReplyStat::Success { verf, results }) => {
                    self.validate(&verf)?;
                    let sealed = reply.get(results..).unwrap_or_default();
                    return self.unwrap_results(sealed).ok_or(RpcFailure::CantDecodeRes);
                }
                (_, ReplyStat::Failed(RpcFailure::AuthError(AUTH_REJECTEDVERF)))
                    if refreshes > 0 =>
                {
                    refreshes -= 1;
                    self.seq = self.seq.wrapping_add(1);
                }
                (_, ReplyStat::Failed(f)) => return Err(f),
            }
        }
    }

    // MIT: `auth_gssapi_seal_seq` (lib/rpc/auth_gssapi_misc.c:92-114)
    // MIT: `auth_gssapi_wrap_data` (lib/rpc/auth_gssapi_misc.c:196-262)
    fn record(&mut self, (xid, proc): (u32, u32), auth_msg: bool, args: &[u8]) -> Option<Vec<u8>> {
        let sent = self.seq.wrapping_add(1).to_be_bytes();
        let verf = self.ctx.wrap_integ(&sent).ok()?;
        let mut inner = Vec::with_capacity(4 + args.len());
        inner.extend_from_slice(&sent);
        inner.extend_from_slice(args);
        let mut body = XdrW::default();
        body.opaque(&self.ctx.wrap_with_rrc(&inner, 0).ok()?);
        let id = RpcCallId {
            xid,
            prog: self.prog.0,
            vers: self.prog.1,
            proc,
        };
        Some(rpc_call_bytes(
            id,
            FLAVOR_AUTH_GSSAPI,
            &creds(auth_msg, &self.handle),
            FLAVOR_AUTH_GSSAPI,
            &verf,
            &body.b,
        ))
    }

    // MIT: `auth_gssapi_unseal_seq` (lib/rpc/auth_gssapi_misc.c:116-144)
    fn validate(&mut self, verf: &[u8]) -> Result<(), RpcFailure> {
        let bad = RpcFailure::AuthError(AUTH_INVALIDRESP);
        let plain = self.ctx.unwrap(verf).map_err(|_| bad.clone())?;
        let got = <[u8; 4]>::try_from(plain.as_slice()).map_err(|_| bad.clone())?;
        let expected = self.seq.wrapping_add(2);
        if u32::from_be_bytes(got) != expected {
            return Err(bad);
        }
        self.seq = expected;
        Ok(())
    }

    // MIT: `auth_gssapi_unwrap_data` (lib/rpc/auth_gssapi_misc.c:264-339)
    fn unwrap_results(&mut self, sealed: &[u8]) -> Option<Vec<u8>> {
        let wrapped = XdrR::new(sealed).opaque().ok()?;
        let plain = self.ctx.unwrap(&wrapped).ok()?;
        let (got, results) = plain.split_first_chunk::<4>()?;
        (u32::from_be_bytes(*got) == self.seq).then(|| results.to_vec())
    }
}

impl Drop for AgssClient {
    // MIT: `auth_gssapi_destroy` (lib/rpc/auth_gssapi.c:703-750)
    fn drop(&mut self) {
        let xid = self.xid;
        let _ = self.stream.set_read_timeout(Some(Duration::from_secs(1)));
        if let Some(rec) = self.record((xid, AUTH_GSSAPI_DESTROY), true, &[]) {
            let _ = exchange(&mut self.stream, xid, &rec);
        }
    }
}
