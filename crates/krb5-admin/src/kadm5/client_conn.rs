//! MIT's `kadm5` client: the connection, RPCSEC_GSS and the calls it makes.

use std::net::{TcpStream, ToSocketAddrs as _};

use krb5_crypto::ProtocolKey;
use krb5_protocol::TicketTimes;
use krb5_types::{PrincipalName, Realm, Ticket};

use super::client_agss::AgssClient;
use super::client_xdr::{
    self as cx, Reply, decode_chrand, decode_extract_keys, decode_generic, decode_get_policies,
    decode_get_policy, decode_get_principal, decode_get_principals, decode_get_privs,
    decode_get_strings,
};
use super::codes::{
    API_V2, API_V3, API_V4, CHPASS_PRINCIPAL, CHPASS_PRINCIPAL3, CHRAND_PRINCIPAL,
    CHRAND_PRINCIPAL3, CREATE_ALIAS, CREATE_POLICY, CREATE_PRINCIPAL, CREATE_PRINCIPAL3,
    DELETE_POLICY, DELETE_PRINCIPAL, EXTRACT_KEYS, FLAVOR_NONE, GET_POLICY, GET_POLS,
    GET_PRINCIPAL, GET_PRINCS, GET_PRIVS, GET_STRINGS, INIT, KADM_PROG, KADM_VERS,
    KADM5_NEW_SERVER_API_VERSION, KADM5_POLICY, KADM5_POLICY_ALLOWED_KEYSALTS, KADM5_RPC_ERROR,
    MODIFY_POLICY, MODIFY_PRINCIPAL, PURGEKEYS, RENAME_PRINCIPAL, SET_STRING,
};
use super::iprop::{IpropClient, ReplyStat, RpcFailure, exchange};
use super::rpc::{RpcCallId, rpc_call_bytes};
use super::{KADM5_CANT_RESOLVE, KADM5_GSS_ERROR};
use crate::{Error, PolicyArgs};

pub(crate) use cx::{ExtractedKey, KeyBlock, PolicyView, PrincView, TlView};

pub(crate) struct AdminTicket {
    pub(crate) ticket: Ticket,
    pub(crate) session: ProtocolKey,
    pub(crate) crealm: Realm,
    pub(crate) cname: PrincipalName,
    pub(crate) times: TicketTimes,
}

pub(crate) type Code = u32;

#[derive(Clone, Copy, Default)]
pub(crate) struct AuthFlavours {
    pub(crate) old_auth_gssapi: bool,
    pub(crate) no_fallback: bool,
}

enum Rpc {
    Gss(IpropClient),
    Agss(AgssClient),
    Bare(AuthNone),
}

/// `-O -N` leaves `clnttcp_create`'s `AUTH_NONE`.
struct AuthNone {
    stream: TcpStream,
    xid: u32,
}

impl AuthNone {
    fn call(&mut self, proc: u32, args: &[u8]) -> Result<Vec<u8>, RpcFailure> {
        let xid = self.xid;
        self.xid = self.xid.wrapping_add(1);
        let id = RpcCallId {
            xid,
            prog: KADM_PROG,
            vers: KADM_VERS,
            proc,
        };
        let rec = rpc_call_bytes(id, FLAVOR_NONE, &[], FLAVOR_NONE, &[], args);
        match exchange(&mut self.stream, xid, &rec)? {
            (reply, ReplyStat::Success { results, .. }) => {
                Ok(reply.get(results..).unwrap_or_default().to_vec())
            }
            (_, ReplyStat::Failed(f)) => Err(f),
        }
    }
}

pub(crate) struct Kadm5Client {
    rpc: Rpc,
    api: u32,
}

// MIT: `connect_to_server` (lib/kadm5/clnt/client_init.c:520-557)
fn connect(host: &str, port: u16) -> Result<TcpStream, Code> {
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|_| KADM5_CANT_RESOLVE)?;
    addrs
        .into_iter()
        .find_map(|a| TcpStream::connect(a).ok())
        .ok_or(KADM5_RPC_ERROR)
}

// MIT: `rpc_auth` (lib/kadm5/clnt/client_init.c:645-683)
fn rpc_auth(stream: TcpStream, t: &AdminTicket, flavours: AuthFlavours) -> Option<Rpc> {
    let prog = (KADM_PROG, KADM_VERS);
    if !flavours.old_auth_gssapi {
        let first = stream.try_clone().ok()?;
        let gss = IpropClient::establish_for(
            first,
            prog,
            t.ticket.clone(),
            &t.session,
            &t.crealm,
            &t.cname,
            &t.times,
        );
        if let Ok(c) = gss {
            return Some(Rpc::Gss(c));
        }
    }
    if flavours.no_fallback {
        return flavours
            .old_auth_gssapi
            .then_some(Rpc::Bare(AuthNone { stream, xid: 1 }));
    }
    AgssClient::establish(stream, prog, t).ok().map(Rpc::Agss)
}

impl Drop for Kadm5Client {
    // MIT: `free_handle` (lib/kadm5/clnt/client_init.c:141-169)
    fn drop(&mut self) {
        if let Rpc::Gss(c) = &mut self.rpc {
            c.destroy();
        }
    }
}

impl Kadm5Client {
    // MIT: `init_any` (lib/kadm5/clnt/client_init.c:290-345)
    pub(crate) fn open(
        host: &str,
        port: u16,
        t: &AdminTicket,
        flavours: AuthFlavours,
    ) -> Result<Self, Code> {
        let stream = connect(host, port)?;
        let rpc = rpc_auth(stream, t, flavours).ok_or(KADM5_GSS_ERROR)?;
        let mut client = Self { rpc, api: API_V4 };
        let mut code = client.init()?;
        for next in [API_V3, API_V2] {
            if code != KADM5_NEW_SERVER_API_VERSION {
                break;
            }
            client.api = next;
            code = client.init()?;
        }
        match code {
            0 => Ok(client),
            c => Err(c),
        }
    }

    fn init(&mut self) -> Result<Code, Code> {
        let reply = self.call(INIT, &cx::encode_init(self.api))?;
        Ok(decode_generic(&reply).map_err(|_| KADM5_RPC_ERROR)?.code)
    }

    fn call(&mut self, proc: u32, args: &[u8]) -> Result<Vec<u8>, Code> {
        let reply = match &mut self.rpc {
            Rpc::Gss(c) => c.call(proc, args),
            Rpc::Agss(c) => c.call(proc, args),
            Rpc::Bare(c) => c.call(proc, args),
        };
        reply.map_err(|_: RpcFailure| KADM5_RPC_ERROR)
    }

    fn run<T>(
        &mut self,
        proc: u32,
        args: &[u8],
        decode: impl FnOnce(&[u8]) -> Result<Reply<T>, Error>,
    ) -> Result<T, Code> {
        let raw = self.call(proc, args)?;
        let reply = decode(&raw).map_err(|_| KADM5_RPC_ERROR)?;
        match (reply.code, reply.body) {
            (0, Some(body)) => Ok(body),
            (0, None) => Err(KADM5_RPC_ERROR),
            (code, _) => Err(code),
        }
    }

    pub(crate) fn get_principal(&mut self, name: &str, mask: u32) -> Result<PrincView, Code> {
        let args = cx::encode_get_principal(self.api, name, mask);
        self.run(GET_PRINCIPAL, &args, decode_get_principal)
    }

    pub(crate) fn get_principals(&mut self, glob: Option<&str>) -> Result<Vec<String>, Code> {
        let args = cx::encode_get_principals(self.api, glob);
        self.run(GET_PRINCS, &args, decode_get_principals)
    }

    pub(crate) fn get_policy(&mut self, name: &str) -> Result<PolicyView, Code> {
        let (args, api) = (cx::encode_get_policy(self.api, name), self.api);
        self.run(GET_POLICY, &args, |b| decode_get_policy(b, api))
    }

    pub(crate) fn get_policies(&mut self, glob: Option<&str>) -> Result<Vec<String>, Code> {
        let args = cx::encode_get_policies(self.api, glob);
        self.run(GET_POLS, &args, decode_get_policies)
    }

    pub(crate) fn get_strings(&mut self, name: &str) -> Result<Vec<(String, String)>, Code> {
        let args = cx::encode_get_strings(self.api, name);
        self.run(GET_STRINGS, &args, decode_get_strings)
    }

    pub(crate) fn get_privs(&mut self) -> Result<u32, Code> {
        let args = cx::encode_get_privs(self.api);
        self.run(GET_PRIVS, &args, decode_get_privs)
    }

    // MIT: `kadm5_create_principal` (lib/kadm5/clnt/client_principal.c:25-60)
    // MIT: `kadm5_create_principal_3` (lib/kadm5/clnt/client_principal.c:63-102)
    pub(crate) fn create_principal(
        &mut self,
        rec: &PrincView,
        mask: u32,
        ks: &[(i32, i32)],
        pass: Option<&[u8]>,
    ) -> Result<(), Code> {
        if ks.is_empty() {
            let args = cx::encode_create_principal(self.api, rec, mask, pass);
            self.run(CREATE_PRINCIPAL, &args, decode_generic)
        } else {
            let args = cx::encode_create_principal3(self.api, rec, mask, ks, pass);
            self.run(CREATE_PRINCIPAL3, &args, decode_generic)
        }
    }

    pub(crate) fn delete_principal(&mut self, name: &str) -> Result<(), Code> {
        let args = cx::encode_delete_principal(self.api, name);
        self.run(DELETE_PRINCIPAL, &args, decode_generic)
    }

    pub(crate) fn modify_principal(&mut self, rec: &PrincView, mask: u32) -> Result<(), Code> {
        let args = cx::encode_modify_principal(self.api, rec, mask);
        self.run(MODIFY_PRINCIPAL, &args, decode_generic)
    }

    pub(crate) fn rename_principal(&mut self, src: &str, dest: &str) -> Result<(), Code> {
        let args = cx::encode_rename_principal(self.api, src, dest);
        self.run(RENAME_PRINCIPAL, &args, decode_generic)
    }

    pub(crate) fn create_alias(&mut self, alias: &str, target: &str) -> Result<(), Code> {
        let args = cx::encode_create_alias(self.api, alias, target);
        self.run(CREATE_ALIAS, &args, decode_generic)
    }

    pub(crate) fn chpass(
        &mut self,
        name: &str,
        pass: &[u8],
        keepold: bool,
        ks: &[(i32, i32)],
    ) -> Result<(), Code> {
        if keepold || !ks.is_empty() {
            let args = cx::encode_chpass3(self.api, name, keepold, ks, pass);
            self.run(CHPASS_PRINCIPAL3, &args, decode_generic)
        } else {
            let args = cx::encode_chpass(self.api, name, pass);
            self.run(CHPASS_PRINCIPAL, &args, decode_generic)
        }
    }

    // MIT: `randkey_princ` (kadmin/cli/kadmin.c:257-274)
    pub(crate) fn randkey(
        &mut self,
        name: &str,
        keepold: bool,
        ks: &[(i32, i32)],
    ) -> Result<Vec<KeyBlock>, Code> {
        let args = cx::encode_chrand3(self.api, name, keepold, ks);
        match self.run(CHRAND_PRINCIPAL3, &args, decode_chrand) {
            Err(KADM5_RPC_ERROR) if !keepold && ks.is_empty() => {
                let args = cx::encode_chrand(self.api, name);
                self.run(CHRAND_PRINCIPAL, &args, decode_chrand)
            }
            other => other,
        }
    }

    pub(crate) fn extract_keys(&mut self, name: &str) -> Result<Vec<ExtractedKey>, Code> {
        let args = cx::encode_extract_keys(self.api, name, 0);
        self.run(EXTRACT_KEYS, &args, decode_extract_keys)
    }

    pub(crate) fn purge_keys(&mut self, name: &str, keepkvno: i32) -> Result<(), Code> {
        let args = cx::encode_purgekeys(self.api, name, keepkvno);
        self.run(PURGEKEYS, &args, decode_generic)
    }

    pub(crate) fn set_string(
        &mut self,
        name: &str,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), Code> {
        let args = cx::encode_set_string(self.api, name, key, value);
        self.run(SET_STRING, &args, decode_generic)
    }

    // MIT: `kadm5_create_policy` (lib/kadm5/clnt/clnt_policy.c:17-35)
    pub(crate) fn create_policy(&mut self, a: &PolicyArgs, clear: bool) -> Result<(), Code> {
        let (rec, mask) = policy_rec(a, clear);
        let args = cx::encode_create_policy(self.api, &rec, mask | KADM5_POLICY);
        self.run(CREATE_POLICY, &args, decode_generic)
    }

    pub(crate) fn modify_policy(&mut self, a: &PolicyArgs, clear: bool) -> Result<(), Code> {
        let (rec, mask) = policy_rec(a, clear);
        let args = cx::encode_modify_policy(self.api, &rec, mask);
        self.run(MODIFY_POLICY, &args, decode_generic)
    }

    pub(crate) fn delete_policy(&mut self, name: &str) -> Result<(), Code> {
        let args = cx::encode_delete_policy(self.api, name);
        self.run(DELETE_POLICY, &args, decode_generic)
    }
}

fn policy_rec(a: &PolicyArgs, clear: bool) -> (PolicyView, u32) {
    let mut mask = super::policy::build_policy(a).1;
    if clear {
        mask |= KADM5_POLICY_ALLOWED_KEYSALTS;
    }
    let rec = PolicyView {
        name: a.name.clone(),
        pw_min_life: a.pw_min_life.unwrap_or(0),
        pw_max_life: a.pw_max_life.unwrap_or(0),
        pw_min_length: a.min_length.unwrap_or(0),
        pw_min_classes: a.min_classes.unwrap_or(0),
        pw_history_num: a.history.unwrap_or(0),
        pw_max_fail: a.max_fail.unwrap_or(0),
        pw_failcnt_interval: a.pw_failcnt_interval.unwrap_or(0),
        pw_lockout_duration: a.pw_lockout_duration.unwrap_or(0),
        allowed_keysalts: a.allowed_keysalts.clone(),
        ..PolicyView::default()
    };
    (rec, mask)
}
