//! MIT's `kadm5` client: the connection, RPCSEC_GSS and the calls it makes.

use std::net::{TcpStream, ToSocketAddrs as _};

use krb5_crypto::ProtocolKey;
use krb5_protocol::TicketTimes;
use krb5_types::{PrincipalName, Realm, Ticket};

use super::client_xdr::{
    self as cx, Reply, decode_generic, decode_get_policies, decode_get_policy,
    decode_get_principal, decode_get_principals, decode_get_privs, decode_get_strings,
};
use super::codes::{
    API_V2, API_V3, API_V4, GET_POLICY, GET_POLS, GET_PRINCIPAL, GET_PRINCS, GET_PRIVS,
    GET_STRINGS, INIT, KADM_PROG, KADM_VERS, KADM5_NEW_SERVER_API_VERSION, KADM5_RPC_ERROR,
};
use super::iprop::IpropClient;
use super::{KADM5_CANT_RESOLVE, KADM5_GSS_ERROR};
use crate::Error;

pub(crate) use cx::{PolicyView, PrincView};

pub(crate) struct AdminTicket {
    pub(crate) ticket: Ticket,
    pub(crate) session: ProtocolKey,
    pub(crate) crealm: Realm,
    pub(crate) cname: PrincipalName,
    pub(crate) times: TicketTimes,
}

pub(crate) type Code = u32;

pub(crate) struct Kadm5Client {
    rpc: IpropClient,
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

impl Kadm5Client {
    // MIT: `init_any` (lib/kadm5/clnt/client_init.c:290-345)
    pub(crate) fn open(host: &str, port: u16, t: &AdminTicket) -> Result<Self, Code> {
        let stream = connect(host, port)?;
        let rpc = IpropClient::establish_for(
            stream,
            (KADM_PROG, KADM_VERS),
            t.ticket.clone(),
            &t.session,
            &t.crealm,
            &t.cname,
            &t.times,
        )
        .map_err(|_: Error| KADM5_GSS_ERROR)?;
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
        self.rpc.call(proc, args).map_err(|_| KADM5_RPC_ERROR)
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
}
