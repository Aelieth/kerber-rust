//! TCP/UDP listeners for kadmind (749), kpasswd (464), and kprop (754).
//! The ticket must be for `kadmin/changepw`.

use std::io::{self, Read};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use krb5_asn1::{decode, encode};
use krb5_crypto::ProtocolKey;
use krb5_kdc::{Principal, SharedDump as SharedStore};
use krb5_protocol::{
    AUTH_CONTEXT_DO_SEQUENCE, AcceptorAuthContext, AcceptorConfig, ApVerifyOk, ApVerifyParams,
    KeytabLookup, ReplayCache, local_host_address, verify_ap_req_ex,
};
use krb5_types::{
    ChangePasswdData, HostAddress, KerberosTime, KrbError, Microseconds, PrincipalName, err,
    principal_compare,
};
use zeroize::{Zeroize, Zeroizing};

use crate::kadmind::{Kadmind, serve_kadmind_until};
use crate::kprop::is_app_tag;
use crate::{AdminSession, Error, Op};

/// Ports from the Kerberos assigned set.
pub const KADMIND_PORT: u16 = 749;
/// RFC 3244.
pub const KPASSWD_PORT: u16 = 464;
/// kprop.
pub const KPROP_PORT: u16 = 754;

const WIRE_VERSION: u8 = 1;

// MIT: `client_addr` (kadmin/server/server_stubs.c:152-162)
/// `k5_print_addr` of the peer, without the port.
#[must_use]
pub fn client_addr(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
        std::net::IpAddr::V4(v4) => v4.to_string(),
    }
}

/// UDP kpasswd: send `body` to `dest` and accept only that peer's reply.
pub fn kpasswd_udp_exchange_to(dest: SocketAddr, body: &[u8]) -> io::Result<Vec<u8>> {
    let bind = if dest.ip().is_loopback() {
        "127.0.0.1:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind)?;
    let backoffs = [
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_secs(2),
    ];
    let mut last = io::Error::new(io::ErrorKind::TimedOut, "kpasswd udp timeout");
    for bo in backoffs {
        sock.set_read_timeout(Some(bo))?;
        if let Err(e) = sock.send_to(body, dest) {
            last = e;
            continue;
        }
        match kpasswd_udp_recv_until(&sock, dest, Instant::now() + bo) {
            Ok(v) => return Ok(v),
            Err(e)
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock =>
            {
                last = e;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

fn kpasswd_udp_recv_until(
    sock: &UdpSocket,
    dest: SocketAddr,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    loop {
        let mut buf = vec![0u8; 65_535];
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if src.ip() != dest.ip() || src.port() != dest.port() {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "kpasswd udp timeout",
                        ));
                    }
                    continue;
                }
                buf.truncate(n);
                return Ok(buf);
            }
            Err(e)
                if e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                if Instant::now() >= deadline {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }
}

fn status_bytes(status: u32) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(status.to_be_bytes().to_vec())
}

/// Version-1 kadmind body: `version, op, ap_len, ap-req, pay_len, payload`. The reply is wiped when dropped: a ktadd's holds the keytab, in one buffer of its size.
/// (or `name\0password`). The create, cpw, delete, and ktadd ops (1-4; there is no dump op: MIT kadmind serves none) also return their [`AdminSession`] call's [`Error::AclDenied`], [`Error::NotFound`], [`Error::PasswordPolicy`], [`Error::PassTooSoon`], or [`Error::Inner`].
pub fn dispatch_kadmind(
    store: &SharedStore,
    acl: &krb5_kdc::Acl,
    service_key: &ProtocolKey,
    replay: &ReplayCache,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if body.len() < 10 || body[0] != WIRE_VERSION {
        return Err(Error::Inner("kadmind version".into()));
    }
    let op = match body[1] {
        1 => Op::Create,
        2 => Op::Delete,
        3 => Op::Ktadd,
        4 => Op::Cpw,
        _ => return Err(Error::Inner("kadmind op".into())),
    };
    let ap_len = u32::from_be_bytes(
        body[2..6]
            .try_into()
            .map_err(|_| Error::Inner("kadmind truncated".into()))?,
    ) as usize;
    if 6 + ap_len + 4 > body.len() {
        return Err(Error::Inner("kadmind truncated".into()));
    }
    let ap_req = &body[6..6 + ap_len];
    let pay_off = 6 + ap_len;
    let pay_len = u32::from_be_bytes(
        body[pay_off..pay_off + 4]
            .try_into()
            .map_err(|_| Error::Inner("kadmind payload".into()))?,
    ) as usize;
    if pay_off + 4 + pay_len > body.len() {
        return Err(Error::Inner("kadmind payload".into()));
    }
    let payload = &body[pay_off + 4..pay_off + 4 + pay_len];

    let mut g = store
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut sess = AdminSession::from_ap_req(&mut g, acl, service_key, ap_req, replay)?;
    match op {
        Op::Create => {
            let (name, password) = split_name_pass(payload)?;
            sess.create_password(&name, password)?;
            Ok(status_bytes(0))
        }
        Op::Cpw => {
            let (name, password) = split_name_pass(payload)?;
            sess.change_password(&name, password)?;
            Ok(status_bytes(0))
        }
        Op::Delete => {
            let name = PrincipalName::try_new(
                PrincipalName::NT_PRINCIPAL,
                [std::str::from_utf8(payload).unwrap_or("")],
            )
            .map_err(|e| Error::Inner(e.to_string()))?;
            sess.delete(&name)?;
            Ok(status_bytes(0))
        }
        Op::Ktadd => {
            let name = PrincipalName::try_new(
                PrincipalName::NT_PRINCIPAL,
                [std::str::from_utf8(payload).unwrap_or("")],
            )
            .map_err(|e| Error::Inner(e.to_string()))?;
            let kt = sess.ktadd(&name)?;
            let keytab = Zeroizing::new(kt.to_bytes());
            let mut out = Zeroizing::new(Vec::with_capacity(4 + keytab.len()));
            out.extend_from_slice(&status_bytes(0));
            out.extend_from_slice(&keytab);
            Ok(out)
        }
    }
}

fn split_name_pass(payload: &[u8]) -> Result<(PrincipalName, &[u8]), Error> {
    let z = payload
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error::Inner("name\\0password".into()))?;
    let name_s = std::str::from_utf8(&payload[..z]).map_err(|e| Error::Inner(e.to_string()))?;
    let (name, _realm) =
        krb5_types::principal_from_unparsed(name_s, "").map_err(|e| Error::Inner(e.to_string()))?;
    Ok((name, &payload[z + 1..]))
}

#[must_use]
pub fn encode_kadmind_req(op: Op, ap_req: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = vec![WIRE_VERSION, op as u8];
    v.extend_from_slice(&(u32::try_from(ap_req.len()).unwrap_or(0)).to_be_bytes());
    v.extend_from_slice(ap_req);
    v.extend_from_slice(&(u32::try_from(payload.len()).unwrap_or(0)).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn frame_kpasswd_rep(ap_rep: &[u8], priv_der: &[u8]) -> Vec<u8> {
    let total = 6usize
        .saturating_add(ap_rep.len())
        .saturating_add(priv_der.len());
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(u16::try_from(total).unwrap_or(0)).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(u16::try_from(ap_rep.len()).unwrap_or(0)).to_be_bytes());
    out.extend_from_slice(ap_rep);
    out.extend_from_slice(priv_der);
    out
}

fn changepw_krb_error(realm: &str, code: i32, e_data: Option<Vec<u8>>) -> Result<Vec<u8>, Error> {
    let realm_s = krb5_types::try_ascii(realm).map_err(|e| Error::Inner(e.to_string()))?;
    let sname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin", "changepw"]);
    let pdu = KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: code,
        crealm: None,
        cname: None,
        realm: realm_s,
        sname,
        e_text: None,
        e_data: e_data.map(Into::into),
    };
    encode(&pdu).map_err(|e| Error::Inner(e.to_string()))
}

fn kpasswd_chpwfail_error(realm: &str, result: u16, text: &str) -> Result<Vec<u8>, Error> {
    let mut e_data = Vec::from(result.to_be_bytes());
    e_data.extend_from_slice(text.as_bytes());
    kpasswd_krb_error(realm, e_data)
}

fn kpasswd_krb_error(realm: &str, e_data: Vec<u8>) -> Result<Vec<u8>, Error> {
    // MIT: `process_chpw_request` (schpw.c:273-345)
    // alloc_data overwrites `ret` with 0, so `error -= ERROR_TABLE_BASE_krb5` wraps past KRB_ERR_MAX → 60.
    let der = changepw_krb_error(realm, err::GENERIC, Some(e_data))?;
    Ok(frame_kpasswd_rep(&[], &der))
}

/// The reply to a kpasswd TCP request whose length is past the buffer: `KRB_ERR_FIELD_TOOLONG` from `kadmin/changepw`, not framed as a kpasswd reply.
// MIT: `make_toolong_error` (kadmin/server/misc.c:139-161)
/// the time, `KRB_ERR_FIELD_TOOLONG` and `kadmin/changepw` in the realm, with no client, text or data.
pub(crate) fn kpasswd_toolong_error(realm: &str) -> Result<Vec<u8>, Error> {
    changepw_krb_error(realm, err::FIELD_TOOLONG, None)
}

struct KpasswdReply {
    ac: AcceptorAuthContext,
    ap_rep: Vec<u8>,
    local: HostAddress,
}

impl KpasswdReply {
    fn result(&mut self, realm: &str, result: &[u8]) -> Result<Vec<u8>, Error> {
        let made = self
            .ac
            .mk_priv(result, &self.local, None)
            .and_then(|p| Ok(encode(&p)?));
        match made {
            Ok(priv_der) => Ok(frame_kpasswd_rep(&self.ap_rep, &priv_der)),
            Err(_) => kpasswd_krb_error(realm, result.to_vec()),
        }
    }
}

/// RFC 3244 / MIT changepw request: `len, version, ap-req-len, AP-REQ, KRB-PRIV`.
/// Version 1 (MIT `kpasswd`) carries the raw password in KRB-PRIV. Version `0xff80` (setpw) carries `ChangePasswdData`. KRB-PRIV is encrypted with the authenticator subkey when present (MIT always sends one).
/// built. A bad AP-REQ, KRB-PRIV, ACL, or password change is an `Ok` framed result code.
pub fn handle_kpasswd_rfc3244(
    store: &SharedStore,
    acl: &krb5_kdc::Acl,
    conf: &AcceptorConfig,
    replay: &ReplayCache,
    raw: &[u8],
) -> Result<Vec<u8>, Error> {
    let loopback = std::net::IpAddr::from([127, 0, 0, 1]);
    handle_kpasswd_from(store, acl, conf, replay, raw, "127.0.0.1", Some(loopback))
}

const RFC3244_VERSION: u16 = 0xff80;
const UNK_PRINC_PRIV: &str =
    "Password not changed.\nPrincipal does not exist while trying to change password.\n";
const DECODE_FAIL: &str = "Failed decoding ChangePasswdData";

/// What `process_chpw_request` holds once the AP-REQ is accepted: the request as verified, the auth context it leaves and the AP-REP that answers it.
pub struct ChangepwAccepted {
    /// The verified AP-REQ (the ticket's server is `kadmin/changepw`, as the KDB keytab names it).
    pub ok: ApVerifyOk,
    /// The context after it: `DO_SEQUENCE` only, no address set.
    pub ac: AcceptorAuthContext,
    /// The AP-REP, DER.
    pub ap_rep: Vec<u8>,
}

/// Which of `process_chpw_request`'s two AUTHERROR answers a refused AP-REQ gets.
#[derive(Debug)]
pub enum ChangepwRefused {
    Read(krb5_protocol::Error),
    Reply(krb5_protocol::Error),
}

/// The AP-REQ half of kpasswd's request: MIT's `krb5_rd_req` for `kadmin/changepw` in the realm, on kadmind's acceptor profile values `conf`, its key looked up in the KDB as the KDB keytab does, then the AP-REP.
/// `krb5_rd_req` names `kadmin/changepw` against the `KDB:` keytab, and a refusal is AUTHERROR "Failed reading application request".
// MIT: `krb5_ktkdb_get_entry` (lib/kdb/keytab.c:117-185)
/// the KDB keytab gives the principal's first permitted key at the ticket's kvno and refuses another enctype.
// MIT: `rd_req_decoded_opt` (lib/krb5/krb/rd_req_dec.c:631-631)
/// the authenticator's time is checked against kadmind's context's `clockskew`.
/// [`ChangepwRefused`], with the error that refused the request.
pub fn changepw_accept(
    ap_req: &[u8],
    changepw: Option<&Principal>,
    realm: &str,
    conf: &AcceptorConfig,
    replay: &ReplayCache,
) -> Result<ChangepwAccepted, ChangepwRefused> {
    let permitted = conf.permitted().map_err(ChangepwRefused::Read)?;
    let server = krb5_kdc::principals::kadmin_changepw();
    let get_entry = |_: &PrincipalName, _: &str, kvno: u32, etype: i32| {
        krb5_kdc::ktkdb_get_entry(changepw, &server, realm, kvno, etype, |e| {
            permitted.contains(&e)
        })
        .map(|entry| entry.key.clone())
        .map_err(KeytabLookup::from)
    };
    let params = ApVerifyParams {
        keys: &[],
        key_kvnos: None,
        key_principals: None,
        kvno: None,
        expected_server: Some(&server),
        expected_realm: Some(realm),
        get_entry: Some(&get_entry),
        skew: i64::from(conf.clockskew),
        ignore_acceptor_hostname: conf.ignore_acceptor_hostname,
        capaths: &conf.capaths,
        remote_addr: None,
        now: None,
    };
    let ok = verify_ap_req_ex(ap_req, &params, replay, None).map_err(ChangepwRefused::Read)?;
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, conf).map_err(ChangepwRefused::Read)?;
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    let ap_rep = ac
        .mk_rep()
        .and_then(|r| Ok(encode(&r)?))
        .map_err(ChangepwRefused::Reply)?;
    Ok(ChangepwAccepted { ok, ac, ap_rep })
}

// MIT: `_kadm5_chpass_principal_util` (lib/kadm5/chpass_util.c:195-200)
/// too short names the policy minimum.
/// a too-short code with no policy uses the code text and Password not changed.
fn kpasswd_quality_reply(msg: &str, empty_policy: &EmptyPolicy) -> String {
    if let Some(n) = quality_count(msg, "min_length ") {
        return too_short_text(n);
    }
    if let Some(n) = quality_count(msg, "min_classes ") {
        return too_few_classes_text(n);
    }
    if msg == krb5_kdc::PWQUAL_DICT || msg == krb5_kdc::PWQUAL_PRINC {
        return DICT_REPLY.to_owned();
    }
    if msg == "history" {
        return REUSE_REPLY.to_owned();
    }
    if msg == krb5_kdc::PWQUAL_EMPTY {
        return match empty_policy {
            EmptyPolicy::MinLength(n) => too_short_text(*n),
            EmptyPolicy::Missing => MISSING_POLICY_EMPTY.to_owned(),
            EmptyPolicy::Unbound => EMPTY_NO_POLICY.to_owned(),
        };
    }
    msg.to_owned()
}

fn quality_count(msg: &str, prefix: &str) -> Option<u32> {
    msg.strip_prefix(prefix)?.parse().ok()
}

fn too_short_text(n: u32) -> String {
    format!(
        "New password is too short.\nPlease choose a password which is at least {n} characters long."
    )
}

fn too_few_classes_text(n: u32) -> String {
    format!(
        "New password does not have enough character classes.\n\
The character classes are:\n\
\t- lower-case letters,\n\
\t- upper-case letters,\n\
\t- digits,\n\
\t- punctuation, and\n\
\t- all other characters (e.g., control characters).\n\
Please choose a password with at least {n} character classes."
    )
}

const DICT_REPLY: &str = "New password was found in a dictionary of possible passwords and\n\
therefore may be easily guessed. Please choose another password.\n\
See the kpasswd man page for help in choosing a good password.";

const REUSE_REPLY: &str = "New password was used previously. Please choose a different password.";

const EMPTY_NO_POLICY: &str = "Password is too short\n\nPassword not changed.";

const MISSING_POLICY_EMPTY: &str = "Policy does not exist while getting policy info.\n\
Password is too short while trying to change password.\n\
\n\
Password not changed.\n ";

/// How an empty-password refusal relates to the principal's named policy.
enum EmptyPolicy {
    /// No policy name. The reply is the code text plus `Password not changed.`
    Unbound,
    MinLength(u32),
    Missing,
}

// MIT: `kadm5_get_principal` (lib/kadm5/srv/svr_principal.c:759-759)
/// the lookup clears that message, so the notice is the code's table text.
// MIT: `empty_check` (lib/kadm5/srv/pwqual_empty.c:41-43)
/// an empty password sets Empty passwords are not allowed with the too-short code, so the notice reads the table text.
// MIT: `KADM5_PASS_Q_TOOSHORT` (lib/kadm5/kadm_err.et:29-29)
/// the table text is Password is too short.
// MIT: `passwd_check` (lib/kadm5/srv/server_misc.c:122-129)
/// the Error line is written before the clear and keeps the module's sentence.
// MIT: `princ_check` (lib/kadm5/srv/pwqual_princ.c:52-55)
/// a component match sets Password may not match principal name for that code.
fn kpasswd_quality_log(msg: &str) -> String {
    if msg == krb5_kdc::PWQUAL_PRINC {
        return msg.to_owned();
    }
    crate::kadm5::chpass_error_text(&Error::PasswordPolicy(msg.to_owned()))
}

// MIT: `get_policy` (lib/kadm5/srv/svr_principal.c:112-117)
/// a missing policy is not a failed change. It only changes the too-short reply.
fn empty_policy(store: &krb5_kdc::PrincipalStore, name: &PrincipalName) -> EmptyPolicy {
    let Some(pol_name) = store
        .get_name(name)
        .and_then(|p| p.pw_policy.as_ref())
        .filter(|s| !s.is_empty())
    else {
        return EmptyPolicy::Unbound;
    };
    match store.policies().get(pol_name) {
        Some(pol) => EmptyPolicy::MinLength(pol.min_length),
        None => EmptyPolicy::Missing,
    }
}

fn too_soon_text(until: u32) -> String {
    let when = krb5_types::KerberosTime::from_unix_seconds(until)
        .0
        .format("%a %b %e %H:%M:%S %Y")
        .to_string();
    format!(
        "Password cannot be changed because it was changed too recently.\n\
Please wait until {when} before you change it.\n\
If you need to change your password before then, contact your system\n\
security administrator."
    )
}

// MIT: `trunc_name` (kadmin/server/misc.c:124-131)
/// at most `MAXPRINCLEN` (125) bytes of a name, and `...` after them when it is longer.
fn kpasswd_trunc_len(len: usize) -> (usize, &'static str) {
    if len > 125 { (125, "...") } else { (len, "") }
}

fn first_bytes(s: &str, n: usize) -> &str {
    let mut end = n.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The line `process_chpw_request` logs once a change is made or refused.
/// `trunc_name` cuts the client to 125 bytes in both lines; a set-password line also cuts the target, and prints at that length the CLIENT's name (`targetp = clientstr`) in the `for` slot, not the target's.
fn kpasswd_log_line(setpw: bool, from: &str, client: &str, target: &str, text: &str) -> String {
    let (clen, cdots) = kpasswd_trunc_len(client.len());
    let by = first_bytes(client, clen);
    if setpw {
        let (tlen, tdots) = kpasswd_trunc_len(target.len());
        let slot = first_bytes(client, tlen);
        format!("setpw request from {from} by {by}{cdots} for {slot}{tdots}: {text}")
    } else {
        format!("chpw request from {from} for {by}{cdots}: {text}")
    }
}

/// That mismatch returns an error and no datagram is sent. The AP-REQ is verified only as a ticket for `kadmin/changepw` in this realm; any failure, a ticket for another service included, is answered with a framed KRB-ERROR (code 60) whose e-data carries result code 3.
pub(crate) fn handle_kpasswd_from(
    store: &SharedStore,
    acl: &krb5_kdc::Acl,
    conf: &AcceptorConfig,
    replay: &ReplayCache,
    raw: &[u8],
    from: &str,
    local: Option<std::net::IpAddr>,
) -> Result<Vec<u8>, Error> {
    if raw.len() < 4 {
        return Err(Error::Inner("Message stream modified".into()));
    }
    let plen = usize::from(u16::from_be_bytes([raw[0], raw[1]]));
    if plen != raw.len() {
        return Err(Error::Inner("Message stream modified".into()));
    }
    let ver = u16::from_be_bytes([raw[2], raw[3]]);
    if ver != 1 && ver != RFC3244_VERSION {
        return Err(Error::Inner(
            "Requested protocol version not supported".into(),
        ));
    }
    if raw.len() < 6 {
        return Err(Error::Inner("Message stream modified".into()));
    }
    let ap_len = usize::from(u16::from_be_bytes([raw[4], raw[5]]));
    if 6 + ap_len >= raw.len() {
        return Err(Error::Inner("Message stream modified".into()));
    }
    let ap_req = &raw[6..6 + ap_len];
    // Stricter than MIT, which answers these with a KRB-ERROR: a kpasswd reply or error is not answered, so a spoofed datagram cannot set two servers answering each other (CVE-2002-2443).
    if ap_len == 0 || is_app_tag(ap_req, 15) || is_app_tag(ap_req, 30) {
        return Err(Error::Inner("Invalid message type".into()));
    }
    let priv_raw = &raw[6 + ap_len..];
    let (store_realm, changepw) = {
        // that does not read leaves the KDB keytab without it, so the AP-REQ is refused.
        let (g, read) = krb5_kdc::read_fresh(store);
        (
            g.realm().to_owned(),
            read.ok().and_then(|()| {
                g.get_name(&krb5_kdc::principals::kadmin_changepw())
                    .cloned()
            }),
        )
    };
    // the auth context does sequence numbers only, `krb5_rd_req` names `kadmin/changepw` against the KDB keytab and also refuses an enctype the server (on kadmind's KDC profile) does not permit, and the AP-REP is made before the request is decrypted.
    let accepted = match changepw_accept(ap_req, changepw.as_ref(), &store_realm, conf, replay) {
        Ok(a) => a,
        Err(ChangepwRefused::Read(_)) => {
            return kpasswd_chpwfail_error(&store_realm, 3, "Failed reading application request");
        }
        Err(ChangepwRefused::Reply(_)) => {
            return kpasswd_chpwfail_error(
                &store_realm,
                3,
                "Failed replying to application request",
            );
        }
    };
    let ChangepwAccepted { ok, ac, ap_rep } = accepted;
    let mut reply = KpasswdReply {
        ac,
        ap_rep,
        local: local_host_address(local),
    };
    let Ok(user_data) = reply.ac.rd_priv(priv_raw) else {
        let mut body = Vec::from(2u16.to_be_bytes());
        body.extend_from_slice(b"Failed decrypting request");
        return reply.result(&store_realm, &body);
    };
    let ticket_crealm = String::from_utf8_lossy(ok.ticket_part.crealm.as_bytes()).into_owned();
    let (targ, targ_realm, newpass) = if ver == RFC3244_VERSION {
        let decoded = decode::<ChangePasswdData>(&user_data);
        wipe_secret(user_data);
        if let Ok(cpw) = decoded {
            // MIT: `decode_krb5_setpw_req` (lib/krb5/asn.1/asn1_k_encode.c:1253-1276)
            // the target is required, so a request that names none, or a target that does not decode, is MALFORMED; it never changes the caller's own password.
            let name = cpw.targname;
            let realm = String::from_utf8_lossy(cpw.targrealm.as_bytes()).into_owned();
            let newpass = cpw.newpasswd.to_vec();
            wipe_octets(cpw.newpasswd);
            (name, realm, newpass)
        } else {
            let mut body = Vec::with_capacity(2 + DECODE_FAIL.len());
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(DECODE_FAIL.as_bytes());
            return reply.result(&store_realm, &body);
        }
    } else {
        (
            ok.ticket_part.cname.clone(),
            ticket_crealm.clone(),
            user_data,
        )
    };
    let client = ok.ticket_part.cname.unparse_with_realm(&ticket_crealm);
    let target_unparsed = targ.unparse_with_realm(&targ_realm);
    // MIT: `schpw_util_wrapper` (misc.c:33-54)
    // compare first, INITIAL, auth(OP_CPW), then DB.
    let self_change = principal_compare(&targ, &targ_realm, &ok.ticket_part.cname, &ticket_crealm);
    let (code, text, log_err) = if self_change && !ok.ticket_part.flags.initial() {
        (
            7u16,
            "Ticket must be derived from a password".to_owned(),
            "Operation requires initial ticket".to_owned(),
        )
    } else if !self_change
        && acl
            .check(
                &client,
                krb5_kdc::AdminOp::ChangePassword,
                Some(&target_unparsed),
            )
            .is_err()
    {
        (
            5u16,
            "Unauthorized request".to_owned(),
            "Operation requires ``change-password'' privilege".to_owned(),
        )
    } else if targ_realm != store_realm {
        (
            2u16,
            UNK_PRINC_PRIV.to_owned(),
            "Principal does not exist".to_owned(),
        )
    } else {
        let mut g = store
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // of the database to its write, as `AdminSession::change_password` makes it.
        // the changepw dispatcher uses the global handle, so `current_caller` is `kadmind@REALM`, not the ticket client.
        let stamp = format!("kadmind@{store_realm}");
        // MIT: `ctx_lock` (plugins/kdb/db2/kdb_db2.c:438-447)
        // the change locks the database first, and a database the server may not write changes nothing.
        let changed = (|| -> Result<(), krb5_kdc::Error> {
            g.reload_if_stale()?;
            // Stricter than MIT, whose kpasswd path has no lockdown test: the target's keys are refused as the kadm5 chpass stub refuses them.
            // MIT: `chpass_principal_2_svc` (kadmin/server/server_stubs.c:855-861)
            // KADM5_PROTECT_KEYS is answered as KADM5_AUTH_CHANGEPW.
            if g.get_in_realm(&targ, &targ_realm)
                .is_some_and(|p| p.attributes & krb5_kdc::KDB_LOCKDOWN_KEYS != 0)
            {
                return Err(krb5_kdc::Error::AclDenied);
            }
            if self_change {
                g.check_min_life_in(&targ, &targ_realm)?;
            }
            g.change(|s| s.set_password_keepold_n_in(&targ, &targ_realm, &newpass, 0, &stamp))?
        })();
        match changed {
            Ok(()) => (0u16, String::new(), "success".to_owned()),
            Err(krb5_kdc::Error::PasswordPolicy(msg)) => {
                let empty = if msg == krb5_kdc::PWQUAL_EMPTY {
                    empty_policy(&g, &targ)
                } else {
                    EmptyPolicy::Unbound
                };
                (
                    4,
                    kpasswd_quality_reply(&msg, &empty),
                    kpasswd_quality_log(&msg),
                )
            }
            Err(krb5_kdc::Error::PassTooSoon { until }) => (
                4,
                too_soon_text(until),
                "Current password's minimum life has not expired".to_owned(),
            ),
            Err(krb5_kdc::Error::AclDenied) => (
                5,
                "Unauthorized request".to_owned(),
                "Operation requires ``change-password'' privilege".to_owned(),
            ),
            Err(krb5_kdc::Error::NotFound) => (
                2,
                UNK_PRINC_PRIV.to_owned(),
                "Principal does not exist".to_owned(),
            ),
            Err(e) => (
                2,
                format!(
                    "Password not changed.\n{} while trying to change password.\n",
                    crate::kadm5::chpass_store_error_text(&e)
                ),
                e.to_string(),
            ),
        }
    };
    // both copies of the new password are zapped once the change is made or refused.
    wipe_secret(newpass);
    let log_outcome = if code == 0 { "ok" } else { "error" };
    let log_line = kpasswd_log_line(
        ver == RFC3244_VERSION,
        from,
        &client,
        &target_unparsed,
        &log_err,
    );
    tracing::info!(
        event = krb5_log::events::ADMIN,
        component = "krb5-admin",
        outcome = log_outcome,
        code,
        client = client.as_str(),
        "{log_line}"
    );
    krb5_log::klog::syslog(krb5_log::klog::Severity::Notice, &log_line);
    let mut body = Vec::with_capacity(2 + text.len());
    body.extend_from_slice(&code.to_be_bytes());
    body.extend_from_slice(text.as_bytes());
    reply.result(&store_realm, &body)
}

/// Zeroizes every byte of `buf`'s allocation, then frees it: a new password a kpasswd request carried, or the request plaintext holding one. A test build keeps each wiped allocation ([`wiped::take`]) instead of freeing it, so a test can see it zeroed, whole.
fn wipe_secret(mut buf: Vec<u8>) {
    buf.resize(buf.capacity(), 0);
    buf.as_mut_slice().zeroize();
    #[cfg(test)]
    let _ = wiped::WIPED.try_with(|w| w.borrow_mut().push(buf));
}

/// Wipes an octet string's bytes when it holds the only reference to them, as a field decoded from a request does.
fn wipe_octets(octets: krb5_types::OctetString) {
    if let Ok(buf) = bytes::Bytes::from(octets).try_into_mut() {
        wipe_secret(Vec::<u8>::from(buf));
    }
}

/// The allocations this module's wipes zeroed on the current thread, kept for the tests.
#[cfg(test)]
mod wiped {
    use std::cell::RefCell;

    thread_local! {
        /// What [`super::wipe_secret`] zeroed on this thread, kept alive.
        pub(super) static WIPED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    /// The allocations wiped on this thread since the last call.
    pub(super) fn take() -> Vec<Vec<u8>> {
        WIPED.with(|w| std::mem::take(&mut *w.borrow_mut()))
    }
}

/// Parse a kpasswd reply (`len,ver,AP-REP-len,AP-REP,KRB-PRIV`).
pub fn parse_kpasswd_rep(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if raw.len() < 6 {
        return Err(Error::Inner("kpasswd truncated".into()));
    }
    let ap_len = usize::from(u16::from_be_bytes([raw[4], raw[5]]));
    if ap_len == 0 {
        return Err(Error::Inner("kpasswd framed error".into()));
    }
    if 6 + ap_len > raw.len() {
        return Err(Error::Inner("kpasswd AP-REP".into()));
    }
    Ok((raw[6..6 + ap_len].to_vec(), raw[6 + ap_len..].to_vec()))
}

#[must_use]
pub fn encode_kpasswd_req(ap_req: &[u8], krb_priv_der: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&1u16.to_be_bytes());
    inner.extend_from_slice(&(u16::try_from(ap_req.len()).unwrap_or(0)).to_be_bytes());
    inner.extend_from_slice(ap_req);
    inner.extend_from_slice(krb_priv_der);
    let mut out = Vec::new();
    out.extend_from_slice(&(u16::try_from(inner.len() + 2).unwrap_or(0)).to_be_bytes());
    out.extend_from_slice(&inner);
    out
}

const STOP_POLL: Duration = Duration::from_millis(100);

#[allow(clippy::needless_pass_by_value)]
pub fn serve_kpasswd_udp(
    store: SharedStore,
    acl: krb5_kdc::Acl,
    service_key: ProtocolKey,
    conf: AcceptorConfig,
    sock: UdpSocket,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut kadmind = Kadmind::from_parts(store, acl, Some(service_key), conf);
    let udp = [sock];
    let sockets = krb5_kdc::net_server::Sockets {
        udp: &udp,
        ..krb5_kdc::net_server::Sockets::default()
    };
    serve_kadmind_until(&mut kadmind, &sockets, &shutdown, STOP_POLL)
}

#[allow(clippy::needless_pass_by_value)]
pub fn serve_kpasswd_tcp(
    store: SharedStore,
    acl: krb5_kdc::Acl,
    service_key: ProtocolKey,
    conf: AcceptorConfig,
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut kadmind = Kadmind::from_parts(store, acl, Some(service_key), conf);
    let tcp = [listener];
    let sockets = krb5_kdc::net_server::Sockets {
        tcp: &tcp,
        ..krb5_kdc::net_server::Sockets::default()
    };
    serve_kadmind_until(&mut kadmind, &sockets, &shutdown, STOP_POLL)
}

/// kprop dump over TCP: send MIT dump version-7 text (4-byte length prefix).
/// The body is `kdb5_util load_dump version 7`, not a KDB3 blob. MIT-wire sendauth lives in `crate::kprop`.
/// (string-to-key or key wrap under `master_password`), or the `io::Error` of a failed write or flush on `stream`.
pub fn kprop_send(
    store: &krb5_kdc::PrincipalStore,
    master_password: &[u8],
    stream: &mut TcpStream,
) -> io::Result<()> {
    let blob = crate::kprop::kprop_dump_bytes(store, master_password)
        .map_err(|e| io::Error::other(e.to_string()))?;
    krb5_protocol::write_messages(stream, &[blob.as_slice()])
}

/// Receive a length-prefixed dump v7 body and load it.
/// the master key from `master_password`.
pub fn kprop_recv(
    stream: &mut TcpStream,
    master_password: &[u8],
) -> Result<krb5_kdc::PrincipalStore, Error> {
    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .map_err(|e| Error::Inner(e.to_string()))?;
    let n = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(0);
    let mut blob = vec![0u8; n];
    stream
        .read_exact(&mut blob)
        .map_err(|e| Error::Inner(e.to_string()))?;
    crate::kprop::kprop_load_bytes(&blob, master_password)
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    use krb5_config::listen::ListenAddr;
    use krb5_kdc::principals::kadmin_changepw;
    use krb5_kdc::testrealm::bootstrap_documented;
    use krb5_protocol::AcceptorConfig;

    use super::{encode_kpasswd_req, serve_kpasswd_udp, wiped};

    fn exchange(sock: &UdpSocket, to: Option<SocketAddr>) -> Option<(Vec<u8>, SocketAddr)> {
        let req = encode_kpasswd_req(&[0, 1, 2, 3], b"x");
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        match to {
            Some(a) => sock.send_to(&req, a).unwrap(),
            None => sock.send(&req).unwrap(),
        };
        let mut buf = vec![0u8; 4096];
        let (n, src) = sock.recv_from(&mut buf).ok()?;
        buf.truncate(n);
        Some((buf, src))
    }

    #[test]
    fn a_kpasswd_reply_leaves_from_the_address_the_request_was_sent_to() {
        // MIT: `send_to_from` (lib/apputils/udppktinfo.c:443-474)
        // kpasswd's reply on a wildcard socket leaves from the request's destination.
        let (store, acl) = bootstrap_documented().unwrap();
        let key = store
            .get_name(&kadmin_changepw())
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let any = ListenAddr {
            host: Some("0.0.0.0".into()),
            port: 0,
        };
        let sock = krb5_kdc::bind_udp_listeners(&[any])
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let to = SocketAddr::from(([127, 0, 0, 2], sock.local_addr().unwrap().port()));
        let stop = Arc::new(AtomicBool::new(false));
        let (shared, flag) = (krb5_kdc::shared_dump(store), Arc::clone(&stop));
        let server = thread::spawn(move || {
            serve_kpasswd_udp(shared, acl, key, AcceptorConfig::default(), sock, flag)
        });
        let plain = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (rep, src) = exchange(&plain, Some(to)).expect("a reply");
        assert_eq!(src, to, "the reply's source");
        assert!(rep.len() > 6 && rep[4..6] == [0, 0], "a framed KRB-ERROR");
        let connected = UdpSocket::bind("127.0.0.1:0").unwrap();
        connected.connect(to).unwrap();
        assert!(
            exchange(&connected, None).is_some(),
            "the connected client's reply"
        );
        stop.store(true, Ordering::Relaxed);
        server.join().unwrap().unwrap();
    }

    /// the decrypted request, the new password decoded from it and the copy the change is made with are each zapped.
    #[test]
    fn kpasswd_zeroes_every_copy_of_the_new_password() {
        use krb5_asn1::encode;
        use krb5_kdc::testrealm::{TEST_REALM, TEST_USER};
        use krb5_protocol::{
            ReplayCache, as_req_sname, build_ap_req, build_krb_priv_with_seq, pa_enc_timestamp,
        };
        use krb5_types::{ChangePasswdData, PrincipalName, ascii};

        krb5_config::isolate_test_krb5();
        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let key_of = |name: &PrincipalName| {
            store
                .get_name(name)
                .unwrap()
                .best_key()
                .unwrap()
                .key
                .clone()
        };
        let user_key = key_of(&user);
        let as_req = as_req_sname(
            user.clone(),
            TEST_REALM,
            61,
            Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
            kadmin_changepw(),
            vec![user_key.etype().to_iana()],
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
        let ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let password = b"scratch-wiped-pass-1";
        let cpw = ChangePasswdData {
            newpasswd: password.to_vec().into(),
            targname: user.clone(),
            targrealm: ascii(TEST_REALM),
        };
        let cpw_der = encode(&cpw).unwrap();
        let priv_msg = build_krb_priv_with_seq(&as_out.session_key, &cpw_der, None).unwrap();
        let (ap_der, priv_der) = (encode(&ap).unwrap(), encode(&priv_msg).unwrap());
        let mut req = Vec::new();
        req.extend_from_slice(
            &u16::try_from(6 + ap_der.len() + priv_der.len())
                .unwrap()
                .to_be_bytes(),
        );
        req.extend_from_slice(&0xff80u16.to_be_bytes());
        req.extend_from_slice(&u16::try_from(ap_der.len()).unwrap().to_be_bytes());
        req.extend_from_slice(&ap_der);
        req.extend_from_slice(&priv_der);
        let shared = krb5_kdc::shared_dump(store);
        wiped::take();
        let rep = super::handle_kpasswd_rfc3244(
            &shared,
            &acl,
            &AcceptorConfig::default(),
            &ReplayCache::new(),
            &req,
        )
        .unwrap();
        let zeroed = wiped::take();
        assert!(
            u16::from_be_bytes([rep[4], rep[5]]) > 0,
            "an AP-REP: the request was read"
        );
        assert_eq!(
            zeroed.len(),
            3,
            "the decrypted ChangePasswdData, its decoded new password, and the copy changed to"
        );
        assert!(zeroed.iter().all(|w| w.iter().all(|b| *b == 0)));
        assert!(zeroed[0].len() >= cpw_der.len());
        assert!(zeroed[1].len() >= password.len() && zeroed[2].len() >= password.len());
    }

    #[test]
    fn kpasswd_quality_reply_is_the_chpass_util_paragraph() {
        let short = super::kpasswd_quality_reply("min_length 8", &super::EmptyPolicy::Unbound);
        assert_eq!(
            short,
            "New password is too short.\nPlease choose a password which is at least 8 characters long."
        );
        let classes = super::kpasswd_quality_reply("min_classes 3", &super::EmptyPolicy::Unbound);
        assert!(classes.starts_with(
            "New password does not have enough character classes.\nThe character classes are:\n\t- lower-case letters,\n"
        ));
        assert!(classes.contains("\t- punctuation, and\n"));
        assert!(classes.ends_with("Please choose a password with at least 3 character classes."));
        let dict = "New password was found in a dictionary of possible passwords and\ntherefore may be easily guessed. Please choose another password.\nSee the kpasswd man page for help in choosing a good password.";
        assert_eq!(
            super::kpasswd_quality_reply(krb5_kdc::PWQUAL_DICT, &super::EmptyPolicy::Unbound),
            dict
        );
        assert_eq!(
            super::kpasswd_quality_reply(krb5_kdc::PWQUAL_PRINC, &super::EmptyPolicy::Unbound),
            dict
        );
        assert_eq!(
            super::kpasswd_quality_reply("history", &super::EmptyPolicy::Unbound),
            "New password was used previously. Please choose a different password."
        );
        assert_eq!(
            super::kpasswd_quality_reply(krb5_kdc::PWQUAL_EMPTY, &super::EmptyPolicy::Unbound),
            "Password is too short\n\nPassword not changed."
        );
        assert_eq!(
            super::kpasswd_quality_reply(krb5_kdc::PWQUAL_EMPTY, &super::EmptyPolicy::Missing),
            "Policy does not exist while getting policy info.\nPassword is too short while trying to change password.\n\nPassword not changed.\n "
        );
        assert_eq!(
            super::kpasswd_quality_reply(krb5_kdc::PWQUAL_EMPTY, &super::EmptyPolicy::MinLength(0)),
            "New password is too short.\nPlease choose a password which is at least 0 characters long."
        );
    }

    /// The notice of a refused change is what `krb5_get_error_message` finds on the handle's context once `_kadm5_chpass_principal_util` has run: the code's table text, unless a module gave a dictionary code its own sentence.
    #[test]
    fn kpasswd_quality_log_is_the_text_left_on_the_context() {
        assert_eq!(
            super::kpasswd_quality_log(krb5_kdc::PWQUAL_EMPTY),
            "Password is too short"
        );
        assert_eq!(
            super::kpasswd_quality_log(krb5_kdc::PWQUAL_EMPTY),
            super::kpasswd_quality_log("min_length 8"),
            "the empty module's refusal and the policy floor are the same code"
        );
        assert_eq!(
            super::kpasswd_quality_log(krb5_kdc::PWQUAL_PRINC),
            "Password may not match principal name"
        );
        // MIT: `check_against_policy` (lib/kadm5/srv/server_misc.c:82-101)
        // the floors return their codes with no sentence.
        assert_eq!(
            super::kpasswd_quality_log("min_length 8"),
            "Password is too short"
        );
        assert_eq!(
            super::kpasswd_quality_log("min_classes 3"),
            "Password does not contain enough character classes"
        );
        // MIT: `check_pw_reuse` (lib/kadm5/srv/svr_principal.c:959-959)
        // reuse returns its code with no sentence.
        assert_eq!(
            super::kpasswd_quality_log("history"),
            "Cannot reuse password"
        );
        // MIT: `dict_check` (lib/kadm5/srv/pwqual_dict.c:228-231)
        // a dictionary hit returns its code with no sentence.
        assert_eq!(
            super::kpasswd_quality_log(krb5_kdc::PWQUAL_DICT),
            "Password is in the password dictionary"
        );
    }

    #[test]
    fn a_missing_named_policy_is_not_a_failed_change() {
        let (mut store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
        let name = krb5_types::PrincipalName::new(
            krb5_types::PrincipalName::NT_PRINCIPAL,
            [krb5_kdc::testrealm::TEST_USER],
        );
        assert!(matches!(
            super::empty_policy(&store, &name),
            super::EmptyPolicy::Unbound
        ));
        store
            .apply_admin_fields_in(
                &name,
                krb5_kdc::testrealm::TEST_REALM,
                krb5_kdc::AdminFields {
                    policy: Some("gone".into()),
                    pw_expire: Some(0),
                    ..krb5_kdc::AdminFields::default()
                },
                "kadmind@KERBER.TEST",
            )
            .unwrap();
        assert!(matches!(
            super::empty_policy(&store, &name),
            super::EmptyPolicy::Missing
        ));
        store
            .put_policy(krb5_kdc::NamedPolicy::new("keep"))
            .unwrap();
        store
            .apply_admin_fields_in(
                &name,
                krb5_kdc::testrealm::TEST_REALM,
                krb5_kdc::AdminFields {
                    policy: Some("keep".into()),
                    pw_expire: Some(0),
                    ..krb5_kdc::AdminFields::default()
                },
                "kadmind@KERBER.TEST",
            )
            .unwrap();
        assert!(matches!(
            super::empty_policy(&store, &name),
            super::EmptyPolicy::MinLength(0)
        ));
    }

    /// in a set-password line the `for` slot prints the CLIENT's name (`targetp = clientstr`), cut to the length of the target's.
    #[test]
    fn a_setpw_log_line_names_the_client_cut_to_the_targets_length() {
        let line = super::kpasswd_log_line(
            true,
            "10.0.0.9",
            "ra4user@KERBER.TEST",
            "u\u{df}r@KERBER.TEST",
            "denied",
        );
        assert_eq!(
            line,
            "setpw request from 10.0.0.9 by ra4user@KERBER.TEST for ra4user@KERBER.T: denied"
        );
        let line = super::kpasswd_log_line(true, "h", "u@R", "longer@REALM", "ok");
        assert_eq!(line, "setpw request from h by u@R for u@R: ok");
    }

    /// the client is cut so in both log lines, and the target in a set-password line.
    #[test]
    fn a_name_past_125_bytes_is_cut_with_dots_in_both_log_lines() {
        let client = format!("{}@R", "c".repeat(130));
        let target = format!("{}@R", "t".repeat(126));
        let cut = "c".repeat(125);
        assert_eq!(
            super::kpasswd_log_line(false, "h", &client, "", "success"),
            format!("chpw request from h for {cut}...: success")
        );
        assert_eq!(
            super::kpasswd_log_line(true, "h", &client, &target, "success"),
            format!("setpw request from h by {cut}... for {cut}...: success")
        );
        let exact = format!("{}@R", "c".repeat(123));
        assert_eq!(exact.len(), 125);
        assert_eq!(
            super::kpasswd_log_line(false, "h", &exact, "", "success"),
            format!("chpw request from h for {exact}: success")
        );
    }

    #[test]
    fn a_kpasswd_request_too_short_to_hold_an_ap_req_length_is_message_stream_modified() {
        use krb5_protocol::ReplayCache;

        let (store, acl) = bootstrap_documented().unwrap();
        let shared = krb5_kdc::shared_dump(store);
        for frame in [&[0u8, 3, 0][..], &[0, 4, 0, 1], &[0, 5, 0, 1, 0]] {
            let got = super::handle_kpasswd_rfc3244(
                &shared,
                &acl,
                &AcceptorConfig::default(),
                &ReplayCache::new(),
                frame,
            )
            .unwrap_err()
            .to_string();
            assert_eq!(got, "Message stream modified", "{frame:?}");
        }
    }
}
