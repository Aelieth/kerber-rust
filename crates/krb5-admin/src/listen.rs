//! TCP/UDP listeners for kadmind (749), kpasswd (464), and kprop (754).
//!
//! A kpasswd datagram whose length, version, or framing does not match
//! is not answered. A failed AP-REQ is a framed chpwfail with result 3.
//! The ticket must be for `kadmin/changepw`.

use std::io::{self, Read};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use krb5_asn1::{decode, encode};
use krb5_crypto::ProtocolKey;
use krb5_kdc::SharedDump as SharedStore;
use krb5_protocol::{
    AUTH_CONTEXT_DO_SEQUENCE, AcceptorAuthContext, ApVerifyParams, DEFAULT_SKEW, ReplayCache,
    local_host_address, permitted_enctypes_kdc, verify_ap_req_ex,
};
use krb5_types::{
    ChangePasswdData, HostAddress, KerberosTime, KrbError, Microseconds, PrincipalName, err,
    principal_compare,
};
use zeroize::Zeroize;

use crate::{AdminSession, Error, Op};

/// Ports from the Kerberos assigned set.
pub const KADMIND_PORT: u16 = 749;
/// RFC 3244.
pub const KPASSWD_PORT: u16 = 464;
/// kprop.
pub const KPROP_PORT: u16 = 754;

const WIRE_VERSION: u8 = 1;

/// A client's address as kadmind logs it; an IPv4 client of a dual-stack socket reads as IPv4.
/// MIT `client_addr` (`kadmin/server/server_stubs.c:152-162`): `k5_print_addr` of the peer,
/// without the port.
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
///
/// # Errors
///
/// The `io::Error` when binding the socket or setting its read timeout fails, or a receive
/// fails other than by timing out; after three sends (0.5 s, 1 s, 2 s waits) with no reply
/// from `dest`, the last send error or an `ErrorKind::TimedOut` (or `WouldBlock`) timeout.
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

/// One kpasswd reply over TCP, its length and the reply in one write.
/// MIT `process_stream_response` (`lib/apputils/net-server.c:1319-1323`): kadmind's kpasswd TCP
/// replies go out as the KDC's do, the length and the reply in one writev.
fn write_len_pref(stream: &mut TcpStream, body: &[u8]) -> io::Result<()> {
    krb5_protocol::write_messages(stream, &[body])
}

fn read_len_pref(stream: &mut TcpStream, max: usize) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr)?;
    let n = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(usize::MAX);
    if n == 0 || n > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "kadmind length"));
    }
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn status_bytes(status: u32) -> Vec<u8> {
    status.to_be_bytes().to_vec()
}

/// Version-1 kadmind body: `version, op, ap_len, ap-req, pay_len, payload`.
///
/// # Errors
///
/// [`Error::Inner`] when `body` is under 10 bytes, not version 1, an unknown op, or its AP-REQ
/// or payload overruns it; when the AP-REQ does not verify or the payload is not a usable name
/// (or `name\0password`). The create, cpw, delete, and ktadd ops (1-4; there is no dump op:
/// MIT kadmind serves none) also return their [`AdminSession`] call's [`Error::AclDenied`],
/// [`Error::NotFound`], [`Error::PasswordPolicy`], [`Error::PassTooSoon`], or [`Error::Inner`].
pub fn dispatch_kadmind(
    store: &SharedStore,
    acl: &krb5_kdc::Acl,
    service_key: &ProtocolKey,
    replay: &ReplayCache,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
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
            let mut out = status_bytes(0);
            out.extend_from_slice(&kt.to_bytes());
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

/// Build a version-1 kadmind request body.
#[must_use]
pub fn encode_kadmind_req(op: Op, ap_req: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = vec![WIRE_VERSION, op as u8];
    v.extend_from_slice(&(u32::try_from(ap_req.len()).unwrap_or(0)).to_be_bytes());
    v.extend_from_slice(ap_req);
    v.extend_from_slice(&(u32::try_from(payload.len()).unwrap_or(0)).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Frame a kpasswd reply: `len, version=1, AP-REP-len, AP-REP, KRB-PRIV`.
///
/// MIT `krb5int_rd_chpw_rep` treats AP-REP length 0 as a framed KRB-ERROR
/// and will not accept a successful result. Success replies must include
/// AP-REP; the following KRB-PRIV is encrypted in the authenticator subkey
/// (else the ticket session key).
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

fn kpasswd_chpwfail_error(realm: &str, result: u16, text: &str) -> Result<Vec<u8>, Error> {
    let mut e_data = Vec::from(result.to_be_bytes());
    e_data.extend_from_slice(text.as_bytes());
    kpasswd_krb_error(realm, e_data)
}

fn kpasswd_krb_error(realm: &str, e_data: Vec<u8>) -> Result<Vec<u8>, Error> {
    // MIT `process_chpw_request` (`schpw.c:273-345`): alloc_data overwrites `ret` with 0,
    // so `error -= ERROR_TABLE_BASE_krb5` wraps past KRB_ERR_MAX → 60.
    let realm_s = krb5_types::try_ascii(realm).map_err(|e| Error::Inner(e.to_string()))?;
    let sname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin", "changepw"]);
    let pdu = KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: err::GENERIC,
        crealm: None,
        cname: None,
        realm: realm_s,
        sname,
        e_text: None,
        e_data: Some(e_data.into()),
    };
    let der = encode(&pdu).map_err(|e| Error::Inner(e.to_string()))?;
    Ok(frame_kpasswd_rep(&[], &der))
}

/// The AP-REP and the auth context a kpasswd reply's KRB-PRIV is made in.
struct KpasswdReply {
    ac: AcceptorAuthContext,
    ap_rep: Vec<u8>,
    local: HostAddress,
}

impl KpasswdReply {
    /// MIT `process_chpw_request` (`schpw.c:286-311`): the result is a KRB-PRIV from the address the request came in on and to no address, behind the AP-REP; one that cannot be made leaves the result in a KRB-ERROR.
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
///
/// Version 1 (MIT `kpasswd`) carries the raw password in KRB-PRIV. Version
/// `0xff80` (setpw) carries `ChangePasswdData`. KRB-PRIV is encrypted with
/// the authenticator subkey when present (MIT always sends one).
///
/// # Errors
///
/// [`Error::Inner`] when `raw` is shorter than its header, its length field is not its size,
/// its version is neither 1 nor `0xff80`, or its AP-REQ leaves no KRB-PRIV (framing MIT drops
/// unanswered), or when the ticket's session key or subkey is unusable or the reply cannot be
/// built. A bad AP-REQ, KRB-PRIV, ACL, or password change is an `Ok` framed result code.
pub fn handle_kpasswd_rfc3244(
    store: &SharedStore,
    acl: &krb5_kdc::Acl,
    service_key: &ProtocolKey,
    replay: &ReplayCache,
    raw: &[u8],
) -> Result<Vec<u8>, Error> {
    let loopback = std::net::IpAddr::from([127, 0, 0, 1]);
    handle_kpasswd_from(
        store,
        acl,
        service_key,
        replay,
        raw,
        "127.0.0.1",
        Some(loopback),
    )
}

const RFC3244_VERSION: u16 = 0xff80;
const UNK_PRINC_PRIV: &str =
    "Password not changed.\nPrincipal does not exist while trying to change password.\n";
const DECODE_FAIL: &str = "Failed decoding ChangePasswdData";

/// MIT `krb5_rd_req` walks the changepw keytab. Ticket etype is
/// `first_current_key` (profile order); `best_key` follows
/// [`krb5_crypto::EncryptionType::preferred`] (sha1-first) and is not enough alone.
fn changepw_verify_keys(
    store: &krb5_kdc::PrincipalStore,
    extra: &ProtocolKey,
) -> (Vec<ProtocolKey>, Vec<u32>) {
    let mut keys = Vec::new();
    let mut kvnos = Vec::new();
    if let Some(p) = store.get_name(&krb5_kdc::principals::kadmin_changepw()) {
        for k in &p.keys {
            keys.push(k.key.clone());
            kvnos.push(k.kvno);
        }
    }
    if !keys
        .iter()
        .any(|k| k.etype() == extra.etype() && k.as_bytes() == extra.as_bytes())
    {
        keys.push(extra.clone());
        kvnos.push(0);
    }
    (keys, kvnos)
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

/// MIT `process_chpw_request` (`schpw.c:62-95`): a length, version, or framing mismatch
/// bails out before a reply is built.
/// That mismatch returns an error and no datagram is sent. The AP-REQ is verified only as a
/// ticket for `kadmin/changepw` in this realm; any failure, a ticket for another service
/// included, is answered with a framed KRB-ERROR (code 60) whose e-data carries result code 3.
fn handle_kpasswd_from(
    store: &SharedStore,
    acl: &krb5_kdc::Acl,
    service_key: &ProtocolKey,
    replay: &ReplayCache,
    raw: &[u8],
    from: &str,
    local: Option<std::net::IpAddr>,
) -> Result<Vec<u8>, Error> {
    // MIT `process_chpw_request` (`schpw.c:47-82`): length then version before AP-REQ;
    // ChangePasswdData only for 0xff80.
    if raw.len() < 4 {
        return Err(Error::Inner("kpasswd truncated".into()));
    }
    let plen = usize::from(u16::from_be_bytes([raw[0], raw[1]]));
    if plen != raw.len() {
        // MIT `process_chpw_request` (`schpw.c:62-68`): goto bailout; dispatch sends no datagram.
        return Err(Error::Inner("Message stream modified".into()));
    }
    let ver = u16::from_be_bytes([raw[2], raw[3]]);
    if ver != 1 && ver != RFC3244_VERSION {
        return Err(Error::Inner(
            "Requested protocol version not supported".into(),
        ));
    }
    if raw.len() < 6 {
        return Err(Error::Inner("kpasswd truncated".into()));
    }
    let ap_len = usize::from(u16::from_be_bytes([raw[4], raw[5]]));
    if 6 + ap_len >= raw.len() {
        // MIT `process_chpw_request` (`schpw.c:89-95`): the AP-REQ length check is `>=`
        // (no PRIV byte) → bailout, no datagram.
        return Err(Error::Inner("Message stream modified".into()));
    }
    let ap_req = &raw[6..6 + ap_len];
    let priv_raw = &raw[6 + ap_len..];
    let (store_realm, keys, kvnos) = {
        let mut g = store
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The kadmin/changepw keys as the database holds them now, whoever changed them.
        g.reload_if_stale()?;
        let (keys, kvnos) = changepw_verify_keys(&g, service_key);
        (g.realm().to_owned(), keys, kvnos)
    };
    // MIT schpw.c / the changepw acceptor acquires the kadmin/changepw cred, so
    // krb5_rd_req is pinned to that service: a ticket for any other principal
    // (e.g. host/x) is refused even if it decrypts under a shared key.
    let changepw = krb5_kdc::principals::kadmin_changepw();
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: Some(kvnos.as_slice()),
        kvno: None,
        expected_server: Some(&changepw),
        expected_realm: Some(store_realm.as_str()),
        skew: DEFAULT_SKEW,
        addresses: None,
        now: None,
    };
    // MIT `process_chpw_request` (`schpw.c:102-161`): the auth context does sequence numbers only, `krb5_rd_req` also refuses an enctype the server (on kadmind's KDC profile) does not permit, and the AP-REP is made before the request is decrypted.
    let Ok(ok) = verify_ap_req_ex(ap_req, &params, replay, None) else {
        return kpasswd_chpwfail_error(&store_realm, 3, "Failed reading application request");
    };
    let Ok(mut ac) =
        permitted_enctypes_kdc().and_then(|p| AcceptorAuthContext::from_ap_req(&ok, &p))
    else {
        return kpasswd_chpwfail_error(&store_realm, 3, "Failed reading application request");
    };
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    let Ok(ap_rep) = ac.mk_rep().and_then(|r| Ok(encode(&r)?)) else {
        return kpasswd_chpwfail_error(&store_realm, 3, "Failed replying to application request");
    };
    let mut reply = KpasswdReply {
        ac,
        ap_rep,
        local: local_host_address(local),
    };
    // MIT `process_chpw_request` (`schpw.c:153-166`): `krb5_rd_priv` on that context, with no address set, takes the request's KRB-PRIV only with the authenticator's sequence number (none when it had none); any failure is HARDERROR "Failed decrypting request".
    let Ok(user_data) = reply.ac.rd_priv(priv_raw) else {
        let mut body = Vec::from(2u16.to_be_bytes());
        body.extend_from_slice(b"Failed decrypting request");
        return reply.result(&store_realm, &body);
    };
    let ticket_crealm = String::from_utf8_lossy(ok.ticket_part.crealm.as_bytes()).into_owned();
    let (targ, targ_realm, newpass) = if ver == RFC3244_VERSION {
        let decoded = decode::<ChangePasswdData>(&user_data);
        // MIT `process_chpw_request` (`kadmin/server/schpw.c:174-185`): the decrypted request is zapped once ChangePasswdData is decoded from it.
        wipe_secret(user_data);
        if let Ok(cpw) = decoded {
            let name = cpw.targname.unwrap_or_else(|| ok.ticket_part.cname.clone());
            let realm = cpw.targrealm.as_ref().map_or_else(
                || ticket_crealm.clone(),
                |r| String::from_utf8_lossy(r.as_bytes()).into_owned(),
            );
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
    // MIT `schpw_util_wrapper` (`misc.c:33-54`): compare first, INITIAL, auth(OP_CPW), then DB.
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
        // House rule (`kadm5/dispatch.rs` `write_store`): kadmind's store lock first, then the
        // database's: the key change is one change under the exclusive lock, from a fresh read
        // of the database to its write, as `AdminSession::change_password` makes it.
        // MIT `main` (`ovsec_kadmd.c:446-446`): the global handle comes from
        // `kadm5_init(…, "kadmind", …)`.
        // MIT `dispatch` (`schpw.c:407-407`): the changepw dispatcher uses the global handle,
        // so `current_caller` is `kadmind@REALM`, not the ticket client.
        let stamp = format!("kadmind@{store_realm}");
        // MIT `ctx_lock` (`plugins/kdb/db2/kdb_db2.c:438-447`): the change locks the database
        // first, and a database the server may not write changes nothing.
        let changed = (|| -> Result<(), Error> {
            g.reload_if_stale()?;
            if self_change {
                g.check_min_life_in(&targ, &targ_realm)?;
            }
            g.change(|s| s.set_password_keepold_n_in(&targ, &targ_realm, &newpass, 0, &stamp))
                .map_err(Error::from)?
                .map_err(Error::from)
        })();
        match changed {
            Ok(()) => (0u16, String::new(), "success".to_owned()),
            Err(Error::PasswordPolicy(msg)) => {
                let text = crate::kadm5::chpass_error_text(&Error::PasswordPolicy(msg.clone()));
                (4, msg, text)
            }
            Err(Error::PassTooSoon { until }) => (
                4,
                too_soon_text(until),
                "Current password's minimum life has not expired".to_owned(),
            ),
            Err(Error::AclDenied) => (
                5,
                "Unauthorized request".to_owned(),
                "Operation requires ``change-password'' privilege".to_owned(),
            ),
            Err(Error::NotFound) => (
                2,
                UNK_PRINC_PRIV.to_owned(),
                "Principal does not exist".to_owned(),
            ),
            Err(e) => {
                let msg = e.to_string();
                (
                    2,
                    format!("Password not changed.\n{msg} while trying to change password.\n"),
                    msg,
                )
            }
        }
    };
    // MIT `process_chpw_request` (`kadmin/server/schpw.c:215-218`): both copies of the new password are zapped once the change is made or refused.
    wipe_secret(newpass);
    let log_outcome = if code == 0 { "ok" } else { "error" };
    let log_line = if ver == RFC3244_VERSION {
        format!("setpw request from {from} by {client} for {target_unparsed}: {log_err}")
    } else {
        format!("chpw request from {from} for {client}: {log_err}")
    };
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

/// Zeroizes every byte of `buf`'s allocation, then frees it: a new password a kpasswd request
/// carried, or the request plaintext holding one. A test build keeps each wiped allocation
/// ([`wiped::take`]) instead of freeing it, so a test can see it zeroed, whole.
fn wipe_secret(mut buf: Vec<u8>) {
    buf.resize(buf.capacity(), 0);
    buf.as_mut_slice().zeroize();
    #[cfg(test)]
    let _ = wiped::WIPED.try_with(|w| w.borrow_mut().push(buf));
}

/// Wipes an octet string's bytes when it holds the only reference to them, as a field decoded
/// from a request does.
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
///
/// AP-REP length 0 is a framed KRB-ERROR.
///
/// # Errors
///
/// [`Error::Inner`] when `raw` is shorter than 6 bytes, its AP-REP length is 0 (a framed
/// KRB-ERROR), or the AP-REP overruns `raw`.
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

/// Encode an RFC 3244 kpasswd request.
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

/// Serve kpasswd (RFC 3244) on UDP until shutdown. A reply leaves from the address its request
/// was sent to, as the KDC's do ([`krb5_kdc::recv_from_to`]).
///
/// # Errors
///
/// The `io::Error` when setting the read timeout fails; a failed receive, send or request is
/// logged, not returned.
#[allow(clippy::needless_pass_by_value)]
pub fn serve_kpasswd_udp(
    store: SharedStore,
    acl: krb5_kdc::Acl,
    service_key: ProtocolKey,
    sock: UdpSocket,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut buf = vec![0u8; 65_535];
    while !shutdown.load(Ordering::Relaxed) {
        match krb5_kdc::recv_from_to(&sock, &mut buf) {
            // MIT `process_packet` (`lib/apputils/net-server.c:1169-1172`): an empty datagram is dropped before kpasswd sees it.
            Ok(d) if d.len == 0 => {}
            Ok(d) => {
                let replay = ReplayCache::new();
                // MIT `process_packet` (`lib/apputils/net-server.c:1174-1187`): the request's local address is its pktinfo destination, else the socket's own.
                let local =
                    d.to.map(|p| p.addr)
                        .or_else(|| sock.local_addr().ok().map(|a| a.ip()));
                match handle_kpasswd_from(
                    &store,
                    &acl,
                    &service_key,
                    &replay,
                    &buf[..d.len],
                    &client_addr(d.from.ip()),
                    local,
                ) {
                    Ok(rep) => {
                        let _ = krb5_kdc::send_udp_reply(&sock, &rep, &d);
                    }
                    Err(e) => tracing::error!(
                        event = krb5_log::events::ADMIN,
                        component = "krb5-admin",
                        outcome = "error",
                        error = %e,
                        "{e} - while dispatching (udp)"
                    ),
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::Interrupted
                    || e.kind() == io::ErrorKind::ConnectionRefused => {}
            // MIT `process_packet` (`lib/apputils/net-server.c:1155-1167`): a failed receive is
            // logged and the socket goes on serving.
            Err(e) => {
                krb5_log::klog::com_err(
                    Some(&krb5_log::klog::os_error_text(&e)),
                    "while receiving from network",
                );
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    Ok(())
}

/// Serve kpasswd on TCP 464 (MIT 4-byte length prefix, then RFC 3244 body).
///
/// MIT 1.22.2 `kpasswd` tries TCP first.
///
/// # Errors
///
/// The `io::Error` when `set_nonblocking` fails; a failed accept and per-connection failures
/// are logged, not returned.
#[allow(clippy::needless_pass_by_value)]
pub fn serve_kpasswd_tcp(
    store: SharedStore,
    acl: krb5_kdc::Acl,
    service_key: ProtocolKey,
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                let _closed = krb5_kdc::ClosingFd(std::os::fd::AsRawFd::as_raw_fd(&stream));
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                match read_len_pref(&mut stream, 64 * 1024) {
                    Ok(body) => {
                        let replay = ReplayCache::new();
                        match handle_kpasswd_from(
                            &store,
                            &acl,
                            &service_key,
                            &replay,
                            &body,
                            &client_addr(peer.ip()),
                            stream.local_addr().ok().map(|a| a.ip()),
                        ) {
                            Ok(rep) => {
                                let _ = write_len_pref(&mut stream, &rep);
                            }
                            Err(e) => tracing::error!(
                                event = krb5_log::events::ADMIN,
                                component = "krb5-admin",
                                outcome = "error",
                                error = %e,
                                error_suffix = "while dispatching (tcp)",
                            ),
                        }
                    }
                    Err(e) => tracing::error!(
                        event = krb5_log::events::ADMIN,
                        component = "krb5-admin",
                        outcome = "error",
                        error = %e,
                    ),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                krb5_kdc::wait_for_connection(&[&listener], Duration::from_millis(100));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // MIT `accept_stream_connection` (`lib/apputils/net-server.c:1238-1241`): a failed
            // accept is dropped and the listener goes on.
            Err(e) => {
                tracing::error!(
                    event = krb5_log::events::ADMIN,
                    component = "krb5-admin",
                    outcome = "error",
                    error = %e,
                    detail = "kpasswd accept",
                );
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    Ok(())
}

/// kprop dump over TCP: send MIT dump version-7 text (4-byte length prefix).
///
/// The body is `kdb5_util load_dump version 7`, not a KDB3 blob. MIT-wire
/// sendauth lives in `crate::kprop`.
///
/// # Errors
///
/// An `ErrorKind::Other` error carrying the message when the store cannot be dumped
/// (string-to-key or key wrap under `master_password`), or the `io::Error` of a failed write
/// or flush on `stream`.
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
///
/// # Errors
///
/// [`Error::Inner`] when the length prefix or body cannot be read from `stream`, or the body
/// is a KDB blob, is not UTF-8, lacks a dump header, does not parse, or does not decrypt under
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

    use super::{encode_kpasswd_req, serve_kpasswd_udp, wiped};

    /// A request whose AP-REQ does not decode: kpasswd answers it with a framed KRB-ERROR.
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
        // MIT `send_to_from` (`lib/apputils/udppktinfo.c:443-474`): kpasswd's reply on a wildcard socket leaves from the request's destination.
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
        let server = thread::spawn(move || serve_kpasswd_udp(shared, acl, key, sock, flag));
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

    /// MIT `process_chpw_request` (`kadmin/server/schpw.c:174-218`): the decrypted request, the new password decoded from it and the copy the change is made with are each zapped.
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
        let (user_key, cpw_key) = (key_of(&user), key_of(&kadmin_changepw()));
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
            targname: Some(user.clone()),
            targrealm: Some(ascii(TEST_REALM)),
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
        let rep = super::handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
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
}
