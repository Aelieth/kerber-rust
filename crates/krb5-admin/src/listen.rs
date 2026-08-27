//! TCP/UDP listeners for kadmind (749), kpasswd (464), and kprop (754).

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::{SharedStore, save_store};
use krb5_protocol::{
    ReplayCache, build_ap_rep, build_krb_priv_with_seq, unwrap_krb_priv_ex, verify_ap_req,
};
use krb5_types::{ChangePasswdData, EncryptionKey, PrincipalName};

use crate::{AdminSession, Error, Op};

/// Ports from the Kerberos assigned set.
pub const KADMIND_PORT: u16 = 749;
/// RFC 3244.
pub const KPASSWD_PORT: u16 = 464;
/// kprop.
pub const KPROP_PORT: u16 = 754;

const WIRE_VERSION: u8 = 1;

/// Serve kadmind until `shutdown`. GSS AP-REQ authenticates each op.
///
/// # Errors
///
/// Bind / accept failures.
#[allow(clippy::needless_pass_by_value)]
pub fn serve_kadmind(
    store: SharedStore,
    acl: krb5_kdc::Acl,
    service_key: ProtocolKey,
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let replay = ReplayCache::new();
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                match handle_kadmind_conn(&store, &acl, &service_key, &replay, &mut stream) {
                    Ok(reply) => {
                        let _ = write_len_pref(&mut stream, &reply);
                    }
                    Err(e) => {
                        tracing::error!(
                            event = krb5_log::events::ADMIN,
                            component = "krb5-admin",
                            outcome = "error",
                            error = %e,
                        );
                        let _ = write_len_pref(&mut stream, &status_bytes(1));
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn write_len_pref(stream: &mut TcpStream, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len()).unwrap_or(0);
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()
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

fn handle_kadmind_conn(
    store: &SharedStore,
    acl: &krb5_kdc::Acl,
    service_key: &ProtocolKey,
    replay: &ReplayCache,
    stream: &mut TcpStream,
) -> Result<Vec<u8>, Error> {
    let body = read_len_pref(stream, 64 * 1024).map_err(|e| Error::Inner(e.to_string()))?;
    dispatch_kadmind(store, acl, service_key, replay, &body)
}

/// Version-1 kadmind body: `version, op, ap_len, ap-req, pay_len, payload`.
///
/// # Errors
///
/// AP-REQ, ACL, or truncated framing.
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
        5 => Op::Dump,
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
        Op::Dump => {
            drop(sess);
            let tmp = std::env::temp_dir().join(format!("kprop-{}-{}", std::process::id(), {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            }));
            let db = tmp.with_extension("db");
            let stash = tmp.with_extension("stash");
            save_store(&g, &db, &stash).map_err(|e| Error::Inner(e.to_string()))?;
            let blob = std::fs::read(&db).map_err(|e| Error::Inner(e.to_string()))?;
            let _ = std::fs::remove_file(&db);
            let _ = std::fs::remove_file(&stash);
            let mut out = status_bytes(0);
            out.extend_from_slice(&blob);
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
    let (user, realm) = name_s.split_once('@').unwrap_or((name_s, ""));
    let parts: Vec<&str> = user.split('/').collect();
    let ntype = if parts.len() > 1 {
        PrincipalName::NT_SRV_INST
    } else {
        PrincipalName::NT_PRINCIPAL
    };
    let name = PrincipalName::try_new(ntype, parts).map_err(|e| Error::Inner(e.to_string()))?;
    let _ = realm;
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

fn protocol_key_from_enc(kt: &EncryptionKey) -> Result<ProtocolKey, Error> {
    let etype = EncryptionType::from_iana(kt.keytype)
        .or_else(|_| EncryptionType::known(kt.keytype))
        .map_err(|e| Error::Inner(e.to_string()))?;
    ProtocolKey::from_bytes(etype, kt.keyvalue.as_ref()).map_err(|e| Error::Inner(e.to_string()))
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

fn kpasswd_success_rep(
    session: &ProtocolKey,
    priv_key: &ProtocolKey,
    authenticator: &krb5_types::Authenticator,
    result: &[u8],
) -> Result<Vec<u8>, Error> {
    // Match AP-REP seq to KRB-PRIV seq (MIT rd_rep then rd_priv).
    let seq = authenticator.seq_number.or(Some(1));
    let ap_rep =
        build_ap_rep(session, authenticator, None, seq).map_err(|e| Error::Inner(e.to_string()))?;
    let ap_der = encode(&ap_rep).map_err(|e| Error::Inner(e.to_string()))?;
    let priv_rep =
        build_krb_priv_with_seq(priv_key, result, seq).map_err(|e| Error::Inner(e.to_string()))?;
    let priv_der = encode(&priv_rep).map_err(|e| Error::Inner(e.to_string()))?;
    Ok(frame_kpasswd_rep(&ap_der, &priv_der))
}

/// RFC 3244 / MIT changepw request: `len, version, ap-req-len, AP-REQ, KRB-PRIV`.
///
/// Version 1 (MIT `kpasswd`) carries the raw password in KRB-PRIV. Version
/// `0xff80` (setpw) carries `ChangePasswdData`. KRB-PRIV is encrypted with
/// the authenticator subkey when present (MIT always sends one).
///
/// # Errors
///
/// AP-REQ, PRIV unwrap, or ACL.
pub fn handle_kpasswd_rfc3244(
    store: &SharedStore,
    acl: &krb5_kdc::Acl,
    service_key: &ProtocolKey,
    replay: &ReplayCache,
    raw: &[u8],
) -> Result<Vec<u8>, Error> {
    if raw.len() < 6 {
        return Err(Error::Inner("kpasswd truncated".into()));
    }
    let _msglen = u16::from_be_bytes([raw[0], raw[1]]);
    let _ver = u16::from_be_bytes([raw[2], raw[3]]);
    let ap_len = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    if 6 + ap_len > raw.len() {
        return Err(Error::Inner("kpasswd AP-REQ".into()));
    }
    let ap_req = &raw[6..6 + ap_len];
    let priv_raw = &raw[6 + ap_len..];
    let ok = verify_ap_req(ap_req, service_key, replay).map_err(|e| Error::Inner(e.to_string()))?;
    let session = protocol_key_from_enc(&ok.ticket_part.key)?;
    let priv_key = match &ok.authenticator.subkey {
        Some(sk) => protocol_key_from_enc(sk)?,
        None => session.clone(),
    };
    let user_data = unwrap_krb_priv_ex(&priv_key, priv_raw, replay, false, false)
        .map_err(|e| Error::Inner(e.to_string()))?;
    let (targ, newpass) = match decode::<ChangePasswdData>(&user_data) {
        Ok(cpw) => {
            let name = cpw.targname.unwrap_or(ok.authenticator.cname.clone());
            (name, cpw.newpasswd.to_vec())
        }
        Err(_) => (ok.authenticator.cname.clone(), user_data),
    };
    {
        let mut g = store
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut sess = AdminSession::local(
            &mut g,
            acl,
            format!(
                "{}@{}",
                ok.authenticator.cname.components_joined(),
                String::from_utf8_lossy(ok.authenticator.crealm.as_bytes())
            ),
        );
        sess.change_password(&targ, &newpass)?;
    }
    kpasswd_success_rep(&session, &priv_key, &ok.authenticator, &[0, 0])
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

/// Serve kpasswd (RFC 3244) on UDP until shutdown.
///
/// # Errors
///
/// Socket I/O.
#[allow(clippy::needless_pass_by_value)]
pub fn serve_kpasswd_udp(
    store: SharedStore,
    acl: krb5_kdc::Acl,
    service_key: ProtocolKey,
    sock: UdpSocket,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;
    let replay = ReplayCache::new();
    let mut buf = vec![0u8; 65_535];
    while !shutdown.load(Ordering::Relaxed) {
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                match handle_kpasswd_rfc3244(&store, &acl, &service_key, &replay, &buf[..n]) {
                    Ok(rep) => {
                        let _ = sock.send_to(&rep, peer);
                    }
                    Err(e) => tracing::error!(
                        event = krb5_log::events::ADMIN,
                        component = "krb5-admin",
                        outcome = "error",
                        error = %e,
                    ),
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
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
/// Bind / accept failures.
#[allow(clippy::needless_pass_by_value)]
pub fn serve_kpasswd_tcp(
    store: SharedStore,
    acl: krb5_kdc::Acl,
    service_key: ProtocolKey,
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let replay = ReplayCache::new();
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                match read_len_pref(&mut stream, 64 * 1024) {
                    Ok(body) => {
                        match handle_kpasswd_rfc3244(&store, &acl, &service_key, &replay, &body) {
                            Ok(rep) => {
                                let _ = write_len_pref(&mut stream, &rep);
                            }
                            Err(e) => tracing::error!(
                                event = krb5_log::events::ADMIN,
                                component = "krb5-admin",
                                outcome = "error",
                                error = %e,
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
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// kprop dump over TCP: send MIT dump version-7 text (4-byte length prefix).
///
/// The body is `kdb5_util load_dump version 7`, not a KDB3 blob. MIT-wire
/// sendauth lives in [`crate::kprop`].
///
/// # Errors
///
/// Dump or I/O.
pub fn kprop_send(
    store: &krb5_kdc::PrincipalStore,
    master_password: &[u8],
    stream: &mut TcpStream,
) -> io::Result<()> {
    let blob = crate::kprop::kprop_dump_bytes(store, master_password)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let len = u32::try_from(blob.len()).unwrap_or(0);
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&blob)?;
    stream.flush()
}

/// Receive a length-prefixed dump v7 body and load it.
///
/// # Errors
///
/// I/O or dump parse/crypto.
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
