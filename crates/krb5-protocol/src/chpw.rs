//! RFC 3244 kpasswd client (`chpw.c` / `gic_pwd.c` KEY_EXP).
//!
//! KEY_EXP is the expired-password path. A reply that is not a
//! KRB-ERROR is not read until its AP-REP verifies, and a success code
//! inside a KRB-ERROR is not accepted. The random subkey buffer is wiped
//! once the key is built; the subkey copy in the authenticator and the
//! authenticator DER are not wiped. The copies of the new password this
//! module and the KRB-PRIV builder make are wiped once encrypted.

use std::io::{self, Read};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use krb5_asn1::encode;
use krb5_crypto::{KeyUsage, ProtocolKey, encrypt};
use krb5_types::{
    ApOptions, ApReq, Authenticator, ChangePasswdData, EncryptedData, EncryptionKey, HostAddress,
    PrincipalName, Realm, Ticket, err, ku,
};
use zeroize::{Zeroize, Zeroizing};

use crate::ap_rep::verify_ap_rep;
use crate::as_ex::AsOutcome;
use crate::auth_con::RemoteSeq;
use crate::error::Error;
use crate::safe_priv::{build_krb_priv_from, read_krb_priv, wipe_octets};
use crate::trace::{self, RemoteAddr, Transport};
use crate::transport::{KdcAddr, errno, is_timeout, read_errno};

/// MIT `KRB5_KPASSWD_SUCCESS`.
pub const KPASSWD_SUCCESS: u16 = 0;
/// MIT `KRB5_KPASSWD_MALFORMED`.
pub const KPASSWD_MALFORMED: u16 = 1;
/// MIT `KRB5_KPASSWD_HARDERROR`.
pub const KPASSWD_HARDERROR: u16 = 2;
/// MIT `KRB5_KPASSWD_AUTHERROR`.
pub const KPASSWD_AUTHERROR: u16 = 3;
/// MIT `KRB5_KPASSWD_SOFTERROR`.
pub const KPASSWD_SOFTERROR: u16 = 4;
/// MIT `KRB5_KPASSWD_ACCESSDENIED`.
pub const KPASSWD_ACCESSDENIED: u16 = 5;
/// MIT `KRB5_KPASSWD_BAD_VERSION`.
pub const KPASSWD_BAD_VERSION: u16 = 6;
/// MIT `KRB5_KPASSWD_INITIAL_FLAG_NEEDED` — last valid result code.
pub const KPASSWD_INITIAL_FLAG_NEEDED: u16 = 7;
/// RFC 3244 set-password version (`krb5int_mk_setpw_req`).
pub const KPASSWD_SETPW_VERSION: u16 = 0xff80;
/// kpasswd / kadmind port.
pub const KPASSWD_PORT: u16 = 464;

const AD_POLICY_LEN: usize = 30;
const AD_POLICY_COMPLEX: u32 = 0x0000_0001;
const AD_POLICY_TICKS_PER_DAY: u64 = 86_400 * 10_000_000;

/// MIT `krb5_chpw_result_code_string` (`chpw.c:244-279`): the message for each kpasswd result
/// code; an unknown code is "Password change failed".
#[must_use]
pub fn chpw_result_code_string(code: u16) -> &'static str {
    match code {
        KPASSWD_SUCCESS => "Success",
        KPASSWD_MALFORMED => "Malformed request error",
        KPASSWD_HARDERROR => "Server error",
        KPASSWD_AUTHERROR => "Authentication error",
        KPASSWD_SOFTERROR => "Password change rejected",
        KPASSWD_ACCESSDENIED => "Access denied",
        KPASSWD_BAD_VERSION => "Wrong protocol version",
        KPASSWD_INITIAL_FLAG_NEEDED => "Initial password required",
        _ => "Password change failed",
    }
}

/// MIT `krb5_chpw_message` (`chpw.c:476-510`): an AD policy blob is decoded into a message, else
/// a valid UTF-8 server string is returned, else a generic hint.
#[must_use]
pub fn chpw_message(server_string: &[u8]) -> String {
    if let Some(msg) = decode_ad_policy_info(server_string) {
        return msg;
    }
    if !server_string.is_empty()
        && !server_string.contains(&0)
        && let Ok(s) = std::str::from_utf8(server_string)
    {
        return s.to_owned();
    }
    "Try a more complex password, or contact your administrator.".into()
}

/// MIT `decode_ad_policy_info` (`chpw.c:389-474`): decodes the AD 30-byte policy blob.
fn decode_ad_policy_info(data: &[u8]) -> Option<String> {
    if data.len() != AD_POLICY_LEN {
        return None;
    }
    if u16::from_be_bytes([data[0], data[1]]) != 0 {
        return None;
    }
    let min_len = u32::from_be_bytes(data[2..6].try_into().ok()?);
    let history = u32::from_be_bytes(data[6..10].try_into().ok()?);
    let props = u32::from_be_bytes(data[10..14].try_into().ok()?);
    let min_age = u64::from_be_bytes(data[22..30].try_into().ok()?);
    let mut parts = Vec::new();
    if props & AD_POLICY_COMPLEX != 0 {
        parts.push(
            "The password must include numbers or symbols.  \
             Don't include any part of your name in the password."
                .to_owned(),
        );
    }
    if min_len > 0 {
        parts.push(if min_len == 1 {
            "The password must contain at least 1 character.".into()
        } else {
            format!("The password must contain at least {min_len} characters.")
        });
    }
    if history > 0 {
        parts.push(if history == 1 {
            "The password must be different from the previous password.".into()
        } else {
            format!("The password must be different from the previous {history} passwords.")
        });
    }
    if min_age > 0 {
        let mut days = min_age / AD_POLICY_TICKS_PER_DAY;
        if days == 0 {
            days = 1;
        }
        parts.push(if days == 1 {
            "The password can only be changed once a day.".into()
        } else {
            format!("The password can only be changed every {days} days.")
        });
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("  "))
}

/// MIT `krb5int_rd_chpw_rep` (`chpw.c:217-231`): the result-code half of the kpasswd reply check.
///
/// Out-of-range codes, a truncated payload, or SUCCESS taken from a
/// KRB-ERROR, are `KRB5KRB_AP_ERR_MODIFIED`.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] (`KRB5KRB_AP_ERR_MODIFIED`) when `clear` is under two bytes, the
/// code is above `KPASSWD_INITIAL_FLAG_NEEDED`, or `from_error` carries `KPASSWD_SUCCESS`.
pub fn parse_chpw_result(clear: &[u8], from_error: bool) -> Result<u16, Error> {
    Ok(parse_chpw_rep(clear, from_error)?.0)
}

/// Like [`parse_chpw_result`], also returning the result-string octets.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] (`KRB5KRB_AP_ERR_MODIFIED`) when `clear` is under two bytes, the
/// code is above `KPASSWD_INITIAL_FLAG_NEEDED`, or `from_error` carries `KPASSWD_SUCCESS`.
pub fn parse_chpw_rep(clear: &[u8], from_error: bool) -> Result<(u16, &[u8]), Error> {
    if clear.len() < 2 {
        return Err(Error::ReplyMismatch(
            "kpasswd result truncated (MODIFIED)".into(),
        ));
    }
    let code = u16::from_be_bytes([clear[0], clear[1]]);
    if code > KPASSWD_INITIAL_FLAG_NEEDED {
        return Err(Error::ReplyMismatch("kpasswd result code modified".into()));
    }
    if from_error && code == KPASSWD_SUCCESS {
        return Err(Error::ReplyMismatch(
            "kpasswd SUCCESS from KRB-ERROR (MODIFIED)".into(),
        ));
    }
    Ok((code, &clear[2..]))
}

/// Format MIT `kpasswd` stdout: `code_string[: message]`.
#[must_use]
pub fn format_chpw_failure(code: u16, result_data: &[u8]) -> String {
    let title = chpw_result_code_string(code);
    let msg = chpw_message(result_data);
    if msg.is_empty() {
        title.to_owned()
    } else {
        format!("{title}: {msg}")
    }
}

/// RFC 3244 kpasswd using a `kadmin/changepw` AS outcome (version 1).
///
/// # Errors
///
/// [`Error::Io`] when the host does not resolve, or (`TimedOut`) when no kpasswd server answers:
/// TCP first, 15 s to connect to one address and no deadline once connected, then UDP sent at
/// 0, 3 and 8 s and given up at 17 s; [`Error::KrbError`] `BAD_PVNO` for a reply
/// version other than 1 or `0xff80`; [`Error::Crypto`] or [`Error::Asn1`] when the subkey or a
/// message cannot be generated, encrypted, encoded, decrypted, or decoded;
/// [`Error::ReplyMismatch`] for a malformed frame, a KRB-ERROR reply, a missing or out-of-range
/// result code or a success inside an error reply, an AP-REP or KRB-PRIV failing its time
/// check, or a result other than `KPASSWD_SUCCESS` (carrying its text).
pub fn change_password(kdc: &KdcAddr, as_out: &AsOutcome, new_pw: &[u8]) -> Result<(), Error> {
    let (code, data) = change_password_result(kdc, as_out, new_pw)?;
    if code != KPASSWD_SUCCESS {
        return Err(Error::ReplyMismatch(format_chpw_failure(code, &data)));
    }
    Ok(())
}

/// [`change_password`] returning the kpasswd result code and result data
/// like MIT `krb5_change_password` (`result_code`, `result_string`), so a
/// caller can tell a soft rejection (`KRB5_KPASSWD_SOFTERROR`) apart.
///
/// # Errors
///
/// [`Error::Io`] when the host does not resolve, or (`TimedOut`) when no kpasswd server answers:
/// TCP first, 15 s to connect to one address and no deadline once connected, then UDP sent at
/// 0, 3 and 8 s and given up at 17 s; [`Error::KrbError`] `BAD_PVNO` for a reply
/// version other than 1 or `0xff80`; [`Error::Crypto`] or [`Error::Asn1`] when the subkey or a
/// message cannot be generated, encrypted, encoded, decrypted, or decoded;
/// [`Error::ReplyMismatch`] for a malformed frame, a KRB-ERROR reply, a missing or out-of-range
/// result code or a success inside an error reply, or an AP-REP or KRB-PRIV failing its time
/// check. A non-success result code is returned, not an error.
pub fn change_password_result(
    kdc: &KdcAddr,
    as_out: &AsOutcome,
    new_pw: &[u8],
) -> Result<(u16, Vec<u8>), Error> {
    change_or_set(kdc, as_out, new_pw, None)
}

/// RFC 3244 `krb5_set_password` (version `0xff80` + `ChangePasswdData`).
///
/// # Errors
///
/// [`Error::Io`] when the host does not resolve, or (`TimedOut`) when no kpasswd server answers:
/// TCP first, 15 s to connect to one address and no deadline once connected, then UDP sent at
/// 0, 3 and 8 s and given up at 17 s; [`Error::KrbError`] `BAD_PVNO` for a reply
/// version other than 1 or `0xff80`; [`Error::Crypto`] or [`Error::Asn1`] when the subkey or a
/// message cannot be generated, encrypted, encoded, decrypted, or decoded;
/// [`Error::ReplyMismatch`] for a malformed frame, a KRB-ERROR reply, a missing or out-of-range
/// result code or a success inside an error reply, an AP-REP or KRB-PRIV failing its time
/// check, or a result other than `KPASSWD_SUCCESS` (carrying its text).
pub fn set_password(
    kdc: &KdcAddr,
    as_out: &AsOutcome,
    new_pw: &[u8],
    target: (&Realm, &PrincipalName),
) -> Result<(), Error> {
    let (code, data) = change_or_set(kdc, as_out, new_pw, Some(target))?;
    if code != KPASSWD_SUCCESS {
        return Err(Error::ReplyMismatch(format_chpw_failure(code, &data)));
    }
    Ok(())
}

/// MIT `krb5int_rd_chpw_rep` (`chpw.c:227-229`): a success code carried inside an error reply is
/// not accepted. The generated subkey buffer is wiped as soon as the key exists, and a non-error
/// reply is not accepted until its AP-REP verifies.
fn change_or_set(
    kdc: &KdcAddr,
    as_out: &AsOutcome,
    new_pw: &[u8],
    target: Option<(&Realm, &PrincipalName)>,
) -> Result<(u16, Vec<u8>), Error> {
    let mut sk = vec![0u8; as_out.session_key.etype().key_len()];
    getrandom::getrandom(&mut sk).map_err(|e| Error::Crypto(e.to_string()))?;
    let sub = ProtocolKey::from_bytes(as_out.session_key.etype(), &sk)?;
    sk.zeroize();
    let (authenticator, ap_der) = kpasswd_ap_req(
        &as_out.ticket,
        &as_out.session_key,
        (&as_out.crealm, &as_out.cname),
        &sub,
    )?;
    let (priv_plain, version) = if let Some((realm, name)) = target {
        let cpw = ChangePasswdData {
            newpasswd: new_pw.to_vec().into(),
            targname: name.clone(),
            targrealm: realm.clone(),
        };
        let der = encode(&cpw);
        wipe_octets(cpw.newpasswd);
        (Zeroizing::new(der?), KPASSWD_SETPW_VERSION)
    } else {
        (Zeroizing::new(new_pw.to_vec()), 1)
    };
    // MIT `kpasswd_sendto_msg_callback` (`lib/krb5/os/changepw.c:108-195`): the request is made once a connection to a server exists, with that connection's local address as the KRB-PRIV's sender.
    let mut build =
        |sender: &HostAddress| kpasswd_request(&sub, &ap_der, &priv_plain, version, sender);
    let rep = send_kpasswd(&kdc.host, &mut build)?;
    let (ap_rep, priv_rep, from_error) = parse_kpasswd_rep(&rep)?;
    let (code, data) = if from_error {
        let (code, rest) = parse_chpw_rep(&priv_rep, true)?;
        (code, rest.to_vec())
    } else {
        let user = get_clear_result(
            &ap_rep,
            &priv_rep,
            &as_out.session_key,
            &authenticator,
            &sub,
        )?;
        let (code, rest) = parse_chpw_rep(&user, false)?;
        (code, rest.to_vec())
    };
    Ok((code, data))
}

/// The AP-REQ of a kpasswd request, and the authenticator inside it, which the caller keeps to check the AP-REP's echo. The authenticator carries the client, the time and the request's subkey, and no sequence number, checksum or authorization data.
/// MIT `change_set_password` (`lib/krb5/os/changepw.c:230-240`): a fresh authentication context, then `krb5_mk_req_extended` asked for a subkey and nothing else.
/// MIT `krb5_auth_con_init` (`lib/krb5/krb/auth_con.c:39-41`): the new context does time and not sequence numbers.
/// MIT `krb5_mk_req_extended` (`lib/krb5/krb/mk_req_ext.c:137-143`): a sequence number is made only under `DO_SEQUENCE` or `RET_SEQUENCE`, which `krb5int_mk_chpw_req` sets after the authenticator is made, so the authenticator has none.
/// MIT `authenticator_7` (`lib/krb5/asn.1/asn1_k_encode.c:693-693`): the sequence number is an `opt_seqno`, which leaves a zero out, so the field is not on the wire.
fn kpasswd_ap_req(
    ticket: &Ticket,
    session: &ProtocolKey,
    (crealm, cname): (&Realm, &PrincipalName),
    sub: &ProtocolKey,
) -> Result<(Authenticator, Vec<u8>), Error> {
    let sub_enc = EncryptionKey {
        keytype: sub.etype().to_iana(),
        keyvalue: sub.as_bytes().to_vec().into(),
    };
    // MIT `generate_authenticator` (`lib/krb5/krb/mk_req_ext.c:327-327`): the time and its microseconds, from `krb5_us_timeofday`.
    let (now, usec) = crate::auth_con::us_timeofday();
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: crealm.clone(),
        cname: cname.clone(),
        cksum: None,
        cusec: usec,
        ctime: now,
        subkey: Some(sub_enc),
        seq_number: None,
        authorization_data: None,
    };
    let der = encode(&authenticator)?;
    let usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let cipher = encrypt(session, usage, &der)?;
    // MIT `krb5_mk_req_extended` (`lib/krb5/krb/mk_req_ext.c:85-254`): the authenticator is traced
    // with its sequence number and both keys as hashes.
    trace::mk_req(
        trace::Princ::new(cname, crealm.as_bytes()),
        trace::Princ::new(&ticket.sname, ticket.realm.as_bytes()),
        0,
        Some(sub.into()),
        session.into(),
    );
    let ap = ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
        ticket: ticket.clone(),
        authenticator: EncryptedData {
            etype: session.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    Ok((authenticator, encode(&ap)?))
}

/// The result a kpasswd reply's KRB-PRIV carries, after its AP-REP.
/// MIT `get_clear_result` (`lib/krb5/krb/chpw.c:159-181`): `krb5_rd_rep` checks the AP-REP's echo and takes its sequence number as the peer's next, the receive subkey is then put back to the request's own send subkey ("per spec") whatever subkey the AP-REP carried, and `krb5_rd_priv` on that context, which does sequence numbers, reads the KRB-PRIV under it and refuses one that does not carry that number.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] when the AP-REP does not echo the authenticator;
/// [`Error::KrbError`] `BADORDER` (42) when the KRB-PRIV is out of order, `MSG_TYPE` (40) when
/// it is not a KRB-PRIV; [`Error::Asn1`] or [`Error::Crypto`] when either does not decode or
/// decrypt.
fn get_clear_result(
    ap_rep: &[u8],
    priv_rep: &[u8],
    session: &ProtocolKey,
    authenticator: &Authenticator,
    subkey: &ProtocolKey,
) -> Result<Vec<u8>, Error> {
    let rep_part = verify_ap_rep(ap_rep, session, authenticator)?;
    // MIT `krb5_rd_rep` (`lib/krb5/krb/rd_rep.c:130-130`): the AP-REP's sequence number is the one the reply must carry.
    let mut remote = RemoteSeq::new(rep_part.seq_number.unwrap_or(0));
    let part = read_krb_priv(subkey, priv_rep)?;
    if !remote.check(part.seq_number.unwrap_or(0)) {
        return Err(Error::KrbError {
            code: err::BADORDER,
            text: Some("Message out of order".into()),
        });
    }
    Ok(part.user_data.to_vec())
}

/// KEY_EXP plus a new-password source, not keytab.
/// MIT `krb5_get_init_creds_password` (`gic_pwd.c:211-222`): only KEY_EXP with a prompter,
/// and the change-password prompt not turned off, goes on to a password change.
#[must_use]
pub fn key_exp_should_changepw(err: &Error, has_new_password: bool, keytab: bool) -> bool {
    has_new_password
        && !keytab
        && matches!(
            err,
            Error::KrbError {
                code: krb5_types::err::KEY_EXPIRED,
                ..
            }
        )
}

fn encode_kpasswd_req(ap_req: &[u8], krb_priv_der: &[u8], version: u16) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&version.to_be_bytes());
    inner.extend_from_slice(&(u16::try_from(ap_req.len()).unwrap_or(0)).to_be_bytes());
    inner.extend_from_slice(ap_req);
    inner.extend_from_slice(krb_priv_der);
    let mut out = Vec::new();
    out.extend_from_slice(&(u16::try_from(inner.len() + 2).unwrap_or(0)).to_be_bytes());
    out.extend_from_slice(&inner);
    out
}

fn parse_kpasswd_rep(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>, bool), Error> {
    if raw.len() >= 2 && raw[0] == 0x7e {
        return Ok((Vec::new(), raw.to_vec(), true));
    }
    if raw.len() < 6 {
        return Err(Error::ReplyMismatch("kpasswd truncated".into()));
    }
    let plen = usize::from(u16::from_be_bytes([raw[0], raw[1]]));
    if plen != raw.len() {
        return Err(Error::ReplyMismatch("kpasswd length modified".into()));
    }
    let vno = u16::from_be_bytes([raw[2], raw[3]]);
    if vno != 1 && vno != KPASSWD_SETPW_VERSION {
        return Err(Error::KrbError {
            code: err::BAD_PVNO,
            text: Some("kpasswd bad version".into()),
        });
    }
    let ap_len = usize::from(u16::from_be_bytes([raw[4], raw[5]]));
    if ap_len == 0 {
        return Ok((Vec::new(), raw[6..].to_vec(), true));
    }
    if 6 + ap_len > raw.len() {
        return Err(Error::ReplyMismatch("kpasswd AP-REP".into()));
    }
    Ok((
        raw[6..6 + ap_len].to_vec(),
        raw[6 + ap_len..].to_vec(),
        false,
    ))
}

/// One address's share of the first pass, and each UDP resend's wait.
/// MIT `k5_sendto` (`sendto_kdc.c:1537-1557`): each new connection gets 1 s for an answer.
const PASS_SLOT: Duration = Duration::from_secs(1);

/// The wait at the end of each of `k5_sendto`'s three passes.
/// MIT `k5_sendto` (`sendto_kdc.c:1572-1600`): 2 s after the first pass, then 4 s and 8 s.
const PASS_DELAYS: [Duration; 3] = [
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];

/// What makes a request for a connection: it is given the connection's local address, as the sender of the KRB-PRIV.
type Build<'a> = dyn FnMut(&HostAddress) -> Result<Vec<u8>, Error> + 'a;

/// The request for a connection whose socket reports `local` as its address.
fn request_for(local: io::Result<SocketAddr>, build: &mut Build<'_>) -> Result<Vec<u8>, Error> {
    let sender = kpasswd_sender_address(local.map_err(Error::from_io)?, crate::os_localaddr)?;
    build(&sender)
}

/// The sender of a kpasswd request on a connection whose local address is `local`.
/// MIT `kpasswd_sendto_msg_callback` (`lib/krb5/os/changepw.c:127-157`): the address `getsockname` gives, as `ADDRTYPE_INET` or `ADDRTYPE_INET6` unless it is the wildcard, which takes the first address of `krb5_os_localaddr`.
/// A wildcard with no address to take is an error here, where MIT reads `addrs[0]` of an empty list; a connected socket does not have one.
pub(crate) fn kpasswd_sender_address(
    local: SocketAddr,
    host: impl FnOnce() -> Result<Vec<HostAddress>, Error>,
) -> Result<HostAddress, Error> {
    match local.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_unspecified() => Ok(HostAddress {
            addr_type: HostAddress::ADDRTYPE_INET,
            address: ip.octets().to_vec().into(),
        }),
        std::net::IpAddr::V6(ip) if !ip.is_unspecified() => Ok(HostAddress {
            addr_type: HostAddress::ADDRTYPE_INET6,
            address: ip.octets().to_vec().into(),
        }),
        _ => host()?.into_iter().next().ok_or_else(|| {
            Error::from_io(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no local address",
            ))
        }),
    }
}

/// The request for one connection: the version, the AP-REQ and a KRB-PRIV that names `sender`.
/// MIT `krb5int_mk_chpw_req` (`lib/krb5/krb/chpw.c:13-67`): `DO_SEQUENCE` alone, the sender the auth context's local address and no receiver, so no timestamp.
/// MIT `priv_enc_part_3` (`lib/krb5/asn.1/asn1_k_encode.c:866-866`): a sequence number of zero, the authenticator's, is left out of the part.
fn kpasswd_request(
    sub: &ProtocolKey,
    ap_der: &[u8],
    priv_plain: &[u8],
    version: u16,
    sender: &HostAddress,
) -> Result<Vec<u8>, Error> {
    let priv_msg = build_krb_priv_from(sub, priv_plain, None, sender)?;
    let priv_der = encode(&priv_msg)?;
    Ok(encode_kpasswd_req(ap_der, &priv_der, version))
}

/// MIT `change_set_password` (`changepw.c:256-265`): TCP alone first; UDP only when no TCP
/// connection answered, as UDP resends may be taken for replays.
fn send_kpasswd(host: &str, build: &mut Build<'_>) -> Result<Vec<u8>, Error> {
    trace::sendto_kdc_resolving(host);
    let addrs: Vec<SocketAddr> = (host, KPASSWD_PORT)
        .to_socket_addrs()
        .map_err(Error::from_io)?
        .collect();
    kpasswd_tcp(&addrs, build)
        .or_else(|| kpasswd_udp(&addrs, build))
        .ok_or_else(|| {
            Error::from_io(io::Error::new(
                io::ErrorKind::TimedOut,
                "Cannot contact any KDC for requested realm",
            ))
        })
}

/// The exchange over TCP, or `None` when no connection was made or none answered.
/// MIT `k5_sendto` (`sendto_kdc.c:1537-1600`): a pending connect has its 1 s, then the 2, 4 and
/// 8 s ends of the passes; the request is written once. Connections here are tried one after
/// another within that budget, where MIT holds them open together.
/// MIT `service_fds` (`sendto_kdc.c:1421-1421`): a connected stream is waited on without a
/// deadline (`request_timeout` is not read here).
fn kpasswd_tcp(addrs: &[SocketAddr], build: &mut Build<'_>) -> Option<Vec<u8>> {
    let slots = PASS_SLOT.saturating_mul(u32::try_from(addrs.len()).unwrap_or(u32::MAX));
    let deadline = Instant::now() + slots + PASS_DELAYS.iter().sum::<Duration>();
    for (i, addr) in addrs.iter().enumerate() {
        let left = deadline.saturating_duration_since(Instant::now());
        let slot = if i + 1 < addrs.len() {
            left.min(PASS_SLOT)
        } else {
            left
        };
        if slot.is_zero() {
            break;
        }
        // MIT `start_connection` (`lib/krb5/os/sendto_kdc.c:884-990`): a connection is traced as
        // it starts, and `kill_conn` or the cleanup of `k5_sendto` as it ends.
        let ra = RemoteAddr {
            transport: Transport::Tcp,
            addr: *addr,
        };
        trace::sendto_kdc_tcp_connect(&ra);
        let mut stream = match TcpStream::connect_timeout(addr, slot) {
            Ok(stream) => stream,
            Err(e) => {
                if !is_timeout(&e) {
                    trace::sendto_kdc_tcp_error_connect(&ra, errno(&e));
                }
                trace::sendto_kdc_tcp_disconnect(&ra);
                continue;
            }
        };
        // MIT `start_connection` (`lib/krb5/os/sendto_kdc.c:936-945`): the request is built for the connection just made, and one that cannot be built fails the connection.
        let Ok(body) = request_for(stream.local_addr(), build) else {
            trace::sendto_kdc_tcp_disconnect(&ra);
            continue;
        };
        let reply = tcp_round_trip(&mut stream, &body, &ra);
        if let Ok(reply) = &reply {
            trace::sendto_kdc_response(reply.len(), &ra);
        }
        trace::sendto_kdc_tcp_disconnect(&ra);
        if let Ok(reply) = reply {
            return Some(reply);
        }
    }
    None
}

/// MIT `service_tcp_read` (`sendto_kdc.c:1151-1200`): a reply shorter than its length, or a length
/// of 0 or over 1 MiB, ends the connection.
/// MIT `service_tcp_write` (`lib/krb5/os/sendto_kdc.c:1115-1146`): the write and a failed one are
/// traced, and so is a failed read.
fn tcp_round_trip(stream: &mut TcpStream, body: &[u8], ra: &RemoteAddr) -> io::Result<Vec<u8>> {
    // MIT `service_tcp_write` (`lib/krb5/os/sendto_kdc.c:1124-1125`): the length and the request
    // go out in one writev.
    trace::sendto_kdc_tcp_send(ra);
    crate::framing::write_messages(stream, &[body]).inspect_err(|e| {
        trace::sendto_kdc_tcp_error_send(ra, errno(e));
    })?;
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).inspect_err(|e| {
        if !is_timeout(e) {
            trace::sendto_kdc_tcp_error_recv_len(ra, read_errno(e));
        }
    })?;
    let n = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(usize::MAX);
    if n == 0 || n > 1024 * 1024 {
        return Err(io::Error::other("kpasswd tcp length"));
    }
    let mut out = vec![0u8; n];
    stream.read_exact(&mut out).inspect_err(|e| {
        if !is_timeout(e) {
            trace::sendto_kdc_tcp_error_recv(ra, read_errno(e));
        }
    })?;
    Ok(out)
}
/// The exchange over UDP, or `None` when no server answered.
/// MIT `k5_sendto` (`sendto_kdc.c:1537-1600`): each pass sends to every server with 1 s for an
/// answer, then waits 2, 4 or 8 s: sends at 0, 3 and 8 s for one server, given up at 17 s.
/// MIT `maybe_send` (`sendto_kdc.c:1021-1035`): a failed resend keeps the server for the next
/// pass.
/// MIT `start_connection` (`lib/krb5/os/sendto_kdc.c:884-990`): the first send to a server is
/// traced as the initial request, each later one by `maybe_send` as a retry.
fn kpasswd_udp(addrs: &[SocketAddr], build: &mut Build<'_>) -> Option<Vec<u8>> {
    // MIT `start_connection` (`lib/krb5/os/sendto_kdc.c:936-945`): the request is built once for each socket made, and one that cannot be built fails that server. Every resend is the same message.
    let mut bodies: Vec<Vec<u8>> = Vec::with_capacity(addrs.len());
    let mut socks: Vec<Option<UdpSocket>> = Vec::with_capacity(addrs.len());
    for a in addrs {
        let made = udp_connect(a).ok().and_then(|sock| {
            request_for(sock.local_addr(), build)
                .ok()
                .map(|body| (sock, body))
        });
        if let Some((sock, body)) = made {
            socks.push(Some(sock));
            bodies.push(body);
        } else {
            socks.push(None);
            bodies.push(Vec::new());
        }
    }
    for (pass, delay) in PASS_DELAYS.into_iter().enumerate() {
        for i in 0..socks.len() {
            let Some(sock) = &socks[i] else {
                continue;
            };
            let body = &bodies[i];
            let ra = udp_ra(addrs[i]);
            if pass == 0 {
                trace::sendto_kdc_udp_send_initial(&ra);
            } else {
                trace::sendto_kdc_udp_send_retry(&ra);
            }
            if let Err(e) = sock.send(body) {
                if pass == 0 {
                    trace::sendto_kdc_udp_error_send_initial(&ra, errno(&e));
                } else {
                    trace::sendto_kdc_udp_error_send_retry(&ra, errno(&e));
                }
            }
            if let Some(reply) = udp_wait(&mut socks, addrs, PASS_SLOT) {
                return Some(reply);
            }
        }
        if socks.iter().all(Option::is_none) {
            return None;
        }
        if let Some(reply) = udp_wait(&mut socks, addrs, delay) {
            return Some(reply);
        }
    }
    None
}

/// A kpasswd server's UDP address as the trace prints it.
const fn udp_ra(addr: SocketAddr) -> RemoteAddr {
    RemoteAddr {
        transport: Transport::Udp,
        addr,
    }
}

fn udp_connect(addr: &SocketAddr) -> io::Result<UdpSocket> {
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(addr)?;
    Ok(sock)
}

/// The first datagram any of `socks` receives within `wait`.
/// MIT `service_udp_read` (`sendto_kdc.c:1203-1217`): a receive error, such as a refused port,
/// drops that server, and is traced.
fn udp_wait(
    socks: &mut [Option<UdpSocket>],
    addrs: &[SocketAddr],
    wait: Duration,
) -> Option<Vec<u8>> {
    let deadline = Instant::now() + wait;
    let turn = if socks.iter().flatten().count() > 1 {
        Duration::from_millis(50)
    } else {
        wait
    };
    let mut buf = vec![0u8; 65_535];
    loop {
        let mut live = false;
        for (slot, addr) in socks.iter_mut().zip(addrs) {
            let Some(sock) = slot else {
                continue;
            };
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            live = true;
            if sock.set_read_timeout(Some(turn.min(left))).is_err() {
                *slot = None;
                continue;
            }
            match sock.recv(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    trace::sendto_kdc_response(n, &udp_ra(*addr));
                    return Some(buf);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => {
                    trace::sendto_kdc_udp_error_recv(&udp_ra(*addr), errno(&e));
                    *slot = None;
                }
            }
        }
        if !live {
            return None;
        }
    }
}

#[cfg(test)]
mod parse_rep_tests {
    use super::{KPASSWD_SETPW_VERSION, parse_kpasswd_rep};
    use krb5_types::err;

    #[test]
    fn chpw_framed_length_mismatch_is_modified() {
        let mut raw = vec![0u8; 8];
        raw[0..2].copy_from_slice(&7u16.to_be_bytes());
        raw[2..4].copy_from_slice(&1u16.to_be_bytes());
        let err = parse_kpasswd_rep(&raw).unwrap_err();
        assert!(err.to_string().contains("modified"), "{err}");
    }

    #[test]
    fn chpw_bad_version_is_bad_pvno() {
        let mut raw = vec![0u8; 8];
        raw[0..2].copy_from_slice(&8u16.to_be_bytes());
        raw[2..4].copy_from_slice(&2u16.to_be_bytes());
        match parse_kpasswd_rep(&raw).unwrap_err() {
            crate::error::Error::KrbError {
                code: err::BAD_PVNO,
                ..
            } => {}
            e => panic!("{e}"),
        }
    }

    #[test]
    fn chpw_setpw_version_is_accepted() {
        let mut raw = vec![0u8; 6];
        raw[0..2].copy_from_slice(&6u16.to_be_bytes());
        raw[2..4].copy_from_slice(&KPASSWD_SETPW_VERSION.to_be_bytes());
        let (_, _, from_error) = parse_kpasswd_rep(&raw).unwrap();
        assert!(from_error);
    }

    /// MIT `get_clear_result` (`chpw.c:159-181`): the reply KRB-PRIV is read under the request's own subkey, whatever subkey the AP-REP carries, and only with the AP-REP's seq-number.
    #[test]
    fn the_reply_krb_priv_is_read_under_the_requests_subkey_and_the_ap_reps_seq() {
        use krb5_asn1::encode;
        use krb5_crypto::{EncryptionType, ProtocolKey};
        use krb5_types::{Authenticator, EncryptionKey, KerberosTime, Microseconds, PrincipalName};

        use crate::ap_rep::build_ap_rep;
        use crate::safe_priv::build_krb_priv_with_seq;

        let session = ProtocolKey::random(EncryptionType::Aes256CtsHmacSha196).unwrap();
        let ours = ProtocolKey::random(EncryptionType::Aes256CtsHmacSha196).unwrap();
        let fresh = ProtocolKey::random(EncryptionType::Aes256CtsHmacSha196).unwrap();
        let authenticator = Authenticator {
            authenticator_vno: Authenticator::VNO,
            crealm: krb5_types::ascii("KERBER.TEST"),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            cksum: None,
            cusec: Microseconds::from_subsec_micros(1),
            ctime: KerberosTime::now(),
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };
        let result = [0u8, 0];
        let read = |rep_subkey: Option<&ProtocolKey>, priv_key: &ProtocolKey, priv_seq: u32| {
            let wire = rep_subkey.map(|k| EncryptionKey {
                keytype: k.etype().to_iana(),
                keyvalue: k.as_bytes().to_vec().into(),
            });
            let rep = build_ap_rep(&session, &authenticator, wire, Some(77)).unwrap();
            let msg = build_krb_priv_with_seq(priv_key, &result, Some(priv_seq)).unwrap();
            super::get_clear_result(
                &encode(&rep).unwrap(),
                &encode(&msg).unwrap(),
                &session,
                &authenticator,
                &ours,
            )
        };
        assert_eq!(
            read(None, &ours, 77).unwrap(),
            result,
            "the request's subkey"
        );
        assert_eq!(
            read(Some(&fresh), &ours, 77).unwrap(),
            result,
            "the request's subkey, though the AP-REP carries one"
        );
        assert!(
            read(Some(&fresh), &fresh, 77).is_err(),
            "never the AP-REP's subkey"
        );
        match read(None, &ours, 78).unwrap_err() {
            crate::error::Error::KrbError {
                code: err::BADORDER,
                ..
            } => {}
            e => panic!("seq 78 after an AP-REP carrying 77: {e}"),
        }
    }
}

/// The kpasswd transport keeps MIT `k5_sendto`'s schedule (live MIT 1.22.2 `kpasswd` gives up on a
/// blackholed server after 32 s and waits on a connected, silent one).
#[cfg(test)]
mod transport_tests {
    use super::{kpasswd_tcp, kpasswd_udp};
    use crate::error::Error;
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn udp_is_resent_three_seconds_after_the_first_send() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let seen = thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (_, _) = server.recv_from(&mut buf).unwrap();
            let first = Instant::now();
            let (_, from) = server.recv_from(&mut buf).unwrap();
            let gap = first.elapsed();
            server.send_to(b"reply", from).unwrap();
            gap
        });
        assert_eq!(
            kpasswd_udp(&[addr], &mut |_| Ok(b"req".to_vec())).as_deref(),
            Some(&b"reply"[..])
        );
        let gap = seen.join().unwrap();
        assert!(
            gap >= Duration::from_millis(2500) && gap <= Duration::from_millis(4500),
            "resend after {gap:?}, MIT's after 3 s"
        );
    }

    #[test]
    fn a_connected_stream_is_waited_on_past_five_seconds() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut req = [0u8; 7];
            conn.read_exact(&mut req).unwrap();
            thread::sleep(Duration::from_secs(6));
            conn.write_all(&5u32.to_be_bytes()).unwrap();
            conn.write_all(b"reply").unwrap();
        });
        assert_eq!(
            kpasswd_tcp(&[addr], &mut |_| Ok(b"req".to_vec())).as_deref(),
            Some(&b"reply"[..])
        );
    }

    #[test]
    fn refused_ports_fail_at_once() {
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let started = Instant::now();
        assert!(kpasswd_tcp(&[addr], &mut |_| Ok(b"req".to_vec())).is_none());
        assert!(kpasswd_udp(&[addr], &mut |_| Ok(b"req".to_vec())).is_none());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "refused took {:?}",
            started.elapsed()
        );
    }

    /// The request is made for each connection, with that connection's own address as its sender: the address the server sees the client at, whatever the family.
    /// MIT `kpasswd_sendto_msg_callback` (`lib/krb5/os/changepw.c:127-157`): `getsockname` of the connected socket, as `ADDRTYPE_INET` or `ADDRTYPE_INET6`.
    #[test]
    fn the_request_is_built_with_the_connections_own_address() {
        use krb5_types::HostAddress;
        use std::net::IpAddr;
        let hosts = crate::os_localaddr().unwrap_or_default();
        let mut binds = vec!["127.0.0.1:0".to_owned()];
        if UdpSocket::bind("[::1]:0").is_ok() {
            binds.push("[::1]:0".to_owned());
        }
        // The first non-loopback IPv4 address the host has, reached through itself.
        if let Some(h) = hosts
            .iter()
            .find(|h| h.addr_type == HostAddress::ADDRTYPE_INET)
        {
            let o: [u8; 4] = h.address.as_ref().try_into().unwrap();
            binds.push(format!("{}:0", std::net::Ipv4Addr::from(o)));
        }
        for bind in binds {
            let server = TcpListener::bind(&bind).unwrap();
            let addr = server.local_addr().unwrap();
            let seen = thread::spawn(move || {
                let (mut conn, from) = server.accept().unwrap();
                let mut req = [0u8; 3];
                conn.read_exact(&mut req).unwrap();
                conn.write_all(&5u32.to_be_bytes()).unwrap();
                conn.write_all(b"reply").unwrap();
                from
            });
            let mut sender = None;
            let reply = kpasswd_tcp(&[addr], &mut |s| {
                sender = Some(s.clone());
                Ok(b"req".to_vec())
            });
            assert_eq!(reply.as_deref(), Some(&b"reply"[..]), "{bind}");
            let from = seen.join().unwrap();
            let want = match from.ip() {
                IpAddr::V4(ip) => (HostAddress::ADDRTYPE_INET, ip.octets().to_vec()),
                IpAddr::V6(ip) => (HostAddress::ADDRTYPE_INET6, ip.octets().to_vec()),
            };
            let got = sender.unwrap();
            assert_eq!((got.addr_type, got.address.to_vec()), want, "TCP to {addr}");
            // The same over UDP: the connected socket's own address.
            let server = UdpSocket::bind(&bind).unwrap();
            let addr = server.local_addr().unwrap();
            let seen = thread::spawn(move || {
                let mut buf = [0u8; 8];
                let (_, from) = server.recv_from(&mut buf).unwrap();
                server.send_to(b"reply", from).unwrap();
                from
            });
            let mut sender = None;
            let reply = kpasswd_udp(&[addr], &mut |s| {
                sender = Some(s.clone());
                Ok(b"req".to_vec())
            });
            assert_eq!(reply.as_deref(), Some(&b"reply"[..]), "{bind}");
            let from = seen.join().unwrap();
            let want = match from.ip() {
                IpAddr::V4(ip) => (HostAddress::ADDRTYPE_INET, ip.octets().to_vec()),
                IpAddr::V6(ip) => (HostAddress::ADDRTYPE_INET6, ip.octets().to_vec()),
            };
            let got = sender.unwrap();
            assert_eq!((got.addr_type, got.address.to_vec()), want, "UDP to {addr}");
        }
    }

    /// A request that cannot be made for a connection fails that server alone, and the next is tried.
    /// MIT `start_connection` (`lib/krb5/os/sendto_kdc.c:936-945`): a failed callback closes the socket and marks the server failed.
    #[test]
    fn a_request_that_cannot_be_made_fails_the_server_not_the_exchange() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let addrs = [first.local_addr().unwrap(), second.local_addr().unwrap()];
        thread::spawn(move || {
            let _ = first.accept();
        });
        thread::spawn(move || {
            let (mut conn, _) = second.accept().unwrap();
            let mut req = [0u8; 3];
            conn.read_exact(&mut req).unwrap();
            conn.write_all(&5u32.to_be_bytes()).unwrap();
            conn.write_all(b"reply").unwrap();
        });
        let mut tries = 0;
        let reply = kpasswd_tcp(&addrs, &mut |_| {
            tries += 1;
            if tries == 1 {
                Err(Error::Message("cannot be made".into()))
            } else {
                Ok(b"req".to_vec())
            }
        });
        assert_eq!(reply.as_deref(), Some(&b"reply"[..]));
        assert_eq!(tries, 2);
    }
}

/// The sender of a kpasswd request, and the KRB-PRIV that carries it.
#[cfg(test)]
mod sender_tests {
    use super::{kpasswd_request, kpasswd_sender_address};
    use krb5_asn1::decode;
    use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
    use krb5_types::{EncKrbPrivPart, HostAddress, KrbPriv, ku};
    use std::net::SocketAddr;

    fn host_list() -> impl Fn() -> Result<Vec<HostAddress>, crate::error::Error> {
        || {
            Ok(vec![HostAddress {
                addr_type: 2,
                address: vec![198, 51, 100, 9].into(),
            }])
        }
    }

    /// MIT `kpasswd_sendto_msg_callback` (`lib/krb5/os/changepw.c:127-157`): an IPv4 connection is `ADDRTYPE_INET`, an IPv6 one `ADDRTYPE_INET6`, and neither is 127.0.0.1 by default.
    #[test]
    fn the_sender_is_the_connections_address_in_its_family() {
        let v4: SocketAddr = "192.0.2.7:51000".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::5]:51000".parse().unwrap();
        let got = kpasswd_sender_address(v4, host_list()).unwrap();
        assert_eq!(
            (got.addr_type, got.address.to_vec()),
            (2, vec![192, 0, 2, 7])
        );
        let got = kpasswd_sender_address(v6, host_list()).unwrap();
        assert_eq!(got.addr_type, 24);
        assert_eq!(
            got.address.to_vec(),
            "2001:db8::5"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        // Link-local and loopback stay as `getsockname` gives them: MIT filters nothing here.
        let ll: SocketAddr = "[fe80::1]:51000".parse().unwrap();
        assert_eq!(
            kpasswd_sender_address(ll, host_list()).unwrap().addr_type,
            24
        );
        let lo: SocketAddr = "127.0.0.1:51000".parse().unwrap();
        assert_eq!(
            kpasswd_sender_address(lo, host_list())
                .unwrap()
                .address
                .to_vec(),
            vec![127, 0, 0, 1]
        );
    }

    /// MIT `kpasswd_sendto_msg_callback` (`lib/krb5/os/changepw.c:127-157`): a wildcard local address takes the first address of `krb5_os_localaddr`.
    #[test]
    fn a_wildcard_takes_the_first_host_address() {
        for wild in ["0.0.0.0:51000", "[::]:51000"] {
            let got = kpasswd_sender_address(wild.parse().unwrap(), host_list()).unwrap();
            assert_eq!(
                (got.addr_type, got.address.to_vec()),
                (2, vec![198, 51, 100, 9]),
                "{wild}"
            );
        }
        let none = || Ok(Vec::new());
        assert!(kpasswd_sender_address("0.0.0.0:51000".parse().unwrap(), none).is_err());
    }

    /// The KRB-PRIV in the request names the connection's address as its sender and no receiver, with no timestamp and no sequence number (zero is left out), under the request's subkey.
    /// MIT `create_krbpriv` (`lib/krb5/krb/mk_priv.c:60-61`): the sender is the auth context's local address and the receiver its remote one, unset for kpasswd.
    #[test]
    fn the_krb_priv_of_a_request_names_the_sender_and_no_receiver() {
        let sub = ProtocolKey::random(EncryptionType::Aes256CtsHmacSha196).unwrap();
        let sender = HostAddress {
            addr_type: 24,
            address: "2001:db8::5"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec()
                .into(),
        };
        let req = kpasswd_request(&sub, b"ap-req", b"new-password", 1, &sender).unwrap();
        // length, version, AP-REQ length, the AP-REQ, then the KRB-PRIV.
        assert_eq!(u16::from_be_bytes([req[0], req[1]]) as usize, req.len());
        assert_eq!(&req[2..4], &1u16.to_be_bytes());
        assert_eq!(&req[6..12], b"ap-req");
        let priv_msg: KrbPriv = decode(&req[12..]).unwrap();
        let plain = decrypt(
            &sub,
            KeyUsage::new(ku::KRB_PRIV_ENC_PART).unwrap(),
            priv_msg.enc_part.cipher.as_ref(),
        )
        .unwrap();
        let part: EncKrbPrivPart = decode(&plain).unwrap();
        assert_eq!(part.s_address, sender);
        assert_eq!(part.r_address, None);
        assert_eq!(part.timestamp, None);
        assert_eq!(part.usec, None);
        assert_eq!(part.seq_number, None);
        assert_eq!(part.user_data.as_ref(), b"new-password");
    }
}

/// The AP-REQ of a kpasswd request.
#[cfg(test)]
mod ap_req_tests {
    use super::kpasswd_ap_req;
    use krb5_asn1::decode;
    use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
    use krb5_types::{
        ApOptions, ApReq, Authenticator, EncryptedData, PrincipalName, Ticket, ascii, ku,
    };

    /// The tags of the fields of a DER `SEQUENCE` inside an application tag, read without the codec that wrote them.
    fn field_tags(der: &[u8]) -> Vec<u8> {
        fn header(b: &[u8]) -> (usize, usize) {
            // (length of the tag and length octets, length of the content)
            match b[1] {
                n if n < 0x80 => (2, usize::from(n)),
                n => {
                    let used = usize::from(n & 0x7f);
                    let len = b[2..2 + used]
                        .iter()
                        .fold(0usize, |acc, &x| (acc << 8) | usize::from(x));
                    (2 + used, len)
                }
            }
        }
        let (outer, _) = header(der);
        assert_eq!(der[0], 0x62, "[APPLICATION 2]");
        let seq = &der[outer..];
        assert_eq!(seq[0], 0x30, "SEQUENCE");
        let (head, len) = header(seq);
        let mut rest = &seq[head..head + len];
        let mut tags = Vec::new();
        while !rest.is_empty() {
            let (head, len) = header(rest);
            tags.push(rest[0]);
            rest = &rest[head + len..];
        }
        tags
    }

    /// The authenticator of a request carries the client, the time and the request's subkey, and no sequence number, checksum or authorization data; the AP-REQ asks for nothing.
    /// MIT `change_set_password` (`lib/krb5/os/changepw.c:230-240`): a fresh authentication context, then `krb5_mk_req_extended` asked for a subkey and nothing else.
    /// MIT `krb5_mk_req_extended` (`lib/krb5/krb/mk_req_ext.c:137-143`): a sequence number is made only under `DO_SEQUENCE` or `RET_SEQUENCE`, which the new context does not have.
    #[test]
    fn the_authenticator_of_a_request_has_a_subkey_and_no_sequence_number() {
        let session = ProtocolKey::random(EncryptionType::Aes256CtsHmacSha196).unwrap();
        let sub = ProtocolKey::random(EncryptionType::Aes256CtsHmacSha196).unwrap();
        let ticket = Ticket {
            tkt_vno: Ticket::VNO,
            realm: ascii("KERBER.TEST"),
            sname: PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: vec![0u8; 16].into(),
            },
        };
        let crealm = ascii("KERBER.TEST");
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let (kept, ap_der) = kpasswd_ap_req(&ticket, &session, (&crealm, &cname), &sub).unwrap();

        let ap: ApReq = decode(&ap_der).unwrap();
        assert_eq!(ap.ap_options, ApOptions::none(), "no AP option");
        assert_eq!(ap.ticket, ticket);
        assert_eq!(ap.authenticator.etype, session.etype().to_iana());
        assert_eq!(ap.authenticator.kvno, None);
        let plain = decrypt(
            &session,
            KeyUsage::new(ku::AP_REQ_AUTHENTICATOR).unwrap(),
            ap.authenticator.cipher.as_ref(),
        )
        .unwrap();
        let sent: Authenticator = decode(&plain).unwrap();
        assert_eq!(sent, kept, "the authenticator kept is the one sent");
        assert_eq!((&sent.crealm, &sent.cname), (&crealm, &cname));
        assert_eq!(sent.seq_number, None, "no sequence number");
        assert_eq!(sent.cksum, None);
        assert_eq!(sent.authorization_data, None);
        let subkey = sent.subkey.expect("a subkey");
        assert_eq!(subkey.keytype, sub.etype().to_iana());
        assert_eq!(subkey.keyvalue.as_ref(), sub.as_bytes());
        // On the wire: version, realm, client, microseconds, time and the subkey, and no [7].
        assert_eq!(
            field_tags(&plain),
            [0xa0, 0xa1, 0xa2, 0xa4, 0xa5, 0xa6],
            "{plain:02x?}"
        );
    }
}
