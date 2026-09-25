//! RFC 3244 kpasswd client (`chpw.c` / `gic_pwd.c` KEY_EXP).
//!
//! KEY_EXP is the expired-password path. The change is not finished
//! until the AP-REP verifies. The generated subkey bytes are zeroized
//! after the key is built.

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use krb5_asn1::encode;
use krb5_crypto::{KeyUsage, ProtocolKey, encrypt};
use krb5_types::{
    ApOptions, ApReq, Authenticator, ChangePasswdData, EncryptedData, EncryptionKey, KerberosTime,
    PrincipalName, Realm, err, ku,
};
use zeroize::Zeroize;

use crate::ap_rep::verify_ap_rep;
use crate::as_ex::AsOutcome;
use crate::error::Error;
use crate::replay::ReplayCache;
use crate::safe_priv::{build_krb_priv_with_seq, unwrap_krb_priv_ex};
use crate::transport::KdcAddr;

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

/// MIT `chpw.c:244-279` `krb5_chpw_result_code_string`.
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

/// MIT `chpw.c:476-510` `krb5_chpw_message`.
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

/// MIT `chpw.c:389-474` AD 30-byte policy blob.
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

/// MIT `chpw.c:217-231` `krb5int_rd_chpw_rep` result-code half.
///
/// Out-of-range codes, a truncated payload, or SUCCESS taken from a
/// KRB-ERROR, are `KRB5KRB_AP_ERR_MODIFIED`.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] (`KRB5KRB_AP_ERR_MODIFIED`).
pub fn parse_chpw_result(clear: &[u8], from_error: bool) -> Result<u16, Error> {
    Ok(parse_chpw_rep(clear, from_error)?.0)
}

/// Like [`parse_chpw_result`], also returning the result-string octets.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] (`KRB5KRB_AP_ERR_MODIFIED`).
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
/// Transport, crypto, or a non-success / modified result code.
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
/// Transport, crypto, or a modified reply; a non-success result code is
/// returned, not an error.
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
/// Transport, crypto, or a non-success / modified result code.
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
    let sub_enc = EncryptionKey {
        keytype: sub.etype().to_iana(),
        keyvalue: sub.as_bytes().to_vec().into(),
    };
    let now = KerberosTime::now();
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: as_out.crealm.clone(),
        cname: as_out.cname.clone(),
        cksum: None,
        cusec: krb5_types::Microseconds::from_subsec_micros(now.0.timestamp_subsec_micros()),
        ctime: now,
        subkey: Some(sub_enc),
        seq_number: Some(0),
        authorization_data: None,
    };
    let der = encode(&authenticator)?;
    let usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let cipher = encrypt(&as_out.session_key, usage, &der)?;
    let ap = ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
        ticket: as_out.ticket.clone(),
        authenticator: EncryptedData {
            etype: as_out.session_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    let ap_der = encode(&ap)?;
    let (priv_plain, version) = if let Some((realm, name)) = target {
        let cpw = ChangePasswdData {
            newpasswd: new_pw.to_vec().into(),
            targname: Some(name.clone()),
            targrealm: Some(realm.clone()),
        };
        (encode(&cpw)?, KPASSWD_SETPW_VERSION)
    } else {
        (new_pw.to_vec(), 1)
    };
    let priv_msg = build_krb_priv_with_seq(&sub, &priv_plain, Some(0))?;
    let priv_der = encode(&priv_msg)?;
    let req = encode_kpasswd_req(&ap_der, &priv_der, version);
    let rep = send_kpasswd(&kdc.host, &req)?;
    let (ap_rep, priv_rep, from_error) = parse_kpasswd_rep(&rep)?;
    let (code, data) = if from_error {
        let (code, rest) = parse_chpw_rep(&priv_rep, true)?;
        (code, rest.to_vec())
    } else {
        verify_ap_rep(&ap_rep, &as_out.session_key, &authenticator)?;
        let replay = ReplayCache::new();
        let user = unwrap_krb_priv_ex(&sub, &priv_rep, &replay, false, false)?;
        let (code, rest) = parse_chpw_rep(&user, false)?;
        (code, rest.to_vec())
    };
    Ok((code, data))
}

/// MIT `gic_pwd.c:211-222`: KEY_EXP plus a new-password source, not keytab.
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

fn send_kpasswd(host: &str, body: &[u8]) -> Result<Vec<u8>, Error> {
    let tcp = format!("{host}:{KPASSWD_PORT}");
    if let Ok(mut s) = TcpStream::connect(&tcp) {
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        let n = u32::try_from(body.len()).unwrap_or(0);
        s.write_all(&n.to_be_bytes()).map_err(Error::from_io)?;
        s.write_all(body).map_err(Error::from_io)?;
        s.flush().map_err(Error::from_io)?;
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).map_err(Error::from_io)?;
        let n = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(0);
        if n == 0 || n > 64 * 1024 {
            return Err(Error::ReplyMismatch("kpasswd tcp length".into()));
        }
        let mut out = vec![0u8; n];
        s.read_exact(&mut out).map_err(Error::from_io)?;
        return Ok(out);
    }
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(Error::from_io)?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(Error::from_io)?;
    sock.connect(format!("{host}:{KPASSWD_PORT}"))
        .map_err(Error::from_io)?;
    sock.send(body).map_err(Error::from_io)?;
    let mut buf = vec![0u8; 65_535];
    let n = sock.recv(&mut buf).map_err(Error::from_io)?;
    buf.truncate(n);
    Ok(buf)
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
}
