//! RFC 3244 kpasswd client (`chpw.c` / `gic_pwd.c` KEY_EXP).

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use krb5_asn1::encode;
use krb5_crypto::{KeyUsage, ProtocolKey, encrypt};
use krb5_types::{ApOptions, ApReq, Authenticator, EncryptedData, EncryptionKey, KerberosTime, ku};
use zeroize::Zeroize;

use crate::ap_rep::verify_ap_rep;
use crate::as_ex::AsOutcome;
use crate::error::Error;
use crate::replay::ReplayCache;
use crate::safe_priv::{build_krb_priv_with_seq, unwrap_krb_priv_ex};
use crate::transport::KdcAddr;

/// MIT `KRB5_KPASSWD_SUCCESS`.
pub const KPASSWD_SUCCESS: u16 = 0;
/// MIT `KRB5_KPASSWD_INITIAL_FLAG_NEEDED` — last valid result code.
pub const KPASSWD_INITIAL_FLAG_NEEDED: u16 = 7;
/// kpasswd / kadmind port.
pub const KPASSWD_PORT: u16 = 464;

/// MIT `chpw.c:217-231` `krb5int_rd_chpw_rep` result-code half.
///
/// Out-of-range codes, a truncated payload, or SUCCESS taken from a
/// KRB-ERROR, are `KRB5KRB_AP_ERR_MODIFIED`.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] (`KRB5KRB_AP_ERR_MODIFIED`).
pub fn parse_chpw_result(clear: &[u8], from_error: bool) -> Result<u16, Error> {
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
    Ok(code)
}

/// RFC 3244 kpasswd using a `kadmin/changepw` AS outcome.
///
/// # Errors
///
/// Transport, crypto, or a non-success / modified result code.
pub fn change_password(kdc: &KdcAddr, as_out: &AsOutcome, new_pw: &[u8]) -> Result<(), Error> {
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
    let priv_msg = build_krb_priv_with_seq(&sub, new_pw, Some(0))?;
    let priv_der = encode(&priv_msg)?;
    let req = encode_kpasswd_req(&ap_der, &priv_der);
    let rep = send_kpasswd(&kdc.host, &req)?;
    let (ap_rep, priv_rep, from_error) = parse_kpasswd_rep(&rep)?;
    if !from_error {
        verify_ap_rep(&ap_rep, &as_out.session_key, &authenticator)?;
        let replay = ReplayCache::new();
        let user = unwrap_krb_priv_ex(&sub, &priv_rep, &replay, false, false)?;
        let code = parse_chpw_result(&user, false)?;
        if code != KPASSWD_SUCCESS {
            return Err(Error::ReplyMismatch(format!("kpasswd result {code}")));
        }
        return Ok(());
    }
    let code = parse_chpw_result(&priv_rep, true)?;
    Err(Error::ReplyMismatch(format!("kpasswd result {code}")))
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

fn encode_kpasswd_req(ap_req: &[u8], krb_priv_der: &[u8]) -> Vec<u8> {
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

fn parse_kpasswd_rep(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>, bool), Error> {
    if raw.len() >= 2 && raw[0] == 0x7e {
        return Ok((Vec::new(), raw.to_vec(), true));
    }
    if raw.len() < 6 {
        return Err(Error::ReplyMismatch("kpasswd truncated".into()));
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
