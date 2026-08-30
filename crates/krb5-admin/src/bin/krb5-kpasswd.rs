//! RFC 3244 kpasswd client. TCP 464 first, then UDP.
//!
//! Usage: krb5-kpasswd <kdc-host> <user@REALM>
//! Old password: `KRB5_PASSWORD`. New: `KRB5_NEW_PASSWORD`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

use krb5_admin::{encode_kpasswd_req, kpasswd_udp_exchange_to, parse_kpasswd_rep};
use krb5_asn1::encode;
use krb5_crypto::{KeyUsage, ProtocolKey, encrypt};
use krb5_protocol::{
    AsRequest, KdcAddr, ReplayCache, as_exchange, build_krb_priv_with_seq, parse_principal,
    unwrap_krb_priv_ex, verify_ap_rep,
};
use krb5_types::{
    ApOptions, ApReq, Authenticator, EncryptedData, EncryptionKey, KerberosTime, PrincipalName, ku,
};
use zeroize::Zeroize;

fn main() {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| {
        eprintln!("usage: krb5-kpasswd <kdc-host> <user@REALM>");
        std::process::exit(2);
    });
    let princ = args.next().unwrap_or_else(|| {
        eprintln!("missing user@REALM");
        std::process::exit(2);
    });
    let mut old = std::env::var("KRB5_PASSWORD").unwrap_or_else(|_| {
        eprintln!("kpasswd: set KRB5_PASSWORD");
        std::process::exit(2);
    });
    let mut new = std::env::var("KRB5_NEW_PASSWORD").unwrap_or_else(|_| {
        eprintln!("kpasswd: set KRB5_NEW_PASSWORD");
        std::process::exit(2);
    });
    let r = run(&host, &princ, old.as_bytes(), new.as_bytes());
    old.zeroize();
    new.zeroize();
    if let Err(e) = r {
        eprintln!("kpasswd: {e}");
        std::process::exit(1);
    }
    println!("ok");
}

fn run(host: &str, princ: &str, old: &[u8], new: &[u8]) -> Result<(), String> {
    let (cname, realm) = parse_principal(princ)?;
    let kdc = parse_host(host);
    let changepw = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]);
    let as_out = as_exchange(&AsRequest {
        cname: cname.clone(),
        realm: &realm,
        password: old,
        kdc: &kdc,
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: Some(&changepw),
    })
    .map_err(|e| e.to_string())?;
    let tgs = as_out.clone();
    let mut sk = vec![0u8; tgs.session_key.etype().key_len()];
    getrandom::getrandom(&mut sk).map_err(|e| e.to_string())?;
    let sub = ProtocolKey::from_bytes(tgs.session_key.etype(), &sk).map_err(|e| e.to_string())?;
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
    let der = encode(&authenticator).map_err(|e| e.to_string())?;
    let usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR).map_err(|e| e.to_string())?;
    let cipher = encrypt(&tgs.session_key, usage, &der).map_err(|e| e.to_string())?;
    let ap = ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
        ticket: tgs.ticket,
        authenticator: EncryptedData {
            etype: tgs.session_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    let ap_der = encode(&ap).map_err(|e| e.to_string())?;
    let priv_msg = build_krb_priv_with_seq(&sub, new, Some(0)).map_err(|e| e.to_string())?;
    let priv_der = encode(&priv_msg).map_err(|e| e.to_string())?;
    let req = encode_kpasswd_req(&ap_der, &priv_der);
    let rep = send_kpasswd(&kdc, &req)?;
    let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).map_err(|e| e.to_string())?;
    verify_ap_rep(&ap_rep, &tgs.session_key, &authenticator).map_err(|e| e.to_string())?;
    let replay = ReplayCache::new();
    let user =
        unwrap_krb_priv_ex(&sub, &priv_rep, &replay, false, false).map_err(|e| e.to_string())?;
    if user.len() < 2 || user[0] != 0 || user[1] != 0 {
        return Err(format!("kpasswd result {user:?}"));
    }
    Ok(())
}

fn parse_host(host: &str) -> KdcAddr {
    if let Some((h, p)) = host.rsplit_once(':')
        && let Ok(port) = p.parse()
    {
        return KdcAddr {
            host: h.to_owned(),
            port,
        };
    }
    KdcAddr::new(host)
}

fn send_kpasswd(kdc: &KdcAddr, body: &[u8]) -> Result<Vec<u8>, String> {
    let tcp = format!("{}:464", kdc.host);
    if let Ok(mut s) = TcpStream::connect(&tcp) {
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let n = u32::try_from(body.len()).unwrap_or(0);
        s.write_all(&n.to_be_bytes()).map_err(|e| e.to_string())?;
        s.write_all(body).map_err(|e| e.to_string())?;
        s.flush().map_err(|e| e.to_string())?;
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).map_err(|e| e.to_string())?;
        let n = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(0);
        if n == 0 || n > 64 * 1024 {
            return Err("kpasswd tcp length".into());
        }
        let mut out = vec![0u8; n];
        s.read_exact(&mut out).map_err(|e| e.to_string())?;
        return Ok(out);
    }
    let dest = format!("{}:464", kdc.host)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "kpasswd udp dest".to_string())?;
    kpasswd_udp_exchange_to(dest, body).map_err(|e| e.to_string())
}
