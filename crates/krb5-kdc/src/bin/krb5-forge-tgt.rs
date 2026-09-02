//! Gate-only: reseal a FILE-ccache TGT with empty transited and a forged ticket.realm.
//!
//! Usage:
//!   krb5-forge-tgt --ccache IN --out OUT --claim-realm REALM --tgt krbtgt/C.TEST --key-hex HEX
//!   krb5-forge-tgt --ccache IN --out OUT --claim-realm REALM --tgt krbtgt/C.TEST --password PW --principal NAME

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::process::ExitCode;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt, string_to_key};
use krb5_kdc::s2k_params;
use krb5_protocol::{FileCcache, parse_principal};
use krb5_types::{EncTicketPart, OctetString, Ticket, TransitedEncoding, ku};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut ccache = None;
    let mut out = None;
    let mut claim = None;
    let mut claim_crealm = None;
    let mut key_hex = None;
    let mut password = None;
    let mut principal = None;
    let mut tgt = None;
    let mut alias_as = None;
    let mut keep_cipher = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--ccache" => {
                ccache = args.get(i + 1).cloned();
                i += 2;
            }
            "--out" => {
                out = args.get(i + 1).cloned();
                i += 2;
            }
            "--claim-realm" => {
                claim = args.get(i + 1).cloned();
                i += 2;
            }
            "--claim-crealm" => {
                claim_crealm = args.get(i + 1).cloned();
                i += 2;
            }
            "--tgt" => {
                tgt = args.get(i + 1).cloned();
                i += 2;
            }
            "--key-hex" => {
                key_hex = args.get(i + 1).cloned();
                i += 2;
            }
            "--password" => {
                password = args.get(i + 1).cloned();
                i += 2;
            }
            "--principal" => {
                principal = args.get(i + 1).cloned();
                i += 2;
            }
            "--alias-as" => {
                alias_as = args.get(i + 1).cloned();
                i += 2;
            }
            "--keep-cipher" => {
                keep_cipher = true;
                i += 1;
            }
            _ => {
                eprintln!(
                    "usage: krb5-forge-tgt --ccache <in> --out <out> --tgt <krbtgt/REALM> \
                     (--claim-realm <realm> [--keep-cipher | --key-hex <hex> | --password <pw> --principal <name@REALM>] \
                     | --alias-as <krbtgt/REALM@REALM>)"
                );
                return ExitCode::from(2);
            }
        }
    }
    let (Some(cc_path), Some(out_path), Some(tgt_sname)) = (ccache, out, tgt) else {
        eprintln!("krb5-forge-tgt: --ccache, --out, and --tgt are required");
        return ExitCode::from(2);
    };
    if let Some(alias) = alias_as {
        return alias_tgt(&cc_path, &out_path, &tgt_sname, &alias);
    }
    let Some(claim_realm) = claim else {
        eprintln!("krb5-forge-tgt: --claim-realm is required unless --alias-as");
        return ExitCode::from(2);
    };
    if keep_cipher {
        return claim_realm_keep_cipher(&cc_path, &out_path, &tgt_sname, &claim_realm);
    }
    let key = match (key_hex, password, principal) {
        (Some(hex), None, None) => match parse_hex_key(&hex) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("krb5-forge-tgt: key-hex: {e}");
                return ExitCode::from(2);
            }
        },
        (None, Some(pw), Some(princ)) => match key_from_password(&pw, &princ) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("krb5-forge-tgt: password: {e}");
                return ExitCode::from(2);
            }
        },
        _ => {
            eprintln!("krb5-forge-tgt: need --key-hex or --password plus --principal");
            return ExitCode::from(2);
        }
    };
    let bytes = match fs::read(&cc_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("krb5-forge-tgt: read {cc_path}: {e}");
            return ExitCode::from(1);
        }
    };
    let mut cc = match FileCcache::parse(&bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("krb5-forge-tgt: ccache: {e}");
            return ExitCode::from(1);
        }
    };
    let usage = match KeyUsage::new(ku::TICKET) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("krb5-forge-tgt: usage: {e}");
            return ExitCode::from(1);
        }
    };
    let claim_ks = match krb5_types::try_ascii(&claim_realm) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("krb5-forge-tgt: claim-realm: {e}");
            return ExitCode::from(2);
        }
    };
    let claim_crealm_ks = match claim_crealm.as_deref() {
        None => None,
        Some(cr) => match krb5_types::try_ascii(cr) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("krb5-forge-tgt: claim-crealm: {e}");
                return ExitCode::from(2);
            }
        },
    };
    let mut found = false;
    for cred in &mut cc.creds {
        if cred.is_config() || cred.is_removed() {
            continue;
        }
        if cred.server.1.components_joined() != tgt_sname {
            continue;
        }
        let mut ticket: Ticket = match decode(&cred.ticket) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let Ok(plain) = decrypt(&key, usage, ticket.enc_part.cipher.as_ref()) else {
            continue;
        };
        let Ok(mut part) = decode::<EncTicketPart>(&plain) else {
            continue;
        };
        part.transited = TransitedEncoding::empty();
        part.authorization_data = None;
        if let Some(ref r) = claim_crealm_ks {
            part.crealm = r.clone();
        }
        let der = match encode(&part) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("krb5-forge-tgt: encode EncTicketPart: {e}");
                return ExitCode::from(1);
            }
        };
        let cipher = match encrypt(&key, usage, &der) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("krb5-forge-tgt: reseal: {e}");
                return ExitCode::from(1);
            }
        };
        ticket.enc_part.cipher = OctetString::from(cipher);
        ticket.realm = claim_ks.clone();
        match encode(&ticket) {
            Ok(tkt) => cred.ticket = tkt,
            Err(e) => {
                eprintln!("krb5-forge-tgt: encode Ticket: {e}");
                return ExitCode::from(1);
            }
        }
        if let Some(ref r) = claim_crealm_ks {
            cred.client.0 = r.clone();
        }
        found = true;
        break;
    }
    if found && let Some(ref r) = claim_crealm_ks {
        cc.primary.0 = r.clone();
    }
    if !found {
        eprintln!("krb5-forge-tgt: no TGT decrypted with the supplied key");
        return ExitCode::from(1);
    }
    if let Err(e) = cc.write_file(&out_path) {
        eprintln!("krb5-forge-tgt: write {out_path}: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn claim_realm_keep_cipher(
    cc_path: &str,
    out_path: &str,
    tgt_sname: &str,
    claim_realm: &str,
) -> ExitCode {
    let bytes = match fs::read(cc_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("krb5-forge-tgt: read {cc_path}: {e}");
            return ExitCode::from(1);
        }
    };
    let mut cc = match FileCcache::parse(&bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("krb5-forge-tgt: ccache: {e}");
            return ExitCode::from(1);
        }
    };
    let claim_ks = match krb5_types::try_ascii(claim_realm) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("krb5-forge-tgt: claim-realm: {e}");
            return ExitCode::from(2);
        }
    };
    let mut found = false;
    for cred in &mut cc.creds {
        if cred.is_config() || cred.is_removed() {
            continue;
        }
        if cred.server.1.components_joined() != tgt_sname {
            continue;
        }
        let mut ticket: Ticket = match decode(&cred.ticket) {
            Ok(t) => t,
            Err(_) => continue,
        };
        ticket.realm = claim_ks.clone();
        match encode(&ticket) {
            Ok(tkt) => cred.ticket = tkt,
            Err(e) => {
                eprintln!("krb5-forge-tgt: encode Ticket: {e}");
                return ExitCode::from(1);
            }
        }
        found = true;
        break;
    }
    if !found {
        eprintln!("krb5-forge-tgt: no TGT matching {tgt_sname}");
        return ExitCode::from(1);
    }
    if let Err(e) = cc.write_file(out_path) {
        eprintln!("krb5-forge-tgt: write {out_path}: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn alias_tgt(cc_path: &str, out_path: &str, tgt_sname: &str, alias: &str) -> ExitCode {
    let bytes = match fs::read(cc_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("krb5-forge-tgt: read {cc_path}: {e}");
            return ExitCode::from(1);
        }
    };
    let mut cc = match FileCcache::parse(&bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("krb5-forge-tgt: ccache: {e}");
            return ExitCode::from(1);
        }
    };
    let (aname, arealm) = match parse_principal(alias) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("krb5-forge-tgt: alias-as: {e}");
            return ExitCode::from(2);
        }
    };
    let Ok(arealm_ks) = krb5_types::try_ascii(&arealm) else {
        eprintln!("krb5-forge-tgt: alias-as realm");
        return ExitCode::from(2);
    };
    let mut kept = None;
    for cred in &cc.creds {
        if cred.is_config() || cred.is_removed() {
            continue;
        }
        if cred.server.1.components_joined() == tgt_sname {
            let mut c = cred.clone();
            c.server = (arealm_ks.clone(), aname.clone());
            kept = Some(c);
            break;
        }
    }
    let Some(tgt) = kept else {
        eprintln!("krb5-forge-tgt: no {tgt_sname} in ccache");
        return ExitCode::from(1);
    };
    cc.creds.retain(krb5_protocol::CcacheCred::is_config);
    cc.creds.push(tgt);
    if let Err(e) = cc.write_file(out_path) {
        eprintln!("krb5-forge-tgt: write {out_path}: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn key_from_password(password: &str, principal: &str) -> Result<ProtocolKey, String> {
    let (name, realm) = parse_principal(principal)?;
    let salt = name.default_salt(&realm);
    let etype = EncryptionType::Aes256CtsHmacSha196;
    let params = s2k_params(etype);
    string_to_key(etype, password.as_bytes(), &salt, Some(&params)).map_err(|e| e.to_string())
}

fn parse_hex_key(hex: &str) -> Result<ProtocolKey, String> {
    let raw = hex_decode(hex)?;
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &raw).map_err(|e| e.to_string())
}

fn hex_decode(h: &str) -> Result<Vec<u8>, String> {
    let h = h.trim();
    if !h.len().is_multiple_of(2) || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("odd or non-hex".into());
    }
    let mut out = vec![0u8; h.len() / 2];
    for i in 0..out.len() {
        out[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
