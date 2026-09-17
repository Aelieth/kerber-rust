//! Gate-only: reseal a FILE-ccache TGT with empty transited and a forged ticket.realm.
//!
//! Usage:
//!   krb5-forge-tgt --ccache IN --out OUT --claim-realm REALM --tgt krbtgt/C.TEST --key-hex HEX
//!   krb5-forge-tgt --ccache IN --out OUT --claim-realm REALM --tgt krbtgt/C.TEST --password PW --principal NAME
//!   optional --reseal-key-hex / --reseal-password + --reseal-principal to encrypt with a different key
//!   optional `--decrypt-keytab <kt>` auto-selects the key matching the ticket's own etype+kvno
//!   optional --authtime <+secs|epoch> / --drop-starttime rewrite the ticket times (acceptor NYV tests)
//!   optional `--set-kvno <n>` relabels the ticket's cleartext kvno (acceptor key-pinning tests)

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::process::ExitCode;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt, string_to_key};
use krb5_kdc::s2k_params;
use krb5_protocol::{FileCcache, Keytab, parse_principal};
use krb5_types::{EncTicketPart, KerberosTime, OctetString, Ticket, TransitedEncoding, ku};

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
    let mut reseal_hex = None;
    let mut reseal_password = None;
    let mut reseal_principal = None;
    let mut authtime: Option<String> = None;
    let mut drop_starttime = false;
    let mut set_kvno: Option<u32> = None;
    let mut decrypt_keytab: Option<String> = None;
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
            "--reseal-key-hex" => {
                reseal_hex = args.get(i + 1).cloned();
                i += 2;
            }
            "--reseal-password" => {
                reseal_password = args.get(i + 1).cloned();
                i += 2;
            }
            "--reseal-principal" => {
                reseal_principal = args.get(i + 1).cloned();
                i += 2;
            }
            "--authtime" => {
                authtime = args.get(i + 1).cloned();
                i += 2;
            }
            "--drop-starttime" => {
                drop_starttime = true;
                i += 1;
            }
            "--set-kvno" => {
                set_kvno = args.get(i + 1).and_then(|v| v.parse::<u32>().ok());
                i += 2;
            }
            "--decrypt-keytab" => {
                decrypt_keytab = args.get(i + 1).cloned();
                i += 2;
            }
            _ => {
                eprintln!(
                    "usage: krb5-forge-tgt --ccache <in> --out <out> --tgt <krbtgt/REALM> \
                     (--claim-realm <realm> [--keep-cipher | --key-hex <hex> | --password <pw> --principal <name@REALM> | --decrypt-keytab <kt>] \
                     [--reseal-key-hex <hex> | --reseal-password <pw> --reseal-principal <name@REALM>] \
                     [--authtime <+secs|epoch>] [--drop-starttime] [--set-kvno <n>] \
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
    // `--decrypt-keytab` picks the key matching the ticket's own etype+kvno, so
    // callers do not have to know which enctype/kvno the KDC sealed a service
    // ticket under (a keytab can hold several).
    let keytab_keys: Option<Vec<(i32, u32, ProtocolKey)>> = match decrypt_keytab {
        None => None,
        Some(ref path) => match Keytab::parse(&fs::read(path).unwrap_or_default()) {
            Ok(kt) => Some(
                kt.entries
                    .iter()
                    .map(|e| (e.key.etype().to_iana(), e.kvno, e.key.clone()))
                    .collect(),
            ),
            Err(e) => {
                eprintln!("krb5-forge-tgt: decrypt-keytab: {e}");
                return ExitCode::from(2);
            }
        },
    };
    let (hex_for_decrypt, password_key) = match (key_hex, password, principal) {
        (Some(hex), None, None) => (Some(hex), None),
        (None, Some(pw), Some(princ)) => match key_from_password(&pw, &princ) {
            Ok(k) => (None, Some(k)),
            Err(e) => {
                eprintln!("krb5-forge-tgt: password: {e}");
                return ExitCode::from(2);
            }
        },
        (None, None, None) if keytab_keys.is_some() => (None, None),
        _ => {
            eprintln!(
                "krb5-forge-tgt: need --key-hex, --password plus --principal, or --decrypt-keytab"
            );
            return ExitCode::from(2);
        }
    };
    let reseal_override = match (reseal_hex, reseal_password, reseal_principal) {
        (None, None, None) => None,
        (Some(hex), None, None) => match parse_hex_key(&hex) {
            Ok(k) => Some(k),
            Err(e) => {
                eprintln!("krb5-forge-tgt: reseal-key-hex: {e}");
                return ExitCode::from(2);
            }
        },
        (None, Some(pw), Some(princ)) => match key_from_password(&pw, &princ) {
            Ok(k) => Some(k),
            Err(e) => {
                eprintln!("krb5-forge-tgt: reseal-password: {e}");
                return ExitCode::from(2);
            }
        },
        _ => {
            eprintln!(
                "krb5-forge-tgt: reseal needs --reseal-key-hex or --reseal-password plus --reseal-principal"
            );
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
    // `+N` is N seconds from now (a not-yet-valid ticket); a bare integer is an
    // absolute Unix time.
    let authtime_ts: Option<KerberosTime> = match authtime.as_deref() {
        None => None,
        Some(s) => {
            let ts = if let Some(rel) = s.strip_prefix('+') {
                match rel.parse::<i64>() {
                    Ok(n) => KerberosTime::now()
                        .add_seconds(n)
                        .unwrap_or_else(|_| KerberosTime::now()),
                    Err(e) => {
                        eprintln!("krb5-forge-tgt: --authtime: {e}");
                        return ExitCode::from(2);
                    }
                }
            } else {
                match s.parse::<u32>() {
                    Ok(n) => KerberosTime::from_unix_seconds(n),
                    Err(e) => {
                        eprintln!("krb5-forge-tgt: --authtime: {e}");
                        return ExitCode::from(2);
                    }
                }
            };
            Some(ts)
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
        // Ticket enc etype is first_current_key (profile order). --key-hex
        // bytes from dump-keytab must be wrapped as that etype, not always 18.
        let key = if let Some(ref keys) = keytab_keys {
            // Match the ticket's own etype, and its kvno when it carries one
            // (else the highest kvno for that etype).
            let et = ticket.enc_part.etype;
            let want_kvno = ticket.enc_part.kvno;
            let picked = keys
                .iter()
                .filter(|(kt_et, kvno, _)| *kt_et == et && want_kvno.is_none_or(|w| *kvno == w))
                .max_by_key(|(_, kvno, _)| *kvno)
                .map(|(_, _, k)| k.clone());
            let Some(k) = picked else {
                continue;
            };
            k
        } else if let Some(ref hex) = hex_for_decrypt {
            let Ok(et) = EncryptionType::from_iana(ticket.enc_part.etype)
                .or_else(|_| EncryptionType::known(ticket.enc_part.etype))
            else {
                continue;
            };
            let Ok(k) = parse_hex_key_as(hex, et) else {
                continue;
            };
            k
        } else if let Some(ref k) = password_key {
            k.clone()
        } else {
            return ExitCode::from(2);
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
        if let Some(ref at) = authtime_ts {
            part.authtime = at.clone();
        }
        if drop_starttime {
            part.starttime = None;
        }
        let der = match encode(&part) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("krb5-forge-tgt: encode EncTicketPart: {e}");
                return ExitCode::from(1);
            }
        };
        let reseal = reseal_override.as_ref().unwrap_or(&key);
        let cipher = match encrypt(reseal, usage, &der) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("krb5-forge-tgt: reseal: {e}");
                return ExitCode::from(1);
            }
        };
        ticket.enc_part.cipher = OctetString::from(cipher);
        ticket.enc_part.etype = reseal.etype().to_iana();
        if let Some(k) = set_kvno {
            ticket.enc_part.kvno = Some(k);
        }
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
    let et = match raw.len() {
        16 => EncryptionType::Aes128CtsHmacSha196,
        32 => EncryptionType::Aes256CtsHmacSha196,
        n => return Err(format!("key length {n} is not aes128 (16) or aes256 (32)")),
    };
    ProtocolKey::from_bytes(et, &raw).map_err(|e| e.to_string())
}

fn parse_hex_key_as(hex: &str, etype: EncryptionType) -> Result<ProtocolKey, String> {
    let raw = hex_decode(hex)?;
    ProtocolKey::from_bytes(etype, &raw).map_err(|e| e.to_string())
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
