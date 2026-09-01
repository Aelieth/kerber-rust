//! Decrypt a service ticket from a FILE ccache and write PAC bytes.
//!
//! Usage: `krb5-pac-extract --keytab <kt> --ccache <cc> --out <pac>`
//! Optional: `--enc-tkt-out` (raw decrypted EncTicketPart), `--krbtgt-keytab`, `--keys-out`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::process::ExitCode;

use krb5_asn1::decode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, string_to_key};
use krb5_kdc::{pac_from_ticket_part, s2k_params};
use krb5_protocol::{FileCcache, Keytab};
use krb5_types::{EncTicketPart, Ticket, ku};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--s2k")
        || args.first().map(String::as_str) == Some("--s2k-hex")
    {
        return s2k_hex(&args);
    }
    if args.first().map(String::as_str) == Some("--dump-keytab") {
        return dump_keytab(&args);
    }
    let mut keytab = None;
    let mut ccache = None;
    let mut out = None;
    let mut enc_tkt_out = None;
    let mut krbtgt_kt = None;
    let mut keys_out = None;
    let mut print_rid = false;
    let mut print_transited = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--keytab" => {
                keytab = args.get(i + 1).cloned();
                i += 2;
            }
            "--ccache" => {
                ccache = args.get(i + 1).cloned();
                i += 2;
            }
            "--out" => {
                out = args.get(i + 1).cloned();
                i += 2;
            }
            "--enc-tkt-out" => {
                enc_tkt_out = args.get(i + 1).cloned();
                i += 2;
            }
            "--krbtgt-keytab" => {
                krbtgt_kt = args.get(i + 1).cloned();
                i += 2;
            }
            "--keys-out" => {
                keys_out = args.get(i + 1).cloned();
                i += 2;
            }
            "--print-rid" => {
                print_rid = true;
                i += 1;
            }
            "--print-transited" => {
                print_transited = true;
                i += 1;
            }
            _ => {
                eprintln!(
                    "usage: krb5-pac-extract --keytab <kt> --ccache <cc> [--out <pac>] \
                     [--enc-tkt-out <der>] [--krbtgt-keytab <kt>] [--keys-out <txt>] \
                     [--print-rid] [--print-transited]"
                );
                return ExitCode::from(2);
            }
        }
    }
    let (Some(kt_path), Some(cc_path)) = (keytab, ccache) else {
        eprintln!(
            "usage: krb5-pac-extract --keytab <kt> --ccache <cc> [--out <pac>] [--print-transited]"
        );
        return ExitCode::from(2);
    };
    if out.is_none() && !print_transited {
        eprintln!("usage: krb5-pac-extract --keytab <kt> --ccache <cc> --out <pac>");
        return ExitCode::from(2);
    }
    let kt = match Keytab::parse(&fs::read(&kt_path).unwrap_or_default()) {
        Ok(k) if !k.entries.is_empty() => k,
        _ => {
            eprintln!("krb5-pac-extract: bad keytab {kt_path}");
            return ExitCode::from(1);
        }
    };
    let cc = match FileCcache::parse(&fs::read(&cc_path).unwrap_or_default()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("krb5-pac-extract: ccache: {e}");
            return ExitCode::from(1);
        }
    };
    let kdc_key = krbtgt_kt.as_ref().and_then(|p| {
        Keytab::parse(&fs::read(p).unwrap_or_default())
            .ok()
            .and_then(|kt| preferred_key(&kt))
    });
    let usage = match KeyUsage::new(ku::TICKET) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("krb5-pac-extract: usage: {e}");
            return ExitCode::from(1);
        }
    };
    for cred in &cc.creds {
        if cred.is_config() {
            continue;
        }
        let sname = cred.server.1.components_joined();
        if !sname.starts_with("host/") {
            continue;
        }
        let ticket: Ticket = match decode(&cred.ticket) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("krb5-pac-extract: ticket DER: {e}");
                return ExitCode::from(1);
            }
        };
        for ent in &kt.entries {
            let Ok(plain) = decrypt(&ent.key, usage, ticket.enc_part.cipher.as_ref()) else {
                continue;
            };
            let Ok(part) = decode::<EncTicketPart>(&plain) else {
                continue;
            };
            if print_transited {
                let contents = String::from_utf8_lossy(part.transited.contents.as_ref());
                let checked = i32::from(
                    part.flags
                        .bit(krb5_types::flag_bit::TRANSITED_POLICY_CHECKED),
                );
                println!("transited_tr_type={}", part.transited.tr_type);
                println!("transited_contents={contents}");
                println!("transited_realms={}", part.transited.realms().join(","));
                println!("transited_policy_checked={checked}");
                if out.is_none() {
                    return ExitCode::SUCCESS;
                }
            }
            let Some(out_path) = out.as_ref() else {
                return ExitCode::SUCCESS;
            };
            let Some(pac) = pac_from_ticket_part(&part) else {
                if print_transited {
                    return ExitCode::SUCCESS;
                }
                continue;
            };
            if print_rid {
                let rid = krb5_types::pac::Pac::parse(&pac).ok().and_then(|parsed| {
                    parsed
                        .buffer(krb5_types::pac::PAC_LOGON_INFO)
                        .and_then(|b| krb5_types::pac::parse_kerb_validation_info(b).ok())
                        .map(|v| v.user_id)
                });
                let Some(rid) = rid else {
                    eprintln!("krb5-pac-extract: no PAC_LOGON_INFO");
                    return ExitCode::from(1);
                };
                println!("pac_rid={rid}");
            }
            if fs::write(&out_path, &pac).is_err() {
                eprintln!("krb5-pac-extract: write {out_path}");
                return ExitCode::from(1);
            }
            if let Some(der_path) = &enc_tkt_out
                && fs::write(der_path, &plain).is_err()
            {
                eprintln!("krb5-pac-extract: write {der_path}");
                return ExitCode::from(1);
            }
            if let Some(keys_path) = &keys_out {
                let etype = ent.key.etype().to_iana();
                let server = hex_bytes(ent.key.as_bytes());
                let kdc = kdc_key
                    .as_ref()
                    .map(|k| hex_bytes(k.as_bytes()))
                    .unwrap_or_default();
                let body = format!("etype={etype}\nserver={server}\nkdc={kdc}\n");
                if fs::write(keys_path, body).is_err() {
                    eprintln!("krb5-pac-extract: write {keys_path}");
                    return ExitCode::from(1);
                }
            }
            eprintln!(
                "krb5-pac-extract: wrote {} PAC bytes for {sname}",
                pac.len()
            );
            return ExitCode::SUCCESS;
        }
        eprintln!("krb5-pac-extract: no PAC in {sname} (or key mismatch)");
        return ExitCode::from(1);
    }
    eprintln!("krb5-pac-extract: no host/ ticket in ccache");
    ExitCode::from(1)
}

fn preferred_key(kt: &Keytab) -> Option<ProtocolKey> {
    EncryptionType::preferred()
        .into_iter()
        .find_map(|e| {
            kt.entries
                .iter()
                .find(|ent| ent.key.etype() == e)
                .map(|ent| ent.key.clone())
        })
        .or_else(|| kt.entries.first().map(|e| e.key.clone()))
}

fn dump_keytab(args: &[String]) -> ExitCode {
    if args.len() != 2 {
        eprintln!("usage: krb5-pac-extract --dump-keytab <kt>");
        return ExitCode::from(2);
    }
    let kt = match Keytab::parse(&fs::read(&args[1]).unwrap_or_default()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("krb5-pac-extract: keytab: {e}");
            return ExitCode::from(1);
        }
    };
    for e in &kt.entries {
        println!(
            "KEY {} {} {}",
            e.key.etype().to_iana(),
            hex_bytes(e.key.as_bytes()),
            e.name.components_joined()
        );
    }
    ExitCode::SUCCESS
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

fn hex_bytes(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(char::from(HEX[usize::from(x >> 4)]));
        s.push(char::from(HEX[usize::from(x & 0x0f)]));
    }
    s
}

fn s2k_hex(args: &[String]) -> ExitCode {
    if args.len() != 3 {
        eprintln!("usage: krb5-pac-extract --s2k <password> <salt>");
        return ExitCode::from(2);
    }
    let etype = EncryptionType::Aes256CtsHmacSha196;
    let params = s2k_params(etype);
    let pw = if args[0] == "--s2k-hex" {
        match hex_decode(&args[1]) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("krb5-pac-extract: s2k-hex: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        args[1].as_bytes().to_vec()
    };
    match string_to_key(etype, &pw, args[2].as_bytes(), Some(&params)) {
        Ok(key) => {
            for b in key.as_bytes() {
                print!("{b:02x}");
            }
            println!();
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("krb5-pac-extract: s2k: {e}");
            ExitCode::from(1)
        }
    }
}
