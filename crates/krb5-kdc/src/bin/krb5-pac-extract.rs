//! Decrypt a service ticket from a FILE ccache and write PAC bytes.
//!
//! Usage: `krb5-pac-extract --keytab <kt> --ccache <cc> --out <pac>`
//! Optional: `--enc-tkt-out`, `--krbtgt-keytab`, `--keys-out`.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::process::ExitCode;

use krb5_asn1::decode;
use krb5_crypto::{decrypt, string_to_key, EncryptionType, KeyUsage, ProtocolKey};
use krb5_kdc::{pac_from_ticket_part, s2k_params};
use krb5_protocol::{FileCcache, Keytab};
use krb5_types::pac::zero_pac_ad_data;
use krb5_types::{ku, EncTicketPart, Ticket};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--s2k") {
        return s2k_hex(&args);
    }
    let mut keytab = None;
    let mut ccache = None;
    let mut out = None;
    let mut enc_tkt_out = None;
    let mut krbtgt_kt = None;
    let mut keys_out = None;
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
            _ => {
                eprintln!(
                    "usage: krb5-pac-extract --keytab <kt> --ccache <cc> --out <pac> \
                     [--enc-tkt-out <der>] [--krbtgt-keytab <kt>] [--keys-out <txt>]"
                );
                return ExitCode::from(2);
            }
        }
    }
    let (Some(kt_path), Some(cc_path), Some(out_path)) = (keytab, ccache, out) else {
        eprintln!("usage: krb5-pac-extract --keytab <kt> --ccache <cc> --out <pac>");
        return ExitCode::from(2);
    };
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
            let Some(pac) = pac_from_ticket_part(&part) else {
                continue;
            };
            if fs::write(&out_path, &pac).is_err() {
                eprintln!("krb5-pac-extract: write {out_path}");
                return ExitCode::from(1);
            }
            if let Some(der_path) = &enc_tkt_out {
                let der = zero_pac_ad_data(&plain, &pac).unwrap_or(plain.clone());
                if fs::write(der_path, &der).is_err() {
                    eprintln!("krb5-pac-extract: write {der_path}");
                    return ExitCode::from(1);
                }
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
    match string_to_key(etype, args[1].as_bytes(), args[2].as_bytes(), Some(&params)) {
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
