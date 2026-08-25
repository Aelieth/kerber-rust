//! Decrypt a service ticket from a FILE ccache and write PAC bytes.
//!
//! Usage: `krb5-pac-extract --keytab <kt> --ccache <cc> --out <pac>`

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::process::ExitCode;

use krb5_asn1::decode;
use krb5_crypto::{string_to_key, EncryptionType};
use krb5_kdc::{decrypt_ticket_part, pac_from_ticket_part, s2k_params};
use krb5_protocol::{FileCcache, Keytab};
use krb5_types::Ticket;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--s2k") {
        return s2k_hex(&args);
    }
    let mut keytab = None;
    let mut ccache = None;
    let mut out = None;
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
            _ => {
                eprintln!("usage: krb5-pac-extract --keytab <kt> --ccache <cc> --out <pac>");
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
            if let Ok(part) = decrypt_ticket_part(&ent.key, &ticket) {
                if let Some(pac) = pac_from_ticket_part(&part) {
                    if fs::write(&out_path, &pac).is_err() {
                        eprintln!("krb5-pac-extract: write {out_path}");
                        return ExitCode::from(1);
                    }
                    eprintln!(
                        "krb5-pac-extract: wrote {} PAC bytes for {sname}",
                        pac.len()
                    );
                    return ExitCode::SUCCESS;
                }
            }
        }
        eprintln!("krb5-pac-extract: no PAC in {sname} (or key mismatch)");
        return ExitCode::from(1);
    }
    eprintln!("krb5-pac-extract: no host/ ticket in ccache");
    ExitCode::from(1)
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
