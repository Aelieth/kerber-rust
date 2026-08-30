//! MIT-style ktutil: rkt/list/wkt/addent/delent on an in-memory keytab.
//!
//! Commands from argv (one shot) or stdin. Passwords from `KRB5_PASSWORD`
//! or stdin, never argv.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::fmt::Write as _;
use std::io::{self, BufRead, Write};
use std::path::Path;

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_protocol::{Keytab, KeytabEntry, parse_principal};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut kt = Keytab {
        version: 0x0502,
        entries: Vec::new(),
        skipped_unknown_etype: 0,
    };
    if args.is_empty() {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else {
                break;
            };
            if let Err(e) = run_line(&mut kt, &line) {
                eprintln!("ktutil: {e}");
            }
        }
        return;
    }
    if let Err(e) = run_line(&mut kt, &args.join(" ")) {
        eprintln!("ktutil: {e}");
        std::process::exit(1);
    }
}

fn run_line(kt: &mut Keytab, line: &str) -> Result<(), String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(());
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.first().copied() {
        Some("q" | "quit" | "exit") => std::process::exit(0),
        Some("rkt") => {
            let path = parts.get(1).ok_or("rkt <file>")?;
            let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
            let other = Keytab::parse(&bytes).map_err(|e| e.to_string())?;
            kt.version = other.version;
            kt.merge(other);
            Ok(())
        }
        Some("wkt") => {
            let path = parts.get(1).ok_or("wkt <file>")?;
            kt.write_file(Path::new(path)).map_err(|e| e.to_string())
        }
        Some("list" | "l") => {
            print!(
                "{}",
                format_list(
                    kt,
                    parts.contains(&"-t"),
                    parts.contains(&"-e"),
                    parts.contains(&"-K"),
                )
            );
            Ok(())
        }
        Some("delent") => {
            let slot: usize = parts
                .get(1)
                .ok_or("delent <slot>")?
                .parse()
                .map_err(|_| "delent slot")?;
            if slot == 0 || slot > kt.entries.len() {
                return Err("no such slot".into());
            }
            kt.entries.remove(slot - 1);
            Ok(())
        }
        Some("addent") => addent(kt, &parts[1..]),
        Some(other) => Err(format!("unknown command {other}")),
        None => Ok(()),
    }
}

fn format_list(kt: &Keytab, show_t: bool, show_e: bool, show_k: bool) -> String {
    let mut out = String::from("slot KVNO Principal\n");
    for (i, e) in kt.entries.iter().enumerate() {
        let princ = format!(
            "{}@{}",
            e.name.components_joined(),
            String::from_utf8_lossy(e.realm.as_bytes())
        );
        let _ = write!(out, "{:>4} {:>4} {princ}", i + 1, e.kvno);
        if show_t {
            let _ = write!(out, " t={}", e.timestamp);
        }
        if show_e {
            let _ = write!(out, " {}", e.key.etype().to_mit_name());
        }
        if show_k {
            let _ = write!(out, " ({})", hex(e.key.as_bytes()));
        }
        out.push('\n');
    }
    out
}

fn addent(kt: &mut Keytab, args: &[&str]) -> Result<(), String> {
    let mut password = false;
    let mut hexkey = false;
    let mut princ = None::<String>;
    let mut kvno = 1u32;
    let mut etype = EncryptionType::Aes256CtsHmacSha196;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-password" => password = true,
            "-key" => hexkey = true,
            "-p" => {
                i += 1;
                princ = args.get(i).map(|s| (*s).to_owned());
            }
            "-k" => {
                i += 1;
                kvno = args
                    .get(i)
                    .ok_or("-k <kvno>")?
                    .parse()
                    .map_err(|_| "kvno")?;
            }
            "-e" => {
                i += 1;
                etype = EncryptionType::from_mit_name(args.get(i).ok_or("-e <etype>")?)
                    .map_err(|e| e.to_string())?;
            }
            other => return Err(format!("addent: unknown {other}")),
        }
        i += 1;
    }
    let spec = princ.ok_or("addent -p principal")?;
    let (name, realm) = parse_principal(&spec)?;
    let key = if hexkey {
        let mut s = String::new();
        print!("Key for {spec}: ");
        let _ = io::stdout().flush();
        io::stdin().read_line(&mut s).map_err(|e| e.to_string())?;
        let raw = parse_hex(s.trim())?;
        ProtocolKey::from_bytes(etype, &raw).map_err(|e| e.to_string())?
    } else if password {
        let pw = std::env::var("KRB5_PASSWORD").unwrap_or_else(|_| {
            let mut s = String::new();
            print!("Password for {spec}: ");
            let _ = io::stdout().flush();
            let _ = io::stdin().read_line(&mut s);
            s.trim_end_matches(['\n', '\r']).to_owned()
        });
        let salt = name.default_salt(&realm);
        string_to_key(etype, pw.as_bytes(), salt, Some(&4096u32.to_be_bytes()))
            .map_err(|e| e.to_string())?
    } else {
        return Err("addent needs -password or -key".into());
    };
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(0));
    kt.entries.push(KeytabEntry {
        realm: krb5_types::ascii(&realm),
        name,
        timestamp,
        kvno,
        key,
    });
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "hex".to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_crypto::ProtocolKey;
    use krb5_types::{PrincipalName, ascii};

    #[test]
    fn run_line_list_e_prints_etype() {
        let key = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[3u8; 32]).unwrap();
        let mut kt = Keytab {
            version: 0x0502,
            entries: vec![KeytabEntry {
                realm: ascii("KERBER.TEST"),
                name: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
                timestamp: 1_700_000_000,
                kvno: 2,
                key,
            }],
            skipped_unknown_etype: 0,
        };
        run_line(&mut kt, "list -e").unwrap();
        let text = format_list(&kt, false, true, false);
        assert!(text.contains("user@KERBER.TEST"), "{text}");
        assert!(text.contains("aes256-cts-hmac-sha1-96"), "{text}");
        assert!(text.contains("   2"), "{text}");
    }
}
