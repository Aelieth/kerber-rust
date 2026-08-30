//! List tickets in a FILE ccache (MIT `klist -c` / `-f` / `-e`).
//!
//! Usage: krb5-klist [-c ccache] [-f] [-e]

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use krb5_asn1::decode;
use krb5_config::resolve_ccname;
use krb5_crypto::EncryptionType;
use krb5_protocol::FileCcache;
use krb5_types::{Ticket, TicketFlags};

fn main() {
    let mut ccname = None::<String>;
    let mut show_flags = false;
    let mut show_etype = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => {
                let Some(s) = args.next() else {
                    eprintln!("klist: missing -c argument");
                    std::process::exit(2);
                };
                ccname = Some(s);
            }
            "-f" => show_flags = true,
            "-e" => show_etype = true,
            "-fe" | "-ef" => {
                show_flags = true;
                show_etype = true;
            }
            _ => {
                eprintln!("usage: krb5-klist [-c ccache] [-f] [-e]");
                std::process::exit(2);
            }
        }
    }
    let path = resolve_ccname(ccname.as_deref()).unwrap_or_else(|e| {
        eprintln!("klist: {e}");
        std::process::exit(2);
    });
    if let Err(e) = list(&path, show_flags, show_etype) {
        eprintln!("klist: {e}");
        std::process::exit(1);
    }
}

fn list(path: &Path, show_flags: bool, show_etype: bool) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let cc = FileCcache::parse(&bytes).map_err(|e| e.to_string())?;
    println!("Ticket cache: FILE:{}", path.display());
    println!(
        "Default principal: {}",
        FileCcache::format_principal(&cc.primary.0, &cc.primary.1)
    );
    println!();
    println!("Valid starting     Expires            Service principal");
    for cred in cc.list() {
        let server = FileCcache::format_principal(&cred.server.0, &cred.server.1);
        println!(
            "{:>17}  {:>17}  {server}",
            fmt_unix(cred.starttime),
            fmt_unix(cred.endtime)
        );
        if cred.renew_till > 0 {
            println!("\trenew until {}", fmt_unix(cred.renew_till));
        }
        if show_flags {
            let letters = TicketFlags::from_u32(cred.ticket_flags).mit_letters();
            println!("\tFlags: {letters}");
        }
        if show_etype {
            let skey = cred.key.etype().to_mit_name();
            let tkt = decode::<Ticket>(&cred.ticket)
                .ok()
                .and_then(|t| EncryptionType::known(t.enc_part.etype).ok())
                .map_or("unknown", EncryptionType::to_mit_name);
            println!("\tEtype (skey, tkt): {skey}, {tkt}");
        }
        println!("\tTicket server: {server}");
    }
    Ok(())
}

fn fmt_unix(t: u32) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_opt(i64::from(t), 0) {
        chrono::LocalResult::Single(dt) => dt.format("%m/%d/%y %H:%M:%S").to_string(),
        _ => format!("{t}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_unix_has_mit_date_shape() {
        let s = fmt_unix(1_700_000_000);
        assert_eq!(s.matches('/').count(), 2);
        assert!(s.contains(':'));
    }
}
