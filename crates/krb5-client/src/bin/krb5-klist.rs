//! List tickets in a FILE ccache (MIT `klist -c` / `-f` / `-e`).
//!
//! Usage: krb5-klist [-c ccache] [-f] [-e]

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use krb5_asn1::decode;
use krb5_config::{default_ccache_name, env_ccname};
use krb5_crypto::EncryptionType;
use krb5_protocol::FileCcache;
use krb5_types::{Ticket, TicketFlags};

fn main() {
    let mut ccname = None::<PathBuf>;
    let mut show_flags = false;
    let mut show_etype = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => {
                ccname = args
                    .next()
                    .map(|s| PathBuf::from(s.strip_prefix("FILE:").unwrap_or(&s)));
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
    let path = ccname
        .or_else(env_ccname)
        .unwrap_or_else(default_ccache_name);
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
    }
    Ok(())
}

fn fmt_unix(t: u32) -> String {
    let t = i64::from(t);
    let days = t.div_euclid(86_400);
    let rem = t.rem_euclid(86_400);
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = civil_from_days(days);
    format!("{mo:02}/{d:02}/{y:02} {h:02}:{m:02}:{s:02}")
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y.rem_euclid(100), mo, d)
}
