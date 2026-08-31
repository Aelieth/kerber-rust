//! List tickets in a FILE ccache (MIT `klist -c` / `-f` / `-e`).
//!
//! Usage: krb5-klist [-c ccache] [-f] [-e]

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::fmt::Write as _;
use std::path::Path;

use krb5_asn1::decode;
use krb5_config::resolve_ccname;
use krb5_crypto::EncryptionType;
use krb5_protocol::{CcacheCred, FileCcache};
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
    print!("{}", cache_text(path, show_flags, show_etype)?);
    Ok(())
}

fn cache_text(path: &Path, show_flags: bool, show_etype: bool) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let cc = FileCcache::parse(&bytes).map_err(|e| e.to_string())?;
    Ok(format_cache(&cc, path, show_flags, show_etype))
}

fn format_cache(cc: &FileCcache, path: &Path, show_flags: bool, show_etype: bool) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Ticket cache: FILE:{}", path.display());
    let _ = writeln!(
        out,
        "Default principal: {}",
        FileCcache::format_principal(&cc.primary.0, &cc.primary.1)
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Valid starting     Expires            Service principal"
    );
    for cred in cc.list() {
        format_cred(&mut out, cred, show_flags, show_etype);
    }
    out
}

fn format_cred(out: &mut String, cred: &CcacheCred, show_flags: bool, show_etype: bool) {
    let server = FileCcache::format_principal(&cred.server.0, &cred.server.1);
    let _ = writeln!(
        out,
        "{:>17}  {:>17}  {server}",
        fmt_unix(cred.starttime),
        fmt_unix(cred.endtime)
    );
    if cred.renew_till > 0 {
        let _ = writeln!(out, "\trenew until {}", fmt_unix(cred.renew_till));
    }
    if show_flags {
        let letters = TicketFlags::from_u32(cred.ticket_flags).mit_letters();
        let _ = writeln!(out, "\tFlags: {letters}");
    }
    if show_etype {
        let skey = cred
            .session_key()
            .map_or("unknown", |k| k.etype().to_mit_name());
        let tkt = decode::<Ticket>(&cred.ticket)
            .ok()
            .and_then(|t| EncryptionType::known(t.enc_part.etype).ok())
            .map_or("unknown", EncryptionType::to_mit_name);
        let _ = writeln!(out, "\tEtype (skey, tkt): {skey}, {tkt}");
    }
    if let Some(ts) = cred_ticket_server(cred) {
        let _ = writeln!(out, "\tTicket server: {ts}");
    }
}

fn cred_ticket_server(cred: &CcacheCred) -> Option<String> {
    let tkt = decode::<Ticket>(&cred.ticket).ok()?;
    let tkt_s = FileCcache::format_principal(&tkt.realm, &tkt.sname);
    let cred_s = FileCcache::format_principal(&cred.server.0, &cred.server.1);
    (tkt_s != cred_s).then_some(tkt_s)
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
    use krb5_types::PrincipalName;

    #[test]
    fn fmt_unix_has_mit_date_shape() {
        let s = fmt_unix(1_700_000_000);
        assert_eq!(s.matches('/').count(), 2);
        assert!(s.contains(':'));
    }

    fn sample_cred(renew_till: u32) -> CcacheCred {
        let realm = krb5_protocol::realm("KERBER.TEST");
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let key =
            krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[0u8; 16])
                .unwrap();
        CcacheCred {
            client: (realm.clone(), user.clone()),
            server: (realm, PrincipalName::krbtgt("KERBER.TEST")),
            key: krb5_protocol::CcacheKeyblock::from_protocol(&key),
            authtime: 1_700_000_000,
            starttime: 1_700_000_000,
            endtime: 1_700_360_000,
            renew_till,
            is_skey: 0,
            ticket_flags: 0,
            addresses: Vec::new(),
            authdata: Vec::new(),
            ticket: Vec::new(),
            second_ticket: Vec::new(),
        }
    }

    #[test]
    fn format_cred_prints_renew_until_when_set() {
        let cred = sample_cred(1_700_720_000);
        let mut out = String::new();
        format_cred(&mut out, &cred, false, false);
        assert!(out.contains("renew until"), "{out}");
        assert!(!out.contains("Ticket server:"), "{out}");
        let mut none = String::new();
        format_cred(&mut none, &sample_cred(0), false, false);
        assert!(!none.contains("renew until"), "{none}");
    }

    #[test]
    fn ticket_server_only_when_sname_differs() {
        use krb5_asn1::encode;
        use krb5_types::{EncryptedData, OctetString, ascii};
        let mut cred = sample_cred(0);
        let tkt = Ticket {
            tkt_vno: Ticket::VNO,
            realm: ascii("KERBER.TEST"),
            sname: PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![0u8; 16]),
            },
        };
        cred.ticket = encode(&tkt).unwrap();
        let mut out = String::new();
        format_cred(&mut out, &cred, false, false);
        assert!(
            out.contains("Ticket server: host/testhost.kerber.test@KERBER.TEST"),
            "{out}"
        );
        cred.server = (
            krb5_protocol::realm("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]),
        );
        let mut same = String::new();
        format_cred(&mut same, &cred, false, false);
        assert!(!same.contains("Ticket server:"), "{same}");
    }

    #[test]
    fn list_file_ccache_prints_renew_until() {
        let cred = sample_cred(1_700_720_000);
        let cc = FileCcache::new(cred.client.clone(), vec![cred]);
        let path = std::env::temp_dir().join(format!(
            "krb5cc-klist-renew-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        cc.write_file(&path).unwrap();
        list(&path, false, false).unwrap();
        let text = cache_text(&path, false, false).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(text.contains("renew until"), "{text}");
        assert!(text.contains("krbtgt/KERBER.TEST@KERBER.TEST"), "{text}");
    }
}
