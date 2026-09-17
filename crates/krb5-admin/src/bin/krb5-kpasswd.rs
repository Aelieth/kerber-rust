//! RFC 3244 kpasswd client. TCP 464 first, then UDP.
//!
//! Usage: `krb5-kpasswd <kdc-host> <user@REALM>`
//! Old password: `KRB5_PASSWORD`. New: `KRB5_NEW_PASSWORD`.
//! `KRB5_KPASSWD_TARGET=name@REALM` uses `krb5_set_password` (0xff80).

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use krb5_protocol::{
    AsRequest, KdcAddr, as_exchange, change_password, parse_principal, set_password,
};
use krb5_types::PrincipalName;
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
    let target = std::env::var("KRB5_KPASSWD_TARGET").ok();
    let r = run(
        &host,
        &princ,
        old.as_bytes(),
        new.as_bytes(),
        target.as_deref(),
    );
    old.zeroize();
    new.zeroize();
    match r {
        Ok(()) => println!("ok"),
        Err(e) => {
            let line = e.strip_prefix("reply validation: ").unwrap_or(e.as_str());
            if is_chpw_result_line(line) {
                println!("{line}");
                std::process::exit(2);
            }
            eprintln!("kpasswd: {e}");
            std::process::exit(1);
        }
    }
}

fn is_chpw_result_line(line: &str) -> bool {
    line.starts_with("Success")
        || line.starts_with("Malformed request error")
        || line.starts_with("Server error")
        || line.starts_with("Authentication error")
        || line.starts_with("Password change rejected")
        || line.starts_with("Access denied")
        || line.starts_with("Wrong protocol version")
        || line.starts_with("Initial password required")
        || line.starts_with("Password change failed")
}

fn run(
    host: &str,
    princ: &str,
    old: &[u8],
    new: &[u8],
    target: Option<&str>,
) -> Result<(), String> {
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
        etypes: None,
        ticket: krb5_protocol::AsTicketOpts::default(),
    })
    .map_err(|e| e.to_string())?;
    if let Some(raw) = target {
        let (tname, trealm) = parse_principal(raw)?;
        set_password(&kdc, &as_out, new, (&krb5_protocol::realm(&trealm), &tname))
            .map_err(|e| e.to_string())
    } else {
        change_password(&kdc, &as_out, new).map_err(|e| e.to_string())
    }
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
