//! RFC 3244 kpasswd client. TCP 464 first, then UDP.
//!
//! Usage: krb5-kpasswd <kdc-host> <user@REALM>
//! Old password: `KRB5_PASSWORD`. New: `KRB5_NEW_PASSWORD`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use krb5_protocol::{AsRequest, KdcAddr, as_exchange, change_password, parse_principal};
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
    let r = run(&host, &princ, old.as_bytes(), new.as_bytes());
    old.zeroize();
    new.zeroize();
    if let Err(e) = r {
        eprintln!("kpasswd: {e}");
        std::process::exit(1);
    }
    println!("ok");
}

fn run(host: &str, princ: &str, old: &[u8], new: &[u8]) -> Result<(), String> {
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
    change_password(&kdc, &as_out, new).map_err(|e| e.to_string())
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
