//! Mint a sendauth AP-REQ whose ticket endtime is in the past.
//!
//! Usage: `kprop-expired-apreq KEYTAB SNAME REALM` — DER on stdout.

use std::io::Write;

use krb5_protocol::Keytab;
use krb5_types::PrincipalName;

fn main() {
    let mut args = std::env::args().skip(1);
    let kt_path = args.next().unwrap_or_else(|| usage());
    let sname = args.next().unwrap_or_else(|| usage());
    let realm = args.next().unwrap_or_else(|| usage());
    let bytes = std::fs::read(&kt_path).unwrap_or_else(|e| {
        eprintln!("kprop-expired-apreq: read {kt_path}: {e}");
        std::process::exit(1);
    });
    let kt = Keytab::parse(&bytes).unwrap_or_else(|e| {
        eprintln!("kprop-expired-apreq: keytab: {e}");
        std::process::exit(1);
    });
    let comps: Vec<&str> = sname.split('/').collect();
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, comps);
    let ent = kt
        .entries
        .iter()
        .find(|e| e.name.components_joined() == host.components_joined())
        .unwrap_or_else(|| {
            eprintln!("kprop-expired-apreq: no {sname} in {kt_path}");
            std::process::exit(1);
        });
    let der =
        krb5_admin::kprop_expired_ap_req(&ent.key, ent.kvno, &host, &realm).unwrap_or_else(|e| {
            eprintln!("kprop-expired-apreq: {e}");
            std::process::exit(1);
        });
    std::io::stdout().write_all(&der).unwrap_or_else(|e| {
        eprintln!("kprop-expired-apreq: stdout: {e}");
        std::process::exit(1);
    });
}

fn usage() -> ! {
    eprintln!("usage: kprop-expired-apreq KEYTAB SNAME REALM");
    std::process::exit(2);
}
