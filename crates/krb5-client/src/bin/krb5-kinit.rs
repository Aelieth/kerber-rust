//! Obtain a TGT from a KDC and write an MIT FILE ccache.
//!
//! Usage: krb5-kinit <kdc-host> <user@REALM> <password> <ccache-path> [service]

use krb5_client::kinit;
use krb5_protocol::KdcAddr;

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter("krb5_crypto=info,krb5_asn1=info,krb5_protocol=info,krb5_client=info")
        .try_init();

    let mut args = std::env::args().skip(1);
    let host = args.next().expect("kdc-host");
    let principal = args.next().expect("user@REALM");
    let mut password = args.next().expect("password").into_bytes();
    let ccache = args.next().expect("ccache-path");
    let service = args.next();
    let addr = KdcAddr::new(host);
    match kinit(
        &addr,
        &principal,
        &mut password,
        &ccache,
        service.as_deref(),
    ) {
        Ok(r) => {
            println!(
                "ok tgt={} tgs={}",
                r.as_out.enc_part.sname.name_string.len(),
                r.tgs_out.is_some()
            );
        }
        Err(e) => {
            eprintln!("kinit failed: {e}");
            std::process::exit(1);
        }
    }
}
