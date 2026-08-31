//! Zero and unlink a FILE ccache (MIT `kdestroy`).
//!
//! Usage: krb5-kdestroy [-c ccache]

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use krb5_client::destroy_ccache;
use krb5_config::resolve_ccspec;

fn main() {
    let mut ccname = None::<String>;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a.as_str() == "-c" {
            let Some(s) = args.next() else {
                eprintln!("kdestroy: missing -c argument");
                std::process::exit(2);
            };
            ccname = Some(s);
        } else {
            eprintln!("usage: krb5-kdestroy [-c ccache]");
            std::process::exit(2);
        }
    }
    let spec = resolve_ccspec(ccname.as_deref()).unwrap_or_else(|e| {
        eprintln!("kdestroy: {e}");
        std::process::exit(2);
    });
    if let Err(e) = destroy_ccache(&spec) {
        eprintln!("kdestroy: {e}");
        std::process::exit(1);
    }
}
