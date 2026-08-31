//! Zero and unlink a FILE ccache (MIT `kdestroy`).
//!
//! Usage: krb5-kdestroy [-c ccache]

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use krb5_client::cli::parse_kdestroy;
use krb5_client::destroy_ccache;
use krb5_config::resolve_ccspec;

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_kdestroy(&raw).unwrap_or_else(|e| {
        eprintln!("kdestroy: {e}");
        std::process::exit(2);
    });
    let spec = resolve_ccspec(args.ccache.as_deref()).unwrap_or_else(|e| {
        eprintln!("kdestroy: {e}");
        std::process::exit(2);
    });
    if let Err(e) = destroy_ccache(&spec) {
        eprintln!("kdestroy: {e}");
        std::process::exit(1);
    }
}
