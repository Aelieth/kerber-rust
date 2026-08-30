//! Zero and unlink a FILE ccache (MIT `kdestroy`).
//!
//! Usage: krb5-kdestroy [-c ccache]

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use krb5_config::{default_ccache_name, env_ccname};
use krb5_protocol::destroy_secret_file;

fn main() {
    let mut ccname = None::<PathBuf>;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a.as_str() == "-c" {
            ccname = args
                .next()
                .map(|s| PathBuf::from(s.strip_prefix("FILE:").unwrap_or(&s)));
        } else {
            eprintln!("usage: krb5-kdestroy [-c ccache]");
            std::process::exit(2);
        }
    }
    let path = ccname
        .or_else(env_ccname)
        .unwrap_or_else(default_ccache_name);
    if let Err(e) = destroy_secret_file(&path) {
        eprintln!("kdestroy: {e}");
        std::process::exit(1);
    }
}
