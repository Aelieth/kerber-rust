//! `kadmin`: MIT's remote administration client over kadmind.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

fn main() {
    std::process::exit(krb5_admin::kadmin_main());
}
