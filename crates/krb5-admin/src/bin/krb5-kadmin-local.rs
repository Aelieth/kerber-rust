//! `kadmin.local`: MIT's local administration tool over the realm's database.
//! No password comes from the environment.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

fn main() {
    std::process::exit(krb5_admin::kadmin_local_main());
}
