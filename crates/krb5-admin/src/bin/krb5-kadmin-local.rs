//! `kadmin.local`: MIT's local administration tool over the realm's database.
//! `test-hooks` build. No password comes from the environment: a principal's is `-pw` or the prompt's, and the master key is the stash's or, with `-m`, the one typed.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

fn main() {
    std::process::exit(krb5_admin::kadmin_local_main());
}
