//! `kadmin.local`: MIT's local administration tool over the realm's database.
//!
//! Usage: kadmin.local [-r realm] [-p principal] [-q query] [-d dbname] [-x db_args]
//! [-e "enc:salt ..."] [-m] [command args...]. With no `-q` and no command, commands are read
//! from stdin at the `kadmin.local:  ` prompt. The database and stash are the realm's in the KDC
//! profile ([`krb5_config::KdcPaths`]).

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

fn main() {
    std::process::exit(krb5_admin::kadmin_local_main());
}
