//! `kadmin.local`: MIT's local administration tool over the realm's database.
//!
//! Usage: kadmin.local [-r realm] [-p principal] [-q query] [-d dbname] [-x db_args]
//! [-e "enc:salt ..."] [-m] [command args...]. With no `-q` and no command, commands are read
//! from stdin at the `kadmin.local:  ` prompt. The database and stash are the realm's in the KDC
//! profile ([`krb5_config::KdcPaths`]); the resolver's `KRB5_KDC_DB`, `KRB5_KDC_STASH`,
//! `KRB5_ACL_FILE`, `KRB5_MASTER_ETYPE` and `KRB5_KDC_CONF` overrides exist only in a
//! `test-hooks` build. No password comes from the environment: a principal's is `-pw` or the
//! prompt's, and the master key is the stash's or, with `-m`, the one typed.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

fn main() {
    std::process::exit(krb5_admin::kadmin_local_main());
}
