//! MIT `kprop`: send a replica KDC the dump file `kdb5_util dump` wrote.
//!
//! ```text
//! kprop [-r realm] [-f file] [-d] [-P port] [-s keytab] replica_host
//! ```
//!
//! The options are MIT's, read as its `getopt` reads them; any other prints the usage and exits
//! 1, as does a count of hosts other than one.
//! - `-r` names the realm, else krb5.conf's `default_realm`.
//! - `-f` names the dump, else `replica_datatrans` in the KDC directory. It must have a
//!   `<file>.dump_ok` mark no older than itself, which `kdb5_util dump` writes, and kprop locks
//!   it shared while it sends it.
//! - `-d` prints the bytes sent after each block.
//! - `-P` names the port, a number or a services name, else `krb5_prop` from `/etc/services`.
//! - `-s` names the keytab, else the default keytab (`KRB5_KTNAME`, else krb5.conf's
//!   `default_keytab_name`, else `/etc/krb5.keytab`).
//!
//! kprop never opens the KDC database and reads no KDC profile, as MIT's: it gets a ticket for
//! `host/<replica_host>` in one AS exchange with a KDC krb5.conf names, as `host/<this host>`
//! with that principal's key from the keytab, then sends the dump. Both names are MIT's without
//! DNS: a hostname without a dot gains `qualify_shortname`, else the resolver's first search
//! domain, and is lowercased. On the replica's acknowledgement it writes
//! `<file>.<replica_host>.last_prop` and prints `Database propagation to <replica_host>:
//! SUCCEEDED`. `KRB5_TRACE` traces it as MIT's.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

use std::process::exit;

use krb5_admin::{
    KPROP_SERVICE, KpropDump, KpropError, kprop_get_tickets, kprop_open_connection, kprop_sendauth,
    kprop_update_last_prop_file, kprop_xmit_database,
};

/// MIT `parse_args`'s results.
struct Args {
    realm: String,
    file: String,
    debug: bool,
    port: String,
    keytab: Option<String>,
    replica_host: String,
}

fn main() {
    let argv: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let progname = argv.first().cloned().unwrap_or_else(|| "kprop".to_owned());
    // MIT `main` (`kprop/kprop.c:100-105`): the library context first, its profile krb5.conf
    // alone; a profile it refuses ends kprop.
    let conf = krb5_config::init_profile().unwrap_or_else(|e| {
        eprintln!("{progname}: {} while initializing krb5", e.init_text());
        exit(1);
    });
    krb5_protocol::trace::init();
    let args = parse_args(&progname, argv.get(1..).unwrap_or_default(), &conf);
    let fail = |e: &KpropError| -> ! {
        for line in e.lines(&progname) {
            eprintln!("{line}");
        }
        exit(1);
    };
    // MIT `main` (`kprop/kprop.c:106-120`): tickets, the dump, the connection, sendauth, the
    // transfer, the `.last_prop` mark, the line on standard output, then the dump's unlock.
    let ctx = krb5_config::ClientContext::new(conf);
    let creds = kprop_get_tickets(
        &ctx,
        &args.realm,
        &args.replica_host,
        args.keytab.as_deref(),
    )
    .unwrap_or_else(|e| fail(&e));
    let mut dump = KpropDump::open(&args.file).unwrap_or_else(|e| fail(&e));
    let (mut stream, sender_addr) =
        kprop_open_connection(&args.replica_host, &args.port).unwrap_or_else(|e| fail(&e));
    let mut auth = kprop_sendauth(&mut stream, &creds, sender_addr).unwrap_or_else(|e| fail(&e));
    let size = dump.size();
    if let Err(e) = kprop_xmit_database(&mut stream, &mut auth, dump.file(), size, args.debug) {
        fail(&e);
    }
    if let Err(e) = kprop_update_last_prop_file(&args.replica_host, &args.file) {
        for line in e.lines(&progname) {
            eprintln!("{line}");
        }
    }
    println!("Database propagation to {}: SUCCEEDED", args.replica_host);
    if let Err(e) = dump.close() {
        for line in e.lines(&progname) {
            eprintln!("{line}");
        }
    }
    exit(0);
}

/// MIT `parse_args` (`kprop/kprop.c:122-162`): `getopt` with `r:f:dP:s:`, exactly one host
/// after the options, and without `-r` the default realm, whose absence ends kprop.
fn parse_args(progname: &str, args: &[String], conf: &krb5_config::Krb5Conf) -> Args {
    let (opts, rest) = krb5_cli::getopt(args, "r:f:dP:s:", &[]).unwrap_or_else(|e| {
        eprintln!("{progname}: {e}");
        usage(progname);
    });
    let mut realm = None;
    let mut file = None;
    let mut debug = false;
    let mut port = None;
    let mut keytab = None;
    for o in opts {
        match (o.flag, o.arg) {
            ('r', Some(a)) => realm = Some(a),
            ('f', Some(a)) => file = Some(a),
            ('d', _) => debug = true,
            ('P', Some(a)) => port = Some(a),
            ('s', Some(a)) => keytab = Some(a),
            _ => usage(progname),
        }
    }
    let [replica_host] = rest.as_slice() else {
        usage(progname);
    };
    // MIT `parse_args` (`kprop/kprop.c:154-161`): no realm prints this context alone (MIT passes
    // `errno`, 0 here, to `com_err`), exit 1.
    let realm = realm
        .or_else(|| conf.default_realm.clone())
        .unwrap_or_else(|| {
            eprintln!("{progname}: while getting default realm");
            exit(1);
        });
    Args {
        realm,
        file: file.unwrap_or_else(|| {
            krb5_config::default_kprop_file()
                .to_string_lossy()
                .into_owned()
        }),
        debug,
        port: port.unwrap_or_else(|| KPROP_SERVICE.to_owned()),
        keytab,
        replica_host: replica_host.clone(),
    }
}

/// MIT `usage` (`kprop/kprop.c:83-88`): the line between blank lines on standard error, exit 1.
fn usage(progname: &str) -> ! {
    eprintln!("\nUsage: {progname} [-r realm] [-f file] [-d] [-P port] [-s keytab] replica_host\n");
    exit(1);
}
