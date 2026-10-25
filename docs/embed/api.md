# Embed API

## Bootstrap

`bootstrap_realm_into` fills a store the caller owns. It creates only the
K/M, krbtgt, `kadmin/admin`, `kadmin/changepw`, and optional admin rows that
are missing, and it does not rotate a key that is already there. An existing
realm stamps each new row with the active K/M kvno (`TL_ACTKVNO`, else the
newest key). A new realm uses `RealmSpec.mkvno`; `kdb5_util create` uses 1,
and so does `embed-realm`. `Bootstrapped.kvno` is that kvno. The admin
requires pre-auth unless `AdminSpec` says otherwise. The keytab comes back
on `Bootstrapped` for the caller to write.

`create_database` writes the stash (a temp file renamed into place, mode 0600),
then both lock files, then the database by renaming a finished temp file into
place. That rename is the commit. A re-run that finds the stash and no database
reuses that master and kvno. A database with no lock file is refused, as an
open is.

`open_or_create` does that open-or-create — a present database is opened, a stash
with no database resumes its master and kvno, else a new random master — then
`bootstrap_realm_into` and `create_database`, returning the store and `Bootstrapped`.
`examples/embed-realm --bootstrap-only` calls it and writes
`admin.keytab` beside the database. A store takes the realm's lifetimes, flags,
and enctypes only after `apply_profile`, and `embed-realm` applies it before
`--create-trust` and `--allow-to-delegate`. A store keeps its own kdcpreauth,
kdcpolicy, audit, authdata, and OTP modules. Register on the store, or before
open. A global register after a store has opened applies only to stores opened
later, and the KDC logs that at error. The same module again is a no-op, and a
different module of that name is added. A second OTP verifier of a taken name
is an error.

## One store

`shared_dump` returns a `SharedDump` (`Arc<RwLock<PrincipalStore>>`). Cloning it
into a `SharedStore` (`let kdc: SharedStore = dump.clone()`) is that same lock,
so the KDC loop and kadmind serve one store. A write on either is what the next
AS, TGS, or admin read sees, with no file round trip. `serve_all_until` runs on
the caller's thread until its flag is set. `Kadmind::serve` runs on the caller's
thread until `Shutdown::trigger`. `Shutdown::stop_flag` is the flag
`serve_all_until` takes, so one `Shutdown` stops both. A plugin or a kadm5 hook
must not take the store's write guard, and must not re-enter the store.

## Logging

`serve`, `serve_all`, `serve_until`, `serve_all_until`, and `serve_daemon`
take `&KdcLog` as the last argument. `KdcLog::process` uses the process log.
`KdcLog::with_sink` installs an `Arc<dyn klog::LogSink>` for that serve loop.
`klog::set_sink` sets the process sink. A sink is used before an initialized
logger. With neither, a klog line goes to tracing on the target `krb5_klog`.
`LogSink::line` receives the severity and the message. The MIT-format
per-request line comes from a klog sink (`klog::set_sink` or
`KdcLog::with_sink`). A subscriber with no sink and no `klog::init`
gets the structured `kdc.issue` event. Startup and the other klog lines
still reach tracing on `krb5_klog`. A `TracingAdmin` embed gets one `admin`
event per kadm5 operation and per password change. The MIT-format line for
that operation goes to a klog logger, not to the subscriber.

## kadmind serve limits

`kadmind::ServeLimits` caps what one kadmind loop takes on. `max_connections`
(45) and `max_request` (1 MiB) are MIT's defaults. `idle_timeout` and
`per_ip_conns` are `None` by default, as MIT keeps neither; set them to shed an
idle RPC connection or to refuse a new one past a per-source-IP count. A record
that stalls is always closed at the loop's 35 s per-record deadline, whatever
these are set to.
