# Embed API

An embedder links `krb5-kdc` and `krb5-admin` as libraries, with `krb5-config`,
`krb5-types`, `krb5-crypto` and `krb5-log` for the profile, names, keys and log, and
drives the KDC and kadmind in its own process. This page is the whole surface it
needs. A default build carries the daemon runtime (`daemon`, on by default) and not
the test fixtures (`test-hooks`, off), so an embedder takes `krb5-kdc` and
`krb5-admin` with `default-features = false`.

This page is as of v1.2.0.

## One store and its locking

`shared_dump` returns a `SharedDump` (`Arc<RwLock<PrincipalStore>>`). Cloning it
into a `SharedStore` (`Arc<RwLock<dyn Store>>`) — `let kdc: SharedStore = dump.clone()`
— is that same lock, so the KDC loop and kadmind serve one store: a write on
either is what the next AS, TGS, or admin read sees, with no file round trip.

Every store mutator refuses outside `PrincipalStore::change()` before it touches
anything. KLLDAP's seam writes (`remove_in`, `set_status`) run inside `change()`;
`put_policy` / `delete_policy` commit themselves. On a shared store, a password
change or a create goes through `change_password_shared` or `create_password_shared`,
which derive the keys under no lock and then take the write guard for the `change()`.
`set_password`, `create_principal_3_in`, `change_password_staged` and `AdminSession`
derive while the caller holds the guard, so every KDC read waits on the string-to-key;
use them only on a store nothing else is reading. `set_status` on a missing principal
is `NotFound`, and the caller decides what that means. A kadm5 hook or a plugin
must not take the store's write guard or re-enter the store: a hook runs after the
write and the database file's lock, but still under the caller's write guard and
before kadmind replies. A create's postcommit hook runs even on a failed change, as
MIT's does.

With `persist_paths`, `change()` writes the database file before it returns, so a
write kadmind acknowledges is on disk, as with MIT's db2. A host that keeps the realm
in its own database has no seam for that yet: a hook can only queue the host's
commit, so a crash between kadmind's reply and that commit loses an acknowledged
write, and policy writes and the KDC's lockout counters call no hook. Use
`persist_paths` until such a seam exists.

## Bootstrap

`bootstrap_realm_into` fills a store the caller owns. It creates only the
K/M, krbtgt, `kadmin/admin`, `kadmin/changepw`, and optional admin rows that
are missing, and does not rotate a key that is already there. An existing realm
stamps each new row with the active K/M kvno (`TL_ACTKVNO`, else the newest key).
A new realm uses `RealmSpec.mkvno`; `kdb5_util create` and `embed-realm` use 1.
`Bootstrapped.kvno` is that kvno. The admin requires pre-auth unless `AdminSpec`
says otherwise. The admin keytab comes back on `Bootstrapped` on every open, with the
current key, for the caller to write.

After bootstrap, keep no master key: drop `Bootstrapped.master`, and don't read the
stash, parse a dump, or use `PrincipalStore::persist_paths` yourself; the store does
all three. Back the stash and the database up together. `Bootstrapped`, `MasterKey`,
`Principal`, `OpaqueKey` and `KeySlot` are `#[non_exhaustive]`, so a later field or variant
doesn't break a build: build a `Principal` with `PrincipalBuilder`.

`create_database` writes the stash (a temp file renamed into place, mode 0600),
then both lock files, then the database by renaming a finished temp file into
place. That rename is the commit. A re-run that finds the stash and no database
reuses that master and kvno. A database with no lock file is refused, as an open is.

`open_or_create(paths, profile, admin) -> Result<(PrincipalStore, Bootstrapped),
Error>` does that whole open-or-create — a present database is opened, a stash with no
database resumes its master and kvno, else a new random master — then
`bootstrap_realm_into` and `create_database`. An embedder gets the crash-safe
resume without copying the example's lines; `examples/embed-realm` calls it.

## Config by `ProfileSet`

`ProfileSet::from_structs(realm, krb5, kdc)` builds the realm's configuration from
the `Krb5Conf` and an optional `KdcConf` (`kdc: Option<KdcConf>`). `store.apply_profile(&profile)` then gives
the store the realm's ticket lifetimes, flags, and enctypes. Apply it before
serving (the example applies it before `--create-trust` and `--allow-to-delegate`).

## kadmind and kpasswd

`Kadmind::new` prepares the store (`prepare_store`, which calls `apply_profile`),
checks the acceptor names, and takes the kpasswd key when the service set asks
for it. `Listeners::bind` binds the sockets, and `Kadmind::serve` runs the loop
on the caller's thread until a `Shutdown`. The binary's log is `KlogAdmin`; an
embedder passes `TracingAdmin` or its own `AdminLog`. Password-quality modules
and kadm5 hooks on `KadmindConfig` apply to that kadmind alone, the modules after
the built-ins, as MIT loads its modules beside them; empty lists keep
`register_pwqual` and `register_kadm5_hook`. Remote MIT `kadmin` on 749 is that
loop on a thread beside the KDC's, or `krb5-kadmind` run beside the embedder.

`krb5_admin::ServeLimits` caps what one kadmind loop takes on. `max_connections`
(45) and `max_request` (1 MiB) are MIT's defaults. `idle_timeout` and
`per_ip_conns` are `None` by default, as MIT keeps neither; set them to shed an
idle RPC connection or to refuse a new one past a per-source-IP count. A record
that stalls is always closed at the loop's 35 s per-record deadline, whatever
these are set to.

## kadm5 hooks and `kadm5_auth`

`kadm5_hook` ([`Kadm5Hook`](../../crates/krb5-kdc/src/store/kadm5_hook.rs)) lets an
embedder register a module with `register_kadm5_hook`; it runs after the write,
still under the caller's write guard and before kadmind replies. The directory need
not register one.

`kadm5_auth` is the admin-authorization interface: an embedder's `Kadm5Auth` module
goes in `KadmindConfig.auth_modules` or is chosen by `[plugins] kadm5_auth`, and the
built-in `acl` and `self` modules answer each verb alongside it. A module returns
`Decision::Allow`, `Abstain` or `Deny`; `Deny` refuses at once, and the
allowing module supplies the restrictions (`docs/parity/a4-kadmin.md`). A target
whose name isn't UTF-8 is decided by the built-in `acl` and `self` modules
alone, by its bytes; other modules aren't asked.

## OTP and require-MFA

The `otp` kdcpreauth module (RFC 6560) asks an embedder `OtpVerifier`; a second
verifier of a taken name is an error. MIT does not refuse a password login for a
principal that keeps a key, so MFA is enforced one of three ways, each with the
indicator the principal's `otp` attribute or the type's `[otp]` indicator names,
and none on krbtgt (which would refuse the keytab login that gets the FAST armor):

- **(a)** `require_auth = <indicator>` on each service to protect — MIT-native and
  per-service, but the client still gets a TGT and only the protected service refuses;
- **(b)** an embedder `KdcPolicy` (e.g. `examples/embed-realm`'s `require_mfa`)
  refusing the AS and the TGS of a flagged client whose ticket lacks the indicator
  (denial code 24, which neither reveals the password oracle nor skips the lockout
  count) — KDC-wide and strongest, but custom;
- **(c)** a keyless principal — no long-term key, so no password to fall back to,
  simplest but with no password path at all.

`OtpVerifier::verify` runs on four shared `otp-verify` threads with a queue of 64.
The KDC answers at the request's deadline and fails closed, but a verifier still
running keeps its thread, so `verify` should return by `req.deadline` itself (for
example, by setting its socket timeouts from it).

## Logging and plugin sets

The serve functions take `&KdcLog` as the last argument. `KdcLog::process` uses
the process log; `KdcLog::with_sink` installs an `Arc<dyn klog::LogSink>` for that
serve loop; `klog::set_sink` sets the process sink. `LogSink::line` receives the
severity and the message. The MIT-format per-request line comes from a klog sink;
a subscriber with no sink and no `klog::init` gets the structured `kdc.issue`
event, and startup and the other klog lines still reach tracing on `krb5_klog`. A
`TracingAdmin` embed gets one `admin` event per kadm5 operation and per password
change; the MIT-format line for that operation goes to a klog logger.

A store keeps its own kdcpreauth, kdcpolicy, audit, authdata, and OTP modules.
Register on the store, or before it is opened. A global register after a store
has opened applies only to stores opened later, and the KDC logs that at error.
The same module again is a no-op; a different module of that name is added.
`[plugins] kdcpolicy` and `[plugins] audit` select modules by name; the audit
name `json` loads only when `enable_only` lists it.

## The `rasn` `[patch]` and `panic = "unwind"`

The build pins a vendored `rasn`: `rasn = "=0.28.14"` with `[patch.crates-io]
rasn = { path = "vendor/rasn" }`. The patch makes the BER decoder fail a message
whose OPTIONAL explicit field or SEQUENCE OF element is present but does not
decode, and decode as MIT 1.22.2 does (`vendor/rasn/PATCHES.md` has the diff). An
embedder's workspace must carry the same patch, from this repository at the tag its
`krb5-*` crates come from:

```toml
[patch.crates-io]
rasn = { git = "https://github.com/Aelieth/kerber-rust", tag = "v1.2.1" }
```

Without it, `krb5-types` fails to compile on `rasn::KERBER_RUST_NEEDS_THIS_PATCH`.

Keep `panic = "unwind"` (the default). The serve loop and the plugin and OTP
paths `catch_unwind` each request and each plugin call, turning a panic into a
dropped connection or an error instead of a crashed KDC; `panic = "abort"`
defeats that.

## Privileged ports by pre-bound sockets

The embed-safe serve calls take sockets the caller already bound:

- `serve_until(store, udp, tcp, shutdown, limits, log)`
- `serve_all_until(store, Vec<UdpSocket>, Vec<TcpListener>, shutdown, ListenLimits, log)`

So bind the privileged ports first — `bind_udp_listeners(addrs)` and
`bind_tcp_listeners(addrs)` (or `bind_tcp_listeners_with_backlog`), which may run
while the process still has the privilege to bind below 1024 — then serve on them.
`serve` and `serve_all` instead install SIGTERM / SIGINT handlers, and `serve_daemon` takes
the caller's. All three are behind the `daemon` feature, so they are not the embed path.

`Shutdown::new()` with `Shutdown::stop_flag()` is the `AtomicBool` that
`serve_all_until` polls; one `Shutdown` stops the KDC loop and `Kadmind::serve`
together. `ListenLimits` holds `max_tcp_workers`, `max_tcp_request`,
`max_dgram_reply_size`, and `shutdown_poll` (250 ms by default; it must be more
than zero). The KDC's TCP backlog is 128.

## Process hardening

A default build does not change process credentials: the in-process privilege
drop is a `test-hooks` facility for the lab, which runs the KDC as root in a
container. An embedder that binds privileged ports drops privileges by its own
means — systemd `User=` or ambient capabilities, or a drop after the bind — and
applies the usual daemon hardening, such as disabling core dumps so key material
never reaches one.

## Threading

The KDC loop and `Kadmind::serve` run on the thread that calls them; the crates
are synchronous and start no runtime of their own. A tokio embedder runs each on
a thread of its own and calls `block_on` only from such a loop thread, never from
a runtime worker, which it would block. No store or plugin re-entry: a plugin or a
kadm5 hook must not take the store's write guard or call back into the store.
