# krb5-embed-realm

`kadmind` run in-process through the library's embed API, the kadmind counterpart of
[`otp-kdc`](../otp-kdc/README.md)'s in-process KDC. It is kept to prove the embed path end to end
against MIT `kadmin` and `kpasswd`; it is not a shipped product.

It is the whole of what an embedder (the KLLDAP seam) does to start the admin service over a realm
it already has a store for:

```rust
let listeners = Listeners::bind(&listen, Services::DAEMON, None)?;   // kpasswd 464, kadm5 749
let mut kadmind = Kadmind::new(shared_store, config)?;              // password modules, GSS names
let stop = Shutdown::new();
kadmind.serve(&listeners, &stop)?;                                 // one loop, until stop.trigger()
```

Unlike the daemon it never detaches and writes no pid file. `Listeners::bind` and `Kadmind::new`
run every start-up check in the foreground, so a bad dictionary, profile or port stops it here with
a `StartError`, leaving nothing behind. `Shutdown::trigger` — wired to SIGTERM and SIGINT — stops the
loop at once.

## Running it

It reads the same profile the daemon reads. Point it at a realm's `kdc.conf` and `krb5.conf`, as in
[`examples/configs`](../configs/README.md):

```sh
KRB5_KDC_PROFILE=examples/configs/kdc.conf KRB5_CONFIG=examples/configs/krb5.conf \
    cargo run -p krb5-embed-realm-example
```

Each start opens the database the profile names, or creates it when the file is missing.
A start that finds the stash and no database finishes that create and keeps the stashed master.
`--bootstrap-only` stops after that and writes `admin.keytab` beside the database. A later start
prints `created` empty and leaves the key versions as they were. MIT `kadmin -p admin/admin` and
`kpasswd` then work against it exactly as against the daemon.

## Authorization modules

It registers two example `kadm5_auth` modules in [`auth_modules.rs`](src/auth_modules.rs) through
`KadmindConfig::auth_modules`: `welcomer` lets any caller read a `guest-*` principal, and `bouncer`
denies every write to a `deny-*` one, overriding the ACL. The built-in `acl` and `self` run first.
`[plugins] kadm5_auth` in the profile selects and orders the stack — `enable_only = self` turns the
ACL file off, `disable = bouncer` drops the bouncer — as MIT's stanza does. This library's interface
passes the caller and target names, not MIT's field mask, policy entry or string value.
