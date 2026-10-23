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

The database and stash the profile names must already exist (create them with `krb5-kdb`, as
`otp-kdc`'s README shows). Then MIT `kadmin -p admin/admin` and `kpasswd` work against it exactly as
against the daemon.
