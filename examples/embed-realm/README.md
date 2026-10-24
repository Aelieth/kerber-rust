# krb5-embed-realm

Two embedders run in-process through the library's embed API: `krb5-embed-realm` runs `kadmind`,
and `krb5-otp-kdc` ([below](#the-otp-kdc-krb5-otp-kdc)) runs the KDC with an example TOTP
`OtpVerifier` and a `require_mfa` policy. Both prove the embed path end to end against MIT `kadmin`
and `kpasswd` and `kinit -T`; neither is a shipped product.

The kadmind half is the whole of what an embedder (the KLLDAP seam) does to start the admin service over a realm
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

The realm profile is applied before either flag writes a principal, so the new
principal takes that profile's lifetimes, flags, and enctypes.

`--create-trust OTHER.TEST --key-file key.hex` creates both trust principals and stops. The file is
32 bytes of aes256 written as 64 hex characters, and the bytes are wiped after the key is built.
`--kvno N` sets that version on both; without it the version is 1. The actor is `admin/admin@REALM`,
checked against the realm's ACL before either principal is written.

`--allow-to-delegate host/svc HTTP/target@REALM` adds that target, in MIT's principal string form,
to the service's allowed-to list, writes it, and stops. The service has to already be in the realm.

## Authorization modules

It registers two example `kadm5_auth` modules in [`auth_modules.rs`](src/auth_modules.rs) through
`KadmindConfig::auth_modules`: `welcomer` lets any caller read a `guest-*` principal, and `bouncer`
denies every write to a `deny-*` one, overriding the ACL. The built-in `acl` and `self` run first.
`[plugins] kadm5_auth` in the profile selects and orders the stack — `enable_only = self` turns the
ACL file off, `disable = bouncer` drops the bouncer — as MIT's stanza does. This library's interface
passes the caller and target names, not MIT's field mask, policy entry or string value.

## The OTP KDC (`krb5-otp-kdc`)

`krb5-otp-kdc` runs the KDC in-process and registers the example TOTP [`OtpVerifier`](src/totp.rs)
and the [`require_mfa`](src/require_mfa.rs) `KdcPolicy` — the shape KLLDAP fills for OTP. Run it like
the kadmind half:

```sh
KRB5_KDC_PROFILE=examples/configs/kdc.conf KRB5_CONFIG=examples/configs/krb5.conf \
    KERBER_EXAMPLE_TOTP_SEEDS=seeds KERBER_EXAMPLE_TOTP_STATE=state \
    cargo run -p krb5-embed-realm-example --bin krb5-otp-kdc -- -n
```

The verifier:

- A `SeedSource` trait is the sealing boundary KLLDAP fills; the demo `FileSeeds` reads a 0600
  `principal base32-seed` file named by `KERBER_EXAMPLE_TOTP_SEEDS`. Seeds are `Zeroizing` and never
  logged; unset, every code is refused.
- RFC 6238 TOTP over a ±1 step window.
- `KERBER_EXAMPLE_TOTP_STATE` names a 0600 state file holding each principal's **monotonic last
  accepted step** and failure count — never a seed — so a code cannot be replayed, even across a
  restart. Unset, the memory is in-process only.
- By default `password‖code`: the trailing six digits are the TOTP code and the rest is the
  password, checked against the principal's keys in constant time. `KERBER_EXAMPLE_TOTP_ONLY` opts
  into a code-only login.

`require_mfa`, selected by `[plugins] kdcpolicy enable_only = require_mfa`, refuses an AS and a TGS
for a principal whose `require_mfa` string attribute is set unless the ticket carries the MFA auth
indicator (`mfa`, or `KERBER_EXAMPLE_MFA_INDICATOR`). The refusal is code 24, as a wrong password is,
so it is no oracle.

The `chaos` cargo feature is off by default and is never built by `build-bins.sh` or CI. Built with
`--features chaos`, a token username of `chaos:hang`, `chaos:slow:<ms>`, `chaos:panic` or
`chaos:error` drives the verifier, for lab cells V9 and V10 only.
