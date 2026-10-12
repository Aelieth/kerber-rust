# krb5-otp-kdc (example)

An example embedder. `krb5-otp-kdc` runs the kerber-rust KDC in-process through the library's
public embed API, and registers a TOTP `OtpVerifier` (RFC 6238) before it serves. It is the
KLLDAP integration in miniature (see [docs/embed/klldap.md](../../docs/embed/klldap.md)), used to
prove OTP preauth end to end against MIT `kinit`. It is not a shipped product, and no crate in the
workspace depends on it.

It starts as `krb5-kdc` does for one realm, in the foreground: the profile, the daemon log, the
realm's database and stash, kdc.conf and the plugin relations, then the listeners. The loop runs on
the main thread until SIGTERM or SIGINT. `-n` is accepted and changes nothing: there is no fork and
no pid file.

## Build

```sh
cargo build -p krb5-otp-kdc-example --release --locked
```

The binary is `target/release/krb5-otp-kdc`.

## Run it in place of krb5kdc

Set the environment `krb5-kdc` reads (`KRB5_CONFIG`, `KRB5_KDC_PROFILE`), create the realm with
`krb5-kdb` as [examples/configs](../configs/README.md) does, then:

```sh
KERBER_EXAMPLE_TOTP_SEEDS=/etc/kerber-rust/totp.seeds krb5-otp-kdc
```

## The seeds file

One line per user: the username the token carries, then the base32 seed.

```text
ra4user@KERBER.TEST GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
```

- The username is matched byte for byte. A token with no `username` carries the principal unparsed
  with its realm, as `ra4user@KERBER.TEST`.
- The seed is RFC 4648 base32, in either case. `=` padding is optional.
- A line that is not exactly a name and a seed is ignored. The first line for a name wins.
- The file is read on every request, so it can change without a restart.
- A seeds file that is unset, unreadable, or has no line for the user refuses the code.
- Neither a seed nor a code is ever logged.

## Admin step

The `otp` attribute selects the verifier. The kadmin command line splits words the way
kerber-rust's port of MIT's `ss_parse` does: inside a double-quoted word, `""` stands for one `"`.
The JSON therefore has to be quoted as below. Unquoted, the `"` characters are stripped and the
stored value is not JSON.

```sh
krb5-kadmin-local -q 'setstr ra4user otp "[{""type"":""totp""}]"'
krb5-kadmin-local -q 'getstrs ra4user'    # otp: [{"type":"totp"}]
```

## What it checks

- A code is exactly six ASCII digits: HMAC-SHA1 truncated as RFC 4226, on a 30-second step. The step
  before, the step itself and the step after are accepted.
- An accepted code is remembered for 90 seconds, per user and step. Presenting it again is refused.
- Any other value is refused, and so is a code for a user with no seed.

## Limits

- OTP preauth is armored with FAST (RFC 6560), so a login needs an armor ticket: MIT `kinit -T
  <armor ccache>` with the OTP prompt answered. The `krb5-kinit` in this tree does not do OTP.
- The verifier reads its seeds file under the store's read lock, once per OTP request. That suits a
  demonstration, not a directory of many users.
