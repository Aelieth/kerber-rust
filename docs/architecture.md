# Architecture

kerber-rust is a Cargo workspace of small crates. Dependencies flow
downward only:

```
examples/consumer, examples/kdc-consumer
        │
        ├──────────────► krb5-asn1 ──► krb5-types
        │                     │
        ├──────────────► krb5-kdc / krb5-admin / krb5-gss
        │                      │
        ├──────────────► krb5-client ──► krb5-protocol ──► krb5-crypto
        │                      │                └──► krb5-config
        │                      │                │
        └──────────────► krb5-crypto            └──► krb5-asn1
```

## Crate responsibilities

**`krb5-log`** defines the structured event field names and allocates
correlation IDs. It does not install a `tracing` subscriber. Binaries,
tests, and the harness installer do.

**`krb5-crypto`** is pure functions over keys and byte slices. No
sockets, no ASN.1. Long-term keys (`ProtocolKey`) zeroize on drop.
HMAC comparison is constant-time (`subtle`). Random confounders come
from the OS CSPRNG (`getrandom`).

**`krb5-types`** holds RFC 4120 owned values with rasn derives. Tagging
is EXPLICIT, matching the RFC. This crate is the protocol vocabulary;
it does not catch codec errors.

**`krb5-asn1`** is the DER boundary: `encode` / `decode` return
`Result`, never panic, and emit log events for success and failure.

**`krb5-protocol`** runs AS and TGS over UDP with TCP fallback, plus
AP-REQ build/verify.

**`krb5-client`** is `kinit`, MIT FILE ccache v4, and keytab v2.

**`krb5-protocol`** runs AS/TGS/AP/SAFE/PRIV/CRED, plus MIT keytab and
FILE ccache (so the KDC does not depend on the client crate). UDP uses
`send_to`/`recv_from` and ignores off-path source addresses.

**`krb5-client`** is `kinit` (password from env/stdin, never argv).

**`krb5-kdc`** issues AS/TGS from an in-memory store with optional
persist/stash. Default bind is `127.0.0.1` (not `0.0.0.0`). `--test-realm`
bootstraps documented principals; otherwise `KRB5_KDC_DB` + stash.

**`krb5-gss`** / **`krb5-admin`** / **`krb5-config`** provide GSS wrap,
ACL-enforced admin, and `krb5.conf` parsing. MIT GSS remains
out-of-process.

## Security invariants

- Key usage 0 is rejected (RFC 3961 §2).
- PBKDF2 iteration count 0 (RFC 3962 = 2^32) is rejected locally to
  avoid a cheap DoS; this is a documented limitation versus a strict
  reading of the RFC.
- Decrypt discards plaintext when the truncated HMAC does not match.
- No `unsafe` in this workspace (`forbid(unsafe_code)`).
- No C FFI.

## Observability

Every crypto and ASN.1 operation emits a `tracing` event with
`correlation_id`, `event`, `component`, `outcome`, and `duration_us`.
Crypto events include `etype` and `key_usage`. Failures include `error`.
See [logging.md](logging.md).
