# Architecture

kerber-rust is a Cargo workspace of small crates. Dependencies flow
downward only:

```
examples/consumer
        │
        ├──────────────► krb5-asn1 ──► krb5-types
        │                     │
        └──────────────► krb5-crypto ──► krb5-log
                              │
                              └────────► krb5-log
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

Later crates (`krb5-protocol`, `krb5-client`, `krb5-gss`, `krb5-kdc`,
`krb5-admin`) are intentionally absent until the layers they need are
stable.

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
