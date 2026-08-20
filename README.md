# kerber-rust

Pure-Rust, memory-safe reimplementation of Kerberos V5, targeting
wire compatibility with [MIT Kerberos](https://web.mit.edu/kerberos/)
**1.22.2**, Heimdal, and Active Directory. There is no C FFI in this
tree.

This is an early-stage project. Stages 1–3 (workspace, crypto, ASN.1,
MIT harness, AS/TGS client + FILE ccache) are in tree. GSS-API and a
Rust KDC are later; see [docs/stages.md](docs/stages.md).

**License:** [Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT), at your
option. Cryptographic software may be subject to export-control rules in
some jurisdictions.

## Architecture

Focused crates under `crates/`:

| Crate | Responsibility |
| --- | --- |
| `krb5-log` | Structured log field names and correlation IDs |
| `krb5-crypto` | RFC 3961/3962/8009 etypes 17–20 |
| `krb5-types` | RFC 4120 owned protocol values |
| `krb5-asn1` | DER encode/decode of those values |
| `krb5-protocol` | AS/TGS over UDP (TCP fallback) |
| `krb5-client` | `kinit`, MIT FILE ccache v4, keytab v2 |

See [docs/architecture.md](docs/architecture.md) and
[docs/rfc-mapping.md](docs/rfc-mapping.md).

## Current status

- AES-CTS-HMAC etypes 17–20: string-to-key, key-usage derivation,
  encrypt/decrypt, keyed checksum. Known-answer tests against RFC 3962,
  RFC 8009, and MIT `t_derive`/`t_cksums`.
- DER round-trip for `PrincipalName`, `Realm`, `EncryptedData`, `Ticket`,
  `KDC-REQ`, `KDC-REP`, `AP-REQ`, `KRB-ERROR`. Truncated/malformed input
  returns an error (no panic).
- Containerized MIT Kerberos **1.22.2** KDC harness.
- Pure-Rust `kinit` (AS + TGS) writes a FILE ccache that MIT 1.22.2
  `klist` can read. Gate: `scripts/client-gate.sh`.

Not yet: GSS-API/SPNEGO, KDC server, Heimdal/AD interop.

## Build and test

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The in-repo consumer (`examples/consumer`) depends on the crates as a
downstream binary and asserts published encrypt and DER return values.

## Test harness (MIT Kerberos 1.22.2)

The documented entry point is `scripts/run-harness.sh`. It builds the
image pinned to MIT krb5 1.22.2, starts a KDC for realm `KERBER.TEST`
on UDP/TCP port 88, emits JSON structured logs with a `correlation_id`,
and runs `kinit` for `user@KERBER.TEST`.

```bash
./scripts/run-harness.sh
./scripts/client-gate.sh    # Rust kinit + MIT klist of the ccache
./scripts/stop-harness.sh
```

Requires Docker. `scripts/run-harness.sh` uses `docker build` and
`docker run` (Compose is optional; see `harness/docker-compose.yml`).
See [docs/testing.md](docs/testing.md) for the realm layout.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md). Short version: small
focused changes, `tag: Imperative sentence` titles, tests that fail
without the change, GitHub Flow with squash merges.
