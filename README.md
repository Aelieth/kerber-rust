# kerber-rust

Pure-Rust, memory-safe reimplementation of Kerberos V5, targeting
wire compatibility with [MIT Kerberos](https://web.mit.edu/kerberos/)
**1.22.2**, Heimdal, and Active Directory. There is no C FFI in this
tree.

This is an early-stage project targeting MIT 1.22.2 wire compatibility.
Stages 1–8 of `working/plan-initial-audit-0819-2122.md` are in tree at
library depth (AS/TGS KDC+client, GSS wrap/MIC, admin ACL, persist,
kpasswd, FAST armor, SPAKE2-P256, PKINIT CMS+ECDH, NDR PAC, S4U/U2U,
cross-realm referrals). Long soaks
and live Heimdal/AD/SSPI remain environment-dependent. See
[docs/stages.md](docs/stages.md).

**License:** [Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT), at your
option. This tree contains cryptographic software. Export from the
United States (and some other jurisdictions) may require a license;
review local export-control rules before distributing binaries. Supply
chain: `cargo audit` in CI; `deny.toml` for licenses/advisories. The
product itself is `forbid(unsafe_code)`; some dependencies contain
`unsafe` (RustCrypto, getrandom, nix).

## Architecture

Focused crates under `crates/`:

| Crate | Responsibility |
| --- | --- |
| `krb5-log` | Structured log field names and correlation IDs |
| `krb5-crypto` | RFC 3961/3962/8009 etypes 17–20 |
| `krb5-types` | RFC 4120 owned protocol values |
| `krb5-asn1` | DER encode/decode of those values |
| `krb5-config` | `krb5.conf` / `kdc.conf`, env, DNS SRV |
| `krb5-protocol` | AS/TGS/AP/SAFE/PRIV/CRED, keytab, FILE ccache |
| `krb5-client` | `kinit` (password env/stdin), MIT FILE ccache v4, keytab v1/v2 |
| `krb5-kdc` | AS/TGS issue, persist/stash, ACL, UDP/TCP listener |
| `krb5-gss` | GSS wrap/unwrap/MIC, SPNEGO framing (no C FFI) |
| `krb5-admin` | kadmind-equivalent ACL session, ktadd, kprop dump/load |

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

- Pure-Rust KDC issues TGTs and host service tickets; `kadm5.acl`-style
  allow/deny for create/delete/ktadd; MIT keytab v2 export; AP-REQ
  verify (truncated / wrong-key / replay rejected). Gate:
  `scripts/kdc-gate.sh`.

GSS-API is `krb5-gss` (library wrap/MIC; MIT `libgssapi_krb5` is
out-of-process only). kadmind MIT RPC ABI is not implemented;
`krb5-admin` enforces the ACL over a library/session API. Weak etypes
(16/23/25/26) are known but refused unless `allow_weak_crypto`.

## Build and test

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The in-repo consumer (`examples/consumer`) depends on the crates as a
downstream binary and asserts published encrypt and DER return values.
`examples/kdc-consumer` issues a TGT and host ticket, exports a keytab,
and verifies AP-REQ without binding a socket.

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

## Rust KDC

The documented Rust KDC entry point is `scripts/run-rust-kdc.sh`
(`krb5-kdc --test-realm`). It bootstraps realm `KERBER.TEST` and listens
on **127.0.0.1:88**, falling back to **127.0.0.1:8888** if the privileged
port cannot be bound. It does not silently bind `0.0.0.0`.

| Item | Value |
| --- | --- |
| Realm | `KERBER.TEST` |
| User | `user@KERBER.TEST` / `userpassword` |
| Admin | `admin@KERBER.TEST` (ACL `*`: create, delete, ktadd) |
| Host | `host/testhost.kerber.test` (random AES-256 key) |
| Default etype | 18 (`aes256-cts-hmac-sha1-96`), s2kparams 4096 |

```bash
./scripts/run-rust-kdc.sh
# or: cargo run -p krb5-kdc --bin krb5-kdc -- 127.0.0.1:8888
./scripts/kdc-gate.sh    # MIT 1.22.2 kinit + kvno against the Rust KDC
```

Admin mutations are library calls (not kadmind RPC): `Acl::check` plus
`PrincipalStore::create_host` / `export_keytab`. POSIX machine auth at
the Kerberos layer is AP-REQ build (`krb5-protocol::build_ap_req`) and
verify with the host keytab (`verify_ap_req`).

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md). Short version: small
focused changes, `tag: Imperative sentence` titles, tests that fail
without the change, GitHub Flow with squash merges.
