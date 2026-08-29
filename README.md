# kerber-rust

> **Pure-Rust, memory-safe Kerberos V5** — wire-compatible with
> [MIT Kerberos](https://web.mit.edu/kerberos/) **1.22.2**, Heimdal, and
> Active Directory. No C FFI anywhere in the tree.

[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE-APACHE)
[![Edition 2024](https://img.shields.io/badge/edition-2024-informational.svg)](Cargo.toml)
[![MSRV 1.95](https://img.shields.io/badge/MSRV-1.95-informational.svg)](Cargo.toml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](Cargo.toml)
[![interop MIT 1.22.2 · Heimdal · AD](https://img.shields.io/badge/interop-MIT%201.22.2%20%C2%B7%20Heimdal%20%C2%B7%20AD-brightgreen.svg)](docs/interop-matrix.md)

A ground-up reimplementation of Kerberos V5 in safe Rust: the crypto
(RFC 3961/3962/8009), the RFC 4120 wire protocol, a KDC (AS + TGS), a
client (`kinit`), GSS-API, and the admin/propagation daemons (`kadmind`,
`kpasswd`, `kprop`/`kpropd`, iprop). Every feature is proven against a
**real** external implementation — never a Rust-only round-trip.

## Status

| | |
|---|---|
| **v1.0.0** | Tagged interop milestone: the MIT 1.22.2 / Heimdal / Active Directory core, proven by 30+ content-asserting external gates in CI. `publish = false` (not on crates.io). |
| **v1.1** *(in progress)* | **General-purpose MIT completeness** — make the KDC *behave* like MIT across the board and stand alone as a client toolset. See the [roadmap](#roadmap-to-11). |

**The one rule:** a feature is *done* only when a content-asserting gate
drives a real external implementation (MIT primary; then Samba / Heimdal).
A Rust-vs-Rust round-trip is never proof, and production structured logs
plus packet captures outrank unit tests.

## Architecture

Focused crates under `crates/`:

| Crate | Responsibility |
| --- | --- |
| `krb5-log` | Structured log field names and correlation IDs |
| `krb5-crypto` | RFC 3961/3962/8009 etypes 17–20 (plus legacy behind `allow_weak_crypto`) |
| `krb5-types` | RFC 4120 owned protocol values |
| `krb5-asn1` | DER encode/decode of those values |
| `krb5-config` | `krb5.conf` / `kdc.conf`, env, DNS SRV |
| `krb5-protocol` | AS/TGS/AP/SAFE/PRIV/CRED, keytab, FILE ccache |
| `krb5-client` | `kinit` (AS + TGS), MIT FILE ccache v4, keytab v1/v2 |
| `krb5-kdc` | AS/TGS issue, persist/stash, MIT dump/load, named policies, iprop, plugin traits |
| `krb5-gss` | GSS wrap/unwrap/MIC, SPNEGO framing (library; no C FFI) |
| `krb5-admin` | kadmind (AUTH_GSSAPI 300001), kpasswd 464, kprop/kpropd 754, iprop |

See [docs/architecture.md](docs/architecture.md) and
[docs/rfc-mapping.md](docs/rfc-mapping.md).

## What's proven

Every claim below is backed by a live gate in the CI `harness` job. Full
inventory: [docs/interop-matrix.md](docs/interop-matrix.md); the stage map is
[docs/stages.md](docs/stages.md).

| External oracle | Proves | Gates (examples) |
| --- | --- | --- |
| **MIT Kerberos 1.22.2** *(primary)* | AS/TGS · GSS wrap (RFC 4121 RRC=16) · PKINIT · SPAKE (`pa_type` 151 / group 2) · RFC 8009 SHA-2 · cross-realm · kadmin (add/get/list/mod/chrand/rename/del) · kpasswd (464) · kprop **both directions** · iprop · dump/load (v7) · byte-for-byte differential · stress / chaos / soak | `client-gate`, `kdc-gate`, `gss-gate`, `pkinit-gate`, `spake-gate`, `sha2-gate`, `cross-realm-gate`, `kadmin-gate`, `kpasswd-gate`, `kprop-gate`, `kprop-reverse-gate`, `iprop-gate`, `kdb-dump-gate`, `differential-gate`, `store-gate`, `policy-gate`, `history-mit-gate`, `stress`/`chaos`/`soak-gate` |
| **Samba 4 AD DC** *(live)* | AD PAC (NDR golden) · S4U2Self / S4U2Proxy / RBCD · live `AD.KERBER.TEST`↔`KERBER.TEST` trust via real `samba-tool domain trust create` | `samba-ad-gate`, `ad-windows-gate`, `ad-s4u-gate`, `samba-pac-verify-gate`, `samba-crossrealm-gate`, `samba-realtrust-gate` |
| **Heimdal 7.8** *(live)* | AES-SHA1, both directions (Heimdal client ↔ Rust KDC; Rust client ↔ Heimdal KDC) | `heimdal-gate` |

The KDC's live at-rest file is MIT dump **version 7** (the stash holds the
master key); `krb5-kadmind` speaks ONC RPC program 2112 with AUTH_GSSAPI
flavor 300001. `krb5-config` is consumed end to end: the KDC applies
`kdc.conf` ticket policy, and `kinit` / TGS referral chasing read
`KRB5_CONFIG` then `/etc/krb5.conf`.

**Honest caveats, stated plainly:**

- `bidirectional-gate` is **Rust↔Rust**, not an external oracle.
- Windows **SSPI** has no live oracle yet — `gss-sspi` is an honest
  `exit 2` placeholder.
- The Samba **L2** PAC-crypto oracle is a *vendored Python reference*, not
  Samba's C library (L1/L3 are live Samba).
- The product is `forbid(unsafe_code)`; some dependencies (RustCrypto,
  getrandom, nix) contain `unsafe`.

## Roadmap to 1.1

A three-agent parity survey against MIT 1.22.2 found the core strong and
interop-proven, but not yet 100%. **1.1 closes the gap** — nine phases, each
gated against real MIT before it counts as done:

| Phase | Delivers |
| --- | --- |
| **G1** | **Faithfulness — landed.** Principal/password expiration, stored `DISALLOW_*` / `OK_AS_DELEGATE` / `REQUIRES_HW_AUTH` / `NO_AUTH_DATA_REQUIRED`, real `GET_PRIVS`, iprop/kpropd ACLs. Gates: `expire-gate`, `flags-gate`, `getprivs-gate`, `prop-acl-gate` |
| **G2** | **Renewal & postdating** — `kinit -R`, MAY-POSTDATE / POSTDATED / VALIDATE, the PROXIABLE flag |
| **G3** | **kadmin completeness** — `getprinc` returns keys (→ `ktadd -norandkey`), PURGEKEYS, SETKEY, GET/SET_STRINGS, EXTRACT_KEYS |
| **G4** | **iprop fidelity** — carry policy / history / lockout in incremental updates; persist the ulog on disk |
| **G5** | **GSS breadth** — credential delegation, real SPNEGO negotiation, `wrap_iov`/`unwrap_iov` for NFSv4 `RPCSEC_GSS` / SSH / HTTP · *hard requirement* |
| **G6** | **Client-side preauth & names** — wire PKINIT / SPAKE / FAST into `kinit`; NT-ENTERPRISE canonicalization |
| **G7** | **Standalone user CLIs** — `klist`, `kvno`, `kdestroy`, `kpasswd`, `kadmin`, `ktutil` (and retire the harness's reliance on MIT's own clients) |
| **G8** | **ccache breadth** — KEYRING (the SSSD/PAM default on Fedora/RHEL) · *hard requirement* |
| **G9** | **Config breadth** — `[capaths]`, key `[libdefaults]` knobs, `dns_lookup_realm` |

G5 (GSS) and G8 (KEYRING ccache) are hard requirements: kerber-rust is meant
to host real client networks that already use SSH GSSAPI delegation, HTTP
`Negotiate`, NFSv4 `RPCSEC_GSS`, and KEYRING-backed tickets. Beyond 1.1 lies
the pure-Rust KDC embed into [KLLDAP](docs/integration-klldap.md).

## Build and test

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The in-repo consumer (`examples/consumer`) depends on the crates as a
downstream binary and asserts published encrypt and DER return values;
`examples/kdc-consumer` issues a TGT and host ticket, exports a keytab, and
verifies an AP-REQ without binding a socket.

## Test harness (MIT Kerberos 1.22.2)

The documented entry point is `scripts/run-harness.sh`. It builds an image
pinned to MIT krb5 1.22.2, starts a KDC for realm `KERBER.TEST` on UDP/TCP
port 88, emits JSON logs with a `correlation_id`, and runs `kinit` for
`user@KERBER.TEST`.

```bash
./scripts/run-harness.sh
./scripts/client-gate.sh    # Rust kinit + MIT klist of the ccache
./scripts/stop-harness.sh
```

Requires Docker (Compose optional — `harness/docker-compose.yml`). See
[docs/testing.md](docs/testing.md) for the realm layout, and
[docs/ad-lab.md](docs/ad-lab.md) for the AD lab coordinates and the `~/adlab`
isolation protocol.

## Rust KDC

`scripts/run-rust-kdc.sh` (`krb5-kdc --test-realm`) bootstraps realm
`KERBER.TEST` and listens on **127.0.0.1:88**, falling back to
**127.0.0.1:8888** if the privileged port cannot be bound. It never silently
binds `0.0.0.0`.

| Item | Value |
| --- | --- |
| Realm | `KERBER.TEST` |
| User | `user@KERBER.TEST` / `userpassword` |
| Admin | `admin@KERBER.TEST` (ACL `*`: create, delete, ktadd) |
| Host | `host/testhost.kerber.test` (random keys, etypes 17–20) |
| Default etype | 18 (`aes256-cts-hmac-sha1-96`); krbtgt/host also hold RFC 8009 19/20 |

```bash
./scripts/run-rust-kdc.sh
# or: cargo run -p krb5-kdc --bin krb5-kdc -- 127.0.0.1:8888
./scripts/kdc-gate.sh    # MIT 1.22.2 kinit + kvno against the Rust KDC
```

Admin mutations go through MIT `kadmin` against `krb5-kadmind` on 749
(AUTH_GSSAPI) for add/get/list/mod/chrand/rename/del, RFC 3244 `kpasswd` on
UDP/TCP 464, and `kprop`/`kpropd` (TCP 754) both directions. Named password
policies, lockout with time-based auto-unlock, and incremental propagation
(iprop / ulog, program 100423) are in tree; the plugin surface is Rust traits,
not `dlopen` ([docs/plugins.md](docs/plugins.md)).

## License & supply chain

Dual-licensed **[Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT)**, at your
option. See [NOTICE](NOTICE) and [docs/export-control.md](docs/export-control.md)
(cryptographic software; honest ECCN 5D002 / TSU §740.13(e) note).

Supply chain, all in the CI `audit` job: `cargo audit`, `cargo deny`,
per-crate `cargo geiger` (`scripts/geiger.sh`, 0-unsafe product), and
`cargo vet --locked`. MSRV is **1.95** (`package.rust-version`), edition
**2024**, matching KLLDAP 0.7.5; `rasn` is unpinned (`0.28`, lock 0.28.14)
with MIT golden DER as the byte-level net. See
[docs/security.md](docs/security.md).

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md). Short version: small focused
changes, `tag: Imperative sentence` titles, tests that fail without the
change, GitHub Flow with squash merges.
