# kerber-rust

> **Pure-Rust, memory-safe Kerberos V5** — wire-compatible with
> [MIT Kerberos](https://web.mit.edu/kerberos/) **1.22.2**, Heimdal, and
> Active Directory. No C FFI anywhere in the tree.

[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE-APACHE)
[![Edition 2024](https://img.shields.io/badge/edition-2024-informational.svg)](Cargo.toml)
[![MSRV 1.95](https://img.shields.io/badge/MSRV-1.95-informational.svg)](Cargo.toml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](Cargo.toml)
[![interop MIT 1.22.2 · Heimdal · AD](https://img.shields.io/badge/interop-MIT%201.22.2%20%C2%B7%20Heimdal%20%C2%B7%20AD-brightgreen.svg)](docs/interop-matrix.md)

## Purpose

A ground-up reimplementation of Kerberos V5 in safe Rust: the crypto
(RFC 3961/3962/8009), the RFC 4120 wire protocol, a KDC (AS + TGS), a
client (`kinit`), GSS-API, and the admin/propagation daemons (`kadmind`,
`kpasswd`, `kprop`/`kpropd`, iprop). Every feature is proven against a
**real** external implementation — never a Rust-only round-trip.

**The one rule:** a feature is *done* only when a content-asserting gate
drives a real external implementation (MIT primary; then Samba / Heimdal).
A Rust-vs-Rust round-trip is never proof, and production structured logs
plus packet captures outrank unit tests.

## Status

| | |
|---|---|
| **v1.0.0** | Tagged interop milestone: the MIT 1.22.2 / Heimdal / Active Directory core, proven by content-asserting external gates in CI. `publish = false` (not on crates.io). |
| **v1.1** *(in progress)* | **General-purpose MIT completeness**: the KDC behaves like MIT across the board and the client tools stand alone. The nine 1.1 phases and the MIT 1.22.2 parity sweep have landed ([docs/stages.md](docs/stages.md)); the swept MIT functions are graded one row per check in the [parity ledger](docs/parity/README.md). |

Every push runs 55 gates in `ci.yml`: 52 fail-red and 3 soft (`continue-on-error`).
Nine more run only nightly (the eight Samba / AD / Heimdal peers and the KCM opcode
pin); soak also runs longer nightly. [docs/gates.md](docs/gates.md) has one row per gate.

## Architecture

Focused crates under `crates/`:

| Crate | Responsibility |
| --- | --- |
| `krb5-log` | Structured log field names and correlation IDs |
| `krb5-cli` | MIT-style command lines (getopt, `kdb5_util` / `kadmind` option tables) and password prompts |
| `krb5-crypto` | RFC 3961/3962/8009 etypes 17–20 (plus legacy behind `allow_weak_crypto`) |
| `krb5-types` | RFC 4120 owned protocol values |
| `krb5-asn1` | DER encode/decode of those values |
| `krb5-config` | `krb5.conf` / `kdc.conf`, env, DNS SRV |
| `krb5-protocol` | AS/TGS/AP/SAFE/PRIV/CRED, keytab, FILE ccache |
| `krb5-client` | `kinit` (AS + TGS), MIT FILE ccache v4, keytab v1/v2 |
| `krb5-kdc` | AS/TGS issue, persist/stash, MIT dump/load, named policies, iprop, plugin traits |
| `krb5-gss` | GSS wrap/unwrap/MIC, SPNEGO framing (library; no C FFI) |
| `krb5-admin` | kadmind (AUTH_GSSAPI 300001), kpasswd 464, kprop/kpropd 754, iprop |
| `krb5-tools` | Harness-only gate tools (`publish = false`). Not a product surface. |
| `krb5-testkit` | Shared test helpers (`publish = false`, dev-dependency only) |

See [docs/architecture.md](docs/architecture.md) and
[docs/rfc-mapping.md](docs/rfc-mapping.md).

## What's proven

Every claim below is backed by a live gate with a Rust leg, per push or nightly; [docs/gates.md](docs/gates.md)
names each gate's job and lane (the `kadmin-gate` / `kpasswd-gate` wrappers stand for the legs CI runs),
[docs/interop-matrix.md](docs/interop-matrix.md) the oracles, and [docs/stages.md](docs/stages.md) the stage map.

| External oracle | Proves | Gates (examples) |
| --- | --- | --- |
| **MIT Kerberos 1.22.2** *(primary)* | AS/TGS · GSS wrap/unwrap (RFC 4121; wrap sends RRC=0, as MIT) · S4U2Self / S4U2Proxy / RBCD · PKINIT · SPAKE (`pa_type` 151 / group 2) · RFC 8009 SHA-2 · cross-realm · kadmin (add/get/list/mod/chrand/rename/del) · kpasswd (464) · kprop **both directions** · iprop · dump/load (v7) · byte-for-byte differential · stress / chaos / soak | `client-gate`, `kdc-gate`, `gss-gate`, `s4u-mit-gate`, `pkinit-gate`, `rust-kinit-pkinit-gate`, `rust-kinit-enterprise-gate`, `spake-gate`, `sha2-gate`, `cross-realm-gate`, `kadmin-gate`, `kpasswd-gate`, `kprop-gate`, `kprop-reverse-gate`, `iprop-gate`, `kdb-dump-gate`, `differential-gate`, `store-gate`, `policy-gate`, `stress`/`chaos`/`soak-gate` |
| **Samba 4 AD DC** *(live)* | AD PAC (NDR golden) · live `AD.KERBER.TEST`↔`KERBER.TEST` trust via real `samba-tool domain trust create` | `samba-pac-verify-gate`, `samba-pac-l2-gate`, `samba-crossrealm-gate`, `samba-realtrust-gate` |
| **Heimdal 7.8** *(live)* | Both directions (Heimdal client ↔ Rust KDC; Rust client ↔ Heimdal KDC), with AES256-SHA1 configured | `heimdal-gate` |

The KDC's live at-rest file is MIT dump **version 7** (the stash holds the
master key); `krb5-kadmind` speaks ONC RPC program 2112 with AUTH_GSSAPI
flavor 300001. `krb5-config` is consumed end to end: the KDC applies
`kdc.conf` ticket policy, and `kinit` / TGS referral chasing read
`KRB5_CONFIG` then `/etc/krb5.conf`. An omitted `max_renewable_life`
leaves the realm cap at 7 d and new principals at 0, as in MIT
(`kdc/main.c`, `alt_prof.c`); a written value sets both.

**Honest caveats, stated plainly:**

- `bidirectional-gate` is **Rust↔Rust**, not an external oracle.
- Windows **SSPI** has no gate. Over the AD trust it accepted a user of
  the realm (SMB, LDAP) and reached Apache as a SPNEGO client, both in the
  KVM field lab ([harness/field/README.md](harness/field/README.md));
  `krb5-gss` has not been run against SSPI.
- The Samba **L2** PAC-crypto oracle is a *vendored Python reference*, not
  Samba's C library (L1/L3 are live Samba).
- The product is `forbid(unsafe_code)`; some dependencies (RustCrypto,
  getrandom, nix) contain `unsafe`.

## Non-goals

Stated up front so their absence is not read as a gap: OTP / SAM-2 preauth
(PA-OTP over RADIUS), IAKERB, `KEYRING:` ccaches (post-embed), kdcproxy /
MS-KKDCP, FIPS mode, MSLSA ccaches, `ksu` / `.k5login`, `kpropd` under
inetd, `gss_wrap_size_limit`, dlopen plugins (plugins are Rust traits),
db2 / LMDB / LDAP KDB backends, and master-key rollover. The two `absent`
rows in the parity ledger are the first and the `gss_wrap_size_limit`
entries of this list.

## Quick start

kerber-rust installs the way Fedora's `krb5-server` does: MIT's command names, its systemd
units and the `/var/kerberos/krb5kdc` layout. On Fedora, with the Rust toolchain from
[docs/install.md](docs/install.md#prerequisites):

```bash
make build                                      # as yourself: the release build, no test hooks
sudo dnf remove -y --no-autoremove krb5-server  # when it is installed; krb5-workstation stays
sudo make install PREFIX=/usr                   # krb5kdc, kadmind, kadmin.local, kdb5_util, units
sudo kdb5_util create -s                        # once the realm is named in krb5.conf and kdc.conf
sudo systemctl enable --now krb5kdc kadmin
```

[docs/install.md](docs/install.md) is the whole procedure: the realm's files, SELinux, the
firewall, the first administrator, keying clients, upgrading an MIT realm, and what is not
supported yet.

To work on the code, `make safety` runs fmt, clippy, nextest (CI profile) and ci-policy; it
needs `cargo-nextest`. The gates drive real MIT 1.22.2 in Docker (Compose optional):

```bash
./scripts/run-harness.sh  # MIT 1.22.2 KDC for KERBER.TEST on port 88 (Docker)
./scripts/client-gate.sh  # Rust kinit + MIT klist of the ccache
./scripts/stop-harness.sh
./scripts/run-rust-kdc.sh # the Rust KDC for KERBER.TEST on 127.0.0.1:88 (else :8888)
./scripts/kdc-gate.sh     # MIT 1.22.2 kinit + kvno vs the Rust krb5-kdc in the gate's MIT container
```

The realms, principals and ports are in [docs/testing.md](docs/testing.md).
[examples/](examples/README.md) has two downstream-consumer crates and a working one-realm
config `kdc-gate.sh` runs.

## Documentation

[docs/README.md](docs/README.md) lists every document. Reading order:
[architecture](docs/architecture.md) → [stages](docs/stages.md) →
[testing](docs/testing.md) → [gates](docs/gates.md) →
[security](docs/security.md) → [MIT deviations](docs/mit-deviations.md) →
[parity ledger](docs/parity/README.md) →
[logging](docs/logging.md) → [interop](docs/interop-matrix.md) →
[plugins](docs/plugins.md) → [RFC mapping](docs/rfc-mapping.md) →
[gate-unit index](docs/gate-unit-index.md) → the labs
([AD](docs/labs/ad-lab.md), [Samba](docs/labs/samba-lab.md),
[KCM / NFS verdict](docs/labs/kcm-nfs-verdict.md)) → the
[KLLDAP embed](docs/embed/klldap.md) →
[export control](docs/export-control.md).

## License & supply chain

Dual-licensed **[Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT)**, at your
option. See [NOTICE](NOTICE) and [docs/export-control.md](docs/export-control.md)
(cryptographic software; honest ECCN 5D002 / TSU §740.13(e) note).

Supply chain, all in the CI `audit` job: `cargo audit`, `cargo deny`,
per-crate `cargo geiger` (`scripts/geiger.sh`, 0-unsafe product), and
`cargo vet --locked`. MSRV is **1.95** (`package.rust-version`, asserted by
`ci-policy.py` against the `msrv` jobs), `rust-toolchain.toml` pins stable **1.99.0**
with rustfmt and clippy, edition **2024**, matching KLLDAP (checkout 0.7.4, upstream 0.7.6); `rasn` is unpinned (`0.28`, lock 0.28.14)
with MIT golden DER as the byte-level net. See
[docs/security.md](docs/security.md).

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md). Short version: small focused
changes, `tag: Imperative sentence` titles, tests that fail without the
change, and PRs that land by fast-forward or a merge commit, never squash.
