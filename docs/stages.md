# Stage progress

Promotion through a stage requires the multi-sided tests for that stage
and, once a live component exists, a production-gate run with structured
logs. Unit tests alone do not promote a stage.

| Stage | Content | Status |
| --- | --- | --- |
| 1 | Foundation, inventory, MIT 1.22.2 harness, logging schema | **In tree** |
| 2 | Crypto primitives + ASN.1/DER core, KATs, parser negative tests | **In tree** (etypes 17–20, RFC 4120 core PDUs) |
| 3 | Protocol library + minimal client (AS/TGS), ccache/keytab, first live MIT production gate | **In tree** (`krb5-protocol`, `krb5-client`; gate: `scripts/client-gate.sh`) |
| 4 | Higher-level client, GSS-API/SPNEGO (RFC 4121) | **In tree** (`krb5-gss` wrap/unwrap/MIC, SPNEGO framing; MIT GSS is out-of-process) |
| 5 | KDC core (AS+TGS) + database backend, bidirectional interop | **In tree** (in-memory + dump-v7 at-rest; one-release KDB3 load; MIT `kdb5_util` dump/load; ACL; AP-REQ; gates: `kdc-gate.sh`, `bidirectional-gate.sh`, `kdb-dump-gate.sh`). MIT `kinit` both directions is the database oracle. |
| 6 | Admin tools, plugins, propagation, remaining parity | **In tree** (1.0: kadmind AUTH_GSSAPI, kpasswd, full-dump kprop both ways). **Era III Tier 1:** KDB traits + registries ([`plugins.md`](plugins.md), not dlopen); named policies (`policy-gate.sh`); iprop serial/ulog (`iprop-gate.sh`). |
| 7–8 | Hardening, stress, chaos, adversarial, observability, final gates | **In tree (1.0).** MIT-oracle gates exist for AS/TGS, FAST TGS `kvno`, GSS wrap, PKINIT `kinit`, SPAKE `kinit` (`pa_type` 151 / group 2), two-realm `kvno`, and SHA-2 `kinit`/`kvno`. Golden MIT DER is byte-diffed; published crypto KATs; 9 cargo-fuzz targets; panic-deny lints (`unwrap_used` / `expect_used` / `panic`) on all twelve library roots (every crate but the test-only `krb5-testkit`) and every binary but the four harness-only `krb5-tools` probes (`ccache-probe`, `diffsend`, `kprop-expired-apreq`, `loadgen`) (the gap on `krb5-admin`, `krb5-asn1` and `krb5-log` closed at zero code cost). AD PAC NDR is golden-gated. Wire **stress/chaos/soak** run over `harness/prod` (`stress-gate`, `chaos-gate`, `soak-gate`; scheduled soak in `soak.yml`). Differential-vs-MIT is `scripts/differential-gate.sh` (same AS/TGS bytes to Rust and MIT 1.22.2 on one dump). Heimdal 7.8 bidirectional is `scripts/heimdal-gate.sh`. Inventory: [`interop-matrix.md`](interop-matrix.md). Live SSPI remains environment-dependent. |

Stage 2 production-gate of a *Rust client* is Stage 3. This repository
currently gates crypto/ASN.1 on known-answer tests, malformed-input
tests, fmt/clippy, and harness `kinit` against MIT 1.22.2. 9 cargo-fuzz
targets.

## Era II — Active Directory interop & production verification (closed at 1.0)

Stages 1–8 are done at the MIT-1.22.2 + Samba + Heimdal level that
**v1.0.0** claims. The external-oracle inventory is [`gates.md`](gates.md)
(per gate) and [`interop-matrix.md`](interop-matrix.md) (per oracle).

- **AD/Windows interop:** NDR32 `KERB_VALIDATION_INFO` decodes the
  captured `kbruser` PAC (`tests/traces/pac-kbruser.ndr`) byte-identically.
  Issued PACs include buffers 12/17/18 and store SID/RID. Samba L1/L3
  gates: `samba-pac-verify-gate.sh`, `samba-pac-l2-gate.sh` (vendored kcrypto 6/7/16/19),
  `samba-crossrealm-gate.sh`. Production
  GSS wrap emits RRC=0, as MIT does. S4U2Self/Proxy against the Rust KDC:
  `scripts/s4u-mit-gate.sh` (in CI; evidence PAC copy, classic
  constrained delegation, RBCD). Live Windows
  `kinit`/`kvno` (`ad-windows-gate.sh`) and AD S4U (`ad-s4u-gate.sh`)
  drive live Samba (`samba-ad-dc`), not the torn-down Windows DC.
- **Operational parity:** serving store is `RwLock` so kadmind
  mutations persist; KDC reads the db again, under its shared lock,
  when its age (`principal.ok`'s mtime), the file or its change time
  moves.
  `krb5-kadmind` AUTH_GSSAPI 300001: MIT `kadmin` add/cpw/get/list/mod/
  chrand/ktadd/`ktadd -norandkey`/purgekeys/setstr/`renprinc`/del then
  `kinit extra@KERBER.TEST` (`scripts/kadmin-gate.sh`). RFC 3244
  kpasswd on UDP/TCP 464 (`scripts/kpasswd-gate.sh` MIT `kpasswd` then
  `kinit`); kprop on 754 wrapping dump version 7 both directions
  (`scripts/kprop-gate.sh` MIT→Rust; `scripts/kprop-reverse-gate.sh`
  Rust→MIT `kpropd` then MIT `kinit`); RFC 8636
  SHA-256 PKINIT KDF on the issue path when
  AuthPack advertises it (`scripts/pkinit-gate.sh`). Stage-5 database
  backend is MIT `kdb5_util` dump/load (`krb5-kdb`, version 7): MIT
  `kinit` against the Rust KDC on a loaded dump, and MIT `krb5kdc` +
  `kinit` on a Rust-written dump (`scripts/kdb-dump-gate.sh`).
- **Production verification:** `scripts/prod-gate.sh` (loopback
  Rust↔Rust) plus **`scripts/prod-realm-gate.sh`** (MIT client vs Rust
  primary/replica on a docker network, realm `PROD.KERBER.TEST`, kprop
  failover, structured logs + NIC pcap). Wire **stress-gate** (p99 SLO),
  **chaos-gate** (netem + memory + failover-under-load), and **soak-gate**
  (RSS leak check; scheduled longer run). Differential-vs-MIT
  (`differential-gate`) is in CI. Heimdal 7.8 bidirectional (`heimdal-gate`)
  runs nightly in `peers.yml`. `cargo deny`, per-crate `cargo geiger` (`scripts/geiger.sh`),
  and `cargo vet --locked` are in the CI `audit` job. Timing/replay
  matrix: [`docs/security.md`](security.md). Export: [`NOTICE`](../NOTICE),
  [`docs/export-control.md`](export-control.md). Logs-as-metrics:
  [`docs/logging.md`](logging.md) (in-process counters deferred).
  Windows SSPI has no gate; over the AD trust it accepted a user of the
  realm (SMB, LDAP) and reached Apache as a SPNEGO client in the KVM field
  lab ([`harness/field/README.md`](../harness/field/README.md)).

**Audit caveats (2026-08-25).** PAC **NDR codec** and **RFC 8636 KDF** are
done. Samba L1 decodes the full buffer set of a Rust PAC
(`samba-pac-verify-gate.sh`); Samba `kcrypto` validates checksums 6/7/16/19
(`samba-pac-l2-gate.sh`); Samba's KDC accepts a Rust referral PAC
both directions (`samba-crossrealm-gate.sh`). TGS
verifies a presented PAC and copies LOGON_INFO (in-repo two-realm
tests; `kvno` is not that copy proof). Rust S4U2Self/Proxy is
MIT KDC + client gated (`scripts/s4u-mit-gate.sh`); S4U2Proxy copies the evidence
PAC, denies classic constrained delegation unless `s4u_allowed_to` lists
the target, and denies RBCD unless allowed. `ad-windows-gate` / `ad-s4u-gate` are live Samba, run nightly in `peers.yml`.
`ad-mit-trust-gate.sh` aliases `samba-realtrust-gate.sh`. **Production verification** is
`prod-gate.sh` (loopback) plus **`prod-realm-gate.sh`** (multi-host MIT
client, named realm, kprop failover; in CI). Wire `stress-gate` /
`chaos-gate` / `soak-gate` are in CI; in-process `bounded_stress`
remains. Differential-vs-MIT is `differential-gate` (in CI). **kprop** on 754
is gated both directions (`kprop-gate` MIT→Rust; `kprop-reverse-gate`
Rust→MIT, additive to the in-process dump/send tests). **kadmind** MIT-gates add/get/list/mod/chrand/
`renprinc`/del. Per push, `ci.yml` spreads them over four jobs, for example: `harness`
(`pkinit-gate`, `policy-gate`, the four `kadmin-*` legs of the local
`kadmin-gate` wrapper), `harness-2`
(`kpasswd-rust-gate` / `kpasswd-mit-gate`, `kdb-dump-gate`,
`differential-gate`, `kprop-gate`, `kprop-reverse-gate`, `iprop-gate`,
`restart-gate`, `prod-gate`, `prod-realm-gate`), `mit-extra` (the
cross-realm / SPAKE / FAST / PKINIT client gates) and `mit-extra-2`
(`s4u-mit-gate`, the client differential); [`gates.md`](gates.md) has one
row per gate with its job and lane. `stress-gate` (`slo` job), `chaos-gate` (`chaos`) and `soak-gate`
(`soak`) are per-push but `continue-on-error`. The eight Samba/AD/Heimdal
gates — `samba-ad-gate`, `ad-windows-gate`, `ad-s4u-gate`,
`samba-pac-verify-gate`, `samba-pac-l2-gate`, `samba-crossrealm-gate`,
`samba-realtrust-gate`, `heimdal-gate` — run **nightly** in `peers.yml`
(not per push); a red there is a red, but a push does not wait for it.

## Era III — the 1.1 roadmap

A three-agent parity survey against MIT 1.22.2 found the core strong and
interop-proven, but not yet 100%. **1.1 closes the gap** — nine feature
phases and then a source-level parity sweep, each gated against real MIT
before it counts as done:

| Phase | Delivers |
| --- | --- |
| **G1** | **Faithfulness — landed.** Principal/password expiration, stored `DISALLOW_*` / `OK_AS_DELEGATE` / `REQUIRES_HW_AUTH` / `NO_AUTH_DATA_REQUIRED`, real `GET_PRIVS`, iprop/kpropd ACLs. Gates: `expire-gate`, `flags-gate`, `getprivs-gate`, `prop-acl-gate` |
| **G2** | **Renewal & postdating — landed.** `kinit -R`, MAY-POSTDATE / POSTDATED / VALIDATE, the PROXIABLE flag. Gates: `renew-gate`, `postdate-gate` |
| **G3** | **kadmin completeness — landed.** `getprinc` key metadata, `EXTRACT_KEYS` (`ktadd -norandkey`), PURGEKEYS, SETKEY, GET/SET_STRINGS. Gate: `kadmin-gate`. MIT `*`/`x` do not grant extract (`e`). SETKEY is unit-tested (no MIT `setkey` verb) |
| **G4** | **iprop fidelity — landed.** Incremental kdbe carries string-attrs / history / policy / lockout; ulog persists across master restart. Gates: `iprop-gate`, `differential-gate` |
| **G5** | **GSS breadth — landed.** Credential delegation, real SPNEGO negotiation, `wrap_iov`/`unwrap_iov` for NFSv4 `RPCSEC_GSS` / SSH / HTTP · *hard requirement*. Gate: `gss-gate` |
| **G6** | **Client-side preauth & names — landed.** Wire PKINIT / SPAKE / FAST into `kinit`; NT-ENTERPRISE canonicalization. Gates: `rust-kinit-{fast,pkinit,spake,enterprise}-gate` |
| **G7** | **Standalone user CLIs — landed.** `klist`, `kvno`, `kdestroy`, `kpasswd`, `kadmin.local` (`krb5-kadmin-local`), `ktutil`. The remote `kadmin` client is deferred (see CHANGELOG); `kadmin-gate` drives MIT `kadmin` against the Rust kadmind. Gates: `client-gate`, `kpasswd-gate`, `kadmin-gate`, `ktutil-gate`. Harness still uses MIT `kinit`/`kvno` as the oracle (retiring that is not this cut) |
| **G8** | **ccache breadth — landed.** FILE/DIR/MEMORY/KCM; `KEYRING:` is rejected (`Unknown credential cache type`). Gates: `ccache-gate`, `kcm-gate` |
| **G9** | **Config breadth — landed.** `[capaths]`, key `[libdefaults]` knobs, `include`/`includedir`. Gates: `capaths-transit-gate`, `knobs-gate`, `config-include-gate` |
| **Parity sweep** | **MIT 1.22.2 parity sweep — closed.** KDC (`do_as_req`/`do_tgs_req`/`kdc_util`/`tgs_policy`/FAST/PAC), client library, acceptor and kadm5 graded function by function against MIT source in [docs/parity/](parity/README.md); every row is `exact`, `stricter-documented` ([docs/mit-deviations.md](mit-deviations.md)), `deviation`, `deferred` with a named promotion oracle, or one of the two `absent` non-goals. Also landed on the way: anonymous PKINIT + `restrict_anonymous_to_tgt`, RFC 8070 PKINIT freshness, FAST hide-client-names, client-side S4U2Self/S4U2Proxy, `krb5-vfy-increds`, `krb5-kswitch`. Gates: `differential-gate` (111 same-bytes cases), `client-differential-gate`, `kadmin-gate`, `mit-fast-kdc-gate`, `kdcpolicy-gate`, `cross-kdc-gate` |

G5 (GSS) is a hard requirement: kerber-rust is meant to host real client
networks that already use SSH GSSAPI delegation, HTTP `Negotiate`, and NFSv4
`RPCSEC_GSS`. `KEYRING:` ccaches are a post-embed item (kernel keyrings need
a shim under `forbid(unsafe_code)`; the fleet default is FILE, see
[labs/kcm-nfs-verdict.md](labs/kcm-nfs-verdict.md)), so `KEYRING:` is refused
as an unknown cache type until then. Beyond 1.1 lies the pure-Rust KDC embed
into [KLLDAP](embed/klldap.md).

## Era III — MIT 1.22.2 parity sweep (closed)

The parity sweep swept the KDC against MIT 1.22.2 source
function by function; four passes (FAST/cookie/entry validation, AS/`kdc_util`,
TGS policy/S4U/PAC, kadm5) produced the graded
[parity ledger](parity/README.md) (one row per MIT check); a
client-library pass swept the client library (`lib/krb5/krb`) and the
acceptor (`rd_req_dec.c`), and a kadm5 pass the kadm5 server. A close-out
ended the section. Every row is graded `exact`, `stricter-documented`,
`deviation`, `absent` or `deferred`; the two `absent` rows are the stated
non-goals (OTP preauth, `gss_wrap_size_limit`), and each `deferred` row
names the oracle that would promote it. 77 of the 364 `exact` rows have a
proof cell that names no gate, `diffsend` case, forge or live cell, and the
per-row sweep that marks a unit-only row forge-only has not been done ([parity README](parity/README.md)).
Deviations are in
[`mit-deviations.md`](mit-deviations.md) § Documented deviations.

## Era III — KLLDAP integration

`v1.0.0` is the tagged MIT/Samba/Heimdal baseline. Phase 1 aligns
edition **2024**, MSRV **1.95**, `nix` 0.31, and unpinned `rasn` 0.28
with KLLDAP (local checkout 0.7.4, upstream `Aelieth/klldap` 0.7.6) so a
future embed has no overlapping crate majors.
See [`embed/klldap.md`](embed/klldap.md). Replacing
`lldap-kerberos` FFI-to-system-MIT is a later phase.

**Tier 1 §6** (plugins / named policies / iprop) is in tree: KDB
traits + `MemoryStore`, kdcpreauth/kdcpolicy registries, named
policies + lockout (`policy-gate.sh`), iprop serial/ulog
(`iprop-gate.sh`). Plugin shape is Rust traits, not dlopen
([`plugins.md`](plugins.md)).
