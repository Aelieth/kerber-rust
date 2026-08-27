# Interop matrix

External-oracle gates that content-assert against a real implementation
(MIT 1.22.2, Samba 4 AD, Heimdal 7.8) plus the fail-red supply-chain
job. Per-gate assertions: [`testing.md`](testing.md). Timing/replay:
[`security.md`](security.md). Isolation: never edit host
`/etc/krb5.conf` (`TESTLABBY.LOCAL`).

A row is **in CI** when the named job runs it on `main` without
`continue-on-error`. Missing docker/image is honest `exit 2` unless
the script documents otherwise.

## MIT 1.22.2 (primary)

| Gate | Drives | Asserts | CI |
| --- | --- | --- | --- |
| `client-gate.sh` | Rust `krb5-kinit` vs MIT `krb5kdc` | MIT `klist` names TGT + `host/testhost.kerber.test` | harness |
| `kdc-gate.sh` | MIT `kinit`/`kvno` vs Rust KDC | MIT TGT + host ticket (FAST TGS `kvno` included) | harness |
| `gss-gate.sh` | MIT `libgssapi_krb5` initiator vs `krb5-gss-accept` | unwrap of `hello-from-mit-gss`; RRC=16 | harness |
| `pkinit-gate.sh` | MIT `kinit -X X509_user_identity=FILE:` vs Rust KDC | `pkinit.so` present; log `rfc8636 sha256 kdf` | harness |
| `spake-gate.sh` | MIT `kinit` `pa_type` 151 / group 2 vs Rust KDC | TRACE 151 + group 2; `klist` `user@KERBER.TEST` | harness |
| `sha2-gate.sh` | MIT `kinit`/`kvno` etype 20 vs Rust KDC | `klist -e` names `aes256-cts-hmac-sha384-192` | harness |
| `cross-realm-gate.sh` | MIT `kinit` + `kvno host/svc.other.test@OTHER.TEST` | `klist` has `krbtgt/OTHER.TEST` and the host ticket | harness |
| `kadmin-gate.sh` | MIT `kadmin` vs `krb5-kadmind` 749 | add/cpw/get/list/mod/chrand/ktadd/`renprinc`/del then `kinit extra` | harness |
| `kpasswd-gate.sh` | MIT `kpasswd` vs kadmind 464 | new password `kinit`; old fails; run twice | harness |
| `kdb-dump-gate.sh` | MIT `kdb5_util` dump/load both ways | MIT `kinit` vs Rust on loaded dump; MIT `krb5kdc` + `kinit` on Rust dump v7 | harness |
| `differential-gate.sh` | same AS/TGS bytes to Rust and MIT on one dump | stable-rep / error-code compare; un-whitelisted mismatch fails red | harness |
| `kprop-gate.sh` | MIT `kprop` dump v7 vs `krb5-kpropd` 754 | MIT `kinit user` on replica; `klist` names `user@KERBER.TEST` | harness |
| `kprop-reverse-gate.sh` | Rust `krb5-kprop` vs MIT `kpropd` | MIT `krb5kdc` + MIT `kinit user@KERBER.TEST` | harness |
| `restart-gate.sh` | MIT `kadmin addprinc extra`; kill `krb5-kdc` by comm; relaunch | MIT `kinit extra` after relaunch; MIT load of persist dump v7 | harness |
| `s4u-mit-gate.sh` | MIT `kvno -U` / `-U -P` vs Rust KDC | `klist` `for client user@KERBER.TEST`; non-forwardable → `BADOPTION` | harness |
| `prod-realm-gate.sh` | MIT client vs Rust primary/replica `PROD.KERBER.TEST` | MIT `kinit`/`kvno`/`kadmin`; kprop failover; NIC pcap when required | harness |
| `stress-gate.sh` | wire AS+TGS + MIT `kinit`/`kvno` under load | p99 `duration_us` ≤ 50 ms; ≥ 8 issue-ok/s; error-rate 0 | harness |
| `chaos-gate.sh` | `tc netem` + memory cap + primary kill under load | MIT completes; no OOM-panic; replica `kinit`/`kvno` after kill | harness |

## Samba 4 AD (AD.KERBER.TEST)

| Gate | Drives | Asserts | CI |
| --- | --- | --- | --- |
| `samba-ad-gate.sh` | live Samba DC `kinit`/`kvno` | `klist` after live AS/TGS; missing image `exit 2` | harness |
| `ad-windows-gate.sh` | Samba `kinit kbruser` + `kvno host/svc` | live Samba ticket (not the torn-down Windows DC) | harness |
| `ad-s4u-gate.sh` | Samba `kvno -U` / `-U -P` | `klist` names `host/svc.ad.kerber.test` for `kbruser` | harness |
| `samba-pac-verify-gate.sh` | Samba decode of a Rust PAC (L1) | buffers `{1,10,12,16,17,18,19,6,7}`; dummy SID fails | harness |
| `samba-pac-l2-gate.sh` | vendored Samba `kcrypto` 6/7/16/19 (L2) | recompute; type-6/16 MAC flip → `L2_MISMATCH` | harness |
| `samba-crossrealm-gate.sh` | MIT `kvno` both ways vs Samba (L3) | Samba logs must not contain `PAC … failed` | harness |
| `samba-realtrust-gate.sh` | `samba-tool domain trust create` + reverse PAC | reverse LOGON_INFO SID/RID = live Samba-A `kbruser` `objectSid` | harness |

`ad-mit-trust-gate.sh` is an alias of `samba-realtrust-gate.sh`. It does
not claim a Windows DC.

## Heimdal 7.8 (secondary)

| Gate | Drives | Asserts | CI |
| --- | --- | --- | --- |
| `heimdal-gate.sh` | Heimdal `kinit`/`kgetcred` vs Rust; Rust `krb5-kinit` vs Heimdal | AES-SHA1 both ways; `klist` names `user@KERBER.TEST` and `host/testhost.kerber.test`; missing image `exit 2` | harness |

## Supply-chain (not an interop oracle)

| Check | Drives | Asserts | CI |
| --- | --- | --- | --- |
| cargo-audit | `rustsec/audit-check` | known advisories fail red | audit |
| cargo-deny | `deny.toml` licenses/advisories/sources | allowlist only; crates.io sources | audit |
| `scripts/geiger.sh` | per-crate `cargo geiger --forbid-only` | product 0-unsafe / `forbid(unsafe)`; dep surface archived, not a count gate | audit |
| `cargo vet --locked` | `supply-chain/` (Google / Mozilla / Bytecode Alliance) | every third-party crate imported, locally audited, or exempt; cargo-vet **0.10.0** | audit |

## Not external oracles

These run in CI (or scheduled) but **do not** count as an external
implementation oracle.

| Item | Why not an oracle | CI |
| --- | --- | --- |
| `bidirectional-gate.sh` | Rust client vs Rust KDC | harness |
| `prod-gate.sh` | loopback Rust↔Rust on `127.0.0.1` | harness |
| `soak-gate.sh` | self RSS / latency on the prod realm (MIT sampling is not the leak proof) | harness + `soak.yml` |
| golden MIT DER + crypto KATs | in-repo fixtures, not a live peer | test |
| 8 cargo-fuzz targets | `fuzz.yml` smoke, not an interop peer | fuzz |
| `gss-sspi-gate.sh` | honest `exit 2` when the SSPI oracle is absent | not a green claim |
| in-process `bounded_stress` | not the wire stress-gate | unit |
| cargo-vet exemptions | shrinking list; not a full local audit of every crate | documented |
| in-process metrics counters | deferred; logs-as-metrics only (`logging.md`) | n/a |

MSRV 1.85 `cargo test --workspace --locked` is the `msrv` job (`rasn = "=0.27.0"`).
`publish = false` stays; this matrix is the 1.0 claim, not crates.io.
