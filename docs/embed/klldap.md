# KLLDAP alignment

Goal: kerber-rust becomes the pure-Rust KDC inside
[KLLDAP](https://github.com/Aelieth/klldap) (AGPL-3.0-only), replacing
the `lldap-kerberos` FFI wrapper (klldap's `kerberos` crate) around system MIT
Kerberos. This document records what is aligned today, how KLLDAP's seam
maps onto kerber-rust's API, and what the embed itself still has to build.

Ground truth is the KLLDAP repository,
[`Aelieth/klldap`](https://github.com/Aelieth/klldap), at **0.7.6**; the local
checkout read for this page reports workspace version `0.7.4` in its
`Cargo.toml`. Both trees are edition 2024 with `rust-version` 1.95.0.
kerber-rust stays Apache-2.0 OR MIT; `publish = false`.

## Toolchain parity

| Knob | kerber-rust | KLLDAP |
| --- | --- | --- |
| edition | 2024 | 2024 |
| MSRV (`rust-version`) | 1.95 | 1.95.0 |
| CI `msrv` job | `cargo build --workspace --all-targets --locked` on 1.95; the tests run on 1.95 in `full-test.yml`'s `msrv-test` | (klldap's own CI) |
| async | sync (no tokio) | tokio; the embed runs the KDC's loop on a thread of its own |
| `unsafe` | product `forbid(unsafe_code)` | its `kerberos` crate's `src/ffi.rs` only (the FFI this replaces) |

## Shared crates

| Crate | Status |
| --- | --- |
| `nix` | **0.31** on both sides (klldap resolves 0.31.3) |
| chrono 0.4, thiserror 2, tracing 0.1, sha2/hmac/md-5 0.10, zeroize 1, getrandom 0.2, serde 1 | already the same major |
| rasn, aes/des/rc4/camellia/cmac, p256, md4, pbkdf2 | kerber-only (additive) |

`rasn` is a normal `0.28` requirement (resolved **0.28.14**). MIT golden DER
(`crates/krb5-protocol/tests/golden_traces.rs`) still byte-matches
checked-in `tests/traces/mit-*.der`. Dual `getrandom` 0.2/0.4 remains
via `rasn-derive-impl` → `uuid` (proc-macro only).

A scratch path-dep of `krb5-kdc` into klldap `crates/kerberos`, then
`cargo tree -d`, showed **no new runtime duplicate major**. The klldap tree
was reverted; nothing was committed there.

## Drift guard

When either tree bumps a shared crate, the other follows the same
generation. Optional check: co-located checkouts, temporary path-dep,
`cargo tree -d`, revert.

## What KLLDAP runs today

- `kerberos_manager` (klldap's `kerberos` crate, `src/manager.rs`) renders
  `kerberos/kdc.template.conf` (`[kdcdefaults] kdc_ports = 750,88`,
  `master_key_type` and `supported_enctypes` aes256-cts-hmac-sha1-96), runs
  `kdb5_util create -s` with a random master password it then discards
  (only the stash keeps the key), creates `admin/admin` with a random key and
  its keytab, and supervises `krb5kdc` and `kadmind`.
- The image publishes 88/tcp, 88/udp and 749/tcp; 464 is not published.
- `LiveKerberos` (the same crate, `src/live.rs`) implements the seam below
  through `libkadm5` (`kadm5_create_principal`, `kadm5_chpass_principal`,
  `kadm5_delete_principal`, `kadm5_randkey_principal`, and
  `kadm5_modify_principal` of `DISALLOW_ALL_TIX`), plus
  `kadmin.local ktadd -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal`
  for the Keycloak keytab.

kerber-rust's KDC and kadmind start on KLLDAP's `kdc.conf` shape as it is:
`scripts/kdc-gate.sh` restarts a realm on `kdc_ports = 750,88` with no listener
relation for kadmind or kpasswd and drives MIT `kinit` (TCP 88, UDP 750),
`kadmin` (`addprinc -randkey`, `ktadd` on 749) and `kinit -k` at the
container's non-loopback address.

## The seam

KLLDAP reaches its KDC through the `KerberosSync` trait
(klldap's `domain-handlers` crate, `src/kerberos.rs`), registered with
`set_kerberos_backend`; errors are `String`. The embed implements it over
kerber-rust's `PrincipalStore`, so the directory stays the writer:

| `KerberosSync` | kerber-rust (`krb5_kdc::PrincipalStore` unless named) | Note |
| --- | --- | --- |
| `ready` | the embedded listener's own state | KLLDAP probes TCP to the KDC port today |
| `sync_principal` (chpass, else create) | `set_password`; `create_principal_3_in` for a new user | `user@REALM`, keys per `supported_enctypes` |
| `delete_principal` (missing is Ok) | `remove_in` | the ACL-gated `delete` is for kadmind |
| `set_principal_enabled` | `set_status` (sets / clears `KDB_DISALLOW_ALL_TIX`) | it also writes `pw_expire`: pass the current value |
| `export_keytab_for_keycloak` | `insert_new_randkey` when missing, then `ktadd_local_atomic` / `chrand_etypes_keepold_in` with aes256 + aes128, and `Keytab::write_file` | MIT's `ktadd` re-keys, so the kvno moves on every export |
| persistence | `load_store` / `save_store` (dump-v7 text + a stash in MIT keytab form) | an existing KLLDAP volume is MIT db2: migrate once with MIT `kdb5_util dump`, then `krb5-kdb load` |
| the KDC | `bind_udp_listeners` / `bind_tcp_listeners` on `KdcConf::kdc_udp_listeners` / `kdc_tcp_listeners`, then `serve_all_until` with the embedder's shutdown flag | not `serve` / `serve_all`: those install SIGTERM / SIGINT handlers; `serve_all_until` runs MIT's one loop on the thread that calls it, and a plugin module set for that thread alone does not apply while it runs |

## Policy and audit

KLLDAP 0.7.6's catalog (its domain-handlers policies module, `POLICY_ITEM_CATALOG`) marks each item "Not yet enforced" on the directory side. The KDC side is the MIT feature or the plugin interface an embedder registers. Nothing here reads the OU catalog.

| KLLDAP item | Where it is served |
| --- | --- |
| `lockout-threshold` | kadm5 policy `max_fail` (`store/policy.rs` `max_fail_for`). `0` is no lockout. The KDC returns `LOCKED_OUT` / `CLIENT_REVOKED` from that count. |
| `lockout-duration-seconds` | kadm5 policy `pw_lockout_duration` on the same policy. `0` lasts until a successful AS. |
| `inactivity-days` | the KDC records `last_success` (`PrincipalRead::last_success_of`, `kdb.rs`). It does not disable a principal after N quiet days. `set_status` is how an account is enabled or disabled. |
| `require-mfa` | not a KDC check. TOTP is KLLDAP's own login, and OTP preauth is not a module here. |
| `login-hours` | not built in. An embedder `KdcPolicy` denies outside the window. `check_as` / `check_tgs` are enough; the request time is the KDC's clock. |
| `allowed-networks` | not built in. An embedder `KdcPolicy` reads the socket peer from `check_as_from` / `check_tgs_from`. That address is the accepted socket, not `request.addresses`. |

`[plugins] kdcpolicy` and `[plugins] audit` select those embedder modules by name. The audit built-in is `json`. KLLDAP's `[logging]` templates stay the kdc.conf lines already in `kerberos/kdc.template.conf` (`kdc_ports = 750,88` and the enctype list).

## What the embed still has to build

These are larger than a release touch-up and belong to the embed or a later
kerber-rust point release:

- **One store for the KDC and the admin verbs.** The KDC serves a
  `SharedStore` (`Arc<RwLock<Box<dyn Store>>>`); the admin verbs above are
  methods of the concrete `PrincipalStore` and are not on `dyn Store`. Today
  the two meet through the dump file (the KDC's `reload_if_stale` re-reads it
  after kadmind writes), which is the two-process model inside one process.
- **kadmind as a library.** `Kadmind` and `serve_kadmind_until` run
  kadmind's loop (kpasswd over UDP and TCP, kadm5 on its RPC listeners) on
  the caller's thread over a `SharedDump`, as `krb5-kadmind` does; the
  listener setup lives in the binary. An embedder serving kadm5 or
  kpasswd from a `SharedDump` calls `PrincipalStore::init_pwqual` on the store
  itself, as `krb5-kadmind` does at start; without it the realm's `dict_file`
  is not applied. Remote MIT `kadmin` on 749 (which
  the satomlin fleet uses for `addprinc -randkey` + `ktadd`) is that loop on
  a thread beside the KDC's, or `krb5-kadmind` run beside KLLDAP.
- **Bootstrap.** `PrincipalStore::bootstrap` creates a test user and admin with
  passwords; KLLDAP wants krbtgt, `kadmin/*` and a random-key admin with no
  password. Build it from `PrincipalStore::new` and `create_principal_3_in`.
- **`kadm5_hook`** is [`Kadm5Hook`](../../crates/krb5-kdc/src/store/kadm5_hook.rs):
  an embedder registers a module with `register_kadm5_hook`. The directory does
  not have to. **`kadm5_auth`** is still not implemented (`docs/parity/a4-kadmin.md`).

## KLLDAP-side items the embed should carry

- `kdc.template.conf` sets no `max_renewable_life`, so new principals get 0 and
  tickets are not renewable (the satomlin fleet fixes each user by hand with
  `modprinc -maxrenewlife`). MIT and kerber-rust agree on that default; the
  template should set `max_renewable_life = 7d`.
- KLLDAP's container gate phases name MIT process names (`krb5kdc`,
  `kadmind`), `kadmin.local` output and MIT file paths; they need MIT
  `kinit` / `klist` / `kvno` as clients only.
- Kerberos as the combined work is AGPL because of klldap; kerber-rust's own
  license does not change.
