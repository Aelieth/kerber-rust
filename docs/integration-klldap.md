# KLLDAP alignment

Era III goal: kerber-rust becomes the pure-Rust KDC inside
[KLLDAP](https://github.com/Aelieth/klldap) (AGPL-3.0-only), replacing
the `lldap-kerberos` FFI wrapper around system MIT/Heimdal. This
document is **Phase 1 only**: matching dependencies and toolchain so a
future path-embed does not pull two generations of the same crate.
The FFI replace is a later phase.

Ground truth for shared versions is KLLDAP **0.7.5**
(`/home/local/Projects/klldap/`, workspace version 0.7.4, edition 2024,
`rust-version` 1.95.0). kerber-rust stays Apache-2.0 OR MIT;
`publish = false`.

## Toolchain parity

| Knob | kerber-rust | KLLDAP 0.7.5 |
| --- | --- | --- |
| edition | 2024 | 2024 |
| MSRV (`rust-version`) | 1.95 | 1.95.0 |
| CI `msrv` job | `cargo test --workspace --locked` on 1.95 | (klldap's own CI) |
| async | sync (no tokio) | tokio; embed will be threads / `spawn_blocking` |
| `unsafe` | product `forbid(unsafe_code)` | (klldap crate policy) |

## Shared crates

| Crate | Status |
| --- | --- |
| `nix` | **0.31** (was the only runtime clash: 0.29 vs klldap 0.31.3) |
| chrono 0.4, thiserror 2, tracing 0.1, sha2/hmac/md-5 0.10, zeroize 1, getrandom 0.2, serde 1 | already the same major |
| rasn, aes/des/rc4/camellia/cmac, p256, md4, pbkdf2 | kerber-only (additive) |

`rasn` is a normal `0.28` requirement (resolved **0.28.14**). The old
`=0.27.0` pin existed only to keep MSRV 1.85 green. MIT golden DER
(`crates/krb5-protocol/tests/golden_traces.rs`) still byte-matches
checked-in `tests/traces/mit-*.der`. Dual `getrandom` 0.2/0.4 remains
via `rasn-derive-impl` → `uuid` (proc-macro only).

A scratch path-dep of `krb5-kdc` into klldap `crates/kerberos`, then
`cargo tree -d`, showed **no new runtime duplicate major**. nix unified
at 0.31.3. The only extra `-d` row was proc-macro `itertools` 0.13
(klldap already carried 0.12 and 0.14). The klldap tree was reverted;
nothing was committed there.

## Drift guard

When either tree bumps a shared crate, the other follows the same
generation. Optional check: co-located checkouts, temporary path-dep,
`cargo tree -d`, revert. Do not merge kerber into klldap until a later
Era III phase owns that seam.

## Later phases (not this document)

- Run the sync KDC on dedicated threads / `spawn_blocking` off klldap's
  tokio. No async refactor of kerber-rust for the embed.
- Replace `lldap-kerberos` FFI with kerber-rust, reusing
  `lldap_domain_handlers` as the principal store.
- Combined work is AGPL because of klldap; kerber-rust's own license
  does not change.
