# T-7: constant-time measurement of krb5-crypto and krb5-types' PKINIT code (dudect)

A measurement tool, not a test, run at a release. For each op it takes two classes of timed
samples, interleaved in random order: **Left**, one fixed secret for the run, and **Right**, a fresh
random secret per sample. Everything not secret is the same in both, and inputs are prepared outside
the timed region. Only public APIs are used: `krb5-crypto`'s, and `krb5_types::pkinit`'s for the
PKINIT ops.

## Files

| file | what |
|---|---|
| `run.sh` | builds `timing` from this checkout into a temporary target dir, then runs every pass |
| `Cargo.toml` | binary package `timing`, its own `[workspace]` like `fuzz/`; path deps on `crates/`, `rasn` patched to `vendor/rasn` as the tree does, `dudect-bencher` to `vendor/dudect-bencher` (no `clap`; its PATCHES.md) |
| `Cargo.lock` | the tree's lock plus `dudect-bencher` and its deps, so the timed crypto crates are the versions that ship |
| `src/main.rs` | the harness |

`dudect-bencher`, `libc` and their dependencies sit outside the workspace's `cargo deny` and
`cargo vet`, as `fuzz/`'s do. CI runs `cargo check --locked` on this package.

After the tree's `Cargo.lock` changes, re-seed: `cp ../../../Cargo.lock Cargo.lock`, then
`cargo build --release` once without `--locked`. Cargo keeps the tree's versions, adds only
`dudect-bencher`'s deps and prunes the rest.

## Run

```sh
taskset -c N bash harness/hand/t7/run.sh            # the full pass: days
T7_DRY=1 bash harness/hand/t7/run.sh                # every pass with a few samples: shows it runs
```

`T7_OUT` names the results dir (default `$TMPDIR/t7-results-<time>`). The build takes the tree's
`.cargo/config.toml` (lld, `p384_backend="fiat"`). For a real run: pin one CPU (on a VM pin the vCPU
and keep its SMT sibling idle), use the `performance` governor, a `tsc` or `kvm-clock` clocksource,
run nothing else, and run twice. The counters need `perf_event_paranoid` at 2 or below.

The binary alone: `timing --list` names the ops; `--op NAME` (repeatable), `--samples N` (both
classes, default 1,000,000), `--seed S`, `--count time|cycles|instructions|branches|nearbranches`,
`--no-early-stop`, `--verbose` (per-batch statistics; with a counter, each class's per-sample
counts), `--crosscheck` (the port of dudect-bencher 0.7.0's statistics against the library itself:
`MATCH` or `MISMATCH`).

## The bar

- `time` (wall ns): |t| < 4.5 passes, |t| > 10 stops the op early; counts only on a fixed clock.
- `branches`: equal for both classes, exactly for an op too short to see an interrupt; for a longer
  one the fixed class's spread must equal the random class's, with equal means. `nearbranches`
  (AMD Zen: retired branches less far transfers, so interrupts drop out) is exact at any length;
  prefer it there.
- `instructions`: equal means at |t| < 4.5, the fixed class's spread quoted.
- `cycles`: the same-seed dudect over 3 seeds; a residual under 0.1% is report-only.
- DES3, RC4 and Camellia are `report-only`: printed, never judged.
- So are the six whole-op brainpool signing ops, `ecdsa-bp{256,384,512}{r1,t1}`: RFC 6979 redraws k
  at or above n on about a third of draws on a brainpool order. Their `-k` rows time the arithmetic
  alone and are judged.

## Output

```
tree=<checkout> rev=<HEAD> dirty=<yes|no>
crates aes=... krb5-crypto=... p384=... sha2=...
run samples=... batch=20000 seed=... cpus=... count=time pass=|t|<4.5 stop=|t|>10
op=<name> samples=<n> max_t=<x.xx> verdict=<pass|FAIL|report-only|ERROR>
```

`max_t` is the largest |t| of dudect-bencher's 101 Welch tests, signed (negative: the fixed secret
was faster). `ERROR` means an op did not give the result the timing assumes (checked on the first
256 inputs, and on every sample for `cksum-verify`); the exit status is then 2. A `FAIL` leaves the
exit status 0. A `pass` means no difference was seen with this noise and sample count, not that
there is none: a t just above 4.5 is often noise, so run again with `--verbose`; a leak keeps its
sign across runs and seeds.

## Not covered

Fixed against random on the secret inputs only: no ciphertext- or plaintext-dependent classes, no
cache or microarchitectural analysis. A result holds for that build, tree and machine. The fixed
secret is random per run, so a leak that shows only for a special secret is found only if a run
happens to choose one; other seeds choose others.
