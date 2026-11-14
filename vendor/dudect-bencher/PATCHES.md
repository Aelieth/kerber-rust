# vendor/dudect-bencher: dudect-bencher 0.7.0, patched

This is dudect-bencher 0.7.0 as crates.io publishes it. The crate is
`dudect-bencher-0.7.0.crate`, sha256
`6a6174adfb35811a6845001876823965032406784c36e795edb84a74353455e1`, the checksum the T-7
harness's `Cargo.lock` held.

Only the T-7 timing harness (`harness/hand/t7/`) uses it, through `[patch.crates-io]` in its
`Cargo.toml`; nothing that ships does. The harness calls the library (`ctbench`, `CtRunner`,
`Class`, `BenchRng`) and never the `ctbench_main!` macro, which is the crate's only use of
`clap` 2. `clap` 2 brings `ansi_term` and `atty`, both unmaintained (RUSTSEC-2021-0139,
RUSTSEC-2024-0375) and `atty` unsound (RUSTSEC-2021-0145), so `cargo audit --deny warnings`
failed on the harness's lock.

The changes:
- `src/macros.rs` and `examples/ctbench-foo.rs` (the macro and its example) are removed, and
  `src/lib.rs` no longer declares the `macros` module.
- `Cargo.toml` drops the `clap` dependency and the example.
- Upstream's `Cargo.lock` is removed; the harness's own lock governs.
- This file is new.

To review the delta:

```sh
curl -sL https://static.crates.io/crates/dudect-bencher/dudect-bencher-0.7.0.crate | tar -xz
diff -ru dudect-bencher-0.7.0 vendor/dudect-bencher
```
