# How to contribute to kerber-rust

This process is modeled on [LLDAP](https://github.com/lldap/lldap)'s
contributor guide: small, focused changes; tests that demonstrate the
bug; branches that land by fast-forward or a merge commit, never squash.
We are all volunteers — be precise, kind, and professional.

## Did you find a bug?

- Make sure there isn't already an [issue](https://github.com/Aelieth/kerber-rust/issues).
- Check whether it still happens on `main`.
- Open an issue with: a short summary, steps to reproduce, **verbose
  structured logs** (include `correlation_id`), expected vs actual
  behavior, and any packet captures or KDC traces.

## Do you want to work on a PR?

Start with an issue unless the change is a trivial doc or test fix. Agree
on the design there so you do not build a large PR that cannot land.

A good PR has:

- A title of the form `tag: Imperative sentence`, at most 72 characters.
  The tag is the crate or area touched: `crypto`, `asn1`, `types`,
  `config`, `log`, `protocol`, `client`, `kdc`, `gss`, `admin`, or
  `test`, `docs`, `ci`, `tool`, `harness`, `examples`. A change that spans
  two takes both (`admin/kdc:`). See [Commit Message
  Guidelines](https://gist.github.com/robertpainsi/b632364184e70900af4ab688decf6f53)
  for the imperative mood.
- A description that explains the **why** and the **how**, references
  the issue (`Fix #123`), and calls out limitations or potential flaws.
- The smallest change that solves the problem. Do not code-golf. Keep
  logically separate work in separate PRs.
- Tests that fail without the change and pass with it, covering
  significant new code paths. Prefer known-answer vectors and live
  interop against the MIT 1.22.2 harness over re-implemented oracles.
  When automation is impractical, document thorough manual testing with
  logs (and traces where relevant).
- For protocol behaviour, a feature is done only when it works in production against MIT 1.22.2 on the lab VMs, MIT first, and against the real AD where it reaches it; a Rust-vs-Rust round-trip is never proof.
- For a change to behaviour MIT also has, its row in the parity ledger
  (`docs/parity/`: MIT cite, check, verdict, proof), added or updated in
  the same PR.
- All existing tests still passing. CI is authoritative.

### Workflow

We use [GitHub Flow](https://docs.github.com/en/get-started/using-git/github-flow):

1. Fork (or branch from `main`).
2. Make the change.
3. Open a PR.
4. Address review by pushing more commits.
5. The PR lands by fast-forward, or by a merge commit when it cannot;
   it is never squash-merged.

## Code comments

Comments explain non-obvious intent, invariants, security considerations,
and protocol subtleties. Do not restate the obvious. A doc comment is one
line, and only where the name cannot say it. Comments are at most 3% of
the code, and doc comments count. Tests are at most 10% of the code.

**R1.** A MIT citation is one line, a pointer:
`// MIT <symbol>; see docs/parity/<file>.md`.
The file exists and names the symbol. The ranged anchor
``MIT `<symbol>` (`<path>:<a>-<b>`): <guarantee>`` stays legal until the
pointers replace it. A mention without a range is not a citation and is
legal.

**R2.** State the invariant, not the steps: an ordering, a fail-closed
rule, a key-material rule, an attacker-relevant subtlety, or a deliberate
deviation. Do not narrate the statements below the comment.

**R3.** No process history in source: no section or item tags (`R12`,
`A′-3`, `W0e`, `W1-Z`, `Round 2`, `B3`, `Y0`, `Z6.3`, `S2.3`, `item 15`,
`Z8 leftover`, a lone `B2` / `F4`), no commit hashes (`parent` plus a
hash, a backticked hash, "fails at" a hash), no red-at-parent notes
(`parent-red`, `Compiles at`, "the parent did X"), and no `working/`
paths. A deferred parity gap gets a ledger row and at most a one-line
pointer.

`check_mit_anchor_form` and `check_mit_anchor_truth` in
`scripts/ci-policy.py` keep R1 true, and `check_no_process_history`
keeps R3 true. See [docs/testing.md](docs/testing.md).

## Local checks

The `test` job in CI is `make safety` (fmt, clippy, nextest,
`ci-policy.py`) plus CI-only extras (nextest `--no-run`, junit).
`make doc` and `make shellcheck` are the sibling `doc` and
`shellcheck` jobs. Do not run `cargo test --workspace`
— CI forbids it on per-push; nextest is the runner. Linking needs `lld`
(`ld.lld` on `$PATH`; see
`.cargo/config.toml`). The gates need Docker.

```bash
make safety
```

The six per-push jobs are in [docs/testing.md](docs/testing.md).
Job walls live in `ci-budget.toml`.

Live MIT oracles (when Docker is available): `make harness` then
`make gate GATE=client-gate`, `make gate GATE=kdc-gate`,
`make gate GATE=bidirectional-gate`. `make stop-harness` tears the
container down.

Gate scripts write host files only under `KERBER_SCRATCH` (their default
is `/tmp/…`; point it at a directory you own). A live MIT settle runs
through `scripts/lib/settle.sh <name> -- <command…>` so its output is
stamped ([docs/testing.md](docs/testing.md)). `working/` is gitignored:
plans and evidence live there, named `<kind>-<topic>-<MMDD-HHMM>.md`, and
no tracked file cites them.

Never add C FFI. `unsafe` is forbidden unless a future exception is
audited, minimized, and documented in the PR.
