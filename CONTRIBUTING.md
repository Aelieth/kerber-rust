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
- For protocol behaviour, a content-asserting gate that drives a real
  implementation (MIT 1.22.2 first, then Samba or Heimdal). A feature is
  done only when such a gate proves it; a Rust-vs-Rust round-trip is never
  proof.
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
and protocol subtleties. Do not restate the obvious, and do not raise the
comment density: a sentence the next two lines already say is deleted.
Public APIs need rustdoc. Four rules give the form; the comment budget moves
from process tags into invariants that are otherwise unstated.

**R1.** A MIT anchor is one line, in one form:
``MIT `<symbol>` (`<path>:<a>-<b>`): <what the port guarantees>``.
The symbol names the MIT definition whose extent contains the cited
range: a C function, a `struct` / `union` / `enum` or typedef, a table
or global, a macro or macro-generated item, an error-table entry, or an
ASN.1 type (its `NAME ::=` comment block). Never a Rust symbol, and
never a callee or macro standing in for the function. One anchor per
line, opening its own sentence. A single source line is written
`<a>-<a>`. A path whose basename names more than one MIT file carries
enough directories to name one. A mention without a range (``MIT `X` ``,
or a MIT file named in prose) is not an anchor and is legal. The
guarantee is what this port does; where the port deviates, the anchor
line says so ("MIT does X; this port does Y") and the deviation has a
parity-ledger row under `docs/parity/` (verdict `deviation` or
`stricter-documented`) or a `docs/security.md` row.

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

**R4.** `# Errors` names variants or conditions. It does not use a family
word ("crypto", "DER") and it does not open with "Returns". A function
that cannot fail says "None:" and why. `# Panics` appears only where a
panic exists.

`check_mit_anchor_form`, `check_mit_anchor_truth` and
`check_no_process_history` in `scripts/ci-policy.py` keep R1 and R3
true. See [docs/testing.md](docs/testing.md).

## Local checks

The `test` job in CI is `make safety` (fmt, clippy, nextest,
`ci-policy.py`) plus CI-only extras (nextest `--no-run`, junit, the
gate ERR-trap self-test). `make doc` and `make shellcheck` are the
sibling `doc` and `shellcheck` jobs. Do not run `cargo test --workspace`
— CI forbids it on per-push; nextest is the runner. Linking needs `lld`
(`ld.lld` on `$PATH`; see
`.cargo/config.toml`). The gates need Docker.

```bash
make safety
```

Per-push CI is three tiers (`docs/testing.md`); job walls live in
`ci-budget.toml`. `make budget` prints medians and `--check-budget`.

Live MIT oracles (when Docker is available): `make harness` then
`make gate GATE=client-gate`, `make gate GATE=kdc-gate`,
`make gate GATE=bidirectional-gate`. `make stop-harness` tears the
container down. Comparison snapshot / full gate checkpoint:

```bash
make snapshot OUT=working/logs/<archive>/new QUALITY=1
make checkpoint OUT=working/logs/<archive>/checkpoint
```

Gate scripts write host files only under `KERBER_SCRATCH` (their default
is `/tmp/…`; point it at a directory you own). A live MIT settle runs
through `scripts/lib/settle.sh <name> -- <command…>` so its output is
stamped ([docs/testing.md](docs/testing.md)). `working/` is gitignored:
plans and evidence live there, named `<kind>-<topic>-<MMDD-HHMM>.md`, and
no tracked file cites them.

Both run only where the host `default_realm` is the `TESTLABBY.LOCAL` lab
stub, never on a machine whose `/etc/krb5.conf` names a real realm
(`KERBER_ALLOW_HOST_REALM=1` overrides and is recorded in the stamp).

Never add C FFI. `unsafe` is forbidden unless a future exception is
audited, minimized, and documented in the PR.
