# How to contribute to kerber-rust

This process is modeled on [LLDAP](https://github.com/lldap/lldap)'s
contributor guide: small, focused changes; tests that demonstrate the
bug; GitHub Flow with squash merges. We are all volunteers — be precise,
kind, and professional.

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

- A title of the form `tag: Imperative sentence`. Tags include
  `crypto`, `asn1`, `protocol`, `client`, `kdc`, `docs`, `test`,
  `harness`, `log`. See [Commit Message
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
- All existing tests still passing. CI is authoritative.

### Workflow

We use [GitHub Flow](https://docs.github.com/en/get-started/using-git/github-flow):

1. Fork (or branch from `main`).
2. Make the change.
3. Open a PR.
4. Address review by pushing more commits.
5. The PR is **squash-merged**.

## Code comments

Comments explain non-obvious intent, invariants, security considerations,
and protocol subtleties. Do not restate the obvious. Public APIs need
rustdoc. The four rules in [docs/architecture.md](docs/architecture.md)
are the form:

- **R1.** A MIT anchor is one line:
  ``MIT `<c_function>` (`<file>.c:<a>-<b>`): <what the port guarantees>``.
  A single source line is `<a>-<a>`. The anchor slot is a C function.
- **R2.** State the invariant (order, fail-closed, key material, or a
  deliberate deviation). Do not narrate the next two lines.
- **R3.** No process history (`R12`, `W1-Z`, `Round 2`, a parent SHA).
  A deferred gap is a ledger row and at most a pointer.
- **R4.** `# Errors` names variants or conditions, never a family word
  and never "Returns …". `# Panics` only where a panic exists.

`check_mit_anchor_form` and `check_no_process_history` in
`scripts/ci-policy.py` keep R1 and R3 true. See
[docs/testing.md](docs/testing.md).

## Local checks

The `test` job in CI is `make safety` (fmt, clippy, nextest,
`ci-policy.py`) plus CI-only extras (nextest `--no-run`, junit, the
gate ERR-trap self-test). `make doc` and `make shellcheck` are the
sibling `doc` and `shellcheck` jobs. Do not run `cargo test --workspace`
for the unit suite — CI forbids that on per-push; nextest is the runner.
Doctests are `cargo test --workspace --doc` on the test job. Linking needs `lld`
(`ld.lld` on `$PATH`; see
`.cargo/config.toml`).

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
make snapshot OUT=working/logs/w3-hygiene/s1/new QUALITY=1
make checkpoint OUT=working/logs/w3-hygiene/s1/checkpoint
```

Both run only where the host `default_realm` is the `TESTLABBY.LOCAL` lab
stub, never on a machine whose `/etc/krb5.conf` names a real realm
(`KERBER_ALLOW_HOST_REALM=1` overrides and is recorded in the stamp).

Never add C FFI. `unsafe` is forbidden unless a future exception is
audited, minimized, and documented in the PR.
