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
rustdoc.

## Local checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Never add C FFI. `unsafe` is forbidden unless a future exception is
audited, minimized, and documented in the PR.
