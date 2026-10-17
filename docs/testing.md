# Testing strategy

How the local checks and the CI jobs run.

## Gate discipline

The local entry point is `make safety` (fmt, clippy, nextest under
`harness/nextest-krb5.conf`, then `python3 scripts/ci-policy.py`). `make doc`
is the sibling `doc` job, `cargo doc --workspace --no-deps` under
`RUSTDOCFLAGS=-D warnings`. `make shellcheck` is the `shellcheck` job.
Clippy runs twice: `--all-features`, then with no features, both
`-D warnings`.


`check_mit_anchor_form` (`scripts/ci-policy.py`) reads every comment
line under `crates/*/src` and `crates/*/tests`: `//`, `///`, `//!`, and
each line of a `/* */`, `/** */` or `/*! */` block. A MIT anchor has the
R1 form ([CONTRIBUTING.md § Code comments](../CONTRIBUTING.md#code-comments)),
with a path ending in `.c`, `.h`, `.hin`, `.et`, `.x` or `.y`. A
mention, ``MIT `X` `` with no range, is legal, and so is a rangeless
file mention (``(`gic_pwd.c`)``, a module header naming the MIT file it
mirrors). Red: a `path.ext:N` or `path.ext:N-M` anywhere outside an
anchor's head, two anchors on one line, an anchor with no guarantee on
its line, a guarantee that is empty, starts with punctuation, or says
only "same check.", "MIT." or the symbol's name, and a basename that
names more than one file under the MIT tree (`main.c`, `str_conv.c`,
`auth.h`, …) without a directory. `MIT_ANCHOR_ALLOW` is 0, so the
check is hard. `check_mit_anchor_truth` (the nightly `anchors` job) proves
that each anchor's range lies inside that definition.

`check_mit_anchor_truth` runs where `KERBER_MIT_SRC` names the MIT
1.22.2 tree (the nightly `anchors` job) and resolves each anchor against a
definition, never a use: a C function (its `(` may open the next line)
from the comment block directly above its storage-class and return-type
lines (three more lines of slack) to its closing `}`; a `struct` /
`union` / `enum`, a typedef (including a declarator list after `}` and
rpcgen's `typedef struct X X;`), or a function-pointer typedef; a
file-scope table or global; a macro-generated definition by its first
argument; an ASN.1 type by the `NAME ::=` comment block MIT copies
above it; and in a header, `.et`, `.x` or `.y` file a `#define`, a type,
a static inline function, a prototype, an `error_code` or an rpcgen
item. The anchor's range must
lie inside that extent. A callee or macro named in a function's place,
a range past the closing brace, MIT test code (`t_*.c`, `tests/`) cited
from product code, an unknown file, and a basename that names more than
one file are red, and so is a rangeless file mention that does not name
exactly one file. It lists every violation. The resolution is a port of
the audit's reference resolver. `MIT_TRUTH_ALLOW` is 0, so the check is
hard.

`check_no_process_history` rejects a process tag on any comment line
under `crates/` (block comments included): `R<n>`, `A′-<n>`, a pass name
of `W`, `0` and a letter a–f, `W1-<letter>`, `Round <n>`, `parent` plus
seven hex digits, `R<n>-<letter><n>`, `Y0`, `Z<n>.<n>` or `Z<n>b.<n>`, a
backticked seven- or eight-digit commit hash, `parent-red`, `Compiles at`,
`item <n>`, `S<n>.<n>`, `Z<n> leftover`, a lone `B<n>` / `F<n>`, "the
parent `…`", a `working/` path, and `fails at` plus a seven- or
eight-digit hash. A tag inside a string literal is not a comment.
`PROCESS_TAG_ALLOW` is 0, so the check is hard. Rule names (`R1`–`R4`)
live in `docs/`, never in `crates/`. `check_no_docs_process_tags` counts
the `docs/**` lines, outside code fences, that carry a process tag, one
arm each, disjoint, one fixture line per arm: `W1-<letter>`,
`R<n>-<letter><n>`, `Z<n>` with an optional `.<n>` and `b`, `item <n>`,
`A′-<n>`, a swath `W<n>-S<n>`, a pass name of `W`, `0` and a letter a–f,
`Track <A-C>`, a phase label `(A<n>)` / `(D<n>)`, a pass name `C<n>`, a
bare workstream `W<n>`, a phase pair `A<n>/A<n>`, a bare phase or audit
label `D<n>` / `E<n>` / `J<n>`, and `Batch <letter>`. Not counted: the
roadmap's stage and era names (G1–G9, Era II–III, which `stages.md`
defines) and the ledger's section keys A1–A5 / B1; a bare phase label
`A<n>` is indistinguishable from a section key and is not judged. A
backticked `==== … ====` section cite that resolves in its script is the
script's text and is skipped until the sections that carry a tag are
renamed. `DOCS_PROCESS_TAG_ALLOW` is 0, so the check is hard.

`check_doc_file_cites` fails a backticked
`crates`/`scripts`/`docs`/`tests`/`harness`/`.github`/`examples` file
path that does not exist. `CHANGELOG.md` is excluded, and so is
`docs/parity/` (history: a retired path there is not a live cite).
`scripts/ci-policy.py` runs the checks in `scripts/ci_policy/`
(`comments`, `docs`, `golden`, `hygiene`, `ledger`, `workflows`).

### Tier contract

Job walls live in `ci-budget.toml` (one source). `ci-status.py --check-budget`
compares a completed SHA, or the last N runs, against that file. A run cannot
measure itself. No workflow runs that check on a schedule.

- **Tier 1** — per-push blocking (`.github/workflows/ci.yml`): `test` 360,
  `doc` 90, `shellcheck` 150, `msrv` 150, `audit` 260, `mit-smoke` 150.
  Combined wall ≤ `[push].run_wall` (360 s).
- **Tier 2** — none. No per-push job is `continue-on-error`.
- **Tier 3** — scheduled: `nightly.yml` (`oracles`, `moving`, `fuzz`,
  `anchors`; `test-release` and `msrv-test` on a tag or a manual run) and
  `peers.yml`.

### CI lanes (which job runs which gates)

Per-push (`.github/workflows/ci.yml`). Every workflow grants `permissions:
contents: read` at the top (the `audit` job adds `checks`/`issues: write`
for `rustsec/audit-check`). `ci.yml` cancels a superseded run
(`concurrency`). Every third-party `uses:` is pinned to a commit SHA
with the tag in a comment, and `.github/dependabot.yml` moves the pins.
The toolchain, lld, and `rust-cache` steps are one composite,
`.github/actions/rust-preamble`.

| Job | Runs |
| --- | --- |
| `test` | `python3 scripts/ci-policy.py`, `cargo fmt --all -- --check`, `cargo clippy -D warnings` with `--all-features` and with none, `cargo nextest run --workspace --profile ci` with the test-hooks features, then `--profile ci-nofeatures --locked`, then doctests |
| `doc` | `cargo doc --workspace --no-deps` under `RUSTDOCFLAGS=-D warnings`, then `cargo check --locked --manifest-path fuzz/Cargo.toml --bins` |
| `shellcheck` | `shellcheck -S style` on `scripts/*.sh`, `scripts/lib/*.sh`, `harness/*.sh`, `dist/*.sh`, `harness/field/*.sh`, `harness/field/lib/*.sh`, and `harness/field/scenarios/*.sh`. ShellCheck is v0.11.0, checked by sha256. `.shellcheckrc` sets `external-sources=true` and disables `SC2329` |
| `msrv` | `cargo build --workspace --all-targets --locked` on Rust 1.95, with the test-hooks features and without |
| `audit` | `cargo audit`, `cargo deny`, `cargo vet --locked` (cargo-vet 0.10.0) |
| `mit-smoke` | `run-harness.sh`, `client-gate.sh`, then a stock MIT KDC and `kdc-gate.sh`, `differential-gate.sh` |

`nightly.yml` (cron `17 4 * * *`, manual, the `nightly` label on a pull request, and `v*` tags) runs four jobs on the schedule and the label. `moving` is one job, `fail-fast: false`, four groups. Each group is its own runner: it loads the MIT image, boots a shell and a stock MIT KDC, and runs only its gates. A gate step runs when its group matches and the job has not been cancelled. Cleanup is `if: always()`.

| Group | Gates |
| --- | --- |
| `harness` | `ccache`, `bidirectional`, `gss`, `pkinit`, `kadmin-rust`, `kadmin-rust-acl`, `kadmin-mit`, `kadmin-both`, `history-mit` |
| `harness-2` | `kpasswd-rust`, `kpasswd-mit`, `kdb-dump`, `kprop`, `kprop-reverse`, `cross-kdc`, `iprop`, `expire`, `kdcpolicy`, `flags`, `renew`, `postdate`, `getprivs`, `policy`, `prop-acl` |
| `mit-extra` | `cross-realm`, `capaths-compress`, `spake`, `rust-kinit-spake`, `mit-fast-kdc`, `rust-kinit-fast`, `rust-kinit-pkinit`, `rust-kinit-enterprise`, `ktutil`, `kadmin-local`, `rust-kpasswd-mit`, `sha2`, `rc4-session` |
| `mit-extra-2` | `client-differential-flows`, `client-differential-cli`, `knobs`, `config-include`, `s4u-mit`, `capaths-transit`, `otp`, `rust-kinit-otp` |

| Job | Runs |
| --- | --- |
| `oracles` | `asn1-decode-oracle-gate.sh`, `rd-priv-oracle-gate.sh` |
| `fuzz` | six smokes, 60 s each, rss limit 2048 MiB: `der_decode`, `gss_token`, `pkinit_cms`, `spake_point`, `oakley_dh`, `transited` |
| `anchors` | `python3 scripts/ci-policy.py` with `KERBER_MIT_SRC` set to the pinned MIT 1.22.2 tree |
| `test-release` | `cargo nextest run --workspace --release --profile ci` with the test-hooks features. Tags and manual runs |
| `msrv-test` | `cargo test --workspace --locked` on Rust 1.95 with the test-hooks features. Tags and manual runs |

A gate in `moving` is deleted in the commit whose production cell passes. At the release cut, `moving` holds only the gates still waiting on a cell, and the `oracles` stay nightly.

`peers.yml` (cron `12 6 * * *`, and manual) runs Samba AD: `samba-ad-gate`, `ad-windows-gate`, `ad-s4u-gate`, `samba-pac-verify-gate`, `samba-pac-l2-gate`, `samba-crossrealm-gate`, `samba-realtrust-gate`. Per-gate detail is in [gates.md](gates.md).


## MIT 1.22.2 harness

The documented entry point is `scripts/run-harness.sh`. It builds an image
pinned to MIT krb5 1.22.2, starts a KDC for realm `KERBER.TEST` on UDP/TCP
port 88, emits JSON logs with a `correlation_id`, and runs `kinit` for
`user@KERBER.TEST`.

Requires Docker.
[labs/ad-lab.md](labs/ad-lab.md) has the AD lab coordinates and the `~/adlab`
isolation protocol.

| Item | Value |
| --- | --- |
| Realm | `KERBER.TEST` |
| KDC ports | UDP/TCP 88 |
| Principal | `user@KERBER.TEST` / password `userpassword` |
| Service | `host/testhost.kerber.test` (randkey) |
| Image | `harness/Dockerfile`, `KRB5_VERSION=1.22.2` |

```bash
./scripts/run-harness.sh
# kinit inside the container; logs on stdout as JSON
./scripts/stop-harness.sh
```

Host-side `kinit` (if you have MIT clients installed):

```bash
KRB5_CONFIG="$PWD/harness/client-krb5.conf" kinit user@KERBER.TEST
```

Golden traces under `tests/traces/mit-*.der` are decoded and
field-diffed in `crates/krb5-protocol/tests/golden_traces.rs` (unit CI).
Reply goldens are MIT-KDC bytes from `client-gate.sh`. Do not commit
`/working`. `bidirectional-gate.sh` is a Rust-client↔Rust-KDC check,
not a live MIT oracle.

## Rust KDC test realm

`scripts/run-rust-kdc.sh` (`krb5-kdc --test-realm`) bootstraps realm
`KERBER.TEST` and listens on **127.0.0.1:88**, falling back to
**127.0.0.1:8888** if the privileged port cannot be bound. It never silently
binds `0.0.0.0`.

| Item | Value |
| --- | --- |
| Realm | `KERBER.TEST` |
| User | `user@KERBER.TEST` / `userpassword` |
| Admin | `admin@KERBER.TEST` (ACL `*`; extract needs `e`) |
| Host | `host/testhost.kerber.test` (random keys, etypes 17–20) |
| Default etype | 18 (`aes256-cts-hmac-sha1-96`); krbtgt/host also hold RFC 8009 19/20 |

```bash
./scripts/run-rust-kdc.sh
# or: cargo run -p krb5-kdc --bin krb5-kdc -- 127.0.0.1:8888
./scripts/kdc-gate.sh    # MIT 1.22.2 kinit + kvno against the Rust KDC
```

Admin mutations go through MIT `kadmin` against `krb5-kadmind` on 749
(AUTH_GSSAPI) for add/get/list/mod/chrand/rename/del, RFC 3244 `kpasswd` on
UDP/TCP 464, and `kprop`/`kpropd` (TCP 754) both directions. Named password
policies, lockout with time-based auto-unlock, and incremental propagation
(iprop / ulog, program 100423) are in tree; the plugin surface is Rust traits,
not `dlopen` ([docs/plugins.md](plugins.md)).

### Test-only inputs (`test-hooks`)

The gates, CI, and `make safety` build with
`--features krb5-kdc/test-hooks,krb5-admin/test-hooks,krb5-client/test-hooks`
(the gates through `scripts/lib/build-bins.sh`, whose one cargo invocation also
carries the client tools); `krb5-kdc/test-hooks` turns on `krb5-config/test-hooks`
and `krb5-protocol/test-hooks` for every binary of that build, and `krb5-admin/test-hooks`
turns on `krb5-gss/test-hooks`. Only such a build reads these inputs or builds the test
programs (`krb5-tools`', `krb5-gss`'s, `krb5-iprop-pull`): a release build has neither, as
MIT's tools read none of these inputs. CI's test job and `make test` then run the
workspace's tests once more without features
(`cargo nextest run --workspace --profile ci-nofeatures --locked`, its junit beside the first
run's), so the release-only units
run too: a release `kvno` and `kinit` refusing the gates' options, `kinit -S`
asking the AS, `a_release_build_reads_no_path_override`, and every test's release
branch.

| Input | Read by | A release build instead |
| --- | --- | --- |
| `KRB5_PASSWORD`, `KRB5_NEW_PASSWORD` | `krb5-kinit`, `krb5-kpasswd`, `krb5-ktutil` (`krb5_config::env_password`) | prompts: `Password for <principal>`, `Enter new password` / `Enter it again`, one line each from a pipe |
| `KRB5_KDC_CONF` | every KDC-side tool, after `KRB5_KDC_PROFILE` | `KRB5_KDC_PROFILE`, else `/var/kerberos/krb5kdc/kdc.conf` |
| `KRB5_KDC_DB`, `KRB5_KDC_STASH`, `KRB5_ACL_FILE`, `KRB5_MASTER_ETYPE` | `KdcPaths` (`crates/krb5-config/src/kdcconf.rs`) | the realm's kdc.conf relations, else MIT's defaults |
| `KERBER_CAPTURE_DIR` | `capture_pdu` (KDC and client sockets) | no capture |
| `kvno`'s `--disable-transited-check`, `--body-realm`, `--renew`, `--renew-ticket`, and a KDC host before the services | `krb5-kvno` (`krb5-client/test-hooks`): request shapes MIT's `kvno` cannot send | refuses them as MIT's `kvno` does, with its usage |
| `kvno -I` / `-U` for a service other than the cache's own | `krb5-kvno` (`krb5-client/test-hooks`): sends that S4U2Self for the KDC to refuse | refuses it first, `client and server principal names must match`, as MIT's `kvno` |
| `kinit`'s `--spake`, `--fast`, `--armor-ccache`, `--pkinit`, `--pkinit-anchors`, and `[kdc-host] principal [ccache [service]]` | `krb5-kinit` (`krb5-client/test-hooks`), which also prints `ok tgt=…` and log lines for the gates | refuses them as MIT's `kinit` does; `-T` and `-X X509_user_identity=` / `X509_anchors=` are MIT's options and stay |
| `kinit -S service` as the gates use it: a TGS-REQ for the service after the TGT, both stored | `krb5-kinit` (`krb5-client/test-hooks`) | MIT's `-S`: the AS-REQ asks for that service, in the client's realm, and the cache holds that ticket |
| `KRB5_KPASSWD_TARGET=name@REALM` (`client-differential-cli-gate.sh`) | `krb5-kpasswd` (`krb5-admin/test-hooks`): sets that principal's password (`krb5_set_password`, `0xff80`) | changes the client's own password, as MIT's `kpasswd` |

The KCM socket is `[libdefaults] kcm_socket` in every build; no build reads `KCM_SOCKET`.

## In-repo consumers

The in-repo consumer (`examples/consumer`) depends on the crates as a
downstream binary and asserts published encrypt and DER return values;
`examples/kdc-consumer` issues a TGT and host ticket, exports a keytab, and
verifies an AP-REQ without binding a socket.
