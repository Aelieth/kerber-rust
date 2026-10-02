# Testing strategy

Testing is continuous. Categories grow with the stages.

## Gate discipline

The local entry point is `make safety` (fmt, clippy, nextest under
`harness/nextest-krb5.conf`, `python3 scripts/ci-policy.py`); `make doc`
is the sibling `doc` job, `cargo doc --workspace --no-deps` under
`RUSTDOCFLAGS=-D warnings`; `make shellcheck` is the `shellcheck` job. Clippy runs `all` + `pedantic` + `cargo` at
deny with eight named allows (`Cargo.toml` says why for each),
`missing_docs` is denied workspace-wide, and every library and binary
root carries `#![deny(clippy::unwrap_used, clippy::expect_used,
clippy::panic)]`. `make snapshot OUT=<dir>` (`scripts/hygiene-snapshot.sh`)
records the test/gate/oracle inventory and the shape of the tree (LOC and
comment lines per package and file, the comment lines that carry a MIT
anchor counted apart from the prose, function and file maxima, `pub` surface,
`#[allow]` sites, binaries, dependencies); `QUALITY=1` adds the
compiler-backed counts (fmt, clippy, rustdoc under `-D warnings`,
doctests, `missing_docs`, shellcheck). `make checkpoint OUT=<dir>` runs
nextest and the gates into a stamped `timings.tsv`, and exits 1 when a
step fails: nextest, ci-policy, `run-harness.sh`, a gate whose rc is neither
0 nor 2 (2 is a lab that is not up), or the `ci-policy --checkpoint`
gate-wall check. It runs every step first; `CHECKPOINT_RC.txt` holds
`checkpoint_rc=` and one `fail=` line per failed step. The MIT image is a
precondition: a missing or stale image, or no docker, stops the run with
exit 2 before any step unless `KERBER_NO_IMAGE=1`, and a step whose stamp
fails later is a failed step. `scripts/checkpoint.sh --self-test`, a step of
the `test` job, runs fixture checkpoints through four hooks
(`KERBER_CHECKPOINT_NEXTEST`, `KERBER_CHECKPOINT_POLICY`,
`KERBER_CHECKPOINT_HARNESS`, `KERBER_CHECKPOINT_GATE_DIR`) under a `docker`
that always fails, so it needs neither docker nor the image; `00-head.txt`
records any hook that is set. Both refuse to run
unless the host `default_realm` is the `TESTLABBY.LOCAL` lab stub
(`scripts/lib/lab-realm.sh` reads the first live `default_realm =` line
of `/etc/krb5.conf`, not a commented one; `KERBER_ALLOW_HOST_REALM=1`
overrides and is recorded in the stamp), stamp every file they write,
and name every file in their own `INDEX.md`; a checkpoint taken into a
snapshot directory (`<snap>/checkpoint/`) re-runs the snapshot's index
writer so the snapshot's `INDEX.md` names it too (`python3
scripts/lib/hygiene_inventory.py --reindex <snap>` by hand). The
checkpoint aborts while a gate (`bash scripts/<x>-gate.sh`) or `cargo`
is running — a process that only reads a gate script does not count.
`python3
scripts/hygiene-diff.py <old> <new>` prints a provenance header, then
fails if a test, cell tag, diffsend case, flow or ledger row
disappeared, a gate went red, or a quality count rose; shape deltas are
informational. Ledger rows are keyed by MIT cite and check, with the
file as a separate column, so a row that changes file (the single-file
ledger split into `docs/parity/`) is counted as moved and a row that
disappears fails; a snapshot from before that key is compared by MIT
cite alone, the verdicts under each cite as a multiset, so a cite the
ledger holds twice stays two rows. A regrade is a change of grade, the verdict cell's first
word (the tally's counting rule), and fails; a change confined to the
parenthetical qualifier is listed as `ledger verdict qualifiers
reworded`. A reworded check cell is a re-key, listed with `--ledger-rekey
FILE` (`path<TAB>cite<TAB>old check = new check<TAB>blob=<the doc at the
old tree>`, and optionally `<TAB>proof: <old span> = <new span>` for one
excused span of the proof cell): with the verdict and proof cells
unchanged it reads `ledger row reworded (check cell)`; unlisted it stays
removed and added, and an unused entry fails. A swath that renames or de-duplicates tests passes its
map (`--renames`, `--duplicates`). `--duplicates` and `--renames` are
keyed `old_binary<TAB>old_name` to `new_binary<TAB>new_name`; a RHS
that is also a LHS is rejected, and many-to-one needs `merged:` on the
RHS. One that deletes a `MIT_*`/`RUST_*` variable that was never a cell
lists it in `--dead` with the reason (`section` and `flow` tags cannot
be waived).
`python3 scripts/hygiene-body-diff.py --old SHA --new SHA --renames
--duplicates [--accept map]` links test fns through those maps,
normalises whitespace/comments/helper names in code spans only, and
fails an assertion-line change that is not in `--accept` or a dropped
test that is not in `--duplicates`. String, byte-string, raw-string
and char literals pass through whole (interior newlines and
indentation included, a zero-length interior line kept; the span
splitter is shared with `hygiene-fn-diff.py`). A literal change on
an assertion line is an assertion change (red unless `--accept`ed);
on any other line it is a
`differ` (green, listed). `--accept` is keyed nextest `binary<TAB>name`
(one entry covers exactly one pair) and pins the old and new
assertion-blob `sha256:` hashes; the RHS must exist in the new tree,
and an unused entry or a blob mismatch is red. Same-file helpers are
smashed only when the name exists on both sides; a rename compares the
helper bodies. The blob keeps helper-call arguments (smash the callee
name only). `--subst` / `--subst-file` rewrite only call positions of
names in the declared helper list (`user_as()`, `temp_dir()`,
`documented_kadmin()`, `harness_master_etype()`, …), never
constants, numerics, or string literals. `testrealm::` and
`principals::` are stripped only after `krb5_kdc::`, `crate::`,
or `super::`. `--self-test` on the
compare tools prints `self-test ok (N cases)`. There is no
request-shape column (no canonical built-request form).

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
check is hard. `check_mit_anchor_truth` (the `ledger-mit` job) proves
that each anchor's range lies inside that definition.

`check_mit_anchor_truth` runs where `KERBER_MIT_SRC` names the MIT
1.22.2 tree (the `ledger-mit` job) and resolves each anchor against a
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

`python3 scripts/hygiene-fn-diff.py --old SHA --new SHA [--moves]
[--accept] [--params] [--split] [--glue] [--roots]` is the product-fn sibling:
every non-test `fn` (and `const` / `static` / `enum` / `struct` /
`trait` / `type` / `macro_rules` items) is keyed
`crate<TAB>module::path::[impl-header::]name`, with inline `mod`
nesting in the path; a file's (or inline mod's) `#![…]` inner
attributes are one more item, `module::path::inner-attrs`, so a
dropped `#![forbid]` or an added `#![allow]` is `changed` / `added` /
`removed`, while a `//!` module header belongs to no item and is not
compared. A `fn …;` declaration inside a trait is its own item, and
the trait item is the header through `{`, so dropping one semicolon
method removes that method and leaves the trait header identical.
Bodies are compared after a normaliser that keeps string,
byte-string, raw-string and char literal contents (whitespace and
comments are still normalised outside literals). A pair is
`identical`, `vis-only` (private → `pub(super)` / `pub(crate)`,
`pub(crate)` ↔ `pub(super)`, or bare `pub` narrowed to
`pub(crate)` / `pub(super)` on the item or a field, including
brace-less `const` / `static` / `type`, with a vis-stripped rest),
`vis-widen` (`pub(crate)` / `pub(super)` → bare `pub`, or private →
any `pub`; counted and listed, red unless `--accept` gives a reason,
never folded into `vis-only`), `fmt-only`, `doc-only`, `params-only`, `const-fold`,
or `changed`.
`const-fold` is the one folding rule: `krb5_log::events::NAME` in code
compares equal to the literal of the `&str` const NAME in `krb5-log`'s
`events` module, each tree against its own consts. A pair that differs
only by that fold (and doc lines) is counted and listed as `const-fold`,
never as `identical`. A new `krb5-log` events const whose literal a
`const-fold` pair replaced is listed as `const-fold-added` instead of
`added`. A same-named `events` const in another crate is an error. A
const of another string, a changed const value, or a path to a non-`&str`
const is `changed` or `added`. Nothing else folds: a print moved into a
binary, a new tracing field, a new struct field and a new type are
`changed` / `added` rows that need a blob-pinned `--accept` entry.
Doc-stripping uses that same class, and only from visibility tokens
in code: a `pub(crate)` that appears only inside a `///` comment is
not a token. `pub` inside an identifier such as `pubkey` is not a
visibility token. `--params` is a map
`crate<TAB>path = Struct: f1, f2, …` whose field order is the old
parameter order (a disagreement exits 2 and names the function).
`params-only` is counted like `vis-only` and needs no accept row.
It covers a definition whose new signature replaces those parameters
with one struct value or reference and whose body is the old body
prefixed by `let Struct { f1, f2, … } = p;` (or `= *p` when the
parameter is `&Struct`), and a call site whose body matches the old
body after the struct literal is rewritten back to those field
expressions in order. The rewrite compares tokens: whitespace is not a
token, a trailing comma is dropped only before the `)` of a call or a
macro, or a `]` / `}`, and a one-tuple `(x,)` keeps its comma. A `(`
after `break`, `let`, `continue`, `return`, `>`, or another operator
or keyword is a tuple, not a call, so `break (z,)`, `let (w,) = t`,
and `a > (z,)` keep the comma. `>` is never a call opener, so a
turbofish `foo::<T>(z,)` keeps it too. `!` still marks a macro, so
`format!(…,)` drops the comma. A
literal stays one token, so the call's `)` is still matched. `& &` is not `&&`.
A struct literal is rewritten only as the direct argument of a bare
call `g(`, or of a method call when that function took `self`.
`other::g(S { … })` and `obj.g(S { … })` for a free function stay
text. An impl associated function is still rewritten at `Type::name(`.
The literal's struct must be that callee's: `g(T { … })` stays
text when `g` maps to `S`. `vec![…]`, `dbg!(…)`, and an unmapped call stay
text. A key whose path contains `::tests::` names a helper fn-diff does
not extract; that helper's calls still rewrite, and any other missing
key exits 2. A `let p = Struct { … }` is not threaded into later calls, so a
whole-struct hoist is `changed`, including a binding used twice and a
statement between the `let` and the call. Passing the struct binding
is valid only when no destructured name is re-bound (`let`, `let mut`,
a closure parameter, `for`, `if let`, `while let`, or a `match` arm
pattern) before that call. The destructure `let Struct { a, … }` does
not itself rebind `a`. Shorthand `f` means `f: f`.
An `&` that borrows the struct as a whole argument is consumed with
the literal. A parameter written `_name` matches the field written
`name: _name`. A semicolon trait method has no destructure. The
destructure `let` carries no attribute. One struct's map entries may
name an ordered subsequence of its longest field list, for a function
that never took the other fields: the destructure then ends with `..`,
a call still names every field, and the rewrite keeps that function's
fields. A reversed field order stays `changed`. A field the old signature
did not keep next to the others is written back at that argument
index, including when the map names every field of the struct and not
only a subsequence. Passing the struct binding does the same. An extra field whose expression is not that
binding, and not a field read of the struct value, stays `changed`.
`#[allow(L…)]` and `#[expect(L…, reason = "…")]` are identical only
when the lint set is the same, including a sibling lint kept on its
own attribute; a lint added or removed, an attribute removed, or a
sibling allow added or removed is `changed`. The direction is ignored
on purpose: `#[expect]` rewritten as `#[allow]` is the same set even
though the suppression is weaker. A conversion may drop
`too_many_arguments` because the arity fell; any other lint still has
to match. A swapped field, a `..`
tail on a call-site literal, a `..` that drops a field the function
did take, an argument hoisted into a `let`, or a destructure that
renames a field stays `changed`. Rule 7: the literal
names every field, in the old parameter order, each expression the old
argument verbatim, and the destructure is the first statement of the
converted function. `hygiene-body-diff --params` applies that order to
a shared helper the test calls, so a reordered literal there is
`differ` and the run fails. Self-test floors are fn-diff 134 and
body-diff 41. Before the vis-stripped compare the text ahead of the
body is re-flowed: whitespace around punctuation goes, and a trailing
comma is dropped only when its `(` / `<` follows an identifier that is
not a keyword and not a lifetime — `wide(a, b,)` and `f<T, U,>` lose
it, `(T,)`, `&mut (T,)`, `*const (T,)` and `&'a (T,)` keep it, and
string / char literals in attributes pass through whole. That runs on
every pair, not only on one that crossed the width limit; a pair
equal after it with the same visibility is `fmt-only` (green, named
in the render), so `vis-only N` is the number of pairs whose
visibility differs. `--moves` is keyed
like the hygiene-diff maps. `--split
old = a + b + …` checks that the concatenated new bodies equal the
old body modulo per-split line-anchored `--glue` lines (whole lines
present in the new bodies and absent from the old; each listed line
excuses one occurrence; unused glue is
red), optional per-phase `head:` / `tail:` blocks (matched only at
the start / end of that phase after whitespace and rewrap
normalisation; a block found anywhere else is red), and
occurrence-counted `edit: OLD => NEW` rows that drop the single
`mut` token after `let` (anything else is red). Under `--split` the
old fn's attribute block must equal the dispatcher's (a doc edit is
`doc-only`); a phase attribute block is empty or a blob-pinned
`--accept`. Phase signatures are named as `split-sig` in the report.
`hygiene_inventory` counts `rustfmt_skip` under `crates/*/src`. The
`allow` metric is outer `#[allow(`, inner `#![allow(`, and
`#[expect(` / `#![expect(`. `allow-sites.txt` lists lint names only;
a `reason = "…"` clause is not a lint. At `e48c0371` the older
outer-only count was 73 and this count is 80. An attribute `expect`
does not increment `unwrap_expect_panic_src` (`(?<!\[)\bexpect\(`);
`.expect(` and `panic!` still do.
`hygiene-diff` fails on a rise. `--roots` adds `examples/` and
`fuzz/` to the default `crates/`
scan. A body
edit, a dropped item, a reordered `--split`, or an unused `--accept`
is red; a pure move and a vis-only narrowing are green. A
`vis-widen` row is red unless `--accept` pins it. `--accept` is
one line per pair: `old_key = new_key | sha256:<old> | sha256:<new> |
reason` (keys are `crate<TAB>path`). A removal pins the old key as
both sides and the empty-blob hash on the new side; an addition pins
the new key as both sides and the empty-blob hash on the old side.
`--glue KEY=LINE` (and `glue: LINE` under a `--split` map entry) is
per-split; `old = old + tail` is the natural phase shape. A missing
`--moves` / `--accept` / `--split` file is an error. Job walls live in
`ci-budget.toml` (see Tier contract below). `python3 scripts/ci-status.py --check-budget` compares a
completed SHA against that file.

CI status is read from the terminal with `python3 scripts/ci-status.py [-n RUNS] [--sha SHA] [--jobs] [--durations] [--workflow ci|peers]`:
the public GitHub REST API answers unauthenticated with run, job and step conclusions and with the
check-run annotations (job logs need `GITHUB_TOKEN`). `--durations` prints
per-job `duration_s=` from `started_at`/`completed_at`; `--save` records
those lines plus `run_wall_s=`. `--check-budget` fails if a completed
run exceeds `ci-budget.toml`. Listings and `--check-budget` keep `main`
pushes and the PR under test (`--pr` or `GITHUB_REF`); dependabot runs
are dropped so their rebase failures do not sit in the nightly
median-of-5. `--workflow` selects a workflow file
(not the global run list filtered to `main`), so peers and PR-head SHAs
are visible. `--budget-report -n 15` prints per-job medians. Every gate sources `scripts/lib/provenance.sh`,
whose `ERR` trap turns a silent `set -e` death into a `::error file=scripts/<gate>.sh,line=N::…` line
naming the failing command; GitHub stores it as an annotation and `ci-status.py` prints it under the
failed job, so a red step names its cell without the log. KDC starts wait
for the listener (or a log line) through `require_listen` /
`require_log` / `require_port_in` in `scripts/lib/gate-common.sh`: a
hard cap of at least 20 s (10 s for a port-free wait), then `die`
naming what never appeared. `require_listen` does not treat
`bind failed` as fatal while a `krb5-kdc` process is still alive
(the `:88 || :8888` fallback start). `die` prints `::error file=…,line=…::`
and `unavailable` prints `::notice file=…,line=…::` when `GITHUB_ACTIONS`
is set (error path only); the file:line is the first frame outside
`scripts/lib/`. Deliberate
failures under `set +e`, `||`, `!` and `if` conditions are not
annotated by the ERR trap.
`scripts/gate-err-trap-selftest.sh` (the `test` job) keeps the trap honest. Check CI after every push;
a job stops at its first red step, so every gate behind that step has no CI evidence until the run is
green again.

Gate helpers live in `scripts/lib/`, one line each in [`scripts/README.md`](../scripts/README.md); the MIT
C programs the gates build in their containers are in `scripts/oracle/` (the clock-skew preload is
`scripts/lib/skew-preload.c`). Every kadmin query a gate or a `scripts/lib` helper runs goes through
`scripts/lib/kadmin-q.sh`, but for the keyed container sites below: the runners `mit_kadmin_local` / `mit_kadmin` / `rust_kadmin_local` take the
`docker exec` options and the container before `--` and the kadmin arguments after, and pass streams and exit
status through. MIT's kadmin exits 0 on a refused query, so a query whose output the cell does not check
itself goes through `kadmin_q_ok` (unless it is best-effort, below), which requires the verb's success line naming the principal. For a verb that prints nothing on
success (the policy verbs) it reads the
effect back with read-only follow-ups derived from the query; `--then QUERY ERE` adds one by hand for what the
query does not say, and `--next-asserts` skips the derived read-back where the cell's very next command reads
the same object back and asserts every field. `kadmin_q_try` marks a best-effort query (a setup
that may already have run on a shared container, a cleanup, or a diagnostic read): it runs with no success check and never fails the gate. Two kinds of query
cannot reach a host helper, because they run inside a container script between in-container steps, and
ci-policy keys them by gate and section: capaths-transit's heredoc `kad` (a `kadmin.local -r` per realm with
that realm's profile, in one container shell; it asserts MIT's success line itself) and the kadmin-local
gate's two race cells (the kadmind `addprinc` must land while the fifo-fed `krb5-kadmin-local` session holds
the store). `retry_until --log CONTAINER FILE... --` prints the log it polled before it dies. Gate cells are
counted by reachability: a gate owns the cell tags at its top level and in the functions it reaches through
its own and its sourced `scripts/lib` functions; a tag in a function nothing reaches is a dead cell, never
counted, and `hygiene-diff.py` accepts its removal only once it has proven it dead from the old tree.

A summary's `script:line` citations are moved to the current tree with `python3 scripts/claim-recite.py --at SHA
[--at SHA …] [--widen N] [--apply] SUMMARY.md`: per file it keeps the one candidate SHA at which the most
citations point at an asserting window (the tree the summary was written against), maps each cited range to
the working tree by exact line content and ordinal (the Rust-leg cell before its MIT-leg copy), and with
`--widen N` extends a citation of a cell's command to the line that asserts one of the bullet's quoted values.
It never invents a cell: a range that no longer matches line for line is reported and left alone, and a
citation that already passes `claim-audit.py` is untouched. Run `claim-audit.py` afterwards; the re-cite is
the step before an archive freezes a summary.

Evidence directories under `working/logs/<archive>/` each carry an `INDEX.md` naming every file with a one-line
"what"; `python3 scripts/index-check.py <dir>…` (or `--all <root>`) prints `files=N unnamed=M` per directory and
exits 1 when a file is unnamed (backticked names and table first cells count, `{a,b}` braces expand, a named
directory covers its files; any directory component starting `scratch` — `scratch/`, `scratch-pre/`,
`scratch-diffsend2/` — is gate `KERBER_SCRATCH` output and never evidence). Run it before a summary cites
the directory; `--all working/logs/w1-sweep` unnamed = 0 is a close-out condition.

`check_doc_file_cites` fails a backticked
`crates`/`scripts`/`docs`/`tests`/`harness`/`.github`/`examples` file
path that does not exist. `CHANGELOG.md` is excluded (history: a
retired path in an old entry is not a live cite).

`scripts/ci-policy.py` is a shim over the `scripts/ci_policy/` package:
one module per domain (`workflows`, `shell`, `kadmin_q`, `gates`, `ledger`,
`docs`, `evidence`, `hygiene`, `comments`; the shared paths in `common`, `main()` in
`__init__`) and the self-test one file per domain under `selftest/`
(`kadmin_q`'s cases live in `selftest/shell.py`). The
shim re-exports the names `kdb-dump-gate.sh` and `hygiene_inventory.py`
read, and `check_policy_module_attrs` loads it from `/` the way they do.
`scripts/py-move-check.py` judged the split: every def, class and
assignment of the old module defined once and identical, each global it
reads bound to its home module, the shim's imports right, no import cycle
(`check_py_move_self_test` keeps its fixtures). Some arms are pinned at
their live counts (the `*_ALLOW` constants): the count must equal the
allow in either direction, so the commit that clears sites lowers the
allow with them. Process tags in `docs/**` are pinned so. At 0, where any
site is red: a gate that sets its own `SCRATCH=`, a shell function defined
twice byte for byte, a shell function nothing calls (judged across files),
a direct kadmin query in a gate or a `scripts/lib` file other than
`scripts/lib/kadmin-q.sh`, bar the keyed container sites described above, and a test that writes under `std::env::temp_dir()`.
Working-plan section names in the public docs and a `scripts/**/*.py` that
does not compile are hard. It enforces workflow YAML (fail-red jobs, nextest
`--profile ci` on every invocation, no per-push `cargo test
--workspace` or `cargo test --all`, `--no-run` + junit upload, no
echo-only `then`/`elif`/`else` arm in `scripts/*-gate.sh` or
`scripts/lib/*.sh`, `"ci.yml"` path-equality) and that every
`differential-gate.sh` status-word cell has a tagged unit twin in
[`gate-unit-index.md`](gate-unit-index.md). A mixed `exit`+`echo`
chain is a hit. Multi-line `||` / `&&` / `\\` conditions are joined
before matching (including 2+ continuations). Each arm is tokenised
(assignments, redirections, quotes, `$(…)` stripped): an assertion is a
**command** in {`exit`, `die`, `return`, `break`, `continue`,
`unavailable`, `log … error`} or a test (`[`, `[[`, `test`, `grep`,
`cmp`) whose `||` branch, if any, itself asserts (`|| true`, `|| :`,
`|| { echo skip; }` swallow the test) and that is not a self-tautology
(a `[ -s F ]` of a file the arm just wrote, a `grep` of a file the arm
wrote with `echo`, `cmp -s /dev/null /dev/null`, `echo lit | grep`).
Words in echo arguments and filenames never count; `/bin/echo` and
`log_*` helpers are noise. `case` arms are walked like `if` arms. `log …
skip` is accepted only when the arm names a `KERBER_REQUIRE_`
requirement that a `die` in the same script enforces. `{ … }`, `( … )`,
and heredoc arms are inspected. The ledger is split:
`docs/parity/README.md` (the header) plus one file per section named
`a1-…` to `a5-…` or `b1-…` whose first heading names that section; the
one-file layout (`docs/mit-parity-ledger.md`, now a pointer) is read
too. A split without its README, a file whose name or heading gives no
section or the wrong one, rows left in the single file beside the split,
and a row (MIT cite and check) present twice fail. The header tally must match a
recount of the verdict cells and the A1–A5 / B1 section split; a missing
total line fails. Rust-site cells that use
`file.rs symbol` (optional crate prefix `krb5-kdc/reply.rs mint_ticket`,
optional `:N` after the symbol) must resolve to an item (`fn`,
`const fn`, `async fn`, `unsafe fn`, `struct`, `enum`, `const`,
`static`) under `crates/*/src`. A bare basename is an error unless
that file is unique across crates; an unresolvable symbol dies (no
silent skip); a symbol defined more than once in a file needs `:N`
inside the intended definition. The MIT column must cite a MIT file
(or say `n/a` / `absent`). `exact` rows must carry an anchor and verify
their claim: every Rust e_text status word — backticked, or a bare
`WORD_WORD` identifier — must appear in the union of the resolved item
bodies, and a row with no such word must name a proof unit, `diffsend`
case or gate that exists. With `KERBER_MIT_SRC=<1.22.2 src>` every MIT
cite must name a file of that tree and every MIT status word must be an
identifier there, a `_`-suffix of one (the RFC form `PADATA_TYPE_NOSUPP`)
or a quoted status string; CI wires the tree in the `ledger-mit` job.
Port commits carry a function
coverage checklist (`file:line` → Rust line or `deviation:`),
`Gates:`, and `Limitation:`. It cannot check
red-at-HEAD artefacts: `working/` is gitignored. `__pycache__/` is
gitignored.

Every `scripts/*-gate.sh` and `scripts/red-at-sha.sh` sources
`scripts/lib/provenance.sh` **before the first cell**. The helper
prints `head_sha=`, `tree_sha=` (temporary-index `git add -A -- .
':!working'` then `write-tree`), `dirty=`, `captured_at=`, the MIT
image id/created, and the SHA-256 of `harness/kadm5.acl` in the tree
versus inside `kerber-rust-mit-kdc:1.22.2`. A hash mismatch dies
`stale MIT image; rebuild from harness/`. The image's hash costs a
`docker run`: a runner that stamps many files (`checkpoint.sh`,
`red-at-sha.sh`) makes one `KERBER_PROV_MEMO` file with `mktemp` under its
`KERBER_SCRATCH` and removes it on exit, and the helper writes no file of
its own that outlives it (`check_provenance_memo`); ci-policy gives the
scripts it runs a scratch. An artefact without this
stamp is not evidence. A "settled live" claim must name its log
file. Gate scripts write host files only under `KERBER_SCRATCH`
(`ci-policy` fails a literal host `>/tmp/` write outside a
`KERBER_SCRATCH:-/tmp/…` default).

Unit greens and parent reds go through `scripts/lib/unit-evidence.sh`:
`unit_green <name> <nextest filter>` (stamped nextest; refuses `dirty != no`
unless `KERBER_UNIT_ALLOW_DIRTY=1`, which prints `override=KERBER_UNIT_ALLOW_DIRTY`)
and `unit_red_at <parent> <name> [--all|<filter>] <files…>` (`red-at-sha.sh
--inject` copies those HEAD files into the parent worktree **before**
`write-tree`; a call with no files is refused). With `--all` (the default)
every `#[test]` fn in the inject files must **FAILED** at the parent; the
helper runs `cargo test --test <stem>` for each inject `tests/<stem>.rs`
(joining names with `|` is not a cargo OR and yields a vacuous red). An
explicit filter still requires every inject-file test to appear as FAILED.
It stamps `red-at-parent=1`. INDEX links only files those helpers or the
gates produced.
These units live under `crates/*/tests/` so `unit_red_at
--inject` can fail them at the parent.
Live settles use `scripts/lib/settle.sh <name> -- <command…>`
(provenance, echoed command, `2>&1 | tee`; a `grep` of an existing
file is refused). A dirty-tree bypass via `KERBER_SETTLE_ALLOW_DIRTY=1`
prints `override=KERBER_SETTLE_ALLOW_DIRTY` into the artefact header.
Three unit files pin answers from a settle that predates `settle.sh`: the
kadmind `CREATE_ALIAS` ACL codes (`crates/krb5-admin/tests/kadm5_alias.rs`,
§D), the GET_PRINCS glob (`kadm5_glob.rs`, §E), and the KDB alias texts and
dump line (`crates/krb5-kdc/tests/kdb_alias.rs`, §A–§C) are MIT 1.22.2's
output, captured by hand before `settle.sh` existed; the capture is kept
outside the repository.
`scripts/ci-status.py --save SHA [--out DIR]` writes `<workflow>-<sha>.txt`
(`ci-<sha>.txt`, `fuzz-<sha>.txt`) only from a **completed**,
non-rate-limited run whose every step GitHub has stamped (it stamps steps
minutes after the run completes; retries with backoff capped at 60 s for
at least 15 minutes, then exit 2 with no file) and drops `title=fixture` / `probe-gate.sh` annotations from
`scripts/gate-err-trap-selftest.sh`. `scripts/evidence-check.py <dir>
--commits SHA…` flags every `.log`/`.txt` that is unstamped, whose
`head_sha` is not a landed commit of the section, or whose `dirty=yes`
lacks a `red-at-parent=` / `override=` label. `claim-audit.py` rejects an
oracle artefact with `override=` or `dirty=yes` unless the bullet labels
it a parent red.

Red-at-HEAD artefact contract (captured under
`working/logs/…/<item>-red-at-head.log`): the file is captured tool
output of the failing unit or live cell, not a paraphrase. Write
"unit-red only; MIT by source" when MIT clients cannot emit the cell.
Retroactive red is `scripts/red-at-sha.sh [--no-overlay] [--inject FILE ...] --
<base-sha> <gate-script-or-command>`: a `git worktree` at the base
SHA with `CARGO_TARGET_DIR` under an absolute `KERBER_SCRATCH`, a
provenance header (`base_sha=`, `tree_sha=` from `git write-tree`
after the overlay and any `--inject` copies, `command=` including
`--inject` when used, worktree, probe sha256, `gate_rc=` /
`cargo_test_rc=`), HEAD's `scripts/lib/`, `scripts/oracle/` and
`scripts/ci_policy/` whole (each replacing the base's), `scripts/*.sh`,
`scripts/*.{c,py}`, and the whole `harness/` tree copied into the
worktree **before** `write-tree` so `tree_sha=` describes the tree
that ran. `--inject` with no files is refused. Binary rebuild is
only for `scripts/*-gate.sh`, and builds the base's bins: its own
`scripts/lib/build-bins.sh` when the base has one, else the five older
gate bins, each from the crate that holds it at the base; `--print-build`
prints that choice and stops (`check_red_at_sha_build`). The worktree is removed and
`git worktree prune`d on EXIT, and so is the `red-target-<sha>` cargo
tree — it is rebuildable scratch (thirty of them held 36 GiB of one section's
evidence dirs) and the stamped log keeps the rc and the FAILED list;
`KERBER_KEEP_RED_TARGET=1` keeps it for a follow-up run at the same
base. Every run stamps `red-at-parent=1` in its provenance block, so the
`dirty=yes` the overlaid worktree records is the labelled kind.
`python3 scripts/ci-policy.py --checkpoint` (the local checkpoint runner;
`working/` is gitignored so CI never sees it) fails on any cargo build
tree left under `working/logs/`.
Archive the captured output under `working/logs/…` and the scratch.
Both legs of a text-equality cell assert pinned literals (never
capture-from-MIT). Every branch asserts: no `if` whose body is only
`echo`. `--no-overlay` keeps the base tree's own `scripts/` and `harness/` so a
red for the tooling itself (a ci-policy fixture against an old helper) is
possible; the default overlays HEAD's helpers.

Summary claims are checked by `scripts/claim-audit.py [--evidence-dir DIR]
[--stamp] SUMMARY…`: every `script:line` reference in a "Settled live"
bullet must carry an assertion on one of the bullet's quoted values (or call
a function of that script which does); a single-line reference must itself
sit within one line of that assertion (a `script:12-20` range covers the
assertion). Every bullet must name a cell on each leg from container
variables (`"$NAME"`, `NAME_MIT`, `MIT_`/`RUST_`, `mit_local`,
`kadmin.local`, `kdb5_util`; a cell in a Samba, Heimdal or AD gate
carries the oracle leg) or `diff <(` — cell-header prose is not a
leg — or an oracle `settle.sh` artefact whose `cmd=` runs a MIT, Samba
or Heimdal tool (a Rust-side gate run is not a leg); a tooling bullet
(references into `scripts/*.py`) must name the `_self_test` fixture line
that exercises the rule (a `_must_die(`, `_must_die_msg(`, `must_fail(`, `_must_pass(`,
`assert` or `raise AssertionError` line); and every named artefact must exist, be stamped
and carry a quoted value. `ci-policy` runs its fixtures; the audit runs it on the
landed summary with `--stamp` into the evidence directory.

Freeze rule: a closed summary carries `Frozen-at: <close-out sha>` under
its title, and `claim-audit.py` then resolves its `script:line` cites and
unit names with `git show <sha>:<script>` / `git grep <sha>` instead of the
working tree — the values were true at that SHA, and a later gate edit must
not re-open a closed summary. An open summary (no header) resolves against
the working tree; `--at SHA` overrides the header for every summary given.
The bare invocation over every summary is the check. A tooling cite's
enclosing def is read from the AST, so a column-0 line inside a string
does not end it. `scripts/claim-remap.py SUMMARY OLD NEW [--moved PATH=DIR]
[--write]` re-maps the Settled-live cites from one commit to another, across
a module split with `--moved` (difflib's unchanged blocks; a cite it cannot
place is flagged, not guessed).

The public docs are `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
every `docs/**/*.md`, and every `README.md` under `examples/`,
`harness/`, `scripts/` and `tests/`. `check_doc_links` resolves every
relative link in them, and its `#anchor` by GitHub's slug rules (the
heading lowercased, characters other than letters, digits, spaces,
hyphens and underscores dropped, spaces turned into hyphens, a repeat
suffixed `-1`, `-2`); links in code are not links. `check_doc_file_cites`
reads the same files except the CHANGELOG. `check_changelog_headings`
allows only the Keep-a-Changelog group names, each the whole heading, plus
`Tests and CI` and `How to …` headings, as `###` headings; `check_docs_size` holds every
`docs/**/*.md` to 60 KiB and `CHANGELOG.md` to its ceiling
(`CHANGELOG_MAX_BYTES`: its size when last re-based, 252,761 bytes, plus
a stated 20,000-byte allowance for the rest of the functional work's bullets,
one per change; a `tool:` commit at the start of a swath that adds bullets
re-bases it, never the commit that adds them). `check_gate_documented` holds `docs/gates.md`
to one row per `scripts/*-gate.sh`, with the workflow and lane columns
equal to the gates' placements in `.github/workflows` (`fail-red`,
`soft`, `nightly`; `stub` or `wrapper` for the documented
stubs), a known oracle, and a non-empty assertion; `check_gate_doc_tokens`
requires every backticked token of an asserts cell in its gate or a
`scripts/lib`, `scripts/oracle` or `harness/` file the gate names.
`check_no_script_line_cites` keeps line numbers out of script cites: a
doc cites a gate cell by the script path and the cell's `==== … ====`
echo text, or a function by `name()` right after the path, and each must
resolve in that script; a `scripts/…:N` cite, a bare script name with
`:N`, or a `:N` after one is red. `check_testing_doc_budgets` holds every
`name` N pair of the Tier 1 and Tier 2 bullets to `ci-budget.toml`. A check that the tree
does not meet yet is advisory at the live count and goes hard with the
commit that clears it.

Wire `e_text` is MIT's status word (`do_as_req.c:806`,
`do_tgs_req.c:205-206`). MIT `k5_setmsg` texts are KDC-log messages
and land in the `kdc.issue` `detail` field, not on the wire. A cell
that pins MIT text must say whether it is wire or log. The KDC MIT
1.22.2 parity ledger is [`parity/`](parity/README.md), one file per section;
a `proof` cell may name an existing gate script or `diffsend` case,
or mark that clause `proposed` / `propose`. `proposed` scopes only
the clause it is in (semicolon-separated).

## Normal / baseline

- Known-answer tests in `crates/krb5-crypto/tests/known_answer.rs`
  (RFC 3961 3DES s2k, RFC 3962, RFC 6803 Camellia-CTS-CMAC, MIT
  `t_prf.c` PRF / RFC 6113 PRF+, RFC 4556 `octetstring2key`, RFC 4757
  RC4 s2k, SPAKE IANA M/N + fixed-scalar public, MIT `t_derive.c` /
  `t_cksums.c`).
- DER round-trip in `crates/krb5-asn1/tests/round_trip.rs`.
- Downstream consumer tests in `examples/consumer`.

These tests call the shipped functions. They do not reimplement AES or
DER inside the test.

## Irregularity / adversarial

- Truncated and malformed DER must return `Error`, never panic.
- Decrypt of a truncated ciphertext or a flipped HMAC bit must fail.
- Key usage 0 is rejected.

DER-strictness negatives live in `crates/krb5-asn1/tests/der_strict.rs`.
`fuzz/` has 9 cargo-fuzz targets (DER, AS/TGS/AP, keytab/ccache,
PKINIT CMS, PAC NDR, SPAKE points, Oakley DH, GSS tokens, transited)
seeded from `tests/traces/` (transited also has `fuzz/corpus/transited/`).
The four thin corpora (`pkinit_cms`, `spake_point`, `oakley_dh`,
`gss_token`) keep extra `seed-*` fixtures (CMS SEQUENCE, IANA M/N,
Oakley 2048 prime, SPNEGO wrapper). After a campaign, minimize with
`cargo +nightly fuzz cmin <target>` and keep only `seed-*` names
(`fuzz/.gitignore` drops hash-named files). CI smokes each target ~60s
(`.github/workflows/fuzz.yml`; schedule, dispatch, and PR on `fuzz/**`
— no `push:` trigger). Transited seeds are
`crealm\\0srealm\\0contents` so `process_intermediates` is reached.

## Interop

The external-oracle inventory is [`gates.md`](gates.md) (per gate) and
[`interop-matrix.md`](interop-matrix.md) (per oracle).

Primary oracle: MIT Kerberos **1.22.2** in `harness/`. Secondary:
Heimdal **7.8** in `harness/heimdal/` (`scripts/heimdal-gate.sh`). A
Windows Server 2022 Evaluation DC (`AD.KERBER.TEST`) is captured for
the AD round; see [`labs/ad-lab.md`](labs/ad-lab.md). Live AD commands use
`~/adlab` only — never `/etc/krb5.conf` or SSSD. Windows SSPI has no
gate; it ran only in the KVM field lab
([`harness/field/README.md`](../harness/field/README.md)).

## Production-gate

Stage 1: harness starts twice, port 88 reachable, MIT `kinit` obtains a
TGT, structured logs include `correlation_id`.

Every gate after that has one row in [gates.md](gates.md): its oracle, the
`workflow:job` that runs it, its lane and what it asserts, with the detail
behind each row under Notes by gate.

AD PAC: `crates/krb5-kdc/tests/pac_ad_capture.rs` decodes committed
`tests/traces/pac-kbruser.ndr` (byte-identical re-encode; `kbruser` /
`kbrgroup` / ADKERBER SID). With `~/adlab/svc.keytab` present, the
captured `host/svc` PAC server checksum is verified (usage 17). Skip
cleanly without the keytab.

MSRV is 1.95 (`package.rust-version`), edition 2024, matching KLLDAP
(local checkout 0.7.4; upstream `Aelieth/klldap` 0.7.6). The `msrv` CI
job is `cargo build --workspace --all-targets --locked` on that
toolchain; the full `cargo test --workspace --locked` on MSRV is the
`msrv-test` job of `full-test.yml` (nightly + `v*` tags). `rasn` is
unpinned (`0.28`); golden MIT DER is the protocol net if encodings
drift. There is no unlocked `--locked` fallback. KLLDAP alignment:
[`embed/klldap.md`](embed/klldap.md).

### Tier contract

Job walls live in `ci-budget.toml` (one source). `ci-status.py --check-budget`
compares a completed SHA, or the last N runs, against that file. A run cannot
measure itself; the nightly `budget.yml` job checks the last five `ci.yml` runs.

- **Tier 1** — per-push blocking: `test`, `harness`, `harness-2`, `mit-extra`,
  `mit-extra-2`, `msrv`, `audit`, `ledger-mit`, `mit-image`, `doc`,
  `shellcheck`. Combined wall ≤ `[push].run_wall` (360 s). Per-job: `test`
  300, `harness` 270, `harness-2` 330, `mit-extra` 180, `mit-extra-2` 210,
  `doc` 90, `shellcheck` 150, `msrv` 120, `audit` 260, `ledger-mit` 60,
  `mit-image` 90.
- **Tier 2** — per-push soft (`continue-on-error`): `slo` 180, `chaos` 180,
  `soak` 240.
- **Tier 3** — nightly: `peers.yml`, `full-test.yml`, `fuzz.yml`,
  `kcm-opcode.yml`, `soak.yml`, `budget.yml`.

Every gate's `gate_wall_s` in a checkpoint `timings.tsv` is ≤ 45 s
(`scripts/gate-wall-exceptions.txt` is empty). Gate proto sleeps sum to
≤ 26 s and are tagged `# proto:` (a lockout/postdate word is not enough).
Unit `sleep(` in `crates/*/tests` is ≤ 14.

### CI lanes (which job runs which gates)

Per-push (`.github/workflows/ci.yml`, every job red-blocks except the
three marked `continue-on-error`). Every workflow grants `permissions:
contents: read` at the top (the `audit` job adds `checks`/`issues: write`
for `rustsec/audit-check`); `ci.yml` and `fuzz.yml` cancel a superseded
run (`concurrency`); every third-party `uses:` is pinned to a commit SHA
with the tag in a comment and `.github/dependabot.yml` moves the pins
(github-actions daily, cargo weekly). The toolchain + lld + `rust-cache`
steps are one composite, `.github/actions/rust-preamble`; checkout, the
docker-tar `actions/cache` step and the gate `run:` lines stay inline
because `ci-policy.py` reads them (`check_workflow_hardening` asserts
all of the above).

| Job | Runs |
| --- | --- |
| `test` | `cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`, `cargo nextest run --workspace --profile ci` |
| `doc` | `cargo doc --workspace --no-deps` under `RUSTDOCFLAGS=-D warnings` (sibling of `test`) |
| `shellcheck` | `shellcheck -S style scripts/*.sh scripts/lib/*.sh harness/*.sh harness/prod/*.sh dist/*.sh harness/field/*.sh harness/field/lib/*.sh harness/field/scenarios/*.sh` with `.shellcheckrc` (`external-sources=true`, `SC2329` off); zero inline disables (`make shellcheck`). ShellCheck is installed by version and sha256 (`SHELLCHECK_VERSION`, v0.11.0 — the runner's package is 0.9.0 and reports hundreds of SC2317/SC2119 notes 0.11.0 does not); the Makefile fallback image and the hygiene inventory name the same version, and `ci-policy.py` keeps the three in step |
| `msrv` | `cargo build --workspace --all-targets --locked` on Rust 1.95 |
| `audit` | `cargo audit`, `cargo deny`, `scripts/geiger.sh` (per-crate `cargo geiger`, 0-unsafe product), `cargo vet --locked` (CI pins cargo-vet **0.10.0**; local 0.10.2 is not an oracle) |
| `ledger-mit` | fetches the SHA-pinned MIT 1.22.2 source and runs `scripts/ci-policy.py` (ledger anchors, tally, proof column, evidence rules) |
| `mit-image` | builds or restores `kerber-rust-mit-kdc:1.22.2` and `kerber-rust-prod-node:latest` into `actions/cache` (no artifact round-trip) |
| `harness` | After `run-harness`/`stop-harness` (client/ccache/knobs/config-include), one shared shell (`KERBER_SHELL`) and one stock MIT KDC (`KERBER_LIVE=1`). Then `kdc-gate`, `store-gate`, `bidirectional-gate`, `gss-gate`, `pkinit-gate`, `kadmin-rust-gate`, `kadmin-rust-acl-gate`, `kadmin-mit-gate`, `kadmin-both-gate` (local wrapper `kadmin-gate.sh`), `history-mit-gate` |
| `harness-2` | One shared shell + one stock MIT KDC, then `kpasswd-rust-gate`, `kpasswd-mit-gate` (local wrapper `kpasswd-gate.sh`), `kdb-dump-gate`, `differential-gate`, `kprop-gate`, `kprop-reverse-gate`, `rd-safe-oracle-gate`, `cross-kdc-gate`, `iprop-gate`, `expire-gate`, `kdcpolicy-gate`, `flags-gate`, `renew-gate`, `postdate-gate`, `getprivs-gate`, `policy-gate`, `prop-acl-gate`, `restart-gate`, `prod-gate`, `prod-realm-gate` |
| `mit-extra` | One shared shell + one stock MIT KDC, then `cross-realm-gate`, `capaths-compress-gate`, `spake-gate`, `rust-kinit-spake-gate`, `mit-fast-kdc-gate`, `rust-kinit-fast-gate`, `rust-kinit-pkinit-gate`, `rust-kinit-enterprise-gate`, `ktutil-gate`, `kadmin-local-gate`, `rust-kpasswd-mit-gate`, `sha2-gate`, `rc4-session-gate` |
| `mit-extra-2` | One shared shell + one stock MIT KDC, then `client-differential-flows-gate`, `client-differential-cli-gate` (local wrapper `client-differential-gate.sh`), `s4u-mit-gate`, `kcm-gate`, `capaths-transit-gate` |
| `slo` (`continue-on-error`) | `stress-gate` over `harness/prod` |
| `chaos` (`continue-on-error`) | `chaos-gate` |
| `soak` (`continue-on-error`) | `soak-gate` (short run) |

Scheduled (a red is a red, but a push does not wait for it):

| Workflow | Cadence | Runs |
| --- | --- | --- |
| `peers.yml` | nightly 06:12 UTC + manual | Restores `kerber-rust-mit-kdc:1.22.2` from the same `actions/cache` key as `harness` (miss → gates `exit 2`, not `KERBER_NO_IMAGE`). Builds `samba-ad-dc:latest`, `samba-kerber-dc:latest`, `kerber-rust-heimdal-kdc:latest` in the job. Then `samba-ad-gate`, `ad-windows-gate`, `ad-s4u-gate`, `samba-pac-verify-gate`, `samba-pac-l2-gate`, `samba-crossrealm-gate`, `samba-realtrust-gate`, `heimdal-gate` — every step `if: always()` via `run-peer-step.sh`; tally `unavailable=N failed=M`; job red only when `failed > 0` |
| `soak.yml` | nightly 05:47 UTC + manual | long `soak-gate` |
| `fuzz.yml` | nightly 04:17 UTC + manual | `cargo +nightly fuzz run <target> -max_total_time=60` per target (9 targets) |
| `kcm-opcode.yml` | nightly 07:18 UTC + manual | Restores the MIT tar (same cache key); installs `lld`; `kcm-opcode-gate` via `run-peer-step.sh` (exit 2 → green `peer-step unavailable`) |
| `full-test.yml` | nightly 05:27 UTC, `v*` tags, manual | `test-release` (release-profile tests) and `msrv-test` (`cargo test --workspace --locked` on 1.95) |

Not in any workflow: `ad-mit-trust-gate.sh` (the retired MIT↔AD trust lab) and the local wrappers `kadmin-gate.sh`, `kpasswd-gate.sh` and `client-differential-gate.sh` (CI runs their legs directly).
`ad-*` are live Samba (`samba-ad-dc`), not the torn-down Windows DC.
`heimdal-gate` is live Heimdal 7.8 both directions. Per-gate detail is in
[gates.md](gates.md).

Live AD work must set `KRB5_CONFIG` / `KRB5CCNAME` / `KRB5_KTNAME` to
`~/adlab`. Never edit host `/etc/krb5.conf` or SSSD.

## MIT 1.22.2 harness

The documented entry point is `scripts/run-harness.sh`. It builds an image
pinned to MIT krb5 1.22.2, starts a KDC for realm `KERBER.TEST` on UDP/TCP
port 88, emits JSON logs with a `correlation_id`, and runs `kinit` for
`user@KERBER.TEST`.

Requires Docker (Compose optional — `harness/docker-compose.yml`).
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

The gates, CI, `make safety` and `scripts/checkpoint.sh` build with
`--features krb5-kdc/test-hooks,krb5-admin/test-hooks,krb5-client/test-hooks`
(the gates through `scripts/lib/build-bins.sh`, whose one cargo invocation also
carries the client tools); `krb5-kdc/test-hooks` turns on `krb5-config/test-hooks`
and `krb5-protocol/test-hooks` for every binary of that build. Only such a build
reads these inputs; a release build ignores them, as MIT's tools do. CI's test
job and `make test` then run the workspace's tests once more without features
(`cargo nextest run --workspace --profile ci --locked`), so the release-only units
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
| `kinit`'s `--spake`, `--fast`, `--armor-ccache`, `--pkinit`, `--pkinit-anchors`, and `[kdc-host] principal [ccache [service]]` | `krb5-kinit` (`krb5-client/test-hooks`), which also prints `ok tgt=…` and log lines for the gates | refuses them as MIT's `kinit` does; `-T` and `-X X509_user_identity=` / `X509_anchors=` are MIT's options and stay |
| `kinit -S service` as the gates use it: a TGS-REQ for the service after the TGT, both stored | `krb5-kinit` (`krb5-client/test-hooks`) | MIT's `-S`: the AS-REQ asks for that service, in the client's realm, and the cache holds that ticket |

`KRB5_KPASSWD_TARGET` is not test-only: `krb5-kpasswd` sets that principal's
password (`krb5_set_password`), a kerber-rust extension MIT's `kpasswd` lacks.

## In-repo consumers

The in-repo consumer (`examples/consumer`) depends on the crates as a
downstream binary and asserts published encrypt and DER return values;
`examples/kdc-consumer` issues a TGT and host ticket, exports a keytab, and
verifies an AP-REQ without binding a socket.
