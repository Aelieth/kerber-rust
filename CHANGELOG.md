# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses semantic versioning once a crate is published.

## [Unreleased] — targeting 1.1.0

### W3-S4 comments and rustdoc

- **ci.** `check_mit_anchor_form` requires a MIT anchor in a `//`
  comment to be one line: a function, a `file.c` range, and a
  guarantee. The six older shapes are red. The check is advisory at
  the `0d5fa7f4` count until a later commit sets the allow to 0.
  No wire or text change in product code.
- **ci.** `check_no_process_history` rejects a process tag (`R12`,
  `A′-3`, `W0e`, `W1-Z`, `Round 2`, a `parent` SHA, `R2-S3`, `B3`,
  `Y0`, `Z6.3`) on a `//` comment under `crates/`. Advisory at the
  `0d5fa7f4` count. The baseline list is
  `working/logs/w3-hygiene/s4/process-tags-before.txt`. No wire or
  text change in product code.
- **docs.** `docs/architecture.md` and `CONTRIBUTING.md` state the
  comment rules R1–R4: one MIT anchor form, an invariant rather than
  a step list, no process history, and `# Errors` naming variants.
- **crates.** The `krb5-admin` header drops `kdb5_util` and names
  ktutil, iprop, and kpropd. The `krb5-crypto` header names weak
  etypes 16/23/25/26 behind `allow_weak_crypto`, plus SPAKE, MODP,
  CF2, and PRF+. `krb5-kdc` and `krb5-protocol` headers end on the
  public-surface line, as do the other two. The `krb5-admin` and
  `krb5-crypto` crate descriptions match those headers. No behaviour
  change.
- **kdc.** Module headers on `acl`, `ad`, `audit`, `listen`, `plugins`,
  and `preauth` state the fail-closed rule for that module. Ledger
  rust-site lines in `ad.rs` and `plugins.rs` move with those headers.
  No behaviour change.
- **protocol.** Module headers on `ap_req`, `tgs`, `safe_priv`,
  `preauth`, `replay`, `chpw`, `keytab`, and `secret_file` state the
  check that makes a success. No behaviour change.
- **crypto.** Module headers on `ops`, `weak`, `cf2`, `derive`, `prf`,
  `spake`, `key`, `cts`, `nfold`, and `modp` state the fail-closed
  rule for that module. No behaviour change.
- **admin.** The `listen` header states that a malformed kpasswd
  datagram is not answered and a failed AP-REQ is a framed chpwfail.
  No behaviour change.
- **types.** Module headers on `fast`, `s4u`, `cammac`, and `spake`
  state which fields are required and what the checksum covers. No
  behaviour change.
- **gss.** The `mic` header states that a bad checksum is rejected
  before the sequence is consumed. The shared token reader refuses a
  length of 0 or above 1 MiB. No behaviour change.
- **admin.** The sixteen src functions over 40 lines each gain one
  MIT anchor and one sentence stating the fail-closed rule for that
  function. No behaviour change.
- **protocol.** The nineteen src functions over 40 lines each gain one
  MIT anchor and one sentence stating the check that makes a success.
  `fast_error_material` names its error conditions. No behaviour change.
- **kdc.** The thirty-two src functions over 40 lines each gain one MIT
  anchor and one sentence stating the fail-closed rule. The PAC, S4U,
  PKINIT, and SPAKE results that clippy does not require still name
  their error conditions. No behaviour change.
- **client.** `kinit_inner` states that key-expired is the only change
  path and that a keytab request has none. No behaviour change.
- **gss.** The eight long functions state when a token, a direction,
  or a delegated credential is rejected. No behaviour change.
- **config.** The profile parser states that an include is a directive
  only at the start of a line, and that the first value of a key wins.
  No behaviour change.
- **types.** The ten long functions state when a parse is not a
  principal, a duration, a transit path, or a certificate. No
  behaviour change.
- **crypto.** The five long functions state when a derive or a
  checksum failure wipes key material. No behaviour change.
- **all.** Each `# Errors` section under 45 characters names a
  variant or a condition. The ones that named a family, or opened
  with "Returns", now say which variant or which check failed.
  No behaviour change.
- **all.** Process-history tags are gone from comments under
  `crates/`. `check_no_process_history` is hard. No behaviour change.
- **all.** Every MIT cite in a `//` comment under `crates/*/src` and
  `crates/*/tests` is one line: a C function, a `file.c` range inside
  that function, and the guarantee. `check_mit_anchor_form` is hard.
  `diffsend` names its cases in the module header. No behaviour change.
- **kdc.** `PrincipalStore::new` still exits if the CSPRNG cannot
  build the realm SID. `docs/security.md` records that abort.
  No wire change.
- **log.** `client.tgs`, `client.pkinit`, `client.fast`,
  `kdc.lookaside.full`, and `kdc.pkinit` are `krb5_log::events`
  constants. Library call sites keep those strings. `target` is the
  Rust module path and is not part of the log contract. The test job
  runs `cargo test --workspace --doc`. No wire change.
- **client.** `krb5-kinit` links `krb5-cli-install`, which prints the
  key-expiry banner. The library does not. `client-gate` checks that
  stderr line.
- **admin.** `krb5-kadmind` links the same installer, which prints
  `kadm5: {error}`. The library does not. `kadmin-rust-gate` checks
  that line.
- **ci.** `ctor` 0.4.3, `ctor-proc-macro` 0.0.6, `dtor` 0.0.6, and
  `dtor-proc-macro` 0.0.5 are cargo-vet exemptions. They exist so
  `krb5-kinit` and `krb5-kadmind` can install the two stderr printers.
  No wire change.

### W3-S3.10 parameter structs

- **tool.** A visibility widening (`pub(crate)` / `pub(super)` → `pub`,
  or private → any `pub`) is `vis-widen` and red unless accepted.
  Narrowing stays vis-only. A `pub(crate)` inside a doc comment is
  not a visibility token. `hygiene-fn-diff` self-test count is 70.
- **tool.** `hygiene-fn-diff --params` classifies a parameter-struct
  conversion as `params-only` when the new body is the old body after
  the rule-7 destructure, and a call site as `params-only` when the
  struct literal rewrites back to the old arguments. A map whose
  field order disagrees with the old signature exits 2.
  `hygiene-body-diff --params` uses that rewrite on test bodies.
  `#[expect(` counts as a suppression and not as a panic.
  Self-test counts are fn-diff 78, body-diff 34, inventory 3.
  A copied argument that rustfmt wraps, including a trailing comma,
  stays `params-only`. `krb5-testkit` `src/` is scanned, so a
  testkit builder call site is judged with the product functions.
- **krb5-types.** `hierarchical_walk_realms` is `#[must_use]`. The
  module `allow(clippy::must_use_candidate)` is gone. The doc cites
  `walk_rtree.c:394-452`. No wire or text change.
- **krb5-protocol.** `tgs_service_once` has seven parameters, so its
  `too_many_arguments` suppression is gone. No wire or text change.
- **krb5-admin.** `kprop_send_store`, `kprop_send_store_iprop`, and
  `serve_kadm5_conn` no longer carry a stale `too_many_arguments`
  suppression. `serve_kadm5_conn` keeps `needless_pass_by_value`.
  No wire or text change.
- **krb5-protocol.** `tgs_req_ex` takes `TgsReqParams`. The short
  wrappers `tgs_req_ex_addr`, `tgs_req_ex_from`, `tgs_req_ex_till`,
  and `tgs_req_ex_subkey` are gone; callers pass the fields those
  wrappers used to fill. No wire or text change.
- **krb5-kdc.** `apply_admin_fields` and `apply_admin_fields_in` take
  `AdminFields` (the kadm5 principal mask). Callers still set every
  field. No wire or text change.
- **krb5-kdc.** `Principal::from_keys` takes `PrincipalFields`
  (`requires_preauth`, `max_life`, `locked`, `pw_expire`). The struct
  is crate-private. No wire or text change.
- **krb5-admin.** `rpc_call_bytes`, `rpcsec_call`, and `rpcsec_data_rec`
  take `RpcCallId` (`xid`, `prog`, `vers`, `proc`). `rpcsec_data` still
  advances its own `xid`. No wire or text change.
- **tool.** A parameter struct may replace a consecutive slice of its
  fields. The destructure ends with `..` for the fields that function
  never took. A call may pass the whole struct or the struct binding.
  `hygiene-fn-diff` self-test count is 83.
- **tool.** Reading `ctx.field` for a field the callee never took is the
  same binding, not a new call. `hygiene-fn-diff` self-test count is 84.
- **tool.** An `&` that borrows a parameter struct as a whole argument
  is consumed when the literal is rewritten. `hygiene-fn-diff`
  self-test count is 85.
- **tool.** A parameter written `_name` matches the field `name`. A
  semicolon trait method needs no destructure, and an attribute on the
  destructure `let` is not part of the body. `hygiene-fn-diff`
  self-test count is 87.
- **tool.** Splitting `needless_pass_by_value` or `unnecessary_wraps`
  off a `too_many_arguments` attribute stays identical.
  `hygiene-fn-diff` self-test count is 88.
- **tool.** A `too_many_arguments` suppression is recognized in either
  position inside a combined attribute, and a converted call is still
  `params-only` after that suppression becomes `expect`.
- **krb5-admin.** `kadm5_handle_rpc`, `handle_rpc`, `handle_rpcsec_gss`,
  `handle_auth_gssapi`, `rpcsec_dispatch`, and `kadm5_or_iprop` take
  `RpcCtx` (store, ACL, service keys, realm). `serve_kadm5_conn` builds
  that value once. The two procedure dispatchers still carry
  `too_many_arguments`. No wire or text change.
- **krb5-admin.** `iprop_pull` takes `IpropLast` (`last_sno`, `last_sec`,
  `last_usec`). No wire or text change.
- **krb5-admin.** `kpropd_handle_conn` takes `&KpropdConfig` (host keys,
  expected peer, realm, master password, database, stash, ACL). No wire
  or text change.
- **krb5-client.** `kinit_ex` and `kinit_to_spec` take `&InitCredsOpt`
  (service, SPAKE, armor ccache, PKINIT identity, anchors, enterprise).
  No wire or text change.
- **krb5-kdc.** `KdcPreauth::process_as` and `run_as_preauth` take
  `&PreauthRock`. No wire or text change.
- **krb5-kdc.** `mint_ticket` takes `MintTicket` (the enc-ticket fields
  plus the PAC inputs). It is a parameter struct, not a wire type. No
  wire or text change.
- **krb5-admin.** `admin_gss_token` returns `AdminGssToken`. The
  `type_complexity` suppression is gone. No wire or text change.
- **lint.** The 26 remaining `too_many_arguments` suppressions are
  `#[expect]` with a reason. `tgs_once` keeps `needless_pass_by_value`
  and `handle_rpcsec_gss` keeps `unnecessary_wraps`. No wire or text
  change.
- **tool.** The parameter-struct judge compares tokens. A trailing
  comma is dropped only before a call's `)` or a `]` / `}`, never a
  one-tuple `(x,)`, and `& &` is not `&&`. A struct literal is
  rewritten only as a direct argument of a mapped call. A threaded
  `let` is not expanded. A shadowed field binding is not the struct
  value. `allow` and `expect` match only when the lint set is the
  same. A conversion may drop `too_many_arguments` because the arity
  fell; any other lint still has to match. The destructure `let`
  carries no attribute; `name: _name` matches an old `_name`
  parameter. A map entry may name an ordered subsequence of the
  struct's fields. `allow` counts outer `#[allow(`, inner `#![allow(`,
  and `#[expect(`; at `e48c0371` that is 80 where the outer-only count
  was 73. A `::tests::` key names a helper the product judge does not
  extract; its calls still rewrite. Self-test counts are fn-diff 119,
  body-diff 39, inventory 3.
- **tool.** A field the old signature did not keep next to the others
  is put back at that argument index when the struct argument is
  rewritten. `hygiene-fn-diff` self-test count is 120.

Residues of this item are under W3-S3.10-R.

### W3-S3.10-R residues

- **krb5-admin.** Three `RpcCtx` functions keep `too_many_arguments`:
  `handle_rpcsec_gss`, `handle_auth_gssapi`, and `rpcsec_dispatch`.
  `rpcsec_dispatch` reads `expected_realm` from the context. `RpcCtx`
  is the per-connection server context; MIT keeps the store and ACL as
  kadmind globals beside `kadm5_server_handle_rec`. No wire or text
  change.
- **krb5-kdc.** `MintTicket` is `pub(super)`. The crate-root re-export
  is gone. No wire or text change.
- **krb5-admin.** `RpcCallId` is `pub(crate)`. The crate-root re-export
  is gone. No wire or text change.
- **krb5-kdc.** The nine `unused_variables` allows on preauth
  destructures are gone. A field the old parameter spelled `_name` is
  written `name: _name`. No wire or text change.
- **krb5-admin.** `KpropdConfig`'s `expected_server` and
  `expected_realm` are the AP-REQ server principal and realm
  (`kprop/kpropd.c:127-143`), not the client's. No wire or text change.
- **krb5-client.** `InitCredsOpt` also cites `extended_options`
  (`lib/krb5/krb/gic_opt.c:19-32`). SPAKE and enterprise are request
  flags. No wire or text change.
- **tool.** Nested struct literals are rewritten before the body
  compare. `allow` counts outer `#[allow(`, inner `#![allow(`, and
  `#[expect(`; at `e48c0371` that is 80 where the outer-only count was
  73.

### W3-S3.10-R2 judge holes

- **tool.** `hygiene-body-diff --params` compares a shared helper the
  test calls. A converted literal whose fields are not in the map's
  order is `differ` and the run fails. No wire or text change.
- **tool.** A struct argument whose old parameters were not adjacent
  is written back at those indexes even when the map names every field.
  A wrong index is `changed`. The interleave in `685e7108` had no
  wrong-index fixture.
- **tool.** A `(` after `break`, `let`, `continue`, or `>` is a tuple.
  A one-tuple there keeps its comma. `>` is not a call opener, so a
  turbofish call with a trailing comma reads `changed`.
- **tool.** Passing the struct binding is not expanded when `for`,
  `if let`, `while let`, or a `match` arm rebinds a field before the
  call.
- **tool.** A mapped call is a bare name, a method call when that
  function took `self`, or `Type::name` for an impl associated
  function. The literal's struct must be that callee's.
  `other::g`, `obj.g` of a free function, and `g(T { … })` stay text.
  `#[expect]` and `#[allow]` stay the same lint set in either
  direction. Self-test counts are fn-diff 134 and body-diff 41.

### W3-S3.8 dead code and surface

- **krb5-tools.** `tgt_hex_must_use_ticket_etype_not_preferred` lives
  in `krb5-tools` tests and runs `krb5-forge-tgt` through
  `CARGO_BIN_EXE_krb5-forge-tgt`. `forge_tgt_exe` and
  `link_forge_tgt.rs` are gone. The assertion text is unchanged.
  `cargo nextest run -p krb5-kdc` no longer needs that bin.
- **tool.** `red-at-sha.sh` builds `krb5-forge-tgt` with `--bin` and
  no `-p`, so the same line works before and after the harness crate.
  `ci-policy` requires `hygiene-body-diff` self-test N ≥ 32 and
  `hygiene-fn-diff` self-test N ≥ 64.
- **krb5-kdc.** `PrincipalRead` no longer has `krbtgt_keys`. The
  trait method, the `Arc` forward, both product impls, the inherent
  wrapper, and the two test wrapper impls are gone. A KLLDAP
  `PrincipalRead` implementor has one fewer method. `krbtgt_key_vec`
  went with them: those wrappers were its only callers. Issuance
  still uses `fetch_krbtgt` and `first_current_key`. No wire or
  text change.
- **krb5-config.** `env_ccname`, `resolve_ccname`, `env_krb5_config`,
  and `lookup_srv_admin` are gone, with their crate-root re-exports.
  Nothing in the workspace called them. No wire or text change.
- **krb5-protocol.** `Error::is_preauth` and `create_exclusive_secret`
  are gone. Nothing called them. No wire or text change.
- **krb5-kdc.** `name_matches`, `key_kvno`, and `chrand_keepold_n_in`
  are gone. `name_matches` was the only caller of the private
  `principal_matches` helper, and `key_kvno` was the only caller of
  `key_for_kvno`, so those helpers go too. No wire or text change.
- **krb5-gss.** `wrap_with_ec` is gone. Nothing called it. Wrap still
  goes through `wrap_with_rrc` and `wrap_integ`. No wire or text change.
- **krb5-admin.** `kadmin_attr_bit` and `kpasswd_set` are gone.
  Nothing called them. Flag parsing still sets the same attribute
  bits. No wire or text change.
- **krb5-asn1.** `round_trip` is gone. Tests encode and decode
  through their own helpers. No wire or text change.
- **krb5-types.** The `err` and `pa` modules, and the PAC buffer
  constants, stay. The module doc says they are the complete MIT
  tables, including values this crate does not raise.
- **krb5-kdc.** The crate no longer re-exports `as_req`,
  `pa_enc_timestamp`, or `tgs_req`. Callers name `krb5_protocol`.
  No wire or text change.
- **tool.** `hygiene-fn-diff` treats a bare `pub` narrowed to
  `pub(crate)` or `pub(super)` as vis-only. A widening to bare `pub`
  stays changed. Self-test count stays 64.
- **krb5-kdc.** Every `status` constant is `pub(crate)`. The module
  is private, so the names were never a path outside the crate.
  `CLIENT_NOT_FOUND`, `SERVER_LOCKED_OUT`, and `SERVER_NOT_ALLOWED`
  stay at the same file and symbol for the ledger. No wire or text
  change.
- **krb5-kdc.** Dump helpers with no external name are `pub(crate)`:
  `KDB_DUMP_VERSION_R18`, `TL_MKVNO`, `TL_ACTKVNO`, `TL_KERBER_POLICY`,
  `SALTTYPE_SPECIAL`, `tl_mod_princ`, `load_dump_mkey`,
  `dump_store_etype`, `write_dump`, and `into_store`.
  `write_dump_path` had no caller and is gone. Types in the public
  dump signatures stay `pub`. No wire or text change.
- **krb5-kdc.** Audit, plugin, lookaside, and listen items with no
  external name are `pub(crate)`, including `Lookaside`,
  `set_client_port`, `bind_udp_tcp`, and `drop_privileges_to`.
  `ISSUE_TKT` and `VALIDATE_POL` had no caller and are gone. No wire
  or text change.
- **krb5-kdc.** Store, ACL, OSA, and realm helpers with no external
  name are `pub(crate)`. `OsaError` stays `pub` because public OSA
  decoders return it. `Restrictions::require_attrs` stays `pub`
  because tests build the struct with `..Default`.
  `MemoryStore::lookup_count` stays `pub` because its only caller is
  `cfg(test)`. No wire or text change.
- **tool.** Raising `pub(crate)` or `pub(super)` to bare `pub`, with
  the same body, is vis-only. Adding `pub` onto a private item stays
  changed. Self-test count stays 64.
- **tool.** A doc line added beside a legal visibility edit stays
  vis-only, so a newly `pub(crate)` helper can satisfy
  `missing_docs`. Self-test count stays 64.
- **tool.** A visibility compare that also strips doc lines does
  not treat a parenthesis inside a doc comment as a parameter
  list. Self-test count stays 64.
- **krb5-types.** `transited::hierarchical_walk_realms` is the one
  copy of MIT `rtree_hier_realms`. The KDC transit walk and
  `krb5-protocol` both call it. It names `MAX_TRANSIT_RAW` the same
  way the KDC copy did. The module doc cites `walk_rtree.c`. The
  module allows `clippy::must_use_candidate`: that lint applies only
  to a `pub` function, and `#[must_use]` would not match the KDC
  copy. No wire or text change.
- **krb5-kdc.** `take_der` is one `pub(crate)` function in `der`.
  `kdc_util` and `preauth` both call it. `take_der_slice` stays
  separate. No wire or text change.
- **krb5-kdc.** Fields of crate-private structs (`AclEntry`,
  `S4u2Self`, `SecondTicket`, `FastOk`, `AsFailState`) are
  `pub(crate)`. No wire or text change.
- **tool.** A `fn …;` inside a trait is its own item, and the trait
  item is the header through `{`. `PrincipalRead` losing
  `krbtgt_keys` is a removal, not a changed trait. `pub` at the
  start of an identifier is not a visibility token. Self-test
  count is 66.

### W3-S3.6 harness tools

- **krb5-kdc.** `start_stop_json` and `AuditState::to_json` return to
  `audit` as `pub(crate)`. `TestAudit` in `testrealm` is the user
  outside that module. `princ_json`, `addr_json`, `int_array`,
  `JsonObj`, and `json_escape` move with them and stay private.
  Bodies are unchanged. No wire or text change.
- **krb5-kdc.** `testrealm/mod.rs` is `testrealm.rs`. The child
  `testrealm/test_plugins.rs` stays. Every `krb5_kdc::testrealm`
  path is unchanged.
- **krb5-tools.** Empty harness crate (`publish = false`).
  `krb5-protocol` is a dependency with `features = ["diff"]`.
  `build-bins.sh` builds it. The seven tools still build from
  their old crates.
- **krb5-tools.** `kprop-expired-apreq` is a bin and depends on
  `krb5-admin` for `kprop_expired_ap_req`. The gate copies
  `debug/kprop-expired-apreq`. Stdout, stderr, and the usage text
  are unchanged.
- **krb5-tools.** `ccache-probe` is a bin. The ccache gate and
  `boot-shell.sh` copy `debug/ccache-probe`. Commands and exit
  codes are unchanged.
- **krb5-tools.** `loadgen` is a bin. `prod-realm-common.sh` copies
  `${CARGO_TARGET_DIR:-$ROOT/target}/debug/loadgen`. The JSON
  summary is unchanged.
- **krb5-tools.** `krb5-vfy-increds` is a bin of this crate.
  `debug/krb5-vfy-increds` is unchanged. Flags and exit codes
  are unchanged.
- **krb5-tools.** `krb5-forge-tgt` is a bin of this crate.
  `debug/krb5-forge-tgt` is unchanged. `red-at-sha.sh` builds
  it from `krb5-tools`. Flags are unchanged.
- **krb5-tools.** `krb5-pac-extract` is a bin of this crate.
  `debug/krb5-pac-extract` is unchanged. Flags are unchanged.
- **krb5-tools.** `diffsend` is a bin. `krb5-protocol` keeps
  `default = ["diff"]` and its dev-dependency on `krb5-kdc`.
  The gate copies `debug/diffsend`. Case count stays 111.
- **krb5-tools.** `hex_decode` is one private function, included by
  `krb5-forge-tgt` and `krb5-pac-extract`. The body matches both
  originals. A bin cannot call a private item of the library.
- **krb5-gss.** `read_token` and `write_token` are one private
  pair in `token_io.rs`, included by `krb5-gss-init` and
  `krb5-gss-accept`. The body is the fully spelled `TcpStream`
  form. Call sites are unchanged.
- **tool.** `hygiene-fn-diff` extracts `crates/<crate>/examples/*.rs`
  so a harness example can be a move row when it becomes a bin.
  Self-test gains that case.
- **krb5-tools.** Usage lines in `loadgen`, `diffsend`, and
  `krb5-forge-tgt` escape `[` and `<` so rustdoc does not read
  them as links. The rendered usage text is unchanged. Flags,
  stdout, and stderr are unchanged.

### W3-S3.5 test-realm namespace

- **tool.** `hygiene-body-diff.py` strips `testrealm::` and
  `principals::` only after `krb5_kdc::`, `crate::`, or `super::`.
  `--subst` accepts `documented_kadmin`, `documented_changepw`,
  `documented_history`, and `harness_master_etype`. Self-test 32
  cases.
- **krb5-kdc.** `kadmin/admin`, `kadmin/changepw`, and `kadmin/history`
  live in `principals` as `kadmin_admin`, `kadmin_changepw`, and
  `kadmin_history` (MIT `admin.h:64-66`). No root alias. The function
  bodies are unchanged. No wire or text change.
- **krb5-kdc.** `harness_master_etype` is `default_master_etype`.
  The body is unchanged. No wire or text change.
- **krb5-kdc.** The documented test realm (`TEST_REALM` and the
  other constants, `documented_host`, `documented_kiprop`,
  `documented_admin_id`, `bootstrap_documented`) lives in
  `testrealm`. No root re-export. Always compiled. No wire or
  text change.
- **krb5-kdc.** `TestAudit`, `TestPolicy`, `DenyPolicy`,
  `DemoPreauth`, `DemoPolicy`, `GreetAuth`, and the `GREET_*`
  constants live in `testrealm` (`test_plugins.rs`; `plugins.rs`
  already names the product registry). `DenyPolicy`
  stays `#[cfg(test)]`. No root re-export. No wire or text change.
- **krb5-kdc.** `start_stop_json` and `AuditState::to_json` stay private
  at the crate root, shared by `JsonAudit` and `TestAudit`. No wire or
  text change.

### W3-S3.4e remaining >1,500-line module splits

- **krb5-types.** `pkinit.rs` is split into `pkinit/{ca,cms}.rs`.
  `PkinitCa` and `cms_wrap` live in `ca` (so `cms` does not import
  the CA); CMS SignedData wrap/verify lives in `cms`
  (`pkinit_crypto_openssl.c` `cms_signeddata_create` /
  `cms_signeddata_verify`). Every `pub` path `krb5_types::pkinit::X`
  is unchanged. Names the parent uses from a child are
  `pub(super)`; names that stay in the parent stay private. No wire,
  text or store behaviour changed.
- **krb5-protocol.** `as_ex.rs` is split into `as_ex/{fast,spake}.rs`.
  FAST armor (`fast.c`) and SPAKE (`spake_client.c`) leave
  `PkinitClient`, `build_as_req`, and the reply-time checks on
  `as_ex.rs` so the three text pins stay. `FastArmor` and
  `fast_error_material` keep their crate paths. Ledger rust-sites
  follow the new files. Names the parent uses from a child are
  `pub(super)`; names that stay in the parent stay private. No
  wire, text or store behaviour changed.
- **krb5-types.** `pac.rs` is split into `pac/ndr.rs` (MS-PAC /
  MS-RPCE Type-Serialization v1; MIT `pac.c` does not parse
  `KERB_VALIDATION_INFO`). Ledger anchors stay on `pac.rs`.
  `pac/tests.rs` and its `include_bytes!` are untouched. Every
  `pub` path `krb5_types::pac::X` is unchanged. Names the parent
  uses from a child are `pub(super)`; names that stay in the parent
  stay private. No wire, text or store behaviour changed.

### W3-S3.4d-R residues

- **docs.** Five ledger proof cells follow the moved tests:
  `cammac_round_trip_and_bad_mac_ignored` and
  `cammac_bad_kdcver_mac_is_skipped` cite
  `ad/handle_authdata_tests.rs`; `omitted_lifetime_is_one_day`
  and `renew_life_shorter_than_till_is_clamped` cite
  `as_ex/as_kdc_options_tests.rs`.

### W3-S3.4d isolate host-/tmp scan and tests-out

- **scripts.** `check_isolate_test_krb5` tokenises through
  `hygiene_inventory.strip_noncode` then brace-matches on the
  blanked text, so a `temp_dir()` in a string or comment is not a
  call. `testenv.rs` is scanned whole (`temp_dir()` in code or
  `/tmp/kerber-test-krb5` anywhere). `#[cfg(test)]` matches
  anywhere on the line; `cfg(all|any(..., test, ...))` counts.
- **tests-out.** In-src test modules leave the five remaining
  files over 1,500 lines (`pkinit.rs`, `krb5-types/src/lib.rs`,
  `as_ex.rs`, `pac.rs`, `ad.rs`). Named modules keep their names
  and nextest ids. `pac/tests.rs` retargets `include_bytes!` of
  the kbruser NDR trace by one `../`.

### W3-S3.4c-R residues

- **krb5-config.** `Error::Ccache`'s doc names MIT only for
  `Unknown credential cache type` (`krb5_err.et:190`); the two
  `%{token}` texts are this crate's (MIT `expand_path.c` says
  `Invalid token` / `variable missing }`). The unknown-type unit
  pins that MIT literal. The 4b entry no longer says the six fns
  keep `Result<_, String>`.
- **scripts.** `check_isolate_test_krb5`'s missing-`tests.rs`
  fixture is a directory tree under scratch so the production
  `is_file()` branch is what goes red; cfg(test) `temp_dir()` is
  scanned by item range, not from the first `#[cfg(test)]` to EOF.

### W3-S3.4c ccache errors use `Error`

- **krb5-config.** The six public ccache-name fns and private
  `ccache_param` return `Result<_, Error>` via a new `Error::Ccache`
  variant whose Display is the previous string (`Unknown credential
  cache type`, `unterminated %{token}`, `unknown ccache parameter
  %{…}`). `kswitch` / `vfy-increds` map that through `.to_string()`
  at the `?` sites; bins that print `{e}` are unchanged. No wire,
  store or gate-grep text changed.
- **scripts.** `check_isolate_test_krb5` dies if `tests.rs` is
  missing, scans every `src/*.rs` cfg(test) region for `temp_dir()`,
  and the self-test reds those arms.

### W3-S3.4b krb5-config module split

- **krb5-config.** `lib.rs` is split into
  `{profile,kdcconf,ccname,srv,testenv}.rs`. Inner attributes,
  `Error`, `Endpoint`, `Krb5Conf`, `KdcConf`, and `CcSpec` stay on
  the crate root so every `pub` path `krb5_config::X` / method /
  field / variant is unchanged (complete before/after list
  identical, 141 paths). Process-global test state
  (`TEST_KRB5_PATHS`, `TEST_KRB5_ISOLATION`, `ISOLATE_SEQ`) moves
  once, into `testenv`. Sibling-only names are `pub(super)`,
  nothing became `pub`. In-src tests moved to `tests.rs` first
  (path `tests`). No wire, text or store behaviour changed. The
  six ccache fns still returned `Result<_, String>` here; 4c
  above takes them to `Error`.
- **docs.** The parity ledger's `krb5-config/lib.rs` rust-sites
  name the module files; `CcSpec` stays on `lib.rs`.
  `check_isolate_test_krb5` reads `testenv.rs`.

### W3-S3.4a krb5-gss module split

- **krb5-gss.** `lib.rs` is split into
  `{context,wrap,mic,iov,export,spnego,deleg,oid}.rs`. Inner attributes,
  `Error`, and `GssContext` stay on the crate root so every `pub` path
  `krb5_gss::X` / `GssContext::method` is unchanged (before/after list
  identical). Sibling-only names are `pub(super)`, nothing became
  `pub`. In-src tests moved to `tests.rs` first (path `tests`). No wire,
  text or store behaviour changed.
- **docs.** The parity ledger's `krb5-gss/lib.rs` rust-sites name the
  module files; `Error` stays on `lib.rs`.

### W3-S3.3b issue.rs module split

- **krb5-kdc.** `issue.rs` is split into
  `issue/{dispatch,as_req,tgs_req,tgs_policy,kdc_util,fast_util,reply}.rs`,
  each headed by the MIT file or function family it mirrors; the root
  keeps the crate's re-exports so `lib.rs` and the `crate::issue::`
  sites stay byte-identical. Every item moved whole (`hygiene-fn-diff`:
  0 changed); sibling-only names are `pub(super)`, nothing became
  `pub`. `mod a2_6_crossrealm` stays beside `tgs_header_is_crossrealm`.
  No wire, text or store behaviour changed.
- **docs.** The parity ledger's `issue.rs` rust-sites name the module
  files; colliding `dispatch.rs` admin sites are `krb5-admin/…` and
  the new KDC dispatcher is `krb5-kdc/dispatch.rs`. Line pins on
  `finish_preauth` and `mint_ticket` follow the moved statements.
  `security.md` cites follow.

### W3-S3.3 issue.rs phase split

- **tool.** `hygiene-body-diff.py` keeps a zero-length interior line
  of a string literal (the newline's own span, not the empty slice).
  Self-test 24 cases.
- **kdc.** `issue_as_body` and `issue_tgs_body` become MIT-phase
  orchestrators (`lookup_client` / `finish_preauth` /
  `finish_process_as_req`; `gather_tgs_req_info` / `check_tgs_req` /
  `compute_ticket_times` / `tgs_issue_ticket`). Each new fn's doc
  cites its MIT line. Carried state is data-only. File split is 3b.
  Ledger rust-sites that named the old bodies follow the phase that
  now holds the status word.
- **tool.** `--split` compares attribute blocks, optional `head:` /
  `tail:` glue (start / end after rewrap), and `let mut` → `let`
  edits. `rustfmt_skip` is a quality key. Self-test 63 cases.
- **kdc.** The nine `#[rustfmt::skip]` and two `#[allow(unused_mut)]`
  come off; rustfmt wraps the glue. The TGS dispatcher makes MIT's
  three calls; flags / times / kdcpolicy is `tgs_flags_times_policy`
  at the tail of `check_tgs_req`.

### W3-S3.2-R residues

- **tool.** `hygiene-body-diff.py` keeps string, byte-string,
  raw-string and char literals whole (the span splitter is shared
  with `hygiene-fn-diff.py`). A whitespace edit inside an asserted
  literal is an assertion change; anywhere else it is a `differ`.
  Self-test 23 cases.
- **tests.** The four `store/tests.rs` kdc.conf raw-string interiors
  that the tests-out mover de-indented are restored to their
  `w3-base` bytes.
- **docs.** `store/rid.rs` drops the invented `kdb5.c` `RID_*`
  attribution (MS-ADTS / MS-PAC; MIT has no RID concept). The
  `store.rs` header names `store/tests.rs`. Ledger `:345`
  `alias_target`, `:401` `store/tests.rs`, `:429` closing backtick.

### W3-S3.2 store by MIT source family

- **tool.** `hygiene-fn-diff.py` treats a lifetime before `(` as a
  type, not a list opener: `&'a (T,)` → `&'a (T)` is `changed`.
  Self-test 56 cases.
- **tests.** The 25 in-src store tests move to `store/tests.rs`; the
  module path stays `store::tests`.
- **krb5-kdc.** `store.rs` is split into
  `store/{flags,principal,policy,password,keys,alias,transit,iprop_ulog,history,rid}.rs`,
  each headed by the MIT file or function family it mirrors; the root
  keeps `PrincipalStore`, `kadm5_mask`, the cfg(test) fault flags, and
  the crate's re-exports. Every item moved whole (`hygiene-fn-diff`: 0
  changed); sibling-only names are `pub(super)`, nothing became `pub`.
  No wire, text or store behaviour changed.
- **tests.** `zeroize_ct.rs` pins the password-history `ct_eq` in
  `store/password.rs`.
- **docs.** The parity ledger's `store.rs` anchors and the
  `security.md` / `plugins.md` cites name the module files; colliding
  `principal.rs` / `policy.rs` admin sites are `krb5-admin/…`. The
  `Principal::first_current_key` rustdoc link is
  `crate::Policy::first_current_key` so rustdoc resolves it after the
  split.

### W3-S3.1 kadm5 by MIT source family

- **krb5-admin.** `kadm5.rs` (4,233 lines) is split into
  `kadm5/{codes,xdr,rpc,auth,iprop,dispatch,principal,policy,glob,log}.rs`,
  each headed by the MIT file or function family it mirrors; the root
  keeps the module list and the crate's re-exports. Every item moved
  whole (`hygiene-fn-diff`: 3,457 pairs, 0 changed); 249 private
  items the siblings or the in-src tests reach are `pub(super)`,
  nothing became `pub`. No wire, text or store behaviour changed.
- **tests.** `keysalt.rs` pins the weak-etype filter in
  `src/kadm5/xdr.rs`; the in-src `kadm5/tests/` import the sibling
  modules explicitly.
- **docs.** The parity ledger's `kadm5.rs` anchors (45 rows) and two
  `security.md` cites name the module files.
- **tool.** `hygiene-fn-diff.py` no longer attaches a `//!` module
  header to the first item under it; a file's `#![…]` inner
  attributes are its own compared `inner-attrs` item. A private →
  `pub(super)` widening whose signature rustfmt re-wraps (one
  parameter per line, trailing comma) is `vis-only`; the same rewrap
  with no visibility change is `fmt-only`; a `(T,)`, `&mut (T,)` or
  `*const (T,)` tuple keeps its comma and string literals in the head
  pass through whole. Self-test 55 cases. `ci-policy.py` skips `#[cfg(test)]` children
  of `src/**` when indexing ledger anchor files, so
  `kadm5/tests/policy.rs` does not collide with `kadm5/policy.rs`;
  `hygiene_inventory.py` skips only a package's own `target/`, so the
  classification holds for a package that lives under one.

### W3-S3-0 pre-flight

- **scripts.** Gate KDC starts wait for the listener (or a log line)
  with a hard cap of at least 20 s (10 s for a port-free wait) and die
  naming what never appeared (`require_listen` / `require_log` /
  `require_port_in` in `gate-common.sh`). `require_listen` keeps
  polling after `bind failed` while `krb5-kdc` is still alive
  (`:88 || :8888`). `kdc-gate.sh` and
  `client-differential-flows-gate.sh` wait with those helpers before
  the single read; no assertion was removed. Expected strings and
  cells are unchanged.
- **scripts.** `ci-status.py` listings and `--check-budget` keep `main`
  pushes and the PR under test; dependabot runs are dropped. Cargo
  dependabot `open-pull-requests-limit` is 0 through W3.
- **tool.** `hygiene-fn-diff.py` compares product `fn` bodies between
  two trees (`crate<TAB>module::path::[impl-header::]name`). A body edit, a
  dropped fn, a reordered `--split`, or an unused `--accept` is red;
  a pure move and a private → `pub(crate)` / `pub(super)` widening
  are green; a change to or from bare `pub` is red. `--self-test` prints
  `self-test ok (43 cases)`; ci-policy requires that count. Literal
  contents (e_text, char, a `--split` phase) are compared. `--glue`
  is line-anchored and new-only. Attribute blocks are compared;
  doc-only `///` edits do not fail. Keys include inline `mod` nesting
  and the full `impl` header; `--roots` adds `examples/` and `fuzz/`.
- **docs.** `docs/testing.md` keeps `--dead` on the `hygiene-diff.py`
  paragraph and describes the fn-diff literal normaliser and
  line-anchored `--glue`.

### W3-S3-0R residues

- **scripts.** Every shape-(b) server-written log or trace is waited
  with `require_log` or `retry_until` (the assertion command itself)
  before the existing read. `die` and `unavailable`
  print a `::error file=…,line=…::` annotation on Actions. `ci-status.py`
  also matches `head_branch` when `pull_requests` is empty.

### W3-S3-0R2 last residues

- **scripts.** `ci-policy.py` and `hygiene_inventory.py` share one
  `_in_poll_loop` (lookback 30). `kdc-gate.sh`'s `/tmp/au.log` wait is
  `retry_until` (20 s). The tagged `# proto:` sleep in `mit_kdc_restart`
  is in the ratchet sum again (22.50 s).
- **scripts.** `unavailable` annotates `::notice`; `die` keeps `::error`.
  Both name the first frame outside `scripts/lib/`.
- **scripts.** A dead shared MIT container is named in a structured
  warning (and `::warning` on Actions); the replacement gets
  `mit_conf_snapshot`.
- **tool.** `vis-only` covers brace-less items and struct fields
  widened to `pub(super)` / `pub(crate)`. `render` names each
  `vis-only` and `doc-only` item. Each `--glue` line excuses one
  occurrence. `mod` and `impl-header` blobs include their attributes.
  `--self-test` is 43 cases. `--glue KEY=LINE` and `glue:` in the
  `--split` map are per-split; `old = old + tail` is accepted; a
  missing map file is an error.

### W3-S2-R3 compare-tool robustness

- **tool.** Each `--self-test` (`hygiene-diff`, `hygiene-body-diff`,
  `hygiene_inventory`) prints `self-test ok (N cases)`. `ci-policy`
  requires N at or above the known count; a copy whose `_self_test`
  body is `return None` (tokens kept in the docstring) is red.
- **tool.** `hygiene-body-diff` smashes a same-file helper only when
  the name exists on both sides; a rename compares helper bodies and a
  weaker body is an assertion change. `--accept` is keyed nextest
  `binary<TAB>name` (one entry, one pair); the RHS must exist in the
  new tree. The assertion blob keeps helper-call arguments.
- **tool.** `check_capture_env_only` requires a
  `refuse_golden_capture_dir` *call* line
  (`^\s*refuse_golden_capture_dir\s+\S`) in
  `prod-realm-common.sh` and `harness/prod/env-up.sh`.

### W3-S2-R2 compare tooling

- **tool.** `hygiene-body-diff --accept` is keyed `binary<TAB>name` and
  pins old→new assertion-blob hashes; an unused entry or a blob
  mismatch is red. `--subst` rewrites only declared-helper call
  positions. Callee names stay in the assertion blob;
  `#[ignore]` / `#[should_panic]` are compared. The request-shape
  column is dropped (no canonical built-request form).
- **tool.** `hygiene-diff --renames` is keyed and collision-checked
  (many-to-one needs `merged:`). Negative duplicates fixtures go
  through `main_compare`; `--accept-rise` has mismatched-N and unused
  reds.
- **tool.** `ci-policy` executes both `--self-test`s. The gutted
  `_self_test` red is S2-R3 (case count + body replacement).
  `check_capture_env_only` scans `harness/**/*.sh` and
  `.github/workflows/*.yml` and matches `var_os` / `option_env!`.
- **tool.** Inventory `CFG_TEST_RE` accepts `#[cfg(test)] mod x;`.
  `check_doc_file_cites` excludes `CHANGELOG.md` (history).

### W3-S2-R residues

- **fix.** Restore `capture.rs` product semantics: unset or empty
  `KERBER_CAPTURE_DIR` writes nothing. Golden-home protection lives in
  `gate-common.sh` `refuse_golden_capture_dir` and `ci-policy`
  `check_capture_env_only`.
- **test.** `cross_tgt_renew_realm_mismatch_is_server_nomatch` (body
  asserts 26 `SERVER_NOMATCH`, not `BADOPTION`).
- **test.** Drop redundant clippy unwrap/expect/panic allows on admin
  `tests/*.rs`; keep the four `tests/common` `dead_code` allows.
  `hygiene-diff` fails an `allow_sites` rise unless `--accept-rise`.
- **docs.** File cites follow the S2 merges (`pac_ad_capture.rs`,
  `tgs_crossrealm.rs`, `acceptor_realm.rs`, crate-qualified
  `diffsend`/`loadgen`). `ci-policy` `check_doc_file_cites` is fail-red
  on a missing backticked path; `check_gate_unit_index` has a missing-twin
  fixture.
- **test.** `checksum_bit_flip_is_integrity` pins `verify_checksum_type`'s
  `mac_verify` line. `docs/security.md` restores `known_answer.rs` and
  the EncryptionKey / PkinitClient Drop rows.
- **tool.** `hygiene_inventory` books a `src/**` file the parent declared
  `#[cfg(test)] mod` as `src-test` (`diff_compare.rs`, `kadm5/tests`).
- **tool.** `hygiene-diff --duplicates` is keyed
  `binary<TAB>name`; many-to-one needs `merged:`.
  `scripts/hygiene-body-diff.py` compares test bodies through those maps
  (a kept twin is not skipped as a duplicate; rustfmt wrap is helper-only).

### W3-S2.6 coverage

- **test.** Gate↔unit index: `// oracle: differential-gate.sh <case>`
  on the status-word twins, generated `docs/gate-unit-index.md`,
  `ci-policy` fail-red when a cell has no tagged twin. Four twins:
  `unknown-sname` 7, `s4u2proxy-not-forwardable` 13,
  `s4u2proxy-header-pac` 13, `s4u2proxy-local-stkt-pac` 13.
  `krb5-crypto/tests/zeroize_ct.rs` pins Drop+zeroize and `ct_eq`.
  `s4u2proxy_rejects_non_forwardable_evidence` also asserts e_text
  `EVIDENCE_TKT_NOT_FORWARDABLE` (the one S2 assertion addition).

### W3-S2.5 fixtures

- **test.** Capture is env-gated (`KERBER_CAPTURE_DIR` set and
  non-empty); gates choose the directory. `.gitignore` allow-lists the
  13 tracked goldens. `scripts/promote-trace.sh` copies one PDU and
  appends the README row. AD keytabs stay in `~/adlab`. Fuzz: `cmin`
  note plus seeds on `pkinit_cms` / `spake_point` / `oakley_dh` /
  `gss_token`.

### W3-S2.4 subject taxonomy

- **test.** `krb5-types/tests/k3_parse_deltat.rs` → `parse_name_deltat.rs`
  (`ci-policy` red-at-sha overlay-probe fixture follows).
  `krb5-client/tests/r1_ccache_config.rs` → `ccache_config.rs`.
  `krb5-gss` 6 → 4: `accept_checksum.rs` ← `process_checksum` +
  `zero_token_cb`; `unwrap_v3.rs` absorbs `v2_callers`;
  `z1_kvno_pin.rs` → `acceptor_kvno.rs`; `context_flow.rs` stays.
  `krb5-protocol` 29 → 12: subject files; `z1_fast_reply` moves
  from kdc into `client_fast.rs`; `z8_rtime` into `client_verify_as.rs`.
  `krb5-admin` 35 → 15: `kadm5_{create,modify,policy,alias,glob}`,
  `pwqual`, `rpcsec`, `acceptor_realm`, `kpasswd`, `kpropd_acl`,
  `cli_stdin`, `keysalt`; `kprop` / `acl_dispatch` / `ktadd` stay
  (ktadd absorbs `z7_local_stamp`).
  `krb5-kdc` 81 → 36: `as_*`, `tgs_*`, `pac_*`, `kdb_*`, `acl`,
  `ap_req`, `audit`, `kdcpolicy`, `kpasswd`, `net_listener`;
  `store_flow` stays. One named duplicate dropped
  (`unknown_client_e_text_is_client_not_found`; keep `j3`).
  Prefix strip (crate-sized): crypto `b1_etype_preferred_omits_weak`
  → `etype_preferred_omits_weak`. GSS `z1_gss_accept_kt_*` →
  `gss_accept_kt_*`. Client `z1b_key_exp_order.rs` → `key_exp_order.rs`
  and the three `z1b_` fns. Config five in-src names (`c1_`/`a4_*`/`f6_`).
  Protocol 111 (`b1_`/`b2_`/`z1_`/`z7_`/`z8_`);
  `rd_req_authenticator_skew_is_37` → `…_is_skew`.
  Admin 39 (`z1_`/`z1b_`/`z6_`/`z7_`/`z8_`/`c1_`/`c2_`/`a2_r16_`).
  KDC 145; documented `a2_r19_expired_caddr` / `a4_16_unsigned_anon`
  rewrites; trailing `_is_24`/`_is_26`/`_is_7`/`_is_still_13` become
  status words.

### W3-S2.3 in-src tests by shape

- **test.** Whole-flow tests leave `src/`; private-bound and
  pure-unit stay. `krb5-config` include-tree (9) →
  `tests/include_tree.rs` (`g9a_tree` uses `scratch_dir`;
  `isolate_test_krb5_stays_off_host_tmp` stays on
  `TEST_KRB5_PATHS`). `krb5-gss` init/accept flow (19) →
  `tests/context_flow.rs`. `krb5-kdc` store whole-flow (17) →
  `tests/store_flow.rs` (15 private-bound + public-only unit
  stay). `krb5-admin` lib (37) →
  `tests/{kpasswd_authz,kpasswd_wire,kpasswd_malformed,kprop,acl_dispatch,ktadd}.rs`
  (4 parser tests stay). `kadm5.rs` 126 tests stay private-bound
  and regroup into `kadm5/tests/{framing,glob,auth_gssapi,rpcsec,privilege,changepw,getprinc,principal,lockdown,keysalt,policy,setstr,reload,iprop}.rs`
  (`privilege` not `acl.rs`, so the ledger `acl.rs` cite stays
  `krb5-kdc/acl.rs`). `tests/diff_compare.rs` →
  `src/diff_compare.rs`; `r10_edata_oracle.rs` deleted (−2 named
  duplicates). `ci-policy` requires a `[[test]]` for every
  `tests/*.rs` in an `autotests = false` crate. Unit `sleep(`
  ratchet 8 → 14: the same waits moved from `src/` into
  `tests/` (the inventory only counts `crates/*/tests`).

### W3-S2.2 shared test helpers (`krb5-testkit`)

- **test.** `crates/krb5-testkit` (`publish = false`, a `krb5-kdc`
  dev-dependency) holds helpers that were copied across KDC test
  binaries. `pref_etypes()` — the 15 remaining copies (two spellings of
  `EncryptionType::preferred()` → IANA numbers). `aes_key(seed)` — the
  five identical AES-256 repeated-byte keys. `host_tgt` — the five
  identical documented-host AS TGTs. `attach_pac` — the four identical
  Win2k PAC attach bodies. `password_key` — the eleven string-to-key
  copies (unwrap vs `expect("s2k")`, salt binding). `issue_tgt` /
  `issue_tgt_password` / `issue_tgt_renewable` — the 19 AS-TGT helpers
  (store-key vs password-key kept as separate paths).   `user_as` /
  `user_as_bits` — the ten TEST_USER AS helpers (two with option
  bits). `status` / `expect_status` — borrowed `proto` vs owned
  `code` (panic strings kept apart); `protocol_code` for the
  `Result`→`Option` `code`;   `err_of` / `err_of_cname` for the two
  wire `KRB-ERROR` decoders. `s4u_tgs` / `s4u_self` / `s4u_admin`
  — the three S4U TGS helpers (`pref_etypes` vs AES-256-only kept
  apart). `evidence_for_user` — the two admin→user evidence
  tickets (`a4_18b`'s inline store-key AS is `issue_tgt`).
  `wrap_if_relevant` — the three test IF-RELEVANT wrappers
  (product `ad.rs` stays `Result`-returning). `user` / `admin` /
  `host` / `krbtgt` / `realm` / `realm_with` — TEST_* principal
  constructors (`cname`/`krbtgt_name` map onto `user`/`krbtgt`;
  protocol `"user"` / `KERBER.TEST` stay local). `scratch_dir` —
  the four local copies plus the test `temp_dir()` sites (client
  and admin take testkit as a **dev-dependency**). `foreign()` —
  the `OTHER.TEST` krbtgt constructor. `reseal` / `reseal_mut` /
  `reseal_store` / `reseal_tgt` / `reseal_incoming` — PAC reseal
  (incompatible bodies kept apart; `z1` decrypt+mutate and `z6`
  etype rewrite stay local). `AsReqBuilder` / `TgsReqBuilder` —
  the 101 test `tgs_req_ex*` sites plus the testkit AS/S4U
  wrappers (`diffsend` and product `src/` stay on the protocol
  helpers; S3 records the pub-surface move). Thin
  `tests/common/mod.rs` in kdc/protocol/client/gss for crate-local
  glue (`isolate_host_krb5`, `client_key`; admin XDR stays in
  admin). Assertion
  text in those files is unchanged.

### W3-S2.1 drop the eight a2_*_parent red-inject files

- **test.** The eight `crates/krb5-kdc/tests/a2_*_parent.rs` binaries
  (1,824 LOC, 36 tests) are deleted. Red-at-parent stays a capture-time
  overlay (`red-at-sha.sh --inject` + `unit-red-check.py`); nothing at
  HEAD read these files. 35 tests share a name with the green twin (15
  byte-identical, 20 cosmetic); `u2u_host_tgt_issues_kvno_none` is
  subsumed by `u2u_host_tgt_issues_kvno_zero`. `unit-red-check.py` and
  `unit-evidence.sh` are byte-unchanged.

### W3-S1 lints, toolchain, dependencies, CI shape

- **Evidence runners.** `checkpoint.sh` and `hygiene-snapshot.sh` refuse
  to run unless the host `default_realm` is the `TESTLABBY.LOCAL` lab
  stub (`scripts/lib/lab-realm.sh`; `KERBER_ALLOW_HOST_REALM=1` overrides,
  recorded in the stamp). The checkpoint stamps its own bookkeeping files
  (`00-head.txt`, `02-progress.txt`, `04-gate-wall.log`, `timings.tsv`)
  and writes an `INDEX.md`; the snapshot index names every `--quality`
  file; `hygiene-diff.py` prints a provenance header. No product code
  changes.
- **Lints.** `missing_docs = "deny"` workspace-wide, paid for with one
  `///` per RFC 4120 field in `krb5-types` (103), the 12 CAMMAC fields and
  the two `krb5-client` modules; the panic-deny trio on `krb5-admin`,
  `krb5-asn1` and `krb5-log` (10/10 libraries, no code fixes); the 33
  rustdoc warnings fixed (ASN.1 `[n]` tags and usage lines in code spans,
  private-item links unlinked, `Error` disambiguated) and `make doc` /
  the `doc` job strict under `RUSTDOCFLAGS=-D warnings`;
  `needless_borrows_for_generic_args` retired (17 borrows dropped, all in
  tests/tools); the clippy `cargo` group at deny with
  `multiple_crate_versions` and `cargo_common_metadata` allowed for the
  reasons stated. `no_effect_underscore_binding` stays allowed: the rasn
  derives bind every field `_`-prefixed (the comment now says so).
- **Toolchain.** `rust-toolchain.toml` (`stable`, rustfmt + clippy, minimal
  profile). Because the file outranks `rustup default`, the `msrv` and
  `msrv-test` jobs pin `RUSTUP_TOOLCHAIN: 1.95`; `fuzz/Cargo.toml` gains
  `rust-version`; `ci-policy.py check_msrv_pinned` asserts both manifests,
  the channel and both jobs agree on 1.95.
- **Dependencies.** The 11 unused declarations removed (`krb5-log` from
  client/config/gss/consumer, `tracing` from config/gss/consumer/kdc-consumer,
  `zeroize` from kdc, `chrono` and dev `tracing-subscriber` from protocol)
  and the duplicate `sha2` dev line; `Cargo.lock` loses 11 edges and no
  package. `krb5_log`: `events::{HARNESS_START, HARNESS_KDC_READY,
  HARNESS_KINIT, PROTOCOL_AP_REP, GSS, CONFIG}` and the ten `FIELD_*`
  constants deleted — none was referenced from Rust; the three harness
  event strings stay live as literals in the `harness/` entrypoints
  (`events::ADMIN` is the `event` of 18 `tracing` calls and stays);
  `docs/logging.md` names the Rust and harness components and the
  harness events the gate scripts grep for. `deny.toml`:
  `yanked = "deny"`, explicit empty `ignore`, `multiple-versions = "deny"`
  with `getrandom 0.4` and `syn 3` as the only skips, `wildcards = "deny"`
  (`allow-wildcard-paths` for the version-less path deps), licence list
  trimmed to the four the lock uses.
- **CI shape.** Every workflow grants `permissions: contents: read`
  (`audit` adds `checks`/`issues: write` for `rustsec/audit-check`);
  `ci.yml` and `fuzz.yml` cancel superseded runs; all 41 third-party
  `uses:` are pinned to a commit SHA with the tag in a comment, and
  `.github/dependabot.yml` moves the pins (github-actions daily, cargo
  weekly). The toolchain + lld + `rust-cache` steps every cargo job
  repeated are one composite (`.github/actions/rust-preamble`, 17 call
  sites; checkout must precede a local action, so it stays inline). A
  fail-red `shellcheck -S style` job (`make shellcheck`) over
  `scripts/*.sh scripts/lib/*.sh harness/*.sh` with `.shellcheckrc`
  (`external-sources=true`, `SC2329` off), on ShellCheck v0.11.0
  installed by version and sha256 (the runner's 0.9.0 package reports
  493 SC2317/SC2119 notes 0.11.0 does not; the Makefile fallback image
  and the hygiene inventory pin the same version, asserted by
  `ci-policy.py`): the 86 inline `SC1091` disables are gone and the 90
  style findings are 0 (69 fixed in the scripts, the 21 `SC2329`
  never-invoked-function notes silenced by `.shellcheckrc` until S6)
  without changing what any gate does — `register_cleanup` strings expand their constant
  container names at registration (the two PID cleanups are named
  functions), 14 unused loop counters and the dead variables removed
  (five `UNAVAIL` paths, `GATE_COMMON_SOURCED`, `STOP_MIT`, `OWN`,
  `free`, `KADMIND_PORT`/`MIT_IPROP_PORT`, the ten `RUST_GSS_ACCEPT`/
  `MIT_GSS_SERVER` assignments, two stale `local` names), `VFY_ENV` is
  an array, `set -- $spec` splits on its one space explicitly. `fuzz.yml` asserts every corpus
  is non-empty (the committed `seed-*` files plus the traces that fit)
  and uploads `fuzz/artifacts/<target>` for 30 days on failure.
  `geiger.sh` and the checkpoint self-test `mktemp` under
  `KERBER_SCRATCH`; `ci-policy.py host_tmp_write_lines` flags a bare
  `mktemp` and `check_no_host_tmp_writes` covers every `scripts/*.sh`.
  `.gitattributes` marks prose as documentation and the parity ledger
  as generated. New `ci-policy.py` assertions: `check_workflow_hardening`;
  `check_msrv_pinned`, `check_rust_cache_shared_key`, `check_build_profile`
  and the `kcm-opcode` lld rule read through the composite; the prod-gate
  cleanup check accepts a named function.
- **Comparison harness.** `hygiene-diff.py --dead <map>`: an `echo`-kind
  cell tag (the `MIT_*`/`RUST_*` identifier scan) listed with a reason is
  reported as information when it disappears, so deleting a dead path or
  port constant does not read as a lost cell; `section`/`flow` tags and
  unlisted `echo` tags still fail. A map may carry the evidence stamp.

### W3-S0 comparison baseline

- **Shape inventory.** `hygiene-snapshot.sh` records, next to the W2
  time inventory, LOC/SLOC/comment/doc lines per package and file,
  functions over 40 lines with scope and doc header, `pub` vs restricted
  items, `#[allow]` sites, process-tag comments, gate assert counts,
  binaries and declared/resolved dependencies. `--quality` adds
  fmt/clippy/rustdoc-`-D warnings`/doctest counts, `missing_docs` per
  library (`--force-warn`, 117 at the W3 base) and `shellcheck -S style`
  (binary or the local `koalaman/shellcheck` image; `na` without either).
  `hygiene-diff.py` fails when any of those counts rises or a quality rc
  goes red, reports shape deltas, and self-tests the new rules. `make
  snapshot QUALITY=1`, `make rust-kdc`. No product code changes.

### W2-Y5 X4 proof and docs truth

- **serve_until probe.** `serve_until_honours_shutdown_within_the_poll_interval`
  sends a real AS-REQ and reads the KRB-ERROR before storing the shutdown
  flag. `unit_red_at` inject with `shutdown_poll = io_timeout` (5 s) fails
  the kept `< 2 s` assertion in 5.13 s (`red-at-parent=` / `--inject`).
- **log() arity.** `gate-common.sh` `log()` refuses a call that is not 2
  or 3 args. `hygiene-diff.py` runs `_self_test` on normal compare runs.
  `check_sleep_ratchet` docstring quotes `GATE_PROTO_SLEEP_MAX`.

### W2-Y4 walls and nightly budget

- **client-differential split.** `client-differential-gate.sh` is a local
  wrapper. CI runs `client-differential-flows-gate.sh` (11 `FLOW_*`
  sections, both legs) then `client-differential-cli-gate.sh` (CLI/gss/Z)
  with `KERBER_CLIENT_DIFF_KEEP=1` so the second leg reuses the MIT
  container. Cell tags are unchanged; `hygiene-diff` identifies a cell
  by `(kind, tag)` so a tag may move files. Named Exit caps unchanged.
- **Nightly `--check-budget`.** Compares each job's median of the last
  five completed runs (and the median wall) to `ci-budget.toml`. Single-run
  breaches are info; fail only when the median breaches or ≥ 3 of 5 runs
  breach.

### W2-S7 budget + fixtures

- **`ci-budget.toml`.** `audit` 240→260 and `mit-extra-2` 180→220 from
  close-SHA run 602 (249 / 211). Named Exit jobs unchanged.
- **`ci-policy` `_self_test`.** Injectable `_must_die` fixtures for
  `check_env_read`, `check_peers_unavailable_convention`,
  `check_gate_common_sourced` / cargo-build, and `check_makefile_matches_ci`.

### W2-S7 kpasswd wall

- **kpasswd-gate.** Expected-no-reply UDP probes use a 0.4 s socket
  timeout (was 2 s × 12). MIT kadmind listen waits are `wait_port_in`.
  Checkpoint `timings.tsv` records `gate_wall_s` when the gate prints it.

### W2-S7 walls

- **Job split + leftover-reset.** `harness-2` and `mit-extra-2` run in
  parallel with `harness` / `mit-extra` so the named jobs fit the Exit
  walls (270 / 180). Shared-shell attach reset is one `docker exec`
  (kill, wipe KDB, restore conf, wait pids+ports in-container) instead
  of 13 host-side waits. Local checkpoint runs kadmin KEEP legs in
  order, not the 139 s wrapper. `kpasswd-gate` listen loops are
  `wait_log`.

### W2-S6

- **Enforce.** `ci-budget.toml` is the one source for per-push job
  walls (ratched from measured CI: harness 500, mit-extra 300,
  run_wall 540). `ci-status.py --check-budget` compares a completed
  SHA; nightly `budget.yml` checks the last five `ci.yml` runs.
  `ci-policy` fail-reds empty `gate-wall-exceptions.txt`, proto-sleep
  ≤ 35 s, unit `sleep(` ≤ 8, and the `docs/testing.md` tier contract.
  Every new rule has a `_self_test` fixture.

### W2-S5

- **Unit sleeps and traces.** Timestamp tests wait until the integer
  unix second has passed instead of a fixed 2 s sleep (`KerberosTime`
  has no fractional seconds). Capture stubs return after the asserted
  PDUs so the client UDP retry backoff (0.5+1+2 s) is not on the test
  thread. Spawn-padding sleeps after an already-bound socket are gone.
  `sleep(` in `crates/*/tests` is 5 (was 32); tests > 2 s is 0 (was 11);
  nextest wall 5.0 s for 1404 tests. Gate captures default under
  `$KERBER_SCRATCH`; `tests/traces` keeps the 13 tracked goldens.
  Assertions, test names, and cells are unchanged.

### W2-S4

- **Shared topologies.** `harness` and `mit-extra` boot one stock MIT
  KDC (`scripts/lib/boot-stock-mit.sh`, `KERBER_LIVE=1`) and one
  `--entrypoint sleep` shell (`boot-shell.sh`, `KERBER_SHELL`) per job.
  Group-A gates attach via `stock_mit_kdc` and restore conf+KDB after
  mutating cells (`mit_live_guard`). Group-B gates attach via
  `shell_container` (leftover KDC/kadmind killed). Cell tags unchanged.

### W2-S3

- **kadmin split.** `kadmin-gate.sh` is a local wrapper. CI runs
  `kadmin-rust-gate.sh`, `kadmin-rust-acl-gate.sh`, `kadmin-mit-gate.sh`,
  then `kadmin-both-gate.sh` (`KERBER_KADMIN_KEEP=1` leaves containers
  for the later legs). Rust-vs-MIT diffs that used to share shell vars
  (`HIST_GET`, `GETPRIVS`, `GETPOL`, `GETF`, `GETU`, `GETNM`) persist
  under `$KERBER_SCRATCH` because KEEP does not preserve the parent
  shell. Cell tags are unchanged; `hygiene-diff` identifies a cell by
  `(kind, tag)` so a tag may move files.

### W2-S2

- **Gate library.** Every `scripts/*-gate.sh` sources
  `scripts/lib/gate-common.sh` (`log`/`die`/`unavailable`/`need_bins`/
  `need_image`/wait helpers). Gates no longer run `cargo build`.
  `provenance.sh` memos the ACL hash per image id and reuses
  `KERBER_TREE_SHA` so `git write-tree` and the throwaway ACL container
  run once per job. Straight-line daemon sleeps are
  `wait_port_in`/`wait_udp_in`/`wait_gone_in`/`wait_pid_gone`/`wait_log`;
  remaining sleeps are tagged `# proto:` and sum to 24.7 s.
  `build-bins.sh` builds `ccache-probe`. Gates use `register_cleanup`
  instead of a private EXIT trap. `kadmin-gate.sh` still sources
  `kadmin-glob-cells.sh` (the S2 converter had dropped it).

### W2-S1

- **CI shape.** `[profile.dev] debug = "line-tables-only"` +
  `split-debuginfo = "unpacked"`; `.cargo/config.toml` uses `lld`.
  `cargo doc` moves to a sibling `doc` job. `Swatinem/rust-cache`
  `shared-key: kerber` on every cargo job (audit included). `mit-image`
  also builds `harness/prod` and both tars restore from `actions/cache`
  (no MIT artifact round-trip). `scripts/lib/build-bins.sh` is the
  job-level cargo build; `soak.yml` drops the unused
  `run-harness`/`stop-harness` pair; unread `KERBER_LIVE` env is gone.
  `peers.yml` maps gate exit 2 through `run-peer-step.sh` so missing
  images are not job-red; live kinit/kvno failures stay exit 1.

### W2-S0

- **Measure.** `ci-status.py --durations` prints per-job
  `duration_s=` / `run_wall_s=` from the jobs payload;
  `--workflow` fetches `/actions/workflows/<file>/runs` so peers and
  PR SHAs are visible; `--budget-report` prints medians; `--save`
  records the duration lines. `scripts/checkpoint.sh` writes
  `timings.tsv`. `hygiene-snapshot.sh` / `hygiene-diff.py` inventory
  tests, gate cell tags, diffsend cases, client-differential flows
  and ledger rows (fail on a removal or regrade). `make safety` is
  fmt → clippy → nextest → doc → `ci-policy.py`; CONTRIBUTING drops
  `cargo test --workspace`.

### W1-Z

- **kpasswd / client / kadm5 / bootstrap (Z8).** kpasswd reloads the
  store before mutate (`reload_if_stale`, the `write_store` house
  rule; Z7.2 had inlined the change and skipped it). Client
  `set_request_times` clamps `rtime` up to `till`
  (`get_in_tkt.c:718-722`; `-r` shorter than the 24 h default till).
  Bootstrap stamps `kadmin/admin` and `kadmin/changepw` `kdb5_util@`
  (`kadm5_create.c:100`) and keeps `krbtgt` / K/M `db_creation@`.
  `purgekeys` stamps `current_caller` like `kdb_put_entry` (even when
  no old keys are dropped).
  `addpol`/`modpol` run `validate_allowed_keysalts` (a tab is
  `KADM5_BAD_KEYSALTS`; unknown tokens are stored like MIT
  `krb5_string_to_keysalts`). v3 `ks_tuple` filters MIT
  `ETYPE_WEAK` only (`is_mit_weak`; des3/rc4/camellia mint like MIT
  kadmind). `chrand_etypes_keepold` keeps the current kvno (was 0);
  `kadmin.local addprinc -policy P` binds P before create. Ledger:
  unknown-tuple half of `svr_principal.c:444-447` is
  `stricter-documented` (MIT `KRB5_BAD_ENCTYPE`); `schpw.c:407`.
  Follow-up: `setstr` stamps `current_caller` like `kadm5_set_string`
  → `kdb_put_entry` (`svr_principal.c:2022-2043`); `kadm5_create`
  applies `ADMIN_LIFETIME` 3 h / `CHANGEPW_LIFETIME` 5 min
  (`kadm5_create.c:54-55,207-213`).
- **kadmind / kpasswd / kadmin.local.** `mod_name` and keysalt families
  match MIT's remaining callers. kpasswd stamps `kadmind@REALM`
  (`ovsec_kadmd.c:446`, `schpw.c:407`; before: the ticket client).
  Local `ktadd` rotate and `modprinc -unlock` stamp the session
  princstr (`server_kdb.c:376-377`; before: `default_mod_actor` /
  no stamp). Bootstrap without a kadm5 handle is
  `db_creation@REALM` (`kdb5_create.c:114-133`; before:
  `kadmin/admin@REALM`). `kadm5_chpass_principal_3` /
  `kadm5_randkey_principal_3` apply `apply_keysalt_policy` on the
  v3 `ks_tuple` (`svr_principal.c:1259,1425`); an unknown etype is
  `KADM5_BAD_KEYSALTS`, not RPC `SYSTEM_ERR`. RPC `CREATE_POLICY`
  keeps `allowed_keysalts` (`kadm_rpc_xdr.c:525`; before: the V4
  string was discarded). `kadmin.local addprinc -policy P -e` binds
  P before create. Ledger: extended
  `svr_principal.c:444-447`, new `kdb5_create.c:114-133` (455
  rows, exact 360).
- **kdc / client.** Lifetime defaults match MIT's two consumers of
  `max_renewable_life` and the client `till` fallback. Omitted
  `kdc.conf` `max_renewable_life` is still 0 for kadm5 create
  (`alt_prof.c:577-578`) but the KDC issue cap is 7 days
  (`kdc/main.c:316-319` `KRB5_KDB_MAX_RLIFE`) — `Policy` /
  `KdcConf` now keep both (`realm_max_renewable_life`); a written
  key still sets both. `as_ex` omitted `-l` / `ticket_lifetime` is
  24 h (`get_in_tkt.c:947`; before: 10 h). Synthesised `K/M` takes
  `params.max_life` / `params.max_rlife` (`kdb5_create.c:394-395`;
  before: 10 h / 7 d). Ledger: new `kdc/main.c:312-319` and
  `get_in_tkt.c:936-947` rows, `alt_prof.c` cite `:573-574` (454
  rows, exact 359).
- **kadmind.** `kadm5_create_principal_3` now applies every field the
  request masks, like `svr_principal.c:376-420`: `KADM5_ATTRIBUTES`
  (else `[realms] default_principal_flags`, new in `kdc.conf`, else the
  `requires_preauth` knob for password-keyed creates and MIT's 0 for
  `-randkey` creates — `security.md`), `KADM5_MAX_LIFE` /
  `KADM5_MAX_RLIFE` (else the realm `max_life` / `max_renewable_life`),
  `KADM5_PRINC_EXPIRE_TIME` (else `[realms] default_principal_expiration`,
  new in `kdc.conf`, a `krb5_string_to_timestamp` form —
  `krb5_types::timestamp`), `KADM5_PW_EXPIRATION` (else `now +
  pw_max_life` of the policy), `KADM5_KVNO`, `KADM5_POLICY`. Before, the
  RPC create skipped the whole principal record: `-kvno`, `-expire`,
  `-pwexpire`, `-maxlife`, `-maxrenewlife` and `+flags` on `addprinc` were
  dropped and the entry took the realm defaults. kadm5.acl restrictions
  are imposed on the *request* before the create/modify runs (MIT
  `impose_restrictions`, `auth.c:205-272`): `-policy P` binds P and its
  quality checks now refuse the password, a masked value below a cap
  (an explicit 0 included) is kept, an absent one takes the cap, flags
  compose `|= require` then `&= forbid`. Before, restrictions were
  applied to the stored entry after the write, so an in-mask 0 was
  raised to the cap and a `-policy` restriction skipped `passwd_check`.
  `Restrictions::apply_to` → `Restrictions::impose(&mut AdminEnt)`;
  `insert_new_password` / `insert_new_randkey` → `create_principal_3_in`.
  Ledger: the A4 `:610` row split into the create row and the
  restriction row (430 rows, exact 344).
- **client.** FAST replies are processed whole, like MIT
  `krb5int_fast_process_response` / `krb5int_fast_process_error`. Once
  the `KrbFastFinished` ticket checksum verifies, the AS-REP's and
  TGS-REP's client (`crealm`/`cname`) and padata are the finished
  message's (`fast.c:548-558`) before `verify_as_reply` compares them
  (`get_in_tkt.c:236-241`) — before, the outer, unauthenticated cname
  was compared and, under CANONICALIZE, returned as the canonical name.
  An armored KRB-ERROR whose `e_data` has no PA-FX-FAST or does not
  decrypt is the fatal outer error with no cookie and no method data —
  the client sends no second AS-REQ (`fast.c:445-458`; before, the outer
  cookie was taken and the exchange retried); an envelope without
  FX-ERROR is `KRB5KDC_ERR_PREAUTH_FAILED`. The TGS path reports the
  inner FX-ERROR (`gc_via_tkt.c:190-194`) instead of the outer code and
  e_text. New MITM `scripts/lib/kdc-rewrite-proxy.py` (`as-rep-cname`,
  `strip-fx-fast`) drives four Z1.2 cells at the end of
  `mit-fast-kdc-gate.sh`, MIT `kinit -T` and Rust `krb5-kinit --fast`
  against the MIT KDC. Ledger: new `## B1` section (3 rows, all exact;
  433 rows, exact 347); `ci-policy.py` counts it.
- **acceptor.** AP-REQ time validation is `krb5int_validate_times`
  (`valid_times.c:36-58`): not-yet-valid is judged against `starttime`
  and, when the ticket carries none, against `authtime` — before, a
  ticket with a future `authtime` and no `starttime` was accepted; the
  `INVALID` flag is `KRB5KRB_AP_ERR_TKT_INVALID` (145, `rd_req_dec.c:636`),
  checked after the times — before it was reported as `TKT_NYV` (33).
  Key pinning follows `try_one_princ` (`rd_req_dec.c:374-385`): the
  product GSS acceptor `krb5-gss-accept` passes the keytab kvnos
  (`accept_sec_context_kt` / `spnego_accept_kt`), so a ticket labelled
  kvno N under a fully-specified acceptor name decrypts only with key N
  — before, every key in the keytab was tried and a relabelled ticket
  was accepted; when the keytab holds the principal at other kvnos only,
  the refusal is `KRB5KRB_AP_ERR_BADKEYVER` (44) with `keytab_fetch_error`'s
  "Cannot find key for %s kvno %d in keytab" (`rd_req_dec.c:139-148`),
  not `NOKEY` (45); the kpasswd listener pins `expected_server` to
  `kadmin/changepw@REALM`, so a `host/x` ticket that happens to decrypt
  under the changepw key is refused with `NOT_US` (35), MIT's
  `nomatch_error` at `rd_req_dec.c:382`. `krb5-forge-tgt`
  grows `--authtime`, `--drop-starttime`, `--set-kvno`,
  `--decrypt-keytab`; `krb5-pac-extract` prints the keytab kvno;
  `scripts/gss-mit-server.c` takes an optional acceptor principal.
  Z1.3 cells at the end of `client-differential-gate.sh`: a forged
  future-`authtime`/no-`starttime` service ticket and a kvno-relabelled
  one, both refused by the Rust acceptor and by MIT `gss-server` given
  the fully-specified name. Ledger: `rd_req_dec.c` pinning row rewritten,
  new `valid_times.c` row (434 rows, exact 348).
- **kdc.** The TGS header-ticket time check is `krb5int_validate_times`
  whole as well (`kdc_rd_ap_req` → `krb5_rd_req_decoded_anyflag` →
  `rd_req_dec.c:627` → `valid_times.c:44-51`): a TGT that carries no
  `starttime` is judged by its `authtime` — before, a PAC-less TGT with
  a future `authtime` and no `starttime` was accepted (a PAC-bearing one
  already failed `HEADER_PAC` on the rewritten `authtime`). New
  `diffsend` case `tgt-nyv-no-starttime` (110 cases): 33 `PROCESS_TGS`
  on both KDCs for the same forged bytes.
- **ci.** When the `test` job fails, nextest's junit is turned into one
  `::error` annotation per failed testcase (`scripts/lib/junit-annotate.py`)
  — the job log is private, the annotations are what `ci-status.py`
  reads.
- **kdc.** Every long-term key the KDC picks out of a principal record
  goes through MIT `krb5_dbe_find_enctype` (`kdb_default.c:47-94`), now
  `Principal::find_enctype` behind `Policy::find_enctype` /
  `Policy::first_current_key`: a requested etype outside
  `[libdefaults] permitted_enctypes` is `NO_PERMITTED_KEY` before the
  keys are read; kvno 0 means the highest kvno and no other; keys of a
  non-permitted enctype are skipped, and when they were the only
  matches the miss is `NO_PERMITTED_KEY` rather than `NO_MATCHING_KEY`
  (`KeyLookup`). Callers rewired: the AS and TGS server key
  (`get_first_current_key`, `do_as_req.c:225`, `do_tgs_req.c:1004`), the
  local TGT key, `find_server_key` (`kdc_util.c:426`), the AS client key
  (`select_client_key`, `do_as_req.c:119` — the top kvno only),
  `dbentry_supports_enctype` (`kdc_util.c:1076`), the PAC old-kvno retry
  (`:616`), the FAST cookie and freshness-token kvno lookups
  (`fast_util.c:511`, `kdc_preauth.c:545`), the CAMMAC verifier kvno
  (`cammac.c:155`) and the enc-timestamp key search
  (`kdc_preauth_encts.c:76-78` `krb5_dbe_search_enctype`: the client's
  keys of the timestamp's etype at the *highest kvno* only, so a stale
  keytab after `cpw -randkey -keepold` is 24 like MIT — before, every
  kept kvno still authenticated). Before, `first_current_key` took the
  first stored key of the top kvno whatever `permitted_enctypes` said,
  so a server keyed
  `-e aes128:normal,aes256:normal` under `permitted_enctypes = aes256`
  got aes128 tickets and a server with only non-permitted keys still got
  tickets; `key_for(etype)` also reached down to older kvnos for the AS
  client key. `rc4-session-gate.sh` E restarts both KDCs with
  `permitted_enctypes = aes256-cts-hmac-sha1-96`: the mixed-keyed
  service's ticket is aes256 on both, the aes128-only service is `kvno:
  KDC returned error string: FINDING_SERVER_KEY` on both (and, as the
  control under the earlier config, aes128 on both); F: `kinit -kt` with
  the kvno-2 keytab after `cpw -randkey -keepold` is `kinit: Password
  incorrect while getting initial credentials` on both (24).
  Ledger: two A2 rows (`kdb_default.c:47-94`, `do_as_req.c:104-130`),
  436 rows, exact 350; the `kdc_preauth_encts.c:47-118` row names the
  top-kvno search.
- **kdc.** FAST armor-TGT decrypt is MIT `krb5_ktkdb_get_entry`
  (`keytab.c:152-178`, reached from `armor_ap_request` at
  `fast_util.c:52-54`): `krb5_dbe_find_enctype(entry, xrealm ? etype : -1,
  -1, kvno)` pins the ticket kvno and skips non-permitted enctypes; a
  local TGS whose first permitted key is not similar to the ticket etype
  is `KRB5_KDB_NO_PERMITTED_KEY` → wire 60 `FIND_FAST`. Before,
  `armor_key_from_ap` walked every krbtgt key unfiltered, so an
  aes128-sealed armor TGT still decrypted when `permitted_enctypes`
  was aes256-only and a ticket labelled kvno N sealed under N+1 was
  accepted. The PAC `key_history` fallback (`ad.rs`) and the audit
  `ticket_key` helper now go through `Policy::find_enctype` /
  `etype_permitted` as well. `rc4-session-gate.sh` G: both KDCs under
  `permitted_enctypes = aes256-cts-hmac-sha1-96`, MIT `kinit -T` with an
  aes128-resealed armor TGT is `kinit: Generic error (see e-text) while
  getting initial credentials` on both legs (wire 60; units pin
  `FIND_FAST`); the unforged aes256 TGT still armors. Ledger: new A3 row
  `keytab.c:152-178` (449 rows, exact 353).
- **kdc.** ENC-TS (2) and ENC-CHALLENGE (138) hints follow MIT
  `have_client_keys` (`kdc_preauth.c:434-447`, `kdc_preauth_encts.c:39-43`,
  `kdc_preauth_ec.c:42-46`): advertised only when the client has a
  permitted key of a requested etype at the top kvno. SPAKE (151) uses
  the same condition via `client_keyblock` (`spake_kdc.c:309-314`: omit
  when `select_client_key` left `ENCTYPE_NULL`). Before, ENC-TS was
  offered whenever the request was not FAST-armored, ENC-CHALLENGE
  whenever the client had any stored key, and SPAKE whenever groups were
  configured. A preauth-required AS-REQ with no matching client key is
  now 25 with that hint list (MIT `select_client_key` may return
  `ENCTYPE_NULL` and still emit NEEDED_PREAUTH; `add_etype_info` skips
  PA 19 when there is no key). diffsend `as-needpreauth-hints-unpermitted`
  (111 cases; hint types `[136, 16, 147, 133]`, no 2 / 19 / 151).
- **kadmind.** Unset `kdc.conf` `max_life` is 24 h, like
  `alt_prof.c:574-575` `GET_DELTAT_PARAM(…, 24 * 60 * 60)`. Before,
  `Policy` and `KdcConf` defaulted to 10 h, so a bare `addprinc` showed
  `Maximum ticket life: 0 days 10:00:00` whenever the relation was
  omitted. Ledger: new A4 row `alt_prof.c:574-575` (452 rows, exact 357).
- **kadmind.** RPC `kadm5_create_principal_3` honours the v3 `ks_tuple`
  array like `apply_keysalt_policy` (`svr_principal.c:444-447`): `addprinc
  -e` is the key list, else the bound policy's `allowed_keysalts`, else
  `supported_enctypes`; a tuple outside the policy is `KADM5_BAD_KEYSALTS`.
  Before, `parse_create` skipped the array and the CREATE arm passed
  `&[]`. Ledger: new A4 row `svr_principal.c:444-447` (451 rows, exact 356).
- **kadmind.** `kdb_put_entry` stamps `KRB5_TL_MOD_PRINC` with the
  authenticated kadm5 caller (`server_kdb.c:376-377`
  `krb5_dbe_update_mod_princ_data(…, now, handle->current_caller)`), and
  `getprinc` unparses that name. Before, every create/modify/cpw wrote
  `kadmin/admin@REALM` regardless of the GSS client or `kadmin.local`
  princstr. RPC `addprinc` as `admin/admin` now shows
  `Last modified: … (admin/admin@KERBER.TEST)`; `kadmin.local` without
  `-p` is MIT `kadmin.c:455-536` (`$USER/admin@REALM`, else the euid's
  passwd name) — `root/admin@KERBER.TEST` in the gate containers.
  Ledger: new A4 row `server_kdb.c:376-377` (450 rows, exact 355).
- **kdc.** AS lookup `CANTLOCK_DB` is 29 `SVC_UNAVAILABLE` **and**
  `LOOKING_UP_CLIENT` / `LOOKING_UP_SERVER` (`do_as_req.c:579-590`,
  `:598-606`: the remap precedes the `else if (errcode)` status chain).
  The TGS `db_get_svc_princ` twin (`do_tgs_req.c:533-537`) labels CANTLOCK
  `LOOKING_UP_SERVER` too. Before, a backend 29 passed through with no
  e_text (`z1b_as_lookup_faults` asserted that form). `KRB5KDC_ERR_DISCARD`
  is on `filter_preauth_error`'s pass-through list (`kdc_preauth.c:1125`)
  and `as_reply` suppresses the KRB-ERROR (`do_as_req.c:371-372`). Forge-only
  — no lockable KDB in tree.
- **kadmind.** The AUTH_GSSAPI `GSSAPI_INIT` arg-version switch is MIT's
  (`svc_auth_gssapi.c:326-341`): versions 1 and 2 are answered with
  `init_res.version` 1 and a "Accepted old RPC protocol request" warning,
  3 and 4 are echoed, any other version is `AUTH_BADCRED` before the
  token is looked at, and an undecodable init arg is `AUTH_BADCRED`
  (`:308-315`). Before, every version was echoed and 5 was accepted.
  `scripts/lib/auth-gssapi-init-probe.py` forges the init;
  `kadmin-gate.sh` runs it against both kadminds (1,2 → `accepted
  version=1`; 3,4 echoed; 5,0 → `denied auth_stat=1 AUTH_BADCRED`).
  Ledger `svc_auth_gssapi.c:308-341` → exact (351).
- **client.** `krb5-kinit`'s expired-password flow is `gic_pwd.c:205-240`
  in MIT's order: a typed `KDC_ERR_KEY_EXP` (no more matching the error
  text) → the `kadmin/changepw` AS *first*, with the password just typed
  → only then `Password expired.  You must change it now.` and the
  `Enter new password` / `Enter it again` prompts (three tries; mismatch,
  empty and soft kpasswd results re-prompt with MIT's banners, a hard
  result is `Password change failed`), the change, the final AS. A wrong
  password on an expired principal is now `kinit: Password incorrect
  while getting initial credentials` (`kinit.c:785-790`) and never
  prompts; before, the prompts came first and the failure surfaced only
  after the user had typed a new password twice. The gate's first run
  found the other half of that line: against a principal without
  `+requires_preauth` (MIT's harness default) a wrong password is an
  AS-REP the client cannot verify, and `krb5-kinit` printed `crypto:
  integrity check failed` — a KDC-REP enc-part that fails its HMAC is now
  the typed `krb5_protocol::Error::ReplyIntegrity` (MIT
  `krb5_kdc_rep_decrypt_proc` → `KRB5KRB_AP_ERR_BAD_INTEGRITY`, "Decrypt
  integrity check failed"), which `krb5_client::mit_error_code` reports
  as 31 and `krb5-kinit` as `Password incorrect` like MIT. The prompts
  themselves are `krb5_prompter_posix` (`prompter.c:47-93`): on stdout,
  echo off while stdin is a terminal, a newline after each hidden read
  — before, `Password for` went to stderr and a password typed at a
  terminal echoed. `KinitParams.prompter` (`NewPasswordPrompter`) carries the
  prompter; `KRB5_NEW_PASSWORD` remains the non-interactive source.
  `krb5_protocol::change_password_result` returns the kpasswd result
  code. `kpasswd-gate.sh` Z1b.2 runs MIT `kinit` and `krb5-kinit` side
  by side against the MIT KDC. Ledger B1 `gic_pwd.c:205-240` and
  `prompter.c:47-93` exact (438 rows, exact 353).
- **kdc / kadmind (latent).** Three wire-code hygiene fixes with no
  in-tree trigger. `errcode_to_protocol` (`kdc_util.c:691-697`) now runs
  at the KRB-ERROR encoder itself (`issue.rs encode_krb_error`, MIT
  `do_as_req.c:804` / `do_tgs_req.c:199`), so a `KdcPolicy` plugin that
  returns a library-local code such as 145 is `KRB_ERR_GENERIC` 60 on
  the wire instead of an out-of-range `error-code`; before, only the
  `Error::Protocol` path in `error.rs` clamped. A store-level
  `Error::AclDenied` in kadmind is the stub's own `KADM5_AUTH_*` for the
  procedure (`auth_code_for(proc)`, e.g. `AUTH_ADD` for
  `CREATE_PRINCIPAL`) instead of `AUTH_GET` for every op. The eight
  client-caused PKINIT verify failures (CMS, cert chain, eContentType,
  checksum, ctime, AuthPack, DH group, SPKI) log at `info` /
  `outcome = "denied"` like MIT's `LOG_INFO "preauth (%s) verify
  failure"` (`kdc_preauth.c:1224-1228`), not `error`; the KDC's own
  faults stay `error`. `scripts/kdc-gate.sh:411` had a malformed JSON
  literal. Ledger: a new A2 `kdc_util.c:691-697` row (exact, latent),
  `kdc_preauth.c:1224-1228` and the add/delete ACL denial row → exact
  (439 rows, exact 356, deviation 32). Follow-up: the AS client and
  server lookups are labelled like `do_as_req.c:577-607` — a backend's
  `CANTLOCK_DB` (a 29 `Error::Protocol`) passes through on either
  lookup, any other backend fault is 60 `LOOKING_UP_CLIENT` /
  `LOOKING_UP_SERVER` with the fault text in the log detail, and an
  error that set no status of its own is `UNKNOWN_REASON`
  (`:346-347`); before, every post-decode fault in the AS was labelled
  `LOOKING_UP_CLIENT`. No in-tree store faults a lookup; the unit
  wraps one. Ledger `do_as_req.c:588-590`, `:604-606`,
  `:579-580,598-599` absent → exact (exact 359, absent 5).
- **kdc (fix, CI 550-552 red).** `differential-gate.sh`
  `as-optimistic-encts-wrong-etype` — a PA-ENC-TIMESTAMP declaring des3
  against the harness profile's aes-only `permitted_enctypes` — has
  been 60 on the Rust leg since Z1.4 (`59c363b`), 24 on MIT. The Z1.4
  comment had `KRB5_KDB_NO_PERMITTED_KEY` "not remapped, a KDB code →
  60": `enc_ts_verify` indeed remaps only `NO_MATCHING_KEY`
  (`kdc_preauth_encts.c:113-114`), but every kdcpreauth failure then
  passes `filter_preauth_error` (`kdc_preauth.c:1092-1133`, at `:1206`),
  which turns any code off its pass-through list into 24. That filter
  now exists at the module boundary (`plugins.rs run_as_preauth` →
  `filter_preauth_error`): the list verbatim (31, 37, 25, 14, the RFC
  4556 codes 62-66/70-75/77-81, 100, 91) plus 34 `REPEAT` as the
  documented R2-D1 exception; anything else, and any non-protocol module
  error, is 24; the e_text is always the `PREAUTH_FAILED` status
  `finish_preauth` sets (`do_as_req.c:442`), with the module's own status
  word and the rewritten code in the log detail. `PreauthAction` is
  exported (a `KdcPreauth` implementation outside the crate could not
  name its own return type). Ledger `do_as_req.c:439-442` deviation →
  exact, `kdc_preauth_encts.c:47-118` and `kdc_preauth.c:1092-1133`
  bodies corrected (exact 360, deviation 31). Units
  `z1b_preauth_filter.rs` (red at `7a44ef8`: 60 both),
  `z1b_wire_codes.rs` module cell; `differential-gate.sh` 110 cases green.
- **docs (Z2 truth commit).** Ledger: the W1-Z audit's row list re-graded
  — twelve unit-only or nonexistent-cell rows go `deferred` with the
  oracle that promotes them (`tgs_policy.c` VALIDATE/RENEW/cross-realm
  S4U/referral S4U2Proxy, `do_tgs_req.c:642/694`, `pac.c:640-673`
  cross-KDC `TICKET_CHECKSUM`, `pkinit_srv.c:371-373` certauth, the
  remaining AS order differences of `do_as_req.c:577-762`), the FAST
  armor realm (`fast_util.c:62-67`) is `stricter-documented`,
  `supported_enctypes` unset (four keys vs MIT's two) is a `deviation`,
  `do_tgs_req.c:1103/1121` and `do_as_req.c:251-256` (`return_padata`,
  forge-only) are `exact`, seven drifting
  `check_tgs_constraints_skeleton:N` anchors lose their line numbers,
  eight `deferred` rows re-home the W1-C kadm5 folds
  (`kadm5_get_principal` TL > 255, `krb5_dbe_update_tl_data` order,
  multi-put, `xdr_krb5_int16` TL width, `ulog_replay` skip-vs-fail,
  `kdb5_util load` text, create-existing `KADM5_DUP`, `check_1_6_dummy`);
  header gains the dual-verdict counting rule and the `forge-only`
  annotation rule; `absent` = the two non-goals. Counts 447 = A1 128 +
  A2 91 + A3 78 + A4 145 + B1 5; exact 354 · stricter-documented 15 ·
  deviation 28 · absent 2 · deferred 48. `security.md`: TGS AP-REQ,
  PA-ENC-TIMESTAMP and encrypted-challenge replay rows; FAST TGS envelope
  row rewritten for `29a5ec8`; FAST armor realm STRICTER; `s4u_allowed_*`
  paragraph points at the KLLDAP embed; stale `min_life is W1` /
  `Extraneous flags stay unchecked` gone. `stages.md`: the eight
  Samba/AD/Heimdal gates are `peers.yml` nightly, `stress`/`chaos`/`soak`
  laned, the panic-deny claim names the three crates without it, a W1
  section. `README.md`: no remote `kadmin`, a W1 roadmap row, the
  non-goals list, gate count, KLLDAP 0.7.4/0.7.6. `interop-matrix.md`:
  four missing gate rows (`rd-safe-oracle`, `cross-kdc`, `kdcpolicy`,
  `rc4-session`), Heimdal cell asserts only what the gate asserts, `soak`
  lane, `ad-mit-trust` never invoked, PKINIT/FAST rows carry the
  freshness / anonymous / `edwards25519` cells. `testing.md`: the CI lane
  table (every `ci.yml` job and scheduled workflow → gates), `msrv` job is
  `cargo build --all-targets`. `rfc-mapping.md`: RFC 8070 and RFC 8062
  rows. The two CHANGELOG bullets `500acf4` / `0c153f3` had missed are
  under W1-A′-4. `krb5-kdc` / `krb5-admin` / `krb5-protocol` `//!` headers
  and `Cargo.toml` descriptions name their current modules (kpropd +
  iprop included).
- **tooling (Z3 evidence contract).** `claim-audit.py` freeze rule: a
  closed summary's `Frozen-at: <sha>` header resolves its `script:line`
  cites and unit names at that commit (`git show`, `git grep`; `--at`
  overrides), so a later gate edit cannot re-open it; the six closed W1
  summaries carry it. `index-check.py` and `evidence-check.py` skip any
  directory component starting `scratch` (`scratch-pre/`,
  `scratch-dev/`, …), never a file so named. `differential-gate.sh`
  asserts `as-needchange` (23 `REQUIRED PWCHANGE` both legs) and checks
  `DIFFSEND_RATCHET=110` against the count of distinct emitted ok cases,
  not diffsend's summary literal; `ci-policy.py` reconciles the four
  copies of the case list (`diffsend.rs` names, `DIFFSEND_CASES`, ledger
  header, gate greps — every case grepped) and the ratchet against the
  driver's literal. `red-at-sha.sh` removes its `red-target-<sha>` cargo
  tree on EXIT (`KERBER_KEEP_RED_TARGET=1` keeps it) and stamps
  `red-at-parent=1`; `ci-policy.py --checkpoint` fails on any cargo build
  tree left under `working/logs/`. `ci.yml` `mit-extra` drops the
  `run-harness`/`stop-harness` pair that booted and stopped the stock
  container before its first gate. Every rule has a `_self_test` fixture.
- **docs (Z4 archive + close).** The two remaining class-sweep text-shape
  items are ledgered: kpasswd TCP frames over the 64 KiB cap are logged
  and the connection closed where MIT's shared `net-server.c:1391-1414`
  answers `KRB_ERR_FIELD_TOOLONG` at 1 MiB (`deviation`, forge-only), and
  kpropd's Rust-only error kinds reach the wire as **60** with the Rust
  `Display` text where MIT names the com_err string (`recvauth.c:168`,
  clause on the existing `exact` row). Counts 448 = A1 128 + A2 91 +
  A3 78 + A4 146 + B1 5; exact 354 · stricter-documented 15 · deviation
  29 · absent 2 · deferred 48. W1 is closed: its plans, summaries,
  audits and ledger draft are archived under `working/w1-sweep/`
  (goal.txt `-<mmdd>-<time>` names, README + closeout); the in-tree
  cross-references (`stages.md`, ledger header, `kadm5.rs`,
  `ci-policy.py`) point at the archive.

### W1-C

- **docs.** GSS context remainder graded against `gss-gate.sh` (ledger
  419): mutual AP-REP / acceptor subkey / initial sequence (deviation on
  the acceptor side: `seq-number` 0, no acceptor subkey; initiator side
  exact), `gss_wrap_size_limit` (absent; `wrap_iov_length` carries the
  sizes), IOV `SIGN_ONLY` and DCE wrap/unwrap (exact for AES, both legs
  live), SPNEGO `negotiate_mech` / `mechListMIC` (deviation: single-leg
  acceptor, MIC always sent, no `request-mic`; a krb5-less list is
  refused). No code change; `security.md` GSS paragraph extended. The
  remaining W1-C parity buckets are deferred-with-oracle rows (ledger 428,
  deferred 29): `kproplog`, `kadm5_hook` and `kadm5_auth` plugin
  registries, `server_init.c` local handles, `kdb5_util` verbs, `kprop_util`
  / `kpropd_rpc`, `gss_display_status` texts, cred-store / lucid / IAKERB /
  exported contexts, and the remote `kadmin` client — each names the live
  gate that already exercises MIT's side. W1-C closes.
- **kpropd.** `kpropd.acl` now has MIT `authorized_principal` semantics
  (`kpropd.c:1298-1348`): a line authorizes when it starts with the
  unparsed client principal and ends there or at whitespace; an optional
  remainder must be an enctype name or alias (`krb5_string_to_enctype`,
  case-insensitive, never a number) equal to the ticket's enctype, an
  unknown token skips the line; no wildcards, no leading whitespace, `#`
  is not a comment; the file is re-read per connection and an unopenable
  or unset `KRB5_KPROP_ACL` authorizes nobody. Previously the lines went
  through the kadm5 glob matcher with the enctype token ignored, so
  `*@REALM` authorized every peer and an enctype restriction was not
  enforced. The check now runs after the AP-REP like `kpropd.c:528`; a
  refused peer sees the socket close and MIT kprop reports `Broken pipe
  while sending database block starting at 0` on both kpropds; the Rust
  kpropd logs `Rejected connection from unauthorized principal NAME`.
  Live: `prop-acl-gate.sh` `acl-*` cells, 17 ACL variants identical on
  MIT kpropd and Rust kpropd.
- **kadmin.** MIT `passwd_check` built-in modules on kadm5 create and
  chpass, `kadmin.local addprinc`/`cpw` and kpasswd
  (`server_misc.c:110-135`): `empty` refuses `""` even without a policy
  (`KADM5_PASS_Q_TOOSHORT`, `Empty passwords are not allowed`); under a
  policy `princ` refuses a principal component or the realm and `dict`
  refuses a `[realms] dict_file` word (`KADM5_PASS_Q_DICT`, `Password
  may not match principal name` / `Password is in the password
  dictionary`), all `strcasecmp`. The check runs before the entry is
  written, so `addprinc -pw short -policy p8` creates nothing like
  MIT. `dict_file` is a realm-stanza relation (`alt_prof.c:513`);
  ENOENT continues without a dictionary. Live: `kadmin-local-gate.sh`
  `pwq-*` cells, Rust vs MIT `kadmin.local` identical.
- **kadmin.** kadm5 `create_principal` with a NULL `passwd` — MIT
  `kadmin addprinc -randkey` since 1.8 (`kadmin.c:1297`) — now creates
  with random keys like `krb5_dbe_crk` (`svr_principal.c:463-470`) and
  skips `passwd_check`. Previously the NULL was decoded as `""` and the
  principal was keyed from the empty password. `-nokey` also gets a
  random key (MIT: keyless; ledger deviation).

### W1-B

- **client.** FAST `KrbFastResponse.nonce` must match the request
  (`fast.c:397-402`). A flip is `KRB5_KDCREP_MODIFIED` on AS/TGS
  success; a FAST error with a bad nonce is ignored like MIT
  `krb5int_fast_process_error`. Unit-only (`b1_fast_nonce`); no MIT
  tool emits a flipped FAST nonce.
- **client.** Default `kdc_timesync` skips AS-REP starttime vs the
  local clock (`get_in_tkt.c:260-270`). `kdc_timesync = 0` is
  `KRB5_KDCREP_SKEW`. The +3d `client-differential-gate.sh` cell
  recovers on both CLIs; `kdc_timesync = 0` is Clock skew on both.
- **client.** Default AS `kdc_options` include `RENEWABLE_OK`
  (`init_ctx.c:265-267`); `kinit -r` clears it when `RENEWABLE` is set
  (`get_in_tkt.c:723`).
- **client.** `kinit -R` KDCOptions are `KDC_OPT_RENEW` plus
  `old_creds.ticket_flags & KDC_TKT_COMMON_MASK` (`val_renew.c:62-67`).
  No `CANONICALIZE` (that bit is the `get_creds` referral walk).
- **client.** AS-REP `verify_as_reply` compares the issued server as a
  full principal (name and realm) to both the ticket and the request
  (`get_in_tkt.c:227-239`). `CANONICALIZE` / NT-ENTERPRISE / anonymous
  may rename only when both names are TGS.
- **client.** AS-REP `verify_as_reply` compares request `till`/`rtime`/
  `from` to the issued times (`get_in_tkt.c:243-255`). `endtime` after
  `till`, `renew_till` after `rtime` (RENEWABLE) or after `till`
  (RENEWABLE_OK without RENEWABLE), or POSTDATED `from` ≠ starttime,
  is `KRB5_KDCREP_MODIFIED`. Unit-only for the EncKdcRepPart fixture;
  the live MIT KDC AS cells are the production oracle.
- **client.** `kinit -k` uses only the highest keytab kvno for the
  client principal (name and realm) and sorts those etypes to the
  front of the AS-REQ (`gic_keytab.c:84-174`). A stale lower kvno
  listed first is ignored.
- **client.** Password `KEY_EXP` (23) runs the `kadmin/changepw`
  ticket + kpasswd + retry path (`gic_pwd.c:211-336`). kpasswd
  result codes outside 0–7, or SUCCESS from a KRB-ERROR, are
  `KRB5KRB_AP_ERR_MODIFIED` (`chpw.c:217-231`).
- **client.** `krb5_verify_init_creds` (`vfy_increds.c:259-321`)
  verifies the TGT with mk_req + rd_req against a keytab. Missing /
  empty / non-`host/` keytabs succeed unless `-n` or
  `verify_ap_req_nofail`; an outdated host key fails. Live
  `t_vfy_increds` vs `krb5-vfy-increds` in
  `client-differential-gate.sh`.
- **client.** `chpw.c` result-code texts, AD 30-byte policy messages,
  and `krb5_set_password` (version `0xff80` + `ChangePasswdData`).
  A framed reply with a bad length is `MODIFIED`; a bad version is
  `BAD_PVNO`. Live MIT `kpasswd` `Password change rejected` and
  `krb5_set_password` `Access denied` vs `krb5-kpasswd`.
- **client.** `kinit -C` and `[libdefaults] canonicalize` set
  `KDC_OPT_CANONICALIZE` (`gic_opt.c:76-83`, `get_in_tkt.c:921-930`).
  `kinit -s` sets `from` plus `ALLOW_POSTDATE`/`POSTDATED`
  (`get_in_tkt.c:711-714,932-934`).
- **client.** Default AS/TGS etype list is AES 18/17/20/19
  (`preferred()`). MIT `init_ctx.c:59-66` also offers 16/23/25/26;
  those stay behind `is_weak` unless named in the profile
  (stricter-documented).
- **client.** FAST AS outer `till` is the epoch (`19700101`) like MIT
  `krb5int_fast_prep_req_body` (`fast.c:157-161`,
  `get_in_tkt.c:836-838`) taken before `set_request_times`. The inner
  FAST-REQ body keeps the live times; `req_checksum` is over the
  snapshotted outer body.
- **client.** PKINIT / anonymous second AS-REQ padata is
  `[133, 16, 150, 149]` (`preauth2.c:992-1019` cookie then module;
  `get_in_tkt.c:1365-1372` empty 150/149).
- **client.** SPAKE `--spake` first-shots `[150, 149]` like MIT
  default kinit (`get_in_tkt.c:807-813`); the first KRB-ERROR is
  PREAUTH_REQUIRED 25 with the full hint list. PA-SPAKE support
  follows that hint, not an optimistic first-shot 151.
- **client.** After PREAUTH_REQUIRED, `sort_krb5_padata_sequence`
  plus the first runnable `k5_preauth` module (`get_in_tkt.c:400-471`,
  `preauth2.c:649-713`). Default preferred is `17, 16, 15, 14`; when
  the KDC advertises 151 before 2, password kinit sends SPAKE support
  then the response (three AS-REQs). Plain extra MIT UDP/TCP copies
  stay with B3 `sendto_kdc.c`.
- **client.** `kvno -U` TGS-REQ padata is `[1, 136, 130, 129]`
  (`s4u_creds.c:517-567` PA-S4U-X509-USER then PA-FOR-USER;
  `fast.c:227-250` outer FAST duplicates the inner S4U padata).
  130 is checksummed with the TGS subkey (ku 26) after nonce and
  subkey exist. A TGS-REP that carries 130 is checked
  (`verify_s4u2self_reply`, `s4u_creds.c:273-397`): enc-only 130,
  nonce/user/checksum mismatch is `KRB5_KDCREP_MODIFIED`; an unkeyed
  reply checksum on a modern etype is `INAPP_CKSUM`.
- **client.** `kvno -U -P` is S4U2Proxy (`s4u_creds.c:1013-1031`):
  S4U2Self for the ccache principal, then a TGS with
  `CNAME_IN_ADDL_TKT`, the evidence ticket, and PA-PAC-OPTIONS 167.
  FAST outer padata is `[1, 136, 167]`. `-P` without `-U` is refused.
- **client.** `kinit -v` KDCOptions are `KDC_OPT_VALIDATE` plus
  `old_creds.ticket_flags & KDC_TKT_COMMON_MASK` (`val_renew.c:62-67`,
  `krb5_get_credentials_validate`). No `CANONICALIZE`. Live both
  CLIs vs a postdated TGT send `forwardable`+`allow_postdate`+
  `validate` (KDC `NOT_YET_VALID` 33 before starttime).
- **kdc.** Hierarchical `find_alternate_tgs` walks MIT
  `rtree_hier_realms` (`walk_rtree.c`) instead of transit
  intermediates, so `krbtgt/X.SUB.KERBER.TEST` issues
  `krbtgt/SUB.KERBER.TEST` without `[capaths]`. `common == 0` walks
  every suffix. Backend server-lookup errors are 7
  `LOOKING_UP_SERVER` (29 passthrough). Host referrals skip numeric
  addresses (`k5_is_numeric_address`). `is_referral` uses
  `krb5_principal_compare` (ignores name-type). diffsend 109.
- **acceptor.** AP-REQ key selection uses the ticket kvno and etype
  (`rd_req_dec.c:325-347` `try_one_princ` → `krb5_kt_get_entry`).
  Ticket kvno 0 (or a key labeled 0) means any. A labeled mismatch is
  `NOKEY`; a key at the claimed kvno that fails decrypt is integrity.
  kpasswd and `verify_init_creds` pass keytab kvnos. GSS accept still
  iterates similar-enctype keys (`decrypt_try_server`).
- **acceptor.** AP-REQ re-checks the ticket transited list when
  `TRANSITED_POLICY_CHECKED` is unset (`rd_req_dec.c:590-610`,
  `chk_trans.c:309-355`). A hop not on `krb5_walk_realm_tree` is
  `ILL_CR_TKT` 43. The T flag, an empty field, or anonymous crealm
  skips the check like MIT. Live MIT KDC tickets carry T, so GSS
  accept is unchanged.
- **acceptor.** AP-REQ server matching uses `krb5_sname_match`
  (`sname_match.c:30-57`). A two-component `NT-SRV-HST` expected name
  checks the service and hostname; an empty hostname or
  `[libdefaults] ignore_acceptor_hostname` skips the host component.
  Other name-types compare name-string + realm. Live GSS / `vfy_increds`
  still pass a concrete host (ignore off).
- **client.** After the first referral-style TGS error, a specified
  server realm retries without `CANONICALIZE` (`get_creds.c:503-516`
  `try_fallback`). A later hop keeps the error. Host-realm DNS rewrite
  (`:517-542`) stays deferred (B3).
- **client.** `krb5_fwd_tgt_creds` KDCOptions are
  `ticket_flags & KDC_TKT_COMMON_MASK` plus `FORWARDED`
  (`fwd_tgt.c:147-153`). `forwardable == false` clears `FORWARDABLE`.
  Remote `k5_os_hostaddr` when the TGT has addresses stays deferred
  (B3).
- **client / acceptor.** Remaining B2 files are graded: AP-REQ
  clockskew and replay, referral hop cap and dest-TGT walk,
  `krb5_principal_compare`, AP-REQ/AP-REP/KRB-CRED builders. On-disk
  rcache, ccache retrieve, cross-realm S4U2Proxy walk, and a standalone
  `krb5_auth_context` stay deferred (B3).
- **kdc.** Realm-stanza `restrict_anonymous_to_tgt`,
  `pkinit_require_freshness`, `disable_pac`, and `reject_bad_transit`
  win over a later `[kdcdefaults]` (`main.c:286-345`). Host-based
  referral lists still combine both sections.
- **kdc.** TGS audit seeds `AUTHN_REQ_CL` like MIT
  `do_tgs_req.c:1181-1184`. Unknown-server failures report stage
  `SRVC_PRINC`. S4U/U2U records use `S4U2SELF` / `S4U2PROXY` / `U2U`.
  `enctype_name` 6/24 are `DEPRECATED:`. TGS-fail logs
  `UNKNOWN_REASON` and the header `authtime`. JSON keys remain a
  documented subset of `j_dict.h`.
- **docs.** W1-B B3 grade pass: 23 ledger rows for `lib/krb5/ccache`
  (FILE v4 layout, `ccache_type`, resolve, create/destroy, tombstone,
  DIR, `cache_match`, ccselect, KCM), `keytab/kt_file.c`,
  `os/{sendto_kdc,locate_kdc,hostrealm*,sn2princ,ccdefname,init_os_ctx,
  changepw}.c` and `clients/{kinit,klist,kvno,kdestroy,kswitch,kpasswd}`
  graded against `ccache-gate` / `kcm-gate` / `ktutil-gate` /
  `knobs-gate` / `client-gate` / `client-differential-gate`. Two
  stricter-documented rows (`kdestroy` `O_NOFOLLOW`; DIR not created
  on a read) join `docs/security.md`. Host-realm DNS, `dfl` rcache,
  `sendto_kdc` pacing, `sname_to_principal` canonicalization, kpasswd
  server locate, ccselect and `com_err` CLI texts stay deferred with
  their live oracles named.
- **client.** TGS-REP `krb5int_process_tgs_reply` checks the reply
  client against the TGT client (`gc_via_tkt.c:257-270`), refuses a
  self-inconsistent ticket/enc server (`:108-110`), and rejects an
  `endtime` after request `till` (`:278-297`; skipped on RENEW and
  VALIDATE like MIT `get_valrenewed_creds` zeroed times). S4U2Self whose client
  equals the requested server is `PADATA_TYPE_NOSUPP`; a final
  S4U2Proxy hop skips the TGT-client compare. A foreign TGT without
  `ok-as-delegate` strips that flag on the reply (`:247-252`).
  Starttime skew (`:302-307`) stays deferred (no `krb5_context`
  `time_offset`).
- **test.** `scripts/client-differential-gate.sh` drives MIT and Rust
  `kinit`/`kvno` against the live MIT 1.22.2 KDC through
  `scripts/lib/kdc-req-proxy.py` (request-shape JSONL: padata,
  KDCOptions, etypes, addresses, rtime/till class, nonce, sname,
  KRB-ERROR e_data). Eleven seeded flows (CORE match; every flow
  `SHAPE_MATCH kdc_options`; remaining SHAPE diffs are the W1-B ranked
  list); MIT `klist -C -f -e -a` over both FILE caches;
  seven CLI error paths non-zero on both CLIs; +3d `skew-preload.c`
  records default `kdc_timesync` recovery on both CLIs and Clock skew
  when `kdc_timesync = 0`; `gss-mit-client` → Rust acceptor majors;
  `t_vfy_increds` vs `krb5-vfy-increds`; kpasswd result texts and
  setpw; `kinit -C` / `-s` / `[libdefaults] canonicalize`; default
  etype list (MIT 18/17/20/19/16/23/25/26, Rust AES-only); FAST AS
  outer `till=zero`; PKINIT / anon second AS `[133, 16, 150, 149]`;
  SPAKE first-shot `[150, 149]` / error 25; password preauth cascade
  `[[150, 149], [133, 151, 150, 149], [133, 151, 150, 149]]`;
  `kvno -U` TGS padata `[1, 136, 130, 129]`; `kvno -U -P` S4U2Proxy
  `[1, 136, 167]`; `kinit -v` VALIDATE options
  `forwardable`+`allow_postdate`+`validate`; TGS-REP client vs TGT
  client (`gc_via_tkt.c`); acceptor `sname_match`; TGS
  `try_fallback` specified-realm retry; `fwd_tgt` FORWARDED options;
  diffsend
  `tgs-alternate-tgs-hierarchical`. Fail-red
  on `mit-extra`.

### W1-A′-4

- **kdc.** Anonymous PKINIT + `check_anon` / `restrict_anonymous_to_tgt`.
  `REQUEST_ANONYMOUS` from a named client is 13 before preauth; a
  `WELLKNOWN/ANONYMOUS` client is rewritten to `@WELLKNOWN:ANONYMOUS`
  and forced through preauth. Unsigned AuthPack from a named client is
  24. Issued anonymous tickets carry `PA-PKINIT-KX` (ku 44), no PAC,
  and `crealm` `WELLKNOWN:ANONYMOUS`. `restrict_anon` + a non-local-TGS
  server is 12 `ANONYMOUS NOT ALLOWED` on AS and TGS.
- **kdc.** FAST `hide-client-names` now anonymizes the outer KRB-ERROR
  and TGS-REP as well as the AS-REP; inner FX-ERROR / `fast_finished`
  keep the real client.
- **client.** `kinit -n` sends unsigned PKINIT and verifies
  `PA-PKINIT-KX`.
- **kdc / client.** RFC 8070 PKINIT freshness (`500acf4`): the KDC mints
  `PA-AS-FRESHNESS` (padata 150, ku 514 over the krbtgt key,
  `FRESHNESS_LIFETIME` 600 s like `kdc_preauth.c:91`) into the
  preauth-required METHOD-DATA when the request advertised 150
  (`kdc_preauth.c:826-871`) and checks the echoed token inside the
  AuthPack; with
  `pkinit_require_freshness = true` a stale or missing token is 24 with
  the log `no freshness token, rejecting`, a good one logs `freshness
  token received`. The Rust `kinit` echoes the token. Gates:
  `pkinit-gate.sh` `require_freshness: MIT kinit -X vs rust KDC`,
  `rust-kinit-pkinit-gate.sh` `require_freshness: rust kinit vs MIT KDC`;
  diffsend `pkinit-stale-freshness`.
- **kdc / client.** SPAKE `verify_support` (`0c153f3`): a PA-SPAKE support
  message that offers no group in `spake_preauth_groups` is 24 like MIT
  (the MIT client's default `edwards25519` against a P-256-only KDC is 24
  on both legs — pinning the MIT client to P-256 had hidden that); the
  Rust client armors **every** TGS-REQ with the TGT like MIT `send_tgs`
  (random subkey, `krb_fx_cf2` `subkeyarmor`/`ticketarmor`) and requires
  the finished message inside a present envelope. Gates:
  `mit-fast-kdc-gate.sh` `default-client edwards25519 vs P-256 KDC is 24
  both`, `rust-kinit-fast-gate.sh` strengthen-key cells.
- **test.** Diffsend 102 → 105 (`as-anonymous-unsigned-authpack-named-client`,
  `as-fast-hide-error-client`, `tgs-fast-hide-client`). `pkinit-gate.sh` / `rust-kinit-pkinit-gate.sh`
  `kinit -n` + `restrict_anon` `kvno`. Unit-test scratch stays off host
  `/tmp` (`isolate_scratch_dir` workspace fallback).
- **docs.** Hide-client scope; ledger 295/361/362/469/499; F3 cite slack
  on the A′-3 summary/plan.
- **kdc.** AS last-req is always `[{type 0, epoch}]`; `get_key_exp` is
  MIT's min of principal/password expiry and 0 is omitted. TGS omits
  `key_expiration`. `TestPolicy` (`KRB5_KDCPOLICY=test`) matches MIT
  `kdcpolicy_test.so`: `fail` is 12, `ONE_HOUR`/`SEVEN_HOURS` rewrite
  life (AS divisor 1, TGS 2), any other indicator is 12.
  `supported_enctypes` orders `kdb create` / `addprinc` without `-e`;
  empty profile keeps `randkey_etypes()` 18,17,20,19. RENEW+POSTDATED
  starts at `from` (`do_tgs_req.c:826-827`).
- **test.** Diffsend 107 → 108 (`tgs-renew-postdated-from`).
  `expire-gate.sh` MIT kinit password-expiry warning both legs;
  `kdb-dump-gate.sh` `Key:` order; `kdcpolicy-gate.sh` vs
  `kdcpolicy_test.so`. Image copies the test policy module.
- **admin.** kpasswd `rd_req` tries every current `kadmin/changepw`
  key. Ticket etype follows `first_current_key` (profile order);
  `best_key` is sha1-first and is not enough after
  `supported_enctypes` 20,19,18,17.
- **kdc.** `krb5-forge-tgt --key-hex` wraps dump-keytab bytes as
  the ticket enc etype, not always 18.
- **test.** `sha2-gate.sh` expects ticket etype 20 (`first_current_key`
  after `supported_enctypes`), not sha1-first 18.
- **kdc.** `kdc.issue` carries the MIT ISSUE tuple (`kind`,
  `req_etypes`, `from`, `status`, `authtime`, `etypes`, `client`,
  `server`; S4U `s4u` / `s4u_client`). Unexpected transit checks
  log at error (`kdc_log.c:201-206`). `KdcAudit` (`kdc_audit.c`)
  hashes `tkt_out_id` as SHA-256 of the ticket ciphertext (64 hex
  uppercase) and mints a 31-character `req_id`. `KRB5_KDC_AUDIT=test`
  writes MIT `j_dict.h` field names. Image copies `k5audit_test.so`.
- **test.** `kdc-gate.sh` greps the ISSUE tuple on both legs and
  compares audit field names / `tkt_out_id` format.

### W1-A′-3

- **kdc.** `get_ticket_flags` + `kdc_get_ticket_renewtime` (`kdc_util.c:812-858,1712-1757`).
  TGS `FORWARDED`/`PROXY`/`MAY_POSTDATE`/`POSTDATED`+`INVALID` copy MIT
  `OPTS2FLAGS`/`COPY_TKT_FLAGS`. `check_tgs_opts` refuses postdate
  without header `MAY_POSTDATE` (`TGT NOT POSTDATABLE` 13). deny_opts
  `RENEWABLE`+`DISALLOW_RENEWABLE` is `NON-RENEWABLE TICKET` 12;
  `NON-POSTDATABLE` keys only on `ALLOW_POSTDATE`. GSS initiator
  `tgs_forward` (`krb5_fwd_tgt_creds`); diffsend 81 → 85.
- **test.** `klist -f` flag parsers split on `Flags: ` so a
  `renew until` clause is not taken as `$2` (`until` hid `O` on
  CI 465 `flags-gate`; a whole-line `T` match was `until`).
- **kdc.** TGS `REQUIRES_PRE_AUTH` without header `PRE_AUTHENT` is
  `NO PREAUTH` 60 (`tgs_policy.c:180-184`). `kdc_get_ticket_endtime`
  mins client/server/realm max_life against header end/`till`.
  `starttime == authtime` is omitted. diffsend 85 → 88.
- **kdc.** `handle_authdata` (`kdc_authdata.c:576-628`): TGS body AD
  decrypts session ku 4 then subkey ku 5; `AD-MANDATORY-FOR-KDC` is
  POLICY 12 `HANDLE_AUTHDATA`. `KdcAuthdata` registry (empty in
  production). `copy_tgt` / `is_kdc_issued_authdatum` strip
  SIGNTICKET/KDC-ISSUED/WIN2K-PAC/CAMMAC/AUTH-INDICATOR. diffsend
  88 → 91.
- **kdc.** Auth indicators: `require_auth` any-match is POLICY 12
  `HIGHER_AUTHENTICATION_REQUIRED` (`kdc_util.c:862-894`). Extract
  verified CAMMAC (96) from the TGS subject ticket (`get_auth_indicators`);
  skip extract and the check for S4U2Self. Undecodable CAMMAC is
  `GENERIC` `GET_AUTH_INDICATORS`. `add_auth_indicators` wraps AD-97
  in CAMMAC ku 64 inside IF-RELEVANT before the PAC checksum.
  `[realms]` `encrypted_challenge_indicator` / `pkinit_indicator` /
  `spake_preauth_indicator`. diffsend 91 → 92.
- **kdc.** `get_preauth_hint_list` order is empty 136, etype-info,
  modules, cookie (`kdc_preauth.c:974-1014`). EncTs is omitted under
  FAST; EncChallenge 138 is listed only with armor. EC outside FAST is
  24. `return_enc_padata` echoes PAC-OPTIONS RBCD and FAST nego.
  TGS FAST always emits `strengthen_key` and CF2s the reply key.
  SPAKE 91 e_data is `[151, 19, 133]` (`maybe_add_etype_info2` then
  `prepare_error_as` cookie last). FAST-inner 151 makes MIT kinit
  send SPAKE support (91) when the client shares P-256.
  diffsend 92 → 94.
- **kdc.** `max_renewable_life` 0 is a cap of 0 (`kdc_util.c:1744-1747`).
  Omitted kdc.conf `max_renewable_life` is 0. kadm5 modify honours
  `KADM5_MAX_RLIFE`. AS `PRE_AUTHENT` is set only after EncTs/EC/SPAKE/PKINIT
  verifies. `check_tgs_opts` emits `TICKET NOT RENEWABLE` 13 before
  `TICKET NOT VALID` 33. Client `tgs_renew` ORs `KDC_TKT_COMMON_MASK`.
  diffsend 94 → 95.
- **kdc.** TGS times/flags use MIT's `t->client` (`do_tgs_req.c:694-778`):
  S4U2Self is the impersonated user; a normal TGS looks up the subject
  only when the server lacks `NO_AUTH_DATA_REQUIRED` and the realm
  matches. `kdc_get_ticket_endtime` uses signed `ts_delta` so a till
  in the past is an expired endtime. `check_tgs_svc_time` runs in
  `svc_pol_fns` before `check_indicators`. POSTDATED `starttime = from`
  unconditionally. diffsend 95 → 98.
- **kdc.** PAC is prepended at index 0 (`pac_sign.c:389-419`). Greet
  wraps KDC-ISSUED usage 19 (`greet_auth.c:62-72`) when
  `KERBER_KDC_GREET=1`. Body AD still tries session ku 4 then
  client_key ku 5. diffsend 98 → 101.
- **kdc.** `cammac_check_kdcver` refuses an unkeyed KDC-verifier
  checksum (`verify_checksum_keyed`; MIT `cammac.c:168` has no gate).
  `require_auth` live cells are exact `KDC policy rejects request` plus
  the KDC log word. PKINIT / Encrypted Challenge / SPAKE indicator
  pairs issue when the TGT carries the matching indicator.
- **kdc.** Stock PKINIT does not set `HW_AUTHENT` (`pkinit_srv.c:360-366,602`;
  no certauth hook). A `+requires_hwauth` service is `NO HW PREAUTH` 60.
  TGS RENEW uses signed header life (`do_tgs_req.c:836-838`), so
  `endtime < starttime` renews expired. diffsend 101 → 102.
- **client.** TGS FAST reply without PA-FX-FAST is accepted like MIT
  `decode_kdc.c:66-67` (`KRB5_ERR_FAST_REQUIRED` ignored). A present
  FAST envelope still requires finished + strengthen. Empty-groups
  stray PA-SPAKE is skipped (`kdc_preauth.c:1306-1307`), not 24.
- **test.** Unit-test `isolate_test_krb5` writes under
  `CARGO_TARGET_TMPDIR` / `CARGO_TARGET_DIR` / `KERBER_SCRATCH` and
  removes the file on drop. `s4u_user_life` fails closed on an empty
  klist line; `date -d` renew deltas are unguarded.

### W1-A′-2

- **docs.** R25 close-out: ledger `:269`/`:272` unit-only with live
  deferred; `:270` referral S4U2Proxy `deferred` (A′-4 item 18);
  `:199` rust-site `issue_tgs_body:942-945` `NULL_SERVER`; `:295`
  TGS half disclosed. `docs/security.md` names the missing
  dump/kadm5/iprop S4U carrier (W1-C).
- **test.** `host_tmp_write_lines` matches the heredoc delimiter on
  the unquoted host-side text (not `<<<` or a quoted/`#` `<<WORD`)
  and scans quoted redirect targets. `provenance.sh` `mktemp`s under
  `KERBER_SCRATCH`/`TMPDIR`. Fixture `ci-status --save` stays off
  stdout.
- **docs.** Ledger `tgs_policy.c:100` rust-site is
  `check_tgs_constraints_skeleton:1609-1610` (`TICKET NOT VALID` 33).
  `tgs_policy.c:352` FOREIGN_PAC is `deferred` until a MIT incoming-trust
  cell (unit `a2_r17_foreign_pac_client` only).
- **test.** `a2_r18_parent` `cross_store()` grants the impersonator as
  `name@FOREIGN` so the leftover inject stays green after realm-aware
  RBCD (R22).
- **test.** `host_tmp_write_lines` ends a quoted heredoc on `EOF'` /
  `EOF"`, walks `$(…)` and `$'…'`, and strips only `docker exec`/`run`
  argv so a host redirect on that line is still scanned. Fail-red
  fixtures cover a multi-line quote, a quoted heredoc, a docker host
  redirect, and the four gate probes. Ledger `:218` / `:269` rust-sites
  name the functions that hold the backticked codes.
- **kdc.** PAC `UnsupportedChecksum` on a krbtgt header or krbtgt
  second ticket wires 60 `GENERIC` (`KRB5_BAD_ENCTYPE` →
  `errcode_to_protocol`). The privsvr-retry sentinel stays internal
  14. diffsend 78 → 81: `tgs-pac-server-cksum-wrong-enctype`,
  `u2u-2nd-ticket-pac-wrong-enctype`, `u2u-success-offered`;
  `u2u-success` uses a distinct stkt session.
- **kdc.** RBCD `s4u_allowed_from` is `name@REALM` (bare name = local
  realm at insert) and `allowed_to_delegate_from` compares the
  impersonator name and realm (`tgs_policy.c:753-756`,
  `kdb_test.c:761-774`). `create_host` seeds no delegation lists.
- **test.** MIT test-KDB `kvno -U user -P host/rbcd` proves same-realm
  RBCD (`allowed_to_delegate_from`) on both legs; rust `--test-realm`
  grows `KRB5_TEST_EXTRA_HOST` / `KRB5_TEST_S4U_FROM`.
- **test.** R18's rust-kdc restart kill is one line so
  `check_no_host_tmp_writes` does not treat the later container
  `>/tmp/kdc-r18.log` as a host write (CI 451–454 `ledger-mit` /
  `test`). `evidence-check.py` skips `scratch/` only relative to the
  tree being checked.
- **test.** diffsend 74 → 78: U2U success decrypts with the second-ticket
  session key (kvno absent, ticket etype = stkt session, reply session
  etype from `select_session_keytype` when the client omitted it);
  `u2u-2nd-ticket-kvno-miss` (60), `u2u-2nd-ticket-disallow-svr` (7),
  `s4u2self-cert-only` (60 `LOOKING_UP_S4U2SELF_PRINCIPAL` on MIT db2),
  and FORWARDED TGT address copy.
- **test.** A′-2 items 8–10 parent-red injects cover no-2nd-tkt, U2U combo,
  U2U kvno omission, and RENEW address copy. Copy-and-resign is an AD-like
  superset (MIT db2 copies CLIENT_INFO + DELEGATION_INFO only). Product
  acceptors pass `ApVerifyParams.addresses: None`.
- **kdc.** TGS constraint slots run before service policy
  (`tgs_policy.c:668-746`, `do_tgs_req.c:872-882`): lineage before U2U,
  `check_normal_tgs_pac` before deny_all, `DUP_SKEY` in deny_opts before
  `TGT BASED`. Header times run after BADMATCH/BADADDR
  (`rd_req_dec.c:532-539,627`). Privsvr retry accepts `ETYPE_NOSUPP` as
  well as `MODIFIED` (`kdc_util.c:610`).
- **kdc.** S4U2Proxy issuance is proven against MIT's `plugins/kdb/test`
  KDB (`delegation = { … }` in the harness image). First hop writes
  `PAC_DELEGATION_INFO` (`kdc_authdata.c:382-439`). Cross-realm gather
  takes the PAC client with realm before `check_tgs_s4u2proxy`
  (`do_tgs_req.c:737-745`, `RBCD_PAC_PRINC`); ticket identity and
  transited use that realm; final S4U CLIENT_INFO omits the realm.
  Evidence vs header client compare includes realm
  (`tgs_policy.c:501-502`). Oracle is MIT test-KDB, not Samba.
- **kdc.** `create_host` / `addprinc -randkey` no longer seeds
  `allowed_to_delegate` to self (MIT db2 default). S4U2Self keeps F
  unless a target list is set and `OK_TO_AUTH_AS_DELEGATE` is clear.
  `is_referral` is only entry substitution (`do_tgs_req.c:680-682`);
  an explicit `krbtgt/OTHER` S4U2Self is 36. Reply PA-S4U-X509-USER
  copies nonce/user/options only (`kdc_util.c:1467-1472`).
- **kdc.** Incoming cross-realm trust is its own principal
  `krbtgt/<local>@<foreign>` (`kdc_util.c:377-379`). Header and second-ticket
  lookup use `ticket->server` with realm; there is no fallback to
  `krbtgt/<ticket.realm>@local`. `check_tgs_nontgt` compares name and realm
  (`tgs_policy.c:636`, 26). `KRB5_TEST_INTERREALM_KEY_ACCEPT` replaces the
  incoming keys. The peers lane runs every gate with `if: always()`.
  A copied Samba TGT PAC may carry `PAC_WAS_GIVEN_IMPLICITLY`; the L1
  decoder accepts that flag as well as `PAC_WAS_REQUESTED`.
- **kdc.** TGS gather follows `gather_tgs_req_info`: missing PA-TGS-REQ
  is 16 `PROCESS_TGS`; header times run inside PROCESS_TGS; local TGT
  then HEADER_PAC then `search_sprinc`. `is_crossrealm` is the header
  ticket server realm versus the canonical server realm. Non-TGS headers
  decrypt via `kdc_get_server_key` (DISALLOW_SVR → 7 `PROCESS_TGS`);
  `is_local_tgs_principal` compares the instance to the ticket server
  realm; a foreign ticket looks up `ticket.server` only (incoming
  `krbtgt/<local>@<foreign>`). `check_tgs_constraints` slots run
  opts/times then `check_tgs_nontgt` / `check_tgs_tgt` by
  `NON_TGT_OPTION` (RENEW of a service ticket issues; PROXY of a TGT is
  13 `CAN'T PROXY TGT`; name mismatch is 26). `get_verified_pac` checks
  the server signature only on a TGS header and retries privsvr with
  `pac_privsvr_enctype` / PRF+ `pac_privsvr` on a service header.
  `handle_pac` preconditions: `disable_pac`, anonymous,
  `NO_AUTH_DATA_REQUIRED`, AS PA-PAC-REQUEST (undecodable → include),
  TGS includes a PAC only when the subject had one. A regular TGS
  copies the subject's non-checksum PAC buffers and re-signs (MIT
  default `issue_pac` is NOTSUPP — no invented LOGON/UPN/ATTRIBUTES).
  Privsvr signing uses `get_first_current_key` of the local TGT, then
  `pac_privsvr_enctype` / PRF+ `pac_privsvr`. Transited appends only
  when `is_crossrealm` and the header server realm is not the client
  realm. A regular TGS preserves the subject ticket `authtime`
  (`do_tgs_req.c:826-827`) so copied CLIENT_INFO still matches at the
  next hop. A cross-TGS header whose PAC is not the ticket client is
  fail-closed 13 until item 8 (`verify_deleg_pac`).
- **kdc.** S4U2Self is `kdc_process_s4u2self_req` + `check_tgs_s4u2self` +
  `s4u2self_forwardable` + `kdc_make_s4u2self_rep` (`kdc_util.c:1232-1644`,
  `tgs_policy.c:261-358`). PA-S4U-X509-USER (130) wins over PA-FOR-USER;
  checksum ku 26 under the authenticator subkey else the TGT session;
  nonce mismatch and a bad keyed checksum are 41; empty user+cert is 6;
  a missing header PAC is 20; local PAC must be the impersonator, foreign
  PAC the subject with realm; cert-only local is 60
  `LOOKING_UP_S4U2SELF_PRINCIPAL` (db2 has no x509 hook); the impersonated
  client's `pw_expiration` / `REQUIRES_PWCHANGE` are cleared. FORWARDABLE
  stays set unless the service has `allowed_to_delegate` targets and
  lacks `OK_TO_AUTH_AS_DELEGATE` (MIT db2 has no hook, so F stays).
  Reply 130 only when the request carried 130.
- **kdc.** S4U2Proxy is `check_tgs_s4u2proxy` + `check_s4u2proxy_policy` +
  `verify_deleg_pac` (`tgs_policy.c:365-572`). No second ticket is 60
  `UNKNOWN_REASON` (`kau_make_tkt_id` on a NULL evidence ticket);
  `check_tgs_s4u2proxy` would say 13 `NO_2ND_TKT` after that. A
  non-forwardable evidence ticket is 13
  `EVIDENCE_TKT_NOT_FORWARDABLE`; CNAME-IN-ADDL-TKT plus U2U is 13
  `INVALID_S4U2PROXY_OPTIONS`; a TGS target is 12 `NOT_ALLOWED_TO_DELEGATE`;
  a missing header PAC is 20; a header PAC that is not the impersonator is
  13 `S4U2PROXY_HEADER_PAC`; a missing evidence PAC is 41
  `S4U2PROXY_NO_STKT_PAC`; same-realm evidence server ≠ header client is 26
  `EVIDENCE_TICKET_MISMATCH`; evidence PAC ≠ evidence client is 13
  `S4U2PROXY_LOCAL_STKT_PAC`. First hop writes `S4U_DELEGATION_INFO`
  (`update_delegation_info`). Classic allow is `s4u_allowed_to` on the
  impersonator; RBCD is `s4u_allowed_from` on the resource; empty lists
  deny (MIT db2 hooks are NULL → `UNSUPPORTED_S4U2PROXY_REQUEST`).
  `decrypt_2ndtkt` is shared with U2U. diffsend 58 cases.
- **kdc.** U2U is `check_tgs_u2u` + `get_2ndtkt_enctype` + ticket kvno 0
  (`tgs_policy.c:575-598`, `do_tgs_req.c:310-328,997-1060`). No second
  ticket is 13 `NO_2ND_TKT`; a service evidence ticket is 12
  `2ND_TKT_NOT_TGS`; a TGT whose client is not the dest is 26
  `2ND_TKT_MISMATCH`; a corrupt second-ticket PAC is 41 `2ND_TKT_PAC`;
  an invalid session etype is 14 `BAD_ETYPE_IN_2ND_TKT`. The issued
  ticket is encrypted in the second ticket's session key; MIT sets
  `enc_part.kvno = 0`, which `DEFOPTIONALZEROTYPE` omits on the wire
  (a present INTEGER 0 breaks FAST finished). `DISALLOW_DUP_SKEY` is
  12 `DUP_SKEY DISALLOWED`. diffsend 64 cases.
- **kdc.** Ticket addresses follow MIT AS/TGS copy rules
  (`do_as_req.c:713,245`, `do_tgs_req.c:1012-1027`). The TGS binds the
  UDP/TCP peer (`kdc_util.c:197-200`) with `krb5_address_search`
  (`addr_srch.c:55-59`: NULL matches; a lone NetBIOS list is empty) and
  rejects a mismatch as 38 `BADADDR` `PROCESS_TGS`. FORWARDED/PROXY
  put the request addresses on the ticket and the reply; RENEW/VALIDATE
  keep the header `caddrs` and omit them from the reply. diffsend 66
  cases. The acceptor still compares whole address lists
  (`docs/security.md`).
- **test.** `a2_6_tgs_gather.rs` is the parent-red truth table.
  `a2_6_tgs_pac_extra.rs` covers PAC-REQUEST / `disable_pac` / privsvr /
  MIT-shape copy. `cross-kdc-gate.sh` compares MIT-TGT → Rust-TGS PAC
  buffer types to MIT's own and verifies `setstr pac_privsvr_enctype`
  with `krb5-pac-extract --verify-privsvr` on both legs.

### W1-0

- **docs.** W1-0 archive leftovers and the master-plan Active-W1 index
  were already on disk; no KDC behavior change.

### W1-A′-1

- **kdc.** `kdc_find_fast` / `armor_ap_request` are ported whole
  (`fast_util.c:35-90,126-247`): AS (and TGS-without-PA-TGS-REQ-subkey)
  AP-REQ armor whose authenticator has no subkey is 12 `FIND_FAST`; TGS
  explicit armor with a PA-TGS-REQ subkey stays 24. diffsend
  `fast-armor-no-subkey` sends the same bytes to both KDCs.
- **kdc.** A PA-TGS-REQ whose header ticket or authenticator carries
  AD-FX-ARMOR (71), including inside IF-RELEVANT, is 12 `PROCESS_TGS`
  (`kdc_util.c:217-229`, `authdata_dec.c:115-181`). Nothing in 1.22.2
  emits 71. diffsend `armor-ap-req-as-pa-tgs-req` and
  `tgs-ad-fx-armor-authenticator`.
- **kdc.** PA-FX-COOKIE is MIT1 ‖ kvno ‖ enc(PRF+ of the first current
  local TGT key over `COOKIE`‖unparsed client, ku 513, 600 s). Mint and
  read use `get_first_current_key`; an unknown kvno is ignored. Garbage,
  expired, and wrong-client cookies are ignored (`kdc_fast_read_cookie`
  returns 0). Empty module state is the 3-byte `MIT` cookie. TGS FAST
  errors carry no cookie. Armor AP-REQ `starttime` in the future is 33
  `FIND_FAST`.
- **kdc.** AS/TGS entry validation matches `process_as_req` /
  `gather_tgs_req_info` / `kdc_rd_ap_req`: AS `msg_type` ≠ 10 is 60
  `VALIDATE_MESSAGE_TYPE`; pvno ≠ 5 is dropped; TGS `msg_type` ≠ 12 is
  60 `UNKNOWN_REASON` with no cname; AS `DISALLOW_SVR` is 27 with no
  ENC-TKT-IN-SKEY exemption; TGS AP-REQ `USE_SESSION_KEY` /
  `MUTUAL_REQUIRED` is 12 `PROCESS_TGS`; header decrypt binds the
  labeled kvno (kvno 0 retries ≤ 3). diffsend `as-bad-msg-type`,
  `as-bad-pvno`, `tgs-bad-msg-type`, `as-service-not-allowed`,
  `tgs-ap-options`, `tgs-header-kvno-zero`.
- **admin.** `kadm5_modify_principal` / create refuse `tl_data_type < 256`
  (`KADM5_BAD_TL_TYPE`) and a non-zero `fail_auth_count`
  (`KADM5_BAD_SERVER_PARAMS`) before any store write.
- **kdc/admin.** AS error codes match `errcode_to_protocol`: missing HW
  preauth is 25 `NEEDED_HW_PREAUTH` with the hw_only hint list; no
  matching client key is 14 `CANT_FIND_CLIENT_KEY`; no server/krbtgt
  key is 60 `FINDING_SERVER_KEY` / `GET_LOCAL_TGT`. S4U2Proxy PAC and
  U2U second-ticket local-TGT misses are 60 `GET_LOCAL_TGT` (not 7).
  `kdc_rd_ap_req` kvno 0 walks back at most three keys. A TGS KRB-ERROR
  with no decrypted client omits `cname` and `crealm`. Every e_data-bearing
  AS error carries PA-FX-COOKIE; PKINIT `dh_params_not_accepted` 65 is
  TYPED-DATA (tags [0]/[1]) plus cookie; FAST inner PA-FX-ERROR has empty
  e_data. `modprinc -unlock` stores `KRB5_TL_LAST_ADMIN_UNLOCK`
  (1792, 4-byte LE) and zeroes fail_auth_count. Absent unlock TL
  reads as stamp 0 (`kdb5.c:1539-1545,1574-1576`). `record_as_outcome`
  clears fail count only for `REQUIRES_PRE_AUTH` (`lockout.c:181-190`).
  diffsend `as-hw-preauth`, `tgs-bad-msg-type`, `tgs-ap-options`.
- **docs/tooling.** Golden dump `nosvr`/`hwuser` rows are MIT
  `kadmin.local addprinc` captures with principal-derived keys.
  `ci-policy.py DIFFSEND_CASES` lists all 30 live diffsend names.
- **test/ci (A′-1 Round 3 R8).** The evidence contract is mechanical:
  `unit_green` refuses a dirty tree unless `KERBER_UNIT_ALLOW_DIRTY=1`
  (stamps `override=`); `unit_red_at --all` derives every inject-file
  `#[test]` and exits non-zero unless each FAILED at the parent
  (`red-at-parent=1`); `settle.sh` stamps `override=KERBER_SETTLE_ALLOW_DIRTY`
  when the dirty guard is bypassed; `ci-status.py --save` writes only
  completed runs and drops `title=fixture` / `probe-gate.sh` annotations;
  `claim-audit.py` rejects dirty/override oracle artefacts unless the
  bullet is a parent red; `scripts/evidence-check.py` flags unstamped,
  wrong-SHA, and unlabeled-dirty artefacts.
- **test/ci (A′-1 Round 3 R8 follow-up).** `unit_red_at --all` runs each
  inject file as `cargo test --test <stem>` instead of joining names with
  `|` (cargo treats that as one substring and skips every inject test).
- **admin/kdc (A′-1 Round 3 R9).** `KADM5_BAD_MASK` on create/modify
  (`svr_principal.c:310-326,565-580`); `tl_data_type` decoded as int16
  before the `< 256` guard; create-path reserved TL / type 500 probe cells;
  `merge_tl_data_in` appends `KRB5_TL_DB_ARGS` (0x7fff). U2U missing
  second-ticket server is 7 `2ND_TKT_SERVER` (`do_tgs_req.c:280-285`), not
  60 `GET_LOCAL_TGT`. Gate `docker cp` uses `${CARGO_TARGET_DIR:-target}/debug`
  so a Cursor/sandbox target dir cannot ship a stale kadmind. Limitation:
  modify may still do more than one store write (documented deviation vs
  MIT's single `kdb_put_entry`).
- **protocol/kdc (A′-1 Round 3 R10).** `compare_preauth_e_data` compares
  type **multisets** for 25/24/91/65 (TYPED-DATA decoded); order stays
  item 15. SPAKE 91 adds ETYPE-INFO2 unless a cookie was already seen
  (`kdc_preauth.c:1141-1170`). `stable_krb_error` carries crealm/cname
  presence. `TypedData.data_value` is mandatory on encode. diffsend
  `as-spake-round1` (30 cases); `as-hw-preauth` asserts
  `e_data_types:[19,133,136]`. Old-kvno cookie unit; pkinit P-384 cell
  relabelled as shape-only (item 17); FAST-error outer e_data shape pinned
  through `kdc-padata-proxy.py` on both legs of `mit-fast-kdc-gate.sh`.
- **test (R10 tooling).** `unit_red_at --all` only passes `--test` for
  `tests/*.rs` injects so `Cargo.toml` overlays are not mistaken for stems.
- **docs/test (A′-1 Round 3 R11).** Summary/ledger/INDEX truth pass:
  `CANTLOCK_DB` one verdict; Settled-live line cites retargeted; ledger
  U2U/kadm5/e_data rows graded by what is ported; `kdb-dump-gate` prints
  real all-slot key comparisons; `ci-policy` finds `cases:N` anywhere and
  gains dump/cases fixtures; `status.rs` order + `READ_COOKIE` marked;
  `openssl-seclevel0.cnf` documents inert CipherString.
- **admin/test (A′-1 close-out).** Modify stub order is lookup → ACL →
  lockdown → mask like `server_stubs.c:296-301,621-638` (R12's plan had
  ACL then mask then lookup). `mit-fast-kdc-gate.sh` sets
  `+requires_preauth` on the MIT harness `user` and dies unless both
  legs' wrong-password FAST shapes are `25` then `24` method `[136]`;
  the earlier AS-REP `0x6b` / item-2 deferral was the harness flag, not
  a FAST wrap. `unit_green` captures nextest (`2>&1`) and requires a
  `Summary … passed` line.
- **admin/kdc (A′-1 Round 4 R12).** Every principal put strips
  `KRB5_TL_DB_ARGS` (0x7fff) like `krb5_db_put_principal`; a leftover
  `db_args` is EINVAL 22 `Unsupported argument "…" for db2` and the
  entry/file is unchanged. `krb5-kdb load` of a dump with 32767 fails
  with no partial store; iprop apply skips that record. Modify order is
  lookup → ACL → lockdown → mask → TL/failcount → `db_args` (close-out
  restored MIT's stub order; R12 as landed was ACL → mask → lookup).
  Create decodes `n_key_data` so `KEY_DATA`+`n_key_data!=0` is
  `KADM5_BAD_MASK`. Limitation: a successful modify with both admin
  fields and TL may still write twice (documented).
- **kdc/protocol (A′-1 Round 4 R13).** `u2u_session` answers MIT
  `decrypt_2ndtkt` statuses: no key / unknown etype of the second ticket
  is 60 `2ND_TKT_SERVER`; decrypt failure is 31 `2ND_TKT_DECRYPT`. Three
  `diffsend` cases pin those words on both KDCs (33 live cases).
  Limitation: kvno-scoped search, `match_enctype`, PAC/`2ND_TKT_PAC`, and
  the S4U2Proxy evidence half stay item 9.
- **test/ci (A′-1 Round 4 R14).** `mit-fast-kdc-gate.sh` pins a real FAST
  error on both legs: TGS `nosuch/service` is `error_code=7
  e_data_encoding=method e_data_types=[136]` (no cookie) equal on both;
  wrong-password is `25` then `24` method `[136]` on both once the MIT
  harness `user` has `+requires_preauth` (the harness image creates
  `user` with empty Attributes; Rust `--test-realm` already sets
  `REQUIRES_PRE_AUTH`). The UDP proxy logs non-0x7e replies. `ci-policy.py`
  fixtures cover `unit_guard_dirty`, `unit-red-check.py`,
  `ci-status.py --save` in_progress/403/completed, a diffsend name-set
  mismatch, and artefact-scoped parent-red in `claim-audit.py`. The R14
  `unit_guard_dirty` fixtures set `KERBER_NO_IMAGE=1` so
  `provenance.sh` does not require the MIT image (CI test /
  ledger-mit jobs have docker but not `kerber-rust-mit-kdc:1.22.2`).
  The `8800336` commit body still records the false AS-REP wrap (immutable).
- **docs/test (A′-1 Round 4 R15).** Round 3 truth pass: recaptured
  `r10-unit-green` / r9 kadm5 parent-red / `ci-<sha>.txt`; summary
  cites anchored by text; `kdb-dump-gate.sh` dies unless both dump
  principals have `*_key_slots=4`. `a1-r2/INDEX.md` keeps the 47
  evidence-check findings as history.

### Round-up R2 (re-audit fixes)

The R2 re-audit's product, security, tooling, and ledger findings, one item
per commit, each MIT-settled with a red-at-parent gate or unit.

- **kdc/protocol — parity.** The SPAKE client refuses a challenge whose factor
  list offers no SF-NONE, like `spake_client.c` (P6). The AS tests only
  `AS_INVALID_OPTIONS` and refuses a `REQUEST_ANONYMOUS` from a named client
  with `VALIDATE_ANONYMOUS_PRINCIPAL` after preauth, like `do_as_req.c` (P3;
  differential `as-request-anonymous`). FAST `hide-client-names` is honoured:
  the AS-REP outer client becomes the anonymous principal (P4). The AS ticket
  and enc-part server name are canonicalized under `-C` for a krbtgt alias
  (P7). `[libdefaults]` no longer honours `[kdcdefaults]`-only knobs like
  `kdc_ports` (P8).
- **kdc/kadmind — DoS hardening.** At the concurrent-connection cap (45, MIT's
  `max_stream_data_connections`) a new KDC TCP connection evicts the oldest
  live one rather than being refused (S6, `ConnRegistry`). kadmind reuses that
  registry, bounds the accumulated RPC record at 1 MiB, and sets a write
  timeout, so a pre-auth client cannot exhaust threads or memory (S3).
- **tooling.** ci-policy gained red fixtures for its `check_ci`/`check_nightly`
  rules, loud skips for the overlay-probe (with `fetch-depth: 0`) and the
  MIT-anchor check, and a wider whitelist-ban scan (T2/T3/T7/T8);
  `index-check --all` flags directories with files but no covering INDEX (T4);
  `settle.sh` refuses a dirty tree and the glob cell asserts the MIT
  `Invalid argument` text (T8). The `handle_tcp` self-test pin is now
  drift-proof (S7 follow-up).
- **docs.** The MIT-parity ledger consolidated its R2 regrades — the iprop
  wire divergence, the enc-challenge replay code, the vestigial policy-dump
  fields, and the FAST `pa_type` are recorded as documented deviations (D1);
  `docs/security.md` gained rows for the cross-realm PAC filter, the kadmind
  caps, the TGS unknown-option stance, and the FAST hide-client-names scope.

### Round-up R1 (residue sweep)

- **tooling.** `scripts/claim-recite.py` moves a summary's `script:line` citations
  from the tree they were written against to HEAD by line content and ordinal
  (choosing, per file, the candidate SHA where the most citations assert) and,
  with `--widen N`, extends a citation of a cell's command to its asserting
  line; the round-up's evidence review used it to bring the W1-I summaries back
  under `claim-audit.py` after later gates grew above their cells.
- **test/ci.** A gate that dies silently under `set -e` now names its cell:
  `scripts/lib/provenance.sh` installs an `ERR` trap that prints
  `::error file=scripts/<gate>.sh,line=N::<command>`, which GitHub stores as a
  check-run annotation readable without a token; `scripts/ci-status.py` prints
  those annotations under a failed job, and `scripts/gate-err-trap-selftest.sh`
  guards the trap in the `test` job. `scripts/kadmin-local-gate.sh` restarts
  the kadmind by waiting for the old process to exit and removing its log
  before the relaunch, so the readiness poll can no longer match the previous
  process's `listening` line (the likely cause of the job's intermittent red at
  that step, twice in three runs, never reproduced locally).
- **client.** `kinit` records `fast_avail = yes` (when the KDC echoed
  PA-FX-FAST) and the selected preauth type as `pa_type` in the ccache, as
  `X-CACHECONF:` config entries keyed by the TGT's server and stored ahead of
  the credentials, like MIT `write_out_ccache`; MIT `klist -C` lists them in a
  Rust-written cache exactly as in its own. `FileCcache::set_config` takes the
  principal the entry is keyed by. (The L3b deferral.)
- **client.** Under FAST the advertised PA-AS-FRESHNESS/PA-REQ-ENC-PA-REP
  were dropped from the FAST-REQ (the armor wrapper replaced the padata list,
  the SPAKE bug's twin), so a FAST kinit never negotiated availability; the
  inner request now carries them like `krb5int_fast_prep_req`, and the
  client verifies the KDC's enc-pa-rep checksum over the outer request with
  the strengthened reply key like `krb5int_fast_verify_nego` (it skipped the
  check under FAST). A FAST kinit records `fast_avail` too.
- **config.** `allow_weak_crypto`, `allow_rc4`, `allow_des3` and
  `permitted_enctypes` are read from `[libdefaults]` only, like MIT's
  `init_ctx.c`; a copy under `[kdcdefaults]` or a realm stanza is ignored (the
  KDC used to honour it). `scripts/rc4-session-gate.sh` proves both KDCs refuse
  an rc4-only client when `allow_rc4` lives only under `[kdcdefaults]`.
- **test.** `scripts/kadmin-gate.sh` lists `listprincs`/`listpols` glob patterns
  through the kadm5 RPC on both the Rust and the MIT kadmind and diffs them
  (the W1-K M4c glob port had only a kadmin.local cell).
- **admin.** The kadmind's `GET_UPDATES` reply no longer ships the store's
  `policy:` ulog markers: MIT never logs policy changes (`kdb5.c` calls
  `ulog_add_update` for principals only) and its kpropd's `ulog_replay` parses
  every entry as a principal, so a marker made MIT kpropd fail
  `Malformed representation of principal` and drop the whole batch. Policies
  reach a replica by full resync, as with MIT. `scripts/iprop-gate.sh` now
  creates a policy on the master after the replica's resync (its marker must
  stay off the wire), propagates a password change under a history policy,
  and has the MIT kpropd replica refuse the old password itself.
- **kdc/admin.** Password history is stored the way MIT stores it. Every
  principal's `KRB5_TL_KADM_DATA` is now the XDR `osa_princ_ent_rec`
  (`adb_xdr.c`): the bound policy and `KADM5_POLICY`, `old_key_next`,
  `admin_history_kvno`, and `old_keys` — one entry per remembered password,
  its key data encrypted under the `kadmin/history` key like
  `create_history_entry`/`add_to_history` (`svr_principal.c`). The history
  principal is created lazily on the first password change of a
  policy-bound principal with `create_hist`'s shape (`server_kdb.c`: max life
  64 s, no attributes, one key of the master enctype at kvno 2). Before this,
  Rust kept the policy name and the history in private `tl_data` types under
  the master key, so a MIT `kdb5_util load` of a Rust dump (or a Rust load of
  a MIT dump) lost the policy binding and the reuse history, and iprop shipped
  history entries MIT could not decrypt. Older Rust dumps still load (the
  private types are read and retired on the next change).
  `scripts/kdb-dump-gate.sh` now proves both directions (Rust refuses MIT's
  old password after loading MIT's dump; MIT refuses Rust's after loading
  Rust's; `Policy:` and the `kadmin/history` shape agree), and
  `scripts/kadmin-gate.sh` asserts the lazy creation and the shape on both
  legs instead of creating the principal itself. The MIT dump fixture
  `tests/traces/kdb/mit-dump-v7-history.txt` is the oracle for the codec.
- **admin.** `krb5-kadmin-local` prints the whole `getprinc` record like
  `kadmin_getprinc` (dates, lifetimes, keys with `DEPRECATED:`, `MKey`,
  `Attributes:` names, `Policy:`) — it printed only the principal line — and
  uses MIT's `add_principal`/`change_password` texts (`Principal "…"
  created.`, `Password for "…" changed.`, `change_password: Cannot reuse
  password while changing password for "…".`), continuing after a failed
  verb like `com_err`. A realm created without `master_key_type` now gets
  MIT's default aes256-cts-hmac-sha384-192 master key (it got
  aes256-cts-hmac-sha1-96), which is also what the history key inherits.

### Round-up R0 (clear CI)

- **client.** The SPAKE response AS-REQ replaced its padata list with
  `[PA-SPAKE, PA-FX-COOKIE]`, dropping the PA-AS-FRESHNESS/PA-REQ-ENC-PA-REP
  pair W1-J L3b advertises on every AS-REQ; MIT's KDC then echoed no enc-pa-rep
  checksum (`kdc_util.c:1780-1783`) and the client rejected the reply with
  `KRB5_KDCREP_MODIFIED`. CI was red at `rust-kinit-spake-gate` for every push
  from `e5d9e28` to `a8563e1`. The final request now carries the cookie, the
  PA-SPAKE response, then 150 and 149, in MIT's order (`k5_preauth` copies the
  cookie first, `init_creds_step_request` appends the pair last), and the
  second-round support request orders the cookie before PA-SPAKE the same way.
  `scripts/lib/kdc-padata-proxy.py` (new) prints the padata types of every
  forwarded KDC-REQ for live settles.
- **kdc/test.** The lookaside held every request's bytes twice (the map key
  and the eviction FIFO); they are now one shared allocation, so the cache's
  memory tracks MIT's `req_packet + reply_packet + sizeof(entry)` accounting
  (`replay.c`). The KDC logs `kdc.lookaside.full` once when the 10 MiB bound
  first forces an eviction, and `scripts/lib/analyze-kdc-slo.py` judges the
  RSS slope from that event on (a bounded cache filling is a ramp that
  flattens; a leak keeps climbing), spending a `--rss-fill-allowance-mib`
  before it, and the steady window opens only after the replay caches' 5-minute
  window (`--rss-steady-after-s`) — a 300 s soak showed RSS still climbing at
  ~0.03 MiB/s after the lookaside filled, flattening near 300 s, which is the
  two replay caches (a documented stricter-than-MIT deviation) and not a leak.
  `scripts/soak-gate.sh` runs 120 s per push (bounded by the growth cap,
  `first×1.5 + 33 MiB` = 8 MiB slack + the 25 MiB working set measured at
  300 s) and 480 s scheduled (a real steady window); it was red since
  `32bb4d5` because the 8 MiB allowance predated the cache.
- **ci.** `scripts/ci-status.py` (new) prints recent GitHub Actions runs with
  per-job conclusions and the first failing step from the public REST API (no
  `gh`, no token needed; exit 0/1/2 = newest run green/red/pending). CI had been
  red for twelve pushes while the working notes said it was unobservable.

### W1-K M4c (kadmind operation logging)

- **admin.** kadmind now logs every operation like MIT `log_done`/`log_unauth`
  (`server_stubs.c:403-459`): a completed op emits `Request: <op>, <target>,
  <success|result>, client=…, service=…, addr=…` and an ACL-denied op emits
  `Unauthorized request: <op>, <target>, client=…, service=…, addr=…`, at info
  level. The `service` (acceptor principal) comes from the GSS context and the
  `addr` from the connection's peer address, both newly threaded into
  `rpcsec_dispatch`; the op name and target follow MIT's per-stub strings and
  `prime_arg`. This closes the M4c residue that was deferred for lack of
  service/addr plumbing. `kadmin-gate.sh` asserts the create-success and the
  changepw-list-denied lines in the Rust kadmind log, matching a live MIT
  kadmind settle.

### W1-J L5b (lookaside reply cache)

- **kdc.** The listener now keeps a lookaside reply cache like MIT
  `kdc/replay.c`: a retransmitted request, keyed by its exact bytes, is answered
  from the cache instead of re-processed, so the reply is byte-for-byte the
  first (a fresh AS-REP would carry a new random session key, and a preauth or
  TGS authenticator replay would otherwise error). A duplicate arriving while
  the first is still being processed is dropped (MIT `KRB5KDC_ERR_DISCARD`);
  entries older than two minutes are purged and the cache is capped at 10 MiB,
  oldest first. The cache is shared across the UDP and TCP threads and wraps
  `handle_request` in the listener, so direct `issue_as`/`issue_tgs` callers
  (the authenticator/PA replay-cache tests) are unaffected.
  `differential-gate.sh` gains an `as-retransmit` case: the same request sent
  twice yields an identical reply on both legs. Ledger row `replay.c`/
  `dispatch.c` regrades deviation → exact.

### W1-J L5a-3 (validate_as_request: order, AS_INVALID_OPTIONS, REQUIRED PWCHANGE)

- **kdc.** The AS policy checks now run as one ordered `validate_as_request`
  (`kdc_util.c:727-800`) after the client/server lookup and **before** preauth,
  matching MIT (`do_as_req.c:630` precedes `check_padata` at `:758`). Rust had
  checked the client lockout first and the expiry/pwchange/postdate/service
  checks only after preauth, so a preauth-required client that also needed a
  password change (or had an expired password, or was expired) got
  `NEEDED_PREAUTH` (25) where MIT returns the validate status (23/1). The
  DISALLOW_ALL_TIX client-lockout and the failcount lockout are now split into
  MIT's positions (client-lockout after the expiry/postdate checks, failcount
  last). `differential-gate.sh` gains an `as-validate-before-preauth` case (a
  preauth+needchange `pwprau` principal), `23`/`REQUIRED PWCHANGE` on both legs.
  Ledger rows `kdc_util.c:778-780`, the order row, and the failcount row regrade
  deviation → exact.
- **kdc.** An AS-REQ that sets a TGS-only `kdc-option` (`FORWARDED`, `PROXY`,
  `RENEW`, `VALIDATE`, `ENC-TKT-IN-SKEY`, or `CNAME-IN-ADDL-TKT`) is now
  rejected with `INVALID AS OPTIONS` (code BADOPTION 13) like
  `validate_as_request` (`kdc_util.c:727-729`, `AS_INVALID_OPTIONS`); Rust's
  `unsupported_bits` counted those bits as supported, so the AS silently issued
  a ticket. A new `KdcOptions::as_invalid_bits` masks them in `issue_as_body`.
  `differential-gate.sh` gains an `as-invalid-opts` case (`RENEW`), `13`/`INVALID
  AS OPTIONS` on both legs.
- **kdc.** A client with `REQUIRES_PWCHANGE` now fails with MIT's distinct
  status `REQUIRED PWCHANGE` (code KEY_EXP 23) checked after SERVICE EXPIRED,
  like `validate_as_request` (`kdc_util.c:762-766`); Rust had merged it into
  the lapsed-pw-expiration `CLIENT KEY EXPIRED` branch. `differential-gate.sh`
  gains an `as-needchange` case against a new `pwchgu` (needchange, no preauth)
  dump principal, `23`/`REQUIRED PWCHANGE` on both legs.
- **kdc.** A PREAUTH_FAILED (24) AS error now carries the `get_preauth_hint_list`
  e_data like MIT `finish_preauth` (`do_as_req.c:443-447`), so the client can
  retry with the right salt/etype; a SKEW (37) still carries none. The
  differential oracle compares the hint e_data structurally for 24 as well as
  25, gated by `as-optimistic-encts-wrong-etype`. The rest of
  `validate_as_request`'s check order remains.

### W1-J L5a-2 (AS KRB-ERROR client echo)

- **kdc.** The AS KRB-ERROR now echoes the requested `crealm` and `cname` like
  MIT `prepare_error_as` (`do_as_req.c:806-808`, `errpkt.client =
  request->client`); Rust had left both `None`. `scripts/differential-gate.sh`
  compares `crealm`/`cname` on every AS error case (`expect_error`'s
  `check_client`).
- **kdc.** A TGS KRB-ERROR now echoes the decrypted header ticket's client like
  MIT `prepare_error_tgs` (`do_tgs_req.c:201-204`); `tgs_reply` derives it with
  `tgs_header_client` and the gate compares `crealm`/`cname` on `tgt-expired`
  and `tgt-nyv`. A service ticket the KDC rejects before decrypt (`tgs-not-a-tgt`,
  which needs a fuller `kdc_get_server_key`), FAST client-hiding, and the
  `errcode_to_protocol` code-table adjustments remain for the rest of L5a-2.

### W1-J L3b (client FAST negotiation)

- **client.** The AS client now advertises an empty PA-AS-FRESHNESS (150) and
  PA-REQ-ENC-PA-REP (149) on every AS-REQ like MIT `info_pa_permitted`
  (`get_in_tkt.c:1365-1372`); verifies the KDC's enc-pa-rep checksum over the
  AS-REQ under the reply key and rejects a missing or bad checksum with
  `KRB5_KDCREP_MODIFIED` like `krb5int_fast_verify_nego` (`fast.c:635-675`); and
  records RFC 6806 FAST availability on the outcome (`AsOutcome::fast_avail`)
  from the echoed PA-FX-FAST. `scripts/mit-fast-kdc-gate.sh` pins that a plain
  MIT kinit against the Rust KDC traces `FAST negotiation: available`. Persisting
  `fast_avail` to the ccache config is deferred to the round-up.

### W1-K M2b (delete the differential whitelist)

- **ci/protocol.** The differential oracle no longer has a case-name
  whitelist. Every named mask was removed by its owning item (L0, L3a, L4a,
  L4b, L5a-1); M2b deletes the mechanism itself: `Whitelist`, `CompareOk`,
  `whitelist_hits`, and the `named_flag_mask` renewable mask in
  `crates/krb5-protocol/src/diff.rs`. `compare_stable_rep` now compares every
  stable field with no masking (the renewable and canonicalize flag bits
  included) and returns `()`. `examples/diffsend.rs` drops the `"whitelist"`
  output key; `scripts/differential-gate.sh` fails if any diffsend line
  carries one; and a new `scripts/ci-policy.py` rule bans the whitelist
  mechanism identifiers from the diffsend driver and the gate scripts.

### W1-J L4b (AS/TGS reply padata)

- **kdc.** The AS-REP and TGS-REP no longer carry `PA-SUPPORTED-ENCTYPES`
  (padata type 165). MIT 1.22.2 `return_padata` (`kdc_preauth.c:1394-1506`)
  emits only `add_etype_info`/`add_pw_salt` output, and MIT 1.22.2 defines no
  type 165 anywhere; the field was a Windows/MS-KILE-only extension. Rust now
  matches MIT's outer padata set exactly: `PA-ETYPE-INFO2` always, plus
  `PA-ETYPE-INFO` and `PW-SALT` for a des3/rc4-only request. The dead
  `supported_enctypes_mask` helper and the `SUPPORTED_ENCTYPES` constant are
  removed. The `mit-as-padata` differential whitelist and its padata filtering
  are removed, so `scripts/differential-gate.sh` `as-success`/`tgs-success`
  compare the full outer padata-type set on both legs (`whitelist:[]`).
- **kdc.** A PA-ENC-TIMESTAMP whose declared enctype the client has no key for
  is now `KDC_ERR_PREAUTH_FAILED` (24), matching MIT `enc_ts_verify`
  (`kdc_preauth_encts.c:74-116`, `KRB5_KDB_NO_MATCHING_KEY` remapped to 24);
  Rust had returned NEEDED_PREAUTH (25). The NEEDED_PREAUTH hint now lists a
  single ETYPE-INFO2 entry for the selected client key like MIT
  `get_preauth_hint_list` (`kdc_preauth.c:1003`), so the differential oracle
  `compare_preauth_e_data` compares the etype set exactly (the `MIT ⊆ Rust`
  leniency is removed). `scripts/differential-gate.sh` gains the
  `as-optimistic-encts-wrong-etype` case (24 on both legs).


### W1-J L3a (enc-pa-rep flag)

- **kdc.** Every issued AS and TGS ticket now sets the `TKT_FLG_ENC_PA_REP`
  flag like MIT `get_ticket_flags` (`kdc_util.c:824`), independent of whether
  the client sent PA-REQ-ENC-PA-REP; the enc-pa-rep padata stays request-keyed.
  The `mit-extra-ticket-flags` differential whitelist and its flag masking are
  removed, so `scripts/differential-gate.sh` compares the ticket flags in full
  (the enc-pa-rep bit included) on both legs. The remaining `get_ticket_flags`
  bits (FORWARDED, PROXY, MAY_POSTDATE, POSTDATED, ANONYMOUS, HW_AUTH) are still
  a documented deviation.


### W1-J L4a

- **kdc.** The AS-REP enc-part no longer carries a `kvno`. MIT assigns
  `reply.enc_part.kvno` only after `krb5_encode_kdc_rep` (`do_as_req.c:329`),
  so the wire reply has no kvno; Rust was emitting the client key's kvno on a
  no-preauth AS. The `mit-as-enc-kvno` differential whitelist is removed and
  `scripts/differential-gate.sh` `as-success` compares the enc-part kvno equal
  on both legs.


### W1-J L5a-1

- **kdc.** An expired or not-yet-valid TGS header ticket now reports status
  `PROCESS_TGS` (e_text) like MIT, which validates ticket times inside
  `kdc_process_tgs_req`/`rd_req` (`krb5int_validate_times`, status set at
  `do_tgs_req.c:623`); the wire code is unchanged (32 / 33). The renew branch
  is untouched, so renew-after-endtime still issues. The `mit-order-tgs-times`
  differential whitelist is removed; `scripts/differential-gate.sh` now
  compares the `tgt-expired`/`tgt-nyv` e_text equal on both legs.


### W1-K M1b

- **ci.** A required `ledger-mit` job fetches the SHA-pinned MIT 1.22.2 source
  (the same tarball `harness/Dockerfile` builds) and runs `scripts/ci-policy.py`
  with `KERBER_MIT_SRC` set, so `check_ledger_mit_cites` verifies every ledger
  MIT `file:line` and status word against the real tree in CI. Previously the
  check was opt-in and never ran in CI; a broken MIT cite now fails a required
  job instead of being silently accepted.


### W1-K M4c (partial)

- **client/admin.** `krb5-klist -e` prefixes `DEPRECATED:` on a deprecated
  enctype like MIT `klist.c etype_string` (`EncryptionType::is_deprecated`
  covers des3-cbc-sha1 and arcfour-hmac). `listprincs`/`listpols` filter with
  MIT `glob_to_regexp` semantics (`?`/`*`/`[...]`/`\`, implicit `@*` for
  principals, `EINVAL` on a trailing `\`) instead of a substring match, on
  both the kadmind RPC path and kadmin.local. The dead `Acl::privs` is removed
  (the wire `GET_PRIVS` already returns `~0`). Verified on
  `scripts/rc4-session-gate.sh` (the `DEPRECATED:arcfour-hmac` `Etype` line on
  both legs) and `scripts/kadmin-local-gate.sh` (glob list diffs). The
  `log_unauth`/`log_done` kadmind log lines are deferred (they need service and
  address plumbing through the RPC dispatch).


### W1-K M4b

- **kdc (on-disk format change).** The master-key stash `.k5.REALM` is now a
  FILE keytab with a single `K/M@REALM` entry (etype and kvno embedded), like
  MIT `krb5_def_store_mkey_list`; loading tries the keytab first
  (`krb5_db_def_fetch_mkey_keytab`, one decrypt with the embedded etype) and
  falls back to the legacy raw-key stash (`krb5_db_def_fetch_mkey_stash`),
  rewriting it in keytab format on the next save. A `krb5-kdb stash` subcommand
  (re)writes the stash. Existing raw stashes keep loading; no operator action
  is needed. MIT `klist -k` reads the Rust stash's `K/M` entry (verified on
  `scripts/kdb-dump-gate.sh`).


### W1-K M3b

- **admin.** kadmin.local grows the `alias`/`add_alias` verb
  (`kadmin_addalias`) with MIT's `usage:`/success/`com_err` texts, and the
  local `addpol`/`modpol` path now routes through the same validators as
  kadmind (`kadm5_create_policy` order DUP → name → min>max → length →
  classes → history, with the exact `kadm_err.et` texts `Invalid number of
  character classes` / `Invalid password history count` / `Password minimum
  life is greater than password maximum life`). `parse_interval` reports
  `Invalid date specification "…".` and the addmodpol usage block. Like MIT,
  a failed `addpol`/`modpol`/`alias` prints the error and exits 0. The
  `getdate.y` natural-language interval is recorded as a deferred ledger row.
  Verified on `scripts/kadmin-local-gate.sh` (alias and policy-order/text
  cells diffed against MIT `kadmin.local` on both legs).


### W1-K M3a

- **admin/kdc.** `create_alias` (kadmin proc 27) like `create_alias_2_svc`
  / `kadm5_create_alias` / `acl_addalias`: an alias stub is a keyless
  `DISALLOW_ALL_TIX` entry carrying `KRB5_TL_ALIAS_TARGET`, and every
  `PrincipalStore` lookup resolves it up to `MAX_ALIAS_DEPTH` (10) hops like
  `krb5_db_get_principal`. The AS keeps the requested cname unless
  CANONICALIZE is set, and the AS-REP now carries PA-ETYPE-INFO2 with the
  canonical client's salt (`add_etype_info`/`add_pw_salt`) so `kinit` under an
  alias derives the target key. `krb5-kadmin-local` and `krb5-kdb alias` mint
  stubs; dump v7 round-trips them (MIT `kdb5_util` ↔ Rust both directions).
  Verified live on `scripts/kadmin-gate.sh` (alias cells, both legs) and
  `scripts/kdb-dump-gate.sh` (MIT-written and Rust-written alias kinit).


### W1-J Round 2 V5 / V3

- **protocol.** `build_krb_safe_ex` checksums the full KRB-SAFE with a
  spliced zero checksum (`create_krbsafe`, `mk_safe.c:68-80`) — MIT's
  primary verify branch — instead of the body alone, so a Rust-originated
  KRB-SAFE no longer relies on MIT's RFC 1510 fallback. Documented as
  fail-closed deviations (no product path exercises them): the
  `k5_privsafe_check_addrs` local-address walk and its KRB-PRIV caller
  (`privsafe.c:366-375`, `rd_priv.c:77-78`; no r-address is emitted), and
  the GSS sequence window enforced unconditionally where
  `g_seqstate_check` skips it when unnegotiated (`util_seqstate.c:84-117`;
  MIT peers always negotiate replay/sequence).

### W1-J Round 2 V6

- **protocol.** The TGS-REP enc-part decoder goes through
  `decode_enc_kdc_rep_part` (APPLICATION 26 then 25 then untagged, MIT
  `kdc_rep_dc.c:69`) instead of 26-then-untagged, converting the caller
  L0 left behind; a MIT/Heimdal TGS-REP tagged RFC 25 now decodes.

### W1-J Round 2 V2

- **gss/admin.** The callers of `unwrap_v3` and `process_checksum` now match
  MIT 1.22.2. `unwrap` reports `conf_state` and the RPCSEC_GSS privacy
  service rejects an integrity-only body (`authgss_prot.c:238-240`), so a
  client cannot downgrade `rpc_gss_svc_privacy` to an unsealed request.
  Storing a delegated credential sets `GSS_C_DELEG_FLAG`, the established
  context sets `GSS_C_PROT_READY_FLAG`, a `GSS_EXTS_FINISHED` extension and
  a bad forwarded KRB-CRED are `GSS_S_FAILURE`, and RRC is reduced modulo
  the payload length so a token MIT accepts is no longer rejected.

### W1-J Round 2 V4

- **types/kdc.** PAC shape follows MIT 1.22.2 `k5_pac_should_have_ticket_signature`:
  ticket (16) and full (19) checksums are signed and verified only for
  service tickets; a presented TGT is verified on its server signature
  alone (`kdc_util.c:597-602`); the S4U evidence ticket retries the two
  previous krbtgt kvnos. `Pac::parse` refuses what `krb5_pac_parse`
  refuses (version, buffer count, alignment, header overlap) and a
  duplicate buffer type is 60. The ticket key is the first key of the
  highest kvno (`get_first_current_key`), not the key matching the
  session etype, so MIT's KDB keytab decrypts Rust-issued TGTs. New
  `scripts/cross-kdc-gate.sh`: MIT and Rust TGTs accepted by the other
  TGS on one dump, TGT enc-part etype equal on both legs. `sign_pac` takes
  a `PacTicket`. A presented TGT whose PAC has no LOGON_INFO (MIT's db2
  minimal PAC) is accepted.

### W1-J Round 2 V1

- **ci/docs.** `ci-policy.py` verifies the ledger claim, not its punctuation:
  Rust e_text status words are checked backticked or bare, an `exact` row
  without one must name an existing proof, the MIT column must cite a MIT
  file, a symbol defined twice in a file needs `:N`, and `KERBER_MIT_SRC`
  checks every MIT cite and status word against the 1.22.2 tree (opt-in
  until W1-K §M1b). The informational-arm detector walks `case` arms and
  treats a test whose `||` branch does not assert, a `grep` of an
  echo-written file, `/bin/echo` and `log_*` as noise; `log … skip` is
  excused only for the `KERBER_REQUIRE_` it names. `claim-audit.py` takes
  the oracle leg only from container variables, Samba/Heimdal/AD gates or
  an oracle settle (a Rust-side gate run is not a leg) and requires tooling
  bullets to name their fixture line. Ledger: four de-quoted statuses
  restored, seven rows moved to the MIT-cite schema, five duplicate-symbol
  anchors disambiguated, four aggregate rows given real proofs.

### W1-J L2b

- **protocol/admin.** KRB-SAFE verify matches MIT 1.22.2 `rd_safe.c`:
  APPLICATION 20 (`MSG_TYPE` 40), `k5_privsafe_check_addrs` before the
  checksum, dummy encoding splices the received KRB-SAFE-BODY, then the
  RFC 1510 body-only fallback. kprop send still checksums `encode_krb5_safe`
  with a zero checksum (`create_krbsafe`).

### W1-J L2a

- **types/kdc.** PAC `verify_pac_checksums` matches MIT 1.22.2 `pac.c`:
  checksums run over the received PAC bytes; privsvr covers the server
  buffer minus the 4-byte type (RODC trailer kept); a missing buffer is
  60; a failed server checksum is overwritten by a valid privsvr
  result. Ticket checksum stays over the recoded EncTicketPart with PAC
  ad-data `0x00`. MIT `t_pac.c` `saved_pac` / S4U / fuzz vectors land
  under `crates/krb5-kdc/tests/data/`.

### W1-J L1b

- **gss.** `process_checksum` matches MIT 1.22.2 `accept_sec_context.c`:
  a missing authenticator checksum yields flags 0 and no AP-REP; a
  non-0x8003 checksum is verified over empty data with the ticket session
  key; `cb_len != 16` is failure; an all-zero token CB is accepted when
  the acceptor has bindings; mismatch is channel-bindings; matching CB
  sets `GSS_C_CHANNEL_BOUND`. `gss-gate.sh` pins no-checksum / CB accept /
  CB mismatch on both legs.

### W1-J L1a

- **gss.** `unwrap_v3` / `verify_enc_header` match MIT 1.22.2 `unwrap.c`:
  filler `0xFF`, direction, RRC rotate, confidential `plain.len - ec - 16`,
  non-conf `ec == cksumsize`. `gss-gate.sh` pins DCE-style wrap_iov plaintext
  on both legs and mutation rejects (direction / filler / EC).

### W1-J L0

- **kdc/client.** AS and TGS EncKDCRepPart are encoded with APPLICATION 26
  (`encode_krb5_enc_kdc_rep_part` / `enc_tgs_rep_part`), matching MIT
  1.22.2 `asn1_k_encode.c`. Decode tries 26, then RFC 25, then untagged,
  without an ERROR log on the tag fallback. The `mit-as-enc-app-26`
  diffsend whitelist is gone; `differential-gate.sh` pins enc-part tag
  `0x7a` on both legs.

### W1-K M2a

- **ci.** `scripts/ci-policy.py` tokenises informational-if arms
  (command position, `|| true`, self-tautology); `scripts/chaos-gate.sh`
  no-netem arms `log … skip` and rely on `KERBER_REQUIRE_NETEM`.
  `scripts/claim-audit.py` takes legs from container variables only; a
  single-line reference must sit within one line of an assertion.

### W1-K M1a

- **ci/docs.** `scripts/ci-policy.py` `check_ledger_anchors` dies on an
  unresolvable or ambiguous rust-site, crate-qualifies anchors, brace-matches
  item spans (`fn` / `const` / `struct` / `enum` / `static`), requires every
  `exact` row to carry an anchor, and quote-checks MIT status and Rust e_text
  (including short forms such as `TKT_NYV`). Unowned ledger rows are pointed
  at the real items or regraded; A4 rows for `acl_init`/default `acl_file`,
  `ipropx_resync`, `get_privs`, `CREATE_ALIAS` (absent until M3a), and the
  AUTH_GSSAPI `FLAVOR_NONE` / arg-version residues. Tally 280. `docs/security.md`
  names the W1-I surface.

### W1-I sub-plan 07

- **tooling.** `scripts/lib/settle.sh` refuses every file reader (`grep`,
  `rg`, `zgrep`, `sed`, `cat`, `awk`, `head`, `tail`) given a path, existing
  or vanished, and a `bash -c` string that invokes one; `ci-policy.py` pins
  the four refusals and a live `bash -c`.
- **test.** `getpol_prints_allowed_keysalts_only_when_set` (injectable red for
  `7381c3c` at `e6561f9`); `rpcsec_wrong_handle_with_valid_mic_dispatches`
  (injectable red for `c795351` at `946b434`). `red-at-sha.sh --no-overlay`
  keeps the base tree's helpers so a tooling red (the K6 ci-policy fixtures
  at `2ec7dfb`) is possible.
  `tests/j3_unknown_client.rs` restores the W1-H J3 assertion red (fails at
  `0d28e62`, passes at HEAD). `kadmin-gate.sh` asserts `DISALLOW_TGT_BASED`
  on `kadmin/admin` on both legs.
- **docs.** Ledger row for the RPCSEC `SYSTEM_ERR` reply (`svc.c:290-300`,
  `kadm_rpc_svc.c:263-268`): MIT emits it only when `svc_sendreply` fails,
  kerber-rust for any dispatcher-internal failure (`deviation`, no unit yet).
- **docs.** Ledger `dispatch.c:145-153` row describes the listener drop path
  (`listen.rs:18-25`, debug event without the `while dispatching` suffix).

### W1-I sub-plan 06

- **tooling.** `scripts/claim-audit.py` checks a summary's "Settled live"
  section: every `script:line` reference must carry an assertion on one of the
  bullet's quoted values (or call a function that does), every bullet must name
  a cell on each leg or a live `settle.sh` artefact, and every named artefact
  must exist, be stamped and carry a quoted value. `ci-policy.py` runs its
  fixtures (a non-asserting line, a log-only bullet, a grep settle, a one-leg
  bullet all fail; a live settle counts as the MIT leg).

### W1-I sub-plan 05

- **admin.** `create_policy` checks DUP before the non-printable-name check and
  zeroes unset lifetimes, so an unmasked `pw_max_life` on the wire is ignored
  and `BAD_MIN_PASS_LIFE` needs both mask bits like `svr_policy.c:83-109`.
  `krb5_string_to_deltat` treats trailing whitespace as `tok_WS`: only the
  `opt_s: ws` slot after a `d`/`h`/`m` unit absorbs it, so `"42 "`, `"1s "` and
  `"1d5s "` are refused while `"1d "` is accepted. `kadmin.local -q` tokenises
  like `ss_parse` (`util/ss/parse.c`): `"` quotes, `""` is a literal quote,
  and an open quote is `Unbalanced quotes in command line`.
- **kdb.** `krb5-kdb setlastpwd <princ> <unix-seconds>` (gate-only backdate).
- **test.** `kadmin-gate.sh` backdates `user` on both legs (Rust `setlastpwd`,
  MIT `kdb5_util dump`/edit tl-data 1/`load`) and diffs `Last password change`,
  `Password expiration date` and the full `getpol` output across legs; the
  admin cpw success line, purgekeys on a lockdown target, and an unmasked
  `pw_max_life` create run through RPC clients on both legs; `cpw -randkey
  -keepold` ×6 as self clamps to 5 kvnos on both legs; `setkey -keepold` ×6 as
  self keeps 5 on Rust while MIT 1.22.2 keeps only the newest key
  (`svr_principal.c` never advances `n_new_key_data` past the new keys; pinned
  as a deviation cell). `kadmin-local-gate.sh` mirrors the policy sequence
  and a quoted `"1d "`/`"42 "` `-maxlife` through MIT `kadmin.local` and diffs.

### W1-I sub-plan 04

- **admin.** AUTH_GSSAPI DESTROY is answered in the auth layer before the
  iprop flavor gate, like `svc_auth_gssapi.c:616-623`. `kadmin/history` joins
  the kadmind acceptor keys, so a history-service INIT completes and the name
  gate answers `AUTH_TOOWEAK` like MIT's KDB keytab.
- **test.** The MIT harness kadmind serves the iprop program on `iprop_port`
  2121 in `kadmin-gate.sh` (and, since gssrpc registers programs process-wide,
  on the kadmind port too); the probe gains `iprop-valid` and
  `iprop-auth-gssapi`; both legs assert the iprop program cells and the
  kiprop-on-kadm5 and `kadmin/history` acceptor rejects. `iprop-gate.sh`
  drives MIT `kpropd` against a no-`p` Rust master (`get_updates permission
  denied`) and prog-qualifies the RPCSEC_GSS flavor check.

### W1-I sub-plan 03

- **admin.** The kadmind no longer compares the RPCSEC_GSS context handle
  (`gc_handle`) on DATA/DESTROY, matching MIT `_svcauth_gss` (the per-connection
  context and the header MIC authenticate the request). `RpcsecGss.handle` and
  `Gcred.handle` are dropped.
- **test.** `scripts/kadm5-rpc-probe.c` hand-frames malformed RPCSEC_GSS calls
  after a real libgssrpc handshake; `kadmin-gate.sh` drives the reject machine
  (valid, corrupt-verf, maxseq, wrong-handle, destroy-then-data, garbage-args)
  and asserts the same auth/accept status on the MIT and Rust kadminds.

### W1-I sub-plan 02

- **admin.** The RPCSEC_GSS DATA path now dispatches on the negotiated service
  like `authgss_prot.c`: NONE sends plain args; INTEGRITY sends
  `databody_integ` plus a `gss_get_mic` `checksum` (verified with
  `gss_verify_mic`, inner seq checked); PRIVACY keeps `gss_wrap`. The reply
  mirrors it, so a real MIT libgssrpc client negotiating `rpc_gss_svc_integrity`
  is accepted. `kadmin-gate.sh` runs an integrity `listprincs` on both legs.

### W1-I sub-plan 01

- **admin.** Route every kadm5 acceptor check — `changepw_acceptor`,
  `check_auth_gssapi_names`, `check_rpcsec_auth`, `check_iprop_rpcsec_auth`
  — through one realm gate `acceptor_realm_ok`, matching MIT's full
  realm-qualified acceptor-name compare (`server_stubs.c:28-32`,
  `ovsec_kadmd.c:468-477`). The realm is already bound at
  `accept_sec_context`; the gate is parity and defense-in-depth.
- **admin.** On an ACL parse failure the kadmind now logs MIT's second line
  `<path>: syntax error at line N <text...>` (`auth_acl.c:418-422`) in
  addition to the specific `parse_line` error, like `load_acl_file`.
  `kadmin-gate.sh` asserts the full aZ/3dd text on both legs.

### W1-I Round 3 (K12–K17)

- **K17.** Eight checkpoint gates ×2 at the Round 3 SHA; `unit_red_at
  --inject` reds for K12–K16 parents; INDEX/claim-audit/isolation;
  `add_policy_ent` DUP before floors like `svr_policy.c`; kadmin-gate
  diffs the two legs' `getprivs` lines.
- **K16.** `stub_setup` with `rec_out == NULL` authorises CREATE/DELETE/RENAME
  on the request principal (including a foreign realm). Authorised
  `addprinc user@OTHER.REALM` stores that realm. ACL unknown op is
  `Unrecognized ACL operation '%c' in %s`. `krb5_string_to_deltat`
  leftover unknown chars are EOF (`42x` is 42 s; `3dd` is still
  `invalid restrictions`).
- **K15.** AUTH_GSSAPI INIT on IPROP_PROG is auth-layer SUCCESS
  (`svc_auth_gssapi.c` `no_dispatch`); DATA without a context is
  `AUTH_FAILED`; established DATA is `AUTH_TOOWEAK`. Gate cells pin
  one `init_code` per leg (no `43787528|43787566` alternation) and
  `iprop-gate.sh` dies if MIT kpropd logs `AUTH_GSSAPI` against Rust.
- **K14.** RPCSEC_GSS `_svcauth_gss`: INIT requires NULLPROC;
  `accept_sec_context` fail is `AUTH_REJECTEDCRED`; DATA without
  context / bad MIC / unknown handle is `CREDPROBLEM`; sequence
  window / `gc_seq > MAXSEQ` is `CTXPROBLEM`; DESTROY then drop;
  unknown `gc_proc` is `AUTH_REJECTEDCRED`; NONE/INTEGRITY/PRIVACY
  accepted. Empty KDC drop is silent of `while dispatching`. kprop
  `e_text` uses MIT `error_message()` including `Ticket expired`.
- **K13.** `kadm5_modify_policy` validates the merged record
  (`BAD_LENGTH` / `BAD_CLASS` / `BAD_HISTORY` / `BAD_MIN_PASS_LIFE`).
  Create is DUP before floors. `pw_expiration` on modify is
  `last_pwd_change + pw_max_life`. `set_keys` clears
  `REQUIRES_PWCHANGE` and `fail_auth_count`. Self keepold is exactly
  5; non-self keepold=1 is unbounded. Purgekeys on a locked-down
  target is allowed. kadmin.local `modpol`/`listpols`/`delpol`.
  `getpol` prints `Allowed key/salt types:` only when
  `allowed_keysalts` is set (`kadmin.c:1808-1809`).
- **K12.** `red-at-sha.sh --inject` copies named HEAD files before
  `write-tree`. `unit_red_at` refuses a call with no files.
  `settle.sh` tees and refuses `grep` of an existing file. Parent
  reds of K3/K5a/K5b/`4031ab7`/`b211cbf` are real failing tests.

### W1-I (K1–K5)

- **K1.** `provenance.sh` stamps every gate; `red-at-sha.sh` overlays
  `scripts/*.sh` before `write-tree`; `rc4-session-gate.sh`; no host
  `/tmp` writes in gates.
- **K2a.** ACL default `<kdc dir>/kadm5.acl`; missing file refuses
  start; empty `acl_file=` is self-only.
- **K2b.** `check_rpcsec_auth` / `check_iprop_rpcsec_auth`; full-resync
  deny is `kdb_fullresync_result_t`.
- **K3.** `parse_name` / `unparse_name` / `deltat::parse` like MIT
  `parse.c` / `unparse.c` / `x-deltat.y`.
- **K4.** `check_min_life`, `clamp_self_keepold`, policy
  `pw_min_life` / `pw_max_life`.
- **K5a.** kpasswd `chpwfail` 60; TCP 1 MiB−4; kprop `recvauth`
  `error_message()` + NUL.
- **K5b.** RPC `PROG_UNAVAIL` / `PROG_MISMATCH`; REPLY keeps the
  connection.

### W1-I Round 2 (K6–K11)

- **K6.** `provenance.sh` dies when docker or the MIT image is absent
  unless `KERBER_NO_IMAGE=1`. `ci-policy` `_HOST_TMP_REDIR` matches
  `cp|tee|mv|mkdir|touch|install … /tmp/` and `>/tmp/` in `$()`.
  `scripts/lib/unit-evidence.sh` / `settle.sh`. `rc4-session-gate.sh`
  echoes the `"key_usage":9` line. Dead `kadmin-gate.sh` host
  `/tmp/kadm5-cc.err` cat removed.
- **K7.** AUTH_GSSAPI-on-iprop INIT/DATA is `AUTH_TOOWEAK`. RPCSEC INIT
  MIC of the sequence window. `check_rpcsec_auth` compares ticket
  realm. IPROP on kadmind 749 stays a ledger `deviation` (MIT
  `PROG_UNAVAIL`, Rust `AUTH_TOOWEAK`). `rpc.flavor=` log.
- **K8.** stub_setup keeps the wire realm (`UNK_PRINC` for
  `user@OTHER.REALM`). GSS client names use `unparse_with_realm`. ACL
  `get_line` strips only `\n` (CRLF `\\\r` is not continuation). Hex
  flags truncate to 32 bits (`str_conv.c:150`).
- **K9.** kadm5 create-policy floors min length/classes/history to 1
  when unspecified (`svr_policy.c`). `kadmin.local addpol` accepts MIT
  flags; `getpol` prints `strdur` layout. kpasswd `result_code=4`.
- **K10.** RPCSEC `AUTH_BADCRED` / `CREDPROBLEM` / `CTXPROBLEM` replies
  instead of dropping the connection; those AUTH_ERROR replies precede
  program match (`svc.c:486-497`). `serve_kadmind` v1 listener
  removed. Empty KDC replies log at `debug`. kprop APPLICATION 14
  ASN.1 fail is KRB-ERROR 60.
- **K11.** Evidence INDEX/summary restamp at the landing SHA.

The **1.1** line is *general-purpose MIT 1.22.2 completeness*: making the KDC
behave like MIT across the board and stand alone as a client toolset. The
roadmap is nine gated phases — **G1** faithfulness (enforce expiration +
principal flags, real `GET_PRIVS`, iprop/kpropd ACLs) · **G2** ticket
renewal + postdating · **G3** full kadmin verbs · **G4** iprop fidelity ·
**G5** GSS breadth (delegation / SPNEGO / IOV) · **G6** client-side preauth +
NT-ENTERPRISE · **G7** standalone user CLIs · **G8** KEYRING ccache · **G9**
config breadth. Each phase lands behind a real-MIT gate before it counts as
done. The entries below are the post-1.0 groundwork already in tree (Tier-1
plugin/policy/propagation parity + the KLLDAP 0.7.5 toolchain alignment).
**G1–G9 have landed** (faithfulness, renewal/postdating, kadmin,
iprop, GSS breadth, client preauth, user CLIs, ccache/KCM, config
breadth). 1.1 is cut after the remaining polish/general pass.

### Added

- **W1-H J1a.** kadm5.acl parse matches MIT `auth_acl.c`: upper-case
  op letters revoke, unknown letters fail the load, `#` only at
  column 0, `\` continuation, realm-less names take the store realm,
  flag aliases/hex (`str_conv.c`), and a readable file is never
  replaced by a full-power default. `Acl::allow_admin` is `Result`.
  Units: `acl_uppercase_letter_revokes`,
  `acl_unknown_op_letter_is_load_error`,
  `acl_file_without_admin_is_not_replaced`, `acl_default_realm_applies`,
  `acl_flag_aliases_parse`, `acl_comment_only_at_column_zero`,
  `acl_backslash_continuation`, `acl_allow_admin_rejects_unparseable`.
  Gate: `scripts/kadmin-gate.sh` `*D` / admin-less / `aZ` both legs.
  Harness `kadm5.acl` lists `admin@KERBER.TEST`, `*/admin@`, and
  `kiprop/*` `p` (the file is the ACL; no fallback).

- **W1-H J1b.** kadm5 ops use MIT ACL bits and denial codes:
  listprincs/listpols `l`/`AUTH_LIST`, addpol `AUTH_ADD`, delpol
  `AUTH_DELETE`, self rules (`auth_self.c`), `AUTH_INITIAL` on
  self-cpw/chrand with a TGS ticket, `get_privs` `~0`, `kadmin.local`
  applies no ACL. Units: `listprincs_inquire_is_auth_list`,
  `listprincs_list_is_ok`, `addpol_denied_is_auth_add`,
  `delpol_denied_is_auth_delete`, `getprinc_self_without_acl_is_ok`,
  `cpw_self_without_initial_is_auth_initial`, `get_privs_is_all_ones`.
  Gate: `scripts/kadmin-gate.sh` list/addpol/self-getprinc both legs.

- **W1-H J1c.** GSS acceptor sname is stored on the context. Non-self
  ops over `kadmin/changepw` are denied (`CHANGEPW_SERVICE`). iprop
  refuses a non-`kiprop` acceptor with RPC `AUTH_TOOWEAK`. Unit:
  `changepw_service_listprincs_is_auth_list`.

- **W1-H skeptic residues.** SPAKE first-round KRB-ERROR **91**
  `e_text` is MIT `PREAUTH_FAILED` (`do_as_req.c:439-442,809`), not
  prose `SPAKE challenge`. Unit:
  `handle_request_spake_91_e_text_is_preauth_failed`. Live both legs
  via `scripts/lib/kdc-error-proxy.py` in `spake-gate.sh` /
  `rust-kinit-spake-gate.sh`. Every kadm5 stub applies
  `CHANGEPW_SERVICE` / `changepw_not_self` like
  `server_stubs.c` (`getstrs`/`purgekeys` deny even self; getprinc
  self and getpol of own policy still allowed). Units:
  `changepw_service_denies_non_self_ops`,
  `changepw_service_self_getprinc_is_ok`,
  `changepw_service_self_getstrs_is_auth_get`,
  `changepw_service_self_purgekeys_is_auth_modify`,
  `changepw_service_own_policy_getpol_is_ok`. Live crafted
  `kadm5-changepw-rpc.c` listprincs is `KADM5_AUTH_LIST` both legs.

- **W1-H J8.** Ledger rust sites are `file.rs symbol` (optional
  `:N` inside the function). `ci-policy.py` `check_ledger_anchors`
  resolves `fn symbol` under `crates/` and, for `exact` rows, checks
  the backticked status word sits in that function. Six I8 rows moved
  to `## A4 — kadmin/server/*.c, lib/kadm5/*`. Recount **244** =
  A1 116 + A2 67 + A3 55 + A4 6 (exact 61 · deviation 91).
  `enc_rc4.c` usage 9 regraded `exact` (J7 live rc4). W1-C prose no
  longer claims W0e `chpwfail` framing.

- **W1-H J5.** `chaos-gate.sh` reads `KERBER_REQUIRE_NETEM=1` and
  dies unless netem was applied; otherwise it skips netem and still
  runs the memory and failover cells. `prod-gate.sh` missing
  tcpdump/sudo is `unavailable` (exit 2) with
  `pcap-unavailable.log`. `stress-gate.sh` no longer uses a no-op
  `mid_rc=0` to appease the detector. `ci-policy.py` treats an arm
  as asserting only on `exit`/`die`/`return`/`break`/`continue`/
  `unavailable`, `log … error`, or `[`/`test`/`grep`/`cmp` — not a
  bare assignment — and inspects `{ … }`, `( … )`, and heredocs.
  `check_ledger_tally` fails when the A1/A2/A3 total line is missing
  or the section split does not match a recount.

- **W1-H J6.** `scripts/red-at-sha.sh` copies `scripts/lib/*.py` and
  the whole `harness/` tree from HEAD into the historical worktree,
  echoes `command=`, stamps `base_sha=` and `tree_sha=` (`git
  write-tree` after the overlay), and prints `gate_rc=`. W0f greens
  recaptured under `working/logs/audit-polish-0902/w1h/` with the
  tested-tree SHA; `i3`/`i4-unit-green` are real runs; `ci-I*.json`
  are raw Actions API bodies; assembled `w0d/e1|e2-live-red-*.log`
  deleted.

- **W1-H J7.** Session key type is `select_session_keytype` /
  `dbentry_supports_enctype`: the server's `session_enctypes` string
  attribute, else AES256-sha1 assumed, else a long-term key;
  `allow_rc4` / `allow_des3` / `permitted_enctypes` from
  `krb5-config`. AS uses krbtgt; TGS uses the service. Ticket
  encryption stays the server long-term key. `insert_password` /
  `addprinc -e` honour `supported_enctypes` including
  `rc4-hmac:normal`. EncTs tries keys of the PA etype (optimistic
  AES ENC-TS on an rc4-only client is `PREAUTH_REQUIRED`, not
  `PREAUTH_FAILED`). ETYPE-INFO2 omits `s2kparams` for rc4. RC4
  `checksum()` is RFC 4757 type -138. Dump reload keeps kdc.conf
  ticket policy. The client parses KDC-issued etypes with `known()`
  so an rc4 session is not `WeakEtypeRefused`. Units:
  `session_enctypes_attr_is_membership_not_client_key`,
  `session_enctypes_rc4_with_allow_rc4_issues_rc4_session`,
  `allow_rc4_false_skips_rc4_session_even_if_requested`,
  `tgs_session_enctypes_attr_is_membership`,
  `insert_password_honours_supported_enctypes_rc4`,
  `reload_if_stale_sees_kadmin_create` (`allow_rc4` survives). Gate:
  `diffsend` `as-session-enctype`; live rc4 both directions
  (MIT `kinit`+`kvno` against Rust = TGS-REP usage 9; Rust
  `krb5-kinit`+`krb5-kvno` against MIT).

- **W1-H J3.** KRB-ERROR `e_text` is the MIT status word
  (`do_as_req.c` / `do_tgs_req.c` / `tgs_policy.c` / `kdc_util.c`).
  `errcode_to_protocol` maps internal codes outside 0..=128 to 60.
  Catch-alls carry the stage word (`PREAUTH_FAILED`, `PROCESS_TGS`,
  `LOOKING_UP_CLIENT`, `UNKNOWN_REASON`) with the message in `detail`.
  `diffsend` compares `error_code` and `e_text`. Units:
  `unknown_client_e_text_is_client_not_found`;
  `krb_error_volatile_only_passes_stable_mismatch_fails` (e_text).
  Gate: `scripts/differential-gate.sh` pins `CLIENT_NOT_FOUND`,
  `BAD_ENCRYPTION_TYPE`, `NEEDED_PREAUTH`, `PREAUTH_FAILED`,
  `SERVER_NOT_FOUND`, `BAD TGS SERVER NAME`.

- **W1-H J4.** Listeners match MIT on malformed input: KDC drops
  empty/undecodable/unknown-tag (`dispatch.c`), UDP oversize is
  `RESPONSE_TOO_BIG` 52, over-long TCP length is `FIELD_TOOLONG` 61,
  kpasswd post-AP-REQ failures answer `chpwfail` (AUTHERROR 3 /
  HARDERROR 2) with no per-listener rcache (`schpw.c:110-111`), kprop
  AP-REQ failure is a KRB-ERROR (`recvauth.c`), kadmind unknown-proc
  is RPC `PROC_UNAVAIL` / truncated XDR `GARBAGE_ARGS` / non-GSS
  `AUTH_TOOWEAK`. Units: `handle_request_empty_is_dropped`,
  `udp_oversize_reply_is_response_too_big`,
  `tcp_oversize_length_is_field_toolong`,
  `kpasswd_bad_ap_req_is_chpwfail_autherror`,
  `kpropd_ap_req_fail_is_krb_error`, `unknown_proc_is_proc_unavail`,
  `truncated_getprinc_is_garbage_args`, `auth_none_is_auth_too_weak`.
  Gates: `differential-gate.sh` `garbage-pdu` both-drop;
  `kpasswd-gate.sh` bad-AP-REQ/retransmit; `kprop-gate.sh` junk
  AP-REQ; `kadmin-gate.sh` AUTH_NONE `AUTH_TOOWEAK`.

- **W1-H J2.** Every checksum is verified by declared type, length,
  and keyed/coll-proof class (`krb5_c_verify_checksum`).
  `verify_checksum` is gone; `verify_checksum_type` is the only
  verifier, with `verify_checksum_keyed` / `verify_checksum_collproof`
  wrappers. Sites: AP-REQ authenticator, KRB-SAFE (`rd_safe.c` dummy
  then body), kprop, GSS wrap-without-conf `EC==cksumsize` and MIC
  fillers/direction/reconstructed header, GSS non-0x8003 over empty
  data and short 0x8003 `BAD_BINDINGS`, PA-FOR-USER (unkeyed 50 /
  bad MAC 41 `INVALID_S4U2SELF_CHECKSUM`), PAC SignatureType
  (SHA-1 server 15, unkeyed 60, MAC 41), client FAST-finished.
  Units: `verify_checksum_type_honours_declared_unkeyed`,
  `verify_checksum_keyed_rejects_unkeyed_declared`,
  `safe_unkeyed_cksumtype_is_inapp`, `wrap_integ_wrong_ec_is_truncated`,
  `verify_mic_bad_filler_is_truncated`, `accept_short_8003_is_channel_bindings`,
  `s4u2self_unkeyed_cksumtype_is_inapp`, `s4u2self_bad_checksum_rejected`
  (41), `pac_sha1_server_checksum_is_sumtype_nosupp`,
  `fast_as_exchange_strengthen_and_finished` (tamper),
  `as_req_enc_pa_rep_is_verified`, `ap_req_checksum_uses_declared_type`.

- **W0f I8.** Ledger header recount 244 = 116+67+61 (exact 54 ·
  deviation 96). AS time/flag anchors are `issue.rs:1697-1734`.
  `diffsend` names in the ORDER/FAST/AD-FX-ARMOR rows are backticked
  `proposed`. New rows: kpasswd pre-AP-REQ drop (`exact`), acceptor/
  KRB-SAFE/GSS declared-cksumtype ignore (W1-B/C `deviation`),
  `kadm5_code` `AclDenied → AUTH_GET` (W1-C `deviation`). F1 is not
  opened.

- **W0f I7.** `scripts/red-at-sha.sh` copies `scripts/lib/*.sh` and
  the gate's `scripts/*.c`/`*.py` from HEAD into the worktree, prints
  the probe sha256, requires an absolute `KERBER_SCRATCH`, and prunes
  the worktree on EXIT. e1/e2 at `6e2d0e4` recaptured verbatim
  (`red-at-sha-e{1,2}.log`). Assembled `e1/e2-live-red-at-6e2d0e4.log`
  deleted.

- **W0f I6.** `ci-policy` joins 2+ `||` / `&&` / `\\` continuations
  without hanging; one-line `if` with ≥2 `elif` sees every arm;
  `echo | tee` / `echo > file` is informational unless the arm also
  asserts. `prod-gate.sh` / `chaos-gate.sh` skip arms assert or
  `unavailable`. `check_ledger_tally` recounts verdict cells against
  the header (241 = 116+67+58; exact 53 · deviation 94).

- **W0f I5.** Malformed kpasswd pre-AP-REQ datagrams (inconsistent
  length, unknown version, truncated) produce no reply, matching MIT
  `schpw.c:62-68,76-82` `goto bailout` and `dispatch`
  `respond(..., NULL)`. The UDP path logs MIT com_err text
  (`Message stream modified` / `Requested protocol version not
  supported`) plus `- while dispatching (udp)` (`net-server.c:1103`).
  Units: `kpasswd_unknown_version_is_bad_version`,
  `kpasswd_inconsistent_length_is_malformed`. Gate:
  `scripts/kpasswd-gate.sh` raw datagram both legs (timeout + pinned
  log; no `hex=` on Rust).

- **W0f I4.** FAST unwrap is decrypt → decode → verify like
  `fast_util.c:191-222`. Every unwrap error including store/`other`
  wires `FIND_FAST`; provider-mismatch detail is MIT `Bad encryption
  type` (`krb5_err.et:254`). Units:
  `fast_as_corrupt_enc_and_bad_checksum_is_bad_integrity` (31
  `FIND_FAST` on a decoded PDU),
  `fast_as_provider_mismatch_detail_is_bad_enctype`. H1/H2 tests also
  assert the decoded `KrbError`.

- **W0f I3.** TGS authenticator checksum provider mismatch and wrong
  MAC length return wire 60 `PROCESS_TGS` like `errcode_to_protocol`
  (`kdc_util.c:130-136,691-697`). Missing checksum keeps 50
  `INAPP_CKSUM` with wire `e_text` `PROCESS_TGS` (`kdc_util.c:232-235`).
  Units assert a decoded `KrbError`:
  `tgs_authenticator_cksum_provider_mismatch_is_generic`,
  `tgs_authenticator_cksum_wrong_length_is_generic`,
  `tgs_authenticator_missing_checksum_is_process_tgs`.

- **W0f I2.** cksumtype `-137` (`MD5_HMAC_ARCFOUR`) is HMAC(raw key,
  MD5(le32(usage) ‖ msg)) with no `signaturekey` KS
  (`checksum_hmac_md5.c:53-66`); `-138` still derives KS. RC4 usage map
  is `3→8, 9→9, 23→13` (`enc_rc4.c:17-35`) in checksum and encryption
  paths. Units: `verify_checksum_type_md5_hmac_rc4_uses_raw_key`,
  `arcfour_usage_9_is_9`. Live: this MIT 1.22.2 image returns
  `KDC has no support for encryption type` for an rc4-only `kinit`
  even with `allow_rc4` and `supported_enctypes` `rc4-hmac:normal`;
  Rust bootstrap has no rc4 long-term keys, so the KDC cannot mint
  rc4 session keys.

- **W0f I1.** kadm5.acl target patterns and restrictions match MIT
  `auth_acl.c`: grammar `<principal> <opstring> [<target>
  [<restrictions>]]`; `*` target is any; `match_princ` same component
  count/realm/`*` and `*N` back-references; first client **and** target
  match; rename is `Delete` on src **and** `Create` on dest **and** that
  add entry has no restrictions; `-clearpolicy`/`-policy`/`-maxlife`/
  `-maxrenewlife`/`-expire`/`-pwexpire`/`+flag`/`-flag` imposed on
  create/modify; unparseable target or unknown restriction is a load
  error (`acl_init`). `*`/`x` still exclude `e`. Settled live: `user*`
  is a literal (`match_data`); `*@REALM` scopes single-component names;
  AUTH_ADD text is `add_principal: Operation requires ``add'' privilege
  while creating "svc/x@KERBER.TEST".`. Units:
  `acl_target_pattern_scopes_add_and_delete`,
  `acl_target_backreference_matches_own_instance`,
  `acl_rename_needs_delete_on_src_and_add_on_dest_without_restrictions`,
  `acl_restriction_clearpolicy_is_imposed`,
  `acl_unknown_restriction_is_load_error`, `acl_target_star_is_any`,
  `kpasswd_acl_c_honours_target_pattern`. Gate: `scripts/kadmin-gate.sh`
  both legs.

- **W0e H8.** Ledger F4 gains `check_anon`/`restrict_anon`,
  `NEEDED_HW_PREAUTH` 25, and admin-unlock; phantom gate cells are
  `proposed` per clause; five real tests are un-`proposed`; armor
  NYV is 33; `validate_as_request` sub-order is a row; lookaside
  stays in F5; oracle lines state `sha256sum -c`. `security.md`
  records hide-client-names / critical FAST options. `docs/testing.md`
  matches `ci-policy` after H4.

- **W0e H7.** kadm5 rename checks ACL before lockdown like
  `rename_principal_2_svc` (`server_stubs.c:700-712`): unauthorised
  rename is `KADM5_AUTH_INSUFFICIENT` (43787525) `Insufficient
  authorization for operation`, not `AUTH_DELETE`. Unit:
  `rename_unauthorised_lockdown_is_auth_insufficient`. Gate:
  `scripts/kadmin-gate.sh` ACL-without-`d` `renprinc krbtgt/KERBER.TEST
  x` both legs.

- **W0e H6.** kpasswd validates the length prefix and version before
  AP-REQ work like `process_chpw_request` (`schpw.c:60-82`). W0f I5
  drops those datagrams like MIT `goto bailout` / `dispatch`
  `respond(..., NULL)` instead of framing a KRB-ERROR. `ChangePasswdData`
  is decoded only for `0xff80` (decode failure is result 1); vno-1 valid
  DER stays a password. Units: `kpasswd_unknown_version_is_bad_version`,
  `kpasswd_inconsistent_length_is_malformed`,
  `kpasswd_vno1_der_stays_password`,
  `kpasswd_setpw_decode_failure_is_malformed`. Gate:
  `scripts/kpasswd-gate.sh` raw datagram both legs.

- **W0e H5.** `scripts/kpasswd-gate.sh` asserts every `helper_rc` and
  that `extra` `addprinc` succeeded. `scripts/red-at-sha.sh` rebuilds
  a historical SHA in a `KERBER_SCRATCH` worktree and writes a
  provenance header (base SHA, worktree, `Compiling`/`Finished`,
  binary SHA-256s). Retroactive e1/e2 reds at `6e2d0e4` are
  `working/logs/audit-polish-0902/w0f/red-at-sha-e{1,2}.log`
  (verbatim `red-at-sha.sh` stdout; W0f I7).

- **W0e H4.** `scripts/ci-policy.py` flags echo-only `then`/`elif`/`else`
  arms independently (mixed `exit`+`echo` chains fail), joins `||` /
  `&&` / `\\` continuations before matching the condition, scans
  `scripts/lib/*.sh`, and treats `"ci.yml"` as path-equality. Ledger
  `proof` `proposed` scopes only the clause it precedes. Historical:
  0 hits on 60 gates at `bafc5f2`; `gss-gate.sh:344` at `a9f0666`;
  `kpasswd-gate.sh:387` at `6e2d0e4`; 0 at HEAD.

- **W0e H3 (unit-red; MIT by source).** TGS authenticator checksum
  grades like `comp_cksum` (`kdc_util.c:112-140`): unknown type 15
  `SUMTYPE_NOSUPP` `PROCESS_TGS`; not collision-proof 50 (1.22.2 sets
  `CKSUM_NOT_COLL_PROOF` on no table row); bad bytes 31
  `BAD_INTEGRITY` `PROCESS_TGS`. Units:
  `tgs_authenticator_unknown_cksumtype_is_sumtype_nosupp`,
  `tgs_authenticator_bad_bytes_is_bad_integrity`. MIT clients cannot
  emit these.

- **W0e H2 (unit-red; MIT by source).** Keyed checksum types match by
  enc provider like `verify_key` (`crypto_int.h:596-608`). `-138`
  HMAC-MD5-ARCFOUR has NULL enc (any key); `-137` is arcfour.
  Types 15/19 share aes128; 16/20 share aes256. `cksumtype` 0
  substitutes the key's mandatory type, then FAST `is_keyed(0)` is
  12 `FIND_FAST`. Units: `fast_as_arcfour_hmac_type_over_aes_key_wrong_bytes_is_modified`,
  `fast_as_same_provider_type_wrong_bytes_is_modified`,
  `fast_as_cross_provider_type_is_generic`,
  `fast_as_cksumtype_zero_valid_mac_is_policy`. MIT clients cannot
  emit these.

- **W0e H1 (MIT-gated).** FAST unwrap `Error::Crypto` / `Error::Asn1`
  (corrupt `enc_fast_req`, malformed `KrbFastReq`) wire `FIND_FAST`
  with protocol 31 / 60 (`do_as_req.c:531-535`,
  `errcode_to_protocol` `kdc_util.c:691-698`). `kdc.issue` `detail`
  is carried on `Error::Protocol` (no thread-local); empty `detail`
  is omitted. MIT-leg pin `FIND_FAST: .*while handling ap-request
  armor`. Units: `fast_as_corrupt_enc_fast_req_is_bad_integrity_find_fast`,
  `fast_as_malformed_krbfastreq_is_generic_find_fast`,
  `fast_tgs_corrupt_enc_fast_req_is_bad_integrity_find_fast`. Gate:
  `scripts/mit-fast-kdc-gate.sh`.

- **W0d G5.** `docs/mit-parity-ledger.md` is the W1-A KDC parity
  ledger with Part 0 applied: wire codes (`CLIENT EXPIRED` 1,
  `SERVICE EXPIRED` 2, req-body checksum 31, `MORE_PREAUTH` 91,
  FAST option 93), FAST wire `e_text` `FIND_FAST` after G3, honest
  `proposed` proofs, 28 additions (AD-FX-ARMOR, `get_ticket_flags`,
  TCP `FIELD_TOOLONG` 61, lockout last, …), and the ranked F-batches
  recut from the verification reports. `docs/testing.md` records
  wire-e_text vs log-detail and scripted retroactive-red.
  `scripts/ci-policy.py` checks the ledger `proof` column.

- **W0d G4.** `scripts/ci-policy.py` flags echo-only `if`/`elif`/`else`
  of any shape (not only `if !`), strips quoted strings before token
  matching, pairs `fi` by depth, and bans per-push `cargo test --all`.
  Detector: 0 hits on 60 gates at `bafc5f2`; flags `gss-gate.sh` at
  `a9f0666` and `kpasswd-gate.sh` at `6e2d0e4`. `__pycache__/` is
  gitignored.

- **W0d G3 (MIT-gated).** FAST unwrap failures put MIT's status word
  `FIND_FAST` on the wire `e_text` (`do_as_req.c:806`,
  `do_tgs_req.c:205-206`). The descriptive `k5_setmsg` text is the
  `kdc.issue` `detail` field, not the wire. Gates:
  `mit-fast-kdc-gate.sh`, `rust-kinit-fast-gate.sh`.

- **W0d G2 (unit-red; MIT by source).** `verify_checksum` dispatches on
  the claimed cksumtype like `krb5_c_verify_checksum`
  (`verify_checksum.c:46-79`). Unknown type and `output_size` length
  mismatch are 60 `GENERIC` `FIND_FAST`. Unkeyed set is MIT
  `cksumtypes.c` `{2,7,9,14}` (CRC32 is not unkeyed). Units:
  `fast_as_crc32_checksum_is_generic`, `fast_as_short_mac_is_generic`,
  `fast_as_rsa_md5_unkeyed_is_policy`. MIT clients cannot emit these.

- **W0d G1 (MIT-gated).** kpasswd orders checks like
  `schpw_util_wrapper` (`misc.c:33-54`): principal compare first,
  non-INITIAL self → 7, unprivileged other principal → 5
  `Unauthorized request`, privileged foreign-realm target → 2 with
  the `chpass_util` two-line text. RFC 3244 kadmind log is
  `setpw request from 127.0.0.1 by user@KERBER.TEST for
  user@KERBER.TEST: Operation requires initial ticket`. Units:
  `kpasswd_foreign_self_change_needs_initial`,
  `kpasswd_unprivileged_other_principal_is_accessdenied`,
  `modprinc_keeping_lockdown_bit_is_allowed`. Gate:
  `scripts/kpasswd-gate.sh`. Purgekeys on a locked-down principal
  is refused (stricter); MIT succeeds.

- **W0b D5 (MIT-gated).** Forged-realm FAST TGS (`krb5-forge-tgt
  --keep-cipher --claim-realm` then `kvno`) is 7 `PROCESS_TGS` on both
  KDCs; MIT log `UNKNOWN SERVER: server='krbtgt/KERBER.TEST@FORGED.EXAMPLE'`;
  client `Server host/testhost.kerber.test@KERBER.TEST not found in
  Kerberos database` verbatim. Units:
  `tgs_fast_forged_ticket_realm_is_process_tgs`. Gate:
  `scripts/mit-fast-kdc-gate.sh`.

- **W0b D4 (MIT-gated).** MIT GSS acceptor replay is KRB-ERROR 34
  (`Request is a replay`). Rust grep is
  `accept_sec_context: KRB-ERROR 34: authenticator replay`. Gate:
  `scripts/gss-gate.sh`. MIT `dfl` persistence across restart is W1-C.

- **W0b D3 (unit-red; MIT by source).** A bad FAST `req_checksum` is 41
  `MODIFIED` wire `FIND_FAST`; MIT log message `FAST req_checksum
  invalid; request modified` (`fast_util.c:207-224`). An unkeyed
  checksum type is 12 (MIT log `Unkeyed checksum used in fast_req`).
  Unknown armor type is 24 (MIT log `Unknown FAST armor type %d`).
  The AS checksum covers the outer `KDC-REQ-BODY` only (`do_as_req.c`).
  TGS authenticator client ≠ ticket client is 36 `PROCESS_TGS`
  (`rd_req_dec.c`). MIT clients cannot emit these; live FAST gates
  stay green. Wire `e_text` is the status word as of W0d G3.

- **W0c E4.** `scripts/ci-policy.py` rejects echo-only `if !` bodies in
  gate scripts, requires `--profile ci` on every `cargo nextest run`,
  forbids per-push `cargo test --workspace`, and ratchets the
  `--no-run` + junit upload. `_self_test` has a negative fixture per
  rule. The red-at-HEAD artefact contract is in `docs/testing.md`
  (CI cannot read `working/`).

- **W0c E3 (unit-red; MIT by source).** AS FAST `req_checksum` binds the
  wire KDC-REQ-BODY (`do_as_req.c:526-531`); a re-encode is used only
  when no raw packet exists. Verify runs before keyedness
  (`fast_util.c:207-224`): unkeyed type with bad bytes is 41
  `MODIFIED` `FIND_FAST`; unknown cksumtype is 60 `GENERIC` `FIND_FAST`.
  MIT clients cannot emit these. Gates: `mit-fast-kdc-gate.sh`,
  `rust-kinit-fast-gate.sh`.

- **W0c E2 (MIT-gated).** Bootstrap sets `LOCKDOWN_KEYS` on krbtgt
  (`kdb5_create.c:465`; dump `8388608`) and K/M (`8388672` =
  `DISALLOW_ALL_TIX|LOCKDOWN_KEYS`). Remote delete/modify-clearing-the-bit/
  rename of a locked-down principal are MIT privilege codes; chpass/
  extract/setkey remap from `PROTECT_KEYS` to `AUTH_CHANGEPW` /
  `AUTH_EXTRACT` / `AUTH_SETKEY`. Purgekeys stays `PROTECT_KEYS`
  (stricter). Gate: `scripts/kadmin-gate.sh`.

- **W0c E1 (MIT-gated).** kpasswd self-change compares the RFC 3244
  target to the ticket client like `krb5_principal_compare` (components
  + realm, name type ignored). A TGS-obtained ticket with
  `targname` type 0 is still result 7. A foreign `targrealm` is 2
  `HARDERROR` `Principal does not exist`. TGS authenticator vs ticket
  client includes realm (36 `PROCESS_TGS`). Gate:
  `scripts/kpasswd-gate.sh` `KPASSWD_TARGNAME_TYPE=0`. MIT kadmind log
  `chpw request from 127.0.0.1 for user@KERBER.TEST: Operation requires
  initial ticket`.

- **W0b D2 (MIT-gated).** kpasswd self-change without `INITIAL` is
  RFC 3244 result 7 (`Ticket must be derived from a password`, MIT
  `misc.c` / `schpw.c`). Admin-style changes (target ≠ client) ignore
  INITIAL. `min_life` stays W1. Gate: `scripts/kpasswd-gate.sh`
  `kpasswd-tgs-client.c` after `+allow_tgs_req`.

- **W0b D1 (MIT-gated).** `kadmin/admin` and `kadmin/changepw` bootstrap
  with MIT `kadm5_create` attributes (`DISALLOW_TGT_BASED|LOCKDOWN_KEYS`;
  changepw also `PWCHANGE_SERVICE`). A TGT-based TGS is 12
  `TGT BASED NOT ALLOWED`. MIT `kvno` prints `KDC policy rejects request
  while getting credentials for kadmin/changepw@KERBER.TEST` (verbatim
  on the Rust KDC). Remote `ktadd -norandkey` is `extract-keys`.
  Create-time name special-casing stays `PWCHANGE_SERVICE` only.
  Gate: `scripts/kpasswd-gate.sh`.

- **W0 C9.** Changelog X2 foreign `body.realm` is 60 `GET_LOCAL_TGT`
  (Y1), not 7 `LOOKING_UP_SERVER`. `docs/stages.md`, interop matrix,
  README G5–G9, and `docs/logging.md` `code`/`e_text` rows match the
  landed W0 gates.

- **W0 C8 (MIT-gated).** kpasswd policy/ACL rejection is a KRB-PRIV
  result (`[0,4]` `SOFTERROR`, `[0,5]` `ACCESSDENIED`, else `[0,2]`
  `HARDERROR`) instead of dropping the datagram. Gate:
  `scripts/kpasswd-gate.sh` `-minlength 8` vs Rust and MIT kadmind.

- **W0 C7 (knob hygiene).** `krb5-kvno --renew` without `--body-realm`
  is exit 2 (MIT `kvno` has no renew; `kinit -R` is `renew-gate.sh`).
  `-U` binds `body.realm` to the presented TGT and refuses a missing
  dest TGT instead of a foreign `body.realm`. Gate: C1's `-U` cell.

- **W0 C6 (MIT-gated).** Referral chase rejects a hop back to the start
  realm and a repeated realm (`ReplyMismatch`); hop cap is 10
  (`KRB5_REFERRAL_MAXHOPS`). Asked-for path TGTs are stored (MIT `kvno`
  keeps `krbtgt/C.TEST@B.TEST`, not an unasked `krbtgt/B.TEST@A.TEST`).
  Gate: `scripts/capaths-transit-gate.sh` bare-A-TGT `klist`.

- **W0 C5 (MIT-gated, test-gap).** Local and cross krbtgt `DISALLOW_SVR`
  / `DISALLOW_ALL_TIX` are 7 `PROCESS_TGS` on the presented-TGT decrypt
  (`kdc_get_server_key`). `--test-realm` honours
  `KRB5_TEST_DISALLOW_TIX` / `KRB5_TEST_DISALLOW_SVR`. Gate:
  `scripts/capaths-transit-gate.sh` MIT C `modprinc -allow_tix` and
  Rust C restart.

- **W0 C4 (MIT-gated).** GSS `accept_sec_context` shares one acceptor
  `ReplayCache` across calls (MIT cred rcache). A captured AP-REQ is 34
  `REPEAT` (`authenticator replay`). Gate: `scripts/gss-gate.sh`
  replayed AP-REQ vs Rust acceptor. MIT rejects the replayed AP-REQ
  with KRB-ERROR 34 (equality cell).

- **W0 C3 (MIT-gated).** Explicit FAST armor looks up the armor ticket
  by (`ticket.realm`, sname) first like MIT `rd_req`: foreign/missing
  is 35 `NOT_US` wire `FIND_FAST` (log `detail` `FAST armor TGT`); a
  local non-krbtgt armor is 26 `SERVER_NOMATCH`. `krb5-forge-tgt
  --keep-cipher` rewrites only DER `ticket.realm` so MIT `kinit -T`
  still selects the armor cred. Gate: `scripts/mit-fast-kdc-gate.sh`
  forged `kinit -T` vs MIT and Rust.

- **G9 Y4/Y5.** FAST armor decrypt selects keys by the armor ticket's
  realm. After the presented-TGT krbtgt entry is selected, `DISALLOW_SVR`
  or `DISALLOW_ALL_TIX` is 7 `PROCESS_TGS` (`kdc_util.c:390-393`).

- **W0 C2 (MIT-gated).** TGS FAST armor is derived from the PA-TGS-REQ
  decrypt after `PROCESS_TGS` (`kdc_find_fast`): `cf2(subkey,
  "subkeyarmor", session, "ticketarmor")`. Explicit AP-REQ armor on a
  TGS-REQ is 24 `PREAUTH_FAILED`; FAST TGS without an authenticator
  subkey is 24. Forged `ticket.realm` on a FAST TGS is 7 `PROCESS_TGS`
  (not a second armor decrypt;
  `tgs_fast_forged_ticket_realm_is_process_tgs`). Gate:
  `scripts/mit-fast-kdc-gate.sh` FAST TGS cell.

- **G9 Y3 (MIT-gated).** A peer-minted TGT for a *local* user
  (`crealm` local, header TGT realm foreign, not S4U2Self) is 12
  `INVALID LINEAGE` for both `reject_bad_transit` values (MIT
  `check_tgs_lineage`). Gate: `scripts/capaths-transit-gate.sh`
  `--claim-crealm` cells.

- **G9 Y2.** Non-ASCII `ticket.realm` on a presented TGT is 7
  `PROCESS_TGS` (`PrincipalName::try_new`), not a per-request panic.

- **G9 Y1 KDC (MIT-gated).** TGS `body.realm` must be the served realm
  (`get_local_tgt`): otherwise 60 `GET_LOCAL_TGT` for every option set,
  including destination RENEW/VALIDATE. The Rust-only foreign-realm
  referral and the renew/validate carve-out are gone. Gate:
  `scripts/capaths-transit-gate.sh` GARBAGE equality + dest-RENEW.

- **G9 Y1 client (MIT-gated).** TGS chase asks the *current* TGT's
  realm for `krbtgt/<next>` with `body.realm` = that realm (MIT
  `make_request_for_tgt` / `k5_client_realm_path`: dest first, then
  closer `[capaths]` hops; a closer-hop `krbtgt` reply is accepted).
  `krb5-kvno` / `kinit -S` no longer send a foreign `body.realm` to
  the first hop. `--body-realm` is gate-only so GARBAGE cells can
  still present `GET_LOCAL_TGT`. Gate: bare A TGT → `krb5-kvno
  host/svc.c.test@C.TEST` vs three MIT KDCs.

- **G9 Y0 (MIT KDC + client gated).** S4U2Self requires the requested
  server to be the TGT client's DB entry *and* realm
  (`is_client_db_alias` / `check_tgs_s4u2self`): a foreign impersonator
  whose name collides with a local principal is 36
  `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH`. Referral TGTs name the
  header client. `FORWARDABLE` is kept only with
  `+ok_to_auth_as_delegate`. Gates: `scripts/s4u-mit-gate.sh` (MIT +
  Rust mismatch legs) and `scripts/capaths-transit-gate.sh` (cross-TGT
  colliding-name cell).

- **G9 X3.** Add-path hop emission is `push_hop`-capped; no-append
  inbound ≥ 500 is 43. Anonymous crealm skips transited parse.
  `kdc.issue` `krb-error` lines are `info` and carry `duration_us`.
  Transited fuzz seeds are `crealm\\0srealm\\0contents`.

- **G9 X2 (superseded by Y1).** TGS server lookup is by full principal
  like MIT `search_sprinc`: a local sname is served only when
  `body.realm` equals the KDC realm. A foreign `body.realm` is 60
  `GET_LOCAL_TGT` (Y1), not 7 `LOOKING_UP_SERVER`. Hierarchical walks
  of a ≥512-byte realm return empty. Non-UTF-8 realm is `GENERIC`.
  Gate: `scripts/capaths-transit-gate.sh` GARBAGE.EXAMPLE cells.

- **G9 X1 (MIT-gated).** Presented TGS-TGT decryption is bound to
  `ticket.realm` like MIT `kdc_get_server_key`: local `krbtgt/<local>`
  keys only when the ticket realm is local; that peer's interrealm
  keys when it is a known foreign realm; unknown realm is 7
  `PROCESS_TGS`; bound-key decrypt failure is 31 `PROCESS_TGS`. Gate:
  `scripts/capaths-transit-gate.sh` forge cells.

- **G9 W-pass (MIT-gated).** Emitted hops capped at 4096
  (`TooManyFields`, STRICTER than MIT). Rejected requests log
  `kdc.issue` `outcome=krb-error` with `code` and `e_text`. Add-path
  tokenizer matches MIT `MAX_REALM_LN` (499 raw / 498 joined / 499
  total). `v1.0.0` AS emitted `tr_type` 0; a 1.0-minted TGT
  forwarded by a 1.0 intermediate gets 17 at a 1.1/MIT final hop.

- **G9 V-pass (MIT-gated).** Transited expansion errors out of band
  (raw ≤ 511 / joined ≤ 512; lone NUL is the empty list); null
  subfields match MIT `process_intermediates`; skip-bit POLICY
  e-text is `BAD_TRANSIT`.

- **G9 U-pass U1 (MIT-gated).** Default `reject_bad_transit` rejects
  TGS `DISABLE_TRANSITED_CHECK` as `KDC_ERR_POLICY` (12, `KDC policy
  rejects request`), matching MIT 1.22.2 `do_tgs_req`. RENEW/VALIDATE
  of a ticket that already has `T` still inherit it.
  `krb5-kvno --disable-transited-check` is the bit-26 client (MIT
  `kvno` cannot set the bit). `krb5-kvno` targets the service
  realm's KDC when that TGT is cached (MIT-like). Gate:
  `scripts/capaths-transit-gate.sh`.

- **G9 U-pass U2 (MIT-gated).** DOMAIN-X500-COMPRESS joins on the
  unescaped field (MIT `chk_trans.c` `maybe_join`): `X.COM,C\.` →
  `X.COM,C.X.COM`. Honest `EX.COM,B.` is unchanged. Comma cap stays.

- **G9 U-pass U4 (MIT-gated).** Raw transited field ≥ 512 unescaped
  bytes or joined component > 512 is an expansion error (MIT
  `MAXLEN`: 511 raw / 512 joined still expand).

- **G9 T-pass (MIT-gated).** More than 256 commas is
  `TooManyFields` (Rust-STRICTER; MIT has no field-count cap). Gate:
  `scripts/capaths-compress-gate.sh`.

- **G9 S-pass (MIT-gated).** A present file whose nested `include`
  names a missing target is an error even on colon-split
  `KRB5_CONFIG` merge; a missing top-level path still skips.
  DOMAIN-X500-COMPRESS decode expands MIT `EX.COM,B.` to
  `EX.COM,B.EX.COM`. `[capaths]` space-separated intermediates are
  distinct hops. FAST nopreauth asserts aes256-sha2 / etype 20.
  `reject_bad_transit = false` accepts a failed check without `T`.
  Indented `include` inside a section is Improper format; an
  unterminated `%{` in `default_ccache_name` fails closed.

- **G9a include/includedir (MIT-gated).** Top-level `include` /
  `includedir` and colon-split `KRB5_CONFIG` merge into one
  `Krb5Conf` (MIT first-wins scalars, appended `kdc=`). `includedir`
  reads `*.conf` (including `10.conf`) and alnum/`-`/`_` names, skips
  dotfiles; include cycles and missing includes error. `/etc/krb5.conf.d`
  is not invented. Gate: `scripts/config-include-gate.sh`.

- **G9d + P-pass carry-forwards (MIT-gated).** `[domain_realm]`
  longest-suffix host→realm on `kvno`; conf `proxiable` like
  `forwardable`, and TGS copies `P` from the TGT so `kvno` host
  tickets are `PT` like MIT. FAST no-`+requires_preauth` SHA-2 leg on
  `rust-kinit-fast-gate.sh`. KCM `GET_CRED_LIST` length uses
  saturating remaining-bytes. KCM oracle runs as in-container root
  (sssd_kcm `/var/lib/sss/secrets`), documented.

- **G9c `[capaths]` transit (MIT-gated).** Incoming foreign-crealm
  TGS checks transited hops against `[capaths]` (`.` = direct) or
  hierarchical derivation; `TRANSITED_POLICY_CHECKED` only on pass;
  unpermitted hop is `KDC_ERR_POLICY` (12), matching live MIT 1.22.2.
  Issued transited encoding matches MIT 1.22.2 `add_to_transited`
  (previous hop, `tr-type` 1, contents `B.TEST` on A→B→C). Gate:
  `scripts/capaths-transit-gate.sh`.

- **G9b default_ccache_name (MIT-gated).** `KRB5CCNAME` beats
  `[libdefaults] default_ccache_name` beats builtin
  `FILE:/tmp/krb5cc_%{uid}`. Conf values expand `%{uid}` / `%{USERID}`
  / `%{euid}` (and `%{null}` / `%{TEMP}` / `%{username}`); unknown
  tokens fail closed. Env and `-c` are not expanded (MIT). Folded into
  `scripts/knobs-gate.sh`.

- **G1 faithfulness (MIT-gated).** AS/TGS enforce stored principal
  expiration (`KDC_ERR_NAME_EXP`) before password/key expiration
  (`KDC_ERR_KEY_EXPIRED`); 0 still means never; `PWCHANGE_SERVICE`
  (`kadmin/changepw`) still issues to a password-expired client
  (`scripts/expire-gate.sh`). Stored KDB flags are honored at issue
  time: `DISALLOW_*` (ALL_TIX / SVR / TGT_BASED / FORWARDABLE /
  RENEWABLE / PROXIABLE / POSTDATED), `OK_AS_DELEGATE`,
  `REQUIRES_HW_AUTH`, `NO_AUTH_DATA_REQUIRED`
  (`scripts/flags-gate.sh`). kadmind `GET_PRIVS` is the actor's ACL
  mask, not constant `0x3F` (`scripts/getprivs-gate.sh`). iprop
  GET_UPDATES/FULL_RESYNC require `p`; kpropd matches the AP-REQ
  client against `KRB5_KPROP_ACL` (unset or empty is deny-all;
  `scripts/prop-acl-gate.sh`). TGS does not re-check client
  expiration. TGS `DISALLOW_RENEWABLE` strips, not `POLICY`.
  Lockout `DISALLOW_ALL_TIX` → `CLIENT_REVOKED` is unchanged.
  `EncKdcRepPart.key_expiration` stays `None`.

- **G2 renewal and postdating (MIT-gated).** `kinit -R` copies
  `renew-till`, sets `starttime=now`, and caps the new lifetime by
  the presented ticket (`scripts/renew-gate.sh`). `DISALLOW_RENEWABLE`
  on renew strips `R` (a second `-R` is then `BADOPTION`). `kinit -p`
  sets `P`. `kinit -s` issues `INVALID`+`POSTDATED`; `kvno` is
  `TKT_NYV` until `kinit -v` (`scripts/postdate-gate.sh`).
  `DISALLOW_POSTDATED` is `CANNOT_POSTDATE`. `RENEWABLE_OK` is still
  accepted and ignored (G2c).

- **G3 kadmin completeness (MIT-gated).** `GET_PRINCIPAL` returns key
  metadata (`Number of keys` / `Key: vno N`; MIT 1.22.2 has no
  `getprinc -keys`). `EXTRACT_KEYS` (op 26) plus ACL `e` unblocks
  `ktadd -norandkey` then `kinit -k`; MIT `*`/`x` do not include `e`.
  `PURGEKEYS` (op 22) drops old kvnos. SETKEY ops 16/21/25 (no MIT
  `kadmin setkey` verb; unit-tested). `GET_STRINGS`/`SET_STRING` plus
  dump `KRB5_TL_STRING_ATTRS`. Unknown kadm5 procs return
  `KADM5_FAILURE`, not `7`. `LOCKDOWN_KEYS` refuses extract/purge/setkey/
  chpass; chrand still rotates but returns no key bytes (MIT `ktadd`
  must not leak).
  Gate: `scripts/kadmin-gate.sh`.

- **G4 iprop fidelity (MIT-gated).** Incremental kdbe encode/decode
  carry lockout, policy, `TL_STRING_ATTRS` (0x000b), and `AT_PW_HIST`.
  Replica apply merges partial MIT updates so a later `setstr` does
  not wipe keys. Ulog serial+entries persist next to the dump
  (`principal.ulog`) and reload after master restart, so the next
  replica poll stays incremental. Local `--export-keytab` /
  `--export-krbtgt-keytab` bypass `LOCKDOWN_KEYS` (MIT flags krbtgt
  lockdown by default); remote extract still refuses. Gate:
  `scripts/iprop-gate.sh` (string-attrs on extra2; master restart
  then incremental extra, no extra FULL_RESYNC). `scripts/differential-gate.sh` is green
  again. SETKEY4 is MIT `xdr_kadm5_key_data`. `getprinc` lists
  current keys only.

- **G1–G4 consolidation (MIT-gated).** S4U2Self looks up the
  impersonated for-user (missing `C_PRINCIPAL_UNKNOWN`,
  `DISALLOW_ALL_TIX` `CLIENT_REVOKED`, expired `NAME_EXP`). Iprop
  decode caps hostile XDR counts. `+needchange` /
  `REQUIRES_PWCHANGE` is `KEY_EXPIRED` except `PWCHANGE_SERVICE`.
  Incremental kdbe omits vendor `0x4B0x` TL. Keepold key_data is
  separate from OSA password history (EXTRACT / getprinc /
  `cpw -keepold`). getprinc dates come from stored TL. CHRAND
  denial is `AUTH_CHANGEPW`. Renewal rejects `renew_till <= now`.
  Keyless incremental apply keeps replica keys. Gates:
  `s4u-mit-gate`, `expire-gate`, `kadmin-gate`.

- **G5 GSS breadth (in progress).** Replica incremental apply
  allocates a RID when kdbe has none, so a new principal's PAC is
  not RID 1000 (`scripts/iprop-gate.sh`). `cpw -randkey` / setkey
  stamp last-password-change and last-modified (`scripts/kadmin-gate.sh`).
  GSS `GSS_C_DELEG_FLAG` carries a 0x8003 KRB-CRED trailer; the acceptor
  bound-checks `Dlgth`. SPNEGO `NegTokenResp` carries `mechListMIC`.
  AES/RFC 8009 `wrap_iov`/`unwrap_iov` slice CFX wrap tokens
  (HEADER|DATA|empty PADDING|TRAILER, RRC=0); `SIGN_ONLY` is in the
  integrity HMAC. `export_sec_context`/`import_sec_context` round-trip
  wrap; `inquire_context` reports ticket lifetime and GSS flags
  (`scripts/gss-gate.sh`). A delegated KRB-CRED must decrypt under the
  ticket session key (or authenticator subkey); a plaintext
  EncKrbCredPart trailer is `Integrity`. SPNEGO accept requires the
  krb5 OID in `MechTypeList`. Wrap/MIC verify integrity before
  advancing the GSS sequence window. Replica incremental PAC RID is
  still allocated locally (≠ 1000); matching the master's RID is
  deferred because MIT kdbe has no SID and F4 keeps vendor `0x4B0x`
  TL off the incremental wire. Delegated KRB-CRED uses the accept
  replay cache; RFC 8009 IOV verifies Ki HMAC before CTS decrypt;
  no-AD `unwrap_iov` is AES-only; SPNEGO duplicate NegToken fields
  are `Truncated`; `krb5-gss-accept` sets a 30s socket timeout.
  Rust `kinit --spake` obtains a TGT from MIT 1.22.2 via PA-SPAKE
  151 / P-256 (`scripts/rust-kinit-spake-gate.sh`). `kinit --fast
  --armor-ccache` wraps PA-ENC-TIMESTAMP in PA-FX-FAST
  (`scripts/rust-kinit-fast-gate.sh`). `kinit --pkinit FILE:` obtains
  a TGT via PA-PK-AS-REQ (`scripts/rust-kinit-pkinit-gate.sh`).
  `kinit -E` / NT-ENTERPRISE (name-type 10) canonicalizes to the stored
  principal (`scripts/rust-kinit-enterprise-gate.sh`). PKINIT client
  verifies the KDC CMS signer is `id-pkinit-KPKdc` with SAN
  `krbtgt/REALM@REALM` before ECDH; a CA-issued client cert cannot
  impersonate the KDC. The KDC binds client SAN to the AS-REQ cname
  and requires `id-pkinit-KPClientAuth`. CMS path validation checks
  leaf validity, CA `basicConstraints`, and issuer DN. KDC-reply
  `eContentType` is `id-pkinit-DHKeyData`. SPAKE is fail-closed when
  requested. `unwrap_iov` integrity is AES-only. Enterprise suffixes
  that are not the local realm are not aliases.

- KDB extension surface: `PrincipalRead` / `PrincipalWrite` /
  `StoreLifecycle`. Dump-v7 is the default backend; `db_library=memory`
  serves `MemoryStore` seeded from dump (`scripts/store-gate.sh`).
  Kadmind mutation on `&mut dyn Store` is still deferred. kdcpreauth:
  PKINIT, SPAKE, and enc-timestamp `process_as` (no double-verify;
  first module to return an action wins; EncTsOk short-circuits EXTRA
  on a normal login; observe-every-AS is a future kadm5_hook).
  `KdcPolicy::check_as` / `check_tgs` can deny (`DenyPolicy`);
  `set_policy` is process-wide (serve threads); tests use
  `set_thread_policy`. AS lockout stays a mandatory inline gate.
  Named policies: five password classes; `pw_failcnt_interval` /
  `pw_lockout_duration`; history depth N (current counts inside N;
  store N-1 old kvnos; `keepold=false`, `TL_KERBER_HIST` 0x4B04).
  Lockout overlay is reload-safe and **memory-only across a full KDC
  restart**. Iprop serial + ulog; kadmind program 100423; password
  history on full-resync dump and incremental iprop (`AT_PW_HIST`).
  Gates:
  `policy-gate.sh` (MIT `cpw` too-short/reuse/minclasses-5/history-N,
  maxfailure-2, lockout duration/interval), `store-gate.sh`,
  `kdb-dump-gate.sh`, `iprop-gate.sh`. Traits, not dlopen:
  [`docs/plugins.md`](docs/plugins.md).

### Changed

- `krb5-kvno` obtains a service ticket via TGS (no `-U`/`-P`).
  `krb5-ktutil` rkt/list(`-t`/`-K`)/wkt/addent/delent. Gates:
  `client-gate.sh` (kvno) and `scripts/ktutil-gate.sh` (MIT `ktadd`
  list + Rust keytab `kinit -k`).

- `krb5-kadmin-local` (Cargo bin; MIT `kadmin.local`) mutates dump
  + stash; no-`@` specs go through `parse_principal` with the store
  realm so `host/foo` is `NT_SRV_INST`. MIT `kadmin` getprinc/listprincs
  is the oracle (`scripts/kadmin-local-gate.sh`, including
  `host/slashhost`). `krb5-kpasswd` is RFC 3244
  TCP-464 first; the AS-REQ sname is `kadmin/changepw` because MIT
  flags that principal `DISALLOW_TGT_BASED`. Gates: Rust kpasswd
  vs Rust kadmind (`kpasswd-gate.sh`) and vs MIT kadmind
  (`scripts/rust-kpasswd-mit-gate.sh`); new-password `kinit`
  succeeds and the old password fails.

- CLI unit coverage: klist `fmt_unix`, `parse_kadmin_args`,
  `parse_ccname`, `parse_kpasswd_rep`. `ktutil-gate` compares
  kvno and etype (timestamp compare is G8b). `client-gate` emits `log()` + `exit 0`.
  Samba/AD `docker run` error logs write under `KERBER_SCRATCH`, not
  host `/tmp`. `-c` without a value is an error; non-`FILE:` ccache
  types return MIT `Unknown credential cache type` (no FILE fallback).

- **G8a FILE fidelity (MIT-gated).** FILE v4 marshal is lossless
  (`is_skey`, addresses, authdata, `second_ticket`, `FCC_TAG_DELTATIME`,
  etype-0 `X-CACHECONF`). `delete_cred` writes MIT tombstones
  (`endtime = 0`, `authtime = -1`, config realm `X-RMED-CONF:`);
  readers skip them. `FILE`, `MEMORY` (process-global), and `DIR`
  (`primary` / `tkt` / `DIR::` / `kswitch`) resolve; `KEYRING:` stays
  unknown. `KCM:` is G8c (sssd-kcm). Unknown critical FAST options
  are RFC bits 0 and 2–15. Gate: `scripts/ccache-gate.sh`.

- **G8b (in progress).** FAST `hide-client-names` (bit 1) is
  `KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION` rather than a silent
  cleartext-cname issue. DIR collections init on store, not resolve.
  FILE principal/realm identity is ASCII GeneralString. Committed MIT
  `kinit -a` + u2u FILE golden (`tests/traces/ccache-mit-addr-u2u.bin`)
  identity-checks addresses, authdata, and `second_ticket`.
  `kinit`/`klist`/`kvno`/`kdestroy` parse getopt-clustered shorts
  (`kinit -kt` is keytab mode). `kinit -E` keeps the first `@` in the
  UPN (MIT parse.c); MIT db2 has no UPN alias so `-E user@REALM` is
  `CLIENT_NOT_FOUND`. `klist -s` follows MIT `klist.c`
  `check_ccache`. Password-on-stdin strips a trailing newline.
  Fleet knobs: `udp_preference_limit`, etype lists, `forwardable`,
  lifetimes, dns-lookup flags are parsed; Heimdal `kdc_timeout` /
  `max_retries` are stored and ignored. Ticket renew time is the min
  of request, krbtgt entry, client entry, and kdc.conf realm
  `max_renewable_life` when set. New principals copy the 7d policy
  onto `max_renewable_life`. `kit-conformance-gate` /
  `gssproxy-gate` / `nfs-krb5p-gate` / `sssd-renew-gate` honest
  **exit 2** until those oracles are vendored. FILE write stays
  temp+rename.

- **G8c KCM client (sssd-kcm-gated).** `KCM:` is a unix-socket ccache
  (`GET_CRED_LIST`; `INITIALIZE`+`STORE` because Fedora `sssd-kcm`
  2.12/2.11 returns `KRB5_FCC_INTERNAL` for `RETRIEVE`/`REPLACE`).
  `scripts/kcm-gate.sh` asserts MIT 1.22.2 `klist` principal names,
  `kswitch`, restart persist, re-prime, `kdestroy`. `KEYRING:` stays
  unknown. NFS/gssproxy/kit cells honest exit 2; fleet default stays
  FILE (`docs/kcm-nfs-verdict.md`).

- **G8 P-pass FAST SHA-2 client (MIT-gated).** `kinit --fast` derives
  the FAST reply-key base from PA-ETYPE-INFO2 (RFC 6113 / RFC 8009
  etype 20), not `preferred()[0]` (aes256-sha1).
  `scripts/rust-kinit-fast-gate.sh` is fail-red on `mit-extra`.
  KCM `GET_CRED_LIST` rejects a hostile count with `InvalidData`.
  Store is INITIALIZE+STORE (no REPLACE probe); `kvno` does not
  `SET_DEFAULT_CACHE`. Socket path honors `kcm_socket` / `KCM_SOCKET`.
  `kcm-opcode-gate.sh` value-asserts F43/F42 opcodes on a scheduled
  workflow. R6 SSSD `krb5_child` renewal stays ungated.

- `klist` flag letters are MIT order `F f P p D d i R I H A T O a`
  (anonymous `a`); it prints `renew until` in local time and
  `Ticket server` only when cred server ≠ ticket sname. AS/TGS sname
  compare is component-wise. Trust-anchor
  with **absent** `keyUsage` is accepted (RFC 5280 §6.1.4(n)); KU
  present without `keyCertSign` is still refused. NT-ENTERPRISE
  suffix match is exact octets (MIT `kinit -E user@kerber.test` in
  `KERBER.TEST` is `CLIENT_NOT_FOUND`).

- `kvno` FILE rewrites keep unparsed MIT `X-CACHECONF` records
  (`klist -C` `config:`). `kadmin.local` honors `-randkey` / `-pw` /
  `-policy` / `+|-requires_preauth` and rejects unknown flags;
  `ktadd` merges into an existing keytab and randomizes by default
  (`-norandkey` keeps the key). `listprincs` no longer rewrites the
  dump at exit.

- kpasswd UDP accepts only the KDC it sent to and retries until the
  deadline; password and subkey buffers are zeroized. `kadmin.local`
  exits non-zero if `KRB5_ACL_FILE` is set and unreadable (not full
  privs). The ACL is not a security boundary here (self-chosen
  `KRB5_KADMIN_PRINCIPAL`; the master key is).

- PKINIT CMS without `signedAttrs` is refused (RFC 5652 §5.3).
  PA-PK-AS-REQ under FAST hashes the FAST-inner `KDC-REQ-BODY` for
  AuthPack `paChecksum`. `PKAuthenticator` `ctime`/`cusec` are checked
  against the skew window and the PA replay cache (replay is
  `PREAUTH_FAILED`).

- `krb5-klist` (`-c`/`-f`/`-e`) reads a FILE ccache; `krb5-kdestroy`
  zeros then unlinks. Bidirectional MIT oracle in
  `scripts/client-gate.sh`: Rust klist of a MIT-`kinit` ccache and MIT
  `klist` of a Rust-written ccache agree on principal, service, flags,
  and etype; after kdestroy MIT `klist` reports no cache. kdestroy
  refuses a symlink (target bytes unchanged). Default FILE ccache
  without `-c`/`KRB5CCNAME` is `/tmp/krb5cc_<uid>` (MIT
  `FILE:/tmp/krb5cc_%{uid}`), not the literal `/tmp/krb5cc_0`.

- `--spake` cannot combine with `--armor-ccache` or `--pkinit`.
  PKINIT trust-anchor `notBefore`/`notAfter` and `keyCertSign` are
  enforced. Realm compares at PKINIT SAN and NT-ENTERPRISE lookup are
  exact octets (RFC 4120 §6.1). SPAKE SKEW retry keeps the support
  padata. AES `wrap_iov(false)` round-trips.

- PKINIT AuthPack `paChecksum` is SHA-1 of `KDC-REQ-BODY` (RFC 4556
  §3.2.2). CMS signed `content-type` must equal `eContentType`
  (RFC 5652 §5.3); the KDC also requires client `id-pkinit-authData`.
  Client SAN is bound to the canonical issued cname, not a stripped
  enterprise suffix.

- FAST/SPAKE/PKINIT reverse-kinit gates assert MIT 1.22.2 TRACE
  completion (`Decrypted AP-REQ`, `SPAKE response received` /
  `SPAKE derived K'`), not a PREAUTH_REQUIRED offer or a string
  MIT never prints. Rogue PKINIT is `pkinit kdc eku` (MIT not
  listening is red). SAN≠cname greps the Rust KDC log for
  `pkinit client san`.

- **G7 M-pass / N-batch (MIT-gated).** Local `kadmin.local ktadd`
  ignores `LOCKDOWN_KEYS` like MIT 1.22.2 (rotate + write). **krbtgt
  `ktadd krbtgt/REALM` is the MIT footgun** (rotates + writes;
  lockdown is wire-only — user decision 2026-08-30). Remote kadm5
  extract stays gated. Mutating local/remote verbs reload the dump
  before save. MIT `kinit -T` against the Rust KDC armors AS via
  PA-FX-FAST + PA-ENCRYPTED-CHALLENGE (`scripts/mit-fast-kdc-gate.sh`,
  ≥2 `KrbFastResponse`). Encrypted-challenge, SPAKE, and PKINIT
  record AS success/failure like enc-ts, so MIT `kinit -T` with a
  bad password locks at `maxfailure` (`scripts/policy-gate.sh`).
  kadm5 `EXTRACT_KEYS` / `GET_PRINCIPAL` / `GET_STRINGS` and native
  ktadd reload the dump before read so a local `cpw` then remote
  `ktadd -norandkey` exports the new key. FAST post-armor errors are
  wrapped (RFC 6113 §5.4.4); issue uses the inner KDC-REQ-BODY and
  inner nonce; unknown critical fast-options bits 0 and 2–15 are
  error 93 (bits 16–31 ignored; bit 1 is not unknown-critical); explicit
  FAST armor TGT is local TGS, unexpired, not INVALID (implicit
  PA-TGS-REQ armor may be INVALID under VALIDATE / MIT `kinit -v`).
  ktutil-gate lists a MIT
  unknown-etype keytab as parsed princ/kvno plus `Unknown (N)`.
  Local ktadd rolls back if chrand's own save fails.

- Align the workspace with KLLDAP 0.7.5: edition **2024**, MSRV **1.95**,
  `nix` **0.31**, and `rasn` unpinned at **0.28.14**. MIT golden DER
  still byte-matches `tests/traces/mit-*.der`. Privilege-drop still
  no-ops when not root. See
  [`docs/integration-klldap.md`](docs/integration-klldap.md).
  Bisect: `c6c59d8` (MSRV bump) was clippy-red on stable until
  `d226f8c` folded MSRV-gated `is_multiple_of` / if-let-chains.

Deferred (committed G7 ledger; not this 1.1 cut): kvno `-U`/`-P`;
G7g remote AUTH_GSSAPI `kadmin` client; ktutil argv-join; kpasswd
`ap_len==0`; PKINIT TRACE self-grade / nonce / `signatureAlgorithm` /
SignerInfo `sid` / 64 KiB DER cap; KDC retransmit lookaside; TGS/AS
sname asymmetry; argv `PrincipalName::new` ×3; `addpol` ACL+save;
client-gate config-key equality; kpasswd subkey zeroize; `delprinc
-force`; klist `for client` / `starttime==0`; keytab v1 endian;
`take_der` dup; replay window vs skew; `pa_replay` cap; PKINIT
`cusec` range; enterprise error code 6; `cms_wrap_signed(None)` pub;
N4 `create_host` double dump write; N7 reload→save has no dump file
lock (with db2/LMDB); FAST armor AP-REQ not stored in the TGS replay
cache (MIT `kinit -T` reuses it); G8a-1 FILE ccache tagged header;
G8b-1 kinit `-k/-t` unknown-flag parse. Nits: N1 raceprinc-leg
stderr; N3 `Error::Crypto` flattening + root-fragile `0555` test; N5
`skipped_unknown_etype` dead field + module doc "skipped"; N7
`API_V2` hardcode + `kadm5_code` string-match + deleted-dump-proceeds-stale;
N8 `FAST_COOKIE`==`ENC_CHALLENGE_CLIENT`==54 + cookie-as-encryption-oracle;
N10 FIFO `is_err()` not `ENXIO` + `temp_dir()` host `/tmp`; iprop-gate
FULL_RESYNC wait `$ok` printed-not-enforced.


## [1.0.0] - 2026-08-27

### Fixed

- Clippy on rustc 1.98 (`-D clippy::pedantic`) accepts `map_or` /
  `is_ok_and` in place of `map().unwrap_or`. GitHub Actions `test`
  was failing at clippy before tests or the harness ran.
- `imports.lock` is formatted for cargo-vet **0.10.0** (CI pin
  `cargo-vet@0.10.0`). 0.10.2 writes unescaped quotes in imported
  `notes` and fails store-format against 0.10.0.
- Same-realm TGS service tickets set `TRANSITED_POLICY_CHECKED` (RFC
  bit 12) when the KDC performs the transited check (empty same-realm
  transited included), matching MIT 1.22.2. `DISABLE_TRANSITED_CHECK`
  skips the check and leaves the flag off. AS-REP TGTs are unchanged.
- TGS-REP sname compare uses name-string components, not `name-type`.
  RFC 4120 treats name-type as a hint; Heimdal canonicalize may return
  NT-SRV-HST for a host principal requested as NT-PRINCIPAL.
- MSRV 1.85 is actually green on the locked tree: `rasn` is pinned at
  `=0.27.0` (`0.27.1+` uses `usize::is_multiple_of` as a const fn,
  which is not stable on 1.85). The CI `msrv` job runs
  `cargo test --workspace --locked` only (no unlocked fallback).
  Golden MIT DER tests still pass on that pin. The kpasswd UDP
  listener test waits 15s for a reply (1.85 debug s2k can exceed 2s).

### Added

- PAC type-7 (KDC) and type-19 (full) MAC-byte tamper negatives:
  shipped `sign_pac` then `verify_pac_signatures` returns
  `BAD_INTEGRITY`. Unix `save_store` writes db and stash mode 0600.
- Interop matrix: [`docs/interop-matrix.md`](docs/interop-matrix.md)
  (MIT / Samba / Heimdal external oracles + supply-chain; loopback,
  soak, golden/KAT/fuzz, and SSPI `exit 2` labeled not-external).
- C3 supply-chain and security artifacts: `docs/security.md` timing/replay
  matrix; KDC TGS-authenticator and PA-ENC-TIMESTAMP `REPEAT` tests;
  `ReplayCache` window/cap/poison tests; per-crate `scripts/geiger.sh`
  (0-unsafe product, dependency surface archived); `cargo vet --locked`
  with Google / Mozilla / Bytecode Alliance imports (`rasn-derive`
  0.27.0 locally audited; remaining third-party crates exempt;
  dual `getrandom` 0.2/0.4 justified by the MSRV `rasn` pin). `NOTICE`
  plus `docs/export-control.md` (ECCN 5D002 / TSU §740.13(e) note).
  Logs-as-metrics documented; in-process counters deferred. In the CI
  `audit` job.
- Heimdal 7.8 secondary oracle: `harness/heimdal/` (Debian bookworm apt,
  no `krb5-user`; HDB master key etype 18) and
  `scripts/heimdal-gate.sh`. Both directions content-assert AES-SHA1:
  Heimdal `kinit`/`kgetcred` vs the Rust KDC, Rust `krb5-kinit` vs the
  Heimdal KDC; `klist` names `user@KERBER.TEST` and
  `host/testhost.kerber.test`. Missing docker/image is honest `exit 2`.
  In CI after the Samba block.
- Differential-vs-MIT: `scripts/differential-gate.sh` loads one dump into
  a live Rust KDC and MIT 1.22.2 `krb5kdc` at once and
  `examples/diffsend.rs` sends the same encoded AS/TGS bytes to both.
  KRB-ERROR compares `error_code`/`realm`/`sname` (times/`e_text`
  masked). PREAUTH ETYPE-INFO2 requires the MIT etype set ⊆ the Rust
  set. Success replies decrypt, null volatiles, and compare the
  stable set including the full ticket-flag word (only named
  whitelist bits masked). Known MIT divergences are named in
  `docs/testing.md`. Un-whitelisted mismatch fails red. The compare
  surface is feature `diff`, not the default public API. TGS success
  uses a hand-minted PAC-less TGT (exported krbtgt etype 20); PAC
  copy/re-sign is not on this path. Rust issues renewable when
  requested; `mit-renewable-flags` is default-policy, not a missing
  flag. In CI after `kdb-dump-gate`.
- C2 soak/stress/chaos over the multi-host realm: `scripts/stress-gate.sh`
  drives concurrent wire AS+TGS (`krb5-client` `examples/loadgen.rs`)
  with MIT `kinit`/`kvno` sampling and fails unless KDC `duration_us`
  p99 is ≤ 50 ms, throughput ≥ 8 issue-ok/s, intra-run p99 degrade-factor
  2.5, error-rate 0, panics 0.
  `scripts/chaos-gate.sh` applies `tc netem` (`KERBER_REQUIRE_NETEM=1`
  in CI), a low memory cap, and primary-kill failover under load
  (`State.Running=false` after kill). `scripts/soak-gate.sh` runs a
  bounded window with RSS slope + additive leak detection and
  non-degrading latency (scheduled longer run in
  `.github/workflows/soak.yml`; `KERBER_REQUIRE_REAL_PCAP=1` is honored).
  `KERBER_REQUIRE_REAL_PCAP=1` makes `prod-realm-gate` require a real
  eth0 capture (CI builds `kerber-rust-prod-node` as its own fail-red
  step). In CI after `prod-realm-gate`.
- C1 multi-host prod realm: `krb5-kdb create <realm>` writes dump
  version 7; kadmind ACL is `admin@<store.realm()>` (or `acl_file`);
  kpropd realm is `KRB5_KDC_REALM` (fallback `KRB5_TEST_REALM`) and the
  documented `host/testhost.kerber.test` keytab fallback is test-realm
  only. `scripts/prod-realm-gate.sh` drives MIT `kinit`/`kvno`/`kadmin`
  on `PROD.KERBER.TEST` across a docker network, Rust `krb5-kprop` to a
  replica, primary-kill failover, structured-log analysis, and a real
  NIC pcap when `NET_RAW` works. In CI after loopback `prod-gate`.
  `restart-gate` also has MIT `kdb5_util` load the daemon persist file.
- AD PAC: MS-RPCE NDR32 `KERB_VALIDATION_INFO` in field-encounter
  referent order. Golden `tests/traces/pac-kbruser.ndr` (kbruser /
  kbrgroup / ADKERBER SID) re-encodes byte-identically. Server checksum
  usage 17 verifies against the lab `svc.keytab` when present.
- PAC signatures 6, 7, 16 (`PAC_TICKET_CHECKSUM`), 19
  (`PAC_FULL_CHECKSUM`). `ulType` 12 is UPN/DNS; 16 is the ticket
  checksum. Issued tickets self-verify all four with the local krbtgt.
- `PA-SUPPORTED-ENCTYPES` bits follow keys on the principal (not a
  static `0x18`).
- GSS wrap send-side RRC=16 (RFC 4121).
- Runtime-mutable `SharedStore` (`RwLock`) so kadmind/kpasswd mutations
  reach stash/db. The KDC reloads the db when mtime/length changes.
  Privilege drop is skipped when a shared persist db is configured
  (kadmind writes 0600 files the dropped user could not re-read).
  `krb5-kadmind` ONC RPC program 2112 / AUTH_GSSAPI flavor 300001:
  MIT 1.22.2 `kadmin` `addprinc`/`cpw`/`getprinc`/`listprincs`/
  `modprinc`/`cpw -randkey`/`ktadd`/`renprinc`/`delprinc` then `kinit`
  is gated by `scripts/kadmin-gate.sh`. Rename is kadm5 proc 4
  (add+delete ACL; RID/keys kept). `getprinc` encodes `mod_name` (MIT
  unparses it; a NULL modifier is `KRB5_PARSE_MALFORMED`).
  `listprincs` is MIT `xdr_gprincs_ret` (count, then `xdr_array` of
  `xdr_nullstring`). Version-1 AP-REQ framing remains for
  library tests. RFC 3244 kpasswd on UDP/TCP 464 (`kadmin/changepw`):
  MIT 1.22.2 `kpasswd` then `kinit` is gated by
  `scripts/kpasswd-gate.sh`. KRB-PRIV uses the authenticator subkey
  when present; success replies include AP-REP. kprop dump encrypts
  with the existing shared stash (never a throwaway master) and is
  proven over a real TCP socket (`kprop_tcp_replica_issues_as_with_shared_stash`).
  `krb5-kpropd` on TCP 754: MIT `sendauth` version `kprop5_01`, KRB-SAFE
  dump size (MIT checksums the full KRB-SAFE with a dummy checksum),
  `initivector` then KRB-PRIV 32768-byte dump-v7 chunks. MIT `kprop`
  then MIT `kinit user` is gated by `scripts/kprop-gate.sh`. Rust
  `krb5-kprop` → MIT `kpropd` then MIT `kinit user` is
  `scripts/kprop-reverse-gate.sh` (dump-size SAFE uses the authenticator
  sequence). A kadmind `addprinc` survives killing
  `krb5-kdc` by `/proc/PID/comm` and relaunching
  (`scripts/restart-gate.sh`).
- RFC 8636 SHA-256 PKINIT KDF on the KDC issue path when AuthPack
  `supportedKDFs` includes `id-pkinit-kdf-ah-sha256`: `kdf` is set in
  `DHRepInfo` and the reply key is `SHA-256(counter||Z||OtherInfo)`.
  MIT 1.22.2 `kinit` TRACE `PKINIT used KDF 2B06010502030602`. Without
  `supportedKDFs` the KDC still uses RFC 4556 `octetstring2key`.
- FILE ccache parser skips MIT `X-CACHECONF` etype 0 so AD `ad.ccache`
  tickets remain readable.
- In-tree TGS referral hop for `krbtgt/AD.KERBER.TEST`. Live
  bidirectional `AD.KERBER.TEST`↔`KERBER.TEST` host tickets
  (`scripts/ad-mit-trust-gate.sh` aliases `samba-realtrust-gate.sh`).
  Referral TGTs carry a PAC signed with the
  inter-realm key (`scripts/samba-crossrealm-gate.sh` both directions).
  TGS verifies a presented TGT PAC with the key that opened the ticket
  and copies LOGON_INFO into the issued service PAC (foreign SID/RID
  survive; corrupt server or type-16 checksum is `KRB_AP_ERR_BAD_INTEGRITY`).
  Type-16 is over the original decrypted EncTicketPart bytes with PAC
  ad-data a single zero (not a rasn re-encode). Foreign TGTs check the
  server checksum plus type-16; KDC/19 use the issuing krbtgt. A TGT
  without a PAC still issues (MIT). `kvno` success is not that copy proof.
- `scripts/prod-gate.sh` drives shipped `krb5-kinit` against
  `127.0.0.1:18888`, requires `kdc.issue` JSON with `correlation_id`,
  and archives a PDU pcap. Heimdal and SSPI gates record unavailability.
- Live Samba S4U2Self/S4U2Proxy: `scripts/ad-s4u-gate.sh` (`kinit -k
  kbrsvc`, `kvno -U kbruser kbrsvc` / `kvno -U kbruser -P host/svc`,
  client `kbruser@AD.KERBER.TEST`). `ad-windows-gate.sh` is live Samba
  `kinit kbruser` + `kvno host/svc`.
- MIT `kvno -U` / `-U -P` against the **Rust** KDC
  (`scripts/s4u-mit-gate.sh`, in CI); S4U2Proxy copies the evidence PAC,
  requires a forwardable evidence ticket, and denies classic constrained
  delegation unless `s4u_allowed_to` lists the target (and RBCD unless
  `s4u_allowed_from` lists the evidence server). PA-FOR-USER accepts
  HMAC-MD5-ARCFOUR (cksumtype -138) on AES session keys.
- `bounded_stress_handle_request` asserts 64 concurrent valid AS+TGS
  succeed. Harness CI runs `kadmin-gate`, `kpasswd-gate`, `kdb-dump-gate`,
  `kprop-gate`, `kprop-reverse-gate`, `restart-gate`, `prod-gate`,
  `prod-realm-gate`, `s4u-mit-gate`, `samba-ad-gate`, `ad-windows-gate`, `ad-s4u-gate`,
  `samba-pac-verify-gate` (Samba IDL decode of a Rust PAC),
  `samba-pac-l2-gate` (vendored Samba kcrypto validates PAC 6/7/16/19;
  type-16 pre-image rebuilt in the oracle; a type-6 MAC flip and a
  type-16 EncTicketPart pre-image flip fail),
  `samba-crossrealm-gate` (MIT `kvno` both directions vs Samba), and
  `samba-realtrust-gate` (peer DC + `samba-tool domain trust create`; reverse
  PAC SID/RID equals live Samba-A `kbruser` `objectSid`).
  `samba-ad-gate.sh` exits 2 unless a live Samba/AD `kinit`/`kvno`
  succeeds (no fabricated pass from “image exists”).
- MIT `kdb5_util` dump/load (version 7; `-r18` is version 6):
  `krb5-kdb load`/`dump`, KDB usage-0 `key_data` with a cleartext
  `int16_LE` length prefix, master key string-to-key of
  `masterpassword` with salt `KERBER.TESTKM` and etype 20. Golden
  `tests/traces/kdb/mit-dump-v7.txt`. Gate `scripts/kdb-dump-gate.sh`
  (MIT `kinit` both directions). Protocol `KeyUsage::new(0)` still
  rejected. The live at-rest file is dump version 7; KDB3 still loads
  for one release.

### Security

- PKINIT `cms_verify` is mandatory against a provisioned CA; forged CMS
  is `PREAUTH_FAILED` (no `cms_unwrap` fallback). The PKINIT CA is
  opt-in, not auto-generated.
- GSS OID length is bound-checked (hostile tokens return Truncated).
- GSS acceptor requires `expected_server` / `expected_realm`.
- TCP workers use an RAII slot plus `catch_unwind`.
- Request-path realms use `try_ascii` (non-ASCII → KRB-ERROR).
- `--test-realm` reads passwords from `KRB5_TEST_*_PASSWORD` (not
  compiled into the binary). Network crates deny `unwrap`/`expect`/`panic`.

### Previously added

- Phase 0–8 audit work: honest CI oracles (`client-gate`, `kdc-gate`,
  bidirectional Rust↔Rust), `cargo audit`/`deny`, MSRV 1.85, `--release`
  tests, `cargo doc`.
- RFC 4120 TicketFlags INITIAL=9 / PRE-AUTHENT=10; every KDC request
  yields a KRB-ERROR; AS-REP enc-part APPLICATION 25; TGS checksum,
  replay, TGT check, `KDC_ERR_ETYPE_NOSUPP` (14).
- Keytab/ccache atomic 0600 writes; AP-REQ skew/expiry/server-name;
  bounded shared replay caches; UDP `send_to`/`recv_from` with source
  filter; configurable bind (no silent `0.0.0.0`); `--test-realm` vs
  persistent DB.
- `krb5-config` (`krb5.conf`/`kdc.conf`/env/SRV), ccache reader,
  keytab v1/merge, AP-REP / KRB-SAFE / PRIV / CRED, PRF/PRF+,
  `krb5-gss` RFC 4121 wrap/unwrap/MIC with channel bindings,
  `krb5-admin` ACL-enforced kadmind
  equivalent, persist+stash, kpasswd (kvno bump + multi-kvno),
  FAST `PA-FX-FAST` CHOICE + armor/cookie/strengthen, SPAKE2-P256 (MIT `wbytes` / K'[n] / group 2),
  PKINIT Oakley MODP 2048/4096 + ECDH P-256 inside CMS SignedData with a
  test CA (`pkinit_anchors` FILE PEM) and ECDSA-SHA256, PAC with NDR logon-info,
  S4U2Self/S4U2Proxy/U2U, cross-realm referrals/transited, ktadd of
  all kvnos, kprop dump/load, weak etypes behind `allow_weak_crypto`.

### Fixed

- Hostile/non-ASCII/`i32::MIN` keytab no longer panics.
- Wrong password answers `KDC_ERR_PREAUTH_FAILED` instead of dropping.
- Layering: KDC no longer depends on the client crate for keytabs.
- Client UDP no longer uses `connect()` (MIT TGS replies were dropped);
  AS-REP enc-part is decoded as RFC APPLICATION 25, with MIT tag 26
  only when the plaintext starts with `0x7a`.
- KDC TCP worker cap, privilege drop after bind :88, and SIGTERM/SIGINT
  shutdown. GSS wrap tokens use the RFC 4121 16-byte header; SPNEGO
  uses long-form DER length. PKINIT CMS includes an X.509 test cert.

### Changed

- `clippy::pedantic` is a workspace deny; noisy lints (rasn bindings,
  rustdoc RFC vocabulary, long issue/TGS functions) stay allowed.
- PRF+ prepends the RFC 6113 counter; RFC 8009 PRF emits the full
  SHA-2 output; Camellia uses the `camellia`+`cmac` crates and Camellia
  ECB for PRF (not AES); RC4 uses the RFC 4757 usage map; PAC checksums
  use usage 17; SPAKE P-256 group id is 2.
- KRB-SAFE/PRIV/CRED unwrap consults `ReplayCache` and a 300s timestamp
  window; SAFE/PRIV builders increment `seq_number`.
- Docs: MIT `kinit` PKINIT, SPAKE (`pa_type` 151), FAST TGS `kvno`, and
  two-realm `kvno` are gated; AD PAC NDR is golden-gated; MIT `kadmin`
  AUTH_GSSAPI add/get/list/mod/chrand/del is gated
  (`scripts/kadmin-gate.sh`).
  `KRB5_CONFIG` / `KRB5_KDC_PROFILE` / `/etc/krb5.conf` /
  `/etc/krb5kdc/kdc.conf` are consumed when present.
- `pkinit-gate.sh` fails when MIT PKINIT interop fails; `cargo-deny`
  is blocking in CI.
- `KERBER_CAPTURE_DIR` writes raw PDUs. Checked-in `tests/traces/mit-*.der`
  are decoded and **byte-diffed** (`encode(decode(raw)) == raw`) against
  the shipped encoder in unit CI (`golden_traces.rs`). Reply goldens are
  MIT-KDC bytes from `client-gate.sh`. AD lab coordinates: `docs/ad-lab.md`.
- RFC 6803 Camellia uses KDF-FEEDBACK-CMAC (not RFC 3961 n-fold DK).
  RFC 3961 3DES s2k uses 168-fold + random-to-key. Published KATs live
  in `krb5-crypto/tests/known_answer.rs`.
- `cargo fuzz` targets under `fuzz/` (CI smoke ~60s each).
- `krb5-config` / `krb5-types` / `krb5-crypto` deny `unwrap`/`expect`/`panic`.
- krbtgt and host principals carry RFC 8009 keys; `sha2-gate.sh` is a
  live MIT `kinit`/`kvno` forcing aes256-cts-hmac-sha384-192.
- Persistence is stash/db with a runtime-mutable `RwLock` store. GSS
  first-seq matches the AP-REQ authenticator; wrap/MIC use a windowed
  replay cache. Production wrap emits RRC=16.

## [0.1.0] - 2026-08-19

### Added

- Dual license Apache-2.0 OR MIT.
- Cargo workspace with `krb5-log`, `krb5-crypto`, `krb5-types`,
  `krb5-asn1`, and `examples/consumer`.
- Structured logging schema (correlation ID, crypto timing, error paths).
- RFC 3961/3962/8009 etypes 17–20: string-to-key, encrypt, decrypt,
  keyed checksum, key-usage derivation, secret zeroization.
- DER encode/decode for RFC 4120 `PrincipalName`, `Realm`,
  `EncryptedData`, `Ticket`, `KDC-REQ`, `KDC-REP`, `AP-REQ`, `KRB-ERROR`.
- Containerized MIT Kerberos 1.22.2 KDC harness and launch scripts.
- Stage 3: `krb5-protocol` AS/TGS over UDP/TCP and `krb5-client` kinit
  writing MIT FILE ccache v4 plus keytab v2. Live gate:
  `scripts/client-gate.sh` (Rust TGT + service ticket; MIT `klist`).
- Stage 5: `krb5-kdc` AS/TGS issue, kadm5.acl-style admin, MIT keytab
  v2 export, AP-REQ verify, UDP/TCP 88 listener. Gate:
  `scripts/kdc-gate.sh` (MIT `kinit` + `kvno` against the Rust KDC).
