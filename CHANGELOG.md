# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses semantic versioning once a crate is published.

## [Unreleased] — targeting 1.1.0

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
  guards the trap in the `audit` job. `scripts/kadmin-local-gate.sh` restarts
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
