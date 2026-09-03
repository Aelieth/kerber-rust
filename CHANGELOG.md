# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses semantic versioning once a crate is published.

## [Unreleased] — targeting 1.1.0

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
  `MODIFIED` with MIT log message `FIND_FAST` (`fast_util.c`). An
  unkeyed checksum type is 12 (MIT log `Unkeyed checksum used in
  fast_req`). Unknown armor type is 24 (MIT log `Unknown FAST armor
  type %d`). The AS checksum covers the outer `KDC-REQ-BODY` only
  (`do_as_req.c`). TGS authenticator client ≠ ticket client is 36
  `PROCESS_TGS` (`rd_req_dec.c`). MIT clients cannot emit these; live
  FAST gates stay green. Wire `e_text` is the status word as of W0d G3.

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
  is 35 `NOT_US` `FAST armor TGT`; a local non-krbtgt armor is 26
  `SERVER_NOMATCH`. `krb5-forge-tgt --keep-cipher` rewrites only DER
  `ticket.realm` so MIT `kinit -T` still selects the armor cred. Gate:
  `scripts/mit-fast-kdc-gate.sh` forged `kinit -T` vs MIT and Rust.

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
