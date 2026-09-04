# MIT 1.22.2 KDC parity ledger

Oracle: MIT Kerberos **1.22.2** source SHA `3243ffbc…af13`
(`https://github.com/krb5/krb5/tree/krb5-1.22.2-final`) plus the live
image `kerber-rust-mit-kdc:1.22.2`. Heimdal/Samba are regression, not
the equality bar. Isolation: host `/etc/krb5.conf` stays
`TESTLABBY.LOCAL`.

This file is the W1-A sweep (`working/ledger-w1a-0903-1702.md`) with
Part 0 of `working/plan-audit-polish-w1a-f-0903-1330.md` applied from
the three verification reports
`working/logs/audit-polish-0902/w0c-audit/ledger-verify-a{1,2,3}-*.md`.
Overlap (PROCESS_TGS, GET_LOCAL_TGT, FIND_FAST, HANDLE_AUTHDATA,
AD-FX-ARMOR) is left in both sections on purpose — A1 owns TGS gather,
A2 owns AS/`kdc_util`, A3 owns FAST residue.

W0d G3 is in tree: FAST unwrap failures put the MIT status word
`FIND_FAST` on the wire `e_text` (`do_as_req.c:806`,
`do_tgs_req.c:205-206`) and the `k5_setmsg` text in the `kdc.issue`
`detail` field. Rows that were `deviation (e_text)` only for that
mismatch are `exact` here.

Schema: `MIT file:line | check | MIT status + wire code | Rust site | Rust e_text + code | verdict | proof`.
Verdict ∈ {exact, stricter-documented (`docs/security.md` row), absent,
deviation, deferred (reason + promotion oracle)}. Proof `none` only
with deferred. A named gate cell or `diffsend` case that does not exist
is `proposed`. The twelve live `diffsend` cases are `garbage-pdu`,
`unknown-cname`, `etype-nosupp`, `wrong-realm`, `pauser-no-preauth`,
`skewed-timestamp`, `unknown-sname`, `as-success`, `tgs-success`,
`tgs-not-a-tgt`, `tgt-expired`, `tgt-nyv`.

Wire `e_text` is the MIT **status word**. MIT log messages are not
wire text. `errcode_to_protocol` passes `offset ∈ [0,128]`
(`kdc_util.c:696-697`).

Counts (after Part 0): **237** = A1 116 + A2 66 + A3 55.
exact 49 · stricter-documented 11 · deviation 94 ·
absent 68 · deferred 15.

Draft was 209 = 108 + 56 + 45 at HEAD `bafc5f2`. Additions: A1 8 +
A2 10 (9 report rows + the `kdc_util.c:144-191` split) + A3 10 = 28
row inserts (the plan's "27" counted the split inside the A2 9).

## Ranked F-batches (security > parity > e_text)

Corrected by the verification reports. Each batch ≤ 6 commits. One MIT
check family per commit. F1 starts after this ledger lands; F3–F9 get
a short plan when reached.

### F1 FAST armor / AD-FX-ARMOR / cookie (security)

1. `kdc: Refuse FAST armor without an authenticator subkey like armor_ap_request` —
   AS explicit armor (`fast_util.c:70-76`) and TGS-without-subkey
   (`:157-166`): 12, e_text `FIND_FAST`, detail `ap-request armor without subkey`.
   Rust falls back to the TGT session. MIT clients always send a subkey.
2. `kdc: Refuse a header ticket or authenticator carrying AD-FX-ARMOR like kdc_process_tgs_req` —
   `kdc_util.c:218-228` → 12 `PROCESS_TGS` (detail `ticket valid only as FAST armor`).
3. `kdc: Bind PA-FX-COOKIE to the client and expire it at 600 seconds like kdc_fast_make_cookie` —
   `MIT1` ‖ kvno ‖ enc(prf+(local TGT key, `COOKIE` ‖ unparsed client), ku 513);
   non-`MIT1` ignored (`:588-590,:610`). The ku-54 / ENC_CHALLENGE_CLIENT
   collision is a naming collision with no shared key — not the security
   content.

TGS reply-key strengthen is **parity** (F7): the MIT client copies
`existing_key` when `strengthen_key` is NULL.

### F2 S4U / header PAC integrity (security)

Prerequisite: `kdc: Compute is_crossrealm from the header server entry
like do_tgs_req` (`do_tgs_req.c:686`). Then `S4U2SELF_NO_PAC` 20,
`S4U2PROXY_NO_HEADER_PAC` 20, `HEADER_PAC` 13, PAC client match,
`S4U2PROXY_LOCAL_STKT_PAC` 13, U2U `2ND_TKT_PAC`, `PA-PAC-REQUEST`
include_pac=false, `disable_pac`/anonymous no-PAC. S4U2Self pw-expiry
exemption is stricter — document or match.

### F3 second ticket (security / parity)

`2ND_TKT_NOT_TGS` 12, `2ND_TKT_MISMATCH` 26, `INVALID_S4U2PROXY_OPTIONS` 13,
TGS-target `NOT_ALLOWED_TO_DELEGATE` 12, `CAN'T PROXY TGT` 13,
`BAD_ETYPE_IN_2ND_TKT` 14, RBCD/xrealm PAC, `INVALID_S4U2SELF_CHECKSUM` 41
not 50. Demoted to e_text (F9): `NO_2ND_TKT`, `EVIDENCE_TKT_NOT_FORWARDABLE`
(both already refuse with 13).

### F4 AS request validation (security)

`INVALID AS OPTIONS` 13 (`kdc_util.c:727-729`) and drop the AS
`DISALLOW_SVR` ENC_TKT_IN_SKEY exemption (`:789-793`) in the **same
commit**. Validate `msg-type` (60 `VALIDATE_MESSAGE_TYPE`) and `pvno`
(MIT drops). Failcount lockout last. `ANONYMOUS NOT ALLOWED` vs
unsupported 13 is parity + a security.md row, not a hole.

### F5 TGS options and ticket flags (security / parity)

Implement `get_ticket_flags` (`kdc_util.c:813`). `TGT NOT
FORWARDABLE/PROXIABLE/POSTDATABLE` 13. Ticket addresses.
`check_tgs_nontgt` 26 + `check_tgs_tgt` after decrypt and only when
`NON_TGT_OPTION` is clear. `NOT_YET_VALID` without skew.
`NON-POSTDATABLE` only on `ALLOW_POSTDATE`. Lookaside consequence
(UDP TGS retransmit → 34) is a deviation here; the cache itself stays
deferred.

### F6 CAMMAC + HANDLE_AUTHDATA (security, latent)

`cammac_create`/`cammac_check_kdcver` (ku 64) **before**
`copy_tgt_authdata`. `require_auth` → `HIGHER_AUTHENTICATION_REQUIRED`
12. `GET_AUTH_INDICATORS`. `AD-MANDATORY-FOR-KDC` → 12. Below F2/F3
because nothing is unsigned today.

### F7 RFC 6806 negotiation, FAST reply parity (parity)

149 checksum (ku 56) + empty 136 in `enc_padata` + `TKT_FLG_ENC_PA_REP`,
gated on request 149 — flag without 149 hard-fails MIT kinit. TGS
`strengthen_key`. PA-FX-COOKIE on every e_data-bearing AS error
(**after F1 cookie**). FAST error inner-padata order. Hint-list order
`[136,(11),19,modules]`. ETYPE-INFO2 only when the reply key was not
replaced.

### F8 gather order and lookups (parity)

AS lockout last; TGS `GET_LOCAL_TGT` before times; `HEADER_PAC` before
`search_sprinc`. TCP `FIELD_TOOLONG` 61 above UDP `RESPONSE_TOO_BIG` 52
(52 is dead at MIT's default 65536). `no PA-TGS-REQ` 16. `last_req` /
`key_expiration`. `starttime == authtime` omission. CANONICALIZE
canonical sname. `CANTLOCK_DB` 29 (deferred: no lockable KDB).
`select_session_keytype`.

### F9 e_text and the differential unmask (parity, last)

Token renames (`locked` → `CLIENT LOCKED OUT`, …). Then
`compare_krb_error` compares `e_text` on every `diffsend` case.
Whitelist names the documented stricter rows.

## Not this ledger (W1-B / W1-C)

W1-B: `tgs_req_ex` FAST sibling; `get_dest_tgt` referral memory;
start-realm in the service loop; acceptor kvno / transited re-check;
ERROR-level `asn1.decode`/`crypto.decrypt` on expected failures.
W1-C: kpasswd result-code strings; kadmind chpw log `from <addr>`;
`kprop.rs` per-connection rcache; `dfl` restart cell; min_life/dictionary;
kadm5 ACL denial codes; policy-rejection text.

OTP kdcpreauth, PA-S4U-X509-USER, PKINIT freshness, anonymous PKINIT stay
deferred with those promotion oracles (Batch D / user non-goal).

## A1 — tgs_policy.c / do_tgs_req.c / kdc_transit.c

MIT SHA 3243ffbc…af13. Wire codes are RFC 4120 `KRB-ERROR.error-code`.
Rust sites are `crates/krb5-kdc/src/…`. `ORDER` rows are check-sequence
mismatches, not extra statuses.

| MIT file:line | check (condition) | MIT status + wire code | Rust site | Rust e_text + code | verdict | proof |
| --- | --- | --- | --- | --- | --- | --- |
| kdc_util.c:171 | no PA-TGS-REQ (`KRB5_PADATA_AP_REQ`) | PROCESS_TGS 16 `PADATA_TYPE_NOSUPP` (set do_tgs_req.c:623) | issue.rs:571 | `no PA-TGS-REQ` 24 | deviation | proposed: diffsend; proposed: MIT-client `kdc-gate.sh` no-PA-TGS-REQ cell |
| kdc_util.c:179 | AP-REQ `USE_SESSION_KEY` or `MUTUAL_REQUIRED` | PROCESS_TGS 12 `POLICY` | process_tgs_header issue.rs:588 | no AP-options check | absent | proposed: diffsend |
| kdc_util.c:190 | TGS AP-REQ replay cache | disabled (`auth_con_setflags 0`) | issue.rs:678 | `TGS authenticator replay` 34 | stricter-documented | `tgs_authenticator_replay_is_repeat`; docs/security.md Replay — TGS authenticator |
| kdc_util.c:233 | authenticator missing checksum | PROCESS_TGS 50 `INAPP_CKSUM` | issue.rs:646-649 | `TGS authenticator missing checksum` 50 | exact | proposed: diffsend |
| kdc_util.c:112-140; :248 | req-body checksum (`comp_cksum`) | unknown 15 `SUMTYPE_NOSUPP`; not coll-proof 50 (no 1.22.2 type has `CKSUM_NOT_COLL_PROOF`); bad bytes 31 `BAD_INTEGRITY`; status PROCESS_TGS | issue.rs:625-644 | unknown 15; bad bytes 31; PROCESS_TGS (H3) | exact | `tgs_authenticator_unknown_cksumtype_is_sumtype_nosupp`; `tgs_authenticator_bad_bytes_is_bad_integrity`; proposed diffsend |
| kdc_util.c:379 | header ticket server KDB NOENTRY | PROCESS_TGS 7 | issue.rs:1008 | `PROCESS_TGS` 7 | exact | `tgs_fast_forged_ticket_realm_is_process_tgs`; `mit-fast-kdc-gate.sh`; `capaths-transit-gate.sh` forged realm |
| kdc_util.c:390 | header krbtgt `DISALLOW_SVR`/`DISALLOW_ALL_TIX` | PROCESS_TGS 7 | issue.rs:1011 | `PROCESS_TGS` 7 | exact | `tgs_krbtgt_disallow_all_tix_is_process_tgs`; `tgs_local_krbtgt_disallow_svr_is_process_tgs`; `capaths-transit-gate.sh` DISALLOW_ALL_TIX |
| kdc_util.c:337 | header ticket decrypt/rd_req fail | PROCESS_TGS 31 (typical `BAD_INTEGRITY`) | issue.rs:1033 | `PROCESS_TGS` 31 | exact | proposed: diffsend (no unit asserts 31+text) |
| rd_req_dec.c:627 | header endtime/nyv inside PROCESS_TGS (`krb5int_validate_times`) | PROCESS_TGS 32/33 | issue.rs:1052,1078 expired; **issue.rs:1060-1063** NYV | `expired` 32 / `not yet valid` 33 | deviation | `tgs_renew_after_endtime_still_issues`; proposed: diffsend |
| rd_req_dec.c:530-532 | authenticator cname/crealm ≠ ticket client | PROCESS_TGS 36 `BADMATCH` | issue.rs:613 | `PROCESS_TGS` 36 | exact | `tgs_authenticator_cname_mismatch_is_badmatch`; `tgs_authenticator_crealm_mismatch_is_badmatch`; docs/security.md |
| do_tgs_req.c:609 | `msg_type != TGS_REQ` | no status (retval `BADMSGTYPE`) | handle_request dispatch | not TGS path | deferred | proposed: diffsend non-12 application tag |
| do_tgs_req.c:623 | `kdc_process_tgs_req` any fail | PROCESS_TGS + inner code | issue.rs:572 `process_tgs_header` | see rows above | exact | `phase7_preauth.rs` PROCESS_TGS cells; `capaths.rs` PROCESS_TGS |
| do_tgs_req.c:637 | `kdc_find_fast` fail | FIND_FAST + inner code (41/12/24/60/93); MIT log is the `k5_setmsg` text | preauth.rs `verify_fast_req_checksum` + issue.rs:573 | FIND_FAST + inner code (G3; detail = previous message) | exact | `fast_tgs_unkeyed_type_with_bad_bytes_is_modified`; docs/security.md FAST req_checksum |
| do_tgs_req.c:637 + fast_util.c:159 | explicit AP-REQ FAST armor on TGS | FIND_FAST 24 only if subkey present (log `Ap-request armor not permitted with TGS`) | preauth.rs TGS armor | FIND_FAST 24 even without subkey (G3) | stricter-documented | `tgs_fast_explicit_armor_is_preauth_failed`; docs/security.md FAST TGS AP-REQ armor |
| do_tgs_req.c:642 | FAST inner body `server == NULL` | NULL_SERVER 7 | issue.rs:684 | `no sname` 7 | deviation | proposed: diffsend FAST inner without sname |
| do_tgs_req.c:649 `get_local_tgt` kdc_util.c:486 | no `krbtgt/<body.realm>@<body.realm>` | GET_LOCAL_TGT 60 (`KDB_NOENTRY`→GENERIC) | issue.rs:689 | `GET_LOCAL_TGT` 60 | exact | `tgs_local_sname_unknown_body_realm_is_get_local_tgt`; `phase7_preauth.rs` GET_LOCAL_TGT; `capaths-transit-gate.sh` GARBAGE.EXAMPLE / dest RENEW |
| ORDER do_tgs_req.c:649 vs tgs_policy.c:687 | GET_LOCAL_TGT before `check_tgs_times` | 60 then times | issue.rs:666 then :689 | times (`NOT_YET_VALID`/`expired`/`INVALID`) then 60 | deviation | proposed: diffsend: foreign `body.realm` + INVALID/NYV TGT (MIT 60, Rust 33/32) |
| do_tgs_req.c:662 | `get_verified_pac` fail (header) | HEADER_PAC 41 `MODIFIED` (path kdc_util.c:589-630 / :629) | ad.rs:222 `presented_tgt_logon` (called issue.rs:750) | `PAC server checksum` / `PAC ticket checksum` 31 | deviation | `tgs_rejects_corrupt_foreign_referral_pac`; proposed: diffsend |
| tgs_policy.c:622 `check_normal_tgs_pac` | PAC present but not client and not RBCD-deleg | HEADER_PAC 13 | no `krb5_pac_verify` client match | missing PAC ok (`tgs_without_pac_still_issues`); no HEADER_PAC 13 | absent | proposed: diffsend PAC client mismatch |
| ORDER do_tgs_req.c:657 vs :669 | HEADER_PAC before `search_sprinc` | PAC 41 then LOOKING_UP_SERVER | issue.rs:696 fetch then :750 PAC | unknown-server 7 can precede PAC | deviation | proposed: diffsend unknown sname + bad PAC |
| do_tgs_req.c:536 `db_get_svc_princ` | server lookup fail | LOOKING_UP_SERVER 7 (remap :575) | issue.rs:697 | `unknown server` 7 | deviation | proposed: diffsend missing host; `flags-gate.sh`/`kdc-gate.sh` |
| do_tgs_req.c:409 `find_alternate_tgs` | walk_realm_tree finds no intermediate TGS | UNKNOWN_SERVER 7 | no `find_alternate_tgs` | `unknown server` 7 (no realm-tree hop) | absent | proposed: diffsend `krbtgt/FAR` with only near hop; promote via `cross-realm-gate.sh` |
| do_tgs_req.c:483 `find_referral_tgs` | host-based DNS referral | may issue `krbtgt/other` or fall through LOOKING_UP_SERVER | no hostbased/`host_realm` referral | explicit `krbtgt/OTHER` only (`tgs_canonicalize_issues_cross_realm_krbtgt`) | absent | proposed: diffsend `host/foo.other.test` + CANONICALIZE |
| kdc_util.c:1322 | PA-FOR-USER decode fail | DECODE_PA_FOR_USER (ASN.1 code→60 often) | ad.rs:283 | DER `Error` (not that e_text) | absent | proposed: diffsend truncated PA-FOR-USER |
| kdc_util.c:1328 | PA-FOR-USER checksum fail | INVALID_S4U2SELF_CHECKSUM 41 on verify failure / 50 unkeyed (`kdc_util.c:1245,1297`) | ad.rs:293 | `PA-FOR-USER` 50 (both) | deviation (code 50 vs 41 on a failed verify) | `s4u2self_bad_checksum_rejected` (50); proposed: diffsend |
| kdc_util.c:1424 | PA-S4U-X509-USER decode | DECODE_PA_S4U_X509_USER | types constant 130 only; `s4u2self_client` ignores | no X509-USER path | absent | proposed: diffsend PA-S4U-X509-USER |
| kdc_util.c:1435 | PA-S4U-X509-USER checksum | INVALID_S4U2SELF_CHECKSUM 41 on verify failure / 50 unkeyed | — | — | absent | proposed: diffsend |
| kdc_util.c:1443 | empty user and empty cert | INVALID_S4U2SELF_REQUEST 6 | — | — | absent | proposed: diffsend |
| kdc_util.c:1605 | local S4U user KDB NOENTRY | UNKNOWN_S4U2SELF_PRINCIPAL 6 | issue.rs:721 | `S4U2Self` 6 | deviation | `s4u2self_unknown_for_user_is_refused` (code) |
| kdc_util.c:1608 | local S4U user lookup other error | LOOKING_UP_S4U2SELF_PRINCIPAL (varies) | issue.rs:720 fetch | store error, not that e_text | deferred | none (named store-fail hook) |
| do_tgs_req.c:283 | 2nd ticket server lookup/key | 2ND_TKT_SERVER (7 typical) | ad.rs:337 / u2u ad.rs:410 | `evidence server`/`evidence key` 7; U2U uses local krbtgt | deviation | proposed: diffsend; `s4u-mit-gate.sh` extra ticket |
| do_tgs_req.c:288 | 2nd ticket decrypt fail | 2ND_TKT_DECRYPT 31 typical | ad.rs:343 | decrypt `Error` (no 2ND_TKT_DECRYPT) | deviation | proposed: diffsend |
| do_tgs_req.c:294 | 2nd ticket PAC verify fail | 2ND_TKT_PAC 41 | ad.rs:372 S4U2Proxy; U2U skips PAC | `S4U2Proxy evidence PAC` 31; U2U none | deviation | proposed: diffsend U2U+bad PAC (security) |
| do_tgs_req.c:319 | 2nd ticket session etype invalid | BAD_ETYPE_IN_2ND_TKT 14 | ad.rs:419 `from_iana` | crypto/known fail, not that e_text | absent | proposed: diffsend U2U bogus session etype |
| do_tgs_req.c:740 | cross S4U2Proxy PAC client extract fail | RBCD_PAC_PRINC 13 | no `get_pac_princ_with_realm` | no cross-RBCD PAC princ | absent | proposed: diffsend cross CNAME-IN-ADDL-TKT |
| do_tgs_req.c:767 | `get_auth_indicators` fail | GET_AUTH_INDICATORS (varies) | — | no CAMMAC extract | absent | proposed: diffsend truncated CAMMAC |
| do_tgs_req.c:792 | header transited `tr_type != 1` on add path | VALIDATE_TRANSIT_TYPE 17 | issue.rs:771 | `VALIDATE_TRANSIT_TYPE` 17 | exact | `transited_add_path_type_and_ill_formed` |
| do_tgs_req.c:799 | `add_to_transited` fail | ADD_TO_TRANSITED_LIST 43 (`ILL_CR_TKT`; kdc_transit.c:214+) | issue.rs:775 | `ADD_TO_TRANSITED_LIST` 43 | exact | `transited_add_path_type_and_ill_formed`; `capaths-compress-gate.sh` |
| kdc_transit.c:143 | add-path realm compress/escape | MIT encoder (no `\,` escape) | transited append | escapes `\` `,`; uncompressed X.500 | stricter-documented | docs/security.md Append escaping / Encode-side X.500; `capaths-compress-gate.sh` |
| chk_trans vs issue.rs:780 | transited comma/hop caps | MIT checker no 256-comma / 4096-hop cap | `realms_for` TooManyFields | POLICY (not a MIT status) | stricter-documented | docs/security.md Transited field-count/hop-emission cap; `capaths.rs` |
| do_tgs_req.c:945 | `reject_bad_transit` and T not set | BAD_TRANSIT 12 | issue.rs:790 | `BAD_TRANSIT` 12 | exact | `capaths.rs` BAD_TRANSIT; `capaths-transit-gate.sh` skip cells |
| tgs_policy.c:66 | `FORWARDED` without TKT `FORWARDABLE` | TGT NOT FORWARDABLE 13 | issue.rs:848-863 (TGS flag builder); `flag_bit::FORWARDED` only at issue.rs:1636 S4U2Self mask | FORWARDED never read on TGS; `TKT_FLG_FORWARDED` never set; issues (no reject) | absent | proposed: diffsend FORWARDED on non-F TGT; proposed: `flags-gate.sh` cell |
| tgs_policy.c:68 | `PROXY` without TKT `PROXIABLE` | TGT NOT PROXIABLE 13 | issue.rs:848-863; `flag_bit::PROXY` only at issue.rs:1637 S4U2Self mask | PROXY never read on TGS; `TKT_FLG_PROXY` never set; issues | absent | proposed: diffsend |
| tgs_policy.c:70 | `ALLOW_POSTDATE`/`POSTDATED` without TKT `MAY_POSTDATE` | TGT NOT POSTDATABLE 13 | no header-flag check | issues | absent | proposed: diffsend |
| tgs_policy.c:72 | `VALIDATE` without TKT `INVALID` | VALIDATE VALID TICKET 13 | issue.rs:1046 | `VALIDATE VALID TICKET` 13 | exact | proposed: diffsend VALIDATE of already-valid TGT (`tgs_renew_and_validate_together_is_badoption` is Rust-only combo) |
| tgs_policy.c:74 | `RENEW` without TKT `RENEWABLE` | TICKET NOT RENEWABLE 13 | issue.rs:1067,801 | `TICKET NOT RENEWABLE` 13 | exact | `tgs_renew_non_renewable_is_badoption` |
| tgs_policy.c:100 | TKT `INVALID` and not `VALIDATE` | TICKET NOT VALID 33 | issue.rs:1058 | `INVALID` 33 | deviation | proposed: `as_postdated_is_invalid_until_validate` (code); diffsend e_text |
| tgs_policy.c:231 | `VALIDATE` and starttime > now | NOT_YET_VALID 33 | issue.rs:1050 | `NOT_YET_VALID` 33 | deviation (laxer: MIT no skew, Rust `+skew`) | `tgs_validate_allows_starttime_within_skew` (asserts the divergence) |
| tgs_policy.c:241 | `RENEW` and now > `renew_till` | TKT_EXPIRED 32 | issue.rs:1071 | `renew_till` 32 | deviation | proposed: `tgs_renew_rejects_renew_till_not_after_now` (code); diffsend e_text |
| tgs_policy.c:636 | `NON_TGT_OPTION` and `tkt.server != req.server` | SERVER DIDN'T MATCH TICKET FOR RENEW/FORWARD/ETC 26 | issue.rs:692 RENEW/VALIDATE only | `RENEW/VALIDATE server mismatch` 13; FORWARD/PROXY unchecked | deviation | proposed: `tgs_renew_wrong_sname_is_badoption` (13); diffsend FORWARD mismatch |
| tgs_policy.c:642 | `PROXY` and req.server is TGS | CAN'T PROXY TGT 13 | — | — | absent | proposed: diffsend PROXY `krbtgt/REALM` |
| tgs_policy.c:657 | header server not TGS princ (normal TGS) | BAD TGS SERVER NAME 35 | issue.rs:595 | `presented ticket is not a TGT` 35 | deviation | proposed: diffsend service ticket as PA-TGS-REQ |
| tgs_policy.c:662 | TGS instance ≠ `req.server.realm` | BAD TGS SERVER INSTANCE 35 | issue.rs:595/`GET_LOCAL_TGT` | not-a-TGT 35 or GET_LOCAL_TGT 60 | deviation | proposed: diffsend `krbtgt/OTHER` header vs local body.realm |
| tgs_policy.c:275 | S4U2Self local server ≠ header client (`is_client_db_alias`) | INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH 36 | issue.rs:732 | `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH` 36 | exact | `s4u2self_user_tgt_host_sname_is_badmatch`; `s4u2self_cross_tgt_foreign_client_named_like_local_server_is_badmatch`; `s4u-mit-gate.sh`; `capaths-transit-gate.sh` S4U collision |
| tgs_policy.c:281 | S4U2Self `AS_INVALID_OPTIONS` | INVALID S4U2SELF OPTIONS 13 | issue.rs:1621 | `INVALID S4U2SELF OPTIONS` 13 | exact | proposed: diffsend S4U2Self+RENEW/U2U/CNAME-IN-ADDL-TKT |
| tgs_policy.c:298 | S4U2Self local TGT + referral | LOOKING_UP_SERVER 7 | issue.rs:1624 | `LOOKING_UP_SERVER` 7 | exact | `s4u2self_local_tgt_referral_is_looking_up_server` |
| tgs_policy.c:307 | S4U2Self local user + cross TGT + not referral | NOT_CROSS_REALM_REQUEST 6 | issue.rs:1627 | `NOT_CROSS_REALM_REQUEST` 6 | exact | `s4u2self_cross_tgt_local_user_local_server_is_not_cross_realm` |
| tgs_policy.c:316 | S4U2Self foreign user + local TGT | S4U2SELF_CLIENT_NOT_OURS 12 | issue.rs:1630 | `S4U2SELF_CLIENT_NOT_OURS` 12 | exact | `s4u2self_local_tgt_foreign_user_is_not_ours` |
| tgs_policy.c:325 | S4U2Self foreign + empty user name (cert-only) | INVALID_XREALM_S4U2SELF_REQUEST 12 | — | — | absent | proposed: diffsend empty-name PA-S4U-X509-USER on cross TGT |
| tgs_policy.c:331 | S4U2Self header PAC missing | S4U2SELF_NO_PAC 20 | presented_tgt_logon Ok(None); no S4U PAC require | issues without PAC | absent | proposed: diffsend S4U2Self on PAC-less TGT (security) |
| tgs_policy.c:339 | S4U2Self local: PAC not impersonator | S4U2SELF_LOCAL_PAC_CLIENT 13 | — | — | absent | proposed: diffsend PAC client ≠ header client |
| tgs_policy.c:352 | S4U2Self foreign: PAC not subject+realm | S4U2SELF_FOREIGN_PAC_CLIENT 13 | — | — | absent | proposed: diffsend |
| tgs_policy.c:345 `validate_as_request` | S4U2Self local client expired | CLIENT EXPIRED 1 | issue.rs:1656 | `CLIENT EXPIRED` 1 | exact | `s4u2self_expired_for_user_is_name_exp` (code) |
| kdc_util.c:779 via tgs_policy.c:345 | S4U2Self local client `DISALLOW_ALL_TIX` | CLIENT LOCKED OUT 18 | issue.rs:1646 | `S4U2Self locked` 18 | deviation | `s4u2self_disabled_for_user_is_revoked` (code) |
| kdc_util.c:743 via tgs_policy.c:345 | S4U2Self pw expired / needchange | MIT clears pw_expire+needchange (kdc_util.c:1612) | issue.rs:1658 `check_db_times` | `CLIENT KEY EXPIRED` 23 possible | deviation | proposed: diffsend S4U2Self needchange user |
| tgs_policy.c:255 | cross TGT + client realm == server realm; skip S4U2Self | INVALID LINEAGE 12 | issue.rs:767 | `INVALID LINEAGE` 12 | exact | `tgs_lineage_local_user_on_foreign_tgt_is_policy`; `capaths-transit-gate.sh` lineage |
| tgs_policy.c:580 | U2U without 2nd ticket | NO_2ND_TKT 13 | ad.rs:409 | `U2U needs additional-ticket` 13 | deviation | proposed: diffsend ENC_TKT_IN_SKEY no additional-ticket |
| tgs_policy.c:587 | U2U 2nd ticket not local TGS | 2ND_TKT_NOT_TGS 12 | ad.rs:417 decrypt w/ local krbtgt only | no TGS-princ/instance check | absent | proposed: diffsend U2U service ticket as 2nd |
| tgs_policy.c:593 | U2U 2nd ticket client ≠ requested server | 2ND_TKT_MISMATCH 26 | — | — | absent | proposed: diffsend U2U admin TGT for host sname (`u2u_encrypts_ticket_in_additional_tgt_session` does not assert match) |
| tgs_policy.c:432 | S4U2Proxy without 2nd ticket | NO_2ND_TKT 13 | ad.rs:329 | `S4U2Proxy needs additional-ticket` 13 | deviation | proposed: diffsend CNAME-IN-ADDL-TKT no ticket |
| tgs_policy.c:436 | evidence not forwardable | EVIDENCE_TKT_NOT_FORWARDABLE 13 | ad.rs:347 | `S4U2Proxy evidence ticket is not forwardable` 13 | deviation | proposed: `s4u2proxy_rejects_non_forwardable_evidence` (code); `s4u-mit-gate.sh` |
| tgs_policy.c:443 | S4U2Proxy + NON_TGT_OPTION or ENC_TKT_IN_SKEY | INVALID_S4U2PROXY_OPTIONS 13 | — | combo not rejected as that status | absent | proposed: diffsend CNAME-IN-ADDL-TKT+RENEW/U2U |
| tgs_policy.c:449 | S4U2Proxy target is TGS princ | NOT_ALLOWED_TO_DELEGATE 12 | — | no TGT-target deny | absent | proposed: diffsend S4U2Proxy `krbtgt/REALM` |
| tgs_policy.c:455 | S4U2Proxy header PAC missing | S4U2PROXY_NO_HEADER_PAC 20 | — | — | absent | proposed: diffsend (security) |
| tgs_policy.c:460 | S4U2Proxy header PAC not impersonator | S4U2PROXY_HEADER_PAC 13 | — | — | absent | proposed: diffsend |
| tgs_policy.c:472 | S4U2Proxy evidence PAC missing | S4U2PROXY_NO_STKT_PAC 41 | ad.rs:372 | `S4U2Proxy evidence PAC` 31 | deviation | proposed: diffsend |
| tgs_policy.c:480 | same-realm evidence server ≠ header client | EVIDENCE_TICKET_MISMATCH 26 | ad.rs:331 | `evidence sname must match TGT client` 13 | deviation | proposed: diffsend; `s4u-mit-gate.sh` |
| tgs_policy.c:488 | same-realm evidence PAC ≠ evidence client | S4U2PROXY_LOCAL_STKT_PAC 13 | ad.rs:380 signatures only | no PAC-client match status | absent | proposed: diffsend |
| tgs_policy.c:503 | cross evidence not referral TGT to us | XREALM_EVIDENCE_TICKET_MISMATCH 13 | — | no cross-RBCD evidence TGT path | absent | proposed: diffsend |
| tgs_policy.c:512 + :365 `verify_deleg_pac` | cross evidence PAC deleg info | S4U2PROXY_CROSS_STKT_PAC 13 | — | — | absent | proposed: diffsend |
| tgs_policy.c:541 | referral S4U2Proxy without PA-PAC-OPTIONS RBCD | UNSUPPORTED_S4U2PROXY_REQUEST 13 | ad.rs:317 RBCD bit; referral policy not MIT-shaped | `RBCD not allowed` / `constrained delegation not allowed` 13 | deviation | `s4u2proxy_classic_denied_without_allowed_to`; `s4u2proxy_honors_pac_options_rbcd` |
| tgs_policy.c:569 | KDB deny RBCD/classic | NOT_ALLOWED_TO_DELEGATE 13 (same string as :449 but 13 not 12) | ad.rs:363,368 | `RBCD not allowed` / `constrained delegation not allowed` 13 | deviation | proposed: `s4u2proxy_classic_denied_without_allowed_to`; `s4u-mit-gate.sh` |
| tgs_policy.c:108 | `RENEWABLE` + server `DISALLOW_RENEWABLE` | NON-RENEWABLE TICKET 12 | issue.rs:1730 strips R | issues, flag cleared | deviation | `tgs_strips_renewable_when_server_disallow_renewable` (laxer) |
| tgs_policy.c:110 | `ALLOW_POSTDATE` + server `DISALLOW_POSTDATED` | NON-POSTDATABLE TICKET 10 | issue.rs:1715 | `NON-POSTDATABLE TICKET` 10 (also fires on `POSTDATED` bit; MIT keys only on `KDC_OPT_ALLOW_POSTDATE`) | deviation (stricter; extra POSTDATED bit; no security.md row) | proposed: diffsend TGS MAY_POSTDATE + DISALLOW_POSTDATED; proposed security.md row |
| tgs_policy.c:112 | `ENC_TKT_IN_SKEY` + `DISALLOW_DUP_SKEY` | DUP_SKEY DISALLOWED 12 | no `KDB_DISALLOW_DUP_SKEY` in store.rs | — | absent | proposed: diffsend; `flags-gate.sh` `allow_dup_skey` |
| tgs_policy.c:149 | server `DISALLOW_ALL_TIX` | SERVER LOCKED OUT 7 | issue.rs:1700 | `SERVER LOCKED OUT` 7 | exact | `tgs_honors_svr_tgt_based_lockout_and_ok_as_delegate` |
| tgs_policy.c:154 | `DISALLOW_SVR` and not U2U | SERVER NOT ALLOWED 27 | issue.rs:1703 | `SERVER NOT ALLOWED` 27 | exact | `tgs_honors_svr_tgt_based_lockout_and_ok_as_delegate`; `flags-gate.sh` |
| tgs_policy.c:159 | `DISALLOW_TGT_BASED` and header is TGS | TGT BASED NOT ALLOWED 12 | issue.rs:1706 | `TGT BASED NOT ALLOWED` 12 | exact | `tgs_for_changepw_with_tgt_is_tgt_based_not_allowed`; `kpasswd-gate.sh` |
| tgs_policy.c:176 | server `REQUIRES_HW_AUTH` without TKT HW | NO HW PREAUTH 60 | issue.rs:1709 | `NO HW PREAUTH` 60 | exact | `tgs_requires_hw_auth_without_hw_flag` |
| tgs_policy.c:182 | server `REQUIRES_PRE_AUTH` without TKT preauth | NO PREAUTH 60 | check_tgs_policy_flags no PRE_AUTH test | issues | absent | proposed: diffsend service +requires_preauth, TGT without PA flag; `flags-gate.sh` |
| tgs_policy.c:194 | server expiration < now | SERVICE EXPIRED 2 | issue.rs:1665 via :708 | `SERVICE EXPIRED` 2 | exact | `tgs_rejects_expired_server` |
| tgs_policy.c:763 `check_anon` kdc_util.c:703 | `restrict_anon` + anon client + non-local-TGS server | ANONYMOUS NOT ALLOWED 12 | issue.rs:777 anon crealm only skips transited | no restrict_anon deny | absent | proposed: diffsend WELLKNOWN/ANONYMOUS TGS to host; `kdc-gate.sh` |
| tgs_policy.c:768 | `krb5_db_check_policy_tgs` | plugin status + code | plugins.rs:362 `check_tgs`; issue.rs:694 | default allow; DenyPolicy `kdcpolicy` 12 | deferred | plugin-not-KDB; promote DenyPolicy unit vs MIT kdcpolicy module |
| ORDER tgs_policy.c:746 vs :768 | svc_policy then S4U2Proxy policy then anon then KDB | MIT last is KDB | issue.rs:694 plugin **before** fetch/flags/S4U | plugin earlier | deviation | proposed: diffsend plugin+locked server |
| ORDER tgs_policy.c:682 vs :746 | opts/times/nontgt **before** svc_policy | TGT NOT FORWARDABLE before SERVER LOCKED | issue.rs:709 flags before missing opts checks | svc flags early | deviation | proposed: diffsend FORWARDED+locked server |
| do_tgs_req.c:898 | `check_indicators` require-auth | HIGHER_AUTHENTICATION_REQUIRED 12 | — | — | absent | proposed: diffsend `+require_auth` string attr |
| do_tgs_req.c:358 `gen_session_key` | no session etype intersection | BAD_ENCRYPTION_TYPE 14 | issue.rs:698 `best_key` fallback | `no server key` 7 only if no keys; TGS does not use `select_etype` | deviation | proposed: diffsend TGS etype list disjoint from server (laxer) |
| do_tgs_req.c:1006 | `get_first_current_key` fail | FINDING_SERVER_KEY (often 60) | issue.rs:705 | `no server key` 7 | deviation | proposed: diffsend keyless service |
| do_tgs_req.c:1046 | `handle_authdata` fail | HANDLE_AUTHDATA (varies) | issue.rs:1119 `mint_ticket` PAC | `PAC logon: {e}` 31 possible; no HANDLE_AUTHDATA | absent | proposed: diffsend TGS req authdata / PAC sign fail |
| do_tgs_req.c:1103 | `return_enc_padata` fail | KDC_RETURN_ENC_PADATA | — | — | deferred | none (FAST+referral enc padata oracle) |
| do_tgs_req.c:1121 | successful TGS | ISSUE 0 (log only, not KRB-ERROR) | issue.rs:970 success | no ISSUE e_text | absent | `kdc-gate.sh` / `capaths-transit-gate.sh` success logs |
| do_tgs_req.c:1203 | status still NULL on error | UNKNOWN_REASON | proto() always sets text | no UNKNOWN_REASON | deferred | none (only if a TGS path returns Protocol without text) |
| kdc_util.c:754 AS; tgs empty_server | AS/S4U `SERVICE EXPIRED` on empty_server | not TGS svc_time | TGS uses SERVER path `SERVICE EXPIRED` | n/a for empty_server | exact | TGS covered `tgs_rejects_expired_server` |
| kdc_util.c:773 | AS `POSTDATE NOT ALLOWED` | POSTDATE NOT ALLOWED 10 | issue.rs:1688 AS-only | TGS uses NON-POSTDATABLE TICKET; AS `POSTDATE NOT ALLOWED` | exact | AS `as_cannot_postdate_when_disallow`; TGS proposed: diffsend |
| kdc_util.c:785/791 | AS SERVICE LOCKED OUT / SERVICE NOT ALLOWED | 7 / 27 | issue.rs:1680 AS vs :1700 TGS SERVER_* | TGS strings SERVER_* (MIT TGS too) | exact | TGS rows above |
| issue.rs:664 extra | RENEW and VALIDATE together | MIT no dedicated status (opts interact) | issue.rs:664 | `RENEW with VALIDATE` 13 | deviation | `tgs_renew_and_validate_together_is_badoption` |
| security.md realm octets | TGS realm not UTF-8 | MIT uses bytes | issue.rs:1744 | `non-ascii realm` 60 | stricter-documented | docs/security.md TGS realm octets; `tgs_non_ascii_ticket_realm_is_process_tgs` |
| do_tgs_req.c:721 `decrypt_2ndtkt` vs tgs_policy.c:710 | 2nd ticket decrypt in gather, before constraints | 2ND_TKT_* then U2U/S4U policy | issue.rs:747/755 after lineage-adjacent S4U | later; U2U after S4U2Proxy | deviation | proposed: diffsend both flags set |
| kdc_util.c:222-228 | header ticket/authenticator carries `KRB5_AUTHDATA_FX_ARMOR` (armor-only ticket used as a TGT) | PROCESS_TGS 12 (log `ticket valid only as FAST armor`) | `process_tgs_header` issue.rs:588-633 | no FX_ARMOR scan anywhere in `crates/krb5-kdc` | absent (security) | proposed: unit + diffsend armor-marked TGT as PA-TGS-REQ (mirror MIT `t_ad_fx_armor.c`) |
| kdc_util.c:813 `get_ticket_flags` | `OPTS2FLAGS` + `COPY_TKT_FLAGS` on the issued ticket (FORWARDED, PROXY, MAY_POSTDATE, POSTDATED+INVALID, HW_AUTH, ENC_PA_REP, ANONYMOUS) | n/a (flags, not an error) | issue.rs:848-863, 874-879 | sets only TRANSITED/PRE_AUTHENT/FORWARDABLE/RENEWABLE/PROXIABLE/OK_AS_DELEGATE; never FORWARDED, PROXY, MAY_POSTDATE, POSTDATED(+INVALID), ANONYMOUS, HW_AUTH, ENC_PA_REP | deviation | proposed: `flags-gate.sh` cell asserting `f`/`p`/`d`/`H` on a TGS ticket |
| do_tgs_req.c:1019-1027 | ticket addresses: `req->addresses` for FORWARDED/PROXY, else header `caddrs` | n/a | issue.rs:1115 (and 1188) `caddr: None` | addresses always dropped | deviation (laxer: address-restricted TGT → address-free service ticket) | proposed: unit + diffsend addressful TGT |
| do_tgs_req.c:551-555 (`search_sprinc`) | `NO_REFERRAL_OPTION` (FORWARDED/PROXY/RENEW/VALIDATE/ENC_TKT_IN_SKEY) suppresses `KRB5_KDB_FLAG_REFERRAL_OK` | n/a (drops to LOOKING_UP_SERVER 7) | issue.rs:695-697, 716 | no suppression; canonicalize/referral logic runs for u2u/ticket-modification too | absent | proposed: diffsend CANONICALIZE+RENEW |
| do_tgs_req.c:919 `check_kdcpolicy_tgs` | kdcpolicy module deny / times rewrite (distinct from `krb5_db_check_policy_tgs`) | no status → `UNKNOWN_REASON`, module code | plugins.rs:350-375 (`check_as`/`check_tgs` only) | no kdcpolicy hook, no times rewrite | deferred | none (promotion: MIT kdcpolicy module oracle) |
| do_tgs_req.c:686 | `is_crossrealm` = header-server-entry realm ≠ canonical server realm | n/a | issue.rs:763 `prev_hop != store.realm() && prev_hop != crealm` | for the normal cross case (client from REMOTE on a REMOTE cross TGT) Rust computes **false** where MIT computes true → S4U2Self/S4U2Proxy/normal-PAC cross branches never engage | deviation | proposed: unit on `is_crossrealm` truth table |
| ORDER tgs_policy.c:652-665 vs do_tgs_req.c:617 | `check_tgs_tgt` runs inside `check_tgs_constraints` (after PROCESS_TGS/FIND_FAST/GET_LOCAL_TGT/HEADER_PAC/search_sprinc/S4U/2nd-ticket/opts/times) and **only when `NON_TGT_OPTION` is clear** | BAD TGS SERVER NAME 35 last | issue.rs:594 | runs first, before the header ticket is decrypted, unconditionally → refuses RENEW/PROXY of a service ticket that MIT permits via `check_tgs_nontgt` | deviation | proposed: diffsend RENEW of a service ticket |
| issue.rs:645-646 (Rust-only) | any unsupported `KDCOptions` bit | MIT ignores unknown option bits (`OPTS2FLAGS` masks) | issue.rs:645 | `unsupported KDCOptions` 13 | deviation (stricter; no `docs/security.md` row) | proposed: add security.md row + unit |

## A2 — do_as_req.c / kdc_util.c / policy.c / replay.c / dispatch.c

MIT 1.22.2 `src/kdc/{do_as_req,kdc_util,policy,replay,dispatch}.c` vs
`crates/krb5-kdc/src/{issue,listen,store,preauth,ad,plugins}.rs`.
Wire = RFC 4120 protocol code (MIT `errcode_to_protocol`).

| MIT file:line | check (condition) | MIT status + wire code | Rust site | Rust e_text + code | verdict | proof |
| --- | --- | --- | --- | --- | --- | --- |
| do_as_req.c:513-516 | decoded req `msg_type != AS_REQ` | `VALIDATE_MESSAGE_TYPE` + `KRB5_BADMSGTYPE`→**60** | `issue.rs:117` tag `0x6a` only; `KdcReq.msg_type` never read | APPLICATION-10 with msg-type 12 **issues** an AS-REP; other-tag / pvno is **3** `BAD_PVNO` (`issue.rs:140`) | deviation (security: Rust issues what MIT refuses with 60) | proposed: diffsend `as-bad-msg-type`; `handle_inner` |
| do_as_req.c:531-535 | `kdc_find_fast` fail | `FIND_FAST` + 41/60/24 | `preauth.rs:147` `verify_fast_req_checksum` | `FIND_FAST` **41** `MODIFIED` / **60** `GENERIC` / **12** (G3) | exact | `phase7_preauth.rs` FIND_FAST cells |
| do_as_req.c:551-554 | `request->client == NULL` | `NULL_CLIENT` **6** | `issue.rs:265-268` | `no cname` **6** | deviation | proposed: diffsend `as-null-cname` |
| do_as_req.c:562-565 | `request->server == NULL` | `NULL_SERVER` **7** — unreachable live (sname-less AS-REQ dies at `dispatch.c:154` and is **dropped**) | `issue.rs:382-386` | AS synthesizes `krbtgt`; TGS `no sname` **7** | deviation (MIT drops / unreachable single-realm) | proposed: diffsend `as-null-sname` |
| do_as_req.c:581-587 | client `KRB5_KDB_NOENTRY` | `CLIENT_NOT_FOUND` **6** (vague→**60**) | `issue.rs:269-271` | `unknown client` **6** | deviation | diffsend `unknown-cname`; `scripts/rust-kinit-enterprise-gate.sh` |
| do_as_req.c:588-590 | client DB err ≠ NOENTRY | `LOOKING_UP_CLIENT` + com_err | `kdb.rs:95` `fetch_name` `Err` | `as_reply` **60** `e.to_string()` | absent | proposed: diffsend `as-client-db-err` |
| do_as_req.c:600-603 | server `KRB5_KDB_NOENTRY` | `SERVER_NOT_FOUND` **7** | `issue.rs:386-388` | `unknown server` **7** | deviation | diffsend `unknown-sname` |
| do_as_req.c:604-606 | AS server DB err ≠ NOENTRY | `LOOKING_UP_SERVER` + com_err | no AS analogue | — | absent | proposed: diffsend `as-server-db-err` |
| tgs_policy.c:298-302 | S4U `!cross && referral` | `LOOKING_UP_SERVER` **7** | `issue.rs:1623-1624` | `LOOKING_UP_SERVER` **7** | exact | `phase7_preauth.rs` S4U LOOKING_UP_SERVER |
| do_as_req.c:611-615 | client/server DB *entry* realms differ (needs a multi-realm KDB) | `REFERRAL` **68** `WRONG_REALM` | `issue.rs:259-260` | `wrong realm` **6** (`body.realm≠store`, before lookup) — different trigger | deferred (multi-realm KDB; promotion: KDB returning different entry realms) | reachable body.realm cell is diffsend `wrong-realm` (6/6 green) |
| do_as_req.c:618-623 | `get_local_tgt` fail (AS) | `GET_LOCAL_TGT` + KDB err | `issue.rs:432-437` mint `fetch_krbtgt` | `no krbtgt` **7** (not this status) | absent | proposed: diffsend `as-missing-krbtgt` |
| do_tgs_req.c:649-654 | `get_local_tgt` on `sprinc->realm` | `GET_LOCAL_TGT` + KDB err | `issue.rs:685-689` | `GET_LOCAL_TGT` **60** if `body.realm≠store` | exact | `phase7_preauth.rs`; `capaths.rs`; `docs/security.md:60-63` |
| kdc_util.c:727-729 | AS `kdc_options & AS_INVALID_OPTIONS` (FORWARDED/PROXY/RENEW/VALIDATE/ENC_TKT_IN_SKEY/CNAME_IN_ADDL_TKT) | `INVALID AS OPTIONS` **13** | `issue.rs:262-264` `unsupported_bits` includes those bits as supported | AS with VALIDATE/FORWARDED **succeeds** | deviation (security) | proposed: diffsend `as-invalid-opts`; proposed as-invalid-options-gate |
| kdc_util.c:733-738 | `now > client.expiration` | `CLIENT EXPIRED` **1** (vague→**60**) | `issue.rs:1654-1656` | `CLIENT EXPIRED` **1** | exact | `issue_acl_ap.rs::as_rejects_expired_principal_before_expired_password`; `scripts/expire-gate.sh` |
| kdc_util.c:743-749 | `now > pw_expiration` && !PWCHANGE_SERVICE | `CLIENT KEY EXPIRED` **23** | `issue.rs:1658-1661` `pw_lapsed` | `CLIENT KEY EXPIRED` **23** | exact | `issue_acl_ap.rs::as_rejects_expired_password_unless_pwchange_service`; `scripts/expire-gate.sh` |
| kdc_util.c:762-765 | `REQUIRES_PWCHANGE` && !PWCHANGE_SERVICE | `REQUIRED PWCHANGE` **23** | `issue.rs:1658-1661` merges into pw path | `CLIENT KEY EXPIRED` **23** | deviation | proposed: diffsend `as-needchange-etext`; `issue_acl_ap.rs::as_needchange_is_key_expired_unless_changepw` |
| kdc_util.c:753-755 | `now > server.expiration` | `SERVICE EXPIRED` **2** | `issue.rs:1664-1665` | `SERVICE EXPIRED` **2** | exact | `issue_acl_ap.rs::tgs_rejects_expired_server` (TGS); proposed: diffsend `as-service-expired` |
| kdc_util.c:769-774 | POSTDATE/ALLOW_POSTDATE vs DISALLOW_POSTDATED | `POSTDATE NOT ALLOWED` **10** | `issue.rs:1685-1688` | `POSTDATE NOT ALLOWED` **10** | exact | `issue_acl_ap.rs::as_cannot_postdate_when_disallow`; `scripts/postdate-gate.sh` |
| kdc_util.c:778-780 | client `DISALLOW_ALL_TIX` | `CLIENT LOCKED OUT` **18** | `issue.rs:293-294` (+ failcnt lockout) | `locked` **18** | deviation | proposed: diffsend `as-locked-etext`; `scripts/flags-gate.sh`; `scripts/policy-gate.sh`; `issue_acl_ap.rs::as_disallow_all_tix_still_client_revoked` |
| kdc_util.c:784-786 | server `DISALLOW_ALL_TIX` (AS) | `SERVICE LOCKED OUT` **7** | `issue.rs:1679-1680` | `SERVICE LOCKED OUT` **7** | exact | proposed: diffsend `as-service-locked` (no e_text unit); TGS is `SERVER LOCKED OUT` `issue_acl_ap.rs:1232` |
| kdc_util.c:790-792 | server `DISALLOW_SVR` (AS) | `SERVICE NOT ALLOWED` **27** | `issue.rs:1682-1683` (skip if ENC_TKT_IN_SKEY — TGS exemption copied onto AS) | `SERVICE NOT ALLOWED` **27** (AS with ENC_TKT_IN_SKEY against DISALLOW_SVR **issues**) | deviation (security) | proposed: diffsend `as-service-not-allowed`; TGS `scripts/flags-gate.sh` DISALLOW_SVR |
| kdc_util.c:700-712,796-797 | `restrict_anon` && anon client && !local TGS | `ANONYMOUS NOT ALLOWED` **12** | no `restrict_anon`; ANONYMOUS bit not in `unsupported_bits` allow-list | AS ANONYMOUS → `unsupported KDCOptions` **13** | absent | proposed: diffsend `as-anon-restrict`; `as-anonymous-principal` |
| do_as_req.c:718-724 | `REQUEST_ANONYMOUS` && cname ≠ WELLKNOWN/ANONYMOUS | `VALIDATE_ANONYMOUS_PRINCIPAL` **13** | same: bit rejected before principal check | `unsupported KDCOptions` **13** | deviation | proposed: diffsend `as-anon-cname` |
| do_as_req.c:641-648 | `select_session_keytype`==0 (server session_enctypes + permitted) | `BAD_ENCRYPTION_TYPE` **14** | `issue.rs:1211-1223` first requested etype with **client** long-term key | `no common etype` **14** | deviation | `issue_acl_ap.rs::no_common_etype_is_etype_nosupp`; `scripts/differential-gate.sh` etype-nosupp; proposed: diffsend `as-session-etype` |
| kdc_util.c:1084-1112 | session etype vs server `session_enctypes` / AES256 default | 0 → BAD_ENCRYPTION_TYPE | session=`select_etype` (client key etype), not server session list | coupled to client key | deviation | proposed: diffsend `as-session-enctypes-attr` |
| do_as_req.c:736-741 | `select_client_key` decrypt fail | `DECRYPT_CLIENT_KEY` + decrypt err | keys already in store; no runtime decrypt | — | deferred | none (dump-time decrypt only) |
| do_as_req.c:747-751 | `kdc_fast_read_cookie` | `READ_COOKIE` | `preauth.rs:246-254` SPAKE/FAST cookie | `bad cookie` **24**; MIT `fast_util.c:610` **always returns 0** (status dead in 1.22.2) | absent | proposed: diffsend `as-mit1-cookie` |
| do_as_req.c:439-442 | `check_padata` fail | `PREAUTH_FAILED` **24** (vague→**60**) | `as_reply` crypto→**24** `preauth`; EncTs/SPAKE/PKINIT own texts | not the string `PREAUTH_FAILED` | deviation | proposed: diffsend `as-bad-enc-ts-etext`; `issue_acl_ap.rs` wrong-password **24** |
| kdc_preauth.c:743-749; do_as_req.c:455-457 | missing PRE_AUTH / HW_AUTH after padata | `NEEDED_PREAUTH` **25** / `NEEDED_HW_PREAUTH` **25** | `issue.rs:375-379` `preauth_required` **25** (empty e_text; log NEEDED_PREAUTH); HW: `NO HW PREAUTH` **24** | HW **24** vs MIT **25** | deviation | `issue_acl_ap.rs::as_hw_auth_required_rejects_enc_ts`; `scripts/flags-gate.sh` |
| tgs_policy.c:174-177 | TGS server REQUIRES_HW_AUTH && !HW_AUTHENT | `NO HW PREAUTH` **60** | `issue.rs:1708-1709` | `NO HW PREAUTH` **60** | exact | `issue_acl_ap.rs::tgs_requires_hw_auth_without_hw_flag` |
| do_as_req.c:218-221 | `check_kdcpolicy_as` plugin | plugin `*status` | `plugins.rs:368-370` `DefaultPolicy::check_as` Ok; `issue.rs:296` **before** preauth | `kdcpolicy` **12** only if DenyPolicy | absent | proposed: diffsend `as-kdcpolicy-plugin` |
| policy.c:103-136 | kdcpolicy module endtime + deny (`check_kdcpolicy_as`) | plugin status + ret | `plugins.rs:349-375` stub | no MIT plugin load | deferred | none |
| do_as_req.c:225-229 | `get_first_current_key(server)` fail | `FINDING_SERVER_KEY` + KDB err | `issue.rs:389-392` before mint | `no server key` **7** | deviation | proposed: diffsend `as-no-server-key` |
| do_as_req.c:251-256 | `return_padata` fail | `KDC_RETURN_PADATA` + mech err | extra_padata SPAKE/PKINIT/ETYPE; no MIT return_padata | various | absent | proposed: diffsend `as-return-padata` |
| do_as_req.c:261-264 | client_keyblock ENCTYPE_NULL && no replaced reply key | `CANT_FIND_CLIENT_KEY` **14** | `issue.rs:297-300` requires client key **before** preauth | `no common etype` **14** or `no client key` **6**; PKINIT-without-keys cannot proceed | deviation | proposed: diffsend `as-pkinit-nokey`; `as-null-client-enctype` |
| do_as_req.c:270-281 | `handle_authdata` fail | `HANDLE_AUTHDATA` + ad err | `issue.rs:443` `mint_ticket` PAC | PAC `PAC logon: {e}` **31**; no MIT ad plugins | absent | proposed: diffsend `as-authdata-fail` |
| do_as_req.c:284-287; kdc_util.c:862-887 | `check_indicators` / `require_auth` string | `HIGHER_AUTHENTICATION_REQUIRED` **12** | no `require_auth` | — | absent | proposed: diffsend `as-require-auth`; gate `require-auth-gate` |
| do_as_req.c:316-321 | `return_enc_padata` fail | `KDC_RETURN_ENC_PADATA` | `issue.rs:1189` `encrypted_pa_data: None` | — | deferred | none (RFC 6806 enc padata oracle; F7) |
| do_as_req.c:346-347 | err && status==NULL | `UNKNOWN_REASON` | `proto()` always sets text; leftover **60** `e.to_string()` | no `UNKNOWN_REASON` | deferred | none (only if an AS path returns Protocol without text) |
| kdc_util.c:1320-1323 | `decode_krb5_pa_for_user` fail | `DECODE_PA_FOR_USER` + ASN.1 | `ad.rs:283` `decode(raw)?` | TGS `asn1` **60** | deviation | proposed: diffsend `tgs-pa-for-user-undecodable` |
| kdc_util.c:1326-1330,1434-1438 | FOR-USER / S4U-X509 checksum fail | `INVALID_S4U2SELF_CHECKSUM` **41** failed verify / **50** unkeyed (both sites) | `ad.rs:292-293` | `PA-FOR-USER` **50** `INAPP_CKSUM` (both) | deviation (code 50 vs 41) | `phase7_preauth.rs::s4u2self_bad_checksum_rejected`; proposed: diffsend `s4u-cksum-etext` |
| kdc_util.c:1422-1425 | `decode_krb5_pa_s4u_x509_user` fail | `DECODE_PA_S4U_X509_USER` | `pa::FOR_X509_USER` unused (`ad.rs` only FOR_USER) | ignored | absent | proposed: diffsend `pa-s4u-x509-user`; `s4u-x509-gate.sh` |
| kdc_util.c:1441-1446 | empty user && empty subject_cert | `INVALID_S4U2SELF_REQUEST` **6** | no X509-USER path | — | absent | proposed: diffsend `s4u-x509-empty` |
| kdc_util.c:1604-1606 | S4U client `KDB_NOENTRY` | `UNKNOWN_S4U2SELF_PRINCIPAL` **6** | `issue.rs:718-721` | `S4U2Self` **6** | deviation | `phase7_preauth.rs::s4u2self_unknown_for_user_is_refused`; `scripts/s4u-mit-gate.sh` |
| kdc_util.c:1607-1609 | S4U client DB err ≠ NOENTRY | `LOOKING_UP_S4U2SELF_PRINCIPAL` + com_err | `fetch_name` Err | **60** store err | deferred | none (named store-fail hook) |
| kdc_util.c:1453-1530 | `kdc_make_s4u2self_rep` PA-S4U-X509-USER in TGS-REP | no status (reply padata) | `issue.rs:939-956` only `SUPPORTED_ENCTYPES` / FAST | no S4U2Self reply PA | absent | proposed: diffsend `s4u2self-rep-padata` |
| kdc_util.c:1534-1548; tgs_policy.c:273-276 | `is_client_db_alias` header client vs server | mismatch → `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH` **36** | `issue.rs:726-735` name+realm | same **36** | exact | `phase7_preauth.rs`; `scripts/s4u-mit-gate.sh`; `docs/security.md:67-69` |
| kdc_util.c:318-346 | `kdc_rd_ap_req` kvno==0: ≤3 tries, decrement kvno; local TGS `search_enctype=-1` | PROCESS_TGS / rd_req err | `issue.rs:1017-1033` kvno hit then **all** keys | `PROCESS_TGS` **31** | deviation | proposed: diffsend `tgs-kvno0-ad`; `decrypt_presented_tgt` |
| kdc_util.c:370-398,438-448 | `kdc_get_server_key`: DISALLOW_SVR/ALL_TIX → 7; enctype-mismatch (`:438-448`) → 60 GENERIC (`KRB5_KDB_NO_PERMITTED_KEY` outside 0..128) | DISALLOW half **7**; enctype-mismatch half **60** | `issue.rs:1011-1012` same **7** `PROCESS_TGS` | `PROCESS_TGS` **7** on DISALLOW; enctype-mismatch not split | deviation (enctype-mismatch 60 vs not split) | `docs/security.md:74-75` |
| kdc_util.c:144-191 | TGS AP-REQ replay cache (`auth_con_setflags 0` — MIT disables) | no rcache | `issue.rs:678-679` | TGS replay **34** `TGS authenticator replay` | stricter-documented | `issue_acl_ap.rs::tgs_authenticator_replay_is_repeat`; `docs/security.md:19` |
| do_tgs_req.c:617-675 vs issue.rs:666-697 | **ORDER TGS**: MIT PROCESS_TGS(rd_req times, no rcache)→FAST→NULL_SERVER→**GET_LOCAL_TGT→HEADER_PAC→search_sprinc**→S4U→…→`check_tgs_times`. Rust PROCESS_TGS(no times)→FAST→**check_ticket_times→tgs_replay→GET_LOCAL_TGT→search_sprinc** | times/RENEW-not-renewable **after** search_sprinc | times+replay **before** GET_LOCAL_TGT | RENEW/VALIDATE/expired can 32/13 before 60/7 | deviation | proposed: diffsend `tgs-renew-unrenewable-foreign-realm`; `tgs-expired-vs-unknown-sname` |
| do_as_req.c:577-762 vs issue.rs:259-394 | **ORDER AS**: MIT NULL_C/S→lookup c/s→REFERRAL→GET_LOCAL_TGT→**validate_as (expiry then lockout)**→etype→anon→client key→cookie→**preauth**. Rust realm→opts→client→**lockout**→etype→**preauth**→HW→**then** server→times→flags | lockout after expiry; preauth after server+policy | lockout first; preauth before server/times | locked client never hits NAME_EXP; bad EncTs never hits unknown server | deviation | proposed: diffsend `as-expired-and-locked`; `as-bad-pa-unknown-server` |
| replay.c:59,166-187; dispatch.c:114-141 | lookaside: hash full pkt; in-progress NULL→drop; hit resend success only (`dispatch.c:82`); stale 2 min. MIT TGS has no rcache (`kdc_util.c:190-191`) | cached TGS-REP on UDP retransmit; KRB-ERRORs recomputed | `listen.rs:222-230` `handle_request` per datagram; no pkt cache | identical UDP TGS retransmit → **34** (rcache without lookaside) | deviation (UDP TGS retransmit → 34); the cache itself stays deferred | proposed: unit + proposed: diffsend `udp-retransmit-lookaside`; proposed kdc-lookaside-gate.sh |
| dispatch.c:177-209 | UDP reply > `max_dgram_reply_size` (default 65536, path dead unless configured down) | `KRB_ERR_RESPONSE_TOO_BIG` **52** | `listen.rs` UDP send full reply | `listen.rs` UDP send full reply; no **52** | absent | proposed: diffsend `udp-too-big`; proposed kdc-udp-size-gate.sh |
| dispatch.c:145-150 | non-AS/TGS pkt | no packet (`response == NULL` → `net-server.c:1101-1105` drop); status `MSG_TYPE` is not on the wire | `issue.rs:138-144` | **3** `BAD_PVNO` (`issue.rs:138-144`) | deviation (MIT drops / unreachable as a wire code) | diffsend `garbage-pdu` (`mit-drop-garbage-pdu` whitelist) |
| dispatch.c:154-157 | `setup_server_realm` NULL | **68** `WRONG_REALM` — unreachable on a single-realm KDC (`main.c:127-132`); never on the wire | single-realm; AS **6** `wrong realm`; TGS **60** `GET_LOCAL_TGT` | single-realm; AS **6** `wrong realm`; TGS **60** `GET_LOCAL_TGT` | deviation (MIT drops / unreachable single-realm) | `docs/security.md:60-63`; diffsend `wrong-realm` |
| kdc_util.c:169-171 | no PA-TGS-REQ (`KRB5_PADATA_AP_REQ`) — split from the rcache row | PROCESS_TGS 16 `PADATA_TYPE_NOSUPP` | issue.rs:570-571 | `no PA-TGS-REQ` 24 | deviation (code 24 vs 16) | proposed: diffsend; proposed: MIT-client `kdc-gate.sh` cell |
| kdc_util.c:1881-1913; net-server.c:1391-1414 | TCP length prefix > `bufsiz-4` | no status; `KRB_ERR_FIELD_TOOLONG` **61** | `listen.rs:365-370` | none — `InvalidData`, connection closed, **no packet** | absent | proposed: diffsend `tcp-length-toolong`; MIT oracle `kdc/t_bigreply.py:21-31` |
| kdc_util.c:800-803; lockout.c:92-113 | `krb5_db_check_policy_as` failcount lockout — **last** check in `validate_as_request` | `LOCKED_OUT` **18** | `issue.rs:279-295` — **first** check, before etype/preauth/server | `locked` **18** | deviation | `store.rs::failed_as_stamps_last_failed`; proposed `policy-gate.sh` order cell |
| lockout.c:102-104 | not locked if `last_admin_unlock >= last_failed` | n/a | `store.rs:1099-1117` `set_status(locked=false)` clears `KDB_DISALLOW_ALL_TIX` only; `clear_as_fail_count` is called **only** from `issue.rs:287` | stays 18 `locked` when `pw_lockout_duration == 0` | absent | proposed: unit `unlock_clears_failcount`; `kadmin-gate.sh` unlock cell |
| do_as_req.c:579-580,598-599 | `KRB5_KDB_CANTLOCK_DB` on client/server lookup | no status; `KRB5KDC_ERR_SVC_UNAVAILABLE` **29** | `kdb.rs` `fetch_name` `Err` | **60** `e.to_string()` | absent | proposed: diffsend `as-db-locked`; deferred if no lockable KDB |
| do_as_req.c:236-241 | `fetch_last_req_info` + `get_key_exp(client)` into AS-REP enc-part | no status (reply fields) | `issue.rs:1175-1180` | `last_req` hardcoded `lr_type: 0`/now; `key_expiration: None` | absent | MIT `kinit` password-expiry warning; proposed `expire-gate.sh` warn cell |
| do_as_req.c:709-712 | `starttime == authtime` → omit `starttime` | no status | `issue.rs:1112,1183` | `starttime` always `Some(..)` | deviation | CHANGELOG G7 `klist starttime==0`; proposed `client-gate.sh` cell |
| do_as_req.c:656-664 | CANONICALIZE + both TGS principals → ticket sname = `server->princ` | no status | `issue.rs:449` mints the **requested** `sname` | requested sname echoed | absent | proposed `rust-kinit-enterprise-gate.sh` canonicalize cell |
| kdc_util.c:1612-1615 | S4U2Self clears impersonated client's `pw_expiration` + `REQUIRES_PWCHANGE` (as Windows does) | n/a (exemption) | `issue.rs:1644-1648` `check_s4u2self_locked` → `check_db_times` enforces both | **23** `CLIENT KEY EXPIRED` where MIT issues | deviation (stricter, undocumented) | proposed `s4u-mit-gate.sh` expired-user cell + `docs/security.md` row |
| asn1_k_encode.c:30 | `pvno != 5` | decode error `KRB5KDC_ERR_BAD_PVNO` **3** → dispatch drop | `krb5-types/src/lib.rs:557-558` decoded, never read | accepted; AS-REP issued | deviation (security: Rust issues what MIT drops) | proposed: diffsend `as-bad-pvno` (sibling of the msg-type row) |

## A3 — kdc_preauth*.c / fast_util.c / kdc_authdata.c / cammac.c / kdc_log.c

MIT 1.22.2 `src/kdc/` vs kerber-rust. Lines actually read. Wire codes
are RFC 4120/6113 integers. After W0d G3, FAST unwrap failures wire
`FIND_FAST`; the MIT log message is `kdc.issue` `detail`.

| MIT file:line | check (condition) | MIT status + wire code | Rust site | Rust e_text + code | verdict | proof |
| --- | --- | --- | --- | --- | --- | --- |
| kdc_preauth.c:999-1000 | PREAUTH_REQUIRED hint: empty PA-FX-FAST (136) first, then ETYPE-INFO (11), then 19, then modules | no status; METHOD-DATA `[136, (11), 19, modules]` | plugins.rs:64-76 FastMod.advertise; issue.rs:1440-1458 | n/a (e_data 136); order `[136, 16, 109, 151, 2, 19]` — 19 last | deviation (order) | `ca_enabled_preauth_required_method_data_types`; `scripts/mit-fast-kdc-gate.sh` |
| kdc_util.c:1768-1801 + :822-824; do_as_req.c:316-320 | RFC 6806 FAST nego: if PA 149, enc_padata 149 cksum + empty 136; ticket flag ENC_PA_REP | success silent; fail `KDC_RETURN_ENC_PADATA` | issue.rs:1173-1189 `encrypted_pa_data: None`; no ENC_PA_REP bit | MIT kinit writes no `fast_avail`/`pa_type` (client fast.c:626-671) | absent | proposed: propose `scripts/mit-fast-nego-gate.sh` (kinit then `klist -C` `fast_avail`); diffsend enc_padata |
| kdc_preauth.c:1003-1004 + :767-799 | hint always PA-ETYPE-INFO2; ETYPE-INFO only for old ktypes | chosen client etype | issue.rs:1443-1456 all client keys | 19 present; etype set ⊇ MIT | deviation | proposed: diffsend `compare_preauth_e_data` (already MIT ⊆ Rust); pin chosen-etype |
| kdc_preauth.c:779-823 | PA-ETYPE-INFO (11) + PW-SALT (3) for pre-info2 clients | in hint + AS-REP if !key_modified | none in KDC issue/plugins | absent | absent | proposed: diffsend old-enctype AS; propose `scripts/mit-etype-info-gate.sh` |
| kdc_preauth.c:1141-1170 | MORE_PREAUTH_DATA_REQUIRED: add ETYPE-INFO2 unless cookie already seen | **91** `MORE_PREAUTH_DATA_REQUIRED` + PA 19 (unless cookie already seen) | `issue.rs:344` `MORE_PREAUTH_DATA_REQUIRED` | SPAKE challenge **91** `MORE_PREAUTH_DATA_REQUIRED`; no extra 19 | deviation | `scripts/rust-kinit-spake-gate.sh`; proposed: diffsend 91 e_data |
| do_as_req.c:786-796; fast_util.c:653-676 | AS error e_data gets PA-FX-COOKIE (133) **only when `e_data_in != NULL`**; empty = 3-byte `MIT` (not MIT1) when no module state | cookie on e_data-bearing errors | preauth_required omits 133; wrap_as_fast:1411-1415 only FAST errors | preauth_required omits 133; wrap_as_fast:1411-1415 only FAST errors | absent | proposed: diffsend PREAUTH_REQUIRED types; `diff.rs:157-158` currently ignores 133/136 |
| fast_util.c:545-610 + :656-721 | cookie MIT1+kvno+enc, ku 513, PRF+ `COOKIE`+princ, TTL 600s; non-MIT1/undecryptable ignored (`return 0` at :610; PREAUTH_EXPIRED dead in 1.22.2) | `READ_COOKIE` do_as_req.c:747-752 (fn actually `return 0`) | preauth.rs:234-255 encrypt krbtgt `best_key()` (preferred enctype, not kvno) ku `FAST_COOKIE`=54 | `bad cookie` 24; no client bind, no TTL, no kvno index. ku-54 vs ENC_CHALLENGE_CLIENT 54 is a naming collision with no shared key | deviation (security: no client bind / no 600s TTL) | proposed: unit MIT1 round-trip; proposed mit-fx-cookie-gate.sh |
| kdc_preauth.c:129-141 | auto-register pkinit, otp, spake, encrypted_challenge, encrypted_timestamp | module edata into hint | plugins.rs:279-287 Fast/Pkinit/Spake/EncTs; no otp | otp types 141/142 unused | absent (otp) | propose `scripts/proposed mit-otp-gate.sh` or defer otp; pkinit/spake: `scripts/pkinit-gate.sh` `scripts/spake-gate.sh` |
| plugins pkinit edata | PA-PK-AS-REQ (+ TD-DH) when CA | empty 16 | plugins.rs:99-112 only if `pkinit_ca` | 16+109 iff CA | exact | `pkinit_advertised_in_method_data_when_ca_enabled`; `pkinit_not_advertised_without_ca` |
| SPAKE plugin edata | empty 151 in hint | 151 | plugins.rs:154-158 always | 151 always | exact | `ca_enabled_preauth_required_method_data_types` (types `[136,16,109,151,2,19]`) |
| kdc_preauth_ec.c:37-48 | EC hint only if armor_key && client keys; FAST-inner METHOD-DATA keeps empty 136 and 151 | empty 138 | wrap_as_fast:1370-1381 strips 136/151, inserts 138 | wrap_as_fast:1370-1381 strips 136/151, inserts 138 | deviation (FAST-inner METHOD-DATA strips 136/151) | `encrypted_challenge_skew_is_fast_wrapped`; proposed FAST-inner METHOD-DATA pin |
| kdc_preauth_ec.c:71-76 | EC outside FAST | wire **24** `PREAUTH_FAILED` (ENOENT filtered; log `Encrypted Challenge used outside of FAST tunnel`) | issue.rs:358-360 only if `fast` | ignored → NEEDED_PREAUTH 25 | deviation | proposed: diffsend non-FAST 138; proposed `scripts/mit-fast-kdc-gate.sh` cell |
| kdc_preauth_ec.c:101-118 | EC decrypt fail | `PREAUTH_FAILED` 24 `Incorrect password in encrypted challenge` | issue.rs:1261-1262 | `encrypted challenge` 24 | deviation | `encrypted_challenge_wrong_key_locks_at_max_fail`; e_text mismatch |
| kdc_preauth_ec.c:124-126 | EC clockskew | SKEW 37 | issue.rs:1269-1271 | `encrypted challenge skew` 37 | exact | `encrypted_challenge_stale_ts_is_skew` |
| kdc_preauth_ec.c:87-140 | EC success: PRE_AUTH + optional auth-indicator | CAMMAC later | issue.rs:363-367 skip_ts; no indicator | no CAMMAC/AD-97 | absent | propose CAMMAC unit + `scripts/mit-fast-kdc-gate.sh` |
| kdc_preauth_ec.c:154-205 | EC return: KDC challenge ku 55 | PA 138 in AS-REP (FAST inner) | issue.rs:1286-1311 | 138 on success | exact | `encrypted_challenge_*`; phase7 FAST AS |
| kdc_preauth_encts.c:39-43 | ENC_TIMESTAMP hint iff !armor && have keys | empty 2 | EncTsMod.advertise always 2; wrap_as_fast keeps 2 | FAST inner still lists 2 | deviation | FAST METHOD-DATA pin; propose mit-fast-kdc-gate dump inner padata |
| kdc_preauth_encts.c:47-118 | ENC_TS verify; NO_MATCHING_KEY→24 | 24; SKEW 37 pass-through (filter :1101) | issue.rs:1314-1341 | skew 37; replay 34 `PA-ENC-TIMESTAMP replay` (MIT has no enc-ts rcache; filter maps unknown→24) | stricter-documented | `pa_enc_timestamp_replay_is_repeat`; docs/security.md replay row |
| kdc_preauth.c:1394-1506; do_as_req.c:251-256 | return_padata; fail `KDC_RETURN_PADATA` | `KDC_RETURN_PADATA` | extra_padata SUPPORTED_ENCTYPES; no status | status absent; AS-REP padata ≠ MIT etype-info2 | absent | `diff.rs` `mit_as_padata` whitelist; `as_rep_advertises_supported_enctypes` |
| return_enc_padata kdc_preauth.c:1636-1663; do_tgs_req.c:1098-1104 | enc_padata: referral + FAST nego + PAC-OPTIONS | `KDC_RETURN_ENC_PADATA` | never filled | absent | absent | proposed: diffsend EncKDCRepPart tag 12; propose mit-fast-nego-gate |
| kdc_preauth.c:1578-1609 | PA-PAC-REQUEST (128) include_pac; default TRUE | omit PAC if false | issue.rs:431/893 only `NO_AUTH_DATA_REQUIRED` | always PAC | deviation | propose `scripts/ad-windows-gate.sh` / unit PA-PAC-REQUEST=false |
| fast_util.c:207-224 (post-E3) | verify req_checksum **then** keyed-cksum | bad bytes 41 FIND_FAST; unkeyed 12 FIND_FAST (log `Unkeyed checksum used in fast_req`); unknown type 60 FIND_FAST; keyed types match by enc provider (`crypto_int.h:596-608`); cksumtype 0 → mandatory then `is_keyed(0)` → 12 | preauth.rs verify then `is_keyed`; `verify_checksum_type` provider match | 41/12/60 FIND_FAST (G2+G3+H2; detail holds the MIT log text) | exact | `fast_as_rsa_md5_unkeyed_is_policy`; `fast_as_unkeyed_type_with_bad_bytes_is_modified`; `fast_as_crc32_checksum_is_generic`; `fast_as_short_mac_is_generic`; `fast_as_arcfour_hmac_type_over_aes_key_wrong_bytes_is_modified`; `fast_as_same_provider_type_wrong_bytes_is_modified`; `fast_as_cross_provider_type_is_generic`; `fast_as_cksumtype_zero_valid_mac_is_policy`; proposed diffsend `-138`/type-0 |
| do_as_req.c:526-532 | AS checksum over wire KDC-REQ-BODY (field 4) | `FIND_FAST` | unwrap_fast_as body_der; issue.rs:302-307 | `FIND_FAST` | exact | E3; `scripts/mit-fast-kdc-gate.sh` |
| fast_util.c:159-163 | TGS explicit AP-REQ armor **with** tgs_subkey | FIND_FAST 24 (log `Ap-request armor not permitted with TGS`) | preauth.rs:81-86 always reject armor | FIND_FAST 24 (G3; detail is the previous e_text) | exact | `tgs_fast_explicit_armor_is_preauth_failed` |
| fast_util.c:157-166 | TGS explicit AP-REQ armor **without** tgs_subkey → `armor_ap_request` | may succeed or FIND_FAST 12 (log `ap-request armor without subkey`) | preauth.rs:81-86 still 24 | preauth.rs:81-86 still FIND_FAST 24 | stricter-documented | docs/security.md:86-88; proposed unit `tgs_fast_explicit_armor_no_subkey` + mit-fast-kdc-gate cell |
| fast_util.c:180-184 | TGS FAST, no armor, no subkey | FIND_FAST 24 (log `No armor key but FAST armored request present`) | preauth.rs:87-91 | FIND_FAST 24 (G3) | exact | `tgs_fast_without_subkey_is_preauth_failed` |
| fast_util.c:70-76 | AS AP-REQ armor missing authenticator subkey | FIND_FAST 12 POLICY (log `ap-request armor without subkey`) | preauth.rs:225-231 `Ok(session)` | accepts; armor=TGT session (`preauth.rs:225-231` `Ok(session)`) | deviation (security) | proposed: unit + `scripts/mit-fast-kdc-gate.sh` no-subkey armor (MIT clients always send a subkey) |
| fast_util.c:277-355 + :427-440 | FAST reply always strengthen_key; CF2 replykey (`kdc_fast_response_handle_padata` / `kdc_fast_handle_reply_key`; no `kdc_fast_strengthen_reply_key` symbol). MIT client copies existing_key when strengthen_key is NULL | silent | AS issue.rs:492-503 exact; TGS issue.rs:943-951 `strengthen=None`, enc with subkey/session | AS issue.rs:492-503 exact; TGS issue.rs:943-951 `strengthen=None` | deviation (parity, not interop-breaking) | `fast_as_exchange_strengthen_and_finished` (AS only); proposed TGS strengthen pin in mit-fast-kdc-gate |
| fast_util.c:443-447; do_as_req.c:324-325 | hide-client-names (bit 1) anonymizes reply client | known option; hide-client-names (bit 1) anonymizes reply client | issue.rs:1345-1354 refuse any bit 0..15 | issue.rs:1345-1354 refuse any bit 0..15; **93** `FIND_FAST` (G3; detail `FAST option`) | stricter-documented (bit 1 refused; MIT supports it) | `hide_client_names_is_refused`; docs/security.md |
| kdc_preauth.c:1092-1133 | filter_preauth_error: unknown → 24 | 24 default | issue.rs leaks 34 REPEAT (enc-ts/EC), etc. | 34 vs MIT 24 | stricter-documented | `encrypted_challenge_replayed_blob_is_repeat`; security.md |
| do_as_req.c:270-281; do_tgs_req.c:1038-1046 | handle_authdata fail | `HANDLE_AUTHDATA` + LOG_INFO `AS_REQ/TGS_REQ : handle_authdata (%d)` | issue.rs:1118-1143 mint_ticket PAC inline | no `HANDLE_AUTHDATA` (status-strings.txt absent) | absent | working/logs/.../mit-vs-rust-status-strings.txt; propose e_text on PAC fail |
| kdc_authdata.c:576-627 | HANDLE_AUTHDATA order: copy TGS body AD → kdcauthdata plugins → copy TGT AD → handle_pac | POLICY 12 if AD-MANDATORY-FOR-KDC | no copy_request/copy_tgt; AD_MANDATORY_FOR_KDC const only | uncopied AD dropped | absent | proposed: propose TGS-body AD unit; diffsend |
| kdc_authdata.c:300-336; cammac.c:55-127 | auth indicators → AD-97 inside CAMMAC (96) + IF-RELEVANT; ku 64 (`add_auth_indicators`) | ticket AD | no CAMMAC/AD-97 in crates | absent | absent | propose CAMMAC encode/verify unit |
| cammac.c:134-175 | cammac_check_kdcver over EncTicketPart with CAMMAC elements as AD | ignore unverified CAMMAC | none | absent | deferred | none (promotion: CAMMAC create/verify) |
| kdc_authdata.c:517-564 vs :456-494 | PAC: issue_pac → **add_auth_indicators (CAMMAC)** → client/deleg info → sign PAC | CAMMAC in tkt before PAC sign | ad.rs:30-131 sign_pac 16→19→6→7 only; mint_ticket placeholder then PAC | PAC-only; no CAMMAC | deviation | `crates/krb5-kdc/tests/ad_pac.rs`; samba-pac-*-gate.sh (PAC sigs only) |
| kdc_authdata.c:488-494 | TGS: no PAC if subject_pac==NULL (still indicators) | skip PAC | issue.rs:750-752 missing PAC ok, still mint PAC | PAC on MIT-TGT TGS | deviation | propose TGS-from-MIT-TGT PAC-absent pin |
| do_tgs_req.c:657-664 | HEADER_PAC verify immediately after FAST unwrap | `HEADER_PAC` | presented_tgt_logon after S4U/policy (issue.rs:750) | `PAC …` 31 not `HEADER_PAC` | deviation | ad.rs:213-241; status-strings.txt |
| kdc_log.c:76-90 | AS fail/success LOG_INFO `AS_REQ (%s) %s: STATUS: cname for sname` | two formats: success `AS_REQ (%s) %s: ISSUE: authtime %u, %s, %s for %s` (76-83); fail `AS_REQ (%s) %s: %s: %s for %s%s%s` (85-89) | issue.rs:72-86 tracing::info `kdc.issue` JSON: event, correlation_id, duration_us, outcome, code, e_text | issue.rs:72-86 tracing::info `kdc.issue` JSON: event, correlation_id, duration_us, outcome, code, e_text, detail | deviation | docs/logging.md; proposed kdc-gate JSON field pin |
| kdc_log.c:142-152 | TGS LOG_INFO same shape | `TGS_REQ (%s) %s: %s: authtime %u, %s%s %s for %s%s%s` (146-152) plus PROTOCOL-TRANSITION / CONSTRAINED-DELEGATION lines (153-160) and SERVER_NOMATCH special case (142-143) | same `kdc.issue` | same `kdc.issue` | deviation | docs/logging.md |
| kdc_log.c:201-206 | unexpected transit check: LOG_ERR | ERR | issue.rs BAD_TRANSIT/ILL_CR_TKT still info krb-error | info vs ERR | deviation | capaths tests; propose log-level pin |
| kdc_preauth.c:1224-1228 | preauth verify fail LOG_INFO `preauth (%s) verify failure: %s` | INFO | preauth.rs:418-532 PKINIT `tracing::error!` on expected CMS/cert/checksum/AuthPack | ERROR vs MIT INFO | deviation | propose demote PKINIT client fails to info; kdc-gate log |
| kdc_audit.c:143-171 + :178-210 + :258-341 | audit plugin: SHA256 tkt_id, req_id[32], cl_addr/port, stage, kau_as/tgs/s4u/u2u | plugin | krb5-log correlation_id hex; no tkt hash, addr, stage, plugin | JSON ≠ MIT audit state | deferred | none (audit plugin; docs/logging.md metrics deferred) |
| kdc_preauth.c:826-871 + :508-564 | PA-AS-FRESHNESS token 600s | PREAUTH_EXPIRED | none | absent | deferred | none (PA-AS-FRESHNESS / Batch D) |
| kdc_preauth.c:902-904 | empty hint list LOG_INFO | INFO | always ads 136+2+19(+151) | n/a | exact | method-data unit |
| diff.rs:157-159 | PREAUTH_REQUIRED compare requires only 2+19; extras are “mechanism ads (Rust SPAKE 151 vs MIT FAST 133/136)” | n/a | whitelist hides missing 133 and treats 136 as optional vs MIT cookie | not a wire check | deviation | proposed: diffsend; **require 136**; add 133 once cookie shipped |
| kdc_util.c:218-227 | header ticket **or** authenticator carries AD-FX-ARMOR (71) → ticket usable only as FAST armor (same family as A1 `kdc_util.c:222-228`) | `PROCESS_TGS` 12 POLICY (msg `ticket valid only as FAST armor`, log-only) | none — no `FX_ARMOR` in `crates/` | absent | absent (security) | proposed: unit mirroring MIT `lib/krb5/krb/t_ad_fx_armor.c`; diffsend armor-AP-REQ replayed as PA-TGS-REQ |
| fast_util.c:62-67 | armor AP-REQ ticket server ≠ local TGS (`krb5_principal_compare_any_realm`) | `FIND_FAST` 26 SERVER_NOMATCH (log `ap-request armor for something other than the local TGS`) | preauth.rs:185-187 | `FIND_FAST` 26 (G3; detail `FAST armor TGT`) | exact | `fast_as_armor_for_host_ticket_is_server_nomatch`; `docs/security.md:71-73` |
| fast_util.c:53-59 | armor `krb5_rd_req` failure (bad key / unknown server / expired) | `FIND_FAST` + inner code (log `%s while handling ap-request armor`) | preauth.rs:178-205 | `FIND_FAST` 35 / 31 / 34 / 32 (G3; detail `FAST armor TGT` / `INVALID` / `expired`) | exact | `explicit_as_armor_invalid_tgt_is_tkt_nyv`; proposed: diffsend |
| fast_util.c:167-170 | unknown FAST armor type | `FIND_FAST` 24 (log `Unknown FAST armor type %d`) | preauth.rs:163-167 | `FIND_FAST` 24 (G3; detail `Unknown FAST armor type {}`) | exact | `fast_as_unknown_armor_type_is_preauth_failed`; `docs/security.md:84-85` |
| fast_util.c:225-228 (`UNSUPPORTED_CRITICAL_FAST_OPTIONS 0xbfff0000`) | critical fast-option bits 0 and 2..15 (bit 1 = hide-client-names is **supported** by MIT, k5-int.h:803) | `FIND_FAST` 93 | issue.rs:1349-1356 `check_fast_options` | `FIND_FAST` 93 for bits 0..15 incl. bit 1 (G3) | stricter-documented (bit 1) | `hide_client_names_is_refused`; `docs/security.md` |
| fast_util.c:364-424 `kdc_fast_handle_error` | FAST error shape: inner padata = `[caller e_data…, PA-FX-COOKIE, PA-FX-ERROR]`, `strengthen_key = NULL`, `finished = NULL`; outer = single PA-FX-FAST | silent | issue.rs:1394-1420 | `[FX_ERROR, FX_COOKIE, method…]` — same set, FX_ERROR first | deviation (order) | `encrypted_challenge_skew_is_fast_wrapped`; proposed: order pin |
| fast_util.c:588-590, :610 | non-`MIT1` or undecryptable cookie is **silently ignored** (`return 0` at :610 — the `PREAUTH_EXPIRED` set at :598 is dead code in 1.22.2) | none | preauth.rs:246-255 / :314-318 | `bad cookie` 24 / `SPAKE cookie` 24 | deviation (stricter; fail-closed on an opaque echoed blob) | proposed: unit `garbage_cookie_is_ignored` |
| do_tgs_req.c:767 (`get_auth_indicators`, kdc_authdata.c:340-380) | extract verified auth indicators from the header ticket | `GET_AUTH_INDICATORS` | none | absent | absent | proposed: diffsend truncated CAMMAC; seed absent list |
| kdc_authdata.c:484-493 | no PAC when the realm sets `disable_pac`, or the reply ticket is ANONYMOUS (still adds indicators) | skip PAC | issue.rs:431, :893 gate on `KDB_NO_AUTH_DATA_REQUIRED` only | always PAC | absent | proposed: unit; folds into F2/F5 |
| kdc_preauth.c:1476-1493 | AS-REP `padata` gets ETYPE-INFO2 (+PW-SALT for pre-info2 clients) **only when the reply key was not replaced** (`key_modified`) | `KDC_RETURN_PADATA` | issue.rs `supported_enctypes_pa` only | absent | absent | refines the existing `return_padata` row; `diff.rs mit_as_padata` whitelist |

