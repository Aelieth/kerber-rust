# MIT 1.22.2 parity ledger

Oracle: MIT Kerberos **1.22.2** source SHA `3243ffbc…af13`
(`https://github.com/krb5/krb5/tree/krb5-1.22.2-final`) plus the live
image `kerber-rust-mit-kdc:1.22.2`. The source is verified with
`sha256sum -c` in CI: the `ledger-mit` job fetches the tarball and checks
that SHA, as `harness/Dockerfile` does.
Heimdal/Samba are regression, not the equality bar. Isolation: host
`/etc/krb5.conf` stays `TESTLABBY.LOCAL`.

The ledger began as the W1-A sweep, with Part 0 of its plan applied from
the three verification reports (one per section A1–A3).
Overlap (PROCESS_TGS, GET_LOCAL_TGT, FIND_FAST, HANDLE_AUTHDATA,
AD-FX-ARMOR) is left in both sections on purpose — A1 owns TGS gather,
A2 owns AS/`kdc_util`, A3 owns FAST residue.

## Files

One file per section. Each holds its heading, a short scope note and one
table in the schema below; a row lives in exactly one file.

| File | Section |
| --- | --- |
| [a1-tgs.md](a1-tgs.md) | A1 — TGS: `tgs_policy.c`, `do_tgs_req.c`, `kdc_transit.c` |
| [a2-as.md](a2-as.md) | A2 — AS and the KDC core: `do_as_req.c`, `kdc_util.c`, `policy.c`, `replay.c`, `dispatch.c` |
| [a3-preauth.md](a3-preauth.md) | A3 — preauth, FAST, authdata, CAMMAC, KDC logging |
| [a4-kadmin.md](a4-kadmin.md) | A4 — kadmind and kadm5, the KDB, `kdb5_util`, `kadmin.local`, kpasswd |
| [a5-prop.md](a5-prop.md) | A5 — kprop, kpropd, iprop and the gssrpc layer |
| [b1-client.md](b1-client.md) | B1 — the client library, crypto, GSS, the acceptor and the client tools |

W0d G3 is in tree: FAST unwrap failures put the MIT status word
`FIND_FAST` on the wire `e_text` (`do_as_req.c:806`,
`do_tgs_req.c:205-206`) and the `k5_setmsg` text in the `kdc.issue`
`detail` field. Rows that were `deviation (e_text)` only for that
mismatch are `exact` here.

Schema: `MIT file:line | check | MIT status + wire code | Rust site | Rust e_text + code | verdict | proof`.
Verdict ∈ {exact, stricter-documented (`docs/security.md` row), absent,
deviation, deferred (reason + promotion oracle)}. Proof `none` only
with deferred. A named gate cell or `diffsend` case that does not exist
is `proposed`. The 111 live `diffsend` cases are `garbage-pdu`,
`unknown-cname`, `etype-nosupp`, `as-session-enctype`, `wrong-realm`, `pauser-no-preauth`,
`as-needpreauth-hints-unpermitted`,
`skewed-timestamp`, `as-needchange`, `as-invalid-opts`, `as-validate-before-preauth`,
`as-optimistic-encts-wrong-etype`, `unknown-sname`, `as-success`, `as-retransmit`,
`as-request-anonymous`, `tgs-success`, `tgs-not-a-tgt`, `tgt-expired`, `tgt-nyv`, `tgt-nyv-no-starttime`,
`fast-armor-no-subkey`, `armor-ap-req-as-pa-tgs-req`, `tgs-ad-fx-armor-authenticator`,
`as-bad-msg-type`, `as-bad-pvno`, `tgs-bad-msg-type`, `as-service-not-allowed`,
`tgs-ap-options`, `tgs-header-kvno-zero`, `as-hw-preauth`, `as-spake-round1`,
`u2u-2nd-ticket-unknown-server`, `u2u-2nd-ticket-bad-etype`, `u2u-2nd-ticket-corrupt`,
`tgs-pac-client-mismatch`, `tgs-pac-corrupt-before-sname`, `tgs-pac-request-false`,
`tgs-from-pacless-tgt`, `tgs-renew-service-ticket`, `tgs-proxy-krbtgt`,
`tgs-canonicalize-renew`, `tgs-expired-vs-unknown-sname`, `s4u2self-no-pac`,
`s4u2self-pac-client-mismatch`, `pa-s4u-x509-user-bad-checksum`, `pa-s4u-x509-user-nonce`,
`pa-for-user-only`, `pa-s4u-x509-user-empty`, `pa-for-user-undecodable`,
`pa-s4u-x509-user`, `s4u2proxy-no-2nd-tkt`, `s4u2proxy-not-forwardable`,
`s4u2proxy-u2u-combo`, `s4u2proxy-tgs-target`, `s4u2proxy-no-header-pac`,
`s4u2proxy-header-pac`, `s4u2proxy-no-stkt-pac`, `s4u2proxy-evidence-mismatch`,
`s4u2proxy-local-stkt-pac`, `u2u-no-2nd-tkt`, `u2u-2nd-ticket-not-tgs`,
`u2u-2nd-ticket-mismatch`, `u2u-2nd-ticket-bad-pac`, `u2u-bad-etype`,
`u2u-success`, `tgs-addr-mismatch`, `tgs-forwarded-addresses`,
`u2u-2nd-ticket-foreign-realm`, `s4u2self-renew-options`,
`pa-s4u-x509-user-truncated`, `s4u2self-krbtgt-other`,
`tgs-locked-pac-mismatch`, `u2u-dup-skey-tgt-based`,
`tgs-expired-addr-mismatch`, `tgs-expired-badmatch`,
`u2u-2nd-ticket-kvno-miss`, `u2u-2nd-ticket-disallow-svr`,
`s4u2self-cert-only`, `tgs-forwarded-tgt-addresses`,
`tgs-pac-server-cksum-wrong-enctype`, `u2u-2nd-ticket-pac-wrong-enctype`,
`u2u-success-offered`, `tgs-forwarded-on-non-f-tgt`, `tgs-proxy-on-non-p-tgt`,
`tgs-postdate-on-non-postdatable`, `tgs-postdated-is-invalid`,
`tgs-validate-invalid-non-renewable`,
`tgs-till-in-past`, `tgs-service-expired-require-auth`, `tgs-postdated-from`,
`tgs-no-preauth-flag`, `tgs-hw-preauth-flag`, `tgs-nyv-inside-skew`,
`tgs-body-authdata`, `tgs-ad-mandatory-for-kdc`,
`tgs-body-authdata-kdc-issued-stripped`, `tgs-body-authdata-subkey`,
`tgs-body-authdata-session-ku5`, `tgs-tgt-and-or-kept`,
`tgs-truncated-cammac`,
`ec-outside-fast`, `tgs-rbcd-pac-options`,
`tgs-renew-header-end-before-start`,
`as-anonymous-unsigned-authpack-named-client`, `as-fast-hide-error-client`,
`tgs-fast-hide-client`, `pkinit-stale-freshness`, `tgs-referral-no-dot`,
`tgs-alternate-tgs-hierarchical`, `tgs-renew-postdated-from`.

Wire `e_text` is the MIT **status word**. MIT log messages are not
wire text. `errcode_to_protocol` passes `offset ∈ [0,128]`
(`kdc_util.c:696-697`).

Counts:
**462** = A1 128 + A2 93 + A3 79 + A4 58 + A5 25 + B1 79.
exact 362 · stricter-documented 16 · deviation 33 ·
absent 2 · deferred 49.

When the ledger was split into these files, the one-file A4 (153 rows,
kadm5 plus the client library) was re-cut by subject: A4 58, A5 25 and
69 of B1's 79; A4's `session_enctypes` row moved to A2. No row's text
changed.

Counting rule: a row with two verdicts (`exact (unit)`,
`deviation (decision)`, `absent (otp)`) counts under its **first**
verdict word; the parenthetical is a qualifier, not a second verdict.
Annotation rule: an `exact` row whose proof is unit-only carries
`forge-only — no MIT tool reaches this state` in its proof cell (the
state is reachable only by forged PDUs / faulted stores, so no live
differential cell can exist); rows without it name a live gate cell or
`diffsend` case. The per-row sweep that adds the annotation to every
unit-only `exact` row is W3's (the W1-Z handoff). The two
`absent` rows are the user's stated non-goals (OTP preauth,
`gss_wrap_size_limit`).

Draft was 209 = 108 + 56 + 45 at HEAD `bafc5f2`. Additions: A1 8 +
A2 10 (9 report rows + the `kdc_util.c:144-191` split) + A3 10 = 28
row inserts (the plan's "27" counted the split inside the A2 9).
W1-Z Z2 added the eight `deferred` A4 rows for the W1-C kadm5 folds
that had no owner (the W1-Z handoff table).

## Ranked fix batches (security > parity > e_text)

Corrected by the verification reports. Each batch ≤ 6 commits. One MIT
check family per commit. The plan numbered the batches F1–F9 in the order
below (ledger cells cite them by that number); F1 starts after this
ledger lands; F3–F9 get a short plan when reached.

### 1. FAST armor / AD-FX-ARMOR / cookie (security)

1. `kdc: Refuse FAST armor without an authenticator subkey like armor_ap_request` —
   **landed (A′-1 item 1).** AS explicit armor (`fast_util.c:70-76`) and TGS
   explicit armor without a PA-TGS-REQ subkey (`:157-166`): 12, e_text
   `FIND_FAST`, detail `ap-request armor without subkey`. TGS explicit armor
   with a PA-TGS-REQ subkey stays 24. MIT clients always send a subkey.
2. `kdc: Refuse a header ticket or authenticator carrying AD-FX-ARMOR like kdc_process_tgs_req` —
   **landed (A′-1 item 3).** `kdc_util.c:217-229` → 12 `PROCESS_TGS` (detail
   `ticket valid only as FAST armor`). Recurses into IF-RELEVANT only
   (`authdata_dec.c:115-181`). Nothing in 1.22.2 emits 71.
3. `kdc: Bind PA-FX-COOKIE to the client and expire it at 600 seconds like kdc_fast_make_cookie` —
   **landed (A′-1 item 2).** `MIT1` ‖ kvno ‖ enc(prf+(local TGT key, `COOKIE` ‖
   unparsed client), ku 513); non-`MIT1` ignored (`:588-590,:610`). The ku-54 /
   ENC_CHALLENGE_CLIENT collision is a naming collision with no shared key.

TGS reply-key strengthen is **parity** (F7): the MIT client copies
`existing_key` when `strengthen_key` is NULL.

### 2. S4U / header PAC integrity (security)

Prerequisite: `kdc: Compute is_crossrealm from the header server entry
like do_tgs_req` (`do_tgs_req.c:686`). Then `S4U2SELF_NO_PAC` 20,
`S4U2PROXY_NO_HEADER_PAC` 20, `HEADER_PAC` 13, PAC client match,
`S4U2PROXY_LOCAL_STKT_PAC` 13, U2U `2ND_TKT_PAC`, `PA-PAC-REQUEST`
include_pac=false, `disable_pac`/anonymous no-PAC. S4U2Self pw-expiry
exemption is stricter — document or match.

### 3. Second ticket (security / parity)

`2ND_TKT_NOT_TGS` 12, `2ND_TKT_MISMATCH` 26, `INVALID_S4U2PROXY_OPTIONS` 13,
TGS-target `NOT_ALLOWED_TO_DELEGATE` 12, `CAN'T PROXY TGT` 13,
`BAD_ETYPE_IN_2ND_TKT` 14, RBCD/xrealm PAC, `INVALID_S4U2SELF_CHECKSUM` 41
not 50. Demoted to e_text (F9): `NO_2ND_TKT`, `EVIDENCE_TKT_NOT_FORWARDABLE`
(both already refuse with 13).

### 4. AS request validation (security)

`INVALID AS OPTIONS` 13 (`kdc_util.c:727-729`) and drop the AS
`DISALLOW_SVR` ENC_TKT_IN_SKEY exemption (`:789-793`) in the **same
commit**. Validate `msg-type` (60 `VALIDATE_MESSAGE_TYPE`) and `pvno`
(MIT drops). Failcount lockout last. `ANONYMOUS NOT ALLOWED` /
`restrict_anon` (`kdc_util.c:700-712`; TGS `tgs_policy.c:763`) vs
unsupported 13 is parity + a security.md row, not a hole.
`NEEDED_HW_PREAUTH` 25 (`do_as_req.c:455-457`; hw_only hint list).
Admin unlock: `last_admin_unlock >= last_failed` (`lockout.c:102-104`).

### 5. TGS options and ticket flags (security / parity)

Implement `get_ticket_flags` (`kdc_util.c:813`). `TGT NOT
FORWARDABLE/PROXIABLE/POSTDATABLE` 13. Ticket addresses.
`check_tgs_nontgt` 26 + `check_tgs_tgt` after decrypt and only when
`NON_TGT_OPTION` is clear. `NOT_YET_VALID` without skew.
`NON-POSTDATABLE` only on `ALLOW_POSTDATE`. The lookaside reply cache is
now implemented (`lookaside.rs`), so an identical retransmit is answered
from the cache on both UDP and TCP.

### 6. CAMMAC + HANDLE_AUTHDATA (security, latent)

`cammac_create`/`cammac_check_kdcver` (ku 64) after copy, inside
`handle_pac` / `mint_ticket`. `require_auth` → `HIGHER_AUTHENTICATION_REQUIRED`
12. `GET_AUTH_INDICATORS`. `AD-MANDATORY-FOR-KDC` → 12.

### 7. RFC 6806 negotiation, FAST reply parity (parity)

149 checksum (ku 56) + empty 136 in `enc_padata` + `TKT_FLG_ENC_PA_REP`,
gated on request 149 — flag without 149 hard-fails MIT kinit. TGS
`strengthen_key`. PA-FX-COOKIE on every e_data-bearing AS error
(**after F1 cookie**). FAST error inner-padata order. Hint-list order
`[136,(11),19,modules]`. ETYPE-INFO2 only when the reply key was not
replaced.

### 8. Gather order and lookups (parity)

AS lockout last; TGS `GET_LOCAL_TGT` before times; `HEADER_PAC` before
`search_sprinc`. TCP `FIELD_TOOLONG` 61 above UDP `RESPONSE_TOO_BIG` 52
(52 is dead at MIT's default 65536). `no PA-TGS-REQ` 16. `last_req` /
`key_expiration`. `starttime == authtime` omission. CANONICALIZE
canonical sname. `CANTLOCK_DB` 29 (exact by pass-through on the AS and TGS
lookups; no lockable KDB in tree — the unit fakes the backend).
`select_session_keytype`.

### 9. e_text and the differential unmask (parity, last)

Token renames (`locked` → `CLIENT LOCKED OUT`, …). Then
`compare_krb_error` compares `e_text` on every `diffsend` case.
Whitelist names the documented stricter rows.

## Not this ledger

W1-B: `tgs_req_ex` FAST sibling; `get_dest_tgt` referral memory;
start-realm in the service loop; acceptor transited re-check;
ERROR-level `asn1.decode`/`crypto.decrypt` on expected failures.
W1-C: kpasswd pre-AP-REQ drop and post-AP-REQ `chpwfail` (J4 / `schpw.c`); kadmind chpw log `from <addr>`;
`kprop.rs` per-connection rcache; `dfl` restart cell; min_life (dictionary landed W1-C C1);
kadm5 ACL denial codes (rename AUTH_INSUFFICIENT-before-lockdown landed W0e H7); policy-rejection text.

OTP kdcpreauth, PA-S4U-X509-USER, PKINIT freshness, anonymous PKINIT stay
deferred with those promotion oracles (Batch D / user non-goal).
