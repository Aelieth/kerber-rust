# MIT 1.22.2 parity ledger

Oracle: MIT Kerberos **1.22.2** source SHA `3243ffbc…af13`
(`https://github.com/krb5/krb5/tree/krb5-1.22.2-final`) plus the live
image `kerber-rust-mit-kdc:1.22.2`. The source is verified with
`sha256sum -c` in CI: the `ledger-mit` job fetches the tarball and checks
that SHA, as `harness/Dockerfile` does.
Heimdal/Samba are regression, not the equality bar. Isolation: host
`/etc/krb5.conf` stays `TESTLABBY.LOCAL`.

The ledger began as a sweep of the KDC, with corrections applied from
the three verification reports (one per section A1–A3).
Overlap (PROCESS_TGS, GET_LOCAL_TGT, FIND_FAST, HANDLE_AUTHDATA,
AD-FX-ARMOR) is left in both sections on purpose — A1 owns TGS gather,
A2 owns AS/`kdc_util`, A3 owns FAST residue.

## Files

One or more files per section, each named `<key>-<subject>.md`; A4 and B1
have two. Each holds a heading that names its section, a short scope note
and one table in the schema below; a row lives in exactly one file, and a
section's count is the sum over its files.

| File | Section |
| --- | --- |
| [a1-tgs.md](a1-tgs.md) | A1 — TGS: `tgs_policy.c`, `do_tgs_req.c`, `kdc_transit.c` |
| [a2-as.md](a2-as.md) | A2 — AS and the KDC core: `do_as_req.c`, `kdc_util.c`, `policy.c`, `replay.c`, `dispatch.c` |
| [a3-preauth.md](a3-preauth.md) | A3 — preauth, FAST, authdata, CAMMAC, KDC logging |
| [a4-kadmin.md](a4-kadmin.md) | A4 — kadmind and kadm5, `kadmin.local`, kpasswd |
| [a4-kdb.md](a4-kdb.md) | A4 — `kdb5_util` (dump and load), the KDB library and plugins, the KDB lock |
| [a5-prop.md](a5-prop.md) | A5 — kprop, kpropd, iprop and the gssrpc layer |
| [b1-client.md](b1-client.md) | B1 — the client library, crypto, GSS, the acceptor, ccache and keytab |
| [b1-tools.md](b1-tools.md) | B1 — the client tools: `kinit`, `klist`, `kvno`, `kdestroy`, `kswitch`, `kpasswd`, `ktutil` |

FAST unwrap failures put the MIT status word
`FIND_FAST` on the wire `e_text` (`do_as_req.c:808`,
`do_tgs_req.c:205-206`) and the `k5_setmsg` text in the `kdc.issue`
`detail` field. Rows that were `deviation (e_text)` only for that
mismatch are `exact` here.

Schema: `MIT file:line | check | MIT status + wire code | Rust site | Rust e_text + code | verdict | proof`.
Verdict ∈ {exact, stricter-documented (`docs/mit-deviations.md` row), absent,
deviation, deferred (reason + promotion oracle)}. Proof `none` only
with deferred. A named gate cell or `diffsend` case that does not exist
is `proposed`. The 112 live `diffsend` cases are `garbage-pdu`,
`unknown-cname`, `etype-nosupp`, `as-session-enctype`, `wrong-realm`, `pauser-no-preauth`,
`as-needpreauth-hints-unpermitted`,
`skewed-timestamp`, `as-needchange`, `as-invalid-opts`, `as-validate-before-preauth`, `as-locked-out`,
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
**464** = A1 128 + A2 94 + A3 79 + A4 59 + A5 25 + B1 79.
exact 369 · stricter-documented 13 · deviation 35 ·
absent 2 · deferred 45.

When the ledger was split into these files, the one-file A4 (153 rows,
kadm5 plus the client library) was re-cut by subject: A4 58, A5 25 and
69 of B1's 79; A4's `session_enctypes` row moved to A2. No row's text
changed. Later A4 and B1 each became two files by subject (A4: 51 in
`a4-kadmin.md`, 8 in `a4-kdb.md`; B1: 73 in `b1-client.md`, 6 in
`b1-tools.md`), each row moved byte for byte.

Counting rule: a row with two verdicts (`exact (unit)`,
`deviation (decision)`, `absent (otp)`) counts under its **first**
verdict word; the parenthetical is a qualifier, not a second verdict.
Annotation rule: an `exact` row whose proof is unit-only carries
`forge-only — no MIT tool reaches this state` in its proof cell (the
state is reachable only by forged PDUs / faulted stores, so no live
differential cell can exist); rows without it name a live gate cell or
`diffsend` case. The per-row sweep that adds the annotation to every
unit-only `exact` row has not been done. The two
`absent` rows are the user's stated non-goals (OTP preauth,
`gss_wrap_size_limit`).

Draft was 209 = 108 + 56 + 45 at HEAD `bafc5f2`. Additions: A1 8 +
A2 10 (9 report rows + the `kdc_util.c:144-191` split) + A3 10 = 28
row inserts (the plan's "27" counted the split inside the A2 9).
The close-out added the eight `deferred` A4 rows for the kadm5 folds
that had no owner.

## Check families (security > parity > e_text)

The KDC checks fall into nine families, in the order below, security first. Each family's paragraph says
what its rows cover; the grades are in the section files, and a cell that names a family uses its title.

### 1. FAST armor / AD-FX-ARMOR / cookie (security)

1. FAST armor without an authenticator subkey is refused like `armor_ap_request` —
   **landed.** AS explicit armor (`fast_util.c:70-76`) and TGS
   explicit armor without a PA-TGS-REQ subkey (`:157-166`): 12, e_text
   `FIND_FAST`, detail `ap-request armor without subkey`. TGS explicit armor
   with a PA-TGS-REQ subkey stays 24. MIT clients always send a subkey.
2. A header ticket or authenticator carrying AD-FX-ARMOR is refused like `kdc_process_tgs_req` —
   **landed.** `kdc_util.c:217-229` → 12 `PROCESS_TGS` (detail
   `ticket valid only as FAST armor`). Recurses into IF-RELEVANT only
   (`authdata_dec.c:115-181`). Nothing in 1.22.2 emits 71.
3. PA-FX-COOKIE is bound to the client and expires at 600 seconds like `kdc_fast_make_cookie` —
   **landed.** `MIT1` ‖ kvno ‖ enc(prf+(local TGT key, `COOKIE` ‖
   unparsed client), ku 513); non-`MIT1` ignored (`:588-590,:610`). The ku-54 /
   ENC_CHALLENGE_CLIENT collision is a naming collision with no shared key.

TGS reply-key strengthen belongs to the RFC 6806 family (7): the MIT client copies
`existing_key` when `strengthen_key` is NULL.

### 2. S4U / header PAC integrity (security)

`is_crossrealm` from the header server entry like `do_tgs_req` (`do_tgs_req.c:686`); `S4U2SELF_NO_PAC` 20,
`S4U2PROXY_NO_HEADER_PAC` 20, `HEADER_PAC` 13, the PAC client match,
`S4U2PROXY_LOCAL_STKT_PAC` 13, U2U `2ND_TKT_PAC`, `PA-PAC-REQUEST`
include_pac=false, `disable_pac` / anonymous no-PAC, and the S4U2Self
password-expiry handling.

### 3. Second ticket (security / parity)

`2ND_TKT_NOT_TGS` 12, `2ND_TKT_MISMATCH` 26, `INVALID_S4U2PROXY_OPTIONS` 13,
TGS-target `NOT_ALLOWED_TO_DELEGATE` 12, `CAN'T PROXY TGT` 13,
`BAD_ETYPE_IN_2ND_TKT` 14, RBCD/xrealm PAC, `INVALID_S4U2SELF_CHECKSUM` 41 on a failed verify
and 50 for an unkeyed checksum. `NO_2ND_TKT` and `EVIDENCE_TKT_NOT_FORWARDABLE` refuse with 13.

### 4. AS request validation (security)

`INVALID AS OPTIONS` 13 (`kdc_util.c:727-729`), with no AS `DISALLOW_SVR`
ENC_TKT_IN_SKEY exemption (`:789-793`); `msg-type` (60 `VALIDATE_MESSAGE_TYPE`)
and `pvno` (MIT drops); the failcount lockout checked last; `ANONYMOUS NOT
ALLOWED` / `restrict_anon` (`kdc_util.c:700-712`; TGS `tgs_policy.c:763`);
`NEEDED_HW_PREAUTH` 25 (`do_as_req.c:455-457`; the hw_only hint list); the
admin unlock `last_admin_unlock >= last_failed` (`lockout.c:102-104`).

### 5. TGS options and ticket flags (security / parity)

`get_ticket_flags` (`kdc_util.c:813`); a TGT not forwardable, proxiable or
postdatable is 13; after decrypt, `check_tgs_nontgt` 26 when `NON_TGT_OPTION` is set and
`check_tgs_tgt` only when it is clear; `NOT_YET_VALID` without skew;
`NON-POSTDATABLE` only on `ALLOW_POSTDATE`. The lookaside reply cache is
implemented (`lookaside.rs`): an identical retransmit is answered from the
cache on both UDP and TCP.

### 6. CAMMAC + HANDLE_AUTHDATA (security, latent)

`cammac_check_kdcver` (ku 64) on the header ticket in `get_auth_indicators`, before the authdata is handled;
`cammac_create` after the authdata copy, inside
`handle_pac` / `mint_ticket`; `require_auth` → `HIGHER_AUTHENTICATION_REQUIRED`
12; `GET_AUTH_INDICATORS`; `AD-MANDATORY-FOR-KDC` → 12.

### 7. RFC 6806 negotiation, FAST reply parity (parity)

`TKT_FLG_ENC_PA_REP` on every ticket; the 149 checksum (ku 56) and the empty 136 in `enc_padata` only
when the request carries 149; TGS
`strengthen_key`; PA-FX-COOKIE on every e_data-bearing AS error; the FAST
error inner-padata order; the hint-list order `[136,(11),19,modules]`;
ETYPE-INFO2 only when the reply key was not replaced.

### 8. Gather order and lookups (parity)

AS lockout last; TGS `GET_LOCAL_TGT` before times; `HEADER_PAC` before
`search_sprinc`. TCP `FIELD_TOOLONG` 61 above UDP `RESPONSE_TOO_BIG` 52
(52 is dead at MIT's default 65536). `no PA-TGS-REQ` 16. `last_req` /
`key_expiration`. The `starttime == authtime` omission. The CANONICALIZE
canonical sname. `CANTLOCK_DB` 29 (exact by pass-through on the AS and TGS
lookups; no lockable KDB in tree — the unit fakes the backend).
`select_session_keytype`.

### 9. e_text and the differential compare (parity)

MIT's e_text tokens (`CLIENT LOCKED OUT` for a `DISALLOW_ALL_TIX` client, …); `compare_krb_error`
compares `e_text` on every `diffsend` case.

## Not this ledger

Client library: the `tgs_req_ex` FAST sibling; ERROR-level
`asn1.decode` / `crypto.decrypt` log lines on expected failures.
kadm5 and kprop: the kadmind chpw log's `from <addr>`; `kprop.rs`'s
per-connection replay cache.

OTP kdcpreauth is not implemented (a user non-goal; its row is
`absent (otp)`). PKINIT freshness (`a3-preauth.md`), anonymous PKINIT
(`a2-as.md`) and PA-S4U-X509-USER (`a1-tgs.md`) are graded `exact`.
