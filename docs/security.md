# Timing, replay, and secret-handling matrix

Constant-time MAC compare, replay detection, zeroize-on-drop, and
0600 secret files are product code, not a later audit item. This
matrix names the shipped site and the test that drives it.

Replay is one implementation (`krb5-protocol` `ReplayCache`: 50_000
entries, 5-minute window, fail-closed on mutex poison). GSS acceptors
share one AP-REQ cache across `accept_sec_context` calls. GSS wrap/MIC
uses a per-context sequence window in addition to that cache.

## Matrix

| Protection | Code site | Test |
| --- | --- | --- |
| Constant-time MAC / checksum | `krb5-crypto` `mac_verify` (`derive.rs`); callers `ops.rs` decrypt/checksum, `weak.rs` RC4/DES | `decrypt_bad_mac_is_error` (`krb5-crypto/tests/known_answer.rs`) |
| Constant-time PAC signature | `verify_checksum_type` over PAC `SignatureType` (`ad.rs` `verify_pac_sig`; `pac.c:478-514`) | `crates/krb5-kdc/tests/ad_pac.rs` `verify_pac_signatures` / `pac_sha1_server_checksum_is_sumtype_nosupp` |
| Replay — AP-REQ authenticator | `verify_ap_req` (`krb5-protocol` `ap_req.rs`) | `ap_req_valid_truncated_wrong_key_replay` |
| Replay — TGS authenticator | `issue_tgs` (`krb5-kdc` `issue.rs`) `tgs_replay` | `tgs_authenticator_replay_is_repeat` |
| Replay — PA-ENC-TIMESTAMP | `verify_enc_timestamp` (`issue.rs`) `pa_replay` | `pa_enc_timestamp_replay_is_repeat` |
| Replay — KRB-SAFE / PRIV / CRED | `safe_priv.rs` `check_and_store` on unwrap | `messages.rs` unwrap path; `ReplayCache` unit tests |
| Replay — GSS wrap/MIC sequence | `krb5-gss` `accept_seq` (`recv_window`) | `wrap_mic_replay_inside_window_is_rejected` |
| Replay — GSS acceptor AP-REQ | `accept_sec_context` shared `ReplayCache`. kadm5 RPC holds one in-memory cache (300 s). MIT `dfl` file persists across restarts (`rc_file2.c:165-195`; W1-C cell). kpasswd uses a fresh `ReplayCache` per datagram like MIT `schpw.c:110-111` (a UDP retransmit is answered). | `accept_same_token_twice_is_repeat`; `gss-gate.sh` replay cell (MIT KRB-ERROR 34 `Request is a replay`); `kpasswd-gate.sh` retransmit |
| Replay cache window / cap / poison | `ReplayCache::check_and_store` | `replay::tests::{window_prune_is_not_replay, cap_evicts_oldest_not_grow, poison_fails_closed}` |
| Zeroize-on-drop — protocol keys | `ProtocolKey` `Drop` (`krb5-crypto` `key.rs`) | Drop impl; `ProtocolKey` is every stash / keytab / ccache key |
| Zeroize-on-drop — derived keys | `DerivedKeys` `Drop` (`derive.rs`) | Drop impl; used on every encrypt/decrypt |
| Zeroize-on-drop — DH exponent | `DhKeypair` `Drop` (`modp.rs`); SPAKE seed (`spake.rs`) | Drop impl; PKINIT / SPAKE issue path |
| Zeroize — client password | `kinit` (`krb5-client` `lib.rs`) zeros the buffer before return | `kinit` return path; live `client-gate` |
| 0600 secret files | `write_secret_file` (`secret_file.rs`); keytab, ccache, dump, stash | `persist_survives_restart_without_key_regen` (save_store) |
| Product 0-unsafe | Workspace lint `unsafe_code = "forbid"`; `#![forbid(unsafe_code)]` on every library crate | compile (`clippy -D warnings`); `scripts/geiger.sh` |

`DISABLE_TRANSITED_CHECK` and ticket flags are protocol policy, not
timing. There is no injectable clock; replay windows use
`std::time::Instant` plus RFC 4120 authenticator `ctime`/`cusec`.

## Documented deviations from MIT 1.22.2

These are deliberate and fail closed (Rust rejects or bounds where
MIT would accept or grow). Honest UTF-8 paths are not laxer than MIT;
the UTF-8 transited row below is mixed on absurd inputs.

| Deviation | MIT | Rust | Why |
| --- | --- | --- | --- |
| Transited field-count cap | Checker has no comma cap; add path clamps rebuilt encoding at 499 bytes so a 300-hop path cannot be *built* | More than 256 commas (raw comma bytes, including escaped `\,`) is `TooManyFields` (POLICY on the non-add path) | **STRICTER** than MIT |
| Transited hop-emission cap | No hop cap; `process_intermediates` streams callbacks at O(1) memory | More than 4096 emitted hops is `TooManyFields` (`MAX_TRANSIT_HOPS`) | **STRICTER** than MIT |
| Transited component bounds | Raw field ≤ 511 unescaped bytes; joined ≤ 512 (`chk_trans.c` `MAXLEN`) | Same (511 raw / 512 joined); over is `FieldTooLong` out of band | MIT-exact |
| Invalid UTF-8 in transited | Byte-exact `memcmp` | `from_utf8_lossy` inflates invalid bytes 3× against the 512 bound (STRICTER) and collapses distinct invalid sequences to one U+FFFD string, so equal-length compare can succeed where MIT errors (laxer; absurd inputs). Byte-exact matching is general-pass | Mixed; fail-closed on honest UTF-8 |
| Append escaping | MIT `add_to_transited` does not escape `\` or `,` in the new realm | Escapes both | Stricter-correct than MIT's encoder |
| Add-path bounds | `MAX_REALM_LN` 500: raw ≥ 500, joined ≥ 499, rebuilt ≥ 500 (`strlcat` clamp; whole transited ≤ 499). Trailing empty field of `EDU,` is dropped (`EDU,`+`X` → `EDU,X`). Internal `,,` truncates MIT's list | Same raw/joined/total bounds. Encode stays uncompressed (total bound is stricter by the compression delta). Trailing-comma drop. Internal `,,` is preserved | MIT-exact bounds; `,,` preservation is stricter-correct |
| Encode-side X.500 RDN compression | MIT `add_to_transited` may emit compressed RDN form | Encode stays uncompressed (`from_realms`) | Deferred; decode still expands MIT compressed contents |
| Hierarchical intermediates on ≥512-byte realm | MIT `walk_rtree.c` copies every tween unbounded | Empty permitted set (nothing allowed) | **STRICTER** on absurd `crealm`/`srealm` |
| TGS realm octets that are not UTF-8 | MIT uses the bytes | `GENERIC` `non-ascii realm` | fail-closed (was the literal `KERBER.TEST`) |

### Parity decisions (not deviations)

DOMAIN-X500-COMPRESS joins on unescaped field text (MIT `maybe_join`:
`X.COM,C\.` → `C.X.COM`). Null subfields match MIT
`process_intermediates` (leading/trailing comma, `,,`).

A TGS-REQ whose `body.realm` is not a realm this KDC serves is 60
`GET_LOCAL_TGT` (MIT `get_local_tgt` on a single-realm KDC; a
multi-realm MIT KDC may answer 68 `WRONG_REALM` from `dispatch.c`).
Destination RENEW/VALIDATE is not exempt.

A cross-realm TGT whose client realm is this KDC (`check_tgs_lineage`)
is 12 `INVALID LINEAGE` even when `reject_bad_transit = false`.
S4U2Self is exempt (MIT `tgs_policy.c`). S4U2Self server match is by
DB entry *and* realm (`is_client_db_alias`): a foreign TGT client with
a colliding local name is 36 `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH`.

FAST armor decrypt binds keys to the armor `ticket.realm` (MIT
`fast_util.c` `rd_req`); forged-realm armor is 35 `NOT_US` (`rd_req`).
A local non-krbtgt armor ticket is 26 `SERVER_NOMATCH`.
A presented-TGT krbtgt with `DISALLOW_SVR` or `DISALLOW_ALL_TIX` is 7
`PROCESS_TGS` (`kdc_util.c:390-393`).

Checksums are verified by the declared `cksumtype` (`verify_checksum.c`):
type 0 substitutes the key's mandatory type, `output_size` is
`KRB5_BAD_MSIZE`, unkeyed/not coll-proof is 50 (`rd_safe.c:70-74`,
`kdc_util.c:1244`). KRB-SAFE checksums the dummy (zeroed-cksum) encoding
first, then the body. GSS wrap-without-conf requires `EC == cksumsize`;
MIC fillers are 0xFF and the header is reconstructed (`util_crypt.c:322-334`).
A GSS authenticator checksum that is not 0x8003 is verified over empty
data (`accept_sec_context.c:494-511`); 0x8003 shorter than 24 is
`GSS_S_BAD_BINDINGS`. PA-FOR-USER unkeyed is 50 and a bad MAC is 41
(`INVALID_S4U2SELF_CHECKSUM`). PAC SHA-1 on the server checksum is 15
(`pac.c:496-497`). The FAST client verifies `ticket_checksum`
(`fast.c:543-551`). PA-REQ-ENC-PA-REP (149) is produced when the AS-REQ
advertises it; the kinit client verify of 149 is not wired until the
client also sends the empty padata (RFC 6806 F7) so MIT KDCs that set
`enc-pa-rep` without returning 149 are not rejected.

FAST `req_checksum` is verified over the wire KDC-REQ-BODY (field 4)
when a raw packet is present (`do_as_req.c:526-531`); socketless tests
re-encode. Verify runs before the keyedness check (`fast_util.c:207-224`):
a failed verify is 41 `MODIFIED` wire `FIND_FAST`; an unkeyed type is
12 wire `FIND_FAST` (log `detail` `Unkeyed checksum used in fast_req`)
only after verify succeeds (RSA-MD4 2, RSA-MD5 7, NIST-SHA 9, SHA-1 14;
MIT `cksumtypes.c`). CRC32 (1) has no table entry. Unknown type or
`output_size` length mismatch is 60 `GENERIC` wire `FIND_FAST`
(`KRB5_BAD_ENCTYPE` / `KRB5_BAD_MSIZE`). Keyed types match by enc
provider (`crypto_int.h:596-608`): 15/19 aes128, 16/20 aes256, 12 des3,
17/18 camellia, `-138` NULL (any key), `-137` arcfour. `-137` is
HMAC(raw key, MD5(le32(usage) ‖ msg)); `-138` first derives
HMAC(key, `"signaturekey\0"`) (`checksum_hmac_md5.c:53-66`). RC4
usage translation is `3→8, 9→9, 23→13` (`enc_rc4.c:17-35`). Session
etype walks the request list like `select_session_keytype`
(`kdc_util.c:1084-1112`): valid, permitted, `allow_des3`/`allow_rc4`,
then `dbentry_supports_enctype` (`session_enctypes` attr, else
AES256-sha1 assumed, else a long-term key). AS uses krbtgt; TGS uses
the service. Ticket encryption stays the server long-term key. RC4
`checksum()` is RFC 4757 type `-138`. `cksumtype` 0
substitutes the key's mandatory type, then `is_keyed(0)` is 12.
Unknown armor type is
24 with wire `FIND_FAST` (log `detail` is `Unknown FAST armor type %d`).
TGS authenticator client ≠ ticket client is 36 `PROCESS_TGS`. Explicit
TGS AP-REQ armor is 24 `FIND_FAST` even without a subkey; MIT only
rejects it when a subkey is present (`fast_util.c:159-166`).
Corrupt `enc_fast_req` is 31 `FIND_FAST`; malformed `KrbFastReq` is
60 `FIND_FAST` (`do_as_req.c:531-535`). Log `detail` is MIT's
`k5_setmsg` where MIT has one; the critical-FAST-option `detail`
(`FAST option`) is Rust's own (`UNKNOWN_CRITICAL_FAST_OPTION` has
no MIT `k5_setmsg`). Hide-client-names (FAST option bit 1) is
refused as 93 `FIND_FAST`; MIT supports it (`k5-int.h:803`). Any
critical bit 0..15 is 93 (MIT only rejects bits 0 and 2..15).

`kadmin/admin` and `kadmin/changepw` are bootstrapped with MIT
`kadm5_create` attributes: both `DISALLOW_TGT_BASED|LOCKDOWN_KEYS`;
changepw also `PWCHANGE_SERVICE`. A TGS from a TGT is 12
`TGT BASED NOT ALLOWED`. `kdb5_util create` also sets `LOCKDOWN_KEYS`
on `krbtgt/REALM` and `K/M` (`kdb5_create.c:465`). Remote kadm5
maps lockdown to the privilege codes MIT kadmind remaps in
`server_stubs.c`: extract `KADM5_AUTH_EXTRACT`, chpass
`KADM5_AUTH_CHANGEPW`, setkey `KADM5_AUTH_SETKEY`, delete
`KADM5_AUTH_DELETE`, modify that clears the bit `KADM5_AUTH_MODIFY`,
rename of the source `KADM5_AUTH_DELETE` after the ACL check.
Unauthorised rename is `KADM5_AUTH_INSUFFICIENT` first
(`server_stubs.c:700-712`). kadm5.acl lines are
`<principal> <opstring> [<target> [<restrictions>]]`
(`auth_acl.c:330-338`). A target of `*` is any principal; otherwise
`match_princ` (`:472-492`) requires the same component count and realm
and matches each component with `*` (whole component only; `user*` is
a literal) and `*N` back-references from the client pattern. The first
entry whose client **and** target match wins (`find_entry` `:497-524`).
Rename is `ACL_DELETE` on src **and** `ACL_ADD` on dest **and** the add
entry carries no restrictions (`:638-648`). Restrictions
(`-clearpolicy`, `-policy`, `-maxlife`, `-maxrenewlife`, `-expire`,
`-pwexpire`, `+flag`/`-flag`) are imposed on create/modify
(`auth.c:211-272`). Flag names use MIT aliases, hyphen→underscore,
case-fold, and `0x` hex (`str_conv.c:50-95,147-197`). Lower-case op
letters grant and upper-case letters revoke (`auth_acl.c:276-282`);
an unknown letter is a load error (`:286-291`). `#` comments only at
column 0; `\` continues a line (`:120-160`). Realm-less names take the
store realm (`krb5_parse_name`). A readable ACL file is the ACL: it is
not replaced when `admin@REALM` is absent (`acl_init:547-563`). An
unparseable target or unknown restriction token is a load error
(`acl_init`); kadmind refuses the file. `*`/`x` still
exclude extract (`e`). `listprincs`/`listpols` require `l`
(`KADM5_AUTH_LIST`, `server_stubs.c:814,1443`). addpol is
`KADM5_AUTH_ADD`, delpol `KADM5_AUTH_DELETE`. Self cpw/chrand/purgekeys/
getprinc/getstrs (and own-policy getpol) follow `auth_self.c:38-75`.
Self key change without an INITIAL ticket is `KADM5_AUTH_INITIAL`
(`server_stubs.c:368-381`). `get_privs` returns `~0`
(`server_misc.c:146-158`). `kadmin.local` applies no ACL (`KRB5_ACL_FILE`
is kadmind-only). A `kadmin/changepw` GSS acceptor is
`CHANGEPW_SERVICE` (`server_stubs.c:28-32`): every stub denies with
MIT's code except self `chpass`/`chrand`/`getprinc`
(`changepw_not_self`, `:348-354`) and getpol of the caller's own
policy (`:1401-1403`). `getstrs` and `purgekeys` use
`CHANGEPW_SERVICE` (even self is denied).
iprop requires a `kiprop` acceptor (`ipropd_svc.c:457-548`) or the
RPC reply is `AUTH_TOOWEAK`. Purgekeys stays
`KADM5_PROTECT_KEYS` (stricter than MIT, which has no lockdown check).
`kadmin.local` ktadd ignores lockdown like MIT. Create-time name
special-casing keeps `PWCHANGE_SERVICE` only (`create_principal` has
none of the `kdb5_util create` bits).

kpasswd self-change (RFC 3244 target absent or equal to the ticket
client on components and realm, name-type-insensitive like
`krb5_principal_compare`) is checked first (`misc.c:33-54`). Non-INITIAL
self is result 7 `Ticket must be derived from a password`. Unprivileged
other principal is result 5 `Unauthorized request`
(`KADM5_AUTH_CHANGEPW`). A privileged actor targeting a missing or
foreign-realm principal is result 2 with `chpass_util.c:136-140`
(`Password not changed.\nPrincipal does not exist while trying to
change password.\n`). Admin-style changes ignore INITIAL. `min_life`
is W1. Purgekeys of a locked-down principal is `KADM5_PROTECT_KEYS`
(stricter than MIT, which has no lockdown check on purgekeys).
Length prefix and version are checked before AP-REQ work
(`schpw.c:47-82`). Inconsistent length, unknown version, and the
truncated cases `goto bailout` (`:384-397`); `dispatch` calls
`respond(..., NULL)` so no datagram is sent (`:424-435`). The UDP
path logs MIT com_err text (`Message stream modified` /
`Requested protocol version not supported`) plus
`- while dispatching (udp)` (`net-server.c:1103`). Framing a
KRB-ERROR here would be a 22–25× UDP reflector for a 6-byte
spoofable datagram; MIT does not have that. `ChangePasswdData` is
decoded only for version `0xff80`.

## Not in this matrix

In-process metrics counters are deferred (logs already carry
`duration_us` and `outcome`; see [`logging.md`](logging.md)).
Dependency `unsafe` is not a numeric gate.
