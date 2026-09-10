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
| iprop keys never sent in the clear | `dispatch_iprop` GET_UPDATES answers `UPDATE_ERROR` (`kadm5.rs`, `krb5_kdc::IPROP_ERROR`) when `iprop_master_key` is `None`, rather than ship the store's plaintext keys | `iprop_get_updates_refuses_plaintext_keys_without_master_key` |
| Cross-realm PAC SID filtering | `filter_cross_realm_logon` (`ad.rs`) drops local-domain SIDs from a cross-realm subject's `LOGON_INFO`; `issue.rs` calls it when the header ticket is from a foreign realm | `cross_realm_pac_drops_local_domain_sids_keeps_foreign`, `cross_realm_pac_claiming_local_domain_base_is_policy` (`crates/krb5-kdc/tests/capaths.rs`) |

`DISABLE_TRANSITED_CHECK` and ticket flags are protocol policy, not
timing. There is no injectable clock; replay windows use
`std::time::Instant` plus RFC 4120 authenticator `ctime`/`cusec`.

## Documented deviations from MIT 1.22.2

These are deliberate and fail closed (Rust rejects or bounds where
MIT would accept or grow). Honest UTF-8 paths are not laxer than MIT;
the UTF-8 transited row below is mixed on absurd inputs.

| Deviation | MIT | Rust | Why |
| --- | --- | --- | --- |
| Master-key type default | `DEFAULT_KDC_ENCTYPE` = aes256-cts-hmac-sha1-96 (`osconf.hin:90`) when `master_key_type` is unset | Honours `master_key_type` when set; defaults to the stronger aes256-cts-hmac-sha384-192 when unset (`persist.rs persist_master_etype`, `krb5-kdb.rs master_etype`) | **STRICTER** than MIT |
| Transited field-count cap | Checker has no comma cap; add path clamps rebuilt encoding at 499 bytes so a 300-hop path cannot be *built* | More than 256 commas (raw comma bytes, including escaped `\,`) is `TooManyFields` (POLICY on the non-add path) | **STRICTER** than MIT |
| Transited hop-emission cap | No hop cap; `process_intermediates` streams callbacks at O(1) memory | More than 4096 emitted hops is `TooManyFields` (`MAX_TRANSIT_HOPS`) | **STRICTER** than MIT |
| Transited component bounds | Raw field ≤ 511 unescaped bytes; joined ≤ 512 (`chk_trans.c` `MAXLEN`) | Same (511 raw / 512 joined); over is `FieldTooLong` out of band | MIT-exact |
| Invalid UTF-8 in transited | Byte-exact `memcmp` | `from_utf8_lossy` inflates invalid bytes 3× against the 512 bound (STRICTER) and collapses distinct invalid sequences to one U+FFFD string, so equal-length compare can succeed where MIT errors (laxer; absurd inputs). Byte-exact matching is general-pass | Mixed; fail-closed on honest UTF-8 |
| Append escaping | MIT `add_to_transited` does not escape `\` or `,` in the new realm | Escapes both | Stricter-correct than MIT's encoder |
| Add-path bounds | `MAX_REALM_LN` 500: raw ≥ 500, joined ≥ 499, rebuilt ≥ 500 (`strlcat` clamp; whole transited ≤ 499). Trailing empty field of `EDU,` is dropped (`EDU,`+`X` → `EDU,X`). Internal `,,` truncates MIT's list | Same raw/joined/total bounds. Encode stays uncompressed (total bound is stricter by the compression delta). Trailing-comma drop. Internal `,,` is preserved | MIT-exact bounds; `,,` preservation is stricter-correct |
| Encode-side X.500 RDN compression | MIT `add_to_transited` may emit compressed RDN form | Encode stays uncompressed (`from_realms`) | Deferred; decode still expands MIT compressed contents |
| Hierarchical intermediates on ≥512-byte realm | MIT `walk_rtree.c` copies every tween unbounded | Empty permitted set (nothing allowed) | **STRICTER** on absurd `crealm`/`srealm` |
| TGS realm octets that are not UTF-8 | MIT uses the bytes | `GENERIC` `non-ascii realm` | fail-closed (was the literal `KERBER.TEST`) |
| Unknown TGS KDCOptions bit | The TGS acts only on the options it recognises (RENEWABLE / RENEWABLE-OK / POSTDATE / FORWARDED / PROXY / ENC-TKT-IN-SKEY) and ignores unknown or reserved KDCOption bits (`do_tgs_req.c`) | `issue_tgs_body` refuses any bit outside the honoured set with `BADOPTION` (`unsupported_bits`) | **STRICTER** than MIT (a TGT-authenticated request carrying an unknown option is anomalous; fail closed). The AS twin is now exact: `validate_as_request` tests `AS_INVALID_OPTIONS` only, and `do_as_req.c:718` then handles REQUEST_ANONYMOUS |
| kadmind reserved TL types | `kadm5_modify_principal` / create refuse `tl_data_type < 256` with `KADM5_BAD_TL_TYPE` before `kdb_put_entry` (`svr_principal.c:327-333,581-588`) | same refuse before any store write (`kadm5.rs`) | exact |
| kadmind connection caps | net-server caps concurrent connections at 45 with LRU eviction (`net-server.c:85,1571`) and streams each RPC over a fixed 1 MiB buffer; established connections carry `SO_KEEPALIVE`, no short read timeout | Same cap + LRU eviction (kadmind reuses the KDC `ConnRegistry`); additionally bounds the accumulated RPC record at 1 MiB (`MAX_KADM5_RECORD`, `read_record`) and sets a 5 s write timeout; no short read timeout, so a paused interactive session is not dropped | **STRICTER** than MIT (an explicit total-record bound so a pre-auth fragment chain cannot exhaust memory, and a write timeout so a slow reader cannot pin a worker) |
| TGS authenticator checksum retry | `kdc_process_tgs_req` verifies the PA-TGS-REQ authenticator checksum over the raw request body (packet field 4) and, when that fails, retries over its own canonical re-encoding of the KDC-REQ-BODY; with no raw packet the check is skipped (`kdc_util.c:246-255`) | `issue.rs` verifies once, over the wire body only; a mismatch is 31 `PROCESS_TGS` | **STRICTER** than MIT (a client whose body is not canonical DER is refused; MIT clients emit canonical DER; recorded by the R2 re-audit, W1 grades the row) |
| TGS cross-TGS header PAC (`check_normal_tgs_pac`) | Client-info mismatch is 13 `HEADER_PAC` unless `is_crossrealm` and the requested server is a cross TGS and `verify_deleg_pac` succeeds (`tgs_policy.c:616-620`) | Same client-info match; `verify_deleg_pac` (`tgs_policy.c:366-421`) accepts a delegation PAC (CLIENT_INFO with realm, authtime, DELEGATION_INFO, last transited = impersonator) | exact; live accept path is Samba |
| Acceptor ticket addresses (`rd_req_dec.c:536-540`) | `krb5_address_search`: NULL list matches; a lone NetBIOS entry is treated as empty; otherwise type+octets (`addr_srch.c:55-59`) | `verify_ap_req` (`ap_req.rs`) compares the whole `caddr` list to `ApVerifyParams.addresses` when both are present | **STRICTER** on the acceptor (B) path: a ticket whose `caddr` is a proper subset of the acceptor list, or a lone-NetBIOS ticket, is 38 where MIT would accept. Product callers (`verify_ap_req`, GSS accept, AP builders) pass `ApVerifyParams.addresses: None`, so the list-equality path is not taken unless a caller supplies addresses. The KDC TGS sender bind uses `address_search` (A′-2 item 10). Do not weaken KDC search to list-equality. |

### Parity decisions (not deviations)

DOMAIN-X500-COMPRESS joins on unescaped field text (MIT `maybe_join`:
`X.COM,C\.` → `C.X.COM`). Null subfields match MIT
`process_intermediates` (leading/trailing comma, `,,`).

A TGS-REQ whose `body.realm` is not a realm this KDC serves is 60
`GET_LOCAL_TGT` (MIT `get_local_tgt` on a single-realm KDC; a
multi-realm MIT KDC may answer 68 `WRONG_REALM` from `dispatch.c`).
Destination RENEW/VALIDATE is not exempt.

The master-key stash `.k5.REALM` is a FILE keytab with one `K/M@REALM`
entry (etype and kvno embedded, MIT `krb5_def_store_mkey_list`); loading reads
the keytab first, then a legacy raw-key stash, rewriting it in keytab format on
the next save. This removes the blind etype trial the raw format required.

Principal aliases resolve like `krb5_db_get_principal` (`kdb5.c:800-840`):
an alias stub is a keyless `DISALLOW_ALL_TIX` entry whose only content is
`KRB5_TL_ALIAS_TARGET`, followed up to `MAX_ALIAS_DEPTH` (10) hops to the
canonical entry; a longer or self-referential chain is `NOENTRY`. Every
`krb5_db_get_principal` caller resolves (AS/TGS lookup, kadm5 modify/cpw/
delete-through-alias), so an alias is a live name for its target; kadmin's
`getprinc` prints the target's record. The AS keeps the requested name in the
ticket unless CANONICALIZE is set (`do_as_req.c:681-687`), and the AS-REP
carries PA-ETYPE-INFO2 with the *canonical* client's salt
(`_make_etype_info_entry`), so `kinit` under an alias derives the target key.
The AS *server* name is canonicalized on the same condition, and only for a
krbtgt request whose requested and DB server are both TGS principals: the
ticket sname and `reply_encpart.server` then carry the canonical DB name
(`do_as_req.c:660-666,243`), matching Windows short-realm aliasing.
`create_alias` needs unrestricted ADD on the alias and MODIFY on the target
(`acl_addalias`); the target need not exist and a dangling alias is
overwritable (MIT emergent behavior); `renprinc` of an alias is
`KRB5_KDB_ALIAS_UNSUPPORTED`.

A cross-realm TGT whose client realm is this KDC (`check_tgs_lineage`)
is 12 `INVALID LINEAGE` even when `reject_bad_transit = false`.
S4U2Self is exempt (MIT `tgs_policy.c`). S4U2Self server match is by
DB entry *and* realm (`is_client_db_alias`): a foreign TGT client with
a colliding local name is 36 `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH`.
S4U2Self is not password authentication: the impersonated client's
`pw_expiration` and `REQUIRES_PWCHANGE` are cleared (`kdc_util.c:1612-1615`).
`s4u2self_forwardable` keeps FORWARDABLE when `allowed_to_delegate` is
empty (MIT `addprinc -randkey` / Rust `create_host` seed no targets);
a non-empty target list without `OK_TO_AUTH_AS_DELEGATE` clears F.

FAST armor decrypt binds keys to the armor `ticket.realm` (MIT
`fast_util.c` `rd_req`); forged-realm armor is 35 `NOT_US` (`rd_req`).
A local non-krbtgt armor ticket is 26 `SERVER_NOMATCH`.
A presented-TGT krbtgt with `DISALLOW_SVR` or `DISALLOW_ALL_TIX` is 7
`PROCESS_TGS` (`kdc_util.c:390-393`). AS `DISALLOW_SVR` is 27
`SERVICE NOT ALLOWED` with no ENC-TKT-IN-SKEY exemption
(`kdc_util.c:790-793`); that bit is already `INVALID AS OPTIONS` 13
on an AS-REQ. Header-ticket decrypt uses only the labeled kvno, with
at most three tries when kvno is 0 (`kdc_rd_ap_req`).

Checksums are verified by the declared `cksumtype` (`verify_checksum.c`):
type 0 substitutes the key's mandatory type, `output_size` is
`KRB5_BAD_MSIZE`, unkeyed/not coll-proof is 50 (`rd_safe.c:70-74`,
`kdc_util.c:1244`). KRB-SAFE checksums the dummy (zero-type/zero-length
checksum) encoding that splices the received KRB-SAFE-BODY
(`encode_krb5_safe_with_body`), then the saved body (RFC 1510). A
non-APPLICATION-20 tag is 40 `MSG_TYPE`. Sender/receiver addresses are
checked before the checksum (`privsafe.c:312-382`). Two `k5_privsafe_check_addrs`
arms are deliberately laxer, fail-closed on the real wire: when no local address
is set MIT walks `krb5_os_localaddr` and rejects a non-local r-address
(`privsafe.c:366-375`), and MIT also runs the check on KRB-PRIV (`rd_priv.c:77-78`);
Rust accepts an r-address when no local address is supplied and does not run the
check on the KRB-PRIV path, because no product path (kprop, kpasswd) emits an
r-address and the protocol crate has no OS address enumeration. The GSS sequence
window (`accept_seq`) is enforced unconditionally where MIT's `g_seqstate_check`
returns `GSS_S_COMPLETE` when neither replay nor sequence was negotiated
(`util_seqstate.c:84-117`); Rust is stricter (it never delivers an out-of-order
token), and MIT peers always negotiate replay/sequence so the window is enforced
identically for them. `build_krb_safe_ex` checksums the full KRB-SAFE with a
spliced zero checksum (`create_krbsafe`, `mk_safe.c:68-80`), MIT's primary verify
branch, rather than the body alone. GSS wrap-without-conf requires `EC == cksumsize`;
MIC fillers are 0xFF and the header is reconstructed (`util_crypt.c:322-334`).
A GSS authenticator checksum that is not 0x8003 is verified over empty
data with the ticket session key (`accept_sec_context.c:494-511`,
`rd_req_dec.c:748-749`). Missing checksum: flags 0 and no AP-REP.
0x8003 shorter than 24 is `GSS_S_BAD_BINDINGS`; `cb_len != 16` is
`GSS_S_FAILURE`. An all-zero token CB is accepted when the acceptor has
bindings; a mismatch is `GSS_S_BAD_BINDINGS`; a match sets
`GSS_C_CHANNEL_BOUND_FLAG`. Token flags are masked with `INITIATOR_FLAGS`;
a forwarded KRB-CRED sets `GSS_C_DELEG_FLAG` and the acceptor keeps only
the delegated client name, not a usable credential handle (stricter than
MIT `rd_and_store_for_creds`, `accept_sec_context.c:571-577`); the
established context sets
`GSS_C_PROT_READY_FLAG` (`:1089`), a `GSS_EXTS_FINISHED` extension and a
bad forwarded KRB-CRED are `GSS_S_FAILURE` (`:380-384`, `:571-574`), and
RRC is reduced modulo the payload length (`unwrap.c:255-263`). `unwrap`
reports `conf_state`; the RPCSEC_GSS privacy service rejects an
integrity-only body (`authgss_prot.c:238-240`), so a client that
negotiated `rpc_gss_svc_privacy` cannot downgrade to an unsealed request.
PA-FOR-USER unkeyed is 50 and a bad MAC is 41
(`INVALID_S4U2SELF_CHECKSUM`). PAC SHA-1 on the server checksum is 15
(`pac.c:496-497`). PAC signatures are verified over the received bytes
(`pac.c:478-579`): a copy zeros the server and privsvr payloads in place;
privsvr covers the whole server-checksum buffer minus the 4-byte type
(RODCIdentifier trailer included); a missing buffer is 60 `GENERIC`; a
failed server checksum does not abort before privsvr. Ticket (16) and
full (19) checksums exist only on service tickets
(`k5_pac_should_have_ticket_signature`, `pac.c:583-592`,
`pac_sign.c:239-243`); a presented TGT is checked on its server
signature alone with the key that opened it (`kdc_util.c:597-602`), so
MIT-issued TGTs are accepted and Rust-issued TGTs are accepted by MIT
(`scripts/cross-kdc-gate.sh`). Because that server signature is the
shared inter-realm key, a trusted realm could otherwise forge a
`LOGON_INFO` asserting the local domain's Domain Admins or RID 500.
On a reissue whose header ticket is from a foreign realm, MS-PAC SID
filtering (`filter_cross_realm_logon`) drops every SID under the local
domain from the subject's extra SIDs and resource groups, keeping the
foreign realm's own SIDs and well-known SIDs (`S-1-18-1`); a base
identity that itself claims the local domain is refused `POLICY`. This
matches an Active Directory domain controller and is stricter than
MIT with the db2 KDB, which carries no cross-realm `LOGON_INFO` at all.
`scripts/samba-realtrust-gate.sh` shows the legitimate reverse PAC
keeping the foreign Samba domain SID through the Rust KDC. `krb5_pac_parse` refusals (version,
buffer count, 8-byte alignment, header overlap) and duplicate buffer
types are 60 (`pac.c:281-317,137-147`). Ticket checksum
(`pac.c:640-673`) is over the recoded EncTicketPart with PAC ad-data
`0x00`. The FAST client verifies `ticket_checksum`
(`fast.c:543-551`). PA-REQ-ENC-PA-REP (149) is produced when the AS-REQ
advertises it; since the R0a SPAKE-padata fix the kinit client always
appends the empty PA-AS-FRESHNESS (150) and PA-REQ-ENC-PA-REP (149) on
every AS-REQ (`as_ex.rs build_as_req`) and verifies the returned 149
checksum (`fast.c:646-666`), so a KDC that sets `enc-pa-rep` without
returning 149 is rejected `KDCREP_MODIFIED`.

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
TGS AP-REQ armor with a PA-TGS-REQ subkey is 24 `FIND_FAST` (log
`Ap-request armor not permitted with TGS`); without that subkey the KDC
runs `armor_ap_request` (`fast_util.c:159-166`). AP-REQ armor whose
authenticator has no subkey is 12 `FIND_FAST` (log `ap-request armor
without subkey`, `fast_util.c:70-77`) on both AS and TGS. A PA-TGS-REQ
header ticket or authenticator carrying AD-FX-ARMOR (71) — including
inside IF-RELEVANT — is 12 `PROCESS_TGS` (`kdc_util.c:217-229`); 1.22.2
never emits 71 (RFC 6113 §5.4.1 defence in depth). The FAST armor AP-REQ
is not scanned. PA-FX-COOKIE is bound to the unparsed client with PRF+
and expires at 600 s (`fast_util.c:465-721`, ku 513); a garbage, expired,
or wrong-client cookie is ignored, matching MIT's `return 0`.
Corrupt `enc_fast_req` is 31 `FIND_FAST`; malformed `KrbFastReq` is
60 `FIND_FAST` (`do_as_req.c:531-535`). Log `detail` is MIT's
`k5_setmsg` where MIT has one; the critical-FAST-option `detail`
(`FAST option`) is Rust's own (`UNKNOWN_CRITICAL_FAST_OPTION` has
no MIT `k5_setmsg`). Hide-client-names (FAST option bit 1) is
honoured (R2-P4): the AS-REP outer client becomes the anonymous
principal `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS`
(`kdc_fast_hide_client`, `do_as_req.c:324`). Only critical bits 0 and
2..15 are refused as 93 `FIND_FAST` (`UNSUPPORTED_CRITICAL_FAST_OPTIONS`
`0xbfff0000`, `k5-int.h:802-803`).

**FAST hide-client-names scope:** the AS-REP *success* reply is
anonymized; the FAST *error* reply and the TGS-REP / TGS error are not
yet (`do_as_req.c:831`, `do_tgs_req.c:235,1111`), because the outer
KRB-ERROR is built from the request body without the FAST hide flag. A
hide-client-names request that then errors, or a hidden TGS, still
exposes the client name in the outer reply — a documented residual
(ledger `do_as_req.c:831` row).

### W1-J L1a — GSS unwrap_v3 / verify_enc_header

MIT `unwrap.c` `unwrap_v3` checks toktype, filler `0xFF`, and direction
(`FLAG_SENDER_IS_ACCEPTOR` vs `initiate` → `GSS_S_BAD_SIG`). Confidential
tokens decrypt then `verify_enc_header` (toktype, flags, filler, EC, seq;
RRC bytes are not compared) and return `plain.len - ec - 16`. Non-conf
requires `ec == cksumsize`. Rust `unwrap_v3` is that function for wrap and
the no-SIGN_ONLY wrap_iov path. DCE-style wrap_iov (real EC padding) is
pinned by `gss-gate.sh`. DCE handshake (`kg_accept_dce`) is only the extra
token needed for that cell; SIGN_ONLY + DCE trailer EC is out of this item.

### W1-J L0 — EncKDCRepPart APPLICATION 26

MIT encodes both EncASRepPart and EncTGSRepPart with application tag 26
(`asn1_k_encode.c:1127-1133`) and decodes 26 then 25. Rust matches that
on emit and decode. Other Kerberos clients that accept only RFC
APPLICATION 25 are out of this item's scope.

### W1-I — kadmind acceptors, RPCSEC_GSS, iprop, K13 policy, kadmin.local

The W1-I surface is the kadmind AUTH_GSSAPI acceptors, the RPCSEC_GSS
state machine (`_svcauth_gss` / `check_rpcsec_auth`), the iprop
program (`ipropx_resync` / `kiprop`), K13 policy (`pw_min_life` /
`pw_max_life` / `krb5_string_to_deltat`), and `kadmin.local` (no ACL;
exit 1 after a failed verb). The paragraphs below pin that surface
against MIT 1.22.2.

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
store realm (`krb5_parse_name`). Principal strings use
`krb5_parse_name` / `krb5_unparse_name` (`parse.c:62-102`,
`unparse.c:85-134`): `\/` `\@` `\\` `\t` `\n` `\b` `\0`, empty
components allowed, `foo@` keeps an empty realm. ACL `*/admin@R`
does not match a one-component `foo/admin`. Restriction durations
are `krb5_string_to_deltat` (`x-deltat.y`); `12:34` loads,
`42x` is 42 s (`mylex` default is `YYEOF`), `3dd` is
`invalid restrictions`, and trailing whitespace is `tok_WS`
(`x-deltat.y:225`): `42 ` is invalid while `1d ` is absorbed by the
`opt_s` slot after `d`/`h`/`m` (`:146,169-170`). CREATE/DELETE/RENAME authorise on the
request principal with no lookup (`server_stubs.c:262-303`,
`rec_out == NULL`). An authorised `addprinc user@OTHER.REALM`
creates that principal in the local KDB. Unknown ACL op letters
are `Unrecognized ACL operation '%c' in %s` (`auth_acl.c:286-290`). Unauthorised `getprinc` of a
missing principal is `KADM5_UNK_PRINC` (`stub_setup` `:296-301`)
before ACL. A readable ACL file is the ACL: it is
not replaced when `admin@REALM` is absent (`acl_init:547-563`). With no
`KRB5_ACL_FILE` and no kdc.conf `acl_file`, kadmind loads
`<kdc dir>/kadm5.acl` (`alt_prof.c:509-510`, `osconf.hin:106`). A
missing or unreadable file is `fail_to_start` (`ovsec_kadmd.c:497-500`,
`auth_acl.c:398-406`): `Cannot open PATH: No such file or directory
while initializing ACL file, aborting`. An empty `acl_file` is
`acl_init(NULL)` (`ovsec_kadmd.c:497`) → self rules only
(`auth_acl.c:554-555`); the embed API is `Acl::none()`. An
unparseable target or unknown restriction token is a load error
(`acl_init`); kadmind refuses the file. `*`/`x` still
exclude extract (`e`). `listprincs`/`listpols` require `l`
(`KADM5_AUTH_LIST`, `server_stubs.c:814,1443`). addpol is
`KADM5_AUTH_ADD`, delpol `KADM5_AUTH_DELETE`. Self cpw/chrand/purgekeys/
getprinc/getstrs (and own-policy getpol) follow `auth_self.c:38-75`.
Self key change without an INITIAL ticket is `KADM5_AUTH_INITIAL`
(`server_stubs.c:368-381`). Policy `pw_min_life` / `pw_max_life` round-trip
on `getpol`. Self chpass/chrand/kpasswd run `check_min_life`
(`misc.c:60-121`): `KADM5_PASS_TOOSOON` / kpasswd result 4 unless
`REQUIRES_PWCHANGE`; a non-self admin ignores min_life. `pw_max_life`
sets `pw_expiration` (`-policy` from `last_pwd_change`, cpw from now;
`svr_principal.c:614-625,1336`). Self `-keepold` clamps to
`MAX_SELF_KEEPOLD` 5 (`server_stubs.c:391-399`) for chpass, chrand and
setkey alike as a version count (`kdb_cpw.c:117-137`). MIT 1.22.2
`kadm5_setkey_principal_4` copies the old keys but never advances
`n_new_key_data` past the new ones (`svr_principal.c:1695-1710`), so its
setkey `-keepold` drops every old key; kerber-rust keeps them (deviation,
pinned on both legs by `scripts/kadmin-gate.sh`). Chpass order is lockdown → ACL → self
keychange (`:851-869`). `get_privs` returns `~0`
(`server_misc.c:146-158`). `kadmin.local` applies no ACL (`KRB5_ACL_FILE`
is kadmind-only). `addpol`/`modpol`/`alias` print a `com_err` line and
exit 0 like MIT (`kadmin.c`); other verbs still exit 1 where MIT exits 0
outside script mode (`ss_wrapper.c:66-76`, `kadmin.c:89-99`; stricter,
so scripted runs fail loud). The `alias` verb and the shared policy
create/modify path (`kadm5_create_policy` order min>max → length →
classes → history, `kadm_err.et` texts) landed in W1-K M3b; the
`getdate.y` natural-language interval (`1 day ago`) is a deferred gap
(`parse_pol_interval` accepts only `krb5_string_to_deltat`). A `kadmin/changepw` GSS acceptor is
`CHANGEPW_SERVICE` (`server_stubs.c:28-32`, a full realm-qualified
name compare against `kadmin/changepw@REALM`): every stub denies with
MIT's code except self `chpass`/`chrand`/`getprinc`
(`changepw_not_self`, `:348-354`) and getpol of the caller's own
policy (`:1401-1403`). `getstrs` and `purgekeys` use
`CHANGEPW_SERVICE` (even self is denied).
Kadmind AUTH_GSSAPI acceptors are the realm-qualified `kadmin/admin@REALM`
and `kadmin/changepw@REALM`, built with `params.realm`
(`ovsec_kadmd.c:468-477`). RPCSEC_GSS is
`check_rpcsec_auth` (`kadm_rpc_svc.c:324-331`): two components,
realm match, `kadmin`, not `history`, else `svcerr_weakauth`. All four
acceptor checks are realm-qualified in Rust through `acceptor_realm_ok`;
the realm is bound at `accept_sec_context` and re-checked at the gate.
iprop is RPCSEC_GSS only (`ipropd_svc.c:481-483`) with
`kiprop/<host>` (`:508-516`); AUTH_GSSAPI INIT is the auth-layer
SUCCESS/`no_dispatch` path (`svc_auth_gssapi.c:495-497`), DESTROY is
likewise answered in the auth layer (`:616-623`), and DATA is
`AUTH_TOOWEAK` once a context exists (`ipropd_svc.c:542-548`). A
`kadmin/admin` RPCSEC acceptor on the iprop program is `AUTH_TOOWEAK`;
`kiprop/<host>` dispatches. MIT accepts any KDB principal as an acceptor
(`setup_kdb_keytab`) and gates by name; the Rust kadmind loads the four
documented kadm5 principals (`kadmin/admin`, `kadmin/changepw`,
`kadmin/history`, `kiprop/<host>`). The RPCSEC_GSS INIT reply verifier is
`gss_get_mic(htonl(seq_window))` (`svc_auth_gss.c:271-286,496-504`).
MIT ships each key as the master-key ciphertext its KDB already stores
(`kdb_convert.c` copies `key_data_contents`), so it structurally never
sends plaintext. The Rust store holds plaintext keys and wraps them
under the master key at ship time (`iprop_master_key`: stash, then
`KRB5_MASTER_PASSWORD`, then the `K/M` principal). With none of those
available it answers `UPDATE_ERROR` rather than send keys in the clear
(a fail-closed deviation, stricter than MIT). A persisted primary always
has a stash, so this is reached only by an in-memory or stash-less
configuration.
`_svcauth_gss` answers version mismatch as `AUTH_BADCRED`, INIT without
NULLPROC as `AUTH_FAILED`, `accept_sec_context` / unknown `gc_proc` as
`AUTH_REJECTEDCRED`, DATA/DESTROY header MIC failure as `CREDPROBLEM`,
and `gc_seq > MAXSEQ` / window replay as `CTXPROBLEM`; DESTROY then
drops the context (`:449-547`). The context is selected by the
connection, so `gc_handle` is not compared (`:385-419`): a DATA with a
wrong handle but a valid header MIC dispatches, matching MIT.
Accepted/mismatch replies carry
`xp_verf` (`svc.c:342,361`). Empty KDC drops are silent of
`while dispatching` when the issue code is 0 (`net-server.c:1101-1105`).
A full-resync deny is `kdb_fullresync_result_t`
(`ipropd_svc.c:312-320`, `iprop.x:208-211`). Purgekeys of a
locked-down principal is allowed (`server_stubs.c:1495-1530`).
Kadmind ONC RPC (`svc.c:486-520`) answers `PROG_UNAVAIL` for an
unknown program, `PROG_MISMATCH` with low=high=`KADMVERS` 2 for
program 2112 and a wrong version, and `AUTH_TOOWEAK` for AUTH_NONE
on a matching program (`kadm_rpc_svc.c:80-88`). A REPLY-typed
message fails `xdr_callmsg` (`rpc_callmsg.c:107-108`) so no reply
is sent and the connection is kept.
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
is W1. Purgekeys of a locked-down principal is allowed
(`server_stubs.c:1495-1530`, `svr_principal.c:1937`).
Length prefix and version are checked before AP-REQ work
(`schpw.c:47-82`). Inconsistent length, unknown version, and the
truncated cases `goto bailout` (`:384-397`); `dispatch` calls
`respond(..., NULL)` so no datagram is sent (`:424-435`). AP-REQ
length `>=` remaining bytes (no PRIV) is that bailout (`:89-95`).
Post-AP-REQ `chpwfail` (`:320-345`) is always `error_code` **60**
(`alloc_data` zeros `ret` so `ERROR_TABLE_BASE_krb5` wraps past
`KRB_ERR_MAX`), `client = NULL`, `server = kadmin/changepw@R`
(`krb5_build_principal` NT_PRINCIPAL), empty `e_text`,
`e_data = result‖text`. The UDP path logs MIT com_err text
(`Message stream modified` / `Requested protocol version not
supported`) plus `- while dispatching (udp)` (`net-server.c:1103`).
Framing a KRB-ERROR here would be a 22–25× UDP reflector for a
6-byte spoofable datagram; MIT does not have that.
`ChangePasswdData` is decoded only for version `0xff80`. KDC TCP
`bufsiz` is 1 MiB; `msglen > bufsiz-4` is **61** (`net-server.c:1278,
1391-1414`). Concurrent KDC TCP connections are capped at 45
(`max_stream_data_connections`); at the cap a new connection evicts the
oldest live one (`kill_lru_stream_connection`, `net-server.c:1192-1282`)
rather than being refused, so a slow-loris cannot starve the newcomer. kpropd `recvauth` junk that is not APPLICATION 14 is
**40** `Invalid message type` plus the trailing NUL (`rd_req.c:56-57`,
`recvauth.c:165-170`).

## Not in this matrix

In-process metrics counters are deferred (logs already carry
`duration_us` and `outcome`; see [`logging.md`](logging.md)).
Dependency `unsafe` is not a numeric gate.
