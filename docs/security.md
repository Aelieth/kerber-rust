# Timing, replay, and secret-handling matrix

Constant-time MAC compare, replay detection, zeroize-on-drop, and
0600 secret files are product code, not a later audit item. This
matrix names the shipped site and the test that drives it.

Replay is one implementation (`krb5-protocol` `ReplayCache`: 50_000
entries, 5-minute window, fail-closed on mutex poison). GSS wrap/MIC
uses a per-context sequence window in addition to the AP-REQ cache.

## Matrix

| Protection | Code site | Test |
| --- | --- | --- |
| Constant-time MAC / checksum | `krb5-crypto` `mac_verify` (`derive.rs`); callers `ops.rs` decrypt/checksum, `weak.rs` RC4/DES | `decrypt_bad_mac_is_error` (`krb5-crypto/tests/known_answer.rs`) |
| Constant-time PAC signature | `krb5-types` `verify_sig_buf` (`pac.rs`); KDC `verify_pac` / `verify_pac_signatures` | `crates/krb5-kdc/tests/ad_pac.rs` `verify_pac_signatures` |
| Replay — AP-REQ authenticator | `verify_ap_req` (`krb5-protocol` `ap_req.rs`) | `ap_req_valid_truncated_wrong_key_replay` |
| Replay — TGS authenticator | `issue_tgs` (`krb5-kdc` `issue.rs`) `tgs_replay` | `tgs_authenticator_replay_is_repeat` |
| Replay — PA-ENC-TIMESTAMP | `verify_enc_timestamp` (`issue.rs`) `pa_replay` | `pa_enc_timestamp_replay_is_repeat` |
| Replay — KRB-SAFE / PRIV / CRED | `safe_priv.rs` `check_and_store` on unwrap | `messages.rs` unwrap path; `ReplayCache` unit tests |
| Replay — GSS wrap/MIC sequence | `krb5-gss` `accept_seq` (`recv_window`) | `wrap_mic_replay_inside_window_is_rejected` |
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
MIT would accept or grow). They are not laxer than MIT.

| Deviation | MIT | Rust | Why |
| --- | --- | --- | --- |
| Transited field-count cap | No cap; a 300-hop honest path succeeds with T | More than 256 commas is `TooManyFields` (POLICY on the non-add path) | **STRICTER** than MIT |
| Transited hop-emission cap | No hop cap; `process_intermediates` streams callbacks at O(1) memory | More than 4096 emitted hops is `TooManyFields` (`MAX_TRANSIT_HOPS`) | **STRICTER** than MIT |
| Transited component bounds | Raw field ≤ 511 unescaped bytes; joined ≤ 512 (`chk_trans.c` `MAXLEN`) | Same (511 raw / 512 joined); over is `FieldTooLong` out of band | MIT-exact |
| Invalid UTF-8 in transited | Byte-exact | `from_utf8_lossy` inflates invalid bytes 3× against the 512 bound and collapses sequences to U+FFFD | STRICTER; byte-exact matching is general-pass |
| Append escaping | MIT `add_to_transited` does not escape `\` or `,` in the new realm | Escapes both | Stricter-correct than MIT's encoder |
| Add-path bounds | `MAX_REALM_LN` 500: raw ≥ 500, joined ≥ 499, rebuilt ≥ 500 (`strlcat` clamp; whole transited ≤ 499). Trailing empty field of `EDU,` is dropped (`EDU,`+`X` → `EDU,X`). Internal `,,` truncates MIT's list | Same raw/joined/total bounds. Encode stays uncompressed (total bound is stricter by the compression delta). Trailing-comma drop. Internal `,,` is preserved | MIT-exact bounds; `,,` preservation is stricter-correct |
| Encode-side X.500 RDN compression | MIT `add_to_transited` may emit compressed RDN form | Encode stays uncompressed (`from_realms`) | Deferred; decode still expands MIT compressed contents |

### Parity decisions (not deviations)

DOMAIN-X500-COMPRESS joins on unescaped field text (MIT `maybe_join`:
`X.COM,C\.` → `C.X.COM`). Null subfields match MIT
`process_intermediates` (leading/trailing comma, `,,`).

## Not in this matrix

In-process metrics counters are deferred (logs already carry
`duration_us` and `outcome`; see [`logging.md`](logging.md)).
Dependency `unsafe` is not a numeric gate.
