# RFC mapping

Authoritative protocol text is the IETF RFC. MIT Kerberos 1.22.2 is the
primary implementation oracle. Existing Rust crates (`rasn-kerberos`,
`krb5-rs`, …) are reference material only.

| RFC | Title | Status in this tree |
| --- | --- | --- |
| [4120](https://www.rfc-editor.org/rfc/rfc4120) | The Kerberos Network Authentication Service (V5) | Core types + DER; AS/TGS client in `krb5-protocol` / `krb5-client`; AS/TGS KDC in `krb5-kdc`; AP-REQ verify. |
| [3961](https://www.rfc-editor.org/rfc/rfc3961) | Encryption and Checksum Specifications | n-fold, DK, simplified profile, key usage. Etypes 17–20 only. |
| [3962](https://www.rfc-editor.org/rfc/rfc3962) | AES Encryption for Kerberos 5 | Etypes 17, 18 (`aes128/256-cts-hmac-sha1-96`). |
| [8009](https://www.rfc-editor.org/rfc/rfc8009) | AES Encryption with HMAC-SHA2 | Etypes 19, 20 (`aes128-cts-hmac-sha256-128`, `aes256-cts-hmac-sha384-192`). |
| [4121](https://www.rfc-editor.org/rfc/rfc4121) | GSS-API Kerberos V5 Mechanism | `krb5-gss` wrap/unwrap/MIC with 16-byte tokens, sequence numbers, 0x8003 channel bindings, and send-side RRC=16. MIT `libgssapi_krb5` interop is out-of-process (`scripts/gss-gate.sh`). |
| [4556](https://www.rfc-editor.org/rfc/rfc4556) | PKINIT | Oakley MODP 2048/4096 (RFC 3526) plus ECDH P-256. CMS SignedData is **mandatory** against a provisioned CA (no unverified fallback). CA is **opt-in** (`--export-pkinit` / `KRB5_ENABLE_PKINIT=1`). Reply key is RFC 4556 `octetstring2key` unless RFC 8636 KDF is selected. `clientPublicValue` is SPKI; KDC CMS uses `signedAttrs` + issuerAndSerialNumber. `scripts/pkinit-gate.sh` **fails** if MIT `pkinit.so` is missing or MIT `kinit` PKINIT fails (MIT 1.22.2 `kinit` with FILE identity **passes**). |
| [6113](https://www.rfc-editor.org/rfc/rfc6113) | FAST | `PA-FX-FAST` rasn CHOICE `{ armored-data [0] }`. AS armor is explicit AP-REQ; TGS FAST uses implicit PA-TGS-REQ armor (usage 7) and checksums the AP-REQ bytes (MIT 1.22.2). Exercised by `kdc-gate.sh` MIT `kvno`. PRF+ counter is prepended per RFC 6113 §5.1. |
| [SPAKE](https://datatracker.ietf.org/doc/draft-ietf-kitten-krb-spake-preauth/) | SPAKE preauth | MIT 1.22.2 SPAKE2-P256: group id 2, IANA compressed M/N, `wbytes` from PRF+ of the long-term key with seed `SPAKEsecret` plus group id, K'[n] via CF2, factor usage 65, `KDC_ERR_MORE_PREAUTH_DATA_REQUIRED` (91). `scripts/spake-gate.sh` requires MIT `kinit` TRACE `SPAKE` and `klist user@KERBER.TEST`. |
| [3244](https://www.rfc-editor.org/rfc/rfc3244) | kpasswd | UDP/TCP 464: AP-REQ + KRB-PRIV. MIT `kpasswd` uses version 1, authenticator subkey, seq 0, and often omits the PRIV timestamp; success replies include AP-REP. Version `0xff80` carries `ChangePasswdData`. `set_password` bumps kvno; ACL `c` plus self-service. Gate: `scripts/kpasswd-gate.sh`. |
| [8636](https://www.rfc-editor.org/rfc/rfc8636) | PKINIT KDF agility | When AuthPack `supportedKDFs` includes SHA-256, the KDC sets `DHRepInfo.kdf` and derives the reply key with `SHA-256(counter\|\|Z\|\|OtherInfo)` over RFC 8636 `OtherInfo` (KRB5PrincipalName partyU/V, PkinitSuppPubInfo). MIT 1.22.2 TRACE: `PKINIT used KDF 2B06010502030602`. Absent `supportedKDFs` → RFC 4556 `octetstring2key`. |
| MS-PAC / MS-RPCE | PAC | NDR32 `KERB_VALIDATION_INFO` in field-encounter referent order. Golden `tests/traces/pac-kbruser.ndr`. Buffers 1,10,12,16,17,18,19,6,7. Signatures 6, 7, 16 (`PAC_TICKET_CHECKSUM`), 19 (`PAC_FULL_CHECKSUM`). Store SID/RID. TGS copies a verified presented TGT PAC (LOGON_INFO) and re-signs; type-16 over original EncTicketPart bytes (PAC ad-data `0x00`), not a rasn re-encode. MIT TGTs without a PAC still synthesize. Samba L1: `scripts/samba-pac-verify-gate.sh`. Samba L2: `scripts/samba-pac-l2-gate.sh` (vendored kcrypto 6/7/16/19; type-16 pre-image rebuilt in the oracle). |
| MS-SFU | S4U2Self / S4U2Proxy | TGS `issue_tgs`: PA-FOR-USER (HMAC-MD5-ARCFOUR cksumtype -138 on AES session keys, MIT 1.22.2); S4U2Proxy requires a **forwardable** evidence ticket, copies/re-signs the evidence PAC, denies classic constrained delegation unless `s4u_allowed_to` lists the target, and denies RBCD unless `s4u_allowed_from` lists the evidence server. Gate: `scripts/s4u-mit-gate.sh` MIT `kvno -U` / `-U -P` (in CI). |
| ONC RPC / kadm5 | kadmind 749 | Version-1 AP-REQ framing (library). `krb5-kadmind`: program 2112 vers 2, AUTH_GSSAPI flavor 300001 (`init_res.signed_isn`, wrap_data). MIT 1.22.2 `kadmin` add/get/list/mod/chrand/`renprinc`/del gated by `scripts/kadmin-gate.sh`. Rename is proc 4 (add+delete ACL); RID/keys are kept. `xdr_krb5_principal` is `xdr_nullstring` of the unparsed name; `mod_name` is never NULL (MIT unparses it). `xdr_gprincs_ret` writes count then `xdr_array` of `xdr_nullstring`. Policy opcodes 8–11, 15 (`policy-gate.sh`). Iprop program 100423 (`iprop-gate.sh`). |
| [4120] transited / referrals | Cross-realm | `krbtgt/FOREIGN` keys with an explicit shared key (`KRB5_TEST_INTERREALM_KEY`); optional `KRB5_TEST_INTERREALM_KEY_ACCEPT` when inbound/outbound AES salts differ. Referral TGTs **carry a PAC**. First-hop transited is empty (RFC 4120). Accepting TGS verifies that PAC and copies LOGON_INFO. `scripts/cross-realm-gate.sh`; Samba both directions: `scripts/samba-crossrealm-gate.sh` (`kvno` is not PAC-copy proof). |
| [4120] §7.2.1 / UDP-TCP 88 | KDC protocol | Harness and `krb5-kdc` listen on 127.0.0.1:88 (fallback 8888). |

3DES (16), RC4 (23), and Camellia (25/26) exist behind
`allow_weak_crypto` (Camellia-CTS-CMAC uses RFC 6803 KDF-FEEDBACK-CMAC
plus the `camellia`+`cmac` crates, with §10 s2k/DK/checksum KATs; RC4
applies the RFC 4757 usage map; 3DES uses RFC 3961 §6.3 s2k with
appendix A.4 output). Single-DES is not implemented.

`krb5-config` parses `krb5.conf`/`kdc.conf` and DNS SRV. The KDC applies
`kdc.conf` ticket policy (and non-test listen/db paths, including
`master_key_type` / `db_library`). `kinit` and TGS referral chase use
`KRB5_CONFIG` then `/etc/krb5.conf` `[realms]` (argv is the fallback).
The KDC database oracle is MIT `kdb5_util` dump/load (`krb5-kdb`,
version 7): the live at-rest file is dump text (`kdb5_util load_dump
version 7`); MIT `kinit` both directions (`scripts/kdb-dump-gate.sh`
loads the running KDC db file). Legacy KDB3 still loads for one
release. MIT-wire kprop/kpropd on 754 wraps dump version 7 both
directions (`scripts/kprop-gate.sh` MIT→Rust; `scripts/kprop-reverse-gate.sh`
Rust `krb5-kprop` → MIT `kpropd` then MIT `kinit`; additive to the
in-process kprop tests). C1 multi-host MIT client vs Rust primary/replica
is `scripts/prod-realm-gate.sh`. C2 stress/chaos/soak over that realm
are `scripts/stress-gate.sh`, `scripts/chaos-gate.sh`, and
`scripts/soak-gate.sh`.
