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
| [4121](https://www.rfc-editor.org/rfc/rfc4121) | GSS-API Kerberos V5 Mechanism | `krb5-gss` wrap/unwrap/MIC with 16-byte tokens, sequence numbers, and 0x8003 channel bindings. MIT `libgssapi_krb5` interop is out-of-process (`scripts/gss-gate.sh`). |
| [4556](https://www.rfc-editor.org/rfc/rfc4556) | PKINIT | ECDH P-256 + CMS SignedData. `cms_verify` is **mandatory** against a provisioned CA (no unverified fallback). The CA is **opt-in** (`--export-pkinit` / `KRB5_ENABLE_PKINIT=1`). Reply key uses RFC 4556 `octetstring2key`. `scripts/pkinit-gate.sh` **fails** if MIT `pkinit.so` is missing or MIT `kinit` PKINIT fails. Remaining gaps vs MIT: SPKI `clientPublicValue`, `signedAttrs`, cert EKU. |
| [6113](https://www.rfc-editor.org/rfc/rfc6113) | FAST | `PA-FX-FAST` rasn CHOICE `{ armored-data [0] }`, armor AP-REQ, cookie, KrbFastReq/Rep, CF2 strengthen on AS. **Self-tested, not MIT-gated.** TGS FAST is not sent (MIT FIND_FAST vs PA-TGS-REQ usage 7). PRF+ counter is prepended per RFC 6113 §5.1. |
| [3244](https://www.rfc-editor.org/rfc/rfc3244) | kpasswd | `PrincipalStore::set_password` bumps kvno and keeps prior keys; ACL `c` plus self-service. |
| [4120] transited / referrals | Cross-realm | `krbtgt/FOREIGN` keys; TGS referral tickets; comma-separated transited (tr-type 1, not X.500 compress); AS `WRONG_REALM`. |
| [4120] §7.2.1 / UDP-TCP 88 | KDC protocol | Harness and `krb5-kdc` listen on 127.0.0.1:88 (fallback 8888). |

3DES (16), RC4 (23), and Camellia (25/26) exist behind
`allow_weak_crypto` (Camellia-CTS-CMAC uses the `camellia`+`cmac`
crates; RC4 applies the RFC 4757 usage map; 3DES uses RFC 3961 §6.3
s2k). Single-DES is not implemented. These paths are **self-tested**.

`krb5-config` parses `krb5.conf`/`kdc.conf` and DNS SRV but is **not**
the KDC/client resolver: kinit still takes the KDC host as argv.
