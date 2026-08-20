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
| [4121](https://www.rfc-editor.org/rfc/rfc4121) | GSS-API Kerberos V5 Mechanism | `krb5-gss` wrap/unwrap/MIC; MIT libgssapi is out-of-process. |
| [4556](https://www.rfc-editor.org/rfc/rfc4556) | PKINIT | ECDH P-256 reply-key on AS. `signedAuthPack` / `dhSignedData` are CMS SignedData ContentInfo wrapping the inner blob; no X.509 certificates. Raw inner DER is still accepted. |
| [6113](https://www.rfc-editor.org/rfc/rfc6113) | FAST | Armor AP-REQ, PA-FX-COOKIE, KrbFastReq/Rep, strengthen-key (KRB-FX-CF2) on the AS path. |
| [3244](https://www.rfc-editor.org/rfc/rfc3244) | kpasswd | `PrincipalStore::set_password` bumps kvno and keeps prior keys; ACL `c` plus self-service. |
| [4120] transited / referrals | Cross-realm | `krbtgt/FOREIGN` keys; TGS referral tickets; comma-separated transited (tr-type 1, not X.500 compress); AS `WRONG_REALM`. |
| [4120] §7.2.1 / UDP-TCP 88 | KDC protocol | Harness and `krb5-kdc` listen on 127.0.0.1:88 (fallback 8888). |

DES, 3DES, and RC4 are out of scope (removed or non-default in MIT
1.22.2).
