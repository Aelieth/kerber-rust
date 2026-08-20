# RFC mapping

Authoritative protocol text is the IETF RFC. MIT Kerberos 1.22.2 is the
primary implementation oracle. Existing Rust crates (`rasn-kerberos`,
`krb5-rs`, …) are reference material only.

| RFC | Title | Status in this tree |
| --- | --- | --- |
| [4120](https://www.rfc-editor.org/rfc/rfc4120) | The Kerberos Network Authentication Service (V5) | Core types + DER in `krb5-types` / `krb5-asn1`. AS/TGS/AP *flows* are Stage 3+. |
| [3961](https://www.rfc-editor.org/rfc/rfc3961) | Encryption and Checksum Specifications | n-fold, DK, simplified profile, key usage. Etypes 17–20 only. |
| [3962](https://www.rfc-editor.org/rfc/rfc3962) | AES Encryption for Kerberos 5 | Etypes 17, 18 (`aes128/256-cts-hmac-sha1-96`). |
| [8009](https://www.rfc-editor.org/rfc/rfc8009) | AES Encryption with HMAC-SHA2 | Etypes 19, 20 (`aes128-cts-hmac-sha256-128`, `aes256-cts-hmac-sha384-192`). |
| [4121](https://www.rfc-editor.org/rfc/rfc4121) | GSS-API Kerberos V5 Mechanism | Mapped, **not implemented** (Stage 4). |
| [4556](https://www.rfc-editor.org/rfc/rfc4556) | PKINIT | Mapped, **not implemented**. |
| [6113](https://www.rfc-editor.org/rfc/rfc6113) | FAST | Mapped, **not implemented**. |
| [4120] §7.2.1 / UDP-TCP 88 | KDC protocol | Harness exposes 88; Rust KDC is Stage 5. |

DES, 3DES, and RC4 are out of scope (removed or non-default in MIT
1.22.2).
