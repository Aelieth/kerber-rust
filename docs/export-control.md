# Export control

This tree is cryptographic software: a Kerberos V5 implementation with
AES-CTS-HMAC (IANA 17–20), RFC 3961 3DES, Camellia-CTS-CMAC, RC4-HMAC,
HMAC, PBKDF2, Oakley MODP Diffie–Hellman, ECDH P-256, and SPAKE. It is
not a toy or a documentation-only stub.

## Classification (honest, not a determination)

Publicly available encryption source code of this kind is commonly
discussed under **ECCN 5D002**. When the source is publicly available
and the notification steps in **15 CFR 740.13(e)** (TSU — technology
and software unrestricted) are followed, distributors of *source code*
often rely on that open-source exception. Object-code / binary
distribution is a different analysis.

This document is **not** a formal classification, a BIS ruling, or
legal advice. Anyone who exports, re-exports, or transfers this
software (source or binary) must review the EAR, any TSU notification
they are required to file, and the laws of their own jurisdiction.

## License coherence

The product is **Apache-2.0 OR MIT** (`LICENSE`, `LICENSE-APACHE`,
`LICENSE-MIT`; `workspace.package.license`). Third-party crates are
gated by `deny.toml` (`cargo deny` in CI): MIT, Apache-2.0,
BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib. See `NOTICE`.
