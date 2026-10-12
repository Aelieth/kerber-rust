# Gates — decode and rd-priv oracles

Rows moved here byte for byte from [gates.md](gates.md).

| Gate | Oracle | Workflow | Lane | Asserts |
| --- | --- | --- | --- | --- |
| `scripts/asn1-decode-oracle-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT 1.22.2's own `decode_krb5_<type>` in an in-container C oracle (`scripts/oracle/asn1-decode-oracle.c`, no Rust code) over the decode sweep (`asn1-sweep corpus`: every explicit `[n]` field and SEQUENCE OF element of 41 message types broken each of nine ways, and each 32-bit counter at MIT's int32 edges), then over the Rust decoder's re-encoding of each case it decodes: red when the Rust decoder refuses a case MIT decodes, decodes one MIT refuses, or decodes one to a value MIT re-encodes otherwise, and when the committed golden (`crates/krb5-tools/tests/data/asn1-mit-golden.tsv`, which the unit test reads) is not MIT's answer |
| `scripts/rd-priv-oracle-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT 1.22.2 `krb5_rd_req`, `krb5_rd_priv` and `krb5_rd_safe` in an in-container C oracle (`scripts/oracle/rd-priv-oracle.c`, the sibling of `rd-safe-oracle.c`) over `rd-sweep cases`: an AP-REQ whose authenticator, a KRB-PRIV whose `EncKrbPrivPart` and a KRB-SAFE whose body is broken as the decode sweep breaks a message, then re-encrypted or re-signed, and the three messages themselves broken the same way; MIT accepts the pristine three; red on any case the Rust acceptor answers otherwise than MIT (accepted, an ASN.1 error, or the krb5 code) |
