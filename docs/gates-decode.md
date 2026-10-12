# Gates — decode and rd-priv oracles

Rows moved here byte for byte from [gates.md](gates.md).

| Gate | Oracle | Workflow | Lane | Asserts |
| --- | --- | --- | --- | --- |
| `scripts/asn1-decode-oracle-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT 1.22.2's own `decode_krb5_<type>` in an in-container C oracle (`scripts/oracle/asn1-decode-oracle.c`, no Rust code) over the decode sweep (`asn1-sweep corpus`: every explicit `[n]` field and SEQUENCE OF element of 41 message types broken each of nine ways, and each 32-bit counter at MIT's int32 edges), then over the Rust decoder's re-encoding of each case it decodes: red when the Rust decoder refuses a case MIT decodes, decodes one MIT refuses, or decodes one to a value MIT re-encodes otherwise, and when the committed golden (`crates/krb5-tools/tests/data/asn1-mit-golden.tsv`, which the unit test reads) is not MIT's answer |
