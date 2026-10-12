# vendor/rasn: rasn 0.28.14, patched

This is rasn 0.28.14 as crates.io publishes it. The crate is `rasn-0.28.14.crate`, sha256
`0d1b71dd951343df0fe30b11bca09518f3aba8e5bd0ece4564adbc2dabd875fa`, the checksum `Cargo.lock` held;
it was cut from upstream commit `398c530c`.

Only `src/ber/de.rs`, `src/ber/enc.rs` and `src/types/strings/general.rs` differ, and this file is
new. The workspace takes the crate through `[patch.crates-io]` in the root `Cargo.toml`.
cargo-vet audits it as crates.io's 0.28.14 (`[policy.rasn] audit-as-crates-io = true` in
`supply-chain/config.toml`), so this file and its diff are the review of the delta:

```sh
curl -sL https://static.crates.io/crates/rasn/rasn-0.28.14.crate | tar -xz
diff -ru rasn-0.28.14 vendor/rasn
```

## From upstream: rasn 0.29.0, commit ab9d0fd565

rasn 0.29.0 also rewrites the BER parser and changes its API, so it is not taken whole. This is
the commit's error handling, backported to 0.28.14.

- **An OPTIONAL explicit field that is present but does not decode fails the message.**
  `decode_optional_with_explicit_prefix` used to map every error to `None`, so such a field read as
  absent. It now goes through `decode_optional_with_check`: the field is absent only when the
  contents have ended or the next tag is another one.
- **A SEQUENCE OF, SET OF or SET element that does not decode fails the message.** These loops used
  to stop at the first error. The failing element's octets had already been read, so a broken last
  element was dropped. Each loop now reads to the end of its contents (`at_end_of_contents`, with
  `closed_by_end_of_contents` for indefinite lengths) and passes an element's error on.
- **Tests.** Upstream's three tests come with it: `malformed_optional_explicit_prefix_is_an_error`,
  `malformed_set_of_element_reports_its_own_error` and
  `indefinite_sequence_of_ends_at_the_end_of_contents_octets`.

## kerber-rust: as MIT 1.22.2 decodes (`lib/krb5/asn.1/asn1_encode.c`)

Each change is marked `kerber-rust:` in the source.

- **An explicit tag is constructed** (`check_atype_tag`, X.690 8.14.3). `decode_explicit_prefix`
  refuses a primitive `[n]`. An OPTIONAL field takes a primitive element as another field's.
- **An INTEGER, a BOOLEAN, a NULL and an OBJECT IDENTIFIER are primitive** (`check_atype_tag`).
  `parse_primitive_value` refuses a constructed one. Before, it read the inner element's octets as
  the value.
- **A SEQUENCE is extensible** (`decode_sequence`). Contents after the last field it reads, or from
  an element no later field takes, are left unread, not refused.
- **A GeneralString is octets** (`k5_asn1_decode_bytestring`). `decode_general_string` keeps any
  octets (`GeneralString::from_octets`), not only those of its alphabet.
- **An INTEGER keeps MIT's overflow** (`k5_asn1_decode_int`, `store_int`). The value is the
  INTEGER's two's complement in up to eight octets. No octet is dropped to make it fit. A value
  outside the type is an overflow.
- **A `u32` is MIT's `int32`.** It decodes from `INT32_MIN..=INT32_MAX` into its 32 bits, and its 32
  bits encode as an int32 (`src/ber/enc.rs`). In kerber-rust a `u32` is always such a field: a kvno,
  a nonce or a cusec. Sequence numbers, which MIT reads differently (`decode_seqno`), go through
  `krb5-types`'s own `WireSeqNumber`.
