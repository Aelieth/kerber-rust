# vendor/rasn: rasn 0.28.14, patched

This is rasn 0.28.14 as crates.io publishes it. The crate is `rasn-0.28.14.crate`, sha256
`0d1b71dd951343df0fe30b11bca09518f3aba8e5bd0ece4564adbc2dabd875fa`, the checksum `Cargo.lock` held;
it was cut from upstream commit `398c530c`.

Only `src/ber/de.rs` differs, and this file is new. The workspace takes the crate through
`[patch.crates-io]` in the root `Cargo.toml`. cargo-vet audits it as crates.io's 0.28.14
(`[policy.rasn] audit-as-crates-io = true` in `supply-chain/config.toml`), so this file and its
diff are the review of the delta:

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
