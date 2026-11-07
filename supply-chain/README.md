# Supply chain (`cargo vet`)

Imported audit sets: **Google**, **Mozilla**, **Bytecode Alliance**
(names in the cargo-vet registry). `cargo vet --locked` is the CI
gate. CI installs **cargo-vet 0.10.0** (`cargo-vet@0.10.0`); 0.10.2
escapes imported `notes` quotes differently and fails store-format
on this `imports.lock`.

**RustCrypto** is not in that registry (checked 2026-08-27) and no
published `audits.toml` URL was found. RustCrypto crates in this tree
stay on the exemption list until a peer publishes audits or we
locally certify them.

**`getrandom` 0.2.17 + 0.4.3.** The product uses 0.2 (`workspace.dependencies`).
0.4 is pulled only by `rasn-derive-impl` 0.28.14 → `uuid` 1.24 (proc-macro).
Both getrandom versions stay exempt with notes in `config.toml`.

**`rasn` is vendored** (`vendor/rasn`, taken by `[patch.crates-io]`): crates.io 0.28.14 with the
decoder patches `vendor/rasn/PATCHES.md` lists and diffs. `[policy.rasn] audit-as-crates-io = true`
audits it as the crates.io crate (its 0.28.14 exemption); vet cannot hash a path dependency, so the
delta is reviewed in that file.

**`curve25519-dalek` 5.0.0** (SPAKE edwards25519) has no importable
safe-to-deploy audit (Google's is `ub-risk-1`, for 4.0.0), so it, its
build-time `curve25519-dalek-derive` are exempt with notes. `fiat-crypto` 0.3.0
is built, as the P-384 constant-time field, and is exempt too. Its build dependencies `rustc_version`
0.4.1 and `semver` 1.0.28 are vetted by imported Mozilla and Bytecode
Alliance audits; `deny.toml` pins its feature set.

Local audits: `rasn-derive` 0.28.14 and `dns-lookup` 4.0.2 (`audits.toml`;
the notes name dns-lookup's canonical-name unwrap, which the caller contains).
**`socket2` 0.6.5**, dns-lookup's one new dependency, is trusted by its
publisher, Thomas de Zeeuw, as the Mozilla and Bytecode Alliance sets trust
him; `imports.lock` holds that publisher record. Remaining
third-party crates are honest exemptions; the list is smaller than a blank
`cargo vet init`.
