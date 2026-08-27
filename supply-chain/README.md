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
0.4 is pulled only by `rasn-derive-impl` 0.27.0 → `uuid` 1.24. `rasn` is
pinned at `=0.27.0` so MSRV 1.85 stays locked-green. Unifying the two
versions would require moving that pin. Both versions are exempt with
notes in `config.toml`.

Local audit: `rasn-derive` 0.27.0 (`audits.toml`). Remaining third-party
crates are honest exemptions; the list is smaller than a blank `cargo
vet init`.
