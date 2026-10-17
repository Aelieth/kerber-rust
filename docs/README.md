# Documentation

To install kerber-rust and run a realm with it, read
[install.md](install.md): the Fedora install under MIT's command names and
units, a new realm, and upgrading an MIT realm.

The design, test and parity record of kerber-rust, in reading order. Each
entry says what the file holds.

1. [architecture.md](architecture.md): the crates, how they layer, and the
   conventions they follow.
2. [stages.md](stages.md): the stage map, from the eras and the 1.1 roadmap to
   what is closed.
3. [testing.md](testing.md): the gate discipline, the tiers and CI lanes, the
   harness realms.
4. [gates.md](gates.md): one row per gate, with its oracle, job, lane and
   assertions.
5. [security.md](security.md): timing, replay and secret handling.
6. [mit-deviations.md](mit-deviations.md): the deliberate deviations from MIT,
   and the parity decisions that are not deviations.
7. [parity/README.md](parity/README.md): the MIT 1.22.2 parity ledger, one or
   more files per section: [A1](parity/a1-tgs.md), [A2](parity/a2-as.md),
   [A3](parity/a3-preauth.md), A4 ([kadmin](parity/a4-kadmin.md),
   [kdb](parity/a4-kdb.md)), [A5](parity/a5-prop.md), B1
   ([client](parity/b1-client.md), [gss](parity/b1-gss.md), [tools](parity/b1-tools.md)).
   [mit-parity-ledger.md](mit-parity-ledger.md) is a pointer to it.
8. [logging.md](logging.md): the structured log schema.
9. [interop-matrix.md](interop-matrix.md): the external implementations this
   port is checked against, and what is kept from them.
10. [plugins.md](plugins.md): the extension points (Rust traits, not
    `dlopen`).
11. [rfc-mapping.md](rfc-mapping.md): RFC sections mapped to code.
12. [gate-unit-index.md](gate-unit-index.md): which unit test backs which gate
    cell.
13. [labs/](labs/README.md): [ad-lab.md](labs/ad-lab.md) (the AD lab and its
    isolation protocol), [samba-lab.md](labs/samba-lab.md) (the live Samba AD
    DC oracle) and [kcm-nfs-verdict.md](labs/kcm-nfs-verdict.md) (why the
    fleet default stays FILE).
14. [embed/](embed/README.md): [klldap.md](embed/klldap.md), the KLLDAP
    alignment and the `KerberosSync` seam.
15. [export-control.md](export-control.md): the cryptography export note.
