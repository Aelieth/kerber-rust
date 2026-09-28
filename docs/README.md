# Documentation

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
5. [security.md](security.md): timing, replay and secret handling, and the
   deliberate deviations from MIT.
6. [parity/README.md](parity/README.md): the MIT 1.22.2 parity ledger, one file
   per section: [A1](parity/a1-tgs.md), [A2](parity/a2-as.md),
   [A3](parity/a3-preauth.md), [A4](parity/a4-kadmin.md),
   [A5](parity/a5-prop.md), [B1](parity/b1-client.md).
   [mit-parity-ledger.md](mit-parity-ledger.md) is a pointer to it.
7. [logging.md](logging.md): the structured log schema.
8. [interop-matrix.md](interop-matrix.md): the external implementations this
   port is checked against, and what is kept from them.
9. [plugins.md](plugins.md): the extension points (Rust traits, not
   `dlopen`).
10. [rfc-mapping.md](rfc-mapping.md): RFC sections mapped to code.
11. [gate-unit-index.md](gate-unit-index.md): which unit test backs which gate
    cell.
12. [labs/](labs/README.md): [ad-lab.md](labs/ad-lab.md) (the AD lab and its
    isolation protocol), [samba-lab.md](labs/samba-lab.md) (the live Samba AD
    DC oracle) and [kcm-nfs-verdict.md](labs/kcm-nfs-verdict.md) (why the
    fleet default stays FILE).
13. [embed/](embed/README.md): [klldap.md](embed/klldap.md), the KLLDAP
    alignment and the `KerberosSync` seam.
14. [export-control.md](export-control.md): the cryptography export note.
