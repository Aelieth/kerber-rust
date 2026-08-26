# `harness/prod/` — C1 multi-host prod-realm substrate

A resource-capped, docker-network testbed for the C1 production gate: a Rust KDC
**primary**, a Rust KDC **replica**, and an **MIT client**, each in its own
container on a dedicated network. `scripts/prod-realm-gate.sh` is the
content-asserting CI gate over this substrate.

## What it proves

- **Named realm** `PROD.KERBER.TEST` via `krb5-kdb create` (not `--test-realm`).
- **Cross-container AS+TGS with the real MIT client** — `kinit user@PROD.KERBER.TEST`
  + `kvno host/testhost.prod.kerber.test` from the client container against the
  Rust KDC in a *different* container, addressed by docker-network IP.
- **kadmind** ACL `admin@PROD.KERBER.TEST` (MIT `kadmin addprinc` + `ktadd`).
- **kprop** primary→replica on `:754` and primary-kill failover (`prod-realm-gate.sh`).
- **Real NIC packet capture** when `NET_RAW` works (`tcpdump -i eth0`); otherwise
  the gate logs `pcap-source=reconstructed` (still requires AS/TGS PDUs).
  CI sets `KERBER_REQUIRE_REAL_PCAP=1`.
- **C2** `stress-gate` / `chaos-gate` / `soak-gate` reuse this substrate
  (`NET_ADMIN` is added so `tc netem` can run).
- **Resource caps hold** — each node capped at 1 GiB / 2 CPU.

## Quick start

```sh
cargo build -p krb5-kdc -p krb5-admin
./harness/prod/env-up.sh        # network + 3 capped nodes + self-smoke
./harness/prod/env-status.sh    # IPs, listeners, live mem/cpu vs caps
./scripts/prod-realm-gate.sh    # kadmin + kprop + failover + logs/pcap
./scripts/stress-gate.sh        # wire load + p99 SLO
./scripts/chaos-gate.sh         # netem + memory + failover-under-load
./scripts/soak-gate.sh          # bounded soak + RSS
./harness/prod/env-down.sh      # tear down (add --all to also drop Samba nodes)
```

`env-up.sh` self-verifies the cross-container AS+TGS path and prints a real-pcap
summary; on success it leaves the realm running for manual work.

## Resource budget (host: 64 GB / many cores)

All caps live in `limits.env` and are environment-overridable.

| Node kind | mem cap | cpu cap | typical use |
|---|---|---|---|
| Rust KDC primary/replica, MIT client | `1g` | `2` | < 10 MiB, ~0 % idle |
| Samba AD DC (oracle) | `2g` | `2` | ~300–500 MiB running |

- **Hard ceiling:** `env-up.sh` refuses to launch past `KERBER_PROD_MAX_NODES`
  (default **8**) `kerber-rust-*` containers.
- **Whole matrix at once** (3 prod nodes + 2 Samba DCs) caps at **~7 GB / 10 CPU** —
  leaves > 50 GB and > 20 cores free. You can safely run several realms in parallel;
  raise `KERBER_PROD_MAX_NODES` if you deliberately want more.
- **Builds** are the only real spike (MIT-from-source, Samba provisioning, `cargo`).
  Don't run several heavy `docker build`s at once; the images here are already built.

## Topology

```
        docker network: kerber-rust-prod (bridge)
  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
  │ kdc1 (primary)  │   │ kdc2 (replica)  │   │ client          │
  │ krb5-kdc :88    │   │ krb5-kpropd:754 │   │ MIT kinit/kvno  │
  │ krb5-kadmind:749│◀──│ krb5-kdc :88    │   │ /kadmin         │
  │ kerber-rust-    │   │ (after kprop)   │   │ KRB5_CONFIG →    │
  │  prod-node img  │   │                 │   │  kdc1,kdc2 by IP │
  └─────────────────┘   └─────────────────┘   └─────────────────┘
```

Nodes run the `kerber-rust-prod-node` image (the MIT 1.22.2 reference image +
`tcpdump`/`tshark`/`iproute2`/`procps`); the Rust binaries are `docker cp`'d in at
bring-up. Cross-container name resolution is `/etc/hosts` injection by inspected IP
(no DNS), mirroring `scripts/samba-realtrust-gate.sh`.

## Isolation (standing security constraint)

Fully in-container on the `kerber-rust-prod` bridge. Never touches the host
`/etc/krb5.conf` (stays `TESTLABBY.LOCAL`) or host SSSD. Passwords in `limits.env`
are throwaway test values, identical in kind to those already used across
`scripts/*-gate.sh`.
