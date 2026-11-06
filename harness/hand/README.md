# Hand legs

The release proof's hand legs: drivers the tester runs by hand on the lab VMs (they drive `harness/field/lab.sh`; never run in CI, only shellchecked).

Environment (each driver takes the 40-hex sha of the build under test as `$1`):
- `HAND_WT`: the kerber-rust checkout the leg runs against (`$HAND_WT/harness/field/lab.sh` is the lab, `$HAND_WT/target-rp/release` the ship; `HAND_SHIP` overrides it).
- `HAND_REC`: the record dir; each leg writes under `$HAND_REC/<sha>/`; `lib/ship-guard.sh` reads `$HAND_REC/<sha>/step1/ship.sha256`.
- `$KERBER_LAB_HOME/field.env` (default `~/kerber-lab`, mode 0600) is sourced by `lib/env.sh`; `require_env NAME...` stops on an empty name.
- `FIELD_LAB_NET` (field.env): the lab network, for the legs that start the embed example on klldap (`rp-az.sh` too).
- `krb5-embed-realm`, built from `examples/embed-realm` into the ship dir, for `rp-ss.sh`, `rp-al-a45.sh`, `rp-ba.sh`, `rp-az.sh`, `rp-tr.sh`, `rp-tr-cell2.sh` and `rp-sc.sh`.
- Passwords a leg generates go to a private `mktemp -d` under `TMPDIR`, never the record, and are removed on exit.

Drivers:
- `rp-plw-mit.sh`: power-loss, MIT replica: a kill control, then 20 virsh-destroy cycles with iprop.
- `rp-plw-rust.sh`: the same power-loss cell with our kdb/kpropd/kadmin.local streamed onto the replica.
- `rp-p18-diag.sh`: write speed, one cell (N=10, iprop on, 5 rounds, MIT first).
- `rp-p18-matrix.sh`: write speed, the untraced MIT-vs-ours grade (N=10/1000/5000, 3 reps).
- `rp-p18-go.sh`: installs the build under /opt on the klldap VM, then runs `p18-trace.sh`.
- `p18-trace.sh`: guest script; strace of kadmind's fsync/write path, MIT then ours.
- `rp-ss.sh`: embed realm cells 1, 2, 3, 6, 4, 7, MIT first, then the example.
- `rp-a2.sh`, `rp-a3-mit.sh`, `rp-trickle-mit.sh`: cell A2, cell A3 and the KDC trickler, MIT legs.
- `rp-al-a45.sh`: A4 (SS cells 1-4) and A5 (the embed trickle) on klldap.
- `rp-al-rerun.sh`: A2, A3 and the trickler on one build.
- `rp-wr-mit.sh`, `rp-wr-ours.sh`: WR, the MIT and our legs, each on a fresh snapshot.
- `rp-wr-chain.sh`: WR, MIT first; ours only after a clean MIT end.
- `rp-ba.sh`: BA on klldap, MIT first.
- `rp-az.sh`: AZ: kadmin ACL cells, MIT first, then the doc upgrade, then embed cells 2-4 on klldap.
- `rp-tr.sh`, `rp-tr-cell2.sh`: TR: trust cells (MIT kadmin.local, embed realm, kinit/kvno legs); cell 2 reads the profiles `rp-tr.sh` saved.
- `rp-sc.sh`: SC: MIT first on the kdc, then the upgrade, then ours (tl-data, S4U, RID cells).
- `rp-fz.sh`: FZ: a raw TGS-REQ with a non-ASCII service name, MIT first, then the upgrade.
- `rp-bg.sh`: BG: GSS sequence-number rig and the channel-binding cells in a private namespace, no VM.
- `rp-bd.sh`: BD: des3 SPAKE legs on the mitd3 VM, MIT KDC first, then ours.
- `lib/`: `env.sh`, `ship-guard.sh` (re-hashes the 13 ship binaries).
- `lib/`: also the guest and client helpers the legs copy onto the VMs (`*.py`, `*.c`) and the `bg-ns.sh`/`bg-seq.sh` namespace scripts.
