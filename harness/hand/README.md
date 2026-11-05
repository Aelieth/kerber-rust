# Hand legs

The release proof's hand legs: drivers the tester runs by hand on the lab VMs (they drive `harness/field/lab.sh`; never run in CI, only shellchecked).

Environment (each driver takes the 40-hex sha of the build under test as `$1`):
- `HAND_WT`: the kerber-rust checkout the leg runs against (`$HAND_WT/harness/field/lab.sh` is the lab, `$HAND_WT/target-rp/release` the ship; `HAND_SHIP` overrides it).
- `HAND_REC`: the record dir; each leg writes under `$HAND_REC/<sha>/`; `lib/ship-guard.sh` reads `$HAND_REC/<sha>/step1/ship.sha256`.
- `$KERBER_LAB_HOME/field.env` (default `~/kerber-lab`, mode 0600) is sourced by `lib/env.sh`; `require_env NAME...` stops on an empty name.

Drivers:
- `rp-plw-mit.sh`: power-loss, MIT replica: a kill control, then 20 virsh-destroy cycles with iprop.
- `rp-plw-rust.sh`: the same power-loss cell with our kdb/kpropd/kadmin.local streamed onto the replica.
- `rp-p18-diag.sh`: write speed, one cell (N=10, iprop on, 5 rounds, MIT first).
- `rp-p18-matrix.sh`: write speed, the untraced MIT-vs-ours grade (N=10/1000/5000, 3 reps).
- `rp-p18-go.sh`: installs the build under /opt on the klldap VM, then runs `p18-trace.sh`.
- `p18-trace.sh`: guest script; strace of kadmind's fsync/write path, MIT then ours.
- `lib/`: `env.sh`, `ship-guard.sh` (re-hashes the 13 ship binaries).
