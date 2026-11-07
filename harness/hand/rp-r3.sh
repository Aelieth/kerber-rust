#!/bin/bash
# rp-r3.sh: R3 (sshd GSSAPI, client1 -> client2), the scripts in r3/.
# Default is a read: copy the scripts, check the helpers, do not touch the lab. R3_LAUNCH=1 runs the hold.
# The services restore is the live snapshot (services-rust-f44) in r3/hc.sh.
set -u
# Needs HAND_WT (the checkout), HAND_REC (record dir), FIELD_LAB_NET and FIELD_KIT_DIR (field.env: the lab net, the lab copy of the reference client kit).
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC FIELD_LAB_NET FIELD_KIT_DIR
export FIELD_LAB_NET FIELD_KIT_DIR
# host python bytecode stays under HAND_REC. Guest /tmp paths are unchanged.
export PYTHONPYCACHEPREFIX=$HAND_REC/pycache
mkdir -p "$PYTHONPYCACHEPREFIX"
WT=$HAND_WT
SRC_SCRIPTS=$HDIR/r3
PHASEC_SHA=${1:?phasec sha}
COPY=$HAND_REC/$PHASEC_SHA/r3-copy
IN=$SRC_SCRIPTS
SHIP=${HAND_SHIP:-$WT/target-rp/release}
TREE=$(git -C "$WT" rev-parse 'HEAD^{tree}')
COMMIT=$PHASEC_SHA
LAB=$WT/harness/field/lab.sh
REC=$HAND_REC/$PHASEC_SHA/r3
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
BASE=$HAND_REC/$PHASEC_SHA/r3-base
TMP=${TMPDIR_R3:-$BASE/r3-tmp}
LOCK=/var/tmp/kr-lab.lock
HANDLOCK=$LAB_HOME/state/lab.lock

case $(realpath -m "$TMP") in /tmp|/tmp/*) echo "rp-r3.sh: TMP is under /tmp" >&2; exit 2 ;; esac
mkdir -p "$COPY" "$TMP"
rm -rf "${COPY:?}/hc.sh" "${COPY:?}/vmctl.sh" "${COPY:?}/install-ours.sh" "${COPY:?}/parity.py" "${COPY:?}/cells" "${COPY:?}/lib"
cp -a "$SRC_SCRIPTS/hc.sh" "$SRC_SCRIPTS/vmctl.sh" "$SRC_SCRIPTS/install-ours.sh" "$SRC_SCRIPTS/parity.py" "$COPY/"
cp -a "$SRC_SCRIPTS/cells" "$SRC_SCRIPTS/lib" "$COPY/"

# Ship list hc.sh checks: hashes of this tree's release build.
PROGS=(krb5-kdc krb5-kadmind krb5-kadmin-local krb5-kdb krb5-kprop krb5-kpropd)
for p in "${PROGS[@]}"; do [ -x "$SHIP/$p" ] || { echo "R3_STOP ship $p"; exit 2; }; done
(
  cd "$SHIP" || exit 2
  sha256sum "${PROGS[@]}"
) > "$COPY/ship-sha256.txt" || { echo "rp-r3.sh: a ship program is missing from $SHIP" >&2; exit 2; }
printf 'tree %s commit %s built %s; default features, --release --locked\n' "$TREE" "$COMMIT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$COPY/ship-source.txt"

echo "COPY_HC $(sha256sum "$COPY/hc.sh" | awk '{print $1}')"

bash -n "$COPY/hc.sh" || exit 2
bash -n "$COPY/cells/r3.sh" || exit 2
bash -n "$COPY/lib/cellfns.sh" || exit 2
bash -n "$COPY/lib/undef-check.sh" || exit 2
python3 -m py_compile "$COPY/parity.py"

HCSRC=$WT TMPDIR=$TMP bash "$COPY/lib/undef-check.sh" "$COPY/cells/r3.sh" "$COPY/lib/cellfns.sh" || exit 2

if [ "${R3_LAUNCH:-0}" != 1 ]; then
  echo "R3_PREP_ONLY no lab step. Set R3_LAUNCH=1 to run."
  echo "SHIP $SHIP"
  echo "IN $IN"
  echo "REC $REC"
  echo "services restore: services-rust-f44 (live snapshot). kdc and client1 f4-mit. client2 rust-ssh."
  exit 0
fi

# Launch. hc.sh checks its inputs, takes the locks, downs services, then refuses any of the four still running.
exec 9>&-
cd "$WT" || exit 2
export REPO=$WT
export HCD=$BASE
export HC=$COPY
export CELLFNS=$COPY/lib/cellfns.sh
export SRC=$WT
export IN
export SHIP
export SHIPSHA=$COPY/ship-sha256.txt
export SHIPSRC=$COPY/ship-source.txt
export TREE COMMIT LAB LOCK HANDLOCK
OUT=$BASE/work-r3/out-$(date -u +%Y%m%dT%H%M%SZ)
export OUT
export REC
export TMPDIR=$TMP
export SESSION=rp-r3-$PHASEC_SHA
export MAX_LEG_S=${MAX_LEG_S:-1800}
mkdir -p "$OUT" "$TMP"
exec bash "$COPY/hc.sh"
