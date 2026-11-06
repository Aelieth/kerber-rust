#!/bin/bash
# rp-b2.sh: B2, the combined driver and the full B2 hold. Prep copies b2/ (the driver trees, fixes included) and lib/ into the record.
# The lab runs only when B2_LAUNCH=1. A plain run stops after prep.
# Needs HAND_WT (the checkout), HAND_REC (record dir), HAND_BASELINE_DIR (the last graded B2 record: b2/results.tsv, combined/results.tsv),
# HAND_FIXTURE_DIR (D3.TEST's dumps, stashes, keytabs and passwords, 0700, equal to b2/shared/d3-fixtures.sha256), FIELD_LAB_NET (field.env).
# Order, as FULL-r2 ran it: the combined driver, then the full B2 hold (every module, ks and d3 included).
set -euo pipefail
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC HAND_BASELINE_DIR HAND_FIXTURE_DIR FIELD_LAB_NET
export FIELD_LAB_NET HAND_FIXTURE_DIR
[ "$(stat -c %a "$HAND_FIXTURE_DIR")" = 700 ] || { echo "rp-b2.sh: $HAND_FIXTURE_DIR must be mode 0700" >&2; exit 2; }
(cd "$HAND_FIXTURE_DIR" && sha256sum -c --quiet "$HDIR/b2/shared/d3-fixtures.sha256") \
    || { echo "rp-b2.sh: $HAND_FIXTURE_DIR does not match b2/shared/d3-fixtures.sha256" >&2; exit 2; }
# host python bytecode stays under HAND_REC. Guest /tmp paths are unchanged.
export PYTHONPYCACHEPREFIX=$HAND_REC/pycache
mkdir -p "$PYTHONPYCACHEPREFIX"
exec 9>&-
exec < /dev/null

WT=$HAND_WT
BASE_B2=$HAND_BASELINE_DIR/b2/results.tsv
BASE_CB=$HAND_BASELINE_DIR/combined/results.tsv
PHASEC_SHA=${1:?phasec sha}
COMMIT=$PHASEC_SHA
TREE=$(git -C "$WT" rev-parse 'HEAD^{tree}')
SCRATCH=$HAND_REC/$PHASEC_SHA/b2-scratch
COPY=$SCRATCH/b2-copy
REC_ROOT=$HAND_REC/$PHASEC_SHA/b2
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC_ROOT" || exit $?
SHIP=${HAND_SHIP:-$WT/target-rp/release}

# The nine FULL-r2 FAIL rows (status column), by id.
# B10 x1, B11 x4, B24 x4.
REDS=(
    KP.ours.transport.no-udp-error
    KS.ours.E1-mit.log-failed
    KS.ours.E1-ours.log-failed
    KS.parity.E1-xkdc-mit.kdc-slice
    KS.parity.E1-xkdc-ours.kdc-slice
    KS.mit.T3c-ours.stderr-line
    KS.ours.T3c-ours.stderr-line
    KS.parity.T3c-prog-mit
    KS.parity.T3c-prog-ours
)

case $SCRATCH in "$HAND_REC"/*) ;; *) echo "rp-b2.sh: scratch is not under HAND_REC" >&2; exit 2 ;; esac
[ -d "$WT" ] && [ -f "$BASE_B2" ] && [ -f "$BASE_CB" ] || { echo "rp-b2.sh: tree or baseline missing" >&2; exit 2; }
got=$(git -C "$WT" rev-parse HEAD)
[ "$got" = "$COMMIT" ] || { echo "rp-b2.sh: $WT is $got, not $COMMIT" >&2; exit 2; }
got=$(git -C "$WT" rev-parse 'HEAD^{tree}')
[ "$got" = "$TREE" ] || { echo "rp-b2.sh: tree id $got, not $TREE" >&2; exit 2; }

prep() {
    rm -rf "$COPY"
    mkdir -p "$COPY"
    cp -a "$HDIR/b2/shared" "$COPY/b2"
    cp -a "$HDIR/b2/combined" "$COPY/combined"
    cp -a "$HDIR/b2/fix-p8" "$COPY/fix-p8"
    cp -a "$HDIR/lib/compare-legs.py" "$HDIR/lib/expected-diff.txt" "$COPY/"
    bash -n "$COPY/b2/mod/d3.sh"
    bash -n "$COPY/b2/driver-b2.sh"
    bash -n "$COPY/b2/helpers/kp-vm.sh"
    bash -n "$COPY/b2/mod/kp.sh"
    bash -n "$COPY/combined/driver.sh"
    bash -n "$COPY/combined/ra/stage.sh"
    python3 -m py_compile "$COPY/combined/ra/cmp.py" "$COPY/compare-legs.py"
    cp -a "$0" "$SCRATCH/rp-b2.sh"
    bash -n "$SCRATCH/rp-b2.sh"
    echo "B2_PREP copy $COPY"
    echo "COPY_B2 $(sha256sum "$COPY/b2/driver-b2.sh" | awk '{print $1}')"
    echo "COPY_COMBINED $(sha256sum "$COPY/combined/driver.sh" | awk '{print $1}')"
    echo "COPY_VMCTL $(sha256sum "$COPY/combined/otp/vmctl.sh" | awk '{print $1}')"
    echo "FIELD_CHECK $(sha256sum "$COPY/fix-p8/field-check.sh" | awk '{print $1}')"
    echo "COMPARE $(sha256sum "$COPY/compare-legs.py" | awk '{print $1}')"
}

grade() {
    local new=$1 base=$2 tag=$3
    if [ ! -f "$new" ]; then
        echo "grade: no $new; nothing to compare" >&2
        return 0
    fi
    local -a specs=()
    local p
    while IFS= read -r p; do
        specs+=("${p}=${base}")
    done < <(python3 - "$base" << 'PY'
import sys
seen = []
with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    for line in f:
        lab = line.split("\t", 1)[0]
        if not lab:
            continue
        pre = lab.split(".", 1)[0] + "."
        if pre not in seen:
            seen.append(pre)
for pre in seen:
    print(pre)
PY
)
    python3 -I "$COPY/compare-legs.py" "$new" "${specs[@]}" > "$REC_ROOT/$tag/compare-legs.txt" || true
    python3 - "$new" "$REC_ROOT/$tag/compare-legs.txt" "$tag" "${REDS[@]}" << 'PY'
import sys
new, report, tag = sys.argv[1], sys.argv[2], sys.argv[3]
reds = sys.argv[4:]
rows = {}
with open(new, encoding="utf-8", errors="replace") as f:
    for line in f:
        p = line.rstrip("\n").split("\t")
        if len(p) >= 2:
            rows[p[0]] = p[1]
print("RED_ROWS %s" % tag)
for lab in reds:
    print("  %s %s" % (lab, rows.get(lab, "ABSENT")))
text = open(report, encoding="utf-8", errors="replace").read()
n = text.count("\n   REGRESSION ")
print("REGRESSION_LINES %s %d" % (tag, n))
PY
}

if [ "${B2_LAUNCH:-}" != 1 ]; then
    prep
    echo "B2_LAUNCH is not 1. Prep only. The lab was not started."
    exit 0
fi

# Launch path. Build first, then lab down, then the drivers.
# The combined driver copies rd-sweep out of SHIP and exits if it is missing. make build does not produce it.
prep
if [ "${B2_HOLD_ONLY:-}" = 1 ]; then
    echo "B2_HOLD_ONLY 1: combined stays accepted. Build, lab down, then the full B2 hold only."
else
    echo "B2_LAUNCH 1: build the ship, then lab down kdc client1 client2, then combined, then the full B2 hold."
fi
LAB=$WT/harness/field/lab.sh
cd "$WT"
mkdir -p "$WT/target-b2" "$REC_ROOT/combined" "$REC_ROOT/hold" \
    "$SCRATCH/tmp-combined" "$SCRATCH/tmp-b2" \
    "$SCRATCH/work-combined" "$SCRATCH/work-b2" \
    "$SCRATCH/secrets-combined" "$SCRATCH/secrets-b2"
make -C "$WT" build CARGO_TARGET_DIR="$WT/target-b2"
# otp-kdc and rd-sweep are not part of make build. Build them in a side directory and copy
# only those two binaries into the ship. rd-sweep needs krb5-admin/test-hooks; building that
# in target-b2 would relink the release kadmind with the harness feature.
mkdir -p "$WT/target-b2-extra"
cargo build --release --locked --manifest-path "$WT/Cargo.toml" \
    --target-dir "$WT/target-b2-extra" -p krb5-embed-realm-example --bin krb5-otp-kdc
cargo build --release --locked --manifest-path "$WT/Cargo.toml" \
    --target-dir "$WT/target-b2-extra" -p krb5-tools --bin rd-sweep \
    --features krb5-admin/test-hooks
cp -p "$WT/target-b2-extra/release/krb5-otp-kdc" "$WT/target-b2-extra/release/rd-sweep" "$SHIP/"
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC_ROOT" || exit $?
for p in krb5-kdc krb5-kadmind krb5-kadmin-local krb5-kdb krb5-kprop krb5-kpropd krb5-otp-kdc \
         krb5-kinit krb5-klist krb5-kvno krb5-kdestroy krb5-kpasswd rd-sweep; do
    [ -x "$SHIP/$p" ] || { echo "rp-b2.sh: missing $SHIP/$p" >&2; exit 2; }
done
echo "B2_SHIP_READY"
# services, klldap, and mitd3 are not touched here. mitd3 is already shut off.
# win stays shut off (8 GiB). Do not start it: mitd3 adds 4 GiB during d3.
for v in kdc client1 client2; do
    timeout 180 "$LAB" down "$v"
done
echo "B2_DOWN kdc client1 client2"

export P8E_CHECK=$COPY/fix-p8/field-check.sh
# Alice stays the driver's baseline.env MIT_SECRET_ALICE. Do not set the rust-realm file.
common=(
    TREE="$TREE" SHIP="$SHIP" DIST="$WT" REPO="$WT" LAB="$LAB"
    LOCK=/var/tmp/kr-lab.lock
    HANDLOCK="$LAB_HOME/state/lab.lock"
)
# Combined first (FULL-r2 leg 3B), then B2 (leg 3B2). B2_HOLD_ONLY=1 skips combined.
if [ "${B2_HOLD_ONLY:-}" = 1 ]; then
    echo "B2_HOLD_ONLY: combined not started"
    cb_rc=0
else
set +e
# The earlier pass stays at $REC_ROOT/combined. This run publishes beside it.
# P16a's leg script ships in lib/ (the checkout under test may predate it).
# D3: the combined P8 check is the same fixed script as P8E_CHECK, not the unpatched original.
env "${common[@]}" \
    DRIVER_TMPDIR="$SCRATCH/tmp-combined" \
    W="$SCRATCH/work-combined" \
    SECD="$SCRATCH/secrets-combined" \
    REC="$REC_ROOT/combined-r2" \
    MAX_LEG_S="${MAX_LEG_S_COMBINED:-5400}" \
    P16A_LEG="$HDIR/lib/p16a-leg.sh" \
    P8_CHECK="$COPY/fix-p8/field-check.sh" \
    bash "$COPY/combined/driver.sh"
cb_rc=$?
set -e
echo "COMBINED_RC $cb_rc"
# the 8 pending client1 trace rows do not stop the hold. Any other FAIL does.
set +e
python3 - "$REC_ROOT/combined-r2/results.tsv" "$COPY/expected-diff.txt" << 'PY'
import sys
tsv, exp = sys.argv[1], sys.argv[2]
pending = set()
try:
    for line in open(exp, encoding="utf-8", errors="replace"):
        if "\tPENDING\t" in line:
            pending.add(line.split("\t", 1)[0])
except OSError as e:
    sys.exit("no expected-diff: %s" % e)
fails, other = [], []
try:
    fh = open(tsv, encoding="utf-8", errors="replace")
except OSError as e:
    sys.exit("no results.tsv: %s" % e)
with fh:
    for line in fh:
        p = line.rstrip("\n").split("\t")
        if len(p) >= 2 and p[1] == "FAIL":
            fails.append(p[0])
            if p[0] not in pending:
                other.append(p[0])
print("COMBINED_FAILS %d pending %d other %d" % (len(fails), len(fails) - len(other), len(other)))
for lab in other:
    print("COMBINED_OTHER_FAIL", lab)
if other:
    sys.exit(1)
if not fails:
    sys.exit(2)
sys.exit(0)
PY
pend_rc=$?
set -e
if [ "$pend_rc" = 1 ] || { [ "$cb_rc" != 0 ] && [ "$pend_rc" != 0 ]; }; then
    echo "rp-b2.sh: combined driver rc=$cb_rc; B2 not started" >&2
    exit "$cb_rc"
fi
if [ "$cb_rc" != 0 ]; then
    echo "rp-b2.sh: combined rc=$cb_rc; only pending PARITY.trace client1 rows; B2 hold continues"
fi
grade "$REC_ROOT/combined-r2/results.tsv" "$BASE_CB" combined-r2
fi

set +e
env "${common[@]}" \
    DRIVER_TMPDIR="$SCRATCH/tmp-b2" \
    W="$SCRATCH/work-b2" \
    SECD="$SCRATCH/secrets-b2" \
    REC="$REC_ROOT/hold" \
    MAX_LEG_S="${MAX_LEG_S_B2:-7200}" \
    bash "$COPY/b2/driver-b2.sh"
b2_rc=$?
set -e
echo "B2_RC $b2_rc"
grade "$REC_ROOT/hold/results.tsv" "$BASE_B2" hold
echo "B2_DONE combined_rc=$cb_rc b2_rc=$b2_rc"
exit "$b2_rc"
