#!/bin/bash
# Step 1, the opposite test. One argument: the commit to build (make build in HAND_WT).
# KDCDIR and KERBER_KDC_DIR stay unset.
# The 13 are compared to HAND_STEP1_BASE's step1/ship.sha256. STEP1_EQUAL:yes prints
# only when all 13 are byte-equal. A differing name prints, and the script stops after the extras.
# Before make build, target-rp is moved to target-rp-<base sha12>.
# If that name exists, stop. Nothing is deleted. The fresh build uses the
# same path. COMPILING must be greater than 0.
# The three extra builds are recorded either way, as information, against the base's extra.sha256. They
# do not change STEP1_EQUAL. A missing extra binary stops so the record is not silent.
# target-accept and target-pac stay incremental. The embed build writes into
# the fresh target-rp after the 13 are hashed.
# Record: $HAND_REC/<sha>/step1. This does not start the lab.
set -u
SHA=${1:?phasec sha}
printf '%s\n' "$SHA" | grep -Eq '^[0-9a-f]{40}$' || { echo "STEP1_STOP sha"; exit 2; }
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC HAND_REPO HAND_STEP1_BASE
REPO=$HAND_REPO
WT=$HAND_WT
REC=$HAND_REC/$SHA/step1
BASE=$HAND_REC/$HAND_STEP1_BASE/step1/ship.sha256
BASE_EXTRA=$HAND_REC/$HAND_STEP1_BASE/step1/extra.sha256
names='krb5-kdc krb5-kadmind krb5-kadmin-local krb5-kdb krb5-kprop krb5-kpropd krb5-kinit krb5-klist krb5-kdestroy krb5-kswitch krb5-kvno krb5-kpasswd krb5-ktutil'
# The base must be another sha's full record of the 13, or nothing is compared.
printf '%s\n' "$HAND_STEP1_BASE" | grep -Eq '^[0-9a-f]{40}$' || { echo "STEP1_STOP base sha"; exit 2; }
[ "$HAND_STEP1_BASE" != "$SHA" ] || { echo "STEP1_STOP base is the build"; exit 2; }
[ -f "$BASE" ] || { echo "STEP1_STOP no baseline"; exit 2; }
[ "$(awk '{ print $2 }' "$BASE" | sort | paste -sd' ' -)" = "$(tr ' ' '\n' <<< "$names" | sort | paste -sd' ' -)" ] \
    || { echo "STEP1_STOP baseline names"; exit 2; }
mkdir -p "$REC"
if [ ! -e "$WT/.git" ]; then
    git -C "$REPO" worktree add --detach "$WT" "$SHA"
else
    git -C "$WT" checkout --detach "$SHA"
fi
echo "HEAD:$(git -C "$WT" rev-parse HEAD)"
echo "TREE:$(git -C "$WT" rev-parse 'HEAD^{tree}')"
got=$(git -C "$WT" rev-parse HEAD)
[ "$got" = "$SHA" ] || { echo "STEP1_STOP head $got"; exit 2; }
cd "$WT" || exit 2
unset KDCDIR
unset KERBER_KDC_DIR
aside="$WT/target-rp-${HAND_STEP1_BASE:0:12}"
if [ -e "$aside" ]; then
    echo "STEP1_STOP aside exists"
    exit 2
fi
if [ -e "$WT/target-rp" ]; then
    mv "$WT/target-rp" "$aside" || { echo "STEP1_STOP mv"; exit 2; }
    echo "TARGET_ASIDE:$aside"
else
    echo "TARGET_ASIDE:none"
fi
set -o pipefail
CARGO_TERM_COLOR=never make -C "$WT" build CARGO_TARGET_DIR="$WT/target-rp" 2>&1 | tee "$REC/build.log"
rc=${PIPESTATUS[0]}
set +o pipefail
echo "BUILD_RC:$rc"
if [ "$rc" -ne 0 ]; then
    echo "STEP1_STOP build"
    exit 2
fi
compiling=$(grep -cE '^[[:space:]]*Compiling ' "$REC/build.log" || true)
echo "COMPILING:$compiling"
if [ "${compiling:-0}" -lt 1 ]; then
    echo "STEP1_STOP compiling"
    exit 2
fi
rel=${HAND_SHIP:-$WT/target-rp/release}
: > "$REC/ship.sha256"
for name in $names; do
    if [ ! -x "$rel/$name" ]; then
        echo "MISSING $name"
        echo "STEP1_STOP missing"
        exit 2
    fi
    newhash=$(sha256sum "$rel/$name" | awk 'NR==1 {print $1}')
    printf '%s  %s\n' "$newhash" "$name" | tee -a "$REC/ship.sha256"
done
equal=yes
while read -r oldhash name; do
    [ -n "${name:-}" ] || continue
    newhash=$(awk -v n="$name" '$2==n {print $1}' "$REC/ship.sha256")
    if [ -z "$newhash" ]; then
        echo "MISSING $name"
        equal=no
    elif [ "$newhash" = "$oldhash" ]; then
        echo "EQUAL $name"
    else
        echo "DIFFER $name"
        equal=no
    fi
done < "$BASE"
if CARGO_TERM_COLOR=never cargo build --release --locked --manifest-path "$WT/Cargo.toml" -p krb5-embed-realm-example --bin krb5-embed-realm --target-dir "$WT/target-rp"; then
    echo "EMBED_BUILD_RC:0"
else
    echo "EMBED_BUILD_RC:$?"
    echo "EXTRA_STOP embed"
    exit 2
fi
if CARGO_TERM_COLOR=never cargo build --release --locked --manifest-path "$WT/Cargo.toml" -p krb5-gss --bin krb5-gss-accept --features krb5-gss/test-hooks --target-dir "$WT/target-accept"; then
    echo "ACCEPT_BUILD_RC:0"
else
    echo "ACCEPT_BUILD_RC:$?"
    echo "EXTRA_STOP gss-accept"
    exit 2
fi
if CARGO_TERM_COLOR=never cargo build --release --locked --manifest-path "$WT/Cargo.toml" -p krb5-tools --bin krb5-pac-extract --features krb5-kdc/test-hooks,krb5-admin/test-hooks,krb5-client/test-hooks --target-dir "$WT/target-pac"; then
    echo "PAC_BUILD_RC:0"
else
    echo "PAC_BUILD_RC:$?"
    echo "EXTRA_STOP pac-extract"
    exit 2
fi
extra() {
    local name="$1" bin="$2" expect got
    expect=$(awk -v n="$name" '$1 == "EXTRA" && $2 == n { e = $3 } END { print e }' "$BASE_EXTRA" 2>/dev/null)
    if [ ! -x "$bin" ]; then
        echo "EXTRA_MISSING $name"
        echo "EXTRA_STOP $name"
        exit 2
    fi
    got=$(sha256sum "$bin" | awk 'NR==1 {print $1}')
    printf 'EXTRA %s %s\n' "$name" "$got" | tee -a "$REC/extra.sha256"
    if [ "$got" = "$expect" ]; then
        echo "EXTRA_EQUAL $name"
    else
        echo "EXTRA_DIFFER $name"
    fi
}
: > "$REC/extra.sha256"
extra krb5-embed-realm "$rel/krb5-embed-realm"
extra krb5-gss-accept "$WT/target-accept/release/krb5-gss-accept"
extra krb5-pac-extract "$WT/target-pac/release/krb5-pac-extract"
echo "STEP1_EQUAL:$equal"
[ "$equal" = yes ] || exit 2
echo "STEP1_END"
