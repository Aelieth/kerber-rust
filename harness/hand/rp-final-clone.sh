#!/bin/bash
# Argument: the tag commit. Record: $HAND_REC/<sha>/clone.
# README step 1, block 1 of "## Download, install and use", from that commit,
# with no --drop and no stand-in. The clone is the README's own git clone.
set -u
set +x
umask 077
export GIT_OPTIONAL_LOCKS=0
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC HAND_RELEASE_TAG HAND_RELEASE_TREE
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")
trap 'rm -rf "$SEC"' EXIT
TMPDIR=$SEC
export TMPDIR

SHA=${1:?tag commit}
printf '%s\n' "$SHA" | grep -Eq '^[0-9a-f]{40}$' || { echo "CLONE_STOP sha"; exit 2; }

WT=$HAND_WT
BASE=$HAND_REC/$SHA
REC=$BASE/clone
LAB=$WT/harness/field/lab.sh
DOC=$WT/harness/field/lib/docblocks.py
SCAN=$WT/harness/field/lib/scan-secrets.py
HAND=$LAB_HOME/state/lab.lock
H_USE='## Download, install and use'
TREE_BAR=$HAND_RELEASE_TREE

clone_pass=yes
reset_done=no
clone_stop() { echo "CLONE_STOP $*"; clone_pass=no; }

down_vm() {
    if [ "$reset_done" != yes ]; then
        return 0
    fi
    reset_done=down
    "$LAB" down kdc > "$REC/down.out" 2>&1
    echo "DOWN_RC:$?"
}
trap 'down_vm; rm -rf "$SEC"' EXIT

[ -e "$REC" ] && { echo "CLONE_STOP exists $REC"; exit 2; }
git -C "$WT" cat-file -e "$SHA^{commit}" || { echo "CLONE_STOP no-object"; exit 2; }
require_bins "$LAB"
require_files "$DOC" "$SCAN"
exec 8>>"$HAND"
if ! flock -n 8; then
    echo "CLONE_STOP hand-flock"
    exit 2
fi
flock -u 8
exec 8>&-

mkdir -p "$REC"
echo $$ > "$BASE/driver.pid"
git -C "$WT" show "$SHA:README.md" > "$REC/README.md" || { echo "CLONE_STOP readme"; exit 2; }
echo "HEAD_ARG:$SHA"
echo "README_FROM:$SHA"

echo "==== reset ===="
echo "RESET:kdc:f44-base"
"$LAB" reset kdc f44-base > "$REC/reset-kdc.out" 2>&1
rc=$?
echo "RESET_RC:kdc:$rc"
reset_done=yes
if [ "$rc" != 0 ]; then
    clone_stop "reset"
    echo "CLONE_PASS:$clone_pass"
    echo "CLONE_DONE"
    exit 2
fi

echo "==== readme block 1, no drop ===="
python3 -B "$DOC" script "$REC/README.md" "$H_USE" 1 --session "cd \"\$HOME\"" > "$REC/use1.sh"
rc=$?
echo "EXTRACT:use1.sh:$rc"
if [ "$rc" != 0 ]; then
    clone_stop "extract"
else
    if grep -q -- '--drop' "$REC/use1.sh"; then
        echo "UNIT_FAIL:use1:drop-present"
        clone_pass=no
    fi
    if ! "$LAB" ssh kdc -- 'install -d -m 0700 ~/field && cat > ~/field/block.sh' < "$REC/use1.sh" > "$REC/use1.copy" 2>&1; then
        clone_stop "copy"
        echo "BLOCK_RC:use1:not-run"
    else
    "$LAB" ssh kdc -- 'bash ~/field/block.sh' > "$REC/use1.out" 2>&1
    rc=$?
    echo "BLOCK_RC:use1:$rc"
    if [ ! -s "$REC/use1.out" ]; then
        echo "UNIT_FAIL:use1:no-output"
        clone_pass=no
    elif ! python3 -B "$DOC" results "$REC/use1.out" > "$REC/use1.results"; then
        echo "UNIT_FAIL:use1:results"
        clone_pass=no
    else
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            echo "UNIT_RESULT:use1:$line"
            n=${line%%$'\t'*}
            rest=${line#*$'\t'}
            urc=${rest%%$'\t'*}
            rest=${rest#*$'\t'}
            rest=${rest#*$'\t'}
            if [ "$urc" != 0 ]; then
                echo "UNIT_FAIL:use1:$n:$rest"
                clone_pass=no
            fi
        done < "$REC/use1.results"
    fi
    fi
fi

echo "==== guest git and binaries ===="
"$LAB" ssh kdc -- 'bash -s' > "$REC/guest-meta.out" 2>&1 << 'EOF'
set +e
if [ -d "$HOME/kerber-rust/.git" ]; then
    echo "CLONE_HEAD:$(git -C "$HOME/kerber-rust" rev-parse HEAD)"
    echo "CLONE_TREE:$(git -C "$HOME/kerber-rust" rev-parse 'HEAD^{tree}')"
    desc=$(git -C "$HOME/kerber-rust" describe --tags --exact-match 2>&1)
    drc=$?
    printf 'CLONE_DESCRIBE:%s\n' "$desc"
    echo "CLONE_DESCRIBE_RC:$drc"
else
    echo "CLONE_HEAD:missing"
    echo "CLONE_TREE:missing"
    echo "CLONE_DESCRIBE:missing"
    echo "CLONE_DESCRIBE_RC:missing"
fi
for name in krb5-kdc krb5-kadmind; do
    f="$HOME/kerber-rust/target/release/$name"
    if [ -f "$f" ]; then
        echo "BIN_SHA:$name:$(sha256sum "$f" | awk '{print $1}')"
    else
        echo "BIN_SHA:$name:missing"
    fi
done
EOF
echo "GUEST_META_RC:$?"
cat "$REC/guest-meta.out"

got_head=$(sed -n 's/^CLONE_HEAD://p' "$REC/guest-meta.out" | head -n 1)
got_tree=$(sed -n 's/^CLONE_TREE://p' "$REC/guest-meta.out" | head -n 1)
got_desc=$(sed -n 's/^CLONE_DESCRIBE://p' "$REC/guest-meta.out" | head -n 1)
if [ "$got_head" != "$SHA" ]; then
    echo "CLONE_HEAD_MATCH:no"
    clone_pass=no
else
    echo "CLONE_HEAD_MATCH:yes"
fi
if [ "$got_tree" != "$TREE_BAR" ]; then
    echo "CLONE_TREE_MATCH:no"
    clone_pass=no
else
    echo "CLONE_TREE_MATCH:yes"
fi
if [ "$got_desc" != "$HAND_RELEASE_TAG" ]; then
    echo "CLONE_DESCRIBE_MATCH:no"
    clone_pass=no
else
    echo "CLONE_DESCRIBE_MATCH:yes"
fi

python3 -B "$SCAN" "$REC" > "$REC/secret-scan.out" 2>&1
scan_rc=$?
echo "SECRET_SCAN:$scan_rc"
[ "$scan_rc" = 0 ] || clone_pass=no

echo "CLONE_PASS:$clone_pass"
echo "CLONE_DONE"
exit 0
