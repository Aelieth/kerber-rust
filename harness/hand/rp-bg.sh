#!/bin/bash
# 3k BG driver. The BG-1 rig, then the BG-2 cells, one record.
# Rig: lib/bg-seq.sh as-is (mit-default 10, mit-nomutual 10, ours 10).
# Cells: bg-ns.sh, aes128-only test-realm KDC. Private namespace. No lab VM,
# no snapshot, no lab lock. target-bg only; target-rp is not used.
#
# 806c20f1 has no krb5-vfy-increds bin, so the verify-init-creds rows are
# omitted and BG_VFY prints skipped.
#
# Pass:
#   BG_ETYPE: keytab is aes128; both legs init rc 0, seq present and non-zero,
#   subkey keytype 18, authorization_data absent.
#   BG_CBT_OFF: both legs authorization_data absent.
#   BG_CBT_REL: client_aware_channel_bindings = true, both legs flags 0x4000.
#   BG_CBT_FLAG: channel-bound flag, both legs flags 0x4000.
#   BG_MAYBE: client_aware_channel_bindings = maybe, both init rc 1,
#   text "Invalid boolean value".
#   BG_SEQ: every recorded seq is non-zero and the set is distinct.
set -u
umask 077
exec 9>&-
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
PHASEC_SHA=${1:?phasec sha}
SHA=$PHASEC_SHA
HERE=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-bg.XXXXXX")
trap 'rm -rf "$HERE"' EXIT
export REC
REC=$HAND_REC/$PHASEC_SHA/hand-bg
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
LOG=$REC/driver.log
mkdir -p "$REC"
exec > >(tee -a "$LOG") 2>&1
NS=$HDIR/lib/bg-ns.sh
SEQ=$HDIR/lib/bg-seq.sh
INIT_C=$HDIR/lib/gss-seq-init.c
ACC_C=$HDIR/lib/gss-seq-acceptor.c
SUMMARY=$HDIR/lib/gss-seq-summary.py
stop() { echo "BG_STOP $*"; exit 2; }
scan_secrets() {
    python3 - "$NS" "$SEQ" << 'PY'
import os
import sys
from pathlib import Path
import re
needles = []
for src in sys.argv[1:]:
    ns = Path(src).read_text(errors="replace")
    for name in ("KRB5_TEST_USER_PASSWORD", "KRB5_TEST_ADMIN_PASSWORD"):
        m = re.search(rf"{name}=(\S+)", ns)
        if m and m.group(1) not in needles:
            needles.append(m.group(1))
blob = ""
rec = Path(os.environ["REC"])
for p in (rec / "cells.txt", rec / "rig.txt", rec / "driver.log"):
    if p.exists():
        blob += p.read_text(errors="replace")
hit = 0
for n in needles:
    if n and n in blob:
        hit += 1
print(f"SECRET_SCAN_HITS:{hit}")
PY
}
trap 'scan_secrets; rm -rf "$HERE"' EXIT
mkdir -p "$REC" "$HERE/bin"
echo "REC:hand-bg-$(date -u +%Y%m%dT%H%M%SZ)"
echo "TREE:$(git -C "$WT" rev-parse HEAD)"
echo "TREE_ID:$(git -C "$WT" rev-parse 'HEAD^{tree}')"
echo "NS_SHA:$(sha256sum "$NS" | awk 'NR==1 {print $1}')"
echo "SEQ_SHA:$(sha256sum "$SEQ" | awk 'NR==1 {print $1}')"
echo "INIT_C_SHA:$(sha256sum "$INIT_C" | awk 'NR==1 {print $1}')"
echo "ACC_C_SHA:$(sha256sum "$ACC_C" | awk 'NR==1 {print $1}')"
echo "SUMMARY_SHA:$(sha256sum "$SUMMARY" | awk 'NR==1 {print $1}')"
[ "$(sha256sum "$SEQ" | awk 'NR==1 {print $1}')" = "2b13fe0363832aa852a6fc16111524558d9269bf81b1827474a9811a419d9f2a" ] || stop "bg-seq sha"
[ "$(sha256sum "$INIT_C" | awk 'NR==1 {print $1}')" = "db2cae72ccf70c04e6a37b7032ac74b4291978b2506507636593d9e0247e46cd" ] || stop "init sha"
[ "$(sha256sum "$ACC_C" | awk 'NR==1 {print $1}')" = "45f4dfd1ab47048a34dadfc7d809204238006fa890499550d40ff8a485abc779" ] || stop "acceptor sha"
[ "$(sha256sum "$SUMMARY" | awk 'NR==1 {print $1}')" = "30bae46b878ce871d1ab881a605a8c17c338dcbb3cf957769eb54b10e7e1cc60" ] || stop "summary sha"
command -v unshare >/dev/null || stop "no unshare"
command -v cc >/dev/null || stop "no cc"
head=$(git -C "$WT" rev-parse HEAD)
[ "$head" = "$SHA" ] || stop "tree is not $SHA"
dirty=$(git -C "$WT" status --porcelain --untracked-files=no | wc -l | tr -d ' ')
echo "TREE_DIRTY:$dirty"
[ "$dirty" = 0 ] || stop "worktree dirty"
echo "==== build ===="
export CARGO_TARGET_DIR=$WT/target-bg
build_rc=0
set +e
(
    cd "$WT" || exit 1
    CARGO_BUILD_JOBS=2 cargo build --offline --locked -p krb5-gss --bin krb5-gss-init --features test-hooks \
        && CARGO_BUILD_JOBS=2 cargo build --offline --locked -p krb5-client --bins \
        && CARGO_BUILD_JOBS=2 cargo build --offline --locked -p krb5-kdc --bin krb5-kdc --features test-hooks
)
build_rc=$?
set +e
echo "BUILD_RC:$build_rc"
[ "$build_rc" = 0 ] || stop "build failed"
BIN=$CARGO_TARGET_DIR/debug
for b in krb5-kdc krb5-gss-init krb5-kinit krb5-klist krb5-kdestroy krb5-kvno; do
    [ -x "$BIN/$b" ] || stop "missing $b"
    echo "BIN_SHA:$b:$(sha256sum "$BIN/$b" | awk 'NR==1 {print $1}')"
done
cc -O2 -o "$HERE/bin/gss-seq-init" "$INIT_C" -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err
echo "INIT_CC:$?"
cc -O2 -o "$HERE/bin/gss-seq-acceptor" "$ACC_C" -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err
echo "ACC_CC:$?"
[ -x "$HERE/bin/gss-seq-init" ] || stop "init cc"
[ -x "$HERE/bin/gss-seq-acceptor" ] || stop "acceptor cc"
export KDC=$BIN/krb5-kdc
export OURS=$BIN/krb5-gss-init
export INIT=$HERE/bin/gss-seq-init
export ACC=$HERE/bin/gss-seq-acceptor
export SUMMARY=$SUMMARY
export KINIT_OURS=$BIN/krb5-kinit
export KLIST_OURS=$BIN/krb5-klist
export KDESTROY_OURS=$BIN/krb5-kdestroy
export KVNO_OURS=$BIN/krb5-kvno
echo "==== rig ===="
rm -rf "$REC/rig"
mkdir -p "$REC/rig"
set +e
bash "$SEQ" "$REC/rig" | tee "$REC/rig.txt"
rig_rc=${PIPESTATUS[0]}
set +e
echo "RIG_RC:$rig_rc"
[ "$rig_rc" = 0 ] || stop "rig"
echo "==== grade rig ===="
python3 - "$REC/rig.txt" << 'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(errors="replace")

def block(label):
    m = re.search(
        rf"^== {re.escape(label)}: (\d+) fresh contexts\n(.*?)(?=^== |\Z)",
        text,
        re.M | re.S,
    )
    if not m:
        return None, ""
    return int(m.group(1)), m.group(2)

def line_has(body, pat):
    return re.search(pat, body, re.M) is not None

ok_all = True
for label in ("mit-default", "mit-nomutual", "ours"):
    n, body = block(label)
    seq = line_has(body, r"seq-number values:.*distinct 10 of 10")
    zero = "present and 0 in contexts none" in body and "absent in contexts none" in body
    sub = "subkey ids: distinct 10 of 10" in body
    snd = "SND_SEQ equals the authenticator's seq-number: yes" in body
    plus = "second token = first + 1: yes" in body
    authz = "authorization-data [8]: ['ABSENT']" in body
    decoding = "MIT's own decoding of the authenticator:" in body and "authorization_data absent" in body
    replay_in = "duplicate of an earlier token" in body
    replay_x = "invalid Message Integrity Check (MIC)" in body
    good = n == 10 and seq and zero and sub and snd and plus and authz and decoding and replay_in and replay_x
    ok_all = ok_all and good
    print(
        f"RIG_{label}:{'yes' if good else 'no'} "
        f"n={n if n is not None else 'missing'} seq10={seq} zero={zero} "
        f"sub={sub} snd={snd} plus={plus} authz={authz} "
        f"decode={decoding} replay_in={replay_in} replay_x={replay_x}"
    )
print("RIG_ALL:" + ("yes" if ok_all else "no"))
PY
echo "==== cells ===="
rm -rf "$REC/ns"
mkdir -p "$REC/ns"
export KDC=$BIN/krb5-kdc
export INIT=$HERE/bin/gss-seq-init
export ACC=$HERE/bin/gss-seq-acceptor
export OURS=$BIN/krb5-gss-init
export KINIT_OURS=$BIN/krb5-kinit
export KLIST_OURS=$BIN/krb5-klist
export KDESTROY_OURS=$BIN/krb5-kdestroy
export KVNO_OURS=$BIN/krb5-kvno
set +e
bash "$NS" "$REC/ns" | tee "$REC/cells.txt"
ns_rc=${PIPESTATUS[0]}
set +e
echo "NS_RC:$ns_rc"
[ "$ns_rc" = 0 ] || stop "namespace cells"
grep -q '^NS_DONE$' "$REC/cells.txt" || stop "cells incomplete"
echo "==== grade ===="
python3 - "$REC/cells.txt" << 'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(errors="replace")

def section(label):
    m = re.search(
        rf"^==== {re.escape(label)} acceptor ====\n(.*?)(?=^==== |\Z)",
        text,
        re.M | re.S,
    )
    return m.group(1) if m else ""

def init_rc(label):
    m = re.search(rf"^{re.escape(label)} init rc (\d+)$", text, re.M)
    return m.group(1) if m else "missing"

def seq_of(body):
    m = re.search(r"seq-number \[7\]: PRESENT, value (\d+)", body)
    return int(m.group(1)) if m else None

def keytype(body):
    m = re.search(r"keytype (\d+)", body)
    return m.group(1) if m else "missing"

def show(label):
    body = section(label)
    seq = seq_of(body)
    kt = keytype(body)
    absent = "authorization_data absent" in body
    cbt = "flags 0x4000" in body
    rc = init_rc(label)
    print(
        f"{label} rc={rc} seq={seq if seq is not None else 'missing'} "
        f"keytype={kt} authz={'absent' if absent else 'present'} "
        f"cbt={'yes' if cbt else 'no'}"
    )
    return rc, seq, kt, absent, cbt

aes = "aes128-cts-hmac-sha1-96" in text
print("KEYTAB_AES128:" + ("yes" if aes else "no"))
pairs = {}
for label in (
    "mit-etype", "ours-etype",
    "mit-cbt-off", "ours-cbt-off",
    "mit-cbt-rel", "ours-cbt-rel",
    "mit-cbt-flag", "ours-cbt-flag",
):
    pairs[label] = show(label)

def both(a, b, pred):
    return pred(pairs[a]) and pred(pairs[b])

etype_ok = aes and both(
    "mit-etype", "ours-etype",
    lambda t: t[0] == "0" and t[1] not in (None, 0) and t[2] == "18" and t[3],
)
off_ok = both(
    "mit-cbt-off", "ours-cbt-off",
    lambda t: t[0] == "0" and t[3] and not t[4],
)
rel_ok = both(
    "mit-cbt-rel", "ours-cbt-rel",
    lambda t: t[0] == "0" and t[4],
)
flag_ok = both(
    "mit-cbt-flag", "ours-cbt-flag",
    lambda t: t[0] == "0" and t[4],
)
seqs = [t[1] for t in pairs.values() if t[1] not in (None, 0)]
seq_ok = len(seqs) == 8 and len(set(seqs)) == 8
maybe_mit = init_rc("mit-maybe")
maybe_ours = init_rc("ours-maybe")
maybe_text = text.count("Invalid boolean value") >= 2
maybe_ok = maybe_mit == "1" and maybe_ours == "1" and maybe_text
print(f"maybe mit rc={maybe_mit} ours rc={maybe_ours} invalid_boolean={maybe_text}")
print("BG_ETYPE:" + ("yes" if etype_ok else "no"))
print("BG_CBT_OFF:" + ("yes" if off_ok else "no"))
print("BG_CBT_REL:" + ("yes" if rel_ok else "no"))
print("BG_CBT_FLAG:" + ("yes" if flag_ok else "no"))
print("BG_MAYBE:" + ("yes" if maybe_ok else "no"))
print("BG_SEQ:" + ("yes" if seq_ok else "no"))
print("BG_VFY:skipped")
PY
echo "BG_END"
