#!/usr/bin/env bash
# harness/field/scenarios/secrets-gcore.sh --leg mit|rust: SR-1's "secrets in memory" cell. On kdc, as
# upgrade.sh left it (MIT's kadmind on the mit leg, kerber-rust's on the rust leg), admin changes a test
# principal's password twice -- once over the kpasswd protocol (464) and once with a remote `kadmin cpw`
# (749), each to a fresh random password -- then kadmind is core-dumped (gcore; gdb is installed on kdc
# when it is missing) and the core is scanned on the VM for each password's raw occurrences, with the realm
# name as a positive control. The core is deleted on the VM and never copied off; only counts are recorded.
# MIT runs first (the oracle): it records its counts (it does not zero these). Ours passes when it leaves
# no more copies of each password than MIT did (the rust leg reads the mit leg's counts from the sibling
# record). The passwords are drawn here per run and reach the VMs only on stdin, never on a command line
# or in the record.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: secrets-gcore.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset ADMIN
R=${REALM//./\\.}

cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- 'sudo rm -f /tmp/sr1core.* 2>/dev/null; sudo kadmin.local -q "delprinc -force sruser" > /dev/null 2>&1; true' < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh client2 -- 'rm -rf ~/sr1; true' < /dev/null > /dev/null 2>&1
    rm -f "$STATE/pw1" "$STATE/pw2" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Two fresh random passwords for this run, on the runner's scratch only.
python3 -c 'import secrets; print(secrets.token_urlsafe(18))' > "$STATE/pw1"
python3 -c 'import secrets; print(secrets.token_urlsafe(18))' > "$STATE/pw2"

# corecount <pw-file>: occurrences of that password in kadmind's core on kdc, into $LAST_OUT (a number).
# The password arrives on stdin; the command line and the record hold no secret, and grep -o feeds wc,
# so only the count reaches stdout.
# The password is grep's pattern on stdin (-f -), so it never reaches grep's argv (/proc) or the record.
corecount() { runin kdc "count a secret's raw occurrences in the core" 'grep -o -a -F -f - /tmp/sr1core.* 2>/dev/null | wc -l' < "$1"; }

section "secrets-gcore --leg $LEG: kadmind core after a kpasswd change and a kadmin cpw on kdc, realm $REALM"
kdcis
check kadmin.active '^active$' run kdc "systemctl is-active kadmin"
resetvm client2
run client2 "rm -rf ~/sr1; mkdir -m 0700 ~/sr1"
check client2.setpw rc runin client2 "lib/setpw.py" "cat > ~/sr1/setpw.py" < "$FIELD_LIB/setpw.py"
check setup.sruser "^Principal \"sruser@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'delprinc -force sruser' > /dev/null 2>&1; sudo kadmin.local -q 'addprinc -randkey sruser' 2>&1"

section "the admin changes sruser's password over kpasswd (464), then with a remote kadmin cpw (749)"
check kinit.admin "^Default principal: admin/admin@$R\$" runin client2 "admin/admin's password" "kinit -S kadmin/changepw -c FILE:\$HOME/sr1/admin.cc admin/admin@$REALM && klist -c FILE:\$HOME/sr1/admin.cc" < <(once "$ADMIN")
check kpasswd.change '^result: 0 \(Success\)$' runin client2 "sruser's new password (pw1)" "python3 \$HOME/sr1/setpw.py -c FILE:\$HOME/sr1/admin.cc -t sruser@$REALM kdc.kerber.test" < "$STATE/pw1"
check kadmin.cpw "^Password for \"sruser@$R\" changed\\.\$" runin client2 "admin's password, then sruser's new password (pw2) twice" "kadmin -p admin/admin@$REALM -r $REALM -q 'cpw sruser' 2>&1" < <(once "$ADMIN"; cat "$STATE/pw2"; cat "$STATE/pw2")

section "core-dump kadmind and scan the core on the VM (counts only; the core is deleted on the VM)"
check gcore.tool '^gdb-[0-9]' run kdc "rpm -q gdb > /dev/null 2>&1 || sudo dnf -y -q install gdb > /dev/null 2>&1; rpm -q gdb"
check gcore.taken '^core: [0-9]+ bytes$' run kdc "p=\$(pgrep -x kadmind | head -1); sudo gcore -o /tmp/sr1core \"\$p\" > /dev/null 2>&1; f=\$(ls /tmp/sr1core.* 2>/dev/null | head -1); [ -s \"\$f\" ] && echo \"core: \$(stat -c %s \"\$f\") bytes\""
corecount "$STATE/pw1"; KPW=$(cat "$LAST_OUT" 2>/dev/null); KPW=${KPW//[^0-9]/}
corecount "$STATE/pw2"; KCPW=$(cat "$LAST_OUT" 2>/dev/null); KCPW=${KCPW//[^0-9]/}
observe gcore.kpasswd-copies 'copies: [0-9]+' host "echo \"copies: ${KPW:-0}\""
observe gcore.cpw-copies 'copies: [0-9]+' host "echo \"copies: ${KCPW:-0}\""
# Positive control: the realm name must be in the core, so a zero above is a real absence, not a broken scan.
check gcore.control '^control: [1-9][0-9]*$' run kdc "echo \"control: \$(grep -o -a -F -- '$REALM' /tmp/sr1core.* 2>/dev/null | wc -l)\""
run kdc "sudo rm -f /tmp/sr1core.*"

section "grade: ours leaves no more copies than MIT (mit records; rust compares the sibling leg)"
if [ "$LEG" = mit ]; then
    printf 'MIT_KPW=%s\nMIT_CPW=%s\n' "${KPW:-0}" "${KCPW:-0}" > "$REC_DIR/counts.env"
    observe sr1.mit-baseline 'mit: kpasswd [0-9]+ cpw [0-9]+' host "echo \"mit: kpasswd ${KPW:-0} cpw ${KCPW:-0}\""
else
    if [ -f "$REC_DIR/../mit/counts.env" ]; then
        MIT_KPW='' MIT_CPW=''
        # shellcheck source=/dev/null
        . "$REC_DIR/../mit/counts.env"
        check sr1.kpasswd.le-mit rc host "test \"${KPW:-0}\" -le \"${MIT_KPW:-0}\""
        check sr1.cpw.le-mit rc host "test \"${KCPW:-0}\" -le \"${MIT_CPW:-0}\""
        observe sr1.compare 'ours kpasswd [0-9]+/[0-9]+ cpw [0-9]+/[0-9]+' host "echo \"ours kpasswd ${KPW:-0}/${MIT_KPW:-0} cpw ${KCPW:-0}/${MIT_CPW:-0}\""
    else
        # A rust-only run has no MIT oracle, so it records ours' counts rather than grading.
        observe sr1.baseline-absent 'baseline absent: ours kpasswd [0-9]+ cpw [0-9]+' host "echo \"baseline absent: ours kpasswd ${KPW:-0} cpw ${KCPW:-0}\""
    fi
fi

finish
