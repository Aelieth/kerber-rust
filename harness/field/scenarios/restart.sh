#!/usr/bin/env bash
# harness/field/scenarios/restart.sh --leg mit|rust: write, kill, relaunch, on the leg's KDC as upgrade.sh left it on
# kdc. MIT kadmin from client2 adds rw-<hex> with a generated password (stdin only); once that is acknowledged both
# daemons are SIGKILLed by main pid and started again; MIT kinit with the same password works; kdc's own
# kdb5_util dump of the database loads into MIT's kdb5_util on kdc2 (as kill-loop.sh judges) and MIT's getprinc
# there finds the principal.
# vms: kdc client2 kdc2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: restart.sh --leg mit|rust" >&2; exit 1 ;;
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
WC="\$HOME/rw"
KW=/var/tmp/rw
RW=rw-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')
PW=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
UNITS="$UNIT_KDC $UNIT_ADMIN"

# Best effort on any exit: the daemons up, the principal gone, kdc2 back to its snapshot and parked.
cleanup() {
    timeout -k 5 120 "$LAB" ssh kdc -- "sudo systemctl start $UNITS; sudo kadmin.local -q 'delprinc -force $RW' \
        > /dev/null 2>&1; sudo rm -rf $KW; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh client2 -- "rm -rf $WC; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 300 "$LAB" reset kdc2 "$MIT_SNAPSHOT_KDC2" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" down kdc2 < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# kdc2: MIT's side of the dump, args: mode realm kdcdir principal. conf writes kill-loop.py judge's kdc.conf (a first
# stanza for a scratch database and the stash, then kdc2's own); load loads the dump and asks getprinc.
judgesh() {
    cat <<'EOF'
#!/bin/bash
D=$(cd "$(dirname "$0")" && pwd)
export KRB5_KDC_PROFILE="$D/kdc.conf" SS_READLINE_PATH=none
case $1 in
    conf)
        mkt=$(python3 -I -c 'import importlib.util as u, sys
s = u.spec_from_file_location("kl", sys.argv[1]); m = u.module_from_spec(s); s.loader.exec_module(m)
print(m.ENCTYPES.get(m.stash_enctype(open(sys.argv[2], "rb").read(4096)), ""))' "$D/kill-loop.py" "$D/stash")
        mkdir -m 0700 -p "$D/mit"
        {
            printf '[realms]\n    %s = {\n        database_name = %s/mit/principal\n' "$2" "$D"
            printf '        key_stash_file = %s/stash\n        iprop_enable = false\n' "$D"
            if [ -n "$mkt" ]; then printf '        master_key_type = %s\n' "$mkt"; fi
            printf '    }\n\n'
            cat "$3/kdc.conf"
        } > "$D/kdc.conf"
        echo "conf: master key type ${mkt:-default}"
        ;;
    load)
        kdb5_util -r "$2" load "$D/rw.dump"
        rc=$?
        echo "load rc=$rc"
        kadmin.local -r "$2" -q "getprinc $4" 2>&1 | grep -v '^Authenticating'
        exit $rc
        ;;
esac
EOF
}

section "restart --leg $LEG: $RW added, both daemons killed and started again, kinit, the dump into MIT on kdc2"
kdcis
resetvm client2
check reset.kdc2 rc host "$LABQ reset kdc2 $MIT_SNAPSHOT_KDC2"
waitsync kdc2
check kdc2.mit '^kdc2: MIT krb5-server-[0-9].*, binaries as packaged, python 3' run kdc2 \
    "sudo rpm -V krb5-server krb5-libs | grep -E ' /usr/(s?bin|lib64)/'; ! sudo rpm -V krb5-server | \
    grep -qE '^..5.* /usr/sbin/(kdb5_util|kadmin\\.local)\$' && \
    echo \"kdc2: MIT \$(rpm -q krb5-server), binaries as packaged, \$(python3 -V | tr P p)\""
check kdc2.dir rc runin kdc2 "judge.sh" "sudo install -d -m 0700 $KW && sudo tee $KW/judge.sh > /dev/null" < <(judgesh)
check kdc2.driver rc runin kdc2 "lib/kill-loop.py" "sudo tee $KW/kill-loop.py > /dev/null" < "$FIELD_LIB/kill-loop.py"
check kdc2.stash '^stash copied$' host "$LABQ ssh kdc -- 'sudo cat $KDCDIR/.k5.$REALM' | $LABQ ssh kdc2 -- \
    'sudo install -m 0600 /dev/stdin $KW/stash && echo stash copied'"
check client2.dir rc run client2 "rm -rf $WC; mkdir -m 0700 $WC && echo 'client2: ~/rw made'"
if awk -F'\t' '$2 == "FAIL"' "$CHECKS" | grep -q .; then
    note "a setup check failed: the leg stops here, before any write to kdc's database"
    finish
    exit 1
fi

section "1. RW.add: MIT kadmin from client2 adds $RW; its password and the admin's go on stdin"
ADDED=0
check RW.add "Principal \"$RW@$R\" created\\." runin client2 "admin/admin's password ($ADMIN), $RW's twice" \
    "kadmin -p admin/admin@$REALM -q 'addprinc $RW' 2>&1" < <(once "$ADMIN"; printf '%s\n%s\n' "$PW" "$PW")
if [ "$LAST_RC" = 0 ] && grep -qE "Principal \"$RW@$R\" created\\." "$LAST_OUT"; then ADDED=1; fi

section "2. RW.kill: only after the acknowledgment, both main pids SIGKILLed"
KP='' AP=''
if [ "$ADDED" = 1 ]; then
    check RW.kill '^gone: kdc [1-9][0-9]* admin [1-9][0-9]*$' run kdc \
        "kp=\$(systemctl show -p MainPID --value $UNIT_KDC); ap=\$(systemctl show -p MainPID --value $UNIT_ADMIN); \
        echo \"pids: kdc \$kp admin \$ap\"; [ \"\${kp:-0}\" -gt 0 ] && [ \"\${ap:-0}\" -gt 0 ] || exit 1; \
        sudo kill -9 \$kp \$ap; for i in \$(seq 1 40); do [ -d /proc/\$kp ] || [ -d /proc/\$ap ] || break; \
        sleep 0.25; done; [ ! -d /proc/\$kp ] && [ ! -d /proc/\$ap ] && echo \"gone: kdc \$kp admin \$ap\""
    read -r KP AP < <(sed -n 's/^pids: kdc \([0-9]*\) admin \([0-9]*\)$/\1 \2/p' "$LAST_OUT")
else
    _checkrow RW.kill FAIL "the add acknowledged first" 1 "NOT-RUN: $RW was not acknowledged, so nothing is killed"
fi

section "3. RW.relaunch: started again (or by systemd already), active, new main pids"
if [ "$ADDED" = 1 ] && [[ ${KP:-x} =~ ^[0-9]+$ && ${AP:-x} =~ ^[0-9]+$ ]]; then
    check RW.relaunch '^relaunched: kdc [1-9][0-9]* admin [1-9][0-9]*, 88 and 749 listening$' run kdc \
        "sudo systemctl start $UNITS; rc=\$?; for i in \$(seq 1 40); do systemctl is-active -q $UNIT_KDC && \
        systemctl is-active -q $UNIT_ADMIN && ss -Hlun 'sport = :88' | grep -q . && \
        ss -Hltn 'sport = :749' | grep -q . && break; sleep 0.5; done; \
        echo \"units: \$(systemctl is-active $UNITS | paste -sd' ' -)\"; \
        nk=\$(systemctl show -p MainPID --value $UNIT_KDC); na=\$(systemctl show -p MainPID --value $UNIT_ADMIN); \
        echo \"pids: kdc \$nk admin \$na (killed: kdc $KP admin $AP)\"; \
        [ \$rc = 0 ] && [ \"\$(systemctl is-active $UNITS | paste -sd' ' -)\" = 'active active' ] && \
        [ \"\${nk:-0}\" -gt 0 ] && [ \"\${na:-0}\" -gt 0 ] && [ \"\$nk\" != $KP ] && [ \"\$na\" != $AP ] && \
        ss -Hlun 'sport = :88' | grep -q . && ss -Hltn 'sport = :749' | grep -q . && \
        echo \"relaunched: kdc \$nk admin \$na, 88 and 749 listening\""
else
    _checkrow RW.relaunch FAIL "the daemons killed first" 1 "NOT-RUN: the kill did not run, or gave no pids"
fi

section "4. RW.kinit: MIT kinit as $RW with the generated password, on client2"
check RW.kinit rc runin client2 "$RW's password (generated)" \
    "export KRB5CCNAME=FILE:$WC/rw.cc; kinit $RW@$REALM" < <(printf '%s\n' "$PW")
check RW.klist "krbtgt/$R@$R\$" run client2 "export KRB5CCNAME=FILE:$WC/rw.cc; klist; kdestroy -q"

section "5. RW.dump, RW.load: kdc's kdb5_util dump, loaded by MIT's kdb5_util on kdc2, MIT's getprinc there"
check RW.dump "^dump: [1-9][0-9]* bytes, 0600, $RW lines: [1-9][0-9]*\$" run kdc \
    "sudo install -d -m 0700 $KW && sudo rm -f $KW/rw.dump* && sudo kdb5_util dump $KW/rw.dump && \
    sudo chmod 0600 $KW/rw.dump && n=\$(sudo grep -c '$RW@' $KW/rw.dump); \
    echo \"dump: \$(sudo stat -c '%s bytes, %04a' $KW/rw.dump), $RW lines: \$n\""
check RW.copy "^dump on kdc2: 600 [1-9][0-9]*\$" host "$LABQ ssh kdc -- 'sudo cat $KW/rw.dump' | \
    $LABQ ssh kdc2 -- 'sudo install -m 0600 /dev/stdin $KW/rw.dump && echo \"dump on kdc2: \$(sudo stat -c \"%a %s\" \
    $KW/rw.dump)\"'"
check RW.conf '^conf: master key type ' run kdc2 "sudo bash $KW/judge.sh conf $REALM $KDCDIR"
check RW.load "^Principal: $RW@$R\$" run kdc2 "sudo bash $KW/judge.sh load $REALM $KDCDIR $RW@$REALM"
checklast RW.load.rc '^load rc=0$'

finish
