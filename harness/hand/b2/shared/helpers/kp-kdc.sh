#!/bin/bash
# kp-kdc.sh STAGE SECTION [ARGS]: KP's kdc-side steps (the primary), as root: `sudo bash kp-kdc.sh mit|ours SECTION ...`. (lab-agent; module mod/kp.sh; VM-LEG.md)
# Pushed by the module to $VMD/b2a/ beside b2a-lib.sh and kp-bulk-dump.py (KP's scripts/lib/bulk-dump.py, byte for byte). Work directory: $VMD/kp/p (0700). No stdin is read.
# What it makes, per stage (and deletes at the end: the shell compares the realm database at the module boundary, and alice's key must not move):
#   host/kdc.kerber.test        the primary's own key, as kprop names itself host/<this host>: the realm's default flags (+requires_preauth on the lab's kdc.conf); the keytab $P/kdc.keytab holds the key
#                               of the second ktadd (kvno 3), $P/stale.keytab the first's alone (kvno 2, stale from the second ktadd on)
#   kpdecoy/kdc.kerber.test     a principal of no use to kprop; its keytab $P/other.keytab has no host/kdc entry ("no key for the client")
# Sections: setup | dump | run -- CMD... | stash-cat | preauth-off | preauth-on | touch-new | cleanup   (setup, dump, preauth-*, cleanup print the packages' record format CELL name / RC:n / output / CELL_END name;
#   run prints [rc=N], == which, == stdout, == stderr, == trace, == last_prop, for the module's `cell`)
set -u
STAGE=${1:?mit|ours}; SECTION=${2:?section}; shift 2
. "$(dirname "$0")/b2a-lib.sh"
case $STAGE in mit|ours) ;; *) echo "kp-kdc.sh: stage mit|ours" >&2; exit 2 ;; esac
P=$B2A_D/kp/p
KPRINC=host/kdc.kerber.test
DPRINC=kpdecoy/kdc.kerber.test

kp_dump_facts() {   # the dumps in numbers (a dump holds the principals' encrypted keys: only a short hash is printed, to compare with what the replica received)
    local x f
    for x in A B; do
        f=$P/dump$x
        if [ -s "$f" ]; then
            printf 'DUMP_%s_BYTES %s\nDUMP_%s_BLOCKS %s\nDUMP_%s_PRINCS %s\nDUMP_%s_SHA16 %s\nDUMP_%s_HEADER %s\n' \
                "$x" "$(stat -c %s "$f")" "$x" "$(( ($(stat -c %s "$f") + 32767) / 32768 ))" "$x" "$(grep -c '^princ' "$f")" "$x" "$(sha256sum < "$f" | cut -c1-16)" "$x" "$(head -n 1 "$f")"
            printf 'DUMP_%s_HAS_HOSTKDC %s\nDUMP_%s_HAS_ALICE %s\nDUMP_%s_HAS_BULK250 %s\n' "$x" "$(grep -c "	$KPRINC@" "$f")" "$x" "$(grep -c '	alice@' "$f")" "$x" "$(grep -c '	bulk0250@' "$f")"
            printf 'DUMP_%s_NAMES_SHA16 %s\n' "$x" "$(grep '^princ' "$f" | awk -F'\t' '{ print $7 }' | LC_ALL=C sort | sha256sum | cut -c1-16)"
            stat -c '%A %h %U %G %s %y %n' "$f" "$f.dump_ok" 2>&1 | sed "s#$P/##"
        else
            printf 'DUMP_%s_BYTES 0\n' "$x"
        fi
    done
}
kp_keytab_facts() {   # the keytabs by principal, kvno and enctype (never a key)
    local k
    for k in kdc stale other; do
        echo "== klist -ke $k.keytab"
        klist -ke "$P/$k.keytab" 2>&1 | sed "s#$P/##"
        echo "mode $(stat -c %a "$P/$k.keytab" 2>&1)"
    done
}
kp_which() {   # the kprop that will run: its path, size and a short hash (MIT's from krb5-server, or ours from the ship build)
    local p
    p=$(command -v kprop)
    echo "which kprop: $p"
    stat -c '%A %h %U %G %s %y %n' "$p" 2>&1 | sed 's/^/  /'
    echo "sha256 $(sha256sum < "$p" | cut -c1-16)"
    echo "hostname: $(hostname)"
}

case $SECTION in
setup)
    install -d -m 0700 "$B2A_D/kp" "$P"
    rm -f "$P"/*.keytab
    echo "== facts"
    echo "hostname: $(hostname) / $(hostname -f 2>&1)"
    b2a_run which kp_which
    b2a_kal add-1 "addprinc -randkey $KPRINC"
    b2a_kal add-2 "addprinc -randkey $DPRINC"
    b2a_kal getprinc-kdc "getprinc $KPRINC"
    b2a_kal ktadd-1 "ktadd -k $P/stale.keytab $KPRINC"      # the key the second ktadd replaces: this keytab goes stale at once
    b2a_kal ktadd-2 "ktadd -k $P/kdc.keytab $KPRINC"
    b2a_kal ktadd-decoy "ktadd -k $P/other.keytab $DPRINC"
    chmod 600 "$P"/*.keytab
    b2a_run keytabs kp_keytab_facts
    ;;
dump)
    rm -f "$P"/dump*
    b2a_run dump-A kdb5_util dump "$P/dumpA"
    b2a_run dump-B python3 "$B2A_D/b2a/kp-bulk-dump.py" "$P/dumpA" "$P/dumpB" 250
    cp -p "$P/dumpA" "$P/dumpC"; cp -p "$P/dumpA.dump_ok" "$P/dumpC.dump_ok"   # dumpC: the one `touch-new` makes newer than its .dump_ok
    cp -p "$P/dumpA" "$P/dumpD"                                                # dumpD: no .dump_ok at all
    chmod 600 "$P"/dump*
    b2a_run dump-facts kp_dump_facts
    ;;
run)   # run -- CMD...: the command with KRB5_TRACE in a file of its own (a trace written to /dev/stderr shares the file with the error message and overwrites it), stdout and stderr kept apart, then what it left beside the dump
    [ "${1:-}" = -- ] && shift
    kp_which > "$P/which.txt" 2>&1
    env KRB5_TRACE="$P/run.trace" "$@" > "$P/run.out" 2> "$P/run.err" < /dev/null; rc=$?
    echo "[rc=$rc]"
    echo "== which"; cat "$P/which.txt"
    echo "== stdout"; cat "$P/run.out"
    echo "== stderr"; cat "$P/run.err"
    echo "== trace"; sed -E 's/(Received cookie: ).*/\1<masked>/' "$P/run.trace" 2> /dev/null   # the cookie is the KDC's opaque state, not part of any judgement
    echo "== last_prop"
    lp=""; for lp in "$P"/*.last_prop; do [ -e "$lp" ] || lp=""; break; done
    if [ -n "$lp" ]; then
        echo "file $(basename "$lp")"; echo "size_mode $(stat -c '%s %a' "$lp")"; echo "bytes $(od -An -tx1 "$lp" | tr -s ' ' | sed 's/^ //')"
    else
        echo "absent"
    fi
    rm -f "$P"/*.last_prop "$P/run.out" "$P/run.err" "$P/run.trace" "$P/which.txt"
    ;;
stash-cat)   # the realm's stash on stdout, for a pipe to client2 (never recorded; the stage's other sections do not print it)
    kd=$B2A_KDCDIR
    f=$(sed -n 's/^[[:space:]]*key_stash_file[[:space:]]*=[[:space:]]*//p' "$kd/kdc.conf" | head -n 1)
    [ -n "$f" ] || f=$kd/.k5.$B2A_REALM
    cat "$f"
    ;;
preauth-off) b2a_kal preauth-off "modprinc -requires_preauth $KPRINC" ;;
preauth-on)  b2a_kal preauth-on "modprinc +requires_preauth $KPRINC" ;;
touch-new)   # dumpC modified after its .dump_ok (the .dump_ok is a second older: the check compares seconds)
    sleep 2; touch "$P/dumpC"; b2a_run touch-new ls -l --time-style=full-iso "$P/dumpC" "$P/dumpC.dump_ok"
    ;;
cleanup)
    b2a_kal del-1 "delprinc -force $KPRINC"
    b2a_kal del-2 "delprinc -force $DPRINC"
    b2a_kal getprinc-gone "getprinc $KPRINC"
    shred -u "$P"/*.keytab "$P"/dump* 2> /dev/null; rm -f "$P"/*.last_prop
    rmdir "$P" 2> /dev/null
    echo "CELL left"; if [ -d "$P" ]; then echo "KP_LEFT $(find "$P" -mindepth 1 -maxdepth 1 | wc -l)"; else echo "KP_LEFT 0"; fi; echo "CELL_END left"
    ;;
*) echo "kp-kdc.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
