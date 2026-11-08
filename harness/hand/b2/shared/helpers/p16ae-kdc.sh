#!/bin/bash
# p16ae-kdc.sh STAGE SECTION [ARG [ARG2]]: P16a-edges' kdc-side cells, as root: `sudo bash p16ae-kdc.sh mit|ours prep|side|dict NAME [iso]|fifo-enforcing|fifo-permissive|fifo-nowriter|fifo-restore|cleanup|clean`.
# stdin: three lines, the leg's throwaway passwords PW1 (the initial password of p16auser and p16anopol) PW2 (unused here) PW3 (the master password of the side databases).
# Source: {driver.log,edges-mit.txt,edges-rust.txt,side-mit.txt,prep.txt,discover.txt}; the original helpers kdc-prep.sh, kdc-dict.sh, kdc-side.sh, kdc-upgrade.sh were not saved: this is
# rewritten from those outputs and from the Oct 5 container scripts s1-content-edges.sh, s2-create-failure.sh, s3-passwd-check-log.sh in the same directory.
#   prep            the dictionaries under $KDCDIR/p16a (nul.dict, latin.dict, fifo.dict + a FIFO writer that outlives the restarts, fifo-nowriter.dict), labels, the policy p16apol and the principals
#                   p16auser (policy p16apol, REQUIRES_PRE_AUTH) and p16anopol (no policy)
#   side            two throwaway databases (kdb5_util create -s) whose dict_file is a directory and a missing file: where create stops, what it prints, its exit status, the files it leaves, the log lines
#   dict NAME [iso] dict_file := the stock file (NAME stock) or p16a/NAME.dict, kadmin restarted; iso: LC_ALL=en_US.ISO-8859-1 in kadmind's environment (a systemd drop-in)
#   fifo-enforcing  dict_file := fifo.dict with a live writer; kadmin restarted under SELinux Enforcing (it fails: Permission denied while initializing); the journal and the AVC records of the window
#   fifo-permissive setenforce 0, kadmin restarted (works)         fifo-nowriter  dict_file := fifo-nowriter.dict, restart under a 25 s cap (blocks: rc 124), the stuck start stopped
#   fifo-restore    the writer killed, kdc.conf and the environment as found, setenforce 1, kadmin restarted        cleanup  the stage's principals and the policy deleted        clean  fifo-restore + the files gone
# kadmin/history: the lab's f4-mit realm lacks it as found and the kadm5 layer creates it lazily at the first password change under a policy (the cpw cells of p16auser, policy p16apol), on both stages. prep records
# whether it exists at the stage's start (HISTORY_AT_START; marker $B2A_D/p16ae-hist-<stage>), cleanup deletes it when the stage made it (HISTORY_CREATED_BY_STAGE), after the principals and the policy, and says
# HISTORY_AT_END, so that the realm is as found and the next stage (and the install's dump, which would carry it into the ours stage) starts without it. Nothing here creates it.
# The units: prep first finds krb5kdc and kadmin (ENTRY_UNITS; one found down, an earlier module's leftover, is reset-failed and started once: ENTRY_STARTED) and fifo-restore / clean end with both active
# (UNITS krb5kdc=active kadmin=active; KRB5KDC_FOUND_DOWN when krb5kdc, which this module never stops, is found down at the end: it is started and the module's row is red).
set -u
STAGE=${1:?mit|ours}; SECTION=${2:?section}; ARG=${3:-}; ARG2=${4:-}
. "$(dirname "$0")/b2a-lib.sh"
P16=$B2A_KDCDIR/p16a
HIST=kadmin/history@$B2A_REALM
HISTMARK=$B2A_D/p16ae-hist-$STAGE
W=$B2A_D/p16ae
LCDROP=${VMCTL_SYSD:-/etc/systemd/system}/kadmin.service.d/b2a-lc.conf
IFS= read -r PW1; IFS= read -r _PW2_UNUSED; IFS= read -r PW3
[ -n "$PW1" ] && [ -n "$PW3" ] || { echo "P16AE_ABORT no passwords on stdin"; exit 2; }

state() {   # kadmin's state in the record's words: the dict_file line, the unit, the pid, the environment that matters
    local pid dl
    dl=$(sed -n 's/^[[:space:]]*dict_file[[:space:]]*=[[:space:]]*//p' "$B2A_KDCDIR/kdc.conf" | head -n 1)
    echo "dict_file ${dl:-(none)}"
    echo "active=$(systemctl is-active kadmin 2>&1)"
    pid=$(systemctl show -p MainPID --value kadmin 2> /dev/null)
    echo "kadmind_pid=${pid:-0}"
    if [ "${pid:-0}" -gt 0 ] 2> /dev/null && [ -r "/proc/$pid/environ" ]; then tr '\0' '\n' < "/proc/$pid/environ" | grep -E '^(LANG|LC_ALL)='; fi
}
hist() {   # hist: yes when kadmin/history exists in the realm database (a read: getprinc does not create it)
    if kadmin.local -q "getprinc $HIST" < /dev/null 2>&1 | grep -q "^Principal: $HIST\$"; then echo yes; else echo no; fi
}
units() { printf 'krb5kdc=%s kadmin=%s' "$(systemctl is-active krb5kdc 2>&1)" "$(systemctl is-active kadmin 2>&1)"; }
entry_units() {   # the units as this module finds them; a unit found down (an earlier module's leftover) is started once, and said
    local u
    echo "ENTRY_UNITS $(units)"
    for u in krb5kdc kadmin; do
        if [ "$(systemctl is-active "$u" 2>&1)" != active ]; then
            systemctl reset-failed "$u" > /dev/null 2>&1
            timeout 60 systemctl start "$u" > /dev/null 2>&1
            echo "ENTRY_STARTED $u rc=$?"
        fi
    done
    b2a_wait_kadmind || echo "ENTRY_KADMIND_NOT_LISTENING"
    echo "ENTRY_UNITS_NOW $(units)"
}
restart_kadmin() {   # restart_kadmin [SECONDS]: capped; the cap is the record's 25 s for the blocking case; prints nothing but the state
    systemctl reset-failed kadmin > /dev/null 2>&1
    timeout "${1:-60}" systemctl restart kadmin > /dev/null 2>&1
    return $?
}
dropin() {   # dropin on|off: LC_ALL=en_US.ISO-8859-1 in kadmind's environment, through a systemd drop-in
    if [ "$1" = on ]; then mkdir -p "$(dirname "$LCDROP")"; printf '[Service]\nEnvironment=LC_ALL=en_US.ISO-8859-1\n' > "$LCDROP"; else rm -f "$LCDROP"; fi
    systemctl daemon-reload
}
stop_writer() {
    local wp
    touch "$W/stop-writer" 2> /dev/null
    wp=$(cat "$W/writer.pid" 2> /dev/null)
    if [ -n "$wp" ]; then pkill -P "$wp" 2> /dev/null; kill "$wp" 2> /dev/null; fi
}
restore_all() {
    stop_writer
    b2a_conf
    dropin off
    setenforce 1
    echo "setenforce 1"
    echo "enforce_now=$(getenforce)"
    restart_kadmin 60
    b2a_wait_kadmind || echo "KADMIND_NOT_LISTENING"
    if [ "$(systemctl is-active krb5kdc 2>&1)" != active ]; then   # never stopped by this module: said, and started, so that the next module is not left with it
        echo "KRB5KDC_FOUND_DOWN $(systemctl is-active krb5kdc 2>&1)"
        systemctl reset-failed krb5kdc > /dev/null 2>&1
        timeout 60 systemctl start krb5kdc > /dev/null 2>&1
    fi
    echo "UNITS $(units)"
    state
}
side_create() {   # side_create LABEL DICTPATH: kdb5_util create -s with a private profile whose dict_file is DICTPATH
    local label=$1 dict=$2 d rc f
    d=$W/side-$STAGE/$label-db; mkdir -p "$d"
    {
        printf '[realms]\n%s = {\n     database_name = %s/principal\n     key_stash_file = %s/stash\n' "$B2A_REALM" "$d" "$d"
        printf '     master_key_type = aes256-cts-hmac-sha1-96\n     acl_file = %s/kadm5.acl\n     dict_file = %s\n}\n' "$d" "$dict"
        printf '[logging]\n    admin_server = FILE:%s/admin.log\n    default = FILE:%s/default.log\n' "$d" "$d"
    } > "$d/kdc.conf"
    echo "CELL create-$label"
    echo "dict_file=$dict"
    printf '%s\n%s\n' "$PW3" "$PW3" | KRB5_KDC_PROFILE="$d/kdc.conf" timeout 60 kdb5_util create -s > "$d/create.out" 2> "$d/create.err"; rc=$?
    echo "rc=$rc"
    # the two streams as they came (the record has out: and err: lines); the master-key prompts, which MIT and ours put on different streams, are cut out
    sed 's/Enter KDC database master key: //; s/Re-enter KDC database master key to verify: //' "$d/create.out" | grep -v '^$' | sed 's/^/  out: /'
    sed 's/Enter KDC database master key: //; s/Re-enter KDC database master key to verify: //' "$d/create.err" | grep -v '^$' | sed 's/^/  err: /'
    echo "  files: $(cd "$d" && for f in *; do case $f in kdc.conf|create.out|create.err) ;; *) printf '%s\n' "$f" ;; esac; done | sort | tr '\n' ' ')"
    if [ -e "$d/principal" ]; then
        # as the record has it: kadmin.local with the profile as configured (it stops at the dictionary when that cannot be read: nothing listed; its complaint is the next line)
        echo "  principals: $(KRB5_KDC_PROFILE="$d/kdc.conf" timeout 60 kadmin.local -q listprincs < /dev/null 2> "$d/list.err" | grep -v -e '^Authenticating as principal ' | tr '\n' ' ')"
        echo "  listprincs-stderr: $(tr '\n' ' ' < "$d/list.err")"
    fi
    # the log files last: kadmin.local's own warning (the record has both the kdb5_util and the kadmin.local line) is written by the listing above
    for f in admin.log default.log; do
        [ -s "$d/$f" ] && sed -E 's/^[A-Z][a-z]{2} [0-9 ]{2} [0-9:]{8} [^ ]+ //; s/\[[0-9]+\]/[pid]/' "$d/$f" | sed "s/^/  $f: /"
    done
    if [ -e "$d/principal" ]; then
        # and what the database holds once the dictionary line is gone (new: where kdb5_util create had got to when it stopped)
        sed -i '/dict_file/d' "$d/kdc.conf"
        echo "  principals-without-dict: $(KRB5_KDC_PROFILE="$d/kdc.conf" timeout 60 kadmin.local -q listprincs < /dev/null 2>&1 | grep -v -e '^Authenticating as principal ' | tr '\n' ' ')"
    fi
    echo "CELL_END create-$label"
}

case $SECTION in
prep)
    entry_units
    hist > "$HISTMARK"
    echo "HISTORY_AT_START $(cat "$HISTMARK")"
    rm -rf "$P16" "$W"; mkdir -p "$P16" "$W"
    printf 'abc\000def\nxyz\nqrs\n' > "$P16/nul.dict"
    printf 'caf\351\nzebra\n' > "$P16/latin.dict"
    mkfifo "$P16/fifo.dict" "$P16/fifo-nowriter.dict"
    printf 'zebra\n' > "$W/fifo.src"
    restorecon -R "$P16" 2> /dev/null
    # the writer that reopens the FIFO in a loop: it outlives this ssh session (own session, no stdin) and the kadmin restarts; fifo-restore / clean stop it
    setsid nohup bash -c "echo \$\$ > \"\$1\"; while [ ! -e \"\$2\" ]; do cat \"\$3\" > \"\$4\" 2> /dev/null; done" _ "$W/writer.pid" "$W/stop-writer" "$W/fifo.src" "$P16/fifo.dict" < /dev/null > /dev/null 2>&1 &
    for _ in $(seq 1 50); do [ -s "$W/writer.pid" ] && break; sleep 0.1; done
    STOCK=$(sed -n 's/^[[:space:]]*dict_file[[:space:]]*=[[:space:]]*//p' "$B2A_D/kdc.conf.pristine" | head -n 1)
    WORD=aahing; grep -qx "$WORD" "$STOCK" 2> /dev/null || WORD=$(grep -m1 -E '^[a-z]{6,}$' "$STOCK" 2> /dev/null)
    echo "stock_dict $STOCK"
    echo "stock_word $WORD"
    echo "words_bytes $(stat -L -c %s "$STOCK" 2> /dev/null)"
    echo "fifo_writer_pid=$(cat "$W/writer.pid" 2> /dev/null)"
    kill -0 "$(cat "$W/writer.pid" 2> /dev/null)" 2> /dev/null && echo "fifo_writer_alive"
    ls -lZ "$P16"
    b2a_kal addpol 'addpol p16apol'
    b2a_kal addprinc-user "addprinc -pw $PW1 -policy p16apol +requires_preauth p16auser"
    b2a_kal addprinc-nopol "addprinc -pw $PW1 +requires_preauth p16anopol"
    echo "CELL getprinc-user"
    kadmin.local -q 'getprinc p16auser' < /dev/null 2>&1 | grep -E '^(Principal:|Attributes:|Policy:)'
    echo "CELL_END getprinc-user"
    echo "PREP_DONE"
    state
    ;;
side)
    mkdir -p "$W/side-$STAGE/dictdir"
    side_create dir "$W/side-$STAGE/dictdir"
    side_create missing "$W/side-$STAGE/no-such-dict"
    echo "SIDE_DONE_$STAGE"
    ;;
dict)
    if [ "$ARG" = stock ]; then b2a_conf; else b2a_conf realm dict_file "$P16/$ARG.dict"; fi
    if [ "$ARG2" = iso ]; then dropin on; else dropin off; fi
    restart_kadmin 60
    b2a_wait_kadmind || echo "KADMIND_NOT_LISTENING"
    state
    ;;
fifo-enforcing)
    b2a_conf realm dict_file "$P16/fifo.dict"
    dropin off
    echo "dict_file $P16/fifo.dict"
    echo "fifo_writer_pid=$(cat "$W/writer.pid" 2> /dev/null)"
    kill -0 "$(cat "$W/writer.pid" 2> /dev/null)" 2> /dev/null && echo "fifo_writer_alive"
    ls -lZ "$P16/fifo.dict"
    T0=$(date '+%Y-%m-%d %H:%M:%S'); TM=$(date '+%H:%M:%S')
    echo "enforce_before=$(getenforce)"
    if restart_kadmin 40; then echo "fifo_restart_ok enforce=$(getenforce)"; else echo "fifo_restart_failed enforce=$(getenforce)"; fi
    sleep 2
    echo "== journal: kadmin.service since $T0"
    journalctl -u kadmin.service --no-pager --since "$T0" 2>&1 | cut -c1-200
    echo "== end of journal"
    echo "== avc since $TM"
    ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts "$TM" 2>&1 | grep -E 'denied|no matches' | cut -c1-300
    echo "== end of avc"
    ;;
fifo-permissive)
    setenforce 0
    echo "setenforce 0"
    echo "enforce_now=$(getenforce)"
    restart_kadmin 60
    b2a_wait_kadmind || echo "KADMIND_NOT_LISTENING"
    state
    ;;
fifo-nowriter)
    b2a_conf realm dict_file "$P16/fifo-nowriter.dict"
    echo "dict_file $P16/fifo-nowriter.dict"
    echo "restart_begin $(date -u +%FT%TZ)"
    restart_kadmin 25
    echo "restart_rc=$?"
    echo "state_after_timeout=$(systemctl is-active kadmin 2>&1)"
    timeout 30 systemctl stop kadmin > /dev/null 2>&1
    echo "stop_rc=$?"
    ;;
fifo-restore) restore_all ;;
cleanup)
    b2a_kal del-user 'delprinc -force p16auser'
    b2a_kal del-nopol 'delprinc -force p16anopol'
    b2a_kal del-pol 'delpol -force p16apol'
    echo "HISTORY_BEFORE_CLEANUP_END $(hist)"
    if [ "$(cat "$HISTMARK" 2> /dev/null)" = no ] && [ "$(hist)" = yes ]; then   # this stage made kadmin/history: it goes, after the principals that used it
        echo "HISTORY_CREATED_BY_STAGE"
        b2a_kal del-history "delprinc -force $HIST"
    fi
    echo "HISTORY_AT_END $(hist)"
    rm -f "$HISTMARK"
    ;;
clean)
    restore_all
    rm -rf "$P16" "$W"
    echo "P16AE_CLEAN_DONE"
    ;;
*) echo "p16ae-kdc.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
