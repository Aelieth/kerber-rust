#!/bin/bash
# b2a-lib.sh: the VM-side functions of the b2-admin modules (pg7, pg6, bl, p16ae), sourced by their kdc-side scripts: `. "$(dirname "$0")/b2a-lib.sh"`. Pushed by the modules next to the scripts.
# The record format is the packages' own (*-cells.txt): CELL name / RC:n / the output / CELL_END name.
# The paths are the Fedora VM's; VMCTL_* override them for the rehearsals on the host (the same variables vmctl.sh and b2ctl.sh read, plus VMCTL_ALOG, VMCTL_SYSD).
B2A_D=${VMCTL_D:-/var/tmp/otp3}
B2A_KDCDIR=${VMCTL_KDCDIR:-/var/kerberos/krb5kdc}
B2A_ALOG=${VMCTL_ALOG:-/var/log/kadmind.log}
B2A_REALM=${B2A_REALM:-KERBER.TEST}

b2a_filter() { grep -v -e '^Authenticating as principal ' -e '^No policy specified for ' -e '^WARNING: no policy specified for ' || true; }

# b2a_run NAME CMD ARGS...: one cell. The output (stdout and stderr) is kept in a variable, so the command's own exit status is the RC: line (139 is the shell's word for a SEGV).
b2a_run() {
    local n=$1 out rc; shift
    echo "CELL $n"
    out=$("$@" 2>&1 < /dev/null); rc=$?
    echo "RC:$rc"
    printf '%s\n' "$out" | b2a_filter
    echo "CELL_END $n"
}
# b2a_run_in INPUT NAME CMD ARGS...: the same with INPUT (a printf %b string) on the command's stdin; the input is never printed
b2a_run_in() {
    local in=$1 n=$2 out rc; shift 2
    echo "CELL $n"
    out=$(printf '%b' "$in" | "$@" 2>&1); rc=$?
    echo "RC:$rc"
    printf '%s\n' "$out" | b2a_filter
    echo "CELL_END $n"
}
# b2a_kal NAME 'kadmin.local command': one kadmin.local -q cell (the command line may carry a throwaway password: it is not printed; the transcript's header shows the script, not this line)
b2a_kal() { b2a_run "$1" kadmin.local -q "$2"; }
# b2a_kinit NAME PRINC PASSWORD: kinit with the password on its stdin; KINIT_RC and the stderr line (the prompt is stdout and dropped), the ticket cache is removed
b2a_kinit() {
    local n=$1 p=$2 pw=$3 cc err rc
    cc=$B2A_D/kinit-$$-$RANDOM.cc                       # *.cc: the shell's L7 clean (vmctl.sh clean) shreds a leftover
    echo "CELL $n"
    err=$(printf '%s\n' "$pw" | KRB5CCNAME=FILE:$cc kinit "$p" 2>&1 > /dev/null); rc=$?
    echo "KINIT_RC:$rc"
    echo "ERR:$(printf '%s' "$err" | tr '\n' ' ')"
    echo "CELL_END $n"
    KRB5CCNAME=FILE:$cc kdestroy > /dev/null 2>&1; rm -f "$cc"
}

# b2a_conf ARGS...: kdc.conf := the pristine file with the edits (b2a-kdcconf.py): `b2a_conf` alone puts the pristine file back
b2a_conf() { python3 -I "$B2A_D/b2a/b2a-kdcconf.py" "$@"; }
# b2a_unit_state: the two units, in the record's words
b2a_unit_state() { echo "KADMIN:$(systemctl is-active kadmin 2>&1)"; echo "KDC:$(systemctl is-active krb5kdc 2>&1)"; }
# b2a_restart_kadmin LABEL: restart kadmin.service and say what became of it (RESTART_RC, the units); the label names the configuration it ran under
b2a_restart_kadmin() {
    local rc
    systemctl reset-failed kadmin > /dev/null 2>&1       # a unit that failed (MIT's crash) must not trip systemd's start limit on the next restart
    echo "STANZA $1"
    echo "CONF_PLUGINS_LINES:$(grep -c '^\[plugins\]' "$B2A_KDCDIR/kdc.conf" 2>/dev/null)"
    systemctl restart kadmin > /dev/null 2>&1; rc=$?
    echo "RESTART_RC:$rc"
    b2a_unit_state
}
# b2a_wait_kadmind: kadmind has bound :749 (the unit says active before it listens)
b2a_wait_kadmind() { local _; for _ in $(seq 1 50); do ss -H -lnt 'sport = :749' 2>/dev/null | grep -q . && return 0; sleep 0.2; done; return 1; }
# b2a_alog_size / b2a_alog_since N: the kadmind log
b2a_alog_size() { { wc -c < "$B2A_ALOG"; } 2>/dev/null || echo 0; }
b2a_alog_since() { tail -c +$(($1 + 1)) "$B2A_ALOG" 2>/dev/null; }
