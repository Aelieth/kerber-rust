#!/bin/bash
# d3-kdc.sh STAGE SECTION [ARGS]: d3's kdc-side steps, as root: `sudo bash d3-kdc.sh mit|ours SECTION ...`. (lab-agent; module mod/d3.sh "d3-lite": what the Fedora side does with des3)
# stdin: three lines, the leg's throwaway passwords PW1 PW2 PW3 (PW1 is the password of the lab-realm probe principal that has one); library b2a-lib.sh (pushed beside this file).
# Sections:
#   kadmin               the lab realm's own kadmin.local (stock MIT before the upgrade, ours after): what `addprinc -e des3-cbc-sha1:normal` does (a randkey one and a -pw one), an arcfour control (-e works for a type the build has)
#                        and a default control; each principal's getprinc. Principals d3probe d3probepw d3rc4 d3aes (the realm is handed back as found by `cleanup`).
#   init ADDR            the PRIVATE realm D3.TEST under $VMD/d3/r (0700): kdc.conf profile (database, stash, kdc_listen ADDR:$D3_PORT, logging into the lab's KDC log so that the shell's cells slice it), krb5.conf, the stash pushed
#                        beside this file (d3-realm.stash), the dump (d3-realm.dump)
#   load                 kdb5_util load of the dump (the stage's own kdb5_util), its rc and every line it prints; a dump of the loaded DB (the names kept?); getprinc of every principal (the key lists the stage shows)
#   start | stop         the private KDC (the stage's own krb5kdc -n on ADDR:$D3_PORT, setsid, a pid file) | its end
#   heal                 cpw -pw on the des3-only principal desonly (what a password change does to a des3-only principal) and its getprinc
#   cleanup              the private KDC ended, $VMD/d3 shredded and removed, the lab-realm probe principals deleted
# What the realm D3.TEST holds was made by UPSTREAM MIT 1.22.2 (helpers/d3-make-dump.sh); Fedora's build has no des3-cbc-sha1 (krb5_c_valid_enctype is 0 for it), so its kadmin cannot make such keys.
# Rehearsal knobs (the paths are the Fedora VM's): D3_SBIN (the stage's krb5kdc; default /usr/sbin), D3_KLOG (the lab KDC log; default /var/log/krb5kdc.log), D3_DBMOD_DIR ([dbmodules] db_module_dir), D3_PORT (8089), VMCTL_D.
set -u
STAGE=${1:?mit|ours}; SECTION=${2:?section}; shift 2
. "$(dirname "$0")/b2a-lib.sh"
case $STAGE in mit|ours) ;; *) echo "d3-kdc.sh: stage mit|ours" >&2; exit 2 ;; esac
IFS= read -r PW1; IFS= read -r PW2; IFS= read -r PW3
[ -n "$PW1" ] && [ -n "$PW2" ] && [ -n "$PW3" ] || { echo "D3_ABORT no passwords on stdin"; exit 2; }
D=${VMCTL_D:-/var/tmp/otp3}
DD=$D/d3
R=$DD/r
SBIN=${D3_SBIN:-/usr/sbin}
KLOG=${D3_KLOG:-/var/log/krb5kdc.log}
PORT=${D3_PORT:-8089}
REALM=D3.TEST
PRIVNAMES="krbtgt/$REALM desonly desonlyp mixedp aesp rc4onlyp host/svcdes.d3.test host/svcmix.d3.test host/svcaes.d3.test"
PROBES="d3probe d3probepw d3rc4 d3aes"
priv() { env KRB5_KDC_PROFILE="$R/kdc.conf" KRB5_CONFIG="$R/krb5.conf" "$@"; }   # a command of the private realm (both flavors read the profile)
pk() { b2a_run "$1" env KRB5_KDC_PROFILE="$R/kdc.conf" KRB5_CONFIG="$R/krb5.conf" kadmin.local -r $REALM -q "$2"; }
listening() {   # listening PORT SECONDS: a TCP listener on PORT within SECONDS
    local _
    for _ in $(seq 1 $(( $2 * 5 ))); do
        ss -H -lnt "sport = :$1" 2> /dev/null | grep -q . && return 0
        sleep 0.2
    done
    return 1
}
stop_pid() {   # stop_pid PIDFILE
    local f=$1 pid _
    [ -s "$f" ] || return 0
    pid=$(cat "$f")
    if kill -0 "$pid" 2> /dev/null; then
        kill "$pid" 2> /dev/null
        for _ in $(seq 1 25); do kill -0 "$pid" 2> /dev/null || break; sleep 0.2; done
        kill -0 "$pid" 2> /dev/null && kill -9 "$pid" 2> /dev/null
    fi
    rm -f "$f"
}
case $SECTION in
kadmin)
    echo "== facts"
    sha256sum "$SBIN/krb5kdc" /usr/sbin/kadmin.local /usr/sbin/kdb5_util 2>&1
    command -v kadmin.local
    b2a_kal add-randkey 'addprinc -randkey -e des3-cbc-sha1:normal d3probe'
    b2a_kal get-randkey 'getprinc d3probe'
    b2a_kal add-pw "addprinc -pw $PW1 -e des3-cbc-sha1:normal d3probepw"
    b2a_kal get-pw 'getprinc d3probepw'
    b2a_kal add-rc4 'addprinc -randkey -e arcfour-hmac:normal d3rc4'
    b2a_kal get-rc4 'getprinc d3rc4'
    b2a_kal add-default 'addprinc -randkey d3aes'
    b2a_kal get-default 'getprinc d3aes'
    ;;
init)
    addr=${1:?address}
    install -d -m 0700 "$DD" "$R"
    cp -p "$DD/d3-realm.stash" "$R/stash" && chmod 600 "$R/stash"
    cat > "$R/kdc.conf" <<EOF
[kdcdefaults]
    kdc_listen = $addr:$PORT
    kdc_tcp_listen = $addr:$PORT

[realms]
    $REALM = {
        database_name = $R/principal
        key_stash_file = $R/stash
        master_key_type = aes256-cts-hmac-sha384-192
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
EOF
    {
        cat <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false

[realms]
    $REALM = {
        kdc = $addr:$PORT
    }

[logging]
    kdc = FILE:$KLOG
    default = FILE:$R/default.log
EOF
        [ -n "${D3_DBMOD_DIR:-}" ] && printf '\n[dbmodules]\n    db_module_dir = %s\n' "$D3_DBMOD_DIR"
    } > "$R/krb5.conf"
    chmod 600 "$R/kdc.conf" "$R/krb5.conf"
    echo "== kdc.conf"; sed "s#$R/#R/#g" "$R/kdc.conf"
    echo "INIT_OK $addr:$PORT"
    echo "listeners on $PORT before: $(ss -H -lnt "sport = :$PORT" 2> /dev/null | wc -l)"
    ;;
load)
    echo "CELL load"
    out=$(priv kdb5_util load "$DD/d3-realm.dump" 2>&1 < /dev/null); rc=$?
    echo "LOAD_RC:$rc"
    printf '%s\n' "$out" | b2a_filter | sed "s#$R/#R/#g; s#$DD/#D3/#g"
    echo "CELL_END load"
    echo "DB_FILES: $(find "$R" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ')"
    echo "CELL dump-after-load"
    priv kdb5_util dump "$R/after.dump" 2>&1 < /dev/null | sed "s#$R/#R/#g"; echo "DUMP_RC:${PIPESTATUS[0]}"
    names() { grep '^princ' "$1" 2> /dev/null | awk -F'\t' '{ print $7 }' | LC_ALL=C sort; }
    names "$DD/d3-realm.dump" > "$R/names.orig"; names "$R/after.dump" > "$R/names.after"
    echo "PRINCS_ORIGINAL:$(grep -c . "$R/names.orig") PRINCS_AFTER:$(grep -c . "$R/names.after") NAMES_SAME:$(cmp -s "$R/names.orig" "$R/names.after" && echo yes || echo no)"
    echo "KEYS_PER_PRINCIPAL_ORIGINAL: $(grep '^princ' "$DD/d3-realm.dump" | awk -F'\t' '{ printf "%s=%s ", $7, $5 }' | sed "s/@$REALM//g")"
    echo "KEYS_PER_PRINCIPAL_AFTER:    $(grep '^princ' "$R/after.dump" | awk -F'\t' '{ printf "%s=%s ", $7, $5 }' | sed "s/@$REALM//g")"
    echo "CELL_END dump-after-load"
    shred -u "$R/after.dump" 2> /dev/null; rm -f "$R/after.dump.dump_ok"
    for p in $PRIVNAMES; do pk "getprinc-${p//\//_}" "getprinc $p"; done
    ;;
start)
    rm -f "$R/kdc.pid" "$R/kdc.run" "$R/kdc.out"
    KRB5_KDC_PROFILE="$R/kdc.conf" KRB5_CONFIG="$R/krb5.conf" setsid nohup "$SBIN/krb5kdc" -r $REALM -n -P "$R/kdc.pid" > "$R/kdc.out" 2>&1 < /dev/null &
    echo $! > "$R/kdc.run"
    if listening "$PORT" 20; then echo "KDC_LISTENING $PORT pid $(cat "$R/kdc.run")"; else echo "KDC_NOT_LISTENING $PORT"; echo "== kdc.out"; sed "s#$R/#R/#g" "$R/kdc.out" 2>&1; fi
    echo "LISTENERS_ON_PORT: $(ss -H -lnt "sport = :$PORT" 2> /dev/null | wc -l) tcp, $(ss -H -lnu "sport = :$PORT" 2> /dev/null | wc -l) udp"
    ;;
heal)
    pk heal-cpw "cpw -pw $PW2 desonly"
    pk heal-getprinc 'getprinc desonly'
    ;;
stop)
    stop_pid "$R/kdc.run"; stop_pid "$R/kdc.pid"
    echo "== listeners on $PORT after: $(ss -H -lnt "sport = :$PORT" 2> /dev/null | wc -l)"
    ;;
cleanup)
    stop_pid "$R/kdc.run"; stop_pid "$R/kdc.pid"
    shred -u "$R/stash" "$R"/principal* "$DD"/d3-realm.* "$DD"/*.keytab 2> /dev/null
    rm -rf "$DD"
    echo "PRIVATE_DIR_GONE: $([ -e "$DD" ] && echo no || echo yes)"
    for n in $PROBES; do b2a_kal "del-$n" "delprinc -force $n"; done
    b2a_kal getprinc-gone 'getprinc d3probe'
    echo "LISTENERS_ON_PORT_AFTER: $(ss -H -lnt "sport = :$PORT" 2> /dev/null | wc -l)"
    ;;
*) echo "d3-kdc.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
