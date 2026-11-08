#!/bin/bash
# d3-mitd3.sh STAGE SECTION [ARGS]: d3's steps ON mitd3, the lab VM that carries upstream MIT krb5 1.22.2 (built from the release tarball under $D3_MITROOT, /opt/mit-1.22.2) and nothing of Fedora's krb5-server.
# (lab agent; module mod/d3.sh, cell 3 "the des3 proof of record on a real lab VM, MIT first".) Sections that make or change a realm run as root (`sudo bash d3-mitd3.sh mit|ours SECTION ...`); `run` and `keyparity` run as the lab user.
# stdin of the sections that take passwords: three lines, the leg's throwaway passwords PW1 PW2 PW3.
#   facts                 the build's brand (krb5-config --version, klist -V), RUNPATH, the SELinux labels, getenforce, the listeners on the KDC ports
#   realm-init            (provisioning, once) the permanent realm D3.TEST: $MR/etc/krb5.conf, $MR/var/krb5kdc/{kdc.conf,kadm5.acl}, the DB and its stash (kdb5_util create -s, a random throwaway master password); the realm is empty
#   conf                  the client profiles in $D3M/conf: def des3 aesdes3 encts (default permissions) wdef wdes3 waesdes3 wencts wd3 (allow_weak_crypto, allow_des3, allow_rc4; wd3: des3 for the TGT and the service tickets) old oldd (the B25 realm's port; oldd offers des3)
#   mit-setup-a           (MIT stage) set A: krbtgt with a des3 key, desonly, desonlyp, mixedp, aesp, the services svcdes, svcmix, svcaes, made by MIT's kadmin.local; the keytabs in $D3M/kt (owned by the lab user)
#   dump                  (MIT stage, after set A) kdb5_util dump -> $D3M/mit.dump (set A only); its size and sha256 prefix
#   mit-setup-b           (MIT stage) set B: nd-desonly, nd-desonlyp, nd-mixedp, the services nd-svcdes, nd-svcmix, made by MIT's kadmin.local (the ours stage makes its own with our kadmin.local)
#   ours-load             (ours stage) install.md's `krb5-kdb load` of MIT's dump (pushed to $D3M/mit.dump) into $OURS, with the permanent realm's stash; set A as the load made it
#   ours-setup            (ours stage) set B made by OUR kadmin.local (new des3 keys: facet ii), the keytabs
#   ours-dump             (ours stage) our krb5-kdb dump -> $D3M/ours.dump;  mit-reload: upstream's kdb5_util load of it into $MITRE (a scratch MIT DB, the same stash)
#   getprinc              getprinc of every principal of both sets with the stage's own kadmin.local (RELOAD=1: MIT's, on the reloaded DB)
#   old-init              (B25) the scratch realm of a DB made by an OLD build: $OLD with its profile (port $D3_OLDPORT); the stash and the dump were pushed to $OLD/stash and $OLD/old.dump;  old-load: the stage's own load of it
#   base-load             (ours stage, the wire cell) the UNFIXED build's krb5-kdb ($SHIPBASE, pushed by the module) loads MIT's dump into $BASE; kdc-start base [weak] serves it with the unfixed krb5-kdc on $D3_BASEPORT
#   flipkt SRC DST        (as the lab user) DST := the keytab SRC with the parity bit of octet 3 of its des3 key flipped (the client-side bad key); only counts are printed
#   kdc-start [mitre|old|base] [weak]   the stage's KDC (MIT's krb5kdc from $MR, or our krb5-kdc from $SHIP) on $D3_ADDR:$D3_KPORT ($D3_OLDPORT for old); `weak`: its krb5.conf has allow_weak_crypto, allow_des3 and allow_rc4;
#                         `mitre`: MIT's krb5kdc on the reloaded DB; `old`: the stage's KDC on the old build's DB
#   kdc-stop
#   run LOG [K=V ...] -- CMD1 ARGS... [-- CMD2 ARGS...]   (as the lab user) CMD1 with the caller's stdin, then each further command (stdin /dev/null) only while the earlier ones exited 0; per command [rc=N], == stdout, == stderr; and
#                         == kdc log: the lines the KDC log gained during the run (LOG auto = the log of the KDC kdc-start started). A program `mit:kinit` is $MR/bin/kinit, `ours:kinit` is $SHIP/krb5-kinit; a command
#                         `gss:SERVICE` runs MIT's sample acceptor (gss-server, KRB5_KTNAME from the K=V list) and initiator (gss-client) against each other on the VM, the client's words first, then the server's.
#                         K=V CCFROM=FILE: a ticket cache copied to $KRB5CCNAME's file before the run
#   keyparity KEYTAB...   (as the lab user) per des3 entry of each keytab, the octets of the key whose parity is even (MIT's klist -k -K -e); the key itself is never printed
#   avc                   getenforce and the SELinux denials since boot (a count and the distinct ones)
#   clean                 the KDC ended, the keytabs, dumps and databases shredded, $D3M removed
# Rehearsal knobs (the paths are the VM's): D3_MITROOT, D3_LDPATH (LD_LIBRARY_PATH for a stand-in unpacked elsewhere than its prefix), D3_DBMOD_DIR ([dbmodules] db_module_dir), D3_ADDR, D3_KPORT, D3_OLDPORT, D3_GSSPORT,
# D3_LABUSER, VMCTL_D.
set -u
STAGE=${1:?mit|ours}; SECTION=${2:?section}; shift 2
case $STAGE in mit|ours) ;; *) echo "d3-mitd3.sh: stage mit|ours" >&2; exit 2 ;; esac
[ "$SECTION" = getprinc-re ] && { RELOAD=1; SECTION=getprinc; }   # getprinc-re: upstream's kadmin.local on the DB it loaded from our dump
D=${VMCTL_D:-/var/tmp/otp3}
D3M=$D/d3m
MR=${D3_MITROOT:-/opt/mit-1.22.2}
RC=$MR/etc/krb5.conf
KDIR=$MR/var/krb5kdc
KC=$KDIR/kdc.conf
REALM=D3.TEST
ADDR=${D3_ADDR:?D3_ADDR is not set}
KPORT=${D3_KPORT:-88}
OLDPORT=${D3_OLDPORT:-8091}
GSSPORT=${D3_GSSPORT:-4455}
SHIP=$D3M/ship
OURS=$D3M/ours
MITRE=$D3M/mitre
OLD=$D3M/old
BASE=$D3M/base
BASEPORT=${D3_BASEPORT:-8092}
SHIPBASE=$D3M/shipbase
LABUSER=${D3_LABUSER:-lab}
KT=$D3M/kt
CONF=$D3M/conf
STASH=$KDIR/.k5.$REALM
[ -n "${D3_LDPATH:-}" ] && export LD_LIBRARY_PATH=$D3_LDPATH
export PATH="$MR/bin:$MR/sbin:$PATH"
AES4=aes256-cts-hmac-sha384-192:normal,aes128-cts-hmac-sha256-128:normal,aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal
DES3=des3-cbc-sha1:normal
MIX=aes256-cts-hmac-sha1-96:normal,des3-cbc-sha1:normal,arcfour-hmac:normal
SETA="krbtgt/$REALM desonly desonlyp mixedp aesp host/svcdes.d3.test host/svcmix.d3.test host/svcaes.d3.test"
SETB="nd-desonly nd-desonlyp nd-mixedp host/nd-svcdes.d3.test host/nd-svcmix.d3.test"

# the programs of the stage: MIT's from the build under $MR, ours from the ship the module pushed to $SHIP (ours use the profile of a copy that names our database)
if [ "$STAGE" = mit ]; then
    PKC=$KC; PRC=$RC; KADM=$MR/sbin/kadmin.local; KLOG=$MR/var/log/krb5kdc.log; LOADER=$MR/sbin/kdb5_util; DUMPER=$MR/sbin/kdb5_util
else
    PKC=$OURS/kdc.conf; PRC=$OURS/krb5.conf; KADM=$SHIP/krb5-kadmin-local; KLOG=$OURS/kdc.log; LOADER=$SHIP/krb5-kdb; DUMPER=$SHIP/krb5-kdb
fi
if [ "${RELOAD:-0}" = 1 ]; then PKC=$MITRE/kdc.conf; PRC=$MITRE/krb5.conf; KADM=$MR/sbin/kadmin.local; fi
kadm() { env KRB5_KDC_PROFILE="$PKC" KRB5_CONFIG="$PRC" "$KADM" -r $REALM -q "$1" 2>&1 | grep -v -e '^Authenticating' -e 'No policy specified' -e 'dictionary file'; }
listening() {   # listening PORT SECONDS
    local _
    for _ in $(seq 1 $(( $2 * 5 ))); do
        ss -H -lnt "sport = :$1" 2> /dev/null | grep -q . && return 0
        sleep 0.2
    done
    return 1
}
stop_pid() {
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
profile_files() {   # profile_files DIR KDCLOG DBNAME PORT STASHFILE: kdc.conf and krb5.conf of a realm's KDC under DIR
    local dir=$1 klog=$2 db=$3 port=$4 stash=$5
    {
        cat <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    dns_canonicalize_hostname = false
    rdns = false

[realms]
    $REALM = {
        kdc = $ADDR:$port
    }

[logging]
    kdc = FILE:$klog
    admin_server = FILE:$dir/kadmin.log
    default = FILE:$dir/default.log
EOF
        [ -n "${D3_DBMOD_DIR:-}" ] && printf '\n[dbmodules]\n    db_module_dir = %s\n' "$D3_DBMOD_DIR"
    } > "$dir/krb5.conf"
    cat > "$dir/kdc.conf" <<EOF
[kdcdefaults]
    kdc_listen = $ADDR:$port
    kdc_tcp_listen = $ADDR:$port

[realms]
    $REALM = {
        database_name = $db
        key_stash_file = $stash
        acl_file = $KDIR/kadm5.acl
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        master_key_type = aes256-cts-hmac-sha1-96
        supported_enctypes = $(printf '%s' "$AES4" | tr ',' ' ')
    }
EOF
}
make_a() {   # make_a PW: set A with the stage's kadmin.local (MIT's in the MIT stage); keytabs for the three services
    local pw=$1
    kadm "cpw -randkey -e $AES4,$DES3,arcfour-hmac:normal krbtgt/$REALM"
    kadm "addprinc -pw $pw -e $DES3 desonly"
    kadm "addprinc -pw $pw -e $DES3 +requires_preauth desonlyp"
    kadm "addprinc -pw $pw -e $MIX +requires_preauth mixedp"
    kadm "addprinc -pw $pw +requires_preauth aesp"
    kadm "addprinc -randkey -e $DES3 host/svcdes.d3.test"
    kadm "addprinc -randkey -e $MIX host/svcmix.d3.test"
    kadm "addprinc -randkey host/svcaes.d3.test"
    kadm "ktadd -k $KT/svcdes.keytab -e $DES3 host/svcdes.d3.test"
    kadm "ktadd -k $KT/svcmix.keytab -e $MIX host/svcmix.d3.test"
    kadm "ktadd -k $KT/svcaes.keytab host/svcaes.d3.test"
    kadm "addprinc -randkey -e $DES3 bpk"
    kadm "addprinc -randkey -e $DES3 +requires_preauth bpkp"
    kadm "addprinc -pw $pw okpw"
    kadm "ktadd -norandkey -k $KT/bpk.keytab bpk"
    kadm "ktadd -norandkey -k $KT/bpkp.keytab bpkp"
}
make_b() {   # make_b PW: set B, the same kinds under new names, with the stage's own kadmin.local (ours in the ours stage: keys our tool makes)
    local pw=$1
    kadm "addprinc -pw $pw -e $DES3 -requires_preauth nd-desonly"
    kadm "addprinc -pw $pw -e $DES3 +requires_preauth nd-desonlyp"
    kadm "addprinc -pw $pw -e $MIX +requires_preauth nd-mixedp"
    kadm "addprinc -randkey -e $DES3 host/nd-svcdes.d3.test"
    kadm "addprinc -randkey -e $MIX host/nd-svcmix.d3.test"
    kadm "ktadd -k $KT/nd-svcdes.keytab -e $DES3 host/nd-svcdes.d3.test"
    kadm "ktadd -k $KT/nd-svcmix.keytab -e $MIX host/nd-svcmix.d3.test"
}
readpw() { IFS= read -r PW1; IFS= read -r PW2; IFS= read -r PW3; [ -n "$PW1" ] && [ -n "$PW2" ] && [ -n "$PW3" ] || { echo "D3M_ABORT no passwords on stdin"; exit 2; }; }
cell_open() { echo "CELL $1"; }
cell_close() { echo "CELL_END $1"; }
mkconf() {   # mkconf NAME BASE LINES...: $CONF/NAME.conf := BASE with the lines first under [libdefaults] (the first value of a relation wins)
    local base=$2 f="$CONF/$1.conf" l
    shift 2
    {
        printf '[libdefaults]\n'
        for l in "$@"; do printf '    %s\n' "$l"; done
        sed '1{/^\[libdefaults\]/d}' "$base"
    } > "$f"
    chmod 644 "$f"
}
parity_even() {   # parity_even HEXKEY: the number of octets whose bit count is even (a DES key octet must have an odd one)
    local hex=$1 i b j c even=0
    for ((i = 0; i + 1 < ${#hex}; i += 2)); do
        b=$((16#${hex:i:2})); c=0
        for ((j = 0; j < 8; j++)); do c=$((c + ((b >> j) & 1))); done
        [ $((c % 2)) = 0 ] && even=$((even + 1))
    done
    echo "$even"
}

case $SECTION in
facts)
    echo "== brand"
    echo "krb5-config --version: $(krb5-config --version 2>&1)"
    echo "krb5-config --prefix: $(krb5-config --prefix 2>&1)"
    echo "klist -V: $(klist -V 2>&1 | head -n 2 | tr '\n' ' ')"
    echo "RUNPATH of kinit: $(readelf -d "$MR/bin/kinit" 2>/dev/null | grep -E 'RPATH|RUNPATH' | sed 's/.*\[\(.*\)\]/\1/')"
    echo "== where it is"
    command -v kinit kadmin.local krb5kdc kdb5_util
    ls -ldZ "$MR" "$MR/bin/kinit" "$MR/sbin/krb5kdc" "$MR/lib/libkrb5.so.3" "$KDIR" 2>&1
    echo "getenforce: $(getenforce 2>&1)"
    echo "krb5-server installed: $(rpm -q krb5-server 2>&1 | head -n 1)"
    echo "krb5-workstation installed: $(rpm -q krb5-workstation 2>&1 | head -n 1)"
    echo "listeners on $KPORT: $(ss -H -lnt "sport = :$KPORT" 2> /dev/null | wc -l); on $OLDPORT: $(ss -H -lnt "sport = :$OLDPORT" 2> /dev/null | wc -l); on $GSSPORT: $(ss -H -lnt "sport = :$GSSPORT" 2> /dev/null | wc -l)"
    echo "== the stage's programs"
    sha256sum "$KADM" "$LOADER" 2>&1
    ;;
realm-init)
    install -d -m 0755 "$MR/etc" "$KDIR" "$MR/var/log"
    mkdir -p "$D3M.rinit"
    profile_files "$D3M.rinit" "$MR/var/log/krb5kdc.log" "$KDIR/principal" "$KPORT" "$STASH"
    sed -i "s#^    admin_server = FILE:.*#    admin_server = FILE:$MR/var/log/kadmin.log#; s#^    default = FILE:.*#    default = FILE:$MR/var/log/krb5lib.log#" "$D3M.rinit/krb5.conf"
    cp "$D3M.rinit/krb5.conf" "$RC"; cp "$D3M.rinit/kdc.conf" "$KC"; rm -rf "$D3M.rinit"
    echo "*/admin@$REALM *" > "$KDIR/kadm5.acl"
    chmod 644 "$RC" "$KC" "$KDIR/kadm5.acl"
    echo "== $RC"; cat "$RC"
    echo "== $KC"; cat "$KC"
    env KRB5_CONFIG="$RC" KRB5_KDC_PROFILE="$KC" kdb5_util create -s -P "$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')" -r $REALM 2>&1 | tail -n 3
    echo "CREATE_RC:${PIPESTATUS[0]}"
    chmod 755 "$KDIR"; ls -la "$KDIR"
    echo "== the realm as made (no test principals)"
    kadm "listprincs"
    ;;
conf)
    install -d -m 0755 -o "$LABUSER" "$D3M" 2> /dev/null; install -d -m 0755 -o "$LABUSER" "$CONF"
    mkconf def "$RC"
    mkconf des3 "$RC" "default_tkt_enctypes = des3-cbc-sha1"
    mkconf aesdes3 "$RC" "default_tkt_enctypes = aes256-cts-hmac-sha1-96 des3-cbc-sha1"
    mkconf encts "$RC" "default_tkt_enctypes = des3-cbc-sha1 aes256-cts-hmac-sha1-96 arcfour-hmac" "preferred_preauth_types = 2"
    WK="allow_weak_crypto = true"
    mkconf wdef "$RC" "$WK" "allow_des3 = true" "allow_rc4 = true"
    mkconf wdes3 "$RC" "$WK" "allow_des3 = true" "allow_rc4 = true" "default_tkt_enctypes = des3-cbc-sha1"
    mkconf waesdes3 "$RC" "$WK" "allow_des3 = true" "allow_rc4 = true" "default_tkt_enctypes = aes256-cts-hmac-sha1-96 des3-cbc-sha1"
    mkconf wencts "$RC" "$WK" "allow_des3 = true" "allow_rc4 = true" "default_tkt_enctypes = des3-cbc-sha1 aes256-cts-hmac-sha1-96 arcfour-hmac" "preferred_preauth_types = 2"
    mkconf wd3 "$RC" "$WK" "allow_des3 = true" "allow_rc4 = true" "default_tkt_enctypes = des3-cbc-sha1" "default_tgs_enctypes = des3-cbc-sha1"
    sed "s#^        kdc = .*#        kdc = $ADDR:$OLDPORT#" "$CONF/def.conf" > "$CONF/old.conf"; chmod 644 "$CONF/old.conf"
    mkconf oldd "$CONF/old.conf" "default_tkt_enctypes = aes256-cts-hmac-sha1-96 des3-cbc-sha1"
    mkconf wold "$CONF/old.conf" "$WK" "allow_des3 = true" "allow_rc4 = true"
    mkconf woldd "$CONF/old.conf" "$WK" "allow_des3 = true" "allow_rc4 = true" "default_tkt_enctypes = aes256-cts-hmac-sha1-96 des3-cbc-sha1"
    mkconf woldd3 "$CONF/old.conf" "$WK" "allow_des3 = true" "allow_rc4 = true" "default_tkt_enctypes = des3-cbc-sha1"
    mkconf wmixed "$RC" "$WK" "allow_des3 = true" "allow_rc4 = true" "default_tkt_enctypes = des3-cbc-sha1 aes256-cts-hmac-sha1-96"
    mkconf tkt128 "$RC" "default_tkt_enctypes = aes128-cts-hmac-sha1-96"
    mkconf tgs256 "$RC" "default_tgs_enctypes = aes256-cts-hmac-sha1-96"
    mkconf tktnosuch "$RC" "default_tkt_enctypes = nosuch-enctype"
    mkconf tgsnosuch "$RC" "default_tgs_enctypes = nosuch-enctype"
    mkconf mixed "$RC" "default_tkt_enctypes = des3-cbc-sha1 aes256-cts-hmac-sha1-96"
    mkconf tgsdes3 "$RC" "allow_weak_crypto = true" "allow_des3 = true" "allow_rc4 = true" "default_tgs_enctypes = des3-cbc-sha1 aes256-cts-hmac-sha1-96"
    mkconf rank-aesfirst "$CONF/wdef.conf" "default_tgs_enctypes = aes256-cts-hmac-sha1-96 des3-cbc-sha1"
    mkconf rank-desfirst "$CONF/wdef.conf" "default_tgs_enctypes = des3-cbc-sha1 aes256-cts-hmac-sha1-96"
    sed "s#^        kdc = .*#        kdc = $ADDR:$BASEPORT#" "$CONF/wmixed.conf" > "$CONF/wmixedb.conf"; chmod 644 "$CONF/wmixedb.conf"
    echo "CONF_PROFILES: $(find "$CONF" -maxdepth 1 -type f -printf '%f ' | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ')"
    ;;
mit-setup-a)
    readpw
    install -d -m 0755 -o "$LABUSER" "$D3M" 2> /dev/null; install -d -m 0700 -o "$LABUSER" "$KT"
    cell_open make-a; make_a "$PW1"; cell_close make-a
    chown "$LABUSER" "$KT"/*.keytab; chmod 600 "$KT"/*.keytab
    ;;
mit-setup-b)
    readpw
    cell_open make-b; make_b "$PW1"; cell_close make-b
    chown "$LABUSER" "$KT"/*.keytab; chmod 600 "$KT"/*.keytab
    ;;
dump)
    cell_open dump
    env KRB5_KDC_PROFILE="$KC" KRB5_CONFIG="$RC" "$DUMPER" dump "$D3M/mit.dump" 2>&1; echo "DUMP_RC:$?"
    echo "DUMP_BYTES:$(stat -c %s "$D3M/mit.dump" 2>/dev/null) DUMP_PRINCS:$(grep -c '^princ' "$D3M/mit.dump" 2>/dev/null) DUMP_SHA16:$(sha256sum < "$D3M/mit.dump" | cut -c1-16)"
    chown "$LABUSER" "$D3M/mit.dump"; chmod 600 "$D3M/mit.dump"
    cell_close dump
    ;;
ours-load)
    install -d -m 0755 -o "$LABUSER" "$D3M" 2> /dev/null; install -d -m 0700 -o "$LABUSER" "$KT"
    install -d -m 0755 "$OURS"
    profile_files "$OURS" "$OURS/kdc.log" "$OURS/principal" "$KPORT" "$STASH"
    : > "$OURS/kdc.log"; chmod 644 "$OURS/kdc.log" "$OURS/krb5.conf" "$OURS/kdc.conf"
    cell_open load
    env KRB5_KDC_PROFILE="$PKC" KRB5_CONFIG="$PRC" "$LOADER" load "$D3M/mit.dump" 2>&1 < /dev/null; echo "LOAD_RC:$?"
    cell_close load
    echo "DB_FILES: $(find "$OURS" -mindepth 1 -maxdepth 1 -printf '%f ')"
    ;;
ours-setup)
    readpw
    cell_open make-b; make_b "$PW1"; cell_close make-b
    chown "$LABUSER" "$KT"/*.keytab; chmod 600 "$KT"/*.keytab
    ;;
ours-dump)
    cell_open ours-dump
    env KRB5_KDC_PROFILE="$PKC" KRB5_CONFIG="$PRC" "$DUMPER" dump "$D3M/ours.dump" 2>&1 < /dev/null; echo "DUMP_RC:$?"
    echo "DUMP_BYTES:$(stat -c %s "$D3M/ours.dump" 2>/dev/null) DUMP_PRINCS:$(grep -c '^princ' "$D3M/ours.dump" 2>/dev/null) DUMP_SHA16:$(sha256sum < "$D3M/ours.dump" | cut -c1-16)"
    chown "$LABUSER" "$D3M/ours.dump"; chmod 600 "$D3M/ours.dump"
    cell_close ours-dump
    ;;
mit-reload)
    install -d -m 0755 "$MITRE"
    profile_files "$MITRE" "$MITRE/kdc.log" "$MITRE/principal" "$KPORT" "$STASH"
    : > "$MITRE/kdc.log"; chmod 644 "$MITRE/kdc.log" "$MITRE/krb5.conf" "$MITRE/kdc.conf"
    cell_open mit-reload
    env KRB5_KDC_PROFILE="$MITRE/kdc.conf" KRB5_CONFIG="$MITRE/krb5.conf" "$MR/sbin/kdb5_util" load "$D3M/ours.dump" 2>&1 < /dev/null; echo "LOAD_RC:$?"
    cell_close mit-reload
    echo "DB_FILES: $(find "$MITRE" -mindepth 1 -maxdepth 1 -printf '%f ')"
    ;;
getprinc)
    for p in $SETA $SETB; do
        cell_open "getprinc-${p//\//_}"
        kadm "getprinc $p" | grep -E '^Principal:|Number of keys|^Key:|^Attributes:|rror|not found'
        cell_close "getprinc-${p//\//_}"
    done
    ;;
old-init)
    install -d -m 0755 -o "$LABUSER" "$D3M" 2> /dev/null
    install -d -m 0755 "$OLD"
    profile_files "$OLD" "$OLD/kdc.log" "$OLD/principal" "$OLDPORT" "$OLD/stash"
    : > "$OLD/kdc.log"; chmod 644 "$OLD/kdc.log" "$OLD/krb5.conf" "$OLD/kdc.conf"
    echo "OLD_INIT_OK $ADDR:$OLDPORT"
    ;;
old-load)
    cell_open old-load
    env KRB5_KDC_PROFILE="$OLD/kdc.conf" KRB5_CONFIG="$OLD/krb5.conf" "$LOADER" load "$OLD/old.dump" 2>&1 < /dev/null; echo "LOAD_RC:$?"
    cell_close old-load
    echo "DB_FILES: $(find "$OLD" -mindepth 1 -maxdepth 1 -printf '%f ')"
    for p in krbtgt/$REALM olduser olddes host/oldsvc.d3.test host/oldmix.d3.test host/oldaes.d3.test oldrnd oldrndp; do
        cell_open "old-getprinc-${p//\//_}"
        env KRB5_KDC_PROFILE="$OLD/kdc.conf" KRB5_CONFIG="$OLD/krb5.conf" "$KADM" -r $REALM -q "getprinc $p" 2>&1 | grep -E '^Principal:|Number of keys|^Key:|^Attributes:|rror|not found'
        cell_close "old-getprinc-${p//\//_}"
    done
    ;;
base-load)
    install -d -m 0755 "$BASE"
    profile_files "$BASE" "$BASE/kdc.log" "$BASE/principal" "$BASEPORT" "$STASH"
    : > "$BASE/kdc.log"; chmod 644 "$BASE/kdc.log" "$BASE/krb5.conf" "$BASE/kdc.conf"
    cell_open base-load
    env KRB5_KDC_PROFILE="$BASE/kdc.conf" KRB5_CONFIG="$BASE/krb5.conf" "$SHIPBASE/krb5-kdb" load "$D3M/mit.dump" 2>&1 < /dev/null; echo "LOAD_RC:$?"
    cell_close base-load
    echo "BASE_PROGRAMS: $(sha256sum "$SHIPBASE/krb5-kdc" "$SHIPBASE/krb5-kdb" | cut -c1-12 | paste -sd' ' -)"
    ;;
flipkt)   # flipkt SRC DST: DST := the keytab SRC with the parity bit (bit 0) of octet 3 of its des3 key flipped; the counts of even-parity octets, never the key
    python3 - "$1" "$2" <<'PYEOF'
import re, subprocess, sys
src, dst = sys.argv[1], sys.argv[2]
out = subprocess.run(["klist", "-k", "-K", "-e", src], capture_output=True, text=True).stdout
m = re.search(r"des3.*\(0x([0-9a-f]{48})\)", out)
if not m:
    print("FLIPKT %s: no des3 key" % src); sys.exit(1)
key = bytes.fromhex(m.group(1))
data = open(src, "rb").read()
at = data.find(key)
if at < 0 or data.count(key) != 1:
    print("FLIPKT %s: the key is not found exactly once in the file" % src); sys.exit(1)
even = lambda b: sum(1 for x in b if bin(x).count("1") % 2 == 0)
bad = bytearray(data); bad[at + 3] ^= 1
open(dst, "wb").write(bytes(bad))
out2 = subprocess.run(["klist", "-k", "-K", "-e", dst], capture_output=True, text=True).stdout
m2 = re.search(r"des3.*\(0x([0-9a-f]{48})\)", out2)
key2 = bytes.fromhex(m2.group(1))
print("FLIPKT %s -> %s: %d octets, even-parity octets before %d, after %d" % (src.rsplit("/", 1)[-1], dst.rsplit("/", 1)[-1], len(key2), even(key), even(key2)))
PYEOF
    ;;
kdc-start)
    mode=" $* "
    rm -f "$D3M/kdc.pid" "$D3M/kdc.run" "$D3M/kdc.out"
    kprof=$PKC; kconf=$PRC; kprog=$SHIP/krb5-kdc; klog=$KLOG; lport=$KPORT
    [ "$STAGE" = mit ] && kprog=$MR/sbin/krb5kdc
    case $mode in
        *" mitre "*) kprof=$MITRE/kdc.conf; kconf=$MITRE/krb5.conf; kprog=$MR/sbin/krb5kdc; klog=$MITRE/kdc.log ;;
        *" old "*) kprof=$OLD/kdc.conf; kconf=$OLD/krb5.conf; klog=$OLD/kdc.log; lport=$OLDPORT ;;
        *" base "*) kprof=$BASE/kdc.conf; kconf=$BASE/krb5.conf; kprog=$SHIPBASE/krb5-kdc; klog=$BASE/kdc.log; lport=$BASEPORT ;;
    esac
    case $mode in
        *" weak "*) { printf '[libdefaults]\n    allow_weak_crypto = true\n    allow_des3 = true\n    allow_rc4 = true\n'; sed '1{/^\[libdefaults\]/d}' "$kconf"; } > "$CONF/kdc-weak.conf"
                    chmod 644 "$CONF/kdc-weak.conf"; kconf=$CONF/kdc-weak.conf ;;
    esac
    echo "$klog" > "$D3M/kdc.logpath"
    env KRB5_KDC_PROFILE="$kprof" KRB5_CONFIG="$kconf" setsid nohup "$kprog" -r $REALM -n -P "$D3M/kdc.pid" > "$D3M/kdc.out" 2>&1 < /dev/null &
    echo $! > "$D3M/kdc.run"
    echo "$lport" > "$D3M/kdc.port"
    if listening "$lport" 20; then echo "KDC_LISTENING $ADDR:$lport pid $(cat "$D3M/kdc.run") mode${mode% }"; else echo "KDC_NOT_LISTENING $lport"; echo "== kdc.out"; cat "$D3M/kdc.out" 2>&1; fi
    chmod 644 "$klog" 2> /dev/null
    echo "KDC_PROGRAM: ${kprog##*/}"
    ;;
kdc-stop)
    lport=$(cat "$D3M/kdc.port" 2> /dev/null || echo "$KPORT")
    stop_pid "$D3M/kdc.run"; stop_pid "$D3M/kdc.pid"
    echo "== listeners on $lport after: $(ss -H -lnt "sport = :$lport" 2> /dev/null | wc -l)"
    ;;
run)
    log=${1:?kdc log}; shift
    [ "$log" = auto ] && log=$(cat "$D3M/kdc.logpath" 2> /dev/null)
    envs=(); ccfrom=""
    while [ $# -gt 0 ] && [ "$1" != -- ]; do
        case $1 in CCFROM=*) ccfrom=${1#CCFROM=} ;; *) envs+=("$1") ;; esac
        shift
    done
    [ "${1:-}" = -- ] || { echo "d3-mitd3.sh run: no command" >&2; exit 2; }
    n0=$(stat -c %s "$log" 2> /dev/null || echo 0)
    t=$(mktemp -d "$D3M/run.XXXXXX")
    if [ -n "$ccfrom" ]; then
        for e in "${envs[@]}"; do case $e in KRB5CCNAME=FILE:*) cp -p "$ccfrom" "${e#KRB5CCNAME=FILE:}" ;; esac; done
    fi
    n=0; ok=1
    while [ $# -gt 0 ]; do
        shift   # the --
        cmd=()
        while [ $# -gt 0 ] && [ "$1" != -- ]; do cmd+=("$1"); shift; done
        n=$((n + 1))
        case ${cmd[0]} in
            mit:*) cmd[0]=$MR/bin/${cmd[0]#mit:} ;;
            ours:*) cmd[0]=$SHIP/krb5-${cmd[0]#ours:} ;;
        esac
        if [ "$ok" != 1 ]; then echo "== cmd $n: ${cmd[0]##*/} ${cmd[*]:1}" | sed "s#$D3M/#D3M/#g"; echo "[skipped]"; continue; fi
        if [ "${cmd[0]#gss:}" != "${cmd[0]}" ]; then   # MIT's sample acceptor and initiator, one exchange
            svc=${cmd[0]#gss:}
            env "${envs[@]}" timeout 60 "$MR/sbin/gss-server" -port "$GSSPORT" -once "$svc" > "$t/sout" 2> "$t/serr" < /dev/null &
            spid=$!
            listening "$GSSPORT" 10 || echo "(gss-server not listening on $GSSPORT)"
            env "${envs[@]}" timeout 60 "$MR/bin/gss-client" -port "$GSSPORT" -d "$ADDR" "$svc" "d3-message" > "$t/out" 2> "$t/err" < /dev/null; rc=$?
            for _ in $(seq 1 50); do kill -0 "$spid" 2> /dev/null || break; sleep 0.1; done
            kill -0 "$spid" 2> /dev/null && { kill "$spid" 2> /dev/null; echo "(gss-server had to be ended)" >> "$t/serr"; }
            wait "$spid" 2> /dev/null; src=$?
            echo "== cmd $n: gss-client -d $svc"
            echo "[rc=$rc]"
            echo "== stdout"; cat "$t/out"
            echo "== stderr"; cat "$t/err"
            n=$((n + 1))
            echo "== cmd $n: gss-server -once $svc"
            echo "[rc=$src]"
            echo "== stdout"; cat "$t/sout"
            echo "== stderr"; cat "$t/serr"
            [ "$rc" = 0 ] || ok=0
            continue
        fi
        echo "== cmd $n: ${cmd[0]##*/} ${cmd[*]:1}" | sed "s#$D3M/#D3M/#g"
        if [ "$n" = 1 ]; then env "${envs[@]}" timeout 120 "${cmd[@]}" > "$t/out" 2> "$t/err"; rc=$?
        else env "${envs[@]}" timeout 120 "${cmd[@]}" > "$t/out" 2> "$t/err" < /dev/null; rc=$?; fi
        echo "[rc=$rc]"
        echo "== stdout"; cat "$t/out"
        echo "== stderr"; cat "$t/err"
        [ "$rc" = 0 ] || ok=0
    done
    sleep 0.3
    tracep=""
    for e in "${envs[@]}"; do
        case $e in
            KRB5_TRACE=FILE:*) tracep=${e#KRB5_TRACE=FILE:} ;;
            KRB5_TRACE=*) tracep=${e#KRB5_TRACE=} ;;
        esac
    done
    if [ -n "$tracep" ]; then
        ntk=0
        if [ -f "$tracep" ]; then ntk=$(grep -c 'No credentials found with supported encryption types' "$tracep" || true); rm -f "$tracep"; fi
        echo "TRACE_NOT_KTYPE $ntk"
    fi
    echo "== kdc log"; tail -c +$((n0 + 1)) "$log" 2> /dev/null
    rm -rf "$t"
    ;;
keyparity)
    for kt in "$@"; do
        nm=$(basename "$kt" .keytab)
        klist -k -K -e "$kt" 2>&1 | while IFS= read -r line; do
            case $line in *des3*"(0x"*) ;; *) continue ;; esac
            hex=${line##*(0x}; hex=${hex%%[!0-9a-fA-F]*}
            princ=$(printf '%s' "$line" | awk '{ print $2 }')
            echo "KEYPARITY $nm $princ des3 octets=$(( ${#hex} / 2 )) even=$(parity_even "$hex")"
        done
    done
    ;;
avc)
    echo "getenforce: $(getenforce 2>&1)"
    n=$(ausearch -m avc,user_avc -ts boot 2> /dev/null < /dev/null | grep -c '^type=AVC'); [ "${n:-0}" = 0 ] && n=$(journalctl -k -b --no-pager 2> /dev/null < /dev/null | grep -c 'avc: *denied')
    echo "AVC_DENIALS_SINCE_BOOT: ${n:-0}"
    { ausearch -m avc,user_avc -ts boot 2> /dev/null < /dev/null | grep '^type=AVC'; journalctl -k -b --no-pager 2> /dev/null < /dev/null | grep 'avc: *denied'; } | sed -E 's/^.*avc: +denied +(\{[^}]*\}).*scontext=([^ ]*) tcontext=([^ ]*) tclass=([^ ]*).*/\1 \2 \3 \4/' | sort | uniq -c | head -n 10
    ;;
clean)
    stop_pid "$D3M/kdc.run"; stop_pid "$D3M/kdc.pid"
    shred -u "$KT"/*.keytab "$D3M/mit.dump" "$D3M/ours.dump" "$OURS"/principal* "$MITRE"/principal* "$OLD"/principal* "$BASE"/principal* "$OLD/stash" "$OLD/old.dump" "$OLD"/*.keytab 2> /dev/null
    rm -rf "$D3M"
    echo "D3M_GONE: $([ -e "$D3M" ] && echo no || echo yes)"
    echo "LISTENERS_ON_PORTS_AFTER: $(( $(ss -H -lnt "sport = :$KPORT" 2> /dev/null | wc -l) + $(ss -H -lnt "sport = :$OLDPORT" 2> /dev/null | wc -l) + $(ss -H -lnt "sport = :$GSSPORT" 2> /dev/null | wc -l) + $(ss -H -lnt "sport = :$BASEPORT" 2> /dev/null | wc -l) ))"
    ;;
*) echo "d3-mitd3.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
