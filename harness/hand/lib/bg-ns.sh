#!/usr/bin/env bash
# 3k BG kdc cells, copied from bg2-ns.sh. Rust test-realm KDC, aes128-only keys. MIT initiator first.
# The verify-init-creds rows are omitted: 806c20f1 has no krb5-vfy-increds bin.
set -u
OUT=${1:?outdir}
if [ -z "${IN_NS:-}" ]; then
    mkdir -p "$OUT"
    exec unshare -Urnm env IN_NS=1 bash "$0" "$@"
fi
KDC=${KDC:?}
INIT=${INIT:?}
ACC=${ACC:?}
OURS=${OURS:?}
KINIT_OURS=${KINIT_OURS:?}
KLIST_OURS=${KLIST_OURS:?}
KDESTROY_OURS=${KDESTROY_OURS:?}
KVNO_OURS=${KVNO_OURS:?}
HOST=testhost.kerber.test
export PATH="$PATH:/usr/sbin:/usr/bin"
export KRB5_TEST_USER_PASSWORD=userpassword KRB5_TEST_ADMIN_PASSWORD=adminpassword
export KRB5_KDC_USER=root
export KRB5_TEST_HOST=$HOST
ip link set lo up
printf '127.0.0.1 localhost %s\n' "$HOST" > "$OUT/hosts"
mount --bind "$OUT/hosts" /etc/hosts
cat > "$OUT/kdc.conf" <<'EOF'
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88
[realms]
    KERBER.TEST = {
        max_life = 1d 0h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        supported_enctypes = aes128-cts-hmac-sha1-96:normal
    }
EOF
mkconf() {
    local dest=$1 extra=$2
    cat > "$dest" <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    dns_canonicalize_hostname = false
    $extra
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF
}
mkconf "$OUT/krb5.conf" ""
mkconf "$OUT/krb5-cbt.conf" "client_aware_channel_bindings = true"
mkconf "$OUT/krb5-maybe.conf" "client_aware_channel_bindings = maybe"
export KRB5_CONFIG=$OUT/krb5.conf KRB5_KDC_PROFILE=$OUT/kdc.conf
"$KDC" --test-realm --export-keytab "$OUT/host.keytab" 127.0.0.1:88 > "$OUT/kdc.log" 2>&1 &
up=0
for _ in $(seq 1 50); do
    if grep -q '^listening ' "$OUT/kdc.log" 2>/dev/null; then
        up=1
        break
    fi
    sleep 0.2
done
echo "KDC_UP:$up"
if [ "$up" != 1 ]; then
    echo "KDC_LOG:"
    cat "$OUT/kdc.log"
    echo "NS_DONE"
    exit 1
fi
echo "==== keytab etypes ===="
klist -k -e "$OUT/host.keytab" | grep -E 'host/|aes|Keytab' || true
kinit_as() {
    local who=$1 bin=$2
    printf '%s\n' "$KRB5_TEST_USER_PASSWORD" | KRB5CCNAME=FILE:$OUT/cc-$who "$bin" user@KERBER.TEST > "$OUT/kinit-$who.out" 2>&1
    echo "kinit $who rc $?"
}
kinit_as mit /usr/bin/kinit
kinit_as ours "$KINIT_OURS"
port=4500
next_port() { port=$((port + 1)); }
phase() {
    local label=$1 kt=$2
    shift 2
    : > "$OUT/$label.acceptor.txt"
    KRB5_KTNAME=FILE:$kt KRB5RCACHETYPE=none KRB5_CONFIG=$OUT/krb5.conf \
        "$ACC" "$label" "$port" "$OUT/$label" > "$OUT/$label.acceptor.txt" 2> "$OUT/$label.acceptor.err" &
    local apid=$!
    for _ in $(seq 1 50); do
        grep -q '^listening ' "$OUT/$label.acceptor.txt" 2>/dev/null && break
        sleep 0.1
    done
    "$@" > "$OUT/$label.init.out" 2>&1
    echo "$label init rc $?"
    sleep 0.4
    kill "$apid" 2>/dev/null || true
    wait "$apid" 2>/dev/null || true
    echo "==== $label acceptor ===="
    grep -E 'ad-type|subkey|seq-number|AP-REP|listening|error|CBT' "$OUT/$label.acceptor.txt" || true
    echo "---- $label init ----"
    grep -E 'Invalid boolean|gss-init|error|failed|sent ' "$OUT/$label.init.out" || true
}
KRB5CCNAME=FILE:$OUT/cc-mit kvno "host/$HOST" > "$OUT/kvno-mit.out" 2>&1
echo "kvno mit rc $?"
next_port
phase mit-etype "$OUT/host.keytab" \
    env KRB5_CONFIG="$OUT/krb5.conf" KRB5CCNAME=FILE:"$OUT/cc-mit" "$INIT" "$HOST" host 127.0.0.1 "$port"
KRB5CCNAME=FILE:$OUT/cc-ours "$KVNO_OURS" "host/$HOST" > "$OUT/kvno-ours.out" 2>&1
echo "kvno ours rc $?"
next_port
phase ours-etype "$OUT/host.keytab" \
    env KRB5_CONFIG="$OUT/krb5.conf" "$OURS" --ccache "$OUT/cc-ours" --host "$HOST" --ip 127.0.0.1 --port "$port"
next_port
phase mit-cbt-off "$OUT/host.keytab" \
    env KRB5_CONFIG="$OUT/krb5.conf" KRB5CCNAME=FILE:"$OUT/cc-mit" "$INIT" "$HOST" host 127.0.0.1 "$port"
next_port
phase ours-cbt-off "$OUT/host.keytab" \
    env KRB5_CONFIG="$OUT/krb5.conf" "$OURS" --ccache "$OUT/cc-ours" --host "$HOST" --ip 127.0.0.1 --port "$port"
next_port
phase mit-cbt-rel "$OUT/host.keytab" \
    env KRB5_CONFIG="$OUT/krb5-cbt.conf" KRB5CCNAME=FILE:"$OUT/cc-mit" "$INIT" "$HOST" host 127.0.0.1 "$port"
next_port
phase ours-cbt-rel "$OUT/host.keytab" \
    env KRB5_CONFIG="$OUT/krb5-cbt.conf" "$OURS" --ccache "$OUT/cc-ours" --host "$HOST" --ip 127.0.0.1 --port "$port"
next_port
phase mit-cbt-flag "$OUT/host.keytab" \
    env GSS_CHANNEL_BOUND=1 KRB5_CONFIG="$OUT/krb5.conf" KRB5CCNAME=FILE:"$OUT/cc-mit" "$INIT" "$HOST" host 127.0.0.1 "$port"
next_port
phase ours-cbt-flag "$OUT/host.keytab" \
    env KRB5_CONFIG="$OUT/krb5.conf" "$OURS" --ccache "$OUT/cc-ours" --host "$HOST" --ip 127.0.0.1 --port "$port" --channel-bindings tls-unique-test
printf '%s\n' "$KRB5_TEST_USER_PASSWORD" | KRB5_CONFIG=$OUT/krb5-maybe.conf KRB5CCNAME=FILE:$OUT/cc-mit-maybe /usr/bin/kinit user@KERBER.TEST > "$OUT/maybe-mit-kinit.out" 2>&1
echo "maybe mit kinit rc $?"
KRB5_CONFIG=$OUT/krb5-maybe.conf KRB5CCNAME=FILE:$OUT/cc-mit-maybe /usr/bin/klist > "$OUT/maybe-mit-klist.out" 2>&1
echo "maybe mit klist rc $?"
KRB5_CONFIG=$OUT/krb5-maybe.conf KRB5CCNAME=FILE:$OUT/cc-mit-maybe /usr/bin/kdestroy > "$OUT/maybe-mit-kdestroy.out" 2>&1
echo "maybe mit kdestroy rc $?"
printf '%s\n' "$KRB5_TEST_USER_PASSWORD" | KRB5_CONFIG=$OUT/krb5-maybe.conf KRB5CCNAME=FILE:$OUT/cc-mit-maybe /usr/bin/kinit user@KERBER.TEST > "$OUT/maybe-mit-kinit2.out" 2>&1
KRB5CCNAME=FILE:$OUT/cc-mit-maybe kvno "host/$HOST" > "$OUT/maybe-mit-kvno.out" 2>&1
echo "maybe mit kvno rc $?"
next_port
phase mit-maybe "$OUT/host.keytab" \
    env KRB5_CONFIG="$OUT/krb5-maybe.conf" KRB5CCNAME=FILE:"$OUT/cc-mit-maybe" "$INIT" "$HOST" host 127.0.0.1 "$port"
printf '%s\n' "$KRB5_TEST_USER_PASSWORD" | KRB5_CONFIG=$OUT/krb5-maybe.conf KRB5CCNAME=FILE:$OUT/cc-ours-maybe "$KINIT_OURS" user@KERBER.TEST > "$OUT/maybe-ours-kinit.out" 2>&1
echo "maybe ours kinit rc $?"
KRB5_CONFIG=$OUT/krb5-maybe.conf KRB5CCNAME=FILE:$OUT/cc-ours-maybe "$KLIST_OURS" > "$OUT/maybe-ours-klist.out" 2>&1
echo "maybe ours klist rc $?"
KRB5_CONFIG=$OUT/krb5-maybe.conf KRB5CCNAME=FILE:$OUT/cc-ours-maybe "$KDESTROY_OURS" > "$OUT/maybe-ours-kdestroy.out" 2>&1
echo "maybe ours kdestroy rc $?"
printf '%s\n' "$KRB5_TEST_USER_PASSWORD" | KRB5_CONFIG=$OUT/krb5-maybe.conf KRB5CCNAME=FILE:$OUT/cc-ours-maybe "$KINIT_OURS" user@KERBER.TEST > "$OUT/maybe-ours-kinit2.out" 2>&1
KRB5_CONFIG=$OUT/krb5-maybe.conf KRB5CCNAME=FILE:$OUT/cc-ours-maybe "$KVNO_OURS" "host/$HOST" > "$OUT/maybe-ours-kvno.out" 2>&1
echo "maybe ours kvno rc $?"
next_port
phase ours-maybe "$OUT/host.keytab" \
    env KRB5_CONFIG="$OUT/krb5-maybe.conf" "$OURS" --ccache "$OUT/cc-ours-maybe" --host "$HOST" --ip 127.0.0.1 --port "$port"
echo "VFY_BIN:absent"
kill %1 2>/dev/null || true
echo "NS_DONE"
