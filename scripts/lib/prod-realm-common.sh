# Shared helpers for C2 gates over harness/prod. Source after ROOT is set.
# shellcheck disable=SC1091
. "$ROOT/harness/prod/limits.env"

REALM="${KERBER_PROD_REALM:-PROD.KERBER.TEST}"
export KERBER_PROD_REALM="$REALM"
DNS_DOMAIN="$(printf '%s' "$REALM" | tr '[:upper:]' '[:lower:]')"
PRIMARY="kerber-rust-prod-kdc1"
REPLICA="kerber-rust-prod-kdc2"
CLIENT="kerber-rust-prod-client"
HOST_SMOKE="host/testhost.${DNS_DOMAIN}"
HOST_APP="host/app.${DNS_DOMAIN}"
HOST_REPLICA="host/kdc2.${DNS_DOMAIN}"
REPLICA_FQDN="kdc2.${DNS_DOMAIN}"
CONF=/tmp/prod-krb5.conf

prod_ip_of() {
    docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" "$1"
}

prod_client() {
    docker exec -e KRB5_CONFIG="$CONF" "$CLIENT" "$@"
}

prod_wait_log() {
    local node="$1" file="$2" pat="$3" n="${4:-80}"
    local i
    for i in $(seq 1 "$n"); do
        docker exec "$node" grep -q "$pat" "$file" 2>/dev/null && return 0
        sleep 0.25
    done
    return 1
}

prod_stage_loadgen() {
    local bin="$ROOT/target/debug/examples/loadgen"
    [ -x "$bin" ] || {
        echo "missing $bin" >&2
        return 1
    }
    docker cp "$bin" "$CLIENT":/usr/local/bin/loadgen
    docker exec "$CLIENT" chmod +x /usr/local/bin/loadgen
}

prod_loadgen() {
    local kdc_ip="$1"
    shift
    docker exec \
        -e KRB5_PASSWORD="$KERBER_PROD_USER_PW" \
        -e KERBER_LOAD_WORKERS="${KERBER_LOAD_WORKERS:-8}" \
        -e KERBER_LOAD_ITERS="${KERBER_LOAD_ITERS:-8}" \
        -e KERBER_LOAD_SECONDS="${KERBER_LOAD_SECONDS:-}" \
        "$CLIENT" /usr/local/bin/loadgen "$kdc_ip" "user@$REALM" "$HOST_SMOKE" "$@"
}

prod_mit_sample() {
    local tag="$1"
    prod_client kdestroy -A >/dev/null 2>&1 || true
    prod_client sh -c "printf '%s\n' '$KERBER_PROD_USER_PW' | kinit user@$REALM"
    prod_client kvno "${HOST_SMOKE}@$REALM"
    local kl
    kl="$(prod_client klist 2>&1)"
    echo "$kl"
    echo "$kl" | grep -q "krbtgt/${REALM}" || return 1
    echo "$kl" | grep -q "testhost.${DNS_DOMAIN}" || return 1
    printf '%s\n' "$kl" >"$OUT/klist-${tag}.txt"
}

prod_kprop_replica() {
    prod_client kadmin -p "admin@$REALM" -w "$KERBER_PROD_ADMIN_PW" \
        -q "addprinc -randkey $HOST_APP" || return 1
    prod_client kadmin -p "admin@$REALM" -w "$KERBER_PROD_ADMIN_PW" \
        -q "ktadd -k /tmp/app.keytab $HOST_APP" || return 1
    prod_client kadmin -p "admin@$REALM" -w "$KERBER_PROD_ADMIN_PW" \
        -q "addprinc -randkey $HOST_REPLICA" || return 1
    prod_client kadmin -p "admin@$REALM" -w "$KERBER_PROD_ADMIN_PW" \
        -q "ktadd -k /tmp/kdc2.keytab $HOST_REPLICA" || return 1
    docker cp "$CLIENT":/tmp/kdc2.keytab "$OUT/kdc2.keytab" || return 1
    docker cp "$OUT/kdc2.keytab" "$PRIMARY":/tmp/kdc2.keytab || return 1
    docker cp "$OUT/kdc2.keytab" "$REPLICA":/tmp/kdc2.keytab || return 1
    docker exec "$REPLICA" mkdir -p /tmp/pdus || return 1

    docker exec "$REPLICA" sh -c "printf '%s@%s\\n' '$HOST_REPLICA' '$REALM' >/tmp/kpropd.acl"
    docker exec -d \
        -e KRB5_MASTER_PASSWORD="$KERBER_PROD_MASTER_PW" \
        -e KRB5_KPROP_KEYTAB=/tmp/kdc2.keytab \
        -e KRB5_KPROP_ACL=/tmp/kpropd.acl \
        -e KRB5_KDC_DB=/tmp/replica.db \
        -e KRB5_KDC_STASH=/tmp/replica.stash \
        -e KRB5_KDC_REALM="$REALM" \
        -e RUST_LOG=info \
        "$REPLICA" sh -c '/usr/local/bin/krb5-kpropd 0.0.0.0:754 >/tmp/kpropd.log 2>&1'
    prod_wait_log "$REPLICA" /tmp/kpropd.log '^listening' 40 || return 1

    docker exec \
        -e KRB5_KDC_DB=/tmp/prod.db \
        -e KRB5_KDC_STASH=/tmp/prod.stash \
        -e KRB5_MASTER_PASSWORD="$KERBER_PROD_MASTER_PW" \
        -e KRB5_KPROP_KEYTAB=/tmp/kdc2.keytab \
        "$PRIMARY" /usr/local/bin/krb5-kprop -P 754 -s /tmp/kdc2.keytab -n "$REPLICA_FQDN" "$REPLICA_FQDN" \
        | tee "$OUT/kprop.log" | grep -q 'kprop ok' || return 1

    docker exec -d \
        -e KRB5_KDC_DB=/tmp/replica.db \
        -e KRB5_KDC_STASH=/tmp/replica.stash \
        -e KERBER_CAPTURE_DIR=/tmp/pdus \
        -e RUST_LOG=info \
        -e CORRELATION_ID="${CORRELATION_ID:-}" \
        "$REPLICA" sh -c '/usr/local/bin/krb5-kdc 0.0.0.0:88 >/tmp/kdc.log 2>&1'
    prod_wait_log "$REPLICA" /tmp/kdc.log '^listening' 80 || return 1
}

prod_point_client_at() {
    local ip="$1"
    docker exec "$CLIENT" sh -c "cat >$CONF <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_prod
[realms]
    $REALM = {
        kdc = $ip
        admin_server = $ip
    }
EOF"
}

prod_rss_mib() {
    # Anonymous RSS of krb5-kdc (not cgroup file cache of kdc.log / pdus).
    docker exec "$PRIMARY" sh -c '
        for d in /proc/[0-9]*; do
            [ -r "$d/comm" ] || continue
            comm=$(tr -d "\n" < "$d/comm")
            [ "$comm" = krb5-kdc ] || continue
            if [ -r "$d/smaps_rollup" ]; then
                awk "BEGIN{n=0} /^RssAnon:/ { printf \"%.3f\\n\", \$2/1024; n=1 } END{if(!n) exit 1}" "$d/smaps_rollup" && exit 0
            fi
            awk "/^VmRSS:/ { printf \"%.3f\\n\", \$2/1024 }" "$d/status"
            exit 0
        done
        echo 0
    '
}
