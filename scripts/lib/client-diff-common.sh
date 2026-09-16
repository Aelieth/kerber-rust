# Shared helpers for client-differential-flows-gate / client-differential-cli-gate.
# KEEP-attach: KERBER_CLIENT_DIFF_KEEP=1 leaves the MIT container for the next leg.
# Functions expand $NAME at call time.

reset_cap() {
    docker exec "$NAME" sh -c 'cat /dev/null > /tmp/cdiff/live.jsonl'
}

save_cap() {
    docker exec "$NAME" cp /tmp/cdiff/live.jsonl "/tmp/cdiff/$1.jsonl"
    docker exec "$NAME" test -s "/tmp/cdiff/$1.jsonl" || die "empty capture $1"
}

mit_kinit() {
    local cc=$1
    shift
    docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf -e KRB5_TRACE=/tmp/mit-client.trace \
        "$NAME" sh -c "printf 'userpassword\n' | kinit -c '$cc' $* user@KERBER.TEST"
}

rust_kinit() {
    local cc=$1
    shift
    docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf -e KRB5_PASSWORD=userpassword \
        "$NAME" /tmp/krb5-kinit -c "$cc" "$@" user@KERBER.TEST
}

