#!/usr/bin/env bash
# The OTP gates' shared cells (otp-gate.sh, rust-kinit-otp-gate.sh). Sourced after gate-common.sh, kadmin-q.sh and
# proc-common.sh. Everything runs in $NAME under $OTP_DIR, on the realm's own kdc.conf and krb5.conf (never the
# image's); a login is MIT's kinit (kind mit) or the Rust kinit copied to $OTP_DIR/ours/kinit (kind rust), so the
# Rust program's messages carry MIT's name, "kinit:".
# shellcheck shell=bash

OTP_DIR=/tmp/otp
OTP_REALM=OTP.TEST
OTP_SVC="host/svc.otp.test@$OTP_REALM"

# otp_x COMMAND...: COMMAND in $NAME on the OTP realm's profile.
otp_x() {
    docker exec -e KRB5_CONFIG="$OTP_DIR/krb5.conf" -e KRB5_KDC_PROFILE="$OTP_DIR/kdc.conf" "$NAME" "$@"
}

# otp_stage FILE...: the directories, the Rust kinit as "kinit", the shim (built here) and its dump reader, and the
# scripts/lib FILEs the gate names.
otp_stage() {
    docker exec "$NAME" mkdir -p "$OTP_DIR/ours" "$OTP_DIR/db"
    docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kinit" "$NAME":"$OTP_DIR/ours/kinit"
    docker exec "$NAME" chmod +x "$OTP_DIR/ours/kinit"
    local f
    for f in otp-fast-shim.c otp-fastdump.py "$@"; do
        docker cp "$ROOT/scripts/lib/$f" "$NAME":"$OTP_DIR/$f"
    done
    docker exec "$NAME" cc -shared -fPIC -o "$OTP_DIR/otp-fast-shim.so" "$OTP_DIR/otp-fast-shim.c" -ldl \
        || die "cc otp-fast-shim.so failed in $NAME"
}

# otp_write_confs KDC_EXTRA: krb5.conf and kdc.conf of the realm (SPAKE offered: the client's default group
# edwards25519 and the KDC's optimistic challenge, as the lab's realm), KDC_EXTRA appended to kdc.conf.
otp_write_confs() {
    docker exec -i "$NAME" sh -c 'cat >"$1/krb5.conf"' sh "$OTP_DIR" <<EOF
[libdefaults]
    default_realm = $OTP_REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
[realms]
    $OTP_REALM = {
        kdc = 127.0.0.1:88
    }
EOF
    docker exec -i "$NAME" sh -c 'cat >"$1/kdc.conf"' sh "$OTP_DIR" <<EOF
[realms]
    $OTP_REALM = {
        database_name = $OTP_DIR/db/principal
        key_stash_file = $OTP_DIR/db/stash
        master_key_type = aes256-cts-hmac-sha1-96
    }
[logging]
    kdc = FILE:$OTP_DIR/kdc.log
[libdefaults]
    spake_preauth_groups = edwards25519
[kdcdefaults]
    spake_preauth_kdc_challenge = edwards25519
$1
EOF
}

# otp_stop: the gate's daemons, by name and pid file (a shared shell outlives the gate).
otp_stop() {
    term_comm krb5kdc
    term_comm krb5-otp-kdc
    docker exec "$NAME" sh -c 'kill $(cat "$1/stub.pid" 2>/dev/null) 2>/dev/null; true' sh "$OTP_DIR"
}

# otp_log_lines: the KDC log's line count (a cell's mark); otp_log_since MARK: the lines after it.
otp_log_lines() {
    docker exec "$NAME" sh -c 'wc -l <"$1"' sh "$OTP_DIR/kdc.log" | tr -d '[:space:]'
}
otp_log_since() {
    docker exec "$NAME" tail -n "+$(($1 + 1))" "$OTP_DIR/kdc.log"
}

# otp_kinit KIND TAG STDIN ARG...: one login, `kinit -c $OTP_DIR/TAG.cc ARG...`, STDIN the exact bytes on its stdin
# (printf %b), with $OTP_PRELOAD (the shim, for a cell that reads this client's FAST traffic) in LD_PRELOAD. Leaves
# TAG.out, TAG.err (a test-hooks Rust kinit's JSON log lines and `ok tgt=` line removed: the shipped one prints
# neither), TAG.rc and TAG.trace (KRB5_TRACE).
otp_kinit() {
    local kind=$1 tag=$2 input=$3 bin=kinit
    shift 3
    [ "$kind" = rust ] && bin="$OTP_DIR/ours/kinit"
    printf '%b' "$input" | docker exec -i -e KRB5_CONFIG="$OTP_DIR/krb5.conf" -e KRB5_TRACE="$OTP_DIR/$tag.trace" \
        -e LD_PRELOAD="${OTP_PRELOAD:-}" -e KR_SHIM_OUT="$OTP_DIR/shim.out" "$NAME" \
        sh -c '
            bin=$1 out=$2/$3
            shift 3
            rm -f "$out.cc" "$out.trace"
            "$bin" -c "$out.cc" "$@" >"$out.raw.out" 2>"$out.raw.err"
            echo $? >"$out.rc"
            grep -v -e "^ok tgt=" -e "^{\"timestamp\"" "$out.raw.out" >"$out.out" || true
            grep -v -e "^ok tgt=" -e "^{\"timestamp\"" "$out.raw.err" >"$out.err" || true
        ' sh "$bin" "$OTP_DIR" "$tag" "$@"
}

# otp_rc TAG WANT: the login's exit status.
otp_rc() {
    [ "$(docker exec "$NAME" cat "$OTP_DIR/$1.rc")" = "$2" ] || die "$1: exit status is not $2"
}

# otp_expect TAG STREAM TEXT: TAG.STREAM (out or err) is exactly TEXT (printf %b), byte for byte.
otp_expect() {
    printf '%b' "$3" | docker exec -i "$NAME" cmp - "$OTP_DIR/$1.$2" || die "$1.$2 is not the expected bytes"
}

# otp_same TAG1 TAG2 STREAM: the two logins wrote the same bytes to STREAM (out, err, rc).
otp_same() {
    docker exec "$NAME" cmp "$OTP_DIR/$1.$3" "$OTP_DIR/$2.$3" || die "$1 and $2 differ in .$3"
}

# otp_has TAG EXT TEXT / otp_lacks TAG EXT TEXT: TAG.EXT holds / does not hold the fixed string TEXT.
otp_has() {
    docker exec "$NAME" grep -qF -- "$3" "$OTP_DIR/$1.$2" || die "$1.$2 lacks: $3"
}
otp_lacks() {
    ! docker exec "$NAME" grep -qF -- "$3" "$OTP_DIR/$1.$2" || die "$1.$2 holds: $3"
}

# otp_cc TAG KEY VALUE: klist -C of the login's ccache shows the config entry KEY = VALUE on the realm's krbtgt.
otp_cc() {
    docker exec "$NAME" klist -C -c "$OTP_DIR/$1.cc" | grep -qF "config: $2(krbtgt/$OTP_REALM@$OTP_REALM) = $3" \
        || die "$1: no ccache config $2 = $3"
}

# otp_flags TAG: the ticket flags klist -f prints for the login's ccache.
otp_flags() {
    docker exec "$NAME" klist -f -c "$OTP_DIR/$1.cc" | sed -n 's/^[[:space:]]*Flags: //p'
}

# otp_kvno TAG: MIT kvno of the require_auth service with the login's ccache; prints its output, never fails.
otp_kvno() {
    docker exec -e KRB5_CONFIG="$OTP_DIR/krb5.conf" "$NAME" kvno -c "$OTP_DIR/$1.cc" "$OTP_SVC" 2>&1 || true
}

# otp_dump_reset: empty the shim's output; otp_dump TAG: the FAST events the shim saw since, as otp-fastdump.py
# prints them, in TAG.sum.
otp_dump_reset() {
    docker exec "$NAME" sh -c ': >"$1/shim.out"' sh "$OTP_DIR"
}
otp_dump() {
    docker exec "$NAME" sh -c 'python3 -I "$1/otp-fastdump.py" "$1/shim.out" >"$1/$2.sum"' sh "$OTP_DIR" "$1" \
        || die "otp-fastdump.py could not read the shim's lines for $1"
}

# nonce_back TAG: the PA-OTP-CHALLENGE nonce the KDC sent (usage 52) is the one the client sent back (usage 45).
nonce_back() {
    local n141 n45
    n141="$(docker exec "$NAME" sed -n 's/.* nonce141=//p' "$OTP_DIR/$1.sum" | head -n 1)"
    n45="$(docker exec "$NAME" sed -n 's/^nonce45=//p' "$OTP_DIR/$1.sum" | head -n 1)"
    [ -n "$n141" ] && [ "$n141" = "$n45" ] || die "$1: the nonce sent back is not the KDC's"
}

# masked_sum TAG: the shim summary with the random nonces blanked, to compare two clients.
masked_sum() {
    docker exec "$NAME" sed -e 's/nonce141=[0-9a-f]*/nonce141=N/' -e 's/^nonce45=.*/nonce45=N/' "$OTP_DIR/$1.sum"
}
