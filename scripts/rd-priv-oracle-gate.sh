#!/usr/bin/env bash
# MIT 1.22.2's krb5_rd_req, krb5_rd_priv and krb5_rd_safe (scripts/oracle/rd-priv-oracle.c, the
# sibling of rd-safe-oracle.c) against the Rust acceptor: `rd-sweep cases` breaks an AP-REQ's
# authenticator, a KRB-PRIV's EncKrbPrivPart and a KRB-SAFE's body as the decode sweep breaks a
# message, re-encrypting or re-signing each, and both sides answer every case. Red on any case the
# Rust acceptor answers otherwise than MIT (accepted, an ASN.1 error, or the krb5 code).
# Second leg: kadmind's kpasswd acceptor (RFC 3244, kadmin/changepw). `rd-sweep kpasswd` writes the
# cases as kpasswd requests for a realm built here; MIT's acceptor calls (`rd-priv-oracle kpasswd`:
# krb5_rd_req naming kadmin/changepw against the KDB: keytab, krb5_mk_rep, krb5_rd_priv with no address)
# and the Rust acceptor (`rd-sweep judge-explicit`) answer each, both in the container, so both see the
# same host addresses. Red on any request answered otherwise than MIT (read, AP-REQ refused, KRB-PRIV refused).
# Third leg: kadmind's GSS acceptor over the same database (accept_sec_context.c kg_accept_krb5: krb5_rd_req
# against the KDB: keytab). `rd-sweep kadmind` writes AP-REQs for the services a `ktadd -norandkey` keytab holds
# (kadmin/admin, kadmin/changepw, kadmin/history, a host), sealed in each of their keys, at the wrong kvno and
# under the wrong cleartext server; MIT's acceptor calls (`rd-priv-oracle kadmind`: krb5_rd_req with no server,
# the RPCSEC_GSS acceptor, then naming kadmin/admin and kadmin/changepw, AUTH_GSSAPI's two) and the Rust
# acceptor (`rd-sweep judge-kdb`) answer each. Red on any case the Rust acceptor answers otherwise than MIT.
# Isolated: docker --entrypoint sleep; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-q.sh"
need_bins rd-sweep

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-rd-priv-oracle"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
OUT="$SCRATCH/rd-priv-oracle"
mkdir -p "$OUT"
SWEEP="${CARGO_TARGET_DIR:-target}/debug/rd-sweep"

need_image
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "rd.priv.oracle" "error" ',"error":"MIT image unavailable"'
    exit 2
fi

shell_container 300

docker cp "$ROOT/scripts/oracle/rd-priv-oracle.c" "$NAME":/tmp/rd-priv-oracle.c
mit_oracle_cc "$NAME" /tmp/rd-priv-oracle /tmp/rd-priv-oracle.c krb5 -O1
# The cases carry the time they are made: MIT reads them at once, inside its clock skew.
"$SWEEP" cases >"$OUT/cases.tsv"
docker cp "$OUT/cases.tsv" "$NAME":/tmp/rd-priv-cases.tsv
docker exec -e KRB5RCACHETYPE=none "$NAME" sh -c '/tmp/rd-priv-oracle </tmp/rd-priv-cases.tsv >/tmp/rd-priv-mit.tsv'
docker cp "$NAME":/tmp/rd-priv-mit.tsv "$OUT/mit.tsv"
CASES="$(grep -vc '^#' "$OUT/cases.tsv")"
[ "$(wc -l <"$OUT/mit.tsv" | tr -d ' ')" = "$CASES" ] || die "MIT answered $(wc -l <"$OUT/mit.tsv") of $CASES cases"
for pristine in ap-req krb-priv krb-safe; do
    grep -q "^$pristine/pristine$(printf '\t')0$" "$OUT/mit.tsv" || die "MIT refuses the pristine $pristine"
done
if ! "$SWEEP" judge "$OUT/cases.tsv" "$OUT/mit.tsv" >"$OUT/judge.txt"; then
    grep -m 20 '^PART' "$OUT/judge.txt" || true
    log "rd.priv.oracle" "error" ",\"error\":\"$(tail -1 "$OUT/judge.txt")\""
    exit 1
fi
MIT_OK="$(grep -c "$(printf '\t')0$" "$OUT/mit.tsv" || true)"

# MIT's order and texts (rd_req_dec.c rd_req_decoded_opt): `rd-sweep order` writes faults alone and in pairs, some
# sent twice (`-again`), so MIT reads them with a replay cache and the Rust acceptor with one of its own. Only
# aes256 is permitted, and the keytab also holds an aes128 key.
TAB="$(printf '\t')"
"$SWEEP" order >"$OUT/order.tsv"
docker cp "$OUT/order.tsv" "$NAME":/tmp/rd-order.tsv
docker exec "$NAME" sh -c 'printf "[libdefaults]\n    permitted_enctypes = aes256-cts-hmac-sha1-96\n" >/tmp/rd-order.conf'
docker exec -e KRB5RCACHENAME=file2:/tmp/rd-order.rcache2 -e KRB5_CONFIG=/tmp/rd-order.conf "$NAME" \
    sh -c 'rm -f /tmp/rd-order.rcache2; /tmp/rd-priv-oracle text </tmp/rd-order.tsv >/tmp/rd-order-mit.tsv'
docker cp "$NAME":/tmp/rd-order-mit.tsv "$OUT/order-mit.tsv"
ORDER="$(grep -vc '^#' "$OUT/order.tsv")"
[ "$(wc -l <"$OUT/order-mit.tsv" | tr -d ' ')" = "$ORDER" ] || die "MIT answered $(wc -l <"$OUT/order-mit.tsv") of $ORDER order cases"
for want in "order/pristine${TAB}0" "transit/server-realm${TAB}krb5:43${TAB}Illegal cross-realm ticket" \
    "transit/one-realm${TAB}krb5:185${TAB}Cannot find ticket for requested realm" \
    "order/expired-badmatch${TAB}krb5:36${TAB}Ticket/authenticator don't match" \
    "order/invalid-skew${TAB}krb5:37${TAB}Clock skew too great" \
    "decrypt/authenticator-key${TAB}krb5:31${TAB}Decrypt integrity check failed" \
    "order/authenticator-key-expired${TAB}krb5:31${TAB}Decrypt integrity check failed" \
    "decrypt/session-key-size-etype${TAB}krb5:188${TAB}Bad encryption type" \
    "etype/ticket-noperm-named${TAB}krb5:236${TAB}Encryption type not permitted" \
    "order/ticket-noperm-replay-again${TAB}krb5:236${TAB}Encryption type not permitted" \
    "order/expired-replay-again${TAB}krb5:34${TAB}Request is a replay" \
    "order/transit-replay-again${TAB}krb5:43${TAB}Illegal cross-realm ticket"; do
    grep -qx "$want" "$OUT/order-mit.tsv" || die "MIT answers otherwise than $want"
done
if ! "$SWEEP" judge-order "$OUT/order.tsv" "$OUT/order-mit.tsv" >"$OUT/order-judge.txt"; then
    grep -m 20 '^PART' "$OUT/order-judge.txt" || true
    log "rd.priv.oracle" "error" ",\"error\":\"order: $(tail -1 "$OUT/order-judge.txt")\""
    exit 1
fi

# kadmind's kpasswd acceptor. The realm is built here, so the oracle's KDB: keytab and the Rust
# acceptor's store are one database (`kdb5_util dump`, read by `rd-sweep judge-explicit`).
docker cp "$SWEEP" "$NAME":/tmp/rd-sweep
mit_oracle_cc "$NAME" /tmp/rd-priv-oracle-kdb /tmp/rd-priv-oracle.c kadm-server -O1 -DKPASSWD_KDB
docker exec "$NAME" kdb5_util create -s -P masterpassword >/dev/null
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'addprinc -randkey ra4user' >/dev/null
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'ktadd -norandkey -k /tmp/cpw.keytab kadmin/changepw' >/dev/null
docker exec "$NAME" kdb5_util dump /tmp/mit.dump
SIP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME")"
[ -n "$SIP" ] || die "the container has no address"
# The cases, each KRB-PRIV naming the container as the receiver; then one pristine request for each
# other receiver address (none, 127.0.0.1, one no machine has) and one ticket sealed in each key of
# kadmin/changepw but its first (`rd-sweep kpasswd` fails on the entry the keytab lacks).
docker exec -e SIP="$SIP" "$NAME" sh -c '
    gen="/tmp/rd-sweep kpasswd /tmp/cpw.keytab ra4user"
    $gen raddr=$SIP >/tmp/kp-frames.tsv
    for ra in none:absent 127.0.0.1:loopback 203.0.113.77:foreign; do
        v=${ra%%:*}; name=${ra#*:}
        if [ "$v" = none ]; then a=""; else a="raddr=$v"; fi
        $gen $a 2>/dev/null | grep "^krb-priv/pristine" | sed "s|^krb-priv/pristine|raddr/$name|" >>/tmp/kp-frames.tsv
    done
    k=1
    while $gen raddr=$SIP entry=$k >/dev/null 2>&1; do
        $gen raddr=$SIP entry=$k 2>/dev/null | grep "^ap-req/pristine" | sed "s|^ap-req/pristine|keysel/entry$k|" >>/tmp/kp-frames.tsv
        k=$((k + 1))
    done'
docker exec -e KRB5RCACHETYPE=none "$NAME" sh -c '/tmp/rd-priv-oracle-kdb kpasswd </tmp/kp-frames.tsv >/tmp/kp-mit.tsv'
docker cp "$NAME":/tmp/kp-frames.tsv "$OUT/kp-frames.tsv"
docker cp "$NAME":/tmp/kp-mit.tsv "$OUT/kp-mit.tsv"
KP_CASES="$(wc -l <"$OUT/kp-frames.tsv" | tr -d ' ')"
[ "$(grep -vc '^#' "$OUT/kp-mit.tsv")" = "$KP_CASES" ] || die "MIT answered $(grep -vc '^#' "$OUT/kp-mit.tsv") of $KP_CASES kpasswd cases"
grep -q '^#local .' "$OUT/kp-mit.tsv" || die "MIT lists no host address"
for pristine in ap-req/pristine krb-priv/pristine raddr/absent; do
    grep -q "^$pristine${TAB}0$" "$OUT/kp-mit.tsv" || die "MIT refuses the pristine kpasswd request $pristine"
done
# MIT looks a receiver address up among the host's (not the loopback) and reads only the first key.
for refused in raddr/loopback raddr/foreign; do
    grep -q "^$refused${TAB}priv:krb5:38$" "$OUT/kp-mit.tsv" || die "MIT reads the KRB-PRIV of $refused"
done
KEYSEL="$(grep -c '^keysel/' "$OUT/kp-mit.tsv" || true)"
[ "$KEYSEL" -ge 1 ] || die "no ticket sealed in a later key"
[ "$(grep -c "^keysel/.*${TAB}req:" "$OUT/kp-mit.tsv" || true)" = "$KEYSEL" ] || die "MIT reads a ticket sealed in a later key"
if ! docker exec "$NAME" sh -c '/tmp/rd-sweep judge-explicit /tmp/kp-frames.tsv /tmp/kp-mit.tsv /tmp/mit.dump masterpassword >/tmp/kp-judge.txt'; then
    docker cp "$NAME":/tmp/kp-judge.txt "$OUT/kp-judge.txt"
    grep -m 20 '^PART' "$OUT/kp-judge.txt" || true
    log "rd.priv.oracle" "error" ",\"error\":\"kpasswd: $(tail -1 "$OUT/kp-judge.txt")\""
    exit 1
fi
KP_OK="$(grep -c "${TAB}0$" "$OUT/kp-mit.tsv" || true)"

# kadmind's GSS acceptor, in the same realm. kadmin/admin and kadmin/changepw exist in a database `kdb5_util
# create` made; kadmin/history (kadmind makes it when a policy keeps history) and a host service join them, and
# `ktadd -norandkey` writes each one's keys.
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'addprinc -randkey kadmin/history' >/dev/null
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'addprinc -randkey host/testhost.kerber.test' >/dev/null
for svc in kadmin/admin kadmin/changepw kadmin/history host/testhost.kerber.test; do
    kadmin_q_ok mit_kadmin_local "$NAME" -- -q "ktadd -norandkey -k /tmp/ka.keytab $svc" >/dev/null
done
docker exec "$NAME" kdb5_util dump /tmp/mit-ka.dump
docker exec "$NAME" sh -c '/tmp/rd-sweep kadmind /tmp/ka.keytab ra4user >/tmp/ka-cases.tsv'
docker exec -e KRB5RCACHETYPE=none "$NAME" sh -c '/tmp/rd-priv-oracle-kdb kadmind </tmp/ka-cases.tsv >/tmp/ka-mit.tsv'
docker cp "$NAME":/tmp/ka-cases.tsv "$OUT/ka-cases.tsv"
docker cp "$NAME":/tmp/ka-mit.tsv "$OUT/ka-mit.tsv"
KA_CASES="$(wc -l <"$OUT/ka-cases.tsv" | tr -d ' ')"
[ "$KA_CASES" -gt 0 ] || die "rd-sweep kadmind wrote no case"
[ "$(wc -l <"$OUT/ka-mit.tsv" | tr -d ' ')" = "$KA_CASES" ] || die "MIT answered $(wc -l <"$OUT/ka-mit.tsv") of $KA_CASES kadmind cases"
# Each service is read with no name; kadmin/admin and kadmin/changepw also by their own name, never by the other's.
# Any database principal is read with no name (RPCSEC_GSS), the history key and a host included.
NK="other:-1780008418"
for want in "kadmin/admin${TAB}0${TAB}0${TAB}krb5:35" "kadmin/changepw${TAB}0${TAB}krb5:35${TAB}0" \
    "kadmin/history${TAB}0${TAB}krb5:35${TAB}krb5:35" "host/testhost.kerber.test${TAB}0${TAB}krb5:35${TAB}krb5:35"; do
    grep -q "^$want$" "$OUT/ka-mit.tsv" || die "MIT answers the pristine kadmind ticket otherwise than $want"
done
# A ticket in a key after the first, or in an enctype the principal has no key in, finds no permitted key by any name.
for cls in 'key[0-9]+' 'etype=[0-9]+'; do
    n="$(grep -cE "/$cls${TAB}" "$OUT/ka-mit.tsv" || true)"
    [ "$n" -ge 1 ] || die "no kadmind ticket of class $cls"
    [ "$(grep -cE "/$cls${TAB}$NK${TAB}$NK${TAB}$NK$" "$OUT/ka-mit.tsv" || true)" = "$n" ] || die "MIT reads a kadmind ticket of class $cls"
done
# The kvno of the ticket's own server: BADKEYVER by the name it is read under, NOT_US by another's.
grep -q "^kadmin/admin/kvno99${TAB}krb5:44${TAB}krb5:44${TAB}krb5:35$" "$OUT/ka-mit.tsv" || die "MIT answers kvno 99 otherwise"
# A cleartext server another than the key's: a name takes the key it names whatever the ticket says; no name looks the
# cleartext server up (its key does not open the ticket, an unknown server is NOT_US).
grep -q "^kadmin/admin/as=kadmin/changepw${TAB}krb5:31${TAB}0${TAB}krb5:31$" "$OUT/ka-mit.tsv" || die "MIT answers a rewritten cleartext server otherwise"
grep -q "^kadmin/admin/as=nosuch/service${TAB}krb5:35${TAB}0${TAB}krb5:35$" "$OUT/ka-mit.tsv" || die "MIT answers an unknown cleartext server otherwise"
if ! docker exec "$NAME" sh -c '/tmp/rd-sweep judge-kdb /tmp/ka-cases.tsv /tmp/ka-mit.tsv /tmp/mit-ka.dump masterpassword >/tmp/ka-judge.txt'; then
    docker cp "$NAME":/tmp/ka-judge.txt "$OUT/ka-judge.txt"
    grep -m 20 '^PART' "$OUT/ka-judge.txt" || true
    log "rd.priv.oracle" "error" ",\"error\":\"kadmind: $(tail -1 "$OUT/ka-judge.txt")\""
    exit 1
fi
docker cp "$NAME":/tmp/ka-judge.txt "$OUT/ka-judge.txt"
KA_OK="$(awk -F"$TAB" '$2 == "0"' "$OUT/ka-mit.tsv" | wc -l | tr -d ' ')"
log "rd.priv.oracle" "ok" ",\"cases\":$CASES,\"mit_accepts\":$MIT_OK,\"rust_parts\":0,\"order_cases\":$ORDER,\"order_rust_parts\":0,\"kpasswd_cases\":$KP_CASES,\"kpasswd_mit_accepts\":$KP_OK,\"kpasswd_rust_parts\":0,\"kadmind_cases\":$KA_CASES,\"kadmind_mit_accepts\":$KA_OK,\"kadmind_rust_parts\":0"
exit 0
