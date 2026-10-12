#!/usr/bin/env bash
# MIT 1.22.2's krb5_rd_req, krb5_rd_priv and krb5_rd_safe (scripts/oracle/rd-priv-oracle.c, the
# sibling of rd-safe-oracle.c) against the Rust acceptor: `rd-sweep cases` breaks an AP-REQ's
# authenticator, a KRB-PRIV's EncKrbPrivPart and a KRB-SAFE's body as the decode sweep breaks a
# message, re-encrypting or re-signing each, and both sides answer every case. Red on any case the
# Rust acceptor answers otherwise than MIT (accepted, an ASN.1 error, or the krb5 code).
# Isolated: docker --entrypoint sleep; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
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

shell_container 180

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
log "rd.priv.oracle" "ok" ",\"cases\":$CASES,\"mit_accepts\":$MIT_OK,\"rust_parts\":0"
exit 0
