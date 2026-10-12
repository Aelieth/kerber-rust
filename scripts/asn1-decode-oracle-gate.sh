#!/usr/bin/env bash
# MIT 1.22.2's own decoder over the decode sweep: `asn1-sweep corpus` breaks every explicit [n]
# field and SEQUENCE OF element of each message type libkrb5 decodes, and
# scripts/oracle/asn1-decode-oracle.c runs each case through decode_krb5_<type>, then through it
# again the Rust decoder's re-encoding of each case it decodes (`asn1-sweep rust`). Red when the
# Rust decoder refuses a case MIT decodes, decodes one MIT refuses, or decodes one to a value MIT
# re-encodes otherwise, and when the golden the unit test reads
# (crates/krb5-tools/tests/data/asn1-mit-golden.tsv) is not MIT's answer.
# Isolated: docker --entrypoint sleep; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
need_bins asn1-sweep

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-asn1-decode-oracle"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
OUT="$SCRATCH/asn1-decode-oracle"
mkdir -p "$OUT"
SWEEP="${CARGO_TARGET_DIR:-target}/debug/asn1-sweep"
GOLDEN="crates/krb5-tools/tests/data/asn1-mit-golden.tsv"

need_image
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "asn1.decode.oracle" "error" ',"error":"MIT image unavailable"'
    exit 2
fi

shell_container 180

"$SWEEP" corpus >"$OUT/corpus.tsv"
"$SWEEP" rust >"$OUT/rust.tsv"
docker cp "$ROOT/scripts/oracle/asn1-decode-oracle.c" "$NAME":/tmp/asn1-decode-oracle.c
mit_oracle_cc "$NAME" /tmp/asn1-decode-oracle /tmp/asn1-decode-oracle.c krb5 -O1
docker cp "$OUT/corpus.tsv" "$NAME":/tmp/asn1-corpus.tsv
docker cp "$OUT/rust.tsv" "$NAME":/tmp/asn1-rust.tsv
docker exec "$NAME" sh -c '/tmp/asn1-decode-oracle </tmp/asn1-corpus.tsv >/tmp/asn1-mit.tsv &&
    /tmp/asn1-decode-oracle </tmp/asn1-rust.tsv >/tmp/asn1-mit-rust.tsv'
docker cp "$NAME":/tmp/asn1-mit.tsv "$OUT/mit.tsv"
docker cp "$NAME":/tmp/asn1-mit-rust.tsv "$OUT/mit-rust.tsv"
CASES="$(wc -l <"$OUT/corpus.tsv" | tr -d ' ')"
MIT_OK="$(grep -c "$(printf '\tOK\t')" "$OUT/mit.tsv" || true)"
[ "$(wc -l <"$OUT/mit.tsv" | tr -d ' ')" = "$CASES" ] || die "MIT's decoder answered $(wc -l <"$OUT/mit.tsv") of $CASES cases"
if ! "$SWEEP" golden "$OUT/mit.tsv" "$OUT/mit-rust.tsv" "$OUT/golden.tsv" >"$OUT/judge.txt"; then
    grep -m 20 '^PART' "$OUT/judge.txt" || true
    log "asn1.decode.oracle" "error" ",\"error\":\"$(tail -1 "$OUT/judge.txt")\""
    exit 1
fi
if ! cmp -s "$OUT/golden.tsv" "$GOLDEN"; then
    diff "$GOLDEN" "$OUT/golden.tsv" | head -20 || true
    log "asn1.decode.oracle" "error" ',"error":"the committed golden is not MIT 1.22.2s answer"'
    exit 1
fi
log "asn1.decode.oracle" "ok" ",\"cases\":$CASES,\"mit_decodes\":$MIT_OK,\"rust_parts\":0,\"golden\":\"$GOLDEN\""
exit 0
