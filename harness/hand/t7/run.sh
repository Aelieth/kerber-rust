#!/usr/bin/env bash
# T-7: the dudect harness, built from this checkout, over all 48 ops.
# One seed, three user-mode counters, --no-early-stop, each class's per-sample counts (--verbose);
# then the AES-SHA2 watch, in wall time, which counts only on the fixed clock.
# The caller pins the CPU (taskset) and sets the clock; this script changes nothing on the host.
# T7_DRY=1 runs every pass with a few samples, to show it runs. T7_OUT names the results directory.
# The build takes the tree's .cargo/config.toml (lld, p384_backend="fiat"), so RUSTFLAGS is unset.
set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TGT=$(mktemp -d "${TMPDIR:-/var/tmp}/t7-target.XXXXXX") || exit 1
trap 'rm -rf "$TGT"' EXIT
(cd "$HERE" && env -u RUSTFLAGS cargo build --release --locked --target-dir "$TGT") || exit 1
B=$TGT/release/timing
SEED=0x4b455242
OUT=${T7_OUT:-${TMPDIR:-/var/tmp}/t7-results-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$OUT" || exit 1

SYM=(aes128-sha1-enc aes128-sha1-dec aes256-sha1-enc aes256-sha1-dec aes128-sha256-enc aes128-sha256-dec aes256-sha384-enc aes256-sha384-dec cksum-verify des3-enc des3-dec rc4-enc rc4-dec cam128-enc cam128-dec cam256-enc cam256-dec)
CPK=(spake-p256 spake-ed25519 ecdh-p256)
PK=(s2k-aes256 rsa-2048-msg rsa-2048-key rsa-2048-3p-msg modp1024 modp2048 ecdh-p256-pk ecdh-p384 ecdh-p521 ecdsa-p224 ecdsa-p256 ecdsa-p384 ecdsa-p521 ecdsa-secp256k1 ecdsa-bp256r1 ecdsa-bp256t1 ecdsa-bp384r1 ecdsa-bp384t1 ecdsa-bp512r1 ecdsa-bp512t1 ecdsa-bp256r1-k ecdsa-bp256t1-k ecdsa-bp384r1-k ecdsa-bp384t1-k ecdsa-bp512r1-k ecdsa-bp512t1-k)
SLOW=(rsa-8192-msg modp4096)
AES2=(aes128-sha256-enc aes128-sha256-dec aes256-sha384-enc aes256-sha384-dec)

# Samples per op (both classes): counts are exact, so instructions and branches need few;
# cycles need more; the slow ops get fewer. s2k-aes256 runs MIT's default count, 4096 (about 3 ms).
if [ "${T7_DRY:-0}" = 1 ]; then
    N_EXACT_SYM=200 N_EXACT_PK=20 N_EXACT_SLOW=2
    N_CYC_SYM=1000 N_CYC_CPK=200 N_CYC_PK=20 N_CYC_SLOW=2 N_WATCH=1000
else
    N_EXACT_SYM=20000 N_EXACT_PK=2000 N_EXACT_SLOW=200
    N_CYC_SYM=1000000 N_CYC_CPK=20000 N_CYC_PK=20000 N_CYC_SLOW=2000 N_WATCH=1000000
fi

run() { # label count samples ops...
    local label=$1 count=$2 n=$3 rc t0
    shift 3
    local args=()
    for o in "$@"; do args+=(--op "$o"); done
    t0=$(date +%s)
    "$B" --seed "$SEED" --count "$count" --no-early-stop --samples "$n" --verbose "${args[@]}" \
        > "$OUT/$label.log" 2> "$OUT/$label.err"
    rc=$?
    printf '%s count=%s samples=%s rc=%s seconds=%s\n' "$label" "$count" "$n" "$rc" "$(( $(date +%s) - t0 ))" \
        | tee -a "$OUT/summary.txt"
}

{
    printf 'start %s host=%s cpus=%s dry=%s\n' "$(date -u +%FT%TZ)" "$(hostname)" \
        "$(taskset -pc $$ 2>/dev/null | sed 's/.*: //')" "${T7_DRY:-0}"
    printf 'commit %s dirty=%s\n' "$(git -C "$HERE" rev-parse HEAD)" \
        "$(git -C "$HERE" status --porcelain --untracked-files=no | grep -q . && echo yes || echo no)"
    rustc -V
    sha256sum "$B"
} > "$OUT/summary.txt"
{
    for c in instructions branches; do
        run "$c-sym" "$c" "$N_EXACT_SYM" "${SYM[@]}" "${CPK[@]}"
        run "$c-pk" "$c" "$N_EXACT_PK" "${PK[@]}"
        run "$c-slow" "$c" "$N_EXACT_SLOW" "${SLOW[@]}"
    done
    run cycles-sym cycles "$N_CYC_SYM" "${SYM[@]}"
    run cycles-cpk cycles "$N_CYC_CPK" "${CPK[@]}"
    run cycles-pk cycles "$N_CYC_PK" "${PK[@]}"
    run cycles-slow cycles "$N_CYC_SLOW" "${SLOW[@]}"
    run watch-aes-sha2-time time "$N_WATCH" "${AES2[@]}"
}
printf 'end %s\n' "$(date -u +%FT%TZ)" >> "$OUT/summary.txt"
grep -h '^op=' "$OUT"/*.log > "$OUT/verdicts.txt"
echo "results: $OUT"
