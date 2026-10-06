#!/usr/bin/env bash
# MIT ktadd keytab listed by Rust ktutil; Rust-written keytab kinit -k on MIT; MIT's version-1
# keytab read, and added to as MIT ktutil's wkt adds to it, record for record.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-q.sh"
need_bins krb5-ktutil

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-ktutil-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

if ! command -v docker >/dev/null 2>&1; then
    log "ktutil.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

stock_mit_kdc
mit_live_guard

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-ktutil" "$NAME":/tmp/krb5-ktutil
docker exec "$NAME" chmod +x /tmp/krb5-ktutil

echo "==== MIT ktadd then Rust ktutil list ===="
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'ktadd -k /tmp/mit.keytab -norandkey user'
MITK="$(docker exec "$NAME" klist -k -t -e /tmp/mit.keytab)"
echo "$MITK"
LIST="$(docker exec "$NAME" sh -c 'printf "rkt /tmp/mit.keytab\nlist -t -e\n" | /tmp/krb5-ktutil')"
echo "$LIST"
echo "$LIST" | grep -q 'user@KERBER.TEST'
MIT_KVNO="$(echo "$MITK" | awk '/user@KERBER.TEST/{print $1; exit}')"
RUST_KVNO="$(echo "$LIST" | awk '/user@KERBER.TEST/{print $2; exit}')"
MIT_ET="$(echo "$MITK" | awk -F'[()]' '/user@KERBER.TEST/{print $2; exit}')"
RUST_ET="$(echo "$LIST" | awk '/user@KERBER.TEST/{print $NF; exit}')"
RUST_T="$(echo "$LIST" | awk '/user@KERBER.TEST/{for(i=1;i<=NF;i++) if($i ~ /^t=/){print substr($i,3); exit}}')"
echo "mit_kvno=$MIT_KVNO rust_kvno=$RUST_KVNO"
echo "mit_etype=$MIT_ET rust_etype=$RUST_ET"
echo "rust_timestamp=$RUST_T"
test "$MIT_KVNO" = "$RUST_KVNO"
test "$MIT_ET" = "$RUST_ET"
test -n "$RUST_T"
test "$RUST_T" -gt 0

echo "==== MIT unknown-etype keytab listed by Rust ktutil ===="
docker exec -i "$NAME" python3 - <<'PY'
import struct
def put16(b, data):
    return b + struct.pack('>H', len(data)) + data
body = struct.pack('>H', 1)
body = put16(body, b'KERBER.TEST')
body = put16(body, b'user')
body += struct.pack('>i', 1)
body += struct.pack('>I', 1700000000)
body += struct.pack('B', 3)
body += struct.pack('>H', 99)
body = put16(body, b'\x00' * 16)
body += struct.pack('>I', 3)
open('/tmp/unk.keytab', 'wb').write(b'\x05\x02' + struct.pack('>i', len(body)) + body)
PY
MITU="$(docker exec "$NAME" sh -c 'printf "rkt /tmp/unk.keytab\nlist\n" | ktutil')"
echo "$MITU"
echo "$MITU" | grep -q 'user@KERBER.TEST'
echo "$MITU" | grep -Eq ' 3 .*user@KERBER.TEST'
RUSTU="$(docker exec "$NAME" sh -c 'printf "rkt /tmp/unk.keytab\nlist -e\n" | /tmp/krb5-ktutil')"
echo "$RUSTU"
echo "$RUSTU" | grep -q 'user@KERBER.TEST'
echo "$RUSTU" | grep -q 'Unknown (99)'
echo "$RUSTU" | grep -Eq ' 3 .*user@KERBER.TEST Unknown \(99\)'

echo "==== Rust ktutil-written keytab MIT kinit -k ===="
docker exec -e KRB5_PASSWORD=userpassword "$NAME" sh -c \
    'printf "addent -password -p user@KERBER.TEST -k 1 -e aes256-cts-hmac-sha1-96\nwkt /tmp/rust.keytab\n" | /tmp/krb5-ktutil'
docker exec "$NAME" kinit -k -t /tmp/rust.keytab user@KERBER.TEST
KLIST="$(docker exec "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'

echo "==== MIT version-1 keytab: Rust ktutil reads it and adds to it as MIT ktutil does ===="
# MIT keeps an existing keytab's version (krb5_ktfileint_open): ktadd onto a file holding only the
# version-1 header writes version-1 records in host byte order, a kvno past 255 in the 32-bit
# field, the last record four bytes short of its size (kt_file.c:1127-1269,1314-1382). wkt adds
# each entry the same way (ktutil_write_keytab): onto a copy of that file in version 1, and to a
# new file at version 2.
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'modprinc -kvno 300 user'
docker exec "$NAME" sh -c 'printf "\005\001" >/tmp/v1.keytab'
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'ktadd -k /tmp/v1.keytab -norandkey user'
docker exec "$NAME" od -A d -t x1 -N 10 /tmp/v1.keytab
MITV1="$(docker exec "$NAME" klist -k -e /tmp/v1.keytab | awk '/user@KERBER.TEST/{split($0, a, /[()]/); print $1, a[2]}')"
RUSTV1="$(docker exec "$NAME" sh -c 'printf "rkt /tmp/v1.keytab\nlist -e\n" | /tmp/krb5-ktutil' |
    awk '/user@KERBER.TEST/{print $2, $NF}')"
echo "mit_v1: $(echo "$MITV1" | paste -sd,)"
echo "rust_v1: $(echo "$RUSTV1" | paste -sd,)"
echo "$MITV1" | grep -q '^300 '
test "$MITV1" = "$RUSTV1"
docker exec "$NAME" sh -c 'cp /tmp/v1.keytab /tmp/v1-mit.keytab && cp /tmp/v1.keytab /tmp/v1-rust.keytab'
T0="$(docker exec "$NAME" date +%s)"
for k in mit rust; do
    if [ "$k" = mit ]; then util=ktutil; else util=/tmp/krb5-ktutil; fi
    docker exec "$NAME" sh -c "printf 'rkt /tmp/mit.keytab\nwkt /tmp/v1-$k.keytab\n' | $util >/dev/null"
    docker exec "$NAME" sh -c "printf 'rkt /tmp/v1.keytab\nwkt /tmp/new-$k.keytab\n' | $util >/dev/null"
done
T1="$(docker exec "$NAME" date +%s)"
HEADS="$(docker exec "$NAME" sh -c 'for f in v1-mit v1-rust new-mit new-rust; do printf "%s %s\n" $f "$(od -A n -t x1 -N 2 /tmp/$f.keytab | tr -d " ")"; done')"
echo "$HEADS"
test "$(echo "$HEADS" | awk '{print $2}' | paste -sd,)" = "0501,0501,0502,0502"
# Each entry wkt writes gets the time of day (krb5_ktfileint_write_entry), so the two files are
# compared record by record with each timestamp aside: equal, or in both the time of the writes.
ktsame() {
    docker exec -i "$NAME" python3 - "$@" <<'PY'
import struct, sys
a, b, t0, t1 = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
def stamps(path):
    d = bytearray(open(path, "rb").read())
    v1 = d[1] == 1
    o = "<" if v1 else ">"
    i, out = 2, []
    while i + 4 <= len(d):
        (size,) = struct.unpack_from(o + "i", d, i)
        i += 4
        if size == 0:
            break
        if size < 0:
            i -= size
            continue
        j = i
        (n,) = struct.unpack_from(o + "H", d, j)
        j += 2
        for _ in range(n if v1 else n + 1):
            (ln,) = struct.unpack_from(o + "H", d, j)
            j += 2 + ln
        j += 0 if v1 else 4
        out.append(struct.unpack_from(o + "I", d, j)[0])
        d[j:j + 4] = bytes(4)
        i += size
    return bytes(d), out
(da, sa), (db, sb) = stamps(a), stamps(b)
assert da == db, "the keytabs differ beyond their timestamps"
assert len(sa) == len(sb) and sa, (sa, sb)
for x, y in zip(sa, sb):
    assert x == y or (t0 <= x <= t1 and t0 <= y <= t1), (x, y, t0, t1)
new = sum(t0 <= x <= t1 for x in sa)
print(f"{a} = {b} but for timestamps; {new} of {len(sa)} records stamped at the write")
PY
}
ktsame /tmp/v1-mit.keytab /tmp/v1-rust.keytab "$T0" "$T1"
ktsame /tmp/new-mit.keytab /tmp/new-rust.keytab "$T0" "$T1"
docker exec "$NAME" klist -k /tmp/v1-rust.keytab | grep -c 'user@KERBER.TEST'
echo "v1_append=same new_file_v2=same"
log "ktutil.gate" "ok" ',"principal":"user@KERBER.TEST"'
exit 0
