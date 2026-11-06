#!/bin/bash
# build-oracle.sh SRC OUTDIR: rd-priv-oracle, RA r4's library acceptor (MIT's krb5_rd_req / rd_priv / rd_safe in a C program), built from the tree's scripts/oracle/rd-priv-oracle.c against
# the host's libkrb5. The host (the rust-dev distrobox) is Fedora 43 with krb5-devel and krb5-libs 1.22.2-4.fc43, the lab VMs' own MIT, so the program runs on the VMs: RA r4 built it in
# a Fedora 43 container for the same reason. No docker. The VM-side checks are the driver's (ldd finds every library; the acceptor's 652 / 75 / 3 rows).
# Writes OUTDIR/rd-priv-oracle, build.txt (the toolchain and the libraries it linked) and oracle-sha256.txt.
set -eu
SRC=${1:?source file}
OUT=${2:?output directory}
[ -f "$SRC" ] || { echo "build-oracle.sh: $SRC is missing" >&2; exit 2; }
grep -q 'Fedora release 43' /etc/fedora-release || { echo "build-oracle.sh: the host is not Fedora 43 ($(cat /etc/fedora-release)): the oracle would not match the VMs' libkrb5" >&2; exit 3; }
rpm -q krb5-libs | grep -Eq '^krb5-libs-1\.22\.2-[0-9]+\.fc43' || { echo "build-oracle.sh: the host's krb5-libs is not 1.22.2-<rel>.fc43 ($(rpm -q krb5-libs))" >&2; exit 3; }
mkdir -p "$OUT"
{
    echo "== build"
    read -r -a CF <<< "$(krb5-config --cflags krb5)"; read -r -a LF <<< "$(krb5-config --libs krb5)"
    cc -O1 -o "$OUT/rd-priv-oracle" "$SRC" "${CF[@]}" "${LF[@]}" && echo build_rc=0
    echo "== rpm -q krb5-devel krb5-libs gcc"; rpm -q krb5-devel krb5-libs gcc
    echo "== krb5-config --version; cc --version"; krb5-config --version; cc --version | head -1; cat /etc/fedora-release
    echo "== ldd"; ldd "$OUT/rd-priv-oracle"
    echo "== needed / glibc"; readelf -d "$OUT/rd-priv-oracle" | grep NEEDED; objdump -T "$OUT/rd-priv-oracle" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1
} > "$OUT/build.txt" 2>&1
grep -q '^build_rc=0$' "$OUT/build.txt" || { cat "$OUT/build.txt" >&2; exit 4; }
chmod 755 "$OUT/rd-priv-oracle"
{ sha256sum "$SRC"; ( cd "$OUT" && sha256sum rd-priv-oracle ); } | tee "$OUT/oracle-sha256.txt"
