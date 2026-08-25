#!/usr/bin/env python3
"""L2: Samba kcrypto recomputes Rust PAC signatures 6/7/16/19."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kcrypto import Cksumtype, Enctype, Key, make_checksum

KU = 17
PAC_SRV = 6
PAC_KDC = 7
PAC_TICKET = 16
PAC_FULL = 19

CKSUM = {
    15: Cksumtype.SHA1_AES128,
    16: Cksumtype.SHA1_AES256,
}
ENCTYPE = {
    17: Enctype.AES128,
    18: Enctype.AES256,
}


def parse_pac(blob: bytes):
    n, _ver = struct.unpack_from("<II", blob)
    bufs = []
    for i in range(n):
        typ, size, off = struct.unpack_from("<IIQ", blob, 8 + i * 16)
        bufs.append((typ, off, size, blob[off : off + size]))
    return bufs


def zeroed(blob: bytes, bufs, kinds) -> bytes:
    out = bytearray(blob)
    for typ, off, size, _data in bufs:
        if typ in kinds and size > 4:
            for i in range(off + 4, off + size):
                out[i] = 0
    return bytes(out)


def sig_mac(data: bytes) -> tuple[int, bytes]:
    (stype,) = struct.unpack_from("<I", data)
    return stype, data[4:]


def load_keys(path: str):
    etype, server, kdc = None, None, None
    for line in open(path, encoding="ascii"):
        line = line.strip()
        if line.startswith("etype="):
            etype = int(line.split("=", 1)[1])
        elif line.startswith("server="):
            server = bytes.fromhex(line.split("=", 1)[1])
        elif line.startswith("kdc="):
            kdc = bytes.fromhex(line.split("=", 1)[1])
    if etype is None or not server or not kdc:
        raise SystemExit("pac_l2: keys file missing etype/server/kdc")
    enc = ENCTYPE[etype]
    return Key(enc, server), Key(enc, kdc)


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: pac_l2.py <pac.bin> <enc_tkt.bin> <keys.txt>", file=sys.stderr)
        return 2
    blob = open(sys.argv[1], "rb").read()
    enc_tkt = open(sys.argv[2], "rb").read()
    server_key, kdc_key = load_keys(sys.argv[3])
    bufs = parse_pac(blob)
    by_type = {t: (off, size, data) for t, off, size, data in bufs}
    for need in (PAC_SRV, PAC_KDC, PAC_TICKET, PAC_FULL):
        if need not in by_type:
            print("L2_MISSING", need)
            return 1

    srv_type, srv_mac = sig_mac(by_type[PAC_SRV][2])
    kdc_type, kdc_mac = sig_mac(by_type[PAC_KDC][2])
    t16_type, t16_mac = sig_mac(by_type[PAC_TICKET][2])
    t19_type, t19_mac = sig_mac(by_type[PAC_FULL][2])
    for st, name in (
        (srv_type, "server"),
        (kdc_type, "kdc"),
        (t16_type, "ticket"),
        (t19_type, "full"),
    ):
        if st not in CKSUM:
            print("L2_BAD_CKSUMTYPE", name, st)
            return 1

    server_in = zeroed(blob, bufs, (PAC_SRV, PAC_KDC))
    full_in = zeroed(blob, bufs, (PAC_SRV, PAC_KDC, PAC_FULL))
    got_srv = make_checksum(CKSUM[srv_type], server_key, KU, server_in)
    got_kdc = make_checksum(CKSUM[kdc_type], kdc_key, KU, srv_mac)
    got_full = make_checksum(CKSUM[t19_type], kdc_key, KU, full_in)
    got_t16 = make_checksum(CKSUM[t16_type], kdc_key, KU, enc_tkt)

    failed = []
    if got_srv != srv_mac:
        failed.append("6")
    if got_kdc != kdc_mac:
        failed.append("7")
    if got_t16 != t16_mac:
        failed.append("16")
    if got_full != t19_mac:
        failed.append("19")
    if failed:
        print("L2_MISMATCH", ",".join(failed))
        return 1
    print("L2_OK types 6,7,16,19")
    return 0


if __name__ == "__main__":
    sys.exit(main())
