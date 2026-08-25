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


def read_der_len(data: bytes, off: int):
    if off >= len(data):
        return None
    b = data[off]
    if b < 0x80:
        return b, 1
    nbytes = b & 0x7F
    if nbytes == 0 or nbytes > 4 or off + 1 + nbytes > len(data):
        return None
    n = 0
    for i in range(nbytes):
        n = (n << 8) | data[off + 1 + i]
    return n, 1 + nbytes


def read_tlv(data: bytes, off: int):
    if off >= len(data):
        return None
    tag = data[off]
    if tag & 0x1F == 0x1F:
        return None
    constructed = tag & 0x20 != 0
    parsed = read_der_len(data, off + 1)
    if parsed is None:
        return None
    length, len_bytes = parsed
    hdr = 1 + len_bytes
    start = off + hdr
    end = start + length
    if end > len(data):
        return None
    return tag, constructed, data[start:end], hdr + length


def encode_der_len(n: int) -> bytes:
    if n <= 127:
        return bytes([n])
    if n <= 255:
        return bytes([0x81, n])
    if n <= 65535:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    if n <= 16_777_215:
        return bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    return bytes(
        [0x84, (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]
    )


def encode_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + encode_der_len(len(content)) + content


def rewrite_one(data: bytes, off: int, pac: bytes):
    parsed = read_tlv(data, off)
    if parsed is None:
        return None
    tag, constructed, content, tlv_len = parsed
    orig = data[off : off + tlv_len]
    if tag == 0x04 and content == pac:
        return encode_tlv(0x04, b"\x00"), True, tlv_len
    if constructed:
        children = bytearray()
        pos = 0
        any_r = False
        while pos < len(content):
            inner = rewrite_one(content, pos, pac)
            if inner is None:
                return None
            ch, replaced, n = inner
            children.extend(ch)
            any_r = any_r or replaced
            pos += n
        if pos != len(content):
            return None
        if any_r:
            return encode_tlv(tag, bytes(children)), True, tlv_len
        return orig, False, tlv_len
    if tag == 0x04 and content[:1] == b"\x30":
        inner = rewrite_one(content, 0, pac)
        if inner is not None:
            inn, ok, n = inner
            if ok and n == len(content):
                return encode_tlv(tag, inn), True, tlv_len
    return orig, False, tlv_len


def zero_pac_ad_data(enc_tkt: bytes, pac: bytes):
    if not pac:
        return None
    inner = rewrite_one(enc_tkt, 0, pac)
    if inner is None:
        return None
    out, replaced, n = inner
    if replaced and n == len(enc_tkt):
        return out
    return None


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

    failed = []
    if got_srv != srv_mac:
        failed.append("6")
    if got_kdc != kdc_mac:
        failed.append("7")
    if got_full != t19_mac:
        failed.append("19")
    pre16 = zero_pac_ad_data(enc_tkt, blob)
    if pre16 is None:
        if not failed:
            print("L2_NO_TYPE16_PREIMAGE")
            return 1
    elif make_checksum(CKSUM[t16_type], kdc_key, KU, pre16) != t16_mac:
        failed.append("16")
    if failed:
        print("L2_MISMATCH", ",".join(failed))
        return 1
    print("L2_OK types 6,7,16,19")
    return 0


if __name__ == "__main__":
    sys.exit(main())
