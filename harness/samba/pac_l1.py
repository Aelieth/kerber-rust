#!/usr/bin/env python3
"""L1: Samba IDL decode of a Rust-issued PAC (PAC_DATA_RAW + typed buffers)."""
import struct
import sys

from samba.dcerpc import krb5pac, security
from samba.ndr import ndr_pack, ndr_print, ndr_unpack

NEED = {
    krb5pac.PAC_TYPE_LOGON_INFO: "LOGON_INFO",
    krb5pac.PAC_TYPE_LOGON_NAME: "CLIENT_INFO",
    krb5pac.PAC_TYPE_UPN_DNS_INFO: "UPN_DNS",
    krb5pac.PAC_TYPE_TICKET_CHECKSUM: "TICKET_CHECKSUM",
    krb5pac.PAC_TYPE_ATTRIBUTES_INFO: "ATTRIBUTES",
    krb5pac.PAC_TYPE_REQUESTER_SID: "REQUESTER_SID",
    krb5pac.PAC_TYPE_FULL_CHECKSUM: "FULL_CHECKSUM",
    krb5pac.PAC_TYPE_SRV_CHECKSUM: "SRV_CHECKSUM",
    krb5pac.PAC_TYPE_KDC_CHECKSUM: "KDC_CHECKSUM",
}

DUMMY = "S-1-5-21-1-2-3"


def utf16_at(data: bytes, off: int, length: int) -> str:
    return data[off : off + length].decode("utf-16le")


def write_dummy_requestor(src: str, dst: str) -> int:
    blob = bytearray(open(src, "rb").read())
    n, _ver = struct.unpack_from("<II", blob)
    dummy = ndr_pack(security.dom_sid("S-1-5-21-1-2-3-1000"))
    for i in range(n):
        typ, size, off = struct.unpack_from("<IIQ", blob, 8 + i * 16)
        if typ != 18:
            continue
        if len(dummy) > size:
            print("L1_DUMMY_TOO_BIG", len(dummy), size)
            return 1
        blob[off : off + len(dummy)] = dummy
        struct.pack_into("<I", blob, 8 + i * 16 + 4, len(dummy))
        open(dst, "wb").write(blob)
        return 0
    print("L1_NO_REQUESTOR")
    return 1


def extra_sid_strings(ctr) -> list[str]:
    extra = []
    try:
        for item in ctr.info.info3.sids or []:
            extra.append(str(getattr(item, "sid", item)))
    except (AttributeError, TypeError):
        return []
    return extra


def dump_sids(path: str) -> int:
    blob = open(path, "rb").read()
    raw = ndr_unpack(krb5pac.PAC_DATA_RAW, blob)
    by_type = {int(b.type): bytes(b.info.remaining) for b in raw.buffers}
    if 1 not in by_type:
        print("L1_NO_LOGON", "have", sorted(by_type))
        return 1
    ctr = ndr_unpack(krb5pac.PAC_LOGON_INFO_CTR, by_type[1][16:], allow_remaining=True)
    base = ctr.info.info3.base
    extra = extra_sid_strings(ctr)
    print("EXTRA_SIDS", ",".join(extra) if extra else "-")
    print(
        "SIDFILTER_OK",
        "domain",
        str(base.domain_sid),
        "rid",
        int(base.rid),
        "account",
        str(base.account_name.string),
        "types",
        sorted(by_type),
    )
    return 0


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "--write-dummy":
        return write_dummy_requestor(sys.argv[2], sys.argv[3])
    if len(sys.argv) == 3 and sys.argv[1] == "--sids":
        return dump_sids(sys.argv[2])
    if len(sys.argv) != 2:
        print(
            "usage: pac_l1.py <pac.bin> | --write-dummy <src> <dst> | --sids <pac.bin>",
            file=sys.stderr,
        )
        return 2
    blob = open(sys.argv[1], "rb").read()
    raw = ndr_unpack(krb5pac.PAC_DATA_RAW, blob)
    print(ndr_print(raw)[:2000])
    by_type = {int(b.type): bytes(b.info.remaining) for b in raw.buffers}
    types = sorted(by_type)
    missing = [f"{n}={NEED[n]}" for n in NEED if n not in by_type]
    if missing:
        print("L1_MISSING", ",".join(missing), "have", types)
        return 1

    req = ndr_unpack(security.dom_sid, by_type[18], allow_remaining=True)
    requestor = str(req)
    if requestor.startswith(DUMMY):
        print("L1_DUMMY_REQUESTOR", requestor)
        return 1

    attr = by_type[17]
    flags_len, flags = struct.unpack_from("<II", attr)
    if flags_len != 2 or flags & 1 == 0:
        print("L1_BAD_ATTRIBUTES", flags_len, flags)
        return 1

    upn_buf = by_type[12]
    upn_len, upn_off, dns_len, dns_off, upn_flags = struct.unpack_from("<HHHHI", upn_buf)
    if upn_flags & 2 == 0:
        print("L1_UPN_NO_SAM_SID", upn_flags)
        return 1
    upn = utf16_at(upn_buf, upn_off, upn_len)
    dns = utf16_at(upn_buf, dns_off, dns_len)

    logon = by_type[1]
    ctr = ndr_unpack(krb5pac.PAC_LOGON_INFO_CTR, logon[16:], allow_remaining=True)
    base = ctr.info.info3.base
    logon_sid = str(base.domain_sid)
    rid = int(base.rid)
    account = str(base.account_name.string)
    extra_sids = extra_sid_strings(ctr)
    if logon_sid.startswith(DUMMY):
        print("L1_DUMMY_DOMAIN", logon_sid)
        return 1
    if not requestor.startswith(logon_sid + "-"):
        print("L1_REQUESTOR_MISMATCH", requestor, logon_sid, rid)
        return 1

    print("EXTRA_SIDS", ",".join(extra_sids) if extra_sids else "-")
    print(
        "L1_OK",
        "types",
        types,
        "requestor",
        requestor,
        "domain",
        logon_sid,
        "rid",
        rid,
        "account",
        account,
        "upn",
        upn,
        "dns",
        dns,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
