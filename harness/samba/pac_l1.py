#!/usr/bin/env python3
"""L1: Samba IDL decode of a Rust-issued PAC (PAC_DATA_RAW + typed buffers)."""
import struct
import sys

from samba.dcerpc import krb5pac, security
from samba.ndr import ndr_print, ndr_unpack

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


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: pac_l1.py <pac.bin>", file=sys.stderr)
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
    if logon_sid.startswith(DUMMY):
        print("L1_DUMMY_DOMAIN", logon_sid)
        return 1
    if not requestor.startswith(logon_sid + "-"):
        print("L1_REQUESTOR_MISMATCH", requestor, logon_sid, rid)
        return 1

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
