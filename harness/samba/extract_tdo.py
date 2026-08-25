#!/usr/bin/env python3
"""Print TDO SID and CLEAR trust password from sam.ldb."""
import sys

from samba.auth import system_session
from samba.credentials import Credentials
from samba.dcerpc import drsblobs, lsa, security
from samba.ndr import ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-sid":
        lp = LoadParm()
        lp.load_default()
        creds = Credentials()
        creds.guess(lp)
        sam = SamDB(session_info=system_session(), credentials=creds, lp=lp)
        res = sam.search(sam.domain_dn(), scope=0, attrs=["objectSid"])
        sid = str(ndr_unpack(security.dom_sid, res[0]["objectSid"][0]))
        print("DOMAIN_SID", sid)
        return 0
    if len(sys.argv) != 2:
        print("usage: extract_tdo.py <TRUST_REALM>|--self-sid", file=sys.stderr)
        return 2
    realm = sys.argv[1]
    lp = LoadParm()
    lp.load_default()
    creds = Credentials()
    creds.guess(lp)
    sam = SamDB(session_info=system_session(), credentials=creds, lp=lp)
    dn = f"CN={realm},CN=System,{sam.domain_dn()}"
    res = sam.search(dn, scope=0, attrs=["securityIdentifier", "trustAuthOutgoing", "trustAuthIncoming", "trustType", "trustDirection"])
    if not res:
        print("TDO_MISSING", dn)
        return 1
    m = res[0]
    sid = str(ndr_unpack(security.dom_sid, m["securityIdentifier"][0]))
    blob = bytes(m["trustAuthOutgoing"][0]) if "trustAuthOutgoing" in m else b""
    if not blob and "trustAuthIncoming" in m:
        blob = bytes(m["trustAuthIncoming"][0])
    password_hex = ""
    auth_type = -1
    if blob:
        info = ndr_unpack(drsblobs.trustAuthInOutBlob, blob)
        arr = info.current
        if arr is not None and arr.count >= 1:
            a = arr.array[0]
            auth_type = int(a.AuthType)
            raw = bytes(a.AuthInfo.password)
            print("TDO_RAW_HEX", raw.hex())
            if auth_type == int(lsa.TRUST_AUTH_TYPE_CLEAR):
                password = raw.decode("utf-16-le", "surrogatepass")
                password_hex = password.encode("utf-8", "surrogatepass").hex()
            else:
                password_hex = raw.hex()
    print("TDO_SID", sid)
    print("TDO_AUTH_TYPE", auth_type)
    print("TDO_PASSWORD_HEX", password_hex)
    print("TDO_OK", dn)
    return 0 if password_hex else 1


if __name__ == "__main__":
    sys.exit(main())
