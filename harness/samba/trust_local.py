#!/usr/bin/env python3
"""Create a local trustedDomain for KERBER.TEST (no remote DC lookup)."""
import argparse
import sys

from samba.auth import system_session
from samba.credentials import Credentials
from samba.dcerpc import drsblobs, lsa, security
from samba.ndr import ndr_pack
from samba.param import LoadParm
from samba.samdb import SamDB
import ldb


def auth_blob(password: str) -> bytes:
    raw = password.encode("utf-16-le")
    info = drsblobs.AuthenticationInformation()
    info.LastUpdateTime = 0
    info.AuthType = lsa.TRUST_AUTH_TYPE_CLEAR
    info.AuthInfo.size = len(raw)
    info.AuthInfo.password = list(raw)
    arr = drsblobs.AuthenticationInformationArray()
    arr.count = 1
    arr.array = [info]
    blob = drsblobs.trustAuthInOutBlob()
    blob.count = 1
    blob.current = arr
    return ndr_pack(blob)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--realm", required=True)
    p.add_argument("--flat", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--sid", required=True)
    p.add_argument("--type", choices=("mit", "uplevel"), default="uplevel")
    args = p.parse_args()
    lp = LoadParm()
    lp.load_default()
    creds = Credentials()
    creds.guess(lp)
    sam = SamDB(session_info=system_session(), credentials=creds, lp=lp)
    packed = auth_blob(args.password)
    sid = security.dom_sid(args.sid)
    dn = f"CN={args.realm},CN=System,{sam.domain_dn()}"
    try:
        sam.delete(dn)
    except ldb.LdbError:
        pass
    trust_type = (
        int(lsa.LSA_TRUST_TYPE_MIT)
        if args.type == "mit"
        else int(lsa.LSA_TRUST_TYPE_UPLEVEL)
    )
    msg = ldb.Message()
    msg.dn = ldb.Dn(sam, dn)
    msg["objectClass"] = ldb.MessageElement(
        "trustedDomain", ldb.FLAG_MOD_ADD, "objectClass"
    )
    msg["flatName"] = ldb.MessageElement(args.flat, ldb.FLAG_MOD_ADD, "flatName")
    msg["trustPartner"] = ldb.MessageElement(args.realm, ldb.FLAG_MOD_ADD, "trustPartner")
    msg["trustPosixOffset"] = ldb.MessageElement("0", ldb.FLAG_MOD_ADD, "trustPosixOffset")
    msg["trustDirection"] = ldb.MessageElement("3", ldb.FLAG_MOD_ADD, "trustDirection")
    msg["trustType"] = ldb.MessageElement(str(trust_type), ldb.FLAG_MOD_ADD, "trustType")
    msg["trustAttributes"] = ldb.MessageElement("0", ldb.FLAG_MOD_ADD, "trustAttributes")
    msg["securityIdentifier"] = ldb.MessageElement(
        ndr_pack(sid), ldb.FLAG_MOD_ADD, "securityIdentifier"
    )
    msg["trustAuthIncoming"] = ldb.MessageElement(
        packed, ldb.FLAG_MOD_ADD, "trustAuthIncoming"
    )
    msg["trustAuthOutgoing"] = ldb.MessageElement(
        packed, ldb.FLAG_MOD_ADD, "trustAuthOutgoing"
    )
    msg["msDS-SupportedEncryptionTypes"] = ldb.MessageElement(
        "24", ldb.FLAG_MOD_ADD, "msDS-SupportedEncryptionTypes"
    )
    sam.add(msg)
    print("TDO_OK", dn, "type", args.type, "sid", args.sid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
