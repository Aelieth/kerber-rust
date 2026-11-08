#!/usr/bin/env python3
"""raw-tgs.py: one authenticated TGS-REQ for a non-ASCII krbtgt hop, through MIT's libkrb5.

    raw-tgs.py [-c <ccache>] [-r <realm>]

The ccache holds a TGT (kinit on client2). The server name is krbtgt/<U+00E9>@<realm>,
UTF-8 (second component c3 a9), the cross-realm hop find_alternate_tgs builds.
krb5_get_credentials sends that TGS-REQ with the cached TGT.

Prints sname, component-hex, and the client-side result. Exit 0 when the library
was called, including a drop. Exit 2 when the ccache or the name could not be set up.
It does not read the KDC journal.

A KDC error in MIT's KRB5KDC_ERR_NONE window (-1765328384 + 0..127) is result=error
with kdc-code the protocol number (7 is S_PRINCIPAL_UNKNOWN). Any other library
error is result=dropped. A ticket is result=tgs-rep.
"""
import argparse
import ctypes as C
import sys

KDC_ERR_NONE = -1765328384
P = C.c_void_p
I = C.c_int32


class Data(C.Structure):
    _fields_ = [("magic", C.c_int32), ("length", C.c_uint), ("data", P)]

    def bytes(self):
        return C.string_at(self.data, self.length) if self.length else b""


class Principal(C.Structure):
    _fields_ = [("magic", C.c_int32), ("realm", Data), ("data", P), ("length", C.c_int32), ("type", C.c_int32)]


class Creds(C.Structure):
    _fields_ = [("magic", C.c_int32), ("client", P), ("server", P),
                ("kb_magic", C.c_int32), ("kb_enctype", C.c_int32), ("kb_length", C.c_uint), ("kb_contents", P),
                ("times", C.c_int32 * 4), ("is_skey", C.c_uint), ("ticket_flags", C.c_int32), ("addresses", P),
                ("ticket", Data), ("second_ticket", Data), ("authdata", P)]


def main():
    ap = argparse.ArgumentParser(description="one authenticated TGS-REQ for krbtgt/é")
    ap.add_argument("-c", help="ccache (default: the process default)")
    ap.add_argument("-r", help="client realm (default: the TGT's realm)")
    a = ap.parse_args()
    k = C.CDLL("libkrb5.so.3")
    for name, args in (
        ("krb5_init_context", [P]),
        ("krb5_cc_resolve", [P, C.c_char_p, P]),
        ("krb5_cc_default", [P, P]),
        ("krb5_cc_get_principal", [P, P, P]),
        ("krb5_parse_name", [P, C.c_char_p, P]),
        ("krb5_get_credentials", [P, I, P, P, P]),
    ):
        fn = getattr(k, name)
        fn.argtypes = args
        fn.restype = I
    k.krb5_get_error_message.restype = C.c_char_p
    k.krb5_get_error_message.argtypes = [P, I]
    ctx = P()

    def bail(code, what):
        text = ""
        if ctx:
            msg = k.krb5_get_error_message(ctx, code)
            text = msg.decode(errors="replace") if msg else ""
        sys.stderr.write(f"raw-tgs.py: {what}: {text}\n")
        raise SystemExit(2)

    code = k.krb5_init_context(C.byref(ctx))
    if code:
        bail(code, "krb5_init_context")
    cc = P()
    if a.c:
        code = k.krb5_cc_resolve(ctx, a.c.encode(), C.byref(cc))
        if code:
            bail(code, "krb5_cc_resolve")
    else:
        code = k.krb5_cc_default(ctx, C.byref(cc))
        if code:
            bail(code, "krb5_cc_default")
    client = P()
    code = k.krb5_cc_get_principal(ctx, cc, C.byref(client))
    if code:
        bail(code, "krb5_cc_get_principal")
    if a.r:
        realm = a.r.encode()
    else:
        realm = C.cast(client, C.POINTER(Principal)).contents.realm.bytes()
    server = C.POINTER(Principal)()
    sname = b"krbtgt/" + "é".encode() + b"@" + realm
    code = k.krb5_parse_name(ctx, sname, C.byref(server))
    if code:
        bail(code, "krb5_parse_name")
    comp = C.cast(server.contents.data, C.POINTER(Data))
    second = comp[1].bytes() if server.contents.length >= 2 else b""
    if second != b"\xc3\xa9":
        sys.stderr.write(f"raw-tgs.py: second component is {second.hex() or 'empty'}, want c3a9\n")
        raise SystemExit(2)
    print(f"sname={sname.decode()}")
    print(f"component-hex={second.hex()}")
    want = Creds(client=client, server=C.cast(server, P))
    creds = C.POINTER(Creds)()
    rc = k.krb5_get_credentials(ctx, 0, cc, C.byref(want), C.byref(creds))
    if rc == 0:
        print("result=tgs-rep")
        return
    msg = k.krb5_get_error_message(ctx, rc)
    text = (msg.decode(errors="replace") if msg else "").replace("\n", " ")
    if KDC_ERR_NONE <= rc < KDC_ERR_NONE + 128:
        print("result=error")
        print(f"kdc-code={rc - KDC_ERR_NONE}")
    else:
        print("result=dropped")
    print(f"lib-rc={rc}")
    print(f"text={text}")


if __name__ == "__main__":
    main()
