#!/usr/bin/env python3
"""MIT's krb5_cc_remove_cred, from the host's libkrb5, on one credential of a ccache.

usage: cc-remove.py <ccache> <server>          remove the cache owner's ticket for <server>
       cc-remove.py --self-test <scratch path>  store two made-up credentials in a new FILE cache there,
                                                remove one, and list what is left
Prints `removed: <server>`, libkrb5's error text, or the self-test's verdict. It never reads or prints a key.
"""
import ctypes
import ctypes.util
import sys

lib = ctypes.CDLL(ctypes.util.find_library("krb5") or "libkrb5.so.3")
lib.krb5_get_error_message.restype = ctypes.c_char_p


class Data(ctypes.Structure):
    _fields_ = [("magic", ctypes.c_int32), ("length", ctypes.c_uint), ("data", ctypes.c_void_p)]


class Keyblock(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_int32), ("enctype", ctypes.c_int32), ("length", ctypes.c_uint),
        ("contents", ctypes.c_void_p),
    ]


class Times(ctypes.Structure):
    _fields_ = [
        ("authtime", ctypes.c_int32), ("starttime", ctypes.c_int32), ("endtime", ctypes.c_int32),
        ("renew_till", ctypes.c_int32),
    ]


class Creds(ctypes.Structure):
    # krb5_creds as krb5.h lays it out.
    _fields_ = [
        ("magic", ctypes.c_int32), ("client", ctypes.c_void_p), ("server", ctypes.c_void_p),
        ("keyblock", Keyblock), ("times", Times), ("is_skey", ctypes.c_uint), ("ticket_flags", ctypes.c_int32),
        ("addresses", ctypes.c_void_p), ("ticket", Data), ("second_ticket", Data), ("authdata", ctypes.c_void_p),
    ]


ctx = ctypes.c_void_p()


def ok(code, what):
    if code:
        msg = lib.krb5_get_error_message(ctx, code)
        sys.exit(f"{what}: {msg.decode(errors='replace') if msg else code}")


def principal(name):
    p = ctypes.c_void_p()
    ok(lib.krb5_parse_name(ctx, name.encode(), ctypes.byref(p)), f"parse {name}")
    return p


def resolve(name):
    cc = ctypes.c_void_p()
    ok(lib.krb5_cc_resolve(ctx, name.encode(), ctypes.byref(cc)), f"resolve {name}")
    return cc


def remove(cc, client, server):
    m = Creds()
    m.client, m.server = client.value, server.value
    return lib.krb5_cc_remove_cred(ctx, cc, 0, ctypes.byref(m))


def servers(cc):
    cur = ctypes.c_void_p()
    ok(lib.krb5_cc_start_seq_get(ctx, cc, ctypes.byref(cur)), "start_seq_get")
    out = []
    c = Creds()
    while lib.krb5_cc_next_cred(ctx, cc, ctypes.byref(cur), ctypes.byref(c)) == 0:
        s = ctypes.c_char_p()
        ok(lib.krb5_unparse_name(ctx, ctypes.c_void_p(c.server), ctypes.byref(s)), "unparse")
        out.append(s.value.decode())
        lib.krb5_free_unparsed_name(ctx, s)
        lib.krb5_free_cred_contents(ctx, ctypes.byref(c))
    lib.krb5_cc_end_seq_get(ctx, cc, ctypes.byref(cur))
    return out


def self_test(path):
    cc = resolve("FILE:" + path)
    client = principal("ctuser@SELF.TEST")
    ok(lib.krb5_cc_initialize(ctx, cc, client), "initialize")
    keep, gone = principal("krbtgt/SELF.TEST@SELF.TEST"), principal("svc/self@SELF.TEST")
    ticket = ctypes.create_string_buffer(b"made-up ticket", 14)
    key = ctypes.create_string_buffer(32)
    for server in (keep, gone):
        c = Creds()
        c.client, c.server = client.value, server.value
        c.keyblock.enctype, c.keyblock.length, c.keyblock.contents = 18, 32, ctypes.addressof(key)
        c.times.authtime = c.times.starttime = 1_700_000_000
        c.times.endtime = 1_700_086_400
        c.ticket.length, c.ticket.data = 14, ctypes.addressof(ticket)
        ok(lib.krb5_cc_store_cred(ctx, cc, ctypes.byref(c)), "store")
    before = servers(cc)
    ok(remove(cc, client, gone), "remove")
    after = servers(cc)
    lib.krb5_cc_destroy(ctx, cc)
    if before != ["krbtgt/SELF.TEST@SELF.TEST", "svc/self@SELF.TEST"] or after != ["krbtgt/SELF.TEST@SELF.TEST"]:
        sys.exit(f"cc-remove self-test failed: before {before}, after {after}")
    print("cc-remove self-test ok")


def main(argv):
    ok(lib.krb5_init_context(ctypes.byref(ctx)), "init_context")
    if len(argv) == 3 and argv[1] == "--self-test":
        self_test(argv[2])
        return
    if len(argv) != 3:
        sys.exit(__doc__)
    cc = resolve(argv[1])
    client = ctypes.c_void_p()
    ok(lib.krb5_cc_get_principal(ctx, cc, ctypes.byref(client)), "get_principal")
    ok(remove(cc, client, principal(argv[2])), f"remove {argv[2]}")
    print(f"removed: {argv[2]}")


if __name__ == "__main__":
    main(sys.argv)
