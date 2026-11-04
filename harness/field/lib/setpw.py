#!/usr/bin/env python3
"""setpw.py: one kpasswd set-password request through MIT's libkrb5 (ctypes), for the kpasswd scenario.

    setpw.py -c <ccache> -t <target principal> [--frame] <kdc host>     (the new password on stdin)

The changepw ticket is krb5_get_credentials' from the ccache (`kinit -S kadmin/changepw` puts an INITIAL one
there). Without --frame the request is MIT's krb5_set_password_using_ccache. With --frame it is built as MIT's
change_set_password builds it (krb5_mk_req_extended with a subkey, the local address, krb5_mk_priv of the
ChangePasswdData under DO_SEQUENCE, version 0xff80, UDP 464) and read as get_clear_result reads it (krb5_rd_rep and
krb5_rd_priv, or krb5_rd_error), so the password may hold a NUL, which MIT's own functions cannot send. Stdin is
read whole, one trailing newline cut. Prints the ticket's INITIAL flag, the result code with MIT's string for it,
and the server's text (newlines and other controls escaped). Exit 0 when a result was read, whatever it says.
"""
import argparse
import ctypes as C
import socket
import sys

K = C.CDLL("libkrb5.so.3")
P = C.c_void_p
I = C.c_int


class Data(C.Structure):
    _fields_ = [("magic", C.c_int32), ("length", C.c_uint), ("data", C.c_void_p)]

    def bytes(self):
        return C.string_at(self.data, self.length) if self.length else b""


class Principal(C.Structure):
    _fields_ = [("magic", C.c_int32), ("realm", Data), ("data", P), ("length", C.c_int32), ("type", C.c_int32)]


class Creds(C.Structure):
    _fields_ = [("magic", C.c_int32), ("client", P), ("server", P),
                ("kb_magic", C.c_int32), ("kb_enctype", C.c_int32), ("kb_length", C.c_uint), ("kb_contents", P),
                ("times", C.c_int32 * 4), ("is_skey", C.c_uint), ("ticket_flags", C.c_int32), ("addresses", P),
                ("ticket", Data), ("second_ticket", Data), ("authdata", P)]


class Address(C.Structure):
    _fields_ = [("magic", C.c_int32), ("addrtype", C.c_int32), ("length", C.c_uint), ("contents", P)]


class KrbError(C.Structure):
    _fields_ = [("magic", C.c_int32), ("ctime", C.c_int32), ("cusec", C.c_int32), ("susec", C.c_int32),
                ("stime", C.c_int32), ("error", C.c_uint32), ("client", P), ("server", P), ("text", Data),
                ("e_data", Data)]


K.krb5_get_error_message.restype = C.c_char_p
K.krb5_get_error_message.argtypes = [P, I]
CTX = P()
KEEP = []


def ok(code, what):
    if code:
        sys.exit(f"setpw.py: {what}: {K.krb5_get_error_message(CTX, code).decode(errors='replace')}")


def data(b):
    buf = C.create_string_buffer(b, len(b))
    KEEP.append(buf)
    return Data(0, len(b), C.cast(buf, P))


def address(ip):
    buf = C.create_string_buffer(socket.inet_aton(ip), 4)
    KEEP.append(buf)
    return Address(0, 2, 4, C.cast(buf, P))


def der(tag, body):
    n = len(body)
    head = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + head + body


def setpw_req(password, princ):
    """MIT encode_krb5_setpw_req: ChangePasswdData { [0] newpasswd, [1] targname, [2] targrealm }."""
    p = princ.contents
    comps = C.cast(p.data, C.POINTER(Data))
    names = b"".join(der(0x1B, comps[i].bytes()) for i in range(p.length))
    name = der(0x30, der(0xA0, der(0x02, p.type.to_bytes(1, "big", signed=True))) + der(0xA1, der(0x30, names)))
    return der(0x30, der(0xA0, der(0x04, password)) + der(0xA1, name) + der(0xA2, der(0x1B, p.realm.bytes())))


def main():
    ap = argparse.ArgumentParser(description="one kpasswd set-password request through MIT's libkrb5")
    ap.add_argument("-c", required=True, help="the ccache")
    ap.add_argument("-t", required=True, help="the target principal")
    ap.add_argument("--frame", action="store_true", help="build the request here (the password may hold a NUL)")
    ap.add_argument("kdc")
    a = ap.parse_args()
    pw = sys.stdin.buffer.read()
    pw = pw[:-1] if pw.endswith(b"\n") else pw
    ok(K.krb5_init_context(C.byref(CTX)), "krb5_init_context")
    cc, client, server, target = P(), P(), P(), C.POINTER(Principal)()
    ok(K.krb5_cc_resolve(CTX, a.c.encode(), C.byref(cc)), "krb5_cc_resolve")
    ok(K.krb5_parse_name(CTX, a.t.encode(), C.byref(target)), "krb5_parse_name")
    realm = target.contents.realm.bytes().decode()
    ok(K.krb5_cc_get_principal(CTX, cc, C.byref(client)), "krb5_cc_get_principal")
    ok(K.krb5_parse_name(CTX, f"kadmin/changepw@{realm}".encode(), C.byref(server)), "krb5_parse_name")
    want, creds = Creds(client=client, server=server), C.POINTER(Creds)()
    ok(K.krb5_get_credentials(CTX, 0, cc, C.byref(want), C.byref(creds)), "krb5_get_credentials")
    print(f"ticket: kadmin/changepw@{realm}, {'initial' if creds.contents.ticket_flags & 0x00400000 else 'not initial'}")
    if not a.frame:
        if b"\0" in pw:
            sys.exit("setpw.py: a password holding a NUL needs --frame")
        rc, rcs, rs = I(), Data(), Data()
        ok(K.krb5_set_password_using_ccache(CTX, cc, C.c_char_p(pw), target, C.byref(rc), C.byref(rcs),
                                            C.byref(rs)), "krb5_set_password_using_ccache")
        code, text = rc.value, rs.bytes()
    else:
        ac, ap_req = P(), Data()
        ok(K.krb5_auth_con_init(CTX, C.byref(ac)), "krb5_auth_con_init")
        ok(K.krb5_mk_req_extended(CTX, C.byref(ac), 1, None, creds, C.byref(ap_req)), "krb5_mk_req_extended")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((a.kdc, 464))
        s.settimeout(10)
        local = address(s.getsockname()[0])
        ok(K.krb5_auth_con_setaddrs(CTX, ac, C.byref(local), None), "krb5_auth_con_setaddrs")
        ok(K.krb5_auth_con_setflags(CTX, ac, 4), "krb5_auth_con_setflags")
        clear, priv = data(setpw_req(pw, target)), Data()
        ok(K.krb5_mk_priv(CTX, ac, C.byref(clear), C.byref(priv), None), "krb5_mk_priv")
        req, cipher = ap_req.bytes(), priv.bytes()
        s.send((6 + len(req) + len(cipher)).to_bytes(2, "big") + b"\xff\x80" + len(req).to_bytes(2, "big") + req + cipher)
        try:
            rep = s.recv(65536)
        except socket.timeout:
            sys.exit("setpw.py: no reply in 10 s")
        aplen = int.from_bytes(rep[4:6], "big")
        print(f"reply: {len(rep)} bytes, version {int.from_bytes(rep[2:4], 'big')}, AP-REP length {aplen}")
        if aplen:
            sub, enc, out = P(), P(), Data()
            ok(K.krb5_auth_con_getsendsubkey_k(CTX, ac, C.byref(sub)), "krb5_auth_con_getsendsubkey_k")
            ok(K.krb5_rd_rep(CTX, ac, C.byref(data(rep[6:6 + aplen])), C.byref(enc)), "krb5_rd_rep")
            ok(K.krb5_auth_con_setrecvsubkey_k(CTX, ac, sub), "krb5_auth_con_setrecvsubkey_k")
            ok(K.krb5_rd_priv(CTX, ac, C.byref(data(rep[6 + aplen:])), C.byref(out), None), "krb5_rd_priv")
            res = out.bytes()
        else:
            err = C.POINTER(KrbError)()
            ok(K.krb5_rd_error(CTX, C.byref(data(rep[6:])), C.byref(err)), "krb5_rd_error")
            print(f"krb-error: {err.contents.error}")
            res = err.contents.e_data.bytes()
        code, text = int.from_bytes(res[:2], "big"), res[2:]
    s_out = C.c_char_p()
    K.krb5_chpw_result_code_string(CTX, code, C.byref(s_out))
    print(f"result: {code} ({s_out.value.decode()})")
    print("text: " + text.decode(errors="replace").encode("unicode_escape").decode("ascii"))


main()
