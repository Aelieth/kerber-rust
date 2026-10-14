#!/usr/bin/env python3
"""Reads the lines otp-fast-shim.so wrote and prints one summary line per FAST event, for a gate to grep.

  otp-fastdump.py FILE

FILE lines: `<decrypt|encrypt> usage=N rc=N keyetype=N len=N hex=<plaintext>`, as written by a krb5kdc (the
decrypt of the client's KrbFastReq, usage 51; the encrypt of its KrbFastResponse, usage 52; the decrypt of
the PA-OTP-REQUEST nonce, usage 45) or by a kinit (the encrypt of its KrbFastReq, the decrypt of the
response, the encrypt of the nonce). Output, in file order:

  fastreq inner=133,142,150,149 pa142=<hex of the PA-OTP-REQUEST DER, its ciphertext replaced by {cipher:N}>
  fastresp types=136,19,141,... pa141=<hex of the PA-OTP-CHALLENGE, its nonce replaced by {nonce:N}> nonce141=<hex>
  nonce45=<hex of the nonce the client sent back>

DER walker only; no crypto. A line it cannot read is `bad <kind> usage=N` and the exit status is 1.
"""
import sys


def tlv(b, off=0):
    tag = b[off]
    ln = b[off + 1]
    hdr = 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[off + 2:off + 2 + n], "big")
        hdr = 2 + n
    if off + hdr + ln > len(b):
        raise ValueError("short")
    return tag, off + hdr, off + hdr + ln


def kids(b, start, end):
    out, off = [], start
    while off < end:
        tag, vs, ve = tlv(b, off)
        out.append((tag, vs, ve))
        off = ve
    return out


def integer(b, vs, ve):
    return int.from_bytes(b[vs:ve], "big", signed=True)


def padata(b, vs, ve):
    """[(type, value start, value end)] of a SEQUENCE OF PA-DATA whose body is b[vs:ve]."""
    out = []
    for _tag, ps, pe in kids(b, vs, ve):
        ptype = pval = None
        for ft, fs, fe in kids(b, ps, pe):
            _t, is_, ie = tlv(b, fs)
            if ft == 0xA1:
                ptype = integer(b, is_, ie)
            elif ft == 0xA2:
                pval = (is_, ie)
        out.append((ptype, pval[0], pval[1]))
    return out


def masked_142(b, vs, ve):
    """The PA-OTP-REQUEST DER as hex with encData's ciphertext octets replaced by {cipher:N}."""
    _t, bs, be = tlv(b, vs)
    for tag, es, ee in kids(b, bs, be):
        if tag != 0xA2:
            continue
        for ftag, fs, fe in kids(b, es, ee):
            if ftag == 0xA2:
                _t, cs, ce = tlv(b, fs)
                return b[vs:cs].hex() + "{cipher:%d}" % (ce - cs) + b[ce:ve].hex()
    return b[vs:ve].hex()


def fastreq(b):
    """KrbFastReq ::= SEQUENCE { fast-options [0], padata [1] SEQUENCE OF PA-DATA, req-body [2] }"""
    _t, bs, be = tlv(b, 0)
    for tag, fs, _fe in kids(b, bs, be):
        if tag == 0xA1:
            _t, ss, se = tlv(b, fs)
            pas = padata(b, ss, se)
            line = "fastreq inner=" + ",".join(str(t) for t, _s, _e in pas)
            for t, s, e in pas:
                if t == 142:
                    line += " pa142=" + masked_142(b, s, e)
            return line
    raise ValueError("no padata")


def masked_141(b, vs, ve):
    """The PA-OTP-CHALLENGE DER as hex with the nonce octets replaced by {nonce:N}."""
    _t, bs, be = tlv(b, vs)
    for tag, ns, ne in kids(b, bs, be):
        if tag == 0x80:
            return b[vs:ns].hex() + "{nonce:%d}" % (ne - ns) + b[ne:ve].hex()
    raise ValueError("no nonce")


def nonce_of(b, vs, ve):
    """The `nonce [0]` octets of a SEQUENCE whose first member is the implicit-tagged nonce (PA-OTP-CHALLENGE, the echo)."""
    _t, bs, be = tlv(b, vs)
    for tag, ns, ne in kids(b, bs, be):
        if tag == 0x80:
            return b[ns:ne].hex()
    raise ValueError("no nonce")


def fastresp(b):
    """KrbFastResponse ::= SEQUENCE { padata [0] SEQUENCE OF PA-DATA, strengthen-key [1], finished [2], nonce [3] }"""
    _t, bs, be = tlv(b, 0)
    for tag, fs, _fe in kids(b, bs, be):
        if tag == 0xA0:
            _t, ss, se = tlv(b, fs)
            pas = padata(b, ss, se)
            line = "fastresp types=" + ",".join(str(t) for t, _s, _e in pas)
            for t, s, e in pas:
                if t == 141:
                    line += " pa141=" + masked_141(b, s, e) + " nonce141=" + nonce_of(b, s, e)
            return line
    raise ValueError("no padata")


def main(path):
    bad = 0
    for raw in open(path, encoding="ascii"):
        parts = raw.split()
        if len(parts) < 5:
            continue
        kind = parts[0]
        f = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
        usage = int(f["usage"])
        if f["rc"] != "0" or usage not in (45, 51, 52):
            continue
        data = bytes.fromhex(f.get("hex", ""))
        try:
            if usage == 51:
                print(fastreq(data))
            elif usage == 52:
                print(fastresp(data))
            else:
                print("nonce45=" + nonce_of(data, 0, len(data)))
        except (ValueError, IndexError):
            print("bad %s usage=%d" % (kind, usage))
            bad = 1
    return bad


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
