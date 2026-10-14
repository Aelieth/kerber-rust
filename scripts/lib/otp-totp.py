#!/usr/bin/env python3
"""RFC 6238 TOTP (HMAC-SHA1, six digits, 30 s steps) from the standard library: the OTP gates' independent
oracle for the example embedder's Rust verifier. It imports no kerber-rust code and prints only a code.

  otp-totp.py code SEED_BASE32 [STEP_OFFSET]   the code of the current step plus STEP_OFFSET (default 0)
  otp-totp.py wrong SEED_BASE32                six digits that are the code of none of the steps -2 .. +2
  otp-totp.py selftest                         RFC 6238 appendix B and RFC 4226 appendix D vectors; exit 0
"""
import base64
import hashlib
import hmac
import struct
import sys
import time

STEP = 30


def hotp(key, counter, digits=6):
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    return "%0*d" % (digits, value % 10 ** digits)


def seed(text):
    text = text.strip().upper()
    return base64.b32decode(text + "=" * (-len(text) % 8))


def code(text, offset=0):
    return hotp(seed(text), int(time.time()) // STEP + offset)


def wrong(text):
    near = {code(text, o) for o in range(-2, 3)}
    for n in range(1000000):
        cand = "%06d" % n
        if cand not in near:
            return cand
    raise SystemExit("no wrong code")


def selftest():
    key = b"12345678901234567890"
    appendix_b = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                  (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]
    appendix_d = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
    bad = [t for t, want in appendix_b if hotp(key, t // STEP, 8) != want]
    bad += [n for n, want in enumerate(appendix_d) if hotp(key, n) != want]
    if bad:
        raise SystemExit("selftest failed: %s" % bad)


def main(argv):
    if len(argv) >= 2 and argv[1] == "selftest":
        selftest()
        return 0
    if len(argv) >= 3 and argv[1] == "code":
        print(code(argv[2], int(argv[3]) if len(argv) > 3 else 0))
        return 0
    if len(argv) == 3 and argv[1] == "wrong":
        print(wrong(argv[2]))
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
