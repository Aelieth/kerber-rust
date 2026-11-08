#!/usr/bin/env python3
"""totp.py: RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) from the Python standard library only.

The OTP1 lab leg's independent oracle for the example embedder's Rust verifier: it never imports the
kerber-rust code, and runs on the HOST, where the lab-only seed lives. The seed file holds one base32 seed on
one line. The code is printed to stdout and nowhere else; the seed is never printed.

  totp.py selftest
        RFC 6238 appendix B vectors (SHA1, the 20-octet ASCII secret), six digits; exit 0 when all agree.
  totp.py now SEEDFILE [--offset SECS]
        the code for the current 30-second step (the clock is the host's plus --offset, the measured
        offset of the KDC's clock).
  totp.py fresh SEEDFILE USEDFILE [--offset SECS]
        like `now`, but the step must not be one USEDFILE lists: it waits for the next step if need be,
        records the step it used (one integer per line), and prints the code. Stderr says only the step.
  totp.py wrong SEEDFILE [--offset SECS]
        a six-digit code that is NOT the code of the step before, the step itself or the step after:
        what a verifier with a one-step window must refuse.
  totp.py stepinfo [--offset SECS]
        the current step and the seconds left in it (no seed read).
"""
import base64
import hashlib
import hmac
import struct
import sys
import time

STEP = 30
DIGITS = 6


def hotp(key, counter, digits=DIGITS):
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return "%0*d" % (digits, (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits))


def totp_at(key, t, digits=DIGITS):
    return hotp(key, int(t) // STEP, digits)


def load_seed(path):
    text = open(path, "r", encoding="ascii").read().strip().replace(" ", "")
    return base64.b32decode(text.upper() + "=" * (-len(text) % 8))


def now(offset):
    return time.time() + offset


def selftest():
    secret = b"12345678901234567890"
    # RFC 6238 appendix B, SHA1 column (eight digits there; the last six digits are the six-digit code).
    vectors = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
               (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]
    bad = 0
    for t, want in vectors:
        got8 = totp_at(secret, t, 8)
        got6 = totp_at(secret, t, 6)
        ok = got8 == want and got6 == want[-6:]
        bad += 0 if ok else 1
        print("T=%d 8-digit %s (want %s) 6-digit %s: %s" % (t, got8, want, got6, "ok" if ok else "MISMATCH"))
    print("selftest: %s" % ("all agree" if not bad else "%d MISMATCH" % bad))
    return 1 if bad else 0


def main(argv):
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, args = argv[0], argv[1:]
    offset = 0.0
    if "--offset" in args:
        i = args.index("--offset")
        offset = float(args[i + 1])
        del args[i:i + 2]
    if cmd == "selftest":
        return selftest()
    if cmd == "stepinfo":
        t = now(offset)
        print("step %d, %.1f s left" % (int(t) // STEP, STEP - (t % STEP)))
        return 0
    if cmd == "now" and len(args) == 1:
        print(totp_at(load_seed(args[0]), now(offset)))
        return 0
    if cmd == "fresh" and len(args) == 2:
        key = load_seed(args[0])
        try:
            used = {int(x) for x in open(args[1]).read().split()}
        except FileNotFoundError:
            used = set()
        while True:
            t = now(offset)
            step = int(t) // STEP
            if step not in used:
                break
            wait = STEP - (t % STEP) + 0.4
            print("step %d already used; waiting %.1f s for the next" % (step, wait), file=sys.stderr)
            time.sleep(wait)
        with open(args[1], "a") as f:
            f.write("%d\n" % step)
        print("using step %d (%.1f s left in it)" % (step, STEP - (t % STEP)), file=sys.stderr)
        print(hotp(key, step))
        return 0
    if cmd == "wrong" and len(args) == 1:
        key = load_seed(args[0])
        step = int(now(offset)) // STEP
        valid = {hotp(key, step + d) for d in (-2, -1, 0, 1, 2)}
        n = 0
        while True:
            cand = "%06d" % ((int(hotp(key, step)) + 1 + n * 7919) % 10 ** DIGITS)
            if cand not in valid:
                print(cand)
                return 0
            n += 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
