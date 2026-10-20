#!/usr/bin/env python3
"""openssl-ecdsa-sha256.py <work dir> > openssl-ecdsa-sha256.kat: ECDSA with SHA-256 on P-224, P-384, P-521 and
secp256k1 from OpenSSL, the library MIT's pkinit signs with (it signs with SHA-256 whatever the curve). Each run makes
new keys in <work dir>; the .kat beside this is one run."""
import os
import subprocess
import sys

D = sys.argv[1]
os.makedirs(D, exist_ok=True)
MESSAGES = [b'', b'abc', bytes(range(256)) * 4]


def run(*args, data=None):
    return subprocess.run(args, capture_output=True, cwd=D, input=data, check=True).stdout


print('# OpenSSL ' + run('openssl', 'version').decode().split()[1] + ' (the library MIT\'s pkinit signs with), ECDSA with'
      ' SHA-256 on P-224, P-384, P-521 and secp256k1: keys from')
print('# `openssl genpkey -algorithm EC`, signatures from `openssl dgst -sha256 -sign` (ASN.1 DER). "key" is a PKCS#8 key'
      ' and')
print('# "spki" its SubjectPublicKeyInfo (hex); "tc" is an id, the message (hex, "-" when empty) and the signature (hex).'
      ' Made by')
print('# openssl-ecdsa-sha256.py.')
tc = 0
for curve in ('P-224', 'P-384', 'P-521', 'secp256k1'):
    for n in range(2):
        key = os.path.join(D, f'{curve}-{n}.der')
        run('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', f'ec_paramgen_curve:{curve}', '-outform', 'DER',
            '-out', key)
        spki = run('openssl', 'pkey', '-inform', 'DER', '-in', key, '-pubout', '-outform', 'DER')
        p8 = run('openssl', 'pkcs8', '-topk8', '-nocrypt', '-inform', 'DER', '-in', key, '-outform', 'DER')
        print(f'# {curve}')
        print('key ' + p8.hex())
        print('spki ' + spki.hex())
        for m in MESSAGES:
            tc += 1
            sig = run('openssl', 'dgst', '-sha256', '-keyform', 'DER', '-sign', key, data=m)
            print(f'tc {tc} {m.hex() or "-"} {sig.hex()}')
