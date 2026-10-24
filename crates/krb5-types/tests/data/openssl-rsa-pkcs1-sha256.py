#!/usr/bin/env python3
"""openssl-rsa-pkcs1-sha256.py <work dir> > openssl-rsa-pkcs1-sha256.kat: RSASSA-PKCS1-v1_5 SHA-256 signatures from
OpenSSL, the library MIT's pkinit signs with. Each run makes new keys in <work dir>; the .kat beside this is one run."""
import base64
import math
import os
import subprocess
import sys

D = sys.argv[1]
os.makedirs(D, exist_ok=True)


def run(*args):
    return subprocess.run(args, capture_output=True, cwd=D)


def tlv(tag, body):
    n = len(body)
    head = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + head + body


def der_int(v):
    return tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big'))


def pkcs1(n, e, d, primes, qinv=None):
    p, q = primes[0], primes[1]
    qinv = pow(q, -1, p) if qinv is None else qinv
    body = der_int(1 if len(primes) > 2 else 0)
    body += b''.join(der_int(x) for x in (n, e, d, p, q, d % (p - 1), d % (q - 1), qinv))
    if len(primes) > 2:
        others, prod = b'', p * q
        for r in primes[2:]:
            others += tlv(0x30, der_int(r) + der_int(d % (r - 1)) + der_int(pow(prod, -1, r)))
            prod *= r
        body += tlv(0x30, others)
    return tlv(0x30, body)


def pkcs8(der):
    alg = tlv(0x30, tlv(0x06, bytes.fromhex('2a864886f70d010101')) + b'\x05\x00')
    return tlv(0x30, der_int(0) + alg + tlv(0x04, der))


def write_pem(name, der):
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    with open(os.path.join(D, name), 'w') as f:
        f.write('-----BEGIN RSA PRIVATE KEY-----\n' + '\n'.join(lines) + '\n-----END RSA PRIVATE KEY-----\n')
    return name


def prime(bits):
    return int(run('openssl', 'prime', '-generate', '-bits', str(bits)).stdout.split()[0])


def key_of(primes, e=65537):
    lam = 1
    for r in primes:
        lam = lam * (r - 1) // math.gcd(lam, r - 1)
    return math.prod(primes), e, pow(e, -1, lam)


def sign(name, msg):
    with open(os.path.join(D, 'msg'), 'wb') as f:
        f.write(msg)
    r = run('openssl', 'dgst', '-sha256', '-sign', name, 'msg')
    return r.stdout if r.returncode == 0 else None


keys = []
for bits, n_primes in ((512, 2), (2048, 3), (8192, 2), (8192, 5), (16384, 5)):
    name = f'k{bits}p{n_primes}.pem'
    run('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', f'rsa_keygen_bits:{bits}',
        '-pkeyopt', f'rsa_keygen_primes:{n_primes}', '-out', name)
    der = run('openssl', 'rsa', '-in', name, '-traditional', '-outform', 'DER').stdout
    keys.append((f'{bits}-bit, {n_primes} primes', name, der))
p, q, other = prime(1024), prime(1024), prime(1024)
n, e, d = key_of([p, q])
der = pkcs1(n, e, d, [p, q], qinv=(pow(q, -1, p) + 1) % p)
keys.append(('2048-bit, a wrong qInv', write_pem('badqinv.pem', der), der))
der = pkcs1(n, e, d, [other, q])
keys.append(('2048-bit, p not a factor of n', write_pem('wrongp.pem', der), der))
six = [prime(384) for _ in range(6)]
n, e, d = key_of(six)
der = pkcs1(n, e, d, six)
keys.append((f'{n.bit_length()}-bit, 6 primes', write_pem('six.pem', der), der))

version = run('openssl', 'version').stdout.split()[1].decode()
print(f"""# OpenSSL {version} (the library MIT's pkinit signs with) and RSASSA-PKCS1-v1_5 with SHA-256: keys from
# `openssl genpkey -algorithm RSA` (rsa_keygen_bits, rsa_keygen_primes), two 2048-bit keys with a wrong CRT value, which
# OpenSSL signs through d, and a 6-prime key, which it does not sign; signatures from `openssl dgst -sha256 -sign`.
# "key" is a PKCS#8 key (hex); "tc" is an id, the message (hex, "-" when empty) and the signature (hex); "refuse" is
# an id and a message the key does not sign. Made by openssl-rsa-pkcs1-sha256.py.""")
tc = 0
for desc, name, der in keys:
    print(f'# {desc}')
    print('key ' + pkcs8(der).hex())
    for msg in ((b'abc',) if desc.endswith('6 primes') else (b'', bytes(range(64)))):
        tc += 1
        sig = sign(name, msg)
        print(f'refuse {tc} {msg.hex()}' if sig is None else f'tc {tc} {msg.hex() or "-"} {sig.hex()}')
