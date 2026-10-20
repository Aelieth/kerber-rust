#!/usr/bin/env python3
"""openssl-kx.py <work dir> > openssl-kx.kat: Diffie-Hellman and ECDH shared secrets from OpenSSL, the library MIT's
pkinit runs its key exchange on, for the groups MIT's pkinit uses: MODP 2048 and 4096 (RFC 3526 groups 14 and 16),
P-256, P-384 and P-521, and MODP 1024 (RFC 2409 group 2). Each run makes new keys in <work dir>; the .kat beside this
is one run."""
import base64
import os
import subprocess
import sys

D = os.path.abspath(sys.argv[1])
os.makedirs(D, exist_ok=True)
TRIES = 4000
# The group, genpkey's algorithm and option for it, and the size in bytes of its shared secrets (of p, or of the field).
GROUPS = [
    ('modp2048', 'DH', 'group:modp_2048', 256),
    ('modp4096', 'DH', 'group:modp_4096', 512),
    ('P-256', 'EC', 'ec_paramgen_curve:P-256', 32),
    ('P-384', 'EC', 'ec_paramgen_curve:P-384', 48),
    ('P-521', 'EC', 'ec_paramgen_curve:P-521', 66),
    ('modp1024', 'DH', None, 128),
]
# RFC 2409 group 2, MIT's oakley_1024; OpenSSL names no such group, so its keys come from these parameters.
P1024 = int(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD'
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF', 16)
HEADER = """\
OpenSSL {} (the library MIT's pkinit runs its key exchange on), Diffie-Hellman and ECDH shared secrets for the
groups MIT's pkinit uses: MODP 2048 and 4096 (RFC 3526 groups 14 and 16; keys from `openssl genpkey -algorithm DH
-pkeyopt group:modp_N`), P-256, P-384 and P-521 (`openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-N`), and
MODP 1024 (RFC 2409 group 2, MIT's oakley_1024; keys from `openssl genpkey -paramfile` of its PKCS#3 parameters).
Keys are read with `openssl pkey -text` and `-pubout`. A shared secret is `openssl pkeyutl -derive` of our key and the
peer's public key, for MODP with `-pkeyopt dh_pad:1`, which pads to the length of p as MIT's dh_result does. "group"
names a group; "tc" is an id, our private value (hex; MODP the exponent in its minimal length, EC the scalar padded to
the field size), the peer's public key as it rides in the subjectPublicKey BIT STRING (hex; MODP the DER INTEGER of y,
EC the uncompressed point 04||X||Y) and the shared secret (hex; MODP padded to the length of p, EC the x coordinate at
the field size). The last test of each group has a shared secret whose first byte is 00. Made by openssl-kx.py."""


def run(*args, data=None):
    return subprocess.run(args, capture_output=True, cwd=D, input=data, check=True).stdout


def put(name, data):
    path = os.path.join(D, name)
    with open(path, 'wb') as f:
        f.write(data)
    return path


def tlv(b):
    """The tag, contents and rest of the DER element at the start of b."""
    n, i = b[1], 2
    if n & 0x80:
        i += n & 0x7F
        n = int.from_bytes(b[2:i], 'big')
    return b[0], b[i:i + n], b[i + n:]


def der_int(n):
    """The DER INTEGER of a positive n."""
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    b = b'\0' + b if b[0] & 0x80 else b
    if len(b) < 128:
        return b'\x02' + bytes([len(b)]) + b
    k = (len(b).bit_length() + 7) // 8
    return b'\x02' + bytes([0x80 | k]) + len(b).to_bytes(k, 'big') + b


def genkey(name, algorithm, option):
    if option is None:
        body = der_int(P1024) + der_int(2)
        der = base64.encodebytes(b'\x30\x81' + bytes([len(body)]) + body)
        params = put('modp1024.pem', b'-----BEGIN DH PARAMETERS-----\n' + der + b'-----END DH PARAMETERS-----\n')
        return put(name + '.pem', run('openssl', 'genpkey', '-paramfile', params))
    return put(name + '.pem', run('openssl', 'genpkey', '-algorithm', algorithm, '-pkeyopt', option))


def pubkey(path):
    """The public key of the key at path: its PEM file and its SubjectPublicKeyInfo."""
    pem = run('openssl', 'pkey', '-in', path, '-pubout')
    body = b''.join(line for line in pem.splitlines() if not line.startswith(b'-----'))
    return put(os.path.basename(path)[:-4] + '.pub.pem', pem), base64.b64decode(body)


def spki(der):
    """The AlgorithmIdentifier and the subjectPublicKey BIT STRING contents of a SubjectPublicKeyInfo."""
    _, alg, rest = tlv(tlv(der)[1])
    tag, bits, _ = tlv(rest)
    assert tag == 3 and bits[0] == 0
    return alg, bits[1:]


def dump(path, *labels):
    """The bytes under each label of `openssl pkey -text`, an indented colon separated hex dump."""
    lines = run('openssl', 'pkey', '-in', path, '-text', '-noout').decode().splitlines()
    out = []
    for label in labels:
        hexa = ''
        for line in lines[lines.index(label) + 1:]:
            if not line.startswith(' '):
                break
            hexa += line.strip().replace(':', '')
        out.append(bytes.fromhex(hexa))
    return out


def derive(key, peer, modp, pad=True):
    return run('openssl', 'pkeyutl', '-derive', '-inkey', key, '-peerkey', peer,
               *(['-pkeyopt', 'dh_pad:1'] if modp and pad else []))


def case(group, size, a, b):
    """The secret, peer and shared fields of a test of the key a (ours) with the key b (the peer's), checked."""
    modp = group.startswith('modp')
    labels = ('private-key:', 'public-key:') if modp else ('priv:', 'pub:')
    x = int.from_bytes(dump(a, *labels)[0], 'big')
    b_pub = dump(b, *labels)[1]
    a_pem, a_der = pubkey(a)
    b_pem, b_der = pubkey(b)
    alg, peer = spki(b_der)
    shared = derive(a, b_pem, modp)
    assert derive(b, a_pem, modp) == shared, 'the peer derives another secret'
    if modp:
        # `openssl pkey -text` of a named group has no prime, only the group's name: p is in the SPKI parameters.
        _, p, rest = tlv(tlv(tlv(alg)[2])[1])
        p, g, y = int.from_bytes(p, 'big'), tlv(rest)[1], int.from_bytes(b_pub, 'big')
        assert p.bit_length() == 8 * size and g == b'\x02'
        assert peer == der_int(y), 'the BIT STRING is not the DER INTEGER of y'
        assert pow(y, x, p).to_bytes(size, 'big') == shared, 'pow(y, x, p) is not the shared secret'
        if shared[0] == 0:
            assert derive(a, b_pem, modp, pad=False) == shared.lstrip(b'\0'), 'dh_pad:1 changes more than the length'
        secret = x.to_bytes((x.bit_length() + 7) // 8, 'big')
    else:
        assert peer == b_pub and peer[0] == 4 and len(peer) == 1 + 2 * size and len(shared) == size
        secret = x.to_bytes(size, 'big')
        # The scalar as an ECPrivateKey: OpenSSL must find the public key of a from it.
        curve = tlv(alg)[2]
        sec1 = b'\2\1\1\4' + bytes([size]) + secret + b'\xa0' + bytes([len(curve)]) + curve
        sec1 = put(os.path.basename(a)[:-4] + '.sec1.der', b'\x30' + bytes([len(sec1)]) + sec1)
        assert run('openssl', 'pkey', '-inform', 'DER', '-in', sec1, '-pubout', '-outform', 'DER') == a_der
    return secret, peer, shared


for line in HEADER.format(run('openssl', 'version').decode().split()[1]).splitlines():
    print('# ' + line)
tc = 0
for group, algorithm, option, size in GROUPS:
    rows = []
    for n in (1, 2):
        rows.append(case(group, size, genkey(f'{group}-{n}-a', algorithm, option),
                         genkey(f'{group}-{n}-b', algorithm, option)))
    b = genkey(f'{group}-3-b', algorithm, option)
    b_pem, tries = pubkey(b)[0], 0
    while True:
        tries += 1
        assert tries <= TRIES, f'{group}: no shared secret starting with 00 in {TRIES} keys'
        a = genkey(f'{group}-3-a', algorithm, option)
        if derive(a, b_pem, group.startswith('modp'))[0] == 0:
            break
    rows.append(case(group, size, a, b))
    print(f'# {group}: tc {tc + 3}, a shared secret whose first byte is 00, came at try {tries}')
    print('group ' + group)
    for secret, peer, shared in rows:
        tc += 1
        print(f'tc {tc} {secret.hex()} {peer.hex()} {shared.hex()}')
    print(f'{group}: tc {tc} with a leading 00 came at try {tries}', file=sys.stderr)
