# kpasswd-req-lengths.py PCAP [PORT]: one line per change-password request in a capture (client to port 464 by default): the parts' lengths, to compare MIT's kpasswd with ours.
# Equal on both clients: ap_req, ticket_cipher, priv and priv_cipher. auth_cipher is equal unless the microseconds in the authenticator take a different number of octets (cusec under 32768: -1 or -2).
import subprocess, sys

def tlv(b, i):
    t = b[i]; i += 1
    l = b[i]; i += 1
    if l & 0x80:
        n = l & 0x7f
        l = int.from_bytes(b[i:i + n], "big"); i += n
    return t, l, i

def children(b):
    out, i = [], 0
    while i < len(b):
        t, l, j = tlv(b, i)
        out.append((t, b[j:j + l]))
        i = j + l
    return out

def seq_body(b):
    # [APPLICATION n] { SEQUENCE { ... } }
    t, l, j = tlv(b, 0)
    t2, l2, k = tlv(b, j)
    return b[k:k + l2]

def enc_cipher_len(enc_part):
    # the body of the context tag holding an EncryptedData ::= SEQUENCE { etype [0], kvno [1] OPTIONAL, cipher [2] OCTET STRING }
    _, l, j = tlv(enc_part, 0)
    for tag, body in children(enc_part[j:j + l]):
        if tag == 0xa2:
            _, l, _ = tlv(body, 0)
            return l
    return None

def request(payload):
    ap_len = int.from_bytes(payload[4:6], "big")
    ap, priv = payload[6:6 + ap_len], payload[6 + ap_len:]
    fields = dict(children(seq_body(ap)))               # a0 pvno, a1 msg-type, a2 ap-options, a3 ticket, a4 authenticator
    ticket = dict(children(seq_body(fields[0xa3])))      # a0 tkt-vno, a1 realm, a2 sname, a3 enc-part
    t_cipher = enc_cipher_len(ticket[0xa3])
    a_cipher = enc_cipher_len(fields[0xa4])
    pf = dict(children(seq_body(priv)))                  # a0 pvno, a1 msg-type, a3 enc-part
    p_cipher = enc_cipher_len(pf[0xa3])
    return (f"msg={int.from_bytes(payload[0:2], 'big')} version=0x{int.from_bytes(payload[2:4], 'big'):04x} ap_req={ap_len} "
            f"ticket_cipher={t_cipher} auth_cipher={a_cipher} priv={len(priv)} priv_cipher={p_cipher}")

pcap = sys.argv[1]; port = sys.argv[2] if len(sys.argv) > 2 else "464"
for proto, flt, field in (("udp", f"udp.dstport=={port}", "udp.payload"), ("tcp", f"tcp.dstport=={port} && tcp.len>0", "tcp.payload")):
    r = subprocess.run(["tshark", "-r", pcap, "-Y", flt, "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "ipv6.src",
                        "-e", "ip.dst", "-e", "ipv6.dst", "-e", field], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        f = line.split("\t")
        if len(f) < 6 or not f[5].strip():
            continue
        raw = bytes.fromhex(f[5].replace(":", ""))
        if proto == "tcp":
            raw = raw[4:]                                # the record mark
        try:
            print(f"frame={f[0]} {proto} {f[1] or f[2]} -> {f[3] or f[4]} {request(raw)}")
        except (IndexError, KeyError, ValueError) as e:
            print(f"frame={f[0]} {proto} {f[1] or f[2]} -> {f[3] or f[4]} (not a change-password request: {e!r})")
