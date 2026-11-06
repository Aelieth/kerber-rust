# gss-seq-summary.py OUTDIR: one table per phase from the decoding acceptor's logs (ns-gss-seq.sh).
import glob, os, re, sys

out = sys.argv[1]
order = ["mit-default", "mit-nomutual", "ours"]

def blocks(text):
    items, cur = [], None
    for line in text.splitlines():
        m = re.match(r"== CTX (\d+) \(", line)
        if m:
            cur = {"n": int(m.group(1)), "lines": []}
            items.append(cur)
        elif cur is not None:
            cur["lines"].append(line)
    return items

def parse(ctxb):
    L = ctxb["lines"]
    t = "\n".join(L)
    g = lambda pat, d=None: (re.search(pat, t) or [None, d])[1]
    r = {"n": ctxb["n"]}
    r["fields"] = g(r"fields \(tag:length\):([^\n]*)", "").split()
    r["der"] = g(r"authenticator DER: (\d+) octets")
    r["cipher"] = g(r"authenticator ciphertext: (\d+) octets")
    s = re.search(r"seq-number \[7\]: (ABSENT|PRESENT, value (-?\d+))", t)
    r["seq"] = None if not s else (None if s.group(1) == "ABSENT" else int(s.group(2)))
    r["seq_text"] = s.group(1).replace("PRESENT, value ", "") if s else "?"
    r["subkey"] = g(r"subkey \[6\]: (PRESENT[^\n]*|ABSENT)")
    r["subkey_id"] = g(r"id ([0-9a-f]{8})")
    r["cksum"] = g(r"cksum \[3\]: ([^\n]*)")
    r["authz"] = "ABSENT" if "authorization-data [8]: ABSENT" in t else ("PRESENT" if "authorization-data [8]: PRESENT" in t else "?")
    r["authz_detail"] = [x.strip() for x in L if re.match(r"\s+ad-type", x)]
    r["mit_decoded"] = g(r"MIT's own decoding: ([^\n]*)")
    r["accept"] = g(r"gss_accept_sec_context: major (0x[0-9a-f]+) minor (\d+)")
    r["ret_flags"] = g(r"acceptor ret_flags ([^\n]*)")
    toks = re.findall(r"token header: CFX (wrap|MIC) \((\d+)\) flags (0x[0-9a-f]+) .*?SND_SEQ (\d+)", t)
    r["tokens"] = [(k, int(s)) for k, _, _, s in toks]
    r["unwrap"] = re.findall(r"gss_unwrap: major (0x[0-9a-f]+) minor (\d+)(?: \[([^\]]*)\])?", t)
    r["mic"] = re.findall(r"gss_verify_mic over the plaintext item before it: major (0x[0-9a-f]+) minor (\d+)(?: \[([^\]]*)\])?", t)
    r["replay_in"] = re.findall(r"replay in this context[^\n]*: major (0x[0-9a-f]+) minor (\d+)(?: \[([^\]]*)\])?(?: \[([^\]]*)\])?", t)
    r["replay_across"] = re.findall(r"replay across contexts: the first wrap token of context (\d+) \(SND_SEQ (\d+); this context's first token has SND_SEQ (\d+)\) given to this context (\d+), gss_unwrap: major (0x[0-9a-f]+) minor (\d+)(?: \[([^\]]*)\])?(?: \[([^\]]*)\])?", t)
    r["flags_tok"] = re.findall(r"token header: CFX wrap \(0504\) flags (0x[0-9a-f]+)", t)
    return r

for label in order:
    p = os.path.join(out, label + ".acceptor.txt")
    if not os.path.exists(p):
        continue
    rows = [parse(b) for b in blocks(open(p).read())]
    print(f"== {label}: {len(rows)} fresh contexts")
    print(" ctx  authenticator fields             seq-number [7]   subkey [6] id  first per-message SND_SEQ  2nd (MIC) SND_SEQ  accept   unwrap   verify_mic")
    for r in rows:
        first = r["tokens"][0][1] if r["tokens"] else "-"
        second = r["tokens"][1][1] if len(r["tokens"]) > 1 else "-"
        un = r["unwrap"][0][0] if r["unwrap"] else "-"
        mi = r["mic"][0][0] if r["mic"] else "-"
        print(f" {r['n']:>3}  {' '.join(f for f in r['fields']):<32} {r['seq_text']:<16} {r['subkey_id'] or '-':<14} {first!s:<26} {second!s:<18} {r['accept'] or '-':<8} {un:<8} {mi}")
    seqs = [r["seq"] for r in rows]
    ids = [r["subkey_id"] for r in rows]
    firsts = [r["tokens"][0][1] if r["tokens"] else None for r in rows]
    print(f"   seq-number values: {sorted(set(map(str, seqs)))}; distinct {len(set(map(str, seqs)))} of {len(rows)}")
    print(f"   subkey ids: distinct {len(set(ids))} of {len(rows)} (one per context)")
    absent = [r["n"] for r in rows if r["seq"] is None]
    zero = [r["n"] for r in rows if r["seq"] == 0]
    print(f"   authenticator seq-number absent in contexts {absent or 'none'}; present and 0 in contexts {zero or 'none'}")
    same = all(f is not None and (r["seq"] or 0) == f for f, r in zip(firsts, rows))
    print(f"   first per-message token's SND_SEQ equals the authenticator's seq-number: {'yes' if same else 'NO'}; second token = first + 1: {'yes' if all(len(r['tokens'])<2 or r['tokens'][1][1]==r['tokens'][0][1]+1 for r in rows) else 'NO'}")
    print(f"   cksum [3]: {sorted(set(str(r['cksum']) for r in rows))}")
    print(f"   authorization-data [8]: {sorted(set(r['authz'] for r in rows))} {sorted(set(d for r in rows for d in r['authz_detail']))}")
    print(f"   acceptor ret_flags: {sorted(set(str(r['ret_flags']) for r in rows))}")
    print(f"   MIT's own decoding of the authenticator: {sorted(set(re.sub(r'seq_number \\d+', 'seq_number N', str(r['mit_decoded'])) for r in rows))}")
    ri = sorted(set(" ".join(x for x in t if x) for r in rows for t in r["replay_in"]))
    ra = sorted(set(" ".join(x for x in t[4:] if x) for r in rows for t in r["replay_across"]))
    same_seq = [t[1] == t[2] for r in rows for t in r["replay_across"]]
    print(f"   replay of the first wrap token in the same context: {ri}")
    print(f"   replay of the previous context's first wrap token in this one: {ra}; the replayed token's SND_SEQ equals this context's first one in {sum(same_seq)} of {len(same_seq)} replays (so the sequence check alone would pass in those)")
    print()
