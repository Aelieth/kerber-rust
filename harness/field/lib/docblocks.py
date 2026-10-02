#!/usr/bin/env python3
"""docblocks.py: a doc's shell blocks, run as a reader pastes them into one terminal.

  docblocks.py count <file.md> <heading>
      the number of ```sh blocks in the section whose heading line is <heading> (to the next heading of the
      same or a higher level)
  docblocks.py script <file.md> <heading> <n> [--set NAME=VALUE]... [--drop ERE]... [--session LINE]...
      a bash script for block n (1-based): the --session lines first (the state the reader's terminal already
      has), then each top-level command of the block, echoed before it runs and followed by its exit status:
          @@ unit <i>/<total> lines=<k>      then the command's k lines prefixed `$ ` / `> `, then its output
          @@ unit <i> rc=<status>
      --set gives the assignment `NAME=...` the reader's value; --drop leaves out the unit an ERE matches (each
      ERE must match exactly one unit). Both are echoed as what they are. A here-document stays whole in its
      unit, its body unread. Every unit must parse alone (`bash -n`).
  docblocks.py results <session output>
      one line per unit: <i> TAB <rc, or "none" when it did not finish> TAB <output lines> TAB <first line>
  docblocks.py output <session output> <i>
      unit i's output, without the echoed command
Exit 1 with a message when the doc does not have what was asked for.
"""
import re
import shlex
import subprocess
import sys

FENCE = re.compile(r"^\s*```(\w*)\s*$")
HEADING = re.compile(r"^(#+)\s")
OPENERS = {"if", "for", "while", "until", "case", "select"}
CLOSERS = {"fi", "done", "esac"}
START = re.compile(r"^@@ unit (\d+)/(\d+) lines=(\d+)$")
END = re.compile(r"^@@ unit (\d+) rc=(\d+)$")
EOF_TAG = "@@DOCBLOCKS-UNIT-EOF"


def die(msg):
    print("docblocks.py: " + msg, file=sys.stderr)
    sys.exit(1)


def blocks(path, heading):
    lines = open(path, encoding="utf-8").read().split("\n")
    try:
        start = next(i for i, ln in enumerate(lines) if ln.rstrip() == heading)
    except StopIteration:
        die("no heading %r in %s" % (heading, path))
    level = len(HEADING.match(heading).group(1)) if HEADING.match(heading) else 0
    out, cur, fenced = [], None, False
    for ln in lines[start + 1:]:
        m = FENCE.match(ln)
        if not fenced:
            h = HEADING.match(ln)
            if h and len(h.group(1)) <= level:
                break
            if m:
                fenced = True
                cur = [] if m.group(1) in ("sh", "bash", "shell") else None
            continue
        if m and not m.group(1):
            fenced = False
            if cur is not None:
                out.append(cur)
            cur = None
            continue
        if cur is not None:
            cur.append(ln)
    return out


def code_of(line):
    """The line with quoted text blanked and a trailing comment cut, position for position (for keyword
    counting and here-document detection only)."""
    out, quote, i = [], None, 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < len(line):
                out.append("  ")
                i += 2
                continue
            if c == quote:
                quote = None
            out.append(" ")
        elif c in "'\"":
            quote = c
            out.append(" ")
        elif c == "#" and (i == 0 or line[i - 1].isspace()):
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


def heredocs(line):
    """[(strip_tabs, delimiter)] for each here-document a line opens (`<<` outside quotes, not `<<<`)."""
    code, out = code_of(line), []
    for i in range(len(code) - 1):
        if code[i:i + 2] != "<<" or code[i + 2:i + 3] == "<" or (i and code[i - 1] == "<"):
            continue
        m = HEREDOC.match(line, i)
        if m:
            out.append((m.group(1) == "-", m.group(3)))
    return out


def depth_change(code):
    d = 0
    for seg in re.split(r";|&&|\|\||\||\n", code):
        words = seg.split()
        while words and words[0] in ("then", "do", "else", "elif", "!"):
            words = words[1:]
        if words:
            if words[0] in OPENERS:
                d += 1
            elif words[0] in CLOSERS:
                d -= 1
    return d


def continues(line):
    """How a line carries its command on to the next one, as bash reads it: "\\" (a trailing backslash), "op" (a
    trailing &&, ||, | or |&, outside quotes and comments: bash reads on, past blank and comment lines), or ""."""
    if line.rstrip().endswith("\\"):
        return "\\"
    return "op" if code_of(line).rstrip().endswith(("&&", "||", "|", "|&")) else ""


def units(block):
    """The block's top-level commands, each a list of lines (comments and blank lines between them dropped).
    A here-document's body and its delimiter line belong to the command that opens it. A command goes on past a
    line that ends in a backslash or in &&, ||, | or |& (after a here-document too, when its opening line does)."""
    out, cur, depth, pending, cont = [], [], 0, [], ""
    for ln in block:
        if pending:
            cur.append(ln)
            strip_tabs, word = pending[0]
            if (ln.lstrip("\t") if strip_tabs else ln) == word:
                pending.pop(0)
                if not pending and depth == 0 and not cont:
                    out.append(cur)
                    cur = []
            continue
        if cont == "op" and (not ln.strip() or ln.lstrip().startswith("#")):
            cur.append(ln)
            continue
        if not cur and (not ln.strip() or ln.lstrip().startswith("#")):
            continue
        cur.append(ln)
        depth += depth_change(code_of(ln))
        if depth < 0:
            die("unbalanced block near %r" % ln)
        pending.extend(heredocs(ln))
        cont = continues(ln)
        if pending or cont:
            continue
        if depth == 0:
            out.append(cur)
            cur = []
    if cur:
        die("the block ends inside a command: %r" % cur)
    return out


def parses(text):
    return subprocess.run(["bash", "-n"], input=text, text=True, capture_output=True).returncode == 0


def cmd_script(args):
    if len(args) < 3:
        die("usage: script <file.md> <heading> <n> [--set NAME=VALUE]... [--drop ERE]... [--session LINE]...")
    path, heading, n = args[0], args[1], int(args[2])
    sets, drops, sessions, rest = {}, [], [], args[3:]
    while rest:
        opt = rest.pop(0)
        if not rest:
            die("%s needs a value" % opt)
        val = rest.pop(0)
        if opt == "--set" and "=" in val:
            k, v = val.split("=", 1)
            sets[k] = v
        elif opt == "--drop":
            drops.append(re.compile(val))
        elif opt == "--session":
            sessions.append(val)
        else:
            die("unknown option %s" % opt)
    bl = blocks(path, heading)
    if not 1 <= n <= len(bl):
        die("%s %r has %d sh block(s), not a block %d" % (path, heading, len(bl), n))
    us = units(bl[n - 1])
    used_sets, drop_hits = set(), [0] * len(drops)
    plan = []
    for u in us:
        text = "\n".join(u)
        if not parses(text):
            die("a unit does not parse alone: %r" % text)
        if EOF_TAG in text:
            die("a unit holds %s" % EOF_TAG)
        dropped = [i for i, rx in enumerate(drops) if rx.search(text)]
        if dropped:
            for i in dropped:
                drop_hits[i] += 1
            plan.append(("drop", text, None))
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(\S*)(\s+#.*)?$", text)
        if m and m.group(1) in sets:
            name = m.group(1)
            used_sets.add(name)
            value = sets[name]
            plan.append(("set", "%s=%s" % (name, shlex.quote(value) if value else ""),
                         "the reader's value; the doc's line: " + text.strip()))
            continue
        plan.append(("run", text, None))
    missing = [k for k in sets if k not in used_sets]
    if missing:
        die("block %d of %r has no assignment for: %s" % (n, heading, ", ".join(missing)))
    for rx, hits in zip(drops, drop_hits):
        if hits != 1:
            die("--drop %r matches %d units of block %d of %r, not exactly one" % (rx.pattern, hits, n, heading))
    runs = [p for p in plan if p[0] != "drop"]
    out = ["# docblocks.py: %s %r block %d: %d unit(s)" % (path.rsplit("/", 1)[-1], heading, n, len(runs))]
    for s in sessions:
        out.append("printf '%%s\\n' %s" % shlex.quote("# session: " + s))
        out.append("%s || { echo '@@ session line failed'; exit 1; }" % s)
    i = 0
    for kind, text, why in plan:
        if kind == "drop":
            shown = "# not run (the harness replaces it): " + text.replace("\n", " ")
            out.append("printf '%%s\\n' %s" % shlex.quote(shown))
            continue
        i += 1
        lines = text.split("\n")
        echo = ["$ " + lines[0] + ("    # " + why if why else "")] + ["> " + ln for ln in lines[1:]]
        out.append("printf '\\n@@ unit %d/%d lines=%d\\n'" % (i, len(runs), len(echo)))
        out.append("cat <<'%s'" % EOF_TAG)
        out.extend(echo)
        out.append(EOF_TAG)
        out.append(text)
        out.append("printf '@@ unit %d rc=%%s\\n' \"$?\"" % i)
    print("\n".join(out))


def parse_output(path):
    """{i: (rc or None, [output lines], first line)} and the total the markers announce."""
    res, total, cur, skip = {}, 0, None, 0
    for ln in open(path, encoding="utf-8", errors="replace").read().split("\n"):
        m = START.match(ln)
        if m:
            cur, total, skip = int(m.group(1)), int(m.group(2)), int(m.group(3))
            res[cur] = [None, [], None]
            continue
        if cur is not None and skip:
            if res[cur][2] is None:
                res[cur][2] = ln[2:]
            skip -= 1
            continue
        m = END.match(ln)
        if m and cur == int(m.group(1)):
            res[cur][0] = int(m.group(2))
            cur = None
            continue
        if cur is not None:
            res[cur][1].append(ln)
    return res, total


def cmd_results(args):
    res, total = parse_output(args[0])
    if not total:
        die("no unit markers in %s" % args[0])
    for i in range(1, total + 1):
        rc, out, first = res.get(i, [None, [], "(never started)"])
        print("%d\t%s\t%d\t%s" % (i, "none" if rc is None else rc, len(out), first or ""))


def cmd_output(args):
    res, _total = parse_output(args[0])
    for ln in res.get(int(args[1]), [None, [], None])[1]:
        print(ln)


def main():
    if len(sys.argv) < 3:
        die("usage: count|script|results|output ... (see the header)")
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "count":
        print(len(blocks(args[0], args[1])))
    elif cmd == "script":
        cmd_script(args)
    elif cmd == "results":
        cmd_results(args)
    elif cmd == "output":
        cmd_output(args)
    else:
        die("unknown command %s" % cmd)


if __name__ == "__main__":
    main()
