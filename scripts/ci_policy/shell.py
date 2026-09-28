"""Bash lexers for the gate scripts: echo-only `if` arms and host `/tmp` writes."""

from __future__ import annotations

import re

from .common import ROOT, SCRIPTS, _die
_IF_ONELINER = re.compile(
    r"^\s*(if|elif)\b.*;\s*then\b.*;\s*fi\b",
)
_IF_START = re.compile(r"^\s*(if|elif)\b")
_ELSE = re.compile(r"^\s*else\b")
_FI = re.compile(r"^\s*fi\b")
_NOISE_ONLY = re.compile(r"^(?:echo|printf|true|cat|tee)\b|^:(?:\s|$)")
_ASSIGN_ONLY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_QUOTED = re.compile(r"""('([^'\\]|\\.)*'|"([^"\\]|\\.)*")""")
_ASSERT_CMDS = frozenset(
    {"exit", "die", "return", "break", "continue", "unavailable"}
)
_TEST_CMDS = frozenset({"[", "[[", "test", "grep", "egrep", "fgrep", "cmp"})
_NOISE_CMDS = frozenset({"echo", "printf", "true", "cat", "tee", ":"})
_REQUIRE_DIE = re.compile(r"KERBER_REQUIRE_")
_LOG_ERROR = re.compile(r"""log\s+\S+\s+(?:error|"error")""")
_LOG_SKIP = re.compile(r"""log\s+\S+\s+(?:skip|"skip")""")
_OR_TRUE = re.compile(r"\|\|\s*true\s*$")
_PIPE = re.compile(r"(?<!\|)\|(?!\|)")
_REDIR = re.compile(r"(?:\d*)(?:>>?|<)\s*(\S+)")
_TEE_FILE = re.compile(r"\btee(?:\s+-a)?\s+(\S+)")
_DOLLAR_PAREN = re.compile(r"\$\([^()]*\)")
_HEREDOC = re.compile(
    r"(?:cat\s+)?<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n.*?^\1\s*$",
    re.M | re.S,
)
_BRACE_GROUP = re.compile(r"\{([^{}]*)\}(?:\s*(?:>>?|\|(?!\|))\s*\S+)?")
_PAREN_GROUP = re.compile(r"(?<!\$)\(([^()]*)\)(?:\s*(?:>>?|\|(?!\|))\s*\S+)?")


def _flatten_arm(body: str) -> str:
    """Unwrap `{...}`, `(...)`, and heredocs so wrappers cannot hide echo-only."""
    body = _HEREDOC.sub("echo heredoc", body)
    prev = None
    while prev != body:
        prev = body
        body = _BRACE_GROUP.sub(lambda m: m.group(1), body)
        body = _PAREN_GROUP.sub(lambda m: m.group(1), body)
    return body


def _code_without_comment(line: str) -> str:
    in_s = in_d = False
    for j, ch in enumerate(line):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d:
            return line[:j].rstrip()
    return line.rstrip()


def _join_shell_continuations(text: str) -> str:
    """Join `\\`, `||`, and `&&` continuations; blank the swallowed lines."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        code = _code_without_comment(lines[i])
        if code.endswith("\\") or re.search(r"(?:\|\||&&)\s*$", code):
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines):
                nxt = lines[j].lstrip()
                if code.endswith("\\"):
                    lines[i] = code[:-1].rstrip() + " " + nxt
                else:
                    lines[i] = code + " " + nxt
                lines[j] = ""
                continue
        i += 1
    return "\n".join(lines)


def _strip_quoted(s: str) -> str:
    return _QUOTED.sub(" ", s)


def _split_semi(line: str) -> list[str]:
    """Split on `;` that are not inside quotes."""
    out: list[str] = []
    buf: list[str] = []
    in_s = in_d = False
    for ch in line:
        if ch == "'" and not in_d:
            in_s = not in_s
            buf.append(ch)
        elif ch == '"' and not in_s:
            in_d = not in_d
            buf.append(ch)
        elif ch == ";" and not in_s and not in_d:
            piece = "".join(buf).strip()
            if piece:
                out.append(piece)
            buf = []
        else:
            buf.append(ch)
    piece = "".join(buf).strip()
    if piece:
        out.append(piece)
    return out or ([line.strip()] if line.strip() else [])


def _written_paths(body: str) -> set[str]:
    found: set[str] = set()
    for rx in (_TEE_FILE, _REDIR):
        for m in rx.finditer(body):
            tok = m.group(1)
            found.add(tok)
            found.add(tok.strip("'\""))
    return found


def _cmd_word(stage: str) -> str:
    s = _DOLLAR_PAREN.sub(" ", stage.strip())
    while True:
        m = re.match(r"^[A-Za-z_][A-Za-z0-9_]*\+?=\S*\s+", s)
        if not m:
            break
        s = s[m.end() :]
    s = _QUOTED.sub(lambda m: m.group(0) if "$" in m.group(0) else " ", s)
    s = re.sub(r"(?:\d*)(?:>>?|<)\s*\S+", " ", s)
    s = re.sub(r"\d*>&?\d+", " ", s)
    s = s.strip()
    if s.startswith("[["):
        return "[["
    if s.startswith("["):
        return "["
    return (s.split() or [""])[0]


_LOGICAL_OPS = ("||", "&&")
_REQUIRE_NAME = re.compile(r"KERBER_REQUIRE_([A-Z0-9_]+)")
_CASE_START = re.compile(r"^\s*case\b.*\bin\s*$")
_ESAC = re.compile(r"^\s*esac\b")
_CASE_ARM = re.compile(r"^\s*\(?[^()$]*\)\s*(.*)$")


def _split_logical(stmt: str) -> list[tuple[str, str]]:
    """`(op, part)` pieces split on `||` / `&&` outside quotes; the first op is empty."""
    parts: list[tuple[str, str]] = []
    buf: list[str] = []
    op = ""
    in_s = in_d = False
    i = 0
    while i < len(stmt):
        ch = stmt[i]
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif not in_s and not in_d and stmt[i : i + 2] in _LOGICAL_OPS:
            parts.append((op, "".join(buf).strip()))
            buf = []
            op = stmt[i : i + 2]
            i += 2
            continue
        buf.append(ch)
        i += 1
    parts.append((op, "".join(buf).strip()))
    return [(o, x) for o, x in parts if x]


def _is_tautology(
    cmd: str, stage: str, written: set[str], noise_written: frozenset[str], stmt: str
) -> bool:
    if cmd in {"[", "[[", "test"}:
        for w in written:
            if w and w in stage and re.search(r"(?:^|[\s[])-[sfe]\b", stage):
                return True
        if "$" not in stage:
            return True
    if cmd == "cmp":
        args = [a for a in _QUOTED.sub(" ", stage).split()[1:] if not a.startswith("-")]
        if len(args) >= 2 and (args[0] == args[1] or args[:2] == ["/dev/null", "/dev/null"]):
            return True
    if cmd in {"grep", "egrep", "fgrep"}:
        echo = re.search(r"\becho\b(.*)\|\s*(?:e|f)?grep\b", stmt)
        if echo is not None and "$" not in echo.group(1):
            return True
        if any(w and w in stage for w in noise_written):
            return True
    return False


def _part_kind(part: str, written: set[str], noise_written: frozenset[str]) -> str:
    stages = [s.strip() for s in _PIPE.split(part) if s.strip()] or [part]
    kinds: list[str] = []
    for stage in stages:
        if not stage or _ASSIGN_ONLY.match(stage):
            continue
        cmd = _cmd_word(stage).rsplit("/", 1)[-1]
        if not cmd:
            continue
        if cmd == "log" or cmd.startswith("log_"):
            kinds.append("assert" if re.search(r"\berror\b", stage) else "noise")
        elif cmd in _ASSERT_CMDS:
            kinds.append("assert")
        elif cmd in _TEST_CMDS:
            taut = _is_tautology(cmd, stage, written, noise_written, part)
            kinds.append("noise" if taut else "assert")
        elif cmd in _NOISE_CMDS or _NOISE_ONLY.match(stage):
            kinds.append("noise")
        else:
            kinds.append("work")
    if "assert" in kinds:
        return "assert"
    if "work" in kinds:
        return "work"
    return "noise"


def _stmt_kind(stmt: str, written: set[str], noise_written: frozenset[str] = frozenset()) -> str:
    """`assert`, `work`, or `noise`; a test whose `||` branch does not assert is noise."""
    parts = _split_logical(stmt.strip())
    if not parts:
        return "noise"
    kinds = [_part_kind(x, written, noise_written) for _, x in parts]
    for i in range(1, len(parts)):
        if kinds[i - 1] != "assert":
            continue
        if parts[i][0] == "||":
            kinds[i - 1] = "assert" if kinds[i] == "assert" else "noise"
        elif kinds[i] != "assert":
            kinds[i - 1] = kinds[i]
    if "assert" in kinds:
        return "assert"
    if "work" in kinds:
        return "work"
    return "noise"


def _noise_written(stmts: list[str]) -> frozenset[str]:
    noise: set[str] = set()
    work: set[str] = set()
    for s in stmts:
        for _, part in _split_logical(s):
            targets = _written_paths(part)
            if not targets:
                continue
            cmd = _cmd_word(part).rsplit("/", 1)[-1]
            (noise if cmd in _NOISE_CMDS else work).update(targets)
    return frozenset(noise - work)


def _echo_only_body(body: str, script: str = "") -> bool:
    """True when the arm is an informational skip, not a real assert or work."""
    flat = _flatten_arm(body)
    if _LOG_SKIP.search(flat) and re.search(r"\bdie\b", script):
        low = flat.lower()
        if any(name.lower() in low for name in _REQUIRE_NAME.findall(script)):
            return False
    stmts: list[str] = []
    for ln in flat.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        stmts.extend(_split_semi(s))
    if not stmts:
        return False
    written = _written_paths(flat)
    noise_written = _noise_written(stmts)
    actionable = [s for s in stmts if not _ASSIGN_ONLY.match(s)]
    if not actionable:
        return False
    return all(_stmt_kind(s, written, noise_written) == "noise" for s in actionable)


def _case_informational_starts(text: str) -> list[int]:
    hits: list[int] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if not _CASE_START.match(lines[i]):
            i += 1
            continue
        start = i + 1
        depth = 1
        arms: list[list[str]] = []
        cur: list[str] | None = None
        j = i + 1
        while j < len(lines):
            line = lines[j]
            if _CASE_START.match(line):
                depth += 1
            elif _ESAC.match(line):
                depth -= 1
                if depth == 0:
                    break
            elif depth == 1:
                m = _CASE_ARM.match(line)
                if cur is None and m:
                    cur = [m.group(1)] if m.group(1).strip() else []
                elif cur is not None:
                    cur.append(line)
                if cur is not None and line.rstrip().endswith(";;"):
                    cur[-1] = cur[-1].rstrip()[:-2]
                    arms.append(cur)
                    cur = None
            j += 1
        if cur:
            arms.append(cur)
        if any(_echo_only_body("\n".join(a), text) for a in arms if "\n".join(a).strip()):
            hits.append(start)
        i = j + 1
    return hits


def informational_if_starts(text: str) -> list[int]:
    """Line numbers of if-chains with any echo-only then/elif/else arm.

    Nested `fi` is paired by depth so an inner `if` cannot pop the outer
    frame. Each arm is tokenised: assignments, redirections, quotes and
    `$(…)` do not supply assertion words. An assertion is a command in
    {exit, die, return, break, continue, unavailable, log … error} or a
    test (`[`, `[[`, `test`, `grep`, `cmp`) whose `||` branch, if any,
    asserts, and that is not a self-tautology (a `grep` of a file the arm
    wrote with `echo` is one). `case` arms are walked like `if` arms.
    `log … skip` is accepted only when the arm names a `KERBER_REQUIRE_`
    requirement that a `die` in the same script enforces.
    """
    text = _join_shell_continuations(text)
    hits: list[int] = []
    # frame: start_line, arms (completed), current arm lines
    stack: list[tuple[int, list[str], list[str]]] = []

    def _close_if(start: int, arms: list[str], current: list[str]) -> bool:
        blobs = list(arms)
        if current:
            blobs.append("\n".join(current))
        any_echo = bool(blobs) and any(_echo_only_body(b, text) for b in blobs)
        all_echo = bool(blobs) and all(_echo_only_body(b, text) for b in blobs)
        if any_echo:
            hits.append(start)
        if stack:
            stack[-1][2].append("echo x" if all_echo else "exit 1")
        return any_echo

    def _after_then(line: str) -> str:
        parts = re.split(r"\bthen\b", line, maxsplit=1)
        return parts[1].strip() if len(parts) == 2 else ""

    for i, raw in enumerate(text.splitlines(), 1):
        hash_at = None
        in_s = in_d = False
        for j, ch in enumerate(raw):
            if ch == "'" and not in_d:
                in_s = not in_s
            elif ch == '"' and not in_s:
                in_d = not in_d
            elif ch == "#" and not in_s and not in_d:
                hash_at = j
                break
        line = (raw[:hash_at] if hash_at is not None else raw).rstrip()
        if not line.strip():
            continue
        if _IF_ONELINER.search(line):
            flat = [
                m.group(1)
                for m in re.finditer(
                    r";\s*(?:then|elif\b.*?;\s*then|else)\b(.*?)(?=;\s*(?:elif\b|else\b|fi\b)|$)",
                    line,
                )
            ]
            if flat and any(_echo_only_body(p, text) for p in flat):
                hits.append(i)
                if stack:
                    stack[-1][2].append(
                        "echo x" if all(_echo_only_body(p, text) for p in flat) else "exit 1"
                    )
            elif stack:
                stack[-1][2].append("exit 1")
            continue
        if re.match(r"^\s*elif\b", line):
            if stack:
                start, arms, cur = stack[-1]
                if cur:
                    arms.append("\n".join(cur))
                stack[-1] = (start, arms, [])
                extra = _after_then(line)
                if extra:
                    stack[-1][2].append(extra)
            continue
        if re.match(r"^\s*then\b", line) and stack:
            extra = _after_then(line)
            if extra:
                stack[-1][2].append(extra)
            continue
        if _IF_START.match(line):
            extra = _after_then(line)
            stack.append((i, [], [extra] if extra else []))
            continue
        if _ELSE.match(line):
            if stack:
                start, arms, cur = stack[-1]
                if cur:
                    arms.append("\n".join(cur))
                extra = re.split(r"\belse\b", line, maxsplit=1)
                rest = extra[1].strip() if len(extra) == 2 else ""
                stack[-1] = (start, arms, [rest] if rest else [])
            continue
        if _FI.match(line):
            if stack:
                start, arms, cur = stack.pop()
                _close_if(start, arms, cur)
            continue
        if stack:
            stack[-1][2].append(line)
    hits.extend(_case_informational_starts(text))
    return sorted(set(hits))


def check_no_informational_gates() -> None:
    paths = list(SCRIPTS.glob("*-gate.sh")) + list((SCRIPTS / "lib").glob("*.sh"))
    for path in sorted(paths):
        hits = informational_if_starts(path.read_text())
        if hits:
            rel = path.relative_to(ROOT)
            _die(f"{rel} informational if at line {hits[0]}")
_HOST_TMP_REDIR = re.compile(
    r"(?:^|[\s;|&])(?:\d*)>>?\s*/tmp/"
    r"|(?:^|[\s;|&])(?:cp|tee|mv|mkdir|touch|install)\b[^\n;|&]*\s/tmp/"
    r"|\$\([^)]*>>?\s*/tmp/"
)
_HEREDOC_DELIM = re.compile(r"""(?<!<)<<(?!<)[-]?\s*['\"]?(\w+)['\"]?""")
_UNQUOTED_REDIR = re.compile(r"(?:^|[\s;|&])(?:\d*)>>?\s*$")
_UNQUOTED_CP = re.compile(
    r"(?:^|[\s;|&])(?:cp|tee|mv|mkdir|touch|install)\b"
)
_QUOTED_TMP = re.compile(r"""['\"]/tmp/""")
# `mktemp` / `mktemp -d` with no template and no -p/--tmpdir lands in host /tmp
# (W3-S1). A template or `-p DIR` follows the flags; a bare call hits a closer.
_BARE_MKTEMP = re.compile(r"(?<![\w-])mktemp\b(?:\s+-[a-zA-Z]+)*\s*(?=$|[)|&;>])")
_QUOTED_REDIR_TMP = re.compile(r""">>?\s*['\"]/tmp/""")


def _quoted_host_tmp(raw: str, unquoted: str) -> bool:
    """Host `>"/tmp/…"` or `cp x "/tmp/…"`; `>` inside a quote is not a host write."""
    if _UNQUOTED_REDIR.search(unquoted.rstrip()) and _QUOTED_REDIR_TMP.search(raw):
        return True
    return bool(_UNQUOTED_CP.search(unquoted) and _QUOTED_TMP.search(raw))


def _skip_dollar_arith(line: str, k: int) -> int:
    """Advance past `$((…))` starting at `$`. Returns `len(line)` if unclosed."""
    k += 3
    n = len(line)
    while k + 1 < n:
        if line[k] == ")" and line[k + 1] == ")":
            return k + 2
        k += 1
    return n


def _push_cmdsubst(in_sq: list[bool], in_dq: list[bool], in_ansi: list[bool]) -> None:
    in_sq.append(False)
    in_dq.append(False)
    in_ansi.append(False)


_DOCKER_CMD = re.compile(r"\bdocker\s+(?:exec|run)\b")
_DOCKER_HOST_OP = re.compile(r"(?:&&|\|\||;&|\|&|[;&|]|[0-9]*>>?)")


def _host_side_code(code: str) -> str:
    """Drop `docker exec`/`run` argv; keep host redirects, pipes, and later commands."""
    out: list[str] = []
    i = 0
    while i < len(code):
        m = _DOCKER_CMD.search(code, i)
        if not m:
            out.append(code[i:])
            break
        out.append(code[i : m.start()])
        op = _DOCKER_HOST_OP.search(code, m.end())
        if not op:
            break
        i = op.start()
    return "".join(out)


def host_tmp_write_lines(text: str) -> list[int]:
    """Host-level `>/tmp/` writes, skipping quotes, `$(…)`, and heredocs.

    A quoted closer (`EOF'`, `EOF"`) ends the heredoc. The delimiter is
    taken from the unquoted host-side text (`<<<` is not a heredoc).
    Quoted redirect targets are scanned. Quoted `sh -c '…'` payloads are
    stripped; a host redirect on the same docker line is not.
    """
    hits: list[int] = []
    in_sq = [False]
    in_dq = [False]
    in_ansi = [False]
    heredoc_end: str | None = None
    for i, line in enumerate(text.splitlines(), 1):
        if heredoc_end is not None:
            s = line.strip()
            if s == heredoc_end:
                heredoc_end = None
            elif s == heredoc_end + "'":
                heredoc_end = None
                in_sq[-1] = False
            elif s == heredoc_end + '"':
                heredoc_end = None
                in_dq[-1] = False
            continue
        started_quoted = in_sq[-1] or in_dq[-1] or in_ansi[-1]
        buf: list[str] = []
        k = 0
        n = len(line)
        while k < n:
            ch = line[k]
            if in_ansi[-1]:
                if ch == "\\" and k + 1 < n:
                    k += 2
                    continue
                if ch == "'":
                    in_ansi[-1] = False
                k += 1
                continue
            if in_sq[-1]:
                if ch == "'":
                    in_sq[-1] = False
                k += 1
                continue
            if in_dq[-1]:
                if ch == "\\" and k + 1 < n:
                    k += 2
                    continue
                if ch == '"':
                    in_dq[-1] = False
                    k += 1
                    continue
                if ch == "$" and k + 1 < n and line[k + 1] == "(":
                    if k + 2 < n and line[k + 2] == "(":
                        k = _skip_dollar_arith(line, k)
                    else:
                        _push_cmdsubst(in_sq, in_dq, in_ansi)
                        k += 2
                    continue
                k += 1
                continue
            if ch == "\\" and k + 1 < n:
                buf.append(line[k + 1])
                k += 2
                continue
            if ch == "$" and k + 1 < n and line[k + 1] == "'":
                in_ansi[-1] = True
                k += 2
                continue
            if ch == "'":
                in_sq[-1] = True
                k += 1
                continue
            if ch == '"':
                in_dq[-1] = True
                k += 1
                continue
            if ch == "$" and k + 1 < n and line[k + 1] == "(":
                if k + 2 < n and line[k + 2] == "(":
                    k = _skip_dollar_arith(line, k)
                else:
                    _push_cmdsubst(in_sq, in_dq, in_ansi)
                    k += 2
                continue
            if ch == ")" and len(in_sq) > 1:
                in_sq.pop()
                in_dq.pop()
                in_ansi.pop()
                k += 1
                continue
            if ch == "#":
                break
            buf.append(ch)
            k += 1
        unquoted = "".join(buf)
        code = _host_side_code(unquoted)
        raw = line[:k]
        if not started_quoted and "<<" in unquoted:
            m = _HEREDOC_DELIM.search(raw)
            if m:
                heredoc_end = m.group(1)
        if "KERBER_SCRATCH:-" in code or "KERBER_SCRATCH:-" in raw:
            continue
        if _HOST_TMP_REDIR.search(code) or _quoted_host_tmp(raw, code):
            hits.append(i)
        elif "mktemp" in code and "TMPDIR=" not in code and _BARE_MKTEMP.search(raw):
            hits.append(i)
    return hits


def check_no_host_tmp_writes(
    text: str | None = None,
    name: str = "gate.sh",
    files: dict[str, str] | None = None,
) -> None:
    """No host `/tmp/` writes (nor bare `mktemp`) in scripts/*.sh or scripts/lib outside KERBER_SCRATCH defaults."""
    if text is not None:
        hits = host_tmp_write_lines(text)
        if hits:
            _die(f"{name} host /tmp write at line {hits[0]}")
        return
    if files is None:
        files = {
            p.name: p.read_text()
            for p in sorted(SCRIPTS.glob("*.sh"))
        }
        lib = SCRIPTS / "lib"
        if lib.is_dir():
            for path in sorted(lib.glob("*.sh")):
                files[f"lib/{path.name}"] = path.read_text()
    for fname, body in files.items():
        hits = host_tmp_write_lines(body)
        if hits:
            _die(f"{fname} host /tmp write at line {hits[0]}")
