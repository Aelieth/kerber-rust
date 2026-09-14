#!/usr/bin/env python3
"""Turn nextest's junit.xml failures into GitHub workflow-command annotations.

The `test` job's log is private; check-run annotations are public, and
`scripts/ci-status.py` reads them. One `::error` per failed or errored
testcase: `file=` the crate's test source when it can be derived from the
classname (`crate::binary`), `title=` the test id, the message is the first
lines of the failure text. Exit 0 always — the step runs under `if: failure()`
and must not mask the real exit code.

Usage: junit-annotate.py <junit.xml> [limit]
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _esc(s: str) -> str:
    # Workflow-command property escaping (`%`, `\r`, `\n`, `:` and `,` in properties).
    return (
        s.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _esc_msg(s: str) -> str:
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _guess_file(classname: str) -> str | None:
    # nextest classname: "<crate>::<binary>"; integration tests live at
    # crates/<crate>/tests/<binary>.rs, unit tests at crates/<crate>/src/lib.rs.
    if "::" not in classname:
        return None
    crate, binary = classname.split("::", 1)
    for cand in (f"crates/{crate}/tests/{binary}.rs", f"crates/{crate}/src/lib.rs"):
        if Path(cand).is_file():
            return cand
    return None


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: junit-annotate.py <junit.xml> [limit]", file=sys.stderr)
        return 0
    path = Path(sys.argv[1])
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    if not path.is_file():
        print(f"::warning::junit-annotate: {path} not found")
        return 0
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        print(f"::warning::junit-annotate: {path} unparsable: {e}")
        return 0
    n = 0
    for tc in root.iter("testcase"):
        bad = tc.find("failure")
        if bad is None:
            bad = tc.find("error")
        if bad is None:
            continue
        n += 1
        if n > limit:
            break
        classname = tc.get("classname") or ""
        name = tc.get("name") or ""
        title = f"nextest {classname}::{name}" if classname else f"nextest {name}"
        text = (bad.get("message") or "").strip()
        body = (bad.text or "").strip()
        if body:
            text = (text + "\n" + body).strip() if text else body
        lines = [ln for ln in text.splitlines() if ln.strip()]
        msg = "\n".join(lines[:12])[:1500] or "test failed"
        props = [f"title={_esc(title)}"]
        f = _guess_file(classname)
        if f:
            props.insert(0, f"file={_esc(f)}")
        print(f"::error {','.join(props)}::{_esc_msg(msg)}")
    if n == 0:
        print("::warning::junit-annotate: no failed testcases in junit.xml")
    elif n > limit:
        print(f"::warning::junit-annotate: {n - limit} more failures not annotated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
