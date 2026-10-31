"""Golden kdb dump keys, kept while scripts/kdb-dump-gate.sh exists."""

from __future__ import annotations

from .common import ROOT, _die

def _dump_key_hexes(line: str) -> tuple[str, tuple[str, ...]] | None:
    """Name and every key_data slot-0 hex from a princ dump line, or None."""
    if not line.startswith("princ\t"):
        return None
    f = line.rstrip(";").split("\t")
    if len(f) < 16:
        return None
    try:
        n_tl = int(f[3])
        n_key = int(f[4])
    except ValueError:
        return None
    i = 15 + 3 * n_tl
    hexes: list[str] = []
    for _ in range(n_key):
        if i + 4 >= len(f):
            return None
        try:
            ver = int(f[i])
        except ValueError:
            return None
        # ver, kvno, then ver × (type, length, hex); slot 0 is the key.
        i += 2
        if i + 2 >= len(f):
            return None
        hexes.append(f[i + 2])
        i += 3 * ver
    if not hexes:
        return None
    return f[6], tuple(hexes)


def check_golden_dump_unique_keys(text: str | None = None) -> None:
    """Golden dump nosvr/hwuser key blobs are MIT-derived, not clones of user/pwprau."""
    if text is None:
        path = ROOT / "tests" / "traces" / "kdb" / "mit-dump-v7.txt"
        if not path.is_file():
            _die("missing tests/traces/kdb/mit-dump-v7.txt")
        text = path.read_text()
    keys: dict[str, tuple[str, ...]] = {}
    for line in text.splitlines():
        parsed = _dump_key_hexes(line)
        if parsed is None:
            continue
        name, hexes = parsed
        keys[name] = hexes
    for need in (
        "user@KERBER.TEST",
        "nosvr@KERBER.TEST",
        "hwuser@KERBER.TEST",
        "pwprau@KERBER.TEST",
    ):
        if need not in keys:
            _die(f"golden dump missing {need}")
    if keys["nosvr@KERBER.TEST"] == keys["user@KERBER.TEST"]:
        _die("nosvr keys clone user")
    if keys["hwuser@KERBER.TEST"] == keys["pwprau@KERBER.TEST"]:
        _die("hwuser keys clone pwprau")
