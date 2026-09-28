#!/usr/bin/env python3
"""Prove that splitting a Python module into a package moved its code and changed nothing.

The old module is a file (`--old`) or `REV:PATH` read through git (`--old-rev`, `--old-path`).
The package is every `*.py` under `--pkg`, recursively; `--shim` is the file left in the old
module's place. Findings, each counted:

- missing / extra / defined-twice: every top-level def, class and assignment target of the old
  module is defined exactly once in the package; a top-level name the old module did not define
  is extra, and so is an `import` of a module the old file did not import;
- changed: a moved def, class or assignment differs from the old one (AST dump without
  positions); `--accept NAME=REASON` names an expected change, printed with its reason, and an
  accept entry that no change uses is itself a finding;
- unresolved: a global that a moved item reads (exact scopes from `symtable`, so a local that
  shadows a global is not a read) must resolve in the item's new module to its home: defined
  there, or bound by `from .home import name`; a standard-library module is imported where used;
- future / stray: each module keeps `from __future__ import annotations` when the old module had
  it, and holds nothing at its top level but a docstring, imports, defs, classes and assignments;
- shim: each `from <pkg>[.<mod>] import name` in the shim names the module that defines `name`;
- cycles: the package's relative imports form no cycle, and the package imports in a fresh
  interpreter.

usage: py-move-check.py (--old FILE | --old-rev REV [--old-path PATH] [--git-dir DIR])
                        --pkg DIR [--shim FILE] [--accept NAME=REASON ...]
       py-move-check.py --self-test
Exit 0 when every count is 0 (accepted changes allowed), 1 when one is not, 2 on a usage error.
"""

from __future__ import annotations

import ast
import builtins
import contextlib
import os
import pathlib
import subprocess
import sys
import symtable
import tempfile

KINDS = ("missing", "extra", "defined-twice", "changed", "unresolved", "future", "stray", "shim", "cycles")
ALLOWED_TOP = (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Assign,
               ast.AnnAssign)


def top_names(tree: ast.Module) -> dict[str, list[ast.stmt]]:
    """Top-level def / class names and assignment targets -> their statements."""
    out: dict[str, list[ast.stmt]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.setdefault(node.name, []).append(node)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name):
                        out.setdefault(name.id, []).append(node)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out.setdefault(node.target.id, []).append(node)
    return out


def imported_modules(tree: ast.Module) -> set[str]:
    """Names bound at the top level by plain `import x` / `import x.y` (binds `x`)."""
    out = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.add(alias.asname or alias.name.split(".")[0])
    return out


def has_future_annotations(tree: ast.Module) -> bool:
    return any(isinstance(n, ast.ImportFrom) and n.module == "__future__" and any(a.name == "annotations" for a in n.names)
               for n in tree.body)


def is_docstring(node: ast.stmt, index: int) -> bool:
    return index == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(
        node.value.value, str)


def load_package(pkg: pathlib.Path) -> dict[str, tuple[pathlib.Path, str, ast.Module]]:
    """Dotted module name (relative to the package; `__init__` for the package itself) -> file."""
    mods = {}
    for path in sorted(pkg.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(pkg).with_suffix("")
        parts = list(rel.parts)
        if parts[-1] == "__init__" and len(parts) > 1:
            parts = parts[:-1]
        name = ".".join(parts)
        src = path.read_text(encoding="utf-8")
        mods[name] = (path, src, ast.parse(src, filename=str(path)))
    return mods


def package_of(module: str, path: pathlib.Path) -> list[str]:
    """The package a module lives in, as parts relative to the top package."""
    if module == "__init__":
        return []
    parts = module.split(".")
    return parts if path.name == "__init__.py" else parts[:-1]


def resolve_from(module: str, path: pathlib.Path, node: ast.ImportFrom, top: str) -> str | None:
    """The package-relative module an ImportFrom names, or None when it is outside the package."""
    if node.level == 0:
        if node.module == top:
            return "__init__"
        if node.module and node.module.startswith(top + "."):
            return node.module[len(top) + 1:]
        return None
    base = package_of(module, path)
    up = node.level - 1
    if up > len(base):
        return None
    base = base[:len(base) - up]
    parts = base + (node.module.split(".") if node.module else [])
    return ".".join(parts) if parts else "__init__"


def bindings(module: str, path: pathlib.Path, tree: ast.Module, top: str) -> dict[str, tuple[str, str]]:
    """Local name -> (package module, original name) for the top-level `from <package> import` lines."""
    out = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            target = resolve_from(module, path, node, top)
            if target is None:
                continue
            for alias in node.names:
                out[alias.asname or alias.name] = (target, alias.name)
    return out


def global_reads(src: str, path: pathlib.Path) -> set[str]:
    """Every name read as a global anywhere in the module: module-level reads of names the module
    does not bind, and the globals of every function and class scope (exact, via symtable)."""
    table = symtable.symtable(src, str(path), "exec")
    out: set[str] = set()

    def walk(t: symtable.SymbolTable) -> None:
        for sym in t.get_symbols():
            if not sym.is_referenced():
                continue
            if t.get_type() == "module":
                out.add(sym.get_name())
            elif sym.is_global() or sym.is_declared_global():
                out.add(sym.get_name())
        for child in t.get_children():
            walk(child)

    walk(table)
    return out


def read_old(args: dict) -> tuple[str, str]:
    if args.get("old"):
        path = pathlib.Path(args["old"])
        return str(path), path.read_text(encoding="utf-8")
    rev = args["old_rev"]
    rel = args.get("old_path") or "scripts/ci-policy.py"
    cmd = ["git"] + (["--git-dir", args["git_dir"]] if args.get("git_dir") else []) + ["show", f"{rev}:{rel}"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"py-move-check: git show {rev}:{rel} failed: {proc.stderr.strip()}")
    return f"{rev}:{rel}", proc.stdout


def find_cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    cycles, state, stack = [], {}, []

    def dfs(u: str) -> None:
        state[u] = 1
        stack.append(u)
        for v in sorted(graph.get(u, ())):
            if state.get(v) == 1:
                cycles.append(stack[stack.index(v):] + [v])
            elif v not in state:
                dfs(v)
        stack.pop()
        state[u] = 2

    for u in sorted(graph):
        if u not in state:
            dfs(u)
    return cycles


def check(old_label: str, old_src: str, pkg: pathlib.Path, shim: pathlib.Path | None,
          accept: dict[str, str], runtime: bool = True) -> tuple[dict[str, list[str]], list[str]]:
    """(findings by kind, accepted lines)."""
    found: dict[str, list[str]] = {k: [] for k in KINDS}
    accepted: list[str] = []
    top = pkg.name
    old_tree = ast.parse(old_src, filename=old_label)
    old = top_names(old_tree)
    old_imports = imported_modules(old_tree)
    old_future = has_future_annotations(old_tree)
    mods = load_package(pkg)
    new: dict[str, list[ast.stmt]] = {}
    home: dict[str, str] = {}
    for mod, (path, _src, tree) in mods.items():
        for name, nodes in top_names(tree).items():
            new.setdefault(name, []).extend(nodes)
            if name in home and home[name] != mod:
                found["defined-twice"].append(f"{name}: {home[name]} and {mod}")
            elif len(nodes) > 1 and name not in home:
                found["defined-twice"].append(f"{name}: {len(nodes)} times in {mod}")
            home.setdefault(name, mod)
        for extra_import in sorted(imported_modules(tree) - old_imports):
            found["extra"].append(f"import {extra_import} in {mod} (the old module does not import it)")
        if old_future and not has_future_annotations(tree):
            found["future"].append(f"{mod} lacks `from __future__ import annotations`")
        for i, node in enumerate(tree.body):
            if not isinstance(node, ALLOWED_TOP) and not is_docstring(node, i):
                found["stray"].append(f"{mod}:{node.lineno} {type(node).__name__}")
    for name in sorted(set(old) - set(new)):
        found["missing"].append(name)
    for name in sorted(set(new) - set(old)):
        found["extra"].append(f"{name} in {home.get(name)}")
    dump = lambda n: ast.dump(n, include_attributes=False)  # noqa: E731
    used_accept = set()
    for name in sorted(set(old) & set(new)):
        if [dump(n) for n in old[name]] != [dump(n) for n in new[name]]:
            if name in accept:
                used_accept.add(name)
                accepted.append(f"{name}: {accept[name]}")
                for tag, nodes in (("old", old[name]), ("new", new[name])):
                    text = " | ".join(ast.unparse(n).replace("\n", " / ") for n in nodes)
                    accepted.append(f"    {tag}: {text[:300]}")
            else:
                found["changed"].append(f"{name} in {home.get(name)}")
    for name in sorted(set(accept) - used_accept):
        found["changed"].append(f"accept entry unused: {name}")
    builtin_names = set(dir(builtins))
    graph: dict[str, set[str]] = {}
    for mod, (path, src, tree) in mods.items():
        bound = bindings(mod, path, tree, top)
        graph[mod] = {target for target, _orig in bound.values()} - {mod}
        own = set(top_names(tree))
        mod_imports = imported_modules(tree)
        for name in sorted(global_reads(src, path)):
            if name in own:
                continue
            if name in bound:
                target, orig = bound[name]
                if name in old and (orig != name or home.get(name) != target):
                    found["unresolved"].append(f"{mod}: {name} is bound from {target}.{orig}, home {home.get(name)}")
                continue
            if name in mod_imports:
                continue
            if name in old:
                found["unresolved"].append(f"{mod}: {name} (home {home.get(name)}) is read but not imported")
            elif name in old_imports:
                found["unresolved"].append(f"{mod}: module {name} is read but not imported")
            elif name not in builtin_names and not (name.startswith("__") and name.endswith("__")):
                # dunders (__file__, __name__, the compiler's __conditional_annotations__) come with
                # every module
                found["unresolved"].append(f"{mod}: {name} is defined nowhere")
    for cycle in find_cycles(graph):
        found["cycles"].append(" -> ".join(cycle))
    if shim is not None:
        shim_tree = ast.parse(shim.read_text(encoding="utf-8"), filename=str(shim))
        for node in shim_tree.body:
            if isinstance(node, ast.ImportFrom) and node.module and (node.module == top or node.module.startswith(top + ".")):
                target = "__init__" if node.module == top else node.module[len(top) + 1:]
                for alias in node.names:
                    if home.get(alias.name) != target:
                        found["shim"].append(f"{alias.name} imported from {node.module}, defined in {home.get(alias.name)}")
    if runtime and not found["cycles"]:
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        if shim is not None:
            # the way a consumer loads it: the shim's own sys.path setup imports the package
            probe = ("import importlib.util, sys\n"
                     f"spec = importlib.util.spec_from_file_location('shim_probe', {str(shim)!r})\n"
                     "mod = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(mod)\n")
            what = f"the shim {shim.name}"
        else:
            probe = f"import sys\nsys.path.insert(0, {str(pkg.parent)!r})\nimport {top}\n"
            what = f"import {top}"
        proc = subprocess.run([sys.executable, "-c", probe], cwd="/", env=env, capture_output=True, text=True,
                              check=False)
        if proc.returncode != 0:
            found["cycles"].append(f"{what} failed to load from cwd=/: "
                                   f"{(proc.stderr.strip().splitlines() or ['?'])[-1]}")
    return found, accepted


def report(old_label: str, pkg: pathlib.Path, found: dict[str, list[str]], accepted: list[str],
           n_old: int) -> int:
    print(f"py-move-check: old={old_label} pkg={pkg} names={n_old}")
    for kind in KINDS:
        print(f"{kind} {len(found[kind])}")
        for line in found[kind]:
            print(f"  {line}")
    print(f"accepted {sum(1 for a in accepted if not a.startswith(' '))}")
    for line in accepted:
        print(f"  {line}")
    bad = sum(len(v) for v in found.values())
    print("py-move-check: ok" if not bad else f"py-move-check: {bad} finding(s)")
    return 1 if bad else 0


# ---------------------------------------------------------------------------------------------
# self-test: one old module, its correct split, and one mutation per finding kind.

_OLD = '''"""Old module."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
PAT = re.compile(r"x+")
LIMIT = 3
CACHE: dict | None = None


def _die(msg):
    raise SystemExit(msg)


def helper(text):
    return PAT.findall(text)


def check_a(text):
    for i, _m in enumerate(helper(text)):
        if i > LIMIT:
            _die("too many")
    return ROOT


class Box:
    size = LIMIT

    def grow(self):
        return helper("xx") and self.size


def main(PAT=None):
    check_a("xxx")
'''

_PKG = {
    "common.py": '''"""Shared."""

from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _die(msg):
    raise SystemExit(msg)
''',
    "rules.py": '''"""Rules."""

from __future__ import annotations

import re

from .common import ROOT, _die

PAT = re.compile(r"x+")
LIMIT = 3
CACHE: dict | None = None


def helper(text):
    return PAT.findall(text)


def check_a(text):
    for i, _m in enumerate(helper(text)):
        if i > LIMIT:
            _die("too many")
    return ROOT


class Box:
    size = LIMIT

    def grow(self):
        return helper("xx") and self.size
''',
    "__init__.py": '''"""Entry."""

from __future__ import annotations

from .rules import check_a


def main(PAT=None):
    check_a("xxx")
''',
}
_SHIM = '''"""Old module."""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from pkgx import main
from pkgx.rules import LIMIT
'''
_ACCEPT = {"ROOT": "one directory deeper"}


def _fixture(root: pathlib.Path, edits: dict[str, tuple[str, str]] | None = None, shim: str = _SHIM) -> pathlib.Path:
    pkg = root / "pkgx"
    pkg.mkdir(parents=True)
    for name, text in _PKG.items():
        for target, (old, new) in (edits or {}).items():
            if target == name:
                assert text.count(old) == 1, (name, old)
                text = text.replace(old, new, 1)
        (pkg / name).write_text(text, encoding="utf-8")
    (root / "shim.py").write_text(shim, encoding="utf-8")
    return pkg


def _self_test() -> int:
    """The correct split is clean; each mutation raises exactly its finding kind."""
    cases = [
        ("clean", {}, _SHIM, _ACCEPT, None),
        ("missing", {"rules.py": ("def helper(text):\n    return PAT.findall(text)\n", "")}, _SHIM, _ACCEPT, "missing"),
        ("extra def", {"rules.py": ("LIMIT = 3\n", "LIMIT = 3\nNEW = 1\n")}, _SHIM, _ACCEPT, "extra"),
        ("extra import", {"rules.py": ("import re\n", "import json\nimport re\n")}, _SHIM, _ACCEPT, "extra"),
        ("defined twice", {"rules.py": ("LIMIT = 3\n", "LIMIT = 3\n\n\ndef _die(msg):\n    raise SystemExit(msg)\n")},
         _SHIM, _ACCEPT, "defined-twice"),
        ("changed def", {"common.py": ("raise SystemExit(msg)", "raise SystemExit(str(msg))")}, _SHIM, _ACCEPT,
         "changed"),
        ("changed assignment", {"rules.py": ("LIMIT = 3\n", "LIMIT = 4\n")}, _SHIM, _ACCEPT, "changed"),
        ("unaccepted change", {}, _SHIM, {}, "changed"),
        ("unused accept", {}, _SHIM, {**_ACCEPT, "PAT": "nothing changed"}, "changed"),
        ("dropped import", {"rules.py": ("from .common import ROOT, _die\n", "from .common import ROOT\n")}, _SHIM,
         _ACCEPT, "unresolved"),
        ("wrong home", {"__init__.py": ("from .rules import check_a\n", "from .common import check_a\n")}, _SHIM,
         _ACCEPT, "unresolved"),
        ("stdlib not imported", {"rules.py": ("import re\n\n", "")}, _SHIM, _ACCEPT, "unresolved"),
        ("future lost", {"rules.py": ("from __future__ import annotations\n", "")}, _SHIM, _ACCEPT, "future"),
        ("stray statement", {"rules.py": ("LIMIT = 3\n", "LIMIT = 3\nprint(LIMIT)\n")}, _SHIM, _ACCEPT, "stray"),
        ("shim wrong module", {}, _SHIM.replace("from pkgx.rules import LIMIT", "from pkgx.common import LIMIT"),
         _ACCEPT, "shim"),
        ("cycle", {"common.py": ("import pathlib\n", "import pathlib\n\nfrom .rules import LIMIT\n")}, _SHIM, _ACCEPT,
         "cycles"),
        ("shim cannot load", {}, _SHIM.replace("from pkgx import main", "sys.path.clear()\nfrom pkgx import main"),
         _ACCEPT, "cycles"),
    ]
    n = 0
    with tempfile.TemporaryDirectory() as tmp:
        for i, (label, edits, shim, accept, want) in enumerate(cases):
            root = pathlib.Path(tmp) / f"c{i}"
            pkg = _fixture(root, edits, shim)
            found, accepted = check("old.py", _OLD, pkg, root / "shim.py", accept)
            hits = {k for k, v in found.items() if v}
            if want is None:
                if hits or [a for a in accepted if not a.startswith("    ")] != ["ROOT: one directory deeper"] \
                        or not any("parents[1]" in a for a in accepted) or not any("parents[2]" in a for a in accepted):
                    raise SystemExit(f"self-test {label}: expected clean with ROOT accepted, got {found} {accepted}")
            elif want not in hits:
                raise SystemExit(f"self-test {label}: expected a {want} finding, got {found}")
            if want == "unresolved" and label == "dropped import" and not any("_die" in x for x in found["unresolved"]):
                raise SystemExit(f"self-test {label}: the unresolved finding must name _die: {found['unresolved']}")
            n += 1
        # a local that shadows a global is not a read: main(PAT=None) in __init__ needs no PAT import
        if any("PAT" in x for x in check("old.py", _OLD, _fixture(pathlib.Path(tmp) / "shadow"), None, _ACCEPT)[0]["unresolved"]):
            raise SystemExit("self-test shadow: a parameter that shadows a global must not need an import")
        n += 1
    return n


def parse_args(argv: list[str]) -> dict:
    args: dict = {"accept": {}}
    it = iter(argv)
    for a in it:
        if a in ("--old", "--old-rev", "--old-path", "--git-dir", "--pkg", "--shim"):
            val = next(it, None)
            if val is None:
                raise SystemExit(2)
            args[a[2:].replace("-", "_")] = val
        elif a == "--accept":
            val = next(it, None)
            if val is None or "=" not in val:
                print("py-move-check: --accept takes NAME=REASON", file=sys.stderr)
                raise SystemExit(2)
            name, reason = val.split("=", 1)
            args["accept"][name.strip()] = reason.strip()
        else:
            print(__doc__, file=sys.stderr)
            raise SystemExit(2)
    if not args.get("pkg") or not (args.get("old") or args.get("old_rev")):
        print(__doc__, file=sys.stderr)
        raise SystemExit(2)
    return args


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        n = _self_test()
        print(f"py-move-check: self-test ok ({n} cases)")
        return 0
    args = parse_args(argv)
    with contextlib.redirect_stdout(sys.stderr):
        _self_test()
    label, src = read_old(args)
    pkg = pathlib.Path(args["pkg"]).resolve()
    shim = pathlib.Path(args["shim"]).resolve() if args.get("shim") else None
    found, accepted = check(label, src, pkg, shim, args["accept"])
    return report(label, pkg, found, accepted, len(top_names(ast.parse(src))))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
