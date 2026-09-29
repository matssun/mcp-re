"""Rust module-path resolution for the remediation dependency graph.

`targets(path)` is the set of tracked `.rs` files whose items the production part
of `path` names: every `crate::` / `super::` / `self::` / `<workspace crate>::`
path, `use` trees expanded, each resolved to the longest prefix that is a module
file, then through that module's `pub use` re-exports to the defining file.

An instrument with a stated reach: text, not name resolution. It cannot see a
glob import's individual names, a macro-generated path, or a trait method reached
through a value; a missed edge makes `related` smaller, never wrong.
"""
from __future__ import annotations

import os
import re
import subprocess

_TEST_REGION = re.compile(r"^#\[cfg\((?:all\()?test", re.M)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_USE = re.compile(r"\b(pub(?:\([^)]*\))?\s+)?use\s+([^;]+);")
_MAX_HOPS = 4


def production_text(src: str) -> str:
    m = _TEST_REGION.search(src)
    body = src[:m.start()] if m else src
    return _STRING.sub('""', _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", body)))


def expand_use_tree(tree: str) -> list[list[str]]:
    """`a::{b, c::{d, e}}` -> [[a,b], [a,c,d], [a,c,e]]; `self` and `*` stop a path."""
    tree = re.sub(r"\s+", "", re.sub(r"\s+as\s+\w+", "", tree))
    out: list[list[str]] = []

    def split_top(s: str) -> list[str]:
        parts, depth, cur = [], 0, ""
        for ch in s:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            if ch == "," and depth == 0:
                parts.append(cur)
                cur = ""
            else:
                cur += ch
        if cur:
            parts.append(cur)
        return parts

    def walk(prefix: list[str], s: str) -> None:
        brace = s.find("{")
        if brace == -1:
            path = prefix + [x for x in s.split("::") if x and x not in ("self", "*")]
            if path:
                out.append(path)
            return
        head = [x for x in s[:brace].split("::") if x]
        for part in split_top(s[brace + 1:s.rfind("}")]):
            walk(prefix + head, part)

    walk([], tree)
    return out


class RustResolver:
    def __init__(self, root: str) -> None:
        self.root = root
        self.crates: dict[str, str] = {}      # crate ident -> crate dir (repo-relative)
        p = subprocess.run(["git", "ls-files", "*Cargo.toml"], cwd=root,
                           capture_output=True, text=True)
        for manifest in p.stdout.split():
            text = open(os.path.join(root, manifest), encoding="utf-8").read()
            m = re.search(r'^\[package\][^\[]*?^name\s*=\s*"([^"]+)"', text, re.M | re.S)
            d = os.path.dirname(manifest)
            if m and os.path.isfile(os.path.join(root, d, "src", "lib.rs")):
                self.crates[m.group(1).replace("-", "_")] = d
        self._reexports: dict[str, dict[str, list[str]]] = {}

    def crate_of(self, path: str) -> str | None:
        best = None
        for ident, d in self.crates.items():
            if path.startswith(d + "/src/") and (best is None or len(d) > len(self.crates[best])):
                best = ident
        return best

    def module_path(self, path: str) -> list[str]:
        ident = self.crate_of(path)
        rel = path[len(self.crates[ident]) + len("/src/"):] if ident else path
        parts = rel[:-3].split("/")
        if parts[-1] in ("lib", "main", "mod"):
            parts = parts[:-1]
        return parts

    def module_file(self, crate: str, mod: list[str]) -> str | None:
        base = os.path.join(self.crates[crate], "src", *mod)
        cands = [os.path.join(self.crates[crate], "src", "lib.rs")] if not mod else \
            [base + ".rs", os.path.join(base, "mod.rs")]
        for c in cands:
            if os.path.isfile(os.path.join(self.root, c)):
                return c
        return None

    def _absolute(self, path: str, segs: list[str]) -> tuple[str, list[str]] | None:
        """(crate, absolute segments) for a path written inside `path`."""
        own = self.crate_of(path)
        if not segs:
            return None
        if segs[0] == "crate" and own:
            return own, segs[1:]
        if segs[0] in ("super", "self") and own:
            mod = self.module_path(path)
            i = 0
            while i < len(segs) and segs[i] in ("super", "self"):
                if segs[i] == "super":
                    mod = mod[:-1]
                i += 1
            return own, mod + segs[i:]
        if segs[0] in self.crates:
            return segs[0], segs[1:]
        if own:
            # A 2018-edition path may start at a child module of the current one.
            mod = self.module_path(path)
            if self.module_file(own, mod + [segs[0]]):
                return own, mod + segs
        return None

    def _module_reexports(self, file: str) -> dict[str, list[str]]:
        """item name -> the path its `pub use` points at, for one module file."""
        if file not in self._reexports:
            table: dict[str, list[str]] = {}
            src = production_text(open(os.path.join(self.root, file), encoding="utf-8",
                                       errors="ignore").read())
            for m in _USE.finditer(src):
                if not m.group(1):
                    continue
                for segs in expand_use_tree(m.group(2)):
                    table[segs[-1]] = segs
            self._reexports[file] = table
        return self._reexports[file]

    def resolve(self, path: str, segs: list[str]) -> str | None:
        ab = self._absolute(path, segs)
        if ab is None:
            return None
        crate, rest = ab
        file = None
        for _ in range(_MAX_HOPS):
            file, used = None, 0
            for n in range(len(rest), -1, -1):
                f = self.module_file(crate, rest[:n])
                if f:
                    file, used = f, n
                    break
            if file is None:
                return None
            item = rest[used] if used < len(rest) else None
            hop = self._module_reexports(file).get(item) if item else None
            if not hop:
                return file
            nxt = self._absolute(file, hop)
            if nxt is None or nxt == (crate, rest):
                return file
            crate, rest = nxt
        return file

    def targets(self, path: str) -> set[str]:
        if not path.endswith(".rs") or self.crate_of(path) is None \
                or not os.path.isfile(os.path.join(self.root, path)):
            return set()
        src = production_text(open(os.path.join(self.root, path), encoding="utf-8",
                                   errors="ignore").read())
        paths: list[list[str]] = []
        for m in _USE.finditer(src):
            paths += expand_use_tree(m.group(2))
        heads = "|".join(["crate", "super", "self"] + [re.escape(c) for c in self.crates])
        for m in re.finditer(r"\b(?:%s)(?:::\w+)+" % heads, _USE.sub("", src)):
            paths.append(m.group(0).split("::"))
        out = set()
        for segs in paths:
            f = self.resolve(path, segs)
            if f and f != path:
                out.add(f)
        return out
