#!/usr/bin/env python3
"""deps_graph.py — the import graph the remediation loop orders and scopes by.

Emits {"deps": {file: [in-scope files it imports]},
       "rdeps": {file: [in-scope files that import it]},
       "importers": {file: n},            # importers ANYWHERE in the monorepo
       "dependency_facing": [file, ...]}  # files whose change needs the wide gate

`deps` gives next_file.py leaf-first order; `rdeps` gives the `related` set to
re-scan after a fix. `importers` and `dependency_facing` decide WHICH gate a file's
fix has to pass: CLAUDE.md rule 15 — a changed dependency-facing declaration needs
a whole-repo pyright and a dependent-tree bazel run, not the owning app's suite.

Instrument: Python — AST imports, barrel (`from pkg import X`) resolved through the
package re-export map to the defining module; it cannot see a string-keyed factory,
an entry point or getattr. Rust — `rust_resolver.RustResolver`, module paths
resolved through `pub use` re-exports; its reach is stated there. Stdlib only;
analysis tooling, not production code.

Usage:
  deps_graph.py --scope <files.json|-> [--root .] --json out.json
    scope: a JSON list of repo-relative paths, or a JSON object whose values are
    lists of paths (the audit's units manifests both work), or "-" for stdin.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resolver import Resolver  # noqa: E402
from rust_resolver import RustResolver  # noqa: E402
from collections import defaultdict

BARREL = "__init" + "__.py"


def load_scope(spec: str) -> list[str]:
    raw = sys.stdin.read() if spec == "-" else open(spec, encoding="utf-8").read()
    doc = json.loads(raw)
    if isinstance(doc, list):
        return sorted({str(p) for p in doc})
    out: set[str] = set()

    def walk(node):
        if isinstance(node, str):
            out.add(node)
        elif isinstance(node, list):
            for x in node:
                walk(x)
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)

    walk(doc)
    return sorted(p for p in out if p.endswith((".py", ".rs")))




def production_files(root: str):
    """Tracked Python and Rust sources outside test trees — every possible importer."""
    p = subprocess.run(["git", "ls-files", "*.py", "*.rs"], cwd=root,
                       capture_output=True, text=True)
    for f in p.stdout.split():
        if "/tests/" in f or "/test/" in f or f.startswith(("tests/", "test/")):
            continue
        base = os.path.basename(f)
        if base.startswith("test_") or base == "build.rs" or "/benches/" in f or "/examples/" in f:
            continue
        yield f


class _Graph:
    """One `targets(path)` over both languages."""

    def __init__(self, root: str) -> None:
        self.root = root
        self.rs = RustResolver(root)
        self._py: Resolver | None = None

    def targets(self, path: str):
        if path.endswith(".rs"):
            return self.rs.targets(path)
        if self._py is None:
            self._py = Resolver(self.root)
        return self._py.targets(path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--root", default=".")
    ap.add_argument("--json", required=True)
    a = ap.parse_args()
    root = os.path.abspath(a.root)
    scope = [p for p in load_scope(a.scope)]
    scopeset = set(scope)
    r = _Graph(root)

    deps = {f: sorted(t for t in r.targets(f) if t in scopeset and t != f) for f in scope}
    rdeps: dict[str, list[str]] = defaultdict(list)
    for f, ds in deps.items():
        for d in ds:
            rdeps[d].append(f)

    # Importers ANYWHERE — the blast radius that decides the gate.
    importers: dict[str, int] = {f: 0 for f in scope}
    ext: dict[str, set[str]] = defaultdict(set)
    for p in production_files(root):
        for t in r.targets(p):
            if t in scopeset and t != p:
                ext[t].add(p)
    for f in scope:
        importers[f] = len(ext.get(f, ()))

    dep_facing = sorted(f for f in scope if importers[f] > 0)
    json.dump({"root": os.path.relpath(root, root), "scope_files": len(scope),
               "deps": deps, "rdeps": {k: sorted(v) for k, v in rdeps.items()},
               "importers": importers, "dependency_facing": dep_facing},
              open(a.json, "w"), indent=1)
    print(json.dumps({"scope_files": len(scope),
                      "files_with_deps": sum(1 for v in deps.values() if v),
                      "files_with_rdeps": len(rdeps),
                      "dependency_facing": len(dep_facing),
                      "max_importers": max(importers.values()) if importers else 0}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
