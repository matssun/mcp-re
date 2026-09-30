# SPDX-License-Identifier: Apache-2.0
"""Crate-spec parity gate — Bazel's declared crates and the Cargo workspace agree.

Bazel resolves external crates from the `crate.spec` entries in MODULE.bazel against
`bazel/crates.lock`; it reads no Cargo file, and nothing executes Cargo. The Cargo manifests
and locks remain as the crates' published description, so the same dependency is declared
in two places, and nothing but this gate keeps them from drifting:

  * a Dependabot bump lands in `Cargo.lock` only, so without this the Bazel-built
    artifacts (the proxy image among them) would silently keep the old version;
  * a feature added to a member's Cargo.toml would reach cargo builds and not Bazel.

Two checks:

  * SPECS — every external dependency a workspace member requests appears as a
    `crate.spec` with the same version requirement, the same feature union and the same
    default-features choice, and there is no spec the workspace does not request.
    Optional dependencies are not compared: no member feature enables one in the hub
    (today only the Verus crates, which the Verus lane builds outside Bazel).
  * LOCKS — every package `bazel/crates.lock` resolves is in `Cargo.lock` at the same
    version and checksum. (The Bazel lock is a subset: it holds only what the specs reach.)

The manifests are READ, never evaluated by Cargo: each member's dependency tables (normal,
dev, build, target-specific), resolved through `workspace = true` inheritance and
`package =` renames — what `cargo metadata` reported, without running it. The Cargo
workspaces covered are the root one and each separate workspace Bazel builds a crate from
(`EXTRA_WORKSPACES`).

Delete this gate together with the last Cargo manifest.

    python3 scripts/crate_spec_parity_gate.py             # the verdict
    python3 scripts/crate_spec_parity_gate.py --selftest  # prove the verdict can be FAIL
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MODULE = REPO / "MODULE.bazel"
BAZEL_LOCK = REPO / "bazel" / "crates.lock"
CARGO_LOCK = REPO / "Cargo.lock"
# The synthetic package crate_universe writes into the lock to hold the specs.
SPLICE_ROOT = "direct-cargo-bazel-deps"
FIX = ("declare the change in MODULE.bazel's crate.spec, then seed bazel/crates.lock with the "
       "Cargo locks' packages (the root lock and each EXTRA_WORKSPACES lock, merged) and "
       "re-pin:\n    CARGO_BAZEL_REPIN=1 bazel mod show_extension "
       "@rules_rust//crate_universe:extension.bzl%crate")

SPEC_BLOCK = re.compile(r"^crate\.spec\((.*?)^\)", re.M | re.S)


#: Separate Cargo workspaces whose crate Bazel builds, each with its own lock.
EXTRA_WORKSPACES = ("sdk/python", "sdk/typescript")

#: Specs no manifest requests, each with why the Bazel build needs it anyway. Their locked
#: packages are exempt from LOCKS for the same reason: no Cargo lock can hold them.
BAZEL_ONLY_SPECS: dict[str, str] = {
    "pyo3-introspection": "required by the rules_rust_pyo3 toolchain (//bazel/pyo3); no Rust "
                          "source names it, so no manifest requests it",
}

_DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def _dep_entries(manifest: dict):
    """(key, spec) for every dependency a manifest declares, in every table Cargo reads."""
    tables = [manifest.get(t, {}) for t in _DEP_TABLES]
    for target in (manifest.get("target") or {}).values():
        tables += [target.get(t, {}) for t in _DEP_TABLES]
    for table in tables:
        yield from table.items()


def _dependency(key: str, spec, workspace_deps: dict) -> dict:
    """One dependency the way `cargo metadata` reports it: name, req, features, defaults."""
    spec = {"version": spec} if isinstance(spec, str) else dict(spec)
    if spec.get("workspace") is True:
        inherited = workspace_deps.get(key, {})
        inherited = {"version": inherited} if isinstance(inherited, str) else dict(inherited)
        features = list(inherited.get("features", [])) + list(spec.get("features", []))
        spec = {**inherited, **{k: v for k, v in spec.items() if k != "workspace"},
                "features": features}
    default = spec.get("default-features", spec.get("default_features", True))
    return {"name": spec.get("package", key), "req": str(spec.get("version", "*")),
            "features": list(spec.get("features", [])), "uses_default_features": default,
            "optional": bool(spec.get("optional", False)), "path": spec.get("path")}


def workspace_meta(root: Path) -> dict:
    """What `cargo metadata --no-deps` reported for the covered workspaces, read from the
    manifests themselves."""
    packages = []
    for ws in ("",) + EXTRA_WORKSPACES:
        top = tomllib.loads((root / ws / "Cargo.toml").read_text())
        workspace = top.get("workspace", {})
        workspace_deps = workspace.get("dependencies", {})
        members = [root / ws / m for m in workspace.get("members", [])] or [root / ws]
        for member in members:
            manifest = tomllib.loads((member / "Cargo.toml").read_text())
            packages.append({"dependencies": [
                _dependency(key, spec, workspace_deps) for key, spec in _dep_entries(manifest)
            ]})
    return {"packages": packages}


def cargo_locks(root: Path) -> str:
    """Every covered workspace's lock, as one lock text (its packages concatenated)."""
    texts = [(root / ws / "Cargo.lock").read_text() for ws in ("",) + EXTRA_WORKSPACES]
    bodies = [re.sub(r"^version = \d+\s*$", "", t, flags=re.M) for t in texts]
    return "version = 4\n" + "\n".join(bodies)


def requested(meta: dict) -> dict[str, tuple[str, frozenset[str], bool]]:
    """What the workspace asks for, unified the way Cargo unifies one crate's requests."""
    out: dict[str, tuple[set[str], set[str], bool]] = {}
    for pkg in meta["packages"]:
        for dep in pkg["dependencies"]:
            if dep.get("path") or dep["optional"]:
                continue
            reqs, feats, default = out.get(dep["name"], (set(), set(), False))
            reqs.add(dep["req"].lstrip("^"))
            feats.update(dep["features"])
            out[dep["name"]] = (reqs, feats, default or dep["uses_default_features"])
    return {name: ("|".join(sorted(r)), frozenset(f), d) for name, (r, f, d) in out.items()}


def declared(module_text: str) -> dict[str, tuple[str, frozenset[str], bool]]:
    out = {}
    for body in SPEC_BLOCK.findall(module_text):
        name = re.search(r'package = "([^"]+)"', body).group(1)
        version = re.search(r'version = "([^"]+)"', body).group(1)
        feats = re.search(r"features = \[([^\]]*)\]", body)
        features = frozenset(re.findall(r'"([^"]+)"', feats.group(1))) if feats else frozenset()
        out[name] = (version, features, "default_features = False" not in body)
    return out


def locked(lock_text: str) -> dict[tuple[str, str], str | None]:
    return {(p["name"], p["version"]): p.get("checksum")
            for p in tomllib.loads(lock_text).get("package", [])}


def bazel_only_packages(bazel_lock: str) -> set[str]:
    """The locked packages reachable ONLY through a Bazel-only spec — no Cargo lock can
    hold them, because no manifest requests the spec that pulls them in."""
    packages = tomllib.loads(bazel_lock).get("package", [])
    edges = {p["name"]: [d.split(" ")[0] for d in p.get("dependencies", [])] for p in packages}

    def reach(roots) -> set[str]:
        seen, stack = set(), list(roots)
        while stack:
            name = stack.pop()
            if name not in seen:
                seen.add(name)
                stack.extend(edges.get(name, []))
        return seen

    direct = edges.get(SPLICE_ROOT, [])
    return reach(set(direct) & set(BAZEL_ONLY_SPECS)) - reach(set(direct) - set(BAZEL_ONLY_SPECS))


def compare(meta: dict, module_text: str, bazel_lock: str, cargo_lock: str) -> tuple[list[str], int, int]:
    problems = []
    want, have = requested(meta), declared(module_text)
    for name in sorted(set(want) - set(have)):
        problems.append(f"SPECS: the workspace requests `{name}` and MODULE.bazel declares no spec for it")
    for name in sorted(set(have) - set(want) - set(BAZEL_ONLY_SPECS)):
        problems.append(f"SPECS: MODULE.bazel declares `{name}` and no workspace member requests it")
    for name in sorted(set(want) & set(have)):
        (wv, wf, wd), (hv, hf, hd) = want[name], have[name]
        if wv != hv:
            problems.append(f"SPECS: `{name}` version: workspace {wv}, spec {hv}")
        if wf != hf:
            problems.append(f"SPECS: `{name}` features: workspace only {sorted(wf - hf)}, "
                            f"spec only {sorted(hf - wf)}")
        if wd != hd:
            problems.append(f"SPECS: `{name}` default features: workspace {wd}, spec {hd}")

    in_bazel, in_cargo = locked(bazel_lock), locked(cargo_lock)
    exempt = bazel_only_packages(bazel_lock)
    compared = 0
    for (name, version), checksum in sorted(in_bazel.items()):
        if name == SPLICE_ROOT or name in exempt:
            continue
        compared += 1
        if (name, version) not in in_cargo:
            others = sorted(v for n, v in in_cargo if n == name)
            problems.append(f"LOCKS: bazel/crates.lock has {name} {version}; Cargo.lock has {others or 'none'}")
        elif in_cargo[(name, version)] != checksum:
            problems.append(f"LOCKS: {name} {version} has a different checksum in the two locks")
    if not have:
        problems.append("SPECS: no crate.spec was read from MODULE.bazel — comparing nothing is not a pass")
    if not compared:
        problems.append("LOCKS: no package was read from bazel/crates.lock — comparing nothing is not a pass")
    return problems, len(have), compared


def verdict() -> int:
    problems, specs, packages = compare(workspace_meta(REPO), MODULE.read_text(),
                                        BAZEL_LOCK.read_text(), cargo_locks(REPO))
    if problems:
        print(f"crate-spec parity gate: FAIL — {len(problems)} problem(s)")
        for p in problems:
            print(f"  - {p}")
        print(f"To fix: {FIX}")
        return 1
    print(f"crate-spec parity gate: OK — {specs} crate spec(s) match the Cargo workspace; "
          f"{packages} package(s) in bazel/crates.lock match the Cargo locks by version and checksum; "
          f"Bazel-only: {', '.join(sorted(BAZEL_ONLY_SPECS))}")
    return 0


def selftest() -> int:
    """Every case asserted in BOTH directions: a gate that always fails passes the failing
    half of a probe, and a gate that never fires passes the passing half."""
    def dep(name, req, features=(), default=True, optional=False, path=None):
        return {"name": name, "req": req, "features": list(features),
                "uses_default_features": default, "optional": optional, "path": path}

    meta = {"packages": [
        {"dependencies": [dep("tokio", "^1", ["rt"], default=False), dep("serde", "^1.0"),
                          dep("vstd", "=0.0.1", optional=True), dep("local", "*", path="/x")]},
        {"dependencies": [dep("tokio", "^1", ["macros"], default=False)]},
    ]}
    serde = 'crate.spec(\n    package = "serde",\n    version = "1.0",\n    repositories = ["h"],\n)\n'
    tokio = ('crate.spec(\n    package = "tokio",\n    version = "1",\n    features = ["macros", "rt"],\n'
             '    default_features = False,\n    repositories = ["h"],\n)\n')
    module = serde + tokio
    lock = ('version = 4\n\n[[package]]\nname = "tokio"\nversion = "1.2.3"\nchecksum = "aa"\n\n'
            f'[[package]]\nname = "{SPLICE_ROOT}"\nversion = "0.0.1"\n')
    cargo_lock = lock.replace(f'name = "{SPLICE_ROOT}"', 'name = "mcp-re-core"')

    def edit(text: str, old: str, new: str) -> str:
        if old not in text:
            raise SystemExit(f"SELFTEST FAILED: fixture edit anchor {old!r} not found")
        return text.replace(old, new)

    cases = [
        ("the workspace and the specs agree", module, lock, None),
        ("a feature the workspace requests is missing",
         edit(module, '"macros", ', ""), lock, "workspace only ['macros']"),
        ("a version requirement differs",
         edit(module, 'version = "1",', 'version = "2",'), lock, "workspace 1, spec 2"),
        ("default features differ",
         edit(module, "    default_features = False,\n", ""), lock, "default features"),
        ("a spec no member requests", module + edit(serde, "serde", "hyper"), lock, "`hyper`"),
        ("a spec is missing", tokio, lock, "`serde` and MODULE.bazel declares no spec"),
        ("the Bazel lock resolves another version",
         module, edit(lock, "1.2.3", "1.2.4"), "tokio 1.2.4"),
        ("the same version with another checksum",
         module, edit(lock, '"aa"', '"bb"'), "different checksum"),
        ("nothing was read", "", lock, "comparing nothing"),
    ]
    for label, mod, blk, expect in cases:
        problems, _, _ = compare(meta, mod, blk, cargo_lock)
        text = "\n".join(problems)
        if expect is None and problems:
            print(f"SELFTEST FAILED: {label}: reported {problems}")
            return 1
        if expect is not None and expect not in text:
            print(f"SELFTEST FAILED: {label}: expected a problem naming {expect!r}, got {problems}")
            return 1
    print(f"crate-spec parity gate selftest: PASS ({len(cases)} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else verdict())
