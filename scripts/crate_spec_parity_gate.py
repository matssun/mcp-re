# SPDX-License-Identifier: Apache-2.0
"""Crate-spec parity gate — Bazel's declared crates and the Cargo workspace agree.

Bazel resolves external crates from the `crate.spec` entries in MODULE.bazel against
`bazel/crates.lock`; it reads no Cargo file. The Cargo lanes still build from the
Cargo manifests and `Cargo.lock`. Until those lanes are gone the same dependency is
declared in two places, and nothing but this gate keeps them from drifting:

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

Delete this gate together with the last Cargo manifest.

    python3 scripts/crate_spec_parity_gate.py             # the verdict
    python3 scripts/crate_spec_parity_gate.py --selftest  # prove the verdict can be FAIL
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MODULE = REPO / "MODULE.bazel"
BAZEL_LOCK = REPO / "bazel" / "crates.lock"
CARGO_LOCK = REPO / "Cargo.lock"
# The synthetic package crate_universe writes into the lock to hold the specs.
SPLICE_ROOT = "direct-cargo-bazel-deps"
FIX = ("declare the change in MODULE.bazel's crate.spec, then refresh the Bazel lock from "
       "Cargo's:\n    cp Cargo.lock bazel/crates.lock && CARGO_BAZEL_REPIN=1 bazel mod "
       "show_extension @rules_rust//crate_universe:extension.bzl%crate")

SPEC_BLOCK = re.compile(r"^crate\.spec\((.*?)^\)", re.M | re.S)


def cargo() -> list[str]:
    """The pinned toolchain — Homebrew's cargo shadows rustup here and ignores
    `rust-toolchain.toml`, so the channel is named explicitly."""
    channel = "1.97.1"
    tc = REPO / "rust-toolchain.toml"
    if tc.exists():
        for line in tc.read_text().splitlines():
            if line.strip().startswith("channel"):
                channel = line.split("=")[1].strip().strip('"')
                break
    if shutil.which("rustup"):
        return ["rustup", "run", channel, "cargo"]
    return ["cargo"]


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


def compare(meta: dict, module_text: str, bazel_lock: str, cargo_lock: str) -> tuple[list[str], int, int]:
    problems = []
    want, have = requested(meta), declared(module_text)
    for name in sorted(set(want) - set(have)):
        problems.append(f"SPECS: the workspace requests `{name}` and MODULE.bazel declares no spec for it")
    for name in sorted(set(have) - set(want)):
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
    compared = 0
    for (name, version), checksum in sorted(in_bazel.items()):
        if name == SPLICE_ROOT:
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
    run = subprocess.run(cargo() + ["metadata", "--no-deps", "--format-version", "1"],
                         cwd=REPO, capture_output=True, text=True)
    if run.returncode != 0:
        print(f"crate-spec parity gate: COULD NOT RUN — cargo metadata failed:\n{run.stderr}")
        return 1
    problems, specs, packages = compare(json.loads(run.stdout), MODULE.read_text(),
                                        BAZEL_LOCK.read_text(), CARGO_LOCK.read_text())
    if problems:
        print(f"crate-spec parity gate: FAIL — {len(problems)} problem(s)")
        for p in problems:
            print(f"  - {p}")
        print(f"To fix: {FIX}")
        return 1
    print(f"crate-spec parity gate: OK — {specs} crate spec(s) match the Cargo workspace; "
          f"{packages} package(s) in bazel/crates.lock match Cargo.lock by version and checksum")
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
