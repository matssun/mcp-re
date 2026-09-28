"""Cargo gate for one Rust file's fix: compile-and-lint every lane that compiles it,
then run the tests that exercise it — never the whole workspace.

(Invoked as `python3 cargo_gate.py …`, or imported by `check.py`.)

The verdict rests on the lane invariant, not on a stored baseline: the writer lane
starts on a tree `batch_gate.py` measured green, and every writer leaves the tree
green or reverted. So a failure here is this change's.

  lint    `cargo clippy -p <crates> --all-targets -- -D warnings`, once per lane
          that compiles the file: default features, and the feature lane read from
          `scripts/local_gate.sh` (`FEATURES=`) when the owning crate declares any
          of those features. A module gated on a feature compiles to nothing in the
          default lane, and a lane that compiled nothing proves nothing.
  size    `scripts/module_size_gate.py` — seconds, whole tree.
  tests   `cargo test -p <crate> --lib -- <module path>::` (the file's own unit
          tests) plus every `--it` integration test the package named, in the lane
          that compiles the file.

Verdicts: `new-failures` (a lint, a compile error, a failed test or a grown
module), `infra` (cargo could not judge: no test ran, lock or toolchain failure),
`ok`.

Usage:
  cargo_gate.py --file F [--related a,b] [--it name,name] --work-dir DIR
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rust_resolver import RustResolver  # noqa: E402

LOCAL_GATE = "scripts/local_gate.sh"
RATCHET_GATE = "scripts/clippy_ratchet_gate.py"
SIZE_GATE = "scripts/module_size_gate.py"
_TEST_RESULT = re.compile(r"test result: (\w+)\. (\d+) passed; (\d+) failed")
_FAILED_TEST = re.compile(r"^---- (\S+) stdout ----$", re.M)
_COMPILE_ERROR = re.compile(r"^error(?:\[E\d+\])?: ", re.M)
_INLINE_TEST = re.compile(r"#\[(?:tokio::)?test\b")


@functools.lru_cache(maxsize=1)
def cargo() -> list[str]:
    """The repository's pinned-toolchain cargo, from the ratchet gate that owns it.
    A bare `cargo` on a machine where another install shadows rustup lints with a
    different clippy than CI does."""
    if not os.path.isfile(RATCHET_GATE):
        return ["cargo"]
    spec = importlib.util.spec_from_file_location("clippy_ratchet_gate", RATCHET_GATE)
    if spec is None or spec.loader is None:
        return ["cargo"]
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return list(mod.cargo()) if hasattr(mod, "cargo") else ["cargo"]


def feature_lane(root: str = ".") -> list[str]:
    """The non-default feature set the local gate builds, read from the gate itself."""
    try:
        text = open(os.path.join(root, LOCAL_GATE), encoding="utf-8").read()
    except OSError:
        return []
    m = re.search(r"^FEATURES=([\w,-]+)", text, re.M)
    return m.group(1).split(",") if m else []


def crate_features(crate_dir: str) -> set[str]:
    try:
        text = open(os.path.join(crate_dir, "Cargo.toml"), encoding="utf-8").read()
    except OSError:
        return set()
    m = re.search(r"^\[features\](.*?)(?=^\[|\Z)", text, re.M | re.S)
    return set(re.findall(r"^([\w-]+)\s*=", m.group(1), re.M)) if m else set()


def package_name(crate_dir: str) -> str | None:
    try:
        text = open(os.path.join(crate_dir, "Cargo.toml"), encoding="utf-8").read()
    except OSError:
        return None
    m = re.search(r'^\[package\][^\[]*?^name\s*=\s*"([^"]+)"', text, re.M | re.S)
    return m.group(1) if m else None


def _slug(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:10]


def _run(cmd: list[str], log: str) -> tuple[int, str]:
    with open(log, "w", encoding="utf-8") as fh:
        p = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT)
    return p.returncode, open(log, encoding="utf-8", errors="replace").read()


def _lint(packages: list[str], features: list[str], log: str) -> dict:
    cmd = cargo() + ["clippy", "--quiet", "--message-format=short"]
    for p in packages:
        cmd += ["-p", p]
    cmd += ["--all-targets"] + (["--features", ",".join(features)] if features else [])
    cmd += ["--", "-D", "warnings"]
    rc, out = _run(cmd, log)
    errors = [ln for ln in out.splitlines() if _COMPILE_ERROR.match(ln) or ": error" in ln][:15]
    if rc == 0:
        return {"verdict": "ok", "exit": rc, "log": log}
    if errors:
        return {"verdict": "new-failures", "exit": rc, "log": log, "errors_head": errors}
    return {"verdict": "infra", "exit": rc, "log": log,
            "why": "clippy failed without a diagnostic — toolchain, lock or registry"}


def _test(package: str, features: list[str], selector: list[str], filt: str, log: str) -> dict:
    cmd = cargo() + ["test", "-p", package] + selector
    cmd += (["--features", ",".join(features)] if features else [])
    cmd += ["--"] + ([filt] if filt else [])
    rc, out = _run(cmd, log)
    results = _TEST_RESULT.findall(out)
    ran = sum(int(p) + int(f) for _, p, f in results)
    failed = _FAILED_TEST.findall(out)
    if rc != 0 and (failed or any(int(f) for _, _, f in results) or _COMPILE_ERROR.search(out)):
        return {"verdict": "new-failures", "exit": rc, "log": log, "failed": failed[:15],
                "compile_error": bool(_COMPILE_ERROR.search(out)) and not results}
    if rc != 0:
        return {"verdict": "infra", "exit": rc, "log": log, "why": "cargo test failed before any test ran"}
    if ran == 0:
        return {"verdict": "infra", "exit": rc, "log": log,
                "why": "0 tests ran — this selection measured nothing"}
    return {"verdict": "ok", "exit": rc, "log": log, "ran": ran}


def gate(file: str, related: list[str], its: list[str], work_dir: str,
         resolver: RustResolver | None = None) -> list[dict]:
    r = resolver or RustResolver(".")
    own = r.crate_of(file)
    if own is None:
        return [{"gate": "cargo", "verdict": "infra", "why": "%s is in no workspace crate" % file}]
    crate_dir = r.crates[own]
    package = package_name(crate_dir) or own
    packages = [package]
    for f in related:
        c = r.crate_of(f)
        dep = package_name(r.crates[c]) if c and c != own else None
        if dep and dep not in packages:
            packages.append(dep)

    lane = [f for f in feature_lane() if f in crate_features(crate_dir)]
    lanes = [[]] + ([lane] if lane else [])
    tag = _slug(file)
    parts: list[dict] = []
    for feats in lanes:
        name = "features" if feats else "default"
        parts.append(dict(_lint(packages, feats, os.path.join(work_dir, "clippy-%s-%s.log" % (name, tag))),
                          gate="clippy", lane=name, packages=packages))

    rc, out = _run([sys.executable, SIZE_GATE], os.path.join(work_dir, "size-%s.log" % tag))
    parts.append({"gate": "module-size", "verdict": "ok" if rc == 0 else "new-failures",
                  "exit": rc, **({} if rc == 0 else {"head": out.strip().splitlines()[-5:]})})

    if any(p["verdict"] == "new-failures" for p in parts):
        return parts          # a tree that does not compile has no test result to add
    test_feats = lane
    mod = "::".join(r.module_path(file))
    parts.append(dict(_test(package, test_feats, ["--lib"], mod + "::" if mod else "",
                            os.path.join(work_dir, "test-lib-%s.log" % tag)),
                      gate="test", target="lib", filter=mod))
    if parts[-1]["verdict"] == "infra" and "0 tests ran" in parts[-1].get("why", "") \
            and not _INLINE_TEST.search(open(file, encoding="utf-8", errors="replace").read()):
        parts[-1]["verdict"] = "ok"
        parts[-1]["note"] = "the file has no unit tests of its own"
    for it in its:
        parts.append(dict(_test(package, test_feats, ["--test", it], "",
                                os.path.join(work_dir, "test-it-%s-%s.log" % (it, tag))),
                          gate="test", target=it))
    return parts


def main() -> int:
    ap = argparse.ArgumentParser(description="cargo gate for one Rust file's fix")
    ap.add_argument("--file", required=True)
    ap.add_argument("--related", default="")
    ap.add_argument("--it", default="", help="integration test targets to run, comma-separated")
    ap.add_argument("--work-dir", required=True)
    a = ap.parse_args()
    os.makedirs(a.work_dir, exist_ok=True)
    ids = lambda s: [x.strip() for x in s.split(",") if x.strip()]  # noqa: E731
    print(json.dumps(gate(a.file, ids(a.related), ids(a.it), a.work_dir), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
