#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cargo test-target gate — a named `--test` lane must name a target that exists.

WHAT THIS PROVES, exactly: every literal `cargo test … --test <name>` in the CI
workflows and the repository scripts names a test target that `cargo metadata`
reports for the package it is scoped to. Non-literal names (`--test "$binary"`)
are skipped — there is nothing static to check.

WHAT IT DOES NOT PROVE: that the lane runs the tests its step name claims, that
a module filter beside it selects anything, or that the target is wired into
Bazel. `scripts/slo_invocation_gate.py` covers the filter-selects-zero case for
the SLO lane specifically.

WHY IT MATTERS. Renaming or merging a test binary breaks every table that names
it, and the tables are not in one place: the security traceability manifest, two
guard tables, `mcp-re-test-paths`, and — the one nothing catalogued — the named
release-gate steps in the workflows. Consolidating thirteen proxy test binaries
silently pointed four workflow lanes at names that no longer exist:

    Release gate — replay race          --test async_replay_test
    Release gate — inner-plane          --test http_inner_test
    redis + ocsp e2e                    --test redis_replay_e2e_test
    etcd replay e2e                     --test cpstore_etcd_e2e_test

`cargo test --test <missing>` exits 101 rather than passing, so those lanes went
red rather than green-on-nothing. That is the good failure mode, and it is still
worth catching locally: the four lanes are release gates, and between the merge
and the next CI run nothing in the local gate said the release gates had stopped
running at all.

Run:  python3 scripts/cargo_test_target_gate.py
      python3 scripts/cargo_test_target_gate.py --selftest
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

SCAN_GLOBS = (
    ".github/workflows/*.yml",
    "scripts/*.sh",
    "scripts/*.sh.example",
)

# `--test name` / `--test "name"`. A `$`-bearing name is a variable, not a claim.
TEST_FLAG = re.compile(r'--test[=\s]+"?([A-Za-z_][A-Za-z0-9_]*)"?')
PACKAGE_FLAG = re.compile(r'(?:-p|--package)[=\s]+"?([A-Za-z][A-Za-z0-9_-]*)"?')
# A libtest filter naming a module inside a merged binary: `module::` or
# `module::test_fn`. Only the module half is checkable statically.
MODULE_FILTER = re.compile(r"(?<![\w:])([a-z][a-z0-9_]*)::")
# A run of lines belonging to one command: YAML folds with `>-`/`|`, and shells
# continue with a trailing backslash, so the package and the flag can be lines
# apart. Blank lines and a new `- name:` end the run.
BLOCK_BREAK = re.compile(r"^\s*(?:-\s+name:|#|$)")


def cargo_test_targets(root: Path) -> dict[str, set[str]]:
    """Package name -> its test target names, from `cargo metadata`."""
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    targets: dict[str, set[str]] = {}
    for package in json.loads(out.stdout)["packages"]:
        targets[package["name"]] = {
            t["name"] for t in package["targets"] if "test" in t["kind"]
        }
    return targets


def invocations(text: str) -> list[tuple[int, str | None, str]]:
    """Every (line number, package or None, test target) a file names."""
    found: list[tuple[int, str | None, str]] = []
    package: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        if BLOCK_BREAK.match(line):
            package = None
        if line.lstrip().startswith("#"):
            continue  # prose and usage examples are not invocations
        match = PACKAGE_FLAG.search(line)
        if match:
            package = match.group(1)
        for name in TEST_FLAG.findall(line):
            found.append((number, package, name))
    return found


def declared_modules(root: Path, package: str, binary: str) -> set[str] | None:
    """The `mod` names in a multi-file test binary's `main.rs`, or None if the
    binary is a single `tests/<name>.rs` with no module structure to filter on."""
    main = root / package / "tests" / binary / "main.rs"
    if not main.is_file():
        return None
    return set(re.findall(r"^mod ([a-z0-9_]+);", main.read_text(encoding="utf-8"), re.M))


def blocks(text: str) -> list[tuple[int, str]]:
    """(first line number, text) for each run of lines forming one command."""
    out: list[tuple[int, str]] = []
    start, buffer = 0, []
    for number, line in enumerate(text.splitlines(), start=1):
        if BLOCK_BREAK.match(line):
            if buffer:
                out.append((start, "\n".join(buffer)))
                buffer = []
            continue
        if not buffer:
            start = number
        buffer.append(line)
    if buffer:
        out.append((start, "\n".join(buffer)))
    return out


def check_filters(root: Path, targets: dict[str, set[str]]) -> list[str]:
    """Every `module::` filter names a module its binary actually declares."""
    failures: list[str] = []
    for pattern in SCAN_GLOBS:
        for path in sorted(root.glob(pattern)):
            rel = path.relative_to(root)
            for number, block in blocks(path.read_text(encoding="utf-8")):
                body = "\n".join(
                    l for l in block.splitlines() if not l.lstrip().startswith("#")
                )
                package = PACKAGE_FLAG.search(body)
                binary = TEST_FLAG.search(body)
                if not (package and binary):
                    continue
                if package.group(1) not in targets:
                    continue
                modules = declared_modules(root, package.group(1), binary.group(1))
                if modules is None:
                    continue
                head, _, tail = body.partition(" -- ")
                if not tail:
                    continue
                for name in MODULE_FILTER.findall(tail):
                    if name not in modules:
                        failures.append(
                            f"{rel}:{number}: filter `{name}::` names no module in "
                            f"`{binary.group(1)}` — libtest would select ZERO tests "
                            "and exit 0"
                        )
    return failures


def manifest_battery_targets(root: Path) -> list[tuple[str, str]]:
    """Every (unit id, test binary) the verification manifest declares a battery in."""
    import tomllib

    manifest = root / "verification" / "policy" / "verification.toml"
    if not manifest.is_file():
        return []
    doc = tomllib.load(manifest.open("rb"))
    return [
        (unit["id"], str(symbol).partition("#")[0][len("tests/"):])
        for unit in doc.get("unit", [])
        for symbol in unit.get("tested_symbols", [])
        if str(symbol).partition("#")[0].startswith("tests/")
    ]


def check_manifest(root: Path, targets: dict[str, set[str]]) -> list[str]:
    """Every `tests/<name>#…` battery member in the verification manifest names a real
    target in its unit's crate.

    The sixth table naming test binaries, and the reason this gate keeps growing sources:
    `verification/policy/verification.toml` declares each review unit's test battery by
    target, so renaming a test binary breaks a unit's evidence the same way it breaks a
    release-gate step. The verification lane catches it too — `cargo test --test <missing>`
    exits 101 and the declared symbols never run — but only after a full build, and only
    on the runs that lane is triggered for.
    """
    import tomllib

    manifest = root / "verification" / "policy" / "verification.toml"
    if not manifest.is_file():
        return []
    doc = tomllib.load(manifest.open("rb"))
    failures: list[str] = []
    for unit in doc.get("unit", []):
        crates = {str(path).split("/", 1)[0] for path in unit.get("paths", [])}
        crate = crates.pop() if len(crates) == 1 else None
        for symbol in unit.get("tested_symbols", []):
            target, _, _path = str(symbol).partition("#")
            if not target.startswith("tests/"):
                continue
            binary = target[len("tests/"):]
            known = targets.get(crate, set()) if crate in targets else {
                name for names in targets.values() for name in names
            }
            if binary not in known:
                where = f"in package '{crate}'" if crate in targets else "anywhere"
                failures.append(
                    f"verification/policy/verification.toml: unit '{unit['id']}' declares "
                    f"`{symbol}` but `{binary}` names no test target {where} — the unit's "
                    "declared battery cannot run, so its evidence would refuse"
                )
    return failures


def check(root: Path, targets: dict[str, set[str]]) -> list[str]:
    every = {name for names in targets.values() for name in names}
    failures: list[str] = []
    for pattern in SCAN_GLOBS:
        for path in sorted(root.glob(pattern)):
            rel = path.relative_to(root)
            for number, package, name in invocations(path.read_text(encoding="utf-8")):
                known = targets[package] if package in targets else every
                if name in known:
                    continue
                where = f"in package '{package}'" if package in targets else "anywhere"
                failures.append(
                    f"{rel}:{number}: `--test {name}` names no test target {where} — "
                    "the binary was renamed or merged; repoint the lane (and add a "
                    "module filter if it now shares a binary)"
                )
    return failures


def selftest() -> int:
    failed = False
    targets = {"pkg": {"real_test", "other_test"}}
    cases = [
        ("a named target that exists", "run: cargo test -p pkg --test real_test\n", ""),
        (
            "a named target that does not exist",
            "run: cargo test -p pkg --test ghost_test\n",
            "names no test target",
        ),
        (
            "a package and flag split across folded lines",
            "        run: >-\n          cargo test -p pkg\n          --test ghost_test\n",
            "names no test target",
        ),
        (
            "a variable name is not a static claim",
            'run: cargo test -p pkg --test "$binary"\n',
            "",
        ),
        (
            "an unknown package falls back to the union of all targets",
            "run: cargo test -p not-a-package --test real_test\n",
            "",
        ),
        (
            "a usage example in a comment is not an invocation",
            "# usage: run_test_lane.sh cargo test -p pkg --test bin -- module::\n",
            "",
        ),
        (
            "a new step resets the package scope",
            "        - name: one\n          run: cargo test -p pkg\n"
            "        - name: two\n          run: cargo test --test ghost_test\n",
            "names no test target",
        ),
    ]
    for label, content, expected in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text(content, encoding="utf-8")
            failures = check(root, targets)
            ok = not failures if not expected else any(expected in f for f in failures)
            print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
            if not ok:
                failed = True
                print(f"        got {failures}")

    manifest_cases = [
        (
            "a battery naming a target that exists",
            'paths = ["pkg/src/a.rs"]\ntested_symbols = ["tests/real_test#one"]\n',
            "",
        ),
        (
            "a battery naming a target that does not exist",
            'paths = ["pkg/src/a.rs"]\ntested_symbols = ["tests/ghost_test#one"]\n',
            "names no test target",
        ),
        (
            "a lib member names no binary and is not checked here",
            'paths = ["pkg/src/a.rs"]\ntested_symbols = ["lib#a::tests::one"]\n',
            "",
        ),
        (
            "a unit spanning two crates falls back to the union of all targets",
            'paths = ["pkg/src/a.rs", "other/src/b.rs"]\n'
            'tested_symbols = ["tests/other_test#one"]\n',
            "",
        ),
    ]
    for label, body, expected in manifest_cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "verification" / "policy"
            policy.mkdir(parents=True)
            (policy / "verification.toml").write_text(
                f'[[unit]]\nid = "u"\n{body}', encoding="utf-8"
            )
            failures = check_manifest(root, targets)
            ok = not failures if not expected else any(expected in f for f in failures)
            print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
            if not ok:
                failed = True
                print(f"        got {failures}")

    if failed:
        print("cargo test-target gate: SELFTEST FAILED")
        return 1
    print("cargo test-target gate: selftest passed")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    targets = cargo_test_targets(REPO)
    failures = (
        check(REPO, targets)
        + check_filters(REPO, targets)
        + check_manifest(REPO, targets)
    )
    if failures:
        print("cargo test-target gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    named = sum(
        len(invocations(p.read_text(encoding="utf-8")))
        for pattern in SCAN_GLOBS
        for p in REPO.glob(pattern)
    )
    # Both scopes are reported, because a summary naming only the lanes would read the
    # same whether the manifest was examined or silently absent.
    batteries = manifest_battery_targets(REPO)
    print(
        f"cargo test-target gate: OK — {named} named `--test` lanes and "
        f"{len(batteries)} manifest battery target(s) all exist"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
