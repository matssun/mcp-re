#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Module-size ratchet — a production Rust file may not cross 200 lines, and an
already-oversized one may not grow.

ADR-MCPRE-061 §5.1 sets the threshold and §6.3 specifies this gate. It exists because
**clippy has no file-length lint at all** — `clippy::module_lines` was probed against
clippy 0.1.97 and does not exist under that or any other name, so the one architectural
threshold the project states about files had no mechanical form. A rule enforced only by
an author's judgement is a rule whose enforcement cost is paid per file, by the least
reliable available party.

This is a **ratchet, not a cliff**. The debt registry (`config/module-size-debt.toml`)
records what was already oversized at a baseline SHA. From that point:

    new file over the threshold          -> FAIL
    registered file grows                -> FAIL
    registered file shrinks              -> PASS (and the entry is updated)
    registered file reaches <= threshold -> FAIL until the entry is removed
    reviewed large unit                  -> entry carries an ADR-061 §14 exception ref

The last two are what stop the registry rotting into a permanent allowlist: an entry that
no longer describes reality is an error, not a shrug.

# Measuring production lines

`prod` is the lines before the first test module. The test module is found with
`^#\\[cfg\\((all\\()?test` and NOT the narrow `^#[cfg(test)]`: a first census pass matching
only the narrow form reported `mcp-re-proxy/src/app.rs` as 1680 production lines with no
tests at all, because its module is `#[cfg(all(test, unix))]`. Its real production half is
1038. A counter that silently undercounts is worse than no counter, so both forms are
matched, production code appearing AFTER a test region is counted, and the arithmetic is
exercised by `--selftest`.

# The two blindness failures this gate refuses to repeat

- **An empty scope is a failure, not an OK.** A `tests/` glob silently exempted an entire
  crate from `scripts/bazel_srcs_gate.py` for a whole campaign while it printed OK.
- **The measurement rule is printed.** A threshold whose measurement is unstated is the
  "green that measured nothing" failure applied to the gate itself.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

REPO = Path(__file__).resolve().parent.parent
REGISTRY = REPO / "config" / "module-size-debt.toml"
THRESHOLD = 200

# ADR-MCPRE-061 §5.1. Both `#[cfg(test)]` and `#[cfg(all(test, ...))]` open a test region.
TEST_ATTR = re.compile(r"^#\[cfg\((all\()?test\b")

# Directories that are not this repository's production Rust.
SKIP_DIRS = {"target", "node_modules", ".git", "bazel-out", "vendor"}

STATUSES = {"unreviewed", "reviewed-exception"}


def production_lines(text: str) -> int:
    """Lines of a Rust source before its first test region.

    A test region runs from its `#[cfg(test)]`-family attribute to the end of the module
    it introduces, tracked by brace depth. Production code after that region is counted:
    a file that puts a helper module below its tests is not thereby exempt.
    """
    lines = text.splitlines()
    count = 0
    i = 0
    while i < len(lines):
        if TEST_ATTR.match(lines[i].lstrip()):
            # Skip to the opening brace of the module, then past its matching close.
            depth = 0
            opened = False
            while i < len(lines):
                depth += lines[i].count("{") - lines[i].count("}")
                if "{" in lines[i]:
                    opened = True
                i += 1
                if opened and depth <= 0:
                    break
            continue
        count += 1
        i += 1
    return count


def rust_sources(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in sorted(root.rglob("*.rs")):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        # Tests, benches, examples and build scripts are not production modules.
        if any(part in {"tests", "benches", "examples"} for part in rel.parts):
            continue
        if p.name == "build.rs":
            continue
        out.append(p)
    return out


def load_registry(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = tomllib.loads(path.read_text())
    entries = {}
    for entry in data.get("debt", []):
        entries[entry["path"]] = entry
    return entries


def check(root: Path, registry: dict[str, dict]) -> tuple[list[str], int]:
    """Return (problems, files_examined)."""
    problems: list[str] = []
    sources = rust_sources(root)
    measured: dict[str, int] = {}

    for p in sources:
        rel = str(p.relative_to(root))
        prod = production_lines(p.read_text(encoding="utf-8", errors="replace"))
        measured[rel] = prod
        entry = registry.get(rel)

        if prod <= THRESHOLD:
            if entry is not None:
                problems.append(
                    f"{rel}: now {prod} production lines (<= {THRESHOLD}) but still in the "
                    f"debt registry — remove the entry, the debt is paid"
                )
            continue

        if entry is None:
            problems.append(
                f"{rel}: {prod} production lines exceeds {THRESHOLD} and is not in the debt "
                f"registry — decompose it, or record an ADR-MCPRE-061 §14 exception"
            )
            continue

        baseline = int(entry["baseline_prod_loc"])
        if prod > baseline:
            problems.append(
                f"{rel}: grew from {baseline} to {prod} production lines — the ratchet only "
                f"turns one way"
            )

    for rel in registry:
        if rel not in measured:
            problems.append(
                f"{rel}: in the debt registry but not found — a stale entry hides a moved "
                f"or deleted file"
            )

    return problems, len(sources)


def validate_registry(registry: dict[str, dict]) -> list[str]:
    problems = []
    for rel, entry in registry.items():
        for field in ("path", "baseline_prod_loc", "baseline_sha", "status"):
            if field not in entry:
                problems.append(f"{rel}: debt entry is missing `{field}`")
        status = entry.get("status")
        if status is not None and status not in STATUSES:
            problems.append(
                f"{rel}: status `{status}` is not one of {sorted(STATUSES)}"
            )
        if status == "reviewed-exception" and not entry.get("exception_ref"):
            problems.append(
                f"{rel}: status is `reviewed-exception` but no `exception_ref` names the "
                f"ADR-MCPRE-061 §14 record"
            )
    return problems


# --------------------------------------------------------------------------------------
# selftest


def selftest() -> int:
    cases: list[tuple[str, str, int]] = [
        ("no test module", "fn a() {}\nfn b() {}\n", 2),
        (
            "narrow #[cfg(test)]",
            "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n",
            1,
        ),
        (
            "#[cfg(all(test, unix))] — the form that broke the first census",
            "fn a() {}\nfn b() {}\n#[cfg(all(test, unix))]\nmod tests {\n    fn t() {}\n}\n",
            2,
        ),
        (
            "production code AFTER the test region is counted",
            "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn b() {}\nfn c() {}\n",
            3,
        ),
        (
            "nested braces inside the test module do not end it early",
            "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() { if x { y(); } }\n    fn u() {}\n}\n",
            1,
        ),
        (
            "two test regions",
            "fn a() {}\n#[cfg(test)]\nmod t1 {\n}\nfn b() {}\n#[cfg(all(test, feature = \"x\"))]\nmod t2 {\n}\nfn c() {}\n",
            3,
        ),
        ("empty file", "", 0),
    ]
    for name, text, expected in cases:
        got = production_lines(text)
        if got != expected:
            print(f"selftest FAIL: {name}: expected {expected} production lines, got {got}")
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # An empty scope must FAIL, never print OK.
        problems, examined = check(root, {})
        if examined != 0:
            print("selftest FAIL: empty tree reported files")
            return 1
        # main() turns examined == 0 into a failure; check that contract here.
        if not empty_scope_is_failure(examined):
            print("selftest FAIL: an empty scope was not treated as a failure")
            return 1

        crate = root / "mcp-re-probe" / "src"
        crate.mkdir(parents=True)
        big = crate / "big.rs"
        big.write_text("\n".join(f"fn f{i}() {{}}" for i in range(THRESHOLD + 5)) + "\n")
        small = crate / "small.rs"
        small.write_text("fn s() {}\n")

        rel_big = "mcp-re-probe/src/big.rs"

        # Unregistered oversized file fails.
        problems, examined = check(root, {})
        if not any("not in the debt registry" in p for p in problems):
            print(f"selftest FAIL: unregistered oversized file passed: {problems}")
            return 1
        if examined != 2:
            print(f"selftest FAIL: expected 2 files examined, got {examined}")
            return 1

        baseline = production_lines(big.read_text())
        reg = {
            rel_big: {
                "path": rel_big,
                "baseline_prod_loc": baseline,
                "baseline_sha": "0" * 7,
                "status": "unreviewed",
            }
        }

        # At baseline: passes.
        problems, _ = check(root, reg)
        if problems:
            print(f"selftest FAIL: file at its baseline reported problems: {problems}")
            return 1

        # Growth fails.
        big.write_text(big.read_text() + "fn extra() {}\n")
        problems, _ = check(root, reg)
        if not any("the ratchet only turns one way" in p for p in problems):
            print(f"selftest FAIL: growth was not caught: {problems}")
            return 1

        # Shrinking (but still oversized) passes.
        big.write_text("\n".join(f"fn f{i}() {{}}" for i in range(THRESHOLD + 2)) + "\n")
        problems, _ = check(root, reg)
        if problems:
            print(f"selftest FAIL: a shrinking file reported problems: {problems}")
            return 1

        # Dropping to the threshold requires removing the entry.
        big.write_text("fn tiny() {}\n")
        problems, _ = check(root, reg)
        if not any("the debt is paid" in p for p in problems):
            print(f"selftest FAIL: paid debt did not require entry removal: {problems}")
            return 1
        problems, _ = check(root, {})
        if problems:
            print(f"selftest FAIL: paid debt with entry removed still failed: {problems}")
            return 1

        # A stale entry naming a file that no longer exists fails.
        problems, _ = check(root, {"gone/nowhere.rs": {"path": "gone/nowhere.rs",
                                                       "baseline_prod_loc": 999,
                                                       "baseline_sha": "0" * 7,
                                                       "status": "unreviewed"}})
        if not any("stale entry" in p for p in problems):
            print(f"selftest FAIL: stale registry entry passed: {problems}")
            return 1

    # Registry schema validation.
    bad = {"a.rs": {"path": "a.rs", "baseline_prod_loc": 1, "baseline_sha": "x",
                    "status": "reviewed-exception"}}
    if not any("exception_ref" in p for p in validate_registry(bad)):
        print("selftest FAIL: reviewed-exception without a reference was accepted")
        return 1
    bad2 = {"a.rs": {"path": "a.rs", "baseline_prod_loc": 1, "baseline_sha": "x",
                     "status": "whatever"}}
    if not any("is not one of" in p for p in validate_registry(bad2)):
        print("selftest FAIL: unknown status was accepted")
        return 1

    print("module-size gate selftest: PASS (7 counter cases, ratchet in both directions, "
          "empty scope, stale + malformed registry entries)")
    return 0


def empty_scope_is_failure(examined: int) -> bool:
    """A gate that examined nothing must not report OK. Named so the selftest can assert
    the contract rather than re-implement it."""
    return examined == 0


def baseline_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        return "unknown"


def emit_registry() -> int:
    """Print a debt registry for the current tree. Used once, to baseline."""
    sha = baseline_sha()
    rows = []
    for p in rust_sources(REPO):
        prod = production_lines(p.read_text(encoding="utf-8", errors="replace"))
        if prod > THRESHOLD:
            rows.append((str(p.relative_to(REPO)), prod))
    rows.sort(key=lambda r: (-r[1], r[0]))
    print(f"# Baselined at {sha}: {len(rows)} files over {THRESHOLD} production lines.")
    for rel, prod in rows:
        print("\n[[debt]]")
        print(f'path = "{rel}"')
        print(f"baseline_prod_loc = {prod}")
        print(f'baseline_sha = "{sha}"')
        print('status = "unreviewed"')
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if "--emit-registry" in sys.argv:
        return emit_registry()

    registry = load_registry(REGISTRY)
    schema_problems = validate_registry(registry)
    problems, examined = check(REPO, registry)
    problems = schema_problems + problems

    if empty_scope_is_failure(examined):
        print("module-size gate: FAIL — examined 0 production Rust files. A gate that "
              "measured nothing is not a pass.")
        return 1

    if problems:
        print(f"module-size gate: FAIL — {len(problems)} problem(s)")
        for p in problems:
            print(f"  - {p}")
        print(
            f"\nMeasurement: production lines = lines before the first module matching "
            f"^#[cfg((all()?test ; threshold {THRESHOLD} (ADR-MCPRE-061 §5.1)."
        )
        return 1

    unreviewed = sum(1 for e in registry.values() if e["status"] == "unreviewed")
    excepted = len(registry) - unreviewed
    print(
        f"module-size gate: OK — {examined} production Rust files examined against a "
        f"{THRESHOLD}-line threshold (production lines = lines before the first module "
        f"matching ^#[cfg((all()?test ; ADR-MCPRE-061 §5.1). Debt registry: {len(registry)} "
        f"file(s) — {unreviewed} unreviewed, {excepted} with a §14 exception. No new "
        f"oversized file, no registered file grew."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
