#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test-inventory gate — every test in the source tree is compiled into a binary `bazel
test //...` runs.

A missing BUILD target, a module no crate root declares, a Bazel crate flavor without the
feature a `#[cfg(feature = ...)]` test needs, or a target tagged `manual` each make a test
disappear with every check still green. Nothing else asks: `bazel test //...` cannot report
a test it never compiled. Two halves, because they cost very different amounts:

  * STATIC (the default, no build) — every `#[test]` in a tracked first-party `.rs` file is
    reachable, through `mod` declarations, from a crate root some `rust_test` target
    compiles. A file no tested root reaches holds tests nothing will ever compile. Runs on
    the merge path.
  * COMPILED (`--collect` then `--compare`, weekly) — every reachable test is LISTED by a
    non-manual `rust_test` on its crate root, and every doctest item by its crate's
    `rust_doc_test`. A test reachable in source and absent from every binary was compiled
    out — a feature no flavor enables.

Tests are keyed as the control census keys them (`tools/verification/_controls`): the
Bazel package, the crate root, the module path. Names prove a test is compiled, not that it
does anything. A test only a `manual` target compiles is a gap unless ALLOWED names the lane
that runs it; an ALLOWED entry that matches nothing also fails.

    python3 scripts/test_inventory_gate.py                      # static
    python3 scripts/test_inventory_gate.py --collect bazel.json # build + list every binary
    python3 scripts/test_inventory_gate.py --compare bazel.json
    python3 scripts/test_inventory_gate.py --selftest
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools" / "verification"))

import _controls  # noqa: E402
import _rust_targets  # noqa: E402

_TEST_ATTR = re.compile(r"^\s*#\[(?:tokio::)?test\b")

#: Tests a non-manual binary does not list, each with the lane that does run them.
ALLOWED: dict[str, str] = {
    "mcp-re-proxy tests/tls_load_harness_bench.rs#*":
        "LANE: `manual` because its tests start a Docker Redis fleet; ci.yml's release-gates "
        "job runs it (`Release gate — load harness`), and :tls_load_harness_bench_builds "
        "compiles it on every `bazel test //...`",
    "mcp-re-proxy tests/gcp_kms_live_test.rs#*":
        "LANE: `manual` live-cloud suite; cloud-kms-live.yml runs it against a real GCP KMS",
}


def tracked_rust_files() -> list[str]:
    # Tracked, and untracked-but-not-ignored: a test file written and not yet added is
    # exactly the one no target compiles yet.
    out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
                          "*.rs"], cwd=REPO, capture_output=True, text=True, check=True).stdout
    return sorted(f for f in out.split("\0") if f and not f.startswith("docs/archive/"))


def count_tests(text: str) -> int:
    return sum(1 for line in text.splitlines() if _TEST_ATTR.match(line))


def static_gaps(files: dict[str, str], carriers: set[str]) -> list[str]:
    """Files holding tests that no crate root a `rust_test` compiles reaches."""
    return [
        f"{path}: {count} test(s) that no Bazel test target compiles — no crate root a "
        f"`rust_test` builds declares this module"
        for path, text in sorted(files.items())
        if (count := count_tests(text)) and path not in carriers
    ]


def key(project: str, identity: str) -> str:
    return f"{project} {identity}"


def matches(name: str, pattern: str) -> bool:
    """`*` is the only wildcard."""
    return re.fullmatch(".*".join(map(re.escape, pattern.split("*"))), name) is not None


def listed(exe: Path) -> list[str]:
    out = subprocess.run([str(exe), "--list", "--format=terse"], capture_output=True, text=True,
                         check=True).stdout
    return sorted(line[: -len(": test")] for line in out.splitlines() if line.endswith(": test"))


def bazel(*args: str) -> str:
    done = subprocess.run(["bazel", *args], cwd=REPO, capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"FAILED ({done.returncode}): bazel {' '.join(args)}\n{done.stderr[-4000:]}")
    return done.stdout


def doctest_items(log: str) -> list[str]:
    """The items a rustdoc test log ran a doctest for. A crate-level doctest names no item
    (`test src/lib.rs - (line 35) - compile ... ok`), and is the empty item."""
    return sorted(set(re.findall(r"^test \S+ - (?:(\S+) )?\(line \d+\)", log, re.M)))


def collect() -> dict:
    """Build every `rust_test` and list what each binary contains; run the doctest targets
    (their runner forwards no arguments, so `--list` cannot reach them) and read the items
    from the log. A `manual` target that does not build is recorded as containing nothing:
    nothing builds it, so it covers nothing."""
    table = _rust_targets.table()
    tests = {label: row for label, row in table.items() if row["kind"] == "rust_test"}
    docs = sorted(label for label, row in table.items() if row["kind"] == "rust_doc_test")
    bazel("build", "--noshow_progress", *(label for label, row in tests.items() if not row["manual"]))
    exec_root = Path(bazel("info", "execution_root").strip())
    binaries = []
    for label, row in sorted(tests.items()):
        entry = {"label": label, "package": row["package"], "root": row["root"],
                 "manual": row["manual"], "tests": []}
        if row["manual"]:
            built = subprocess.run(["bazel", "build", "--noshow_progress", label], cwd=REPO,
                                   capture_output=True, text=True)
            if built.returncode != 0:
                entry["does_not_build"] = built.stderr[-2000:]
                binaries.append(entry)
                continue
        exe = exec_root / bazel("cquery", "--output=files", label).strip().splitlines()[0]
        entry["tests"] = listed(exe)
        binaries.append(entry)
    doctests = []
    if docs:
        bazel("test", "--noshow_progress", "--nocache_test_results", *docs)
        logs = Path(bazel("info", "bazel-testlogs").strip())
        for label in docs:
            package, name = label[2:].split(":")
            log = (logs / package / name / "test.log").read_text()
            items = doctest_items(log)
            doctests.append({"label": label, "package": package, "items": items})
    return {"binaries": binaries, "doctests": doctests}


def compare(inventory: dict, controls: list, allowed: dict[str, str]) -> tuple[list[str], list[str]]:
    """(problems, report lines) for the reachable controls against what the binaries list."""
    covered: set[str] = set()
    manual: set[str] = set()
    report: list[str] = []
    for b in inventory["binaries"]:
        root = _rust_targets.root_identity(b["root"], b["package"])
        names = {key(b["package"], f"{root}#{t}") for t in b["tests"]}
        (manual if b["manual"] else covered).update(names)
        flag = " [manual]" if b["manual"] else ""
        report.append(f"  {len(b['tests']):5} tests  {b['label']}{flag}")
        if "does_not_build" in b:
            report.append(f"        does not build:\n" + "\n".join(
                "          " + line for line in b["does_not_build"].splitlines()[-8:]))
    for d in inventory["doctests"]:
        covered.update(key(d["package"], f"doc#{item}") for item in d["items"])
    problems: list[str] = []
    if not any(b["tests"] for b in inventory["binaries"]):
        problems.append("no binary listed a test — comparing nothing is not a pass")
    used: set[str] = set()
    gaps = 0
    for control in controls:
        name = key(control.project, control.identity)
        if name in covered:
            continue
        gaps += 1
        hits = [p for p in allowed if matches(name, p)]
        used.update(hits)
        where = "only in a `manual` target" if name in manual else "in no Bazel test binary"
        if hits:
            report.append(f"  allowed: {name} ({where}) — {allowed[hits[0]]}")
        else:
            problems.append(f"`{name}` ({control.carrier}:{control.line}) is reachable in source "
                            f"and {where} — compiled out of every non-manual flavor")
    problems += [f"ALLOWED entry `{p}` matches no gap — remove it" for p in sorted(set(allowed) - used)]
    report.append(f"{len(controls)} reachable test(s); {len(covered)} listed by non-manual "
                  f"binaries or doctest targets; {gaps} gap(s), {len(used)} allow entr(ies) used")
    return problems, report


def selftest() -> int:
    failures = []
    files = {"a/src/lib.rs": "#[test]\nfn x() {}\n", "a/tests/orphan.rs": "#[tokio::test]\nasync fn y() {}\n",
             "a/src/plain.rs": "fn z() {}\n"}
    gaps = static_gaps(files, {"a/src/lib.rs"})
    if len(gaps) != 1 or "a/tests/orphan.rs" not in gaps[0]:
        failures.append(f"static: an unreached test file must be the one gap, got {gaps}")
    if static_gaps(files, {"a/src/lib.rs", "a/tests/orphan.rs"}):
        failures.append("static: a reached file is not a gap")
    log = ("test a/src/lib.rs - (line 35) - compile ... ok\n"
           "test a/src/lib.rs - Item (line 9) ... ok\n"
           "test a/src/m.rs - m::Other::new (line 4) - compile fail ... ok\n")
    if doctest_items(log) != ["", "Item", "m::Other::new"]:
        failures.append(f"doctest items: a crate-level doctest must be the empty item, got {doctest_items(log)}")

    class C:
        def __init__(self, project, identity):
            self.project, self.identity, self.carrier, self.line = project, identity, "f.rs", 1

    controls = [C("a", "src/lib.rs#m::tests::x"), C("a", "tests/t.rs#y"), C("a", "doc#Item")]
    inventory = {
        "binaries": [
            {"label": "//a:unit", "package": "a", "root": "a/src/lib.rs", "manual": False, "tests": ["m::tests::x"]},
            {"label": "//a:it", "package": "a", "root": "a/tests/t.rs", "manual": False, "tests": ["y"]},
        ],
        "doctests": [{"label": "//a:doc", "package": "a", "items": ["Item"]}],
    }
    cases = [
        ("every reachable test is listed", inventory, {}, None),
        ("a test compiled out of every flavor",
         {**inventory, "binaries": [inventory["binaries"][0], {**inventory["binaries"][1], "tests": []}]},
         {}, "in no Bazel test binary"),
        ("a test only a manual target lists",
         {**inventory, "binaries": [inventory["binaries"][0], {**inventory["binaries"][1], "manual": True}]},
         {}, "only in a `manual` target"),
        ("an allowed manual-only test passes",
         {**inventory, "binaries": [inventory["binaries"][0], {**inventory["binaries"][1], "manual": True}]},
         {"a tests/t.rs#*": "LANE: x"}, None),
        ("a same-named test under another root does not count",
         {**inventory, "binaries": [{**inventory["binaries"][0], "tests": ["m::tests::x", "y"]}]},
         {}, "`a tests/t.rs#y`"),
        ("a stale allow entry fails", inventory, {"b *": "LANE: x"}, "matches no gap"),
        ("nothing listed", {"binaries": [], "doctests": []}, {}, "comparing nothing"),
    ]
    for label, inv, allowed, expect in cases:
        problems, _ = compare(inv, controls, allowed)
        text = "\n".join(problems)
        if expect is None and problems:
            failures.append(f"{label}: reported {problems}")
        if expect is not None and expect not in text:
            failures.append(f"{label}: expected {expect!r}, got {problems}")
    if failures:
        print("test-inventory gate selftest: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"test-inventory gate selftest: PASS ({len(cases) + 2} cases)")
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--selftest"]:
        return selftest()
    if len(argv) == 2 and argv[0] == "--collect":
        data = collect()
        Path(argv[1]).write_text(json.dumps(data, indent=1))
        print(f"wrote {argv[1]}: {sum(len(b['tests']) for b in data['binaries'])} listed test(s)")
        return 0
    if len(argv) == 2 and argv[0] == "--compare":
        problems, report = compare(json.loads(Path(argv[1]).read_text()), _controls.rust_controls()
                                   + _controls.doctest_controls(), ALLOWED)
        print("\n".join(report))
        if problems:
            print(f"test-inventory gate: FAIL — {len(problems)} problem(s)")
            for p in problems:
                print(f"  - {p}")
            return 1
        print("test-inventory gate: OK — every reachable test is compiled into a binary "
              "`bazel test //...` runs, or into a named lane's `manual` target")
        return 0
    if argv:
        print(__doc__)
        return 2
    carriers = {c.carrier for c in _controls.rust_controls()}
    files = {f: (REPO / f).read_text(errors="replace") for f in tracked_rust_files()}
    gaps = static_gaps(files, carriers)
    total = sum(count_tests(t) for t in files.values())
    if gaps:
        print(f"test-inventory gate: FAIL — {len(gaps)} file(s)")
        for g in gaps:
            print(f"  - {g}")
        return 1
    if not total:
        print("test-inventory gate: FAIL — no test found in the tree; the scan read nothing")
        return 1
    print(f"test-inventory gate: OK — {total} test(s) in {sum(1 for t in files.values() if count_tests(t))} "
          f"file(s), every file reachable from a crate root a Bazel `rust_test` compiles")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
