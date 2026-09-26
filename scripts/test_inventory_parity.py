# SPDX-License-Identifier: Apache-2.0
"""Test-inventory parity — every test the cargo lanes run, a `bazel test //...` binary runs.

Bazel is becoming the only build system, and the PR path is moving from cargo test runs to
`bazel test`. That move is safe only if Bazel compiles every test cargo compiles, under the
features cargo compiles it with. A missing BUILD target, a Bazel crate flavor without the
feature a `#[cfg(feature = ...)]` test needs, or a target tagged `manual` each make a test
disappear with every check still green. Nothing else asks: `bazel test //...` cannot report
a test it never compiled.

This compares NAMES, not results. Each side lists what its binaries contain:

  * cargo — every test executable of the lanes below, `--list`ed, plus the doctests.
    The lanes are the cargo test commands the PR path runs in `ci.yml`; the cross-verify
    and release-gate commands select subsets of these binaries.
  * bazel — every `rust_test` target, `--list`ed. Targets tagged `manual` are recorded but
    do not count as coverage: `bazel test //...` skips them.

A test is keyed by where it lives, so the two build systems' target names do not matter:
`<package dir> [unit]` for tests compiled into a library or binary crate, the crate-root
path for an integration test binary, `[doc] <crate>` for a doctest. A test cargo RUNS (not
`#[ignore]`d) that no non-manual Bazel binary contains is a gap, and a gap fails unless
ALLOWED names it with a reason. An ALLOWED entry that matches nothing also fails.

Delete this together with the last Cargo manifest.

    python3 scripts/test_inventory_parity.py --collect-cargo cargo.json
    python3 scripts/test_inventory_parity.py --collect-bazel bazel.json
    python3 scripts/test_inventory_parity.py --compare cargo.json bazel.json
    python3 scripts/test_inventory_parity.py --selftest
"""

from __future__ import annotations

import fnmatch
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

PROXY_FEATURES = ("dev_env_key_source,pkcs11_keysource,redis_replay,online_ocsp,"
                  "aws_kms_keysource,gcp_kms_keysource,async_serve,cpstore_etcd")

# (lane, the ci.yml job/step it mirrors, cargo test arguments)
CARGO_LANES = [
    ("workspace", "cargo / Test (workspace, incl. conformance suite + drift guard)",
     ["--workspace"]),
    ("proxy-all-features", "cargo-features / Test (mcp-re-proxy, all feature gates)",
     ["-p", "mcp-re-proxy", "--features", PROXY_FEATURES]),
    ("proxy-async-serve", "cargo-features / Release gate — replay race, bounded drain, inner plane",
     ["-p", "mcp-re-proxy", "--features", "async_serve",
      "--test", "integration_async", "--test", "async_drain_test"]),
]

# Gaps accepted on purpose: fnmatch pattern over `<key>::<test name>` -> reason.
ALLOWED: dict[str, str] = {}


def run(cmd: list[str], cwd: Path = REPO) -> str:
    done = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"FAILED ({done.returncode}): {' '.join(cmd)}\n{done.stderr[-4000:]}")
    return done.stdout


def listed(exe: str, cwd: Path) -> tuple[list[str], list[str]]:
    """All test names in a libtest binary, and the `#[ignore]`d subset."""
    def names(extra: list[str]) -> list[str]:
        out = run([exe, "--list", "--format=terse", *extra], cwd)
        return sorted(line[:-len(": test")] for line in out.splitlines() if line.endswith(": test"))
    return names([]), names(["--ignored"])


def rel(path: str) -> str:
    return str(Path(path).resolve().relative_to(REPO))


def collect_cargo() -> dict:
    lanes = []
    for lane, step, args in CARGO_LANES:
        out = run(["cargo", "test", *args, "--no-run", "--message-format=json"])
        binaries = []
        for line in out.splitlines():
            msg = json.loads(line)
            if msg.get("reason") != "compiler-artifact" or not msg.get("executable"):
                continue
            if not msg["profile"]["test"]:
                continue
            target = msg["target"]
            pkg_dir = Path(msg["manifest_path"]).parent
            if "test" in target["kind"]:
                key = rel(target["src_path"])
            else:
                key = f"{rel(str(pkg_dir))} [unit]"
            tests, ignored = listed(msg["executable"], pkg_dir)
            binaries.append({"binary": f"{target['name']} ({'/'.join(target['kind'])})",
                             "key": key, "tests": tests, "ignored": ignored})
        lanes.append({"lane": lane, "ci_step": step, "binaries": binaries})
    doc = run(["cargo", "test", "--workspace", "--doc", "--", "--list", "--format=terse"])
    doctests = sorted(l[:-len(": test")] for l in doc.splitlines() if l.endswith(": test"))
    lanes.append({"lane": "doctests", "ci_step": "cargo / Test (workspace) runs doctests too",
                  "binaries": [{"binary": "doctests", "key": "[doc]", "tests": doctests,
                                "ignored": []}]})
    return {"side": "cargo", "lanes": lanes}


def bazel_test_targets() -> list[dict]:
    out = run(["bazel", "query", "--noshow_progress", 'kind("rust_test rule", //...)',
               "--output=streamed_jsonproto"])
    targets = []
    for line in out.splitlines():
        rule = json.loads(line)["rule"]
        attrs = {a["name"]: a for a in rule.get("attribute", [])}
        srcs = [s.split(":", 1)[1] for s in attrs.get("srcs", {}).get("stringListValue", [])]
        pkg = rule["name"][2:].split(":")[0]
        root = attrs.get("crate_root", {}).get("stringValue")
        if root:
            root = f"{pkg}/{root.split(':', 1)[1]}"
        elif len(srcs) == 1:
            root = f"{pkg}/{srcs[0]}"
        else:
            mains = [s for s in srcs if s.endswith("/main.rs")]
            root = f"{pkg}/{mains[0]}" if len(mains) == 1 else None
        unit = bool(attrs.get("crate", {}).get("stringValue"))
        if not unit and root is None:
            raise SystemExit(f"cannot tell the crate root of {rule['name']} (srcs {srcs})")
        targets.append({"label": rule["name"],
                        "key": f"{pkg} [unit]" if unit else root,
                        "manual": "manual" in attrs.get("tags", {}).get("stringListValue", [])})
    return targets


def collect_bazel() -> dict:
    targets = bazel_test_targets()
    run(["bazel", "build", "--noshow_progress", *(t["label"] for t in targets)])
    bin_dir = Path(run(["bazel", "info", "bazel-bin"]).strip())
    binaries = []
    for t in targets:
        exe = bin_dir / t["label"][2:].replace(":", "/")
        if not exe.is_file():
            raise SystemExit(f"built {t['label']} but found no executable at {exe}")
        tests, ignored = listed(str(exe), REPO)
        binaries.append({"binary": t["label"], "key": t["key"], "manual": t["manual"],
                         "tests": tests, "ignored": ignored})
    return {"side": "bazel", "lanes": [{"lane": "rust_test", "ci_step": "bazel / bazel test //...",
                                        "binaries": binaries}]}


def names(inventory: dict, *, manual: bool | None = None, ignored: bool | None = None) -> set[str]:
    out = set()
    for lane in inventory["lanes"]:
        for b in lane["binaries"]:
            if manual is not None and b.get("manual", False) != manual:
                continue
            skip = set(b["ignored"])
            for t in b["tests"]:
                if ignored is None or (t in skip) == ignored:
                    out.add(f"{b['key']}::{t}")
    return out


def compare(cargo: dict, bazel: dict, allowed: dict[str, str]) -> tuple[list[str], list[str]]:
    """(problems, report lines)."""
    problems, report = [], []
    for inv in (cargo, bazel):
        for lane in inv["lanes"]:
            total = sum(len(b["tests"]) for b in lane["binaries"])
            report.append(f"{inv['side']:5} {lane['lane']:20} {len(lane['binaries']):3} binaries "
                          f"{total:5} tests  ({lane['ci_step']})")
            if not total and lane["lane"] != "doctests":
                problems.append(f"{inv['side']} lane `{lane['lane']}` listed no tests — "
                                f"comparing nothing is not a pass")
    covered = names(bazel, manual=False)
    manual_only = names(bazel, manual=True) - covered
    gaps = sorted(names(cargo, ignored=False) - covered)
    used = set()
    for gap in gaps:
        hits = [p for p in allowed if fnmatch.fnmatchcase(gap, p)]
        used.update(hits)
        where = "only in a `manual` Bazel target" if gap in manual_only else "in no Bazel test binary"
        if hits:
            report.append(f"  allowed gap: {gap} ({where}) — {allowed[hits[0]]}")
        else:
            problems.append(f"cargo runs `{gap}`; it is {where}")
    for pattern in sorted(set(allowed) - used):
        problems.append(f"ALLOWED entry `{pattern}` matches no gap — remove it")
    unmatched_ignored = sorted(names(cargo, ignored=True) - covered - manual_only)
    report.append(f"cargo runs {len(names(cargo, ignored=False))} distinct tests; "
                  f"non-manual Bazel binaries contain {len(covered)}; gaps {len(gaps)}; "
                  f"#[ignore]d in cargo and absent from Bazel {len(unmatched_ignored)} (not a gap)")
    return problems, report


def selftest() -> int:
    def inv(side, *bins):
        return {"side": side, "lanes": [{"lane": "l", "ci_step": "s", "binaries": [
            {"binary": k, "key": k, "tests": list(t), "ignored": list(i), "manual": m}
            for k, t, i, m in bins]}]}

    cargo = inv("cargo", ("a [unit]", ["x", "y"], [], False), ("a/tests/t.rs", ["z", "w"], ["w"], False))
    same = inv("bazel", ("a [unit]", ["x", "y"], [], False), ("a/tests/t.rs", ["z"], [], False))
    cases = [
        ("bazel contains every test cargo runs", cargo, same, {}, None),
        ("a test is missing from bazel",
         cargo, inv("bazel", ("a [unit]", ["x"], [], False), ("a/tests/t.rs", ["z"], [], False)),
         {}, "`a [unit]::y`; it is in no Bazel test binary"),
        ("the test is only in a manual target",
         cargo, inv("bazel", ("a [unit]", ["x", "y"], [], False), ("a/tests/t.rs", ["z"], [], True)),
         {}, "only in a `manual` Bazel target"),
        ("a same-named test under another crate root does not count",
         cargo, inv("bazel", ("a [unit]", ["x", "y", "z"], [], False)), {}, "`a/tests/t.rs::z`"),
        ("an allowed gap passes", cargo, inv("bazel", ("a [unit]", ["x", "y"], [], False)),
         {"a/tests/t.rs::*": "reason"}, None),
        ("a stale allowlist entry fails", cargo, same, {"b::*": "reason"}, "matches no gap"),
        ("bazel listed nothing", cargo, inv("bazel", ("a [unit]", [], [], False)), {},
         "comparing nothing"),
    ]
    for label, c, b, allowed, expect in cases:
        problems, _ = compare(c, b, allowed)
        text = "\n".join(problems)
        if expect is None and problems:
            print(f"SELFTEST FAILED: {label}: reported {problems}")
            return 1
        if expect is not None and expect not in text:
            print(f"SELFTEST FAILED: {label}: expected {expect!r}, got {problems}")
            return 1
    print(f"test-inventory parity selftest: PASS ({len(cases)} cases)")
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--selftest"]:
        return selftest()
    if len(argv) == 2 and argv[0] in ("--collect-cargo", "--collect-bazel"):
        data = collect_cargo() if argv[0] == "--collect-cargo" else collect_bazel()
        Path(argv[1]).write_text(json.dumps(data, indent=1))
        print(f"wrote {argv[1]}: {len(names(data))} tests")
        return 0
    if len(argv) == 3 and argv[0] == "--compare":
        cargo, bazel = (json.loads(Path(p).read_text()) for p in argv[1:])
        problems, report = compare(cargo, bazel, ALLOWED)
        print("\n".join(report))
        if problems:
            print(f"test-inventory parity: FAIL — {len(problems)} problem(s)")
            for p in problems:
                print(f"  - {p}")
            return 1
        print("test-inventory parity: OK")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
