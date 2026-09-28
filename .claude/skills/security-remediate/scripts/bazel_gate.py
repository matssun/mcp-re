"""Bazel gate with BASELINE-DELTA semantics, not exit-code semantics.

(Invoked as `python3 bazel_gate.py …`; no shebang — see reduce.py for why.)

WHY: in tick 1 of a lane run, two files were judged `gate-failed` on `bazel test
… exit 1`. Both judgements were wrong. This tree currently has broken analysis
for distroless image targets, `*_linux` toolchain variants and Go toolchain
drift, so `//<tree>/...:all` exits 1 no matter what you did to the source. Both
workers established this themselves by reproducing on the unmodified tree — the
harness was wrong, not their work.

An exit code is a single bit summarising a set. The gate must compare the SET:

    new_failures = post_failures - baseline_failures

and the change is acceptable iff `new_failures` is empty.

**The baseline failing set is TRACKED DEBT, not an acceptable resting state.**
This module records it so that a genuinely new failure cannot hide inside it, and
it prints the set on every run for exactly that reason. It does not authorise
leaving those targets broken, and `baseline --owner` records the issue that owns
them so the set cannot grow anonymously. A baseline entry with no owner is
reported as `unowned_baseline_failures`, which is a finding in its own right.

Three outcomes, deliberately distinguished — collapsing them is the original sin:

  ok             no target failed that the baseline did not already have failing
  new-failures   at least one target failed that the baseline had passing
  infra          Bazel could not determine target results at all (analysis or
                 loading error, crate-universe splice timeout, server crash).
                 NOT a verdict about the change; the run must be repeated.

Usage:
  python3 bazel_gate.py baseline --tree //components/demo/gadgets/... \\
      --store <dir> --owner "#1234"
  python3 bazel_gate.py check    --tree //components/demo/gadgets/... \\
      --store <dir>
  python3 bazel_gate.py compare  --baseline a.json --post b.json     # no bazel run
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _persist import atomic_write_lines  # noqa: E402

# `bazel test` prints one status line per target. NO STATUS means the target was
# never run (usually a broken upstream analysis), which is NOT the same as a test
# that ran and failed — so it is captured under its own label.
# `(cached)` sits between the label and the status on a cached target, so a
# naive `label\s+STATUS` matches nothing on a warm cache — which is the NORMAL
# case for an untouched tree and would have made the gate see zero passing
# targets on every run after the first.
STATUS_RE = re.compile(
    r"^(//\S+?)\s+(?:\(cached\)\s+)?(PASSED|FAILED|FLAKY|TIMEOUT|NO STATUS|SKIPPED)\b")
EXECUTED_RE = re.compile(r"Executed (\d+) out of (\d+) tests?")
# The shape the known-broken targets ACTUALLY take on this host. Verified against
# a live run: they never appear as a target status line at all, only as an
# analysis warning naming the label. A parser built on invented output missed
# every one of them and reported `failing: 0` on a tree with seven broken
# targets — which would have made the gate blind in the permissive direction.
ANALYSIS_FAILED_RE = re.compile(
    r"errors encountered while analyzing target '(//\S+?)'")
TOOLCHAIN_FAILED_RE = re.compile(
    r"While resolving toolchains for target (//[^\s(]+)")
# Bazel's own summary of the tick-1 situation, in one line.
TESTS_PASSED_OTHER_ERRORS = "All tests passed but there were other errors during the build"
# Bazel-level breakage: nothing downstream of these says anything about the code.
INFRA_RE = re.compile(
    r"(error loading package|Analysis of target .* failed|Failed to generate lockfile|"
    r"error evaluating module extension|no such package|Server terminated abruptly|"
    r"Timed out|toolchain.*not find|Unable to load package)", re.I)
FAILING_STATUSES = {"FAILED", "TIMEOUT", "NO STATUS"}

# `--test_summary=short` is NOT cosmetic: without it bazel prints no per-target
# status line for a passing test, so the gate cannot name what passed and the
# whole set-delta idea collapses to counting. Learned from a live run that
# reported 0 passing while 4 tests passed.
DEFAULT_FLAGS = ["--keep_going", "--test_timeout=900", "--test_output=errors",
                 "--test_summary=short"]


def _tree_key(tree: str) -> str:
    return hashlib.sha1(tree.encode()).hexdigest()[:12]


def run_bazel(tree: str, flags: list, log_path: str) -> dict:
    """Run the gate ONCE and capture its full output before reading anything.

    The exit code is read from the process, never from a pipeline — piping bazel
    through grep/tail reports the FILTER's status and has produced exit 0 on an
    aborted build in this repo (CLAUDE.md trap 14).
    """
    cmd = ["bazel", "test", tree] + flags
    with open(log_path, "w", encoding="utf-8") as fh:
        proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, text=True)
    with open(log_path, encoding="utf-8") as fh:
        output = fh.read()
    return parse_output(output, exit_code=proc.returncode, tree=tree,
                        cmd=" ".join(cmd), log=log_path)


def parse_output(output: str, *, exit_code: int, tree: str = "", cmd: str = "",
                 log: str = "") -> dict:
    """Extract the per-target identity sets. Pure, so it is unit-testable."""
    by_status: dict = {}
    for line in output.splitlines():
        m = STATUS_RE.match(line.strip())
        if m:
            by_status.setdefault(m.group(2), set()).add(m.group(1))

    executed = total = None
    for m in EXECUTED_RE.finditer(output):
        executed, total = int(m.group(1)), int(m.group(2))

    infra = sorted({line.strip()[:200] for line in output.splitlines()
                    if line.startswith("ERROR:") and INFRA_RE.search(line)})

    # Targets whose ANALYSIS failed. These never produce a status line, so they
    # are invisible to STATUS_RE and must be collected separately or the gate
    # under-reports the failing set.
    analysis_failed = set(ANALYSIS_FAILED_RE.findall(output))
    analysis_failed |= set(TOOLCHAIN_FAILED_RE.findall(output))

    passing = by_status.get("PASSED", set())
    failing = set()
    for s in FAILING_STATUSES:
        failing |= by_status.get(s, set())
    # A label can appear in BOTH sets: bazel reports toolchain resolution per
    # CONFIGURATION, so `//x:test` can fail analysis in a linux variant while the
    # default-config target runs and passes. A demonstrated PASS outranks an
    # analysis warning — but the overlap is recorded rather than dropped, because
    # "this target is broken in some configuration" is real information.
    dual = sorted(analysis_failed & passing)
    failing |= (analysis_failed - passing)

    # `executed == 0` on a warm cache means "all results reused", NOT "nothing
    # ran" — CLAUDE.md's cached-target trap. Distinguish None (bazel never got
    # to the summary) from 0 (it did, and everything was cached).
    tests_ran = executed is not None or bool(by_status)
    # Bazel never got far enough to judge the code. NOT when tests actually ran
    # and only the image/toolchain targets broke — that is the tick-1 case and
    # calling it `infra` would discard a real, usable test result.
    no_results = not tests_ran and exit_code != 0

    return {
        "tree": tree, "cmd": cmd, "log": log, "exit_code": exit_code,
        "targets": {k: sorted(v) for k, v in sorted(by_status.items())},
        "failing": sorted(failing),
        "analysis_failed": sorted(analysis_failed),
        "analysis_failed_but_passing_in_default_config": dual,
        "passing": sorted(passing),
        "executed": executed, "total": total,
        "tests_all_passed_with_build_errors": TESTS_PASSED_OTHER_ERRORS in output,
        "infra_errors": infra,
        "infra_suspected": bool(no_results),
    }


def compare(baseline: dict, post: dict) -> dict:
    """Set-to-set delta. The verdict NEVER reduces to exit-code equality."""
    b_fail, p_fail = set(baseline["failing"]), set(post["failing"])
    b_pass = set(baseline["passing"])

    new_failures = sorted(p_fail - b_fail)
    recovered = sorted(b_fail - p_fail)
    # A target that was passing in the baseline and is now absent entirely: it
    # stopped being selected. The suite got narrower without failing, which is
    # the quiet way a gate stops measuring anything.
    vanished = sorted(b_pass - p_fail - set(post["passing"]))

    if post.get("infra_suspected"):
        verdict = "infra"
    elif new_failures:
        verdict = "new-failures"
    else:
        verdict = "ok"

    still_failing = sorted(b_fail & p_fail)
    owner = baseline.get("owner") or ""
    return {
        "verdict": verdict,
        "new_failures": new_failures,
        "baseline_failures_still_failing": still_failing,
        "unowned_baseline_failures": [] if owner else still_failing,
        "baseline_debt_owner": owner or None,
        "baseline_failures_now_recovered": recovered,
        "baseline_passing_now_absent": vanished,
        "baseline_exit": baseline.get("exit_code"),
        "post_exit": post.get("exit_code"),
        "executed": post.get("executed"), "total": post.get("total"),
        "infra_errors": post.get("infra_errors", []),
        "note": ("exit codes are reported but are NOT the verdict: this tree has "
                 "broken targets recorded in the baseline, so a nonzero exit is "
                 "expected and says nothing about the change. The baseline set is "
                 "tracked debt and must carry an owning issue."),
    }


def _store_path(store: str, tree: str, kind: str) -> str:
    os.makedirs(store, exist_ok=True)
    return os.path.join(store, "%s-%s.json" % (kind, _tree_key(tree)))


def cmd_baseline(a) -> int:
    log = _store_path(a.store, a.tree, "baseline").replace(".json", ".log")
    res = run_bazel(a.tree, DEFAULT_FLAGS + (a.flag or []), log)
    res["owner"] = a.owner or ""
    path = _store_path(a.store, a.tree, "baseline")
    atomic_write_lines(path, [json.dumps(res, sort_keys=True, indent=1)])
    print(json.dumps({"tree": a.tree, "stored": path, "exit_code": res["exit_code"],
                      "failing": len(res["failing"]), "passing": len(res["passing"]),
                      "executed": res["executed"], "total": res["total"],
                      "owner": res["owner"] or None,
                      "infra_suspected": res["infra_suspected"]}, indent=1))
    return 0


def cmd_check(a) -> int:
    bpath = _store_path(a.store, a.tree, "baseline")
    if not os.path.exists(bpath):
        print(json.dumps({"verdict": "no-baseline", "expected": bpath,
                          "why": "capture a baseline for this tree before gating "
                                 "against it; comparing to zero is the defect"}, indent=1))
        return 2
    with open(bpath, encoding="utf-8") as fh:
        baseline = json.load(fh)
    log = _store_path(a.store, a.tree, "post").replace(".json", ".log")
    post = run_bazel(a.tree, DEFAULT_FLAGS + (a.flag or []), log)
    atomic_write_lines(_store_path(a.store, a.tree, "post"),
                       [json.dumps(post, sort_keys=True, indent=1)])
    out = compare(baseline, post)
    print(json.dumps(out, indent=1))
    return 0 if out["verdict"] == "ok" else 1


def cmd_compare(a) -> int:
    with open(a.baseline, encoding="utf-8") as fh:
        baseline = json.load(fh)
    with open(a.post, encoding="utf-8") as fh:
        post = json.load(fh)
    out = compare(baseline, post)
    print(json.dumps(out, indent=1))
    return 0 if out["verdict"] == "ok" else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    bl = sub.add_parser("baseline")
    bl.add_argument("--tree", required=True)
    bl.add_argument("--store", required=True)
    bl.add_argument("--owner", default="", help="issue that owns the broken targets")
    bl.add_argument("--flag", action="append")
    bl.set_defaults(fn=cmd_baseline)

    ck = sub.add_parser("check")
    ck.add_argument("--tree", required=True)
    ck.add_argument("--store", required=True)
    ck.add_argument("--flag", action="append")
    ck.set_defaults(fn=cmd_check)

    cp = sub.add_parser("compare")
    cp.add_argument("--baseline", required=True)
    cp.add_argument("--post", required=True)
    cp.set_defaults(fn=cmd_compare)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
