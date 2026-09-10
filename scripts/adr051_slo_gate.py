#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ADR-MCPRE-051 §7 local-regression SLO gate.

Compares a FRESH load-harness report (the JSON the harness writes to
MCP_RE_LOADGEN_OUT) against the committed provisional baseline
(docs/bench/adr-051-baseline-local.json) under the ACTIVE local_regression
tolerances declared in docs/bench/adr-051-slo-targets.json.

This is the executable half of MCPRE-110's committable deliverable. It is a
LOCAL-REGRESSION gate, not a production-SLO gate: it asserts a change has not
regressed the serving path against its own recorded baseline. The absolute
production SLOs (and the authoritative 1->N scaling acceptance) live in the
`production_slo` block of the targets file and stay null until a dedicated
load-generator run on the production hardware class exists (GKE fleet run).

The replay-race and bounded-drain gates are ABSOLUTE and hardware-independent;
they are enforced by their own always-on tests
(//mcp-re-proxy:replay_race_harness_test, //mcp-re-proxy:async_drain_test) and
are NOT re-checked here — this script only guards the throughput/latency
regression band.

Usage — prefer the lane script, which does both steps and refuses the known traps:

    scripts/local_slo_lane.sh          # 6 anchor reps, each gated by THIS script

By hand (see docs/dev/local-gate-order.md before you do):

    # 1. produce a fresh report at the baseline anchor config. `--exact`, NEVER
    #    `--ignored`: this bench is not an #[ignore] test (the file is gated to the
    #    redis_replay feature lane), so `--ignored` selects ZERO tests, exits 0 and
    #    writes no report. MCP_RE_LOADGEN_OUT must be ABSOLUTE — cargo runs the test
    #    binary from the package root. The harness spawns the real CLI, so the BIN
    #    must be built with the same features, not just the test target.
    cargo build --release -p mcp-re-proxy --features async_serve,redis_replay --bins
    MCP_RE_LOADGEN_CORES=1 MCP_RE_LOADGEN_CONCURRENCY=128 \\
    MCP_RE_LOADGEN_REQUESTS=8000 MCP_RE_LOADGEN_MODE=cold \\
    MCP_RE_LOADGEN_HW_CLASS=... MCP_RE_LOADGEN_OUT=$PWD/fresh.json \\
    cargo test -p mcp-re-proxy --release --features async_serve,redis_replay \\
        --test tls_load_harness_bench tls_load_harness_bench -- --exact --nocapture

    # 2. gate it
    python3 scripts/adr051_slo_gate.py --report $PWD/fresh.json

Measure on a QUIET box: the loadgen is co-located with the proxy, so an unrelated
build on the same machine produces an environmental FAIL that says nothing about the
code (this cost one full A/B/B/A investigation in 2026-07). The lane script enforces
this; a hand-run does not.

ONE ANCHOR PER HARDWARE CLASS, and this gate refuses to compare across them. It used to
compare whatever report it was handed against the single committed baseline, whatever
`config.hardware_class` that report carried — so a run measured somewhere else was
adjudicated against numbers recorded on a developer workstation and the verdict read as a
code result. A cross-class comparison is not a stricter or a looser gate; it is a gate
about a different question, which is the whole point of the measurement context in
`config/performance-surface.toml`. The anchor for a report is therefore resolved FROM the
report's own class, and a class with no declared anchor yields UNANCHORED rather than a
pass or a regression: nothing has been measured for that class to be compared against yet.

Exit status: 0 = within tolerance, 1 = regression, 2 = usage/data error,
             4 = not comparable (no anchor for this report's hardware class).
"""
import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGETS = REPO_ROOT / "docs/bench/adr-051-slo-targets.json"

#: Not a regression and not a usage error — a report this gate has no anchor for.
NOT_COMPARABLE = 4

# The declared class vocabulary has ONE owner (the file that declares the measurement
# context), and this gate reads it rather than keeping a second copy that could disagree
# about which class an anchor belongs to.
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from slo_evidence_identity import hardware_classes  # noqa: E402


def _load(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        print(f"adr051-slo-gate: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)


def _resolve_anchor(report, explicit):
    """`(baseline path, None)` when a comparison is legitimate, `(None, reason)` when not.

    The report's own `config.hardware_class` picks the anchor. An explicit `--baseline` is
    still checked against it: naming a file does not make the run a measurement of that
    file's class, and the whole defect this replaces was a comparison nobody had to state.
    """
    report_hw = report.get("config", {}).get("hardware_class")
    if report_hw is None:
        return None, (
            "the report declares no config.hardware_class, so there is no class to resolve "
            "an anchor for. Re-run through scripts/local_slo_lane.sh, which always sets one."
        )
    if explicit is None:
        entry = hardware_classes().get(report_hw)
        if entry is None:
            return None, (
                f"hardware_class {report_hw!r} is not declared in "
                f"config/performance-surface.toml. Declare the class — with its own anchor, "
                f"or with none — before a number measured on it is adjudicated."
            )
        anchor = entry["regression_anchor"]
        if not anchor:
            return None, (
                f"hardware_class {report_hw!r} has no committed regression anchor. This run "
                f"is a measurement of a context nothing has been recorded for yet, so there "
                f"is nothing to compare it against — declare an anchor for this class from a "
                f"deliberate quiet-box run before expecting a regression verdict."
            )
        return REPO_ROOT / anchor, None
    baseline = _load(explicit)
    anchor_hw = baseline.get("anchor", {}).get("config", {}).get("hardware_class")
    if anchor_hw != report_hw:
        return None, (
            f"the report was measured on hardware_class {report_hw!r} and {explicit} is an "
            f"anchor recorded on {anchor_hw!r}. A comparison across classes is not a "
            f"stricter or a looser gate — it is a gate about a different question."
        )
    return Path(explicit), None


def _unanchored(report, reason):
    """The hardware-independent half, for a report this gate has no anchor for.

    Not a pass and not a regression. The correctness check below is hardware-independent —
    a run that dropped requests is never acceptable on any class — so the run is not left
    having established nothing, and the verdict says exactly which of the two it is.
    """
    print("=== ADR-051 §7 local-regression SLO gate ===")
    print(f"NOT COMPARABLE: {reason}")
    dropped = report.get("results", {}).get("failures", 0)
    if dropped:
        print(f"\nRESULT: FAIL — {dropped} request failure(s) in the run. This check is "
              f"hardware-independent and bites on every class.", file=sys.stderr)
        return 1
    print("  [PASS] request failures                    0  (hardware-independent)")
    print("\nRESULT: UNANCHORED — measured, correctness clean, regression band not "
          "established for this class.", file=sys.stderr)
    return NOT_COMPARABLE


def _synth(hw, tput=15000.0, p50=8000, p99=16000, p999=19000, dropped=0):
    report = {"results": {"throughput_rps": tput, "failures": dropped,
                          "added_latency_us": {"p50": p50, "p99": p99, "p999": p999}}}
    if hw is not None:
        report["config"] = {"hardware_class": hw}
    return report


def selftest():
    """The comparability rules, exercised.

    They decide almost nothing on a developer's own box — the default class IS the anchor's
    class there — so without this they would be established only by a run on the one machine
    where they never fire. The anchor and the class names come from the committed
    declaration, so a class renamed in one place and not the other fails here.
    """
    anchored, unanchored = None, None
    for name, entry in hardware_classes().items():
        if entry["regression_anchor"] and anchored is None:
            anchored = name
        if not entry["regression_anchor"] and unanchored is None:
            unanchored = name
    if anchored is None or unanchored is None:
        print("SELFTEST FAILED: the declaration needs an anchored and an unanchored class "
              f"to exercise both paths (anchored={anchored}, unanchored={unanchored})")
        return 1

    cases = [
        ("an anchored class resolves its own anchor",
         _synth(anchored), None, lambda p, r: p is not None and r is None),
        ("an unanchored class is NOT COMPARABLE, not a regression",
         _synth(unanchored), None, lambda p, r: p is None and "no committed regression anchor" in r),
        ("an undeclared class is refused rather than adjudicated",
         _synth("some-box-nobody-declared"), None, lambda p, r: p is None and "not declared" in r),
        ("a report with no hardware_class at all is refused",
         _synth(None), None, lambda p, r: p is None and "no config.hardware_class" in r),
        ("an explicit --baseline may not launder a cross-class comparison",
         _synth(unanchored), str(REPO_ROOT / hardware_classes()[anchored]["regression_anchor"]),
         lambda p, r: p is None and "across classes" in r),
    ]
    ok = True
    for label, report, explicit, expected in cases:
        path, reason = _resolve_anchor(report, explicit)
        held = expected(path, reason)
        print(f"  {'ok  ' if held else 'FAIL'}  {label}")
        if not held:
            ok = False
            print(f"        got path={path}, reason={reason}")

    # An UNANCHORED run is not a pass, and the hardware-independent half still bites.
    if _unanchored(_synth(unanchored), "test") != NOT_COMPARABLE:
        print("  FAIL  a clean unanchored run did not report NOT COMPARABLE")
        ok = False
    if _unanchored(_synth(unanchored, dropped=7), "test") != 1:
        print("  FAIL  an unanchored run that dropped requests was not a failure")
        ok = False

    print("adr051_slo_gate selftest:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="ADR-051 §7 local-regression SLO gate")
    ap.add_argument("--report", help="fresh harness report JSON (MCP_RE_LOADGEN_OUT)")
    ap.add_argument("--baseline", default=None,
                    help="committed baseline JSON (default: the anchor declared for the "
                         "report's own hardware class)")
    ap.add_argument("--targets", default=DEFAULT_TARGETS, help="committed SLO targets JSON")
    ap.add_argument("--selftest", action="store_true", help="exercise the comparability rules")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.report:
        ap.error("--report is required (or --selftest)")

    report = _load(args.report)
    baseline_path, reason = _resolve_anchor(report, args.baseline)
    if baseline_path is None:
        return _unanchored(report, reason)
    args.baseline = baseline_path
    baseline = _load(baseline_path)
    targets = _load(args.targets)

    reg = targets.get("local_regression", {})
    if reg.get("status") != "active":
        print("adr051-slo-gate: local_regression is not active; nothing to gate.")
        return 0
    tol = reg["tolerances"]

    base = baseline["anchor"]["results"]
    got = report["results"]
    base_lat = base["added_latency_us"]
    got_lat = got["added_latency_us"]

    base_rps = base["throughput_rps"]
    got_rps = got["throughput_rps"]

    failures = []
    checks = []

    # Throughput floor: fresh >= fraction * baseline.
    min_rps = base_rps * tol["throughput_rps_min_fraction"]
    ok = got_rps >= min_rps
    checks.append(("throughput_rps", f">= {min_rps:.1f}", f"{got_rps:.1f}", ok))
    if not ok:
        failures.append("throughput regressed below floor")

    # Latency ceilings: fresh <= fraction * baseline, per percentile.
    for pct, key in (("p50", "p50_added_us_max_fraction"),
                     ("p99", "p99_added_us_max_fraction"),
                     ("p999", "p999_added_us_max_fraction")):
        ceil = base_lat[pct] * tol[key]
        val = got_lat[pct]
        ok = val <= ceil
        checks.append((f"{pct}_added_us", f"<= {ceil:.0f}", f"{val}", ok))
        if not ok:
            failures.append(f"{pct} added latency exceeded ceiling")

    # A run that produced request failures is never a pass.
    if got.get("failures", 0) != 0:
        failures.append(f"{got['failures']} request failure(s) in the fresh run")

    width = max(len(c[0]) for c in checks)
    print("=== ADR-051 §7 local-regression SLO gate ===")
    print(f"hardware class: {report['config']['hardware_class']}")
    print(f"baseline: {Path(args.baseline).name}  (anchor rps={base_rps:.1f}, "
          f"p50={base_lat['p50']}us p99={base_lat['p99']}us p999={base_lat['p999']}us)")
    for name, bound, val, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<{width}}  {val:>10}  (bound {bound})")

    if failures:
        print("\nRESULT: FAIL — " + "; ".join(failures), file=sys.stderr)
        return 1
    print("\nRESULT: PASS — within local-regression tolerances.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
