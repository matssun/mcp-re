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

Usage:
    # 1. produce a fresh report at the baseline anchor config
    MCP_RE_LOADGEN_CORES=1 MCP_RE_LOADGEN_CONCURRENCY=128 \\
    MCP_RE_LOADGEN_REQUESTS=8000 MCP_RE_LOADGEN_MODE=cold \\
    MCP_RE_LOADGEN_HW_CLASS=... MCP_RE_LOADGEN_OUT=/tmp/fresh.json \\
    cargo test -p mcp-re-proxy --release --test tls_load_harness_bench \\
        tls_load_harness_bench -- --ignored

    # 2. gate it
    python3 scripts/adr051_slo_gate.py --report /tmp/fresh.json

Exit status: 0 = within tolerance, 1 = regression, 2 = usage/data error.
"""
import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASELINE = REPO_ROOT / "docs/bench/adr-051-baseline-local.json"
DEFAULT_TARGETS = REPO_ROOT / "docs/bench/adr-051-slo-targets.json"


def _load(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        print(f"adr051-slo-gate: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description="ADR-051 §7 local-regression SLO gate")
    ap.add_argument("--report", required=True, help="fresh harness report JSON (MCP_RE_LOADGEN_OUT)")
    ap.add_argument("--baseline", default=DEFAULT_BASELINE, help="committed baseline JSON")
    ap.add_argument("--targets", default=DEFAULT_TARGETS, help="committed SLO targets JSON")
    args = ap.parse_args()

    report = _load(args.report)
    baseline = _load(args.baseline)
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
